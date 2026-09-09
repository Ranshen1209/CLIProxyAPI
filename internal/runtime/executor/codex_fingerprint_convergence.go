package executor

import (
	"crypto/sha256"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Codex fingerprint convergence.
//
// This file stays in package executor next to identity-confuse (codex_executor_request.go)
// because both share unexported request-path types. Moving it to helps/ would export
// that snapshot or split one rewrite across packages.
//
// A single Codex OAuth credential is often shared by many downstream users. Each
// real Codex client reports its own installation/session/thread/turn/window IDs,
// so upstream sees one account with a large, changing device and conversation
// population. Convergence rewrites those identifiers to deterministic values
// derived from the credential and the client's own session, keeping the shapes a
// real Codex client produces:
//
//   - x-codex-installation-id is a per-credential constant (UUIDv4).
//   - session-id / thread-id / x-client-request-id are the same value for a root
//     session, and differ for a subagent thread; the raw relationship is preserved
//     because both are derived with the same namespace.
//   - session/thread/turn/window/context-window UUIDv7 values keep their millisecond
//     timestamp prefix and version 7; everything else derives a UUIDv4.
//   - x-codex-window-id keeps the "<thread>:<window_number>" form when the client
//     sent a numeric window; missing or non-numeric windows are not invented.
//   - root_turn_id follows turn_id for a root turn and stays distinct for a child,
//     and is only written when the client sent one.
//   - the underscore session_id / conversation_id aliases are dropped on HTTP once a
//     hyphen session-id exists.
//
// Cache correctness is the primary constraint: every derived value is a pure
// function of the credential seed plus the client's raw identifier, so the same
// client session always produces the same upstream session and prompt cache key.
// A prompt_cache_key alone is not session evidence and is never staged as one.
// When no client session evidence exists at all, session identity is left untouched
// so a request can never leave the gateway with a freshly invented, cache-busting
// session; only the per-credential installation ID is converged.

const (
	codexConvergenceModeAttr       = "fingerprint_convergence"
	codexConvergenceModeAttrLegacy = "fingerprint-convergence"
	// codexTurnMetadataHeader is the HTTP header name; codexTurnMetadataBodyKey is
	// the same value embedded as a string inside client_metadata, which clients
	// send lower-case.
	codexTurnMetadataHeader   = "X-Codex-Turn-Metadata"
	codexTurnMetadataBodyKey  = "x-codex-turn-metadata"
	codexSubagentHeader       = "X-Openai-Subagent"
	codexSubagentBodyKey      = "x-openai-subagent"
	codexConvergenceNamespace = "cli-proxy-api:codex:fingerprint-convergence:v1"
)

// codexFingerprintConvergenceMode is the resolved convergence strength.
type codexFingerprintConvergenceMode string

const (
	codexConvergenceOff     codexFingerprintConvergenceMode = config.CodexFingerprintConvergenceOff
	codexConvergenceDevice  codexFingerprintConvergenceMode = config.CodexFingerprintConvergenceDevice
	codexConvergenceSession codexFingerprintConvergenceMode = config.CodexFingerprintConvergenceSession
	codexConvergenceFull    codexFingerprintConvergenceMode = config.CodexFingerprintConvergenceFull
)

// codexConvergenceSessionHeaderStyle selects the session header spelling the
// transport contract already uses. HTTP/SSE uses the hyphenated Codex form; the
// websocket handshake keeps the underscore form this proxy already sends and
// deletes the hyphenated duplicate.
type codexConvergenceSessionHeaderStyle int

const (
	codexConvergenceHeadersHyphen codexConvergenceSessionHeaderStyle = iota
	codexConvergenceHeadersUnderscore
)

// codexConvergenceWarned deduplicates the unrecognized-value warning. Mode
// resolution runs several times per request, so warning on every call would turn
// one config typo into a per-request log flood.
var codexConvergenceWarned sync.Map

// resolveCodexFingerprintConvergenceMode resolves the effective mode for one
// credential: an auth-file/attribute override wins over the global config.
func resolveCodexFingerprintConvergenceMode(cfg *config.Config, auth *cliproxyauth.Auth) codexFingerprintConvergenceMode {
	raw, ok := codexConvergenceModeOverride(auth)
	if !ok {
		if cfg == nil {
			return codexConvergenceOff
		}
		raw = cfg.Codex.FingerprintConvergence
	}
	normalized, recognized := config.NormalizeCodexFingerprintConvergence(raw)
	if !recognized {
		if _, warned := codexConvergenceWarned.LoadOrStore(strings.TrimSpace(raw), struct{}{}); !warned {
			log.Warnf("unrecognized codex fingerprint-convergence %q (supported: %s); convergence disabled",
				raw, config.FormatCodexFingerprintConvergenceValues())
		}
		return codexConvergenceOff
	}
	return codexFingerprintConvergenceMode(normalized)
}

func codexConvergenceModeOverride(auth *cliproxyauth.Auth) (string, bool) {
	if auth == nil {
		return "", false
	}
	if auth.Attributes != nil {
		for _, key := range []string{codexConvergenceModeAttr, codexConvergenceModeAttrLegacy} {
			if raw := strings.TrimSpace(auth.Attributes[key]); raw != "" {
				return raw, true
			}
		}
	}
	if auth.Metadata != nil {
		for _, key := range []string{codexConvergenceModeAttr, codexConvergenceModeAttrLegacy} {
			raw, ok := auth.Metadata[key]
			if !ok {
				continue
			}
			switch value := raw.(type) {
			case string:
				if trimmed := strings.TrimSpace(value); trimmed != "" {
					return trimmed, true
				}
			case bool:
				// A bare boolean is the legacy opt-in: true selects session mode.
				if value {
					return config.CodexFingerprintConvergenceSession, true
				}
				return config.CodexFingerprintConvergenceOff, true
			case float64:
				if value != 0 {
					return config.CodexFingerprintConvergenceSession, true
				}
				return config.CodexFingerprintConvergenceOff, true
			}
		}
	}
	return "", false
}

// codexFingerprintConvergenceSeed returns a stable per-credential seed. The
// upstream account ID is preferred because multiple local rows for the same
// ChatGPT account must converge to one device, and it survives file renames.
func codexFingerprintConvergenceSeed(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		for _, key := range []string{"account_id", "chatgpt_account_id"} {
			if raw, ok := auth.Metadata[key].(string); ok {
				if trimmed := strings.TrimSpace(raw); trimmed != "" {
					return "account:" + trimmed
				}
			}
		}
	}
	if id := strings.TrimSpace(auth.ID); id != "" {
		return "auth:" + id
	}
	if index := strings.TrimSpace(auth.Index); index != "" {
		return "index:" + index
	}
	if fileName := strings.TrimSpace(auth.FileName); fileName != "" {
		return "file:" + fileName
	}
	return ""
}

// codexConvergenceDeriveUUID derives a deterministic UUID. When the raw value is a
// canonical UUIDv7 the derived value keeps its millisecond timestamp and version 7,
// mirroring Uuid::now_v7() in the real client; every other value derives a UUIDv4.
func codexConvergenceDeriveUUID(seed, kind, raw string) string {
	hash := sha256.Sum256([]byte(codexConvergenceNamespace + "\x00" + kind + "\x00" + seed + "\x00" + raw))
	var derived uuid.UUID
	copy(derived[:], hash[:16])
	version := byte(4)
	if parsed, err := uuid.Parse(strings.TrimSpace(raw)); err == nil && parsed != uuid.Nil &&
		parsed.String() == strings.TrimSpace(raw) && parsed.Version() == 7 {
		copy(derived[0:6], parsed[0:6])
		version = 7
	}
	derived[6] = (derived[6] & 0x0f) | (version << 4)
	derived[8] = (derived[8] & 0x3f) | 0x80
	return derived.String()
}

// codexConvergenceRawIdentity is the client-supplied identity captured before any
// rewrite. Header evidence wins over body evidence for the same field.
type codexConvergenceRawIdentity struct {
	sessionID          string
	threadID           string
	turnID             string
	rootTurnID         string
	windowID           string
	contextWindowID    string
	parentThreadID     string
	parentTurnID       string
	forkedFromThreadID string
	subagent           string
}

func (raw codexConvergenceRawIdentity) hasSessionEvidence() bool {
	return raw.sessionID != "" || raw.threadID != ""
}

// codexConvergenceIdentity is the converged identity projected onto every carrier.
type codexConvergenceIdentity struct {
	installationID     string
	sessionID          string
	threadID           string
	turnID             string
	rootTurnID         string
	windowID           string
	parentThreadID     string
	parentTurnID       string
	forkedFromThreadID string
	contextWindowID    string
	promptCacheKey     string
	subagent           string
}

// codexFingerprintConvergenceState carries the resolved identity between the body
// rewrite and the header rewrite for a single upstream attempt.
type codexFingerprintConvergenceState struct {
	enabled            bool
	mode               codexFingerprintConvergenceMode
	sessionHeaderStyle codexConvergenceSessionHeaderStyle
	ids                codexConvergenceIdentity
	rawTurnMetadata    string
}

func (state codexFingerprintConvergenceState) active() bool {
	return state.enabled && state.mode != codexConvergenceOff
}

func (state codexFingerprintConvergenceState) convergesSession() bool {
	return state.active() && state.mode != codexConvergenceDevice && state.ids.sessionID != ""
}

// codexConvergenceModeEnabled reports whether convergence is configured for this
// credential. It is used to let convergence supersede identity-confuse instead of
// stacking two different rewrites on the same fields.
func codexConvergenceModeEnabled(cfg *config.Config, auth *cliproxyauth.Auth) bool {
	return resolveCodexFingerprintConvergenceMode(cfg, auth) != codexConvergenceOff
}

// resolveCodexFingerprintConvergence captures client evidence and derives the
// converged identity. cacheID is the prompt cache key the gateway itself assigned
// (empty when it did not). A cache ID that is only the client's prompt_cache_key
// is not independent session evidence and is never staged as a session.
func resolveCodexFingerprintConvergence(
	cfg *config.Config,
	auth *cliproxyauth.Auth,
	clientHeaders http.Header,
	upstreamBody []byte,
	clientBody []byte,
	cacheID string,
	sessionHeaderStyle codexConvergenceSessionHeaderStyle,
) codexFingerprintConvergenceState {
	mode := resolveCodexFingerprintConvergenceMode(cfg, auth)
	state := codexFingerprintConvergenceState{mode: mode, sessionHeaderStyle: sessionHeaderStyle}
	if mode == codexConvergenceOff {
		return state
	}
	seed := codexFingerprintConvergenceSeed(auth)
	if seed == "" {
		return state
	}

	raw := captureCodexConvergenceRawIdentity(clientHeaders, upstreamBody)
	clientPromptCacheKey := strings.TrimSpace(gjson.GetBytes(clientBody, "prompt_cache_key").String())
	cacheID = strings.TrimSpace(cacheID)
	// The gateway's own prompt cache key is a stable per-conversation identity
	// (session affinity, Claude Code session, or a derived session UUID). When the
	// client sent no session header or body session at all it is the only session
	// evidence available, and adopting it keeps session_id == prompt_cache_key
	// without inventing a value that changes between requests. A client-supplied
	// cache key by itself is not a session and must not be staged as one.
	if !raw.hasSessionEvidence() && cacheID != "" && !codexConvergenceCacheIDIsClientKey(cacheID, clientPromptCacheKey) {
		raw.sessionID = cacheID
	}

	ids := codexConvergenceIdentity{
		installationID: codexConvergenceDeriveUUID(seed, "installation", seed),
		subagent:       raw.subagent,
	}

	if mode != codexConvergenceDevice && raw.hasSessionEvidence() {
		sessionSource := raw.sessionID
		if sessionSource == "" {
			sessionSource = raw.threadID
		}
		threadSource := raw.threadID
		if threadSource == "" {
			threadSource = sessionSource
		}
		ids.sessionID = codexConvergenceDeriveUUID(seed, "thread", sessionSource)
		ids.threadID = codexConvergenceDeriveUUID(seed, "thread", threadSource)
		if mode == codexConvergenceFull {
			ids.threadID = ids.sessionID
		}
		if turn, errTurn := uuid.NewV7(); errTurn == nil {
			ids.turnID = turn.String()
		} else if raw.turnID != "" {
			ids.turnID = raw.turnID
		}
		if raw.rootTurnID != "" {
			if raw.turnID != "" && raw.rootTurnID == raw.turnID && ids.turnID != "" {
				ids.rootTurnID = ids.turnID
			} else {
				ids.rootTurnID = codexConvergenceDeriveUUID(seed, "turn", raw.rootTurnID)
			}
		}
		if number, ok := codexConvergenceWindowNumber(raw.windowID); ok {
			ids.windowID = ids.threadID + ":" + number
		}
		if raw.parentThreadID != "" {
			ids.parentThreadID = codexConvergenceDeriveUUID(seed, "thread", raw.parentThreadID)
		}
		if raw.parentTurnID != "" {
			ids.parentTurnID = codexConvergenceDeriveUUID(seed, "turn", raw.parentTurnID)
		}
		if raw.forkedFromThreadID != "" {
			ids.forkedFromThreadID = codexConvergenceDeriveUUID(seed, "thread", raw.forkedFromThreadID)
		}
		if raw.contextWindowID != "" {
			ids.contextWindowID = codexConvergenceDeriveUUID(seed, "context-window", raw.contextWindowID)
		}
		if composite := deriveCodexConvergenceCompositePromptCacheKey(seed, clientPromptCacheKey); composite != "" {
			ids.promptCacheKey = composite
		} else if codexConvergenceShouldRewritePromptCacheKey(raw, clientPromptCacheKey, cacheID) {
			ids.promptCacheKey = ids.sessionID
		}
	}

	state.enabled = true
	state.mode = mode
	state.ids = ids
	state.rawTurnMetadata = codexConvergenceTurnMetadataSource(clientHeaders, upstreamBody)
	return state
}

func codexConvergenceCacheIDIsClientKey(cacheID, clientPromptCacheKey string) bool {
	cacheID = strings.TrimSpace(cacheID)
	clientPromptCacheKey = strings.TrimSpace(clientPromptCacheKey)
	return cacheID != "" && clientPromptCacheKey != "" && cacheID == clientPromptCacheKey
}

// captureCodexConvergenceRawIdentity reads the client identity from the inbound
// headers first, then the request body. Both the flat client_metadata object and
// the turn-metadata embedded inside it are consulted.
func captureCodexConvergenceRawIdentity(clientHeaders http.Header, body []byte) codexConvergenceRawIdentity {
	raw := codexConvergenceRawIdentity{}
	if clientHeaders != nil {
		fillCodexConvergenceRawString(&raw.sessionID, clientHeaders.Get("session-id"))
		fillCodexConvergenceRawString(&raw.sessionID, clientHeaders.Get("session_id"))
		fillCodexConvergenceRawString(&raw.threadID, clientHeaders.Get("thread-id"))
		fillCodexConvergenceRawString(&raw.threadID, clientHeaders.Get("thread_id"))
		fillCodexConvergenceRawString(&raw.windowID, clientHeaders.Get("x-codex-window-id"))
		fillCodexConvergenceRawString(&raw.parentThreadID, clientHeaders.Get("x-codex-parent-thread-id"))
		fillCodexConvergenceRawString(&raw.subagent, clientHeaders.Get(codexSubagentHeader))
		captureCodexConvergenceRawFromResult(&raw, gjson.Parse(strings.TrimSpace(clientHeaders.Get(codexTurnMetadataHeader))))
	}
	if len(body) == 0 {
		return raw
	}
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		return raw
	}
	clientMetadata := root.Get("client_metadata")
	if clientMetadata.IsObject() {
		captureCodexConvergenceRawFromResult(&raw, clientMetadata)
		embedded := clientMetadata.Get(codexTurnMetadataBodyKey)
		if embedded.Type == gjson.String {
			captureCodexConvergenceRawFromResult(&raw, gjson.Parse(embedded.String()))
		}
	}
	return raw
}

func captureCodexConvergenceRawFromResult(raw *codexConvergenceRawIdentity, metadata gjson.Result) {
	if raw == nil || !metadata.IsObject() {
		return
	}
	fillCodexConvergenceRawString(&raw.sessionID, codexConvergenceMetadataString(metadata, "session_id"))
	fillCodexConvergenceRawString(&raw.threadID, codexConvergenceMetadataString(metadata, "thread_id"))
	fillCodexConvergenceRawString(&raw.turnID, codexConvergenceMetadataString(metadata, "turn_id"))
	fillCodexConvergenceRawString(&raw.rootTurnID, codexConvergenceMetadataString(metadata, "root_turn_id"))
	fillCodexConvergenceRawString(&raw.windowID, codexConvergenceMetadataString(metadata, "window_id"))
	fillCodexConvergenceRawString(&raw.windowID, codexConvergenceMetadataString(metadata, "x-codex-window-id"))
	fillCodexConvergenceRawString(&raw.contextWindowID, codexConvergenceMetadataString(metadata, "context_window_id"))
	fillCodexConvergenceRawString(&raw.parentThreadID, codexConvergenceMetadataString(metadata, "parent_thread_id"))
	fillCodexConvergenceRawString(&raw.parentThreadID, codexConvergenceMetadataString(metadata, "x-codex-parent-thread-id"))
	fillCodexConvergenceRawString(&raw.parentTurnID, codexConvergenceMetadataString(metadata, "parent_turn_id"))
	fillCodexConvergenceRawString(&raw.forkedFromThreadID, codexConvergenceMetadataString(metadata, "forked_from_thread_id"))
	fillCodexConvergenceRawString(&raw.subagent, codexConvergenceMetadataString(metadata, codexSubagentBodyKey))
}

func codexConvergenceMetadataString(metadata gjson.Result, name string) string {
	value := metadata.Get(name)
	if value.Type != gjson.String {
		return ""
	}
	return strings.TrimSpace(value.String())
}

func fillCodexConvergenceRawString(target *string, value string) {
	if target == nil || *target != "" {
		return
	}
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		*target = trimmed
	}
}

func codexConvergenceTurnMetadataSource(clientHeaders http.Header, body []byte) string {
	if clientHeaders != nil {
		if raw := strings.TrimSpace(clientHeaders.Get(codexTurnMetadataHeader)); raw != "" {
			return raw
		}
	}
	if len(body) == 0 {
		return ""
	}
	embedded := gjson.GetBytes(body, "client_metadata."+codexTurnMetadataBodyKey)
	if embedded.Type != gjson.String {
		return ""
	}
	return strings.TrimSpace(embedded.String())
}

func codexConvergenceWindowNumber(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if idx := strings.LastIndex(raw, ":"); idx > 0 {
		if number := strings.TrimSpace(raw[idx+1:]); number != "" {
			for _, char := range number {
				if char < '0' || char > '9' {
					return "", false
				}
			}
			return number, true
		}
	}
	return "", false
}

// codexConvergencePromptCacheKeyPattern matches the subagent cache key form
// "<session_source>:<parent_thread_id>". The UUID part is derived; the prefix is kept.
var codexConvergencePromptCacheKeyPattern = regexp.MustCompile(
	`^([A-Za-z0-9_-]{1,64}):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

func deriveCodexConvergenceCompositePromptCacheKey(seed, clientPromptCacheKey string) string {
	clientPromptCacheKey = strings.TrimSpace(clientPromptCacheKey)
	matches := codexConvergencePromptCacheKeyPattern.FindStringSubmatch(clientPromptCacheKey)
	if len(matches) != 3 {
		return ""
	}
	return matches[1] + ":" + codexConvergenceDeriveUUID(seed, "thread", matches[2])
}

// codexConvergenceShouldRewritePromptCacheKey decides whether the prompt cache key
// is a session-scoped default that may follow the converged session. An explicit
// client key is never touched, so a caller that deliberately shares or splits a
// cache bucket keeps that behavior. Composite keys are handled separately.
func codexConvergenceShouldRewritePromptCacheKey(raw codexConvergenceRawIdentity, clientPromptCacheKey string, cacheID string) bool {
	clientPromptCacheKey = strings.TrimSpace(clientPromptCacheKey)
	if codexConvergencePromptCacheKeyPattern.MatchString(clientPromptCacheKey) {
		return false
	}
	if clientPromptCacheKey == "" {
		// No client-supplied key: the upstream body carries either the gateway's
		// own session-derived key or nothing. Align with the session only when the
		// body already has a prompt_cache_key (rewriteCodexConvergenceExistingPromptCacheKey
		// refuses to invent the field).
		return true
	}
	if raw.sessionID != "" && clientPromptCacheKey == raw.sessionID {
		return true
	}
	if raw.threadID != "" && clientPromptCacheKey == raw.threadID {
		return true
	}
	if cacheID != "" && clientPromptCacheKey == cacheID && raw.hasSessionEvidence() {
		return true
	}
	return false
}

// applyCodexFingerprintConvergenceBody rewrites the upstream request body.
// Non-Responses bodies never gain client_metadata. prompt_cache_key is rewritten
// only when the field already exists.
func applyCodexFingerprintConvergenceBody(body []byte, state codexFingerprintConvergenceState) ([]byte, bool) {
	if len(body) == 0 || !state.active() {
		return body, false
	}
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		return body, false
	}

	existing := root.Get("client_metadata")
	hasClientMetadata := existing.IsObject()
	isResponses := hasClientMetadata || root.Get("input").Exists() || root.Get("instructions").Exists()
	if !isResponses {
		return rewriteCodexConvergenceExistingPromptCacheKey(body, state)
	}

	next := body
	changed := false
	if state.ids.installationID != "" {
		if updated, errSet := sjson.SetBytes(next, "client_metadata.x-codex-installation-id", state.ids.installationID); errSet == nil {
			next = updated
			changed = true
		}
	}
	if state.convergesSession() {
		next, changed = setCodexConvergenceBodyString(next, "client_metadata.session_id", state.ids.sessionID, changed)
		next, changed = setCodexConvergenceBodyString(next, "client_metadata.thread_id", state.ids.threadID, changed)
		next, changed = setCodexConvergenceBodyString(next, "client_metadata.turn_id", state.ids.turnID, changed)
		next, changed = setCodexConvergenceBodyString(next, "client_metadata.root_turn_id", state.ids.rootTurnID, changed)
		next, changed = setCodexConvergenceBodyString(next, "client_metadata.x-codex-window-id", state.ids.windowID, changed)
		next, changed = setCodexConvergenceBodyString(next, "client_metadata.x-codex-parent-thread-id", state.ids.parentThreadID, changed)
		next, changed = setCodexConvergenceBodyString(next, "client_metadata.parent_turn_id", state.ids.parentTurnID, changed)
		next, changed = setCodexConvergenceBodyString(next, "client_metadata.forked_from_thread_id", state.ids.forkedFromThreadID, changed)
		next, changed = setCodexConvergenceBodyString(next, "client_metadata.context_window_id", state.ids.contextWindowID, changed)
		next, changed = setCodexConvergenceBodyString(next, "client_metadata."+codexSubagentBodyKey, state.ids.subagent, changed)
	}
	if updated, rewritten := rewriteCodexConvergenceEmbeddedMetadataJSON(next, state); rewritten {
		next = updated
		changed = true
	}
	if updated, updatedOK := rewriteCodexConvergenceExistingPromptCacheKey(next, state); updatedOK {
		next = updated
		changed = true
	}
	return next, changed
}

func setCodexConvergenceBodyString(body []byte, path, value string, changed bool) ([]byte, bool) {
	if strings.TrimSpace(value) == "" {
		return body, changed
	}
	updated, errSet := sjson.SetBytes(body, path, value)
	if errSet != nil {
		return body, changed
	}
	return updated, true
}

func rewriteCodexConvergenceExistingPromptCacheKey(body []byte, state codexFingerprintConvergenceState) ([]byte, bool) {
	if state.ids.promptCacheKey == "" || !gjson.GetBytes(body, "prompt_cache_key").Exists() {
		return body, false
	}
	updated, errSet := sjson.SetBytes(body, "prompt_cache_key", state.ids.promptCacheKey)
	if errSet != nil {
		return body, false
	}
	return updated, true
}

func rewriteCodexConvergenceEmbeddedMetadataJSON(body []byte, state codexFingerprintConvergenceState) ([]byte, bool) {
	changed := false
	for _, key := range []string{codexTurnMetadataBodyKey, codexTurnMetadataHeader} {
		path := "client_metadata." + key
		raw := gjson.GetBytes(body, path)
		if raw.Type != gjson.String || strings.TrimSpace(raw.String()) == "" {
			continue
		}
		rebuilt := applyCodexConvergenceMetadataJSON(raw.String(), state)
		if rebuilt == raw.String() {
			continue
		}
		updated, errSet := sjson.SetBytes(body, path, rebuilt)
		if errSet != nil {
			continue
		}
		body = updated
		changed = true
	}
	return body, changed
}

// applyCodexFingerprintConvergenceHeaders rewrites the outbound identity headers.
// It runs after the transport's own header assembly so the converged values win,
// while preserving unrelated headers (originator, user-agent, version).
func applyCodexFingerprintConvergenceHeaders(headers http.Header, state codexFingerprintConvergenceState) {
	if headers == nil || !state.active() {
		return
	}
	if state.ids.installationID != "" {
		headers.Set("X-Codex-Installation-Id", state.ids.installationID)
	}
	if state.rawTurnMetadata != "" {
		rebuilt := applyCodexConvergenceMetadataJSON(state.rawTurnMetadata, state)
		headers.Set(codexTurnMetadataHeader, rebuilt)
	}
	if state.ids.subagent != "" {
		headers.Set(codexSubagentHeader, state.ids.subagent)
	}
	if !state.convergesSession() {
		return
	}

	if state.sessionHeaderStyle == codexConvergenceHeadersUnderscore {
		setHeaderCasePreserved(headers, "session_id", state.ids.sessionID)
		if headerValueCaseInsensitive(headers, "Conversation_id") != "" {
			setHeaderCasePreserved(headers, "Conversation_id", state.ids.sessionID)
		}
		deleteHeaderCaseInsensitive(headers, "Session-Id")
	} else {
		headers.Set("Session-Id", state.ids.sessionID)
		// A hyphen session-id now exists, so the underscore aliases a real Codex
		// client never sends are removed instead of leaking a second identity.
		deleteHeaderCaseInsensitive(headers, "session_id")
		deleteHeaderCaseInsensitive(headers, "conversation_id")
	}
	headers.Set("Thread-Id", state.ids.threadID)
	headers.Set("X-Client-Request-Id", state.ids.threadID)
	if state.ids.windowID != "" {
		headers.Set("X-Codex-Window-Id", state.ids.windowID)
	}
	if state.ids.parentThreadID != "" {
		headers.Set("X-Codex-Parent-Thread-Id", state.ids.parentThreadID)
	}
}

func applyCodexConvergenceMetadataJSON(raw string, state codexFingerprintConvergenceState) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !state.active() {
		return raw
	}
	next := []byte(raw)
	if !gjson.ValidBytes(next) || !gjson.ParseBytes(next).IsObject() {
		next = []byte("{}")
	}
	set := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		if updated, errSet := sjson.SetBytes(next, key, value); errSet == nil {
			next = updated
		}
	}
	set("installation_id", state.ids.installationID)
	if !state.convergesSession() {
		return string(next)
	}
	set("session_id", state.ids.sessionID)
	set("thread_id", state.ids.threadID)
	set("turn_id", state.ids.turnID)
	set("root_turn_id", state.ids.rootTurnID)
	set("window_id", state.ids.windowID)
	set("parent_thread_id", state.ids.parentThreadID)
	set("parent_turn_id", state.ids.parentTurnID)
	set("forked_from_thread_id", state.ids.forkedFromThreadID)
	set("context_window_id", state.ids.contextWindowID)
	set(codexSubagentBodyKey, state.ids.subagent)
	return string(next)
}
