package executor

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Codex fingerprint convergence.
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
//   - x-codex-window-id keeps the "<thread>:<window_number>" form.
//   - root_turn_id follows turn_id for a root turn and stays distinct for a child.
//   - the underscore session_id / conversation_id aliases are dropped on HTTP once a
//     hyphen session-id exists.
//
// Cache correctness is the primary constraint: every derived value is a pure
// function of the credential seed plus the client's raw identifier, so the same
// client session always produces the same upstream session and prompt cache key.
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
	sessionID       string
	threadID        string
	turnID          string
	rootTurnID      string
	windowID        string
	contextWindowID string
	parentThreadID  string
}

func (raw codexConvergenceRawIdentity) hasSessionEvidence() bool {
	return raw.sessionID != "" || raw.threadID != ""
}

// codexConvergenceIdentity is the converged identity projected onto every carrier.
type codexConvergenceIdentity struct {
	installationID  string
	sessionID       string
	threadID        string
	turnID          string
	rootTurnID      string
	windowID        string
	parentThreadID  string
	contextWindowID string
	promptCacheKey  string
	turnStartedAtMs int64
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
// (empty when it did not), used only to recognise a gateway-invented cache key.
func resolveCodexFingerprintConvergence(
	cfg *config.Config,
	auth *cliproxyauth.Auth,
	clientHeaders http.Header,
	upstreamBody []byte,
	clientBody []byte,
	cacheID string,
	sessionHeaderStyle codexConvergenceSessionHeaderStyle,
) codexFingerprintConvergenceState {
	state := codexFingerprintConvergenceState{sessionHeaderStyle: sessionHeaderStyle}
	mode := resolveCodexFingerprintConvergenceMode(cfg, auth)
	if mode == codexConvergenceOff {
		return state
	}
	seed := codexFingerprintConvergenceSeed(auth)
	if seed == "" {
		return state
	}

	raw := captureCodexConvergenceRawIdentity(clientHeaders, upstreamBody)
	clientPromptCacheKey := strings.TrimSpace(gjson.GetBytes(clientBody, "prompt_cache_key").String())
	// The gateway's own prompt cache key is a stable per-conversation identity
	// (session affinity, Claude Code session, or a derived session UUID). When the
	// client sent no session header or body session at all it is the only session
	// evidence available, and adopting it keeps session_id == prompt_cache_key
	// without inventing a value that changes between requests.
	if !raw.hasSessionEvidence() && strings.TrimSpace(cacheID) != "" {
		raw.sessionID = strings.TrimSpace(cacheID)
	}

	ids := codexConvergenceIdentity{
		installationID:  codexConvergenceDeriveUUID(seed, "installation", seed),
		turnStartedAtMs: time.Now().UnixMilli(),
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
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.rootTurnID = ids.turnID
		if raw.rootTurnID != "" && raw.turnID != "" && raw.rootTurnID != raw.turnID {
			ids.rootTurnID = codexConvergenceDeriveUUID(seed, "turn", raw.rootTurnID)
		}
		ids.windowID = ids.threadID + ":" + codexConvergenceWindowNumber(raw.windowID)
		if raw.parentThreadID != "" {
			ids.parentThreadID = codexConvergenceDeriveUUID(seed, "thread", raw.parentThreadID)
		}
		if raw.contextWindowID != "" {
			ids.contextWindowID = codexConvergenceDeriveUUID(seed, "context-window", raw.contextWindowID)
		}
		if codexConvergenceShouldRewritePromptCacheKey(raw, clientPromptCacheKey, cacheID) {
			ids.promptCacheKey = ids.sessionID
		}
	}

	state.enabled = true
	state.mode = mode
	state.ids = ids
	state.rawTurnMetadata = codexConvergenceTurnMetadataSource(clientHeaders, upstreamBody)
	return state
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

func codexConvergenceWindowNumber(raw string) string {
	raw = strings.TrimSpace(raw)
	if idx := strings.LastIndex(raw, ":"); idx > 0 {
		if number := strings.TrimSpace(raw[idx+1:]); number != "" {
			digits := true
			for _, char := range number {
				if char < '0' || char > '9' {
					digits = false
					break
				}
			}
			if digits {
				return number
			}
		}
	}
	return "0"
}

// codexConvergencePromptCacheKeyPattern matches the subagent cache key form
// "<session_source>:<parent_thread_id>", which must never be collapsed onto the
// converged session or the parent-thread relationship disappears.
var codexConvergencePromptCacheKeyPattern = regexp.MustCompile(
	`^[A-Za-z0-9_-]{1,64}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// codexConvergenceShouldRewritePromptCacheKey decides whether the prompt cache key
// is a session-scoped default that may follow the converged session. An explicit
// client key is never touched, so a caller that deliberately shares or splits a
// cache bucket keeps that behavior.
func codexConvergenceShouldRewritePromptCacheKey(raw codexConvergenceRawIdentity, clientPromptCacheKey string, cacheID string) bool {
	clientPromptCacheKey = strings.TrimSpace(clientPromptCacheKey)
	if codexConvergencePromptCacheKeyPattern.MatchString(clientPromptCacheKey) {
		return false
	}
	if clientPromptCacheKey == "" {
		// No client-supplied key: the upstream body carries either the gateway's
		// own session-derived key or nothing, both safe to align with the session.
		return true
	}
	if raw.sessionID != "" && clientPromptCacheKey == raw.sessionID {
		return true
	}
	if raw.threadID != "" && clientPromptCacheKey == raw.threadID {
		return true
	}
	if cacheID != "" && clientPromptCacheKey == cacheID {
		return true
	}
	return false
}

// applyCodexFingerprintConvergenceBody rewrites the upstream request body. It is
// skipped for the compact form, which has no client_metadata by design; the header
// rewrite still runs there so the outbound device identity stays converged.
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
	// Only Responses-shaped bodies carry client_metadata. Mutating a non-Responses
	// body (for example a direct image endpoint) would invent a field the upstream
	// schema does not expect, so those requests converge headers only.
	if !hasClientMetadata && !root.Get("input").Exists() && !root.Get("instructions").Exists() {
		if state.ids.promptCacheKey == "" {
			return body, false
		}
		return setCodexConvergencePromptCacheKey(body, state.ids.promptCacheKey)
	}

	clientMetadata := map[string]any{}
	if hasClientMetadata {
		if err := json.Unmarshal([]byte(existing.Raw), &clientMetadata); err != nil {
			return body, false
		}
	}

	changed := false
	if state.ids.installationID != "" {
		clientMetadata["x-codex-installation-id"] = state.ids.installationID
		changed = true
	}
	if state.convergesSession() {
		clientMetadata["session_id"] = state.ids.sessionID
		clientMetadata["thread_id"] = state.ids.threadID
		clientMetadata["turn_id"] = state.ids.turnID
		if state.ids.rootTurnID != "" {
			clientMetadata["root_turn_id"] = state.ids.rootTurnID
		}
		clientMetadata["x-codex-window-id"] = state.ids.windowID
		if state.ids.parentThreadID != "" {
			clientMetadata["x-codex-parent-thread-id"] = state.ids.parentThreadID
		}
		if state.ids.contextWindowID != "" {
			clientMetadata["context_window_id"] = state.ids.contextWindowID
		}
		rewriteCodexConvergenceEmbeddedMetadata(clientMetadata, state)
		changed = true
	} else if state.mode == codexConvergenceDevice {
		rewriteCodexConvergenceEmbeddedMetadata(clientMetadata, state)
		changed = true
	}

	next := body
	if changed {
		encoded, errMarshal := json.Marshal(clientMetadata)
		if errMarshal != nil {
			return body, false
		}
		updated, errSet := sjson.SetRawBytes(next, "client_metadata", encoded)
		if errSet != nil {
			return body, false
		}
		next = updated
	}
	if state.ids.promptCacheKey != "" {
		if updated, updatedOK := setCodexConvergencePromptCacheKey(next, state.ids.promptCacheKey); updatedOK {
			next = updated
			changed = true
		}
	}
	return next, changed
}

func setCodexConvergencePromptCacheKey(body []byte, promptCacheKey string) ([]byte, bool) {
	updated, errSet := sjson.SetBytes(body, "prompt_cache_key", promptCacheKey)
	if errSet != nil {
		return body, false
	}
	return updated, true
}

func rewriteCodexConvergenceEmbeddedMetadata(clientMetadata map[string]any, state codexFingerprintConvergenceState) {
	key := codexTurnMetadataBodyKey
	raw, ok := clientMetadata[key].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		key = codexTurnMetadataHeader
		raw, ok = clientMetadata[key].(string)
	}
	if !ok || strings.TrimSpace(raw) == "" {
		return
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		metadata = make(map[string]any)
	}
	applyCodexConvergenceMetadataFields(metadata, state)
	if rebuilt, errMarshal := json.Marshal(metadata); errMarshal == nil {
		clientMetadata[key] = string(rebuilt)
	}
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
		rewriteCodexConvergenceHeaderMetadata(headers, state)
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
	headers.Set("X-Codex-Window-Id", state.ids.windowID)
	if state.ids.parentThreadID != "" {
		headers.Set("X-Codex-Parent-Thread-Id", state.ids.parentThreadID)
	}
}

func rewriteCodexConvergenceHeaderMetadata(headers http.Header, state codexFingerprintConvergenceState) {
	var metadata map[string]any
	if err := json.Unmarshal([]byte(state.rawTurnMetadata), &metadata); err != nil || metadata == nil {
		metadata = make(map[string]any)
	}
	applyCodexConvergenceMetadataFields(metadata, state)
	rebuilt, errMarshal := json.Marshal(metadata)
	if errMarshal != nil {
		return
	}
	headers.Set(codexTurnMetadataHeader, string(rebuilt))
}

func applyCodexConvergenceMetadataFields(metadata map[string]any, state codexFingerprintConvergenceState) {
	if metadata == nil || !state.active() {
		return
	}
	if state.ids.installationID != "" {
		metadata["installation_id"] = state.ids.installationID
	}
	if !state.convergesSession() {
		return
	}
	metadata["session_id"] = state.ids.sessionID
	metadata["thread_id"] = state.ids.threadID
	metadata["turn_id"] = state.ids.turnID
	if state.ids.rootTurnID != "" {
		metadata["root_turn_id"] = state.ids.rootTurnID
	}
	metadata["window_id"] = state.ids.windowID
	if state.ids.parentThreadID != "" {
		metadata["parent_thread_id"] = state.ids.parentThreadID
	}
	if state.ids.contextWindowID != "" {
		metadata["context_window_id"] = state.ids.contextWindowID
	}
	if state.ids.turnStartedAtMs > 0 {
		metadata["turn_started_at_unix_ms"] = state.ids.turnStartedAtMs
	}
}
