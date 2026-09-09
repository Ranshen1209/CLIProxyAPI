package executor

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func convergenceTestConfig(mode string) *config.Config {
	return &config.Config{Codex: config.CodexConfig{FingerprintConvergence: mode}}
}

func convergenceTestAuth(accountID string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		ID:       "auth-" + accountID,
		Provider: "codex",
		Metadata: map[string]any{"account_id": accountID},
	}
}

func resolveConvergenceForTest(t *testing.T, mode string, auth *cliproxyauth.Auth, headers http.Header, body []byte) codexFingerprintConvergenceState {
	t.Helper()
	state := resolveCodexFingerprintConvergence(convergenceTestConfig(mode), auth, headers, body, body, "", codexConvergenceHeadersHyphen)
	return state
}

func applyConvergenceForTest(t *testing.T, body []byte, state codexFingerprintConvergenceState) []byte {
	t.Helper()
	updated, _ := applyCodexFingerprintConvergenceBody(body, state)
	return updated
}

func TestCodexConvergenceDeriveUUIDPreservesV7Timestamp(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	derived := codexConvergenceDeriveUUID("seed-a", "thread", raw)
	parsed, err := uuid.Parse(derived)
	if err != nil {
		t.Fatalf("derived %q is not a UUID: %v", derived, err)
	}
	if parsed.Version() != 7 {
		t.Fatalf("derived version = %d, want 7", parsed.Version())
	}
	if derived[:13] != raw[:13] {
		t.Fatalf("derived timestamp prefix = %q, want %q", derived[:13], raw[:13])
	}
	if derived == raw {
		t.Fatal("derivation must not be the identity")
	}
	if again := codexConvergenceDeriveUUID("seed-a", "thread", raw); again != derived {
		t.Fatalf("derivation is not deterministic: %q vs %q", derived, again)
	}
	if other := codexConvergenceDeriveUUID("seed-b", "thread", raw); other == derived {
		t.Fatal("different seeds produced the same derived value")
	}
	if nonUUID := codexConvergenceDeriveUUID("seed-a", "installation", "not-a-uuid"); nonUUID == "" {
		t.Fatal("derivation of a non-UUID raw value returned empty")
	} else if parsedNonUUID, errParse := uuid.Parse(nonUUID); errParse != nil || parsedNonUUID.Version() != 4 {
		t.Fatalf("non-UUID raw value must derive a UUIDv4, got %q", nonUUID)
	}
}

func TestCodexConvergenceInstallationIsStablePerCredential(t *testing.T) {
	authA := convergenceTestAuth("account-a")
	stateA := resolveConvergenceForTest(t, "device", authA, nil, nil)
	stateARepeat := resolveConvergenceForTest(t, "device", authA, nil, nil)
	if !stateA.active() {
		t.Fatal("device convergence state is not active")
	}
	if stateA.ids.installationID == "" {
		t.Fatal("installation id is empty")
	}
	if stateA.ids.installationID != stateARepeat.ids.installationID {
		t.Fatalf("installation id is not stable: %q vs %q", stateA.ids.installationID, stateARepeat.ids.installationID)
	}
	if parsed, err := uuid.Parse(stateA.ids.installationID); err != nil || parsed.Version() != 4 {
		t.Fatalf("installation id must be a UUIDv4, got %q (err=%v)", stateA.ids.installationID, err)
	}
	stateB := resolveConvergenceForTest(t, "device", convergenceTestAuth("account-b"), nil, nil)
	if stateA.ids.installationID == stateB.ids.installationID {
		t.Fatal("different credentials must not share an installation id")
	}
}

func TestCodexConvergenceRootSessionKeepsSessionEqualsThread(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	headers := http.Header{"Session-Id": {raw}, "Thread-Id": {raw}}
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), headers, nil)
	if !state.convergesSession() {
		t.Fatal("session convergence is not active")
	}
	if state.ids.sessionID == "" || state.ids.sessionID != state.ids.threadID {
		t.Fatalf("root session must keep session_id == thread_id, got session=%q thread=%q", state.ids.sessionID, state.ids.threadID)
	}
	if state.ids.sessionID == raw {
		t.Fatal("root session was not converged")
	}
	if parsed, err := uuid.Parse(state.ids.sessionID); err != nil || parsed.Version() != 7 {
		t.Fatalf("converged session must stay UUIDv7, got %q (err=%v)", state.ids.sessionID, err)
	}
	if state.ids.windowID != state.ids.threadID+":0" {
		t.Fatalf("window id = %q, want %q", state.ids.windowID, state.ids.threadID+":0")
	}
}

func TestCodexConvergenceSubagentThreadStaysDistinct(t *testing.T) {
	session := uuid.Must(uuid.NewV7()).String()
	thread := uuid.Must(uuid.NewV7()).String()
	headers := http.Header{"Session-Id": {session}, "Thread-Id": {thread}}
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), headers, nil)
	if state.ids.sessionID == state.ids.threadID {
		t.Fatal("a subagent thread must stay distinct from its root session")
	}
	if state.ids.windowID != state.ids.threadID+":0" {
		t.Fatalf("window id = %q, want %q", state.ids.windowID, state.ids.threadID+":0")
	}
}

func TestCodexConvergenceFullCollapsesSubagentThread(t *testing.T) {
	session := uuid.Must(uuid.NewV7()).String()
	thread := uuid.Must(uuid.NewV7()).String()
	headers := http.Header{"Session-Id": {session}, "Thread-Id": {thread}}
	state := resolveConvergenceForTest(t, "full", convergenceTestAuth("account-a"), headers, nil)
	if state.ids.sessionID != state.ids.threadID {
		t.Fatalf("full mode must collapse thread onto session, got session=%q thread=%q", state.ids.sessionID, state.ids.threadID)
	}
}

func TestCodexConvergenceIsStableAcrossRequestsForCacheAffinity(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	body := []byte(`{"model":"gpt-5-codex","prompt_cache_key":"` + raw + `","client_metadata":{"session_id":"` + raw + `","thread_id":"` + raw + `"}}`)
	headers := http.Header{"Session-Id": {raw}, "Thread-Id": {raw}}

	first := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), headers, body)
	firstBody := applyConvergenceForTest(t, body, first)
	second := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), headers, body)
	secondBody := applyConvergenceForTest(t, body, second)

	if first.ids.sessionID != second.ids.sessionID || first.ids.threadID != second.ids.threadID {
		t.Fatalf("session/thread must be stable across requests: (%q,%q) vs (%q,%q)",
			first.ids.sessionID, first.ids.threadID, second.ids.sessionID, second.ids.threadID)
	}
	if first.ids.promptCacheKey != second.ids.promptCacheKey || first.ids.promptCacheKey == "" {
		t.Fatalf("prompt cache key must be stable, got %q vs %q", first.ids.promptCacheKey, second.ids.promptCacheKey)
	}
	firstKey := gjson.GetBytes(firstBody, "prompt_cache_key").String()
	secondKey := gjson.GetBytes(secondBody, "prompt_cache_key").String()
	if firstKey != first.ids.sessionID || secondKey != first.ids.sessionID {
		t.Fatalf("prompt_cache_key must follow the converged session, got %q and %q", firstKey, secondKey)
	}
	if first.ids.turnID == second.ids.turnID {
		t.Fatal("turn_id must be fresh per request")
	}
}

func TestCodexConvergenceRebuildsStrippedHyphenHeaders(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	// The relay stripped session-id / thread-id, leaving only the body identity.
	body := []byte(`{"model":"gpt-5-codex","client_metadata":{"session_id":"` + raw + `","thread_id":"` + raw + `"}}`)
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), http.Header{}, body)
	if !state.convergesSession() {
		t.Fatal("body-only session evidence was not picked up")
	}
	headers := http.Header{}
	applyCodexFingerprintConvergenceHeaders(headers, state)
	if headers.Get("Session-Id") != state.ids.sessionID {
		t.Fatalf("Session-Id = %q, want %q", headers.Get("Session-Id"), state.ids.sessionID)
	}
	if headers.Get("Thread-Id") != state.ids.threadID {
		t.Fatalf("Thread-Id = %q, want %q", headers.Get("Thread-Id"), state.ids.threadID)
	}
	if headers.Get("X-Client-Request-Id") != state.ids.threadID {
		t.Fatalf("X-Client-Request-Id = %q, want %q", headers.Get("X-Client-Request-Id"), state.ids.threadID)
	}
	if headers.Get("X-Codex-Window-Id") != state.ids.threadID+":0" {
		t.Fatalf("X-Codex-Window-Id = %q, want %q", headers.Get("X-Codex-Window-Id"), state.ids.threadID+":0")
	}
}

func TestCodexConvergenceDropsUnderscoreAliasesOnHTTP(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	headers := http.Header{
		"Session-Id":      {raw},
		"Thread-Id":       {raw},
		"Session_id":      {"client-underscore-session"},
		"Conversation_id": {"client-conversation"},
	}
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), headers, nil)
	out := headers.Clone()
	applyCodexFingerprintConvergenceHeaders(out, state)
	if out.Get("Session-Id") != state.ids.sessionID {
		t.Fatalf("Session-Id = %q, want %q", out.Get("Session-Id"), state.ids.sessionID)
	}
	if out.Get("session_id") != "" {
		t.Fatalf("session_id alias = %q, want removed", out.Get("session_id"))
	}
	if out.Get("Conversation_id") != "" {
		t.Fatalf("Conversation_id alias = %q, want removed", out.Get("Conversation_id"))
	}
}

func TestCodexConvergenceKeepsUnderscoreContractOnWebsocket(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	headers := http.Header{
		"Session-Id":      {raw},
		"session_id":      {raw},
		"Conversation_id": {raw},
		"Thread-Id":       {raw},
	}
	state := resolveCodexFingerprintConvergence(convergenceTestConfig("session"), convergenceTestAuth("account-a"), headers, nil, nil, "", codexConvergenceHeadersUnderscore)
	out := headers.Clone()
	applyCodexFingerprintConvergenceHeaders(out, state)
	if out.Get("Session-Id") != "" {
		t.Fatalf("hyphen Session-Id = %q, want removed on websocket", out.Get("Session-Id"))
	}
	if out["session_id"][0] != state.ids.sessionID {
		t.Fatalf("session_id = %#v, want [%q]", out["session_id"], state.ids.sessionID)
	}
	if out.Get("Conversation_id") != state.ids.sessionID {
		t.Fatalf("Conversation_id = %q, want %q", out.Get("Conversation_id"), state.ids.sessionID)
	}
}

func TestCodexConvergenceExplicitPromptCacheKeyIsPreserved(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	body := []byte(`{"model":"gpt-5-codex","prompt_cache_key":"explicit-shared-bucket","client_metadata":{"session_id":"` + raw + `"}}`)
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), http.Header{}, body)
	if state.ids.promptCacheKey != "" {
		t.Fatalf("explicit prompt_cache_key must not be converged, got %q", state.ids.promptCacheKey)
	}
	out := applyConvergenceForTest(t, body, state)
	if got := gjson.GetBytes(out, "prompt_cache_key").String(); got != "explicit-shared-bucket" {
		t.Fatalf("prompt_cache_key = %q, want preserved", got)
	}
}

func TestCodexConvergenceCompositePromptCacheKeyIsPreserved(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	composite := "spawn:" + uuid.Must(uuid.NewV7()).String()
	body := []byte(`{"model":"gpt-5-codex","prompt_cache_key":"` + composite + `","client_metadata":{"session_id":"` + raw + `"}}`)
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), http.Header{}, body)
	if state.ids.promptCacheKey != "" {
		t.Fatalf("composite subagent prompt_cache_key must not be converged, got %q", state.ids.promptCacheKey)
	}
}

func TestCodexConvergenceWithoutSessionEvidenceLeavesSessionUntouched(t *testing.T) {
	body := []byte(`{"model":"gpt-5-codex","input":[]}`)
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), http.Header{}, body)
	if !state.active() {
		t.Fatal("convergence should still be active for installation")
	}
	if state.ids.sessionID != "" || state.convergesSession() {
		t.Fatalf("session must stay untouched without evidence, got %q", state.ids.sessionID)
	}
	out := applyConvergenceForTest(t, body, state)
	if gjson.GetBytes(out, "client_metadata.session_id").Exists() {
		t.Fatalf("body gained a session_id without evidence: %s", out)
	}
	if gjson.GetBytes(out, "prompt_cache_key").Exists() {
		t.Fatalf("body gained a prompt_cache_key without evidence: %s", out)
	}
	if got := gjson.GetBytes(out, "client_metadata.x-codex-installation-id").String(); got != state.ids.installationID {
		t.Fatalf("installation id = %q, want %q", got, state.ids.installationID)
	}
}

func TestCodexConvergenceDeviceModeLeavesSessionUntouched(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	body := []byte(`{"model":"gpt-5-codex","prompt_cache_key":"` + raw + `","client_metadata":{"session_id":"` + raw + `","thread_id":"` + raw + `"}}`)
	state := resolveConvergenceForTest(t, "device", convergenceTestAuth("account-a"), http.Header{}, body)
	if state.convergesSession() {
		t.Fatal("device mode must not converge the session")
	}
	out := applyConvergenceForTest(t, body, state)
	if got := gjson.GetBytes(out, "client_metadata.session_id").String(); got != raw {
		t.Fatalf("session_id = %q, want untouched %q", got, raw)
	}
	if got := gjson.GetBytes(out, "prompt_cache_key").String(); got != raw {
		t.Fatalf("prompt_cache_key = %q, want untouched %q", got, raw)
	}
	if got := gjson.GetBytes(out, "client_metadata.x-codex-installation-id").String(); got != state.ids.installationID {
		t.Fatalf("installation id = %q, want %q", got, state.ids.installationID)
	}
}

func TestCodexConvergenceRootTurnFollowsTurn(t *testing.T) {
	rawSession := uuid.Must(uuid.NewV7()).String()
	rawTurn := uuid.Must(uuid.NewV7()).String()
	body := []byte(`{"model":"gpt-5-codex","client_metadata":{"session_id":"` + rawSession + `","thread_id":"` + rawSession + `","turn_id":"` + rawTurn + `","root_turn_id":"` + rawTurn + `"}}`)
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), http.Header{}, body)
	out := applyConvergenceForTest(t, body, state)
	metadata := gjson.GetBytes(out, "client_metadata")
	turnID := metadata.Get("turn_id").String()
	rootTurnID := metadata.Get("root_turn_id").String()
	if turnID == "" || turnID != rootTurnID {
		t.Fatalf("root turn must follow turn_id, got turn=%q root=%q", turnID, rootTurnID)
	}
	if turnID == rawTurn {
		t.Fatal("turn_id was not converged")
	}
	if parsed, err := uuid.Parse(turnID); err != nil || parsed.Version() != 7 {
		t.Fatalf("converged turn_id must be UUIDv7, got %q (err=%v)", turnID, err)
	}
}

func TestCodexConvergencePreservesWindowNumberAndEmbeddedMetadata(t *testing.T) {
	rawThread := uuid.Must(uuid.NewV7()).String()
	embedded := `{\"session_id\":\"` + rawThread + `\",\"thread_id\":\"` + rawThread + `\",\"window_id\":\"` + rawThread + `:3\",\"sandbox\":\"seatbelt\"}`
	body := []byte(`{"model":"gpt-5-codex","client_metadata":{"session_id":"` + rawThread + `","thread_id":"` + rawThread + `","x-codex-window-id":"` + rawThread + `:3","x-codex-turn-metadata":"` + embedded + `"}}`)
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), http.Header{}, body)
	if state.ids.windowID != state.ids.threadID+":3" {
		t.Fatalf("window id = %q, want %q", state.ids.windowID, state.ids.threadID+":3")
	}
	out := applyConvergenceForTest(t, body, state)
	gotEmbedded := gjson.GetBytes(out, "client_metadata.x-codex-turn-metadata").String()
	if got := gjson.Get(gotEmbedded, "session_id").String(); got != state.ids.sessionID {
		t.Fatalf("embedded session_id = %q, want %q", got, state.ids.sessionID)
	}
	if got := gjson.Get(gotEmbedded, "sandbox").String(); got != "seatbelt" {
		t.Fatalf("embedded sandbox = %q, want preserved", got)
	}
	if got := gjson.Get(gotEmbedded, "window_id").String(); got != state.ids.threadID+":3" {
		t.Fatalf("embedded window_id = %q, want %q", got, state.ids.threadID+":3")
	}
}

func TestCodexConvergenceRewritesTurnMetadataHeader(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	headers := http.Header{}
	headers.Set("Session-Id", raw)
	headers.Set("Thread-Id", raw)
	headers.Set("X-Codex-Turn-Metadata", `{"session_id":"`+raw+`","sandbox":"seatbelt"}`)
	headers.Set("X-Codex-Parent-Thread-Id", uuid.Must(uuid.NewV7()).String())
	state := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), headers, nil)
	out := http.Header{}
	applyCodexFingerprintConvergenceHeaders(out, state)
	got := out.Get("X-Codex-Turn-Metadata")
	if gjson.Get(got, "session_id").String() != state.ids.sessionID {
		t.Fatalf("header turn-metadata session_id = %q, want %q", gjson.Get(got, "session_id").String(), state.ids.sessionID)
	}
	if gjson.Get(got, "sandbox").String() != "seatbelt" {
		t.Fatalf("header turn-metadata sandbox = %q, want preserved", gjson.Get(got, "sandbox").String())
	}
	if out.Get("X-Codex-Parent-Thread-Id") != state.ids.parentThreadID || state.ids.parentThreadID == "" {
		t.Fatalf("parent thread id = %q, want %q", out.Get("X-Codex-Parent-Thread-Id"), state.ids.parentThreadID)
	}
}

func TestCodexConvergenceSupersedesIdentityConfuse(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	body := []byte(`{"model":"gpt-5-codex","prompt_cache_key":"` + raw + `","client_metadata":{"session_id":"` + raw + `","thread_id":"` + raw + `","x-codex-installation-id":"client-install"}}`)
	cfg := &config.Config{
		Routing: config.RoutingConfig{Strategy: "fill-first"},
		Codex:   config.CodexConfig{IdentityConfuse: true, FingerprintConvergence: "session"},
	}
	auth := convergenceTestAuth("account-a")
	confused, state := applyCodexIdentityConfuseBody(cfg, auth, body, body)
	if state.enabled {
		t.Fatal("identity-confuse must be superseded while convergence is enabled")
	}
	if string(confused) != string(body) {
		t.Fatalf("identity-confuse modified the body while superseded: %s", confused)
	}
}

func TestCodexConvergenceAuthOverrideWins(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	headers := http.Header{"Session-Id": {raw}, "Thread-Id": {raw}}

	override := convergenceTestAuth("account-a")
	override.Metadata[codexConvergenceModeAttr] = "full"
	state := resolveConvergenceForTest(t, "device", override, headers, nil)
	if state.mode != codexConvergenceFull {
		t.Fatalf("mode = %q, want %q", state.mode, codexConvergenceFull)
	}

	booleanOverride := convergenceTestAuth("account-b")
	booleanOverride.Metadata[codexConvergenceModeAttr] = true
	state = resolveConvergenceForTest(t, "off", booleanOverride, headers, nil)
	if state.mode != codexConvergenceSession {
		t.Fatalf("boolean override mode = %q, want %q", state.mode, codexConvergenceSession)
	}

	// The same client session must converge differently per credential so two
	// accounts never share an upstream session identity.
	otherCredential := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-c"), headers, nil)
	sameCredential := resolveConvergenceForTest(t, "session", convergenceTestAuth("account-a"), headers, nil)
	if otherCredential.ids.sessionID == sameCredential.ids.sessionID {
		t.Fatal("different credentials must derive different session identities")
	}
}

func TestCodexCacheHelperAppliesConvergenceToBodyAndHeaders(t *testing.T) {
	raw := uuid.Must(uuid.NewV7()).String()
	executor := &CodexExecutor{cfg: convergenceTestConfig("session")}
	auth := convergenceTestAuth("account-a")
	payload := []byte(`{"model":"gpt-5-codex","prompt_cache_key":"` + raw + `","client_metadata":{"session_id":"` + raw + `","thread_id":"` + raw + `","x-codex-installation-id":"client-install"}}`)
	clientHeaders := http.Header{"Session-Id": {raw}, "Thread-Id": {raw}}
	req := cliproxyexecutor.Request{Model: "gpt-5-codex", Payload: payload}

	httpReq, body, state, err := executor.cacheHelper(context.Background(), sdktranslator.FromString("openai-response"),
		"https://example.com/responses", auth, req, payload, payload, clientHeaders)
	if err != nil {
		t.Fatalf("cacheHelper error: %v", err)
	}
	if !state.convergence.active() {
		t.Fatal("cacheHelper did not resolve convergence")
	}
	applyCodexHeaders(httpReq, auth, "oauth-token", true, executor.cfg, clientHeaders)
	applyCodexIdentityConfuseHeaders(httpReq.Header, &state)

	wantSession := state.convergence.ids.sessionID
	if got := gjson.GetBytes(body, "client_metadata.session_id").String(); got != wantSession {
		t.Fatalf("body session_id = %q, want %q", got, wantSession)
	}
	if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != wantSession {
		t.Fatalf("body prompt_cache_key = %q, want %q", got, wantSession)
	}
	if got := httpReq.Header.Get("Session-Id"); got != wantSession {
		t.Fatalf("Session-Id = %q, want %q", got, wantSession)
	}
	if got := httpReq.Header.Get("Thread-Id"); got != state.convergence.ids.threadID {
		t.Fatalf("Thread-Id = %q, want %q", got, state.convergence.ids.threadID)
	}
	if got := httpReq.Header.Get("X-Codex-Installation-Id"); got != state.convergence.ids.installationID {
		t.Fatalf("X-Codex-Installation-Id = %q, want %q", got, state.convergence.ids.installationID)
	}
}
