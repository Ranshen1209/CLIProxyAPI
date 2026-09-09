package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestGetCodexFingerprintConvergence(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	h := NewHandlerWithoutConfigFilePath(&config.Config{
		Codex: config.CodexConfig{FingerprintConvergence: " Session "},
	}, nil)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/codex-fingerprint-convergence", nil)
	h.GetCodexFingerprintConvergence(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Value string `json:"codex-fingerprint-convergence"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Value != config.CodexFingerprintConvergenceSession {
		t.Fatalf("codex-fingerprint-convergence = %q, want %q", body.Value, config.CodexFingerprintConvergenceSession)
	}
}

func TestPutCodexFingerprintConvergenceRejectsBogus(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, nil)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/codex-fingerprint-convergence", strings.NewReader(`{"value":"bogus"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	h.PutCodexFingerprintConvergence(ctx)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", rec.Code, rec.Body.String())
	}
	if h.cfg.Codex.FingerprintConvergence != "" {
		t.Fatalf("in-memory value changed to %q after rejected PUT", h.cfg.Codex.FingerprintConvergence)
	}
}

func TestPutCodexFingerprintConvergencePersists(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("codex:\n  fingerprint-convergence: off\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	h := NewHandler(&config.Config{Codex: config.CodexConfig{FingerprintConvergence: config.CodexFingerprintConvergenceOff}}, configPath, nil)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/v0/management/codex-fingerprint-convergence", strings.NewReader(`{"value":"session"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	h.PutCodexFingerprintConvergence(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := h.cfg.Codex.FingerprintConvergence; got != config.CodexFingerprintConvergenceSession {
		t.Fatalf("in-memory FingerprintConvergence = %q, want %q", got, config.CodexFingerprintConvergenceSession)
	}
}
