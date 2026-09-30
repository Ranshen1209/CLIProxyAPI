package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeCodexFingerprintConvergence(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		want   string
		wantOK bool
	}{
		{name: "empty", raw: "", want: CodexFingerprintConvergenceOff, wantOK: true},
		{name: "blank", raw: "   ", want: CodexFingerprintConvergenceOff, wantOK: true},
		{name: "off", raw: "off", want: CodexFingerprintConvergenceOff, wantOK: true},
		{name: "none alias", raw: "none", want: CodexFingerprintConvergenceOff, wantOK: true},
		{name: "disabled alias", raw: "disabled", want: CodexFingerprintConvergenceOff, wantOK: true},
		{name: "device", raw: "device", want: CodexFingerprintConvergenceDevice, wantOK: true},
		{name: "device mixed case", raw: "  Device ", want: CodexFingerprintConvergenceDevice, wantOK: true},
		{name: "session", raw: "session", want: CodexFingerprintConvergenceSession, wantOK: true},
		{name: "full", raw: "full", want: CodexFingerprintConvergenceFull, wantOK: true},
		{name: "typo", raw: "sessions", want: CodexFingerprintConvergenceOff, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := NormalizeCodexFingerprintConvergence(tc.raw)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("NormalizeCodexFingerprintConvergence(%q) = (%q, %t), want (%q, %t)", tc.raw, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestSanitizeCodexFingerprintConvergence(t *testing.T) {
	cfg := &Config{Codex: CodexConfig{FingerprintConvergence: " Session "}}
	cfg.SanitizeCodexFingerprintConvergence()
	if got := cfg.Codex.FingerprintConvergence; got != CodexFingerprintConvergenceSession {
		t.Fatalf("recognized value = %q, want %q", got, CodexFingerprintConvergenceSession)
	}

	// An unrecognized value is trimmed and kept so ValidateCodexFingerprintConvergence
	// can fail load/parse with the operator's original token.
	cfg = &Config{Codex: CodexConfig{FingerprintConvergence: " bogus "}}
	cfg.SanitizeCodexFingerprintConvergence()
	if got := cfg.Codex.FingerprintConvergence; got != "bogus" {
		t.Fatalf("unrecognized value = %q, want %q", got, "bogus")
	}
}

func TestValidateCodexFingerprintConvergence(t *testing.T) {
	for _, value := range []string{"", "off", "device", "session", "full", " FULL "} {
		if err := ValidateCodexFingerprintConvergence(value); err != nil {
			t.Fatalf("ValidateCodexFingerprintConvergence(%q) = %v, want nil", value, err)
		}
	}
	if err := ValidateCodexFingerprintConvergence("bogus"); err == nil {
		t.Fatal("ValidateCodexFingerprintConvergence(bogus) = nil, want error")
	}
}

func TestLoadConfigOptionalRejectsBogusFingerprintConvergence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("codex:\n  fingerprint-convergence: bogus\n"), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	_, err := LoadConfigOptional(configPath, false)
	if err == nil {
		t.Fatal("LoadConfigOptional() error = nil, want unrecognized fingerprint-convergence")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("LoadConfigOptional() error = %v, want it to mention bogus", err)
	}
}

func TestParseConfigBytesRejectsBogusFingerprintConvergence(t *testing.T) {
	_, err := ParseConfigBytes([]byte("codex:\n  fingerprint-convergence: bogus\n"))
	if err == nil {
		t.Fatal("ParseConfigBytes() error = nil, want unrecognized fingerprint-convergence")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("ParseConfigBytes() error = %v, want it to mention bogus", err)
	}
}

func TestParseConfigBytesAcceptsFingerprintConvergenceSession(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("codex:\n  fingerprint-convergence: Session\n"))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if got := cfg.Codex.FingerprintConvergence; got != CodexFingerprintConvergenceSession {
		t.Fatalf("FingerprintConvergence = %q, want %q", got, CodexFingerprintConvergenceSession)
	}
}

func TestFingerprintConvergenceV8MigrationRoundTrip(t *testing.T) {
	for _, input := range []string{
		"codex:\n  fingerprint-convergence: session\n  identity-confuse: true\n",
		"oauth:\n  providers:\n    codex:\n      fingerprint-convergence: session\n      identity-confuse: true\n",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Codex.FingerprintConvergence != CodexFingerprintConvergenceSession || !cfg.Codex.IdentityConfuse {
			t.Fatal("load lost fork identity settings")
		}
		if err = SaveConfigPreserveComments(path, cfg, true); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = ValidateV8Config(data); err != nil {
			t.Fatal(err)
		}
		reloaded, err := LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if reloaded.Codex.FingerprintConvergence != cfg.Codex.FingerprintConvergence || reloaded.Codex.IdentityConfuse != cfg.Codex.IdentityConfuse {
			t.Fatal("v8 save/reload lost fork identity settings")
		}
	}
}
