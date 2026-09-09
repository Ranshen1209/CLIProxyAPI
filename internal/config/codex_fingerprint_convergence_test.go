package config

import "testing"

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

	// An unrecognized value is preserved so sanitizing never destroys operator
	// input; the request path falls back to off and warns once.
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
