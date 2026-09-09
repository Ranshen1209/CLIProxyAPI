package config

import (
	"fmt"
	"strings"
)

// Codex fingerprint convergence modes for CodexConfig.FingerprintConvergence and
// for the matching auth-file / auth-attribute field. This is the single source of
// truth: the runtime, the config sanitizer and the Management API all resolve a
// raw value through NormalizeCodexFingerprintConvergence so an operator cannot end
// up with a value that one layer accepts and another silently ignores.
const (
	// CodexFingerprintConvergenceOff leaves every client identifier untouched.
	// This is the default: convergence is an explicit opt-in.
	CodexFingerprintConvergenceOff = "off"
	// CodexFingerprintConvergenceDevice converges only x-codex-installation-id to a
	// per-credential constant. Upstream sees one device sharing many sessions.
	CodexFingerprintConvergenceDevice = "device"
	// CodexFingerprintConvergenceSession additionally converges session/thread/turn/
	// window/context-window identifiers, deriving them deterministically per
	// credential and client session so session relationships (root session
	// session_id == thread_id, subagent thread_id != session_id) are preserved.
	CodexFingerprintConvergenceSession = "session"
	// CodexFingerprintConvergenceFull is session mode plus collapsing every
	// subagent thread onto the converged root session.
	CodexFingerprintConvergenceFull = "full"
)

// NormalizeCodexFingerprintConvergence maps a raw configured value to its canonical
// form. The second result reports whether the value is recognized; an unrecognized
// value normalizes to off.
func NormalizeCodexFingerprintConvergence(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", CodexFingerprintConvergenceOff, "none", "disabled", "false":
		return CodexFingerprintConvergenceOff, true
	case CodexFingerprintConvergenceDevice:
		return CodexFingerprintConvergenceDevice, true
	case CodexFingerprintConvergenceSession:
		return CodexFingerprintConvergenceSession, true
	case CodexFingerprintConvergenceFull:
		return CodexFingerprintConvergenceFull, true
	default:
		return CodexFingerprintConvergenceOff, false
	}
}

// CodexFingerprintConvergenceValues lists the accepted values for error messages.
func CodexFingerprintConvergenceValues() []string {
	return []string{
		CodexFingerprintConvergenceOff,
		CodexFingerprintConvergenceDevice,
		CodexFingerprintConvergenceSession,
		CodexFingerprintConvergenceFull,
	}
}

// FormatCodexFingerprintConvergenceValues renders the accepted values for logs.
func FormatCodexFingerprintConvergenceValues() string {
	return strings.Join(CodexFingerprintConvergenceValues(), ", ")
}

// ValidateCodexFingerprintConvergence reports an error for values that would be
// silently ignored at request time.
func ValidateCodexFingerprintConvergence(raw string) error {
	if _, ok := NormalizeCodexFingerprintConvergence(raw); !ok {
		return fmt.Errorf("unsupported codex fingerprint-convergence %q (supported: %s)", strings.TrimSpace(raw), FormatCodexFingerprintConvergenceValues())
	}
	return nil
}
