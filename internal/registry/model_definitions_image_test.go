package registry

import "testing"

func TestIsCodexImageGenerationModel(t *testing.T) {
	tests := []struct {
		model string
		want  bool
	}{
		{model: "gpt-image-1.5", want: true},
		{model: "gpt-image-2", want: true},
		{model: "codex/gpt-image-2", want: true},
		{model: "gpt-image-2.5-flare", want: true},
		{model: "codex/gpt-image-2.5-sunburst", want: true},
		{model: "gpt-image-2.5-flare-2026-09-08", want: true},
		{model: "gpt-image-2.5-sunburst-2026-09-08", want: true},
		{model: "gpt-image-2.5", want: false},
		{model: "gpt-5.4", want: false},
		{model: "grok-imagine-image", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			if got := IsCodexImageGenerationModel(tt.model); got != tt.want {
				t.Fatalf("IsCodexImageGenerationModel(%q) = %v, want %v", tt.model, got, tt.want)
			}
		})
	}
}

func TestWithCodexBuiltinsIncludesImage25(t *testing.T) {
	models := WithCodexBuiltins(nil)
	got := make(map[string]bool, len(models))
	for _, model := range models {
		if model != nil {
			got[model.ID] = true
		}
	}
	for _, id := range []string{
		"gpt-image-1.5",
		"gpt-image-2",
		"gpt-image-2.5-flare",
		"gpt-image-2.5-sunburst",
	} {
		if !got[id] {
			t.Errorf("missing builtin %q", id)
		}
	}
}
