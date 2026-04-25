package display

import (
	"strings"
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{500, "   500  B"},
		{2048, "   2.0 KB"},
		{3 * 1024 * 1024, "   3.0 MB"},
		{2 * 1024 * 1024 * 1024, "   2.0 GB"},
	}
	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatBPS(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{500, "500 bps"},
		{1500, "1.5 Kbps"},
		{2.5e6, "2.5 Mbps"},
		{1.2e9, "1.2 Gbps"},
	}
	for _, tt := range tests {
		got := formatBPS(tt.input)
		if got != tt.want {
			t.Errorf("formatBPS(%g) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	d := 2*time.Hour + 5*time.Minute + 9*time.Second
	got := formatDuration(d)
	if got != "02:05:09" {
		t.Errorf("formatDuration = %q, want 02:05:09", got)
	}
}

func TestProgressBar(t *testing.T) {
	bar := progressBar(50, 10)
	// Should contain 5 filled and 5 empty blocks (inside ANSI codes)
	if !strings.Contains(bar, "█████") {
		t.Errorf("expected 5 filled blocks in bar: %q", bar)
	}
}

func TestColorize(t *testing.T) {
	got := Colorize(ColorRed, "hello")
	if !strings.HasPrefix(got, ColorRed) || !strings.HasSuffix(got, ColorReset) {
		t.Errorf("Colorize output missing ANSI codes: %q", got)
	}
}
