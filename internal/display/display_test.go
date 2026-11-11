package display

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"gopacketsniffer/internal/models"
	"gopacketsniffer/internal/stats"
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
	got := FormatDuration(d)
	if got != "02:05:09" {
		t.Errorf("FormatDuration = %q, want 02:05:09", got)
	}
}

func TestProgressBar(t *testing.T) {
	bar := progressBar(50, 10)
	// 50% of 10 columns: 5 filled then 5 empty blocks, inside color codes.
	if !strings.Contains(bar, "█████░░░░░") {
		t.Errorf("expected 5 filled and 5 empty blocks in bar: %q", bar)
	}
	// Out-of-range input must not panic or overflow the bar.
	for _, pct := range []float64{-5, 250} {
		if got := visibleWidth(progressBar(pct, 10)); got != 10 {
			t.Errorf("progressBar(%v) is %d columns wide, want 10", pct, got)
		}
	}
}

func TestColorize(t *testing.T) {
	got := Colorize(ColorRed, "hello")
	if !strings.HasPrefix(got, ColorRed) || !strings.HasSuffix(got, ColorReset) {
		t.Errorf("Colorize output missing ANSI codes: %q", got)
	}
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func TestVisibleWidth(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{Colorize(ColorRed, "abc"), 3},
		{Colorize(ColorCyan+ColorBold, "┌──┐"), 4},
		{"a" + Colorize(ColorGreen, "█░") + "b", 4},
	}
	for _, tt := range tests {
		if got := visibleWidth(tt.in); got != tt.want {
			t.Errorf("visibleWidth(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func sampleSnapshot() stats.Snapshot {
	return stats.Snapshot{
		TotalPackets:   45234,
		TotalBytes:     24641536,
		DroppedPackets: 12,
		Elapsed:        135 * time.Second,
		CurrentBPS:     2.3e6,
		PeakBPS:        5.1e6,
		PeakBPSAt:      time.Date(2025, 1, 1, 14, 23, 15, 0, time.UTC),
		Protocols: map[string]stats.ProtoStats{
			"TCP":   {Packets: 32156, Bytes: 19084083},
			"UDP":   {Packets: 8945, Bytes: 3984588},
			"ICMP":  {Packets: 3133, Bytes: 1048576},
			"Other": {Packets: 1000, Bytes: 524288},
		},
		TopTalkers: []stats.Talker{
			{IP: "192.168.1.100", Bytes: 13107200},
			{IP: "172.217.164.46", Bytes: 8703180},
		},
		HTTPRequests: 234,
		HTTP2xx:      180,
		HTTP4xx:      45,
		HTTP5xx:      9,
		ActiveFlows:  42,
	}
}

// Every boxed line must be exactly innerWidth+2 columns wide, otherwise the
// right border is ragged. Checked for both a busy and an empty snapshot.
func TestRenderStatsAlignment(t *testing.T) {
	snaps := map[string]stats.Snapshot{
		"busy":  sampleSnapshot(),
		"empty": {Protocols: map[string]stats.ProtoStats{}},
	}
	for name, snap := range snaps {
		t.Run(name, func(t *testing.T) {
			var sb strings.Builder
			RenderStats(&sb, "eth0", "v1.2.3", snap)

			lines := strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")
			box := lines[:len(lines)-1] // last line is the Ctrl+C hint
			for i, line := range box {
				plain := ansiRE.ReplaceAllString(line, "")
				if got := utf8.RuneCountInString(plain); got != innerWidth+2 {
					t.Errorf("line %d is %d columns wide, want %d: %q", i, got, innerWidth+2, plain)
				}
			}
		})
	}
}

func TestRenderStatsContent(t *testing.T) {
	var sb strings.Builder
	RenderStats(&sb, "eth0", "v1.2.3", sampleSnapshot())
	out := ansiRE.ReplaceAllString(sb.String(), "")

	for _, want := range []string{
		"GoPacketSniffer v1.2.3",
		"Interface: eth0",
		"Uptime: 00:02:15",
		"45234 packets",
		"2.3 Mbps",
		"5.1 Mbps @ 14:23:15",
		"192.168.1.100",
		"Requests: 234",
		"Active TCP flows: 42",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dashboard is missing %q", want)
		}
	}
}

func TestFormatPacket(t *testing.T) {
	ts := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		info models.PacketInfo
		want string
	}{
		{
			name: "tcp",
			info: models.PacketInfo{Timestamp: ts, Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: 50000, DstPort: 80, TCPFlags: "[SYN]"},
			want: "10:00:00.000000 TCP   10.0.0.1:50000 -> 10.0.0.2:80 [SYN]",
		},
		{
			name: "http request",
			info: models.PacketInfo{Timestamp: ts, Protocol: "TCP", SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: 50000, DstPort: 80, TCPFlags: "[ACK,PSH]",
				HTTP: &models.HTTPInfo{IsRequest: true, Method: "GET", Host: "example.com", URL: "/index.html"}},
			want: "10:00:00.000000 TCP   10.0.0.1:50000 -> 10.0.0.2:80 [ACK,PSH] HTTP GET example.com/index.html",
		},
		{
			name: "udp",
			info: models.PacketInfo{Timestamp: ts, Protocol: "UDP", SrcIP: "10.0.0.1", DstIP: "8.8.8.8",
				SrcPort: 12345, DstPort: 53},
			want: "10:00:00.000000 UDP   10.0.0.1:12345 -> 8.8.8.8:53",
		},
		{
			name: "icmp",
			info: models.PacketInfo{Timestamp: ts, Protocol: "ICMP", SrcIP: "10.0.0.1", DstIP: "8.8.8.8",
				ICMPType: "EchoRequest"},
			want: "10:00:00.000000 ICMP  10.0.0.1 -> 8.8.8.8 (EchoRequest)",
		},
		{
			name: "non-ip",
			info: models.PacketInfo{Timestamp: ts, Protocol: "Other", SrcMAC: "00:11:22:33:44:55",
				DstMAC: "ff:ff:ff:ff:ff:ff", TotalBytes: 42},
			want: "10:00:00.000000 Other 00:11:22:33:44:55 -> ff:ff:ff:ff:ff:ff (42 bytes)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ansiRE.ReplaceAllString(formatPacket(&tt.info), "")
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}
