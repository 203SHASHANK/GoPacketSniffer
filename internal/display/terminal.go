package display

import (
	"fmt"
	"strings"
	"time"

	"gopacketsniffer/internal/models"
	"gopacketsniffer/internal/stats"
)

const dashWidth = 80

// ClearScreen moves the cursor to the top-left and clears the terminal.
func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// PrintStats renders the full statistics dashboard to stdout.
func PrintStats(iface string, snap stats.Snapshot) {
	ClearScreen()

	line := strings.Repeat("─", dashWidth)
	fmt.Println(Colorize(ColorCyan+ColorBold, "┌"+line+"┐"))
	fmt.Printf("│  %-38s %s  │\n",
		Colorize(ColorBold, "GoPacketSniffer v1.0.0"),
		Colorize(ColorGray, "Live Network Traffic Analysis"))
	fmt.Println(Colorize(ColorCyan, "├"+line+"┤"))

	// Header row
	elapsed := formatDuration(snap.Elapsed)
	dropPct := 0.0
	if snap.TotalPackets > 0 {
		dropPct = float64(snap.DroppedPackets) / float64(snap.TotalPackets) * 100
	}
	fmt.Printf("│  Interface: %-10s  Uptime: %-10s                          │\n", iface, elapsed)
	fmt.Printf("│  Captured: %s packets │ %s   Dropped: %d (%.1f%%)%s│\n",
		Colorize(ColorGreen, fmt.Sprintf("%8d", snap.TotalPackets)),
		formatBytes(snap.TotalBytes),
		snap.DroppedPackets, dropPct,
		strings.Repeat(" ", 10))

	fmt.Println(Colorize(ColorCyan, "├"+line+"┤"))

	// Protocol distribution
	fmt.Println(Colorize(ColorBold, "│  PROTOCOL DISTRIBUTION"+strings.Repeat(" ", dashWidth-22)+"│"))
	for _, proto := range []string{"TCP", "UDP", "ICMP", "Other"} {
		ps, ok := snap.Protocols[proto]
		if !ok {
			continue
		}
		pct := 0.0
		if snap.TotalPackets > 0 {
			pct = float64(ps.Packets) / float64(snap.TotalPackets) * 100
		}
		bar := progressBar(pct, 20)
		color := protoColor(proto)
		fmt.Printf("│  %s  %8d pkts (%5.1f%%) │ %s  %s  │\n",
			Colorize(color, fmt.Sprintf("%-5s", proto)),
			ps.Packets, pct,
			formatBytes(ps.Bytes),
			bar)
	}

	fmt.Println(Colorize(ColorCyan, "├"+line+"┤"))

	// Bandwidth
	fmt.Println(Colorize(ColorBold, "│  BANDWIDTH"+strings.Repeat(" ", dashWidth-10)+"│"))
	fmt.Printf("│  Current: %-12s   Peak: %-12s @ %s%s│\n",
		Colorize(bwColor(snap.CurrentBPS), formatBPS(snap.CurrentBPS)),
		Colorize(ColorYellow, formatBPS(snap.PeakBPS)),
		snap.PeakBPSAt.Format("15:04:05"),
		strings.Repeat(" ", 8))

	fmt.Println(Colorize(ColorCyan, "├"+line+"┤"))

	// Top talkers
	fmt.Println(Colorize(ColorBold, "│  TOP TALKERS (by bytes sent)"+strings.Repeat(" ", dashWidth-28)+"│"))
	for i, t := range snap.TopTalkers {
		pct := 0.0
		if snap.TotalBytes > 0 {
			pct = float64(t.Bytes) / float64(snap.TotalBytes) * 100
		}
		rank := Colorize(ColorYellow, fmt.Sprintf("%2d.", i+1))
		fmt.Printf("│  %s %-20s  %s  (%5.1f%%)%s│\n",
			rank, t.IP, formatBytes(t.Bytes), pct,
			strings.Repeat(" ", 12))
	}

	fmt.Println(Colorize(ColorCyan, "├"+line+"┤"))

	// HTTP traffic
	fmt.Println(Colorize(ColorBold, "│  HTTP TRAFFIC"+strings.Repeat(" ", dashWidth-13)+"│"))
	if snap.HTTPRequests > 0 {
		fmt.Printf("│  Requests: %d  │  2xx: %s  4xx: %s  5xx: %s%s│\n",
			snap.HTTPRequests,
			Colorize(ColorGreen, fmt.Sprintf("%d", snap.HTTP2xx)),
			Colorize(ColorYellow, fmt.Sprintf("%d", snap.HTTP4xx)),
			Colorize(ColorRed, fmt.Sprintf("%d", snap.HTTP5xx)),
			strings.Repeat(" ", 20))
	} else {
		fmt.Printf("│  %s%s│\n", Colorize(ColorGray, "No HTTP traffic detected"), strings.Repeat(" ", dashWidth-25))
	}

	fmt.Println(Colorize(ColorCyan, "├"+line+"┤"))
	fmt.Printf("│  Active TCP Flows: %s%s│\n",
		Colorize(ColorCyan, fmt.Sprintf("%d", snap.ActiveFlows)),
		strings.Repeat(" ", dashWidth-21))

	fmt.Println(Colorize(ColorCyan, "└"+line+"┘"))
	fmt.Println(Colorize(ColorGray, "  [Ctrl+C to stop]"))
}

// PrintPacket prints a single decoded packet in verbose mode.
func PrintPacket(info *models.PacketInfo) {
	ts := info.Timestamp.Format("15:04:05.000000")
	switch info.Protocol {
	case "TCP":
		fmt.Printf("%s %s %s:%d → %s:%d %s\n",
			Colorize(ColorGray, ts),
			Colorize(protoColor("TCP"), "TCP "),
			info.SrcIP, info.SrcPort,
			info.DstIP, info.DstPort,
			Colorize(ColorYellow, info.TCPFlags))
	case "UDP":
		fmt.Printf("%s %s %s:%d → %s:%d\n",
			Colorize(ColorGray, ts),
			Colorize(protoColor("UDP"), "UDP "),
			info.SrcIP, info.SrcPort,
			info.DstIP, info.DstPort)
	case "ICMP":
		fmt.Printf("%s %s %s → %s (%s)\n",
			Colorize(ColorGray, ts),
			Colorize(protoColor("ICMP"), "ICMP"),
			info.SrcIP, info.DstIP,
			Colorize(ColorYellow, info.TCPFlags))
	}
}

// --- helpers ---

func progressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return Colorize(ColorGreen, bar)
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%6.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%6.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%6.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%6d  B", b)
	}
}

func formatBPS(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.1f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.1f Kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func protoColor(proto string) string {
	switch proto {
	case "TCP":
		return ColorBlue
	case "UDP":
		return ColorGreen
	case "ICMP":
		return ColorYellow
	default:
		return ColorGray
	}
}

func bwColor(bps float64) string {
	switch {
	case bps >= 100e6:
		return ColorRed
	case bps >= 10e6:
		return ColorYellow
	default:
		return ColorGreen
	}
}
