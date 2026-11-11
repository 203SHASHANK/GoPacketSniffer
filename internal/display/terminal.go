package display

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"gopacketsniffer/internal/models"
	"gopacketsniffer/internal/stats"
)

const (
	innerWidth = 80 // columns between the left and right border
	barWidth   = 20 // columns used by a protocol share bar

	// clearScreen moves the cursor to the top-left corner and erases the
	// display, so each refresh overwrites the previous dashboard.
	clearScreen = "\033[H\033[2J"
)

// protocolOrder fixes the order of the protocol rows so they do not jump
// around between refreshes.
var protocolOrder = []string{"TCP", "UDP", "ICMP", "Other"}

// ClearScreen erases the terminal and homes the cursor.
func ClearScreen() {
	fmt.Print(clearScreen)
}

// PrintStats clears the terminal and draws the dashboard on stdout.
//
// The whole screen is built in memory and written with a single call, which
// avoids the flicker of a half-drawn frame.
func PrintStats(iface, version string, snap stats.Snapshot) {
	_, _ = os.Stdout.WriteString(clearScreen + renderStats(iface, version, snap))
}

// RenderStats writes the statistics dashboard for snap to w.
func RenderStats(w io.Writer, iface, version string, snap stats.Snapshot) error {
	_, err := io.WriteString(w, renderStats(iface, version, snap))
	return err
}

// renderStats returns the dashboard for snap as a single string.
func renderStats(iface, version string, snap stats.Snapshot) string {
	var d dashboard

	d.border("┌", "┐")
	d.split(
		Colorize(ColorBold, "GoPacketSniffer "+version),
		Colorize(ColorGray, "Live Network Traffic Analysis"))
	d.border("├", "┤")

	// Dropped frames never made it into TotalPackets, so the loss rate is
	// measured against everything that came off the socket.
	dropPct := 0.0
	if seen := snap.TotalPackets + snap.DroppedPackets; seen > 0 {
		dropPct = float64(snap.DroppedPackets) / float64(seen) * 100
	}
	dropColor := ColorGreen
	if snap.DroppedPackets > 0 {
		dropColor = ColorRed
	}
	d.row(fmt.Sprintf("Interface: %-16s Uptime: %s", iface, FormatDuration(snap.Elapsed)))
	d.row(fmt.Sprintf("Captured: %s packets | %s    Dropped: %s",
		Colorize(ColorGreen, fmt.Sprintf("%d", snap.TotalPackets)),
		strings.TrimSpace(formatBytes(snap.TotalBytes)),
		Colorize(dropColor, fmt.Sprintf("%d (%.1f%%)", snap.DroppedPackets, dropPct))))

	d.border("├", "┤")
	d.heading("PROTOCOL DISTRIBUTION")
	shown := 0
	for _, proto := range protocolOrder {
		ps, ok := snap.Protocols[proto]
		if !ok {
			continue
		}
		pct := 0.0
		if snap.TotalPackets > 0 {
			pct = float64(ps.Packets) / float64(snap.TotalPackets) * 100
		}
		d.row(fmt.Sprintf("%s %9d pkts (%5.1f%%) | %s  %s",
			Colorize(protoColor(proto), fmt.Sprintf("%-5s", proto)),
			ps.Packets, pct, formatBytes(ps.Bytes), progressBar(pct, barWidth)))
		shown++
	}
	if shown == 0 {
		d.row(Colorize(ColorGray, "Waiting for packets..."))
	}

	d.border("├", "┤")
	d.heading("BANDWIDTH")
	peak := Colorize(ColorGray, "n/a")
	if !snap.PeakBPSAt.IsZero() {
		peak = Colorize(ColorYellow, formatBPS(snap.PeakBPS)) +
			" @ " + snap.PeakBPSAt.Format("15:04:05")
	}
	d.row(fmt.Sprintf("Current: %s    Peak: %s",
		Colorize(bwColor(snap.CurrentBPS), formatBPS(snap.CurrentBPS)), peak))

	d.border("├", "┤")
	d.heading("TOP TALKERS (by bytes sent)")
	if len(snap.TopTalkers) == 0 {
		d.row(Colorize(ColorGray, "No IP traffic seen yet"))
	}
	for i, t := range snap.TopTalkers {
		pct := 0.0
		if snap.TotalBytes > 0 {
			pct = float64(t.Bytes) / float64(snap.TotalBytes) * 100
		}
		d.row(fmt.Sprintf("%s %-15s  %s  (%5.1f%%)",
			Colorize(ColorYellow, fmt.Sprintf("%2d.", i+1)),
			t.IP, formatBytes(t.Bytes), pct))
	}

	d.border("├", "┤")
	d.heading("HTTP TRAFFIC")
	if snap.HTTPRequests+snap.HTTP2xx+snap.HTTP4xx+snap.HTTP5xx > 0 {
		d.row(fmt.Sprintf("Requests: %d  |  Responses  2xx: %s  4xx: %s  5xx: %s",
			snap.HTTPRequests,
			Colorize(ColorGreen, fmt.Sprintf("%d", snap.HTTP2xx)),
			Colorize(ColorYellow, fmt.Sprintf("%d", snap.HTTP4xx)),
			Colorize(ColorRed, fmt.Sprintf("%d", snap.HTTP5xx))))
	} else {
		d.row(Colorize(ColorGray, "No HTTP traffic detected"))
	}

	d.border("├", "┤")
	d.row("Active TCP flows: " + Colorize(ColorCyan, fmt.Sprintf("%d", snap.ActiveFlows)))
	d.border("└", "┘")

	d.sb.WriteString(Colorize(ColorGray, "  [Ctrl+C to stop]") + "\n")
	return d.sb.String()
}

// dashboard accumulates fixed-width boxed rows.
type dashboard struct {
	sb strings.Builder
}

// border writes a horizontal rule with the given corner or junction pieces.
func (d *dashboard) border(left, right string) {
	d.sb.WriteString(Colorize(ColorCyan, left+strings.Repeat("─", innerWidth)+right) + "\n")
}

// row writes one line of content between the vertical borders, padded so
// the right border lines up no matter how many color codes content holds.
func (d *dashboard) row(content string) {
	const indent = 2
	pad := innerWidth - indent - visibleWidth(content)
	if pad < 0 {
		pad = 0
	}
	side := Colorize(ColorCyan, "│")
	d.sb.WriteString(side + strings.Repeat(" ", indent) + content + strings.Repeat(" ", pad) + side + "\n")
}

// heading writes a bold section title row.
func (d *dashboard) heading(title string) {
	d.row(Colorize(ColorBold, title))
}

// split writes a row with left flush left and right flush right.
func (d *dashboard) split(left, right string) {
	gap := innerWidth - 4 - visibleWidth(left) - visibleWidth(right)
	if gap < 1 {
		gap = 1
	}
	d.row(left + strings.Repeat(" ", gap) + right)
}

// PrintPacket prints a one-line summary of a decoded packet (verbose mode).
func PrintPacket(info *models.PacketInfo) {
	fmt.Println(formatPacket(info))
}

// formatPacket builds the verbose-mode line for one packet.
func formatPacket(info *models.PacketInfo) string {
	ts := Colorize(ColorGray, info.Timestamp.Format("15:04:05.000000"))
	proto := Colorize(protoColor(info.Protocol), fmt.Sprintf("%-5s", info.Protocol))

	// Non-IP traffic has no addresses above the link layer.
	if info.SrcIP == "" {
		return fmt.Sprintf("%s %s %s -> %s (%d bytes)",
			ts, proto, info.SrcMAC, info.DstMAC, info.TotalBytes)
	}

	if info.IsFragment {
		return fmt.Sprintf("%s %s %s -> %s %s",
			ts, proto, info.SrcIP, info.DstIP, Colorize(ColorGray, "(IP fragment)"))
	}

	switch info.Protocol {
	case "TCP":
		line := fmt.Sprintf("%s %s %s:%d -> %s:%d %s",
			ts, proto, info.SrcIP, info.SrcPort, info.DstIP, info.DstPort,
			Colorize(ColorYellow, info.TCPFlags))
		if h := info.HTTP; h != nil {
			if h.IsRequest {
				line += " " + Colorize(ColorCyan, fmt.Sprintf("HTTP %s %s%s", h.Method, h.Host, h.URL))
			} else {
				line += " " + Colorize(ColorCyan, "HTTP "+h.StatusText)
			}
		}
		return line
	case "UDP":
		return fmt.Sprintf("%s %s %s:%d -> %s:%d",
			ts, proto, info.SrcIP, info.SrcPort, info.DstIP, info.DstPort)
	case "ICMP":
		return fmt.Sprintf("%s %s %s -> %s (%s)",
			ts, proto, info.SrcIP, info.DstIP, Colorize(ColorYellow, info.ICMPType))
	default:
		return fmt.Sprintf("%s %s %s -> %s", ts, proto, info.SrcIP, info.DstIP)
	}
}

// progressBar renders pct (0-100) as a bar of the given width.
func progressBar(pct float64, width int) string {
	if math.IsNaN(pct) || pct < 0 {
		pct = 0
	}
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return Colorize(ColorGreen, bar)
}

// formatBytes renders a byte count with binary (1024-based) units in a
// fixed 9-column field so that columns of sizes line up.
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

// formatBPS renders a rate in bits per second with decimal (1000-based)
// units, the convention for network speeds.
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

// FormatDuration renders d as HH:MM:SS. Hours keep counting past 24.
func FormatDuration(d time.Duration) string {
	total := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", total/3600, total/60%60, total%60)
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

// bwColor picks a color for a bandwidth reading: green below 10 Mbps,
// yellow up to 100 Mbps, red above.
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
