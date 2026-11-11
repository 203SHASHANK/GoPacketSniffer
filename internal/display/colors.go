// Package display formats captured data for the terminal: the live
// statistics dashboard and the per-packet verbose listing.
package display

import "unicode/utf8"

// ANSI escape sequences (SGR codes) for terminal colors.
const (
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
)

// Colorize wraps text in the given color code and resets the terminal
// attributes afterwards.
func Colorize(color, text string) string {
	return color + text + ColorReset
}

// visibleWidth returns the number of terminal columns s occupies. Escape
// sequences take up bytes in the string but no space on screen, so they have
// to be skipped when padding text to a fixed width.
//
// Every other rune is counted as one column, which holds for the ASCII and
// box-drawing characters the dashboard uses.
func visibleWidth(s string) int {
	width := 0
	for i := 0; i < len(s); {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			// Skip "ESC [ parameters letter".
			i += 2
			for i < len(s) && (s[i] < '@' || s[i] > '~') {
				i++
			}
			i++ // the final letter
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		width++
	}
	return width
}
