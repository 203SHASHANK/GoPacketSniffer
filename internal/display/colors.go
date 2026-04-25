// Package display handles terminal output formatting and colorization.
package display

// ANSI escape codes for terminal colors.
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

// Colorize wraps text with the given ANSI color code and resets afterward.
func Colorize(color, text string) string {
	return color + text + ColorReset
}
