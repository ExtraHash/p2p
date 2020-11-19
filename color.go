package p2p

type color struct {
	boldBlack   string
	boldRed     string
	boldGreen   string
	boldYellow  string
	boldPurple  string
	boldMagenta string
	boldCyan    string
	boldWhite   string
	black       string
	red         string
	green       string
	yellow      string
	purple      string
	magenta     string
	cyan        string
	white       string
	reset       string
}

var colors = color{
	boldBlack:   "\033[1;30m",
	boldRed:     "\033[1;31m",
	boldGreen:   "\033[1;32m",
	boldYellow:  "\033[1;33m",
	boldPurple:  "\033[1;34m",
	boldMagenta: "\033[1;35m",
	boldCyan:    "\033[1;36m",
	boldWhite:   "\033[1;37m",
	black:       "\033[0;30m",
	red:         "\033[0;31m",
	green:       "\033[0;32m",
	yellow:      "\033[0;33m",
	purple:      "\033[0;34m",
	magenta:     "\033[0;35m",
	cyan:        "\033[0;36m",
	white:       "\033[0;37m",
	reset:       "\033[0m",
}
