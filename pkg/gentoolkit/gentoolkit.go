package gentoolkit

import (
	"os"

	"golang.org/x/term"
)

var CONFIG = map[string]interface{}{
	// Color handling: -1: Use Portage settings, 0: Force off, 1: Force on
	"color": -1,
	// Guess piping output:
	"piping": !term.IsTerminal(int(os.Stdout.Fd())),
	// Set some defaults:
	"quiet": false,
	// verbose is True if not quiet and not piping
	"verbose": true,
	"debug":   false,
}
