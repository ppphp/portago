package gentoolkit

import (
	"fmt"
	"os"

	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
)

// command returns a program command string.
func command(s string) string {
	return output.Green(s)
}

// cpv returns a category/package-<version> string.
func cpv(s string) string {
	return output.Green(s)
}

// die returns an error string and exits with an error code.
func die(err int, s string) {
	fmt.Fprintf(os.Stderr, "%s", error(s))
	os.Exit(err)
}

// emph returns a string as emphasized.
func emph(s string) string {
	return output.Bold(s)
}

// error prints an error string.
func error(s string) string {
	return output.Red(s)
}

// globaloption returns a global option string, i.e. the program global options.
func globaloption(s string) string {
	return output.Yellow(s)
}

// localoption returns a local option string, i.e. the program local options.
func localoption(s string) string {
	return output.Green(s)
}

// number returns a number string.
func number(s string) string {
	return output.Turquoise(s)
}

// path returns a file or directory path string.
func path(s string) string {
	return output.Bold(s)
}

// path_symlink returns a symlink string.
func path_symlink(s string) string {
	return output.Turquoise(s)
}

// pkgquery returns a package query string.
func pkgquery(s string) string {
	return output.Bold(s)
}

// productname returns a product name string, i.e. the program name.
func productname(s string) string {
	return output.Turquoise(s)
}

// regexpquery returns a regular expression string.
func regexpquery(s string) string {
	return output.Bold(s)
}

// section returns a string as a section header.
func section(s string) string {
	return output.Turquoise(s)
}

// slot returns a slot string.
func slot(s string) string {
	return output.Bold(s)
}

// subsection returns a string as a subsection header.
func subsection(s string) string {
	return output.Turquoise(s)
}

// useflag returns a USE flag string.
func useflag(s string, enabled bool) string {
	if enabled {
		return output.Red(s)
	}
	return output.Blue(s)
}

// keyword returns a keyword string.
func keyword(s string, stable bool, hardMasked bool) string {
	if stable {
		return output.Green(s)
	}
	if hardMasked {
		return output.Red(s)
	}
	// keyword masked:
	return output.Blue(s)
}

// masking returns a 'masked by' string.
func masking(mask []string) string {
	if len(mask) == 0 {
		return ""
	}
	if myutil.Ins(mask, "package.mask") || myutil.Ins(mask, "profile") {
		// use porthole wrap style to help clarify meaning
		return output.Red("M[" + mask[0] + "]")
	}
	for _, status := range mask {
		if status == "keyword" {
			// keyword masked | " [missing keyword] " <=looks better
			return output.Blue("[" + status + "]")
		}
		if status == "unknown" {
			return output.Green(status)
		}
		if _, ok := archlist[status]; ok {
			return output.Yellow(status)
		}
		return output.Red(status)
	}
	return ""
}

// warn returns a warning string.
func warn(s string) string {
	return fmt.Sprintf("!!! %s\n", s)
}
