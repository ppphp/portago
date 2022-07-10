package vars

import (
	_const "github.com/ppphp/portago/pkg/const"
	"os"
	"path"
	"regexp"
	"strings"
)

var InitializingGlobals *bool
var NotInstalled bool
var InternalCaller = false
var SyncMode = false

var shellQuoteRe = regexp.MustCompile("[\\s><=*\\\\\\\"'$`]")

func ShellQuote(s string) string {

	if shellQuoteRe.MatchString(s) {
		return s
	}
	for _, letter := range "\\\"$`" {
		if strings.Contains(s, string(letter)) {
			s = strings.Replace(s, string(letter), "\\"+string(letter), -1)
		}
	}
	return "\"" + s + "\""
}

func init() {
	ni, err := os.Stat(path.Join(_const.PORTAGE_BASE_PATH, ".portage_not_installed"))
	if err != nil || !ni.IsDir() {
		NotInstalled = true
	}
}

func UnprivilegedMode(eroot string, erootSt os.FileInfo) bool {
	st, err := os.Stat(eroot)
	if err != nil {
		return false
	}
	return os.Getuid() != 0 && st.Mode()&2 != 0 && erootSt.Mode()&00002 == 0
}
