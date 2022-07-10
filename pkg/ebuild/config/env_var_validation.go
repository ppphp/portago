package config

import (
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/shlex"
	"os"
	"path"
	"strings"
)

func validateCmdVar(v string) (bool, []string) {
	invalid := false
	vSplit, _ := shlex.Split(strings.NewReader(v), false, true)
	if len(vSplit) == 0 {
		invalid = true
	} else if path.IsAbs(vSplit[0]) {
		s, _ := os.Stat(vSplit[0])
		invalid = s.Mode()&0111 == 0
	} else if process.FindBinary(vSplit[0]) == "" {
		invalid = true
	}
	return !invalid, vSplit
}
