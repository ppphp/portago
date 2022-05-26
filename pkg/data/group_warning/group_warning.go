package group_warning

import (
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util/msg"
)

func PortageGroupWarning() {
	warnPrefix := output.Colorize("BAD", "*** WARNING ***  ")
	mylines := []string{
		"For security reasons, only system administrators should be",
		"allowed in the portage group.  Untrusted users or processes",
		"can potentially exploit the portage group for attacks such as",
		"local privilege escalation.",
	}
	for _, x := range mylines {
		msg.WriteMsg(warnPrefix, -1, nil)
		msg.WriteMsg(x, -1, nil)
		msg.WriteMsg("\n", -1, nil)
	}
	msg.WriteMsg("\n", -1, nil)
}
