package atom

import (
	"os"
	"runtime"
	"syscall"
)

func TargetEprefix() string {
	if a := os.Getenv("EPREFIX"); a != "" {
		return NormalizePath(a)
	}
	return EPREFIX
}

func targetRoot() string {
	if a := os.Getenv("ROOT"); a != "" {
		return NormalizePath(a)
	}
	return string(os.PathSeparator)
}

func portageGroupWarining() {
	warnPrefix := colorize("BAD", "*** WARNING ***  ")
	mylines := []string{
		"For security reasons, only system administrators should be",
		"allowed in the portage group.  Untrusted users or processes",
		"can potentially exploit the portage group for attacks such as",
		"local privilege escalation.",
	}
	for _, x := range mylines {
		WriteMsg(warnPrefix, -1, nil)
		WriteMsg(x, -1, nil)
		WriteMsg("\n", -1, nil)
	}
	WriteMsg("\n", -1, nil)
}

var userpriv_groups, _portage_grpname, _portage_username *string
var portage_gid *uint32
var portage_uid, secpass *int
var uid = os.Geteuid()

func data_init(settings *Config) {
	if portage_gid == nil && _portage_username == nil {
		v := ""
		if w, ok := settings.ValueDict["PORTAGE_GRPNAME"]; ok {
			v = w
		} else {
			v = "portage"
		}
		_portage_grpname = new(string)
		*_portage_grpname = v
		if w, ok := settings.ValueDict["PORTAGE_USERNAME"]; ok {
			v = w
		} else {
			v = "portage"
		}
		_portage_username = new(string)
		*_portage_username = v
	}
	if secpass == nil {
		v := 0
		if uid == 0 {
			v = 2
		} else if settings.Features.Features["unprivileged"] {
			v = 2
		} else if i, err := syscall.Getgroups(); err != nil {
			for _, x := range i {
				if *portage_gid == uint32(x) {
					v = 1
					break
				}
			}
		}
		secpass = new(int)
		*secpass = v
	}
}

const ostype = runtime.GOOS
