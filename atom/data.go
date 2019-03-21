package atom

import (
	"os"
)

func targetEprefix() string {
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
		writeMsg(warnPrefix, -1, nil)
		writeMsg(x, -1, nil)
		writeMsg("\n", -1, nil)
	}
	writeMsg("\n", -1, nil)
}

var userpriv_groups, _portage_grpname, _portage_username *string
var portage_gid, portage_uid, secpass *int
var uid = os.Geteuid()

func data_init(settings *Config) {
	if portage_gid == nil && _portage_username == nil {
		v := ""
		if w, ok := settings.valueDict["PORTAGE_GRPNAME"]; ok {
			v = w
		} else {
			v = "portage"
		}
		_portage_grpname = new(string)
		*_portage_grpname = v
		if w, ok := settings.valueDict["PORTAGE_USERNAME"]; ok {
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
		} else if settings.features.features["unprivileged"] {
			v = 2
		} else if i, err := os.Getgroups(); err != nil {
			for _, x := range i {
				if *portage_gid == x {
					v = 1
					break
				}
			}
		}
		secpass = new(int)
		*secpass = v
	}
}
