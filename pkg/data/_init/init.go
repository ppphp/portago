package _init

import (
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"syscall"
)

func Data_init(settings *config.Config) {
	if data.Portage_gid == nil && data._portage_username == nil {
		v := ""
		if w, ok := settings.ValueDict["PORTAGE_GRPNAME"]; ok {
			v = w
		} else {
			v = "portage"
		}
		data._portage_grpname = new(string)
		*data._portage_grpname = v
		if w, ok := settings.ValueDict["PORTAGE_USERNAME"]; ok {
			v = w
		} else {
			v = "portage"
		}
		data._portage_username = new(string)
		*data._portage_username = v
	}
	if data.Secpass == nil {
		v := 0
		if data.uid == 0 {
			v = 2
		} else if settings.Features.Features["unprivileged"] {
			v = 2
		} else if i, err := syscall.Getgroups(); err != nil {
			for _, x := range i {
				if *data.Portage_gid == uint32(x) {
					v = 1
					break
				}
			}
		}
		data.Secpass = new(int)
		*data.Secpass = v
	}
}
