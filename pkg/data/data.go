package data

import (
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/util/msg"
	"os"
	"runtime"
)

func TargetEprefix() string {
	if a := os.Getenv("EPREFIX"); a != "" {
		return msg.NormalizePath(a)
	}
	return _const.EPREFIX
}

func targetRoot() string {
	if a := os.Getenv("ROOT"); a != "" {
		return msg.NormalizePath(a)
	}
	return string(os.PathSeparator)
}

var Userpriv_groups []int
var _portage_grpname, _portage_username *string
var Portage_gid *uint32
var Portage_uid, Secpass *int
var uid = os.Geteuid()

const Ostype = runtime.GOOS
