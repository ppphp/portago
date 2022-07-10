package _selinux

import "github.com/opencontainers/selinux/go-selinux"

func Is_selinux_enabled() bool {
	return selinux.GetEnabled()
}
