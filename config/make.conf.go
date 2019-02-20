package config

import (
	"io/ioutil"
)

var R = []byte{}

func Read() {
	R, _ = ioutil.ReadFile("/etc/portage/make.conf")
}
