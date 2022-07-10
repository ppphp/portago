package main

import "fmt"

import (
	_ "github.com/ppphp/portago/pkg/binrepo"
	_ "github.com/ppphp/portago/pkg/checksum"
	_ "github.com/ppphp/portago/pkg/const"
	_ "github.com/ppphp/portago/pkg/data"
	_ "github.com/ppphp/portago/pkg/dep"
	_ "github.com/ppphp/portago/pkg/eapi"
	_ "github.com/ppphp/portago/pkg/ebuild/config"
	_ "github.com/ppphp/portago/pkg/env"
	_ "github.com/ppphp/portago/pkg/getbinpkg"
	_ "github.com/ppphp/portago/pkg/locks"
	_ "github.com/ppphp/portago/pkg/output"
	_ "github.com/ppphp/portago/pkg/process"
	_ "github.com/ppphp/portago/pkg/progress"
	_ "github.com/ppphp/portago/pkg/src"
	_ "github.com/ppphp/portago/pkg/util"
	_ "github.com/ppphp/portago/pkg/versions"
	_ "github.com/ppphp/portago/pkg/xpak"
)

func main() {
	fmt.Println("ok")
}
