package main

import "fmt"

import (
	_ "github.com/ppphp/portago/pkg/binrepo"
	_ "github.com/ppphp/portago/pkg/cache"
	//_ "github.com/ppphp/portago/pkg/ebuild/cache"
	_ "github.com/ppphp/portago/pkg/checksum"
	_ "github.com/ppphp/portago/pkg/const"
	_ "github.com/ppphp/portago/pkg/data"
	//_ "github.com/ppphp/portago/pkg/ebuild/dbapi"
	_ "github.com/ppphp/portago/pkg/dep"
	_ "github.com/ppphp/portago/pkg/eapi"
	//_ "github.com/ppphp/portago/pkg/ebuild/config"
	//_ "github.com/ppphp/portago/pkg/ebuild"
	//_ "github.com/ppphp/portago/pkg/elog"
	//_ "github.com/ppphp/portago/pkg/emaint"
	//_ "github.com/ppphp/portago/pkg/emerge"
	_ "github.com/ppphp/portago/pkg/env"
	_ "github.com/ppphp/portago/pkg/getbinpkg"
	//_ "github.com/ppphp/portago/pkg/gpg"
	//_ "github.com/ppphp/portago/pkg/locale"
	_ "github.com/ppphp/portago/pkg/locks"
	//_ "github.com/ppphp/portago/pkg/mail"
	_ "github.com/ppphp/portago/pkg/manifest"
	//_ "github.com/ppphp/portago/pkg/metadata"
	_ "github.com/ppphp/portago/pkg/output"
	//_ "github.com/ppphp/portago/pkg/portage"
	_ "github.com/ppphp/portago/pkg/process"
	_ "github.com/ppphp/portago/pkg/progress"
	_ "github.com/ppphp/portago/pkg/repository"
	//_ "github.com/ppphp/portago/pkg/sets"
	_ "github.com/ppphp/portago/pkg/src"
	//_ "github.com/ppphp/portago/pkg/sync"
	_ "github.com/ppphp/portago/pkg/util"
	_ "github.com/ppphp/portago/pkg/versions"
	_ "github.com/ppphp/portago/pkg/xpak"
)

func main() {
	fmt.Println("ok")
}
