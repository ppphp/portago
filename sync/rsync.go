package sync

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/ppphp/portago/config"
)

// /usr/portage
func rsync() {

	bin := "/usr/bin/rsync"
	args := []string{"--recursive", "--links", "--safe-links", "--perms", "--times", "--omit-dir-times", "--compress",
		"--force", "--whole-file", "--delete", "--stats", "--human-readable", "--timeout=180", "--exclude=/distfiles",
		"--exclude=/local", "--exclude=/packages", "--exclude=/.git", "--verbose", "--checksum",
	}

	args1 := append([]string{}, args...)
	args1 = append(args1, "--inplace", "rsync://89.238.71.6/gentoo-portage/metadata/timestamp.chk", config.EbuildDir+"/metadata")
	fmt.Printf("%v %v\n", bin, strings.Join(args1, " "))
	r := exec.Command(bin, args1...)
	if err := r.Run(); err != nil {
		println(err.Error())
	}
	args2 := append([]string{}, args...)
	args2 = append(args2, "rsync://89.238.71.6/gentoo-portage/", config.EbuildDir)
	fmt.Printf("%v %v\n", bin, strings.Join(args2, " "))
	s := exec.Command(bin, args2...)
	if err := s.Run(); err != nil {
		println(err.Error())
	}
	println("success")
}
