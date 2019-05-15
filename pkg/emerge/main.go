package emerge

import (
	"fmt"
	"os"
)

var options = []string{
	"--alphabetical",
	"--ask-enter-invalid",
	"--buildpkgonly",
	"--changed-use",
	"--changelog", "--columns",
	"--debug",
	"--digest",
	"--emptytree",
	"--verbose-conflicts",
	"--fetchonly", "--fetch-all-uri",
	"--ignore-default-opts",
	"--noconfmem",
	"--newrepo",
	"--newuse",
	"--nodeps", "--noreplace",
	"--nospinner", "--oneshot",
	"--onlydeps", "--pretend",
	"--quiet-repo-display",
	"--quiet-unmerge-warn",
	"--resume",
	"--searchdesc",
	"--skipfirst",
	"--tree",
	"--unordered-display",
	"--update",
}

var shortMapping = map[string]string{
	"1": "--oneshot",
	"B": "--buildpkgonly",
	"c": "--depclean",
	"C": "--unmerge",
	"d": "--debug",
	"e": "--emptytree",
	"f": "--fetchonly", "F": "--fetch-all-uri",
	"h": "--help",
	"l": "--changelog",
	"n": "--noreplace", "N": "--newuse",
	"o": "--onlydeps", "O": "--nodeps",
	"p": "--pretend", "P": "--prune",
	"r": "--resume",
	"s": "--search", "S": "--searchdesc",
	"t": "--tree",
	"u": "--update", "U": "--changed-use",
	"V": "--version",
}

const COWSAY_MOO = `

Larry loves Gentoo (%s)

_______________________
< Have you mooed today? >
-----------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

`

func multiple_actions(action1, action2 string) {
	os.Stderr.Write([]byte("\n!!! Multiple actions requested... Please choose one only.\n"))
	os.Stderr.Write([]byte(fmt.Sprintf("!!! '%s' or '%s'\n\n", action1, action2)))
	os.Exit(1)
}
