package emerge

import (
	"fmt"
	"os"
	"runtime"

	"github.com/ppphp/portago/atom"
	"github.com/spf13/pflag"
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

func multipleActions(action1, action2 string) {
	os.Stderr.Write([]byte("\n!!! Multiple actions requested... Please choose one only.\n"))
	os.Stderr.Write([]byte(fmt.Sprintf("!!! '%s' or '%s'\n\n", action1, action2)))
	os.Exit(1)
}

func ParseOpts(args []string, silent bool) string { // false
	clean := pflag.BoolP("clean", "", false, "")
	checkNews := pflag.BoolP("check-news", "", false, "")
	config := pflag.BoolP("config", "", false, "")
	depclean := pflag.BoolP("depclean", "", false, "")
	help := pflag.BoolP("help", "", false, "")
	info := pflag.BoolP("info", "", false, "")
	listSets := pflag.BoolP("list-sets", "", false, "")
	metadata := pflag.BoolP("metadata", "", false, "")
	moo := pflag.BoolP("moo", "", false, "")
	prune := pflag.BoolP("prune", "", false, "")
	rageClean := pflag.BoolP("rage-clean", "", false, "")
	regen := pflag.BoolP("regen", "", false, "")
	search := pflag.BoolP("search", "", false, "")
	sync := pflag.BoolP("sync", "", false, "")
	unmerge := pflag.BoolP("unmerge", "", false, "")
	version := pflag.BoolP("version", "", false, "")

	pflag.CommandLine.Parse(args)

	action := []string{}
	if *clean {
		action = append(action, "clean")
	}
	if *checkNews {
		action = append(action, "check-news")
	}
	if *config {
		action = append(action, "config")
	}
	if *depclean {
		action = append(action, "depclean")
	}
	if *help {
		action = append(action, "help")
	}
	if *info {
		action = append(action, "info")
	}
	if *listSets {
		action = append(action, "list-sets")
	}
	if *metadata {
		action = append(action, "metadata")
	}
	if *moo {
		action = append(action, "moo")
	}
	if *prune {
		action = append(action, "prune")
	}
	if *rageClean {
		action = append(action, "rage-clean")
	}
	if *regen {
		action = append(action, "regen")
	}
	if *search {
		action = append(action, "search")
	}
	if *sync {
		action = append(action, "sync")
	}
	if *unmerge {
		action = append(action, "unmerge")
	}
	if *version {
		action = append(action, "version")
	}
	if len(action) > 1 {
		os.Stderr.Write([]byte("\n!!! Multiple actions requested... Please choose one only.\n"))
		os.Stderr.Write([]byte(fmt.Sprintf("!!! '%s' or '%s'\n\n", action[0], action[1])))
		os.Exit(1)
	}

	return action[0]

}

func EmergeMain(args []string) int {
	if args == nil {
		args = os.Args[1:]
	}
	atom.HaveColor = 0

	myAction := ParseOpts(args, true)
	switch myAction {
	case "help":
		emergeHelp()
		return 0
	case "moo":
		fmt.Printf(COWSAY_MOO, runtime.GOOS)
		return 0
	case "sync":
		atom.SyncMode = true
	}
	devNull, _ := os.Open(os.DevNull)
	if devNull != nil {
		devNull.Close()
	}

	emergeConfig := LoadEmergeConfig(nil, nil, myAction)

	runAction(emergeConfig)
	return 0
}
