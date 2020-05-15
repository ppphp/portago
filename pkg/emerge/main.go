package emerge

import (
	"fmt"
	"github.com/ppphp/portago/pkg/portage/emaint"
	"go/parser"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

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

func insert_optional_args(args []string) []string {
	var new_args, arg_stack []string

	valid_integers := func(s string)bool{i, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return i >=0
	}
	valid_floats := func(s string)bool{i, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return false
		}
		return i >=0
	}
	y_or_n := func(s string)bool {return s == "y"||s=="n"}

	default_arg_opts := map[string]func(string)bool{
		"--alert"                : y_or_n,
			"--ask"                  : y_or_n,
			"--autounmask"           : y_or_n,
			"--autounmask-continue"  : y_or_n,
			"--autounmask-only"      : y_or_n,
			"--autounmask-keep-keywords" : y_or_n,
			"--autounmask-keep-masks": y_or_n,
			"--autounmask-unrestricted-atoms" : y_or_n,
			"--autounmask-write"     : y_or_n,
			"--binpkg-changed-deps"  : y_or_n,
			"--buildpkg"             : y_or_n,
			"--changed-deps"         : y_or_n,
			"--changed-slot"         : y_or_n,
			"--changed-deps-report"  : y_or_n,
			"--complete-graph"       : y_or_n,
			"--deep"       : valid_integers,
			"--depclean-lib-check"   : y_or_n,
			"--deselect"             : y_or_n,
			"--binpkg-respect-use"   : y_or_n,
			"--fail-clean"           : y_or_n,
			"--fuzzy-search"         : y_or_n,
			"--getbinpkg"            : y_or_n,
			"--getbinpkgonly"        : y_or_n,
			"--ignore-world"         : y_or_n,
			"--jobs"       : valid_integers,
			"--keep-going"           : y_or_n,
			"--load-average"         : valid_floats,
			"--onlydeps-with-rdeps"  : y_or_n,
			"--package-moves"        : y_or_n,
			"--quiet"                : y_or_n,
			"--quiet-build"          : y_or_n,
			"--quiet-fail"           : y_or_n,
			"--read-news"            : y_or_n,
			"--rebuild-if-new-slot": y_or_n,
			"--rebuild-if-new-rev"   : y_or_n,
			"--rebuild-if-new-ver"   : y_or_n,
			"--rebuild-if-unbuilt"   : y_or_n,
			"--rebuilt-binaries"     : y_or_n,
			"--root-deps"  : func(s string) bool {return s=="rdeps"},
		"--select"               : y_or_n,
			"--selective"            : y_or_n,
			"--use-ebuild-visibility": y_or_n,
			"--usepkg"               : y_or_n,
			"--usepkgonly"           : y_or_n,
			"--verbose"              : y_or_n,
			"--verbose-slot-rebuilds": y_or_n,
			"--with-test-deps"       : y_or_n,
	}
	for _, v := range args {
		arg_stack = append(arg_stack, v)
	}
	for len(arg_stack) > 0 {
		arg := arg_stack[len(arg_stack)-1]
		arg_stack = arg_stack[:len(arg_stack)-1]

		default_arg_choices := default_arg_opts[arg]
		if default_arg_choices != nil {
			new_args=append(new_args, arg)
			if len(arg_stack) > 0 &&  default_arg_choices(arg_stack[len(arg_stack)-1]){
			new_args=append(new_args, arg_stack[len(arg_stack)-1])
				arg_stack = arg_stack[:len(arg_stack)-1]
		}else{
			new_args=append(new_args, "True")
		}
			continue
		}

		if arg[:1] != "-" || arg[:2] == "--"{
			new_args = append(new_args, arg)
			continue
		}

		short_arg_opts := map[string]func(string)bool{
			"D" : valid_integers,
				"j" : valid_integers,
		}
		match := ""
		var arg_choices func(string)bool
		for k ,v:= range short_arg_opts{
			if strings.Contains(arg, k){
			match = k
			arg_choices=v
			break
		}
		}

		short_arg_opts_n := map[string]func(string)bool{
			"a" : y_or_n,
				"A" : y_or_n,
				"b" : y_or_n,
				"g" : y_or_n,
				"G" : y_or_n,
				"k" : y_or_n,
				"K" : y_or_n,
				"q" : y_or_n,
				"v" : y_or_n,
				"w" : y_or_n,
		}
		if match == ""{
			for k,v := range short_arg_opts_n{
			if strings.Contains(arg, k){
			match = k
			arg_choices=v
			break
		}
		}
		}

		if match == "" {
			new_args=append(new_args,arg)
			continue
		}

		if len(arg) == 2 {
			new_args = append( new_args, arg)
			if len(arg_stack) > 0 &&  arg_choices(arg_stack[len(arg_stack)-1]){
				new_args=append(new_args, arg_stack[len(arg_stack)-1])
				arg_stack = arg_stack[:len(arg_stack)-1]
			}else {
				new_args =append(new_args, "True")
			}
			continue
		}

		new_args =append(new_args, "-" + match)
		opt_arg := ""
		saved_opts := ""

		if arg[1:2] == match{
		if  _,ok := short_arg_opts_n[match]; !ok&&  arg_choices(arg[2:]){
				opt_arg = arg[2:]
			}else {
				saved_opts = arg[2:]
				opt_arg = "True"
			}
		}else {
			saved_opts = strings.ReplaceAll(arg[1:],match, "")
			opt_arg = "True"
		}

		if opt_arg == "" && len(arg_stack)>0 && arg_choices(arg_stack[len(arg_stack)-1]){
			opt_arg = arg_stack[len(arg_stack) - 1]
			arg_stack=arg_stack[:len(arg_stack) - 1]
		}

		if opt_arg == ""{
			new_args=append(new_args, "True")
		}else {
			new_args=append(new_args, opt_arg)
		}

		if saved_opts != ""{
arg_stack = append(arg_stack, "-" + saved_opts)
}
	}

	return new_args
}

// false
func _find_bad_atoms(atoms []string, less_strict bool) []string {
	bad_atoms := []string{}
	for _, x := range strings.Fields(strings.Join(atoms, " ")) {
		at := x
		if !strings.Contains(strings.Split(x, ":")[0], "/") {
			x_cat := insert_category_into_atom(x, "dummy-category")
			if x_cat != "" {
				at = x_cat
			}
		}
		bad_atom := false
		atom, err := atom.NewAtom(at, nil, true, &less_strict, nil, "", nil, nil)
		if err != nil {
			//except portage.exception.InvalidAtom:
			bad_atom = true
		}

		if bad_atom || (atom.operator != "" && !less_strict) || atom.blocker != nil || atom.use != nil {
			bad_atoms = append(bad_atoms, x)
		}
	}
	return bad_atoms
}

func ParseOpts(tmpcmdline []string, silent bool) (string, map[string]string, []string) { // false

	actions := map[string]bool{
		"clean": true, "check-news": true, "config": true, "depclean": true, help: true,
		"info": true, "list-sets": true, "metadata": true, "moo": true,
		"prune": true, "rage-clean": true, "regen": true, "search": true,
		"sync": true, "unmerge": true, "version": true,
	}

	longopt_aliases := map[string]string{"--cols": "--columns", "--skip-first": "--skipfirst"}
	
	true_y :=map[string]bool{"True":true, "y":true}
	
	argument_options := map[string]struct{shortopt, help, action string}{

		"--alert": {
			shortopt : "-A",
				help    : "alert (terminal bell) on prompts",
				//"choices" : true_y_or_n
		},

		"--ask": {
			shortopt : "-a",
				help    : "prompt before performing any actions",
				//"choices" : true_y_or_n
		},

		"--autounmask": {
			help    : "automatically unmask packages",
				//"choices" : true_y_or_n
		},

		"--autounmask-backtrack": {
			help: ("continue backtracking when there are autounmask " +
			"configuration changes"),
			//"choices":("y", "n")
		},

		"--autounmask-continue": {
			help    : "write autounmask changes and continue",
				//"choices" : true_y_or_n
		},

		"--autounmask-only": {
			help    : "only perform --autounmask",
				//"choices" : true_y_or_n
		},

		"--autounmask-license": {
			help    : "allow autounmask to change package.license",
				//"choices" : y_or_n
		},

		"--autounmask-unrestricted-atoms": {
			help    : "write autounmask changes with >= atoms if possible",
				//"choices" : true_y_or_n
		},

		"--autounmask-use": {
			help    : "allow autounmask to change package.use",
				//"choices" : y_or_n
		},

		"--autounmask-keep-keywords": {
			help    : "don't add package.accept_keywords entries",
				//"choices" : true_y_or_n
		},

		"--autounmask-keep-masks": {
			help    : "don't add package.unmask entries",
				//"choices" : true_y_or_n
		},

		"--autounmask-write": {
			help    : "write changes made by --autounmask to disk",
				//"choices" : true_y_or_n
		},

		"--accept-properties": {
			help:"temporarily override ACCEPT_PROPERTIES",
				action:"store",
		},

		"--accept-restrict": {
			help:"temporarily override ACCEPT_RESTRICT",
				action:"store",
		},

		"--backtrack": {

			help   : "Specifies how many times to backtrack if dependency " +
			"calculation fails ",

				action : "store",
		},

		"--binpkg-changed-deps": {
			help    : ("reject binary packages with outdated "+
			"dependencies"),
			//"choices" : true_y_or_n
		},

		"--buildpkg": {
			shortopt : "-b",
				help     : "build binary packages",
				//"choices"  : true_y_or_n
		},

		"--buildpkg-exclude": {
			help   :"A space separated list of package atoms for which " +
			"no binary packages should be built. This option overrides all " +
			"possible ways to enable building of binary packages.",

				action : "append",
		},

		"--changed-deps": {
			help    : ("replace installed packages with "+
			"outdated dependencies"),
			//"choices" : true_y_or_n
		},

		"--changed-deps-report": {
			help    : ("report installed packages with "+
			"outdated dependencies"),
			//"choices" : true_y_or_n
		},

		"--changed-slot": {
			help    : ("replace installed packages with "+
			"outdated SLOT metadata"),
			//"choices" : true_y_or_n
		},

		"--config-root": {
			help:"specify the location for portage configuration files",
				action:"store",
		},
		"--color": {
			help:"enable or disable color output",
				//"choices":("y", "n")
		},

		"--complete-graph": {
			help    : "completely account for all known dependencies",
				//"choices" : true_y_or_n
		},

		"--complete-graph-if-new-use": {
			help    : "trigger --complete-graph behavior if USE or IUSE will change for an installed package",
				//"choices" : y_or_n
		},

		"--complete-graph-if-new-ver": {
			help    : "trigger --complete-graph behavior if an installed package version will change (upgrade or downgrade)",
				//"choices" : y_or_n
		},

		"--deep": {

			shortopt : "-D",

				help   : "Specifies how deep to recurse into dependencies " +
			"of packages given as arguments. If no argument is given, " +
			"depth is unlimited. Default behavior is to skip " +
			"dependencies of installed packages.",

				action : "store",
		},

		"--depclean-lib-check": {
			help    : "check for consumers of libraries before removing them",
				//"choices" : true_y_or_n
		},

		"--deselect": {
			help    : "remove atoms/sets from the world file",
				//"choices" : true_y_or_n
		},

		"--dynamic-deps": {
			help: "substitute the dependencies of installed packages with the dependencies of unbuilt ebuilds",
				//"choices": y_or_n
		},

		"--exclude": {
			help   :"A space separated list of package names or slot atoms. " + 
			"Emerge won't  install any ebuild or binary package that " + 
			"matches any of the given package atoms.",

				action : "append",
		},

		"--fail-clean": {
			help    : "clean temp files after build failure",
				//"choices" : true_y_or_n
		},

		"--fuzzy-search": {
			help: "Enable or disable fuzzy search",
				//"choices": true_y_or_n
		},

		"--ignore-built-slot-operator-deps": {
			help: "Ignore the slot/sub-slot := operator parts of dependencies that have "+
			"been recorded when packages where built. This option is intended "+
			"only for debugging purposes, and it only affects built packages "+
			"that specify slot/sub-slot := operator dependencies using the "+
			"experimental \"4-slot-abi\" EAPI.",
				//"choices": y_or_n
		},

		"--ignore-soname-deps": {
			help: "Ignore the soname dependencies of binary and "+
			"installed packages. This option is enabled by "+
			"default, since soname dependencies are relatively "+
			"new, and the required metadata is not guaranteed to "+
			"exist for binary and installed packages built with "+
			"older versions of portage.",
				//"choices": y_or_n
		},

		"--ignore-world": {
			help    : "ignore the @world package set and its dependencies",
				//"choices" : true_y_or_n
		},

		"--implicit-system-deps": {
			help: "Assume that packages may have implicit dependencies on"+
			"packages which belong to the @system set",
				//"choices": y_or_n
		},

		"--jobs": {

			shortopt : "-j",

				help   : "Specifies the number of packages to build " +
			"simultaneously.",

				action : "store",
		},

		"--keep-going": {
			help    : "continue as much as possible after an error",
				//"choices" : true_y_or_n
		},

		"--load-average": {

			help   :"Specifies that no new builds should be started " +
			"if there are other builds running and the load average " +
			"is at least LOAD (a floating-point number).",

				action : "store",
		},

		"--misspell-suggestions": {
			help    : "enable package name misspell suggestions",
				//"choices" : ("y", "n")
		},

		"--with-bdeps": {
			help:"include unnecessary build time dependencies",
				//"choices":("y", "n")
		},
		"--with-bdeps-auto": {
			help:("automatically enable --with-bdeps for installation"+
			" actions, unless --usepkg is enabled"),
			//"choices":("y", "n")
		},
		"--reinstall": {
			help:"specify conditions to trigger package reinstallation",
				//"choices":["changed-use"]
		},

		"--reinstall-atoms": {
			help   :"A space separated list of package names or slot atoms. " +
			"Emerge will treat matching packages as if they are not " +
			"installed, and reinstall them if necessary. Implies --deep.",

				action : "append",
		},

		"--binpkg-respect-use": {
			help    : "discard binary packages if their use flags don't match the current configuration",
			//"choices" : true_y_or_n
		},

		"--getbinpkg": {
			shortopt : "-g",
				help     : "fetch binary packages",
				//"choices"  : true_y_or_n
		},

		"--getbinpkgonly": {
			shortopt : "-G",
				help     : "fetch binary packages only",
				//"choices"  : true_y_or_n
		},

		"--usepkg-exclude": {
			help   :"A space separated list of package names or slot atoms. " +
			"Emerge will ignore matching binary packages. ",

				action : "append",
		},

		"--onlydeps-with-rdeps": {
			help    : "modify interpretation of depedencies",
				//"choices" : true_y_or_n
		},

		"--rebuild-exclude": {
			help   :"A space separated list of package names or slot atoms. " +
			"Emerge will not rebuild these packages due to the " +
			"--rebuild flag. ",

				action : "append",
		},

		"--rebuild-ignore": {
			help   :"A space separated list of package names or slot atoms. " +
			"Emerge will not rebuild packages that depend on matching " +
			"packages due to the --rebuild flag. ",

				action : "append",
		},

		"--package-moves": {
			help     : "perform package moves when necessary",
				//"choices"  : true_y_or_n
		},

		"--prefix": {
			help     : "specify the installation prefix",
				action   : "store",
		},

		"--pkg-format": {
			help     : "format of result binary package",
				action   : "store",
		},

		"--quickpkg-direct": {
			help: "Enable use of installed packages directly as binary packages",
				//"choices": y_or_n
		},

		"--quiet": {
			shortopt : "-q",
				help     : "reduced or condensed output",
				//"choices"  : true_y_or_n
		},

		"--quiet-build": {
			help     : "redirect build output to logs",
				//"choices"  : true_y_or_n,
		},

		"--quiet-fail": {
			help     : "suppresses display of the build log on stdout",
				//"choices"  : true_y_or_n,
		},

		"--read-news": {
			help    : "offer to read unread news via eselect",
				//"choices" : true_y_or_n
		},


		"--rebuild-if-new-slot": {
			help     : ("Automatically rebuild or reinstall packages when slot/sub-slot := "+
			"operator dependencies can be satisfied by a newer slot, so that "+
			"older packages slots will become eligible for removal by the "+
			"--depclean action as soon as possible."),
			//"choices"  : true_y_or_n
		},

		"--rebuild-if-new-rev": {
			help     : "Rebuild packages when dependencies that are " +
			"used at both build-time and run-time are built, " +
			"if the dependency is not already installed with the " +
			"same version and revision.",
				//"choices"  : true_y_or_n
		},

		"--rebuild-if-new-ver": {
			help     : "Rebuild packages when dependencies that are " +
			"used at both build-time and run-time are built, " +
			"if the dependency is not already installed with the " +
			"same version. Revision numbers are ignored.",
				//"choices"  : true_y_or_n
		},

		"--rebuild-if-unbuilt": {
			help     : "Rebuild packages when dependencies that are " +
			"used at both build-time and run-time are built.",
				//"choices"  : true_y_or_n
		},

		"--rebuilt-binaries": {
			help     : "replace installed packages with binary " +
			"packages that have been rebuilt",
				//"choices"  : true_y_or_n
		},

		"--rebuilt-binaries-timestamp": {
			help   : "use only binaries that are newer than this " +
			"timestamp for --rebuilt-binaries",
				action : "store",
		},

		"--root": {
			help   : "specify the target root filesystem for merging packages",
				action : "store",
		},

		"--root-deps": {
			help    : "modify interpretation of depedencies",
				//"choices" :("True", "rdeps")
		},

		"--search-index": {
			help: "Enable or disable indexed search (enabled by default)",
				//"choices": y_or_n
		},

		"--search-similarity": {
			help: ("Set minimum similarity percentage for fuzzy seach "+
			"(a floating-point number between 0 and 100)"),
			action: "store",
		},

		"--select": {
			shortopt : "-w",
				help    : "add specified packages to the world set " +
			"(inverse of --oneshot)",
				//"choices" : true_y_or_n
		},

		"--selective": {
			help    : "identical to --noreplace",
				//"choices" : true_y_or_n
		},

		"--sync-submodule": {
			help    : ("Restrict sync to the specified submodule(s)."+
			" (--sync action only)"),
			//"choices" : tuple(_SUBMODULE_PATH_MAP),
			//	"action" : "append",
		},

		"--sysroot": {
			help:"specify the location for build dependencies specified in DEPEND",
				action:"store",
		},

		"--use-ebuild-visibility": {
			help     : "use unbuilt ebuild metadata for visibility checks on built packages",
				//"choices"  : true_y_or_n
		},

		"--useoldpkg-atoms": {
			help   :"A space separated list of package names or slot atoms. " +
			"Emerge will prefer matching binary packages over newer unbuilt packages. ",

				action : "append",
		},

		"--usepkg": {
			shortopt : "-k",
				help     : "use binary packages",
				//"choices"  : true_y_or_n
		},

		"--usepkgonly": {
			shortopt : "-K",
				help     : "use only binary packages",
				//"choices"  : true_y_or_n
		},

		"--verbose": {
			shortopt : "-v",
				help     : "verbose output",
				//"choices"  : true_y_or_n
		},
		"--verbose-slot-rebuilds": {
			help     : "verbose slot rebuild output",
				//"choices"  : true_y_or_n
		},
		"--with-test-deps": {
			help     : "pull in test deps for packages " +
			"matched by arguments",
				//"choices"  : true_y_or_n
		},
	}
	pf := pflag.NewFlagSet("emerge", pflag.ExitOnError)

	bm := map[string]*bool{}
	for action_opt := range actions {
		bm[action_opt] = pf.BoolP(action_opt, "", false, "")
	}

	for _, myopt := range options {
		bm[myopt] = pf.BoolP(myopt, "", false, "")
	}

	for shortopt, longopt := range shortMapping {
		bm[longopt] = pf.BoolP(longopt, shortopt, false, "")
	}
	for myalias, myopt := range longopt_aliases {
		bm[myopt] = pf.BoolP(myalias, "", false, "")
	}

	am := map[string]*[]string{}
	sm :=map[string]*string{}
	for myopt, kwargs := range argument_options{
		if kwargs.action == "append"{
			am[myopt] = pf.StringArrayP(myopt,kwargs.shortopt, nil, kwargs.help)
		}else {
			sm[myopt] = pf.StringP(myopt,kwargs.shortopt, "", kwargs.help)
		}
	}

	tmpcmdline = insert_optional_args(tmpcmdline)

	pf.Parse(tmpcmdline)

	myaction := ""
	for action_opt := range actions {
		v := *bm[action_opt]
		if v {
			if myaction != "" {
				multipleActions(myaction, action_opt)
				os.Exit(1)
			}
			myaction = action_opt
		}
	}
	if myaction == "" && *bm["deselect"] {
		myaction = "deselect"
	}

	return myaction, nil, pf.Args()
}

func profile_check(trees *atom.Tree, myaction string) int {
	for _, v :=range []string{help, "info", "search", "sync", "version"}{
		if myaction ==v  {
			return syscall.F_OK
		}
	}
	for root_trees := range trees.values(){
		if (root_trees["root_config"].settings.profiles &&	'ARCH' in root_trees["root_config"].settings){
			continue
		}
		validate_ebuild_environment(trees)
		msg := "Your current profile is invalid. If you have just changed " +
				"your profile configuration, you should revert back to the " +
				"previous configuration. Allowed actions are limited to " +
				"--help, --info, --search, --sync, and --version."

		m := ""
		for _, l :=range  emaint.SplitSubN(msg, 70){
			m += fmt.Sprintf("!!! %s\n" % l)
		}
		atom.writeMsgLevel(m, 40, -1)
		return 1
	}
	return syscall.F_OK
}


func EmergeMain(args []string) int { // nil
	if args == nil {
		args = os.Args[1:]
	}
	// TODO: set locale
	atom.HaveColor = 0

	myAction, myOpts, myFiles := ParseOpts(args, true)
	if _, ok := myOpts["--debug"]; ok {
		os.Setenv("PORTAGE_DEBUG", "1")
	}
	if _, ok := myOpts["--config-root"]; ok {
		os.Setenv("PORTAGE_CONFIGROOT", myOpts["--config-root"])
	}
	if _, ok := myOpts["--sysroot"]; ok {
		os.Setenv("SYSROOT", myOpts["--sysroot"])
	}
	if _, ok := myOpts["--root"]; ok {
		os.Setenv("ROOT", myOpts["--root"])
	}
	if _, ok := myOpts["--prefix"]; ok {
		os.Setenv("EPREFIX", myOpts["--prefix"])
	}
	if _, ok := myOpts["--accept-properties"]; ok {
		os.Setenv("ACCEPT_PROPERTIES", myOpts["--accept-properties"])
	}
	if _, ok := myOpts["--accept-restrict"]; ok {
		os.Setenv("ACCEPT_RESTRICT", myOpts["--accept-restrict"])
	}

	switch myAction {
	case help:
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
	syscall.Umask(022)

	emergeConfig := LoadEmergeConfig(nil, nil, myAction, myFiles, myOpts)

	runAction(emergeConfig)
	return 0
}
