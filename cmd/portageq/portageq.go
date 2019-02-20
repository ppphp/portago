package main

import (
	"github.com/ppphp/portago/atom"
	flag "github.com/spf13/pflag"
	"os"
	"os/signal"
	"syscall"
)

var atomValidateStrict bool

func init() {
	if os.Getenv("EBUILD_PHASE") != "" {
		atomValidateStrict = true
	}
}

func main() {
	go signalHandler()

	noColor := os.Getenv("NOCOLOR")
	if noColor == "yes" || noColor == "true" {
		atom.NoColor()
	}
	verbose := flag.BoolP("verbose", "v", false, "verbose form")
	help := flag.BoolP("help", "h", false, "help message")
	version := flag.BoolP("version", "", false, "version")
	//noFilter := flag.BoolP("no-filters", "", false, "no visibility filters (ACCEPT_KEYWORDS, package masking, etc)")
	//noRegex := flag.BoolP("no-regex", "", false, "Use exact matching instead of regex matching for --maintainer-email")
	//orphaned := flag.BoolP("orphaned", "", false, "match only orphaned (maintainer-needed) packages")
	//noVersion := flag.BoolP("no-version", "n", false, "collapse multiple matching versions together")
	//repo := flag.StringP("repo", "", "", "repository to use (all repositories are used by default)")
	//maintainerEmail := flag.StringArrayP("maintainer-email", "", nil, "comma-separated list of maintainer email regexes to search for")

	flag.Parse()
	args := flag.Args()

	if *help {
		os.Exit(syscall.F_OK)
	} else if *version {
		os.Exit(syscall.F_OK)
	}

	cmd := ""
	if len(args) != 0 {
		for _, c := range []string{"all_best_visible", "config_protect_mask", "has_version", "pkgdir", "best_version", "distdir",
			"mass_best_version", "portdir", "best_visible", "envvar", "mass_best_visible", "portdir_overlay", "config_protect",
			"gentoo_mirrors", "match", "vdb_path", "pquery"} {
			if c == args[0] {
				cmd = args[0]
			}
		}
	}
	if cmd == "pquery" {
		cmd = ""
		args = args[1:]
	}
	if cmd == "" {
		//return pquery(parser, opts, args)
	}

	if *verbose {
		args = append(args, "-v")
	}

	argv := make([]string, 1)
	copy(argv, os.Args[:1])
	argv = append(argv, args...)
	if len(argv) < 2 {
		os.Exit(64)
	}

	realArg := argv[2:]

	retval := 0
	switch cmd {
	case "has_version":
		retval = hasVersion(realArg)
	}
	if retval != 0 {
		os.Exit(retval)
	}
}

func signalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGINT:
				os.Exit(128 + 2)
			case syscall.SIGTERM:
				os.Exit(128 + 9)
			}
		}
	}
}

func hasVersion(args []string) int {
	if len(args) < 2 {
		println("ERROR: insufficient parameters!")
		return 3
	}
	return 0
}
func bestVersion(args []string)       {}
func massBestVersion(args []string)   {}
func bestVisible(args []string)       {}
func massBestVisible(args []string)   {}
func allBestVisible(args []string)    {}
func match(args []string)             {}
func vdbPath(args []string)           {}
func gentooMirrors(args []string)     {}
func portdir(args []string)           {}
func configProtect(args []string)     {}
func configProtectMask(args []string) {}
func portdirOverlay(args []string)    {}
func pkgdir(args []string)            {}
func distdir(args []string)           {}
func envvar(args []string) int {
	var newArgs []string
	verbose := false
	for _, v := range args {
		if v != "-v"{
			verbose = true
			newArgs = append(newArgs, v)
		}
	}
	if len(newArgs) == 0 {
		print("ERROR: insufficient parameters!")
		return 2
	}
	for _, a := range newArgs {
		for _, v := range []string{"PORTDIR", "PORTDIR_OVERLAY", "SYNC"} {
			if v == a {
				println("WARNING: 'portageq envvar "+a+"' is deprecated. Use any of 'get_repos, get_repo_path, repos_config' instead.")
			}
		}
		value := atom.Settings.get(a)
		if value == "" {
			return 1
		}

		if verbose {
			println(a+"="+atom.ShellQuote(value))
		} else {
			println(value)
		}
	}

	return 0
}
func pquery(args []string) {}
