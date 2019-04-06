package main

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	flag "github.com/spf13/pflag"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

func init() {
	signalHandler := func() {
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
	go signalHandler()
	atom.InternalCaller = true
}

func eval_atom_use(atom *atom.Atom) *atom.Atom {
	if use, ok := os.LookupEnv("USE"); ok {
		u := map[string]bool{}
		for _, v := range strings.Fields(use) {
			u[v] = true
		}
		atom = atom.EvaluateConditionals(u)
	}
	return atom
}

type fuu struct {
	F              func([]string) int
	UseEroot       bool
	UsesConfigroot bool
	Docstrings     string
}

var globalFunctions = map[string]fuu{
	"colormap": {colormap, false, false, "Display the color.map as environment variables."},
}

var (
	nonCommands = []string{"elog", "eval_atom_use", "exithandler", "match_orphaned", "main", "usage", "uses_eroot"}
	commands    = []string{}
)

func usage(argv []string) {
	fmt.Println(">>> Portage information query tool")
	fmt.Printf(">>> %s\n", atom.VERSION)
	fmt.Println(">>> Usage: portageq <command> [<option> ...]")
	fmt.Println("")
	fmt.Println("Available commands:")
	help_mode := false
	for _, v := range argv {
		if "--help" == v {
			help_mode = true
		}
	}
	for name, f := range globalFunctions {
		lines := strings.Split(strings.TrimPrefix(f.Docstrings, "\n"), "\n")
		fmt.Println("   " + name + " " + strings.TrimSpace(lines[0]))
		if len(argv) > 1 {
			if !help_mode {
				lines = lines[:len(lines)-1]
			}
			for _, line := range lines[1:] {
				fmt.Println("      " + strings.TrimSpace(line))
			}
		}
	}

	fmt.Println()
	fmt.Println("Pkgcore pquery compatible options:")
	fmt.Println()
	//parser = argparse.ArgumentParser(add_help=False,
	//	usage='portageq pquery [options] [atom ...]')
	//add_pquery_arguments(parser)
	//parser.print_help()

	if len(argv) == 1 {
		fmt.Println("\nRun portageq with --help for info")
	}

}

var atomValidateStrict bool

func init() {
	if os.Getenv("EBUILD_PHASE") != "" {
		atomValidateStrict = true
	}
}

var eapi string
var elog func(string, []string)

func init() {
	if atomValidateStrict {
		eapi = os.Getenv("EAPI")
		elog = func(elog_funcname string, lines []string) {
			cmd := fmt.Sprintf("source '%s/isolated-functions.sh' ; ", os.Getenv("PORTAGE_BIN_PATH"))
			for _, line := range lines {
				cmd += fmt.Sprintf("%s %s ; ", elog_funcname, atom.ShellQuote(line))
			}
			c := exec.Command(atom.BashBinary, "-c", cmd)
			c.Run()
		}
	} else {
		elog = func(string, []string) {}
	}
}

func main() {

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
		for c := range globalFunctions {
			if c == args[0] {
				cmd = args[0]
				break
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

	function := globalFunctions[cmd]
	usesEroot := function.UseEroot && len(argv) > 2
	if usesEroot {
		s, err := os.Stat(argv[2])
		if err != nil || !s.IsDir() {
			fmt.Printf("Not a directory: '%s'\n", argv[2])
			fmt.Printf("Run portageq with --help for info\n")
			os.Exit(64)
		}
		eprefix := atom.TargetEprefix()
		eroot := atom.NormalizePath(argv[2])

		root := ""
		if eprefix != "" {
			if !strings.HasSuffix(eroot, eprefix) {
				fmt.Printf("ERROR: This version of portageq only supports <eroot>s ending in '%s'. The provided <eroot>, '%s', doesn't.\n", eprefix, eroot)
				os.Exit(64)
			}
			root = eroot[:1-len(eprefix)]
		} else {
			root = eroot
		}
		os.Setenv("ROOT", root)
		if function.UsesConfigroot {
			os.Setenv("PORTAGE_CONFIGROOT", eroot)
		}
		atom.SyncMode = true
	}

	realArg := argv[2:]
	if usesEroot {
		//realArg[0] = settings["EROOT"]
	}

	retval := function.F(realArg)
	if retval != 0 {
		os.Exit(retval)
	}
}

func hasVersion(args []string) int {
	if len(args) < 2 {
		println("ERROR: insufficient parameters!")
		return 3
	}
	return 0
}
func bestVersion(args []string) int       { return 0 }
func massBestVersion(args []string) int   { return 0 }
func bestVisible(args []string) int       { return 0 }
func massBestVisible(args []string) int   { return 0 }
func allBestVisible(args []string) int    { return 0 }
func match(args []string) int             { return 0 }
func vdbPath(args []string) int           { return 0 }
func gentooMirrors(args []string) int     { return 0 }
func portdir(args []string) int           { return 0 }
func configProtect(args []string) int     { return 0 }
func configProtectMask(args []string) int { return 0 }
func portdirOverlay(args []string) int    { return 0 }
func pkgdir(args []string) int            { return 0 }
func colormap([]string) int {
	fmt.Println(atom.ColorMap())
	return 0
}
func distdir(args []string) int { return 0 }
func envvar(args []string) int {
	var newArgs []string
	verbose := false
	for _, v := range args {
		if v != "-v" {
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
				println("WARNING: 'portageq envvar " + a + "' is deprecated. Use any of 'get_repos, get_repo_path, repos_config' instead.")
			}
		}
		value := "" //atom.Settings.get(a)
		if value == "" {
			return 1
		}

		if verbose {
			println(a + "=" + atom.ShellQuote(value))
		} else {
			println(value)
		}
	}

	return 0
}
func pquery(args []string) int { return 0 }
