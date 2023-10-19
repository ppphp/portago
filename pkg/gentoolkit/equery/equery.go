package equery

import (
	"fmt"
	"go/importer"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ppphp/portago/pkg/gentoolkit"
)

var CONFIG = gentoolkit.CONFIG

var __docformat__ = "epytext"

var __productname__ = "equery"
var __authors__ = []string{
	"Karl Trygve Kalleberg - Original author",
	"Douglas Anderson - 0.3.0 author",
}

var nameMap = map[string]string{
	"b": "belongs",
	"k": "check",
	"d": "depends",
	"g": "depgraph",
	"f": "files",
	"h": "hasuse",
	"l": "list_",
	"y": "keywords",
	"a": "has",
	"m": "meta",
	"s": "size",
	"u": "uses",
	"w": "which",
}

// true
func printHelp(with_description bool) {
	if with_description {
		// fmt.Println(__doc__)
	}
	fmt.Println(main_usage())
	fmt.Println()
	// fmt.Println(pp.globaloption("global options"))
	fmt.Println(
		format_options([][]string{
			{" -h, --help", "display this help message"},
			{" -q, --quiet", "minimal output"},
			{" -C, --no-color", "turn off colors"},
			{" -N, --no-pipe", "turn off pipe detection"},
			{" -V, --version", "display version info"},
		}),
	)
	fmt.Println()
	// fmt.Println(pp.command("modules") + " (" + pp.command("short name") + ")")
	fmt.Println(
		format_options([][]string{
			{" (b)elongs", "list what package FILES belong to"},
			{" chec(k)", "verify checksums and timestamps for PKG"},
			{" (d)epends", "list all packages directly depending on ATOM"},
			{" dep(g)raph", "display a tree of all dependencies for PKG"},
			{" (f)iles", "list all files installed by PKG"},
			{" h(a)s", "list all packages for matching ENVIRONMENT data stored in /var/db/pkg"},
			{" (h)asuse", "list all packages that have USE flag"},
			{" ke(y)words", "display keywords for specified PKG"},
			{" (l)ist", "list package matching PKG"},
			{" (m)eta", "display metadata about PKG"},
			{" (s)ize", "display total size of all files owned by PKG"},
			{" (u)ses", "display USE flags for PKG"},
			{" (w)hich", "print full path to ebuild for PKG"},
		}),
	)
}

func expandModuleName(moduleName string) string {
	if moduleName == "list" {
		return "list_"
	} else if val, ok := nameMap[moduleName]; ok {
		return val
	} else {
		panic(fmt.Sprintf("KeyError: %s", moduleName))
	}
}

func format_options(options [][]string) string {
	var result []string
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	for _, option := range options {
		opt := option[0]
		desc := option[1]
		fmt.Fprintf(tw, "  %s\t%s\n", pp.emph(opt), desc)
	}
	tw.Flush()
	return strings.Join(result, "\n")
}

func format_filetype(path string, fdesc []string, show_type bool, show_md5 bool, show_timestamp bool) string {
	ftype := ""
	fpath := ""
	stamp := ""
	md5sum := ""

	if fdesc[0] == "obj" {
		ftype = "file"
		fpath = path
		stamp = formatTimestamp(fdesc[1])
		md5sum = fdesc[2]
	} else if fdesc[0] == "dir" {
		ftype = "dir"
		fpath = pp.path(path)
	} else if fdesc[0] == "sym" {
		ftype = "sym"
		stamp = formatTimestamp(fdesc[1])
		tgt := strings.Split(fdesc[2], " ")[0]
		if CONFIG["piping"] != 0 {
			fpath = path
		} else {
			fpath = pp.path_symlink(path + " -> " + tgt)
		}
	} else if fdesc[0] == "dev" {
		ftype = "dev"
		fpath = path
	} else if fdesc[0] == "fif" {
		ftype = "fifo"
		fpath = path
	} else {
		os.Stderr.WriteString(pp.error(fmt.Sprintf("%s has unknown type: %s", path, fdesc[0])))
	}

	result := ""
	if show_type {
		result += fmt.Sprintf("%4s ", ftype)
	}
	result += fpath
	if show_timestamp {
		result += "  " + stamp
	}
	if show_md5 {
		result += "  " + md5sum
	}

	return result
}

func formatTimestamp(timestamp string) string {
	ts, _ := strconv.ParseInt(timestamp, 10, 64)
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

func initialize_configuration() {
	// Get terminal size
	term_width := pp.output.get_term_size()[1]
	if term_width < 1 {
		// get_term_size() failed. Set a sane default width:
		term_width = 80
	}

	// Terminal size, minus a 1-char margin for text wrapping
	CONFIG["termWidth"] = term_width - 1

	// Guess color output
	if (CONFIG["color"] == -1 && (os.Getenv("NO_COLOR") != "" || os.Getenv("NOCOLOR") == "yes" || os.Getenv("NOCOLOR") == "true")) || CONFIG["color"] == 0 {
		pp.output.nocolor()
	}

	if CONFIG["piping"] != 0 {
		CONFIG["verbose"] = 0
		// set extra wide, should disable wrapping unless
		// there is some extra long text
		CONFIG["termWidth"] = 600
	}

	if os.Getenv("DEBUG") == "true" {
		CONFIG["debug"] = 1
	} else {
		CONFIG["debug"] = 0
	}
}

func main_usage() string {
	// Return the main usage message for equery
	return fmt.Sprintf("%s %s [%s] %s [%s]", pp.emph("Usage:"), __productname__, strings.Join(nameMap, ""), "mod_name", "mod_opts")
}

func mod_usage(mod_name string, arg string, optional bool) string {
	var argStr string
	if optional {
		argStr = fmt.Sprintf("[%s]", pp.emph(arg))
	} else {
		argStr = pp.emph(arg)
	}
	return fmt.Sprintf("%s: %s [%s] %s", pp.emph("Usage"), pp.command(mod_name), pp.localoption("options"), argStr)
}

func parseGlobalOptions(globalOpts []string, args []string) bool {
	needHelp := false
	doHelp := false
	for _, opt := range globalOpts {
		switch opt {
		case "-h", "--help":
			if len(args) > 0 {
				needHelp = true
			} else {
				doHelp = true
			}
		case "-q", "--quiet":
			CONFIG["quiet"] = 1
		case "-C", "--no-color", "--nocolor":
			CONFIG["color"] = 0
			pp.Output.NoColor()
		case "-N", "--no-pipe":
			CONFIG["piping"] = 0
		case "-V", "--version":
			printVersion()
			os.Exit(0)
		case "--debug":
			CONFIG["debug"] = 1
		}
	}
	if doHelp {
		printHelp(true)
		os.Exit(0)
	}
	return needHelp
}

func printVersion() {
	fmt.Printf("%s (%s) - %s", pp.productname(__productname__), __version__, __doc__)
}

func splitArguments(args []string) (string, []string) {
	return args[0], args[1:]
}

func Equery(argv []string) {
	shortOpts := "hqCNV"
	longOpts := []string{"help", "quiet", "nocolor", "no-color", "no-pipe", "version", "debug"}

	initialize_configuration()

	globalOpts, args, err := getopt.Getopt(argv[1:], shortOpts, longOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", pp.error(fmt.Sprintf("Global %s", err)))
		printHelp(false)
		os.Exit(2)
	}

	// Parse global options
	needHelp := parseGlobalOptions(globalOpts, args)

	// verbose is shorthand for the very common 'not quiet or piping'
	if CONFIG["quiet"] != 0 || CONFIG["piping"] != 0 {
		CONFIG["verbose"] = 0
	} else {
		CONFIG["verbose"] = 1
	}

	if CONFIG["piping"] != 0 {
		// turn off color
		pp.output.nocolor()
	}

	module_name, module_args := splitArguments(args)

	if needHelp {
		module_args = append(module_args, "--help")
	}

	expanded_module_name, err := expandModuleName(module_name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", pp.error(fmt.Sprintf("Unknown module '%s'", module_name)))
		printHelp(false)
		os.Exit(2)
	}

	loaded_module, err := importer.Default().Import(expanded_module_name)
	if err != nil {
		if _, ok := err.(*portage_exception.AmbiguousPackageName); ok {
			panic(errors.NewGentoolkitAmbiguousPackage(err.Error()))
		} else if os.IsNotExist(err) {
			panic(errors.NewGentoolkitAmbiguousPackage(err.Error()))
		} else if err != nil {
			panic(err)
		}
	}

	if err := loaded_module.Main(module_args); err != nil {
		panic(err)
	}
}
