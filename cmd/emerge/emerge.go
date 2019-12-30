package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/emerge"

	"github.com/spf13/pflag"
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
	atom.DisableLegacyGlobals()
}

func main() {
	atom.SanitizeFds()
	emerge.EmergeMain(nil)

	pflag.BoolP("alert", "A", false, "alert (terminal bell) on prompts")
	pflag.BoolP("ask", "a", false, "prompt before performing any actions")
	pflag.BoolP("autounmask", "", false, "automatically unmask packages")
	pflag.BoolP("autounmask-backtrack", "", false, "continue backtracking when there are autounmask configuration changes")
	pflag.BoolP("autounmask-continue", "", false, "write autounmask changes and continue")
	pflag.BoolP("autounmask-only", "", false, "only perform --autounmask")
	pflag.BoolP("autounmask-unrestricted-atoms", "", false, "write autounmask changes with >= atoms if possible")
	pflag.BoolP("autounmask-keep-keywords", "", false, "don't add package.accept_keywords entries")
	pflag.BoolP("autounmask-keep-masks", "", false, "don't add package.unmask entries")
	pflag.BoolP("autounmask-write", "", false, "write changes made by --autounmask to disk")
	pflag.BoolP("accept-properties", "", false, "temporarily override ACCEPT_PROPERTIES")
	pflag.BoolP("accept-restrict", "", false, "temporarily override ACCEPT_RESTRICT")
	pflag.BoolP("backtrack", "", false, "Specifies how many times to backtrack if dependency calculation fails")
	pflag.BoolP("binpkg-changed-deps", "", false, "reject binary packages with outdated dependencies")
	pflag.BoolP("buildpkg", "b", false, "build binary packages")
	pflag.BoolP("buildpkg-exclude", "", false, "A space separated list of package atoms for which no binary packages should be built. This option overrides all possible ways to enable building of binary packages.")
	pflag.BoolP("changed-deps", "", false, "replace installed packages with outdated dependencies")
	pflag.BoolP("changed-deps-report", "", false, "report installed packages with outdated dependencies")
	pflag.BoolP("changed-slot", "", false, "replace installed packages with outdated SLOT metadata")
	pflag.StringP("config-root", "", "", "specify the location for portage configuration files")
	pflag.BoolP("color", "", false, "enable or disable color output")
	pflag.BoolP("complete-graph", "", false, "completely account for all known dependencies")
	pflag.BoolP("complete-graph-if-new-use", "", false, "trigger --complete-graph behavior if USE or IUSE will change for an installed package")
	pflag.BoolP("complete-graph-if-new-ver", "", false, "trigger --complete-graph behavior if an installed package version will change (upgrade or downgrade)")
	pflag.IntP("deep", "D", 0, "Specifies how deep to recurse into dependencies of packages given as arguments. If no argument is given, depth is unlimited. Default behavior is to skip dependencies of installed packages.")
	pflag.BoolP("depclean-lib-check", "", false, "check for consumers of libraries before removing them")
	pflag.BoolP("deselect", "", false, "remove atoms/sets from the world file")
	pflag.BoolP("dynamic-deps", "", false, "substitute the dependencies of installed packages with the dependencies of unbuilt ebuilds")
	pflag.StringArrayP("exclude", "", nil, "A space separated list of package names or slot atoms. Emerge won't  install any ebuild or binary package that matches any of the given package atoms.")
	pflag.BoolP("fail-clean", "", false, "clean temp files after build failure")
	pflag.BoolP("fuzzy-search", "", false, "Enable or disable fuzzy search")
	pflag.BoolP("getbinpkg", "g", false, "fetch binary packages")
	pflag.BoolP("getbinpkgonly", "G", false, "fetch binary packages only")
	pflag.BoolP("ignore-world", "", false, "ignore the @world package set and its dependencies")
	pflag.IntP("jobs", "", 0, "Specifies the number of packages to build simultaneously")
	pflag.BoolP("keep-going", "", false, "continue as much as possible after an error")
	pflag.Float64P("load-average", "", 0, "Specifies that no new builds should be started if there are other builds running and the load average is at least LOAD (a floating-point number).")
	pflag.BoolP("onlydeps-with-rdeps", "", false, "modify interpretation of depedencies")
	pflag.BoolP("package-moves", "", false, "perform package moves when necessary")
	pflag.BoolP("quiet", "q", false, "reduced or condensed output")
	pflag.BoolP("quiet-build", "", false, "redirect build output to logs")
	pflag.BoolP("quiet-fail", "", false, "suppresses display of the build log on stdout")
	pflag.BoolP("read-news", "", false, "offer to read unread news via eselect")
	pflag.BoolP("rebuild-if-new-slot", "", false, "Automatically rebuild or reinstall packages when slot/sub-slot :=operator dependencies can be satisfied by a newer slot, so that older packages slots will become eligible for removal by the --depclean action as soon as possible.")
	pflag.BoolP("rebuild-if-new-rev", "", false, "Rebuild packages when dependencies that are used at both build-time and run-time are built, if the dependency is not already installed with the same version and revision.")
	pflag.BoolP("rebuild-if-new-ver", "", false, "Rebuild packages when dependencies that are used at both build-time and run-time are built, if the dependency is not already installed with the same version. Revision numbers are ignored.")
	pflag.BoolP("rebuild-if-unbuilt", "", false, "Rebuild packages when dependencies that are used at both build-time and run-time are built.")
	pflag.BoolP("rebuilt-binaries", "", false, "replace installed packages with binary packages that have been rebuilt")
	pflag.StringP("rebuilt-binaries-timestamp", "", "", "use only binaries that are newer than this timestamp for --rebuilt-binaries")
	pflag.StringP("root", "", "", "specify the target root filesystem for merging packages")
	pflag.StringP("root-deps", "", "", "modify interpretation of depedencies")
	pflag.BoolP("search-index", "", false, "Enable or disable indexed search (enabled by default)")
	pflag.BoolP("select", "w", false, "add specified packages to the world set (inverse of --oneshot)")
	pflag.BoolP("selective", "", false, "identical to --noreplace")
	pflag.BoolP("use-ebuild-visibility", "", false, "")
	pflag.BoolP("usepkg", "", false, "")
	pflag.BoolP("usepkgonly", "", false, "")
	pflag.BoolP("verbose", "", false, "")
	pflag.BoolP("verbose-slot-rebuilds", "", false, "")
	pflag.BoolP("with-test-deps", "", false, "")

}
