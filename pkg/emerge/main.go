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

	valid_integers := func(s string) bool {
		i, err := strconv.Atoi(s)
		if err != nil {
			return false
		}
		return i >= 0
	}
	valid_floats := func(s string) bool {
		i, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return false
		}
		return i >= 0
	}
	y_or_n := func(s string) bool { return s == "y" || s == "n" }

	default_arg_opts := map[string]func(string) bool{
		"--alert":                         y_or_n,
		"--ask":                           y_or_n,
		"--autounmask":                    y_or_n,
		"--autounmask-continue":           y_or_n,
		"--autounmask-only":               y_or_n,
		"--autounmask-keep-keywords":      y_or_n,
		"--autounmask-keep-masks":         y_or_n,
		"--autounmask-unrestricted-atoms": y_or_n,
		"--autounmask-write":              y_or_n,
		"--binpkg-changed-deps":           y_or_n,
		"--buildpkg":                      y_or_n,
		"--changed-deps":                  y_or_n,
		"--changed-slot":                  y_or_n,
		"--changed-deps-report":           y_or_n,
		"--complete-graph":                y_or_n,
		"--deep":                          valid_integers,
		"--depclean-lib-check":            y_or_n,
		"--deselect":                      y_or_n,
		"--binpkg-respect-use":            y_or_n,
		"--fail-clean":                    y_or_n,
		"--fuzzy-search":                  y_or_n,
		"--getbinpkg":                     y_or_n,
		"--getbinpkgonly":                 y_or_n,
		"--ignore-world":                  y_or_n,
		"--jobs":                          valid_integers,
		"--keep-going":                    y_or_n,
		"--load-average":                  valid_floats,
		"--onlydeps-with-rdeps":           y_or_n,
		"--package-moves":                 y_or_n,
		"--quiet":                         y_or_n,
		"--quiet-build":                   y_or_n,
		"--quiet-fail":                    y_or_n,
		"--read-news":                     y_or_n,
		"--rebuild-if-new-slot":           y_or_n,
		"--rebuild-if-new-rev":            y_or_n,
		"--rebuild-if-new-ver":            y_or_n,
		"--rebuild-if-unbuilt":            y_or_n,
		"--rebuilt-binaries":              y_or_n,
		"--root-deps":                     func(s string) bool { return s == "rdeps" },
		"--select":                        y_or_n,
		"--selective":                     y_or_n,
		"--use-ebuild-visibility":         y_or_n,
		"--usepkg":                        y_or_n,
		"--usepkgonly":                    y_or_n,
		"--verbose":                       y_or_n,
		"--verbose-slot-rebuilds":         y_or_n,
		"--with-test-deps":                y_or_n,
	}
	for _, v := range args {
		arg_stack = append(arg_stack, v)
	}
	for len(arg_stack) > 0 {
		arg := arg_stack[len(arg_stack)-1]
		arg_stack = arg_stack[:len(arg_stack)-1]

		default_arg_choices := default_arg_opts[arg]
		if default_arg_choices != nil {
			new_args = append(new_args, arg)
			if len(arg_stack) > 0 && default_arg_choices(arg_stack[len(arg_stack)-1]) {
				new_args = append(new_args, arg_stack[len(arg_stack)-1])
				arg_stack = arg_stack[:len(arg_stack)-1]
			} else {
				new_args = append(new_args, "True")
			}
			continue
		}

		if arg[:1] != "-" || arg[:2] == "--" {
			new_args = append(new_args, arg)
			continue
		}

		short_arg_opts := map[string]func(string) bool{
			"D": valid_integers,
			"j": valid_integers,
		}
		match := ""
		var arg_choices func(string) bool
		for k, v := range short_arg_opts {
			if strings.Contains(arg, k) {
				match = k
				arg_choices = v
				break
			}
		}

		short_arg_opts_n := map[string]func(string) bool{
			"a": y_or_n,
			"A": y_or_n,
			"b": y_or_n,
			"g": y_or_n,
			"G": y_or_n,
			"k": y_or_n,
			"K": y_or_n,
			"q": y_or_n,
			"v": y_or_n,
			"w": y_or_n,
		}
		if match == "" {
			for k, v := range short_arg_opts_n {
				if strings.Contains(arg, k) {
					match = k
					arg_choices = v
					break
				}
			}
		}

		if match == "" {
			new_args = append(new_args, arg)
			continue
		}

		if len(arg) == 2 {
			new_args = append(new_args, arg)
			if len(arg_stack) > 0 && arg_choices(arg_stack[len(arg_stack)-1]) {
				new_args = append(new_args, arg_stack[len(arg_stack)-1])
				arg_stack = arg_stack[:len(arg_stack)-1]
			} else {
				new_args = append(new_args, "True")
			}
			continue
		}

		new_args = append(new_args, "-"+match)
		opt_arg := ""
		saved_opts := ""

		if arg[1:2] == match {
			if _, ok := short_arg_opts_n[match]; !ok && arg_choices(arg[2:]) {
				opt_arg = arg[2:]
			} else {
				saved_opts = arg[2:]
				opt_arg = "True"
			}
		} else {
			saved_opts = strings.ReplaceAll(arg[1:], match, "")
			opt_arg = "True"
		}

		if opt_arg == "" && len(arg_stack) > 0 && arg_choices(arg_stack[len(arg_stack)-1]) {
			opt_arg = arg_stack[len(arg_stack)-1]
			arg_stack = arg_stack[:len(arg_stack)-1]
		}

		if opt_arg == "" {
			new_args = append(new_args, "True")
		} else {
			new_args = append(new_args, opt_arg)
		}

		if saved_opts != "" {
			arg_stack = append(arg_stack, "-"+saved_opts)
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

	true_y := map[string]bool{"True": true, "y": true}
	pf := pflag.NewFlagSet("emerge", pflag.ExitOnError)

	var myoptions struct {
		// acitons
		clean, check_news, config, depclean, help, info, list_sets, metadata, moo, prune, rage_clean, regen, search, sync, unmerge, version bool
		// options
		alphabetical, ask_enter_invalid, buildpkgonly, changed_use, changelog, columns, debug, digest, emptytree, verbose_conflicts, fetchonly, fetch_all_uri, ignore_default_opts, noconfmem, newrepo, newuse, nodeps, noreplace, nospinner, oneshot, onlydeps, pretend, quiet_repo_display, quiet_unmerge_warn, resume, searchdesc, skipfirst, tree, unordered_display, update bool
		// argument
		alert, ask, autounmask, autounmask_backtrack, autounmask_continue, autounmask_only, autounmask_license, autounmask_unrestricted_atoms, autounmask_use, autounmask_keep_keywords, autounmask_keep_masks, autounmask_write, accept_properties, accept_restrict, backtrack, binpkg_changed_deps, buildpkg, buildpkg_exclude, changed_deps, changed_deps_report, changed_slot, config_root, color, complete_graph, complete_graph_if_new_use, complete_graph_if_new_ver, deep, depclean_lib_check, deselect, dynamic_deps, exclude, fail_clean, fuzzy_search, ignore_built_slot_operator_deps, ignore_soname_deps, ignore_world, implicit_system_deps, jobs, keep_going, load_average, misspell_suggestions, with_bdeps, with_bdeps_auto, reinstall, reinstall_atoms, binpkg_respect_use, getbinpkg, getbinpkgonly, usepkg_exclude, onlydeps_with_rdeps, rebuild_exclude, rebuild_ignore, package_moves, prefix, pkg_format, quickpkg_direct, quiet, quiet_build, quiet_fail, read_news, rebuild_if_new_slot, rebuild_if_new_rev, rebuild_if_new_ver, rebuild_if_unbuilt, rebuilt_binaries, rebuilt_binaries_timestamp, root, root_deps, search_index, search_similarity, selectt, selective, sync_submodule, sysroot, use_ebuild_visibility, useoldpkg_atoms, usepkg, usepkgonly, verbose, verbose_slot_rebuilds, with_test_deps string
	}
	// actions
	pf.BoolVarP(&myoptions.clean, "clean", "", false, "")
	pf.BoolVarP(&myoptions.check_news, "check-news", "", false, "")
	pf.BoolVarP(&myoptions.config, "config", "", false, "")
	pf.BoolVarP(&myoptions.depclean, "depclean", "c", false, "")
	pf.BoolVarP(&myoptions.help, "help", "h", false, "")
	pf.BoolVarP(&myoptions.info, "info", "", false, "")
	pf.BoolVarP(&myoptions.list_sets, "list-sets", "", false, "")
	pf.BoolVarP(&myoptions.metadata, "metadata", "", false, "")
	pf.BoolVarP(&myoptions.moo, "moo", "", false, "")
	pf.BoolVarP(&myoptions.prune, "prune", "P", false, "")
	pf.BoolVarP(&myoptions.rage_clean, "rage-clean", "", false, "")
	pf.BoolVarP(&myoptions.regen, "regen", "", false, "")
	pf.BoolVarP(&myoptions.search, "search", "s", false, "")
	pf.BoolVarP(&myoptions.sync, "sync", "", false, "")
	pf.BoolVarP(&myoptions.unmerge, "unmerge", "C", false, "")
	pf.BoolVarP(&myoptions.version, "version", "V", false, "")

	// options
	pf.BoolVarP(&myoptions.alphabetical, "alphabetical", "", false, "")
	pf.BoolVarP(&myoptions.ask_enter_invalid, "ask-enter-invalid", "", false, "")
	pf.BoolVarP(&myoptions.buildpkgonly, "buildpkgonly", "B", false, "")
	pf.BoolVarP(&myoptions.changed_use, "changed-use", "U", false, "")
	pf.BoolVarP(&myoptions.changelog, "changelog", "l", false, "")
	pf.BoolVarP(&myoptions.columns, "columns", "", false, "")
	pf.BoolVarP(&myoptions.debug, "debug", "d", false, "")
	pf.BoolVarP(&myoptions.digest, "digest", "", false, "")
	pf.BoolVarP(&myoptions.emptytree, "emptytree", "e", false, "")
	pf.BoolVarP(&myoptions.verbose_conflicts, "verbose-conflicts", "", false, "")
	pf.BoolVarP(&myoptions.fetchonly, "fetchonly", "f", false, "")
	pf.BoolVarP(&myoptions.fetch_all_uri, "fetch-all-uri", "F", false, "")
	pf.BoolVarP(&myoptions.ignore_default_opts, "ignore-default-opts", "", false, "")
	pf.BoolVarP(&myoptions.noconfmem, "noconfmem", "", false, "")
	pf.BoolVarP(&myoptions.newrepo, "newrepo", "", false, "")
	pf.BoolVarP(&myoptions.newuse, "newuse", "N", false, "")
	pf.BoolVarP(&myoptions.nodeps, "nodeps", "O", false, "")
	pf.BoolVarP(&myoptions.noreplace, "noreplace", "n", false, "")
	pf.BoolVarP(&myoptions.nospinner, "nospinner", "", false, "")
	pf.BoolVarP(&myoptions.oneshot, "oneshot", "1", false, "")
	pf.BoolVarP(&myoptions.onlydeps, "onlydeps", "o", false, "")
	pf.BoolVarP(&myoptions.pretend, "pretend", "p", false, "")
	pf.BoolVarP(&myoptions.quiet_repo_display, "quiet-repo-display", "", false, "")
	pf.BoolVarP(&myoptions.quiet_unmerge_warn, "quiet-unmerge-warn", "", false, "")
	pf.BoolVarP(&myoptions.resume, "resume", "r", false, "")
	pf.BoolVarP(&myoptions.searchdesc, "searchdesc", "S", false, "")
	pf.BoolVarP(&myoptions.skipfirst, "skipfirst", "", false, "")
	pf.BoolVarP(&myoptions.tree, "tree", "t", false, "")
	pf.BoolVarP(&myoptions.unordered_display, "unordered-display", "", false, "")
	pf.BoolVarP(&myoptions.update, "update", "u", false, "")

	// aliases
	pf.BoolVar(&myoptions.columns, "cols", false, "")
	pf.BoolVar(&myoptions.skipfirst, "skip-first", false, "")

	// argument
	pf.StringVarP(&myoptions.alert, "alert", "A", "", "alert (terminal bell) on prompts")
	pf.StringVarP(&myoptions.ask, "ask", "a", "", "prompt before performing any actions")
	pf.StringVarP(&myoptions.autounmask, "autounmask", "", "", "automatically unmask packages")
	pf.StringVarP(&myoptions.autounmask_backtrack, "autounmask-backtrack", "", "", "continue backtracking when there are autounmask configuration changes")
	pf.StringVarP(&myoptions.autounmask_continue, "autounmask-continue", "", "", "write autounmask changes and continue")
	pf.StringVarP(&myoptions.autounmask_only, "autounmask-only", "", "", "only perform --autounmask")
	pf.StringVarP(&myoptions.autounmask_license, "autounmask-license", "", "", "allow autounmask to change package.license")
	pf.StringVarP(&myoptions.autounmask_unrestricted_atoms, "autounmask-unrestricted-atoms", "", "", "write autounmask changes with >= atoms if possible")
	pf.StringVarP(&myoptions.autounmask_use, "autounmask-use", "", "", "allow autounmask to change package.use")
	pf.StringVarP(&myoptions.autounmask_keep_keywords, "autounmask-keep-keywords", "", "", "don't add package.accept_keywords entries")
	pf.StringVarP(&myoptions.autounmask_keep_masks, "autounmask-keep-masks", "", "", "don't add package.unmask entries")
	pf.StringVarP(&myoptions.autounmask_write, "autounmask-write", "", "", "write changes made by --autounmask to disk")
	pf.StringVarP(&myoptions.accept_properties, "accept-properties", "", "", "temporarily override ACCEPT_PROPERTIES")
	pf.StringVarP(&myoptions.accept_restrict, "accept-restrict", "", "", "temporarily override ACCEPT_RESTRICT")
	pf.StringVarP(&myoptions.backtrack, "backtrack", "", "", "Specifies how many times to backtrack if dependency calculation fails")
	pf.StringVarP(&myoptions.binpkg_changed_deps, "binpkg-changed-deps", "", "", "reject binary packages with outdated dependencies")
	pf.StringVarP(&myoptions.buildpkg, "buildpkg", "b", "", "build binary packages")
	pf.StringVarP(&myoptions.buildpkg_exclude, "buildpkg-exclude", "", "", "A space separated list of package atoms for which no binary packages should be built. This option overrides all possible ways to enable building of binary packages.")
	pf.StringVarP(&myoptions.changed_deps, "changed-deps", "", "", "replace installed packages with outdated dependencies")
	pf.StringVarP(&myoptions.changed_deps_report, "changed-deps-report", "", "", "report installed packages with outdated dependencies")
	pf.StringVarP(&myoptions.changed_slot, "changed-slot", "", "", "replace installed packages with outdated SLOT metadata")
	pf.StringVarP(&myoptions.config_root, "config-root", "", "", "specify the location for portage configuration files")
	pf.StringVarP(&myoptions.color, "color", "", "", "enable or disable color output")
	pf.StringVarP(&myoptions.complete_graph, "complete-graph", "", "", "completely account for all known dependencies")
	pf.StringVarP(&myoptions.complete_graph_if_new_use, "complete-graph-if-new-use", "", "", "trigger --complete-graph behavior if USE or IUSE will change for an installed package")
	pf.StringVarP(&myoptions.complete_graph_if_new_ver, "complete-graph-if-new-ver", "", "", "trigger --complete-graph behavior if an installed package version will change (upgrade or downgrade)")
	pf.StringVarP(&myoptions.deep, "deep", "D", "", "Specifies how deep to recurse into dependencies of packages given as arguments. If no argument is given, depth is unlimited. Default behavior is to skip dependencies of installed packages.")
	pf.StringVarP(&myoptions.depclean_lib_check, "depclean-lib-check", "", "", "check for consumers of libraries before removing them")
	pf.StringVarP(&myoptions.deselect, "deselect", "", "", "deselect")
	pf.StringVarP(&myoptions.dynamic_deps, "dynamic-deps", "", "", "substitute the dependencies of installed packages with the dependencies of unbuilt ebuilds")
	pf.StringVarP(&myoptions.exclude, "exclude", "", "", "A space separated list of package names or slot atoms. Emerge won't install any ebuild or binary package that matches any of the given package atoms.")
	pf.StringVarP(&myoptions.fail_clean, "fail-clean", "", "", "clean temp files after build failure")
	pf.StringVarP(&myoptions.fuzzy_search, "fuzzy-search", "", "", "Enable or disable fuzzy search")
	pf.StringVarP(&myoptions.ignore_built_slot_operator_deps, "ignore-built-slot-operator-deps", "", "", "Ignore the slot/sub-slot := operator parts of dependencies that have been recorded when packages where built. This option is intended only for debugging purposes, and it only affects built packages that specify slot/sub-slot := operator dependencies using the experimental \"4-slot-abi\" EAPI.")
	pf.StringVarP(&myoptions.ignore_soname_deps, "ignore-soname-deps", "", "", "Ignore the soname dependencies of binary and installed packages. This option is enabled by default, since soname dependencies are relatively new, and the required metadata is not guaranteed to exist for binary and installed packages built with older versions of portage.")
	pf.StringVarP(&myoptions.ignore_world, "ignore-world", "", "", "ignore the @world package set and its dependencies")
	pf.StringVarP(&myoptions.implicit_system_deps, "implicit-system-deps", "", "", "Assume that packages may have implicit dependencies on packages which belong to the @system set")
	pf.StringVarP(&myoptions.jobs, "jobs", "j", "", "Specifies the number of packages to build simultaneously.")
	pf.StringVarP(&myoptions.keep_going, "keep-going", "", "", "continue as much as possible after an error")
	pf.StringVarP(&myoptions.load_average, "load-average", "", "", "Specifies that no new builds should be started if there are other builds running and the load average is at least LOAD (a floating-point number).")
	pf.StringVarP(&myoptions.misspell_suggestions, "misspell-suggestions", "", "", "enable package name misspell suggestions")
	pf.StringVarP(&myoptions.with_bdeps, "with-bdeps", "", "", "include unnecessary build time dependencies")
	pf.StringVarP(&myoptions.with_bdeps_auto, "with-bdeps-auto", "", "", "automatically enable --with-bdeps for installation actions, unless --usepkg is enabled")
	pf.StringVarP(&myoptions.reinstall, "reinstall", "", "", "specify conditions to trigger package reinstallation")
	pf.StringVarP(&myoptions.reinstall_atoms, "reinstall-atoms", "", "", "A space separated list of package names or slot atoms. Emerge will treat matching packages as if they are not installed, and reinstall them if necessary. Implies --deep.")
	pf.StringVarP(&myoptions.binpkg_respect_use, "binpkg-respect-use", "", "", "discard binary packages if their use flags don't match the current configuration")
	pf.StringVarP(&myoptions.getbinpkg, "getbinpkg", "g", "", "fetch binary packages")
	pf.StringVarP(&myoptions.getbinpkgonly, "getbinpkgonly", "G", "", "fetch binary packages only")
	pf.StringVarP(&myoptions.usepkg_exclude, "usepkg-exclude", "", "", "A space separated list of package names or slot atoms. Emerge will ignore matching binary packages.")
	pf.StringVarP(&myoptions.onlydeps_with_rdeps, "onlydeps-with-rdeps", "", "", "modify interpretation of depedencies")
	pf.StringVarP(&myoptions.rebuild_exclude, "rebuild-exclude", "", "", "A space separated list of package names or slot atoms. Emerge will not rebuild these packages due to the --rebuild flag.")
	pf.StringVarP(&myoptions.rebuild_ignore, "rebuild-ignore", "", "", "A space separated list of package names or slot atoms. Emerge will not rebuild packages that depend on matching packages due to the --rebuild flag.")
	pf.StringVarP(&myoptions.package_moves, "package-moves", "", "", "perform package moves when necessary")
	pf.StringVarP(&myoptions.prefix, "prefix", "", "", "specify the installation prefix")
	pf.StringVarP(&myoptions.pkg_format, "pkg-format", "", "", "format of result binary package")
	pf.StringVarP(&myoptions.quickpkg_direct, "quickpkg-direct", "", "", "Enable use of installed packages directly as binary packages")
	pf.StringVarP(&myoptions.quiet, "quiet", "q", "", "reduced or condensed output")
	pf.StringVarP(&myoptions.quiet_build, "quiet-build", "", "", "redirect build output to logs")
	pf.StringVarP(&myoptions.quiet_fail, "quiet-fail", "", "", "suppresses display of the build log on stdout")
	pf.StringVarP(&myoptions.read_news, "read-news", "", "", "offer to read unread news via eselect")
	pf.StringVarP(&myoptions.rebuild_if_new_slot, "rebuild-if-new-slot", "", "", "Automatically rebuild or reinstall packages when slot/sub-slot := operator dependencies can be satisfied by a newer slot, so that older packages slots will become eligible for removal by the --depclean action as soon as possible.")
	pf.StringVarP(&myoptions.rebuild_if_new_rev, "rebuild-if-new-rev", "", "", "Rebuild packages when dependencies that are used at both build-time and run-time are built, if the dependency is not already installed with the same version and revision.")
	pf.StringVarP(&myoptions.rebuild_if_new_ver, "rebuild-if-new-ver", "", "", "Rebuild packages when dependencies that are used at both build-time and run-time are built, if the dependency is not already installed with the same version. Revision numbers are ignored.")
	pf.StringVarP(&myoptions.rebuild_if_unbuilt, "rebuild-if-unbuilt", "", "", "Rebuild packages when dependencies that are used at both build-time and run-time are built.")
	pf.StringVarP(&myoptions.rebuilt_binaries, "rebuilt-binaries", "", "", "replace installed packages with binary packages that have been rebuilt")
	pf.StringVarP(&myoptions.rebuilt_binaries_timestamp, "rebuilt-binaries-timestamp", "", "", "use only binaries that are newer than this timestamp for --rebuilt-binaries")
	pf.StringVarP(&myoptions.root, "root", "", "", "specify the target root filesystem for merging packages")
	pf.StringVarP(&myoptions.root_deps, "root-deps", "", "", "modify interpretation of depedencies")
	pf.StringVarP(&myoptions.search_index, "search-index", "", "", "Enable or disable indexed search (enabled by default)")
	pf.StringVarP(&myoptions.search_similarity, "search-similarity", "", "", "Set minimum similarity percentage for fuzzy seach (a floating-point number between 0 and 100)")
	pf.StringVarP(&myoptions.selectt, "select", "w", "", "add specified packages to the world set (inverse of --oneshot)")
	pf.StringVarP(&myoptions.selective, "selective", "", "", "identical to --noreplace")
	pf.StringVarP(&myoptions.sync_submodule, "sync-submodule", "", "", "Restrict sync to the specified submodule(s). (--sync action only)")
	pf.StringVarP(&myoptions.sysroot, "sysroot", "", "", "specify the location for build dependencies specified in DEPEND")
	pf.StringVarP(&myoptions.use_ebuild_visibility, "use-ebuild-visibility", "", "", "use unbuilt ebuild metadata for visibility checks on built packages")
	pf.StringVarP(&myoptions.useoldpkg_atoms, "useoldpkg-atoms", "", "", "A space separated list of package names or slot atoms. Emerge will prefer matching binary packages over newer unbuilt packages.")
	pf.StringVarP(&myoptions.usepkg, "usepkg", "k", "", "use binary packages")
	pf.StringVarP(&myoptions.usepkgonly, "usepkgonly", "K", "", "use only binary packages")
	pf.StringVarP(&myoptions.verbose, "verbose", "v", "", "verbose output")
	pf.StringVarP(&myoptions.verbose_slot_rebuilds, "verbose-slot-rebuilds", "", "", "verbose slot rebuild output")
	pf.StringVarP(&myoptions.with_test_deps, "with-test-deps", "", "", "pull in test deps for packages matched by arguments")

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
	for _, v := range []string{"help", "info", "search", "sync", "version"} {
		if myaction == v {
			return syscall.F_OK
		}
	}
	for root_trees := range trees.values() {
		if (root_trees["root_config"].settings.profiles && 'ARCH' in
		root_trees["root_config"].settings){
			continue
		}
		validate_ebuild_environment(trees)
		msg := "Your current profile is invalid. If you have just changed " +
			"your profile configuration, you should revert back to the " +
			"previous configuration. Allowed actions are limited to " +
			"--help, --info, --search, --sync, and --version."

		m := ""
		for _, l := range emaint.SplitSubN(msg, 70) {
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
