package atom

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/ppphp/shlex"

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
		atom, err := NewAtom(at, nil, true, &less_strict, nil, "", nil, nil)
		if err != nil {
			//except portage.exception.InvalidAtom:
			bad_atom = true
		}

		if bad_atom || (atom.Operator != "" && !less_strict) || atom.Blocker != nil || atom.Use != nil {
			bad_atoms = append(bad_atoms, x)
		}
	}
	return bad_atoms
}

// true
func ParseOpts(tmpcmdline []string, silent bool) (string, map[string]string, []string) { // false

	true_y := func(s string) bool {
		return s == "True" || s == "y"
	}
	pf := pflag.NewFlagSet("emerge", pflag.ExitOnError)

	var myoptions struct {
		// acitons
		clean, check_news, config, depclean, help, info, list_sets, metadata, moo, prune, rage_clean, regen, search, sync, unmerge, version bool
		// options
		alphabetical, ask_enter_invalid, buildpkgonly, changed_use, changelog, columns, debug, digest, emptytree, verbose_conflicts, fetchonly, fetch_all_uri, ignore_default_opts, noconfmem, newrepo, newuse, nodeps, noreplace, nospinner, oneshot, onlydeps, pretend, quiet_repo_display, quiet_unmerge_warn, resume, searchdesc, skipfirst, tree, unordered_display, update bool
		// argument
		alert, ask, autounmask, autounmask_backtrack, autounmask_continue, autounmask_only, autounmask_license, autounmask_unrestricted_atoms, autounmask_use, autounmask_keep_keywords, autounmask_keep_masks, autounmask_write, accept_properties, accept_restrict, backtrack, binpkg_changed_deps, buildpkg, changed_deps, changed_deps_report, changed_slot, config_root, color, complete_graph, complete_graph_if_new_use, complete_graph_if_new_ver, deep, depclean_lib_check, deselect, dynamic_deps, fail_clean, fuzzy_search, ignore_built_slot_operator_deps, ignore_soname_deps, ignore_world, implicit_system_deps, jobs, keep_going, load_average, misspell_suggestions, with_bdeps, with_bdeps_auto, reinstall, binpkg_respect_use, getbinpkg, getbinpkgonly, onlydeps_with_rdeps, package_moves, prefix, pkg_format, quickpkg_direct, quiet, quiet_build, quiet_fail, read_news, rebuild_if_new_slot, rebuild_if_new_rev, rebuild_if_new_ver, rebuild_if_unbuilt, rebuilt_binaries, rebuilt_binaries_timestamp, root, root_deps, search_index, search_similarity, selectt, selective, sysroot, use_ebuild_visibility, usepkg, usepkgonly, verbose, verbose_slot_rebuilds, with_test_deps string
		buildpkg_exclude, exclude, reinstall_atoms, sync_submodule, useoldpkg_atoms, rebuild_exclude, rebuild_ignore, usepkg_exclude                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    []string
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
	pf.StringArrayVarP(&myoptions.buildpkg_exclude, "buildpkg-exclude", "", nil, "A space separated list of package atoms for which no binary packages should be built. This option overrides all possible ways to enable building of binary packages.")
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
	pf.StringArrayVarP(&myoptions.exclude, "exclude", "", nil, "A space separated list of package names or slot atoms. Emerge won't install any ebuild or binary package that matches any of the given package atoms.")
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
	pf.StringArrayVarP(&myoptions.reinstall_atoms, "reinstall-atoms", "", nil, "A space separated list of package names or slot atoms. Emerge will treat matching packages as if they are not installed, and reinstall them if necessary. Implies --deep.")
	pf.StringVarP(&myoptions.binpkg_respect_use, "binpkg-respect-use", "", "", "discard binary packages if their use flags don't match the current configuration")
	pf.StringVarP(&myoptions.getbinpkg, "getbinpkg", "g", "", "fetch binary packages")
	pf.StringVarP(&myoptions.getbinpkgonly, "getbinpkgonly", "G", "", "fetch binary packages only")
	pf.StringArrayVarP(&myoptions.usepkg_exclude, "usepkg-exclude", "", nil, "A space separated list of package names or slot atoms. Emerge will ignore matching binary packages.")
	pf.StringVarP(&myoptions.onlydeps_with_rdeps, "onlydeps-with-rdeps", "", "", "modify interpretation of depedencies")
	pf.StringArrayVarP(&myoptions.rebuild_exclude, "rebuild-exclude", "", nil, "A space separated list of package names or slot atoms. Emerge will not rebuild these packages due to the --rebuild flag.")
	pf.StringArrayVarP(&myoptions.rebuild_ignore, "rebuild-ignore", "", nil, "A space separated list of package names or slot atoms. Emerge will not rebuild packages that depend on matching packages due to the --rebuild flag.")
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
	pf.StringArrayVarP(&myoptions.sync_submodule, "sync-submodule", "", nil, "Restrict sync to the specified submodule(s). (--sync action only)")
	pf.StringVarP(&myoptions.sysroot, "sysroot", "", "", "specify the location for build dependencies specified in DEPEND")
	pf.StringVarP(&myoptions.use_ebuild_visibility, "use-ebuild-visibility", "", "", "use unbuilt ebuild metadata for visibility checks on built packages")
	pf.StringArrayVarP(&myoptions.useoldpkg_atoms, "useoldpkg-atoms", "", nil, "A space separated list of package names or slot atoms. Emerge will prefer matching binary packages over newer unbuilt packages.")
	pf.StringVarP(&myoptions.usepkg, "usepkg", "k", "", "use binary packages")
	pf.StringVarP(&myoptions.usepkgonly, "usepkgonly", "K", "", "use only binary packages")
	pf.StringVarP(&myoptions.verbose, "verbose", "v", "", "verbose output")
	pf.StringVarP(&myoptions.verbose_slot_rebuilds, "verbose-slot-rebuilds", "", "", "verbose slot rebuild output")
	pf.StringVarP(&myoptions.with_test_deps, "with-test-deps", "", "", "pull in test deps for packages matched by arguments")

	tmpcmdline = insert_optional_args(tmpcmdline)

	pf.Parse(tmpcmdline)

	myopt := map[string]string{}

	if true_y(myoptions.alert) {
		myopt["--alert"] = "true"
	}
	if true_y(myoptions.ask) {
		myopt["--ask"] = "true"
	}
	if true_y(myoptions.autounmask) {
		myopt["--autounmask"] = "true"
	} else {
		myopt["--autounmask"] = "false"
	}
	if true_y(myoptions.autounmask_continue) {
		myopt["--autounmask-continue"] = "true"
	} else {
		myopt["--autounmask-continue"] = "false"
	}
	if true_y(myoptions.autounmask_only) {
		myopt["--autounmask-only"] = "true"
	}
	if true_y(myoptions.autounmask_unrestricted_atoms) {
		myopt["--autounmask-unrestricted-atoms"] = "true"
	} else {
		myopt["--autounmask-unrestricted-atoms"] = "false"
	}
	if true_y(myoptions.autounmask_keep_keywords) {
		myopt["--autounmask-keep-keywords"] = "true"
	} else {
		myopt["--autounmask-keep-keywords"] = "false"
	}
	if true_y(myoptions.autounmask_keep_masks) {
		myopt["--autounmask-keep-masks"] = "true"
	} else {
		myopt["--autounmask-keep-masks"] = "false"
	}
	if true_y(myoptions.autounmask_write) {
		myopt["--autounmask-write"] = "true"
	} else {
		myopt["--autounmask-write"] = "false"
	}
	if myoptions.binpkg_changed_deps != "" {
		if true_y(myoptions.binpkg_changed_deps) {
			myopt["--binpkg-changed-deps"] = "y"
		} else {
			myopt["--binpkg-changed-deps"] = "n"
		}
	}
	if true_y(myoptions.buildpkg) {
		myopt["--buildpkg"] = "true"
	} else {
		myopt["--buildpkg"] = "false"
	}

	if len(myoptions.buildpkg_exclude) > 0 {
		bad_atoms := _find_bad_atoms(myoptions.buildpkg_exclude, true)
		if len(bad_atoms) > 0 && !silent {
			//parser.error("Invalid Atom(s) in --buildpkg-exclude parameter: '%s'\n" % \
			//(",".join(bad_atoms),))
		}
	}

	if true_y(myoptions.changed_deps) {
		myopt["--changed-deps"] = "y"
	} else if myoptions.changed_deps != "" {
		myopt["--changed-deps"] = "n"
	}
	if true_y(myoptions.changed_deps_report) {
		myopt["--changed-deps-report"] = "y"
	} else if myoptions.changed_deps_report != "" {
		myopt["--changed-deps-report"] = "n"
	}
	if true_y(myoptions.changed_slot) {
		myopt["--changed-slot"] = "y"
	} else if myoptions.changed_slot != "" {
		myopt["--changed-slot"] = "n"
	}
	if myoptions.changed_use {
		myopt["--reinstall"] = "changed-use"
		myopt["--changed-use"] = "false"
	}
	if true_y(myoptions.deselect) {
		myopt["--deselect"] = "true"
	}

	if myoptions.binpkg_respect_use != "" {
		if true_y(myoptions.binpkg_respect_use) {
			myopt["--binpkg-respect-use"] = "y"
		} else {
			myopt["--binpkg-respect-use"] = "n"
		}
	}

	if true_y(myoptions.complete_graph) {
		myopt["--complete-graph"] = "true"
	}

	if true_y(myoptions.depclean_lib_check) {
		myopt["--depclean-lib-check"] = "true"
	} else {
		myopt["--depclean-lib-check"] = "false"
	}

	if len(myoptions.exclude) > 0 {
		bad_atoms := _find_bad_atoms(myoptions.exclude, false)
		if len(bad_atoms) > 0 && !silent {
			os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid Atom(s) in --exclude parameter: '%s' (only package names and slot atoms (with wildcards) allowed)\n", strings.Join(bad_atoms, ",")))))
			os.Exit(2)
		}
	}

	if len(myoptions.reinstall_atoms) > 0 {
		bad_atoms := _find_bad_atoms(myoptions.reinstall_atoms, false)
		if len(bad_atoms) > 0 && !silent {
			os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid Atom(s) in --reinstall-atoms parameter: '%s' (only package names and slot atoms (with wildcards) allowed)\n", strings.Join(bad_atoms, ",")))))
			os.Exit(2)
		}
	}

	if len(myoptions.rebuild_exclude) > 0 {
		bad_atoms := _find_bad_atoms(myoptions.rebuild_exclude, false)
		if len(bad_atoms) > 0 && !silent {
			os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid Atom(s) in --rebuild-exclude parameter: '%s' (only package names and slot atoms (with wildcards) allowed)\n", strings.Join(bad_atoms, ",")))))
			os.Exit(2)
		}
	}

	if len(myoptions.rebuild_ignore) > 0 {
		bad_atoms := _find_bad_atoms(myoptions.rebuild_ignore, false)
		if len(bad_atoms) > 0 && !silent {
			os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid Atom(s) in --rebuild-ignore parameter: '%s' (only package names and slot atoms (with wildcards) allowed)\n", strings.Join(bad_atoms, ",")))))
			os.Exit(2)
		}
	}

	if len(myoptions.usepkg_exclude) > 0 {
		bad_atoms := _find_bad_atoms(myoptions.usepkg_exclude, false)
		if len(bad_atoms) > 0 && !silent {
			os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid Atom(s) in --usepkg-exclude parameter: '%s' (only package names and slot atoms (with wildcards) allowed)\n", strings.Join(bad_atoms, ",")))))
			os.Exit(2)
		}
	}

	if len(myoptions.useoldpkg_atoms) > 0 {
		bad_atoms := _find_bad_atoms(myoptions.useoldpkg_atoms, false)
		if len(bad_atoms) > 0 && !silent {
			os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid Atom(s) in --useoldpkg-atoms parameter: '%s' (only package names and slot atoms (with wildcards) allowed)\n", strings.Join(bad_atoms, ",")))))
			os.Exit(2)
		}
	}

	if true_y(myoptions.fail_clean) {
		myopt["--fail-clean"] = "true"
	} else {
		myopt["--fail-clean"] = "false"
	}

	if true_y(myoptions.fuzzy_search) {
		myopt["--fuzzy-search"] = "true"
	} else {
		myopt["--fuzzy-search"] = "false"
	}

	if true_y(myoptions.getbinpkg) {
		myopt["--getbinpkg"] = "true"
	}

	if true_y(myoptions.getbinpkgonly) {
		myopt["--getbinpkgonly"] = "true"
	}

	if true_y(myoptions.ignore_world) {
		myopt["--ignore-world"] = "true"
	} else {
		myopt["--ignore-world"] = "false"
	}

	if true_y(myoptions.keep_going) {
		myopt["--keep-going"] = "true"
	}

	if true_y(myoptions.package_moves) {
		myopt["--package-moves"] = "true"
	} else {
		myopt["--package-moves"] = "false"
	}

	if true_y(myoptions.quiet) {
		myopt["--quiet"] = "true"
	}

	if true_y(myoptions.quiet_build) {
		myopt["--quiet-build"] = "y"
	} else {
		myopt["--quiet-build"] = "n"
	}

	if true_y(myoptions.quiet_fail) {
		myopt["--quiet-fail"] = "y"
	} else {
		myopt["--quiet-fail"] = "n"
	}

	if true_y(myoptions.read_news) {
		myopt["--read-news"] = "true"
	}

	if true_y(myoptions.rebuild_if_new_slot) {
		myopt["--rebuild-if-new-slot"] = "y"
	} else {
		myopt["--rebuild-if-new-slot"] = "n"
	}

	if true_y(myoptions.rebuild_if_new_ver) {
		myopt["--rebuild-if-new-ver"] = "true"
	}

	if true_y(myoptions.rebuild_if_new_rev) {
		myopt["--rebuild-if-new-rev"] = "true"
		delete(myopt, "rebuild-if-new-ver")
	}

	if true_y(myoptions.rebuild_if_unbuilt) {
		myopt["--rebuild-if-unbuilt"] = "true"
		delete(myopt, "rebuild-if-new-rev")
		delete(myopt, "rebuild-if-new-ver")
	}

	if true_y(myoptions.rebuilt_binaries) {
		myopt["--rebuilt-binaries"] = "true"
	} else {
		myopt["--rebuilt-binaries"] = "false"
	}

	if true_y(myoptions.root_deps) {
		myopt["--root-deps"] = "true"
	} else {
		myopt["--root-deps"] = "false"
	}

	if true_y(myoptions.selectt) {
		myopt["--select"] = "true"
		myopt["--oneshot"] = "false"
	} else if myopt["--select"] == "n" {
		myopt["--oneshot"] = "true"
	}

	if true_y(myoptions.selective) {
		myopt["--selective"] = "true"
	} else {
		myopt["--selective"] = "false"
	}

	if myoptions.backtrack != "" {
		backtrack, err := strconv.Atoi(myoptions.backtrack)
		if err != nil {
			//except(OverflowError, ValueError):
			backtrack = -1
		}
		if backtrack < 0 {
			if !silent {
				os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid --backtrack parameter: '%s'\n", myoptions.backtrack))))
				os.Exit(2)
			}
		} else {
			myopt["--backtrack"] = fmt.Sprint(backtrack)
		}
	}

	if myoptions.deep != "" {
		db := false
		di := 0
		if myoptions.deep == "true" {
			db = true
		} else {
			deep, err := strconv.Atoi(myoptions.deep)
			di = deep
			if err != nil {
				//except (OverflowError, ValueError){
				di = -1
			}
		}

		if !db && di < 0 {
			if !silent {
				os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid --deep parameter: '%s'\n", myoptions.deep))))
				os.Exit(2)
			}
		} else {
			if db {
				myopt["--deep"] = fmt.Sprint(db)
			} else {
				myopt["--deep"] = fmt.Sprint(di)
			}
		}
	}

	if myoptions.jobs != "" {
		ji := 0
		jb := false
		if myoptions.jobs == "true" {
			jb = true
		} else {
			jobs, err := strconv.Atoi(myoptions.jobs)
			ji = jobs
			if err != nil {
				//except ValueError{
				ji = -1
			}
		}

		if !jb && ji < 1 {
			if !silent {
				os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid --jobs parameter: '%s'\n", myoptions.jobs))))
				os.Exit(2)
			}
		} else {
			if jb {
				myopt["--jobs"] = fmt.Sprint(jb)
			} else {
				myopt["--jobs"] = fmt.Sprint(ji)
			}
		}
	}

	if myoptions.load_average == "true" {
		delete(myopt, "load-average")
	}

	if myoptions.load_average != "" {
		load_average, err := strconv.ParseFloat(myoptions.load_average, 64)
		if err != nil {
			//except ValueError{
			load_average = 0.0
		}

		if load_average <= 0.0 {
			if !silent {
				os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid --load-average parameter: '%s'\n", myoptions.load_average))))
				os.Exit(2)
			}
		} else {
			myopt["--load-average"] = fmt.Sprint(load_average)
		}
	}

	if myoptions.rebuilt_binaries_timestamp != "" {
		rebuilt_binaries_timestamp, err := strconv.Atoi(myoptions.rebuilt_binaries_timestamp)
		if err != nil {
			//except ValueError{
			rebuilt_binaries_timestamp = -1
		}
		if rebuilt_binaries_timestamp < 0 {
			rebuilt_binaries_timestamp = 0
			if !silent {
				os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid --rebuilt-binaries-timestamp parameter: '%s'\n", myoptions.rebuilt_binaries_timestamp))))
				os.Exit(2)
			}
		} else {
			myopt["--rebuilt-binaries-timestamp"] = fmt.Sprint(rebuilt_binaries_timestamp)
		}
	}

	if myoptions.search_similarity != "" {
		search_similarity, err := strconv.ParseFloat(myoptions.search_similarity, 64)
		if err != nil {
			//except ValueError{
			os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid --search-similarity parameter (not a number): '%v'\n", myoptions.search_similarity))))
			os.Exit(2)
		}

		if search_similarity < 0 || search_similarity > 100 {
			os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], fmt.Sprintf("Invalid --search-similarity parameter (not between 0 and 100): '%v'\n", myoptions.search_similarity))))
			os.Exit(2)
		} else {
			myopt["--search-similarity"] = fmt.Sprint(search_similarity)
		}
	}

	if true_y(myoptions.use_ebuild_visibility) {
		myopt["--use-ebuild-visibility"] = "true"
	} else {
		myopt["--use-ebuild-visibility"] = "false"
	}
	if true_y(myoptions.usepkg) {
		myopt["--usepkg"] = "true"
	}
	if true_y(myoptions.usepkgonly) {
		myopt["--usepkgonly"] = "true"
	}
	if true_y(myoptions.verbose) {
		myopt["--verbose"] = "true"
	}
	if true_y(myoptions.with_test_deps) {
		myopt["--with-test-deps"] = "true"
	}
	myaction := ""
	if myoptions.clean {
		if myaction != "" {
			multipleActions(myaction, "clean")
			os.Exit(1)
		}
		myaction = "clean"
	}
	if myoptions.check_news {
		if myaction != "" {
			multipleActions(myaction, "check-news")
			os.Exit(1)
		}
		myaction = "check-news"
	}
	if myoptions.config {
		if myaction != "" {
			multipleActions(myaction, "config")
			os.Exit(1)
		}
		myaction = "config"
	}
	if myoptions.depclean {
		if myaction != "" {
			multipleActions(myaction, "depclean")
			os.Exit(1)
		}
		myaction = "depclean"
	}
	if myoptions.help {
		if myaction != "" {
			multipleActions(myaction, "help")
			os.Exit(1)
		}
		myaction = "help"
	}
	if myoptions.info {
		if myaction != "" {
			multipleActions(myaction, "info")
			os.Exit(1)
		}
		myaction = "info"
	}
	if myoptions.list_sets {
		if myaction != "" {
			multipleActions(myaction, "list-sets")
			os.Exit(1)
		}
		myaction = "list-sets"
	}
	if myoptions.metadata {
		if myaction != "" {
			multipleActions(myaction, "metadata")
			os.Exit(1)
		}
		myaction = "metadata"
	}
	if myoptions.moo {
		if myaction != "" {
			multipleActions(myaction, "moo")
			os.Exit(1)
		}
		myaction = "moo"
	}
	if myoptions.prune {
		if myaction != "" {
			multipleActions(myaction, "prune")
			os.Exit(1)
		}
		myaction = "prune"
	}
	if myoptions.rage_clean {
		if myaction != "" {
			multipleActions(myaction, "rage-clean")
			os.Exit(1)
		}
		myaction = "rage-clean"
	}
	if myoptions.regen {
		if myaction != "" {
			multipleActions(myaction, "regen")
			os.Exit(1)
		}
		myaction = "regen"
	}
	if myoptions.search {
		if myaction != "" {
			multipleActions(myaction, "search")
			os.Exit(1)
		}
		myaction = "search"
	}
	if myoptions.sync {
		if myaction != "" {
			multipleActions(myaction, "sync")
			os.Exit(1)
		}
		myaction = "sync"
	}
	if myoptions.unmerge {
		if myaction != "" {
			multipleActions(myaction, "unmerge")
			os.Exit(1)
		}
		myaction = "unmerge"
	}
	if myoptions.version {
		if myaction != "" {
			multipleActions(myaction, "version")
			os.Exit(1)
		}
		myaction = "version"
	}
	if myaction == "" && myoptions.deselect != "" {
		myaction = "deselect"
	}

	return myaction, myopt, pf.Args()
}

//func profile_check(trees *atom.TreesDict, myaction string) int {
//	for _, v := range []string{"help", "info", "search", "sync", "version"} {
//		if myaction == v {
//			return syscall.F_OK
//		}
//	}
//	for _, root_trees := range trees.Values() {
//		if _, ok := root_trees["root_config"].settings.Value["ARCH"]; root_trees["root_config"].settings.profiles && ok {
//			continue
//		}
//		validate_ebuild_environment(trees)
//		msg := "Your current profile is invalid. If you have just changed " +
//			"your profile configuration, you should revert back to the " +
//			"previous configuration. Allowed actions are limited to " +
//			"--help, --info, --search, --sync, and --version."
//
//		m := ""
//		for _, l := range emaint.SplitSubN(msg, 70) {
//			m += fmt.Sprintf("!!! %s\n", l)
//		}
//		atom.WriteMsgLevel(m, 40, -1)
//		return 1
//	}
//	return syscall.F_OK
//}

func EmergeMain(args []string) int { // nil
	if args == nil {
		args = os.Args[1:]
	}
	// TODO: set locale
	HaveColor = 0

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
	case "help":
		emergeHelp()
		return 0
	case "moo":
		fmt.Printf(COWSAY_MOO, runtime.GOOS)
		return 0
	case "sync":
		SyncMode = true
	}
	dnst, err := os.Stat(os.DevNull)
	if err != nil {
		WriteMsgLevel("Failed to validate a sane '/dev'.\n"+
			"'/dev/null' does not exist.\n",
			40, -1)
		return 1
	}
	if dnst.Sys().(syscall.Stat_t).Rdev == 0 {
		WriteMsgLevel("Failed to validate a sane '/dev'.\n"+
			"'/dev/null' is not a device file.\n",
			40, -1)
		return 1
	}
	devNull, err := os.Open(os.DevNull)
	fd_pipes := map[int]int{
		0: int(devNull.Fd()),
		1: int(devNull.Fd()),
		2: int(devNull.Fd()),
	}
	if pids, err := spawn_bash("[[ $(< <(echo foo) ) == foo ]]", false, "", fd_pipes); err == nil || (len(pids) > 0 && pids[0] != 0) {
		WriteMsgLevel("Failed to validate a sane '/dev'.\n"+
			"bash process substitution doesn't work; this may be an "+
			"indication of a broken '/dev/fd'.\n",
			40, -1)
		return 1
	}
	if devNull != nil {
		devNull.Close()
	}
	syscall.Umask(022)

	emergeConfig := LoadEmergeConfig(nil, nil, myAction, myFiles, myOpts)
	for _, locale_var_name := range []string{"LANGUAGE", "LC_ALL", "LC_ADDRESS", "LC_COLLATE", "LC_CTYPE",
		"LC_IDENTIFICATION", "LC_MEASUREMENT", "LC_MESSAGES", "LC_MONETARY",
		"LC_NAME", "LC_NUMERIC", "LC_PAPER", "LC_TELEPHONE", "LC_TIME", "LANG"} {
		locale_var_value := emergeConfig.runningConfig.Settings.ValueDict[locale_var_name]
		if locale_var_value != "" {
			if os.Getenv(locale_var_name) == "" {
				os.Setenv(locale_var_name, locale_var_value)
			}
		}
	}
	//try:
	//	locale.setlocale(locale.LC_ALL, "")
	//	except locale.Error as e:
	//	writemsg_level("setlocale: %s\n" % e, level=logging.WARN)
	//
	tmpcmdline := []string{}
	if _, ok := myOpts["--ignore-default-opts"]; !ok {
		ss, _ := shlex.Split(strings.NewReader(emergeConfig.targetConfig.Settings.ValueDict["EMERGE_DEFAULT_OPTS"]), false, true)
		tmpcmdline = append(tmpcmdline, ss...)
	}
	tmpcmdline = append(tmpcmdline, args...)
	emergeConfig.action, emergeConfig.opts, emergeConfig.args = ParseOpts(tmpcmdline, true)

	//try
	runAction(emergeConfig)
	for _, x := range emergeConfig.Trees.Values() {
		if x._porttree == nil {
			continue
		}
		x.PortTree().dbapi.close_caches()
	}
	return 0
}
