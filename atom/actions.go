package atom

import (
	"fmt"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func action_build() {}

func action_config() {}

func action_depclean() {}

func calc_depclean() {}

func _calc_depclean() {}

func action_deselect() {}

func action_info() {}

func action_regen() {}

func action_search() {}

func actionSync(emerge_config *EmergeConfig) int {
	syncer := NewSyncRepos(emerge_config, false)
	return_messages := !myutil.Inmss(emerge_config.opts, "--quiet")
	options := map[string]interface{}{"return-messages": return_messages}
	var success bool
	var msgs []string
	if len(emerge_config.args) > 0 {
		options["repo"] = emerge_config.args
		success, msgs = syncer.repo(options)
	} else {
		success, msgs = syncer.auto_sync(options)
	}
	if return_messages {
		print_results(msgs)
	} else if len(msgs) > 0 && !success {
		util.WriteMsgLevel(strings.Join(msgs, "\n")+"\n", 40, -1)
	}

	if success {
		return 0
	} else {
		return 1
	}
}

func action_uninstall() {}

func adjust_configs(myopts map[string]string, trees *TreesDict) {
	for myroot, mytrees := range trees.Values() {
		mysettings := trees.valueDict[myroot].VarTree().settings
		mysettings.Unlock()

		if _, ok := myopts["--usepkgonly"]; ok && mytrees.BinTree()._propagate_config(mysettings) {
			mytrees.PortTree().dbapi.doebuild_settings = NewConfig(mysettings, nil, "", nil, "", "", "", "", true, nil, false, nil)
		}

		adjust_config(myopts, mysettings)
		mysettings.Lock()
	}
}

func adjust_config(myopts map[string]string, settings *Config) {

	if settings.Features.Features["noauto"] {
		delete(settings.Features.Features, "noauto")
	}

	fail_clean := myopts["--fail-clean"]
	if fail_clean != "" {
		if fail_clean == "true" && !settings.Features.Features["fail-clean"] {
			settings.Features.Features["fail-clean"] = true
		} else if fail_clean == "n" && settings.Features.Features["fail-clean"] {
			delete(settings.Features.Features, "fail-clean")
		}
	}

	CLEAN_DELAY := 5
	if s, ok := settings.ValueDict["CLEAN_DELAY"]; ok {
		if v, err := strconv.Atoi(s); err != nil {
			//except ValueError as e:
			util.WriteMsg(fmt.Sprintf("!!! %v\n", err), -1, nil)
			util.WriteMsg(fmt.Sprintf("!!! Unable to parse integer: CLEAN_DELAY='%s'\n", settings.ValueDict["CLEAN_DELAY"]), -1, nil)
		} else {
			CLEAN_DELAY = v
		}
	}
	settings.ValueDict["CLEAN_DELAY"] = fmt.Sprint(CLEAN_DELAY)
	settings.BackupChanges("CLEAN_DELAY")
	CLEAN_DELAY, _ = strconv.Atoi(settings.ValueDict["CLEAN_DELAY"])

	EMERGE_WARNING_DELAY := 10
	if s, ok := settings.ValueDict["EMERGE_WARNING_DELAY"]; ok {
		if v, err := strconv.Atoi(s); err != nil {
			//except ValueError as e:
			util.WriteMsg(fmt.Sprintf("!!! %v\n", err), -1, nil)
			util.WriteMsg(fmt.Sprintf("!!! Unable to parse integer: EMERGE_WARNING_DELAY='%s'\n", settings.ValueDict["EMERGE_WARNING_DELAY"]), -1, nil)
		} else {
			EMERGE_WARNING_DELAY = v
		}
	}
	settings.ValueDict["EMERGE_WARNING_DELAY"] = fmt.Sprint(EMERGE_WARNING_DELAY)
	settings.BackupChanges("EMERGE_WARNING_DELAY")

	buildpkg := myopts["--buildpkg"]
	if buildpkg == "true" {
		settings.Features.Features["buildpkg"] = true
	} else if buildpkg == "n" {
		delete(settings.Features.Features, "buildpkg")
	}

	if _, ok := myopts["--quiet"]; ok {
		settings.ValueDict["PORTAGE_QUIET"] = "1"
		settings.BackupChanges("PORTAGE_QUIET")
	}

	if _, ok := myopts["--verbose"]; ok {
		settings.ValueDict["PORTAGE_VERBOSE"] = "1"
		settings.BackupChanges("PORTAGE_VERBOSE")
	}

	if _, ok := myopts["--noconfmem"]; ok {
		settings.ValueDict["NOCONFMEM"] = "1"
		settings.BackupChanges("NOCONFMEM")
	}

	PORTAGE_DEBUG := 0
	if s, ok := settings.ValueDict["PORTAGE_DEBUG"]; ok {
		if v, err := strconv.Atoi(s); err != nil {
			//except ValueError as e:
			util.WriteMsg(fmt.Sprintf("!!! %v\n", err), -1, nil)
			util.WriteMsg(fmt.Sprintf("!!! Unable to parse integer: PORTAGE_DEBUG='%s'\n", settings.ValueDict["EMERGE_WARNING_DELAY"]), -1, nil)
		} else if v != 0 && v != 1 {
			util.WriteMsg(fmt.Sprintf("!!! Invalid value: PORTAGE_DEBUG='%i'\n", PORTAGE_DEBUG), -1, nil)
			util.WriteMsg("!!! PORTAGE_DEBUG must be either 0 or 1\n", -1, nil)
			PORTAGE_DEBUG = 0
		} else {
			PORTAGE_DEBUG = v
		}
	}
	if _, ok := myopts["--debug"]; ok {
		PORTAGE_DEBUG = 1
		settings.ValueDict["PORTAGE_DEBUG"] = fmt.Sprint(PORTAGE_DEBUG)
		settings.BackupChanges("PORTAGE_DEBUG")
	}

	if settings.ValueDict["NOCOLOR"] != "yes" && settings.ValueDict["NOCOLOR"] != "true" {
		output.HaveColor = 1
	}

	if _, ok := myopts["--color"]; ok {
		if "y" == myopts["--color"] {
			output.HaveColor = 1
			settings.ValueDict["NOCOLOR"] = "false"
		} else {
			output.HaveColor = 0
			settings.ValueDict["NOCOLOR"] = "true"
		}
		settings.BackupChanges("NOCOLOR")
	} else if settings.ValueDict["TERM"] == "dumb" ||
		terminal.IsTerminal(int(os.Stdout.Fd())) {
		output.HaveColor = 0
		settings.ValueDict["NOCOLOR"] = "true"
		settings.BackupChanges("NOCOLOR")
	}

	if _, ok := myopts["--color"]; ok {
		settings.ValueDict["PORTAGE_BINPKG_FORMAT"] = myopts["--pkg-format"]
		settings.BackupChanges("PORTAGE_BINPKG_FORMAT")
	}
}

func display_missing_pkg_set() {}

func relative_profile_path() {}

func getportageversion() {}

type EmergeConfig struct {
	action                      string
	args                        []string
	opts                        map[string]string
	runningConfig, targetConfig *RootConfig
	Trees                       *TreesDict
}

func NewEmergeConfig(action string, args []string, opts map[string]string) *EmergeConfig {
	e := &EmergeConfig{action: action, args: args, opts: opts}
	return e
}

// nil, nil, "", nil, nil
func LoadEmergeConfig(emergeConfig *EmergeConfig, env map[string]string, action string, args []string, opts map[string]string) *EmergeConfig {
	if emergeConfig == nil {
		emergeConfig = NewEmergeConfig(action, args, opts)
	}
	if env == nil {
		env = util.ExpandEnv()
	}
	emergeConfig.Trees = CreateTrees(env["PORTAGE_CONFIGROOT"], env["ROOT"], emergeConfig.Trees, util.ExpandEnv(), env["SYSROOT"], env["EPREFIX"])

	for _, root_trees := range emergeConfig.Trees.Values() {
		settings := root_trees.VarTree().settings
		settings.InitDirs()
		setconfig := LoadDefaultConfig(settings, root_trees)
		root_config := NewRootConfig(settings, root_trees, setconfig)
		if root_trees.RootConfig != nil {
			root_trees.RootConfig.Update(root_config)
		} else {
			root_trees.RootConfig = root_config
		}
	}

	target_eroot := emergeConfig.Trees._target_eroot
	emergeConfig.targetConfig = emergeConfig.Trees.Values()[target_eroot].RootConfig
	emergeConfig.targetConfig.Mtimedb = util.NewMtimeDB(
		filepath.Join(target_eroot, _const.CachePath, "mtimedb"))
	emergeConfig.runningConfig = emergeConfig.Trees.Values()[emergeConfig.Trees._running_eroot].RootConfig
	QueryCommand_db = emergeConfig.Trees

	return emergeConfig
}

func getgccversion() {}

func validate_ebuild_environment() {}

func check_procfs() {}

func config_protect_check() {}

func apply_priorities() {}

func nice() {}

func ionice() {}

func setconfig_fallback() {}

func get_missing_sets() {}

func missing_sets_warning() {}

func ensure_required_sets() {}

func expand_set_arguments() {}

func repo_name_check() {}

func repo_name_duplicate_check() {}

func runAction(emergeConfig *EmergeConfig) int {
	if map[string]bool{"help": true, "info": true, "sync": true, "version": true}[emergeConfig.action] && emergeConfig.opts["--package-moves"] != "n" &&
		Global_updates(emergeConfig.Trees,
			emergeConfig.targetConfig.Mtimedb.dict["updates"].(map[string]string),
			myutil.Inmss(emergeConfig.opts, "--quiet"), false) {
		emergeConfig.targetConfig.Mtimedb.Commit()
		LoadEmergeConfig(emergeConfig, nil, "", nil, nil)
	}

	_, xterm_titles := emergeConfig.targetConfig.Settings.Features.Features["notitles"]
	if xterm_titles {
		output.XtermTitle("emerge", false)
	}

	if myutil.Inmss(emergeConfig.opts, "--digest") {
		os.Setenv("FEATURES", os.Getenv("FEATURES")+" digest")
		LoadEmergeConfig(emergeConfig, nil, "", nil, nil)
	}
	if myutil.Inmss(emergeConfig.opts, "--buildpkgonly") {
		emergeConfig.opts["--buildpkg"] = "true"
	}

	if emergeConfig.targetConfig.Settings.Features.Features["getbinpkg"] {
		emergeConfig.opts["--getbinpkg"] = "true"
	}

	if myutil.Inmss(emergeConfig.opts, "--getbinpkgonly") {
		emergeConfig.opts["--getbinpkg"] = "true"
	}

	if myutil.Inmss(emergeConfig.opts, "--getbinpkgonly") {
		emergeConfig.opts["--usepkgonly"] = "true"
	}

	if myutil.Inmss(emergeConfig.opts, "--getbinpkg") {
		emergeConfig.opts["--usepkg"] = "true"
	}

	if myutil.Inmss(emergeConfig.opts, "--usepkgonly") {
		emergeConfig.opts["--usepkg"] = "true"
	}
	//	if (emerge_config.action in ('search', None) and
	//	'--usepkg' in emerge_config.opts):
	//	for mytrees in emerge_config.trees.values():
	//	kwargs = {}
	//	if (mytrees is emerge_config.target_config.trees and
	//	emerge_config.target_config is not emerge_config.running_config and
	//	emerge_config.opts.get('--quickpkg-direct', 'n') == 'y'):
	//	kwargs['add_repos'] = (emerge_config.running_config.trees['vartree'].dbapi,)
	//
	//try:
	//	mytrees['bintree'].populate(
	//		getbinpkgs='--getbinpkg' in emerge_config.opts,
	//		**kwargs)
	//	except ParseError as e:
	//	writemsg('\n\n!!!%s.\nSee make.conf(5) for more info.\n'
	//	% (e,), noiselevel=-1)
	//	return 1
	//
	//	adjust_configs(emerge_config.opts, emerge_config.trees)
	//
	//	if profile_check(emerge_config.trees, emerge_config.action) != os.EX_OK:
	//	return 1
	//
	//	apply_priorities(emerge_config.target_config.settings)
	//
	//	if ("--autounmask-continue" in emerge_config.opts and
	//	emerge_config.opts.get("--autounmask") == "n"):
	//	writemsg_level(
	//		" %s --autounmask-continue has been disabled by --autounmask=n\n" %
	//			warn("*"), level=logging.WARNING, noiselevel=-1)
	//
	//	for fmt in emerge_config.target_config.settings.get("PORTAGE_BINPKG_FORMAT", "").split():
	//	if not fmt in portage.const.SUPPORTED_BINPKG_FORMATS:
	//	if "--pkg-format" in emerge_config.opts:
	//	problematic="--pkg-format"
	//	else:
	//	problematic="PORTAGE_BINPKG_FORMAT"
	//
	//	writemsg_level(("emerge: %s is not set correctly. Format " + \
	//	"'%s' is not supported.\n") % (problematic, fmt),
	//	level=logging.ERROR, noiselevel=-1)
	//	return 1

	if emergeConfig.action == "version" {
		//writemsg_stdout(getportageversion(
		//	emerge_config.target_config.settings["PORTDIR"],
		//	None,
		//	emerge_config.target_config.settings.profile_path,
		//	emerge_config.target_config.settings.get("CHOST"),
		//	emerge_config.target_config.trees['vartree'].dbapi) + '\n',
		//	noiselevel=-1)
		return 0
	} else if emergeConfig.action == "help" {
		emergeHelp()
		return 0
	}

	//	spinner = stdout_spinner()
	//	if "candy" in emerge_config.target_config.settings.features:
	//	spinner.update = spinner.update_scroll
	//
	//	if "--quiet" not in emerge_config.opts:
	//	portage.deprecated_profile_check(
	//		settings=emerge_config.target_config.settings)
	//	repo_name_check(emerge_config.trees)
	//	repo_name_duplicate_check(emerge_config.trees)
	//	config_protect_check(emerge_config.trees)
	//	check_procfs()
	//
	//	for mytrees in emerge_config.trees.values():
	//	mydb = mytrees["porttree"].dbapi
	//	# Freeze the portdbapi for performance (memoize all xmatch results).
	//	mydb.freeze()
	//
	//	del mytrees, mydb
	//
	//	for x in emerge_config.args:
	//	if x.endswith((".ebuild", ".tbz2")) and \
	//	os.path.exists(os.path.abspath(x)):
	//	print(colorize("BAD", "\n*** emerging by path is broken "
	//	"and may not always work!!!\n"))
	//	break
	//
	//	if emerge_config.action == "list-sets":
	//	writemsg_stdout("".join("%s\n" % s for s in
	//	sorted(emerge_config.target_config.sets)))
	//	return os.EX_OK
	//	if emerge_config.action == "check-news":
	//	news_counts = count_unread_news(
	//		emerge_config.target_config.trees["porttree"].dbapi,
	//		emerge_config.target_config.trees["vartree"].dbapi)
	//	if any(news_counts.values()):
	//	display_news_notifications(news_counts)
	//	elif "--quiet" not in emerge_config.opts:
	//	print("", colorize("GOOD", "*"), "No news items were found.")
	//	return os.EX_OK
	//
	//	ensure_required_sets(emerge_config.trees)
	//
	//	if emerge_config.action is None and \
	//	"--resume" in emerge_config.opts and emerge_config.args:
	//	writemsg("emerge: unexpected argument(s) for --resume: %s\n" %
	//		" ".join(emerge_config.args), noiselevel=-1)
	//	return 1
	//
	//	# only expand sets for actions taking package arguments
	//	oldargs = emerge_config.args[:]
	//	if emerge_config.action in ("clean", "config", "depclean",
	//		"info", "prune", "unmerge", "rage-clean", None):
	//	newargs, retval = expand_set_arguments(
	//		emerge_config.args, emerge_config.action,
	//		emerge_config.target_config)
	//	if retval != os.EX_OK:
	//	return retval
	//
	//	# Need to handle empty sets specially, otherwise emerge will react
	//	# with the help message for empty argument lists
	//	if oldargs and not newargs:
	//	print("emerge: no targets left after set expansion")
	//	return 0
	//
	//	emerge_config.args = newargs
	//
	//	if "--tree" in emerge_config.opts and \
	//	"--columns" in emerge_config.opts:
	//	print("emerge: can't specify both of \"--tree\" and \"--columns\".")
	//	return 1
	//
	//	if '--emptytree' in emerge_config.opts and \
	//	'--noreplace' in emerge_config.opts:
	//	writemsg_level("emerge: can't specify both of " + \
	//	"\"--emptytree\" and \"--noreplace\".\n",
	//		level=logging.ERROR, noiselevel=-1)
	//	return 1
	//
	//	if "--quiet" in emerge_config.opts:
	//	spinner.update = spinner.update_quiet
	//	portage.util.noiselimit = -1
	//
	//	if "--fetch-all-uri" in emerge_config.opts:
	//	emerge_config.opts["--fetchonly"] = True
	//
	//	if "--skipfirst" in emerge_config.opts and \
	//	"--resume" not in emerge_config.opts:
	//	emerge_config.opts["--resume"] = True
	//
	//	# Allow -p to remove --ask
	//	if "--pretend" in emerge_config.opts:
	//	emerge_config.opts.pop("--ask", None)
	//
	//	# forbid --ask when not in a terminal
	//	# note: this breaks `emerge --ask | tee logfile`, but that doesn't work anyway.
	//	if ("--ask" in emerge_config.opts) and (not sys.stdin.isatty()):
	//	portage.writemsg("!!! \"--ask\" should only be used in a terminal. Exiting.\n",
	//		noiselevel=-1)
	//	return 1
	//
	//	if emerge_config.target_config.settings.get("PORTAGE_DEBUG", "") == "1":
	//	spinner.update = spinner.update_quiet
	//	portage.util.noiselimit = 0
	//	if "python-trace" in emerge_config.target_config.settings.features:
	//	portage.debug.set_trace(True)
	//
	//	if not "--quiet" in emerge_config.opts:
	//	if '--nospinner' in emerge_config.opts or \
	//	emerge_config.target_config.settings.get('TERM') == 'dumb' or \
	//	not sys.stdout.isatty():
	//	spinner.update = spinner.update_basic
	//
	//	if "--debug" in emerge_config.opts:
	//	print("myaction", emerge_config.action)
	//	print("myopts", emerge_config.opts)
	//
	//	if not emerge_config.action and not emerge_config.args and \
	//	"--resume" not in emerge_config.opts:
	//	emerge_help()
	//	return 1
	//
	//	pretend = "--pretend" in emerge_config.opts
	//	fetchonly = "--fetchonly" in emerge_config.opts or \
	//	"--fetch-all-uri" in emerge_config.opts
	//	buildpkgonly = "--buildpkgonly" in emerge_config.opts
	//
	//	# check if root user is the current user for the actions where emerge needs this
	//	if portage.data.secpass < 2:
	//	# We've already allowed "--version" and "--help" above.
	//	if "--pretend" not in emerge_config.opts and \
	//	emerge_config.action not in ("search", "info"):
	//	need_superuser = emerge_config.action in ('clean', 'depclean',
	//		'deselect', 'prune', 'unmerge', "rage-clean") or not \
	//	(fetchonly or \
	//	(buildpkgonly and portage.data.secpass >= 1) or \
	//	emerge_config.action in ("metadata", "regen", "sync"))
	//	if portage.data.secpass < 1 or \
	//need_superuser:
	//	if need_superuser:
	//	access_desc = "superuser"
	//	else:
	//	access_desc = "portage group"
	//	# Always show portage_group_warning() when only portage group
	//	# access is required but the user is not in the portage group.
	//	if "--ask" in emerge_config.opts:
	//	writemsg_stdout("This action requires %s access...\n" % \
	//	(access_desc,), noiselevel=-1)
	//	if portage.data.secpass < 1 and not need_superuser:
	//	portage.data.portage_group_warning()
	//	uq = UserQuery(emerge_config.opts)
	//	if uq.query("Would you like to add --pretend to options?",
	//		"--ask-enter-invalid" in emerge_config.opts) == "No":
	//	return 128 + signal.SIGINT
	//	emerge_config.opts["--pretend"] = True
	//	emerge_config.opts.pop("--ask")
	//	else:
	//	sys.stderr.write(("emerge: %s access is required\n") \
	//	% access_desc)
	//	if portage.data.secpass < 1 and not need_superuser:
	//	portage.data.portage_group_warning()
	//	return 1
	//
	//	# Disable emergelog for everything except build or unmerge operations.
	//	# This helps minimize parallel emerge.log entries that can confuse log
	//	# parsers like genlop.
	//		disable_emergelog = False
	//	for x in ("--pretend", "--fetchonly", "--fetch-all-uri"):
	//	if x in emerge_config.opts:
	//	disable_emergelog = True
	//	break
	//	if disable_emergelog:
	//	pass
	//	elif emerge_config.action in ("search", "info"):
	//	disable_emergelog = True
	//	elif portage.data.secpass < 1:
	//	disable_emergelog = True
	//
	//	import _emerge.emergelog
	//	_emerge.emergelog._disable = disable_emergelog
	//
	//	if not disable_emergelog:
	//	emerge_log_dir = \
	//	emerge_config.target_config.settings.get('EMERGE_LOG_DIR')
	//	if emerge_log_dir:
	//try:
	//	# At least the parent needs to exist for the lock file.
	//		portage.util.ensure_dirs(emerge_log_dir)
	//	except portage.exception.PortageException as e:
	//	writemsg_level("!!! Error creating directory for " + \
	//	"EMERGE_LOG_DIR='%s':\n!!! %s\n" % \
	//	(emerge_log_dir, e),
	//	noiselevel=-1, level=logging.ERROR)
	//	portage.util.ensure_dirs(_emerge.emergelog._emerge_log_dir)
	//	else:
	//	_emerge.emergelog._emerge_log_dir = emerge_log_dir
	//	else:
	//	_emerge.emergelog._emerge_log_dir = os.path.join(os.sep,
	//		portage.const.EPREFIX.lstrip(os.sep), "var", "log")
	//	portage.util.ensure_dirs(_emerge.emergelog._emerge_log_dir)
	//
	//	if not "--pretend" in emerge_config.opts:
	//	time_fmt = "%b %d, %Y %H:%M:%S"
	//	time_str = time.strftime(time_fmt, time.localtime(time.time()))
	//	# Avoid potential UnicodeDecodeError in Python 2, since strftime
	//	# returns bytes in Python 2, and %b may contain non-ascii chars.
	//		time_str = _unicode_decode(time_str,
	//		encoding=_encodings['content'], errors='replace')
	//	emergelog(xterm_titles, "Started emerge on: %s" % time_str)
	//	myelogstr=""
	//	if emerge_config.opts:
	//	opt_list = []
	//	for opt, arg in emerge_config.opts.items():
	//	if arg is True:
	//	opt_list.append(opt)
	//	elif isinstance(arg, list):
	//	# arguments like --exclude that use 'append' action
	//	for x in arg:
	//	opt_list.append("%s=%s" % (opt, x))
	//	else:
	//	opt_list.append("%s=%s" % (opt, arg))
	//	myelogstr=" ".join(opt_list)
	//	if emerge_config.action:
	//	myelogstr += " --" + emerge_config.action
	//	if oldargs:
	//	myelogstr += " " + " ".join(oldargs)
	//	emergelog(xterm_titles, " *** emerge " + myelogstr)
	//
	//	oldargs = None
	//
	//	def emergeexitsig(signum, frame):
	//	signal.signal(signal.SIGTERM, signal.SIG_IGN)
	//	portage.util.writemsg(
	//		"\n\nExiting on signal %(signal)s\n" % {"signal":signum})
	//	sys.exit(128 + signum)
	//
	//	signal.signal(signal.SIGTERM, emergeexitsig)
	//
	emergeexit := func() {
		if _, ok := emergeConfig.opts["--pretend"]; !ok {
			emergelog(xterm_titles, " *** terminating.", "")
		}
		if xterm_titles {
			output.xtermTitleReset()
		}
	}
	atexit_register(emergeexit)

	switch emergeConfig.action {
	case "config", "metadata", "regen", "sync":
		if myutil.Inmss(emergeConfig.opts, "--pretend") {
			os.Stderr.Write([]byte(fmt.Sprintf("emerge: The '%s' action does "+
				"not support '--pretend'.\n", emergeConfig.action)))
			return 1
		}
	}
	if "sync" == emergeConfig.action {
		return actionSync(emergeConfig)
	}

	//	if "metadata" == emerge_config.action:
	//	action_metadata(emerge_config.target_config.settings,
	//		emerge_config.target_config.trees['porttree'].dbapi,
	//		emerge_config.opts)
	//	elif emerge_config.action=="regen":
	//	validate_ebuild_environment(emerge_config.trees)
	//	return action_regen(emerge_config.target_config.settings,
	//		emerge_config.target_config.trees['porttree'].dbapi,
	//		emerge_config.opts.get("--jobs"),
	//		emerge_config.opts.get("--load-average"))
	//	# HELP action
	//	elif "config" == emerge_config.action:
	//	validate_ebuild_environment(emerge_config.trees)
	//	return action_config(emerge_config.target_config.settings,
	//		emerge_config.trees, emerge_config.opts, emerge_config.args)
	//
	//	# SEARCH action
	//	elif "search" == emerge_config.action:
	//	validate_ebuild_environment(emerge_config.trees)
	//	action_search(emerge_config.target_config,
	//		emerge_config.opts, emerge_config.args, spinner)
	//
	//	elif emerge_config.action in \
	//	('clean', 'depclean', 'deselect', 'prune', 'unmerge', 'rage-clean'):
	//	validate_ebuild_environment(emerge_config.trees)
	//	rval = action_uninstall(emerge_config.target_config.settings,
	//		emerge_config.trees, emerge_config.target_config.mtimedb["ldpath"],
	//		emerge_config.opts, emerge_config.action,
	//		emerge_config.args, spinner)
	//	if not (emerge_config.action == 'deselect' or
	//	buildpkgonly or fetchonly or pretend):
	//	post_emerge(emerge_config.action, emerge_config.opts,
	//		emerge_config.args, emerge_config.target_config.root,
	//		emerge_config.trees, emerge_config.target_config.mtimedb, rval)
	//	return rval
	//
	//	elif emerge_config.action == 'info':
	//
	//	# Ensure atoms are valid before calling unmerge().
	//		vardb = emerge_config.target_config.trees['vartree'].dbapi
	//	portdb = emerge_config.target_config.trees['porttree'].dbapi
	//	bindb = emerge_config.target_config.trees['bintree'].dbapi
	//	valid_atoms = []
	//	for x in emerge_config.args:
	//	if is_valid_package_atom(x, allow_repo=True):
	//try:
	//	#look at the installed files first, if there is no match
	//	#look at the ebuilds, since EAPI 4 allows running pkg_info
	//	#on non-installed packages
	//	valid_atom = dep_expand(x, mydb=vardb)
	//	if valid_atom.cp.split("/")[0] == "null":
	//	valid_atom = dep_expand(x, mydb=portdb)
	//
	//	if valid_atom.cp.split("/")[0] == "null" and \
	//	"--usepkg" in emerge_config.opts:
	//	valid_atom = dep_expand(x, mydb=bindb)
	//
	//	valid_atoms.append(valid_atom)
	//
	//	except portage.exception.AmbiguousPackageName as e:
	//	msg = "The short ebuild name \"" + x + \
	//	"\" is ambiguous.  Please specify " + \
	//	"one of the following " + \
	//	"fully-qualified ebuild names instead:"
	//	for line in textwrap.wrap(msg, 70):
	//	writemsg_level("!!! %s\n" % (line,),
	//		level=logging.ERROR, noiselevel=-1)
	//	for i in e.args[0]:
	//	writemsg_level("    %s\n" % colorize("INFORM", i),
	//		level=logging.ERROR, noiselevel=-1)
	//	writemsg_level("\n", level=logging.ERROR, noiselevel=-1)
	//	return 1
	//	continue
	//	msg = []
	//	msg.append("'%s' is not a valid package atom." % (x,))
	//	msg.append("Please check ebuild(5) for full details.")
	//	writemsg_level("".join("!!! %s\n" % line for line in msg),
	//	level=logging.ERROR, noiselevel=-1)
	//	return 1
	//
	//	return action_info(emerge_config.target_config.settings,
	//		emerge_config.trees, emerge_config.opts, valid_atoms)
	//
	//	# "update", "system", or just process files:
	//	else:
	//	validate_ebuild_environment(emerge_config.trees)
	//
	//	for x in emerge_config.args:
	//	if x.startswith(SETPREFIX) or \
	//	is_valid_package_atom(x, allow_repo=True):
	//	continue
	//	if x[:1] == os.sep:
	//	continue
	//try:
	//	os.lstat(x)
	//	continue
	//	except OSError:
	//	pass
	//	msg = []
	//	msg.append("'%s' is not a valid package atom." % (x,))
	//	msg.append("Please check ebuild(5) for full details.")
	//	writemsg_level("".join("!!! %s\n" % line for line in msg),
	//	level=logging.ERROR, noiselevel=-1)
	//	return 1
	//
	//	# GLEP 42 says to display news *after* an emerge --pretend
	//	if "--pretend" not in emerge_config.opts:
	//	uq = UserQuery(emerge_config.opts)
	//	if display_news_notification(emerge_config.target_config,
	//		emerge_config.opts) \
	//	and "--ask" in emerge_config.opts \
	//	and "--read-news" in emerge_config.opts \
	//	and uq.query("Would you like to read the news items while " \
	//	"calculating dependencies?",
	//		'--ask-enter-invalid' in emerge_config.opts) == "Yes":
	//try:
	//	subprocess.call(['eselect', 'news', 'read'])
	//	# If eselect is not installed, Python <3.3 will throw an
	//	# OSError. >=3.3 will throw a FileNotFoundError, which is a
	//	# subclass of OSError.
	//	except OSError:
	//	writemsg("Please install eselect to use this feature.\n",
	//	noiselevel=-1)
	//	retval = action_build(emerge_config, spinner=spinner)
	//	post_emerge(emerge_config.action, emerge_config.opts,
	//	emerge_config.args, emerge_config.target_config.root,
	//	emerge_config.trees, emerge_config.target_config.mtimedb, retval)
	//
	//	return retval

	return 0
}
