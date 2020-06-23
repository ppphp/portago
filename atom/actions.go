package atom

import (
	"fmt"
	"github.com/ppphp/portago/pkg/emerge"
	"os"
	"path/filepath"
	"strings"
)

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
		env = ExpandEnv()
	}
	emergeConfig.Trees = CreateTrees(env["PORTAGE_CONFIGROOT"], env["ROOT"], emergeConfig.Trees, ExpandEnv(), env["SYSROOT"], env["EPREFIX"])

	for _, root_trees := range emergeConfig.Trees.Values() {
		settings := root_trees.VarTree().settings
		settings.InitDirs()
		setconfig := LoadDefaultConfig(settings, root_trees)
		root_config := NewRootConfig(settings, root_trees, setconfig)
		if root_trees.RootConfig != nil{
			root_trees.RootConfig.Update(root_config)
		}else{
			root_trees.RootConfig = root_config
		}
	}

	target_eroot := emergeConfig.Trees._target_eroot
	emergeConfig.targetConfig = emergeConfig.Trees.Values()[target_eroot].RootConfig
	emergeConfig.targetConfig.Mtimedb = NewMtimeDB(
		filepath.Join(target_eroot, CachePath, "mtimedb"))
	emergeConfig.runningConfig = emergeConfig.Trees.Values()[
		emergeConfig.Trees._running_eroot].RootConfig
	QueryCommand_db = emergeConfig.Trees

	return emergeConfig
}

func actionSync(emerge_config *EmergeConfig) int {
	syncer := NewSyncRepos(emerge_config, false)
	return_messages := !Inmss(emerge_config.opts, "--quiet")
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
		WriteMsgLevel(strings.Join(msgs, "\n")+"\n", 40, -1)
	}

	if success {
		return 0
	} else {
		return 1
	}
}

func print_results(results []string) {
	if len(results) > 0 {
		println()
		println(strings.Join(results, "\n"))
		println("\n")
	}
}

func runAction(emergeConfig *EmergeConfig) int {
	if map[string]bool{"help": true, "info": true, "sync": true, "version": true}[emergeConfig.action] && emergeConfig.opts["--package-moves"] != "n" &&
		Global_updates(emergeConfig.Trees,
		emergeConfig.targetConfig.Mtimedb.dict["updates"],
		 Inmss( emergeConfig.opts,"--quiet"), false){
		emergeConfig.targetConfig.Mtimedb.Commit()
			LoadEmergeConfig(emergeConfig, nil, "", nil, nil)
	}

	_, xterm_titles := emergeConfig.targetConfig.Settings.Features.Features["notitles"]
	if xterm_titles {
		XtermTitle("emerge", false)
	}
	
	if Inmss(emergeConfig.opts, "--digest") {
		os.Setenv("FEATURES", os.Getenv("FEATURES")+ " digest")
		LoadEmergeConfig(emergeConfig, nil, "", nil, nil)
	}
	if  Inmss( emergeConfig.opts,"--buildpkgonly") {
		emergeConfig.opts["--buildpkg"] = true
	}

	if  emergeConfig.targetConfig.Settings.Features.Features["getbinpkg"] {
		emergeConfig.opts["--getbinpkg"] = true
	}

	if  Inmss(emergeConfig.opts,"--getbinpkgonly") {
		emergeConfig.opts["--getbinpkg"] = true
	}

	if  Inmss( emergeConfig.opts,"--getbinpkgonly") {
		emergeConfig.opts["--usepkgonly"] = true
	}

	if  Inmss( emergeConfig.opts,"--getbinpkg"){
		emergeConfig.opts["--usepkg"] = true
	}

	if  Inmss( emergeConfig.opts,"--usepkgonly"){
		emergeConfig.opts["--usepkg"] = true
	}

	if emergeConfig.action == "version" {
	} else if emergeConfig.action == "help" {
		emergeHelp()
		return 0
	}

	switch emergeConfig.action {
	case "config", "metadata", "regen", "sync":
		if Inmss(emergeConfig.opts, "--pretend"){
			os.Stderr.Write([]byte(fmt.Sprintf("emerge: The '%s' action does "+
				"not support '--pretend'.\n", emergeConfig.action)))
			return 1
		}
	}
	if "sync" == emergeConfig.action {
		return actionSync(emergeConfig)
	}

	return 0
}
