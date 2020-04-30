package emerge

import (
	"fmt"
	"os"
	"strings"

	"github.com/ppphp/portago/atom"
)

type EmergeConfig struct {
	action                      string
	args                        []string
	opts                        map[string]string
	runningConfig, targetConfig struct{ settings *atom.Config }
	Trees                       *atom.TreesDict
}

func NewEmergeConfig(action string, args []string, opts map[string]string) *EmergeConfig {
	e := &EmergeConfig{action: action, args: args, opts: opts}
	return e
}

func LoadEmergeConfig(emergeConfig *EmergeConfig, env map[string]string, action string, args []string, opts map[string]string) *EmergeConfig {
	if emergeConfig == nil {
		emergeConfig = NewEmergeConfig(action, args, opts)
	}
	if env == nil {
		env = atom.ExpandEnv()
	}
	emergeConfig.Trees = atom.CreateTrees(env["PORTAGE_CONFIGROOT"], env["ROOT"], emergeConfig.Trees, atom.ExpandEnv(), env["SYSROOT"], env["EPREFIX"])

	for _, root_trees := range emergeConfig.Trees.Values() {
		settings := root_trees.VarTree()
	}

	return emergeConfig
}

func actionSync(emerge_config *EmergeConfig) int {
	syncer := NewSyncRepos(emerge_config, false)
	return_messages := false
	for _, o := range emerge_config.opts {
		if o == "--quiet" {
			return_messages = true
			break
		}
	}
	options := map[string]interface{}{"return-messages": return_messages}
	var msgs []string = nil
	var success bool
	if len(emerge_config.args) > 0 {
		options["repo"] = emerge_config.args
		success, msgs = syncer.repo(options)
	} else {
		success, msgs = syncer.auto_sync(options)
	}
	if return_messages {
		print_results(msgs)
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
	if map[string]bool{"help": true, "info": true, "sync": true, "version": true}[emergeConfig.action] && emergeConfig.opts["--package-moves"] != "n" {

	}

	_, xterm_titles := emergeConfig.targetConfig.settings.Features.Features["notitles"]
	if xterm_titles {
		atom.XtermTitle("emerge", false)
	}

	if emergeConfig.action == "version" {
	} else if emergeConfig.action == "help" {
		emergeHelp()
		return 0
	}

	switch emergeConfig.action {
	case "config", "metadata", "regen", "sync":
		for _, o := range emergeConfig.opts {
			if o == "--pretend" {
				os.Stderr.Write([]byte(fmt.Sprintf("emerge: The '%s' action does "+
					"not support '--pretend'.\n", emergeConfig.action)))
				return 1
			}
		}
	}
	if "sync" == emergeConfig.action {
		return actionSync(emergeConfig)
	}

	return 0
}