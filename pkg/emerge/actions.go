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
	opts                        []string
	runningConfig, targetConfig string
	trees                       map[string]*atom.TreesDict
}

func NewEmergeConfig(action string) *EmergeConfig {
	e := &EmergeConfig{action: action}
	return e
}

func LoadEmergeConfig(emergeConfig *EmergeConfig, env map[string]string, myaction string) *EmergeConfig {
	if emergeConfig == nil {
		emergeConfig = NewEmergeConfig(myaction)
	}
	//emergeConfig.trees = atom.CreateTrees("", "", emergeConfig.trees, atom.ExpandEnv(), "", "")
	return emergeConfig
}

func runAction(emergeConfig *EmergeConfig) int {
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

func actionSync(emerge_config *EmergeConfig) int {
	//syncer = SyncRepos(emerge_config)
	return_messages := false
	for _, o := range emerge_config.opts {
		if o == "--quiet" {
			return_messages = true
			break
		}
	}
	options := map[string]interface{}{"return-messages": return_messages}
	var msgs []string = nil
	if len(emerge_config.args) > 0 {
		options["repo"] = emerge_config.args
		//success, msgs = syncer.repo(options=options)
	} else {
		//success, msgs = syncer.auto_sync(options=options)
	}
	if return_messages {
		print_results(msgs)
	}
	return 0
}

func print_results(results []string) {
	if len(results) > 0 {
		println()
		println(strings.Join(results, "\n"))
		println("\n")
	}
}
