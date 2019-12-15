package emerge

import "github.com/ppphp/portago/atom"

type EmergeConfig struct {
	action                             string
	args                               []string
	opts                               []string
	runningConfig, targetConfig, trees string
}

func NewEmergeConfig() *EmergeConfig {
	e := &EmergeConfig{}
	return e
}

func LoadEmergeConfig(emergeConfig *EmergeConfig) *EmergeConfig {
	if emergeConfig == nil {
		emergeConfig = NewEmergeConfig()
	}
	emergeConfig.trees = atom.CreateTrees("", "", emergeConfig.trees, env, "", "")
	return emergeConfig
}
