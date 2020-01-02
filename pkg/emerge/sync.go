package emerge

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/ppphp/portago/atom"
)

type SyncRepos struct {
	emerge_config *EmergeConfig
	xterm_titles  bool
}

func (SyncRepos) Name() string {
	return "sync"
}

func (SyncRepos) can_progressbar(func()) bool {
	return false
}

func (s *SyncRepos) auto_sync(options map[string]interface{}) (bool, []string) {
	return_messages := false
	if len(options) > 0 {
		return_messages, _ = options["return-messages"].(bool)
	}

	success, repos, msgs := s._get_repos(true, nil)
	if !success {
		if return_messages {
			return false, msgs
		}
		return false, nil
	}
	return s._sync(repos, return_messages, options)

}

func (s *SyncRepos) all_repos() {
	return
}

func (s *SyncRepos) repo() {
	return
}

func (s *SyncRepos) _match_repos(repos []*atom.RepoConfig, available []*atom.RepoConfig) []*atom.RepoConfig {
	selected := []*atom.RepoConfig{}
	for _, repo := range available {
		in := false
		for _, r := range repos {
			if repo.Name == r.Name {
				in = true
				break
			}
		}
		if in {
			selected = append(selected, repo)
		} else if repo.Aliases != nil {
			in := false
			for aliases := range repo.Aliases {
				for _, repo := range repos {
					if aliases == repo.Name {
						in = true
						break
					}
				}
				if in {
					break
				}
			}
			if in {
				selected = append(selected, repo)
			}
		}
	}
	return selected
}

func (s *SyncRepos) _get_repos(auto_sync_only bool, match_repos interface{}) (bool, []string, []string) { // true, nil

	msgs := []string{}
	//repos := s.emerge_config.target_config.settings.repositories
	return true, nil, msgs
}

func (s *SyncRepos) _filter_auto(repos []*atom.RepoConfig) []*atom.RepoConfig {
	selected := []*atom.RepoConfig{}
	for _, repo := range repos {
		if repo.AutoSync == "yes" || repo.AutoSync == "true" {
			selected = append(selected, repo)
		}
	}
	return selected
}

func (s *SyncRepos) _sync(selected_repos []string, return_messages bool, emaint_opts map[string]interface{}) (bool, []string) { // nil
	msgs := []string{}
	if len(selected_repos) == 0 {
		if return_messages {
			msgs = append(msgs, "Nothing to sync... returning")
			return true, msgs
		}
		return true, nil
	}
	if emaint_opts != nil {
		for k, v := range emaint_opts {
			if v != nil {
				k = "--" + strings.ReplaceAll(k, "_", "-")
				s.emerge_config.opts[k] = fmt.Sprint(v)
			}
		}
	}
	syscall.Umask(0o22)

	return false, nil
}

func (s *SyncRepos) _do_pkg_moves() {
	return
}

func (s *SyncRepos) _check_updates() {
	return
}

func (s *SyncRepos) _reload_config() {
	return
}

func (s *SyncRepos) rmessage() {
	return
}

func NewSyncRepos(emerge_config *EmergeConfig, emerge_logging bool) *SyncRepos { // nil, false
	s := &SyncRepos{}

	if emerge_config == nil {
		//actions, opts, _files := ParseOpts([]string, true)
		//emerge_config = LoadEmergeConfig(nil, "sync", args=_files, opts=opts)
		//cmdline = atom.ShlexSplit .shlex_split(
		//	emerge_config.target_config.settings.get(
		//	"EMERGE_DEFAULT_OPTS", ""))
		//emerge_config.opts = parse_opts(cmdline, silent=True)[1]

		//if hasattr(portage, 'settings'):
		//	# cleanly destroy global objects
		//	portage._reset_legacy_globals()
		//	# update redundant global variables, for consistency
		//	# and in order to conserve memory
		//	portage.settings = emerge_config.target_config.settings
		//	portage.db = emerge_config.trees
		//	portage.root = portage.db._target_eroot
	}

	s.emerge_config = emerge_config
	if emerge_logging {
		disable = false
	}
	s.xterm_titles = true
	//for _, f := range s.emerge_config.target_config.settings.features {
	//	if f == "notitles" {
	//		s.xterm_titles = false
	//		break
	//	}
	//}
	emergelog(s.xterm_titles, " === sync", "")
	return s
}
