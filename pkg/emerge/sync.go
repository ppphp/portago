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
	sync_manager := NewSyncManager(s.emerge_config.targetConfig.settings, emergelog)

	var max_jobs string

	if _, ok := s.emerge_config.targetConfig.settings.Features.Features["parallel-fetch"]; ok {
		max_jobs, ok = s.emerge_config.opts["--jobs"]
		if !ok {
			max_jobs = "1"
		}
	} else {
		max_jobs = "1"
	}
	fmt.Sprint(max_jobs) // TODO: remove it
	sync_scheduler := NewSyncScheduler(s.emerge_config,
		selected_repos, sync_manager)
	//,
	//		max_jobs=max_jobs,
	//		event_loop=asyncio._safe_loop())

	sync_scheduler.start()
	sync_scheduler.wait()
	retvals := sync_scheduler.retvals
	msgs = append(msgs, sync_scheduler.msgs...)
	returncode := true

	if len(retvals) > 0 {
		msgs = append(msgs, s.rmessage(retvals, "sync")...)
		for _, retval := range retvals {
			if retval[1] != "0" {
				returncode = false
			}
			break
		}
	} else {
		msgs = append(msgs, s.rmessage([][2]string{{"None", "0"}}, "sync")...)
	}

	if sync_scheduler.global_hooks_enabled() {
		/*
			rcode := sync_manager.perform_post_sync_hook("")
			if rcode != 0 {
				msgs = append(msgs, s.rmessage([][2]string{{"None", fmt.Sprint(rcode)}}, "post-sync")...)
				if rcode != 0 {
					returncode = false
				}
			}
		*/
	}

	atom.SyncMode = false
	s._reload_config()
	s._do_pkg_moves()
	msgs = append(msgs, s._check_updates()...)
	//display_news_notification(s.emerge_config.targetConfig,
	//	s.emerge_config.opts)

	if return_messages {
		return returncode, msgs
	}
	return returncode, nil
}

func (s *SyncRepos) _do_pkg_moves() {
	return
}

func (s *SyncRepos) _check_updates() []string { // TODO
	msg := []string{}
	return msg
}

func (s *SyncRepos) _reload_config() {
	return
}

func (s *SyncRepos) rmessage(rvals [][2]string, action string) []string {
	messages := []string{}
	for _, rval := range rvals {
		messages = append(messages, fmt.Sprintf("Action: %s for repo: %s, returned code = %s", action, rval[0], rval[1]))
	}
	return messages
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

type SyncScheduler struct {
	*AsyncScheduler
	_emerge_config               *EmergeConfig
	selected_repos               interface{}
	_sync_manager                *SyncManager
	retvals                      [][2]string
	msgs                         []string
	_hooks_repos, _running_repos map[string]bool
	_leaf_nodes                  []string
	_sync_graph                  bool
	_repo_map                    map[string]string
}

func (s *SyncScheduler) _init_graph() {}

func (s *SyncScheduler) _task_exit() {}

func (s *SyncScheduler) _master_hooks(repo_name string) bool {
	traversed_nodes := map[string]bool{}
	node_stack := []string{repo_name}
	for len(node_stack) > 0 {
		node := node_stack[len(node_stack)-1]
		node_stack = node_stack[:len(node_stack)-1]
		if _, ok := s._hooks_repos[node]; ok {
			return true
		}
		if _, ok := traversed_nodes[node]; !ok {
			traversed_nodes[node] = true
			// TODO: node_stack = append(node_stack,s._complete_graph.child_nodes(node)...)
		}
	}
	return false
}

func (s *SyncScheduler) global_hooks_enabled() bool {
	return len(s._hooks_repos) > 0
}

func (s *SyncScheduler) _update_leaf_nodes() {}

func (s *SyncScheduler) _next_task() *SyncRepo {
	if !s._sync_graph {
		// raise StopIteration()
	}
	node := s._leaf_nodes[len(s._leaf_nodes)-1]
	s._leaf_nodes = s._leaf_nodes[:len(s._leaf_nodes)-1]
	s._running_repos[node] = true
	s._update_leaf_nodes()

	return s._sync_manager.sync_async(
		s._emerge_config,
		s._repo_map[node],
		s._master_hooks(node))
}

func (s *SyncScheduler) _can_add_job() {}

func (s *SyncScheduler) _keep_scheduling() {}

func NewSyncScheduler(emerge_config *EmergeConfig, selected_repos interface{}, sync_manager *SyncManager) *SyncScheduler {
	s := &SyncScheduler{_emerge_config: emerge_config, selected_repos: selected_repos, _sync_manager: sync_manager}

	//AsyncScheduler.__init__(self, **kwargs)
	s._init_graph()
	s.retvals = [][2]string{}
	s.msgs = []string{}
	return s
}

type SyncManager struct {
	emerge_config *EmergeConfig
	settings      *atom.Config
	logger        func(bool, string, string)
	hooks         map[string]string
}

func (s *SyncManager) get_module_descriptions() {}

func (s *SyncManager) sync_async(emerge_config *EmergeConfig, repo interface{}, master_hooks bool) *SyncRepo { // nil, nil, true
	s.emerge_config = emerge_config
	//self.settings, self.trees, self.mtimedb = emerge_config
	//	self.xterm_titles = "notitles" not in self.settings.features
	//	self.portdb = self.trees[self.settings['EROOT']]['porttree'].dbapi
	/*
		return NewSyncRepo(AsyncFunction(target=self.sync,
			kwargs=dict(emerge_config=emerge_config, repo=repo,
			master_hooks=master_hooks)),
			s._sync_callback)
	*/ //TODO: async
	s.sync(emerge_config, repo, master_hooks)
	s._sync_callback(nil)
	return nil
}

func (s *SyncManager) sync(emerge_config *EmergeConfig, repo interface{}, master_hooks bool) {}

func (s *SyncManager) do_callback() {}

func (s *SyncManager) perform_post_sync_hook() {}

func (s *SyncManager) pre_sync() {}

func (s *SyncManager) _sync_callback(proc interface{}) {
	/*
		repo = proc.kwargs['repo']
		exitcode = proc.returncode
		updatecache_flg = False
		if proc.returncode == os.EX_OK:
			exitcode, message, updatecache_flg, hooks_enabled = proc.result

		if updatecache_flg and "metadata-transfer" not in self.settings.features:
			updatecache_flg = False

		if updatecache_flg and \
			os.path.exists(os.path.join(
			repo.location, 'metadata', 'md5-cache')):

			# Only update cache for repo.location since that's
			# the only one that's been synced here.
			action_metadata(self.settings, self.portdb, self.emerge_config.opts,
				porttrees=[repo.location])
	*/
}

func NewSyncManager(settings *atom.Config, logger func(bool, string, string)) *SyncManager {
	s := &SyncManager{settings: settings, logger: logger}
	s.hooks = map[string]string{}

	return s
}

type SyncRepo struct {
	sync_task     func()
	sync_callback func()
}

func NewSyncRepo(sync_task func(), sync_callback func()) *SyncRepo {
	s := &SyncRepo{sync_task: sync_task, sync_callback: sync_callback}
	return s
}
