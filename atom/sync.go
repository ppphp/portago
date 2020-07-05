package atom

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type syncBase struct {
	options                                                                                         map[string]string
	 xtermTitles, spawnKwargs, _repoStorage, downloadDir, binCommand, binPkg string
	logger func(string,string)
	settings *Config
	repo *RepoConfig
}

func (s *syncBase) repoStorage() {
}

func (s *syncBase) hasBin() bool {
	if s.binCommand == "" {
		msg := []string{fmt.Sprintf("Command not found: %s", s.binCommand),
			fmt.Sprintf("Type \"emerge %s\" to enable %s support.", s.binPkg, s.binCommand)}
		for _, l := range msg {
			WriteMsgLevel(fmt.Sprintf("!!! %s", l), -40, -1)
		}
		return false
	}

	return true
}

func NewSyncBase(binCommand, binPkg string) *syncBase {
	if binCommand != "" {
		binCommand = FindBinary(binCommand)
	}
	s := &syncBase{}
	s.binCommand = binCommand
	s.binPkg = binPkg
	return s
}

type newBase struct {
	*syncBase
}

func (n *newBase) sync() {

}

func NewNewBase(binCommand, binPkg string) *newBase {
	n := &newBase{syncBase: NewSyncBase(binCommand, binPkg)}
	return n
}

type modules struct {
	modules map[string]map[string][]string
}

var moduleController modules

func moduleSpecificOptions(repo *RepoConfig) map[string]bool {
	r := map[string]bool{}
	if repo.SyncType != "" {
		for _, v := range moduleController.modules[repo.SyncType]["module_specific_options"] {
			r[v] = true
		}
	}
	return r
}

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

func (s *SyncRepos) repo(options map[string]interface{}) (bool, []string) {
	repo_names := []string{}
	return_messages := false
	if len(options) > 0 {
		repo_names = options["repo"].([]string)
		return_messages, _ = options["return-messages"].(bool)
	} else {
		return_messages = false
	}
	success, repos, msgs := s._get_repos(false, repo_names)
	if !success {
		if return_messages {
			return false, msgs
		}
		return false, nil
	}
	return s._sync(repos, return_messages, options)
}

func (s *SyncRepos) _match_repos(repos []string, available map[string]*RepoConfig) map[string]*RepoConfig {
	selected := map[string]*RepoConfig{}
	for k, repo := range available {
		in := false
		for _, r := range repos {
			if repo.Name == r {
				in = true
				break
			}
		}
		if in {
			selected[k] = repo
		} else if repo.Aliases != nil {
			in := false
			for aliases := range repo.Aliases {
				if Ins(repos, aliases) {
					in = true
					break
				}
			}
			if in {
				selected[k] = repo
			}
		}
	}
	return selected
}

// true, nil
func (s *SyncRepos) _get_repos(auto_sync_only bool, match_repos []string) (bool, map[string]*RepoConfig, []string) {
	msgs := []string{}
	repos := s.emerge_config.targetConfig.Settings.Repositories.Prepos
	if match_repos != nil {
		repos := s._match_repos(match_repos, repos)
		if len(repos) < len(match_repos) {
			repo_names := map[string]bool{}
			for _, repo := range repos {
				repo_names[repo.Name] = true
				if repo.Aliases != nil {
					for k := range repo.Aliases {
						repo_names[k] = true
					}
				}
			}
			missing := []string{}
			for _, k := range match_repos {
				if !repo_names[k] {
					missing = append(missing, k)
				}
			}
			if len(missing) > 0 {
				msgs = append(msgs, fmt.Sprintf(Red(" * ")+"The specified repo(s) were not found: %s",
					strings.Join(missing, " ")+
						"\n   ...returning"))
				return false, repos, msgs
			}
		}
	}
	if auto_sync_only {
		repos = s._filter_auto(repos)
	}

	sync_disabled := []string{}
	for _, repo := range repos {
		if repo.SyncType == "" {
			sync_disabled = append(sync_disabled, repo.Name)
		}
	}
	if len(sync_disabled) > 0 {
		rs := map[string]*RepoConfig{}
		for k, repo := range repos {
			if repo.SyncType != "" {
				rs[k] = repo
			}
		}
		repos = rs
		if match_repos != nil {
			msgs = append(msgs, Red(" * ")+fmt.Sprintf("The specified repo(s) have sync disabled: %s",
				strings.Join(sync_disabled, " ")+
					"\n   ...returning"))
			return false, repos, msgs
		}
	}
	missing_sync_uri := []string{}

	for _, repo := range repos {
		if repo.SyncUri == "" {
			missing_sync_uri = append(missing_sync_uri, repo.Name)
		}
	}
	if len(missing_sync_uri) > 0 {
		rs := map[string]*RepoConfig{}
		for k, repo := range repos {
			if repo.SyncUri != "" {
				rs[k] = repo
			}
		}
		repos = rs
		msgs = append(msgs, fmt.Sprintf(Red(" * ")+"The specified repo(s) are missing sync-uri: %s",
			strings.Join(missing_sync_uri, " ")+
				"\n   ...returning"))
		return false, repos, msgs
	}

	return true, repos, msgs
}

func (s *SyncRepos) _filter_auto(repos map[string]*RepoConfig) map[string]*RepoConfig {
	selected := map[string]*RepoConfig{}
	for k, repo := range repos {
		if repo.AutoSync == "yes" || repo.AutoSync == "true" {
			selected[k] = repo
		}
	}
	return selected
}

func (s *SyncRepos) _sync(selected_repos map[string]*RepoConfig, return_messages bool, emaint_opts map[string]interface{}) (bool, []string) { // nil
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
	syscall.Umask(022)
	sync_manager := NewSyncManager(s.emerge_config.targetConfig.Settings, emergelog)

	var max_jobs string

	if _, ok := s.emerge_config.targetConfig.Settings.Features.Features["parallel-fetch"]; ok {
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
		sync_manager.perform_post_sync_hook()
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

	SyncMode = false
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
	if s.emerge_config.opts["--package-moves"] != "n" && Global_updates(s.emerge_config.trees,
		s.emerge_config.targetConfig.Mtimedb["updates"],
		Inmss(s.emerge_config.opts, "--quiet"), true) {
		s.emerge_config.targetConfig.Mtimedb.Commit()
		s._reload_config()
	}
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
		_, opts, _files := ParseOpts([]string{}, true)
		emerge_config = LoadEmergeConfig(nil, nil, "sync", _files, opts)
		cmdline, _ := shlex.Split(strings.NewReader(emerge_config.targetConfig.Settings.ValueDict["EMERGE_DEFAULT_OPTS"]), false, true)
		_, emerge_config.opts, _ = ParseOpts(cmdline, true)

		//ResetLegacyGlobals()
		//Settings() = emerge_config.targetConfig.Settings
		//Db() = emerge_config.Trees
		//Root() = Db()._target_eroot
	}

	s.emerge_config = emerge_config
	if emerge_logging {
		disable = false
	}
	s.xterm_titles = !s.emerge_config.targetConfig.Settings.Features.Features["notitles"]
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
	_repo_map                    map[string]*RepoConfig
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
	emerge_config     *EmergeConfig
	settings          *Config
	logger            func(bool, string, string)
	hooks             map[string]map[string]string
	exitcode          int
	updatecache_flg   bool
	repo              *RepoConfig
	module_controller map[string]
	module_names      []string
}

func (s *SyncManager) get_module_descriptions() {}

func (s *SyncManager) sync_async(emerge_config *EmergeConfig, repo *RepoConfig, master_hooks bool) *SyncRepo { // nil, nil, true
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

func (s *SyncManager) sync(emerge_config *EmergeConfig, repo *RepoConfig, master_hooks bool)  int {
	s.repo = repo
	s.exitcode = 1
	s.updatecache_flg = false

	rval := s.pre_sync(repo)
	if rval != 0 {
		return rval
	}
	tasks := s.module_controller[repo.SyncType]
	return s.exitcode
}

func (s *SyncManager) do_callback() {}

func (s *SyncManager) perform_post_sync_hook() {}

func (s *SyncManager) pre_sync(repo *RepoConfig)int {
	msg := fmt.Sprintf(">>> Syncing repository '%s' into '%s'...", repo.Name, repo.Location)
	WriteMsgLevel(msg+"\n", 0, 0)
	return 0
}

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

func NewSyncManager(settings *Config, logger func(bool, string, string)) *SyncManager {
	s := &SyncManager{settings: settings, logger: logger}
	syscall.Umask(022)

	s.module_controler = map[string]
	s.module_names = []string{"rsync"}

	s.hooks = map[string]map[string]string{}
	for _, _dir := range  []string{"repo.postsync.d", "postsync.d"} {
		postsync_dir := filepath.Join(s.settings.ValueDict["PORTAGE_CONFIGROOT"],
			UserConfigPath, _dir)
		hooks := map[string]string{}
		for _, filepath := range RecursiveFileList(postsync_dir) {
			name := strings.TrimLeft(strings.Split(filepath, postsync_dir)[1], string(os.PathSeparator))
			if st ,_ := os.Stat(filepath); st!= nil && st.Mode()&unix.X_OK!= 0{
				hooks[filepath] = name
			}else {
				WriteMsgLevel(fmt.Sprintf(" %s %s hook: '%s' is not executable\n", Warn("*"), _dir, name,), 30, 2)
			}
		}
		s.hooks[_dir] = hooks
	}

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
