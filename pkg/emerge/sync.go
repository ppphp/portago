package emerge

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

func (s *SyncRepos) auto_sync() {
	return
}

func (s *SyncRepos) all_repos() {
	return
}

func (s *SyncRepos) repo() {
	return
}

func (s *SyncRepos) _match_repos() {
	return
}

func (s *SyncRepos) _get_repos() {
	return
}

func (s *SyncRepos) _filter_auto() {
	return
}

func (s *SyncRepos) _sync() {
	return
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
