package emerge

const FAILURE = 1

type  Scheduler struct {
	*PollScheduler
	_loadavg_latency, _max_display_latency                           int
	_opts_ignore_blockers, _opts_no_background, _opts_no_self_update map[string]bool

	settings        *config.Config
	target_root     string
	trees           interface{}
	myopts          interface{}
	_spinner        interface{}
	_mtimedb        int
	_favorites      []*dep.Atom
	_args_set       *sets.InternalPackageSet
	_build_opts     *_build_opts_class
	_parallel_fetch bool
	curval          int
	_logger         *_emerge_log_class

	_sigcont_time            int
	_sigcont_delay           int
	_job_delay_max           float64
	_choose_pkg_return_early bool
	edebug                   int
	_deep_system_deps        map[string]string
	_unsatisfied_system_deps map[string]string
	_failed_pkgs_all         []*_failed_pkg
	_jobs                    int
	_pkg_count               *_pkg_count_class
	_config_pool             map[string][]*config.Config
	_failed_pkgs             []*_failed_pkg
	_blocker_db              map[string]*BlockerDB
	pkgsettings              map[string]*config.Config
	_binpkg_opts             *_binpkg_opts_class
	_task_queues             *_task_queues_class
	_fetch_log               string
	_running_portage         *structs.Package
	_running_root            *RootConfig
	_previous_job_start_time int
	_status_display          *JobStatusDisplay
}

type  _iface_class struct {
	*SchedulerInterface
	// slot
	fetch, scheduleSetup,scheduleUnpack string
}

// SlotObject
type  _fetch_iface_class struct {
	// slot
	log_file,schedule string
}

type _task_queues_class struct {
	// slot
	merge, jobs, ebuild_locks, fetch, unpack *SequentialTaskQueue
}

// SlotObject
type  _build_opts_class struct {
	// slot
	buildpkg,buildpkg_exclude,buildpkgonly,
	fetch_all_uri bool
	fetchonly,pretend string

}

// SlotObject
type  _binpkg_opts_class struct {
	// slot
	fetchonly,getbinpkg,pretend string
}

// SlotObject
type  _pkg_count_class struct {
	// slot
	curval, maxval int
}

// SlotObject
type _emerge_log_class struct {
	// slot
	xterm_titles bool
}

func (e *_emerge_log_class) log( mystr, short_msg string) {
	if !e.xterm_titles {
		short_msg = ""
	}
	atom.emergelog(e.xterm_titles, mystr, short_msg)
}

// SlotObject
type  _failed_pkg struct {
	// slot
	build_dir,build_log,pkg, postinst_failure,returncode string
}

type  _ConfigPool struct {
	// slot
	_root       string
	_allocate   func(string)*config.Config
	_deallocate func(*config.Config)
}

func NewConfigPool(root string, allocate func(string)*config.Config, deallocate func(*config.Config)) *_ConfigPool {
	c := &_ConfigPool{}
	c._root = root
	c._allocate = allocate
	c._deallocate = deallocate
	return c
}

func (c *_ConfigPool) allocate() *config.Config {
	return c._allocate(c._root)
}

func(c *_ConfigPool) deallocate( settings *config.Config) {
	c._deallocate(settings)
}

type  _unknown_internal_error struct {
	*exception.PortageException
}
// ""
func New_unknown_internal_error(value string) *_unknown_internal_error {
	u := &_unknown_internal_error{}
	u.PortageException = &exception.PortageException{value: value}
	return u
}

// nil, nil, nil
func NewScheduler(settings *config.Config, trees, atom.mtimedb, myopts, spinner, mergelist, favorites, graph_config) *Scheduler {
	s := &Scheduler{}

	s._loadavg_latency = 30
	s._max_display_latency = 3
	s._opts_ignore_blockers = map[string]bool{"--buildpkgonly": true,
		"--fetchonly": true, "--fetch-all-uri": true,
		"--nodeps": true, "--pretend": true,}
	s._opts_no_background = map[string]bool{"--pretend": true,
		"--fetchonly": true, "--fetch-all-uri": true}
	s._opts_no_self_update = map[string]bool{"--buildpkgonly": true,
		"--fetchonly": true, "--fetch-all-uri": true, "--pretend": true}

	s.PollScheduler = NewPollScheduler(true, nil)

	s.settings = settings
	s.target_root = settings.ValueDict["EROOT"]
	s.trees = trees
	s.myopts = myopts
	s._spinner = spinner
	s._mtimedb = atom.mtimedb
	s._favorites = favorites
	s._args_set = sets.NewInternalPackageSet(favorites, true, true)
	s._build_opts = &_build_opts_class{}

	for k
		in
	s._build_opts.__slots__ {
		setattr(s._build_opts, k, myopts.get("--"+k.replace("_", "-")))
	}
	s._build_opts.buildpkg_exclude = sets.NewInternalPackageSet(
		" ".join(myopts.get("--buildpkg-exclude", [])).split(), true, true)
	if s.settings.Features.Features["mirror"] {
		s._build_opts.fetch_all_uri = true
	}

	s._binpkg_opts = &_binpkg_opts_class{}
	for k
		in
	s._binpkg_opts.__slots__:
	setattr(s._binpkg_opts, k, "--"+k.replace("_", "-")
	in
	myopts)

	s.curval = 0
	s._logger = &_emerge_log_class{}
	s._task_queues = &_task_queues_class{}
	s._task_queues.merge= NewSequentialTaskQueue()
	s._task_queues.jobs= NewSequentialTaskQueue()
	s._task_queues.ebuild_locks= NewSequentialTaskQueue()
	s._task_queues.fetch= NewSequentialTaskQueue()
	s._task_queues.unpack= NewSequentialTaskQueue()

	s._merge_wait_queue = deque()
	s._merge_wait_scheduled = []string{}

	s._deep_system_deps = map[string]string{}

	s._unsatisfied_system_deps = map[string]string{}

	s._status_display = NewJobStatusDisplay(false, !settings.Features.Features["notitles"])
	s._max_load = myopts.get("--load-average")
	max_jobs := myopts.get("--jobs")
	if max_jobs == nil {
		max_jobs = 1
	}
	s._set_max_jobs(max_jobs)
	s._running_root = trees[trees._running_eroot]["root_config"]
	s.edebug = 0
	if settings.ValueDict["PORTAGE_DEBUG"] == "1" {
		s.edebug = 1
	}
	s.pkgsettings = map[string]*config.Config{}
	s._config_pool = map[string][]*config.Config{}
	for root
		in
	s.trees {
		s._config_pool[root] = []*config.Config{}
	}

	s._fetch_log = filepath.Join(atom._emerge_log_dir, "emerge-fetch.log")
	fetch_iface := &_fetch_iface_class{log_file: s._fetch_log,
		schedule: s._schedule_fetch}
	s._sched_iface = &_iface_class{
		s._event_loop,
		is_background:  s._is_background,
		fetch:          fetch_iface,
		scheduleSetup:  s._schedule_setup,
		scheduleUnpack: s._schedule_unpack}

	s._prefetchers = weakref.WeakValueDictionary()
	s._pkg_queue = []string{}
	s._jobs = 0
	s._running_tasks =
	{
	}
	s._completed_tasks = map[string]string{}
	s._main_exit = nil
	s._main_loadavg_handle = nil
	s._schedule_merge_wakeup_task = nil

	s._failed_pkgs = []*_failed_pkg{}
	s._failed_pkgs_all = []*_failed_pkg{}
	s._failed_pkgs_die_msgs = []string{}
	s._post_mod_echo_msgs = []string{}
	s._parallel_fetch = false
	s._init_graph(graph_config)
	merge_count := 0
	for x
		in
	s._mergelist {
		if isinstance(x, structs.Package) &&
			x.operation == "merge" {
			merge_count++
		}
	}
	s._pkg_count = &_pkg_count_class{curval: 0, maxval: merge_count}
	s._status_display.maxval = s._pkg_count.maxval

	s._job_delay_max = 5
	s._previous_job_start_time = 0
	s._job_delay_timeout_id = nil

	s._sigcont_delay = 5
	s._sigcont_time = 0

	s._choose_pkg_return_early = false

	features := s.settings.Features.Features
	if features["parallel-fetch"] &&
		not("--pretend" in
	s.myopts ||
		"--fetch-all-uri"
	in
	s.myopts ||
		"--fetchonly"
	in
	s.myopts):
	if !features["distlocks"] {
		msg.WriteMsg(output.Red("!!!")+"\n", -1, nil)
		msg.WriteMsg(output.Red("!!!")+" parallel-fetching "+
			"requires the distlocks feature enabled"+"\n",
			-1, nil)
		msg.WriteMsg(output.Red("!!!")+" you have it disabled, "+
			"thus parallel-fetching is being disabled"+"\n",
			-1, nil)
		msg.WriteMsg(output.Red("!!!")+"\n", -1, nil)
	} else if merge_count > 1 {
		s._parallel_fetch = true
	}

	if s._parallel_fetch {
		f, err := os.OpenFile(s._fetch_log, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			//except EnvironmentError:
			//pass
		} else {
			f.Close()
		}
	}

	s._running_portage = nil
	portage_match := s._running_root.trees.VarTree().dbapi.match(
		PORTAGE_PACKAGE_ATOM, 1)
	if len(portage_match) > 0 {
		cpv := portage_match[len(portage_match)-1]
		portage_match = portage_match[:len(portage_match)-1]
		s._running_portage = s._pkg(cpv, "installed",
			s._running_root, true, nil, nil)
	}
	return s
}

func (s *Scheduler) _handle_self_update() int {

	if s._opts_no_s_update.intersection(s.myopts) {
		return 0
	}

	for x
		in
	s._mergelist {
		if not isinstance(x, structs.Package):
		continue
		if x.operation != "merge" {
			continue
		}
		if x.root != s._running_root.root {
			continue
		}
		if len( dep.matchFromList(PORTAGE_PACKAGE_ATOM, []*versions.PkgStr{x}))==0 {
			continue
		}
		rval := atom._check_temp_dir(s.settings)
		if rval != 0 {
			return rval
		}
		_prepare_s_update(s.settings)
		break
	}

	return 0
}

func (s*Scheduler)_terminate_tasks() {
	s._status_display.quiet = true
	for task
		in
	list(s._running_tasks.values()) {
		if task.isAlive() {
			task.cancel()
		}else {
			del
			s._running_tasks[id(task)]
		}
	}

	for q
		in
	s._task_queues.values() {
		q.clear()
	}
}

func (s*Scheduler) _init_graph( graph_config) {
	s._set_graph_config(graph_config)
	s._blocker_db = map[string]*BlockerDB{}
	depgraph_params := atom.create_depgraph_params(s.myopts, "")
	dynamic_deps:= myutil.Inmss(depgraph_params, "dynamic_deps")

	ignore_built_slot_operator_deps := s.myopts.get(
		"--ignore-built-slot-operator-deps", "n") == "y"
	for root
		in
	s.trees {
		if graph_config == nil {
			fake_vartree := NewFakeVartree(s.trees[root]["root_config"],
				s._pkg_cache,nil,  dynamic_deps, ignore_built_slot_operator_deps, false)
			fake_vartree.sync(1)
		}else {
			fake_vartree = graph_config.trees[root]['vartree']
		}
		s._blocker_db[root] = NewBlockerDB(fake_vartree)
	}
}

func (s *Scheduler) _destroy_graph() {
	s._blocker_db = nil
	s._set_graph_config(nil)
	gc.collect()
}

func (s *Scheduler) _set_max_jobs( max_jobs int) {
	s._max_jobs = max_jobs
	s._task_queues.jobs.max_jobs = max_jobs
	if s.settings.Features.Features["parallel-install"] {
		s._task_queues.merge.max_jobs = max_jobs
	}
}

func (s*Scheduler) _background_mode() bool {
	background := (s._max_jobs
	is
	true ||
		s._max_jobs > 1 ||
		"--quiet"
	in
	s.myopts ||
		s.myopts.get("--quiet-build") == "y") &&
	not
	bool(s._opts_no_background.intersection(s.myopts))

	if background {
		interactive_tasks := s._get_interactive_tasks()
		if interactive_tasks{
			background = false
			msg.WriteMsgLevel(">>> Sending package output to stdio due "+
				"to interactive package(s):\n",
				10, -1)
			msg := []string{""}
			for versions.pkg
				in
			interactive_tasks {
				pkg_str := "  " + output.colorize("INFORM", fmt.Sprint(versions.pkg.cpv))
				if versions.pkg.root_config.settings.ValueDict["ROOT"] != "/" {
					pkg_str += " for " + versions.pkg.root
				}
				msg= append(msg, pkg_str)
			}
			msg= append(msg, "")
			msg.WriteMsgLevel(strings.Join(msg, "\n")+"\n", 20, -1)
			if s._max_jobs is
			true ||
				s._max_jobs > 1
			{
				s._set_max_jobs(1)
				msg.WriteMsgLevel(">>> Setting --jobs=1 due "+
					"to the above interactive package(s)\n",
					20, -1)
				msg.WriteMsgLevel(">>> In order to temporarily mask "+
					"interactive updates, you may\n"+
					">>> specify --accept-properties=-interactive\n",
					20, -1)
			}
		}
	}
	s._status_display.quiet =
		not
	background ||
		("--quiet"
	in
	s.myopts&&
		"--verbose"
	not
	in
	s.myopts)

	s._logger.xterm_titles = !s.settings.Features.Features["notitles"]&& s._status_display.quiet

	return background
}

func (s *Scheduler) _get_interactive_tasks() {
	interactive_tasks := []{}
	for task
		in
	s._mergelist:
	if not(isinstance(task, Package) &&
		task.operation == "merge"){
		continue
	}
	if 'interactive' in
	task.properties:
	interactive_tasks.append(task)
	return interactive_tasks
}

func(s *Scheduler) _set_graph_config( graph_config) {

	if graph_config == nil {
		s._graph_config = nil
		s._pkg_cache =
		{
		}
		s._digraph = nil
		s._mergelist = []
		s._world_atoms = nil
		s._deep_system_deps= map[string]string{}
		return
	}

	s._graph_config = graph_config
	s._pkg_cache = graph_config.pkg_cache
	s._digraph = graph_config.graph
	s._mergelist = graph_config.mergelist

	s._world_atoms =
	{
	}
	for pkg
		in
	s._mergelist:
	if getattr(pkg, 'operation', nil) != 'merge':
	continue
	atom = create_world_atom(pkg, s._args_set,
		pkg.root_config, before_install = true)
	if atom != nil:
	s._world_atoms[pkg] = atom

	if "--nodeps" in
	s.myopts ||
		(s._max_jobs
	is
	not
	true&&
		s._max_jobs < 2):
	s._digraph = nil
	graph_config.graph = nil
	graph_config.pkg_cache.clear()
	s._deep_system_deps.clear()
	for pkg
		in
	s._mergelist:
	s._pkg_cache[pkg] = pkg
	return

	s._find_system_deps()
	s._prune_digraph()
	s._prevent_builddir_collisions()
	if '--debug' in
	s.myopts:
	WriteMsg("\nscheduler digraph:\n\n",  -1, nil)
	s._digraph.debug_print()
	WriteMsg("\n", -1, nil)
}

func (s *Scheduler) _find_system_deps() {
	params := atom.create_depgraph_params(s.myopts, "")
	if not params["implicit_system_deps"] {
		return
	}

	deep_system_deps := s._deep_system_deps
	deep_system_deps = map[string]string{}
	deep_system_deps.update(
		_find_deep_system_runtime_deps(s._digraph))
	deep_system_deps.difference_update([versions.pkg
	for versions.pkg
		in
	deep_system_deps
	if versions.pkg.operation != "merge"])
}

func (s *Scheduler) _prune_digraph() {

	graph := s._digraph
	completed_tasks := s._completed_tasks
	removed_nodes := map[string]bool{}
	for {
		for node in graph.root_nodes(){
			if not isinstance(node, structs.Package) ||(node.installed && node.operation == "nomerge") ||
				node.onlydeps || node in completed_tasks{
				removed_nodes[node] = true
			}
		}
		if len(removed_nodes) > 0 {
			graph.difference_update(removed_nodes)
		}
		if len(removed_nodes) == 0 {
			break
		}
		removed_nodes = map[string]bool{}
	}
}

func (s *Scheduler) _prevent_builddir_collisions() {
	cpv_map :=
	{
	}
	for versions.pkg
		in
	s._mergelist {
		if not isinstance(versions.pkg, structs.Package) {
			continue
		}
		if versions.pkg.installed {
			continue
		}
		if versions.pkg.cpv not
		in
		cpv_map{
			cpv_map[versions.pkg.cpv] = [pkg]
			continue
		}
		for earlier_pkg
			in
		cpv_map[versions.pkg.cpv] {
			s._digraph.add(earlier_pkg, versions.pkg,
				priority = NewDepPriority(true))
		}
		cpv_map[versions.pkg.cpv].append(versions.pkg)
	}
}

type  _pkg_failure struct {
	exception.PortageException
	status int
}
func New_pkg_failure(status *int, pargs) *_pkg_failure {
	p := &_pkg_failure{}
	p.status = 1
	p.PortageException = NewPortageException(pargs)
	if status != nil {
		p.status = *status
	}

	return p
}

func (s *Scheduler) _schedule_fetch( fetcher) {
	if s._max_jobs > 1 {
		fetcher.start()
	}else {
		s._task_queues.fetch.addFront(fetcher)
	}
}

func (s *Scheduler) _schedule_setup( setup_phase) {
	if s._task_queues.merge.max_jobs > 1 && s.settings.Features.Features["ebuild-locks"] {
		s._task_queues.ebuild_locks.add(setup_phase)
	}else {
		s._task_queues.merge.add(setup_phase)
	}
	s._schedule()
}

func (s *Scheduler) _schedule_unpack( unpack_phase) {
	s._task_queues.unpack.add(unpack_phase)
}

func (s *Scheduler) _find_blockers( new_pkg) {
	get_blockers:= func() {
		return s._find_blockers_impl(new_pkg)
	}
	return get_blockers
}

func (s *Scheduler) _find_blockers_impl(new_pkg) {
	if s._opts_ignore_blockers.intersection(s.myopts) {
		return nil
	}

	blocker_db := s._blocker_db[new_pkg.root]

	blocked_pkgs := []{}
	for blocking_pkg
		in
	blocker_db.findInstalledBlockers(new_pkg) {
		if new_pkg.slot_atom == blocking_pkg.slot_atom {
			continue
		}
		if new_pkg.cpv == blocking_pkg.cpv {
			continue
		}
		blocked_pkgs.append(blocking_pkg)
	}

	return blocked_pkgs
}

func (s *Scheduler) _generate_digests() int {

	digest := '--digest'
	in
	s.myopts
	if ! digest {
		for _, pkgsettings := range s.pkgsettings {
			if pkgsettings.mycpv != nil {
				pkgsettings.reset(0)
			}
			if pkgsettings.Features.Features["digest"] {
				digest = true
				break
			}
		}
	}

	if ! digest {
		return 0
	}

	for x
		in
	s._mergelist:
	if not isinstance(x, structs.Package) ||
		x.type_name != 'ebuild' ||
		x.operation != 'merge':
	continue
	pkgsettings = s.pkgsettings.ValueDict[x.root]
	if pkgsettings.mycpv != nil:
	pkgsettings.reset()
	if '--digest' not
	in
	s.myopts&&
		'digest'
	not
	in
	pkgsettings.Features.Features:
	continue
	atom.portdb = x.root_config.trees['porttree'].dbapi
	ebuild_path = atom.portdb.findname(x.cpv, myrepo = x.repo)
	if ebuild_path == nil:
	raise
	AssertionError("ebuild not found for '%s'" % x.cpv)
	pkgsettings.ValueDict['O'] =  filepath.Dir(ebuild_path)
	if atom.digestgen(nil,  pkgsettings, atom.portdb)==0 {
		msg.WriteMsgLevel(fmt.Sprintf("!!! Unable to generate manifest for '%s'.\n", x.cpv), 40,-1)
		return FAILURE
	}

	return 0
}

func (s *Scheduler) _check_manifests() int {
	if  !s.settings.Features["strict"] ||
		"--fetchonly"
		in
	s.myopts ||
		"--fetch-all-uri"
	in
	s.myopts{
		return 0
	}

	shown_verifying_msg := false
	quiet_settings :=map[string]*config.Config{}
	for myroot, pkgsettings := range s.pkgsettings{
		quiet_config := config.NewConfig(pkgsettings,nil, "", nil, "","","","",true, nil, false, nil)
		quiet_config.ValueDict["PORTAGE_QUIET"] = "1"
		quiet_config.BackupChanges("PORTAGE_QUIET")
		quiet_settings[myroot] = quiet_config
		quiet_config.ValueDict = map[string]string{}
	}

	failures := 0

	for x
		in
	s._mergelist {
		if not isinstance(x, structs.Package) ||
			x.type_name != "ebuild" {
			continue
		}

		if x.operation == "uninstall" {
			continue
		}

		if ! shown_verifying_msg {
			shown_verifying_msg = true
			s._status_msg("Verifying ebuild manifests")
		}

		root_config = x.root_config
		atom.portdb = root_config.trees["porttree"].dbapi
		quiet_config = quiet_settings.ValueDict[root_config.root]
		ebuild_path = atom.portdb.findname(x.cpv, myrepo = x.repo)
		if ebuild_path == nil:
		raise
		AssertionError("ebuild not found for '%s'" % x.cpv)
		quiet_config["O"] =  filepath.Dir(ebuild_path)
		if not atom.Digestcheck([], quiet_config, strict = true):
		failures |= 1
	}


	if failures!= 0 {
		return FAILURE
	}
	return 0
}

func (s *Scheduler) _add_prefetchers() {

	if ! s._parallel_fetch {
		return
	}

	if s._parallel_fetch {
		prefetchers := s._prefetchers

		for versions.pkg
			in
		s._mergelist {
			if not isinstance(versions.pkg, structs.Package) ||
				versions.pkg.operation == "uninstall" {
				continue
			}
			prefetcher = s._create_prefetcher(versions.pkg)
			if prefetcher != nil {
				prefetchers[versions.pkg] = prefetcher
				s._task_queues.fetch.add(prefetcher)
			}
		}
	}
}

func (s *Scheduler) _create_prefetcher( pkg *structs.Package) {
	prefetcher = nil

	if pkg.type_name == "ebuild" {
		prefetcher = NewEbuildFetcher(NewConfigPool(pkg.root, s._allocate_config,
			s._deallocate_config), "", s._build_opts.fetch_all_uri, 1, true,
			s._fetch_log, pkg, s._sched_iface, true)
	} else if
	pkg.type_name == "binary" &&
		"--getbinpkg"
		in
	s.myopts &&
		pkg.root_config.trees["bintree"].isremote(pkg.cpv)
	{
		prefetcher = NewBinpkgPrefetcher(true, pkg, s._sched_iface)
	}

	return prefetcher
}

func (s *Scheduler) _run_pkg_pretend()  int {

	failures := 0
	sched_iface := s._sched_iface

	for x
		in
	s._mergelist {
		if not isinstance(x, structs.Package) {
			continue
		}

		if x.operation == "uninstall" {
			continue
		}

		if myutil.Ins([]string{"0", "1", "2", "3"}, x.eapi) {
			continue
		}

		if "pretend" not
		in
		x.defined_phases{
			continue
		}

		out_str := ">>> Running pre-merge checks for " + output.colorize("INFORM", x.cpv) + "\n"
		msg.WriteMsgStdout(out_str, -1)

		root_config := x.root_config
		settings := s.pkgsettings[root_config.root]
		settings.SetCpv(x, nil)

		rval := atom._check_temp_dir(settings)
		if rval != 0 {
			return rval
		}

		fpes, _ := filepath.EvalSymlinks(settings.ValueDict["PORTAGE_TMPDIR"])
		build_dir_path := filepath.Join(fpes, "portage", x.category, x.pf)
		existing_builddir := myutil.pathIsDir(build_dir_path)
		settings.ValueDict["PORTAGE_BUILDDIR"] = build_dir_path
		build_dir := NewEbuildBuildDir(sched_iface, settings)
		sched_iface.run_until_complete(build_dir.async_lock())
		current_task = nil

	try:

		var tree, infloc, ebuild_path string
		if existing_builddir {
			if x.built {
				tree = "bintree"
				infloc = filepath.Join(build_dir_path, "build-info")
				ebuild_path = filepath.Join(infloc, x.pf+".ebuild")
			} else {
				tree = "porttree"
				atom.portdb = root_config.trees["porttree"].dbapi
				ebuild_path = atom.portdb.findname(x.cpv, myrepo = x.repo)
				if ebuild_path == nil {
					raise
					AssertionError(
						"ebuild not found for '%s'" % x.cpv)
				}
			}
			atom.doebuild_environment(
				ebuild_path, "clean", settings, false, nil,
				s.trees[settings.ValueDict["EROOT"]][tree].dbapi)
			clean_phase := NewEbuildPhase(nil, false, "clean", sched_iface, settings, nil)
			current_task = clean_phase
			clean_phase.start()
			clean_phase.wait()
		}

		if x.built {
			tree = "bintree"
			bintree = root_config.trees["bintree"].dbapi.bintree
			fetched = false

			if bintree.isremote(x.cpv):
			fetcher = NewBinpkgFetcher(false, "", x, nil, sched_iface)
			fetcher.start()
			if fetcher.wait() != 0:
			failures += 1
			continue
			fetched = fetcher.pkg_path

			if fetched is
		false:
			filename = bintree.getname(x.cpv)
			else:
			filename = fetched
			verifier = NewBinpkgVerifier(false, "", x,
				sched_iface, filename)
			current_task = verifier
			verifier.start()
			if verifier.wait() != 0:
			failures += 1
			continue

			if fetched:
			bintree.inject(x.cpv, filename = fetched)

			infloc = filepath.Join(build_dir_path, "build-info")
			util.EnsureDirs(infloc)
			s._sched_iface.run_until_complete(
				bintree.dbapi.unpack_metadata(settings, infloc))
			ebuild_path = filepath.Join(infloc, x.pf+".ebuild")
			settings.configDict["pkg"]["EMERGE_FROM"] = "binary"
			settings.configDict["pkg"]["MERGE_TYPE"] = "binary"

		}else {
			tree = "porttree"
			atom.portdb = root_config.trees["porttree"].dbapi
			ebuild_path = atom.portdb.findname(x.cpv, myrepo = x.repo)
			if ebuild_path == nil:
			raise
			AssertionError("ebuild not found for '%s'" % x.cpv)
			settings.configDict["pkg"]["EMERGE_FROM"] = "ebuild"
			if s._build_opts.buildpkgonly:
			settings.configDict["pkg"]["MERGE_TYPE"] = "buildonly"
			else:
			settings.configDict["pkg"]["MERGE_TYPE"] = "source"
		}

		atom.doebuild_environment(ebuild_path,
			"pretend", nil, settings, false, nil,
			s.trees[settings.ValueDict["EROOT"]][tree].dbapi)

		atom.Prepare_build_dirs(settings, false)

		vardb = root_config.trees['vartree'].dbapi
		settings.ValueDict["REPLACING_VERSIONS"] = " ".join(
			set(portage.versions.cpv_getversion(match)
		for match
			in
		vardb.match(x.slot_atom) +
			vardb.match('='+x.cpv)))
		pretend_phase := NewEbuildPhase(nil, false, "pretend", sched_iface, settings, nil)

		current_task = pretend_phase
		pretend_phase.start()
		ret := pretend_phase.wait()
		if ret != 0 {
			failures += 1
		}
		elog.elog_process(x.cpv, settings, nil)
	finally:

		if current_task != nil {
			if current_task.isAlive() {
				current_task.cancel()
				current_task.wait()
			}
			if current_task.returncode == 0 {
				clean_phase := NewEbuildPhase(nil, false, "clean", sched_iface, settings, nil)
				clean_phase.start()
				clean_phase.wait()
			}
		}

		sched_iface.run_until_complete(build_dir.async_unlock())
	}

	if failures != 0{
		return FAILURE
	}
	return 0
}

func (s *Scheduler) merge() int {
	if "--resume" in
	s.myopts{
		msg.WriteMsgStdout(
			output.colorize("GOOD", "*** Resuming merge...\n"), -1)
		s._logger.log(" *** Resuming merge...", "")
	}

	s._save_resume_list()

//try:
	s._background = s._background_mode()
	//except s._unknown_internal_error:
	//return FAILURE

	rval := s._handle_self_update()
	if rval != 0 {
		return rval
	}

	for root
		in
	s.trees {
		root_config = s.trees[root]["root_config"]

		tmpdir := root_config.settings.ValueDict["PORTAGE_TMPDIR"]
		if tmpdir == "" || !myutil.pathIsDir(tmpdir):
		msg := []string{
			"The directory specified in your PORTAGE_TMPDIR variable does not exist:",
			tmpdir,
			"Please create this directory or correct your PORTAGE_TMPDIR setting.",
		}
		out := output.NewEOutput(false)
		for _, l := range msg {
			out.eerror(l)
			return FAILURE
		}

		if s._background {
			root_config.settings.unlock()
			root_config.settings.ValueDict["PORTAGE_BACKGROUND"] = "1"
			root_config.settings.backup_changes("PORTAGE_BACKGROUND")
			root_config.settings.lock()
		}

		s.pkgsettings[root] = config.NewConfig(root_config.settings, nil, "", nil, "", "", "", "", true, nil, false, nil)
	}

	keep_going := "--keep-going"
	in
	s.myopts
	fetchonly := s._build_opts.fetchonly
	mtimedb := s._mtimedb
	failed_pkgs := s._failed_pkgs

	rval = s._generate_digests()
	if rval != 0 {
		return rval
	}

	rval = s._check_manifests()
	if rval != 0 && !keep_going {
		return rval
	}

	if not fetchonly:
	rval = s._run_pkg_pretend()
	if rval != 0 {
		return rval
	}

	for {
		received_signal := []int{}

		sighandler := func(signum int, frame) {
			signal.signal(signal.SIGINT, signal.SIG_IGN)
			signal.signal(signal.SIGTERM, signal.SIG_IGN)
			msg.WriteMsg(fmt.Sprintf("\n\nExiting on signal %s\n", signum), 0, nil)
			s.terminate()
			received_signal = append(received_signal, 128+signum)
		}

		earlier_sigint_handler = signal.signal(signal.SIGINT, sighandler)
		earlier_sigterm_handler = signal.signal(signal.SIGTERM, sighandler)
		earlier_sigcont_handler = signal.signal(signal.SIGCONT, s._sigcont_handler)
		signal.siginterrupt(signal.SIGCONT, false)

	try:
		rval = s._merge()
	finally:
		if earlier_sigint_handler != nil:
		signal.signal(signal.SIGINT, earlier_sigint_handler) else:
		signal.signal(signal.SIGINT, signal.SIG_DFL)
		if earlier_sigterm_handler != nil:
		signal.signal(signal.SIGTERM, earlier_sigterm_handler) else:
		signal.signal(signal.SIGTERM, signal.SIG_DFL)
		if earlier_sigcont_handler != nil:
		signal.signal(signal.SIGCONT, earlier_sigcont_handler) else:
		signal.signal(signal.SIGCONT, signal.SIG_DFL)

		s._termination_check(false)
		if len(received_signal) > 0 {
			os.Exit(received_signal[0])
		}

		if rval == 0 || fetchonly || !keep_going {
			break
		}
		if "resume" not
		in
		mtimedb{
			break
		}
		mergelist = s._mtimedb["resume"].get("mergelist")
		if not mergelist {
			break
		}

		if not failed_pkgs:
		break

		for failed_pkg
			in
		failed_pkgs:
		mergelist.remove(list(failed_pkg.pkg))

		s._failed_pkgs_all = append(s._failed_pkgs_all, failed_pkgs...)
		del
		failed_pkgs[:]

		if not mergelist:
		break

		if not s._calc_resume_list():
		break

		clear_caches(s.trees)
		if not s._mergelist:
		break

		s._save_resume_list()
		s._pkg_count.curval = 0

		s._pkg_count.maxval = 0
		for x
			in
		s._mergelist {
			if isinstance(x, structs.Package) &&
				x.operation == "merge" {
				s._pkg_count.maxval += 1
			}
		}
		s._status_display.maxval = s._pkg_count.maxval
	}

	s._cleanup()

	s._logger.log(" *** Finished. Cleaning up...")

	if failed_pkgs {
		s._failed_pkgs_all.extend(failed_pkgs)
		del
		failed_pkgs[:]
	}

	printer := output.NewEOutput(false)
	background := s._background
	failure_log_shown := false
	if background && len(s._failed_pkgs_all) == 1 &&
		s.myopts.get('--quiet-fail', 'n') != 'y' {
		failed_pkg := s._failed_pkgs_all[len(s._failed_pkgs_all)-1]
		log_file := nil
		log_file_real := nil

		log_path := s._locate_failure_log(failed_pkg)
		if log_path != nil:
	try:
		log_file = open(_unicode_encode(log_path,
			encoding = _encodings['fs'], errors = 'strict'), mode = 'rb')
		except
	IOError:
		pass else:
		if log_path.endswith('.gz'):
		log_file_real = log_file
		log_file = gzip.GzipFile(filename = '',
			mode = 'rb', fileobj = log_file)

		if log_file != nil:
	try:
		for line
			in
		log_file:
		msg.WriteMsgLevel(line, -1, 0)
		except
		zlib.error
		as
	e:
		msg.WriteMsgLevel("%s\n"%(e, ), level = 40,
			noiselevel = -1)
	finally:
		log_file.close()
		if log_file_real != nil:
		log_file_real.close()
		failure_log_shown = true
	}

	mod_echo_output = _flush_elog_mod_echo()

	if background && ! failure_log_shown &&
		s._failed_pkgs_all &&
		s._failed_pkgs_die_msgs &&
		!mod_echo_output {

		for mysettings, key, logentries
			in
		s._failed_pkgs_die_msgs {
			root_msg := ""
			if mysettings.ValueDict["ROOT"] != "/" {
				root_msg = fmt.Sprintf(" merged to %s", mysettings.ValueDict["ROOT"])
			}
			print()
			printer.einfo("Error messages for package %s%s:"%
				(output.colorize("INFORM", key), root_msg))
			print()
			for phase := range _const.EBUILD_PHASES {
				if phase not
				in
				logentries{
				continue
			}
				for msgtype, msgcontent
				in
				logentries[phase]{
				if isinstance(msgcontent, basestring){
				msgcontent = []string{msgcontent}
			}
				for _, line := range msgcontent{
				printer.eerror(strings.Trim(line, "\n"))
			}
			}
			}
		}
	}

	if len(s._post_mod_echo_msgs) > 0 {
		for msg
			in
		s._post_mod_echo_msgs {
			msg()
		}
	}

	if len(s._failed_pkgs_all) > 1 || (len(s._failed_pkgs_all) > 0 && keep_going) {
		msg := ""
		if len(s._failed_pkgs_all) > 1 {
			msg = fmt.Sprintf("The following %d packages have ",
				len(s._failed_pkgs_all)) +
				"failed to build, install, or execute postinst:"
		} else {
			msg = "The following package has " +
				"failed to build, install, or execute postinst:"
		}

		printer.eerror("")
		for _, line := range myutil.SplitSubN(msg, 72) {
			printer.eerror(line)
		}
		printer.eerror("")
		for _, failed_pkg := range s._failed_pkgs_all {
			msg = fmt.Sprintf(" %s", failed_pkg.pkg, )
			if failed_pkg.postinst_failure != "" {
				msg += " (postinst failed)"
			}
			log_path := s._locate_failure_log(failed_pkg)
			if log_path != nil {
				msg += ", Log file:"
			}
			printer.eerror(msg)
			if log_path != nil {
				printer.eerror(fmt.Sprintf("  '%s'", output.colorize("INFORM", log_path)))
			}
		}
		printer.eerror("")
	}

	if len(s._failed_pkgs_all) > 0 {
		return FAILURE
	}
	return 0
}

func (s *Scheduler) _elog_listener(mysettings *config.Config, key, logentries logentries map[string][][2]string, fulltext) {
	errors := elog.filter_loglevels(logentries, map[string]bool{"ERROR": true})
	if len(errors) > 0 {
		s._failed_pkgs_die_msgs = append(s._failed_pkgs_die_msgs,
			(mysettings, key, errors))
	}
}

func (s *Scheduler) _locate_failure_log( failed_pkg *_failed_pkg) string {

	log_paths := []string{failed_pkg.build_log}

	for _, log_path := range log_paths {
		if log_path == "" {
			continue
		}
		st, err := os.Stat(log_path)
		if err != nil {
			//except OSError:
			continue
		}
		log_size := st.Size()

		if log_size == 0 {
			continue
		}

		return log_path
	}

	return ""
}

func (s *Scheduler) _add_packages() {
	pkg_queue := s._pkg_queue
	for versions.pkg
		in
	s._mergelist {
		if isinstance(versions.pkg, structs.Package) {
			pkg_queue.append(versions.pkg)
		}else if
		isinstance(versions.pkg, Blocker) {
			//pass
		}
	}
}

func (s *Scheduler) _system_merge_started(dbapi.merge) {
	graph := s._digraph
	if graph == nil {
		return
	}
	versions.pkg = dbapi.merge.merge.pkg

	if versions.pkg.root_config.settings.ValueDict["ROOT"] != "/" {
		return
	}

	completed_tasks := s._completed_tasks
	unsatisfied := s._unsatisfied_system_deps
	ignore_non_runtime_or_satisfied := func(priority) {
		if isinstance(priority, DepPriority) &&
			not
			priority.satisfied
		&&
		(priority.runtime ||
			priority.runtime_post)
		{
			return false
		}
		return true
	}

	for child
		in
	graph.child_nodes(versions.pkg,
		ignore_priority = ignore_non_runtime_or_satisfied):
	if not isinstance(child, structs.Package) ||
		child.operation == "uninstall":
	continue
	if child is
pkg:
	continue
	if child.operation == "merge" &&
		child
		not
	in
completed_tasks:
	unsatisfied.add(child)
}

func (s *Scheduler) _merge_wait_exit_handler( task) {
	s._merge_wait_scheduled.remove(task)
	s._merge_exit(task)
}

func (s *Scheduler) _merge_exit(dbapi.merge) {
	s._running_tasks.pop(id(dbapi.merge), nil)
	s._do_merge_exit(dbapi.merge)
	s._deallocate_config(dbapi.merge.merge.settings)
	if dbapi.merge.returncode == 0 &&
		not
		dbapi.merge.merge.pkg.installed {
		s._status_display.curval += 1
	}
	s._status_display.merges = len(s._task_queues.merge)
	s._schedule()
}

func (s *Scheduler) _do_merge_exit(dbapi.merge) {
	versions.pkg = dbapi.merge.merge.pkg
	if dbapi.merge.returncode != 0 {
		settings := dbapi.merge.merge.settings
		build_dir := settings.ValueDict["PORTAGE_BUILDDIR"]
		build_log := settings.ValueDict["PORTAGE_LOG_FILE"]

		s._failed_pkgs = append(s._failed_pkgs, &_failed_pkg{
			build_dir, build_log,
			versions.pkg, nil,
			dbapi.merge.returncode})
		if ! s._terminated_tasks {
			s._failed_pkg_msg(s._failed_pkgs[len(s._failed_pkgs)-1], "install", "to")
			s._status_display.failed = len(s._failed_pkgs)
		}
		return
	}

	if dbapi.merge.postinst_failure {
		s._failed_pkgs_all = append(s._failed_pkgs_all, &_failed_pkg{
			dbapi.merge.merge.settings.ValueDict["PORTAGE_BUILDDIR"],
			dbapi.merge.merge.settings.ValueDict["PORTAGE_LOG_FILE"],
			versions.pkg, true, dbapi.merge.returncode})
		s._failed_pkg_msg(s._failed_pkgs_all[len(s._failed_pkgs_all)-1],
			"execute postinst for", "for")
	}

	s._task_complete(versions.pkg)
	pkg_to_replace = dbapi.merge.merge.pkg_to_replace
	if pkg_to_replace != nil:
	if s._digraph != nil&&
		pkg_to_replace
		in
	s._digraph:
try:
	s._pkg_queue.remove(pkg_to_replace)
	except
ValueError:
	pass
	s._task_complete(pkg_to_replace)
	else:
	s._pkg_cache.pop(pkg_to_replace, nil)

	if versions.pkg.installed:
	return

	atom.mtimedb = s._mtimedb
	atom.mtimedb["resume"]["mergelist"].remove(list(versions.pkg))
	if not atom.mtimedb["resume"]["mergelist"]:
	del
	atom.mtimedb["resume"]
	atom.mtimedb.commit()
}

func (s *Scheduler) _build_exit( build) {
	s._running_tasks.pop(id(build), nil)
	if build.returncode == 0 &&
		s._terminated_tasks {
		s.curval += 1
		s._deallocate_config(build.settings)
	}else if
	build.returncode == 0 {
		s.curval += 1
		dbapi.merge = NewPackageMerge(build, s._sched_iface)
		s._running_tasks[id(dbapi.merge)] = dbapi.merge
		if not build.build_opts.buildpkgonly &&
			build.pkg
		in
		s._deep_system_deps{
			s._merge_wait_queue.append(dbapi.merge)
			dbapi.merge.addStartListener(s._system_merge_started)
		} else {
			s._task_queues.merge.add(dbapi.merge)
			dbapi.merge.addExitListener(s._merge_exit)
			s._status_display.merges = len(s._task_queues.merge)
		}
	}else{
		settings = build.settings
		build_dir = settings.ValueDict["PORTAGE_BUILDDIR"]
		build_log = settings.ValueDict["PORTAGE_LOG_FILE"]

		s._failed_pkgs = append(s._failed_pkgs, &_failed_pkg{
			build_dir, build_log, build.pkg, "", build.returncode})
		if !s._terminated_tasks {
			s._failed_pkg_msg(s._failed_pkgs[len(s._failed_pkgs)-1], "emerge", "for")
			s._status_display.failed = len(s._failed_pkgs)
		}
		s._deallocate_config(build.settings)
	}
	s._jobs -= 1
	s._status_display.running = s._jobs
	s._schedule()
}

func (s *Scheduler) _extract_exit( build) {
	s._build_exit(build)
}

func (s *Scheduler) _task_complete(versions.pkg) {
	s._completed_tasks.add(versions.pkg)
	s._unsatisfied_system_deps.discard(versions.pkg)
	s._choose_pkg_return_early = false
	blocker_db := s._blocker_db[versions.pkg.root]
	blocker_db.discardBlocker(versions.pkg)
}

func (s *Scheduler) _main_loop() {
	s._main_exit = s._event_loop.create_future()

	if s._max_load != nil&&
		s._loadavg_latency
	!= nil&&
		(s._max_jobs
	is
	true ||
		s._max_jobs > 1):
	s._main_loadavg_handle = s._event_loop.call_later(
		s._loadavg_latency, s._schedule)

	s._schedule()
	s._event_loop.run_until_complete(s._main_exit)
}

func (s *Scheduler) _merge() int {

	if s._opts_no_background.intersection(s.myopts) {
		s._set_max_jobs(1)
	}

	s._add_prefetchers()
	s._add_packages()
	failed_pkgs := s._failed_pkgs
	quiet := s._background
	elog.add_listener(s._elog_listener)


	display_callback:=func() {
		s._status_display.display()
		display_callback.handle = s._event_loop.call_later(
			s._max_display_latency, display_callback)
	}
	display_callback.handle = nil

	if s._status_display._isatty &&
		!s._status_display.quiet {
		display_callback()
	}
	rval := 0

try:
	s._main_loop()
finally:
	s._main_loop_cleanup()
	quiet = false
	elog.remove_listener(s._elog_listener)
	if display_callback.handle != nil {
		display_callback.handle.cancel()
	}
	if len(failed_pkgs) > 0 {
		rval = failed_pkgs[len(failed_pkgs)-1].returncode
	}

	return rval
}

func (s *Scheduler) _main_loop_cleanup() {
	s._pkg_queue = map[]
	s._completed_tasks.clear()
	s._deep_system_deps.clear()
	s._unsatisfied_system_deps.clear()
	s._choose_pkg_return_early = false
	s._status_display.reset()
	s._digraph = nil
	s._task_queues.fetch.clear()
	s._prefetchers.clear()
	s._main_exit = nil
	if s._main_loadavg_handle != nil:
	s._main_loadavg_handle.cancel()
	s._main_loadavg_handle = nil
	if s._job_delay_timeout_id != nil:
	s._job_delay_timeout_id.cancel()
	s._job_delay_timeout_id = nil
	if s._schedule_merge_wakeup_task != nil:
	s._schedule_merge_wakeup_task.cancel()
	s._schedule_merge_wakeup_task = nil
}

func (s *Scheduler) _choose_pkg() {

	if s._choose_pkg_return_early {
		return nil
	}

	if s._digraph == nil:
	if s._is_work_scheduled() &&
		not("--nodeps"
		in
	s.myopts&&
		(s._max_jobs
	is
	true ||
		s._max_jobs > 1)):
	s._choose_pkg_return_early = true
	return nil
	return s._pkg_queue.pop(0)

	if ! s._is_work_scheduled() {
		return s._pkg_queue.pop(0)
	}

	s._prune_digraph()

	chosen_pkg = nil

	graph = s._digraph
	for versions.pkg
		in
	s._pkg_queue:
	if versions.pkg.operation == "uninstall" &&
		not
		graph.child_nodes(versions.pkg):
	chosen_pkg = versions.pkg
	break

	if chosen_pkg == nil:
	later = set(s._pkg_queue)
	for versions.pkg
		in
	s._pkg_queue:
	later.remove(versions.pkg)
	if not s._dependent_on_scheduled_merges(versions.pkg, later):
	chosen_pkg = versions.pkg
	break

	if chosen_pkg != nil:
	s._pkg_queue.remove(chosen_pkg)

	if chosen_pkg == nil:
	s._choose_pkg_return_early = true

	return chosen_pkg
}

func (s *Scheduler) _dependent_on_scheduled_merges(versions.pkg, later) {

	graph := s._digraph
	completed_tasks := s._completed_tasks

	dependent := false
	traversed_nodes := map[string]bool{versions.pkg: true}
	direct_deps := graph.child_nodes(versions.pkg)
	node_stack := direct_deps
	direct_deps := frozenset(direct_deps)
	for len(node_stack) >  0 {

		node = node_stack.pop()
		if node in
	traversed_nodes:
		continue
		traversed_nodes.add(node)
		if not((node.installed &&
			node.operation == "nomerge") ||
			(node.operation == "uninstall" &&
				node
			not
		in
		direct_deps) ||
node
in
completed_tasks ||
node
in
later):
dependent = true
break

if node.operation != "uninstall":
node_stack.extend(graph.child_nodes(node))
}
return dependent
}

func (s *Scheduler) _allocate_config( root string) *config.Config {
	var temp_settings *config.Config
	if s._config_pool[root] != nil {
		temp_settings = s._config_pool[root][len(s._config_pool[root])-1]
		s._config_pool[root]=s._config_pool[root][:len(s._config_pool[root])-1]
	}else {
		temp_settings = config.NewConfig(s.pkgsettings[root], nil, "", nil, "", "", "", "", true, nil, false, nil)
	}
	temp_settings.reload()
	temp_settings.reset(0)
	return temp_settings
}

func (s *Scheduler) _deallocate_config(settings *config.Config) {
	s._config_pool[settings.ValueDict["EROOT"]]=append(s._config_pool[settings.ValueDict["EROOT"]], settings)
}

func (s *Scheduler) _keep_scheduling() bool {
	return bool(!
	s._terminated.is_set()&&
		s._pkg_queue&&
		!(s._failed_pkgs&&
			!
	s._build_opts.fetchonly))
}

func (s *Scheduler) _is_work_scheduled() bool {
	return bool(s._running_tasks)
}

func (s *Scheduler) _running_job_count() {
	return s._jobs
}

func (s *Scheduler) _schedule_tasks() {
	for {
		state_change := 0

		if (s._merge_wait_queue &&
			not
			s._jobs
		&&
		not
		s._task_queues.merge):
		task = s._merge_wait_queue.popleft()
		task.scheduler = s._sched_iface
		s._merge_wait_scheduled.append(task)
		s._task_queues.merge.add(task)
		task.addExitListener(s._merge_wait_exit_handler)
		s._status_display.merges = len(s._task_queues.merge)
		state_change += 1

		if s._schedule_tasks_imp():
		state_change += 1

		s._status_display.display()

		if s._failed_pkgs &&
			!
			s._build_opts.fetchonly
		&&
		!
		s._is_work_scheduled()
		&&
		s._task_queues.fetch:
		s._task_queues.fetch.clear()

		if !(state_change ||
			(s._merge_wait_queue
		&&
		not
		s._jobs
		&&
		not
		s._task_queues.merge)):
		break
	}

	if !(s._is_work_scheduled() || s._keep_scheduling() || s._main_exit.done()) {
		s._main_exit.set_result(nil)
	}else if s._main_loadavg_handle!= nil {
		s._main_loadavg_handle.cancel()
		s._main_loadavg_handle = s._event_loop.call_later(
			s._loadavg_latency, s._schedule)
	}

	if (s._task_queues.merge &&(s._schedule_merge_wakeup_task== nil || s._schedule_merge_wakeup_task.done())) {
		s._schedule_merge_wakeup_task = asyncio.ensure_future(
			s._task_queues.merge.wait(), loop = s._event_loop)
		s._schedule_merge_wakeup_task.add_done_callback(
			s._schedule_merge_wakeup)
	}
}

func (s *Scheduler) _schedule_merge_wakeup( future interfaces.IFuture) {
	if !future.cancelled() {
		future.result()
		if s._main_exit != nil &&
			not
			s._main_exit.done() {
			s._schedule()
		}
	}
}

func (s *Scheduler) _sigcont_handler( signum, frame) {
	s._sigcont_time = time.Now().Second()
}

func (s *Scheduler) _job_delay() bool {

	if s._jobs && s._max_load!= nil {

		current_time := time.Now().Second()

		if s._sigcont_time != nil {

			elapsed_seconds := current_time - s._sigcont_time
			if elapsed_seconds > 0 &&
				elapsed_seconds < s._sigcont_delay {

				if s._job_delay_timeout_id != nil {
					s._job_delay_timeout_id.cancel()
				}

				s._job_delay_timeout_id = s._event_loop.call_later(
					s._sigcont_delay-elapsed_seconds,
					s._schedule)
				return true
			}

			s._sigcont_time = nil
		}

		avg1, avg5, avg15, err := getloadavg()
		if err != nil {
			//except OSError:
			return false
		}

		delay := s._job_delay_max * avg1 / s._max_load
		if delay > s._job_delay_max {
			delay = s._job_delay_max
		}
		elapsed_seconds := current_time - s._previous_job_start_time
		if elapsed_seconds > 0 && elapsed_seconds < delay {
			if s._job_delay_timeout_id != nil {
				s._job_delay_timeout_id.cancel()
			}
			s._job_delay_timeout_id = s._event_loop.call_later(
				delay-elapsed_seconds, s._schedule)
			return true
		}
	}

	return false
}

func (s *Scheduler) _schedule_tasks_imp() bool{
	state_change := 0

	for {
		if ! s._keep_scheduling(){
			return state_change!= 0
		}

		if s._choose_pkg_return_early || s._merge_wait_scheduled || (s._jobs != 0 && len(s._unsatisfied_system_deps) > 0) || ! s._can_add_job() || s._job_delay() {
			return state_change!= 0
		}

		pkg := s._choose_pkg()
		if pkg == nil {
			return state_change != 0
		}

		state_change += 1

		if not pkg.installed {
			s._pkg_count.curval += 1
		}

		task := s._task(pkg)

		if pkg.installed {
			merge := NewPackageMerge(task,  s._sched_iface)
			s._running_tasks[id(merge)] = merge
			s._task_queues.merge.addFront(merge)
			merge.addExitListener(s._merge_exit)
		} else if pkg.built{
			s._jobs += 1
			s._previous_job_start_time = time.Now().Second()
			s._status_display.running = s._jobs
			s._running_tasks[id(task)] = task
			task.scheduler = s._sched_iface
			s._task_queues.jobs.add(task)
			task.addExitListener(s._extract_exit)
		} else{
			s._jobs += 1
			s._previous_job_start_time = time.Now().Second()
			s._status_display.running = s._jobs
			s._running_tasks[id(task)] = task
			task.scheduler = s._sched_iface
			s._task_queues.jobs.add(task)
			task.addExitListener(s._build_exit)
		}
	}
	return state_change!= 0
}

func (s *Scheduler) _get_prefetcher(versions.pkg) {
//try:
	prefetcher := s._prefetchers.pop(versions.pkg, None)
	//except KeyError:
	prefetcher = nil
	if prefetcher != nil&&!prefetcher.isAlive() {
	//try:
		s._task_queues.fetch._task_queue.remove(prefetcher)
		//except ValueError:
		//pass
		prefetcher = nil
	}
	return prefetcher
}

func (s *Scheduler) _task(versions.pkg) {

	var pkg_to_replace = nil
	if versions.pkg.operation != "uninstall" {
		vardb := versions.pkg.root_config.trees["vartree"].dbapi
		previous_cpv := []*versions.PkgStr{}
		for x
			in
		vardb.match(versions.pkg.slot_atom) {
			if versions.cpvGetKey(x, "") == versions.pkg.cp {
				previous_cpv = append(previous_cpv, x)
			}
		}
		if len(previous_cpv) == 0 && vardb.cpv_exists(versions.pkg.cpv) {
			previous_cpv = []*versions.PkgStr{versions.pkg.cpv}
		}
		if len(previous_cpv) != 0 {
			pc := previous_cpv[len(previous_cpv)-1]
			previous_cpv = previous_cpv[:len(previous_cpv)-1]
			pkg_to_replace = s._pkg(pc,
				"installed", versions.pkg.root_config, true,
				"uninstall")
		}
	}

	prefetcher := s._get_prefetcher(versions.pkg)

	pc := *s._pkg_count
	task := NewMergeListItem(s._args_set, s._background, s._binpkg_opts,
		s._build_opts, NewConfigPool(versions.pkg.root, s._allocate_config,
			s._deallocate_config), s.myopts, s._find_blockers(versions.pkg),
		s._logger, s._mtimedb, versions.pkg, &pc, pkg_to_replace,
		prefetcher, s._sched_iface, s._allocate_config(versions.pkg.root),
		s._status_msg, s._world_atom)

	return task
}

func (s *Scheduler) _failed_pkg_msg(failed_pkg *_failed_pkg, action, preposition string) {
	pkg := failed_pkg.pkg
	msg := fmt.Sprintf(fmt.Sprintf("%s to %s %s",
		bad("Failed"), action, output.colorize("INFORM", pkg.cpv)))
	if pkg.root_config.settings.ValueDict["ROOT"] != "/" {
		msg += fmt.Sprintf(fmt.Sprintf(" %s %s", preposition, pkg.root))
	}

	log_path := s._locate_failure_log(failed_pkg)
	if log_path != "" {
		msg += ", Log file:"
		s._status_msg(msg)
	}

	if log_path != "" {
		s._status_msg(fmt.Sprintf(" '%s'", output.colorize("INFORM", log_path), ))
	}
}

func (s *Scheduler) _status_msg( msg string) {
	if !s._background {
		msg.WriteMsgLevel("\n", 0, 0)
	}
	s._status_display.displayMessage(msg)
}

func (s *Scheduler) _save_resume_list() {
	mtimedb := s._mtimedb

	mtimedb["resume"] = map[string]{}
	mtimedb["resume"]["myopts"] = s.myopts.copy()

	rf := []string{}
	for _, x:= range s._favorites {
		rf = append(rf, string(x.value))
	}
	mtimedb["resume"]["favorites"] = rf
	rm := []string{}
	for x
	in
	s._mergelist{
		if isinstance(x, structs.Package) && x.operation == "merge"{
		rm = append(rm, list(x))
	}
	}
	mtimedb["resume"]["mergelist"] = rm

	mtimedb.commit()
}

func (s *Scheduler) _calc_resume_list() {
	print(output.colorize("GOOD", "*** Resuming merge..."))

	s._destroy_graph()

	myparams := atom.create_depgraph_params(s.myopts, nil)
	success := false
	e = nil
try:
	success, mydepgraph, dropped_tasks = resume_depgraph(
		s.settings, s.trees, s._mtimedb, s.myopts,
		myparams, s._spinner)
	except
	Depgraph.UnsatisfiedResumeDep
	as
exc:
	e = exc
	mydepgraph = e.depgraph
	dropped_tasks =
	{
	}

	if e != nil:

	unsatisfied_resume_dep_msg:= func(){
		mydepgraph.display_problems()
		out := output.NewEOutput(false)
		out.eerror("One or more packages are either masked or " +
			"have missing dependencies:")
		out.eerror("")
		indent := "  "
		show_parents = map[string]string{}
		for dep
			in
		e.value:
		if dep.parent in
	show_parents:
		continue
		show_parents.add(dep.parent)
		if dep.atom == nil:
		out.eerror(indent + "Masked package:")
		out.eerror(2*indent + str(dep.parent))
		out.eerror("")
		else:
		out.eerror(indent + str(dep.atom) + " pulled in by:")
		out.eerror(2*indent + str(dep.parent))
		out.eerror("")
		msg = "The resume list contains packages " +
			"that are either masked or have " +
			"unsatisfied dependencies. " +
			"Please restart/continue " +
			"the operation manually, or use --skipfirst " +
			"to skip the first package in the list and " +
			"any other packages that may be " +
			"masked or have missing dependencies."
		for _, line:= range myutil.SplitSubN(msg, 72) {
			out.eerror(line)
		}
	}
	s._post_mod_echo_msgs.append(unsatisfied_resume_dep_msg)
	return false

	if success && s._show_list() {
		mydepgraph.display(mydepgraph.altlist(), favorites = s._favorites)
	}

	if ! success {
		s._post_mod_echo_msgs=append(s._post_mod_echo_msgs, mydepgraph.display_problems)
		return false
	}
	mydepgraph.display_problems()
	s._init_graph(mydepgraph.schedulerGraph())

	msg_width = 75
	for task, atoms
		in
	dropped_tasks.items():
	if not(isinstance(task, structs.Package) &&
		task.operation == "merge"):
	continue
	versions.pkg = task
	msg = "emerge --keep-going:" +
		" %s" % (versions.pkg.cpv,)
	if versions.pkg.root_config.settings.ValueDict["ROOT"] != "/":
	msg += " for %s" % (versions.pkg.root,)
	if not atoms:
	msg += " dropped because it is masked or unavailable"
	else:
	msg += " dropped because it requires %s" % ", ".join(atoms)
	for line
		in
	myutil.SplitSubN(msg, msg_width):
	elog.eerror(line, "other", versions.pkg.cpv, "", nil)
	settings = s.pkgsettings.ValueDict[versions.pkg.root]
	settings.pop("T", nil)
	portage.elog.elog_process(versions.pkg.cpv, settings)
	s._failed_pkgs_all=append(s._failed_pkgs_all, &_failed_pkg{pkg: versions.pkg})

	return true
}

func (s *Scheduler) _show_list() bool {
	myopts := s.myopts
	if  !myutil.Inmss(myopts, "--quiet")&& myutil.Inmss(myopts, "--ask")|| myutil.Inmss(myopts, "--tree")|| myutil.Inmss(myopts, "--verbose") {
		return true
	}
	return false
}

func (s *Scheduler) _world_atom(versions.pkg) {

	if set(("--buildpkgonly", "--fetchonly",
		"--fetch-all-uri",
		"--oneshot", "--onlydeps",
		"--pretend")).intersection(s.myopts)
	{
		return
	}

	if versions.pkg.root != s.target_root {
		return
	}

	args_set := s._args_set
	if not args_set.findAtomForPackage(versions.pkg, nil) {
		return
	}

	logger := s._logger
	pkg_count := s._pkg_count
	root_config := versions.pkg.root_config
	world_set := root_config.sets["selected"]
	world_locked := false
	atom = nil

	if versions.pkg.operation != "uninstall" {
		atom = s._world_atoms.get(versions.pkg)
	}

try:

	if hasattr(world_set, "lock"):
	world_set.lock()
	world_locked = true

	if hasattr(world_set, "load"):
	world_set.load()

	if versions.pkg.operation == "uninstall":
	if hasattr(world_set, "cleanPackage"):
	world_set.cleanPackage(versions.pkg.root_config.trees["vartree"].dbapi,
		versions.pkg.cpv)
	if hasattr(world_set, "remove"):
	for s
		in
	versions.pkg.root_config.setconfig.active:
	world_set.remove(sets.SETPREFIX + s)
	else:
	if atom != nil:
	if hasattr(world_set, "add"):
	s._status_msg(("Recording %s in \"world\" " +
		"favorites file...") % atom)
	logger.log(" === (%s of %s) Updating world file (%s)" %
		(pkg_count.curval, pkg_count.maxval, versions.pkg.cpv))
	world_set.add(atom)
	else:
	msg.WriteMsgLevel("\n!!! Unable to record %s in \"world\"\n" %
		(atom,), level = logging.WARN, noiselevel=-1)
finally:
	if world_locked:
	world_set.unlock()
}

// false, "", nil
func (s *Scheduler) _pkg( cpv *versions.PkgStr, type_name string, root_config *RootConfig, installed bool,
	operation string, myrepo=nil) *structs.Package {

	versions.pkg = s._pkg_cache.get(structs.NewPackage()._gen_hash_key(cpv = cpv,
		type_name = type_name, repo_name=myrepo, root_config = root_config,
		installed=installed, operation = operation))

	if versions.pkg != nil {
		return versions.pkg
	}

	tree_type = Depgraph.pkg_tree_map[type_name]
	db = root_config.trees[tree_type].dbapi
	db_keys = list(s.trees[root_config.root][
		tree_type].dbapi._aux_cache_keys)
	metadata = zip(db_keys, db.aux_get(cpv, db_keys, myrepo = myrepo))
	pkg := structs.NewPackage(type_name != "ebuild",
		cpv, installed, metadata,
		root_config, type_name)
	s._pkg_cache[pkg] = pkg
	return pkg
}
