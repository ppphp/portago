package emerge

type EbuildFetcher struct {
	*CompositeTask
	//slots
	prefetch bool
	logfile string
	_fetcher_proc *_EbuildFetcherProcess
	config_pool*_ConfigPool
	ebuild_path string
	fetchonly int
	fetchall bool
	pkg, _fetcher_proc
}

func NewEbuildFetcher(config_pool *_ConfigPool,ebuild_path string,
	fetchall bool,fetchonly int, background bool,logfile string,pkg,scheduler *SchedulerInterface,prefetch bool) *EbuildFetcher {
	e := &EbuildFetcher{}
	e.CompositeTask = NewCompositeTask(**kwargs)
	e._fetcher_proc = NewEbuildFetcherProcess(**kwargs)
	e.config_pool = config_pool
	e.ebuild_path = ebuild_path
	e.fetchall = fetchall
	e.fetchonly = fetchonly
	e.background = background
	e.logfile = logfile
	e.pkg = pkg
	e.scheduler = scheduler
	e.prefetch = prefetch

	return e

}

func (e*EbuildFetcher) async_already_fetched(settings *config.Config) {
	return e._fetcher_proc.async_already_fetched(settings)
}

func (e*EbuildFetcher) _start() {
	e._start_task(
		NewAsyncTaskFuture(e._fetcher_proc._async_uri_map()),
	e._start_fetch)
}

func (e *EbuildFetcher) _start_fetch(uri_map_task *AsyncTask) {
	e._assert_current(uri_map_task)
	if uri_map_task.cancelled {
		e._default_final_exit(uri_map_task)
		return
	}

	uri_map, err := uri_map_task.future.result()
	if err != nil {
		msg_lines := []string{}
		msg := fmt.Sprintf("Fetch failed for '%s' due to invalid SRC_URI: %v", e.pkg.cpv, err)
		msg_lines = append(msg_lines, msg)
		e._fetcher_proc._eerror(msg_lines)
		e._current_task = nil
		e.returncode = 1
		e._async_wait()
		return
	}

	e._start_task(
		NewAsyncTaskFuture(
			e.pkg.root_config.trees["porttree"].dbapi.
	async_aux_get(e.pkg.cpv, []string{"SRC_URI"}, myrepo = e.pkg.repo,
		loop = e.scheduler)),
	e._start_with_metadata)
}

func (e*EbuildFetcher) _start_with_metadata( aux_get_task) {
	e._assert_current(aux_get_task)
	if aux_get_task.cancelled {
		e._default_final_exit(aux_get_task)
		return
	}

	e._fetcher_proc.src_uri, = aux_get_task.future.result()
	e._start_task(e._fetcher_proc, e._default_final_exit)
}


type _EbuildFetcherProcess struct {
	*ForkProcess
	// slots
	ebuild_path string
	_manifest *manifest.Manifest
	_digests map[string]map[string]string
	_settings *config.Config
	config_pool *_ConfigPool
	src_uri string
	pkg *versions.PkgStr
	fetchonly, fetchall,
	 prefetch,
	_uri_map
}

func(e*_EbuildFetcherProcess) async_already_fetched(settings *config.Config) {
	result := e.scheduler.create_future()

	uri_map_done:= func(uri_map_future) {
		if uri_map_future.cancelled() {
			result.cancel()
			return
		}

		if uri_map_future.exception() != nil || result.cancelled() {
			if not result.cancelled() {
				result.set_exception(uri_map_future.exception())
			}
			return
		}

		uri_map = uri_map_future.result()
		if uri_map {
			result.set_result(
				e._check_already_fetched(settings, uri_map))
		} else {
			result.set_result(true)
		}
	}

	uri_map_future = e._async_uri_map()
	result.add_done_callback(lambda
result:
	uri_map_future.cancel()
	if result.cancelled()
	else
	None)
	uri_map_future.add_done_callback(uri_map_done)
	return result
}

func(e*_EbuildFetcherProcess) _check_already_fetched( settings *config.Config, uri_map) {
	digests := e._get_digests()
	distdir := settings.ValueDict["DISTDIR"]
	allow_missing := e._get_manifest().allow_missing

	for filename
	in
uri_map:
try:
	st = os.stat(filepath.Join(distdir, filename))
	except
OSError:
	return false
	if st.st_size == 0:
	return false
	expected_size = digests.get(filename,
	{
	}).get('size')
	if expected_size is
None:
	continue
	if st.st_size != expected_size:
	return false

	hash_filter = _hash_filter(settings.get("PORTAGE_CHECKSUM_FILTER", ""))
	if hash_filter.transparent:
	hash_filter = None
	stdout_orig = sys.stdout
	stderr_orig = sys.stderr
	global_havecolor = portage.output.havecolor
	out = io.StringIO()
	eout = output.NewEOutput(false)
	eout.quiet = settings.get("PORTAGE_QUIET") == "1"
	success = true
try:
	sys.stdout = out
	sys.stderr = out
	if portage.output.havecolor:
	portage.output.havecolor = not
	e.background

	for filename
	in
uri_map:
	mydigests = digests.get(filename)
	if mydigests is
None:
	if not allow_missing:
	success = false
	break
	continue
	ok, st = atom._check_distfile(filepath.Join(distdir, filename),
		mydigests, eout, false, hash_filter)
	if not ok:
	success = false
	break
	except
	portage.exception.FileNotFound:
	return false
finally:
	sys.stdout = stdout_orig
	sys.stderr = stderr_orig
	portage.output.havecolor = global_havecolor

	if success:
	msg = out.getvalue()
	if msg:
	e.scheduler.output(msg, log_path = e.logfile)

	return success
}

func(e*_EbuildFetcherProcess) _start() {

	root_config := e.pkg.root_config
	portdb := root_config.trees["porttree"].dbapi
	ebuild_path := e._get_ebuild_path()
		uri_map := e._uri_map

	if not uri_map {
		i := 0
		e.returncode = &i
		e._async_wait()
		return
	}

	settings := e.config_pool.allocate()
	settings.SetCpv(e.pkg, nil)
	settings.configDict["pkg"]["SRC_URI"] = e.src_uri
	atom.doebuild_environment(ebuild_path, "fetch", nil,
		settings , false, nil,  portdb)

	if e.prefetch && e._prefetch_size_ok(uri_map, settings, ebuild_path) {
		e.config_pool.deallocate(settings)
		i := 0
		e.returncode = &i
		e._async_wait()
		return
	}

	nocolor := &settings.ValueDict["NOCOLOR"]

	if e.prefetch {
		settings.ValueDict["PORTAGE_PARALLEL_FETCHONLY"] = "1"
	}

	if e.background {
		 i := 1
		nocolor = &i
	}

	if nocolor != nil {
		settings.ValueDict["NOCOLOR"] = fmt.Sprint(nocolor)
	}

	e._settings = settings        
	
	e.log_filter_file = settings.get("PORTAGE_LOG_FILTER_FILE_CMD")
	e.target = func() {
		e._target(self._settings,
			self._get_manifest(),
			self._uri_map,
			self.fetchonly,
		)
	}

	e.ForkProcess._start()

	e.config_pool.deallocate(settings)
	settings = nil
	e._settings = nil
}

func(e*_EbuildFetcherProcess) _target(settings, manifest, uri_map, fetchonly) {
	h := !(e._settings.ValueDict["NOCOLOR"]== "yes" ||e._settings.ValueDict["NOCOLOR"]== "true")
	if h {
		output.HaveColor = 1
	} else {
		output.HaveColor = 0
	}

	if atom._want_userfetch(e._settings) {
		atom._drop_privs_userfetch(e._settings)
	}

	rval := 1
	allow_missing := manifest.allow_missing||e._settings.Features.Features["digest"]
	if atom.fetch(e._uri_map, e._settings, fetchonly = e.fetchonly,
		digests = copy.deepcopy(manifest._get_digests("DIST")),
		allow_missing_digests = allow_missing){
		rval = 0
	}
	return rval
}

func(e*_EbuildFetcherProcess) _get_ebuild_path() string {
	if e.ebuild_path != "" {
		return e.ebuild_path
	}
	atom.portdb = e.pkg.root_config.trees["porttree"].dbapi
	e.ebuild_path = atom.portdb.findname(e.pkg.cpv, myrepo = e.pkg.repo)
	if e.ebuild_path == "" {
		//raise AssertionError("ebuild not found for '%s'" % e.pkg.cpv)
	}
	return e.ebuild_path
}

func(e*_EbuildFetcherProcess) _get_manifest() *manifest.Manifest {
	if e._manifest == nil {
		pkgdir := filepath.Dir(e._get_ebuild_path())
		e._manifest = e.pkg.root_config.settings.repositories.get_repo_for_location(
			filepath.Dir(filepath.Dir(pkgdir))).load_manifest(pkgdir, None)
	}
	return e._manifest
}

func(e*_EbuildFetcherProcess) _get_digests() map[string]map[string]string{
	if e._digests == nil {
		e._digests = e._get_manifest().getTypeDigests("DIST")
	}
	return e._digests
}

func(e*_EbuildFetcherProcess) _async_uri_map() interfaces.IFuture {
	if e._uri_map != nil {
		result := e.scheduler.create_future()
		result.set_result(e._uri_map)
		return result
	}

	pkgdir := filepath.Dir(e._get_ebuild_path())
	mytree := filepath.Dir(filepath.Dir(pkgdir))
	use := None
	if ! e.fetchall {
		use = e.pkg.use.enabled
	}
	atom.portdb = e.pkg.root_config.trees["porttree"].dbapi


	cache_result:= func(result) {
	try:
		e._uri_map = result.result()
		except
	Exception:
		pass
	}

	result := atom.portdb.async_fetch_map(e.pkg.cpv,
		useflags = use, mytree = mytree, loop=e.scheduler)
	result.add_done_callback(cache_result)
	return result
}

func(e*_EbuildFetcherProcess) _prefetch_size_ok(uri_map, settings *config.Config, ebuild_path string) bool{
	distdir := settings.ValueDict["DISTDIR"]

	sizes :=map[string]int64{}
	for filename
	in
uri_map {
		st, err := os.Stat(filepath.Join(distdir, filename))
		if err != nil {
			//except OSError:
			return false
		}
		if st.Size() == 0 {
			return false
		}
		sizes[filename] = st.Size()
	}

	digests := e._get_digests()
	for filename, actual_size:= range sizes {
		size,ok := digests[filename]["size"]
		if !ok {
			continue
		}
		if size != fmt.Sprint(actual_size) {
			return false
		}
	}

	if e.logfile != "" {
		f, _ := os.OpenFile(e.logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		for filename
			in
		uri_map {
			f.Write(_unicode_decode((' * %s size ;-) ...' % \
			filename).ljust(73) + '[ ok ]\n'))
		}
		f.Close()
	}

	return true
}

func(e*_EbuildFetcherProcess) _pipe(fd_pipes) {
	if e.background ||!sys.stdout.isatty() {
		return os.pipe()
	}
	stdout_pipe = None
	if ! e.background {
		stdout_pipe = fd_pipes.get(1)
	}
	got_pty, master_fd, slave_fd :=
	_create_pty_or_pipe(copy_term_size = stdout_pipe)
	return (master_fd, slave_fd)
}

func(e*_EbuildFetcherProcess) _eerror( lines []string) {
	out := &bytes.Buffer{}
	for _, line:= range lines {
		elog.eerror(line, "unpack", e.pkg.cpv.string, out)
	}
	msg := out.String()
	if msg!= "" {
		e.scheduler.output(msg, e.logfile, false, 0, -1)
	}
}

func(e*_EbuildFetcherProcess) _proc_join_done( proc, future interfaces.IFuture) {
	if !e.prefetch && !future.cancelled() && proc.exitcode != 0 {
		msg_lines := []string{}
		msg := fmt.Sprintf("Fetch failed for '%s'", e.pkg.cpv, )
		if e.logfile != "" {
			msg += ", Log file:"
		}
		msg_lines = append(msg_lines, msg)
		if e.logfile != "" {
			msg_lines = append(msg_lines, fmt.Sprintf(" '%s'", e.logfile, ))
		}
		e._eerror(msg_lines)
	}
}

func NewEbuildFetcherProcess()*_EbuildFetcherProcess {
	e := &_EbuildFetcherProcess{}
	e.ForkProcess = NewForkProcess()
	return e
}
