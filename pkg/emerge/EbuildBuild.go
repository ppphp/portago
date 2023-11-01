package emerge

type EbuildBuild struct {
	*CompositeTask
	settings            *config.Config

	// slot
	_tree, _ebuild_path string
	pkg                 *versions.PkgStr
	_build_dir          *EbuildBuildDir
	_buildpkg,_issyspkg bool
	args_set, config_pool, find_blockers,
	ldpath_mtimes, logger, opts, pkg, pkg_count,
	prefetcher, world_atom,

}

func(e *EbuildBuild) _start() {
	if ! e.opts.fetchonly {
		rval := atom._check_temp_dir(e.settings)
		if rval != 0 {
			e.returncode = &rval
			e._current_task = nil
			e._async_wait()
			return
		}
	}

	e._start_task(
		NewAsyncTaskFuture(
			e.pkg.root_config.trees["porttree"].dbapi.async_aux_get(e.pkg.cpv, ["SRC_URI"], myrepo = e.pkg.repo,
		loop = e.scheduler)),
	e._start_with_metadata)
}

func(e *EbuildBuild) _start_with_metadata( aux_get_task) {
	e._assert_current(aux_get_task)
	if aux_get_task.cancelled {
		e._default_final_exit(aux_get_task)
		return
	}

	pkg := e.pkg
	settings := e.settings
	root_config := pkg.root_config
	tree := "porttree"
	e._tree = tree
	portdb := root_config.trees[tree].dbapi
	settings.SetCpv(pkg)
	settings.configDict["pkg"]["SRC_URI"], = aux_get_task.future.result()
	settings.configDict["pkg"]["EMERGE_FROM"] = "ebuild"
	if e.opts.buildpkgonly {
		settings.configDict["pkg"]["MERGE_TYPE"] = "buildonly"
	}else {
		settings.configDict["pkg"]["MERGE_TYPE"] = "source"
	}
	ebuild_path := portdb.findname(pkg.cpv, myrepo = pkg.repo)
	if ebuild_path == ""{
		//raise AssertionError("ebuild not found for '%s'" % pkg.cpv)
	}
	e._ebuild_path = ebuild_path
	atom.doebuild_environment(ebuild_path, "setup", nil, e.settings, false, nil, portdb)

	if ! e._check_manifest() {
		i := 1
		e.returncode = &i
		e._current_task = nil
		e._async_wait()
		return
	}

	prefetcher := e.prefetcher
	if prefetcher == nil{
		//pass
	}else if prefetcher.isAlive() && prefetcher.poll() == nil {
		if !e.background {
			fetch_log := filepath.Join(_emerge_log_dir, "emerge-fetch.log")
			msg := []string{
				"Fetching files in the background.",
				"To view fetch progress, run in another terminal:",
				fmt.Sprintf("tail -f %s", fetch_log),
			}
			out := output.NewEOutput(false)
			for _, l := range msg {
				out.Einfo(l)
			}
		}

		e._current_task = prefetcher
		prefetcher.addExitListener(e._prefetch_exit)
		return
	}

	e._prefetch_exit(prefetcher)
}

func(e *EbuildBuild) _check_manifest() bool {
	success := 1

	settings := e.settings
	if settings.Features.Features["strict"] && !settings.Features.Features["digest"] {
		settings.ValueDict["O"] = filepath.Dir(e._ebuild_path)
		quiet_setting := settings.ValueDict["PORTAGE_QUIET"]
		settings.ValueDict["PORTAGE_QUIET"] = "1"
	//try:
		success = ebuild2.Digestcheck([]string{}, settings, true, nil)
	//finally:
		if quiet_setting != ""{
			settings.ValueDict["PORTAGE_QUIET"] = quiet_setting
		}else {
			delete(settings.ValueDict, "PORTAGE_QUIET")
		}
	}

	return success != 0
}

func(e *EbuildBuild) _prefetch_exit( prefetcher) {

	if e._was_cancelled() {
		e.wait()
		return
	}

	opts := e.opts
	pkg := e.pkg
	settings := e.settings

	if opts.fetchonly {
		if opts.pretend {
			fetcher := NewEbuildFetchonly(opts.fetch_all_uri, pkg,opts.pretend, settings)
			retval := fetcher.execute()
			if retval == 0 {
				e._current_task = nil
				i := 0
				e.returncode = &i
				e._async_wait()
			} else {
				e._start_task(NewSpawnNofetchWithoutBuilddir(
					e.background,
					atom.portdb = e.pkg.root_config.trees[e._tree].dbapi,
					e._ebuild_path, e.scheduler, nil, e.settings),
				e._default_final_exit)
			}
			return
		}else {
			fetcher := NewEbuildFetcher(e.config_pool, e._ebuild_path,
				e.opts.fetch_all_uri, e.opts.fetchonly, false, "",
				e.pkg, e.scheduler,false)
			e._start_task(fetcher, e._fetchonly_exit)
			return
		}
	}

	e._build_dir = NewEbuildBuildDir(e.scheduler, settings)
	e._start_task(
		NewAsyncTaskFuture(e._build_dir.async_lock()),
	e._start_pre_clean)
}

func(e *EbuildBuild) _start_pre_clean( lock_task) {
	e._assert_current(lock_task)
	if lock_task.cancelled {
		e._default_final_exit(lock_task)
		return
	}

	lock_task.future.result()
	msg := fmt.Sprintf(" === (%s of %s) Cleaning (%s::%s)" ,
	e.pkg_count.curval, e.pkg_count.maxval,
		e.pkg.cpv, e._ebuild_path)
	short_msg := fmt.Sprintf("emerge: (%s of %s) %s Clean" ,
	e.pkg_count.curval, e.pkg_count.maxval, e.pkg.cpv)
	e.logger.log(msg, short_msg = short_msg)

	pre_clean_phase := NewEbuildPhase(nil, e.background,
		"clean", e.scheduler,  e.settings, nil)
	e._start_task(pre_clean_phase, e._pre_clean_exit)
}

func(e *EbuildBuild)_fetchonly_exit( fetcher){
	e._final_exit(fetcher)
	if e.returncode ==nil||*e.returncode!= 0 {
		e.returncode = nil
		atom.portdb = e.pkg.root_config.trees[e._tree].dbapi
		e._start_task(NewSpawnNofetchWithoutBuilddir(e.background,
			atom.portdb = atom.portdb,
			e._ebuild_path, e.scheduler, nil, e.settings),
		e._nofetch_without_builddir_exit)
		return
	}

	e.wait()
}

func(e *EbuildBuild) _nofetch_without_builddir_exit( nofetch) {
	e._final_exit(nofetch)
	i:=1
	e.returncode = &i
	e.wait()
}

func(e *EbuildBuild) _pre_clean_exit( pre_clean_phase) {
	if e._default_exit(pre_clean_phase) != 0 {
		e._async_unlock_builddir(e.returncode)
		return
	}

	ebuild2.Prepare_build_dirs(e.settings, 1)

	fetcher := NewEbuildFetcher(e.config_pool, e._ebuild_path, e.opts.fetch_all_uri,
		 e.opts.fetchonly, e.background, e.settings.ValueDict["PORTAGE_LOG_FILE"],
		e.pkg, e.scheduler, false)

	e._start_task(NewAsyncTaskFuture(
		fetcher.async_already_fetched(e.settings)),
		func(t) {e._start_fetch(fetcher, t)})
}

func(e *EbuildBuild) _start_fetch( fetcher, already_fetched_task) {
	e._assert_current(already_fetched_task)
	if already_fetched_task.cancelled {
		e._default_final_exit(already_fetched_task)
		return
	}

//try:
	already_fetched := already_fetched_task.future.result()
	//except portage.exception.InvalidDependString as e:
	//msg_lines = []string{}
	//msg = "Fetch failed for '%s' due to invalid SRC_URI: %s" % \
	//(e.pkg.cpv, e)
	//msg_lines.append(msg)
	//fetcher._eerror(msg_lines)
	//portage.elog.elog_process(e.pkg.cpv, e.settings)
	//e._async_unlock_builddir(returncode = 1)
	//return

	if already_fetched {
		fetcher = nil
		e._fetch_exit(fetcher)
		return
	}

	fetcher.addExitListener(e._fetch_exit)
	e._task_queued(fetcher)
	e.scheduler.fetch.schedule(fetcher)
}

func(e *EbuildBuild) _fetch_exit( fetcher) {

	if fetcher != nil && e._default_exit(fetcher) != 0 {
		e._fetch_failed()
		return
	}

	e._build_dir.clean_log()
	pkg := e.pkg
	logger := e.logger
	opts := e.opts
	pkg_count := e.pkg_count
	scheduler := e.scheduler
	settings := e.settings
	features := settings.Features.Features
	ebuild_path := e._ebuild_path
	system_set := pkg.root_config.sets["system"]

	e._issyspkg = features["buildsyspkg"] && system_set.findAtomForPackage(pkg) && !features["buildpkg"] && opts.buildpkg != "n"

	if (features["buildpkg"] || e._issyspkg) && !e.opts.buildpkg_exclude.findAtomForPackage(pkg) {

		e._buildpkg = true

		msg := fmt.Sprintf(" === (%s of %s) Compiling/Packaging (%s::%s)",
			pkg_count.curval, pkg_count.maxval, pkg.cpv, ebuild_path)
		short_msg := fmt.Sprintf("emerge: (%s of %s) %s Compile",
			pkg_count.curval, pkg_count.maxval, pkg.cpv)
		logger.log(msg, short_msg = short_msg)
	} else {
		msg := fmt.Sprintf(" === (%s of %s) Compiling/Merging (%s::%s)",
			pkg_count.curval, pkg_count.maxval, pkg.cpv, ebuild_path)
		short_msg := fmt.Sprintf("emerge: (%s of %s) %s Compile",
			pkg_count.curval, pkg_count.maxval, pkg.cpv)
		logger.log(msg, short_msg = short_msg)
	}

	build := NewEbuildExecuter(e.background, pkg, scheduler, settings)
	e._start_task(build, e._build_exit)
}

func(e *EbuildBuild) _fetch_failed() {

	if 'fetch' not
	in
	e.pkg.restrict
	&&
	'nofetch'
	not
	in
	e.pkg.defined_phases{
		e._async_unlock_builddir(e.returncode)
		return
	}

	e.returncode = nil
	nofetch_phase := NewEbuildPhase(nil,e.background,
		"nofetch",e.scheduler, e.settings, nil)
	e._start_task(nofetch_phase, e._nofetch_exit)
}

func(e *EbuildBuild) _nofetch_exit( nofetch_phase) {
	e._final_exit(nofetch_phase)
	i := 1
	e._async_unlock_builddir(&i)
}

// nil
func(e *EbuildBuild) _async_unlock_builddir( returncode *int) {
	if returncode != nil {
		e.returncode = nil
	}
	elog.elog_process(e.pkg.cpv, e.settings, nil)
	e._start_task(
		NewAsyncTaskFuture(e._build_dir.async_unlock()),
	func(unlock_task) {
		e._unlock_builddir_exit(unlock_task, returncode)
	})
}

// nil
func(e *EbuildBuild) _unlock_builddir_exit( unlock_task, returncode *int) {
	e._assert_current(unlock_task)
	if unlock_task.cancelled && returncode!= nil {
		e._default_final_exit(unlock_task)
		return
	}

	if !unlock_task.future.cancelled() {
		unlock_task.future.result()
	}
	if returncode != nil {
		e.returncode = returncode
		e._async_wait()
	}
}

func(e *EbuildBuild) _build_exit( build) {
	if e._default_exit(build) != 0 {
		e._async_unlock_builddir(e.returncode)
		return
	}

	buildpkg := e._buildpkg

	if !buildpkg {
		e._final_exit(build)
		e.wait()
		return
	}

	if e._issyspkg {
		msg :=">>> This is a system package, " +
		"let's pack a rescue tarball.\n"
		e.scheduler.output(msg, e.settings.ValueDict["PORTAGE_LOG_FILE"], false, 0, -1)
	}

	binpkg_tasks := NewTaskSequence(nil)
	t, ok :=e.settings.ValueDict["PORTAGE_BINPKG_FORMAT"]
	if !ok {
		t = "tar"
	}
	requested_binpkg_formats := strings.Fields(t)
	for pkg_fmt := range _const.SUPPORTED_BINPKG_FORMATS {
		if myutil.Ins(
			requested_binpkg_formats, pkg_fmt) {
			if pkg_fmt == "rpm" {
				binpkg_tasks.add(NewEbuildPhase(nil, e.background, "rpm", e.scheduler, e.settings, nil))
			} else {
				task := NewEbuildBinpkg(e.background, e.pkg, e.scheduler, e.settings)
				binpkg_tasks.add(task)
				binpkg_tasks.add(NewRecordBinpkgInfo(
					 task,  e))
			}
		}
	}
	if binpkg_tasks {
		e._start_task(binpkg_tasks, e._buildpkg_exit)
		return
	}

	e._final_exit(build)
	e.wait()
}
