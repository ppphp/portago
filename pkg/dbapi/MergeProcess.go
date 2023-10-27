package dbapi

type MergeProcess struct {
	ForkProcess
	mycat            string
	mypkg            string
	settings         *portage.config
	treetype         string
	vartree          *portage.dbapi.vartree
	blockers         func() []string
	pkgloc           string
	infloc           string
	myebuild         *portage.ebuild.ebuild
	mydbapi          *portage.dbapi.porttree
	postinst_failure bool
	prev_mtimes      map[string]int64
	unmerge          bool
	_elog_reader_fd  int
	_buf             string
	_counter         int
	_dblink          *portage.dblink
	_elog_keys       map[string]bool
	_locked_vdb      bool
	_mtime_reader    *os.File
}

func (mp *MergeProcess) _start() {
	// Portage should always call setcpv prior to this
	// point, but here we have a fallback as a convenience
	// for external API consumers. It's important that
	// this metadata access happens in the parent process,
	// since closing of file descriptors in the subprocess
	// can prevent access to open database connections such
	// as that used by the sqlite metadata cache module.
	cpv := fmt.Sprintf("%s/%s", mp.mycat, mp.mypkg)
	settings := mp.settings
	if cpv != settings.mycpv || "EAPI" not in settings.configdict["pkg"] {
		settings.Reload()
		settings.Reset()
		settings.SetCpv(cpv, mydb: mp.mydbapi)
	}

	// This caches the libc library lookup in the current
	// process, so that it's only done once rather than
	// for each child process.
	if runtime.GOOS == "linux" && portage.HasFeature(settings.Features, "merge-sync") {
		portage.FindLibrary("c")
	}

	// Inherit stdin by default, so that the pdb SIGUSR1
	// handler is usable for the subprocess.
	if mp.fd_pipes == nil {
		mp.fd_pipes = make(map[int]int)
	} else {
		mp.fd_pipes = mp.fd_pipes.copy()
	}
	mp.fd_pipes[0] = portage.GetStdin().Fd()

	mp.log_filter_file = settings.Get("PORTAGE_LOG_FILTER_FILE_CMD")
	mp.ForkProcess._start()
}


func (mp *MergeProcess) _lock_vdb() {
	/*
		Lock the vdb if FEATURES=parallel-install is NOT enabled,
		otherwise do nothing. This is implemented with
		vardbapi.lock(), which supports reentrance by the
		subprocess that we spawn.
	*/
	if !portage.HasFeature(mp.settings.Features, "parallel-install") {
		mp.vartree.Dbapi.Lock()
		mp._locked_vdb = true
	}
}

func (mp *MergeProcess) _unlock_vdb() {
	/*
		Unlock the vdb if we hold a lock, otherwise do nothing.
	*/
	if mp._locked_vdb {
		mp.vartree.Dbapi.Unlock()
		mp._locked_vdb = false
	}
}

func (mp *MergeProcess) _elog_output_handler() bool {
	output := mp._read_buf(mp._elog_reader_fd)
	if output != "" {
		lines := strings.Split(output, "\n")
		if len(lines) == 1 {
			mp._buf += lines[0]
		} else {
			lines[0] = mp._buf + lines[0]
			mp._buf = lines[len(lines)-1]
			lines = lines[:len(lines)-1]
			out := new(strings.Builder)
			for _, line := range lines {
				parts := strings.SplitN(line, " ", 4)
				funcname, phase, key, msg := parts[0], parts[1], parts[2], parts[3]
				mp._elog_keys[key] = true
				reporter := portage.elog.Messages[funcname]
				reporter(msg, phase, key, out)
			}
		}
	} else if output == "" { // EIO/POLLHUP
		mp.scheduler.RemoveReader(mp._elog_reader_fd)
		os.Close(mp._elog_reader_fd)
		mp._elog_reader_fd = -1
		return false
	}
	return true
}

func (mp *MergeProcess) _mtime_handler() {
	if mp._mtime_reader != nil {
		mtimes := make(map[string]int64)
		err := gob.NewDecoder(mp._mtime_reader).Decode(&mtimes)
		if err != nil {
			mp.scheduler.RemoveReader(mp._mtime_reader.Fd())
			mp._mtime_reader.Close()
			mp._mtime_reader = nil
		} else {
			if mp.prev_mtimes != nil {
				for k := range mp.prev_mtimes {
					delete(mp.prev_mtimes, k)
				}
			} else {
				mp.prev_mtimes = make(map[string]int64)
			}
			for k, v := range mtimes {
				mp.prev_mtimes[k] = v
			}
		}
	}
}

func (mp *MergeProcess) _spawn(args []string, fd_pipes map[int]int, kwargs map[string]interface{}) []int {
	elog_reader_fd, elog_writer_fd, _ := os.Pipe()
	fcntl.Fcntl(elog_reader_fd, fcntl.F_SETFL, fcntl.Fcntl(elog_reader_fd, fcntl.F_GETFL, 0)|os.O_NONBLOCK)

	mtime_reader, mtime_writer, _ := os.Pipe()
	fd_pipes[int(mtime_writer.Fd())] = int(mtime_writer.Fd())
	mp.scheduler.AddReader(int(mtime_reader.Fd()), mp._mtime_handler)
	mp._mtime_reader = mtime_reader

	blockers := mp.blockers()
	mylink := portage.NewDblink(mp.mycat, mp.mypkg, mp.settings, mp.treetype, mp.vartree, blockers, elog_writer_fd, mtime_writer)
	fd_pipes[int(elog_writer_fd.Fd())] = int(elog_writer_fd.Fd())
	mp.scheduler.AddReader(int(elog_reader_fd.Fd()), mp._elog_output_handler)

	mp._lock_vdb()
	if !mp.unmerge {
		mp._counter = mp.vartree.Dbapi.CounterTick()
	}

	mp._dblink = mylink
	mp._elog_reader_fd = int(elog_reader_fd.Fd())
	pids := mp.ForkProcess._spawn(args, fd_pipes, kwargs)
	elog_writer_fd.Close()
	mtime_writer.Close()
	mp._buf = ""
	mp._elog_keys = make(map[string]bool)

	portage.ElogMessages.CollectMessages(mylink.Mycpv)

	if mp.vartree.Dbapi.Categories != nil {
		mp.vartree.Dbapi.Categories = nil
	}
	mp.vartree.Dbapi.PkgsChanged = true
	mp.vartree.Dbapi.ClearPkgCache(mylink)

	return pids
}

func (mp *MergeProcess) _run() int {
	os.Close(mp._elog_reader_fd)
	counter := mp._counter
	mylink := mp._dblink

	portage.Output.Havecolor = mp.settings.Get("NOCOLOR") not in []string{"yes", "true"}

	// Avoid wastful updates of the vdb cache.
	mp.vartree.Dbapi.FlushCacheEnabled = false

	// In this subprocess we don't want PORTAGE_BACKGROUND to
	// suppress stdout/stderr output since they are pipes. We
	// also don't want to open PORTAGE_LOG_FILE, since it will
	// already be opened by the parent process, so we set the
	// "subprocess" value for use in conditional logging code
	// involving PORTAGE_LOG_FILE.
	if !mp.unmerge {
		// unmerge phases have separate logs
		if mp.settings.Get("PORTAGE_BACKGROUND") == "1" {
			mp.settings["PORTAGE_BACKGROUND_UNMERGE"] = "1"
		} else {
			mp.settings["PORTAGE_BACKGROUND_UNMERGE"] = "0"
		}
		mp.settings.BackupChanges("PORTAGE_BACKGROUND_UNMERGE")
	}
	mp.settings["PORTAGE_BACKGROUND"] = "subprocess"
	mp.settings.BackupChanges("PORTAGE_BACKGROUND")

	rval := 1
	if mp.unmerge {
		if !mylink.Exists() {
			rval = os.EX_OK
		} else if mylink.Unmerge(LdpathMtimes: mp.prev_mtimes) == os.EX_OK {
			mylink.Lockdb()
			defer mylink.Unlockdb()
			mylink.Delete()
			rval = os.EX_OK
		}
	} else {
		rval = mylink.Merge(
			mp.pkgloc,
			mp.infloc,
			Myebuild: mp.myebuild,
			Mydbapi: mp.mydbapi,
			PrevMtimes: mp.prev_mtimes,
			Counter: counter,
		)
	}
	return rval
}

func (mp *MergeProcess) _proc_join_done(proc *os.Process, future *concurrent.Future) {
	/*
	Extend _proc_join_done to react to RETURNCODE_POSTINST_FAILURE.
	*/
	if !future.Cancelled() && proc.ExitCode() == portage.Const.RETURNCODE_POSTINST_FAILURE {
		mp.postinst_failure = true
		mp.returncode = os.EX_OK
	}
	mp.ForkProcess._proc_join_done(proc, future)
}

func (mp *MergeProcess) _unregister() {
	/*
	Unregister from the scheduler and close open files.
	*/
	if !mp.unmerge {
		// Populate the vardbapi cache for the new package
		// while its inodes are still hot.
		try {
			mp.vartree.Dbapi.AuxGet(mp.settings.Mycpv, []string{"EAPI"})
		} catch KeyError {
			// pass
		}
	}

	mp._unlock_vdb()
	if mp._elog_reader_fd != nil {
		mp.scheduler.RemoveReader(mp._elog_reader_fd)
		os.Close(mp._elog_reader_fd)
		mp._elog_reader_fd = nil
	}
	if mp._elog_keys != nil {
		for key := range mp._elog_keys {
			portage.Elog.ElogProcess(
				key, mp.settings, Phasefilter: []string{"prerm", "postrm"}
			)
		}
		mp._elog_keys = nil
	}

	mp.ForkProcess._unregister()
}
