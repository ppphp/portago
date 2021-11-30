package atom

import (
	"os"
	"strings"
)

type SpawnNofetchWithoutBuilddir struct {
	*CompositeTask

	// slot
	settings *Config
	ebuild_path string
	fd_pipes map[int]int
	portdb
	_private_tmpdir
}

func(s*SpawnNofetchWithoutBuilddir) _start() {
	settings := s.settings
	if settings == nil {
		settings = s.portdb.settings
	}

	if Inmss(settings.ValueDict, "PORTAGE_PARALLEL_FETCHONLY") {
		i := 0
		s.returncode = &i
		s._async_wait()
		return
	}

	s.settings = NewConfig(settings, nil, "", nil, "", "", "", "", true, nil, false, nil)
	settings = s.settings

	portage_tmpdir := settings.ValueDict["PORTAGE_TMPDIR"]
	if portage_tmpdir == "" || osAccess(portage_tmpdir, 0) {
		portage_tmpdir = ""
	}

	s._private_tmpdir, _ = os.MkdirTemp(portage_tmpdir, "")
	private_tmpdir := s._private_tmpdir

	settings.ValueDict["PORTAGE_TMPDIR"] = private_tmpdir
	settings.BackupChanges("PORTAGE_TMPDIR")
	delete(settings.ValueDict, "PORTAGE_BUILDDIR_LOCKED")

	doebuild_environment(s.ebuild_path, "nofetch", nil, settings, false, nil, s.portdb)
	restrict := strings.Fields(settings.ValueDict["PORTAGE_RESTRICT"])
	defined_phases := strings.Fields(settings.ValueDict["DEFINED_PHASES"])
	if len(defined_phases) == 0 {
		for k := range EBUILD_PHASES {
			defined_phases = append(defined_phases, k)
		}
	}

	if !Ins(restrict, "fetch") && !Ins(defined_phases, "nofetch") {
		i := 0
		s.returncode = &i
		s._async_wait()
		return
	}

	prepare_build_dirs(settings, false)

	ebuild_phase := NewEbuildPhase(nil, s.background,
		"nofetch", s.scheduler, settings, s.fd_pipes)

	s._start_task(ebuild_phase, s._nofetch_exit)
}

func(s*SpawnNofetchWithoutBuilddir) _nofetch_exit(ebuild_phase) {
	s._final_exit(ebuild_phase)
	elog_process(s.settings.mycpv, s.settings)
	shutil.rmtree(s._private_tmpdir)
	s._async_wait()
}

func NewSpawnNofetchWithoutBuilddir(
	background bool,
	portdb = portdb,
	ebuild_path string,
	scheduler *SchedulerInterface,
fd_pipes map[int]int,
settings *Config)*SpawnNofetchWithoutBuilddir {
	s := &SpawnNofetchWithoutBuilddir{}
	s.CompositeTask = NewCompositeTask()

	s.background = background
	s.portdb = portdb
	s.ebuild_path = ebuild_path
	s.scheduler = scheduler
	s.fd_pipes = fd_pipes
	s.settings = settings

	return s
}

// nil, nil
func spawn_nofetch(portdb, ebuild_path string, settings *Config, fd_pipes map[int]int) {
	nofetch := NewSpawnNofetchWithoutBuilddir(false,
		portdb = portdb,
		ebuild_path,
		NewSchedulerInterface(asyncio._safe_loop()),
		fd_pipes, settings,)

	nofetch.start()
	return nofetch.wait()
}
