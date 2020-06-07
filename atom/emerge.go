package atom

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type AsynchronousTask struct {
	background                                                bool
	scheduler                                                 *SchedulerInterface
	_exit_listener_handles, _exit_listeners, _start_listeners string
	_cancelled_returncode                                     int
	returncode                                                *int
	cancelled                                                 bool
}

func (a *AsynchronousTask) start() {
	a._start_hook()
	a._start()
}

func (a *AsynchronousTask)  async_wait() {
	waiter := a.scheduler.create_future()
	exit_listener := func(a *AsynchronousTask) { return waiter.cancelled() || waiter.set_result(a.returncode) }
	a.addExitListener(exit_listener)
	waiter.add_done_callback(func(waiter) {
		if waiter.cancelled() {
			return a.removeExitListener(exit_listener)
		} else {
			return nil
		}
	})
	if a.returncode != nil {
		a._async_wait()
	}
	return waiter
}

func (a *AsynchronousTask)  _start() {
	a.returncode = new(int)
	*a.returncode = syscall.F_OK
	a._async_wait()
}

func (a *AsynchronousTask)  isAlive() bool{
	return a.returncode == nil
}

func (a *AsynchronousTask)  poll() *int {
	if a.returncode != nil {
		return a.returncode
	}
	a._poll()
	a._wait_hook()
	return a.returncode
}

func (a *AsynchronousTask)  _poll() *int {
	return a.returncode
}

func (a *AsynchronousTask)  wait() *int {
	if a.returncode == nil {
		if a.scheduler.is_running() {
			raise asyncio.InvalidStateError("Result is not ready for %s" % (a, ))
		}
		a.scheduler.run_until_complete(a.async_wait())
	}
	a._wait_hook()
	return a.returncode
}

func (a *AsynchronousTask)  _async_wait(){
	a.wait()
}

func (a *AsynchronousTask)  cancel() {
	if ! a.cancelled {
		a.cancelled = true
	}
	a._cancel()
}

func (a *AsynchronousTask)  _cancel() {}

func (a *AsynchronousTask)  _was_cancelled()bool{
	if a.cancelled {
		if a.returncode == nil {
			a.returncode = &a._cancelled_returncode
		}
		return true
	}
	return false
}

func (a *AsynchronousTask)  addStartListener( f){
	if a._start_listeners == nil{
		a._start_listeners = []
	}
	a._start_listeners = append(a._start_listeners, f)

	if a.returncode != nil {
		a._start_hook()
	}
}

func (a *AsynchronousTask)  removeStartListener( f) {
	if a._start_listeners == nil {
		return
	}
	sls := a._start_listeners
	a._exit_listener_handles = []{}
	for _,sl:=range sla {
		if sl != f {
			a._exit_listener_handles = append(a._exit_listener_handles, f)
		}
	}
}

func (a *AsynchronousTask)  _start_hook(){
if a._start_listeners != nil {
	start_listeners := a._start_listeners
	a._start_listeners = nil

	for _, f := range start_listeners {
		a.scheduler.call_soon(f, a)
	}
}
}

func (a *AsynchronousTask)  addExitListener( f) {
	if a._exit_listeners == nil {
		a._exit_listeners = []
	}
	a._exit_listeners=append(a._exit_listeners, f)
	if a.returncode != nil {
		a._wait_hook()
	}
}

func (a *AsynchronousTask)  removeExitListener( f){
if a._exit_listeners != nil {
try:
	a._exit_listeners.remove(f)
	except ValueError:
	pass

}
if a._exit_listener_handles != nil {
	handle := a._exit_listener_handles[f]
	delete(a._exit_listener_handles,f)
	if handle != nil {
		handle.cancel()
	}
}
}

func (a *AsynchronousTask)  _wait_hook() {
	if a.returncode != nil {
		a._start_hook()
	}

	if a.returncode != nil && a._exit_listeners != nil {
		listeners := a._exit_listeners
		a._exit_listeners = nil
		if a._exit_listener_handles == nil {
			a._exit_listener_handles = map[]{}
		}

		for _, listener := range listeners {
			if _, ok := a._exit_listener_handles[listener]; !ok {
				a._exit_listener_handles[listener] = a.scheduler.call_soon(a._exit_listener_cb, listener)
			}
		}
	}
}

func (a *AsynchronousTask)  _exit_listener_cb( listener) {
	delete(a._exit_listener_handles,listener)
	listener(a)
}

func NewAsynchronousTask() *AsynchronousTask{
	a := &AsynchronousTask{}
	a._cancelled_returncode = int(-syscall.SIGINT)
	return a
}

type AbstractPollTask struct {
	*AsynchronousTask
	_registered bool
	_bufsize int
}

func (a *AbstractPollTask) _read_array( f int)string{
	f2 := os.NewFile(uintptr(f), "")
	buf := make([]byte, a._bufsize)
	_, err := f2.Read(buf)
	if err != nil {
		return ""
	}
//except EOFError:
//pass
//except TypeError:
//pass
//except IOError as e:
//if e.errno == errno.EIO:
//pass
//else if e.errno == errno.EAGAIN:
//buf = nil
//else:
//raise

return string(buf)
}

func (a *AbstractPollTask) _read_buf( fd int)[]byte{
	f := os.NewFile(uintptr(fd), "")
	buf := make([]byte, a._bufsize)
	_, err := f.Read(buf)
	if err != nil {
		if err == syscall.EIO {
			buf = []byte{}
		} else if err == syscall.EAGAIN {
			buf = nil
		} else {
			//raise
		}
	}
	return buf
}

func (a *AbstractPollTask) _async_wait() {
	a._unregister()
	a.AsynchronousTask._async_wait()
}

func (a *AbstractPollTask)  _unregister() {
	a._registered = false
}

// nil
func (a *AbstractPollTask) _wait_loop(timeout=nil) {
	loop := a.scheduler
	tasks := []{a.async_wait()}
	if timeout != nil {
		tasks = append(asyncio.ensure_future(
			asyncio.sleep(timeout, loop = loop), loop = loop))
	}
try:
	loop.run_until_complete(asyncio.ensure_future(
		asyncio.wait(tasks, return_when = asyncio.FIRST_COMPLETED,
		loop = loop), loop = loop))
finally:
	for _, task := range tasks {
		task.cancel()
	}
}

func NewAbstractPollTask() *AbstractPollTask{
	a := &AbstractPollTask{}
	a.AsynchronousTask = NewAsynchronousTask()
	a._bufsize = 4096
	return a
}

type SubProcess struct {
	*AbstractPollTask
	pid, _waitpid_id int
	_dummy_pipe_fd int
	_files []*os.File
	_cancel_timeout int
}

func (s *SubProcess) _poll() *int{
	return s.returncode
}

func (s *SubProcess) _cancel(){
if s.isAlive() && s.pid != 0{
	err := syscall.Kill(s.pid, syscall.SIGTERM)
	if err != nil {
		//except OSError as e:
		if err == syscall.EPERM {
			WriteMsgLevel(fmt.Sprintf("!!! kill: (%i) - Operation not permitted\n" , s.pid), 40, -1)
		}else if err != syscall.ESRCH {
			//raise
		}
	}
}
}

func (s *SubProcess) _async_wait() {
	if s.returncode == nil {
		//raise asyncio.InvalidStateError('Result is not ready for %s' % (s,))
	} else {
		s.AbstractPollTask._async_wait()
	}
}

func (s *SubProcess) _async_waitpid() {
	if s.returncode != nil {
		s._async_wait()
	} else if s._waitpid_id == 0 {
		s._waitpid_id = s.pid
		s.scheduler._asyncio_child_watcher.add_child_handler(s.pid, s._async_waitpid_cb)

	}
}

func (s *SubProcess) _async_waitpid_cb( pid, returncode int) {
	if pid != s.pid {
		//raise AssertionError("expected pid %s, got %s" % (s.pid, pid))
	}
	s.returncode = new(int)
	*s.returncode = returncode
	s._async_wait()
}

func (s *SubProcess) _orphan_process_warn(){
}

func (s *SubProcess) _unregister() {
	s._registered = false
	if s._waitpid_id != 0 {
		s.scheduler._asyncio_child_watcher.remove_child_handler(s._waitpid_id)
		s._waitpid_id = 0
	}

	if s._files != nil {
		for _, f := range s._files {
			f.Close()
		}
		s._files = nil
	}
}

func NewSubProcess() *SubProcess {
	s := &SubProcess{}
	s._cancel_timeout = 1
	s.AbstractPollTask = NewAbstractPollTask()
	return s
}

type SpawnProcess struct {
	*SubProcess
	_CGROUP_CLEANUP_RETRY_MAX int

	// slot
	opt_name,
	uid, gid, groups, umask, logfile,
	path_lookup, pre_exec, close_fds, cgroup,
	unshare_ipc, unshare_mount, unshare_pid, unshare_net,
	_pipe_logger, _selinux_type string
	fd_pipes map[int]int
	args     []string
	env      map[string]string
}

var _spawn_kwarg_names = []string{"env", "opt_name", "fd_pipes",
"uid", "gid", "groups", "umask", "logfile",
"path_lookup", "pre_exec", "close_fds", "cgroup",
"unshare_ipc", "unshare_mount", "unshare_pid", "unshare_net"}

__slots__ = ("args",) +
_spawn_kwarg_names + ("_pipe_logger", "_selinux_type",)

func(s *SpawnProcess) _start(){
	if s.fd_pipes == nil{
		s.fd_pipes =map[int]int{}
	}else {
		s.fd_pipes = s.fd_pipes
	}
	fd_pipes := s.fd_pipes

	master_fd, slave_fd := s._pipe()

	can_log := s._can_log(slave_fd)
	log_file_path := s.logfile
	if !can_log{
		log_file_path = ""
	}

	var null_input int
	if _, ok := fd_pipes[0]; ! s.background|| ok {
		//pass
	}else{
		null_input, _ = syscall.Open("/dev/null", os.O_RDWR, 0655)
		fd_pipes[0] = null_input
	}

	if _, ok := fd_pipes[0]; !ok {
		fd_pipes[0] = int(getStdin().Fd())
	}
	if _, ok := fd_pipes[1]; !ok {
		fd_pipes[1] = syscall.Stdout
	}
	if _, ok := fd_pipes[2]; !ok {
		fd_pipes[2] = syscall.Stderr
	}

	fd_pipes_orig := map[int]*os.File{}
	for k, v := range fd_pipes{
		fd_pipes_orig[k]=v
	}

	if log_file_path != "" || s.background{
		fd_pipes[1] = slave_fd
		fd_pipes[2] = slave_fd
	}else{
		s._dummy_pipe_fd = slave_fd
		fd_pipes[int(slave_fd.Fd())] = slave_fd
	}

	kwargs = {}
	for k in s._spawn_kwarg_names{
		v = getattr(s, k)
		if v != nil{
		kwargs[k] = v
	}
	}

	kwargs["fd_pipes"] = fd_pipes
	kwargs["returnpid"] = true
	kwargs.pop("logfile", nil)

	retval := s._spawn(s.args, **kwargs)

	syscall.Close(slave_fd)
	if null_input != 0 {
		syscall.Close(null_input)
	}

	if isinstance(retval, int):
	s.returncode = retval
	s._async_wait()
	return

	s.pid = retval[0]

	stdout_fd = nil
	if can_log && ! s.background:
	stdout_fd = syscall.Dup(string(fd_pipes_orig[1].Fd()))
	if sys.hexversion < 0x3040000 && fcntl != nil:
try:
	fcntl.FD_CLOEXEC
	except AttributeError:
	pass
	else:
	fcntl.fcntl(stdout_fd, fcntl.F_SETFD,
		fcntl.fcntl(stdout_fd,
			fcntl.F_GETFD) | fcntl.FD_CLOEXEC)

	s._pipe_logger = PipeLogger(background=s.background,
		scheduler=s.scheduler, input_fd=master_fd,
		log_file_path=log_file_path,
		stdout_fd=stdout_fd)
	s._pipe_logger.addExitListener(s._pipe_logger_exit)
	s._pipe_logger.start()
	s._registered = true
}


func(s *SpawnProcess) _can_log( slave_fd *os.File)bool{
	return true
}

func(s *SpawnProcess) _pipe()(int, int){
	r :=make([]int, 2)
	syscall.Pipe(r)
	return r[0],r[1]
}

func(s *SpawnProcess) _spawn(args []string, **kwargs) {
	spawn_func := spawn

	if s._selinux_type != nil {
		spawn_func = portage.selinux.spawn_wrapper(spawn_func,
			s._selinux_type)
		if args[0] != BashBinary {
			args = append([]string{BashBinary, "-c", "exec \"$@\"", args[0]}, args...)
		}
	}

	return spawn_func(args, **kwargs)
}

// ignored
func(s *SpawnProcess) _pipe_logger_exit(){
	s._pipe_logger = nil
	s._async_waitpid()
}

func(s *SpawnProcess) _unregister(){
	s.SubProcess._unregister()
	if s.cgroup != nil {
		s._cgroup_cleanup()
		s.cgroup = nil
	}
	if s._pipe_logger != nil {
		s._pipe_logger.cancel()
		s._pipe_logger = nil
	}
}

func(s *SpawnProcess) _cancel(){
	s.SubProcess._cancel()
	s._cgroup_cleanup()
}

func(s *SpawnProcess) _cgroup_cleanup() {
	if s.cgroup != nil {
		get_pids := func(cgroup string) []int {
			f, err := os.Open(filepath.Join(cgroup, "cgroup.procs"))
			var b []byte
			if err == nil {
				b, err = ioutil.ReadAll(f)
			}
			if err != nil {
				return []int{}
			}
			ps := []int{}
			for _, p := range strings.Fields(string(b)) {
				pi, _ := strconv.Atoi(p)
				ps = append(ps, pi)
			}
			return ps
		}
		kill_all := func(pids []int, sig syscall.Signal) {
			for _, p := range pids {
				err := syscall.Kill(p, sig)
				if err != nil {
					//except OSError as e:
					if err == syscall.EPERM {
						WriteMsgLevel(fmt.Sprintf("!!! kill: (%i) - Operation not permitted\n", p), 40, -1)
					} else if err != syscall.ESRCH {
						//raise
					}
				}
			}
		}
		remaining := s._CGROUP_CLEANUP_RETRY_MAX
		var pids []int
		for remaining > 0 {
			remaining -= 1
			pids = get_pids(s.cgroup)
			if len(pids) != 0 {
				kill_all(pids, syscall.SIGKILL)
			} else {
				break
			}
		}

		if len(pids) > 0 {
			msg := []string{}
			pidss := []string{}
			for _, p := range pids {
				pidss = append(pidss, fmt.Sprint(p))
			}
			msg = append(msg,
				fmt.Sprintf("Failed to kill pid(s) in '%(cgroup)s': %(pids)s",
					filepath.Join(s.cgroup.Name(), "cgroup.procs", strings.Join(pidss, " "))))

			s._elog("eerror", msg)
		}

		err := os.RemoveAll(s.cgroup.Name())
		if err != nil {
			//except OSError:
			//pass
		}
	}
}

func(s *SpawnProcess) _elog(elog_funcname, lines){
	elog_func = getattr(NewEOutput(), elog_funcname)
	for _, line := range lines{
		elog_func(line)
	}
}

func NewSpawnProcess(args []string, background bool, env map[string]string, scheduler, logfile string) *SpawnProcess {
	s := &SpawnProcess{}
	s.args =args
	s.background = background
	s.env = env
	s.scheduler = scheduler
	s.logfile = logfile
	s._CGROUP_CLEANUP_RETRY_MAX = 8
	s.SubProcess = NewSubProcess()
	return s
}

type ForkProcess struct {
	*SpawnProcess
}

__slots__ = ()

func(f *ForkProcess) _spawn( args, fd_pipes=nil, **kwargs){
	parent_pid := os.Getpid()
	pid = nil
try:
	pid = os.fork()

	if pid != 0:
	if not isinstance(pid, int):
	raise AssertionError(
		"fork returned non-integer: %s" % (repr(pid),))
	return [pid]

	rval = 1
try:

	signal.signal(signal.SIGINT, signal.SIG_DFL)
	signal.signal(signal.SIGTERM, signal.SIG_DFL)

	signal.signal(signal.SIGCHLD, signal.SIG_DFL)
try:
	wakeup_fd = signal.set_wakeup_fd(-1)
	if wakeup_fd > 0:
	syscall.Close(wakeup_fd)
	except (ValueError, OSError):
	pass

	_close_fds()
	_setup_pipes(fd_pipes, false)

	rval := f._run()
	except SystemExit:
	raise
except:
	traceback.print_exc()
	sys.stderr.flush()
finally:
	os._exit(rval)

finally:
	if pid == 0 || (pid == nil && syscall.Getpid() != parent_pid):
	os._exit(1)
}


func(f *ForkProcess) _run(){
	panic("not implemented")
	//raise NotImplementedError(f)
}

type MergeProcess struct {
	*ForkProcess
	settings *Config
	mydbapi *vardbapi
	vartree *varTree
	mycat, mypkg,  treetype, blockers, pkgloc, infloc, myebuild,
	  prev_mtimes, unmerge, _buf   string
	_elog_reader_fd int
	_elog_keys map[string]bool
	postinst_failure, _locked_vdb bool
}

func(m *MergeProcess)  _start() {
	cpv := fmt.Sprintf("%s/%s", m.mycat, m.mypkg)
	settings := m.settings
	if _, ok := settings.configDict["pkg"]["EAPI"]; cpv != settings.mycpv.string || !ok {
		settings.reload()
		settings.reset(0)
		settings.SetCpv(NewPkgStr(cpv, nil, nil, "", "", "", 0, 0, "", 0, nil), m.mydbapi)
	}

	if _, ok := settings.Features.Features["merge-sync"]; runtime.GOOS == "Linux" && ok {
		//find_library("c")
	}

	if m.fd_pipes == nil {
		m.fd_pipes = map[int]int{}
	} else {
		m.fd_pipes = m.fd_pipes
	}
	if _, ok := m.fd_pipes[0]; !ok {
		m.fd_pipes[0] = int(getStdin().Fd())
	}

	m.ForkProcess._start()
}

func(m *MergeProcess) _lock_vdb(){

	if  _, ok :=  m.settings.Features.Features["parallel-install"]; !ok {
		m.vartree.dbapi.lock()
		m._locked_vdb = true
	}
}

func(m *MergeProcess) _unlock_vdb(){
	if m._locked_vdb{
		m.vartree.dbapi.unlock()
		m._locked_vdb = false
	}
}

// true means none
func(m *MergeProcess) _elog_output_handler() bool {
	output := m._read_buf(m._elog_reader_fd)
	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		if len(lines) == 1 {
			m._buf += lines[0]
		} else {
			lines[0] = m._buf + lines[0]
			m._buf = lines.pop()
			out := &bytes.Buffer{}
			for _, line := range lines {
				s4 := strings.SplitN(line, " ", 4)
				funcname, phase, key, msg := s4[0], s4[1], s4[2], s4[3]
				m._elog_keys[key] = true
				reporter = getattr(portage.elog.messages, funcname)
				reporter(msg, phase = phase, key = key, out = out)
			}
		}
	} else if output != nil {
		m.scheduler.remove_reader(m._elog_reader_fd)
		syscall.Close(m._elog_reader_fd)
		m._elog_reader_fd = nil
		return false
	}
	return true
}

func(m *MergeProcess) _spawn( args, fd_pipes map[int]int, **kwargs) {
	r := make([]int, 2)
	syscall.Pipe(r)
	elog_reader_fd, elog_writer_fd := r[0], r[1]

	fcntl.fcntl(elog_reader_fd, fcntl.F_SETFL,
		fcntl.fcntl(elog_reader_fd, fcntl.F_GETFL)|syscall.O_NONBLOCK)

	var blockers = nil
	if m.blockers != nil {
		blockers = m.blockers()
	}
	mylink := NewDblink(m.mycat, m.mypkg, "", m.settings,
		m.treetype, m.vartree,
		blockers, nil, elog_writer_fd)
	fd_pipes[elog_writer_fd] = elog_writer_fd
	m.scheduler.add_reader(elog_reader_fd, m._elog_output_handler)

	m._lock_vdb()
	counter := 0
	if !m.unmerge {
		counter = m.vartree.dbapi.counter_tick()
	}

	parent_pid := syscall.Getpid()
	pid := 0
try:
	pid = syscall.fork()

	if pid != 0 {
		if not isinstance(pid, int):
		raise
		AssertionError(
			"fork returned non-integer: %s" % (repr(pid), ))

		syscall.Close(elog_writer_fd)
		m._elog_reader_fd = elog_reader_fd
		m._buf = ""
		m._elog_keys = map[string]bool{}
		portage.elog.messages.collect_messages(key = mylink.mycpv)

		if m.vartree.dbapi._categories != nil {
			m.vartree.dbapi._categories = nil
		}
		m.vartree.dbapi._pkgs_changed = true
		m.vartree.dbapi._clear_pkg_cache(mylink)

		return []int{pid}
	}

	syscall.Close(elog_reader_fd)

	signal.signal(signal.SIGINT, signal.SIG_DFL)
	signal.signal(signal.SIGTERM, signal.SIG_DFL)

	signal.signal(signal.SIGCHLD, signal.SIG_DFL)
try:
	wakeup_fd := signal.set_wakeup_fd(-1)
	if wakeup_fd > 0 {
		syscall.Close(wakeup_fd)
	}
	except(ValueError, OSError):
	pass

	_close_fds()
	portage.process._setup_pipes(fd_pipes, close_fds = false)

	havecolor := m.settings.ValueDict["NOCOLOR"] == "yes" || m.settings.ValueDict["NOCOLOR"] == "true"

	m.vartree.dbapi._flush_cache_enabled = false

	if !m.unmerge {
		if m.settings.ValueDict["PORTAGE_BACKGROUND"] == "1" {
			m.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] = "1"
		} else {
			m.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] = "0"
		}
		m.settings.backupChanges("PORTAGE_BACKGROUND_UNMERGE")
	}
	m.settings.ValueDict["PORTAGE_BACKGROUND"] = "subprocess"
	m.settings.backupChanges("PORTAGE_BACKGROUND")

	rval := 1
try:
	if m.unmerge {
		if !mylink.exists() {
			rval = syscall.EX_OK
		} else if mylink.unmerge(
			ldpath_mtimes = m.prev_mtimes) == syscall.F_OK{
			mylink.lockdb()
			try:
			mylink.delete()
			finally:
			mylink.unlockdb()
			rval = syscall.EX_OK
		}
	} else {
		rval = mylink.merge(m.pkgloc, m.infloc,
			myebuild = m.myebuild, mydbapi = m.mydbapi,
			prev_mtimes=m.prev_mtimes, counter = counter)
	}
	except
SystemExit:
	raise
except:
	traceback.print_exc()
	sys.stderr.flush()
finally:
	syscall._exit(rval)

finally:
	if pid == 0 || (pid == 0 && syscall.Getpid() != parent_pid) {
		os._exit(1)
	}
}


func(m *MergeProcess) _async_waitpid_cb( *args, **kwargs){
	m.ForkProcess._async_waitpid_cb( *args, **kwargs)
	if *m.returncode == ReturncodePostinstFailure{
		m.postinst_failure = true
		*m.returncode = syscall.F_OK
	}
}

func(m *MergeProcess) _unregister() {
	if !m.unmerge {
		//try:
		m.vartree.dbapi.aux_get(m.settings.mycpv.string, map[string]bool{"EAPI": true}, "")
		//except KeyError:
		//pass
	}

	m._unlock_vdb()
	if m._elog_reader_fd != nil {
		m.scheduler.remove_reader(m._elog_reader_fd)
		syscall.Close(m._elog_reader_fd)
		m._elog_reader_fd = nil
	}
	if m._elog_keys != nil {
		for key := range m._elog_keys {
			portage.elog.elog_process(key, m.settings,
				phasefilter = ("prerm", "postrm"))
		}
		m._elog_keys = nil
	}
	m.ForkProcess._unregister()
}

type AbstractEbuildProcess struct {
	*SpawnProcess
	// slot
	settings *Config
	phase, _build_dir, _build_dir_unlock, _ipc_daemon,
	_exit_command, _exit_timeout_id, _start_future string

	_phases_without_builddir []string
	_phases_interactive_whitelist []string
	_exit_timeout int
	_enable_ipc_daemon bool
}

func NewAbstractEbuildProcess( **kwargs)*AbstractEbuildProcess {
	a := &AbstractEbuildProcess{}
	a._phases_without_builddir = []string{"clean", "cleanrm", "depend", "help",}
	a._phases_interactive_whitelist = []string{"config",}
	a._exit_timeout = 10
	a._enable_ipc_daemon = true

	a.SpawnProcess = NewSpawnProcess(**kwargs)
	if a.phase == "" {
		phase := a.settings.ValueDict["EBUILD_PHASE"]
		if phase == "" {
			phase = "other"
			a.phase = phase
		}
	}
	return a
}

func (a *AbstractEbuildProcess)_start() {

	need_builddir := true
	for _, v := range a._phases_without_builddir {
		if a.phase == v {
			need_builddir = false
			break
		}
	}

	if st, err := os.Stat(a.settings.ValueDict["PORTAGE_BUILDDIR"]); need_builddir && err != nil && !st.IsDir() {
		msg := fmt.Sprintf("The ebuild phase '%s' has been aborted "+
			"since PORTAGE_BUILDDIR does not exist: '%s'", a.phase, a.settings.ValueDict["PORTAGE_BUILDDIR"])
		a._eerror(SplitSubN(msg, 72))
		i := 1
		a.returncode = &i
		a._async_wait()
		return
	}

	if os.Geteuid() == 0 && runtime.GOOS == "linux" && a.settings.Features.Features["cgroup"] && !_global_pid_phases[a.phase] {
		cgroup_root := "/sys/fs/cgroup"
		cgroup_portage := filepath.Join(cgroup_root, "portage")

		mp, err := Mountpoint(cgroup_root)
		if err == nil {
			if mp != cgroup_root {
				st, err1 := os.Stat(cgroup_root)
				if err1 != nil {
					err = err1
				} else {
					if !st.IsDir() {
						os.MkdirAll(cgroup_root, 0755)
					}
					err = exec.Command("mount", "-t", "tmpfs",
						"-o", "rw,nosuid,nodev,noexec,mode=0755",
						"tmpfs", cgroup_root).Run()
				}
			}
		}
		if err == nil {
			mp, err1 := Mountpoint(cgroup_portage)
			if err1 != nil {
				err = err1
			} else {
				if mp != cgroup_portage {
					st, err1 := os.Stat(cgroup_portage)
					if err1 != nil {
						err = err1
					} else {
						if !st.IsDir() {
							os.MkdirAll(cgroup_portage, 0755)
						}
						err = exec.Command("mount", "-t", "cgroup",
							"-o", "rw,nosuid,nodev,noexec,none,name=portage",
							"tmpfs", cgroup_portage).Run()
					}
					if err == nil {
						f, err1 := os.OpenFile(filepath.Join(
							cgroup_portage, "release_agent"), os.O_RDWR|os.O_APPEND, 0644)
						if err1 != nil {
							err = err1
						} else {
							_, err = f.Write([]byte(filepath.Join(a.settings.ValueDict["PORTAGE_BIN_PATH"],
								"cgroup-release-agent")))
						}
					}
					if err == nil {
						f, err1 := os.OpenFile(filepath.Join(
							cgroup_portage, "notify_on_release"), os.O_RDWR|os.O_APPEND, 0644)
						if err1 != nil {
							err = err1
						} else {
							_, err = f.Write([]byte("1"))
						}
					}
				} else {
					release_agent := filepath.Join(
						cgroup_portage, "release_agent")
					f, err1 := os.Open(release_agent)
					release_agent_path := ""
					if err1 != nil {
					}
					defer f.Close()
					l, err1 := ioutil.ReadAll(f)
					if err1 != nil {
					}
					release_agent_path = strings.Split(string(l), "\n")[0]

					if st, _ := os.Stat(release_agent_path); release_agent_path == "" || st != nil {
						f, err1 := os.OpenFile(release_agent, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
						if err1 != nil {

						}
						f.Write([]byte(filepath.Join(
							a.settings.ValueDict["PORTAGE_BIN_PATH"],
							"cgroup-release-agent")))
					}
				}
			}
		}

		var cgroup_path string
		if err == nil {
			cp, err1 :=
				ioutil.TempFile(cgroup_portage,
					fmt.Sprintf("%s:%s.*", a.settings.ValueDict["CATEGORY"],
						a.settings.ValueDict["PF"]))
			if err1 != nil {
				err = err1
			} else {
				cgroup_path = filepath.Join(cgroup_portage, cp.Name())
			}
		}
		if err != nil {
			//except (subprocess.CalledProcessError, OSError){
			//pass
			//}else{
		} else {
			a.cgroup = cgroup_path
		}
	}

	if a.background {
		a.settings.ValueDict["NOCOLOR"] = "true"
	}

	start_ipc_daemon := false
	if a._enable_ipc_daemon {
		delete(a.settings.ValueDict, "PORTAGE_EBUILD_EXIT_FILE")
		if !Ins(a._phases_without_builddir, a.phase) {
			start_ipc_daemon = true
			if _, ok := a.settings.ValueDict["PORTAGE_BUILDDIR_LOCKED"]; !ok {
				a._build_dir = EbuildBuildDir(
					scheduler = a.scheduler, settings = a.settings)
				a._start_future = a._build_dir.async_lock()
				a._start_future.add_done_callback(
					functools.partial(a._start_post_builddir_lock,
						start_ipc_daemon = start_ipc_daemon))
				return
			}
		} else {
			delete(a.settings.ValueDict, "PORTAGE_IPC_DAEMON")
		}
	} else {
		delete(a.settings.ValueDict, "PORTAGE_IPC_DAEMON")
		if Ins(a._phases_without_builddir, a.phase) {
			exit_file := filepath.Join(
				a.settings.ValueDict["PORTAGE_BUILDDIR"],
				".exit_status")
			a.settings.ValueDict["PORTAGE_EBUILD_EXIT_FILE"] = exit_file
			if err := syscall.Unlink(exit_file); err != nil {
				//except OSError{
				if st, err := os.Stat(exit_file); err == nil && st != nil {
					//raise
				}
			}
		} else {
			delete(a.settings.ValueDict, "PORTAGE_EBUILD_EXIT_FILE")
		}
	}

	a._start_post_builddir_lock(nil, start_ipc_daemon)
}

// nil, false
func (a *AbstractEbuildProcess)_start_post_builddir_lock( lock_future , start_ipc_daemon bool) {
	if lock_future != nil {
		//if lock_future is not a._start_future{
		//raise AssertionError("lock_future is not a._start_future")
		a._start_future = nil
		if lock_future.cancelled() {
			a._build_dir = nil
			a.cancelled = true
			a._was_cancelled()
			a._async_wait()
			return
		}
		lock_future.result()
	}
	if start_ipc_daemon {
		a.settings.ValueDict["PORTAGE_IPC_DAEMON"] = "1"
		a._start_ipc_daemon()
	}

	if a.fd_pipes == nil {
		a.fd_pipes = map[int]int{}
	}
	null_fd := 0
	if _, ok := a.fd_pipes[0]; !ok &&
		!Ins(a._phases_interactive_whitelist, a.phase) &&
		!Ins(strings.Fields(a.settings.ValueDict["PROPERTIES"]), "interactive") {
		null_fd, _ := syscall.Open("/dev/null", os.O_RDWR, 0644)
		a.fd_pipes[0] = null_fd
	}

	//try{
	a.SpawnProcess._start()
	//finally{
	if null_fd != 0 {
		syscall.Close(null_fd)
	}
}



func (a *AbstractEbuildProcess)_init_ipc_fifos()(string,string) {

	input_fifo := filepath.Join(
		a.settings.ValueDict["PORTAGE_BUILDDIR"], ".ipc_in")
	output_fifo := filepath.Join(
		a.settings.ValueDict["PORTAGE_BUILDDIR"], ".ipc_out")

	for _, p := range []string{input_fifo, output_fifo} {

		st, err := os.Lstat(p)
		if err != nil {

			//except OSError{
			syscall.Mkfifo(p, 0755)
		} else {
			if st.Mode()&syscall.S_IFIFO == 0 {
				st = nil
				if err := syscall.Unlink(p); err != nil {
					//except OSError{
					//	pass
				}
				syscall.Mkfifo(p, 0755)
			}
		}
		apply_secpass_permissions(p, uint32(os.Getuid()), *portage_gid, 0770, -1, st, true)
	}

	return input_fifo, output_fifo
}

func (a *AbstractEbuildProcess)_start_ipc_daemon() {
	a._exit_command = ExitCommand()
	a._exit_command.reply_hook = a._exit_command_callback
	query_command := NewQueryCommand(a.settings, a.phase)
	commands := map[string]*QueryCommand{
		"available_eclasses":  query_command,
		"best_version":        query_command,
		"eclass_path":         query_command,
		"exit":                a._exit_command,
		"has_version":         query_command,
		"license_path":        query_command,
		"master_repositories": query_command,
		"repository_path":     query_command,
	}
	input_fifo, output_fifo = a._init_ipc_fifos()
	a._ipc_daemon = EbuildIpcDaemon(commands = commands,
		input_fifo = input_fifo,
		output_fifo=output_fifo,
		scheduler = a.scheduler)
	a._ipc_daemon.start()
}

func (a *AbstractEbuildProcess)_exit_command_callback() {
	if a._registered {
		a._exit_timeout_id =
			a.scheduler.call_later(a._exit_timeout,
				a._exit_command_timeout_cb)
	}
}

func (a *AbstractEbuildProcess)_exit_command_timeout_cb() {
	if a._registered {
		a.cancel()
		a._exit_timeout_id =
			a.scheduler.call_later(a._cancel_timeout,
				a._cancel_timeout_cb)
	} else {
		a._exit_timeout_id = nil
	}
}

func (a *AbstractEbuildProcess)_cancel_timeout_cb() {
	a._exit_timeout_id = nil
	a._async_waitpid()
}

func (a *AbstractEbuildProcess)_orphan_process_warn() {
	phase := a.phase

	msg := fmt.Sprintf("The ebuild phase '%s' with pid %s appears "+
		"to have left an orphan process running in the background.", phase, a.pid)

	a._eerror(SplitSubN(msg, 72))
}

func (a *AbstractEbuildProcess)_pipe( fd_pipes map[int]int) (int, int) {
	stdout_pipe := 0
	if !a.background {
		stdout_pipe = fd_pipes[1]
	}
	got_pty, master_fd, slave_fd :=
		_create_pty_or_pipe(copy_term_size = stdout_pipe)
	return master_fd, slave_fd
}

func (a *AbstractEbuildProcess)_can_log( slave_fd int)bool {
	return !(a.settings.Features.Features["sesandbox"] && a.settings.selinux_enabled()) || os.isatty(slave_fd)
}

func (a *AbstractEbuildProcess)_killed_by_signal( signum int) {
	msg := fmt.Sprintf("The ebuild phase '%s' has been killed by signal %s.", a.phase, signum)
	a._eerror(SplitSubN(msg, 72))
}

func (a *AbstractEbuildProcess)_unexpected_exit() {

	phase := a.phase

	msg := fmt.Sprintf("The ebuild phase '%s' has exited "+
		"unexpectedly. This type of behavior "+
		"is known to be triggered "+
		"by things such as failed variable "+
		"assignments (bug #190128) or bad substitution "+
		"errors (bug #200313). Normally, before exiting, bash should "+
		"have displayed an error message above. If bash did not "+
		"produce an error message above, it's possible "+
		"that the ebuild has called `exit` when it "+
		"should have called `die` instead. This behavior may also "+
		"be triggered by a corrupt bash binary or a hardware "+
		"problem such as memory or cpu malfunction. If the problem is not "+
		"reproducible or it appears to occur randomly, then it is likely "+
		"to be triggered by a hardware problem. "+
		"If you suspect a hardware problem then you should "+
		"try some basic hardware diagnostics such as memtest. "+
		"Please do not report this as a bug unless it is consistently "+
		"reproducible and you are sure that your bash binary and hardware "+
		"are functioning properly.", phase)

	a._eerror(SplitSubN(msg, 72))
}

func (a *AbstractEbuildProcess)_eerror( lines []string) {
	a._elog("eerror", lines)
}

func (a *AbstractEbuildProcess)_elog( elog_funcname, lines) {
	out := &bytes.Buffer{}
	phase := a.phase
	elog_func = getattr(elog_messages, elog_funcname)
	global_havecolor := HaveColor
	//try{
	nc, ok := a.settings.ValueDict["NOCOLOR"]
	if !ok {
		HaveColor = 1
	} else if strings.ToLower(nc) == "no" || strings.ToLower(nc) == "false" {
		HaveColor = 0
	}
	for _, line := range lines {
		elog_func(line, phase = phase, key = a.settings.mycpv, out = out)
	}
	//finally{
	HaveColor = global_havecolor
	msg := out.String()
	if msg != "" {
		log_path := ""
		if a.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
			log_path = a.settings.ValueDict["PORTAGE_LOG_FILE"]
		}
		a.scheduler.output(msg, log_path = log_path)
	}
}

func (a *AbstractEbuildProcess)_async_waitpid_cb( *args, **kwargs) {
	a.SpawnProcess._async_waitpid_cb(*args, **kwargs)

	if a._exit_timeout_id != nil {
		a._exit_timeout_id.cancel()
		a._exit_timeout_id = nil
	}

	if a._ipc_daemon != nil {
		a._ipc_daemon.cancel()
		if a._exit_command.exitcode != nil {
			a.returncode = a._exit_command.exitcode
		} else {
			if *a.returncode < 0 {
				if !a.cancelled {
					a._killed_by_signal(-*a.returncode)
				}
			} else {
				i := 1
				a.returncode = &i
				if !a.cancelled {
					a._unexpected_exit()
				}
			}
		}

	} else if !a.cancelled {
		exit_file := a.settings.ValueDict["PORTAGE_EBUILD_EXIT_FILE"]
		if st, _ := os.Stat(exit_file); exit_file != "" && st == nil {
			if *a.returncode < 0 {
				if !a.cancelled {
					a._killed_by_signal(-*a.returncode)
				}
			} else {
				i := 1
				a.returncode = &i
				if !a.cancelled {
					a._unexpected_exit()
				}
			}
		}
	}
}

func (a *AbstractEbuildProcess)_async_wait() {
	if a._build_dir == nil {
		a.SpawnProcess._async_wait()
	} else if a._build_dir_unlock == nil{
		if a.returncode == nil{
		//raise asyncio.InvalidStateError("Result is not ready for %s" % (a,))
	}
		a._async_unlock_builddir(a.returncode)
	}
}

// nil
func (a *AbstractEbuildProcess)_async_unlock_builddir( returncode *int) {
	if a._build_dir_unlock != nil {
		//raise AssertionError("unlock already in progress")
	}
	if returncode != nil {
		a.returncode = nil
	}
	a._build_dir_unlock = a._build_dir.async_unlock()
	a._build_dir = nil
	a._build_dir_unlock.add_done_callback(
		functools.partial(a._unlock_builddir_exit, returncode = returncode))
}

// nil
func (a *AbstractEbuildProcess)_unlock_builddir_exit( unlock_future, returncode *int) {
	unlock_future.cancelled() || unlock_future.result()
	if returncode != nil {
		if unlock_future.cancelled() {
			a.cancelled = true
			a._was_cancelled()
		} else {
			a.returncode = returncode
		}
		a.SpawnProcess._async_wait()
	}
}

type EbuildSpawnProcess struct {
	*AbstractEbuildProcess
	fakeroot_state string
	spawn_func func()
	}
var _spawn_kwarg_names = append(NewAbstractEbuildProcess()._spawn_kwarg_names ,"fakeroot_state",)

func (e *EbuildSpawnProcess)_spawn( args, **kwargs) {

	env := e.settings.environ()

	if e._dummy_pipe_fd != 0 {
		env["PORTAGE_PIPE_FD"] = fmt.Sprint(e._dummy_pipe_fd)
	}

	return e.spawn_func(args, env = env, **kwargs)
}

type BlockerDB struct{
	_vartree *varTree
	_portdb *portdbapi
	_dep_check_trees *TreesDict
	_root_config  ,_fake_vartree string
}

func NewBlockerDB( fake_vartree)*BlockerDB {
	b := &BlockerDB{}
	root_config := fake_vartree._root_config
	b._root_config = root_config
	b._vartree = root_config.trees["vartree"]
	b._portdb = root_config.trees["porttree"].dbapi

	b._dep_check_trees = nil
	b._fake_vartree = fake_vartree
	b._dep_check_trees = &TreesDict{
		valueDict: map[string]*Tree{b._vartree.settings.ValueDict["EROOT"]:
		&Tree{
			_porttree: fake_vartree,
			_vartree:  fake_vartree,
		},
		},
		_running_eroot: "",
		_target_eroot:  "",
	}
	return b
}

func (b *BlockerDB)findInstalledBlockers( new_pkg) {
	blocker_cache := BlockerCache(nil,
		b._vartree.dbapi)
	dep_keys := NewPackage()._runtime_keys
	settings := b._vartree.settings
	stale_cache := set(blocker_cache)
	fake_vartree := b._fake_vartree
	dep_check_trees := b._dep_check_trees
	vardb := fake_vartree.dbapi
	installed_pkgs := list(vardb)

	for _, inst_pkg := range installed_pkgs {
		stale_cache.discard(inst_pkg.cpv)
		cached_blockers := blocker_cache.get(inst_pkg.cpv)
		if cached_blockers != nil &&
			cached_blockers.counter != inst_pkg.counter {
			cached_blockers = nil
		}
		if cached_blockers != nil {
			blocker_atoms = cached_blockers.atoms
		} else {
			depstr := strings.Join(vardb.aux_get(inst_pkg.cpv, dep_keys), " ")
			success, atoms := dep_check(depstr,
				vardb, settings, "yes", inst_pkg.use.enabled, 1, 0,
				inst_pkg.root, dep_check_trees)
			if success == 0 {
				pkg_location := filepath.Join(inst_pkg.root,
					VdbPath, inst_pkg.category, inst_pkg.pf)
				WriteMsg(fmt.Sprintf("!!! %s/*DEPEND: %s\n",
					pkg_location, atoms), -1, nil)
				continue
			}

			blocker_atoms := [][]*Atom{{}}
			for _, atom := range atoms {
				if atom.startswith("!") {
					blocker_atoms[0] = append(blocker_atoms[0], atom)
				}
			}
			blocker_atoms.sort()
			blocker_cache[inst_pkg.cpv] =
				blocker_cache.BlockerData(inst_pkg.counter, blocker_atoms)
		}
	}
	for cpv := range stale_cache {
		delete(blocker_cache, cpv)
	}
	blocker_cache.flush()

	blocker_parents = digraph()
	blocker_atoms = []*Atom{}
	for _, pkg := range installed_pkgs {
		for blocker_atom
			in
		blocker_cache[pkg.cpv].atoms
		{
			blocker_atom = blocker_atom.lstrip("!")
			blocker_atoms = append(blocker_atoms, blocker_atom)
			blocker_parents.add(blocker_atom, pkg)
		}
	}

	blocker_atoms = InternalPackageSet(initial_atoms = blocker_atoms)
	blocking_pkgs = map[string]string{}
	for atom
		in
	blocker_atoms.iterAtomsForPackage(new_pkg)
	{
		blocking_pkgs.update(blocker_parents.parent_nodes(atom))
	}

	depstr = " ".join(new_pkg._metadata[k]
	for k
		in
	dep_keys)
	success, atoms = dep_check(depstr,
		vardb, settings, "yes", new_pkg.use.enabled, 1, 0,
		new_pkg.root, dep_check_trees)
	if success == 0 {
		show_invalid_depstring_notice(new_pkg, atoms)
		assert
		false
	}

	blocker_atoms = [atom.lstrip("!")
	for atom
		in
	atoms
	if atom[:1] == "!"]
if blocker_atoms{
blocker_atoms = InternalPackageSet(initial_atoms = blocker_atoms)
for inst_pkg in installed_pkgs{
//try{
next(blocker_atoms.iterAtomsForPackage(inst_pkg))
//except (portage.exception.InvalidDependString, StopIteration){
//continue
//blocking_pkgs.add(inst_pkg)
}
}
return blocking_pkgs
}

func (b *BlockerDB)discardBlocker( pkg) {
	for cpv_match
	in
	b._fake_vartree.dbapi.match_pkgs(Atom(fmt.Sprintf("=%s", pkg.cpv, )))
	{
		if cpv_match.cp == pkg.cp {
			b._fake_vartree.cpv_discard(cpv_match)
		}
	}
	for slot_match
	in
	b._fake_vartree.dbapi.match_pkgs(pkg.slot_atom)
	{
		if slot_match.cp == pkg.cp {
			b._fake_vartree.cpv_discard(slot_match)
		}
	}
}


type CompositeTask struct {
	*AsynchronousTask

	// slot
	_current_task string

	_TASK_QUEUED int
}

func NewCompositeTask()*CompositeTask {
	c := &CompositeTask{}
	c._TASK_QUEUED = -1
	return c
}

func (c*CompositeTask)_cancel() {
	if c._current_task != nil {
		if c._current_task is
		c._TASK_QUEUED{
			c.returncode = new(int)
			*c.returncode = 1
			c._current_task = nil
			c._async_wait()
		} else {
			c._current_task.cancel()
		}
	} else if c.returncode == nil {
		c._was_cancelled()
		c._async_wait()
	}
}

func(c*CompositeTask) _poll() {
	prev = nil
	for true {
		task = c._current_task
		if task == nil ||
		task
		is
		c._TASK_QUEUED
		||
		task
		is
		prev{
			break
		}
		task.poll()
		prev = task
	}
	return c.returncode
}

func(c*CompositeTask) _assert_current(task) {
	if task != c._current_task {
		raise
		AssertionError("Unrecognized task: %s" % (task, ))
	}
}

func(c*CompositeTask) _default_exit( task) {
	c._assert_current(task)
	if task.returncode != os.EX_OK {
		c.returncode = task.returncode
		c.cancelled = task.cancelled
		c._current_task = nil
		return task.returncode
	}
}
func(c*CompositeTask) _final_exit( task) {
	c._default_exit(task)
	c._current_task = nil
	c.returncode = task.returncode
	return c.returncode
}

func(c*CompositeTask) _default_final_exit( task) {
	c._final_exit(task)
	return c.wait()
}

func(c*CompositeTask) _start_task( task, exit_handler) {
	//try{
	//task.scheduler = c.scheduler
	//except AttributeError{
	//pass
	task.addExitListener(exit_handler)
	c._current_task = task
	task.start()
}

func(c*CompositeTask) _task_queued( task) {
	task.addStartListener(c._task_queued_start_handler)
	c._current_task = c._TASK_QUEUED
}

func(c*CompositeTask) _task_queued_start_handler( task) {
	c._current_task = task
}

func(c*CompositeTask) _task_queued_wait() {
	return c._current_task != c._TASK_QUEUED ||
		c.cancelled || c.returncode != nil
}


type EbuildPhase struct {
	*CompositeTask

	// slot
	actionmap,  phase,  _ebuild_lock string
	settings *Config
	fd_pipes map[int]int

	_features_display []string
	_locked_phases    []string
}

func NewEbuildPhase(actionmap interface{}, background bool, phase string, scheduler *SchedulerInterface, settings *Config) *EbuildPhase {
	e := &EbuildPhase{}
	e._features_display = []string{
		"ccache", "compressdebug", "distcc", "fakeroot",
		"installsources", "keeptemp", "keepwork", "network-sandbox",
		"network-sandbox-proxy", "nostrip", "preserve-libs", "sandbox",
		"selinux", "sesandbox", "splitdebug", "suidctl", "test",
		"userpriv", "usersandbox",
	}
	e._locked_phases = []string{
		"setup", "preinst", "postinst", "prerm", "postrm",
	}

	e.actionmap = actionmap
	e.background = background
	e.phase = phase
	e.scheduler = scheduler
	e.settings = settings

	return e
}

func (e *EbuildPhase) _start() {

	need_builddir := e.phase
	not
	in
	EbuildProcess._phases_without_builddir

	if need_builddir {
		phase_completed_file :=
			filepath.Join(
				e.settings.ValueDict["PORTAGE_BUILDDIR"],
				fmt.Sprintf(".%sed", strings.TrimRight(e.phase,"e")))
		if ! pathExists(phase_completed_file) {

			err := syscall.Unlink(filepath.Join(e.settings.ValueDict["T"],
				"logging", e.phase))
			if err != nil {
				//except OSError{
				//pass
			}
		}
	}

	if e.phase =="nofetch" ||e.phase == "pretend"||e.phase == "setup" {
		use := e.settings.ValueDict["PORTAGE_BUILT_USE"]
		if use == "" {
			use = e.settings.ValueDict["PORTAGE_USE"]
		}

		maint_str := ""
		upstr_str := ""
		metadata_xml_path := filepath.Join(filepath.Dir(e.settings.ValueDict["EBUILD"]), "metadata.xml")
		if MetaDataXML != nil && os.path.isfile(metadata_xml_path) {
			herds_path := filepath.Join(e.settings.ValueDict["PORTDIR"],
				"metadata/herds.xml")
			//try{
			metadata_xml = MetaDataXML(metadata_xml_path, herds_path)
			maint_str = metadata_xml.format_maintainer_string()
			upstr_str = metadata_xml.format_upstream_string()
			//except SyntaxError{
			//maint_str = "<invalid metadata.xml>"
		}

		msg := []string{}
		msg = append(msg, fmt.Sprintf("Package:    %s", e.settings.mycpv))
		if e.settings.ValueDict["PORTAGE_REPO_NAME"] != "" {
			msg = append(msg, fmt.Sprintf("Repository: %s", e.settings.ValueDict["PORTAGE_REPO_NAME"]))
		}
		if maint_str!= "" {
			msg = append(msg, fmt.Sprintf("Maintainer: %s", maint_str))
		}
		if upstr_str!= "" {
			msg = append(msg, fmt.Sprintf("Upstream:   %s", upstr_str))
		}

		msg = append(msg, fmt.Sprintf("USE:        %s", use))
		relevant_features := []string{}
		enabled_features := e.settings.Features.Features
		for _, x := range e._features_display {
			if x := range enabled_features{
				relevant_features = append(relevant_features, x)
			}
		}
		if len(relevant_features) > 0 {
			msg = append(msg, fmt.Sprintf("FEATURES:   %s", strings.Join(relevant_features, " ")))
		}

		e._elog('einfo', msg, background = true)
	}

	if e.phase == "package" {
		if _, ok := e.settings.ValueDict["PORTAGE_BINPKG_TMPFILE"]; !ok{
			e.settings.ValueDict["PORTAGE_BINPKG_TMPFILE"] =
			filepath.Join(e.settings.ValueDict["PKGDIR"],
			e.settings.ValueDict["CATEGORY"], e.settings.ValueDict["PF"]) + ".tbz2"
		}
	}

	if e.phase  == "pretend" || e.phase ==  "prerm" {
		env_extractor = BinpkgEnvExtractor(background = e.background,
			scheduler = e.scheduler, settings=e.settings)
		if env_extractor.saved_env_exists() {
			e._start_task(env_extractor, e._env_extractor_exit)
			return
		}
	}

	e._start_lock()
}

func (e *EbuildPhase) _env_extractor_exit( env_extractor) {
	if e._default_exit(env_extractor) != os.EX_OK {
		e.wait()
		return
	}
	e._start_lock()
}

func (e *EbuildPhase) _start_lock() {
	if Ins(e._locked_phases, e.phase) &&
	e.settings.Features.Features["ebuild-locks"]{
		eroot := e.settings.ValueDict["EROOT"]
		lock_path := filepath.Join(eroot, VdbPath+"-ebuild")
		if os.access(filepath.Dir(lock_path), os.W_OK) {
			e._ebuild_lock = AsynchronousLock(path = lock_path,
				scheduler = e.scheduler)
			e._start_task(e._ebuild_lock, e._lock_exit)
			return
		}
	}

	e._start_ebuild()
}

func (e *EbuildPhase) _lock_exit( ebuild_lock) {
	if e._default_exit(ebuild_lock) != os.EX_OK {
		e.wait()
		return
	}
	e._start_ebuild()
}

func (e *EbuildPhase) _get_log_path() string {
	logfile := ""
	if e.phase != "clean" && e.phase != "cleanrm" &&
		e.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
		logfile = e.settings.ValueDict["PORTAGE_LOG_FILE"]
	}
	return logfile
}

func (e *EbuildPhase) _start_ebuild() {
	if e.phase == "package" {
		e._start_task(PackagePhase(actionmap = e.actionmap,
			background = e.background, fd_pipes = e.fd_pipes,
			logfile=e._get_log_path(), scheduler = e.scheduler,
			settings=e.settings), e._ebuild_exit)
		return
	}

	if e.phase == "unpack" {
		alist := strings.Fields(e.settings.configDict["pkg"]["A"])
		_prepare_fake_distdir(e.settings, alist)
		_prepare_fake_filesdir(e.settings)
	}

	fd_pipes := e.fd_pipes
	if fd_pipes == nil {
		if !e.background && e.phase == "nofetch" {
			fd_pipes = map[int]int{
				1: syscall.Stderr,
			}
		}
	}

	ebuild_process = EbuildProcess(actionmap = e.actionmap,
		background = e.background, fd_pipes=fd_pipes,
		logfile = e._get_log_path(), phase=e.phase,
		scheduler = e.scheduler, settings=e.settings)

	e._start_task(ebuild_process, e._ebuild_exit)
}

func (e *EbuildPhase) _ebuild_exit( ebuild_process) {
	e._assert_current(ebuild_process)
	if e._ebuild_lock == nil {
		e._ebuild_exit_unlocked(ebuild_process)
	} else {
		e._start_task(
			AsyncTaskFuture(future = e._ebuild_lock.async_unlock()),
		functools.partial(e._ebuild_exit_unlocked, ebuild_process))
	}
}

func (e *EbuildPhase) _ebuild_exit_unlocked( ebuild_process, unlock_task=nil) {
	if unlock_task != nil {
		e._assert_current(unlock_task)
		if unlock_task.cancelled {
			e._default_final_exit(unlock_task)
			return
		}
		unlock_task.future.result()
	}

	fail := false
	if ebuild_process.returncode != os.EX_OK {
		e.returncode = ebuild_process.returncode
		if e.phase == "test" && e.settings.Features.Features["test-fail-continue"] {
			f, err := os.OpenFile(filepath.Join(
				e.settings.ValueDict["PORTAGE_BUILDDIR"], ".tested"), os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				//except OSError{
				//pass
			}
			f.Close()
		}else{
			fail = true
		}
	}

	if ! fail {
		e.returncode = nil
	}

	logfile := e._get_log_path()

	if e.phase == "install" {
		out = io.StringIO()
		_check_build_log(e.settings, out = out)
		msg = out.getvalue()
		e.scheduler.output(msg, log_path = logfile)
	}

	if fail {
		e._die_hooks()
		return
	}

	settings := e.settings
	_post_phase_userpriv_perms(settings)

	if e.phase == "unpack" {
		syscall.Utime(settings.ValueDict["WORKDIR"], nil)
		_prepare_workdir(settings)
	} else if e.phase == "install" {
		out = io.StringIO()
		_post_src_install_write_metadata(settings)
		_post_src_install_uid_fix(settings, out)
		msg = out.getvalue()
		if len(msg) > 0 {
			e.scheduler.output(msg, log_path = logfile)
		}
	} else if e.phase == "preinst" {
		_preinst_bsdflags(settings)
	} else if e.phase == "postinst" {
		_postinst_bsdflags(settings)
	}

	post_phase_cmds := _post_phase_cmds.get(e.phase)
	if post_phase_cmds != nil {
		if logfile != nil && e.phase =="install" {
			fd, logfile = tempfile.mkstemp()
			os.close(fd)
		}
		post_phase = _PostPhaseCommands(background = e.background,
			commands = post_phase_cmds, elog=e._elog, fd_pipes = e.fd_pipes,
			logfile=logfile, phase = e.phase, scheduler=e.scheduler,
			settings = settings)
		e._start_task(post_phase, e._post_phase_exit)
		return
	}

	e.returncode = new(int)
	*e.returncode = 0
	e._current_task = nil
	e.wait()
}

func (e *EbuildPhase) _post_phase_exit( post_phase) {

	e._assert_current(post_phase)

	log_path := ""
	if e.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
		log_path = e.settings.ValueDict["PORTAGE_LOG_FILE"]
	}

	if post_phase.logfile != nil &&
		post_phase.logfile != log_path {
		e._append_temp_log(post_phase.logfile, log_path)
	}

	if e._final_exit(post_phase) != os.EX_OK {
		WriteMsg(fmt.Sprintf("!!! post %s failed; exiting.\n", e.phase),
			-1, nil)
		e._die_hooks()
		return
	}

	e._current_task = nil
	e.wait()
	return
}

func (e *EbuildPhase) _append_temp_log( temp_log, log_path) {

	temp_file = open(_unicode_encode(temp_log,
		encoding = _encodings['fs'], errors = 'strict'), 'rb')

	log_file, log_file_real = e._open_log(log_path)

	for line
	in
	temp_file{
		log_file.write(line)
	}

	temp_file.close()
	log_file.close()
	if log_file_real != log_file {
		log_file_real.close()
	}
	syscall.Unlink(temp_log)
}

func (e *EbuildPhase) _open_log( log_path) {

	f = open(_unicode_encode(log_path,
		encoding = _encodings['fs'], errors = 'strict'),
	mode = 'ab')
	f_real = f

	if log_path.endswith('.gz') {
		f = gzip.GzipFile(filename = '', mode = 'ab', fileobj=f)
	}

	return (f, f_real)
}

func (e *EbuildPhase) _die_hooks() {
	e.returncode = nil
	phase := "die_hooks"
	die_hooks := MiscFunctionsProcess(background = e.background,
		commands = [phase], phase = phase, logfile = e._get_log_path(),
		fd_pipes=e.fd_pipes, scheduler = e.scheduler,
		settings=e.settings)
	e._start_task(die_hooks, e._die_hooks_exit)
}

func (e *EbuildPhase) _die_hooks_exit( die_hooks) {
	if e.phase != "clean" &&
		!e.settings.Features.Features["noclean"] &&
		e.settings.Features.Features["fail-clean"] {
		e._default_exit(die_hooks)
		e._fail_clean()
		return
	}
	e._final_exit(die_hooks)
	e.returncode = new(int)
	*e.returncode = 1
	e.wait()
}

func (e *EbuildPhase) _fail_clean() {
	e.returncode = nil
	portage.elog.elog_process(e.settings.mycpv, e.settings)
	phase := "clean"
	clean_phase := EbuildPhase(background = e.background,
		fd_pipes = e.fd_pipes, phase=phase, scheduler = e.scheduler,
		settings=e.settings)
	e._start_task(clean_phase, e._fail_clean_exit)
	return
}

func (e *EbuildPhase) _fail_clean_exit( clean_phase) {
	e._final_exit(clean_phase)
	e.returncode = new(int)
	*e.returncode = 1
	e.wait()
}

func (e *EbuildPhase) _elog( elog_funcname, lines, background=nil){
if background == nil {
	background = e.background
}
out = io.StringIO()
phase = e.phase
elog_func = getattr(elog_messages, elog_funcname)
global_havecolor = portage.output.havecolor
//try{
portage.output.havecolor =
e.settings.ValueDict['NOCOLOR', 'false').lower() in ('no', 'false')
for line in lines{
	elog_func(line, phase = phase, key =e.settings.mycpv, out = out)
	}
//finally{
portage.output.havecolor = global_havecolor
msg = out.getvalue()
if msg {
	log_path = nil
	if e.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
		log_path = e.settings.ValueDict["PORTAGE_LOG_FILE"]
	}
	e.scheduler.output(msg, log_path = log_path,
		background = background)
}
}


type _PostPhaseCommands struct {
	*CompositeTask

	// slots
	commands, elog, fd_pipes, logfile, phase  string
	settings *Config
}

func(p*_PostPhaseCommands) _start(){
if isinstance(p.commands, list){
cmds = [({}, p.commands)]
}else{
cmds = list(p.commands)
}

if ! p.settings.Features.Features["selinux"]{
cmds = [(kwargs, commands) for kwargs, commands in
cmds if not kwargs.get('selinux_only'
})]
}

tasks = TaskSequence()
for kwargs, commands in cmds{

kwargs = dict((k, v) for k, v in kwargs.items()
if k in ('ld_preload_sandbox', ))
tasks.add(MiscFunctionsProcess(background = p.background,
commands = commands, fd_pipes = p.fd_pipes,
logfile = p.logfile, phase = p.phase,
scheduler = p.scheduler, settings= p.settings, **kwargs))

p._start_task(tasks, p._commands_exit)
}
}

func(p*_PostPhaseCommands) _commands_exit( task) {

	if p._default_exit(task) != os.EX_OK {
		p._async_wait()
		return
	}

	if p.phase == "install" {
		out := bytes.Buffer{}
		_post_src_install_soname_symlinks(p.settings, out)
		msg := out.String()
		if len(msg) > 0 {
			p.scheduler.output(msg, log_path = p.settings.ValueDict["PORTAGE_LOG_FILE"])
		}

		if p.settings.Features.Features["qa-unresolved-soname-deps"] {

			future = p._soname_deps_qa()

			future.add_done_callback(func(future) {
				return future.cancelled() || future.result()
			})
			p._start_task(AsyncTaskFuture(future = future), p._default_final_exit)
		} else {
			p._default_final_exit(task)
		}
	} else {
		p._default_final_exit(task)
	}
}

@coroutine
func(p*_PostPhaseCommands) _soname_deps_qa() {

	vardb := QueryCommand.get_db()[p.settings.ValueDict["EROOT"]]["vartree"].dbapi

	all_provides = (yield
	p.scheduler.run_in_executor(ForkExecutor(loop = p.scheduler), _get_all_provides, vardb))

	unresolved := _get_unresolved_soname_deps(filepath.Join(p.settings.ValueDict["PORTAGE_BUILDDIR"], "build-info"), all_provides)

	if len(unresolved) > 0 {
		unresolved.sort()
		qa_msg := []string{"QA Notice: Unresolved soname dependencies:"}
		qa_msg = append(qa_msg, "")
		qa_msg =append(qa_msg, fmt.Sprintf("\t%s: %s", filename, strings.Join(sorted(soname_deps)), " "))
		for filename, soname_deps
			in
		unresolved)
		qa_msg= append(qa_msg, "")
		p.elog("eqawarn", qa_msg)
	}
}

type RootConfig struct {
	// slot
	Mtimedb   *MtimeDB
	root      string
	settings  *Config
	trees     *Tree
	setconfig *SetConfig
	sets      map[string]string

	pkg_tree_map, tree_pkg_map map[string]string
}

func NewRootConfig(settings *Config, trees *Tree, setconfig *SetConfig)*RootConfig {
	r := &RootConfig{}
	r.pkg_tree_map = map[string]string{
		"ebuild":    "porttree",
		"binary":    "bintree",
		"installed": "vartree",
	}
	r.tree_pkg_map = map[string]string{
		"porttree": "ebuild",
		"bintree":  "binary",
		"vartree":  "installed",
	}
	r.trees = trees
	r.settings = settings
	r.root = r.settings.ValueDict["EROOT"]
	r.setconfig = setconfig
	if setconfig == nil {
		r.sets = map[string]string{}
	} else {
		r.sets = r.setconfig.getSets()
	}
	return r
}

func (r*RootConfig) Update(other *RootConfig) {
	r.Mtimedb = other.Mtimedb
	r.root=other.root
	r.settings=other.settings
	r.trees=other.trees
	r.setconfig=other.setconfig
	r.sets=other.sets
}

type PollScheduler struct {
	_scheduling, _terminated_tasks, _background bool
	_term_rlock                                 sync.Mutex
	_max_jobs                                   int
	_max_load float64
}

_loadavg_latency = None


func(p*PollScheduler) _is_background() bool{
	return p._background
}

func(p*PollScheduler)  _cleanup() {
	p._term_rlock.Lock()
	if p._term_check_handle not
	in(None, false)
	{
		p._term_check_handle.cancel()
		p._term_check_handle = false
	}
	p._term_rlock.Unlock()
}

func(p*PollScheduler)  terminate() {
	p._term_rlock.Lock()
	if p._term_check_handle ==nil {
		p._terminated.set()
		p._term_check_handle = p._event_loop.call_soon_threadsafe(
			p._termination_check, true)
	}
	p._term_rlock.Unlock()
}

// false
func(p*PollScheduler)  _termination_check( retry bool) {
	if p._terminated.is_set() &&!p._terminated_tasks{
		if ! p._scheduling {
			p._scheduling = true
		//try:
			p._terminated_tasks = true
			p._terminate_tasks()
		//finally:
			p._scheduling = false
		}else if retry {
			p._term_rlock.Lock()
			p._term_check_handle = p._event_loop.call_soon(
				p._termination_check, true)
			p._term_rlock.Unlock()
		}
	}
}

func(p*PollScheduler)  _terminate_tasks() {
	//raise NotImplementedError()
}

func(p*PollScheduler)  _keep_scheduling() bool{
	return false
}

func(p*PollScheduler)  _schedule_tasks() {
	//pass
}

func(p*PollScheduler)  _schedule() bool {
	if p._scheduling {
		return true
	}
	p._scheduling = true
	p._schedule_tasks()
	p._scheduling = false
	return true
}

func(p*PollScheduler)  _is_work_scheduled() bool {
	return p._running_job_count()==0
}

func(p*PollScheduler)  _running_job_count() int {
	//raise NotImplementedError(p)
	return 0
}

func(p*PollScheduler)  _can_add_job() bool{
	if p._terminated_tasks {
		return false
	}

	max_jobs := p._max_jobs
	max_load := p._max_load

	if p._max_jobs == 0 &&p._running_job_count() >= p._max_jobs{
		return false
	}

	if max_load !=0 &&
	(max_jobs != 0 || max_jobs > 1) &&
	p._running_job_count() >= 1 {
	try:
		avg1, avg5, avg15 = getloadavg()
		except
	OSError:
		return false

		if avg1 >= max_load {
			return false
		}
	}

	return true
}

// false, nil
func NewPollScheduler( main bool, event_loop=None)*PollScheduler {
	p := &PollScheduler{}
	p._term_rlock = sync.Mutex{}
	p._terminated = threading.Event()
	p._terminated_tasks = false
	p._term_check_handle = None
	p._max_jobs = 1
	p._max_load = None
	p._scheduling = false
	p._background = false
	if event_loop != nil {
		p._event_loop = event_loop
	}else if main {
		p._event_loop = global_event_loop()
	}else {
		p._event_loop = asyncio._safe_loop()
	}
	p._sched_iface = SchedulerInterface(p._event_loop,
		is_background = p._is_background)
	return p
}


type  Scheduler struct {
	*PollScheduler
	_loadavg_latency, _max_display_latency                           int
	_opts_ignore_blockers, _opts_no_background, _opts_no_self_update map[string]bool

	settings    *Config
	target_root string
	trees       interface{}
	myopts      interface{}
	_spinner    interface{}
	_mtimedb    int
	_favorites  interface{}
	_args_set   interface{}
	_build_opts interface{}
}

type  _iface_class struct {
	*SchedulerInterface
	// slot
	fetch, scheduleSetup,scheduleUnpack string
}

type  _fetch_iface_class struct {
	// slot
	log_file,schedule string
}(SlotObject):

_task_queues_class = slot_dict_class(
("merge", "jobs", "ebuild_locks", "fetch", "unpack"), prefix="")

type  _build_opts_class struct {
	// slot
	buildpkg,buildpkg_exclude,buildpkgonly,
	fetch_all_uri,fetchonly,pretend string
}(SlotObject):

type  _binpkg_opts_class struct {
	// slot
	fetchonly,getbinpkg,pretend string
}(SlotObject):

type  _pkg_count_class struct {
	// slot
	curval, maxval string
}(SlotObject):

type  _emerge_log_class struct {
	// slot
	xterm_titles string
}(SlotObject):

func (e *_emerge_log_class) log( *pargs, **kwargs) {
	if not e.xterm_titles:
	kwargs.pop("short_msg", None)
	emergelog(self.xterm_titles, *pargs, **kwargs)
}

type  _failed_pkg struct {
	// slot
	build_dir,build_log,pkg, postinst_failure,returncode string
}(SlotObject):

type  _ConfigPool struct {
	// slot
	_root,_allocate,_deallocate string
}

func NewConfigPool(root, allocate, deallocate) *_ConfigPool {
	c := &_ConfigPool{}
	c._root = root
	c._allocate = allocate
	c._deallocate = deallocate
	return c
}
func allocate(self):
return self._allocate(self._root)
func deallocate(self, settings):
self._deallocate(settings)

type  _unknown_internal_error(portage.exception.PortageException):
func New_unknown_internal_error(value="") *_unknown_internal_error{
	u := &_unknown_internal_error{}
	portage.exception.PortageException.__init__(self, value)
	return u
}

// nil, nil, nil
func NewScheduler(settings *Config, trees, mtimedb, myopts,
spinner, mergelist, favorites, graph_config)*Scheduler {
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

	s.PollScheduler = NewPollScheduler(main, )

	if mergelist != nil {
		warnings.warn("The mergelist parameter of the " + 
		"_emerge.Scheduler constructor is now unused. Use " + 
		"the graph_config parameter instead.",
			DeprecationWarning, stacklevel = 2)
	}

	s.settings = settings
	s.target_root = settings.ValueDict["EROOT"]
	s.trees = trees
	s.myopts = myopts
	s._spinner = spinner
	s._mtimedb = mtimedb
	s._favorites = favorites
	s._args_set = InternalPackageSet(favorites, allow_repo = true)
	s._build_opts = s._build_opts_class()

	for k
	in
	s._build_opts.__slots__:
	setattr(s._build_opts, k, myopts.get("--"+k.replace("_", "-")))
	s._build_opts.buildpkg_exclude = InternalPackageSet( 
	initial_atoms = " ".join(myopts.get("--buildpkg-exclude", [])).split(), 
	allow_wildcard = true, allow_repo=true)
	if "mirror" in
	s.settings.features:
	s._build_opts.fetch_all_uri = true

	s._binpkg_opts = s._binpkg_opts_class()
	for k
	in
	s._binpkg_opts.__slots__:
	setattr(s._binpkg_opts, k, "--"+k.replace("_", "-")
	in
	myopts)

	s.curval = 0
	s._logger = s._emerge_log_class()
	s._task_queues = s._task_queues_class()
	for k
	in
	s._task_queues.allowed_keys:
	setattr(s._task_queues, k,
		SequentialTaskQueue())

	s._merge_wait_queue = deque()
	s._merge_wait_scheduled = []

	s._deep_system_deps = map[string]string{}

	s._unsatisfied_system_deps = map[string]string{}

	s._status_display = JobStatusDisplay(
		xterm_titles = (!settings.Features.Features["notitles"]))
	s._max_load = myopts.get("--load-average")
	max_jobs = myopts.get("--jobs")
	if max_jobs is
None:
	max_jobs = 1
	s._set_max_jobs(max_jobs)
	s._running_root = trees[trees._running_eroot]["root_config"]
	s.edebug = 0
	if  settings.ValueDict["PORTAGE_DEBUG"] == "1":
	s.edebug = 1
	s.pkgsettings =
	{
	}
	s._config_pool =
	{
	}
	for root
	in
	s.trees:
	s._config_pool[root] = []

	s._fetch_log =  filepath.Join(_emerge.emergelog._emerge_log_dir,
		'emerge-fetch.log')
	fetch_iface = s._fetch_iface_class(log_file = s._fetch_log,
		schedule = s._schedule_fetch)
	s._sched_iface = s._iface_class(
		s._event_loop,
		is_background = s._is_background,
		fetch = fetch_iface,
		scheduleSetup=s._schedule_setup,
		scheduleUnpack = s._schedule_unpack)

	s._prefetchers = weakref.WeakValueDictionary()
	s._pkg_queue = []
	s._jobs = 0
	s._running_tasks =
	{
	}
	s._completed_tasks = map[string]string{}
	s._main_exit = None
	s._main_loadavg_handle = None
	s._schedule_merge_wakeup_task = None

	s._failed_pkgs = []
	s._failed_pkgs_all = []
	s._failed_pkgs_die_msgs = []
	s._post_mod_echo_msgs = []
	s._parallel_fetch = false
	s._init_graph(graph_config)
	merge_count = len([x
	for x
	in
	s._mergelist 
	if isinstance(x, Package) &&
	x.operation == "merge"])
s._pkg_count = s._pkg_count_class(
curval = 0, maxval = merge_count)
s._status_display.maxval = s._pkg_count.maxval

s._job_delay_max = 5
s._previous_job_start_time = None
s._job_delay_timeout_id = None

s._sigcont_delay = 5
s._sigcont_time = None

s._choose_pkg_return_early = false

features = s.settings.features
if "parallel-fetch" in features && 
not ("--pretend" in s.myopts || 
"--fetch-all-uri" in s.myopts || 
"--fetchonly" in s.myopts):
if "distlocks" not in features:
WriteMsg(red("!!!")+"\n", noiselevel = -1)
WriteMsg(red("!!!")+" parallel-fetching " + 
"requires the distlocks feature enabled"+"\n",
noiselevel = -1)
WriteMsg(red("!!!")+" you have it disabled, " + 
"thus parallel-fetching is being disabled"+"\n",
noiselevel = -1)
WriteMsg(red("!!!")+"\n", noiselevel = -1)
else if merge_count > 1:
s._parallel_fetch = true

if s._parallel_fetch:
try:
open(s._fetch_log, 'w').close()
except EnvironmentError:
pass

s._running_portage = None
portage_match = s._running_root.trees["vartree"].dbapi.match(
portage.const.PORTAGE_PACKAGE_ATOM)
if portage_match:
cpv = portage_match.pop()
s._running_portage = s._pkg(cpv, "installed",
s._running_root, installed = true)
return s
}

func (s *Scheduler) _handle_self_update() {

	if s._opts_no_s_update.intersection(s.myopts):
	return os.EX_OK

	for x
	in
	s._mergelist:
	if not isinstance(x, Package):
	continue
	if x.operation != "merge":
	continue
	if x.root != s._running_root.root:
	continue
	if not portage.dep.match_from_list(
		portage.
	const.PORTAGE_PACKAGE_ATOM, [x]):
	continue
	rval = _check_temp_dir(s.settings)
	if rval != os.EX_OK:
	return rval
	_prepare_s_update(s.settings)
	break

	return os.EX_OK
}

func (s*Scheduler)_terminate_tasks() {
	s._status_display.quiet = true
	for task
	in
	list(s._running_tasks.values()):
	if task.isAlive():
	task.cancel()
	else:
	del
	s._running_tasks[id(task)]

	for q
	in
	s._task_queues.values():
	q.clear()
}

func (s*Scheduler) _init_graph( graph_config) {
	s._set_graph_config(graph_config)
	s._blocker_db =
	{
	}
	depgraph_params = create_depgraph_params(s.myopts, None)
	dynamic_deps = "dynamic_deps"
	in
	depgraph_params
	ignore_built_slot_operator_deps = s.myopts.get(
		"--ignore-built-slot-operator-deps", "n") == "y"
	for root
	in
	s.trees:
	if graph_config is
None:
	fake_vartree = FakeVartree(s.trees[root]["root_config"],
		pkg_cache = s._pkg_cache, dynamic_deps = dynamic_deps,
		ignore_built_slot_operator_deps=ignore_built_slot_operator_deps)
	fake_vartree.sync()
	else:
	fake_vartree = graph_config.trees[root]['vartree']
	s._blocker_db[root] = BlockerDB(fake_vartree)
}

func (s *Scheduler) _destroy_graph() {
	s._blocker_db = None
	s._set_graph_config(None)
	gc.collect()
}

func (s *Scheduler) _set_max_jobs( max_jobs int) {
	s._max_jobs = max_jobs
	s._task_queues.jobs.max_jobs = max_jobs
	if s.settings.Features.Features["parallel-install"] {
		s._task_queues.merge.max_jobs = max_jobs
	}
}

func (s*Scheduler) _background_mode() {
	background = (s._max_jobs
	is
	true
	|| 
	s._max_jobs > 1
 ||
	"--quiet"
	in
	s.myopts 
 ||
	s.myopts.get("--quiet-build") == "y") && 
	not
	bool(s._opts_no_background.intersection(s.myopts))

	if background:
	interactive_tasks = s._get_interactive_tasks()
	if interactive_tasks:
	background = false
	WriteMsgLevel(">>> Sending package output to stdio due " + 
	"to interactive package(s):\n",
		level = logging.INFO, noiselevel=-1)
	msg = [""]
	for pkg
	in
interactive_tasks:
	pkg_str = "  " + colorize("INFORM", str(pkg.cpv))
	if pkg.root_config.settings.ValueDict["ROOT"] != "/":
	pkg_str += " for " + pkg.root
	msg.append(pkg_str)
	msg.append("")
	WriteMsgLevel("".join("%s\n" % (l, )
	for l
	in
	msg),
	level = logging.INFO, noiselevel=-1)
	if s._max_jobs is
	true
 ||
	s._max_jobs > 1:
	s._set_max_jobs(1)
	WriteMsgLevel(">>> Setting --jobs=1 due " + 
	"to the above interactive package(s)\n",
		level = logging.INFO, noiselevel=-1)
	WriteMsgLevel(">>> In order to temporarily mask " + 
	"interactive updates, you may\n" + 
	">>> specify --accept-properties=-interactive\n",
		level = logging.INFO, noiselevel=-1)
	s._status_display.quiet = 
	not
	background
	|| 
	("--quiet"
	in
	s.myopts
	&& 
	"--verbose"
	not
	in
	s.myopts)

	s._logger.xterm_titles = 
	"notitles"
	not
	in
	s.settings.features
	&& 
	s._status_display.quiet

	return background
}

func (s *Scheduler) _get_interactive_tasks() {
	interactive_tasks = []
	for task
	in
	s._mergelist:
	if not(isinstance(task, Package) && 
	task.operation == "merge"):
	continue
	if 'interactive' in
	task.properties:
	interactive_tasks.append(task)
	return interactive_tasks
}

func _set_graph_config( graph_config) {

	if graph_config == nil {
		s._graph_config = None
		s._pkg_cache =
		{
		}
		s._digraph = None
		s._mergelist = []
		s._world_atoms = None
		s._deep_system_deps.clear()
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
	if getattr(pkg, 'operation', None) != 'merge':
	continue
	atom = create_world_atom(pkg, s._args_set,
		pkg.root_config, before_install = true)
	if atom is
	not
None:
	s._world_atoms[pkg] = atom

	if "--nodeps" in
	s.myopts
	|| 
	(s._max_jobs
	is
	not
	true
	&&
	s._max_jobs < 2):
	s._digraph = None
	graph_config.graph = None
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
	writemsg("\nscheduler digraph:\n\n", noiselevel = -1)
	s._digraph.debug_print()
	writemsg("\n", noiselevel = -1)
}

func (s *Scheduler) _find_system_deps() {
	params = create_depgraph_params(s.myopts, None)
	if not params["implicit_system_deps"]:
	return

	deep_system_deps = s._deep_system_deps
	deep_system_deps.clear()
	deep_system_deps.update(
		_find_deep_system_runtime_deps(s._digraph))
	deep_system_deps.difference_update([pkg
	for pkg
	in 
	deep_system_deps
	if pkg.operation != "merge"])
}

func (s *Scheduler) _prune_digraph() {

	graph := s._digraph
	completed_tasks := s._completed_tasks
	removed_nodes := map[string]bool{}
	for {
		for node in graph.root_nodes(){
			if not isinstance(node, Package) ||(node.installed && node.operation == "nomerge") ||
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
	cpv_map =
	{
	}
	for pkg
	in
	s._mergelist:
	if not isinstance(pkg, Package):
	continue
	if pkg.installed:
	continue
	if pkg.cpv not
	in
cpv_map:
	cpv_map[pkg.cpv] = [pkg]
	continue
	for earlier_pkg
	in
	cpv_map[pkg.cpv]:
	s._digraph.add(earlier_pkg, pkg,
		priority = DepPriority(buildtime = true))
	cpv_map[pkg.cpv].append(pkg)
}

type  _pkg_failure struct {
	PortageException
	status int
}
func New_pkg_failure(status *int, pargs) *_pkg_failure{
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
	if s._opts_ignore_blockers.intersection(s.myopts):
	return None

	blocker_db = s._blocker_db[new_pkg.root]

	blocked_pkgs = []
	for blocking_pkg
	in
	blocker_db.findInstalledBlockers(new_pkg):
	if new_pkg.slot_atom == blocking_pkg.slot_atom:
	continue
	if new_pkg.cpv == blocking_pkg.cpv:
	continue
	blocked_pkgs.append(blocking_pkg)

	return blocked_pkgs
}

func (s *Scheduler) _generate_digests() {

	digest = '--digest'
	in
	s.myopts
	if not digest:
	for pkgsettings
	in
	s.pkgsettings.values():
	if pkgsettings.mycpv is
	not
None:
	pkgsettings.reset()
	if 'digest' in
	pkgsettings.features:
	digest = true
	break

	if not digest:
	return os.EX_OK

	for x
	in
	s._mergelist:
	if not isinstance(x, Package)
	|| 
	x.type_name != 'ebuild'
	|| 
	x.operation != 'merge':
	continue
	pkgsettings = s.pkgsettings.ValueDict[x.root]
	if pkgsettings.mycpv is
	not
None:
	pkgsettings.reset()
	if '--digest' not
	in
	s.myopts
	&& 
	'digest'
	not
	in
	pkgsettings.features:
	continue
	portdb = x.root_config.trees['porttree'].dbapi
	ebuild_path = portdb.findname(x.cpv, myrepo = x.repo)
	if ebuild_path is
None:
	raise
	AssertionError("ebuild not found for '%s'" % x.cpv)
	pkgsettings.ValueDict['O'] =  filepath.Dir(ebuild_path)
	if not digestgen(mysettings = pkgsettings, myportdb = portdb):
	WriteMsgLevel(
		"!!! Unable to generate manifest for '%s'.\n" 
	% x.cpv, level = logging.ERROR, noiselevel=-1)
	return FAILURE

	return os.EX_OK
}

func (s *Scheduler) _check_manifests() {
	if "strict" not
	in
	s.settings.features
	|| 
	"--fetchonly"
	in
	s.myopts
	|| 
	"--fetch-all-uri"
	in
	s.myopts:
	return os.EX_OK

	shown_verifying_msg = false
	quiet_settings =
	{
	}
	for myroot, pkgsettings
	in
	s.pkgsettings.items():
	quiet_config = portage.config(clone = pkgsettings)
	quiet_config["PORTAGE_QUIET"] = "1"
	quiet_config.backup_changes("PORTAGE_QUIET")
	quiet_settings.ValueDict[myroot] = quiet_config
	del
	quiet_config

	failures = 0

	for x
	in
	s._mergelist:
	if not isinstance(x, Package)
	|| 
	x.type_name != "ebuild":
	continue

	if x.operation == "uninstall":
	continue

	if not shown_verifying_msg:
	shown_verifying_msg = true
	s._status_msg("Verifying ebuild manifests")

	root_config = x.root_config
	portdb = root_config.trees["porttree"].dbapi
	quiet_config = quiet_settings.ValueDict[root_config.root]
	ebuild_path = portdb.findname(x.cpv, myrepo = x.repo)
	if ebuild_path is
None:
	raise
	AssertionError("ebuild not found for '%s'" % x.cpv)
	quiet_config["O"] =  filepath.Dir(ebuild_path)
	if not digestcheck([], quiet_config, strict = true):
	failures |= 1

	if failures:
	return FAILURE
	return os.EX_OK
}

func (s *Scheduler) _add_prefetchers() {

	if not s._parallel_fetch:
	return

	if s._parallel_fetch:

	prefetchers = s._prefetchers

	for pkg
	in
	s._mergelist:
	if not isinstance(pkg, Package)
 ||
	pkg.operation == "uninstall":
	continue
	prefetcher = s._create_prefetcher(pkg)
	if prefetcher is
	not
None:
	prefetchers[pkg] = prefetcher
	s._task_queues.fetch.add(prefetcher)
}

func (s *Scheduler) _create_prefetcher( pkg) {
	prefetcher = None

	if not isinstance(pkg, Package):
	pass

	else if
	pkg.type_name == "ebuild":

	prefetcher = EbuildFetcher(background = true,
		config_pool = s._ConfigPool(pkg.root,
		s._allocate_config, s._deallocate_config),
		fetchonly=1, fetchall = s._build_opts.fetch_all_uri,
		logfile=s._fetch_log,
		pkg = pkg, prefetch=true, scheduler = s._sched_iface)

	else if
	pkg.type_name == "binary"
	&& 
	"--getbinpkg"
	in
	s.myopts
	&& 
	pkg.root_config.trees["bintree"].isremote(pkg.cpv):

	prefetcher = BinpkgPrefetcher(background = true,
		pkg = pkg, scheduler=s._sched_iface)

	return prefetcher
}

func (s *Scheduler) _run_pkg_pretend() {

	failures = 0
	sched_iface = s._sched_iface

	for x
	in
	s._mergelist:
	if not isinstance(x, Package):
	continue

	if x.operation == "uninstall":
	continue

	if x.eapi in("0", "1", "2", "3"):
	continue

	if "pretend" not
	in
	x.defined_phases:
	continue

	out_str = ">>> Running pre-merge checks for " + colorize("INFORM", x.cpv) + "\n"
	portage.util.writemsg_stdout(out_str, noiselevel = -1)

	root_config = x.root_config
	settings = s.pkgsettings.ValueDict[root_config.root]
	settings.setcpv(x)

	rval = _check_temp_dir(settings)
	if rval != os.EX_OK:
	return rval

	build_dir_path =  filepath.Join(
		os.path.realpath(settings.ValueDict["PORTAGE_TMPDIR"]),
		"portage", x.category, x.pf)
	existing_builddir = pathIsDir(build_dir_path)
	settings.ValueDict["PORTAGE_BUILDDIR"] = build_dir_path
	build_dir = EbuildBuildDir(scheduler = sched_iface,
		settings = settings)
	sched_iface.run_until_complete(build_dir.async_lock())
	current_task = None

try:

	if existing_builddir:
	if x.built:
	tree = "bintree"
	infloc =  filepath.Join(build_dir_path, "build-info")
	ebuild_path =  filepath.Join(infloc, x.pf+".ebuild")
	else:
	tree = "porttree"
	portdb = root_config.trees["porttree"].dbapi
	ebuild_path = portdb.findname(x.cpv, myrepo = x.repo)
	if ebuild_path is
None:
	raise
	AssertionError(
		"ebuild not found for '%s'" % x.cpv)
	portage.package.
	ebuild.doebuild.doebuild_environment(
		ebuild_path, "clean", settings = settings,
		db = s.trees[settings.ValueDict['EROOT']][tree].dbapi)
	clean_phase = EbuildPhase(background = false,
		phase = 'clean', scheduler=sched_iface, settings = settings)
	current_task = clean_phase
	clean_phase.start()
	clean_phase.wait()

	if x.built:
	tree = "bintree"
	bintree = root_config.trees["bintree"].dbapi.bintree
	fetched = false

	if bintree.isremote(x.cpv):
	fetcher = BinpkgFetcher(pkg = x,
		scheduler = sched_iface)
	fetcher.start()
	if fetcher.wait() != os.EX_OK:
	failures += 1
	continue
	fetched = fetcher.pkg_path

	if fetched is
false:
	filename = bintree.getname(x.cpv)
	else:
	filename = fetched
	verifier = BinpkgVerifier(pkg = x,
		scheduler = sched_iface, _pkg_path=filename)
	current_task = verifier
	verifier.start()
	if verifier.wait() != os.EX_OK:
	failures += 1
	continue

	if fetched:
	bintree.inject(x.cpv, filename = fetched)

	infloc =  filepath.Join(build_dir_path, "build-info")
	ensure_dirs(infloc)
	s._sched_iface.run_until_complete(
		bintree.dbapi.unpack_metadata(settings, infloc))
	ebuild_path =  filepath.Join(infloc, x.pf+".ebuild")
	settings.configdict["pkg"]["EMERGE_FROM"] = "binary"
	settings.configdict["pkg"]["MERGE_TYPE"] = "binary"

	else:
	tree = "porttree"
	portdb = root_config.trees["porttree"].dbapi
	ebuild_path = portdb.findname(x.cpv, myrepo = x.repo)
	if ebuild_path is
None:
	raise
	AssertionError("ebuild not found for '%s'" % x.cpv)
	settings.configdict["pkg"]["EMERGE_FROM"] = "ebuild"
	if s._build_opts.buildpkgonly:
	settings.configdict["pkg"]["MERGE_TYPE"] = "buildonly"
	else:
	settings.configdict["pkg"]["MERGE_TYPE"] = "source"

	doebuild_environment(ebuild_path,
		"pretend", nil, settings, false, nil,
		s.trees[settings.ValueDict['EROOT']][tree].dbapi)

	prepare_build_dirs(root_config.root, settings, cleanup = 0)

	vardb = root_config.trees['vartree'].dbapi
	settings.ValueDict["REPLACING_VERSIONS"] = " ".join(
		set(portage.versions.cpv_getversion(match) 
	for match
	in
	vardb.match(x.slot_atom) + 
	vardb.match('=' + x.cpv)))
	pretend_phase = EbuildPhase(
		phase = "pretend", scheduler = sched_iface,
		settings=settings)

	current_task = pretend_phase
	pretend_phase.start()
	ret = pretend_phase.wait()
	if ret != os.EX_OK:
	failures += 1
	portage.elog.elog_process(x.cpv, settings)
finally:

	if current_task is
	not
None:
	if current_task.isAlive():
	current_task.cancel()
	current_task.wait()
	if current_task.returncode == os.EX_OK:
	clean_phase = EbuildPhase(background = false,
		phase = 'clean', scheduler=sched_iface,
		settings = settings)
	clean_phase.start()
	clean_phase.wait()

	sched_iface.run_until_complete(build_dir.async_unlock())

	if failures:
	return FAILURE
	return os.EX_OK
}

func (s *Scheduler) merge() {
	if "--resume" in
	s.myopts:
	WriteMsgStdout(
		colorize("GOOD", "*** Resuming merge...\n"), -1)
	s._logger.log(" *** Resuming merge...")

	s._save_resume_list()

try:
	s._background = s._background_mode()
	except
	s._unknown_internal_error:
	return FAILURE

	rval = s._handle_self_update()
	if rval != os.EX_OK:
	return rval

	for root
	in
	s.trees:
	root_config = s.trees[root]["root_config"]

	tmpdir := root_config. settings.ValueDict["PORTAGE_TMPDIR"]
	if tmpdir=="" || !pathIsDir(tmpdir):
	msg := (
		'The directory specified in your PORTAGE_TMPDIR variable does not exist:',
		tmpdir,
		'Please create this directory or correct your PORTAGE_TMPDIR setting.',
)
	out = portage.output.EOutput()
	for l
	in
msg:
	out.eerror(l)
	return FAILURE

	if s._background:
	root_config.settings.unlock()
	root_config.settings.ValueDict["PORTAGE_BACKGROUND"] = "1"
	root_config.settings.backup_changes("PORTAGE_BACKGROUND")
	root_config.settings.lock()

	s.pkgsettings.ValueDict[root] = portage.config(
		clone = root_config.settings)

	keep_going = "--keep-going"
	in
	s.myopts
	fetchonly = s._build_opts.fetchonly
	mtimedb = s._mtimedb
	failed_pkgs = s._failed_pkgs

	rval = s._generate_digests()
	if rval != os.EX_OK:
	return rval

	rval = s._check_manifests()
	if rval != os.EX_OK &&
	not
keep_going:
	return rval

	if not fetchonly:
	rval = s._run_pkg_pretend()
	if rval != os.EX_OK:
	return rval

	while
true:

	received_signal = []

	func
	sighandler(signum, frame):
	signal.signal(signal.SIGINT, signal.SIG_IGN)
	signal.signal(signal.SIGTERM, signal.SIG_IGN)
	portage.util.writemsg("\n\nExiting on signal %(signal)s\n" % 
	{
		"signal":signum
	})
	s.terminate()
	received_signal.append(128 + signum)

	earlier_sigint_handler = signal.signal(signal.SIGINT, sighandler)
	earlier_sigterm_handler = signal.signal(signal.SIGTERM, sighandler)
	earlier_sigcont_handler = 
	signal.signal(signal.SIGCONT, s._sigcont_handler)
	signal.siginterrupt(signal.SIGCONT, false)

try:
	rval = s._merge()
finally:
	if earlier_sigint_handler is
	not
None:
	signal.signal(signal.SIGINT, earlier_sigint_handler)
	else:
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	if earlier_sigterm_handler is
	not
None:
	signal.signal(signal.SIGTERM, earlier_sigterm_handler)
	else:
	signal.signal(signal.SIGTERM, signal.SIG_DFL)
	if earlier_sigcont_handler is
	not
None:
	signal.signal(signal.SIGCONT, earlier_sigcont_handler)
	else:
	signal.signal(signal.SIGCONT, signal.SIG_DFL)

	s._termination_check()
	if received_signal:
	sys.exit(received_signal[0])

	if rval == os.EX_OK ||
	fetchonly
 ||
	not
keep_going:
	break
	if "resume" not
	in
mtimedb:
	break
	mergelist = s._mtimedb["resume"].get("mergelist")
	if not mergelist:
	break

	if not failed_pkgs:
	break

	for failed_pkg
	in
failed_pkgs:
	mergelist.remove(list(failed_pkg.pkg))

	s._failed_pkgs_all.extend(failed_pkgs)
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
	s._pkg_count.maxval = len([x
	for x
	in
	s._mergelist 
	if isinstance(x, Package) &&
	x.operation == "merge"])
s._status_display.maxval = s._pkg_count.maxval

s._cleanup()

s._logger.log(" *** Finished. Cleaning up...")

if failed_pkgs:
s._failed_pkgs_all.extend(failed_pkgs)
del failed_pkgs[:]

printer = portage.output.EOutput()
background = s._background
failure_log_shown = false
if background && len(s._failed_pkgs_all) == 1 && 
s.myopts.get('--quiet-fail', 'n') != 'y':
failed_pkg = s._failed_pkgs_all[-1]
log_file = None
log_file_real = None

log_path = s._locate_failure_log(failed_pkg)
if log_path is not None:
try:
log_file = open(_unicode_encode(log_path,
encoding = _encodings['fs'], errors = 'strict'), mode ='rb')
except IOError:
pass else:
if log_path.endswith('.gz'):
log_file_real = log_file
log_file = gzip.GzipFile(filename ='',
mode = 'rb', fileobj = log_file)

if log_file is not None:
try:
for line in log_file:
WriteMsgLevel(line, noiselevel =-1)
except zlib.error as e:
WriteMsgLevel("%s\n" % (e, ), level = logging.ERROR,
noiselevel = -1)
finally:
log_file.close()
if log_file_real is not None:
log_file_real.close()
failure_log_shown = true

mod_echo_output = _flush_elog_mod_echo()

if background && not failure_log_shown && 
s._failed_pkgs_all && 
s._failed_pkgs_die_msgs && 
not mod_echo_output:

for mysettings, key, logentries in s._failed_pkgs_die_msgs:
root_msg = ""
if mysettings.ValueDict["ROOT"] != "/":
root_msg = " merged to %s" % mysettings.ValueDict["ROOT"]
print()
printer.einfo("Error messages for package %s%s:" % 
(colorize("INFORM", key), root_msg))
print()
for phase in portage.const.EBUILD_PHASES:
if phase not in logentries:
continue
for msgtype, msgcontent in logentries[phase]:
if isinstance(msgcontent, basestring):
msgcontent = [msgcontent]
for line in msgcontent:
printer.eerror(line.strip("\n"))

if s._post_mod_echo_msgs:
for msg in s._post_mod_echo_msgs:
msg()

if len(s._failed_pkgs_all) > 1 || 
(s._failed_pkgs_all && keep_going):
if len(s._failed_pkgs_all) > 1:
msg = "The following %d packages have " % 
len(s._failed_pkgs_all) + 
"failed to build, install, or execute postinst:"
else:
msg = "The following package has " + 
"failed to build, install, or execute postinst:"

printer.eerror("")
for line in SplitSubN(msg, 72):
printer.eerror(line)
printer.eerror("")
for failed_pkg in s._failed_pkgs_all:
msg = " %s" % (failed_pkg.pkg, )
if failed_pkg.postinst_failure:
msg += " (postinst failed)"
log_path = s._locate_failure_log(failed_pkg)
if log_path is not None:
msg += ", Log file:"
printer.eerror(msg)
if log_path is not None:
printer.eerror("  '%s'" % colorize('INFORM', log_path))
printer.eerror("")

if s._failed_pkgs_all:
return FAILURE
return os.EX_OK
}

func (s *Scheduler) _elog_listener(mysettings, key, logentries, fulltext) {
	errors := filter_loglevels(logentries, ["ERROR"])
	if errors {
		s._failed_pkgs_die_msgs = append(_failed_pkgs_die_msgs
			(mysettings, key, errors))
	}
}

func (s *Scheduler) _locate_failure_log( failed_pkg) {

	log_paths = [failed_pkg.build_log]

	for log_path
	in
log_paths:
	if not log_path:
	continue

try:
	log_size = os.Stat(log_path).st_size
	except
OSError:
	continue

	if log_size == 0:
	continue

	return log_path

	return None
}

func (s *Scheduler) _add_packages() {
	pkg_queue = s._pkg_queue
	for pkg
	in
	s._mergelist:
	if isinstance(pkg, Package):
	pkg_queue.append(pkg)
	else if
	isinstance(pkg, Blocker):
	pass
}

func (s *Scheduler) _system_merge_started(merge) {
	graph := s._digraph
	if graph == nil {
		return
	}
	pkg = merge.merge.pkg

	if pkg.root_config.settings.ValueDict["ROOT"] != "/" {
		return
	}

	completed_tasks := s._completed_tasks
	unsatisfied := s._unsatisfied_system_deps
	ignore_non_runtime_or_satisfied := func(priority) {
		if isinstance(priority, DepPriority) &&
			not
			priority.satisfied
		&&
		(priority.runtime
	||
		priority.runtime_post){
		return false
	}
	return true
}

	for child
	in
	graph.child_nodes(pkg,
		ignore_priority = ignore_non_runtime_or_satisfied):
	if not isinstance(child, Package)
	|| 
	child.operation == 'uninstall':
	continue
	if child is
pkg:
	continue
	if child.operation == 'merge' && 
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

func (s *Scheduler) _merge_exit(merge) {
	s._running_tasks.pop(id(merge), None)
	s._do_merge_exit(merge)
	s._deallocate_config(merge.merge.settings)
	if merge.returncode == os.EX_OK && 
	not
	merge.merge.pkg.installed {
		s._status_display.curval += 1
	}
	s._status_display.merges = len(s._task_queues.merge)
	s._schedule()
}

func (s *Scheduler) _do_merge_exit( merge) {
	pkg = merge.merge.pkg
	if merge.returncode != os.EX_OK:
	settings = merge.merge.settings
	build_dir =  settings.ValueDict["PORTAGE_BUILDDIR")
	build_log =  settings.ValueDict["PORTAGE_LOG_FILE")

	s._failed_pkgs.append(s._failed_pkg(
		build_dir = build_dir, build_log = build_log,
		pkg = pkg,
		returncode=merge.returncode))
	if not s._terminated_tasks:
	s._failed_pkg_msg(s._failed_pkgs[-1], "install", "to")
	s._status_display.failed = len(s._failed_pkgs)
	return

	if merge.postinst_failure:
	s._failed_pkgs_all.append(s._failed_pkg(
		build_dir = merge.merge. settings.ValueDict["PORTAGE_BUILDDIR"),
		build_log = merge.merge. settings.ValueDict["PORTAGE_LOG_FILE"),
		pkg = pkg,
		postinst_failure=true,
		returncode = merge.returncode))
	s._failed_pkg_msg(s._failed_pkgs_all[-1],
		"execute postinst for", "for")

	s._task_complete(pkg)
	pkg_to_replace = merge.merge.pkg_to_replace
	if pkg_to_replace is
	not
None:
	if s._digraph is
	not
	None
	&& 
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
	s._pkg_cache.pop(pkg_to_replace, None)

	if pkg.installed:
	return

	mtimedb = s._mtimedb
	mtimedb["resume"]["mergelist"].remove(list(pkg))
	if not mtimedb["resume"]["mergelist"]:
	del
	mtimedb["resume"]
	mtimedb.commit()
}

func (s *Scheduler) _build_exit( build) {
	s._running_tasks.pop(id(build), None)
	if build.returncode == os.EX_OK &&
	s._terminated_tasks:
	s.curval += 1
	s._deallocate_config(build.settings)
	else if
	build.returncode == os.EX_OK:
	s.curval += 1
	merge = PackageMerge(merge = build, scheduler = s._sched_iface)
	s._running_tasks[id(merge)] = merge
	if not build.build_opts.buildpkgonly
	&& 
	build.pkg
	in
	s._deep_system_deps:
	s._merge_wait_queue.append(merge)
	merge.addStartListener(s._system_merge_started)
	else:
	s._task_queues.merge.add(merge)
	merge.addExitListener(s._merge_exit)
	s._status_display.merges = len(s._task_queues.merge)
	else:
	settings = build.settings
	build_dir =  settings.ValueDict["PORTAGE_BUILDDIR")
	build_log =  settings.ValueDict["PORTAGE_LOG_FILE")

	s._failed_pkgs.append(s._failed_pkg(
		build_dir = build_dir, build_log = build_log,
		pkg = build.pkg,
		returncode=build.returncode))
	if not s._terminated_tasks:
	s._failed_pkg_msg(s._failed_pkgs[-1], "emerge", "for")
	s._status_display.failed = len(s._failed_pkgs)
	s._deallocate_config(build.settings)
	s._jobs -= 1
	s._status_display.running = s._jobs
	s._schedule()
}

func (s *Scheduler) _extract_exit( build) {
	s._build_exit(build)
}

func (s *Scheduler) _task_complete(pkg) {
	s._completed_tasks.add(pkg)
	s._unsatisfied_system_deps.discard(pkg)
	s._choose_pkg_return_early = false
	blocker_db = s._blocker_db[pkg.root]
	blocker_db.discardBlocker(pkg)
}

func (s *Scheduler) _main_loop() {
	s._main_exit = s._event_loop.create_future()

	if s._max_load is
	not
	None
	&& 
	s._loadavg_latency
	is
	not
	None
	&& 
	(s._max_jobs
	is
	true
 ||
	s._max_jobs > 1):
	s._main_loadavg_handle = s._event_loop.call_later(
		s._loadavg_latency, s._schedule)

	s._schedule()
	s._event_loop.run_until_complete(s._main_exit)
}

func (s *Scheduler) _merge() {

	if s._opts_no_background.intersection(s.myopts):
	s._set_max_jobs(1)

	s._add_prefetchers()
	s._add_packages()
	failed_pkgs = s._failed_pkgs
	portage.locks._quiet = s._background
	add_listener(s._elog_listener)

	func
	display_callback():
	s._status_display.display()
	display_callback.handle = s._event_loop.call_later(
		s._max_display_latency, display_callback)
	display_callback.handle = None

	if s._status_display._isatty &&
	not
	s._status_display.quiet:
	display_callback()
	rval = os.EX_OK

try:
	s._main_loop()
finally:
	s._main_loop_cleanup()
	portage.locks._quiet = false
	remove_listener(s._elog_listener)
	if display_callback.handle is
	not
None:
	display_callback.handle.cancel()
	if failed_pkgs:
	rval = failed_pkgs[-1].returncode

	return rval
}

func (s *Scheduler) _main_loop_cleanup() {
	del
	s._pkg_queue[:]
	s._completed_tasks.clear()
	s._deep_system_deps.clear()
	s._unsatisfied_system_deps.clear()
	s._choose_pkg_return_early = false
	s._status_display.reset()
	s._digraph = None
	s._task_queues.fetch.clear()
	s._prefetchers.clear()
	s._main_exit = None
	if s._main_loadavg_handle is
	not
None:
	s._main_loadavg_handle.cancel()
	s._main_loadavg_handle = None
	if s._job_delay_timeout_id is
	not
None:
	s._job_delay_timeout_id.cancel()
	s._job_delay_timeout_id = None
	if s._schedule_merge_wakeup_task is
	not
None:
	s._schedule_merge_wakeup_task.cancel()
	s._schedule_merge_wakeup_task = None
}

func (s *Scheduler) _choose_pkg() {

	if s._choose_pkg_return_early:
	return None

	if s._digraph is
None:
	if s._is_work_scheduled() && 
	not("--nodeps"
	in
	s.myopts
	&& 
	(s._max_jobs
	is
	true
 ||
	s._max_jobs > 1)):
	s._choose_pkg_return_early = true
	return None
	return s._pkg_queue.pop(0)

	if not s._is_work_scheduled():
	return s._pkg_queue.pop(0)

	s._prune_digraph()

	chosen_pkg = None

	graph = s._digraph
	for pkg
	in
	s._pkg_queue:
	if pkg.operation == 'uninstall' && 
	not
	graph.child_nodes(pkg):
	chosen_pkg = pkg
	break

	if chosen_pkg is
None:
	later = set(s._pkg_queue)
	for pkg
	in
	s._pkg_queue:
	later.remove(pkg)
	if not s._dependent_on_scheduled_merges(pkg, later):
	chosen_pkg = pkg
	break

	if chosen_pkg is
	not
None:
	s._pkg_queue.remove(chosen_pkg)

	if chosen_pkg is
None:
	s._choose_pkg_return_early = true

	return chosen_pkg
}

func (s *Scheduler) _dependent_on_scheduled_merges( pkg, later) {

	graph = s._digraph
	completed_tasks = s._completed_tasks

	dependent = false
	traversed_nodes = set([pkg])
	direct_deps = graph.child_nodes(pkg)
	node_stack = direct_deps
	direct_deps = frozenset(direct_deps)
	while
node_stack:
	node = node_stack.pop()
	if node in
traversed_nodes:
	continue
	traversed_nodes.add(node)
	if not((node.installed &&
	node.operation == "nomerge") || 
	(node.operation == "uninstall"
	&& 
	node
	not
	in
	direct_deps) || 
	node
	in
	completed_tasks
	|| 
	node
	in
	later):
	dependent = true
	break

	if node.operation != "uninstall":
	node_stack.extend(graph.child_nodes(node))

	return dependent
}

func (s *Scheduler) _allocate_config( root) {
	if s._config_pool[root]:
	temp_settings = s._config_pool[root].pop()
	else:
	temp_settings = portage.config(clone = s.pkgsettings.ValueDict[root])
	temp_settings.reload()
	temp_settings.reset()
	return temp_settings
}

func (s *Scheduler) _deallocate_config(settings) {
	s._config_pool[settings.ValueDict['EROOT']].append(settings)
}

func (s *Scheduler) _keep_scheduling() {
	return bool(not
	s._terminated.is_set()
	&&
	s._pkg_queue
	&& 
	not(s._failed_pkgs
	&&
	not
	s._build_opts.fetchonly))
}

func (s *Scheduler) _is_work_scheduled() {
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
			not
			s._build_opts.fetchonly
		&&
		not
		s._is_work_scheduled()
		&&
		s._task_queues.fetch:
		s._task_queues.fetch.clear()

		if not(state_change ||
			(s._merge_wait_queue
		&&
		not
		s._jobs
		&&
		not
		s._task_queues.merge)):
		break
	}

	if not(s._is_work_scheduled() ||
	s._keep_scheduling()
 ||
	s._main_exit.done()):
	s._main_exit.set_result(None)
	else if
	s._main_loadavg_handle
	is
	not
None:
	s._main_loadavg_handle.cancel()
	s._main_loadavg_handle = s._event_loop.call_later(
		s._loadavg_latency, s._schedule)

	if (s._task_queues.merge &&(s._schedule_merge_wakeup_task
	is
	None
 ||
	s._schedule_merge_wakeup_task.done())):
	s._schedule_merge_wakeup_task = asyncio.ensure_future(
		s._task_queues.merge.wait(), loop = s._event_loop)
	s._schedule_merge_wakeup_task.add_done_callback(
		s._schedule_merge_wakeup)
}

func (s *Scheduler) _schedule_merge_wakeup( future) {
	if not future.cancelled():
	future.result()
	if s._main_exit is
	not
	None
	&&
	not
	s._main_exit.done():
	s._schedule()
}

func (s *Scheduler) _sigcont_handler( signum, frame) {
	s._sigcont_time = time.time()
}

func (s *Scheduler) _job_delay() {

	if s._jobs &&
	s._max_load
	is
	not
None:

	current_time = time.time()

	if s._sigcont_time is
	not
None:

	elapsed_seconds = current_time - s._sigcont_time
	if elapsed_seconds > 0 && 
	elapsed_seconds < s._sigcont_delay:

	if s._job_delay_timeout_id is
	not
None:
	s._job_delay_timeout_id.cancel()

	s._job_delay_timeout_id = s._event_loop.call_later(
		s._sigcont_delay-elapsed_seconds,
		s._schedule)
	return true

	s._sigcont_time = None

try:
	avg1, avg5, avg15 = getloadavg()
	except
OSError:
	return false

	delay = s._job_delay_max * avg1 / s._max_load
	if delay > s._job_delay_max:
	delay = s._job_delay_max
	elapsed_seconds = current_time - s._previous_job_start_time
	if elapsed_seconds > 0 &&
	elapsed_seconds < delay{
		if s._job_delay_timeout_id is
		not
	None:
		s._job_delay_timeout_id.cancel()

		s._job_delay_timeout_id = s._event_loop.call_later(
			delay-elapsed_seconds, s._schedule)
		return true
	}

	return false
}

func (s *Scheduler) _schedule_tasks_imp() bool{
	state_change := 0

	for {
		if ! s._keep_scheduling(){
			return state_change!= 0
		}

		if s._choose_pkg_return_early || s._merge_wait_scheduled || (s._jobs && s._unsatisfied_system_deps) || ! s._can_add_job() || s._job_delay() {
			return state_change!= 0
		}

		pkg = s._choose_pkg()
		if pkg is
		None:
			return state_change!= 0

		state_change += 1

		if not pkg.installed {
			s._pkg_count.curval += 1
		}

		task = s._task(pkg)

		if pkg.installed {
			merge = PackageMerge(merge = task, scheduler = s._sched_iface)
			s._running_tasks[id(merge)] = merge
			s._task_queues.merge.addFront(merge)
			merge.addExitListener(s._merge_exit)
		} else if pkg.built{
			s._jobs += 1
			s._previous_job_start_time = time.time()
			s._status_display.running = s._jobs
			s._running_tasks[id(task)] = task
			task.scheduler = s._sched_iface
			s._task_queues.jobs.add(task)
			task.addExitListener(s._extract_exit)
		} else{
			s._jobs += 1
			s._previous_job_start_time = time.time()
			s._status_display.running = s._jobs
			s._running_tasks[id(task)] = task
			task.scheduler = s._sched_iface
			s._task_queues.jobs.add(task)
			task.addExitListener(s._build_exit)
		}
	}
	return state_change!= 0
}

func (s *Scheduler) _task( pkg) {

	pkg_to_replace = None
	if pkg.operation != "uninstall"{
		vardb := pkg.root_config.trees["vartree"].dbapi
		previous_cpv = [x
		for x
			in
		vardb.match(pkg.slot_atom)
		if portage.cpv_getkey(x) == pkg.cp]
		if not previous_cpv && vardb.cpv_exists(pkg.cpv):
		previous_cpv = [pkg.cpv]
		if previous_cpv:
		previous_cpv = previous_cpv.pop()
		pkg_to_replace = s._pkg(previous_cpv,
		"installed", pkg.root_config, installed = true,
		operation = "uninstall")
	}

try:
prefetcher = s._prefetchers.pop(pkg, None)
except KeyError:
prefetcher = None
if prefetcher is not None && not prefetcher.isAlive():
try:
s._task_queues.fetch._task_queue.remove(prefetcher)
except ValueError:
pass
prefetcher = None

task = MergeListItem(args_set= s._args_set,
background = s._background, binpkg_opts = s._binpkg_opts,
build_opts = s._build_opts,
config_pool = s._ConfigPool(pkg.root,
s._allocate_config, s._deallocate_config),
emerge_opts = s.myopts,
find_blockers =s._find_blockers(pkg), logger = s._logger,
mtimedb = s._mtimedb, pkg= pkg, pkg_count = s._pkg_count.copy(),
pkg_to_replace = pkg_to_replace,
prefetcher = prefetcher,
scheduler = s._sched_iface,
settings = s._allocate_config(pkg.root),
statusMessage =s._status_msg,
world_atom = s._world_atom)

return task
}

func (s *Scheduler) _failed_pkg_msg(failed_pkg interface{}, action, preposition string) {
	pkg = failed_pkg.pkg
	msg := fmt.Sprintf("%s to %s %s" ,
	bad("Failed"), action, colorize("INFORM", pkg.cpv))
	if pkg.root_config.settings.ValueDict["ROOT"] != "/" {
		msg += fmt.Sprintf(" %s %s", preposition, pkg.root)
	}

	log_path := s._locate_failure_log(failed_pkg)
	if log_path is
	not
None{
	msg += ", Log file:"
	s._status_msg(msg)
}

	if log_path is
	not
None:
	s._status_msg(" '%s'" % (colorize("INFORM", log_path), ))
}

func (s *Scheduler) _status_msg( msg string) {
	if not s._background {
		WriteMsgLevel("\n")
	}
	s._status_display.displayMessage(msg)
}

func (s *Scheduler) _save_resume_list() {
	mtimedb := s._mtimedb

	mtimedb["resume"] = map[string]{}
	mtimedb["resume"]["myopts"] = s.myopts.copy()

	mtimedb["resume"]["favorites"] = [str(x)
	for x
	in
	s._favorites]
mtimedb["resume"]["mergelist"] = [list(x) 
for x in s._mergelist 
if isinstance(x, Package) && x.operation == "merge"]

mtimedb.commit()
}

func (s *Scheduler) _calc_resume_list() {
	print(colorize("GOOD", "*** Resuming merge..."))

	s._destroy_graph()

	myparams := create_depgraph_params(s.myopts, None)
	success := false
	e = None
try:
	success, mydepgraph, dropped_tasks = resume_depgraph(
		s.settings, s.trees, s._mtimedb, s.myopts,
		myparams, s._spinner)
	except
	depgraph.UnsatisfiedResumeDep
	as
exc:
	e = exc
	mydepgraph = e.depgraph
	dropped_tasks =
	{
	}

	if e is
	not
None:

	unsatisfied_resume_dep_msg:= func(){
		mydepgraph.display_problems()
		out := NewEOutput(false)
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
		if dep.atom is
	None:
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
		for line
			in
		SplitSubN(msg, 72):
		out.eerror(line)
	}
	s._post_mod_echo_msgs.append(unsatisfied_resume_dep_msg)
	return false

	if success &&
	s._show_list():
	mydepgraph.display(mydepgraph.altlist(), favorites = s._favorites)

	if not success:
	s._post_mod_echo_msgs.append(mydepgraph.display_problems)
	return false
	mydepgraph.display_problems()
	s._init_graph(mydepgraph.schedulerGraph())

	msg_width = 75
	for task, atoms
	in
	dropped_tasks.items():
	if not(isinstance(task, Package) &&
	task.operation == "merge"):
	continue
	pkg = task
	msg = "emerge --keep-going:" + 
	" %s" % (pkg.cpv,)
	if pkg.root_config.settings.ValueDict["ROOT"] != "/":
	msg += " for %s" % (pkg.root,)
	if not atoms:
	msg += " dropped because it is masked or unavailable"
	else:
	msg += " dropped because it requires %s" % ", ".join(atoms)
	for line
	in
	SplitSubN(msg, msg_width):
	eerror(line, phase = "other", key = pkg.cpv)
	settings = s.pkgsettings.ValueDict[pkg.root]
	settings.pop("T", None)
	portage.elog.elog_process(pkg.cpv, settings)
	s._failed_pkgs_all.append(s._failed_pkg(pkg = pkg))

	return true
}

func (s *Scheduler) _show_list() bool {
	myopts := s.myopts
	if  !Inmss(myopts, "--quiet")&& Inmss(myopts, "--ask")||Inmss(myopts, "--tree")||Inmss(myopts, "--verbose") {
		return true
	}
	return false
}

func (s *Scheduler) _world_atom( pkg) {

	if set(("--buildpkgonly", "--fetchonly",
		"--fetch-all-uri",
		"--oneshot", "--onlydeps",
		"--pretend")).intersection(s.myopts):
	return

	if pkg.root != s.target_root:
	return

	args_set = s._args_set
	if not args_set.findAtomForPackage(pkg):
	return

	logger = s._logger
	pkg_count = s._pkg_count
	root_config = pkg.root_config
	world_set = root_config.sets["selected"]
	world_locked = false
	atom = None

	if pkg.operation != "uninstall":
	atom = s._world_atoms.get(pkg)

try:

	if hasattr(world_set, "lock"):
	world_set.lock()
	world_locked = true

	if hasattr(world_set, "load"):
	world_set.load()

	if pkg.operation == "uninstall":
	if hasattr(world_set, "cleanPackage"):
	world_set.cleanPackage(pkg.root_config.trees["vartree"].dbapi,
		pkg.cpv)
	if hasattr(world_set, "remove"):
	for s
	in
	pkg.root_config.setconfig.active:
	world_set.remove(SETPREFIX + s)
	else:
	if atom is
	not
None:
	if hasattr(world_set, "add"):
	s._status_msg(('Recording %s in "world" ' + 
	'favorites file...') % atom)
	logger.log(" === (%s of %s) Updating world file (%s)" % 
	(pkg_count.curval, pkg_count.maxval, pkg.cpv))
	world_set.add(atom)
	else:
	WriteMsgLevel('\n!!! Unable to record %s in "world"\n' % 
	(atom,), level = logging.WARN, noiselevel=-1)
finally:
	if world_locked:
	world_set.unlock()
}

func (s *Scheduler) _pkg( cpv, type_name, root_config, installed=false,
operation=None, myrepo=None) {

	pkg = s._pkg_cache.get(Package._gen_hash_key(cpv = cpv,
		type_name = type_name, repo_name=myrepo, root_config = root_config,
		installed=installed, operation = operation))

	if pkg is
	not
None:
	return pkg

	tree_type = depgraph.pkg_tree_map[type_name]
	db = root_config.trees[tree_type].dbapi
	db_keys = list(s.trees[root_config.root][
		tree_type].dbapi._aux_cache_keys)
	metadata = zip(db_keys, db.aux_get(cpv, db_keys, myrepo = myrepo))
	pkg = Package(built = (type_name != "ebuild"),
		cpv = cpv, installed=installed, metadata = metadata,
		root_config=root_config, type_name = type_name)
	s._pkg_cache[pkg] = pkg
	return pkg
}

type  SchedulerInterface struct {
	// slot
	add_reader,
	add_writer,
	call_at,
	call_exception_handler,
	call_later,
	call_soon,
	call_soon_threadsafe,
	close,
	create_future,
	default_exception_handler,
	get_debug,
	is_closed,
	is_running,
	remove_reader,
	remove_writer,
	run_in_executor,
	run_until_complete,
	set_debug,
	time,
	_asyncio_child_watcher,
	_asyncio_wrapper,
	_event_loop,
	_is_background string
}

var _event_loop_attrs = []string{
	"add_reader",
	"add_writer",
	"call_at",
	"call_exception_handler",
	"call_later",
	"call_soon",
	"call_soon_threadsafe",
	"close",
	"create_future",
	"default_exception_handler",
	"get_debug",
	"is_closed",
	"is_running",
	"remove_reader",
	"remove_writer",
	"run_in_executor",
	"run_until_complete",
	"set_debug",
	"time",

	"_asyncio_child_watcher",
	"_asyncio_wrapper",
}

func NewSchedulerInterface(event_loop, is_background=None, **kwargs)*SchedulerInterface {
	s := &SchedulerInterface{}
	SlotObject.__init__(s, **kwargs)
	s._event_loop = event_loop
	if is_background is
None:
	is_background = s._return_false
	s._is_background = is_background
	for kfilter_loglevels
	in
	s._event_loop_attrs:
	setattr(s, k, getattr(event_loop, k))
	return s
}

func (s * SchedulerInterface) _return_false() bool{
	return false
}

// "", nil, 0, -1
func (s * SchedulerInterface) output( msg , log_path string, background interface{}, level, noiselevel int) {

	global_background := s._is_background()
	if background == nil || global_background {
		background = global_background
	}

	msg_shown := false
	if not background {
		WriteMsgLevel(msg, level, noiselevel)
		msg_shown = true
	}

	if log_path != "" {
		f, err := os.OpenFile(log_path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
		if err != nil {
			//except IOError as e:
			if err!= syscall.ENOENT&& err!= syscall.ESTALE {
				//raise
			}
			if !msg_shown {
				WriteMsgLevel(msg, level, noiselevel)
			}
		} else{
			if strings.HasSuffix(log_path,".gz") {
				g := gzip.NewWriter(f)
				g.Write([]byte(msg))
			} else {
				f.Write([]byte(msg))
			}
			f.Close()
		}
	}
}
