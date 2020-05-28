package atom

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

type AsynchronousTask struct {
	background, scheduler,_exit_listener_handles,_exit_listeners,_start_listeners string
	_cancelled_returncode int
	returncode *int
	cancelled bool
}

func (a *AsynchronousTask) start() {
	a._start_hook()
	a._start()
}

func (a *AsynchronousTask)  async_wait(){
waiter := a.scheduler.create_future()
exit_listener := func(a *AsynchronousTask) { return waiter.cancelled() || waiter.set_result(a.returncode)}
a.addExitListener(exit_listener)
waiter.add_done_callback(func (waiter) {a.removeExitListener(exit_listener) if waiter.cancelled() else nil}
)
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

	if a.returncode != nil && a._exit_listeners != nil{
		listeners := a._exit_listeners
		a._exit_listeners = nil
		if a._exit_listener_handles == nil{
		a._exit_listener_handles =map[]{}
	}

		for _, listener := range listeners{
		if  _, ok := a._exit_listener_handles[listener]; ! ok{
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
	func (a *AbstractPollTask)  _wait_loop( timeout=nil){
loop := a.scheduler
tasks := []{a.async_wait()}
if timeout != nil{
			tasks= append(asyncio.ensure_future(
			asyncio.sleep(timeout, loop=loop), loop=loop))
		}
try:
loop.run_until_complete(asyncio.ensure_future(
asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED,
loop=loop), loop=loop))
finally:
for _, task := range  tasks{
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

func (s *SubProcess) _async_wait(){
if s.returncode == nil {
	//raise asyncio.InvalidStateError('Result is not ready for %s' % (s,))
}else{
	s.AbstractPollTask._async_wait()
	}
}
}

func (s *SubProcess) _async_waitpid(){
if s.returncode != nil {
	s._async_wait()
} else if s._waitpid_id == 0 {
		s._waitpid_id = s.pid
		s.scheduler._asyncio_child_watcher.add_child_handler(s.pid, s._async_waitpid_cb)

	}
}

func (s *SubProcess) _async_waitpid_cb( pid, returncode int){
if pid != s.pid{
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
	args, env, opt_name,
	uid, gid, groups, umask, logfile,
	path_lookup, pre_exec, close_fds, cgroup,
	unshare_ipc, unshare_mount, unshare_pid, unshare_net,
	_pipe_logger, _selinux_type string
	fd_pipes map[int]int
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
		fd_pipes[0] = string(getStdin().Fd())
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

func(s *SpawnProcess) _spawn(args []string, **kwargs){
	spawn_func := spawn

	if s._selinux_type != nil{
		spawn_func = portage.selinux.spawn_wrapper(spawn_func,
		s._selinux_type)
		if args[0] != BashBinary{
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

func(s *SpawnProcess) _cgroup_cleanup(){
	if s.cgroup != nil{
		get_pids:= func(cgroup string)[]int{
			f, err := os.Open(filepath.Join(cgroup, "cgroup.procs"))
			var b []byte
			if err == nil {
				b, err = ioutil.ReadAll(f)
			}
			if err != nil {
				return []int{}
			}
			ps := []int{}
			for _, p := range strings.Fields(string(b)){
				pi, _ := strconv.Atoi(p)
				ps =append(ps, pi)
			}
			return ps
		}
kill_all:= func(pids []int, sig syscall.Signal){
	for _, p := range pids{
		err := syscall.Kill(p, sig)
		if err != nil {
			//except OSError as e:
			if err == syscall.EPERM{
				WriteMsgLevel(fmt.Sprintf("!!! kill: (%i) - Operation not permitted\n", p), 40,-1)
			}else if err != syscall.ESRCH {
				//raise
			}
		}
	}
	}
remaining := s._CGROUP_CLEANUP_RETRY_MAX
var pids []int
for remaining> 0 {
remaining -= 1
pids = get_pids(s.cgroup)
if len(pids) != 0 {
kill_all(pids, syscall.SIGKILL)
}else{
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

err:= os.RemoveAll(s.cgroup.Name())
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

func NewSpawnProcess() *SpawnProcess {
	s := &SpawnProcess{}
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

func(m *MergeProcess)  _start(){
	cpv := fmt.Sprintf("%s/%s" ,m.mycat, m.mypkg)
	settings := m.settings
	if _, ok := settings.configDict["pkg"]["EAPI"]; cpv != settings.mycpv.string || !ok {
		settings.reload()
		settings.reset(0)
		settings.SetCpv(NewPkgStr(cpv,nil, nil, "", "", "", 0, 0, "", 0, nil), m.mydbapi)
	}

	if _, ok := settings.Features.Features["merge-sync"];runtime.GOOS == "Linux" && ok {
		find_library("c")
	}

	if m.fd_pipes == nil{
		m.fd_pipes = map[int]int{}
	}else{
		m.fd_pipes = m.fd_pipes
	}
	if _, ok := m.fd_pipes[0]; !ok{
		m.fd_pipes[0]=int(getStdin().Fd())
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
func(m *MergeProcess) _elog_output_handler() bool{
output := m._read_buf(m._elog_reader_fd)
if len(output) > 0 {
	lines := strings.Split(string(output), "\n")
	if len(lines) == 1{
		m._buf += lines[0]
	} else{
		lines[0] = m._buf + lines[0]
		m._buf = lines.pop()
		out := &bytes.Buffer{}
		for _, line := range lines{
			s4 := strings.SplitN(line," ", 4)
			funcname, phase, key, msg := s4[0], s4[1],s4[2],s4[3]
			m._elog_keys[key]=true
			reporter = getattr(portage.elog.messages, funcname)
			reporter(msg, phase=phase, key=key, out=out)
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

func(m *MergeProcess) _spawn( args, fd_pipes, **kwargs){
	r := make([]int,2)
	syscall.Pipe(r)
	elog_reader_fd, elog_writer_fd :=r[0],r[1]

	fcntl.fcntl(elog_reader_fd, fcntl.F_SETFL,
		fcntl.fcntl(elog_reader_fd, fcntl.F_GETFL) | syscall.O_NONBLOCK)

	if sys.hexversion < 0x3040000:
try:
	fcntl.FD_CLOEXEC
	except AttributeError:
	pass
	}else{
	fcntl.fcntl(elog_reader_fd, fcntl.F_SETFD,
		fcntl.fcntl(elog_reader_fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)

	blockers = nil
	if m.blockers != nil {
		blockers = m.blockers()
	}
	mylink := NewDblink(m.mycat, m.mypkg, settings=m.settings,
		treetype=m.treetype, vartree=m.vartree,
		blockers=blockers, pipe=elog_writer_fd)
	fd_pipes[elog_writer_fd] = elog_writer_fd
	m.scheduler.add_reader(elog_reader_fd, m._elog_output_handler)

	m._lock_vdb()
	counter = nil
	if ! m.unmerge{
		counter = m.vartree.dbapi.counter_tick()
	}

	parent_pid := syscall.Getpid()
	pid = nil
try:
	pid = syscall.fork()

	if pid != 0{
		if not isinstance(pid, int):
		raise AssertionError(
			"fork returned non-integer: %s" % (repr(pid),))

		syscall.Close(elog_writer_fd)
		m._elog_reader_fd = elog_reader_fd
		m._buf = ""
		m._elog_keys = map[string]bool{}
		portage.elog.messages.collect_messages(key=mylink.mycpv)

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
	if wakeup_fd > 0{
		syscall.Close(wakeup_fd)
	}
	except (ValueError, OSError):
	pass

	_close_fds()
	portage.process._setup_pipes(fd_pipes, close_fds=false)

	havecolor := m.settings.ValueDict["NOCOLOR"]== "yes" ||  m.settings.ValueDict["NOCOLOR"]== "true"

	m.vartree.dbapi._flush_cache_enabled = false

	if ! m.unmerge{
		if m.settings.ValueDict["PORTAGE_BACKGROUND"] == "1" {
			m.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] = "1"
		}else {
			m.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] = "0"
		}
		m.settings.backupChanges("PORTAGE_BACKGROUND_UNMERGE")
	}
	m.settings.ValueDict["PORTAGE_BACKGROUND"] = "subprocess"
	m.settings.backupChanges("PORTAGE_BACKGROUND")

	rval := 1
try:
	if m.unmerge{
		if ! mylink.exists(){
			rval = syscall.EX_OK
		} else if mylink.unmerge(
			ldpath_mtimes=m.prev_mtimes) == syscall.F_OK{
			mylink.lockdb()
			try:
			mylink.delete()
			finally:
			mylink.unlockdb()
			rval = syscall.EX_OK
		}
	}else{
		rval = mylink.merge(m.pkgloc, m.infloc,
			myebuild=m.myebuild, mydbapi=m.mydbapi,
			prev_mtimes=m.prev_mtimes, counter=counter)
	}
	except SystemExit:
	raise
except:
	traceback.print_exc()
	sys.stderr.flush()
finally:
	syscall._exit(rval)

finally:
	if pid == 0 || (pid == 0 && syscall.Getpid() != parent_pid){
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

func(m *MergeProcess) _unregister(){
	if ! m.unmerge{
	//try:
		m.vartree.dbapi.aux_get(m.settings.mycpv.string, map[string]bool{"EAPI":true}, "")
		//except KeyError:
		//pass
	}

	m._unlock_vdb()
	if m._elog_reader_fd != nil{
		m.scheduler.remove_reader(m._elog_reader_fd)
		syscall.Close(m._elog_reader_fd)
		m._elog_reader_fd = nil
	}
	if m._elog_keys != nil{
		for key := range m._elog_keys{
			portage.elog.elog_process(key, m.settings,
				phasefilter=("prerm", "postrm"))
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
	a. _phases_interactive_whitelist = []string{"config",}
	a._exit_timeout = 10
	a._enable_ipc_daemon = true

	a.SpawnProcess = NewSpawnProcess(**kwargs)
	if a.phase == "" {
		phase := a.settings.ValueDict["EBUILD_PHASE"]
		if phase== "" {
			phase = "other"
			a.phase = phase
		}
	}
	return a
}

func (a *AbstractEbuildProcess)_start(){

need_builddir := true
for _, v := range a._phases_without_builddir {
	if a.phase == v {
		need_builddir = false
		break
	}
}

if st, err := os.Stat(a.settings.ValueDict["PORTAGE_BUILDDIR"]);need_builddir &&err != nil && !st.IsDir(){
	msg := fmt.Sprintf("The ebuild phase '%s' has been aborted " +
		"since PORTAGE_BUILDDIR does not exist: '%s'", a.phase, a.settings.ValueDict["PORTAGE_BUILDDIR"])
	a._eerror(SplitSubN(msg, 72))
	i := 1
	a.returncode = &i
	a._async_wait()
	return
}

if os.Geteuid() == 0 && runtime.GOOS == "linux" && a.settings.Features.Features["cgroup"] && ! _global_pid_phases[a.phase] {
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

				if st, _ := os.Stat(release_agent_path); release_agent_path == "" || st!= nil {
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
			cgroup_path = filepath.Join(cgroup_portage,cp.Name())
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
if a._enable_ipc_daemon{
delete(a.settings.ValueDict,"PORTAGE_EBUILD_EXIT_FILE")
if  ! Ins(a._phases_without_builddir,a.phase) {
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
}else{
delete(a.settings.ValueDict,"PORTAGE_IPC_DAEMON")
}
}else{
delete(a.settings.ValueDict,"PORTAGE_IPC_DAEMON")
if   Ins(a._phases_without_builddir,a.phase) {
	exit_file := filepath.Join(
		a.settings.ValueDict["PORTAGE_BUILDDIR"],
		".exit_status")
	a.settings.ValueDict["PORTAGE_EBUILD_EXIT_FILE"] = exit_file
	if err := syscall.Unlink(exit_file); err != nil {
		//except OSError{
		if st, err :=os.Stat(exit_file); err == nil && st!= nil{
			//raise
		}
	}
} else{
	delete(a.settings.ValueDict,"PORTAGE_EBUILD_EXIT_FILE")
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
			a.fd_pipes ={}
		}
			null_fd := nil
			if _, ok := a.fd_pipes[0] ;!ok &&
			 ! Ins( a._phases_interactive_whitelist ,a.phase)&&
			 ! Ins(strings.Fields(a.settings.Valuedict["PROPERTIES"]), "interactive") {
				null_fd, _ := syscall.Open("/dev/null")
				a.fd_pipes[0] = null_fd
			}

			//try{
			a.SpawnProcess._start()
			//finally{
			if null_fd != nil{
				syscall.Close(null_fd)
			}
}



func (a *AbstractEbuildProcess)_init_ipc_fifos()(string,string){

input_fifo := filepath.Join(
a.settings.ValueDict["PORTAGE_BUILDDIR"], ".ipc_in")
output_fifo := filepath.Join(
a.settings.ValueDict["PORTAGE_BUILDDIR"], ".ipc_out")

for _, p := range []string{input_fifo, output_fifo}{

st, err := os.Lstat(p)
if err != nil {

	//except OSError{
		syscall.Mkfifo(p, 0755)
}else {
	if st.Mode()&syscall.S_IFIFO == 0 {
		st = nil
		if err := syscall.Unlink(p); err != nil {
			//except OSError{
			//	pass
		}
		syscall.Mkfifo(p, 0755)
	}
}
	apply_secpass_permissions(p, uint32(os.Getuid()), *portage_gid, 0770, -1,st, true)
}

	return input_fifo, output_fifo
}

func (a *AbstractEbuildProcess)_start_ipc_daemon() {
	a._exit_command = ExitCommand()
	a._exit_command.reply_hook = a._exit_command_callback
	query_command = QueryCommand(a.settings, a.phase)
	commands := map[string]string{
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

func (a *AbstractEbuildProcess)_cancel_timeout_cb(){
		a._exit_timeout_id = nil
		a._async_waitpid()
	}

func (a *AbstractEbuildProcess)_orphan_process_warn() {
	phase := a.phase

	msg := fmt.Sprintf("The ebuild phase '%s' with pid %s appears "+
		"to have left an orphan process running in the "+
		"background.", phase, a.pid)

	a._eerror(SplitSubN(msg, 72))
}

func (a *AbstractEbuildProcess)_pipe( fd_pipes map[int]int) (int, int){
	stdout_pipe := 0
	if !a.background {
		stdout_pipe = fd_pipes[1]
	}
	got_pty, master_fd, slave_fd :=
		_create_pty_or_pipe(copy_term_size = stdout_pipe)
	return master_fd, slave_fd
}

func (a *AbstractEbuildProcess)_can_log( slave_fd int)bool{
		return !(a.settings.Features.Features["sesandbox"] && a.settings.selinux_enabled()) || os.isatty(slave_fd)
	}

func (a *AbstractEbuildProcess)_killed_by_signal( signum int) {
	msg := fmt.Sprintf("The ebuild phase '%s' has been "+
		"killed by signal %s.", a.phase, signum)
	a._eerror(SplitSubN(msg, 72))
}

func (a *AbstractEbuildProcess)_unexpected_exit(){

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
	"are functioning properly.",phase)

	a._eerror(SplitSubN(msg, 72))
	}

func (a *AbstractEbuildProcess)_eerror( lines []string){
	a._elog("eerror", lines)
	}

func (a *AbstractEbuildProcess)_elog( elog_funcname, lines){
out := &bytes.Buffer{}
phase := a.phase
elog_func = getattr(elog_messages, elog_funcname)
global_havecolor := HaveColor
//try{
	HaveColor =
a.settings.Valuedict["NOCOLOR", "false").lower() in ("no", "false")
for _, line := range lines{
	elog_func(line, phase = phase, key =a.settings.mycpv, out = out)
	}
//finally{
	HaveColor = global_havecolor
msg := out.String()
if msg!= ""{
log_path = nil
if a.settings.Valuedict["PORTAGE_BACKGROUND"] != "subprocess"{
log_path = a.settings.Valuedict["PORTAGE_LOG_FILE"]
	}
a.scheduler.output(msg, log_path=log_path)
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

func (e *EbuildSpawnProcess)_spawn( args, **kwargs){

env := e.settings.environ()

if e._dummy_pipe_fd != 0 {
	env["PORTAGE_PIPE_FD"] = fmt.Sprint(e._dummy_pipe_fd)
}

	return e.spawn_func(args, env = env, **kwargs)
}

type BlockerDB struct{
	_vartree *varTree
	_portdb *portdbapi
	_dep_check_trees map[string]map[string] interface{}
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
	b._dep_check_trees =map[string]map[string] interface{}{b._vartree.settings.ValueDict["EROOT"]:
		{
			"porttree"    :  fake_vartree,
			"vartree"     :  fake_vartree,
		},
	}
	return b
}

func (b *BlockerDB)findInstalledBlockers( new_pkg){
blocker_cache := BlockerCache(nil,
b._vartree.dbapi)
dep_keys := NewPackage()._runtime_keys
settings := b._vartree.settings
stale_cache := set(blocker_cache)
fake_vartree := b._fake_vartree
dep_check_trees := b._dep_check_trees
vardb := fake_vartree.dbapi
installed_pkgs := list(vardb)

for _, inst_pkg := range installed_pkgs{
stale_cache.discard(inst_pkg.cpv)
cached_blockers := blocker_cache.get(inst_pkg.cpv)
if cached_blockers != nil &&
cached_blockers.counter != inst_pkg.counter{
		cached_blockers = nil
		}
if cached_blockers != nil{
blocker_atoms = cached_blockers.atoms
}else{
depstr := strings.Join(vardb.aux_get(inst_pkg.cpv, dep_keys), " ")
success, atoms := portage.dep_check(depstr,
vardb, settings, myuse=inst_pkg.use.enabled,
trees=dep_check_trees, myroot=inst_pkg.root)
if not success{
pkg_location := filepath.Join(inst_pkg.root,
VdbPath, inst_pkg.category, inst_pkg.pf)
WriteMsg(fmt.Sprintf("!!! %s/*DEPEND: %s\n" ,
pkg_location, atoms), -1, nil)
continue

blocker_atoms :=
	[atom for atom in atoms
if atom.startswith("!")]
blocker_atoms.sort()
blocker_cache[inst_pkg.cpv] =
blocker_cache.BlockerData(inst_pkg.counter, blocker_atoms)
for cpv in stale_cache{
del blocker_cache[cpv]
blocker_cache.flush()

blocker_parents = digraph()
blocker_atoms = []
for pkg in installed_pkgs{
for blocker_atom in blocker_cache[pkg.cpv].atoms{
blocker_atom = blocker_atom.lstrip("!")
blocker_atoms.append(blocker_atom)
blocker_parents.add(blocker_atom, pkg)

blocker_atoms = InternalPackageSet(initial_atoms=blocker_atoms)
blocking_pkgs = set()
for atom in blocker_atoms.iterAtomsForPackage(new_pkg){
blocking_pkgs.update(blocker_parents.parent_nodes(atom))

depstr = " ".join(new_pkg._metadata[k] for k in dep_keys)
success, atoms = portage.dep_check(depstr,
vardb, settings, myuse=new_pkg.use.enabled,
trees=dep_check_trees, myroot=new_pkg.root)
if not success{
show_invalid_depstring_notice(new_pkg, atoms)
assert false

blocker_atoms = [atom.lstrip("!") for atom in atoms 
if atom[:1] == "!"]
if blocker_atoms{
blocker_atoms = InternalPackageSet(initial_atoms=blocker_atoms)
for inst_pkg in installed_pkgs{
try{
next(blocker_atoms.iterAtomsForPackage(inst_pkg))
except (portage.exception.InvalidDependString, StopIteration){
continue
blocking_pkgs.add(inst_pkg)

return blocking_pkgs

func (b *BlockerDB)discardBlocker( pkg){
for cpv_match in b._fake_vartree.dbapi.match_pkgs(Atom(fmt.Sprintf("=%s" % (pkg.cpv,))){
if cpv_match.cp == pkg.cp{
b._fake_vartree.cpv_discard(cpv_match)
for slot_match in b._fake_vartree.dbapi.match_pkgs(pkg.slot_atom){
if slot_match.cp == pkg.cp{
b._fake_vartree.cpv_discard(slot_match)


type CompositeTask struct {
	*AsynchronousTask
	
	// slot
	_current_task string

	_TASK_QUEUED int
	}

	func NewCompositeTask()*CompositeTask {
	c :=&CompositeTask{}
	c._TASK_QUEUED = -1
	return c
	}

	func (c*CompositeTask)_cancel():
	if c._current_task != nil:
	if c._current_task is c._TASK_QUEUED:
	c.returncode = 1
	c._current_task = nil
	c._async_wait()
	}else{
	c._current_task.cancel()
	}else if c.returncode == nil:
	c._was_cancelled()
	c._async_wait()

	func(c*CompositeTask) _poll():


	prev = nil
	while true:
	task = c._current_task
	if task == nil or 
	task is c._TASK_QUEUED or 
	task is prev:
	break
	task.poll()
	prev = task

	return c.returncode

	func(c*CompositeTask) _assert_current(, task):
	if task != c._current_task:
	raise AssertionError("Unrecognized task: %s" % (task,))

	func(c*CompositeTask) _default_exit( task):
	c._assert_current(task)
	if task.returncode != os.EX_OK:
	c.returncode = task.returncode
	c.cancelled = task.cancelled
	c._current_task = nil
	return task.returncode

	func(c*CompositeTask) _final_exit( task):
	c._default_exit(task)
	c._current_task = nil
	c.returncode = task.returncode
	return c.returncode

	func(c*CompositeTask) _default_final_exit( task):
	c._final_exit(task)
	return c.wait()

	func(c*CompositeTask) _start_task( task, exit_handler):
	try:
	task.scheduler = c.scheduler
	except AttributeError:
	pass
	task.addExitListener(exit_handler)
	c._current_task = task
	task.start()

	func(c*CompositeTask) _task_queued( task):
	task.addStartListener(c._task_queued_start_handler)
	c._current_task = c._TASK_QUEUED

	func(c*CompositeTask) _task_queued_start_handler( task):
	c._current_task = task

	func(c*CompositeTask) _task_queued_wait():
	return c._current_task != c._TASK_QUEUED or
	c.cancelled or c.returncode != nil


	type EbuildPhase struct {
	*CompositeTask
	
	// slot
	actionmap,fd_pipes,phase,settings, _ebuild_lock string


	_features_display []string
	_locked_phases []string
	}

	func NewEbuildPhase() *EbuildPhase {
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
	return e
	}

	func (e *EbuildPhase) _start(){

	need_builddir = e.phase not in EbuildProcess._phases_without_builddir

	if need_builddir{
	phase_completed_file =
	} filepath.Join(
	e.settings.ValueDict['PORTAGE_BUILDDIR'],
	".%sed" % e.phase.rstrip('e'))
	if not os.path.exists(phase_completed_file){
	
	
	
	try{
	syscall.Unlink(filepath.Join(e.settings.ValueDict['T'],
	'logging', e.phase))
	except OSError{
	pass

	if e.phase in ('nofetch', 'pretend', 'setup'){

	use = e.settings.ValueDict['PORTAGE_BUILT_USE')
	if use == nil{
	use = e.settings.ValueDict['PORTAGE_USE']

	maint_str = ""
	upstr_str = ""
	metadata_xml_path = filepath.Join(os.path.dirname(e.settings.ValueDict['EBUILD']), "metadata.xml")
	if MetaDataXML !=
	} nil && os.path.isfile(metadata_xml_path){
herds_path = filepath.Join(e.settings.ValueDict['PORTDIR'],
'metadata/herds.xml')
try{
metadata_xml = MetaDataXML(metadata_xml_path, herds_path)
maint_str = metadata_xml.format_maintainer_string()
upstr_str = metadata_xml.format_upstream_string()
except SyntaxError{
maint_str = "<invalid metadata.xml>"

msg = []
msg.append("Package:    %s" % e.settings.mycpv)
if e.settings.ValueDict['PORTAGE_REPO_NAME'){
msg.append("Repository: %s" % e.settings.ValueDict['PORTAGE_REPO_NAME'])
if maint_str{
msg.append("Maintainer: %s" % maint_str)
if upstr_str{
msg.append("Upstream:   %s" % upstr_str)

msg.append("USE:        %s" % use)
relevant_features = []
enabled_features = e.settings.features
for x in e._features_display{
if x in enabled_features{
relevant_features.append(x)
if relevant_features{
msg.append("FEATURES:   %s" % " ".join(relevant_features))

e._elog('einfo', msg, background=true)

if e.phase == 'package'{
if 'PORTAGE_BINPKG_TMPFILE' not in e.settings{
e.settings.ValueDict['PORTAGE_BINPKG_TMPFILE'] = 
filepath.Join(e.settings.ValueDict['PKGDIR'],
e.settings.ValueDict['CATEGORY'], e.settings.ValueDict['PF']) + '.tbz2'

if e.phase in ("pretend", "prerm"){
env_extractor = BinpkgEnvExtractor(background=e.background,
scheduler=e.scheduler, settings=e.settings)
if env_extractor.saved_env_exists(){
e._start_task(env_extractor, e._env_extractor_exit)
return

e._start_lock()

	func (e *EbuildPhase) _env_extractor_exit( env_extractor){
if e._default_exit(env_extractor) != os.EX_OK{
e.wait()
return

e._start_lock()

func (e *EbuildPhase) _start_lock(){
if (e.phase in e._locked_phases &&
"ebuild-locks" in e.settings.features){
eroot = e.settings.ValueDict["EROOT"]
lock_path = filepath.Join(eroot, portage.VDB_PATH + "-ebuild")
if os.access(os.path.dirname(lock_path), os.W_OK){
e._ebuild_lock = AsynchronousLock(path=lock_path,
scheduler=e.scheduler)
e._start_task(e._ebuild_lock, e._lock_exit)
return

e._start_ebuild()

	func (e *EbuildPhase) _lock_exit( ebuild_lock){
if e._default_exit(ebuild_lock) != os.EX_OK{
e.wait()
return
e._start_ebuild()

func (e *EbuildPhase) _get_log_path(){
logfile = nil
if e.phase not in ("clean", "cleanrm") && 
e.settings.ValueDict["PORTAGE_BACKGROUND") != "subprocess"{
logfile = e.settings.ValueDict["PORTAGE_LOG_FILE")
return logfile

	func (e *EbuildPhase) _start_ebuild(){
if e.phase == "package"{
e._start_task(PackagePhase(actionmap=e.actionmap,
background=e.background, fd_pipes=e.fd_pipes,
logfile=e._get_log_path(), scheduler=e.scheduler,
settings=e.settings), e._ebuild_exit)
return

if e.phase == "unpack"{
alist = e.settings.configdict["pkg"].get("A", "").split()
	_prepare_fake_distdir(e.settings, alist)
	_prepare_fake_filesdir(e.settings)

	fd_pipes = e.fd_pipes
	if fd_pipes == nil{
	if not e.background && e.phase == 'nofetch'{
	
	
	fd_pipes = {1 : sys.__stderr__.fileno()}

	ebuild_process = EbuildProcess(actionmap=e.actionmap,
	background=e.background, fd_pipes=fd_pipes,
	logfile=e._get_log_path(), phase=e.phase,
	scheduler=e.scheduler, settings=e.settings)

	e._start_task(ebuild_process, e._ebuild_exit)

	func (e *EbuildPhase) _ebuild_exit( ebuild_process){
	e._assert_current(ebuild_process)
	if e._ebuild_lock == nil{
	e._ebuild_exit_unlocked(ebuild_process)
	}else{
	e._start_task(
	AsyncTaskFuture(future=e._ebuild_lock.async_unlock()),
	functools.partial(e._ebuild_exit_unlocked, ebuild_process))

	func (e *EbuildPhase) _ebuild_exit_unlocked( ebuild_process, unlock_task=nil){
	if unlock_task != nil{
	e._assert_current(unlock_task)
	if unlock_task.cancelled{
	e._default_final_exit(unlock_task)
	return

	
	unlock_task.future.result()

	fail = false
	if ebuild_process.returncode != os.EX_OK{
	e.returncode = ebuild_process.returncode
	if e.phase == "test" && 
	"test-fail-continue" in e.settings.features{
	
	try{
	open(_unicode_encode(filepath.Join(
	e.settings.ValueDict["PORTAGE_BUILDDIR"], ".tested"),
	encoding=_encodings['fs'], errors='strict'),
	'wb').close()
	except OSError{
	pass
	}else{
	fail = true

	if not fail{
	e.returncode = nil

	logfile = e._get_log_path()

	if e.phase == "install"{
	out = io.StringIO()
	_check_build_log(e.settings, out=out)
	msg = out.getvalue()
	e.scheduler.output(msg, log_path=logfile)

	if fail{
	e._die_hooks()
	return

	settings = e.settings
	_post_phase_userpriv_perms(settings)

	if e.phase == "unpack"{
	os.utime(settings.ValueDict["WORKDIR"], nil)
	_prepare_workdir(settings)
	}else if e.phase == "install"{
	out = io.StringIO()
	_post_src_install_write_metadata(settings)
	_post_src_install_uid_fix(settings, out)
	msg = out.getvalue()
	if msg{
	e.scheduler.output(msg, log_path=logfile)
	}else if e.phase == "preinst"{
	_preinst_bsdflags(settings)
	}else if e.phase == "postinst"{
	_postinst_bsdflags(settings)

	post_phase_cmds = _post_phase_cmds.get(e.phase)
	if post_phase_cmds != nil{
	if logfile != nil && e.phase in ("install",){
	
	
	
	
	fd, logfile = tempfile.mkstemp()
	os.close(fd)
	post_phase = _PostPhaseCommands(background=e.background,
	commands=post_phase_cmds, elog=e._elog, fd_pipes=e.fd_pipes,
	logfile=logfile, phase=e.phase, scheduler=e.scheduler,
	settings=settings)
	e._start_task(post_phase, e._post_phase_exit)
	return

	e.returncode = os.EX_OK
	e._current_task = nil
	e.wait()

	func (e *EbuildPhase) _post_phase_exit( post_phase){

	e._assert_current(post_phase)

	log_path = nil
	if e.settings.ValueDict["PORTAGE_BACKGROUND") != "subprocess"{
	log_path = e.settings.ValueDict["PORTAGE_LOG_FILE")

	if post_phase.logfile != nil && 
	post_phase.logfile != log_path{
	
	
	e._append_temp_log(post_phase.logfile, log_path)

	if e._final_exit(post_phase) != os.EX_OK{
	atom.WriteMsg("!!! post %s failed; exiting.\n" , e.phase),
	-1, nil)
	e._die_hooks()
	return

	e._current_task = nil
	e.wait()
	return

	func (e *EbuildPhase) _append_temp_log( temp_log, log_path){

	temp_file = open(_unicode_encode(temp_log,
	encoding=_encodings['fs'], errors='strict'), 'rb')

	log_file, log_file_real = e._open_log(log_path)

	for line in temp_file{
	log_file.write(line)

	temp_file.close()
	log_file.close()
	if log_file_real != log_file{
	log_file_real.close()
	syscall.Unlink(temp_log)

	func (e *EbuildPhase) _open_log( log_path){

	f = open(_unicode_encode(log_path,
	encoding=_encodings['fs'], errors='strict'),
	mode='ab')
	f_real = f

	if log_path.endswith('.gz'){
	f =  gzip.GzipFile(filename='', mode='ab', fileobj=f)

	return (f, f_real)

	func (e *EbuildPhase) _die_hooks(){
	e.returncode = nil
	phase = 'die_hooks'
	die_hooks = MiscFunctionsProcess(background=e.background,
	commands=[phase], phase=phase, logfile=e._get_log_path(),
	fd_pipes=e.fd_pipes, scheduler=e.scheduler,
	settings=e.settings)
	e._start_task(die_hooks, e._die_hooks_exit)

	func (e *EbuildPhase) _die_hooks_exit( die_hooks){
	if e.phase != 'clean' && 
	'noclean' not in e.settings.features && 
	'fail-clean' in e.settings.features{
	e._default_exit(die_hooks)
	e._fail_clean()
	return
	e._final_exit(die_hooks)
	e.returncode = 1
	e.wait()

	func (e *EbuildPhase) _fail_clean(){
	e.returncode = nil
	portage.elog.elog_process(e.settings.mycpv, e.settings)
	phase = "clean"
	clean_phase = EbuildPhase(background=e.background,
	fd_pipes=e.fd_pipes, phase=phase, scheduler=e.scheduler,
	settings=e.settings)
	e._start_task(clean_phase, e._fail_clean_exit)
	return

	func (e *EbuildPhase) _fail_clean_exit( clean_phase){
	e._final_exit(clean_phase)
	e.returncode = 1
	e.wait()

	func (e *EbuildPhase) _elog( elog_funcname, lines, background=nil){
	if background == nil{
	background = e.background
	out = io.StringIO()
	phase = e.phase
	elog_func = getattr(elog_messages, elog_funcname)
	global_havecolor = portage.output.havecolor
	try{
	portage.output.havecolor = 
	e.settings.ValueDict['NOCOLOR', 'false').lower() in ('no', 'false')
	for line in lines{
	elog_func(line, phase=phase, key=e.settings.mycpv, out=out)
	finally{
	portage.output.havecolor = global_havecolor
	msg = out.getvalue()
	if msg{
	log_path = nil
	if e.settings.ValueDict["PORTAGE_BACKGROUND") != "subprocess"{
	log_path = e.settings.ValueDict["PORTAGE_LOG_FILE")
	e.scheduler.output(msg, log_path=log_path,
	background=background)


	type _PostPhaseCommands sturct{
	*CompositeTask
	
	// slots
	commands,elog,fd_pipes,logfile,phase,settings string
	}
	
	func(p*_PostPhaseCommands) _start(){
	if isinstance(p.commands, list){
	cmds = [({}, p.commands)]
	}else{
	cmds = list(p.commands)

	if 'selinux' not in p.settings.features{
	cmds = [(kwargs, commands) for kwargs, commands in
	cmds if not kwargs.get('selinux_only'
	})]

	tasks = TaskSequence()
	for kwargs, commands in cmds{
	
	kwargs = dict((k, v) for k, v in kwargs.items()
	if k in ('ld_preload_sandbox',))
	tasks.add(MiscFunctionsProcess(background=p.background,
	commands=commands, fd_pipes=p.fd_pipes,
	logfile=p.logfile, phase=p.phase,
	scheduler=p.scheduler, settings=p.settings, **kwargs))

	p._start_task(tasks, p._commands_exit)

	func(p*_PostPhaseCommands) _commands_exit( task){

	if p._default_exit(task) != os.EX_OK{
	p._async_wait()
	return

	if p.phase == 'install'{
	out = io.StringIO()
	_post_src_install_soname_symlinks(p.settings, out)
	msg = out.getvalue()
	if msg{
	p.scheduler.output(msg, log_path=p.settings.ValueDict["PORTAGE_LOG_FILE"))

	if 'qa-unresolved-soname-deps' in p.settings.features{
	
	future = p._soname_deps_qa()
	
	future.add_done_callback(lambda future: future.cancelled() or future.result())
	p._start_task(AsyncTaskFuture(future=future), p._default_final_exit)
	}else{
	p._default_final_exit(task)
	}else{
	p._default_final_exit(task)

	@coroutine
	func(p*_PostPhaseCommands) _soname_deps_qa(){

	vardb = QueryCommand.get_db()[p.settings.ValueDict['EROOT']]['vartree'].dbapi

	all_provides = (yield p.scheduler.run_in_executor(ForkExecutor(loop=p.scheduler), _get_all_provides, vardb))

	unresolved = _get_unresolved_soname_deps(filepath.Join(p.settings.ValueDict['PORTAGE_BUILDDIR'], 'build-info'), all_provides)

	if unresolved{
	unresolved.sort()
	qa_msg = ["QA Notice: Unresolved soname dependencies:"]
	qa_msg.append("")
	qa_msg.extend("\t%s: %s" % (filename, " ".join(sorted(soname_deps)))
	for filename, soname_deps in unresolved)
	qa_msg.append("")
	p.elog("eqawarn", qa_msg)
