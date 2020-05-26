package atom

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
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
waiter.add_done_callback(func (waiter) {a.removeExitListener(exit_listener) if waiter.cancelled() else None}
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
			raise asyncio.InvalidStateError('Result is not ready for %s' % (a, ))
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

func (a *AbstractPollTask) _read_array( f){
buf = array.array('B')
try:
buf.fromfile(f, a._bufsize)
except EOFError:
pass
except TypeError:
pass
except IOError as e:
if e.errno == errno.EIO:
pass
elif e.errno == errno.EAGAIN:
buf = None
else:
raise

if buf is not None:
try:
buf = buf.tobytes()
except AttributeError:
buf = buf.tostring()

return buf
}

func (a *AbstractPollTask) _read_buf( fd io.Reader)[]byte{
	buf := make([]byte, a._bufsize)
	_, err := fd.Read(buf)
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

	func (a *AbstractPollTask)  _wait_loop( timeout=None){
loop := a.scheduler
tasks := []{a.async_wait()}
if timeout is not None{
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
	_dummy_pipe_fd,_files string
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

func (s *SubProcess) _unregister(){
s._registered = false
if s._waitpid_id != 0 {
	s.scheduler._asyncio_child_watcher.remove_child_handler(s._waitpid_id)
	s._waitpid_id = 0
}

if s._files != nil {
	for f in s._files.values(){
		if isinstance(f, int):
		os.close(f)
		else:
		f.close()
	}
	s._files = None
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

	args, env, opt_name,
	uid, gid, groups, umask, logfile,
	path_lookup, pre_exec, close_fds, cgroup,
	unshare_ipc, unshare_mount, unshare_pid, unshare_net,
	_pipe_logger, _selinux_type string
	fd_pipes map[int]string
}

var _spawn_kwarg_names = []string{"env", "opt_name", "fd_pipes",
"uid", "gid", "groups", "umask", "logfile",
"path_lookup", "pre_exec", "close_fds", "cgroup",
"unshare_ipc", "unshare_mount", "unshare_pid", "unshare_net"}

__slots__ = ("args",) +
_spawn_kwarg_names + ("_pipe_logger", "_selinux_type",)

func(s *SpawnProcess) _start(){
	if s.fd_pipes == nil{
		s.fd_pipes ={}
	}else {
		s.fd_pipes = s.fd_pipes.copy()
	}
	fd_pipes := s.fd_pipes

	master_fd, slave_fd := s._pipe(fd_pipes)

	can_log := s._can_log(slave_fd)
	log_file_path := s.logfile
	if !can_log{
		log_file_path = ""
	}

	null_input = None
	if _, ok := fd_pipes[0]; ! s.background|| ok {
		//pass
	}else{
		null_input, _ := os.Open("/dev/null", os.O_RDWR)
		fd_pipes[0] = null_input
	}

	if _, ok := fd_pipes[0]; !ok {
		fd_pipes[0] = getStdin().Fd()
	}
	if _, ok := fd_pipes[1]; !ok {
		fd_pipes[1] = os.Stdout.Fd()
	}
	if _, ok := fd_pipes[2]; !ok {
		fd_pipes[2] = os.Stderr.Fd()
	}

	stdout_filenos = (sys.__stdout__.fileno(), sys.__stderr__.fileno())
	for _, fd := range fd_pipes{
		if fd in stdout_filenos{
			sys.__stdout__.flush()
			sys.__stderr__.flush()
			break
		}
	}

	fd_pipes_orig = fd_pipes.copy()

	if log_file_path != "" || s.background{
		fd_pipes[1] = slave_fd
		fd_pipes[2] = slave_fd
	}else{
		s._dummy_pipe_fd = slave_fd
		fd_pipes[slave_fd] = slave_fd
	}

	kwargs = {}
	for k in s._spawn_kwarg_names{
		v = getattr(s, k)
		if v is not None{
		kwargs[k] = v
	}
	}

	kwargs["fd_pipes"] = fd_pipes
	kwargs["returnpid"] = True
	kwargs.pop("logfile", None)

	retval = s._spawn(s.args, **kwargs)

	os.close(slave_fd)
	if null_input is not None:
	os.close(null_input)

	if isinstance(retval, int):
	s.returncode = retval
	s._async_wait()
	return

	s.pid = retval[0]

	stdout_fd = None
	if can_log and not s.background:
	stdout_fd = os.dup(fd_pipes_orig[1])
	if sys.hexversion < 0x3040000 and fcntl is not None:
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


func(s *SpawnProcess) _can_log( slave_fd)bool{
	return true
}

func(s *SpawnProcess) _pipe( fd_pipes){
	return os.pipe()
}

func(s *SpawnProcess) _spawn( args []string, **kwargs){
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

func(s *SpawnProcess) _pipe_logger_exit( pipe_logger){
	s._pipe_logger = None
	s._async_waitpid()
}

func(s *SpawnProcess) _unregister(){
	s.SubProcess._unregister()
	if s.cgroup is not None:
	s._cgroup_cleanup()
	s.cgroup = None
	if s._pipe_logger is not None:
	s._pipe_logger.cancel()
	s._pipe_logger = None
}

func(s *SpawnProcess) _cancel(){
	s.SubProcess._cancel()
	s._cgroup_cleanup()
}

func(s *SpawnProcess) _cgroup_cleanup(){
	if s.cgroup{
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
filepath.Join(s.cgroup, "cgroup.procs", strings.Join(pidss, " "))))


s._elog("eerror", msg)
	}

err:= os.RemoveAll(s.cgroup)
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

func(f *ForkProcess) _spawn( args, fd_pipes=None, **kwargs){
	parent_pid := os.Getpid()
	pid = None
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
	os.close(wakeup_fd)
	except (ValueError, OSError):
	pass

	_close_fds()
	portage.process._setup_pipes(fd_pipes, close_fds=False)

	rval = f._run()
	except SystemExit:
	raise
except:
	traceback.print_exc()
	sys.stderr.flush()
finally:
	os._exit(rval)

finally:
	if pid == 0 or (pid is None and os.getpid() != parent_pid):
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
	  prev_mtimes, unmerge, _elog_reader_fd, _buf   string
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
		m.fd_pipes = map[int]{}
	}else{
		m.fd_pipes = m.fd_pipes.copy()
	}
	if _, ok := m.fd_pipes[0]; !ok{
		m.fd_pipes[0]=getStdin().fileno()
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
		out = io.StringIO()
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
	os.close(m._elog_reader_fd)
	m._elog_reader_fd = None
	return false
}
return true
}

func(m *MergeProcess) _spawn( args, fd_pipes, **kwargs){
	elog_reader_fd, elog_writer_fd = os.pipe()

	fcntl.fcntl(elog_reader_fd, fcntl.F_SETFL,
		fcntl.fcntl(elog_reader_fd, fcntl.F_GETFL) | os.O_NONBLOCK)

	if sys.hexversion < 0x3040000:
try:
	fcntl.FD_CLOEXEC
	except AttributeError:
	pass
	else:
	fcntl.fcntl(elog_reader_fd, fcntl.F_SETFD,
		fcntl.fcntl(elog_reader_fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)

	blockers = None
	if m.blockers != nil {
		blockers = m.blockers()
	}
	mylink := NewDblink(m.mycat, m.mypkg, settings=m.settings,
		treetype=m.treetype, vartree=m.vartree,
		blockers=blockers, pipe=elog_writer_fd)
	fd_pipes[elog_writer_fd] = elog_writer_fd
	m.scheduler.add_reader(elog_reader_fd, m._elog_output_handler)

	m._lock_vdb()
	counter = None
	if ! m.unmerge{
		counter = m.vartree.dbapi.counter_tick()
	}

	parent_pid := os.Getpid()
	pid = None
try:
	pid = os.fork()

	if pid != 0{
		if not isinstance(pid, int):
		raise AssertionError(
			"fork returned non-integer: %s" % (repr(pid),))

		os.close(elog_writer_fd)
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

	os.close(elog_reader_fd)

	signal.signal(signal.SIGINT, signal.SIG_DFL)
	signal.signal(signal.SIGTERM, signal.SIG_DFL)

	signal.signal(signal.SIGCHLD, signal.SIG_DFL)
try:
	wakeup_fd := signal.set_wakeup_fd(-1)
	if wakeup_fd > 0{
		os.close(wakeup_fd)
	}
	except (ValueError, OSError):
	pass

	_close_fds()
	portage.process._setup_pipes(fd_pipes, close_fds=False)

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
			rval = os.EX_OK
		} else if mylink.unmerge(
			ldpath_mtimes=m.prev_mtimes) == syscall.F_OK{
			mylink.lockdb()
			try:
			mylink.delete()
			finally:
			mylink.unlockdb()
			rval = os.EX_OK
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
	os._exit(rval)

finally:
	if pid == 0 || (pid == 0 && os.Getpid() != parent_pid){
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
	if m._elog_reader_fd is not None{
		m.scheduler.remove_reader(m._elog_reader_fd)
		os.close(m._elog_reader_fd)
		m._elog_reader_fd = None
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
