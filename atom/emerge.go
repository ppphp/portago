package atom

import (
	"os"
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
exit_listener := func(a *AsynchronousTask) { return waiter.cancelled() || waiter.set_result(self.returncode)}
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
			raise asyncio.InvalidStateError('Result is not ready for %s' % (self, ))
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
	a._start_listeners.remove(f)
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
	handle := a._exit_listener_handles.pop(f, None)
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
		a._exit_listener_handles ={}
	}

		for _, listener := range listeners{
		if listener not in a._exit_listener_handles{
		a._exit_listener_handles[listener] = a.scheduler.call_soon(a._exit_listener_cb, listener)
	}
	}
	}
}

func (a *AsynchronousTask)  _exit_listener_cb( listener) {
	del a._exit_listener_handles[listener]
	listener(a)
}

func NewAsynchronousTask() *AsynchronousTask{
	a := &AsynchronousTask{}
	a._cancelled_returncode = int(-syscall.SIGINT)
	return a
}

type AbstractPollTask struct {
	*AsynchronousTask
	_registered string
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

func (a *AbstractPollTask) _read_buf( fd){
buf = None
try:
buf = os.read(fd, self._bufsize)
except OSError as e:
if e.errno == errno.EIO:
buf = b''
elif e.errno == errno.EAGAIN:
buf = None
else:
raise

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
loop = self.scheduler
tasks = [self.async_wait()]
if timeout is not None:
tasks.append(asyncio.ensure_future(
asyncio.sleep(timeout, loop=loop), loop=loop))
try:
loop.run_until_complete(asyncio.ensure_future(
asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED,
loop=loop), loop=loop))
finally:
for task in tasks:
task.cancel()
}

func NewAbstractPollTask() *AbstractPollTask{
	a := &AbstractPollTask{}
	a.AsynchronousTask = NewAsynchronousTask()
	a._bufsize = 4096
	return a
}

type SubProcess struct {
	*AbstractPollTask
	pid,_dummy_pipe_fd,_files, _waitpid_id string
	_cancel_timeout int
}

func (s *SubProcess) _poll() *int{
	return s.returncode
}

func (s *SubProcess) _cancel(){
if self.isAlive() and self.pid is not None:
try:
os.kill(self.pid, signal.SIGTERM)
except OSError as e:
if e.errno == errno.EPERM:
writemsg_level(
"!!! kill: (%i) - Operation not permitted\n" %
(self.pid,), level=logging.ERROR,
noiselevel=-1)
elif e.errno != errno.ESRCH:
raise
}

func (s *SubProcess) _async_wait(){
if self.returncode is None:
raise asyncio.InvalidStateError('Result is not ready for %s' % (self,))
else:
super(SubProcess, self)._async_wait()
}

func (s *SubProcess) _async_waitpid(){
if self.returncode is not None:
self._async_wait()
elif self._waitpid_id is None:
self._waitpid_id = self.pid
self.scheduler._asyncio_child_watcher.\
add_child_handler(self.pid, self._async_waitpid_cb)
}

func (s *SubProcess) _async_waitpid_cb( pid, returncode){
if pid != self.pid:
raise AssertionError("expected pid %s, got %s" % (self.pid, pid))
self.returncode = returncode
self._async_wait()
}

func (s *SubProcess) _orphan_process_warn(){
}

func (s *SubProcess) _unregister(){

self._registered = False

if self._waitpid_id is not None:
self.scheduler._asyncio_child_watcher.\
remove_child_handler(self._waitpid_id)
self._waitpid_id = None

if self._files is not None:
for f in self._files.values():
if isinstance(f, int):
os.close(f)
else:
f.close()
self._files = None
}

func NewSubProcess() *SubProcess {
	s := &SubProcess{}
	s._cancel_timeout = 1
	return s
}

type SpawnProcess struct {
	*SubProcess
}

_spawn_kwarg_names = ("env", "opt_name", "fd_pipes",
"uid", "gid", "groups", "umask", "logfile",
"path_lookup", "pre_exec", "close_fds", "cgroup",
"unshare_ipc", "unshare_mount", "unshare_pid", "unshare_net")

__slots__ = ("args",) + \
_spawn_kwarg_names + ("_pipe_logger", "_selinux_type",)

_CGROUP_CLEANUP_RETRY_MAX = 8

func(s *SpawnProcess) _start(self):

if self.fd_pipes is None:
self.fd_pipes = {}
else:
self.fd_pipes = self.fd_pipes.copy()
fd_pipes = self.fd_pipes

master_fd, slave_fd = self._pipe(fd_pipes)

can_log = self._can_log(slave_fd)
if can_log:
log_file_path = self.logfile
else:
log_file_path = None

null_input = None
if not self.background or 0 in fd_pipes:
pass
else:
null_input = os.open('/dev/null', os.O_RDWR)
fd_pipes[0] = null_input

fd_pipes.setdefault(0, portage._get_stdin().fileno())
fd_pipes.setdefault(1, sys.__stdout__.fileno())
fd_pipes.setdefault(2, sys.__stderr__.fileno())

stdout_filenos = (sys.__stdout__.fileno(), sys.__stderr__.fileno())
for fd in fd_pipes.values():
if fd in stdout_filenos:
sys.__stdout__.flush()
sys.__stderr__.flush()
break

fd_pipes_orig = fd_pipes.copy()

if log_file_path is not None or self.background:
fd_pipes[1] = slave_fd
fd_pipes[2] = slave_fd

else:
self._dummy_pipe_fd = slave_fd
fd_pipes[slave_fd] = slave_fd

kwargs = {}
for k in self._spawn_kwarg_names:
v = getattr(self, k)
if v is not None:
kwargs[k] = v

kwargs["fd_pipes"] = fd_pipes
kwargs["returnpid"] = True
kwargs.pop("logfile", None)

retval = self._spawn(self.args, **kwargs)

os.close(slave_fd)
if null_input is not None:
os.close(null_input)

if isinstance(retval, int):
self.returncode = retval
self._async_wait()
return

self.pid = retval[0]

stdout_fd = None
if can_log and not self.background:
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

self._pipe_logger = PipeLogger(background=self.background,
scheduler=self.scheduler, input_fd=master_fd,
log_file_path=log_file_path,
stdout_fd=stdout_fd)
self._pipe_logger.addExitListener(self._pipe_logger_exit)
self._pipe_logger.start()
self._registered = True

func(s *SpawnProcess) _can_log(self, slave_fd):
return True

func(s *SpawnProcess) _pipe(self, fd_pipes):
return os.pipe()

func(s *SpawnProcess) _spawn(self, args, **kwargs):
spawn_func = portage.process.spawn

if self._selinux_type is not None:
spawn_func = portage.selinux.spawn_wrapper(spawn_func,
self._selinux_type)
if args[0] != BASH_BINARY:
args = [BASH_BINARY, "-c", "exec \"$@\"", args[0]] + args

return spawn_func(args, **kwargs)

func(s *SpawnProcess) _pipe_logger_exit(self, pipe_logger):
self._pipe_logger = None
self._async_waitpid()

func(s *SpawnProcess) _unregister(self):
SubProcess._unregister(self)
if self.cgroup is not None:
self._cgroup_cleanup()
self.cgroup = None
if self._pipe_logger is not None:
self._pipe_logger.cancel()
self._pipe_logger = None

func(s *SpawnProcess) _cancel(self):
SubProcess._cancel(self)
self._cgroup_cleanup()

func(s *SpawnProcess) _cgroup_cleanup(self):
if self.cgroup:
def get_pids(cgroup):
try:
with open(os.path.join(cgroup, 'cgroup.procs'), 'r') as f:
return [int(p) for p in f.read().split()]
except EnvironmentError:
return []

func(s *SpawnProcess) kill_all(pids, sig):
for p in pids:
try:
os.kill(p, sig)
except OSError as e:
if e.errno == errno.EPERM:
writemsg_level(
"!!! kill: (%i) - Operation not permitted\n" %
(p,), level=logging.ERROR,
noiselevel=-1)
elif e.errno != errno.ESRCH:
raise

remaining = self._CGROUP_CLEANUP_RETRY_MAX
while remaining:
remaining -= 1
pids = get_pids(self.cgroup)
if pids:
kill_all(pids, signal.SIGKILL)
else:
break

if pids:
msg = []
msg.append(
_("Failed to kill pid(s) in '%(cgroup)s': %(pids)s") % dict(
cgroup=os.path.join(self.cgroup, 'cgroup.procs'),
pids=' '.join(str(pid) for pid in pids)))

self._elog('eerror', msg)

try:
os.rmdir(self.cgroup)
except OSError:
pass

func(s *SpawnProcess) _elog(self, elog_funcname, lines):
elog_func = getattr(EOutput(), elog_funcname)
for line in lines:
elog_func(line)

type ForkProcess struct {
	*SpawnProcess
}

__slots__ = ()

func(f *ForkProcess) _spawn(self, args, fd_pipes=None, **kwargs):

parent_pid = os.getpid()
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

portage.locks._close_fds()
portage.process._setup_pipes(fd_pipes, close_fds=False)

rval = self._run()
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

func(f *ForkProcess) _run(self):
raise NotImplementedError(self)

type MergeProcess struct {
	*ForkProcess
}

__slots__ = ('mycat', 'mypkg', 'settings', 'treetype',
'vartree', 'blockers', 'pkgloc', 'infloc', 'myebuild',
'mydbapi', 'postinst_failure', 'prev_mtimes', 'unmerge',
'_elog_reader_fd',
'_buf', '_elog_keys', '_locked_vdb')

func(m *MergeProcess)  _start(self):
cpv = "%s/%s" % (self.mycat, self.mypkg)
settings = self.settings
if cpv != settings.mycpv or \
"EAPI" not in settings.configdict["pkg"]:
settings.reload()
settings.reset()
settings.setcpv(cpv, mydb=self.mydbapi)

if platform.system() == "Linux" and \
"merge-sync" in settings.features:
find_library("c")

if self.fd_pipes is None:
self.fd_pipes = {}
else:
self.fd_pipes = self.fd_pipes.copy()
self.fd_pipes.setdefault(0, portage._get_stdin().fileno())

super(MergeProcess, self)._start()

func(m *MergeProcess) _lock_vdb(self):
if "parallel-install" not in self.settings.features:
self.vartree.dbapi.lock()
self._locked_vdb = True

func(m *MergeProcess) _unlock_vdb(self):
if self._locked_vdb:
self.vartree.dbapi.unlock()
self._locked_vdb = False

func(m *MergeProcess) _elog_output_handler(self):
output = self._read_buf(self._elog_reader_fd)
if output:
lines = _unicode_decode(output).split('\n')
if len(lines) == 1:
self._buf += lines[0]
else:
lines[0] = self._buf + lines[0]
self._buf = lines.pop()
out = io.StringIO()
for line in lines:
funcname, phase, key, msg = line.split(' ', 3)
self._elog_keys.add(key)
reporter = getattr(portage.elog.messages, funcname)
reporter(msg, phase=phase, key=key, out=out)

elif output is not None:
self.scheduler.remove_reader(self._elog_reader_fd)
os.close(self._elog_reader_fd)
self._elog_reader_fd = None
return False

func(m *MergeProcess) _spawn(self, args, fd_pipes, **kwargs):

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
if self.blockers is not None:
blockers = self.blockers()
mylink = portage.dblink(self.mycat, self.mypkg, settings=self.settings,
treetype=self.treetype, vartree=self.vartree,
blockers=blockers, pipe=elog_writer_fd)
fd_pipes[elog_writer_fd] = elog_writer_fd
self.scheduler.add_reader(elog_reader_fd, self._elog_output_handler)

self._lock_vdb()
counter = None
if not self.unmerge:
counter = self.vartree.dbapi.counter_tick()

parent_pid = os.getpid()
pid = None
try:
pid = os.fork()

if pid != 0:
if not isinstance(pid, int):
raise AssertionError(
"fork returned non-integer: %s" % (repr(pid),))

os.close(elog_writer_fd)
self._elog_reader_fd = elog_reader_fd
self._buf = ""
self._elog_keys = set()
portage.elog.messages.collect_messages(key=mylink.mycpv)

if self.vartree.dbapi._categories is not None:
self.vartree.dbapi._categories = None
self.vartree.dbapi._pkgs_changed = True
self.vartree.dbapi._clear_pkg_cache(mylink)

return [pid]

os.close(elog_reader_fd)

signal.signal(signal.SIGINT, signal.SIG_DFL)
signal.signal(signal.SIGTERM, signal.SIG_DFL)

signal.signal(signal.SIGCHLD, signal.SIG_DFL)
try:
wakeup_fd = signal.set_wakeup_fd(-1)
if wakeup_fd > 0:
os.close(wakeup_fd)
except (ValueError, OSError):
pass

portage.locks._close_fds()
portage.process._setup_pipes(fd_pipes, close_fds=False)

portage.output.havecolor = self.settings.get('NOCOLOR') \
not in ('yes', 'true')

self.vartree.dbapi._flush_cache_enabled = False

if not self.unmerge:
if self.settings.get("PORTAGE_BACKGROUND") == "1":
self.settings["PORTAGE_BACKGROUND_UNMERGE"] = "1"
else:
self.settings["PORTAGE_BACKGROUND_UNMERGE"] = "0"
self.settings.backup_changes("PORTAGE_BACKGROUND_UNMERGE")
self.settings["PORTAGE_BACKGROUND"] = "subprocess"
self.settings.backup_changes("PORTAGE_BACKGROUND")

rval = 1
try:
if self.unmerge:
if not mylink.exists():
rval = os.EX_OK
elif mylink.unmerge(
ldpath_mtimes=self.prev_mtimes) == os.EX_OK:
mylink.lockdb()
try:
mylink.delete()
finally:
mylink.unlockdb()
rval = os.EX_OK
else:
rval = mylink.merge(self.pkgloc, self.infloc,
myebuild=self.myebuild, mydbapi=self.mydbapi,
prev_mtimes=self.prev_mtimes, counter=counter)
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

func(m *MergeProcess) _async_waitpid_cb(self, *args, **kwargs):
ForkProcess._async_waitpid_cb(self, *args, **kwargs)
if self.returncode == portage.const.RETURNCODE_POSTINST_FAILURE:
self.postinst_failure = True
self.returncode = os.EX_OK

func(m *MergeProcess) _unregister(self):

if not self.unmerge:
try:
self.vartree.dbapi.aux_get(self.settings.mycpv, ["EAPI"])
except KeyError:
pass

self._unlock_vdb()
if self._elog_reader_fd is not None:
self.scheduler.remove_reader(self._elog_reader_fd)
os.close(self._elog_reader_fd)
self._elog_reader_fd = None
if self._elog_keys is not None:
for key in self._elog_keys:
portage.elog.elog_process(key, self.settings,
phasefilter=("prerm", "postrm"))
self._elog_keys = None

super(MergeProcess, self)._unregister()
