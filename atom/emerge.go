package atom

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	ogórek "github.com/kisielk/og-rek"
	"github.com/ppphp/shlex"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"math"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// my interface for python abstraction
type Starter interface {
	start()
}

type IFuture interface{
	done() bool
	cancel() bool
	add_done_callback(func(IFuture, error))
	cancelled() bool
	exception() error
	set_exception(error)
	result()
	set_result(interface{}) bool
}

type ITask interface{
	start()
}

// ------------------emerge begins

type DepPriorityInterface interface{
	__int__() int
}

type AbstractDepPriority struct {
	// slot
	buildtime bool
	buildtime_slot_op,runtime,runtime_post,runtime_slot_op string
}

func(a *AbstractDepPriority) __int__() int{
	return 0
}

func(a *AbstractDepPriority) __lt__( other DepPriorityInterface) bool {
	return a.__int__() < other.__int__()
}

func(a *AbstractDepPriority) __le__(other DepPriorityInterface) bool{
	return a.__int__() <= other.__int__()
}

func(a *AbstractDepPriority) __eq__(other DepPriorityInterface) bool{
	return a.__int__() == other.__int__()
}

func(a *AbstractDepPriority) __ne__(other DepPriorityInterface) bool{
	return a.__int__() != other.__int__()
}

func(a *AbstractDepPriority) __gt__(other DepPriorityInterface) bool{
	return a.__int__() > other.__int__()
}

func(a *AbstractDepPriority) __ge__(other DepPriorityInterface) bool{
	return a.__int__() >= other.__int__()
}

func(a *AbstractDepPriority) copy()DepPriorityInterface {
	b := *a
	return &b
}

func NewAbstractDepPriority() *AbstractDepPriority{
	a := &AbstractDepPriority{}
	return a
}

type AbstractEbuildProcess struct {
	*SpawnProcess
	// slot
	settings *Config
	phase, _build_dir_unlock, _exit_command, _exit_timeout_id, _start_future string
	_build_dir *EbuildBuildDir
	_ipc_daemon *EbuildIpcDaemon

	_phases_without_builddir []string
	_phases_interactive_whitelist []string
	_exit_timeout int
	_enable_ipc_daemon bool
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
				a._build_dir = NewEbuildBuildDir(a.scheduler, a.settings)
				a._start_future = a._build_dir.async_lock()
				a._start_future.add_done_callback(
					func (lock_future) {
						return a._start_post_builddir_lock(lock_future, start_ipc_daemon)
					})
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
func (a *AbstractEbuildProcess)_start_post_builddir_lock( lock_future IFuture , start_ipc_daemon bool) {
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
	input_fifo, output_fifo := a._init_ipc_fifos()
	a._ipc_daemon = NewEbuildIpcDaemon(commands,
		input_fifo,
		output_fifo,
		a.scheduler)
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

func (a *AbstractEbuildProcess)_elog( elog_funcname string, lines []string) {
	out := &bytes.Buffer{}
	phase := a.phase

	var elog_func func(string, string, string, io.Writer)
	switch elog_funcname {
	case "error":
		elog_func = eerror
	}

	global_havecolor := HaveColor
	//try{
	nc, ok := a.settings.ValueDict["NOCOLOR"]
	if !ok {
		HaveColor = 1
	} else if strings.ToLower(nc) == "no" || strings.ToLower(nc) == "false" {
		HaveColor = 0
	}
	for _, line := range lines {
		elog_func(line, phase, a.settings.mycpv.string, out)
	}
	//finally{
	HaveColor = global_havecolor
	msg := out.String()
	if msg != "" {
		log_path := ""
		if a.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
			log_path = a.settings.ValueDict["PORTAGE_LOG_FILE"]
		}
		a.scheduler.output(msg, log_path, false, 0, -1)
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
	a._build_dir_unlock.add_done_callback( func(t) {
		return a._unlock_builddir_exit(t, returncode)
	})
}

// nil
func (a *AbstractEbuildProcess)_unlock_builddir_exit( unlock_future IFuture, returncode *int) {
	//unlock_future.cancelled() || unlock_future.result()
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

func NewAbstractEbuildProcess(actionmap Actionmap, background bool, fd_pipes map[int]int, logfile, phase string, scheduler *SchedulerInterface, settings *Config, **kwargs)*AbstractEbuildProcess {
	a := &AbstractEbuildProcess{}
	a._phases_without_builddir = []string{"clean", "cleanrm", "depend", "help",}
	a._phases_interactive_whitelist = []string{"config",}
	a._exit_timeout = 10
	a._enable_ipc_daemon = true

	a.SpawnProcess = NewSpawnProcess(actionmap, background, env, fd_pipes, logfile, phase, scheduler, settings,**kwargs)
	if a.phase == "" {
		phase := a.settings.ValueDict["EBUILD_PHASE"]
		if phase == "" {
			phase = "other"
			a.phase = phase
		}
	}
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
	//if err == errno.EIO:
	//pass
	//else if err == errno.EAGAIN:
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
func (a *AbstractPollTask) _wait_loop(timeout) {
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
	a._bufsize = 4096
	a.AsynchronousTask = NewAsynchronousTask()
	return a
}

type AsynchronousLock struct {
	*AsynchronousTask
	_use_process_by_default bool
	// slot
	_imp *LockFileS
	_unlock_future IFuture
	path,_force_async,_force_dummy,_force_process,_force_thread string
}

func(a *AsynchronousLock) _start() {

	if ! a._force_async {
		var err error
		a._imp, err = Lockfile(a.path, true, false, "", syscall.O_NONBLOCK)
		if err != nil {
			//except TryAgain:
			//pass
		}else {
			i := 0
			a.returncode = &i
			a._async_wait()
			return
		}
	}

	if a._force_process || (!a._force_thread &&
	(a._use_process_by_default ||threading
	is
	dummy_threading)){
	a._imp = NewLockProcess( a.path, a.scheduler)
	}else{
	a._imp = NewLockThread(a.path,a.scheduler, a._force_dummy)
	}

	a._imp.addExitListener(a._imp_exit)
	a._imp.start()
}

func(a *AsynchronousLock) _imp_exit(imp) {
	a.returncode = imp.returncode
	a._async_wait()
}

func(a *AsynchronousLock) _cancel() {
	if b, ok := a._imp.(*AsynchronousTask); ok {
		b.cancel()
	}
}

func(a *AsynchronousLock) _poll() *int {
	if b, ok := a._imp.(*AsynchronousTask); ok {
		b.poll()
	}
	return a.returncode
}

func(a *AsynchronousLock) async_unlock() IFuture {
	if a._imp == nil {
		raise
		AssertionError('not locked')
	}
	if a._unlock_future != nil {
		raise
		AssertionError("already unlocked")
	}

	var unlock_future IFuture
	if isinstance(a._imp, (_LockProcess, _LockThread)){
		unlock_future = a._imp.async_unlock()
	}else{
		Unlockfile(a._imp)
		unlock_future = a.scheduler.create_future()
		a.scheduler.call_soon(func(){unlock_future.set_result(nil)})
	}
	a._imp = nil
	a._unlock_future = unlock_future
	return unlock_future
}

func NewAsynchronousLock(path string, scheduler *SchedulerInterface)*AsynchronousLock{
	a :=&AsynchronousLock{}
	a._use_process_by_default = true
	a.AsynchronousTask = NewAsynchronousTask()
	a.path = path
	a.scheduler = scheduler

	return a
}

type _LockThread struct {
	*AbstractPollTask
	path,_force_dummy,_thread,_unlock_future string
	_lock_obj *LockFileS
}

func(l *_LockThread) _start() {
	l._registered = true
	threading_mod := threading
	if l._force_dummy {
		threading_mod = dummy_threading
	}
	l._thread = threading_mod.Thread(target = l._run_lock)
	l._thread.daemon = true
	l._thread.start()
}

func(l *_LockThread) _run_lock() {
	l._lock_obj, _ = Lockfile(l.path, true, false, "", 0)
	l.scheduler.call_soon_threadsafe(l._run_lock_cb)
}

func(l *_LockThread) _run_lock_cb() {
	l._unregister()
	i := 0
	l.returncode = &i
	l._async_wait()
}

func(l *_LockThread) _cancel() {
	//pass
}

func(l *_LockThread) _unlock() {
	if l._lock_obj == nil {
		raise
		AssertionError('not locked')
	}
	if l.returncode == nil {
		raise
		AssertionError('lock not acquired yet')
	}
	if l._unlock_future != nil {
		raise
		AssertionError("already unlocked")
	}
	l._unlock_future = l.scheduler.create_future()
	Unlockfile(l._lock_obj)
	l._lock_obj = nil
}

func(l *_LockThread) async_unlock() {
	l._unlock()
	l.scheduler.call_soon(l._unlock_future.set_result, nil)
	return l._unlock_future
}

func(l *_LockThread) _unregister() {
	l._registered = false

	if l._thread != nil {
		l._thread.join()
		l._thread = nil
	}
}

func NewLockThread(path string, scheduler *SchedulerInterface, force_dummy)*_LockThread{
	l := &_LockThread{}
	l.AbstractPollTask = NewAbstractPollTask()
	l.path=path
	l.scheduler=scheduler
	l._force_dummy = force_dummy
	return l
}

type _LockProcess struct {
	*AbstractPollTask
	//slot
	_proc *SpawnProcess
	path,_kill_test string
	_acquired bool
	_files map[string]int
	_unlock_future IFuture
}

func(l *_LockProcess) _start() {
	in2 := make([]int, 2)
	syscall.Pipe(in2)
	in_pr, in_pw :=in2[0],in2[1]
	out2 := make([]int, 2)
	syscall.Pipe(out2)
	out_pr, out_pw := out2[0], out2[1]
	l._files =map[string]int{}
	l._files["pipe_in"] = in_pr
	l._files["pipe_out"] = out_pw

	ar , _ := unix.FcntlInt(in_pr, unix.F_GETFL)|syscall.O_NONBLOCK)
	unix.FcntlInt(in_pr, unix.F_SETFL, ar)

	fcntl.fcntl(in_pr, fcntl.F_SETFL,
		fcntl.fcntl(in_pr, fcntl.F_GETFL)|os.O_NONBLOCK)

	if sys.hexversion < 0x3040000:
try:
	fcntl.FD_CLOEXEC
	except
AttributeError:
	pass
	else:
	fcntl.fcntl(in_pr, fcntl.F_SETFD,
		fcntl.fcntl(in_pr, fcntl.F_GETFD)|fcntl.FD_CLOEXEC)

	l.scheduler.add_reader(in_pr, l._output_handler)
	l._registered = true
	ev := ExpandEnv()
	ev["PORTAGE_PYM_PATH"]=portage._pym_path
	l._proc = NewSpawnProcess([]string{portage._python_interpreter,
		filepath.Join(portage._bin_path, "lock-helper.py"), l.path},false,
		ev, map[int]int{0:out_pr, 1:in_pw, 2:syscall.Stderr}, l.scheduler, "")
l._proc.addExitListener(l._proc_exit)
l._proc.start()
syscall.Close(out_pr)
syscall.Close(in_pw)
}

func(l *_LockProcess) _proc_exit(proc) {

	if l._files != nil {
		pipe_out, ok := l._files["pipe_out"]
		delete(l._files, "pipe_out")
		if !ok {
			//except KeyError:
			//pass
		} else {
			syscall.Close(pipe_out)
		}
	}

	if proc.returncode != 0 {
		if !l._acquire {
			if !(l.cancelled || l._kill_test) {
				WriteMsgLevel(fmt.Sprintf("_LockProcess: %s\n",
					fmt.Sprintf("failed to acquire lock on '%s'", l.path, )),
					40, -1)
			}
			l._unregister()
			l.returncode = proc.returncode
			l._async_wait()
			return
		}

		if !l.cancelled && l._unlock_future == nil {
			//raise AssertionError("lock process failed with returncode %s"
			//% (proc.returncode,))
		}
	}

	if l._unlock_future != nil {
		l._unlock_future.set_result(nil)
	}
}

func(l *_LockProcess) _cancel() {
	if l._proc != nil {
		l._proc.cancel()
	}
}

func(l *_LockProcess) _poll() *int {
	if l._proc != nil {
		l._proc.poll()
	}
	return l.returncode
}

func(l *_LockProcess) _output_handler() bool{
	buf := l._read_buf(l._files["pipe_in"])
	if len(buf) > 0 {
		l._acquired = true
		l._unregister()
		i := 0
		l.returncode = &i
		l._async_wait()
	}

	return true
}

func(l *_LockProcess) _unregister() {
	l._registered = false

	if l._files != nil {
		pipe_in, ok := l._files["pipe_in"]
		if !ok {
			//except KeyError:
			//pass
		} else {
			delete(l._files, "pipe_in")
			l.scheduler.remove_reader(pipe_in)
			syscall.Close(pipe_in)
		}
	}
}

func(l *_LockProcess) _unlock() {
	if l._proc == nil {
		//raise AssertionError('not locked')
	}
	if !l._acquired {
		//raise AssertionError('lock not acquired yet')
	}
	if l.returncode != nil && *l.returncode != 0 {
		//raise AssertionError("lock process failed with returncode %s"% (l.returncode,))
	}
	if l._unlock_future != nil {
		//raise AssertionError("already unlocked")
	}
	l._unlock_future = l.scheduler.create_future()
	syscall.Write(l._files["pipe_out"], []byte{0})
	syscall.Close(l._files["pipe_out"])
	l._files = nil
}

func(l *_LockProcess) async_unlock() {
	l._unlock()
	return l._unlock_future
}

func NewLockProcess(path string, scheduler *SchedulerInterface) *_LockProcess{
	l := &_LockProcess{}
	l.AbstractPollTask = NewAbstractPollTask()
	l.path=path
	l.scheduler=scheduler
	return l
}

type AsynchronousTask struct {
	background                                                bool
	scheduler                                                 *SchedulerInterface
	_start_listeners,_exit_listener_handles []func(*AsynchronousTask)
	_exit_listeners string
	_cancelled_returncode                                     int
	returncode                                                *int
	cancelled                                                 bool
}

func (a *AsynchronousTask) start() {
	a._start_hook()
	a._start()
}

func (a *AsynchronousTask)  async_wait() IFuture {
	waiter := a.scheduler.create_future()
	exit_listener := func(a *AsynchronousTask) bool { return waiter.cancelled() || waiter.set_result(a.returncode) }
	a.addExitListener(exit_listener)
	waiter.add_done_callback(func(waiter IFuture, err error)  {
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

func (a *AsynchronousTask)  wait() int {
	if a.returncode == nil {
		if a.scheduler.is_running() {
			raise asyncio.InvalidStateError("Result is not ready for %s" % (a, ))
		}
		a.scheduler.run_until_complete(a.async_wait())
	}
	a._wait_hook()
	return *a.returncode
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

func (a *AsynchronousTask)  addStartListener( f func(*AsynchronousTask)) {
	if a._start_listeners == nil {
		a._start_listeners = []func(*AsynchronousTask){}
	}
	a._start_listeners = append(a._start_listeners, f)

	if a.returncode != nil {
		a._start_hook()
	}
}

func (a *AsynchronousTask)  removeStartListener( f func(*AsynchronousTask))  {
	if a._start_listeners == nil {
		return
	}
	sls := a._start_listeners
	a._exit_listener_handles = []func(*AsynchronousTask){}
	for _, sl := range sls {
		if sl != f {
			a._exit_listener_handles = append(a._exit_listener_handles, f)
		}
	}
}

func (a *AsynchronousTask)  _start_hook() {
	if a._start_listeners != nil {
		start_listeners := a._start_listeners
		a._start_listeners = nil

		for _, f := range start_listeners {
			a.scheduler.call_soon(func() { f(a) })
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

func (a *AsynchronousTask)  _exit_listener_cb( listener func(*AsynchronousTask)) {
	delete(a._exit_listener_handles,listener)
	listener(a)
}

func NewAsynchronousTask(scheduler*SchedulerInterface) *AsynchronousTask {
	a := &AsynchronousTask{}
	a.scheduler = scheduler
	a._cancelled_returncode = int(-syscall.SIGINT)
	return a
}

type Binpkg struct {
	*CompositeTask
	//slot
	logger    *_emerge_log_class
	opts      *_binpkg_opts_class
	pkg_count *_pkg_count_class
	world_atom func()
	_build_prefix, _ebuild_path, _image_dir, _infloc, _pkg_path, _tree, _verify string
	settings                                                                    *Config
	pkg                                                                         *PkgStr
	_build_dir                                                                  *EbuildBuildDir
	_bintree                                                                    *BinaryTree
	find_blockers,
	ldpath_mtimes,
	prefetcher,
	_fetched_pkg
}

// 0, 0
func (b *Binpkg) _writemsg_level( msg string, level int, noiselevel int) {
	b.scheduler.output(msg, b.settings.ValueDict["PORTAGE_LOG_FILE"], false, level, noiselevel)
}

func (b *Binpkg) _start() {

	pkg := b.pkg
	settings := b.settings
	settings.SetCpv(pkg, nil)
	b._tree = "bintree"
	b._bintree = b.pkg.root_config.trees[b._tree]
	b._verify = !b.opts.pretend

	ss, _ := filepath.EvalSymlinks(settings.ValueDict["PORTAGE_TMPDIR"])
	dir_path := filepath.Join(ss, "portage", pkg.category, pkg.pf)
	b._image_dir = filepath.Join(dir_path, "image")
	b._infloc = filepath.Join(dir_path, "build-info")
	b._ebuild_path = filepath.Join(b._infloc, pkg.pf+".ebuild")
	settings.ValueDict["EBUILD"] = b._ebuild_path
	doebuild_environment(b._ebuild_path, "setup", nil, b.settings, false, nil, b._bintree.dbapi)
	if dir_path != b.settings.ValueDict["PORTAGE_BUILDDIR"] {
		//raise AssertionError("'%s' != '%s'"%
		//	(dir_path, b.Settings.ValueDict["PORTAGE_BUILDDIR"]))
	}
	b._build_dir = NewEbuildBuildDir(b.scheduler, settings)
	settings.configDict["pkg"]["EMERGE_FROM"] = "binary"
	settings.configDict["pkg"]["MERGE_TYPE"] = "binary"

	if eapiExportsReplaceVars(settings.ValueDict["EAPI"]) {
		vardb := b.pkg.root_config.trees["vartree"].dbapi
		settings.ValueDict["REPLACING_VERSIONS"] = " ".join(
			set(cpvGetVersion(x, "")
		for x
			in
		vardb.match(b.pkg.slot_atom) +
			vardb.match("="+b.pkg.cpv)))
	}

	prefetcher := b.prefetcher
	if prefetcher == nil{
		//pass
	} else if prefetcher.isAlive() && prefetcher.poll() != nil {
		if !b.background {
			fetch_log := filepath.Join(_emerge_log_dir, "emerge-fetch.log")
			msg := []string{
				"Fetching in the background:",
				prefetcher.pkg_path,
				"To view fetch progress, run in another terminal:",
				fmt.Sprintf("tail -f %s", fetch_log),
			}
			out := NewEOutput(false)
			for _, l := range msg {
				out.einfo(l)
			}
		}

		b._current_task = prefetcher
		prefetcher.addExitListener(b._prefetch_exit)
		return
	}

	b._prefetch_exit(prefetcher)
}

func (b *Binpkg)_prefetch_exit(prefetcher){
	if b._was_cancelled() {
		b.wait()
		return
	}

	if !(b.opts.pretend || b.opts.fetchonly){
		b._start_task(
			NewAsyncTaskFuture(b._build_dir.async_lock()),
		b._start_fetcher)
	}else {
		b._start_fetcher()
	}
}

// nil
func (b *Binpkg) _start_fetcher( lock_task) {
	if lock_task != nil {
		b._assert_current(lock_task)
		if lock_task.cancelled {
			b._default_final_exit(lock_task)
			return
		}

		lock_task.future.result()
		prepare_build_dirs(b.settings, true)
		b._build_dir.clean_log()
	}

	pkg := b.pkg
	pkg_count := b.pkg_count
	fetcher := nil

	if b.opts.getbinpkg && b._bintree.isremote(pkg.cpv) {

		fetcher := NewBinpkgFetcher(b.background, b.settings.ValueDict["PORTAGE_LOG_FILE"], b.pkg, b.opts.pretend, b.scheduler)

		msg := fmt.Sprintf(" --- (%s of %s) Fetching Binary (%s::%s)",
			pkg_count.curval, pkg_count.maxval, pkg.cpv,
			fetcher.pkg_path)
		short_msg := fmt.Sprintf("emerge: (%s of %s) %s Fetch",
			pkg_count.curval, pkg_count.maxval, pkg.cpv)
		b.logger.log(msg, short_msg)

		fetcher.addExitListener(b._fetcher_exit)
		b._task_queued(fetcher)
		b.scheduler.fetch.schedule(fetcher)
		return
	}

	b._fetcher_exit(fetcher)
}

func (b *Binpkg) _fetcher_exit( fetcher) {

	if fetcher != nil {
		b._fetched_pkg = fetcher.pkg_path
		if b._default_exit(fetcher) != 0 {
			b._async_unlock_builddir(b.returncode)
			return
		}
	}

	if b.opts.pretend {
		b._current_task = nil
		i:=0
		b.returncode = &i
		b.wait()
		return
	}

	var verifier *BinpkgVerifier
	if b._verify {
		path := ""
		if b._fetched_pkg {
			path = b._fetched_pkg
		} else {
			path = b.pkg.root_config.trees["bintree"].getname(
				b.pkg.cpv)
		}
		logfile := b.settings.ValueDict["PORTAGE_LOG_FILE"]
		verifier = NewBinpkgVerifier( b.background, logfile,b.pkg,  b.scheduler, path)
		b._start_task(verifier, b._verifier_exit)
		return
	}

	b._verifier_exit(verifier)
}

func (b *Binpkg) _verifier_exit(verifier func(*int)) {
	if verifier != nil && b._default_exit(verifier) != 0 {
		b._async_unlock_builddir(b.returncode)
		return
	}

	logger := b.logger
	pkg := b.pkg
	pkg_count := b.pkg_count

	pkg_path := ""
	if b._fetched_pkg {
		pkg_path = b._bintree.getname(b._bintree.inject(pkg.cpv, b._fetched_pkg), false)
	} else {
		pkg_path = b.pkg.root_config.trees["bintree"].getname(
			b.pkg.cpv)
	}

	if pkg_path != "" {
		b.settings.ValueDict["PORTAGE_BINPKG_FILE"] = pkg_path
	}
	b._pkg_path = pkg_path

	logfile := b.settings.ValueDict["PORTAGE_LOG_FILE"]
	st, err := os.Stat(logfile)
	if err == nil && !st.IsDir() {
		if err := syscall.Unlink(logfile); err != nil {
			//except OSError:
			//pass
		}
	}

	if b.opts.fetchonly != "" {
		b._current_task = nil
		i := 0
		b.returncode = &i
		b.wait()
		return
	}

	msg := fmt.Sprintf(" === (%s of %s) Merging Binary (%s::%s)",
		pkg_count.curval, pkg_count.maxval, pkg.cpv, pkg_path)
	short_msg := fmt.Sprintf("emerge: (%s of %s) %s Merge Binary",
		pkg_count.curval, pkg_count.maxval, pkg.cpv)
	logger.log(msg, short_msg)

	phase := "clean"
	settings := b.settings
	ebuild_phase := NewEbuildPhase(nil, b.background,
		phase, b.scheduler, settings, nil)

	b._start_task(ebuild_phase, b._clean_exit)
}

func (b *Binpkg) _clean_exit( clean_phase) {
	if b._default_exit(clean_phase) != 0 {
		b._async_unlock_builddir(b.returncode)
		return
	}

	b._start_task(
		NewAsyncTaskFuture(b._unpack_metadata()),
	b._unpack_metadata_exit)
}

@coroutine
func (b *Binpkg) _unpack_metadata() IFuture {

	dir_path := b.settings.ValueDict["PORTAGE_BUILDDIR"]

	infloc := b._infloc
	pkg := b.pkg
	pkg_path := b._pkg_path

	dir_mode := os.FileMode(0755)
	for _, mydir := range []string{dir_path, b._image_dir, infloc} {
		ensureDirs(mydir, uint32(*portage_uid), *portage_gid, dir_mode, -1, nil, true)
	}

	prepare_build_dirs(b.settings, true)
	b._writemsg_level(">>> Extracting info\n", 0, 0)

	yield
	b._bintree.dbapi.unpack_metadata(b.settings, infloc)
	check_missing_metadata := []string{"CATEGORY", "PF"}
	for k, v
		in
	zip(check_missing_metadata,
		b._bintree.dbapi.aux_get(b.pkg.cpv, check_missing_metadata)) {
		if v {
			continue
		} else if k == "CATEGORY" {
			v = pkg.category
		} else if k == "PF" {
			v = pkg.pf
		} else {
			continue
		}

		f, _ := os.OpenFile(filepath.Join(infloc, k), os.O_RDWR|os.O_CREATE, 0644)
		f.Write(v)
		f.Write([]byte("\n"))
		f.Close()
	}

	if pkg_path != "" {
		md5sum := b._bintree.dbapi.aux_get(b.pkg.cpv, map[string]string{"MD5": ""})[0]
		if len(md5sum) == 0 {
			md5sum = string(performMd5(pkg_path, false))
		}
		f, _ := os.OpenFile(filepath.Join(infloc, "BINPKGMD5"), os.O_RDWR|os.O_CREATE, 0644)
		f.Write([]byte(md5sum))
		f.Write([]byte("\n"))
		f.Close()
	}

	env_extractor := NewBinpkgEnvExtractor(b.background,
		b.scheduler, b.settings)
	env_extractor.start()
	yield
	env_extractor.async_wait()
	if env_extractor.returncode != nil && *env_extractor.returncode != 0 {
		raise
		portage.exception.PortageException("failed to extract environment for {}".format(b.pkg.cpv))
	}
}

func (b *Binpkg) _unpack_metadata_exit( unpack_metadata) {
	if b._default_exit(unpack_metadata) != 0 {
		unpack_metadata.future.result()
		b._async_unlock_builddir(b.returncode)
		return
	}

	setup_phase := NewEbuildPhase(nil,  b.background, "setup",b.scheduler, b.settings, nil)

	setup_phase.addExitListener(b._setup_exit)
	b._task_queued(setup_phase)
	b.scheduler.scheduleSetup(setup_phase)
}

func (b *Binpkg) _setup_exit( setup_phase *SpawnProcess) {
	if b._default_exit(setup_phase) != 0 {
		b._async_unlock_builddir(b.returncode)
		return
	}

	b._writemsg_level(fmt.Sprintf(">>> Extracting %s\n" , b.pkg.cpv), 0, 0)
	b._start_task(
		NewAsyncTaskFuture(b._bintree.dbapi.unpack_contents(
		b.settings, b._image_dir)),
	b._unpack_contents_exit)
}

func (b *Binpkg) _unpack_contents_exit( unpack_contents) {
	if b._default_exit(unpack_contents) != 0 {
		unpack_contents.future.result()
		b._writemsg_level(fmt.Sprintf("!!! Error Extracting '%s'\n",
			b._pkg_path), -1, 40)
		b._async_unlock_builddir(b.returncode)
		return
	}

	f, err := ioutil.ReadFile(filepath.Join(b._infloc, "EPREFIX"))
	if err != nil {
		//except IOError:
		b._build_prefix = ""
	} else {
		b._build_prefix = strings.TrimRight(string(f), "\n")
	}

	if b._build_prefix == b.settings.ValueDict["EPREFIX"] {
		ensureDirs(b.settings.ValueDict["ED"], -1, -1, -1, -1, nil, true)
		b._current_task = nil
		i := 0
		b.returncode = &i
		b.wait()
		return
	}

	env := b.settings.environ()
	env["PYTHONPATH"] = b.settings.ValueDict["PORTAGE_PYTHONPATH"]
	chpathtool := NewSpawnProcess(
		[]string{"python", // portage._python_interpreter,
			filepath.Join(b.settings.ValueDict["PORTAGE_BIN_PATH"], "chpathtool.py"),
			b.settings.ValueDict["D"], b._build_prefix, b.settings.ValueDict["EPREFIX"]},
		b.background, env, nil, b.scheduler, b.settings.ValueDict["PORTAGE_LOG_FILE"])
	b._writemsg_level(fmt.Sprintf(">>> Adjusting Prefix to %s\n", b.settings.ValueDict["EPREFIX"]), 0, 0)
	b._start_task(chpathtool, b._chpathtool_exit)
}

func (b *Binpkg) _chpathtool_exit( chpathtool) {
	if i := b._final_exit(chpathtool); i != nil && *i != 0 {
		b._writemsg_level(fmt.Sprintf("!!! Error Adjusting Prefix to %s\n",
			b.settings.ValueDict["EPREFIX"], ),
			-1, 40)
		b._async_unlock_builddir(b.returncode)
		return
	}

	ioutil.WriteFile(filepath.Join(b._infloc, "EPREFIX"), []byte(b.settings.ValueDict["EPREFIX"]+"\n"), 0644)

	image_tmp_dir := filepath.Join(
		b.settings.ValueDict["PORTAGE_BUILDDIR"], "image_tmp")
	build_d := strings.TrimLeft(filepath.Join(b.settings.ValueDict["D"],
		strings.TrimLeft(b._build_prefix, string(os.PathSeparator))), string(os.PathSeparator))
	if pathIsDir(build_d) {
		os.RemoveAll(b._image_dir)
		ensureDirs(b.settings.ValueDict["ED"], -1, -1, -1, -1, nil, true)
	} else {
		os.Rename(build_d, image_tmp_dir)
		if build_d != b._image_dir {
			os.RemoveAll(b._image_dir)
		}
		ensureDirs(strings.TrimRight(filepath.Dir(b.settings.ValueDict["ED"]), string(os.PathSeparator)), -1, -1, -1, -1, nil, true)
		os.Rename(image_tmp_dir, b.settings.ValueDict["ED"])
	}

	b.wait()
}

// nil
func (b *Binpkg) _async_unlock_builddir(returncode *int) {
	if b.opts.pretend != "" || b.opts.fetchonly != "" {
		if returncode != nil {
			b.returncode = returncode
			b._async_wait()
		}
		return
	}
	if returncode != nil {
		b.returncode = nil
	}
	elog_process(b.pkg.cpv.string, b.settings, nil)
	b._start_task(
		NewAsyncTaskFuture(b._build_dir.async_unlock()),
	func(unlock_task) {
		return b._unlock_builddir_exit(unlock_task, returncode)
	})
}

// nil
func (b *Binpkg) _unlock_builddir_exit(unlock_task, returncode *int) {
	b._assert_current(unlock_task)
	if unlock_task.cancelled && returncode!= nil{
		b._default_final_exit(unlock_task)
		return
	}

	unlock_task.future.cancelled() || unlock_task.future.result()
	if returncode != nil {
		b.returncode = returncode
		b._async_wait()
	}
}

func (b *Binpkg) create_install_task() *EbuildMerge{
	task := NewEbuildMerge(b._install_exit, b.find_blockers,
		b.ldpath_mtimes, b.logger, b.pkg, b.pkg_count,
		b._pkg_path, b.scheduler, b.settings, b._tree, b.world_atom)
	return task
}

func (b *Binpkg) _install_exit(task) {
	delete(b.settings.ValueDict, "PORTAGE_BINPKG_FILE")
	if task.returncode == 0 && !b.settings.Features.Features["binpkg-logs"] && b.settings.ValueDict["PORTAGE_LOG_FILE"]!= "" {
		if err := syscall.Unlink(b.settings.ValueDict["PORTAGE_LOG_FILE"]); err != nil {
			//except OSError:
			//pass
		}
	}
	b._async_unlock_builddir(nil)
	var result IFuture
	if b._current_task == nil {
		result = b.scheduler.create_future()
		b.scheduler.call_soon(func(){result.set_result(0)})
	}else {
		result = b._current_task.async_wait()
	}
	return result
}

func NewBinpkg(background bool, find_blockers , ldpath_mtimes, logger*_emerge_log_class,
	opts *_binpkg_opts_class, pkg *PkgStr, pkg_count*_pkg_count_class, prefetcher ,
	settings *Config, scheduler *SchedulerInterface,
	world_atom func())*Binpkg {
	b := &Binpkg{}
	b.CompositeTask = NewCompositeTask()
	b.background = background
	b.find_blockers = find_blockers
	b.ldpath_mtimes = ldpath_mtimes
	b.logger = logger
	b.opts = opts
	b.pkg = pkg
	b.pkg_count = pkg_count
	b.prefetcher = prefetcher
	b.settings = settings
	b.scheduler = scheduler
	b.world_atom = world_atom
	return b
}

type BinpkgEnvExtractor struct {
	*CompositeTask
	settings *Config
}

func(b *BinpkgEnvExtractor) saved_env_exists() bool {
	return pathExists(b._get_saved_env_path())
}

func(b *BinpkgEnvExtractor) dest_env_exists() bool {
	return pathExists(b._get_dest_env_path())
}

func(b *BinpkgEnvExtractor) _get_saved_env_path() string {
	return filepath.Join(filepath.Dir(b.settings.ValueDict["EBUILD"]),
		"environment.bz2")
}

func(b *BinpkgEnvExtractor) _get_dest_env_path() string {
	return filepath.Join(b.settings.ValueDict["T"], "environment")
}

func(b *BinpkgEnvExtractor) _start() {
	saved_env_path := b._get_saved_env_path()
	dest_env_path := b._get_dest_env_path()
	shell_cmd := fmt.Sprintf("${PORTAGE_BUNZIP2_COMMAND:-${PORTAGE_BZIP2_COMMAND} -d} -c -- %s > %s" ,
		ShellQuote(saved_env_path),
		ShellQuote(dest_env_path))
	extractor_proc := NewSpawnProcess([]string{BashBinary, "-c", shell_cmd}, b.background, b.settings.environ(), nil, b.scheduler, b.settings.ValueDict["PORTAGE_LOG_FILE"])

	b._start_task(extractor_proc, b._extractor_exit)
}

func(b *BinpkgEnvExtractor) _remove_dest_env() {
	if err := syscall.Unlink(b._get_dest_env_path()); err != nil {
		//except OSError as e:
		if err != syscall.ENOENT {
			//raise
		}
	}
}

func(b *BinpkgEnvExtractor) _extractor_exit( extractor_proc *SpawnProcess) {

	if b._default_exit(extractor_proc) != 0 {
		b._remove_dest_env()
		b.wait()
		return
	}

	f, _ := os.OpenFile(b._get_dest_env_path()+".raw", os.O_RDWR, 0644)
	f.Close()

	b._current_task = nil
	i := 0
	b.returncode = &i
	b.wait()
}

func NewBinpkgEnvExtractor(background bool, scheduler *SchedulerInterface, settings *Config)*BinpkgEnvExtractor{
	b :=&BinpkgEnvExtractor{}
	b.CompositeTask = NewCompositeTask()
	b.background = background
	b.scheduler = scheduler
	b.settings = settings
	return b
}

type BinpkgExtractorAsync struct {
	*SpawnProcess
	_shell_binary string

	// slot
	features  map[string]bool
	pkg       *PkgStr
	pkg_path  string
	image_dir string
}

func(b *BinpkgExtractorAsync) _start() {
	tar_options := ""
	if b.features["xattr"] {
		pp := &bytes.Buffer{}
		cmd := exec.Command("tar", "--help")
		cmd.Stderr = pp
		cmd.Stdout = pp
		cmd.Run()
		output := pp.String()
		if strings.Contains(output, "--xattrs") {
			tar_options2 := []string{"--xattrs", "--xattrs-include='*'"}
			ss, _ := shlex.Split(strings.NewReader(b.env["PORTAGE_XATTR_EXCLUDE"]), false, true)

			for _, x := range ss {
				tar_options2 = append(tar_options2, ShellQuote(fmt.Sprintf("--xattrs-exclude=%s", x)))
			}
			tar_options = strings.Join(tar_options2, " ")
		}
	}
	decomp := _compressors[compression_probe(b.pkg_path)]
	decomp_cmd := ""
	if decomp != nil {
		decomp_cmd = decomp["decompress"]
	} else if tarfile.is_tarfile(b.pkg_path) {
		decomp_cmd = "cat"
		decomp = map[string]string{
			"compress": "cat",
			"package":  "sys-apps/coreutils",
		}
	} else {
		decomp_cmd = ""
	}
	if decomp_cmd == "" {
		b.scheduler.output(fmt.Sprintf("!!! %s\n",
			fmt.Sprintf("File compression header unrecognized: %s",
				b.pkg_path)), b.logfile,
			b.background, 40, 0)
		i := 1
		b.returncode = &i
		b._async_wait()
		return
	}

	dbs, _ := shlex.Split(strings.NewReader(varExpand(decomp_cmd, b.env, nil)), false, true)
	decompression_binary := ""
	if len(dbs) > 0 {
		decompression_binary = dbs[0]
	}

	if FindBinary(decompression_binary) == "" {
		if decomp["decompress_alt"] != "" {
			decomp_cmd = decomp["decompress_alt"]
		}
		dbs, _ := shlex.Split(strings.NewReader(varExpand(decomp_cmd, b.env, nil)), false, true)
		decompression_binary = ""
		if len(dbs) > 0 {
			decompression_binary = dbs[0]
		}

		if FindBinary(decompression_binary) == "" {
			missing_package := decomp["package"]
			b.scheduler.output(fmt.Sprintf("!!! %s\n",
				fmt.Sprintf("File compression unsupported %s.\n Command was: %s.\n Maybe missing package: %s",
					b.pkg_path, varExpand(decomp_cmd, b.env, nil), missing_package)), b.logfile,
				b.background, 40, -1)
			i := 1
			b.returncode = &i
			b._async_wait()
			return
		}
	}

	pkg_xpak := NewTbz2(b.pkg_path)
	pkg_xpak.scan()

	b.args = []string{b._shell_binary, "-c",
		fmt.Sprintf("cmd0=(head -c %d -- %s) cmd1=(%s) cmd2=(tar -xp %s -C %s -f -); "+
			`"${cmd0[@]}" | "${cmd1[@]}" | "${cmd2[@]}"; `+
			"p=(${PIPESTATUS[@]}) ; for i in {0..2}; do "+
			"if [[ ${p[$i]} != 0 && ${p[$i]} != %d ]] ; then "+
			"echo command $(eval \"echo \\\"'\\${cmd$i[*]}'\\\"\") "+
			"failed with status ${p[$i]} ; exit ${p[$i]} ; fi ; done; "+
			"if [ ${p[$i]} != 0 ] ; then "+
			"echo command $(eval \"echo \\\"'\\${cmd$i[*]}'\\\"\") "+
			"failed with status ${p[$i]} ; exit ${p[$i]} ; fi ; "+
			"exit 0 ;",
			int(pkg_xpak.filestat.Size())-pkg_xpak.xpaksize,
			ShellQuote(b.pkg_path),
			decomp_cmd,
			tar_options,
			ShellQuote(b.image_dir),
			128+int(unix.SIGPIPE))}

	b.SpawnProcess._start()
}

func NewBinpkgExtractorAsync(background bool, env map[string]string, features map[string]bool, image_dir string, pkg *PkgStr, pkg_path, logfile string, scheduler *SchedulerInterface) *BinpkgExtractorAsync{
	b:= &BinpkgExtractorAsync{}
	b._shell_binary=BashBinary
	b.SpawnProcess=NewSpawnProcess()

	b.background=background
	b.env=env
	b.features=features
	b.image_dir = image_dir
	b.pkg=pkg
	b.pkg_path=pkg_path
	b.logfile=logfile
	b.scheduler=scheduler

	return b
}


type BinpkgFetcher struct {
	*CompositeTask

	// slot
	pkg *PkgStr
	pretend,logfile,pkg_path string
}

func (b *BinpkgFetcher) _start() {
	fetcher := NewBinpkgFetcherProcess(b.background,
		b.logfile, b.pkg, b.pkg_path,
		b.pretend, b.scheduler)

	if not b.pretend {
		ensureDirs(filepath.Dir(b.pkg_path),-1,-1,-1,-1,nil,true)
		if "distlocks" in
		b.pkg.root_config.settings.features
		{
			b._start_task(
				NewAsyncTaskFuture(fetcher.async_lock()),
			functools.partial(b._start_locked, fetcher))
			return
		}
	}

	b._start_task(fetcher, b._fetcher_exit)
}

func (b *BinpkgFetcher) _start_locked(fetcher, lock_task) {
	b._assert_current(lock_task)
	if lock_task.cancelled {
		b._default_final_exit(lock_task)
		return
	}

	lock_task.future.result()
	b._start_task(fetcher, b._fetcher_exit)
}

func (b *BinpkgFetcher) _fetcher_exit(fetcher) {
	b._assert_current(fetcher)
	if not b.pretend
	and
	fetcher.returncode == 0{
		fetcher.sync_timestamp()
	}
	if fetcher.locked {
		b._start_task(
			NewAsyncTaskFuture(fetcher.async_unlock()),
		functools.partial(b._fetcher_exit_unlocked, fetcher))
	}else {
		b._fetcher_exit_unlocked(fetcher)
	}
}

// nil
func (b *BinpkgFetcher) _fetcher_exit_unlocked(fetcher, unlock_task=None) {
	if unlock_task != nil {
		b._assert_current(unlock_task)
		if unlock_task.cancelled {
			b._default_final_exit(unlock_task)
			return
		}
	}

	unlock_task.future.result()

	b._current_task = None
	b.returncode = fetcher.returncode
	b._async_wait()
}

func NewBinpkgFetcher(background bool, logfile string, pkg *PkgStr, pretend interface{}, scheduler *SchedulerInterface, **kwargs)*BinpkgFetcher {
	b :=&BinpkgFetcher{}
	b.CompositeTask= NewCompositeTask()
	b.background = background
	b.logfile=logfile
	b.pkg=pkg
	b.pretend = pretend
	b.scheduler=scheduler

	pkg := b.pkg
	b.pkg_path = pkg.root_config.trees["bintree"].getname(
		pkg.cpv) + ".partial"

	return b
}

type _BinpkgFetcherProcess struct {
	*SpawnProcess

	// slot
	locked bool
	pkg,pretend,pkg_path string
	_lock_obj *AsynchronousLock
}

func (b *_BinpkgFetcherProcess) _start() {
	pkg := b.pkg
	pretend := b.pretend
	bintree := pkg.root_config.trees["bintree"]
	settings := bintree.settings
	pkg_path := b.pkg_path

	exists := pathExists(pkg_path)
	resume := exists && filepath.Base(pkg_path)
	in
	bintree.invalids
	if !(pretend || resume) {
		if err := syscall.Unlink(pkg_path); err != nil {
			//except OSError:
			//pass
		}
	}

	uri := strings.TrimRight(settings.ValueDict["PORTAGE_BINHOST"], "/") + "/" + pkg.pf + ".tbz2"
	if bintree._remote_has_index {
		instance_key := bintree.dbapi._instance_key(pkg.cpv)
		rel_uri := bintree._remotepkgs[instance_key].get("PATH")
		if rel_uri == "" {
			rel_uri = pkg.cpv + ".tbz2"
		}
		remote_base_uri := bintree._remotepkgs[
			instance_key]["BASE_URI"]
		uri = strings.TrimRight(remote_base_uri, "/") + "/" + strings.TrimLeft(rel_uri, "/")
	}

	if pretend {
		WriteMsgStdout(fmt.Sprintf("\n%s\n", uri), -1)
		i := 0
		b.returncode = &i
		b._async_wait()
		return
	}

	u, _ := url.Parse(uri)
	protocol := u.Scheme
	fcmd_prefix := "FETCHCOMMAND"
	if resume {
		fcmd_prefix = "RESUMECOMMAND"
	}
	fcmd := settings.ValueDict[fcmd_prefix+"_"+strings.ToUpper(protocol)]
	if fcmd == "" {
		fcmd = settings.ValueDict[fcmd_prefix]
	}

	fcmd_vars := map[string]string{
		"DISTDIR": filepath.Dir(pkg_path),
		"URI":     uri,
		"FILE":    filepath.Base(pkg_path),
	}

	v, ok := settings.ValueDict["PORTAGE_SSH_OPTS"]
	if ok {
		fcmd_vars["PORTAGE_SSH_OPTS"] = v
	}

	fetch_env := dict(settings.items())
	fetch_args := []string{}
	ss, _ := shlex.Split(strings.NewReader(fcmd), false, true)
	for _, x := range ss {
		fetch_args = append(fetch_args, varExpand(x, fcmd_vars, nil))
	}

	if b.fd_pipes == nil {
		b.fd_pipes =map[int]int{}
	}
	fd_pipes := b.fd_pipes

	if _, ok := fd_pipes[0]; !ok {
		fd_pipes[0] = int(getStdin().Fd())
	}
	if _, ok := fd_pipes[0]; !ok {
		fd_pipes[0] = int(os.Stdout.Fd())
	}
	if _, ok := fd_pipes[0]; !ok {
		fd_pipes[0] = int(os.Stdout.Fd())
	}

	b.args = fetch_args
	b.env = fetch_env
	if settings.selinux_enabled() {
		b._selinux_type = settings["PORTAGE_FETCH_T"]
	}
	b.SpawnProcess._start()
}

func (b *_BinpkgFetcherProcess) _pipe( fd_pipes map[int]int) []int {
	if b.background || !terminal.IsTerminal(syscall.Stdout){
		return os.pipe()
	}
	stdout_pipe = None
	if ! b.background {
		stdout_pipe = fd_pipes[1]
	}
	got_pty, master_fd, slave_fd =
		_create_pty_or_pipe(copy_term_size = stdout_pipe)
	return (master_fd, slave_fd)
}

func (b *_BinpkgFetcherProcess) sync_timestamp() {
	bintree := b.pkg.root_config.trees["bintree"]
	if bintree._remote_has_index {
		remote_mtime := bintree._remotepkgs[
			bintree.dbapi._instance_key(
				b.pkg.cpv)].get("_mtime_")
		if remote_mtime != nil {
			remote_mtimeI, err := strconv.Atoi(remote_mtime)
			if err == nil {
				st, err := os.Stat(b.pkg_path)
				if err == nil {
					local_mtime := st.ModTime().Unix()
					if remote_mtimeI != int(local_mtime) {
						err := syscall.Utime(b.pkg_path, &syscall.Utimbuf{Actime: remote_mtime, Modtime: remote_mtime})
						if err != nil {
						}
					}
				}
			}
		}
	}
}

func (b *_BinpkgFetcherProcess) async_lock() IFuture {
	if b._lock_obj != nil{
		//raise b.AlreadyLocked((b._lock_obj, ))
	}

	result := b.scheduler.create_future()

	acquired_lock := func(async_lock) {
		if async_lock.wait() == 0 {
			b.locked = true
			result.set_result(nil)
		} else {
			result.set_exception(AssertionError(
				"AsynchronousLock failed with returncode %s"
			% (async_lock.returncode,)))
		}
	}

	b._lock_obj = NewAsynchronousLock( b.pkg_path, b.scheduler)
	b._lock_obj.addExitListener(acquired_lock)
	b._lock_obj.start()
	return result
}

type AlreadyLocked struct {
	*PortageException
}

func (b *_BinpkgFetcherProcess) async_unlock()IFuture {
	if b._lock_obj == nil{
		//raise AssertionError('already unlocked')
	}
	result := b._lock_obj.async_unlock()
	b._lock_obj = nil
	b.locked = false
	return result
}

func NewBinpkgFetcherProcess(background bool,
	logfile string, pkg *PkgStr, pkg_path string,
	pretend interface{}, scheduler *SchedulerInterface)*_BinpkgFetcherProcess {
	b := &_BinpkgFetcherProcess{}
	b.SpawnProcess = NewSpawnProcess(nil, background, nil, nil, scheduler,
		logfile)

	b.background = background
	b.logfile = logfile
	b.pkg = pkg
	b.pkg_path = pkg_path
	b.pretend = pretend
	b.scheduler = scheduler

	return b
}

type BinpkgPrefetcher struct {
	*CompositeTask

	// slot
	pkg *PkgStr
	pkg_path string
	_bintree *BinaryTree
}

func (b *BinpkgPrefetcher)_start() {
	b._bintree = b.pkg.root_config.trees["bintree"]
	fetcher := NewBinpkgFetcher(b.background,
		b.scheduler.fetch.log_file, b.pkg, nil,
		b.scheduler)
	b.pkg_path = fetcher.pkg_path
	b._start_task(fetcher, b._fetcher_exit)
}

func (b *BinpkgPrefetcher) _fetcher_exit( fetcher) {
	if b._default_exit(fetcher) != 0 {
		b.wait()
		return
	}

	verifier := NewBinpkgVerifier( b.background,
		 b.scheduler.fetch.log_file, b.pkg,
		 b.scheduler, b.pkg_path)
	b._start_task(verifier, b._verifier_exit)
}

func (b *BinpkgPrefetcher) _verifier_exit(verifier ) {
	if b._default_exit(verifier) != 0 {
		b.wait()
		return
	}

	b._bintree.inject(b.pkg.cpv, b.pkg_path)

	b._current_task = nil
	i := 0
	b.returncode = &i
	b.wait()
}

func NewBinpkgPrefetcher(background bool, pkg *PkgStr, scheduler *SchedulerInterface)*BinpkgPrefetcher{
	b := &BinpkgPrefetcher{}
	b.CompositeTask = NewCompositeTask()
	b.background = background
	b.pkg= pkg
	b.scheduler= scheduler

	return b
}

type BinpkgVerifier struct {
	*CompositeTask

	// slot
	logfile,  _digests, _pkg_path string
	pkg *PkgStr
}

func (b *BinpkgVerifier) _start() {

	bintree := b.pkg.root_config.trees["bintree"]
	digests := bintree._get_digests(b.pkg)
	if "size" not
	in
digests{
	i :=0
	b.returncode = &i
	b._async_wait()
	return
}

	digests = filterUnaccelaratedHashes(digests)
	hash_filter := NewHashFilter(
		bintree.settings.ValueDict["PORTAGE_CHECKSUM_FILTER"])
	if ! hash_filter.trasparent {
		digests = applyHashFilter(digests, hash_filter)
	}

	b._digests = digests

	st, err:= os.Stat(b._pkg_path)
	if err != nil {
		//except OSError as e:
		if err!= syscall.ENOENT||err!= syscall.ESTALE {
			//raise
		}
		b.scheduler.output(fmt.Sprintf("!!! Fetching Binary failed "+
		"for '%s'\n", b.pkg.cpv), b.logfile, b.background, 0, -1)
		i := 1
		b.returncode = &i
		b._async_wait()
		return
	}else {
		size := st.Size()
		if size != digests["size"] {
			b._digest_exception("size", size, digests["size"])
			i := 1
			b.returncode = &i
			b._async_wait()
			return
		}
	}

	ds := []string{}
	for k
		in
	digests {
		if k != "size" {
			ds = append(ds, k)
		}
	}
	b._start_task(NewFileDigester(b._pkg_path,ds, b.background, b.logfile, b.scheduler), b._digester_exit)
}

func (b *BinpkgVerifier) _digester_exit(digester) {

	if b._default_exit(digester) != 0 {
		b.wait()
		return
	}

	for hash_name
	in
	digester.hash_names {
		if digester.digests[hash_name] != b._digests[hash_name] {
			b._digest_exception(hash_name,
				digester.digests[hash_name], b._digests[hash_name])
			i := 1
			b.returncode = &i
			b.wait()
			return
		}
	}

	if b.pkg.root_config.settings.ValueDict["PORTAGE_QUIET"] != "1" {
		b._display_success()
	}

	i := 0
	b.returncode = &i
	b.wait()
}

func (b *BinpkgVerifier) _display_success() {
	stdout_orig := os.Stdout
	stderr_orig := os.Stderr
	global_havecolor := HaveColor
	out := &bytes.Buffer{}
	os.Stdout = out
	os.Stderr = out
	if HaveColor!= 0 {
		if b.background{
			HaveColor = 1
		} else {
			HaveColor = 0
		}
	}

	path := b._pkg_path
	if strings.HasSuffix(path,".partial") {
		path = path[:-len(".partial")]
	}
	eout := NewEOutput(false)
	eout.ebegin(fmt.Sprintf("%s %s ;-)",filepath.Base(path),
		" ".join(sorted(b._digests))))
	eout.eend(0, "")

	os.Stdout = stdout_orig
	os.Stderr = stderr_orig
	HaveColor = global_havecolor

	b.scheduler.output(out.String(),  b.logfile, b.background, 0, -1)
}

func (b *BinpkgVerifier) _digest_exception( name, value, expected string) {

	head, tail := filepath.Split(b._pkg_path)
	temp_filename := _checksum_failure_temp_file(b.pkg.root_config.settings, head, tail)

	b.scheduler.output(fmt.Sprintf(
		"\n!!! Digest verification failed:\n"+
	"!!! %s\n"+
	"!!! Reason: Failed on %s verification\n"+
	"!!! Got: %s\n"+
	"!!! Expected: %s\n"+
	"File renamed to '%s'\n",
	b._pkg_path, name, value, expected, temp_filename),
	b.logfile, b.background, 0, -1)
}

func NewBinpkgVerifier(background bool, logfile string, pkg *PkgStr, scheduler *SchedulerInterface, pkg_path string) *BinpkgVerifier {
	b := &BinpkgVerifier{}
	b.CompositeTask = NewCompositeTask()

	b.background = background
	b.logfile=logfile
	b.pkg=pkg
	b.scheduler=scheduler
	b._pkg_path=pkg_path

	return b
}

type Blocker struct {
	*Task

	//slot
	root,atom,cp,eapi,priority,satisfied string
}

__hash__ = Task.__hash__

func NewBlocker( **kwargs) {
	b:=&Blocker{}
	b.Task = NewTask( **kwargs)
	b.cp = b.atom.cp
	b._hash_key = ("blocks", b.root, b.atom, b.eapi)
	b._hash_value = hash(b._hash_key)
}

type BlockerCache struct {
	_cache_threshold int

	_vardb           *vardbapi
	_cache_filename  string
	_cache_version   string
	_modified        map[string]bool
}

type BlockerData struct {
	// slot
	__weakref__,atoms,counter
}

func NewBlockerData(counter, atoms)*BlockerData {
	b := &BlockerData{}
	b.counter = counter
	b.atoms = atoms
	return b
}

func NewBlockerCache(myroot string, vardb *vardbapi)*BlockerCache {
	b := &BlockerCache{}
	b._cache_threshold = 5

	b._vardb = vardb
	b._cache_filename = filepath.Join(vardb.settings.ValueDict["EROOT"], CachePath, "vdb_blockers.pickle")
	b._cache_version = "1"
	b._cache_data = nil
	b._modified = map[string]bool{}
	b._load()
	return b
}

func (b *BlockerCache) _load() {
	//try:
	f, err := os.Open(b._cache_filename)
	mypickle :=ogórek.NewDecoder(f)
//try:
//	mypickle.find_global = nil
//	except AttributeError:
//	pass
	b._cache_data, _ = mypickle.Decode()
	f.Close()
	//except(SystemExit, KeyboardInterrupt):
	//raise
	//except Exception as e:
	//if isinstance(e, EnvironmentError) &&
	//	getattr(e, 'errno', nil)
	//	in(errno.ENOENT, errno.EACCES):
	//pass
	//else:
	//WriteMsg("!!! Error loading '%s': %s\n" %
	//	(b._cache_filename, str(e)), noiselevel = -1)
	//del e

	cache_valid := b._cache_data&&
		isinstance(b._cache_data, dict)&&
		b._cache_data.get("version") == b._cache_version&&
		isinstance(b._cache_data.get("blockers"), dict)
	if cache_valid {
		invalid_items := map[string]bool{}
		for k, v
			in
		b._cache_data["blockers"].items() {
			//if not isinstance(k, basestring):
			//invalid_items.add(k)
			//continue
		//try:
			if CatPkgSplit(k,1, "") == [4]string{} {
				invalid_items[k] = true
				continue
			}
			//except portage.exception.InvalidData:
			//invalid_items.add(k)
			//continue
			//if not isinstance(v, tuple) || len(v) != 2 {
			//	invalid_items[k] = true
			//	continue
			//}
			counter, atoms = v
			if not isinstance(counter, (int, long)){
				invalid_items[k] = true
				continue
			}
			if not isinstance(atoms, (list, tuple)){
				invalid_items[k] = true
				continue
			}
			invalid_atom := false
			for atom
				in
			atoms {
				if not isinstance(atom, basestring) {
					invalid_atom = true
					break
				}
				if atom[:1] != "!" ||!isValidAtom(
					atom, allow_blockers = true){
					invalid_atom = true
					break
				}
			}
			if invalid_atom {
				invalid_items[k] = true
				continue
			}
		}

		for k:= range invalid_items {
			del
			b._cache_data["blockers"][k]
		}
		if not b._cache_data["blockers"] {
			cache_valid = false
		}
	}

	if !cache_valid {
		b._cache_data =
		{
			"version":b._cache_version
		}
		b._cache_data["blockers"] =
		{
		}
	}
	b._modified = map[string]bool{}
}

func (b *BlockerCache) flush() {
	if len(b._modified) >= b._cache_threshold && *secpass >= 2:
//try:
	f := NewAtomic_ofstream(b._cache_filename, os.O_RDWR|os.O_TRUNC|os.O_CREATE, true)
	ogórek.NewEncoder(f).Encode(b._cache_data)
	f.Close()
	apply_secpass_permissions(
		b._cache_filename, -1, *portage_gid, 0644, -1, nil, nil)
	//except(IOError, OSError):
	//pass
	b._modified= map[string]bool{}
}

func (b *BlockerCache)  __setitem__( cpv string, blocker_data) {
	b._cache_data["blockers"][cpv] = (blocker_data.counter,
		tuple(_unicode(x)
	for x
		in
	blocker_data.atoms))
	b._modified[cpv] = true
}

func (b *BlockerCache)  __iter__() []{
	if b._cache_data == nil {
		return []
	}
	return b._cache_data["blockers"]
}

func (b *BlockerCache)  __len__() int {
	return len(b._cache_data["blockers"])
}

func (b *BlockerCache)  __delitem__( cpv) {
	delete(b._cache_data["blockers"],cpv)
}

func (b *BlockerCache)  __getitem__(cpv) *BlockerData {
	return NewBlockerData(*b._cache_data["blockers"][cpv])
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
	blocker_cache := NewBlockerCache("",
		b._vartree.dbapi)
	dep_keys := NewPackage().runtimeKeys
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
				if strings.HasPrefix(atom, "!") {
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

	blocker_parents := NewDigraph()
	blocker_atoms1 := []*Atom{}
	for _, pkg := range installed_pkgs {
		for blocker_atom
			in
		blocker_cache.__getitem__(pkg.cpv).atoms
		{
			blocker_atom = blocker_atom.lstrip("!")
			blocker_atoms1 = append(blocker_atoms1, blocker_atom)
			blocker_parents.add(blocker_atom, pkg)
		}
	}

	blocker_atoms := NewInternalPackageSet(blocker_atoms, false, true)
	blocking_pkgs = map[string]string{}
	for atom
		in
	blocker_atoms.iterAtomsForPackage(new_pkg)
	{
		blocking_pkgs.update(blocker_parents.parent_nodes(atom))
	}

	depstr := " ".join(new_pkg._metadata[k]
	for k
		in
	dep_keys)
	success, atoms := dep_check(depstr,
		vardb, settings, "yes", new_pkg.use.enabled, 1, 0,
		0, new_pkg.root, dep_check_trees)
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
blocker_atoms = NewInternalPackageSet(initial_atoms = blocker_atoms)
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
	a, _ := NewAtom(fmt.Sprintf("=%s", pkg.cpv, ), nil, false, nil, nil, "", nil, nil)
	for cpv_match
		in
	b._fake_vartree.dbapi.match_pkgs(a)
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
	_current_task ITask

	_TASK_QUEUED int
}

func (c*CompositeTask)_cancel() {
	if c._current_task != nil {
		if c._current_task is
		c._TASK_QUEUED{
			i := 1
			c.returncode = &i
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

func(c*CompositeTask) _poll() *int {
	prev = nil
	for true {
		task := c._current_task
		if task == nil ||
			task
			is
		c._TASK_QUEUED ||
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

func(c*CompositeTask) _assert_current(task *SpawnProcess) {
	if task != c._current_task {
		raise
		AssertionError("Unrecognized task: %s" % (task, ))
	}
}

func(c*CompositeTask) _default_exit( task *SpawnProcess) int {
	c._assert_current(task)
	if task.returncode != nil && *task.returncode == 0 {
		c.returncode = task.returncode
		c.cancelled = task.cancelled
		c._current_task = nil
		return *task.returncode
	}
}

func(c*CompositeTask) _final_exit( task) *int{
	c._default_exit(task)
	c._current_task = nil
	c.returncode = task.returncode
	return c.returncode
}

func(c*CompositeTask) _default_final_exit( task) int {
	c._final_exit(task)
	return c.wait()
}

func(c*CompositeTask) _start_task(task ITask, exit_handler func(*int)) {
	//try{
	//task.scheduler = c.scheduler
	//except AttributeError{
	//pass
	task.addExitListener(exit_handler)
	c._current_task = task
	task.start()
}

func(c*CompositeTask) _task_queued(task *EbuildPhase) {
	task.addStartListener(c._task_queued_start_handler)
	c._current_task = c._TASK_QUEUED
}

func(c*CompositeTask) _task_queued_start_handler( task ITask) {
	c._current_task = task
}

func(c*CompositeTask) _task_queued_wait() bool {
	return c._current_task != c._TASK_QUEUED ||
		c.cancelled || c.returncode != nil
}

func NewCompositeTask()*CompositeTask {
	c := &CompositeTask{}
	c._TASK_QUEUED = -1
	c.AsynchronousTask = NewAsynchronousTask()
	return c
}

// slot object
type Dependency struct {
	// slot
	depth int
	collapsed_priority, priority *DepPriority
	atom,blocker,child,
	parent,onlydeps,root,want_update,
	collapsed_parent
}

func NewDependency()*Dependency{
	d := &Dependency{}
	SlotObject.__init__(d, **kwargs)
	if d.priority ==nil {
		d.priority = NewDepPriority(false)
	}
	if d.depth == 0 {
		d.depth = 0
	}
	if d.collapsed_parent == nil {
		d.collapsed_parent = d.parent
	}
	if d.collapsed_priority == nil {
		d.collapsed_priority = d.priority
	}
	return d
}

type DependencyArg struct {
	// slot
	arg                                    string
	root_config                            *RootConfig
	force_reinstall, internal, reset_depth bool
}

func(d*DependencyArg) __eq__(other*DependencyArg) bool{
	return d.arg == other.arg&& d.root_config.root == other.root_config.root
}

func(d*DependencyArg) __hash__() {
	return hash((d.arg, d.root_config.root))
}

func(d*DependencyArg) __str__() string {
	return fmt.Sprintf("%s" ,d.arg,)
}

// "", false, false, true, nil
func NewDependencyArg(arg string, force_reinstall, internal,
	reset_depth bool, root_config*RootConfig)*DependencyArg {
	d := &DependencyArg{}
	d.arg = arg
	d.force_reinstall = force_reinstall
	d.internal = internal
	d.reset_depth = reset_depth
	d.root_config = root_config
	return d
}

type DepPriority struct{
	*AbstractDepPriority

	// slot
	satisfied, optional, ignored
}

func(d*DepPriority) __int__() int {
	if d.optional {
		return -4
	}
	if d.buildtime_slot_op {
		return 0
	}
	if d.buildtime {
		return -1
	}
	if d.runtime {
		return -2
	}
	if d.runtime_post {
		return -3
	}
	return -5
}

func(d *DepPriority) __str__() string {
	if d.ignored {
		return "ignored"
	}
	if d.optional {
		return "optional"
	}
	if d.buildtime_slot_op {
		return "buildtime_slot_op"
	}
	if d.buildtime {
		return "buildtime"
	}
	if d.runtime_slot_op {
		return "runtime_slot_op"
	}
	if d.runtime {
		return "runtime"
	}
	if d.runtime_post {
		return "runtime_post"
	}
	return "soft"
}

func NewDepPriority(buildTime bool)*DepPriority {
	d := &DepPriority{}
	d.AbstractDepPriority = &AbstractDepPriority{}
	d.buildtime = buildTime
	return d
}

type EbuildBinpkg struct {
	*CompositeTask
	// slot
	settings *Config
	_binpkg_tmpfile string
	pkg, _binpkg_info
}

func (e *EbuildBinpkg) _start() {
	pkg := e.pkg
	root_config := pkg.root_config
	bintree := root_config.trees["bintree"]
	binpkg_tmpfile := filepath.Join(bintree.pkgdir,
		pkg.cpv+".tbz2."+fmt.Sprint(os.Getpid()))
	bintree._ensure_dir(filepath.Dir(binpkg_tmpfile))

	e._binpkg_tmpfile = binpkg_tmpfile
	e.settings.ValueDict["PORTAGE_BINPKG_TMPFILE"] = e._binpkg_tmpfile

	package_phase := NewEbuildPhase(nil, e.background, "package", e.scheduler, e.settings, nil)

	e._start_task(package_phase, e._package_phase_exit)
}

func (e *EbuildBinpkg) _package_phase_exit( package_phase) {

	delete(e.settings.ValueDict,"PORTAGE_BINPKG_TMPFILE")
	if e._default_exit(package_phase) != 0 {
		if err := syscall.Unlink(e._binpkg_tmpfile); err != nil {
			//except OSError:
			//pass
		}
		e.wait()
		return
	}

	pkg := e.pkg
	bintree := pkg.root_config.trees["bintree"]
	e._binpkg_info = bintree.inject(pkg.cpv,
		filename = e._binpkg_tmpfile)

	e._current_task = nil
	i := 0
	e.returncode = &i
	e.wait()
}

func (e *EbuildBinpkg) get_binpkg_info() {
	return e._binpkg_info
}

func NewEbuildBinpkg(background bool, pkg *PkgStr, scheduler *SchedulerInterface, settings *Config)*EbuildBinpkg{
	e := &EbuildBinpkg{}
	e.CompositeTask = NewCompositeTask()
	e.background = background
	e.pkg= pkg
	e.scheduler=scheduler
	e.settings=settings

	return e
}

type EbuildBuild struct {
	*CompositeTask
	settings            *Config

	// slot
	_tree, _ebuild_path string
	pkg                 *PkgStr
	_build_dir          *EbuildBuildDir
	_buildpkg,_issyspkg bool
	args_set, config_pool, find_blockers,
	ldpath_mtimes, logger, opts, pkg, pkg_count,
	prefetcher, world_atom,

}

func(e *EbuildBuild) _start() {
	if not e.opts.fetchonly {
		rval := _check_temp_dir(e.settings)
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
	doebuild_environment(ebuild_path, "setup", nil, e.settings, false, nil, portdb)

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
			out := NewEOutput(false)
			for _, l := range msg {
				out.einfo(l)
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
		success = digestcheck([]string{}, settings, true, nil)
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
					portdb = e.pkg.root_config.trees[e._tree].dbapi,
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
		portdb = e.pkg.root_config.trees[e._tree].dbapi
		e._start_task(NewSpawnNofetchWithoutBuilddir(e.background,
			portdb = portdb,
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

	prepare_build_dirs(e.settings, 1)

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
	elog_process(e.pkg.cpv, e.settings, nil)
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
	for pkg_fmt := range SUPPORTED_BINPKG_FORMATS {
		if Ins(
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

type _RecordBinpkgInfo struct {
	*AsynchronousTask
	//slot
	ebuild_binpkg *EbuildBinpkg
	ebuild_build  *EbuildBuild
}

func (r *_RecordBinpkgInfo) _start() {
	r.ebuild_build._record_binpkg_info(r.ebuild_binpkg)
	r.AsynchronousTask._start()
}

func NewRecordBinpkgInfo(ebuild_binpkg *EbuildBinpkg, ebuild_build *EbuildBuild)*_RecordBinpkgInfo {
	r := &_RecordBinpkgInfo{}
	r.AsynchronousTask = NewAsynchronousTask()
	r.ebuild_binpkg = ebuild_binpkg
	r.ebuild_build = ebuild_build
	return r
}

func (r *EbuildBuild)	_buildpkg_exit( packager){

	if r._default_exit(packager) != 0 {
		r._async_unlock_builddir(r.returncode)
		return
	}

	if r.opts.buildpkgonly {
		phase := "success_hooks"
		success_hooks := NewMiscFunctionsProcess(
			r.background, []string{phase}, phase, "", nil,
			r.scheduler, r.settings)
		r._start_task(success_hooks,
			r._buildpkgonly_success_hook_exit)
		return
	}

	r._current_task = nil
	r.returncode = packager.returncode
	r.wait()
}

func (r *EbuildBuild) _record_binpkg_info( task) {
	if task.returncode != 0 {
		return
	}

	pkg := task.get_binpkg_info()
	infoloc := filepath.Join(r.settings.ValueDict["PORTAGE_BUILDDIR"],
		"build-info")
	info := map[string]string{
		"BINPKGMD5": fmt.Sprintf("%s\n", pkg._metadata["MD5"]),
	}
	if pkg.build_id != nil {
		info["BUILD_ID"] = fmt.Sprintf("%s\n", pkg.build_id)
	}
	for k, v := range info {
		f, _ := os.OpenFile(filepath.Join(infoloc, k), os.O_RDWR|os.O_CREATE, 0644)
		f.Write([]byte(v))
	}
}

func (r *EbuildBuild) _buildpkgonly_success_hook_exit( success_hooks) {
	r._default_exit(success_hooks)
	r.returncode = nil
	elog_process(r.pkg.cpv.string, r.settings, nil)
	phase := "clean"
	clean_phase := NewEbuildPhase(nil, r.background, phase,r.scheduler, r.settings, nil)
	r._start_task(clean_phase, r._clean_exit)
}

func (r *EbuildBuild) _clean_exit( clean_phase) {
	if r._final_exit(clean_phase) != 0 || r.opts.buildpkgonly {
		r._async_unlock_builddir(r.returncode)
	} else {
		r.wait()
	}
}

func (r *EbuildBuild) create_install_task() *EbuildMerge {

	ldpath_mtimes := r.ldpath_mtimes
	logger := r.logger
	pkg := r.pkg
	pkg_count := r.pkg_count
	settings := r.settings
	world_atom := r.world_atom
	ebuild_path := r._ebuild_path
	tree := r._tree

	task := NewEbuildMerge(r._install_exit,
		r.find_blockers, ldpath_mtimes, logger, pkg,
		pkg_count, ebuild_path, r.scheduler, settings, tree, world_atom)

	msg := fmt.Sprintf(" === (%s of %s) Merging (%s::%s)",
		pkg_count.curval, pkg_count.maxval,
		pkg.cpv, ebuild_path)
	short_msg := fmt.Sprintf("emerge: (%s of %s) %s Merge",
		pkg_count.curval, pkg_count.maxval, pkg.cpv)
	logger.log(msg, short_msg = short_msg)

	return task
}

func (r *EbuildBuild) _install_exit(task) IFuture {
	r._async_unlock_builddir(nil)
	var result IFuture
	if r._current_task == nil {
		result = r.scheduler.create_future()
		r.scheduler.call_soon(func() {result.set_result(0)})
	}else {
		result = r._current_task.async_wait()
	}
	return result
}

//
func NewEbuildBuild(args_set = args_set,
	background = m.background,
	config_pool=m.config_pool,
	find_blockers = find_blockers,
	ldpath_mtimes=ldpath_mtimes, logger = logger,
	opts=build_opts, pkg = pkg, pkg_count=pkg_count,
	prefetcher = m.prefetcher, scheduler=scheduler,
	settings = settings, world_atom=world_atom)*EbuildBuild{
	e := &EbuildBuild{}
	e.CompositeTask=NewCompositeTask()
	return e
}

type EbuildBuildDir struct {
	// slot
	scheduler *SchedulerInterface
	_catdir string
	_lock_obj *AsynchronousLock
	settings *Config
	locked bool
}

func NewEbuildBuildDir(scheduler *SchedulerInterface, settings *Config **kwargs)*EbuildBuildDir {
	e := &EbuildBuildDir{}
	e.scheduler = scheduler
	e.settings = settings
	e.locked = false

	return e
}

func (e*EbuildBuildDir) _assert_lock( async_lock *AsynchronousLock) error {
	if async_lock.returncode == nil || *async_lock.returncode != 0 {
		//raise AssertionError("AsynchronousLock failed with returncode %s"
		//% (async_lock.returncode,))
		return errors.New("")
	}
	return nil
}

func (e*EbuildBuildDir) clean_log() {
	settings := e.settings
	if settings.Features.Features["keepwork"] {
		return
	}
	log_file := settings.ValueDict["PORTAGE_LOG_FILE"]
	if log_file != "" {
		st, err := os.Stat(log_file)
		if err != nil && !st.IsDir() {
			if err := syscall.Unlink(log_file); err != nil {
				//except OSError:
				//pass
			}
		}
	}
}

func (e*EbuildBuildDir) async_lock() IFuture {
	if e._lock_obj != nil {
		//raise
		//e.AlreadyLocked((e._lock_obj, ))
	}

	dir_path := e.settings.ValueDict["PORTAGE_BUILDDIR"]
	if dir_path == "" {
		//raise
		//AssertionError('PORTAGE_BUILDDIR is unset')
	}
	catdir := filepath.Dir(dir_path)
	e._catdir = catdir
	catdir_lock := NewAsynchronousLock(catdir, e.scheduler)
	builddir_lock := NewAsynchronousLock(dir_path, e.scheduler)
	result := e.scheduler.create_future()

	// nil
	catdir_unlocked := func(future IFuture, exception error) {
		if !(exception == nil && future.exception() == nil) {
			if exception != nil {
				result.set_exception(exception)
			} else {
				result.set_exception(future.exception())
			}
		} else {
			result.set_result(nil)
		}
	}

	builddir_locked := func(builddir_lock *AsynchronousLock) {
		if err := e._assert_lock(builddir_lock); err != nil {
			//except AssertionError as e:
			catdir_lock.async_unlock().add_done_callback(
				catdir_unlocked) // exception = e
			return
		}

		e._lock_obj = builddir_lock
		e.locked = true
		e.settings.ValueDict["PORTAGE_BUILDDIR_LOCKED"] = "1"
		catdir_lock.async_unlock().add_done_callback(catdir_unlocked)
	}

	catdir_locked := func(catdir_lock*AsynchronousLock) {
		if err:=e._assert_lock(catdir_lock); err!= nil {
			//except AssertionError as e:
			result.set_exception(err)
			return
		}

		//try:
		ensureDirs(catdir, -1, *portage_gid, 070, 0, nil, true)
		//except PortageException as e:
		//if ! filepath.Dir(catdir) {
		//	result.set_exception(e)
		//	return
		//}

		builddir_lock.addExitListener(builddir_locked)
		builddir_lock.start()
	}

	//try:
	ensureDirs(filepath.Dir(catdir), -1, *portage_gid, 070, 0, nil, true)
	//except PortageException:
	//if not filepath.Dir(filepath.Dir(catdir)):
	//raise

	catdir_lock.addExitListener(catdir_locked)
	catdir_lock.start()
	return result
}

func (e*EbuildBuildDir) async_unlock() IFuture {
	result := e.scheduler.create_future()

	catdir_unlocked := func(future IFuture) {
		if future.exception() == nil {
			result.set_result(nil)
		} else {
			result.set_exception(future.exception())
		}
	}

	catdir_locked := func(catdir_lock *AsynchronousLock) {
		if catdir_lock.wait() != 0 {
			result.set_result(nil)
		} else {
			if err := os.RemoveAll(e._catdir); err != nil {
				//except OSError:
				//pass
			}
			catdir_lock.async_unlock().add_done_callback(func(future IFuture, err error) {
				catdir_unlocked(future)
			})
		}
	}

	builddir_unlocked := func(future IFuture) {
		if future.exception() != nil {
			result.set_exception(future.exception())
		} else {
			e._lock_obj = nil
			e.locked = false
			delete(e.settings.ValueDict, "PORTAGE_BUILDDIR_LOCKED")
			catdir_lock := NewAsynchronousLock(e._catdir, e.scheduler)
			catdir_lock.addExitListener(catdir_locked)
			catdir_lock.start()
		}
	}

	if e._lock_obj == nil {
		e.scheduler.call_soon(func() { result.set_result(nil) })
	} else {
		e._lock_obj.async_unlock().add_done_callback(func(future IFuture, err error) {
			builddir_unlocked(future)
		})
	}
	return result
}

type AlreadyLocked struct {
	PortageException
}

type EbuildExecuter struct {
	*CompositeTask
	// slot
	pkg *PkgStr
	settings *Config
}

var _phases = []string{"prepare", "configure", "compile", "test", "install"}

func (e*EbuildExecuter)_start() {
	pkg := e.pkg
	scheduler := e.scheduler
	settings := e.settings
	cleanup := 0
	prepare_build_dirs(settings, cleanup!=0)

	if eapiExportsReplaceVars(settings.ValueDict["EAPI"]) {
		vardb := pkg.root_config.trees['vartree'].dbapi
		settings.ValueDict["REPLACING_VERSIONS"] = " ".join(
			set(cpvGetVersion(match, "") \
		for match
			in
		vardb.match(pkg.slot_atom) + \
		vardb.match('=' + pkg.cpv)))

		setup_phase := NewEbuildPhase(nil, e.background, "setup", scheduler, settings, nil)

		setup_phase.addExitListener(e._setup_exit)
		e._task_queued(setup_phase)
		e.scheduler.scheduleSetup(setup_phase)
	}
}

func (e*EbuildExecuter) _setup_exit( setup_phase) {

	if e._default_exit(setup_phase) != 0 {
		e.wait()
		return
	}

	unpack_phase := NewEbuildPhase(nil, e.background, "unpack", e.scheduler, e.settings, nil)

	if Ins(strings.Fields(
		e.settings.ValueDict["PROPERTIES"]), "live") {

		unpack_phase.addExitListener(e._unpack_exit)
		e._task_queued(unpack_phase)
		e.scheduler.scheduleUnpack(unpack_phase)

	} else {
		e._start_task(unpack_phase, e._unpack_exit)
	}
}

func (e*EbuildExecuter) _unpack_exit( unpack_phase) {

	if e._default_exit(unpack_phase) != 0 {
		e.wait()
		return
	}

	ebuild_phases := NewTaskSequence(e.scheduler)

	pkg = e.pkg
	phases := e._phases
	eapi := pkg.eapi
	if ! eapiHasSrcPrepareAndSrcConfigure(eapi) {
		phases = phases[2:]
	}

	for phase
	in
phases {
		ebuild_phases.add(NewEbuildPhase(nil, e.background, phase, e.scheduler, e.settings, nil))
	}

	e._start_task(ebuild_phases, e._default_final_exit)
}

func NewEbuildExecuter(background bool, pkg *PkgStr, scheduler *SchedulerInterface, settings *Config)*EbuildExecuter{
	e := &EbuildExecuter{}
	e.CompositeTask = NewCompositeTask()
	e.background = background
	e.pkg = pkg
	e.scheduler = scheduler
	e.settings = settings
	return e
}


type EbuildFetcher struct {
	*CompositeTask
	//slots
	prefetch bool
	logfile string
	_fetcher_proc *_EbuildFetcherProcess
	config_pool*_ConfigPool
	ebuild_path string
	fetchonly, fetchall,
	pkg, _fetcher_proc
}

func NewEbuildFetcher(config_pool *_ConfigPool,ebuild_path string,
	fetchall,fetchonly, background bool,logfile string,pkg,scheduler *SchedulerInterface,prefetch bool, **kwargs) *EbuildFetcher {
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

func (e*EbuildFetcher) async_already_fetched(settings *Config) {
	return e._fetcher_proc.async_already_fetched(settings)
}

func (e*EbuildFetcher) _start() {
	e._start_task(
		NewAsyncTaskFuture(e._fetcher_proc._async_uri_map()),
	e._start_fetch)
}

func (e*EbuildFetcher) _start_fetch( uri_map_task) {
	e._assert_current(uri_map_task)
	if uri_map_task.cancelled {
		e._default_final_exit(uri_map_task)
		return
	}

try:
	uri_map = uri_map_task.future.result()
	except
	portage.exception.InvalidDependString
	as
e:
	msg_lines := []string{}
	msg = "Fetch failed for '%s' due to invalid SRC_URI: %s" % \
	(e.pkg.cpv, e)
	msg_lines.append(msg)
	e._fetcher_proc._eerror(msg_lines)
	e._current_task = None
	e.returncode = 1
	e._async_wait()
	return

	e._start_task(
		NewAsyncTaskFuture(
			e.pkg.root_config.trees["porttree"].dbapi.
	async_aux_get(e.pkg.cpv, ["SRC_URI"], myrepo = e.pkg.repo,
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
	_manifest *Manifest
	_digests map[string]map[string]string
	_settings *Config
	config_pool *_ConfigPool
	src_uri string
	pkg *PkgStr
	fetchonly, fetchall,
	 prefetch,
	_uri_map
}

func(e*_EbuildFetcherProcess) async_already_fetched(settings *Config) {
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

func(e*_EbuildFetcherProcess) _check_already_fetched( settings *Config, uri_map) {
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
	eout = NewEOutput(false)
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
	ok, st = _check_distfile(filepath.Join(distdir, filename),
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
	doebuild_environment(ebuild_path, "fetch", nil,
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
	e.ForkProcess._start()

	e.config_pool.deallocate(settings)
	settings = nil
	e._settings = nil
}

func(e*_EbuildFetcherProcess) _run() {
	HaveColor = !(e._settings.ValueDict["NOCOLOR"]== "yes" ||e._settings.ValueDict["NOCOLOR"]== "true")

	if _want_userfetch(e._settings) {
		_drop_privs_userfetch(e._settings)
	}

	rval := 1
	allow_missing := e._get_manifest().allow_missing||e._settings.Features.Features["digest"]
	if fetch(e._uri_map, e._settings, fetchonly = e.fetchonly,
		digests = copy.deepcopy(e._get_digests()),
		allow_missing_digests = allow_missing){
		rval = 0
	}
	return rval
}

func(e*_EbuildFetcherProcess) _get_ebuild_path() string {
	if e.ebuild_path != "" {
		return e.ebuild_path
	}
	portdb = e.pkg.root_config.trees["porttree"].dbapi
	e.ebuild_path = portdb.findname(e.pkg.cpv, myrepo = e.pkg.repo)
	if e.ebuild_path == "" {
		//raise AssertionError("ebuild not found for '%s'" % e.pkg.cpv)
	}
	return e.ebuild_path
}

func(e*_EbuildFetcherProcess) _get_manifest() *Manifest{
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

func(e*_EbuildFetcherProcess) _async_uri_map() IFuture{
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
	portdb = e.pkg.root_config.trees["porttree"].dbapi


	cache_result:= func(result) {
	try:
		e._uri_map = result.result()
		except
	Exception:
		pass
	}

	result := portdb.async_fetch_map(e.pkg.cpv,
		useflags = use, mytree = mytree, loop=e.scheduler)
	result.add_done_callback(cache_result)
	return result
}

func(e*_EbuildFetcherProcess) _prefetch_size_ok(uri_map, settings *Config, ebuild_path string) bool{
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
		eerror(line, "unpack", e.pkg.cpv.string, out)
	}
	msg := out.String()
	if msg!= "" {
		e.scheduler.output(msg, e.logfile, false, 0, -1)
	}
}

func(e*_EbuildFetcherProcess) _proc_join_done( proc, future IFuture) {
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

func NewEbuildFetcherProcess()*_EbuildFetcherProcess{
	e := &_EbuildFetcherProcess{}
	e.ForkProcess = NewForkProcess()
	return e
}

type EbuildFetchonly struct {
	settings *Config
	pretend int
	pkg *PkgStr
	fetch_all,
}

func (e *EbuildFetchonly) execute() int {
	settings := e.settings
	pkg := e.pkg
	portdb := pkg.root_config.trees["porttree"].dbapi
	ebuild_path := portdb.findname(pkg.cpv, myrepo = pkg.repo)
	if ebuild_path == "" {
		raise AssertionError("ebuild not found for '%s'" % pkg.cpv)
	}
	settings.SetCpv(pkg)
	debug := settings.ValueDict["PORTAGE_DEBUG"] == "1"

	rval := doebuild(ebuild_path, "fetch", settings, debug, e.pretend,
		1, 0, 1, e.fetch_all,"porttree", portdb, nil, nil, nil, false )

	if rval != 1 && e.pretend == 0{
		msg := fmt.Sprintf("Fetch failed for '%s'" ,pkg.cpv, )
		eerror(msg, "unpack", pkg.cpv.string, nil)
	}
	return rval
}

func NewEbuildFetchonly(fetch_all , pkg *PkgStr, pretend int, settings *Config)*EbuildFetchonly {
	e := &EbuildFetchonly{}
	e.settings = settings

	e.fetch_all = fetch_all
	e.pkg = pkg
	e.pretend = pretend

	return e
}

type EbuildIpcDaemon struct {
	*FifoIpcDaemon
	commands
}

func (e *EbuildIpcDaemon) _input_handler() {
	data := e._read_buf(e._files.pipe_in)
	if data == nil {
		//pass
	}else if len(data) > 0 {
	try:
		obj = pickle.loads(data)
		except
	SystemExit:
		raise
		except
	Exception:
		pass
		else:

		e._reopen_input()

		cmd_key = obj[0]
		cmd_handler = e.commands[cmd_key]
		reply = cmd_handler(obj)
	try:
		e._send_reply(reply)
		except
		OSError
		as
	e:
		if err == errno.ENXIO:
		pass
		else:
		raise

		reply_hook = getattr(cmd_handler,
			'reply_hook', nil)
		if reply_hook != nil:
		reply_hook()

	}else {
		lock_filename := filepath.Join(
			filepath.Dir(e.input_fifo), ".ipc_lock")
		lock_obj, err := Lockfile(lock_filename, false, true, "", os.O_NONBLOCK)
		if err != nil {
			//except TryAgain:
			//pass
		}else {
			//try:
			e._reopen_input()
			//finally:
			Unlockfile(lock_obj)
		}
	}
}

func (e *EbuildIpcDaemon) _send_reply( reply) {
	output_fd, err := os.OpenFile(e.output_fifo,
		os.O_WRONLY|syscall.O_NONBLOCK, 0644)
	if err != nil {
		//except OSError as e:
		WriteMsgLevel(fmt.Sprintf("!!! EbuildIpcDaemon %s: %s\n",
			"failed to send reply", e), 40, -1)
	} else {
		//try:
		output_fd.Write(pickle.dumps(reply))
		//finally:
		output_fd.Close()
	}
}

func NewEbuildIpcDaemon(commands map[string]*QueryCommand, input_fifo, output_fifo string, scheduler *SchedulerInterface) *EbuildIpcDaemon{
	e := &EbuildIpcDaemon{}
	e.FifoIpcDaemon = NewFifoIpcDaemon()
	e.commands = commands
	e.input_fifo = input_fifo
	e.output_fifo = output_fifo
	e.scheduler = scheduler
	return e
}

type EbuildMerge struct {
	*CompositeTask

	// slot
	settings *Config
	tree string
	exit_hook func()
	logger*_emerge_log_class
	pkg_count *_pkg_count_class
	pkg_path string
	world_atom func()
	 find_blockers,  ldpath_mtimes,
	pkg, postinst_failure, pretend
}

func (e*EbuildMerge) _start() {
	root_config := e.pkg.root_config
	settings := e.settings
	mycat := settings.ValueDict["CATEGORY"]
	mypkg := settings.ValueDict["PF"]
	pkgloc := settings.ValueDict["D"]
	infloc := filepath.Join(settings.ValueDict["PORTAGE_BUILDDIR"], "build-info")
	myebuild := settings.ValueDict["EBUILD"]
	mydbapi := root_config.trees[e.tree].dbapi
	vartree := root_config.trees["vartree"]
	background := settings.ValueDict["PORTAGE_BACKGROUND"] == "1"
	logfile := settings.ValueDict["PORTAGE_LOG_FILE"]

	merge_task := NewMergeProcess(
		mycat, mypkg, settings, e.tree, vartree, e.scheduler,
		background, e.find_blockers, pkgloc, infloc, myebuild, mydbapi,
		e.ldpath_mtimes, logfile, nil)

	e._start_task(merge_task, e._merge_exit)
}

func (e*EbuildMerge) _merge_exit( merge_task) {
	if e._final_exit(merge_task) != 0 {
		e._start_exit_hook(e.returncode)
		return
	}

	e.postinst_failure = merge_task.postinst_failure
	pkg := e.pkg
	e.world_atom(pkg)
	pkg_count := e.pkg_count
	pkg_path := e.pkg_path
	logger := e.logger
	if !e.settings.Features.Features["noclean"] {
		short_msg := fmt.Sprintf("emerge: (%s of %s) %s Clean Post",
			pkg_count.curval, pkg_count.maxval, pkg.cpv)
		logger.log(fmt.Sprintf(" === (%s of %s) Post-Build Cleaning (%s::%s)",
			pkg_count.curval, pkg_count.maxval, pkg.cpv, pkg_path), short_msg)
	}
	logger.log(fmt.Sprintf(" ::: completed emerge (%s of %s) %s to %s",
		pkg_count.curval, pkg_count.maxval, pkg.cpv, pkg.root), "")

	e._start_exit_hook(e.returncode)
}

func (e*EbuildMerge) _start_exit_hook(returncode *int) {
	e.returncode = nil
	e._start_task(
		NewAsyncTaskFuture(e.exit_hook(e)),
		func(task) { e._exit_hook_exit(returncode, task) })
}

func (e*EbuildMerge) _exit_hook_exit(returncode *int, task) {
	e._assert_current(task)
	e.returncode = returncode
	e._async_wait()
}

func NewEbuildMerge(exit_hook func(), find_blockers , ldpath_mtimes,
	logger *_emerge_log_class, pkg, pkg_count *_pkg_count_class,
	pkg_path string, scheduler *SchedulerInterface,
	settings *Config, tree string, world_atom func())*EbuildMerge {
	e := &EbuildMerge{}
	e.CompositeTask = NewCompositeTask()
	e.exit_hook = exit_hook
	e.find_blockers = find_blockers
	e.ldpath_mtimes = ldpath_mtimes
	e.logger = logger
	e.pkg = pkg
	e.pkg_count = pkg_count
	e.pkg_path = pkg_path
	e.scheduler = scheduler
	e.settings = settings
	e.tree = tree
	e.world_atom = world_atom

	return e
}

type EbuildMetadataPhase struct {
	*SubProcess
	_files *struct{ ebuild int}
	//slot
	_eapi,repo_path          string
	_eapi_lineno   int
	eapi_supported bool
	metadata map[string]string
	settings *Config
	fd_pipes map[int]int
	portdb *portdbapi
	_raw_metadata []string
	cpv, ebuild_hash,   write_auxdb
}

func(e *EbuildMetadataPhase) _start() {
	ebuild_path := e.ebuild_hash.location

	f, _ := ioutil.ReadFile(ebuild_path)
	e._eapi, e._eapi_lineno =ParseEapiEbuildHead(strings.Split(string(f), "\n"))

	parsed_eapi := e._eapi
	if parsed_eapi == "" {
		parsed_eapi = "0"
	}

	if  parsed_eapi=="" {
		e._eapi_invalid(nil)
		i := 1
		e.returncode = &i
		e._async_wait()
		return
	}

	e.eapi_supported = eapiIsSupported(parsed_eapi)
	if ! e.eapi_supported {
		e.metadata =map[string]string{
			"EAPI": parsed_eapi,
		}
		i:= 0
		e.returncode =&i
		e._async_wait()
		return
	}

	settings := e.settings
	settings.SetCpv(e.cpv)
	settings.configDict["pkg"]["EAPI"] = parsed_eapi

	debug := settings.ValueDict["PORTAGE_DEBUG"] == "1"
	var fd_pipes map[int]int
	if e.fd_pipes != nil {
		fd_pipes = map[int]int{}
		for k, v := range e.fd_pipes{
			fd_pipes[k]=v
		}
	}else {
		fd_pipes = map[int]int{}
	}

	null_input, _ := os.Open("/dev/null")
	if _, ok := fd_pipes[0];!ok {
		fd_pipes[0] = int(null_input.Fd())
	}
	if _, ok := fd_pipes[1];!ok {
		fd_pipes[1] = syscall.Stdout
	}
	if _, ok := fd_pipes[2];!ok {
		fd_pipes[2] = syscall.Stderr
	}

	for _, fd:= range fd_pipes {
		if fd == syscall.Stdout||fd ==syscall.Stderr{
			break
		}
	}

	e._files = &struct{ebuild int}{}
	files := e._files

	pps := make([]int,2)
	syscall.Pipe(pps)
	master_fd, slave_fd := pps[0],pps[1]

	arg, _ := unix.FcntlInt(uintptr(master_fd),syscall.F_GETFL, 0)
	unix.FcntlInt(uintptr(master_fd), syscall.F_SETFL, arg|syscall.O_NONBLOCK)

	arg2, _ := unix.FcntlInt(uintptr(master_fd),syscall.F_GETFD, 0)
	unix.FcntlInt(uintptr(master_fd), syscall.F_SETFD, arg2|syscall.FD_CLOEXEC)

	fd_pipes[slave_fd] = slave_fd
	settings.ValueDict["PORTAGE_PIPE_FD"] = fmt.Sprint(slave_fd)

	e._raw_metadata = []string{}
	files.ebuild = master_fd
	e.scheduler.add_reader(files.ebuild, e._output_handler)
	e._registered = true

	retval := doebuild(ebuild_path, "depend",
		settings, debug, 0, 0, 0, 1, 0,
		"porttree", e.portdb, nil, nil, fd_pipes, true)
	delete(settings.ValueDict,"PORTAGE_PIPE_FD")

	syscall.Close(slave_fd)
	null_input.Close()

	//if isinstance(retval, int):
	e.returncode = &retval
	e._async_wait()
	return

	//e.pid = retval[0]
}

func(e *EbuildMetadataPhase) _output_handler() {
	for{
		buf := e._read_buf(e._files.ebuild)
		if buf == nil {
			break
		}else if len(buf) > 0 {
			e._raw_metadata=append(e._raw_metadata, string(buf))
		}else {
			if e.pid == 0 {
				e._unregister()
				e._async_wait()
			}else {
				e._async_waitpid()
			}
			break
		}
	}
}

func(e *EbuildMetadataPhase) _unregister() {
	if e._files != nil {
		e.scheduler.remove_reader(e._files.ebuild)
	}
	e.SubProcess._unregister()
}

func(e *EbuildMetadataPhase) _async_waitpid_cb( *args, **kwargs) {
	e.SubProcess._async_waitpid_cb(*args, **kwargs)
	if e.returncode != nil && *e.returncode == 0 && e._raw_metadata != nil {
		metadata_lines := strings.Split(strings.Join(e._raw_metadata, ""), "\n")
		metadata_valid := true
		metadata := map[string]string{}
		if len(auxdbkeys) != len(metadata_lines) {
			metadata_valid = false
		} else {
			adk := sortedmsb(auxdbkeys)
			for i := range adk {
				metadata[adk[i]] = metadata_lines[i]
			}
			parsed_eapi := e._eapi
			if parsed_eapi == "" {
				parsed_eapi = "0"
			}
			e.eapi_supported = eapiIsSupported(metadata["EAPI"])
			if (metadata["EAPI"] == "" || e.eapi_supported) && metadata["EAPI"] != parsed_eapi {
				e._eapi_invalid(metadata)
				metadata_valid = false
			}
		}

		if metadata_valid {
			if e.eapi_supported {
				if metadata["INHERITED"] != "" {
					metadata["_eclasses_"] = e.portdb.repositories.getRepoForLocation(
						e.repo_path).eclassDb.get_eclass_data(
						metadata["INHERITED"].split())
				} else {
					metadata["_eclasses_"] =
					{
					}
				}
				delete(metadata, "INHERITED")

				if eapiHasAutomaticUnpackDependencies(metadata["EAPI"]) {
					repo := e.portdb.repositories.getNameForLocation(e.repo_path)
					unpackers := e.settings.unpackDependencies[repo][metadata["EAPI"]]
					unpack_dependencies := extractUnpackDependencies(metadata["SRC_URI"], unpackers)
					if unpack_dependencies != "" {
						if metadata["DEPEND"] != "" {
							metadata["DEPEND"] += " "
						}
						metadata["DEPEND"] += unpack_dependencies
					}
				}

				if e.write_auxdb is
				not
				false{
					e.portdb._write_cache(e.cpv,
						e.repo_path, metadata, e.ebuild_hash)
				}
			} else {
				metadata = map[string]string{
					"EAPI": metadata["EAPI"],
				}
			}
			e.metadata = metadata
		} else {
			i := 1
			e.returncode = &i
		}
	}
}

func(e *EbuildMetadataPhase) _eapi_invalid( metadata map[string]string) {
	repo_name := e.portdb.getRepositoryName(e.repo_path)
	eapi_var := ""
	if metadata!= nil {
		eapi_var = metadata["EAPI"]
	}
	eapi_invalid(e, e.cpv, repo_name, e.settings,
		eapi_var, e._eapi, e._eapi_lineno)
}

func NewEbuildMetadataPhase(cpv string, ebuild_hash, portdb portdbapi, repo_path string, scheduler = loop, settings *Config)*EbuildMetadataPhase {
	e := &EbuildMetadataPhase{}
	e.SubProcess = NewSubProcess()
	e.cpv = cpv
	e.ebuild_hash = ebuild_hash
	e.portdb = portdb
	e.repo_path = repo_path
	e.scheduler = scheduler
	e.settings = settings
	return e
}

type EbuildPhase struct {
	*CompositeTask

	// slot
	actionmap    Actionmap
	phase        string
	_ebuild_lock *AsynchronousLock
	settings     *Config
	fd_pipes     map[int]int

	_features_display []string
	_locked_phases    []string
}

func NewEbuildPhase(actionmap Actionmap, background bool, phase string, scheduler *SchedulerInterface, settings *Config, fd_pipes map[int]int) *EbuildPhase {	e := &EbuildPhase{}
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
	e.fd_pipes = fd_pipes

	return e
}

func (e *EbuildPhase) _start() {

	need_builddir := Ins(NewEbuildProcess(nil, false, nil, "", "", nil, nil)._phases_without_builddir, e.phase)

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
		if MetaDataXML != nil && pathIsFile(metadata_xml_path) {
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
			if enabled_features[ x]{
				relevant_features = append(relevant_features, x)
			}
		}
		if len(relevant_features) > 0 {
			msg = append(msg, fmt.Sprintf("FEATURES:   %s", strings.Join(relevant_features, " ")))
		}

		e._elog("einfo", msg, true)
	}

	if e.phase == "package" {
		if _, ok := e.settings.ValueDict["PORTAGE_BINPKG_TMPFILE"]; !ok{
			e.settings.ValueDict["PORTAGE_BINPKG_TMPFILE"] =
				filepath.Join(e.settings.ValueDict["PKGDIR"],
					e.settings.ValueDict["CATEGORY"], e.settings.ValueDict["PF"]) + ".tbz2"
		}
	}

	if e.phase  == "pretend" || e.phase ==  "prerm" {
		env_extractor := NewBinpkgEnvExtractor(e.background,
			e.scheduler, e.settings)
		if env_extractor.saved_env_exists() {
			e._start_task(env_extractor, e._env_extractor_exit)
			return
		}
	}

	e._start_lock()
}

func (e *EbuildPhase) _env_extractor_exit( env_extractor) {
	if e._default_exit(env_extractor) != 0 {
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
		if osAccess(filepath.Dir(lock_path), unix.W_OK) {
			e._ebuild_lock = NewAsynchronousLock(lock_path, e.scheduler)
			e._start_task(e._ebuild_lock, e._lock_exit)
			return
		}
	}

	e._start_ebuild()
}

func (e *EbuildPhase) _lock_exit( ebuild_lock) {
	if e._default_exit(ebuild_lock) != 0 {
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
		e._start_task(NewPackagePhase(e.actionmap, e.background, e.fd_pipes,
			e._get_log_path(), e.scheduler, e.settings), e._ebuild_exit)
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

	ebuild_process := NewEbuildProcess(e.actionmap,
		e.background, fd_pipes,
		e._get_log_path(), e.phase,
		e.scheduler, e.settings)

	e._start_task(ebuild_process, e._ebuild_exit)
}

func (e *EbuildPhase) _ebuild_exit( ebuild_process) {
	e._assert_current(ebuild_process)
	if e._ebuild_lock == nil {
		e._ebuild_exit_unlocked(ebuild_process)
	} else {
		e._start_task(
			NewAsyncTaskFuture( e._ebuild_lock.async_unlock()),
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
	if ebuild_process.returncode != 0 {
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
		out := &bytes.Buffer{}
		_check_build_log(e.settings, out)
		msg := out.String()
		e.scheduler.output(msg, logfile, false, 0, -1)
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
		out := &bytes.Buffer{}
		_post_src_install_write_metadata(settings)
		_post_src_install_uid_fix(settings, out)
		msg := out.String()
		if len(msg) > 0 {
			e.scheduler.output(msg, logfile, false, 0, -1)
		}
	} else if e.phase == "preinst" {
		_preinst_bsdflags(settings)
	} else if e.phase == "postinst" {
		_postinst_bsdflags(settings)
	}

	post_phase_cmds := _post_phase_cmds.get(e.phase)
	if post_phase_cmds != nil {
		if logfile != "" && e.phase =="install" {
			logfile , _ = os.MkdirTemp("","")
		}
		post_phase := NewPostPhaseCommands(e.background,
			post_phase_cmds, e._elog,  e.fd_pipes,
			logfile,  e.phase, e.scheduler, settings)
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

	if e._final_exit(post_phase) != 0 {
		WriteMsg(fmt.Sprintf("!!! post %s failed; exiting.\n", e.phase),
			-1, nil)
		e._die_hooks()
		return
	}

	e._current_task = nil
	e.wait()
	return
}

func (e *EbuildPhase) _append_temp_log( temp_log, log_path string) {

	temp_file, _ := ioutil.ReadFile(temp_log)

	log_file, log_file_real := e._open_log(log_path)

	for _, line:= range strings.Split(string(temp_file), "\n"){
		log_file.Write([]byte(line))
	}

	log_file.Close()
	if log_file_real != log_file {
		log_file_real.Close()
	}
	syscall.Unlink(temp_log)
}

func (e *EbuildPhase) _open_log( log_path string) (io.WriteCloser, io.WriteCloser) {
	var f, f_real io.WriteCloser
	f, _ = os.OpenFile(log_path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	f_real = f

	if strings.HasSuffix(log_path, ".gz") {
		f = gzip.NewWriter(f)
	}

	return f, f_real
}

func (e *EbuildPhase) _die_hooks() {
	e.returncode = nil
	phase := "die_hooks"
	die_hooks := NewMiscFunctionsProcess(e.background,
		[]string{phase},  phase, e._get_log_path(),
		e.fd_pipes, e.scheduler, e.settings)
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
	elog_process(e.settings.mycpv.string, e.settings, nil)
	phase := "clean"
	clean_phase := NewEbuildPhase(nil, e.background, phase,  e.scheduler,
		e.settings, e.fd_pipes,)
	e._start_task(clean_phase, e._fail_clean_exit)
	return
}

func (e *EbuildPhase) _fail_clean_exit( clean_phase) {
	e._final_exit(clean_phase)
	e.returncode = new(int)
	*e.returncode = 1
	e.wait()
}

func (e *EbuildPhase) _elog( elog_funcname string, lines []string, background bool) {
	if background == false {
		background = e.background
	}
	out := &bytes.Buffer{}
	phase := e.phase

	var elog_func func(msg string, phase string, key string, out io.Writer)
	switch elog_funcname {
	case "eerror":
		elog_func = eerror
	case "eqawarn":
		elog_func = eqawarn
	case "einfo":
		elog_func = einfo
	case "ewarn":
		elog_func = ewarn
	case "elog":
		elog_func = elog
	}

	global_havecolor := HaveColor
	//try{
	if Ins([]string{"no", "false", ""}, strings.ToLower(e.settings.ValueDict["NOCOLOR"])) {
		HaveColor = 1
	}else {
		HaveColor = 0
	}
	for _, line := range lines {
		elog_func(line, phase, e.settings.mycpv.string, out)
	}
	//finally{
	HaveColor = global_havecolor
	msg := out.String()
	if msg != "" {
		log_path := ""
		if e.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
			log_path = e.settings.ValueDict["PORTAGE_LOG_FILE"]
		}
		e.scheduler.output(msg, log_path, background, 0, -1)
	}
}

type _PostPhaseCommands struct {
	*CompositeTask

	// slots
	elog           func(string, []string, bool)
	fd_pipes       map[int]int
	logfile, phase string
	commands       []struct{ a map[string]string; b []string}
	settings       *Config
}

func(p*_PostPhaseCommands) _start() {
	//if isinstance(p.commands, list){
	//	cmds = []struct({}, p.commands)
	//}else{
	//cmds = list(p.commands)
	//}
	cmds := p.commands

	if !p.settings.Features.Features["selinux"] {
		cmds1 := []struct {
			a map[string]string;
			b []string
		}{}
		for _, c := range cmds {
			if c.a["selinux_only"] == "" {
				cmds1 = append(cmds1, c)
			}
		}
		cmds = cmds1
	}

	tasks := NewTaskSequence(nil)
	for _, v := range cmds {
		kwargs, commands := v.a, v.b

		kwargs1 := map[string]string{}
		for k, v:= range kwargs{
			if k == "ld_preload_sandbox" {
				kwargs1[k] = v
			}
		}
		tasks.add(NewMiscFunctionsProcess(p.background,
			commands, p.phase, p.logfile, p.fd_pipes,
			p.scheduler, p.settings, **kwargs))

		p._start_task(tasks, p._commands_exit)
	}
}

func(p*_PostPhaseCommands) _commands_exit( task) {

	if p._default_exit(task) != 0 {
		p._async_wait()
		return
	}

	if p.phase == "install" {
		out := &bytes.Buffer{}
		_post_src_install_soname_symlinks(p.settings, out)
		msg := out.String()
		if len(msg) > 0 {
			p.scheduler.output(msg, p.settings.ValueDict["PORTAGE_LOG_FILE"], false, 0, -1)
		}

		if p.settings.Features.Features["qa-unresolved-soname-deps"] {

			future := p._soname_deps_qa()

			future.add_done_callback(func(future IFuture, err error) {
				//return
				//future.cancelled() || future.result()
			})
			p._start_task(NewAsyncTaskFuture(future), p._default_final_exit)
		} else {
			p._default_final_exit(task)
		}
	} else {
		p._default_final_exit(task)
	}
}

@coroutine
func(p*_PostPhaseCommands) _soname_deps_qa() IFuture{

	vardb := NewQueryCommand(nil, "").get_db().Values()[p.settings.ValueDict["EROOT"]].VarTree().dbapi

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


// post_phase_cmds, nil, nil, logfile, e.phase, e.scheduler, nil
func NewPostPhaseCommands(background bool,
	commands = , elog func(string,[]string,bool), fd_pipes map[int]int,
	logfile string, phase string, scheduler *SchedulerInterface,
	settings *Config)*_PostPhaseCommands {
	p := &_PostPhaseCommands{}
	p.CompositeTask = NewCompositeTask()
	p.background = background
	p.commands = commands
	p.elog = elog
	p.fd_pipes = fd_pipes
	p.logfile = logfile
	p.phase = phase
	p.scheduler = scheduler
	p.settings = settings
	return p
}

type EbuildProcess struct {
	*AbstractEbuildProcess

	actionmap Actionmap
}

func (e *EbuildProcess) _spawn(args, **kwargs) ([]int, error) {
	actionmap := e.actionmap
	if actionmap == nil {
		actionmap = _spawn_actionmap(e.settings)
	}

	if e._dummy_pipe_fd != 0 {
		e.settings.ValueDict["PORTAGE_PIPE_FD"] = fmt.Sprint(e._dummy_pipe_fd)
	}

	defer delete(e.settings.ValueDict, "PORTAGE_PIPE_FD")
	return _doebuild_spawn(e.phase, e.settings, actionmap, **kwargs)
}

func NewEbuildProcess(actionmap Actionmap, background bool, fd_pipes map[int]int, logfile, phase string, scheduler *SchedulerInterface, settings *Config) *EbuildProcess {
	e := &EbuildProcess{}
	e.actionmap = actionmap
	e.AbstractEbuildProcess = NewAbstractEbuildProcess(actionmap, background, fd_pipes, logfile, phase, scheduler, settings)

	return e
}

type EbuildSpawnProcess struct {
	*AbstractEbuildProcess
	fakeroot_state string
	spawn_func     func()
}

var _spawn_kwarg_names = append(NewAbstractEbuildProcess()._spawn_kwarg_names ,"fakeroot_state",)

func (e *EbuildSpawnProcess)_spawn( args, **kwargs) {

	env := e.settings.environ()

	if e._dummy_pipe_fd != 0 {
		env["PORTAGE_PIPE_FD"] = fmt.Sprint(e._dummy_pipe_fd)
	}

	return e.spawn_func(args, env = env, **kwargs)
}

func NewEbuildSpawnProcess(background bool, args []string, scheduler *SchedulerInterface,
spawn_func = spawn_func, settings *Config, **keywords)*EbuildSpawnProcess {
	e := &EbuildSpawnProcess{}
	e.AbstractEbuildProcess = NewAbstractEbuildProcess()
	e.background = background
	e.args = args
	e.scheduler = scheduler
	e.spawn_func = spawn_func
	e.settings = settings
	return e
}

func FakeVardbGetPath(vardb *vardbapi)func(string, string)string {
	return func(cpv, filename string) string {
		settings := vardb.settings
		path := filepath.Join(settings.ValueDict["EROOT"], VdbPath, cpv)
		if filename != "" {
			path = filepath.Join(path, filename)
		}
		return path
	}
}

type _DynamicDepsNotApplicable struct {
	Exception
}

type FakeVartree struct {
	*vartree
	_dynamic_deps, _ignore_built_slot_operator_deps bool
	settings                                        *Config
	_db_keys, _portdb_keys                          []string
	_global_updates                                 map[string][][]string
	_portdb                                         *portdbapi
	dbapi                                           *PackageVirtualDbapi
	_match                                          func(*Atom, int)
}

// nil, nil, false, false, false
func NewFakeVartree(root_config, pkg_cache=None, pkg_root_config=None,
dynamic_deps, ignore_built_slot_operator_deps, soname_deps bool)*FakeVartree{
	f := &FakeVartree{}
	f.vartree = NewVarTree()

	f._root_config = root_config
	f._dynamic_deps = dynamic_deps
	f._ignore_built_slot_operator_deps = ignore_built_slot_operator_deps
	if pkg_root_config is None{
		pkg_root_config = f._root_config
	}
	f._pkg_root_config = pkg_root_config
	if pkg_cache is None{
		pkg_cache ={}
	}
	real_vartree := root_config.trees["vartree"]
	f._real_vardb = real_vartree.dbapi
	portdb := root_config.trees["porttree"].dbapi
	f.settings = real_vartree.settings
	mykeys := list(real_vartree.dbapi._aux_cache_keys)
	if  !　Ins(mykeys, "_mtime_"){
		mykeys=append(mykeys, "_mtime_")
	}
	f._db_keys = mykeys
	f._pkg_cache = pkg_cache
	f.dbapi = NewPackageVirtualDbapi(real_vartree.settings)
	if soname_deps {
		f.dbapi = PackageDbapiProvidesIndex(f.dbapi)
	}
	f.dbapi.getpath = FakeVardbGetPath(f.dbapi)
	f.dbapi._aux_cache_keys = set(f._db_keys)

	f._aux_get = f.dbapi.aux_get
	f._match = f.dbapi.match
	if dynamic_deps {
		f.dbapi.aux_get = f._aux_get_wrapper
		f.dbapi.match = f._match_wrapper
	}
	f._aux_get_history = set()
	f._portdb_keys = Package._dep_keys + ("EAPI", "KEYWORDS")
	f._portdb = portdb
	f._global_updates = None

	return f
}

// 1
func(f*FakeVartree) _match_wrapper(cpv, use_cache int) {
	matches = f._match(cpv, use_cache)
	for cpv in matches{
		if cpv in f._aux_get_history{
		continue
	}
		f._aux_get_wrapper(cpv, [])
	}
	return matches
}

func(f*FakeVartree) _aux_get_wrapper( cpv, wants, myrepo=None) {
	if cpv in
	f._aux_get_history{
		return f._aux_get(cpv, wants)
	}
	f._aux_get_history.add(cpv)

	pkg = f.dbapi._cpv_map[cpv]

try:
	live_metadata = dict(zip(f._portdb_keys,
		f._portdb.aux_get(cpv, f._portdb_keys,
			myrepo = pkg.repo)))
	except(KeyError, portage.exception.PortageException):
	live_metadata = None

	f._apply_dynamic_deps(pkg, live_metadata)

	return f._aux_get(cpv, wants)
}

func(f*FakeVartree) _apply_dynamic_deps(pkg, live_metadata) {

try:
	if live_metadata  ==nil {
		raise
		_DynamicDepsNotApplicable()
	}
	if !(eapiIsSupported(live_metadata["EAPI"]) && eapiIsSupported(pkg.eapi)) {
		raise
		_DynamicDepsNotApplicable()
	}

	built_slot_operator_atoms = None
	if ! f._ignore_built_slot_operator_deps && getEapiAttrs(pkg.eapi).slotOperator {
	try:
		built_slot_operator_atoms = \
		find_built_slot_operator_atoms(pkg)
		except
	InvalidDependString:
		pass
	}

	if built_slot_operator_atoms{
	live_eapi_attrs = _get_eapi_attrs(live_metadata["EAPI"])
	if ! live_eapi_attrs.slot_operator {
		raise
		_DynamicDepsNotApplicable()
	}
	for k, v
	in
	built_slot_operator_atoms.items(){
	live_metadata[k] += (" " +
		" ".join(_unicode(atom)
		for atom
			in
		v))
	}
	}

	f.dbapi.aux_update(pkg.cpv, live_metadata)
	except
_DynamicDepsNotApplicable:
	if f._global_updates == nil {
		f._global_updates = grab_global_updates(f._portdb)
	}

	aux_keys = Package._dep_keys + f.dbapi._pkg_str_aux_keys
	aux_dict = dict(zip(aux_keys, f._aux_get(pkg.cpv, aux_keys)))
	perform_global_updates(
		pkg.cpv, aux_dict, f.dbapi, f._global_updates)
}

func(f*FakeVartree) dynamic_deps_preload(pkg, metadata) {
	if metadata != nil {
		metadata = dict((k, metadata.get(k, ''))
		for k
			in
		f._portdb_keys)
	}
	f._apply_dynamic_deps(pkg, metadata)
	f._aux_get_history.add(pkg.cpv)
}

func(f*FakeVartree) cpv_discard( pkg) {
	old_pkg := f.dbapi.get(pkg)
	if old_pkg != nil {
		f.dbapi.cpv_remove(old_pkg)
		f._pkg_cache.pop(old_pkg, None)
		f._aux_get_history.discard(old_pkg.cpv)
	}
}

// 1
func(f*FakeVartree) sync(acquire_lock int) {
	locked := false
//try:
	if acquire_lock && osAccess(f._real_vardb._dbroot, os.O_RDONLY) {
		f._real_vardb.lock()
		locked = true
	}
	f._sync()
//finally:
	if locked {
		f._real_vardb.unlock()
	}

//try:
	f.dbapi.aux_get = f._aux_get
	f.settings._populate_treeVirtuals_if_needed(f)
//finally:
	if f._dynamic_deps {
		f.dbapi.aux_get = f._aux_get_wrapper
	}
}

func(f*FakeVartree) _sync() {

	real_vardb := f._root_config.trees["vartree"].dbapi
	current_cpv_set := frozenset(real_vardb.cpv_all())
	pkg_vardb := f.dbapi

	for pkg
		in
	list(pkg_vardb) {
		if pkg.cpv not
		in
		current_cpv_set{
			f.cpv_discard(pkg)
		}
	}

	slot_counters :=
	{
	}
	root_config := f._pkg_root_config
	validation_keys := []string{"COUNTER", "_mtime_"}
	for cpv := range current_cpv_set {

		pkg_hash_key := &Package{}._gen_hash_key(cpv = cpv,
			installed = true, root_config = root_config,
			type_name = "installed")
		pkg = pkg_vardb.get(pkg_hash_key)
		if pkg != nil {
			counter, mtime = real_vardb.aux_get(cpv, validation_keys)
		try:
			counter = long(counter)
			except
		ValueError:
			counter = 0

			if counter != pkg.counter || mtime != pkg.mtime {
				f.cpv_discard(pkg)
				pkg = nil
			}
		}

		if pkg == nil {
			pkg = f._pkg(cpv)
		}

		other_counter := slot_counters.get(pkg.slot_atom)
		if other_counter != nil {
			if other_counter > pkg.counter {
				continue
			}
		}

		slot_counters[pkg.slot_atom] = pkg.counter
		pkg_vardb.cpv_inject(pkg)
	}

	real_vardb.flush_cache()
}

func(f*FakeVartree) _pkg(cpv *PkgStr) *Package {
	pkg := NewPackage(true,  cpv, true,
		zip(f._db_keys, f._real_vardb.aux_get(cpv, f._db_keys)),
		f._pkg_root_config, "installed")

	f._pkg_cache[pkg] = pkg
	return pkg
}

func grab_global_updates(portdb *portdbapi) map[string][][]string{
	retupdates := map[string][][]string{}

	for _, repo_name := range portdb.getRepositories("") {
		repo := portdb.getRepositoryPath(repo_name)
		updpath := filepath.Join(repo, "profiles", "updates")
		if !pathIsDir(updpath) {
			continue
		}

		//try:
		rawupdates := grab_updates(updpath, nil)
		//except portage.exception.DirectoryNotFound:
		//rawupdates = []
		upd_commands := [][]string{}
		for _, v := range rawupdates {
			mycontent := v.c
			commands, _ := parse_updates(mycontent)
			upd_commands = append(upd_commands, commands...)
		}
		retupdates[repo_name] = upd_commands
	}

	master_repo := portdb.repositories.mainRepo()
	if _, ok := retupdates[master_repo.Name]; ok {
		retupdates["DEFAULT"] = retupdates[master_repo.Name]
	}

	return retupdates
}

func perform_global_updates(mycpv string, aux_dict map[string]string, mydb IDbApi, myupdates map[string][][]string) {

	//try:
	pkg := NewPkgStr(mycpv, aux_dict, mydb.settings, "", "", "", 0, 0, "", 0, nil)
	//except InvalidData:
	//return
	aux_dict2 := map[string]string{}
	for _, k := range NewPackage().depKeys {
		aux_dict2[k] = aux_dict[k]
	}
	aux_dict = aux_dict2
	mycommands, ok := myupdates[pkg.repo]
	if !ok {
		//except KeyError:
		mycommands, ok = myupdates["DEFAULT"]
		if !ok {
			//except KeyError:
			return
		}
	}

	if len(mycommands) == 0 {
		return
	}

	updates := update_dbentries(mycommands, aux_dict, "", pkg)
	if len(updates) > 0 {
		mydb.aux_update(mycpv, updates)
	}
}

type FifoIpcDaemon struct {
	*AbstractPollTask

	_files *struct{pipe_in int}
	input_fifo, output_fifo string
}

func (f *FifoIpcDaemon) _start() {
	f._files = &struct{ pipe_in int }{}

	f._files.pipe_in, _ = syscall.Open(f.input_fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0644)

	f.scheduler.add_reader(f._files.pipe_in, f._input_handler)

	f._registered = true
}

func (f *FifoIpcDaemon) _reopen_input() {
	f.scheduler.remove_reader(f._files.pipe_in)
	syscall.Close(f._files.pipe_in)
	f._files.pipe_in, _ =
		syscall.Open(f.input_fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0644)

	f.scheduler.add_reader(f._files.pipe_in, f._input_handler)
}

func (f *FifoIpcDaemon) _cancel() {
	if f.returncode == nil {
		i := 1
		f.returncode = &i
	}
	f._unregister()
	f._async_wait()
}

func (f *FifoIpcDaemon) _input_handler() bool {
	//raise NotImplementedError(f)
	 return true
}

func (f *FifoIpcDaemon) _unregister() {

	f._registered = false

	if f._files != nil {
		for f1
			in
		f._files.values() {
			f.scheduler.remove_reader(f1)
			syscall.Close(f1)
		}
		f._files = nil
	}
}

func NewFifoIpcDaemon()*FifoIpcDaemon{
	f := &FifoIpcDaemon{}
	f.AbstractPollTask = NewAbstractPollTask()

	return f
}

type JobStatusDisplay struct {
	_bound_properties                      []string
	_min_display_latency                   int
	_default_term_codes, _termcap_name_map map[string]string

	quiet, xterm_titles, _changed, _displayed, _isatty bool
	maxval, merges, width, _jobs_column_width          int
	_last_display_time                                 int64
	_term_codes                                        map[string]string

	curval,failed,running int
}

// false, true
func NewJobStatusDisplay(quiet, xterm_titles bool)*JobStatusDisplay{
	j := &JobStatusDisplay{}

	j._bound_properties = []string{"curval", "failed", "running"}

	j._min_display_latency = 2

	j._default_term_codes = map[string]string {
		"cr"  : "\r",
			"el"  : "\x1b[K",
			"nel" : "\n",
	}

	j._termcap_name_map = map[string]string{
		"carriage_return" : "cr",
			"clr_eol"         : "el",
			"newline"         : "nel",
	}


	j.quiet=quiet
	j.xterm_titles=xterm_titles
	j.maxval=0
	j.merges=0
	j._changed=false
	j._displayed=false
	j._last_display_time=int64(0)

	j.reset()

	isatty := os.Getenv("TERM") != "dumb" &&terminal.IsTerminal(syscall.Stdout)
	j._isatty=isatty
	if ! isatty || ! j._init_term() {
		term_codes :=map[string]string{}
		for k, capname:= range j._termcap_name_map {
			term_codes[k] = j._default_term_codes[capname]
		}
		j._term_codes = term_codes
	}

	width := 80
	if j._isatty {
		_, width, _ = get_term_size(0)
	}
	j._set_width(width)
	return j
}

func(j*JobStatusDisplay) _set_width( width int) {
	if width == j.width {
		return
	}
	if width <= 0 || width > 80 {
		width = 80
	}
	j.width = width
	j._jobs_column_width = width-32
}

func(j*JobStatusDisplay) _write(s string) {
	out := os.Stdout
	out.Write([]byte(s))
	out.Sync()
}

func(j*JobStatusDisplay) _init_term() bool {

	term_type := strings.TrimSpace(os.Getenv("TERM"))
	if  term_type== "" {
		return false
	}
	tigetstr = None

try:
	import curses

try:
	curses.setupterm(term_type, j.out.fileno())
	tigetstr = curses.tigetstr
	except
	curses.error:
	pass
	except
ImportError:
	pass

	if tigetstr is
None:
	return false

	term_codes =
	{
	}
	for k, capname
	in
	j._termcap_name_map.items():
	code = tigetstr(portage._native_string(capname))
	if code is
None:
	code = j._default_term_codes[capname]
	term_codes[k] = code
	object.__setattr__(j, "_term_codes", term_codes)
	return true
}

func(j*JobStatusDisplay) _format_msg( msg string)string {
	return fmt.Sprintf(">>> %s" , msg)
}

func(j*JobStatusDisplay) _erase() {
	j._write(j._term_codes["carriage_return"] + j._term_codes["clr_eol"])
	j._displayed = false
}

func(j*JobStatusDisplay) _display( line string) {
	j._write(line)
	j._displayed = true
}

func(j*JobStatusDisplay) _update( msg string) {

	if ! j._isatty {
		j._write(j._format_msg(msg) + j._term_codes["newline"])
		j._displayed = true
		return
	}

	if j._displayed {
		j._erase()
	}

	j._display(j._format_msg(msg))
}

func(j*JobStatusDisplay) displayMessage(msg string) {

	was_displayed := j._displayed

	if j._isatty && j._displayed {
		j._erase()
	}

	j._write(j._format_msg(msg) + j._term_codes["newline"])
	j._displayed = false

	if was_displayed {
		j._changed = true
		j.display()
	}
}

func(j*JobStatusDisplay) reset() {
	j.maxval = 0
	j.merges = 0

	j.curval = 0
	j.failed = 0
	j.running = 0

	if j._displayed {
		j._write(j._term_codes["newline"])
		j._displayed = false
	}
}

func(j*JobStatusDisplay) setCurval(curval int) {
	if j.curval!= curval{
		j.curval=curval
		j._property_change()
	}
}


func(j*JobStatusDisplay) setFailed(failed int) {
	if j.failed!= failed{
		j.failed=failed
		j._property_change()
	}
}

func(j*JobStatusDisplay) setRunning(running int) {
	if j.running!= running{
		j.running=running
		j._property_change()
	}
}

func(j*JobStatusDisplay) _property_change() {
	j._changed = true
	j.display()
}

func(j*JobStatusDisplay) _load_avg_str()string {
	avg1, avg2, avg3, err := getloadavg()
	if err != nil {
		//except OSError:
		return "unknown"
	}

	max_avg := math.Max(math.Max(avg1, avg2), avg3)

	digits := 0
	if max_avg < 10 {
		digits = 2
	} else if max_avg < 100 {
		digits = 1
	}

	return fmt.Sprintf("%."+fmt.Sprint(digits)+"f", avg1) + ", " +
		fmt.Sprintf("%."+fmt.Sprint(digits)+"f", avg2) + ", " +
		fmt.Sprintf("%."+fmt.Sprint(digits)+"f", avg3)
}

func(j*JobStatusDisplay) display() bool {

	if j.quiet {
		return true
	}
	current_time := time.Now().Unix()
	time_delta := current_time - j._last_display_time
	if j._displayed && !j._changed {
		if !j._isatty {
			return true
		}
		if int(time_delta) < j._min_display_latency {
			return true
		}
	}

	j._last_display_time = current_time
	j._changed = false
	j._display_status()
	return true
}

func(j*JobStatusDisplay) _display_status() {
	curval_str := fmt.Sprintf("%s", j.curval, )
	maxval_str := fmt.Sprintf("%s", j.maxval, )
	running_str := fmt.Sprintf("%s", j.running, )
	failed_str := fmt.Sprintf("%s", j.failed, )
	load_avg_str := j._load_avg_str()

	color_output := &bytes.Buffer{}
	plain_output := &bytes.Buffer{}
	style_file := NewConsoleStylefile(color_output)
	style_file.write_listener = plain_output
	style_writer := &StyleWriter{File: style_file, maxcol: 9999}
	style_writer.style_listener = style_file.new_styles
	f := &AbstractFormatter{Writer: style_writer}

	number_style := "INFORM"
	f.add_literal_data("Jobs: ")
	f.push_style(number_style)
	f.add_literal_data(curval_str)
	f.pop_style()
	f.add_literal_data(" of ")
	f.push_style(number_style)
	f.add_literal_data(maxval_str)
	f.pop_style()
	f.add_literal_data(" complete")

	if j.running != 0 {
		f.add_literal_data(", ")
		f.push_style(number_style)
		f.add_literal_data(running_str)
		f.pop_style()
		f.add_literal_data(" running")
	}

	if j.failed != 0 {
		f.add_literal_data(", ")
		f.push_style(number_style)
		f.add_literal_data(failed_str)
		f.pop_style()
		f.add_literal_data(" failed")
	}

	padding := j._jobs_column_width - len(plain_output.String())
	if padding > 0 {
		f.add_literal_data(strings.Repeat(" ", padding))
	}

	f.add_literal_data("Load avg: ")
	f.add_literal_data(load_avg_str)

	plain_outputS := plain_output.String()
	if j._isatty && len(plain_outputS) > j.width {
		j._update(plain_outputS[:j.width])
	} else {
		j._update(color_output.String())
	}

	if j.xterm_titles {
		title_str := strings.Join(strings.Fields(plain_outputS), " ")
		hostname := os.Getenv("HOSTNAME")
		if hostname != "" {
			title_str = fmt.Sprintf("%s: %s", hostname, title_str)
		}
		XtermTitle(title_str, false)
	}
}

type MergeListItem struct {
	*CompositeTask

	//slots
	_install_task *EbuildBuild
	args_set      *InternalPackageSet
	binpkg_opts   *_binpkg_opts_class
	build_opts    *_build_opts_class
	config_pool   *_ConfigPool
	logger        *_emerge_log_class
	pkg_count     *_pkg_count_class
	settings      *Config
	statusMessage func(string)
	world_atom    func()
	emerge_opts, find_blockers, mtimedb, pkg,
	pkg_to_replace, prefetcher
}

func(m *MergeListItem) _start() {

	pkg := m.pkg
	build_opts := m.build_opts

	if pkg.installed {
		i := 0
		m.returncode = &i
		m._async_wait()
		return
	}

	args_set := m.args_set
	find_blockers := m.find_blockers
	logger := m.logger
	mtimedb := m.mtimedb
	pkg_count := m.pkg_count
	scheduler := m.scheduler
	settings := m.settings
	world_atom := m.world_atom
	ldpath_mtimes := mtimedb["ldpath"]

	action_desc := "Emerging"
	preposition := "for"
	pkg_color := "PKG_MERGE"
	if pkg.type_name == "binary" {
		pkg_color = "PKG_BINARY_MERGE"
		action_desc += " binary"
	}

	if build_opts.fetchonly {
		action_desc = "Fetching"
	}

	msg := fmt.Sprintf("%s (%s of %s) %s",
		action_desc,
		colorize("MERGE_LIST_PROGRESS", str(pkg_count.curval)),
		colorize("MERGE_LIST_PROGRESS", str(pkg_count.maxval)),
		colorize(pkg_color, pkg.cpv+repoSeparator+pkg.repo))

	if pkg.root_config.settings["ROOT"] != "/" {
		msg += fmt.Sprintf(" %s %s", preposition, pkg.root)
	}

	if build_opts.pretend == "" {
		m.statusMessage(msg)
		logger.log(fmt.Sprintf(" >>> emerge (%s of %s) %s to %s",
			pkg_count.curval, pkg_count.maxval, pkg.cpv, pkg.root))
	}

	if pkg.type_name == "ebuild" {

		build := NewEbuildBuild(args_set, m.background, m.config_pool,
			find_blockers, ldpath_mtimes, logger, build_opts, pkg,
			pkg_count, m.prefetcher, scheduler, settings, world_atom)

		m._install_task = build
		m._start_task(build, m._default_final_exit)
		return
	} else if pkg.type_name == "binary" {

		binpkg := NewBinpkg(m.background, find_blockers,
			ldpath_mtimes, logger, m.binpkg_opts, pkg, pkg_count,
			m.prefetcher, settings, scheduler, world_atom)

		m._install_task = binpkg
		m._start_task(binpkg, m._default_final_exit)
		return
	}
}

func(m *MergeListItem) create_install_task() {

	pkg := m.pkg
	build_opts := m.build_opts
	mtimedb := m.mtimedb
	scheduler := m.scheduler
	settings := m.settings
	world_atom := m.world_atom
	ldpath_mtimes := mtimedb["ldpath"]

	if pkg.installed {
		if !(build_opts.buildpkgonly || build_opts.fetchonly || build_opts.pretend) {

			task = NewPackageUninstall(m.background, ldpath_mtimes,
				m.emerge_opts, pkg, scheduler, settings, world_atom)
		}else {
			task = NewAsynchronousTask()
		}

	}else if  build_opts.fetchonly || build_opts.buildpkgonly {
		task = NewAsynchronousTask()
	}else {
		task = m._install_task.create_install_task()
	}

	return task
}

func NewMergeListItem(args_set *InternalPackageSet, background bool,
	binpkg_opts *_binpkg_opts_class, build_opts *_build_opts_class,
	config_pool *_ConfigPool, emerge_opts , find_blockers ,
	logger *_emerge_log_class,
mtimedb , pkg, pkg_count *_pkg_count_class, pkg_to_replace,
prefetcher , scheduler *SchedulerInterface,
settings *Config, statusMessage func(string) , world_atom func() )*MergeListItem {
	m := &MergeListItem{}
	m.CompositeTask = NewCompositeTask()
	m.args_set = args_set
	m.background = background
	m.binpkg_opts = binpkg_opts
	m.build_opts = build_opts
	m.config_pool = config_pool
	m.emerge_opts = emerge_opts
	m.find_blockers = find_blockers
	m.logger = logger
	m.mtimedb = logger
	m.pkg = pkg
	m.pkg_count = pkg_count
	m.pkg_to_replace = pkg_to_replace
	m.prefetcher = prefetcher
	m.scheduler = scheduler
	m.settings = settings
	m.statusMessage = settings
	m.world_atom = world_atom
	return m
}

type MetadataRegen struct{
	*AsyncScheduler

	_portdb *portdbapi
	_global_cleanse,_write_auxdb bool
	_cp_iter string
}

// "", nil, true
func NewMetadataRegen( portdb *portdbapi, cp_iter string, consumer=None,
write_auxdb bool, **kwargs)*MetadataRegen {
	m := &MetadataRegen{}
	m.AsyncScheduler =NewAsyncScheduler(**kwargs)
	m._portdb = portdb
	m._write_auxdb = write_auxdb
	m._global_cleanse = false
	if cp_iter == "" {
		cp_iter = m._iter_every_cp()[0]
		m._global_cleanse = true
	}
	m._cp_iter = cp_iter
	m._consumer = consumer

	m._valid_pkgs = set()
	m._cp_set = set()
	m._process_iter = m._iter_metadata_processes()
	m._running_tasks = set()
	return m
}

func(m*MetadataRegen) _next_task() {
	return next(m._process_iter)
}

func(m*MetadataRegen) _iter_every_cp() []string {
	cp_all := m._portdb.cp_all
	cps := []string{}
	for _, category:= range sorted(m._portdb.categories()) {
		for _, cp := range cp_all(map[string]bool{category:true}, nil, false, true) {
			cps = append(cps, cp)
		}
	}
	return cps
}

func(m*MetadataRegen) _iter_metadata_processes() {
	portdb := m._portdb
	valid_pkgs := m._valid_pkgs
	cp_set := m._cp_set
	consumer := m._consumer

	WriteMsgStdout("Regenerating cache entries...\n", 0)
	for _, cp := range m._cp_iter {
		if m._terminated.is_set() {
			break
		}
		cp_set.add(cp)
		WriteMsgStdout(fmt.Sprintf("Processing %s\n", cp), 0)
		for _, mytree := range portdb.porttrees {
			repo := portdb.repositories.getRepoForLocation(mytree)
			cpv_list := portdb.cp_list(cp, 1, []string{repo.location})
			for _, cpv := range cpv_list {
				if m._terminated.is_set() {
					break
				}
				valid_pkgs.add(cpv)
				ebuild_path, repo_path := portdb.findname2(cpv, "", repo.Name)
				if ebuild_path == "" {
					//raise AssertionError("ebuild not found for '%s%s%s'"%(cpv, _repo_separator, repo.name))
				}
				metadata, ebuild_hash := portdb._pull_valid_cache(cpv, ebuild_path, repo_path)
				if metadata != nil {
					if consumer != nil {
						consumer(cpv, repo_path, metadata, ebuild_hash, true)
					}
					continue
				}

				yield
				NewEbuildMetadataPhase(cpv, ebuild_hash, portdb, repo_path, nil, portdb.doebuild_settings,
					write_auxdb = m._write_auxdb)
			}
		}
	}
}

func(m*MetadataRegen) _cleanup() {
	m.AsyncScheduler._cleanup()

	portdb := m._portdb
	dead_nodes :=
	{
	}

	if m._terminated.is_set() {
		portdb.flush_cache()
		return
	}

	if m._global_cleanse {
		for _, mytree:= range portdb.porttrees {
		try:
			dead_nodes[mytree] = set(portdb.auxdb[mytree])
			except
			CacheError
			as
		e:
			WriteMsg(fmt.Sprintf("Error listing cache entries for " +
			"'%s': %s, continuing...\n" ,mytree, e), -1, nil)
			del
			e
			dead_nodes = nil
			break
		}
	}else {
		cp_set = m._cp_set
		cpv_getkey = portage.cpv_getkey
		for mytree
			in
		portdb.porttrees:
	try:
		dead_nodes[mytree] = set(cpv
		for cpv
		in \
		portdb.auxdb[mytree] \
		if cpv_getkey(cpv) in
		cp_set)
		except
		CacheError
		as
	e:
		WriteMsg(fmt.Sprintf("Error listing cache entries for "+
			"'%s': %s, continuing...\n", mytree, e), -1, nil)
		del
		e
		dead_nodes = None
		break
	}

	if dead_nodes {
		for y
			in
		m._valid_pkgs {
			for _, mytree := range portdb.porttrees {
				if s, _ := portdb.findname2(y, mytree, ""); s != "" {
					dead_nodes[mytree].discard(y)
				}
			}
		}

		for mytree, nodes
			in
		dead_nodes.items() {
			auxdb = portdb.auxdb[mytree]
			for y
				in
			nodes {
			try:
				del
				auxdb[y]
				except(KeyError, CacheError):
				pass
			}
		}
	}

	portdb.flush_cache()
}

func(m*MetadataRegen) _task_exit(metadata_process) {

	if metadata_process.returncode != 0 {
		m._valid_pkgs.discard(metadata_process.cpv)
		if not m._terminated_tasks {
			WriteMsg(fmt.Sprintf("Error processing %s, continuing...\n", metadata_process.cpv, ), -1, nil)
		}
	}

	if m._consumer != nil {
		m._consumer(metadata_process.cpv,
			metadata_process.repo_path,
			metadata_process.metadata,
			metadata_process.ebuild_hash,
			metadata_process.eapi_supported)
	}

	m.AsyncScheduler._task_exit(metadata_process)
}

type MiscFunctionsProcess struct {
	*AbstractEbuildProcess
	commands []string
	ld_preload_sandbox
}

func (m *MiscFunctionsProcess)_start() {
	settings := m.settings
	portage_bin_path := settings.ValueDict["PORTAGE_BIN_PATH"]
	misc_sh_binary := filepath.Join(portage_bin_path,
		filepath.Base(MISC_SH_BINARY))

	m.args = append([]string{ShellQuote(misc_sh_binary)}, m.commands...)
	if m.logfile == "" &&m.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
		m.logfile = settings.ValueDict["PORTAGE_LOG_FILE"]
	}

	m.AbstractEbuildProcess._start()
}

func (m *MiscFunctionsProcess) _spawn(args []string, debug bool, free *bool, droppriv,
	sesandbox, fakeroot, networked, ipc, mountns, pidns bool, **keywords) {

	if free == nil {
		if m.ld_preload_sandbox == nil {
			*free = false
		} else {
			*free = not m.ld_preload_sandbox
		}
	}

	if m._dummy_pipe_fd != 0 {
		m.settings.ValueDict["PORTAGE_PIPE_FD"] = fmt.Sprint(m._dummy_pipe_fd)
	}

	if m.settings.Features.Features["fakeroot"]{
		fakeroot = true
	}

	phase_backup := m.settings.ValueDict["EBUILD_PHASE"]
	delete(m.settings.ValueDict, "EBUILD_PHASE")

	defer func() {
		if phase_backup != "" {
			m.settings.ValueDict["EBUILD_PHASE"] = phase_backup
		}
		delete(m.settings.ValueDict, "PORTAGE_PIPE_FD")
	}()
	return spawnE(strings.Join(args, " "), m.settings, debug, *free, droppriv,
		sesandbox, fakeroot, networked, ipc, mountns, pidns, **keywords)
}

func NewMiscFunctionsProcess(background bool, commands []string, phase string, logfile string, fd_pipe map[int]int, scheduler *SchedulerInterface, settings *Config)*MiscFunctionsProcess{
	m := &MiscFunctionsProcess{}
	m.AbstractEbuildProcess = NewAbstractEbuildProcess(nil, background, fd_pipe, logfile, phase, scheduler, settings, )
	m.background = background
	m.commands = commands
	m.phase = phase
	m.logfile = logfile
	m.fd_pipes = fd_pipe
	m.scheduler = scheduler
	m.settings = settings
	return m
}

type iUse struct {
	__weakref__, _pkg                  string
	tokens                             []string
	iuseImplicitMatch                  func(string) bool
	aliasMapping                       map[string][]string
	all, allAliases, enabled, disabled map[string]bool
}

func (i *iUse) isValidFlag(flags []string) bool {
	for _, flag := range flags {
		if !i.all[flag] && !i.allAliases[flag] && !i.iuseImplicitMatch(flag) {
			return false
		}
	}
	return true
}

func (i *iUse) getMissingIuse(flags []string) []string {
	missingIUse := []string{}
	for _, flag := range flags {
		if !i.all[flag] && !i.allAliases[flag] && !i.iuseImplicitMatch(flag) {
			missingIUse = append(missingIUse, flag)
		}
	}
	return missingIUse
}

func (i *iUse) getRealFlag(flag string) string {
	if i.all[flag] {
		return flag
	} else if i.allAliases[flag] {
		for k, v := range i.aliasMapping {
			for _, x := range v {
				if flag == x {
					return k
				}
			}
		}
	}
	if i.iuseImplicitMatch(flag) {
		return flag
	}
	return ""
}

func NewIUse(pkg string, tokens []string, iuseImplicitMatch func(string) bool, aliases map[string][]string, eapi string) *iUse {
	i := &iUse{}
	i._pkg = pkg
	i.tokens = tokens
	i.iuseImplicitMatch = iuseImplicitMatch
	enabled := []string{}
	disabled := []string{}
	other := []string{}
	enabledAliases := []string{}
	disabledAliases := []string{}
	otherAliases := []string{}
	aliasesSupported := eapiHasUseAliases(eapi)
	i.aliasMapping = map[string][]string{}
	for _, x := range tokens {
		prefix := x[:1]
		if prefix == "+" {
			enabled = append(enabled, x[1:])
			if aliasesSupported {
				if a, ok := aliases[x[1:]]; ok {
					i.aliasMapping[x[1:]] = a
				} else {
					i.aliasMapping[x[1:]] = []string{}
				}
				enabledAliases = append(enabledAliases, i.aliasMapping[x[1:]]...)
			}
		} else if prefix == "-" {
			disabled = append(disabled, x[1:])
			if aliasesSupported {
				if a, ok := aliases[x[1:]]; ok {
					i.aliasMapping[x[1:]] = a
				} else {
					i.aliasMapping[x[1:]] = []string{}
				}
				disabledAliases = append(disabledAliases, i.aliasMapping[x[1:]]...)
			}
		} else {
			other = append(other, x[1:])
			if aliasesSupported {
				if a, ok := aliases[x[1:]]; ok {
					i.aliasMapping[x[1:]] = a
				} else {
					i.aliasMapping[x[1:]] = []string{}
				}
				otherAliases = append(otherAliases, i.aliasMapping[x[1:]]...)
			}
		}
	}
	i.enabled = map[string]bool{}
	for _, x := range append(enabled, enabledAliases...) {
		i.enabled[x] = true
	}
	i.disabled = map[string]bool{}
	for _, x := range append(disabled, disabledAliases...) {
		i.disabled[x] = true
	}
	i.all = map[string]bool{}
	for _, x := range append(append(enabled, disabled...), other...) {
		i.enabled[x] = true
	}
	i.allAliases = map[string]bool{}
	for _, x := range append(append(enabledAliases, disabledAliases...), otherAliases...) {
		i.allAliases[x] = true
	}

	return i
}

type Package struct {
	*Task
	metadataKeys, buildtimeKeys, runtimeKeys, useConditionalMiscKeys                                                                                                                                 map[string]bool
	depKeys                                                                                                                                                                                          []string
	UnknownRepo                                                                                                                                                                                      string
	built, installed                                                                                                                                                                                 bool
	cpv                                                                                                                                                                                              *PkgStr
	counter, mtime                                                                                                                                                                                   int
	metadata                                                                                                                                                                                         *packageMetadataWrapper
	_raw_metadata                                                                                                                                                                                    map[string]string
	inherited                                                                                                                                                                                        map[string]bool
	depth, onlydeps, operation, type_name, category, cp, cpv_split, iuse, pf, root, slot, sub_slot, slot_atom, version, _invalid, _masks, _provided_cps, _requires, _use, _validated_atoms, _visible string
	_provides                                                                                                                                                                                        map[[2]string]*sonameAtom
	root_config                                                                                                                                                                                      *RootConfig
}

func (p *Package) eapi() string {
	return p.metadata.valueDict["EAPI"]
}

func (p *Package) buildId() int {
	return p.cpv.buildId
}

func (p *Package) buildTime() int {
	return p.cpv.buildTime
}

//func (p *Package)definedPhases()string{
//	return p.metadata
//}

func (p *Package) masks() {
	if p._masks == "" {

	}
}

func NewPackage(built bool, cpv *PkgStr, installed bool, metadata map[string]string, root_config *RootConfig, type_name string) *Package {
	p := &Package{metadataKeys: map[string]bool{
		"BDEPEND": true, "BUILD_ID": true, "BUILD_TIME": true, "CHOST": true, "COUNTER": true, "DEFINED_PHASES": true,
		"DEPEND": true, "EAPI": true, "HDEPEND": true, "INHERITED": true, "IUSE": true, "KEYWORDS": true,
		"LICENSE": true, "MD5": true, "PDEPEND": true, "PROVIDES": true, "RDEPEND": true, "repository": true, "REQUIRED_USE": true,
		"PROPERTIES": true, "REQUIRES": true, "RESTRICT": true, "SIZE": true, "SLOT": true, "USE": true, "_mtime_": true,
	}, depKeys: []string{"BDEPEND", "DEPEND", "HDEPEND", "PDEPEND", "RDEPEND"},
		buildtimeKeys:          map[string]bool{"BDEPEND": true, "DEPEND": true, "HDEPEND": true},
		runtimeKeys:            map[string]bool{"PDEPEND": true, "RDEPEND": true},
		useConditionalMiscKeys: map[string]bool{"LICENSE": true, "PROPERTIES": true, "RESTRICT": true},
		UnknownRepo:            unknownRepo}
	p.built = built
	p.cpv = cpv
	p.installed = installed
	p.root_config = root_config
	p.type_name = type_name

	//p.root = p.root_config.root
	p._raw_metadata = metadata

	p.metadata = NewPackageMetadataWrapper(p, metadata)

	return p
}

var allMetadataKeys = map[string]bool{
	"DEPEND": true, "RDEPEND": true, "SLOT": true, "SRC_URI": true,
	"RESTRICT": true, "HOMEPAGE": true, "LICENSE": true, "DESCRIPTION": true,
	"KEYWORDS": true, "INHERITED": true, "IUSE": true, "REQUIRED_USE": true,
	"PDEPEND": true, "BDEPEND": true, "EAPI": true, "PROPERTIES": true,
	"DEFINED_PHASES": true, "HDEPEND": true, "BUILD_ID": true, "BUILD_TIME": true,
	"CHOST": true, "COUNTER": true, "MD5": true, "PROVIDES": true,
	"repository": true, "REQUIRES": true, "SIZE": true, "USE": true, "_mtime_": true,
}

var wrappedKeys = map[string]bool{
	"COUNTER": true, "INHERITED": true, "USE": true, "_mtime_": true,
}

var useConditionalKeys = map[string]bool{
	"LICENSE": true, "PROPERTIES": true, "RESTRICT": true,
}

type packageMetadataWrapper struct {
	valueDict                                        map[string]string
	pkg                                              *Package
	allMetadataKeys, wrappedKeys, useConditionalKeys map[string]bool
}

func (p *packageMetadataWrapper) setItem(k, v string) {
	if p.allMetadataKeys[k] {
		p.valueDict[k] = v
	}
	switch k {
	case "COUNTER":
		p.setCounter(k, v)
	case "INHERITED":
		p.setInherited(k, v)
	case "USE":
		p.setUse(k, v)
	case "_mtime_":
		p.setMtime(k, v)
	}
}

func (p *packageMetadataWrapper) setInherited(k, v string) {
	p.pkg.inherited = map[string]bool{}
	for _, f := range strings.Fields(v) {
		p.pkg.inherited[f] = true
	}
}

func (p *packageMetadataWrapper) setCounter(k, v string) {
	n, _ := strconv.Atoi(v)
	p.pkg.counter = n
}

func (p *packageMetadataWrapper) setUse(k, v string) {
	p.pkg._use = ""
	rawMetadata := p.pkg._raw_metadata
	for x := range p.useConditionalKeys {
		if v, ok := rawMetadata[x]; ok {
			p.valueDict[x] = v
		}
	}
}

func (p *packageMetadataWrapper) setMtime(k, v string) {
	n, _ := strconv.Atoi(v)
	p.pkg.mtime = n
}

func (p *packageMetadataWrapper) properties() []string {
	return strings.Fields(p.valueDict["PROPERTIES"])
}

func (p *packageMetadataWrapper) restrict() []string {
	return strings.Fields(p.valueDict["RESTRICT"])
}

func (p *packageMetadataWrapper) definedPhases() map[string]bool {
	if s, ok := p.valueDict["DEFINED_PHASES"]; ok {
		phases := map[string]bool{}
		for _, v := range strings.Fields(s) {
			phases[v] = true
		}
		return phases
	}
	return EBUILD_PHASES
}

func NewPackageMetadataWrapper(pkg *Package, metadata map[string]string) *packageMetadataWrapper {
	p := &packageMetadataWrapper{pkg: pkg, valueDict: make(map[string]string), useConditionalKeys: useConditionalKeys, wrappedKeys: wrappedKeys, allMetadataKeys: CopyMapSB(allMetadataKeys)}
	if !pkg.built {
		p.valueDict["USE"] = ""
	}
	for k, v := range metadata {
		p.valueDict[k] = v
	}
	return p
}

type PackageArg struct {
	*DependencyArg

	atom *Atom
	pset *InternalPackageSet
}

// nil
func NewPackageArg(packagee=None, arg string, root_config *RootConfig, **kwargs)*PackaeArg {
	p := &PackageArg{}
	p.DependencyArg = NewDependencyArg(arg, false, false, true, root_config,**kwargs)
	p.packagee = packagee
	atom := "=" + packagee.cpv
	if packagee.repo != Package.UNKNOWN_REPO {
		atom += _repo_separator + packagee.repo
	}
	allow_repo := true
	p.atom, _ = NewAtom(atom, nil, false, &allow_repo, nil, "", nil, nil)
	p.pset = NewInternalPackageSet([]*Atom{p.atom,}, true, true)
	return p
}

type PackageMerge struct{
	*CompositeTask

	// slot
	merge, postinst_failure
}

func (p *PackageMerge) _start() {

	p.scheduler = p.merge.scheduler
	pkg := p.merge.pkg
	pkg_count := p.merge.pkg_count
	pkg_color := "PKG_MERGE"
	if pkg.type_name == "binary" {
		pkg_color = "PKG_BINARY_MERGE"
	}

	if pkg.installed {
		action_desc = "Uninstalling"
		preposition = "from"
		counter_str = ""
	} else {
		action_desc = "Installing"
		preposition = "to"
		counter_str = fmt.Sprintf("(%s of %s) ",
			colorize("MERGE_LIST_PROGRESS", str(pkg_count.curval)),
			colorize("MERGE_LIST_PROGRESS", str(pkg_count.maxval)))
	}

	msg := fmt.Sprintf("%s %s%s", action_desc, counter_str,
		colorize(pkg_color, pkg.cpv+repoSeparator+pkg.repo))

	if pkg.root_config.settings["ROOT"] != "/" {
		msg += fmt.Sprintf(" %s %s", preposition, pkg.root)
	}

	if !p.merge.build_opts.fetchonly && !
		p.merge.build_opts.pretend && !
		p.merge.build_opts.buildpkgonly {
		p.merge.statusMessage(msg)
	}

	task := p.merge.create_install_task()
	p._start_task(task, p._install_exit)
}

func (p *PackageMerge) _install_exit( task) {
	p.postinst_failure = task.postinst_failure
	p._final_exit(task)
	p.wait()
}

func NewPackageMerge(merge , scheduler *SchedulerInterface) *PackageMerge{
	p := &PackageMerge{}
	p.CompositeTask = NewCompositeTask()
	p.merge = merge
	p.scheduler = scheduler
	return p
}

type PackagePhase struct {
	*CompositeTask

	_shell_binary string

	// slots
	_pkg_install_mask *InstallMask
	settings          *Config
	fd_pipes          map[int]int
	actionmap         Actionmap
	logfile, _proot   string
}

func(p*PackagePhase) _start() {
	f, err := ioutil.ReadFile(filepath.Join(p.settings.ValueDict["PORTAGE_BUILDDIR"],
		"build-info", "PKG_INSTALL_MASK"))
	if err != nil {
		p._pkg_install_mask = nil
	} else {
		p._pkg_install_mask = NewInstallMask(string(f))
	}
	if p._pkg_install_mask != nil {
		p._proot = filepath.Join(p.settings.ValueDict["T"], "packaging")
		p._start_task(NewSpawnProcess(
			[]string{p._shell_binary, "-e", "-c", fmt.Sprintf("rm -rf {PROOT}; "+
			"cp -pPR $(cp --help | grep -q -- \" ^ [[: space:]]*-l, \" && echo -l)"+
			" \"${{D}}\" {%s}",  ShellQuote(p._proot))},
			 p.background, p.settings.environ(), nil,
			 p.scheduler,  p.logfile),
		p._copy_proot_exit)
	} else {
		p._proot = p.settings.ValueDict["D"]
		p._start_package_phase()
	}
}

func(p*PackagePhase) _copy_proot_exit( proc) {
	if p._default_exit(proc) != 0 {
		p.wait()
	}else {
		p._start_task(NewAsyncFunction(
			install_mask_dir,
			 (filepath.Join(p._proot,
			strings.TrimLeft(p.settings.ValueDict["EPREFIX"],string(filepath.Separator))),
			p._pkg_install_mask)),
		p._pkg_install_mask_exit)
	}
}

func(p*PackagePhase) _pkg_install_mask_exit( proc) {
	if p._default_exit(proc) != 0 {
		p.wait()
	}else {
		p._start_package_phase()
	}
}

func(p*PackagePhase) _start_package_phase() {
	ebuild_process := NewEbuildProcess( p.actionmap, p.background, p.fd_pipes,
		 p.logfile,"package", p.scheduler, p.settings)

	if p._pkg_install_mask != nil {
		d_orig := p.settings.ValueDict["D"]
	//try:
		p.settings.ValueDict["D"] = p._proot
		p._start_task(ebuild_process, p._pkg_install_mask_cleanup)
	//finally:
		p.settings.ValueDict["D"] = d_orig
	}else {
		p._start_task(ebuild_process, p._default_final_exit)
	}
}

func(p*PackagePhase) _pkg_install_mask_cleanup( proc) {
	if p._default_exit(proc) != 0 {
		p.wait()
	} else {
		p._start_task(NewSpawnProcess([]string{"rm", "-rf", p._proot},
			p.background, p.settings.environ(), nil, p.scheduler, p.logfile),
			p._default_final_exit)
	}
}

func NewPackagePhase(actionmap Actionmap, background bool, fd_pipes map[int]int,
	logfile string, scheduler *SchedulerInterface, settings *Config)*PackagePhase {
	p := &PackagePhase{}
	p.CompositeTask = NewCompositeTask()
	p._shell_binary = BashBinary

	p.actionmap = actionmap
	p.background = background
	p.fd_pipes = fd_pipes
	p.logfile = logfile
	p.scheduler = scheduler
	p.settings = settings

	return p
}

type PackageUninstall struct{
	*CompositeTask

	// slot
	settings *Config
	pkg *PkgStr
	_builddir_lock *EbuildBuildDir
	world_atom
	ldpath_mtimes
	opts
}

func(p*PackageUninstall) _start() {

	vardb := p.pkg.root_config.trees["vartree"].dbapi
	dbdir := vardb.getpath(p.pkg.cpv)
	if !pathExists(dbdir) {
		i := 0
		p.returncode = &i
		p._async_wait()
		return
	}

	p.settings.SetCpv(p.pkg, nil)
	cat, pf := catsplit(p.pkg.cpv.string)[0], catsplit(p.pkg.cpv.string)[1]
	myebuildpath := filepath.Join(dbdir, pf+".ebuild")

	//try:
	doebuild_environment(myebuildpath, "prerm",
		nil, p.settings, false, nil, vardb)
	//except UnsupportedAPIException:
	//pass

	p._builddir_lock = NewEbuildBuildDir(p.scheduler, p.settings)
	p._start_task(NewAsyncTaskFuture(p._builddir_lock.async_lock()), p._start_unmerge)
}

func(p*PackageUninstall) _start_unmerge( lock_task) {
	p._assert_current(lock_task)
	if lock_task.cancelled {
		p._default_final_exit(lock_task)
		return
	}

	lock_task.future.result()
	prepare_build_dirs(p.settings, true)

	retval, pkgmap := _unmerge_display(p.pkg.root_config,
		p.opts, "unmerge", [p.pkg.cpv], clean_delay = 0,
		writemsg_level = p._writemsg_level)

	if retval != 0 {
		p._async_unlock_builddir(retval)
		return
	}

	p._writemsg_level(fmt.Sprintf(">>> Unmerging %s...\n" ,p.pkg.cpv, ), -1, 0)
	p._emergelog(fmt.Sprintf("=== Unmerging... (%s)" ,p.pkg.cpv, ))

	cat, pf := catsplit(p.pkg.cpv.string)[0],catsplit(p.pkg.cpv.string)[1]
	unmerge_task := NewMergeProcess(
		cat, pf, p.settings, "vartree", p.pkg.root_config.trees["vartree"],
		 p.scheduler, p.background, nil, "","","",
		p.pkg.root_config.trees["vartree"].dbapi,
		p.ldpath_mtimes, p.settings.get("PORTAGE_LOG_FILE"), nil, unmerge=true)

	p._start_task(unmerge_task, p._unmerge_exit)
}

func(p*PackageUninstall) _unmerge_exit( unmerge_task) {
	if p._final_exit(unmerge_task) != 0 {
		p._emergelog(fmt.Sprintf(" !!! unmerge FAILURE: %s", p.pkg.cpv, ))
	} else {
		p._emergelog(fmt.Sprintf(" >>> unmerge success: %s", p.pkg.cpv, ))
		p.world_atom(p.pkg)
	}
	p._async_unlock_builddir(p.returncode)
}

// nil
func(p *PackageUninstall) _async_unlock_builddir(returncode *int) {
	if returncode != nil {
		p.returncode = nil
	}
	p._start_task(
		NewAsyncTaskFuture(p._builddir_lock.async_unlock()),
		func(t *int){p._unlock_builddir_exit(t, returncode)})
}

// nil
func(p*PackageUninstall) _unlock_builddir_exit(unlock_task, returncode *int) {
	p._assert_current(unlock_task)
	if unlock_task.cancelled && returncode!= nil {
		p._default_final_exit(unlock_task)
		return
	}

	//unlock_task.future.cancelled() || unlock_task.future.result()
	if returncode != nil {
		p.returncode = returncode
		p._async_wait()
	}
}

func(p*PackageUninstall) _emergelog( msg string) {
	emergelog(!p.settings.Features.Features["notitles"], msg, "")
}

// 0, 0
func(p*PackageUninstall) _writemsg_level(msg string, level, noiselevel int) {

	log_path := p.settings.ValueDict["PORTAGE_LOG_FILE"]
	background := p.background

	if log_path == "" {
		if !(background && level < 30) {
			WriteMsgLevel(msg, level, noiselevel)
		}
	}else {
		p.scheduler.output(msg, log_path,false, level, noiselevel)
	}
}

func NewPackageUninstall(background bool, ldpath_mtimes = ldpath_mtimes, opts=m.emerge_opts,
	pkg *PkgStr, scheduler *SchedulerInterface, settings *Config, world_atom=world_atom)*PackageUninstall{
	p := &PackageUninstall{}
	p.CompositeTask = NewCompositeTask()
	p.background = background
	p.ldpath_mtimes=ldpath_mtimes
	p.opts = opts
	p.pkg=pkg
	p.scheduler=scheduler
	p.settings=settings
	p.world_atom=world_atom
	return p
}

type PackageVirtualDbapi struct{
	*dbapi
}

func NewPackageVirtualDbapi(settings) *PackageVirtualDbapi {
	p := &PackageVirtualDbapi{}
	p.dbapi = NewDbapi()
	p.settings = settings
	p._match_cache =
	{
	}
	p._cp_map =
	{
	}
	p._cpv_map =
	{
	}
	return p
}

func(p*PackageVirtualDbapi) clear() {
	if len(p._cpv_map) > 0 {
		p._clear_cache()
		p._cp_map.clear()
		p._cpv_map.clear()
	}
}

func(p*PackageVirtualDbapi) copy() {
	obj := NewPackageVirtualDbapi(p.settings)
	obj._match_cache = p._match_cache.copy()
	obj._cp_map = p._cp_map.copy()
	for k, v
	in
	obj._cp_map.items() {
		obj._cp_map[k] = v[:]
	}
	obj._cpv_map = p._cpv_map.copy()
	return obj
}

func(p*PackageVirtualDbapi) __bool__() {
	return bool(p._cpv_map)
}

func(p*PackageVirtualDbapi) __iter__() {
	return iter(p._cpv_map.values())
}

func(p*PackageVirtualDbapi) __contains__( item) bool {
	existing = p._cpv_map.get(item.cpv)
	if existing != nil && existing == item {
		return true
	}
	return false
}

// nil
func(p*PackageVirtualDbapi) get( item, default1=None) {
	cpv = getattr(item, "cpv", None)
	if cpv == nil {
		if len(item) != 5 {
			return default1
		}
	}
	type_name, root, cpv, operation, repo_key = item

	existing := p._cpv_map.get(cpv)
	if existing != nil &&
		existing == item {
		return existing
	}
	return default1
}

func(p*PackageVirtualDbapi) match_pkgs( atom) {
	return [p._cpv_map[cpv]
	for cpv
	in
	p.match(atom)]
}

func(p*PackageVirtualDbapi) _clear_cache() {
	if p._categories != nil {
		p._categories = nil
	}
	if len(p._match_cache) > 0 {
		p._match_cache =
		{
		}
	}
}

// 1
func(p*PackageVirtualDbapi) match( origdep *Atom, use_cache int) {
	atom := dep_expand(origdep, p, 1, p.settings)
	cache_key := [2]*Atom{atom, atom.unevaluatedAtom}
	result := p._match_cache[cache_key]
	if result != nil {
		return result[:]
	}
	result = list(p._iter_match(atom, p.cp_list(atom.cp, 1)))
	p._match_cache[cache_key] = result
	return result[:]
}

// nil
func(p*PackageVirtualDbapi) cpv_exists( cpv, myrepo=None) int {
	return cpv
	in
	p._cpv_map
}

// 1
func(p*PackageVirtualDbapi) cp_list( mycp string, use_cache int) {
	cache_key := (mycp, mycp)
	cachelist := p._match_cache.get(cache_key)
	if cachelist != nil {
		return cachelist[:]
	}
	cpv_list := p._cp_map.get(mycp)
	if cpv_list == nil {
		cpv_list = []string{}
	} else {
		cpv_list = []string{}
		for pkg
			in
		cpv_list {
			cpv_list = append(pkg.cpv)
		}
	}
	p._cpv_sort_ascending(cpv_list)
	p._match_cache[cache_key] = cpv_list
	return cpv_list[:]
}

// false
func(p*PackageVirtualDbapi) cp_all( sort bool) {
	if sort {
		return sorted(p._cp_map)
	}else {
		return list(p._cp_map)
	}
}

func(p*PackageVirtualDbapi) cpv_all() {
	return list(p._cpv_map)
}

func(p*PackageVirtualDbapi) cpv_inject( pkg) {
	cp_list := p._cp_map.get(pkg.cp)
	if cp_list == nil {
		cp_list = []string{}
		p._cp_map[pkg.cp] = cp_list
	}
	e_pkg := p._cpv_map.get(pkg.cpv)
	if e_pkg != nil {
		if e_pkg == pkg {
			return
		}
	}
	p.cpv_remove(e_pkg)
	for e_pkg
		in
	cp_list {
		if e_pkg.slot_atom == pkg.slot_atom {
			if e_pkg == pkg {
				return
			}
			p.cpv_remove(e_pkg)
			break
		}
	}
	cp_list = append(cp_list, pkg)
	p._cpv_map[pkg.cpv] = pkg
	p._clear_cache()
}

func(p*PackageVirtualDbapi) cpv_remove( pkg) {
	old_pkg := p._cpv_map.get(pkg.cpv)
	if old_pkg != pkg {
		raise
		KeyError(pkg)
	}
	p._cp_map[pkg.cp].remove(pkg)
	del
	p._cpv_map[pkg.cpv]
	p._clear_cache()
}

// nil
func(p*PackageVirtualDbapi) aux_get( cpv, wants, myrepo=None) {
	metadata := p._cpv_map[cpv]._metadata
	return [metadata.get(x, "")
	for x
	in
	wants]
}

func(p*PackageVirtualDbapi) aux_update(cpv, values) {
	p._cpv_map[cpv]._metadata.update(values)
	p._clear_cache()
}

type PipeReader struct {
	*AbstractPollTask

	// slot
	input_files map[string]int
	_read_data []string
	_use_array
}

func (p* PipeReader) _start() {
	p._read_data = []string{}

	for _, f := range p.input_files {
		fd := uintptr(f)
		//if isinstance(f, int)
		//else
		//f.fileno()
		ff, _ := unix.FcntlInt(fd, unix.F_GETFL, 0)
		unix.FcntlInt(fd, unix.F_SETFL,
			ff|unix.O_NONBLOCK)

		if p._use_array {
			p.scheduler.add_reader(f, func() bool {
				return p._array_output_handler(f)
			})
		} else {
			p.scheduler.add_reader(f, func() bool {
				return p._output_handler(f)
			})
		}
	}

	p._registered = true
}

func (p* PipeReader) _cancel() {
	p._unregister()
	if p.returncode == nil {
		p.returncode = &p._cancelled_returncode
	}
}

func (p* PipeReader) getvalue() string {
	return strings.Join(p._read_data, "")
}

func (p* PipeReader) close() {
	p._read_data = nil
}

func (p* PipeReader) _output_handler( fd int)bool {
	for {
		data := p._read_buf(fd)
		if data == nil {
			break
		}
		if len(data) > 0 {
			p._read_data = append(p._read_data, string(data))
		} else {
			p._unregister()
			//p.returncode = p.returncode ||0
			p._async_wait()
			break
		}
	}
	return true // add
}

func (p* PipeReader) _array_output_handler( f int) bool {
	for {
		data := p._read_array(f)
		if data == "" {
			break
		}
		if len(data) > 0 {
			p._read_data = append(p._read_data, data)
		} else {
			p._unregister()
			//p.returncode = p.returncode ||0
			p._async_wait()
			break
		}
	}

	return true
}

func (p* PipeReader) _unregister() {
	p._registered = false
	if p.input_files != nil {
		for _, f := range p.input_files {
			//if isinstance(f, int):
			p.scheduler.remove_reader(f)
			syscall.Close(f)
			//else:
			//p.scheduler.remove_reader(f.fileno())
			//f.close()
		}
		p.input_files = nil
	}
}

func NewPipeReader(input_files map[string]int, scheduler *SchedulerInterface)*PipeReader {
	p := &PipeReader{}
	p.AbstractPollTask = NewAbstractPollTask()

	p.input_files = input_files
	p.scheduler = scheduler

	return p
}


type ProgressHandler struct {
	curval, maxval int
	min_latency,_last_update float64
}

func NewProgressHandler()*ProgressHandler {
	p := &ProgressHandler{}
	p.curval = 0
	p.maxval = 0
	p._last_update = 0
	p.min_latency = 0.2
	return p
}

func(p *ProgressHandler) onProgress( maxval, curval int) {
	p.maxval = maxval
	p.curval = curval
	cur_time := float64(time.Now().UnixMilli()) / 1000
	if cur_time-p._last_update >= p.min_latency {
		p._last_update = cur_time
		p.display()
	}
}

func(p *ProgressHandler) display() {
	//raise NotImplementedError(p)
}

type RootConfig struct {
	// slot
	Mtimedb   *MtimeDB
	root      string
	Settings  *Config
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
	r.Settings = settings
	r.root = r.Settings.ValueDict["EROOT"]
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
	r.Settings =other.Settings
	r.trees=other.trees
	r.setconfig=other.setconfig
	r.sets=other.sets
}

const FAILURE = 1

type  Scheduler struct {
	*PollScheduler
	_loadavg_latency, _max_display_latency                           int
	_opts_ignore_blockers, _opts_no_background, _opts_no_self_update map[string]bool

	settings        *Config
	target_root     string
	trees           interface{}
	myopts          interface{}
	_spinner        interface{}
	_mtimedb        int
	_favorites      []*Atom
	_args_set       *InternalPackageSet
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
	_config_pool             map[string][]*Config
	_failed_pkgs             []*_failed_pkg
	_blocker_db              map[string]*BlockerDB
	pkgsettings              map[string]*Config
	_binpkg_opts             *_binpkg_opts_class
	_task_queues             *_task_queues_class
	_fetch_log               string
	_running_portage         *Package
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
	fetch_all_uri,fetchonly,pretend string
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
	emergelog(e.xterm_titles, mystr, short_msg)
}

// SlotObject
type  _failed_pkg struct {
	// slot
	build_dir,build_log,pkg, postinst_failure,returncode string
}

type  _ConfigPool struct {
	// slot
	_root       string
	_allocate   func(string)*Config
	_deallocate func(*Config)
}

func NewConfigPool(root string, allocate func(string)*Config, deallocate func(*Config)) *_ConfigPool {
	c := &_ConfigPool{}
	c._root = root
	c._allocate = allocate
	c._deallocate = deallocate
	return c
}

func (c *_ConfigPool) allocate() *Config {
	return c._allocate(c._root)
}

func(c *_ConfigPool) deallocate( settings *Config) {
	c._deallocate(settings)
}

type  _unknown_internal_error struct {
	*PortageException
}
// ""
func New_unknown_internal_error(value string) *_unknown_internal_error {
	u := &_unknown_internal_error{}
	u.PortageException = &PortageException{value: value}
	return u
}

// nil, nil, nil
func NewScheduler(settings *Config, trees, mtimedb, myopts, spinner, mergelist, favorites, graph_config) *Scheduler {
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
	s._mtimedb = mtimedb
	s._favorites = favorites
	s._args_set = NewInternalPackageSet(favorites, true, true)
	s._build_opts = &_build_opts_class{}

	for k
		in
	s._build_opts.__slots__ {
		setattr(s._build_opts, k, myopts.get("--"+k.replace("_", "-")))
	}
	s._build_opts.buildpkg_exclude = NewInternalPackageSet(
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
	s._task_queues.merge=NewSequentialTaskQueue()
	s._task_queues.jobs=NewSequentialTaskQueue()
	s._task_queues.ebuild_locks=NewSequentialTaskQueue()
	s._task_queues.fetch=NewSequentialTaskQueue()
	s._task_queues.unpack=NewSequentialTaskQueue()

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
	s.pkgsettings = map[string]*Config{}
	s._config_pool = map[string][]*Config{}
	for root
		in
	s.trees {
		s._config_pool[root] = []*Config{}
	}

	s._fetch_log = filepath.Join(_emerge_log_dir, "emerge-fetch.log")
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
		if isinstance(x, Package) &&
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
		WriteMsg(Red("!!!")+"\n", -1, nil)
		WriteMsg(Red("!!!")+" parallel-fetching "+
			"requires the distlocks feature enabled"+"\n",
			-1, nil)
		WriteMsg(Red("!!!")+" you have it disabled, "+
			"thus parallel-fetching is being disabled"+"\n",
			-1, nil)
		WriteMsg(Red("!!!")+"\n", -1, nil)
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
		if not isinstance(x, Package):
		continue
		if x.operation != "merge" {
			continue
		}
		if x.root != s._running_root.root {
			continue
		}
		if len( matchFromList(PORTAGE_PACKAGE_ATOM, []*PkgStr{x}))==0 {
			continue
		}
		rval := _check_temp_dir(s.settings)
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
	depgraph_params := create_depgraph_params(s.myopts, "")
	dynamic_deps:= Inmss(depgraph_params, "dynamic_deps")

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
			WriteMsgLevel(">>> Sending package output to stdio due "+
				"to interactive package(s):\n",
				10, -1)
			msg := []string{""}
			for pkg
				in
			interactive_tasks {
				pkg_str := "  " + colorize("INFORM", fmt.Sprint(pkg.cpv))
				if pkg.root_config.settings.ValueDict["ROOT"] != "/" {
					pkg_str += " for " + pkg.root
				}
				msg= append(msg, pkg_str)
			}
			msg= append(msg, "")
			WriteMsgLevel(strings.Join(msg, "\n")+"\n", 20, -1)
			if s._max_jobs is
			true ||
				s._max_jobs > 1
			{
				s._set_max_jobs(1)
				WriteMsgLevel(">>> Setting --jobs=1 due "+
					"to the above interactive package(s)\n",
					20, -1)
				WriteMsgLevel(">>> In order to temporarily mask "+
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
	params := create_depgraph_params(s.myopts, "")
	if not params["implicit_system_deps"] {
		return
	}

	deep_system_deps := s._deep_system_deps
	deep_system_deps = map[string]string{}
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
	cpv_map :=
	{
	}
	for pkg
		in
	s._mergelist {
		if not isinstance(pkg, Package) {
			continue
		}
		if pkg.installed {
			continue
		}
		if pkg.cpv not
		in
		cpv_map{
			cpv_map[pkg.cpv] = [pkg]
			continue
		}
		for earlier_pkg
			in
		cpv_map[pkg.cpv] {
			s._digraph.add(earlier_pkg, pkg,
				priority = NewDepPriority(true))
		}
		cpv_map[pkg.cpv].append(pkg)
	}
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
	if not isinstance(x, Package) ||
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
	portdb = x.root_config.trees['porttree'].dbapi
	ebuild_path = portdb.findname(x.cpv, myrepo = x.repo)
	if ebuild_path == nil:
	raise
	AssertionError("ebuild not found for '%s'" % x.cpv)
	pkgsettings.ValueDict['O'] =  filepath.Dir(ebuild_path)
	if digestgen(nil,  pkgsettings, portdb)==0 {
		WriteMsgLevel(fmt.Sprintf("!!! Unable to generate manifest for '%s'.\n", x.cpv), 40,-1)
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
	quiet_settings :=map[string]*Config{}
	for myroot, pkgsettings := range s.pkgsettings{
		quiet_config := NewConfig(pkgsettings,nil, "", nil, "","","","",true, nil, false, nil)
		quiet_config.ValueDict["PORTAGE_QUIET"] = "1"
		quiet_config.BackupChanges("PORTAGE_QUIET")
		quiet_settings[myroot] = quiet_config
		quiet_config.ValueDict = map[string]string{}
	}

	failures := 0

	for x
		in
	s._mergelist {
		if not isinstance(x, Package) ||
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
		portdb = root_config.trees["porttree"].dbapi
		quiet_config = quiet_settings.ValueDict[root_config.root]
		ebuild_path = portdb.findname(x.cpv, myrepo = x.repo)
		if ebuild_path == nil:
		raise
		AssertionError("ebuild not found for '%s'" % x.cpv)
		quiet_config["O"] =  filepath.Dir(ebuild_path)
		if not digestcheck([], quiet_config, strict = true):
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

		for pkg
			in
		s._mergelist {
			if not isinstance(pkg, Package) ||
				pkg.operation == "uninstall" {
				continue
			}
			prefetcher = s._create_prefetcher(pkg)
			if prefetcher != nil {
				prefetchers[pkg] = prefetcher
				s._task_queues.fetch.add(prefetcher)
			}
		}
	}
}

func (s *Scheduler) _create_prefetcher( pkg *Package) {
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
		if not isinstance(x, Package) {
			continue
		}

		if x.operation == "uninstall" {
			continue
		}

		if Ins([]string{"0", "1", "2", "3"}, x.eapi) {
			continue
		}

		if "pretend" not
		in
		x.defined_phases{
			continue
		}

		out_str := ">>> Running pre-merge checks for " + colorize("INFORM", x.cpv) + "\n"
		WriteMsgStdout(out_str, -1)

		root_config := x.root_config
		settings := s.pkgsettings[root_config.root]
		settings.SetCpv(x, nil)

		rval := _check_temp_dir(settings)
		if rval != 0 {
			return rval
		}

		fpes, _ := filepath.EvalSymlinks(settings.ValueDict["PORTAGE_TMPDIR"])
		build_dir_path := filepath.Join(fpes, "portage", x.category, x.pf)
		existing_builddir := pathIsDir(build_dir_path)
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
				portdb = root_config.trees["porttree"].dbapi
				ebuild_path = portdb.findname(x.cpv, myrepo = x.repo)
				if ebuild_path == nil {
					raise
					AssertionError(
						"ebuild not found for '%s'" % x.cpv)
				}
			}
			doebuild_environment(
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
			ensureDirs(infloc)
			s._sched_iface.run_until_complete(
				bintree.dbapi.unpack_metadata(settings, infloc))
			ebuild_path = filepath.Join(infloc, x.pf+".ebuild")
			settings.configDict["pkg"]["EMERGE_FROM"] = "binary"
			settings.configDict["pkg"]["MERGE_TYPE"] = "binary"

		}else {
			tree = "porttree"
			portdb = root_config.trees["porttree"].dbapi
			ebuild_path = portdb.findname(x.cpv, myrepo = x.repo)
			if ebuild_path == nil:
			raise
			AssertionError("ebuild not found for '%s'" % x.cpv)
			settings.configDict["pkg"]["EMERGE_FROM"] = "ebuild"
			if s._build_opts.buildpkgonly:
			settings.configDict["pkg"]["MERGE_TYPE"] = "buildonly"
			else:
			settings.configDict["pkg"]["MERGE_TYPE"] = "source"
		}

		doebuild_environment(ebuild_path,
			"pretend", nil, settings, false, nil,
			s.trees[settings.ValueDict["EROOT"]][tree].dbapi)

		prepare_build_dirs(settings, false)

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
		elog_process(x.cpv, settings, nil)
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
		WriteMsgStdout(
			colorize("GOOD", "*** Resuming merge...\n"), -1)
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
		if tmpdir == "" || !pathIsDir(tmpdir):
		msg := []string{
			"The directory specified in your PORTAGE_TMPDIR variable does not exist:",
			tmpdir,
			"Please create this directory or correct your PORTAGE_TMPDIR setting.",
		}
		out := NewEOutput(false)
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

		s.pkgsettings[root] = NewConfig(root_config.settings, nil, "", nil, "", "", "", "", true, nil, false, nil)
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
			WriteMsg(fmt.Sprintf("\n\nExiting on signal %s\n", signum), 0, nil)
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
			if isinstance(x, Package) &&
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

	printer := NewEOutput(false)
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
		WriteMsgLevel(line, -1, 0)
		except
		zlib.error
		as
	e:
		WriteMsgLevel("%s\n"%(e, ), level = 40,
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
				(colorize("INFORM", key), root_msg))
			print()
			for phase := range EBUILD_PHASES{
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
		for _, line := range SplitSubN(msg, 72) {
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
				printer.eerror(fmt.Sprintf("  '%s'", colorize("INFORM", log_path)))
			}
		}
		printer.eerror("")
	}

	if len(s._failed_pkgs_all) > 0 {
		return FAILURE
	}
	return 0
}

func (s *Scheduler) _elog_listener(mysettings *Config, key, logentries logentries map[string][][2]string, fulltext) {
	errors := filter_loglevels(logentries, map[string]bool{"ERROR":true})
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
	for pkg
		in
	s._mergelist {
		if isinstance(pkg, Package) {
			pkg_queue.append(pkg)
		}else if
		isinstance(pkg, Blocker) {
			//pass
		}
	}
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
		(priority.runtime ||
			priority.runtime_post)
		{
			return false
		}
		return true
	}

	for child
		in
	graph.child_nodes(pkg,
		ignore_priority = ignore_non_runtime_or_satisfied):
	if not isinstance(child, Package) ||
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

func (s *Scheduler) _merge_exit(merge) {
	s._running_tasks.pop(id(merge), nil)
	s._do_merge_exit(merge)
	s._deallocate_config(merge.merge.settings)
	if merge.returncode == 0 &&
		not
		merge.merge.pkg.installed {
		s._status_display.curval += 1
	}
	s._status_display.merges = len(s._task_queues.merge)
	s._schedule()
}

func (s *Scheduler) _do_merge_exit( merge) {
	pkg = merge.merge.pkg
	if merge.returncode != 0 {
		settings := merge.merge.settings
		build_dir := settings.ValueDict["PORTAGE_BUILDDIR"]
		build_log := settings.ValueDict["PORTAGE_LOG_FILE"]

		s._failed_pkgs = append(s._failed_pkgs, &_failed_pkg{
			build_dir, build_log,
			pkg, nil,
			merge.returncode})
		if ! s._terminated_tasks {
			s._failed_pkg_msg(s._failed_pkgs[len(s._failed_pkgs)-1], "install", "to")
			s._status_display.failed = len(s._failed_pkgs)
		}
		return
	}

	if merge.postinst_failure {
		s._failed_pkgs_all = append(s._failed_pkgs_all, &_failed_pkg{
			merge.merge.settings.ValueDict["PORTAGE_BUILDDIR"],
			merge.merge.settings.ValueDict["PORTAGE_LOG_FILE"],
			pkg, true, merge.returncode})
		s._failed_pkg_msg(s._failed_pkgs_all[len(s._failed_pkgs_all)-1],
			"execute postinst for", "for")
	}

	s._task_complete(pkg)
	pkg_to_replace = merge.merge.pkg_to_replace
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
	s._running_tasks.pop(id(build), nil)
	if build.returncode == 0 &&
		s._terminated_tasks {
		s.curval += 1
		s._deallocate_config(build.settings)
	}else if
	build.returncode == 0 {
		s.curval += 1
		merge = NewPackageMerge(build, s._sched_iface)
		s._running_tasks[id(merge)] = merge
		if not build.build_opts.buildpkgonly &&
			build.pkg
		in
		s._deep_system_deps{
			s._merge_wait_queue.append(merge)
			merge.addStartListener(s._system_merge_started)
		} else {
			s._task_queues.merge.add(merge)
			merge.addExitListener(s._merge_exit)
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

func (s *Scheduler) _task_complete(pkg) {
	s._completed_tasks.add(pkg)
	s._unsatisfied_system_deps.discard(pkg)
	s._choose_pkg_return_early = false
	blocker_db := s._blocker_db[pkg.root]
	blocker_db.discardBlocker(pkg)
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
	add_listener(s._elog_listener)


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
	remove_listener(s._elog_listener)
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
	for pkg
		in
	s._pkg_queue:
	if pkg.operation == "uninstall" &&
		not
		graph.child_nodes(pkg):
	chosen_pkg = pkg
	break

	if chosen_pkg == nil:
	later = set(s._pkg_queue)
	for pkg
		in
	s._pkg_queue:
	later.remove(pkg)
	if not s._dependent_on_scheduled_merges(pkg, later):
	chosen_pkg = pkg
	break

	if chosen_pkg != nil:
	s._pkg_queue.remove(chosen_pkg)

	if chosen_pkg == nil:
	s._choose_pkg_return_early = true

	return chosen_pkg
}

func (s *Scheduler) _dependent_on_scheduled_merges( pkg, later) {

	graph := s._digraph
	completed_tasks := s._completed_tasks

	dependent := false
	traversed_nodes := map[string]bool{pkg:true}
	direct_deps := graph.child_nodes(pkg)
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

func (s *Scheduler) _allocate_config( root string) *Config {
	var temp_settings *Config
	if s._config_pool[root] != nil {
		temp_settings = s._config_pool[root][len(s._config_pool[root])-1]
		s._config_pool[root]=s._config_pool[root][:len(s._config_pool[root])-1]
	}else {
		temp_settings = NewConfig(s.pkgsettings[root], nil, "", nil, "", "", "", "", true, nil, false, nil)
	}
	temp_settings.reload()
	temp_settings.reset(0)
	return temp_settings
}

func (s *Scheduler) _deallocate_config(settings *Config) {
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

func (s *Scheduler) _schedule_merge_wakeup( future IFuture) {
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

func (s *Scheduler) _get_prefetcher(pkg) {
//try:
	prefetcher := s._prefetchers.pop(pkg, None)
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

func (s *Scheduler) _task( pkg) {

	var pkg_to_replace = nil
	if pkg.operation != "uninstall" {
		vardb := pkg.root_config.trees["vartree"].dbapi
		previous_cpv := []*PkgStr{}
		for x
			in
		vardb.match(pkg.slot_atom) {
			if cpvGetKey(x, "") == pkg.cp {
				previous_cpv = append(previous_cpv, x)
			}
		}
		if len(previous_cpv) == 0 && vardb.cpv_exists(pkg.cpv) {
			previous_cpv = []*PkgStr{pkg.cpv}
		}
		if len(previous_cpv) != 0 {
			pc := previous_cpv[len(previous_cpv)-1]
			previous_cpv = previous_cpv[:len(previous_cpv)-1]
			pkg_to_replace = s._pkg(pc,
				"installed", pkg.root_config, true,
				"uninstall")
		}
	}

	prefetcher := s._get_prefetcher(pkg)

	pc := *s._pkg_count
	task := NewMergeListItem(s._args_set, s._background, s._binpkg_opts,
		s._build_opts, NewConfigPool(pkg.root, s._allocate_config,
			s._deallocate_config), s.myopts, s._find_blockers(pkg),
		s._logger, s._mtimedb, pkg, &pc, pkg_to_replace,
		prefetcher, s._sched_iface, s._allocate_config(pkg.root),
		s._status_msg, s._world_atom)

	return task
}

func (s *Scheduler) _failed_pkg_msg(failed_pkg *_failed_pkg, action, preposition string) {
	pkg := failed_pkg.pkg
	msg := fmt.Sprintf(fmt.Sprintf("%s to %s %s",
		bad("Failed"), action, colorize("INFORM", pkg.cpv)))
	if pkg.root_config.settings.ValueDict["ROOT"] != "/" {
		msg += fmt.Sprintf(fmt.Sprintf(" %s %s", preposition, pkg.root))
	}

	log_path := s._locate_failure_log(failed_pkg)
	if log_path != "" {
		msg += ", Log file:"
		s._status_msg(msg)
	}

	if log_path != "" {
		s._status_msg(fmt.Sprintf(" '%s'", colorize("INFORM", log_path), ))
	}
}

func (s *Scheduler) _status_msg( msg string) {
	if !s._background {
		WriteMsgLevel("\n", 0, 0)
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
		if isinstance(x, Package) && x.operation == "merge"{
		rm = append(rm, list(x))
	}
	}
	mtimedb["resume"]["mergelist"] = rm

	mtimedb.commit()
}

func (s *Scheduler) _calc_resume_list() {
	print(colorize("GOOD", "*** Resuming merge..."))

	s._destroy_graph()

	myparams := create_depgraph_params(s.myopts, nil)
	success := false
	e = nil
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

	if e != nil:

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
		for _, line:= range SplitSubN(msg, 72) {
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
	eerror(line, "other", pkg.cpv, "", nil)
	settings = s.pkgsettings.ValueDict[pkg.root]
	settings.pop("T", nil)
	portage.elog.elog_process(pkg.cpv, settings)
	s._failed_pkgs_all=append(s._failed_pkgs_all, &_failed_pkg{pkg: pkg})

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
		"--pretend")).intersection(s.myopts)
	{
		return
	}

	if pkg.root != s.target_root {
		return
	}

	args_set := s._args_set
	if not args_set.findAtomForPackage(pkg, nil) {
		return
	}

	logger := s._logger
	pkg_count := s._pkg_count
	root_config := pkg.root_config
	world_set := root_config.sets["selected"]
	world_locked := false
	atom = nil

	if pkg.operation != "uninstall" {
		atom = s._world_atoms.get(pkg)
	}

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
	if atom != nil:
	if hasattr(world_set, "add"):
	s._status_msg(("Recording %s in \"world\" " +
		"favorites file...") % atom)
	logger.log(" === (%s of %s) Updating world file (%s)" %
		(pkg_count.curval, pkg_count.maxval, pkg.cpv))
	world_set.add(atom)
	else:
	WriteMsgLevel("\n!!! Unable to record %s in \"world\"\n" %
		(atom,), level = logging.WARN, noiselevel=-1)
finally:
	if world_locked:
	world_set.unlock()
}

// false, "", nil
func (s *Scheduler) _pkg( cpv *PkgStr, type_name string, root_config *RootConfig, installed bool,
	operation string, myrepo=nil) *Package {

	pkg = s._pkg_cache.get(NewPackage()._gen_hash_key(cpv = cpv,
		type_name = type_name, repo_name=myrepo, root_config = root_config,
		installed=installed, operation = operation))

	if pkg != nil {
		return pkg
	}

	tree_type = depgraph.pkg_tree_map[type_name]
	db = root_config.trees[tree_type].dbapi
	db_keys = list(s.trees[root_config.root][
		tree_type].dbapi._aux_cache_keys)
	metadata = zip(db_keys, db.aux_get(cpv, db_keys, myrepo = myrepo))
	pkg := NewPackage(type_name != "ebuild",
		cpv, installed, metadata,
		root_config, type_name)
	s._pkg_cache[pkg] = pkg
	return pkg
}

type SequentialTaskQueue struct{
	max_jobs int
	_scheduling bool
	running_tasks, _task_queue
}

func NewSequentialTaskQueue(**kwargs)*SequentialTaskQueue {
	s := &SequentialTaskQueue{}
	SlotObject.__init__(s, **kwargs)
	s._task_queue = deque()
	s.running_tasks = set()
	if s.max_jobs == 0 {
		s.max_jobs = 1
	}
	return s
}

func(s*SequentialTaskQueue) add( task) {
	s._task_queue.append(task)
	s.schedule()
}

func(s*SequentialTaskQueue) addFront(task) {
	s._task_queue.appendleft(task)
	s.schedule()
}

func(s*SequentialTaskQueue) schedule() {

	if s._scheduling {
		return
	}

	s._scheduling = true
try:
	while
	s._task_queue
	and(s.max_jobs
	is
	true
	or
	len(s.running_tasks) < s.max_jobs):
	task = s._task_queue.popleft()
	cancelled = getattr(task, "cancelled", None)
	if not cancelled:
	s.running_tasks.add(task)
	task.addExitListener(s._task_exit)
	task.start()
finally:
	s._scheduling = false
}

func(s*SequentialTaskQueue) _task_exit( task) {
	s.running_tasks.remove(task)
	if s._task_queue:
	s.schedule()
}

func(s*SequentialTaskQueue) clear() {
	for task
		in
	s._task_queue:
	task.cancel()
	s._task_queue.clear()

	for task
		in
	list(s.running_tasks):
	task.cancel()
}

@coroutine
func(s*SequentialTaskQueue) wait() {
	while
s:
	task = next(iter(s.running_tasks), None)
	if task is
None:
	yield
	asyncio.sleep(0)
	else:
	yield
	task.async_wait()
}

func(s*SequentialTaskQueue) __bool__() bool {
	return bool(len(s._task_queue) != 0 || len(s.running_tasks) != 0)
}

func(s*SequentialTaskQueue) __len__() int {
	return len(s._task_queue) + len(s.running_tasks)
}


type SetArg struct{
	*DependencyArg

	// slot
	name string
	pset
}

// nil
func NewSetArg( pset, **kwargs) *SetArg{
	s := &SetArg{}
	s.DependencyArg = NewDependencyArg(**kwargs)
	s.pset = pset
	s.name = s.arg[len(SETPREFIX):]
	return s
}

type SpawnProcess struct {
	*SubProcess
	_CGROUP_CLEANUP_RETRY_MAX int
	_spawn_kwarg_names []string

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

	fd_pipes_orig := map[int]int{}
	for k, v := range fd_pipes{
		fd_pipes_orig[k]=v
	}

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
	stdout_fd = syscall.Dup(string(fd_pipes_orig[1]))
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


func(s *SpawnProcess) _can_log( slave_fd int)bool{
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
					filepath.Join(s.cgroup, "cgroup.procs", strings.Join(pidss, " "))))

			s._elog("eerror", msg)
		}

		err := os.RemoveAll(s.cgroup.Name())
		if err != nil {
			//except OSError:
			//pass
		}
	}
}

func(s *SpawnProcess) _elog(elog_funcname string, lines []string){
	var elog_func func(string)
	switch elog_funcname {
	case "eerror":
		elog_func = NewEOutput(false).eerror
	}
	for _, line := range lines{
		elog_func(line)
	}
}

func NewSpawnProcess(args []string, background bool, env map[string]string, fd_pipes map[int]int, scheduler *SchedulerInterface, logfile string) *SpawnProcess {
	s := &SpawnProcess{}

	s._spawn_kwarg_names = []string{"env", "opt_name", "fd_pipes",
		"uid", "gid", "groups", "umask", "logfile",
		"path_lookup", "pre_exec", "close_fds", "cgroup",
		"unshare_ipc", "unshare_mount", "unshare_pid", "unshare_net"}
	s.args =args
	s.background = background
	s.env = env
	s.scheduler = scheduler
	s.logfile = logfile
	s.fd_pipes = fd_pipes
	s._CGROUP_CLEANUP_RETRY_MAX = 8
	s.SubProcess = NewSubProcess()
	return s
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

func (s *SubProcess) _cancel() {
	if s.isAlive() && s.pid != 0 {
		err := syscall.Kill(s.pid, syscall.SIGTERM)
		if err != nil {
			//except OSError as e:
			if err == syscall.EPERM {
				WriteMsgLevel(fmt.Sprintf("!!! kill: (%i) - Operation not permitted\n", s.pid), 40, -1)
			} else if err != syscall.ESRCH {
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
	s.returncode = &returncode
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

type Task struct {
	hashKey   string
	hashValue string
}

func (t *Task) eq(task *Task) bool {
	return t.hashKey == task.hashKey
}

func (t *Task) ne(task *Task) bool {
	return t.hashKey != task.hashKey
}

func (t *Task) hash() string {
	return t.hashValue
}

func (t *Task) len() int {
	return len(t.hashKey)
}

func (t *Task) iter(key string) int {
	return len(t.hashKey)
}

func (t *Task) contains() int {
	return len(t.hashKey)
}

func (t *Task) str() int {
	return len(t.hashKey)
}

func (t *Task) repr() int {
	return len(t.hashKey)
}

func NewTask() *Task {
	t := &Task{}

	return t
}


type TaskSequence struct{
	*CompositeTask
	_task_queue [] *MiscFunctionsProcess
}

// nil
func NewTaskSequence(scheduler *SchedulerInterface) *TaskSequence {
	t := &TaskSequence{}

	t.AsynchronousTask = NewAsynchronousTask(scheduler)
	t._task_queue = []*MiscFunctionsProcess{}
	return t
}

func (t *TaskSequence) add(task *MiscFunctionsProcess) {
	t._task_queue = append(t._task_queue, task)
}

func (t *TaskSequence) _start() {
	t._start_next_task()
}

func (t *TaskSequence) _cancel() {
	t._task_queue = []*MiscFunctionsProcess{}
	t.CompositeTask._cancel()
}

func (t *TaskSequence) _start_next_task() {
	if len(t._task_queue) == 0 {
		t._current_task = nil
		i := 0
		t.returncode = &i
		t.wait()
		return
	}
	task := t._task_queue[0]
	t._task_queue = t._task_queue[1:]

	t._start_task(task, t._task_exit_handler)
}

func (t *TaskSequence) _task_exit_handler( task) {
	if t._default_exit(task) != 0 {
		t.wait()
	}else if len(t._task_queue) > 0 {
		t._start_next_task()
	}else {
		t._final_exit(task)
		t.wait()
	}
}

func (t *TaskSequence) __bool__() bool {
	return len(t._task_queue) > 0
}

func (t *TaskSequence) __len__() int {
	return len(t._task_queue)
}


type UninstallFailure struct{
	*PortageException
	status int
}

func NewUninstallFailure (*pargs) *UninstallFailure {
	u := &UninstallFailure{}
	u.PortageException = PortageException(pargs)
	u.status = 1
	if len(pargs) > 0 {
		u.status = pargs[0]
	}
	return u
}

type UnmergeDepPriority struct{
	*AbstractDepPriority
	MAX , SOFT, MIN int
	// slots
	optional bool
	ignored, satisfied
}

func NewUnmergeDepPriority(**kwargs)*UnmergeDepPriority {
	u := &UnmergeDepPriority{}

	u.AbstractDepPriority = NewAbstractDepPriority(**kwargs)
	u.MAX    =  0
	u.SOFT   = -3
	u.MIN    = -3

	if u.buildtime {
		u.optional = true
	}
	return u
}

func(u*UnmergeDepPriority) __int__() int {
	if u.runtime_slot_op {
		return 0
	}
	if u.runtime {
		return -1
	}
	if u.runtime_post {
		return -2
	}
	if u.buildtime {
		return -3
	}
	return -3
}

func(u*UnmergeDepPriority) __str__() string {
	if u.ignored {
		return "ignored"
	}
	if u.runtime_slot_op {
		return "hard slot op"
	}
	myvalue := u.__int__()
	if myvalue > u.SOFT {
		return "hard"
	}
	return "soft"
}

type UseFlagDisplay struct {
	// slots
	name,forced string
	enabled bool

	sort_combined func()
	sort_separated func()
}

func NewUseFlagDisplay( name string, enabled bool, forced string)*UseFlagDisplay {
	u := &UseFlagDisplay{}

	u.sort_combined = func (a, b){
		return (a.name > b.name) - (a.name < b.name)
	}

	u.sort_separated = func (a, b) {
		enabled_diff := b.enabled - a.enabled
		if enabled_diff {
			return enabled_diff
		}
		return (a.name > b.name) - (a.name < b.name)
	}

	u.name = name
	u.enabled = enabled
	u.forced = forced
	return u
}

func(u*UseFlagDisplay) __str__() string {
	s := u.name
	if u.enabled {
		s = Red(s)
	} else {
		s = "-" + s
		s = Blue(s)
	}
	if u.forced != "" {
		s = fmt.Sprintf("(%s)", s)
	}
	return s
}

type _flag_info struct{flag, display string}

// nil
func pkg_use_display(pkg, opts map[string]string, modified_use=None) {
	settings := pkg.root_config.settings
	use_expand := pkg.use.expand
	use_expand_hidden := pkg.use.expand_hidden
	_, alphabetical_use :=opts["--alphabetical"]
	forced_flags = set(chain(pkg.use.force,
		pkg.use.mask))
	if modified_use == nil {
		use = set(pkg.use.enabled)
	}else {
		use = set(modified_use)
	}
	use.discard(settings.get('ARCH'))
	use_expand_flags := set()
	use_enabled :=
	{
	}
	use_disabled :=
	{
	}
	for varname
	in
use_expand:
	flag_prefix = varname.lower() + "_"
	for f
	in
use {
		if f.startswith(flag_prefix):
		use_expand_flags.add(f)
		use_enabled.setdefault(
			varname.upper(),[]).append(
			&_flag_info{f, f[len(flag_prefix):]})

		for f
			in
		pkg.iuse.all:
		if f.startswith(flag_prefix):
		use_expand_flags.add(f)
		if f not
		in
	use:
		use_disabled.setdefault(
			varname.upper(),[]).append(
			&_flag_info{f, f[len(flag_prefix):]})
	}

	var_order = set(use_enabled)
	var_order.update(use_disabled)
	var_order = sorted(var_order)
	var_order.insert(0, 'USE')
	use.difference_update(use_expand_flags)
	use_enabled['USE'] = list(&_flag_info{f, f}
	for f
	in
	use)
	use_disabled['USE'] = []

	for f
	in
	pkg.iuse.all{
if f not
in
use
&&
f
not
in
use_expand_flags{
use_disabled['USE'].append(&_flag_info{f, f})
}
}

	flag_displays = []
	for varname
	in
var_order{
if varname.lower() in
use_expand_hidden{
continue
}
flags = []
for f
in
use_enabled.get(varname, []){
flags.append(NewUseFlagDisplay(f.display, true, f.flag
in
forced_flags))
}
for f
in
use_disabled.get(varname, []){
flags.append(UseFlagDisplay(f.display, false, f.flag
in
forced_flags))
}
if alphabetical_use{
flags.sort(key = UseFlagDisplay.sort_combined)
}else{
flags.sort(key = UseFlagDisplay.sort_separated)
}
flag_displays.append('%s="%s"'%(varname,
' '.join("%s"%(f, )
for f
in
flags)))
}

	return strings.Join(flag_displays, " ")
}

type ForkProcess struct {
	*SpawnProcess
}

// nil
func(f *ForkProcess) _spawn(args, fd_pipes=nil, **kwargs){
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

func NewForkProcess() *ForkProcess{
	f := &ForkProcess{}
	f.SpawnProcess=NewSpawnProcess()

	return f
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
			m._buf = lines[len(lines)-1]
			lines = lines[:len(lines)-1]
			out := &bytes.Buffer{}
			for _, line := range lines {
				s4 := strings.SplitN(line, " ", 4)
				funcname, phase, key, msg := s4[0], s4[1], s4[2], s4[3]
				m._elog_keys[key] = true
				var reporter func(msg string, phase string, key string, out io.Writer)
				switch funcname {
				case "eerror":
					reporter = eerror
				case "eqawarn":
					reporter = eqawarn
				case "einfo":
					reporter = einfo
				case "ewarn":
					reporter = ewarn
				case "elog":
					reporter = elog
				}
				reporter(msg, phase, key, out)
			}
		}
	} else if output != nil {
		m.scheduler.remove_reader(m._elog_reader_fd)
		syscall.Close(m._elog_reader_fd)
		m._elog_reader_fd = 0
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
		collect_messages(mylink.mycpv.string, nil)

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
	_setup_pipes(fd_pipes, false)

	HaveColor = m.settings.ValueDict["NOCOLOR"] == "yes" || m.settings.ValueDict["NOCOLOR"] == "true"

	m.vartree.dbapi._flush_cache_enabled = false

	if !m.unmerge {
		if m.settings.ValueDict["PORTAGE_BACKGROUND"] == "1" {
			m.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] = "1"
		} else {
			m.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] = "0"
		}
		m.settings.BackupChanges("PORTAGE_BACKGROUND_UNMERGE")
	}
	m.settings.ValueDict["PORTAGE_BACKGROUND"] = "subprocess"
	m.settings.BackupChanges("PORTAGE_BACKGROUND")

	rval := 1
try:
	if m.unmerge {
		if !mylink.exists() {
			rval = 0
		} else if mylink.unmerge(nil, true, m.prev_mtimes, nil, "", nil) == 0{
			mylink.lockdb()
			//try:
			mylink.delete()
			//finally:
			mylink.unlockdb()
			rval = 0
		}
	} else {
		rval = mylink.merge(m.pkgloc, m.infloc,
			m.myebuild, false, m.mydbapi,
			m.prev_mtimes, counter)
	}
	except
SystemExit:
	raise
except:
	traceback.print_exc()
	sys.stderr.flush()
finally:
	syscall.Exit(rval)

finally:
	if pid == 0 || (pid == 0 && syscall.Getpid() != parent_pid) {
		os.Exit(1)
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
			elog_process(key, m.settings, []string{"prerm", "postrm"})
		}
		m._elog_keys = nil
	}
	m.ForkProcess._unregister()
}

func NewMergeProcess(mycat, mypkg string, settings *Config,treetype string,
	vartree *varTree, scheduler *SchedulerInterface, background bool, blockers interface{},
pkgloc, infloc, myebuild string,mydbapi IDbApi,prev_mtimes interface{},
logfile string, fd_pipes map[int]int) *MergeProcess {
	m := &MergeProcess{}
	m.ForkProcess = NewForkProcess()
	m.mycat = mycat
	m.mypkg = mypkg
	m.settings = settings
	m.treetype = treetype
	m.vartree = vartree
	m.scheduler = scheduler
	m.background = background
	m.blockers = blockers
	m.mydbapi = mydbapi
	m.prev_mtimes = prev_mtimes
	m.logfile = logfile
	m.fd_pipes = fd_pipes

	return m
}

type PollScheduler struct {
	_scheduling, _terminated_tasks, _background bool
	_term_rlock                                 sync.Mutex
	_max_jobs                                   int
	_max_load                                   float64
	_sched_iface                                *SchedulerInterface
}

_loadavg_latency = nil


func(p*PollScheduler) _is_background() bool{
	return p._background
}

func(p*PollScheduler)  _cleanup() {
	p._term_rlock.Lock()
	if p._term_check_handle not
	in(nil, false)
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
	return p._running_job_count() != 0
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
		avg1, _, _, err := getloadavg()
		if err != nil {
			//except OSError:
			return false
		}

		if avg1 >= max_load {
			return false
		}
	}

	return true
}

// false, nil
func NewPollScheduler( main bool, event_loop=nil)*PollScheduler {
	p := &PollScheduler{}
	p._term_rlock = sync.Mutex{}
	p._terminated = threading.Event()
	p._terminated_tasks = false
	p._term_check_handle = nil
	p._max_jobs = 1
	p._max_load = 0
	p._scheduling = false
	p._background = false
	if event_loop != nil {
		p._event_loop = event_loop
	}else if main {
		p._event_loop = global_event_loop()
	}else {
		p._event_loop = asyncio._safe_loop()
	}
	p._sched_iface = NewSchedulerInterface(p._event_loop, p._is_background)
	return p
}

type UserQuery struct{
	myopts map[string]string
}

// nil, nil
func(u*UserQuery) query(prompt string, enterInvalid bool, responses []string, colours []func(string)string) string {
	if responses == nil {
		responses = []string{"Yes", "No"}
		colours = []func(string) string{
			NewCreateColorFunc("PROMPT_CHOICE_DEFAULT"),
			NewCreateColorFunc("PROMPT_CHOICE_OTHER"),
		}
	} else if colours == nil {
		colours = []func(string) string{Bold}
	}
	cs := []func(string) string{}
	for i := range responses {
		cs = append(cs, colours[i%len(colours)])
	}
	colours = cs
	if _, ok := u.myopts["--alert"]; ok {
		prompt = "\a" + prompt
	}
	print(Bold(prompt) + " ")
	for {
		rs := []string{}
		for i := range responses {
			rs = append(rs, colours[i](responses[i]))
		}
		ipt := fmt.Sprintf("[%s] ", strings.Join(rs, "/"))

		fmt.Print(ipt)
		response := ""
		_, err := fmt.Scanln(&response)
		if err != nil {
			//except (EOFError, KeyboardInterrupt):
			print("Interrupted.")
			syscall.Exit(128 + int(unix.SIGINT))
		}
		if len(response) > 0 || !enterInvalid {
			for _, key := range responses {
				if strings.ToUpper(response) == strings.ToUpper(key[:len(response)]) {
					return key
				}
			}
		}
		print(fmt.Sprintf("Sorry, response '%s' not understood.", response) + " ")
	}
	return ""
}

func NewUserQuery(myopts map[string]string)*UserQuery{
	u := &UserQuery{myopts:myopts}
	return u
}

type  SchedulerInterface struct {
	// slot
	add_reader         func(int, func() bool)
	add_writer         func()
	remove_reader      func(int)
	call_soon          func(func())
	create_future      func() IFuture
	run_until_complete func(IFuture)
	_is_background     func() bool
	is_running         func() bool
	call_at,
	call_exception_handler,
	call_later,
	call_soon_threadsafe,
	close,
	default_exception_handler,
	get_debug,
	is_closed,
	remove_writer,
	run_in_executor
	set_debug,
	time,
	_asyncio_child_watcher,
	_asyncio_wrapper
	_event_loop string
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

// nil
func NewSchedulerInterface(event_loop, is_background func()bool, **kwargs)*SchedulerInterface {
	s := &SchedulerInterface{}
	SlotObject.__init__(s, **kwargs)
	s._event_loop = event_loop
	if is_background == nil {
		is_background = s._return_false
	}
	s._is_background = is_background
	for kfilter_loglevels
	in
	s._event_loop_attrs {
		setattr(s, k, getattr(event_loop, k))
	}
	return s
}

func (s *SchedulerInterface) _return_false() bool{
	return false
}

// "", false, 0, -1
func (s *SchedulerInterface) output( msg , log_path string, background bool, level, noiselevel int) {

	global_background := s._is_background()
	if !background || global_background {
		background = global_background
	}

	msg_shown := false
	if !background {
		WriteMsgLevel(msg, level, noiselevel)
		msg_shown = true
	}

	if log_path != "" {
		f, err := os.OpenFile(log_path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
		if err != nil {
			//except IOError as e:
			if err != syscall.ENOENT && err != syscall.ESTALE {
				//raise
			}
			if !msg_shown {
				WriteMsgLevel(msg, level, noiselevel)
			}
		} else {
			if strings.HasSuffix(log_path, ".gz") {
				g := gzip.NewWriter(f)
				g.Write([]byte(msg))
			} else {
				f.Write([]byte(msg))
			}
			f.Close()
		}
	}
}

type AsyncTaskFuture struct {
	*AsynchronousTask
	// slot
	future IFuture
}

func (a* AsyncTaskFuture) _start() {
	a.future.add_done_callback(a._done_callback)
}

func (a* AsyncTaskFuture) _cancel() {
	if ! a.future.done() {
		a.future.cancel()
	}
}

func (a* AsyncTaskFuture) _done_callback(future IFuture, err error) {
	if future.cancelled() {
		a.cancelled = true
		i := -int(unix.SIGINT)
		a.returncode = &i
	} else if future.exception() == nil {
		i := 0
		a.returncode = &i
	} else {
		i := 1
		a.returncode = &i
	}
	a._async_wait()
}

func NewAsyncTaskFuture(future IFuture)*AsyncTaskFuture{
	a := &AsyncTaskFuture{}
	a.AsynchronousTask = NewAsynchronousTask()
	a.future = future
	return a
}

func getloadavg() (float64,float64,float64,error) {
	f, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	loadavg_str := strings.Split(string(f), "\n")[0]
	loadavg_split := strings.Fields(loadavg_str)
	if len(loadavg_split) < 3 {
		//raise OSError('unknown')
		return 0, 0, 0, errors.New("unknown")
	}
	f0, err := strconv.ParseFloat(loadavg_split[0], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	f1, err := strconv.ParseFloat(loadavg_split[1], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	f2, err := strconv.ParseFloat(loadavg_split[2], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	return f0, f1, f2, nil
}

type AsyncScheduler struct {
	*AsynchronousTask
	*PollScheduler
	_remaining_tasks bool
	_running_tasks map[]bool
	_error_count     int
}

// 0, 0
func NewAsyncScheduler(max_jobs int, max_load float64, event_loop) *AsyncScheduler {
	a := &AsyncScheduler{}
	a.AsynchronousTask = NewAsynchronousTask()
	a.PollScheduler = NewPollScheduler(false, event_loop)
	if max_jobs == 0 {
		max_jobs = 1
	}
	a._max_jobs = max_jobs
	if max_load != 0 {
		a._max_load = 0
	} else {
		a._max_load = max_load
	}
	a._error_count = 0
	a._running_tasks = map[]bool{}
	a._remaining_tasks = true
	a._loadavg_check_id = nil
	return a
}

func(a*AsyncScheduler) scheduler() {
	return a._event_loop
}

func(a*AsyncScheduler) _poll() *int {
	if !(a._is_work_scheduled() || a._keep_scheduling()){
		if a._error_count > 0 {
			i := 1
			a.returncode = &i
		} else {
			i := 0
			a.returncode = &i
		}
		a._async_wait()
	}
	return a.returncode
}

func(a*AsyncScheduler) _cancel() {
	a._terminated.set()
	a._termination_check(false)
}

func(a*AsyncScheduler) _terminate_tasks() {
	for task := range a._running_tasks {
		task.cancel()
	}
}

func(a*AsyncScheduler) _next_task() {
	raise
	NotImplementedError(a)
}

func(a*AsyncScheduler) _keep_scheduling() bool {
	return a._remaining_tasks&&!a._terminated.is_set()
}

func(a*AsyncScheduler) _running_job_count() int {
	return len(a._running_tasks)
}

func(a*AsyncScheduler) _schedule_tasks() {
	for a._keep_scheduling() && a._can_add_job() {
	try:
		task := a._next_task()
		except
	StopIteration:
		a._remaining_tasks = false
		else:
		a._running_tasks.add(task)
		task.scheduler = a._sched_iface
		task.addExitListener(a._task_exit)
		task.start()
	}

	if a._loadavg_check_id != nil {
		a._loadavg_check_id.cancel()
		a._loadavg_check_id = a._event_loop.call_later(
			a._loadavg_latency, a._schedule)
	}
	a.poll()
}

func(a*AsyncScheduler) _task_exit( task) {
	delete(a._running_tasks, task)
	if task.returncode != 0 {
		a._error_count += 1
	}
	a._schedule()
}

func(a*AsyncScheduler) _start() {
	if a._max_load != nil && a._loadavg_latency != nil &&
		(a._max_jobs != 0 || a._max_jobs > 1) {
		a._loadavg_check_id = a._event_loop.call_later(
			a._loadavg_latency, a._schedule)
	}
	a._schedule()
}

func(a*AsyncScheduler) _cleanup() {
	a.PollScheduler._cleanup()
	if a._loadavg_check_id != nil {
		a._loadavg_check_id.cancel()
		a._loadavg_check_id = nil
	}
}

func(a*AsyncScheduler) _async_wait() {
	a._cleanup()
	a.AsynchronousTask._async_wait()
}

type FileDigester struct {
	*ForkProcess

	// slot
	hash_names []string
	file_path string
	digests map[string]string
	_digest_pw int
	_digest_pipe_reader *PipeReader
}

func (f*FileDigester) _start() {
	p2 := make([]int, 2)
	syscall.Pipe(p2)
	pr, pw := p2[0], p2[1]
	f.fd_pipes = map[int]int{}
	f.fd_pipes[pw] = pw
	f._digest_pw = pw
	f._digest_pipe_reader = NewPipeReader(map[string]int {"input": pr}, f.scheduler)
	f._digest_pipe_reader.addExitListener(f._digest_pipe_reader_exit)
	f._digest_pipe_reader.start()
	f.ForkProcess._start()
	syscall.Close(pw)
}

func (f*FileDigester) _run() int {
	digests := performMultipleChecksums(f.file_path, f.hash_names, false)

	bs := []string{}
	for k,v := range digests {
		bs =append(bs, fmt.Sprintf("%s=%s\n", k,string(v)))
	}
	buf := strings.Join(bs, "")

	for len(buf) > 0 {
		n, _ :=syscall.Write(f._digest_pw, []byte(buf))
		buf = buf[n:]
	}

	return 0
}

func (f*FileDigester) _parse_digests( data) {
	digests :=map[string]string{}
	for line
		in
	data.decode("utf_8").splitlines() {
		parts := line.split("=", 1)
		if len(parts) == 2 {
			digests[parts[0]] = parts[1]
		}
	}

	f.digests = digests
}

func (f*FileDigester)_async_waitpid(){
	if f._digest_pipe_reader == nil {
		f.ForkProcess._async_waitpid()
	}
}

func (f*FileDigester) _digest_pipe_reader_exit( pipe_reader) {
	f._parse_digests(pipe_reader.getvalue())
	f._digest_pipe_reader = nil
	if f.pid ==nil {
		f._unregister()
		f._async_wait()
	}else {
		f._async_waitpid()
	}
}

func (f*FileDigester) _unregister() {
	f.ForkProcess._unregister()

	pipe_reader := f._digest_pipe_reader
	if pipe_reader != nil {
		f._digest_pipe_reader = nil
		pipe_reader.removeExitListener(f._digest_pipe_reader_exit)
		pipe_reader.cancel()
	}
}

func NewFileDigester(file_path string, hash_names []string, background bool, logfile string, scheduler *SchedulerInterface) *FileDigester {
	f := &FileDigester{}
	f.file_path = file_path
	f.hash_names = hash_names
	f.background = background
	f.logfile = logfile
	f.scheduler = scheduler
	return f
}


type AsyncFunction struct{
	*ForkProcess

	// slot
	_async_func_reader *PipeReader
	_async_func_reader_pw int
	fun func() interface{}
	result interface{}
}

func (a*AsyncFunction) _start() {
	p2 := make([]int, 2)
	syscall.Pipe(p2)
	pr, pw := p2[0], p2[1]
	if a.fd_pipes ==nil{
		a.fd_pipes =map[int]int{}
	}
	a.fd_pipes[pw] = pw
	a._async_func_reader_pw = pw
	a._async_func_reader = NewPipeReader(map[string] int{"input": pr},  a.scheduler)
	a._async_func_reader.addExitListener(a._async_func_reader_exit)
	a._async_func_reader.start()
	a.ForkProcess._start()
	syscall.Close(pw)
}

func (a*AsyncFunction) _run() int {
//try:
	result := a.fun()
	ogórek.NewEncoder(os.NewFile(uintptr(a._async_func_reader_pw), "")).Encode(result)
	//except Exception:
	//traceback.print_exc()
	//return 1

	return 0
}

func (a*AsyncFunction) _async_waitpid() {
	if a._async_func_reader ==nil {
		a.ForkProcess._async_waitpid()
	}
}

func (a*AsyncFunction)_async_func_reader_exit( pipe_reader io.Reader){
//try:
	a.result, _ = ogórek.NewDecoder(pipe_reader).Decode()
	//except Exception:
	//pass
	a._async_func_reader = nil
	if a.returncode ==nil {
		a._async_waitpid()
	}else {
		a._unregister()
		a._async_wait()
	}
}

func (a*AsyncFunction) _unregister() {
	a.ForkProcess._unregister()

	pipe_reader := a._async_func_reader
	if pipe_reader != nil {
		a._async_func_reader = nil
		pipe_reader.removeExitListener(a._async_func_reader_exit)
		pipe_reader.cancel()
	}
}

func NewAsyncFunction(fun func() interface{})*AsyncFunction{
	a:=&AsyncFunction{}
	a.fun = fun
	return a
}
