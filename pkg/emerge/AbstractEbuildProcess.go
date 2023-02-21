package emerge

import (
	"bytes"
	"fmt"
	"github.com/ppphp/portago/pkg/data"
	ebuild2 "github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/elog"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util/permissions"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

type AbstractEbuildProcess struct {
	*SpawnProcess
	// slot
	settings *config.Config
	_exit_command *ebuild2.ExitCommand
	phase, _exit_timeout_id string
	_start_future, _build_dir_unlock IFuture
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
		a._eerror(myutil.SplitSubN(msg, 72))
		i := 1
		a.returncode = &i
		a._async_wait()
		return
	}

	if os.Geteuid() == 0 && runtime.GOOS == "linux" && a.settings.Features.Features["cgroup"] && ! atom._global_pid_phases[a.phase] {
		cgroup_root := "/sys/fs/cgroup"
		cgroup_portage := filepath.Join(cgroup_root, "portage")

		mp, err := myutil.Mountpoint(cgroup_root)
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
			mp, err1 := myutil.Mountpoint(cgroup_portage)
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
		if !myutil.Ins(a._phases_without_builddir, a.phase) {
			start_ipc_daemon = true
			if _, ok := a.settings.ValueDict["PORTAGE_BUILDDIR_LOCKED"]; !ok {
				a._build_dir = NewEbuildBuildDir(a.scheduler, a.settings)
				a._start_future = a._build_dir.async_lock()
				a._start_future.add_done_callback(
					func (lock_future IFuture, err error) {
						return a._start_post_builddir_lock(lock_future, start_ipc_daemon)
					})
				return
			}
		} else {
			delete(a.settings.ValueDict, "PORTAGE_IPC_DAEMON")
		}
	} else {
		delete(a.settings.ValueDict, "PORTAGE_IPC_DAEMON")
		if myutil.Ins(a._phases_without_builddir, a.phase) {
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
func (a *AbstractEbuildProcess)_start_post_builddir_lock( lock_future IFuture, start_ipc_daemon bool) {
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
		!myutil.Ins(a._phases_interactive_whitelist, a.phase) &&
		!myutil.Ins(strings.Fields(a.settings.ValueDict["PROPERTIES"]), "interactive") {
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
		permissions.Apply_secpass_permissions(p, uint32(os.Getuid()), *data.Portage_gid, 0770, -1, st, true)
	}

	return input_fifo, output_fifo
}

func (a *AbstractEbuildProcess)_start_ipc_daemon() {
	a._exit_command = ebuild2.NewExitCommand()
	a._exit_command.Reply_hook = a._exit_command_callback
	query_command := ebuild2.NewQueryCommand(a.settings, a.phase)
	commands := map[string]interface{Call(argv []string) (string, string, int)}{
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

	a._eerror(myutil.SplitSubN(msg, 72))
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
	return !(a.settings.Features.Features["sesandbox"] && *a.settings.Selinux_enabled()) || terminal.IsTerminal(slave_fd)
}

func (a *AbstractEbuildProcess)_killed_by_signal( signum int) {
	msg := fmt.Sprintf("The ebuild phase '%s' has been killed by signal %s.", a.phase, signum)
	a._eerror(myutil.SplitSubN(msg, 72))
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

	a._eerror(myutil.SplitSubN(msg, 72))
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
		elog_func = elog.Eerror
	}

	global_havecolor := output.HaveColor
	//try{
	nc, ok := a.settings.ValueDict["NOCOLOR"]
	if !ok {
		output.HaveColor = 1
	} else if strings.ToLower(nc) == "no" || strings.ToLower(nc) == "false" {
		output.HaveColor = 0
	}
	for _, line := range lines {
		elog_func(line, phase, a.settings.mycpv.string, out)
	}
	//finally{
	output.HaveColor = global_havecolor
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
	a._build_dir_unlock.add_done_callback( func(t IFuture, err error) {
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

func NewAbstractEbuildProcess(actionmap ebuild2.Actionmap, background bool, fd_pipes map[int]int, logfile, phase string, scheduler *SchedulerInterface, settings *config.Config, **kwargs)*AbstractEbuildProcess {
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
