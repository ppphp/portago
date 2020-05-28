package atom

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func FindBinary(binary string) string {
	paths := strings.Split(os.Getenv("PATH"), ":")
	for _, p := range paths {
		fname := path.Join(p, binary)
		s, _ := os.Stat(fname)
		if (s.Mode()&unix.X_OK != 0) && (!s.IsDir()) {
			return fname
		}
	}
	return ""
}

var max_fd_limit uint64

func init() {
	var rLimit syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	max_fd_limit = rLimit.Max
}

var _fd_dir string
var get_open_fds func() []int

const _FD_CLOEXEC = syscall.FD_CLOEXEC

func init() {
	for _, f := range []string{"/proc/self/fd", "/dev/fd"} {
		st, _ := os.Stat(f)
		if st.IsDir() {
			_fd_dir = f
		} else {
			_fd_dir = ""
		}
	}
	if runtime.GOOS == "FreeBSD" && _fd_dir == "/dev/fd" {
		_fd_dir = ""
	}
	if _fd_dir != "" {
		get_open_fds = func() []int {
			m, _ := filepath.Glob(_fd_dir + "/*")
			r := []int{}
			for _, fd := range m {
				i, err := strconv.Atoi(fd)
				if err != nil {
					r = append(r, i)
				}
			}
			return r
		}
	} else if st, _ := os.Stat(fmt.Sprintf("/proc/%v/fd", os.Getpid())); st.IsDir() {
		get_open_fds = func() []int {
			m, _ := filepath.Glob(fmt.Sprintf("/proc/%v/fd/*", os.Getpid()))
			r := []int{}
			for _, fd := range m {
				i, err := strconv.Atoi(fd)
				if err != nil {
					r = append(r, i)
				}
			}
			return r
		}
	} else {
		get_open_fds = func() []int {
			r := []int{}
			for i := 0; i < int(max_fd_limit); i++ {
				r = append(r, i)
			}
			return r
		}
	}
}

var sandbox_capable, fakeroot_capable bool

func init() {
	sts, err := os.Stat(SandboxBinary)
	sandbox_capable = err != nil && sts != nil && !sts.IsDir() && sts.Mode()&syscall.O_EXCL != 0
	stf, err := os.Stat(FakerootBinary)
	sandbox_capable = err != nil && stf != nil && !stf.IsDir() && stf.Mode()&syscall.O_EXCL != 0
}

func SanitizeFds() { // all file descriptors in golang are not inheritable without explicit mentioned
	return
}

var _exithandlers []func()

func atexit_register(f func()) {
	_exithandlers = append(_exithandlers, f)
}

func run_exitfuncs() {
	for len(_exithandlers) != 0 {
		f := _exithandlers[len(_exithandlers)-1]
		_exithandlers = _exithandlers[:len(_exithandlers)-1]
		f()
		//except SystemExit:
		//exc_info = sys.exc_info()
		//except: # No idea what they called, so we need this broad except here.
		//		dump_traceback("Error in portage.process.run_exitfuncs", noiselevel=0)
		//	exc_info = sys.exc_info()
	}
}

func init() {
	//atexit_register(run_exitfuncs)
}

// nil, "", nil, false, 0, 0, nil, 0, "", "", true, nil, false, false, false, false, false, ""
func spawn(mycommand []string, env map[string]string, opt_name string, fd_pipes map[int]uintptr, returnpid bool,
	uid, gid int, groups []int, umask int, cwd, logfile string, path_lookup bool, pre_exec func(),
	close_fds, unshare_net, unshare_ipc, unshare_mount, unshare_pid bool, cgroup string) ([]int, error) {
	if env == nil {
		env = ExpandEnv()
	}
	binary := mycommand[0]
	stb, err := os.Stat(binary)
	if binary != BashBinary && binary != SandboxBinary && binary != FakerootBinary && err != nil && (!filepath.IsAbs(binary) || stb.IsDir()) || stb.Mode()&syscall.O_EXCL == 0 {
		if path_lookup {
			binary = FindBinary(binary)
		} else {
			return nil, errors.New("CommandNotFound(mycommand[0])")
		}
	}

	if fd_pipes == nil {
		fd_pipes = map[int]uintptr{
			0: getStdin().Fd(),
			1: os.Stdout.Fd(),
			2: os.Stderr.Fd(),
		}
	}
	mypids := []int{}
	var pr, pw *os.File
	if logfile != "" {
		if _, ok := fd_pipes[1]; !ok {
			return nil, errors.New("ValueError(fd_pipes)")
		}
		if _, ok := fd_pipes[2]; !ok {
			return nil, errors.New("ValueError(fd_pipes)")
		}
		pr, pw, _ = os.Pipe()
		s, _ := spawn([]string{"tee", "-i", "-a", logfile}, nil, "", map[int]uintptr{0: pr.Fd(), 1: fd_pipes[1], 2: fd_pipes[2]}, true, 0, 0, nil, 0, "", "", true, nil, false, false, false, false, false, "")
		mypids = append(mypids, s...)
		pr.Close()
		fd_pipes[1] = pw.Fd()
		fd_pipes[2] = pw.Fd()
	}
	unshare_flags := 0
	if unshare_net || unshare_ipc || unshare_mount || unshare_pid {
		CLONE_NEWNS := 0x00020000
		CLONE_NEWIPC := 0x08000000
		CLONE_NEWPID := 0x20000000
		CLONE_NEWNET := 0x40000000
		if unshare_net {
			unshare_flags |= CLONE_NEWNET
		}
		if unshare_ipc {
			unshare_flags |= CLONE_NEWIPC
		}
		if unshare_mount {
			unshare_flags |= CLONE_NEWNS
		}
		if unshare_pid {
			unshare_flags |= CLONE_NEWPID | CLONE_NEWNS
		}

		_unshare_validate.call(unshare_flags)
	}

	pid, err := syscall.ForkExec(binary, mycommand, &syscall.ProcAttr{
		Dir:   cwd,
		Env:   os.Environ(),
		Files: nil,
		Sys:   &syscall.SysProcAttr{},
	})
	mypids = append(mypids, pid)

	if logfile != "" {
		syscall.Close(int(pw.Fd()))
	}
	if returnpid {
		return mypids, nil
	}
	for len(mypids) > 0 {
		pid := mypids[len(mypids)-1]
		mypids = mypids[:len(mypids)-1]
		retval, err := syscall.Wait4(pid, nil, 0, nil)
		if err == nil && retval != 0 {
			for _, pid := range mypids {
				if i, err := syscall.Wait4(pid, nil, syscall.WNOHANG, nil); err != nil || i == 0 {
					syscall.Kill(pid, syscall.SIGTERM)
					syscall.Wait4(pid, nil, 0, nil)
				}
			}
			if retval&0xff != 0 {
				return []int{retval & 0xff << 8}, nil
			}
			return []int{retval >> 8}, nil
		}
	}

	return []int{0}, nil
}

// i cannot do this right
//func _exec(binary string, mycommand []string, opt_name string, fd_pipes map[uintptr]uintptr,
//	env map[string]string, gid int, groups []int, uid, umask int, cwd string,
//	pre_exec func(), close_fds []uintptr, unshare_net, unshare_ipc, unshare_mount, unshare_pid bool,
//	unshare_flags int, cgroup string){
//	if opt_name==""{
//		opt_name = path.Base(binary)
//	}
//
//	myargs := []string{opt_name}
//	myargs = append(myargs, mycommand[1:]...)
//	_setup_pipes(fd_pipes, close_fds)
//	if cgroup!=""{
//		if f, err := os.OpenFile(path.Join(cgroup, "cgroup.procs"), syscall.O_APPEND|syscall.O_CREAT|syscall.O_WRONLY, 0777); err== nil {
//			f.Write([]byte(fmt.Sprintf("%v", os.Getpid())))
//			f.Close()
//		}
//		if unshare_net||unshare_ipc||unshare_mount||unshare_pid{
//			errnoValue := _unshare_validate.call(unshare_flags)
//			if err := syscall.Unshare(unshare_flags);errnoValue ==0 &&err!=nil{
//				e, _ := err.(syscall.Errno)
//				errnoValue = int(e)
//			}
//			if errnoValue !=0{
//				WriteMsg(fmt.Sprintf("Unable to unshare: %s\n" , errnoValue), -1, nil)
//			} else {
//				if unshare_pid {
//					var gs,fps []string
//					for _, g := range groups{
//						gs = append(gs, fmt.Sprintf("%v",g))
//					}
//					for f := range fd_pipes{
//						fps = append(fps, fmt.Sprintf("%v",f))
//					}
//					binary, myargs := "python", append([]string{"python", path.Join(PORTAGE_BIN_PATH, "pid-ns-init"), string(uid),string(gid),strings.Join(gs, ","),string(umask), strings.Join(fps,","),binary },myargs...)
//					uid = 0
//					gid = 0
//					groups=nil
//					umask=0
//
//					binary:="python"
//					myargs:= []string{"python", path.Join(PORTAGE_BIN_PATH, "pid-ns-init")}
//				}
//			}
//		}
//	}
//}

type _unshare_validator struct {
	results map[int]int
}

func (u *_unshare_validator) call(flags int) int {
	if v, ok := u.results[flags]; ok {
		return v
	} else {
		v := u.validate(flags)
		u.results[flags] = v
		return v
	}
}

func (u *_unshare_validator) validate(flags int) int {
	return 0
}

//func (u *_unshare_validator) _run_subproc(subproc_pipe, target, args=(), kwargs={}){
//
//}

//func (u *_unshare_validator) _validate_subproc(unshare, flags){
//
//}

func NewUnshareValidator() *_unshare_validator {
	return &_unshare_validator{results: map[int]int{}}
}

var _unshare_validate = NewUnshareValidator()

// true
func _setup_pipes(fd_pipes map[uintptr]uintptr, close_fds bool) {
	reverseMap := map[uintptr][]uintptr{}
	for newFd, oldFd := range fd_pipes {
		if e, ok := reverseMap[oldFd]; !ok || e == nil {
			reverseMap[oldFd] = []uintptr{}
		}
		reverseMap[oldFd] = append(reverseMap[oldFd], newFd)
	}
	for len(reverseMap) > 0 {
		var oldFd uintptr
		var newFds []uintptr
		for oldFd, newFds = range reverseMap {
			break
		}
		delete(reverseMap, oldFd)
		for _, newFd := range newFds {
			if _, ok := reverseMap[newFd]; ok {
				backupFd, _ := syscall.Dup(int(newFd))
				reverseMap[uintptr(backupFd)] = reverseMap[newFd]
				delete(reverseMap, newFd)
			}
			if oldFd != newFd {
				syscall.Dup2(int(oldFd), int(newFd))
			}
		}
		if _, ok := fd_pipes[oldFd]; !ok {
			//syscall.Fsync(oldFd)//os.close(oldfd)
		}
	}

	if close_fds {
		for _, fd := range get_open_fds() {
			if _, ok := fd_pipes[uintptr(fd)]; !ok {
				//os.close(fd) // os.Fsync
			}
		}
	}
}
