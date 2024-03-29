package locks

import (
	"fmt"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util/msg"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	HARDLINK_FD            = -2
	_HARDLINK_POLL_LATENCY = 3
)

var (
	quiet                         = false
	_lock_fn func(int, int) error = nil
)

func _get_lock_fn() func(int, int) error {
	if _lock_fn != nil {
		return _lock_fn
	}
	_test_lock := func(fd int, lock_path string) int {
		syscall.Close(fd)
		f, _ := os.OpenFile(lock_path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0777)
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return 0
		} else {
			return 1
		}
	}
	lock_path, _ := ioutil.TempDir("/tmp/", "lock")
	f, _ := os.Open(lock_path)
	fd := f.Fd()

	if err := syscall.Flock(int(fd), syscall.LOCK_EX); err != nil {
	} else {
		excode := 0
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() { excode = _test_lock(int(fd), lock_path); wg.Done() }()
		wg.Wait()
		if excode == 0 {
			_lock_fn = syscall.Flock
			return _lock_fn
		}
	}
	syscall.Close(int(fd))
	syscall.Unlink(lock_path)

	_lock_fn = syscall.Flock
	return _lock_fn
}

var _open_fds = map[int]bool{}

func _close_fds() {
	for len(_open_fds) > 0 {
		for fd := range _open_fds {
			delete(_open_fds, fd)
			syscall.Close(fd)
			break
		}
	}
}

func Lockdir(mydir string, flags int) (*LockFileS, error) { // 0
	return Lockfile(mydir, true, false, "", flags)
}

func Unlockdir(mylock *LockFileS) bool {
	return Unlockfile(mylock)
}

type LockFileS struct {
	string
	int
	bool
	f func(int, int) error
}

// false, false, "", 0
func Lockfile(mypath string, wantnewlockfile, unlinkfile bool, waiting_msg string, flags int) (*LockFileS, error) {
	l := &LockFileS{}
	var e error = nil
	for l.string == "" {
		l, e = _lockfile_iteration(mypath, wantnewlockfile, unlinkfile, waiting_msg, flags)
		if e != nil {
			return l, e
		}
		if l.string == "" {
			msg.WriteMsg("lockfile removed by previous lock holder, retrying\n", 1, nil)
		}
	}
	return l, e
}

func _lockfile_iteration(mypath string, wantnewlockfile, unlinkfile bool, waiting_msg string, flags int) (*LockFileS, error) { // false, false, "", 0
	if mypath == "" {

	}
	gid := *data.Portage_gid
	if mypath[len(mypath)-1] == '/' {
		mypath = mypath[:len(mypath)-1]
	}
	lockfilename_path := mypath
	lockfilename := ""
	if wantnewlockfile {
		base, tail := path.Split(mypath)
		lockfilename = path.Join(base, "."+tail+".portage_lockfile")
		lockfilename_path = lockfilename
		unlinkfile = true
	} else {
		lockfilename = mypath
	}
	if st, err := os.Stat(path.Dir(mypath)); err != nil || !st.IsDir() {
	}
	lfn, err := os.Stat(lockfilename)
	preexisting := err != nil
	old_mask := syscall.Umask(000)
	var myfd int
	for {
		fd, err := os.OpenFile(lockfilename, os.O_CREATE|os.O_RDWR, 0660)
		myfd = int(fd.Fd())
		if (err == syscall.ENONET || err == syscall.ESTALE) && lfn.IsDir() {
			//_raise_exc(err)
		} else {
			break
		}
	}

	if !preexisting {
		if st, err := os.Stat(lockfilename); *data.Secpass >= 1 && err == nil && st.Sys() != data.Portage_gid {

		}
		if err := syscall.Chown(lockfilename, -1, int(gid)); err != nil {
			if err == syscall.ENONET || err == syscall.ESTALE {
				return Lockfile(mypath, wantnewlockfile, unlinkfile, waiting_msg, flags)
			} else {
				msg.WriteMsg(fmt.Sprintf("%s: chown('%s', -1, %d)\n", err, lockfilename, gid), -1, nil)
				msg.WriteMsg(fmt.Sprintf("Cannot chown a lockfile: '%s'\n", lockfilename), -1, nil)
				s, _ := os.Getgroups()
				p := []string{}
				for _, v := range s {
					p = append(p, string(v))
				}
				msg.WriteMsg(fmt.Sprintf("Group IDs of current user: %s\n", strings.Join(p, " ")), -1, nil)
			}
		}
	}
	syscall.Umask(old_mask)
	locking_method := func(a, b int) error {
		for {
			if err := _get_lock_fn()(a, b); err != nil {
				if err != syscall.EINTR {
					return err
				}
				continue
			}
			break
		}
		return nil
	}
	if _, ok := os.LookupEnv("__PORTAGE_TEST_HARDLINK_LOCKS"); ok {
		return nil, syscall.ENOSYS //, "Function not implemented")
	}
	var out *output.EOutput = nil
	if err := locking_method(myfd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if err == syscall.EACCES || err == syscall.EAGAIN || err == syscall.ENOLCK {
			if flags&syscall.O_NONBLOCK != 0 {
				syscall.Close(myfd)
				//raise TryAgain(mypath)
			}
			var out *output.EOutput = nil
			if quiet {
				out = nil
			} else {
				out = output.NewEOutput(false)
			}
			if waiting_msg == "" {
				waiting_msg = fmt.Sprintf("waiting for lock on %s", lockfilename)
			}
			out.Ebegin(waiting_msg)
			enolock_msg_shown := false
			for {
				if err := locking_method(myfd, syscall.LOCK_EX); err != nil {
					if err == syscall.ENOLCK {
						if !enolock_msg_shown {
							enolock_msg_shown = true
							context_desc := fmt.Sprintf("Error while waiting to lock '%s'", lockfilename)
							msg.WriteMsg(fmt.Sprintf("\n!!! %s: %s\n", context_desc, err), -1, nil)
						}
						time.Sleep(_HARDLINK_POLL_LATENCY * time.Second)
						continue
					}
					if out != nil {
						out.Eend(1, err.Error())
					}
					//raise
				} else {
					break
				}
			}
		}

		if out != nil {
			out.Eend(syscall.F_OK, "")
		}
	} else if err == syscall.ENOSYS {
		syscall.Close(myfd)
		link_success := hardlink_lockfile(lockfilename_path, waiting_msg, flags)
		if !link_success {
			return nil, err
		}
		lockfilename = lockfilename_path
		locking_method = nil
		myfd = HARDLINK_FD
	} else {
		return nil, err
	}

	if myfd != HARDLINK_FD && unlinkfile {
		removed := _lockfile_was_removed(myfd, lockfilename)
		syscall.Close(myfd)
		//raise

		if removed {
			syscall.Close(myfd)
			return nil, nil
		}
	}
	if myfd != HARDLINK_FD {
		i, _ := unix.FcntlInt(uintptr(myfd), syscall.F_GETFD, 0)

		unix.FcntlInt(uintptr(myfd), syscall.F_SETFD, i|syscall.FD_CLOEXEC)
	}

	_open_fds[myfd] = true

	msg.WriteMsg(fmt.Sprintf("%v%v%v\n", lockfilename, myfd, unlinkfile), 1, nil)
	return &LockFileS{lockfilename, myfd, unlinkfile, locking_method}, nil
}

func _lockfile_was_removed(lock_fd int, lock_path string) bool {
	var fstat_st *syscall.Stat_t
	if err := syscall.Fstat(lock_fd, fstat_st); err != nil {
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//_raise_exc(e)
		}
		return true
	}

	hardlink_path := hardlock_name(lock_path)
	if err := syscall.Unlink(hardlink_path); err != nil {
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//_raise_exc(e)
		}
	}
	if err := syscall.Link(lock_path, hardlink_path); err != nil {
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//_raise_exc(e)
		}
		return true
	}

	var hardlink_stat *syscall.Stat_t
	if err := syscall.Stat(hardlink_path, hardlink_stat); err != nil {
		if err := syscall.Unlink(hardlink_path); err != nil {
			if err != syscall.ENOENT && err != syscall.ESTALE {
				//_raise_exc(e)
			}
		}
		return false
	}
	if hardlink_stat.Ino != fstat_st.Ino || hardlink_stat.Dev != fstat_st.Dev {
		inode_test := hardlink_path + "-inode-test"
		if err := syscall.Unlink(inode_test); err != nil {
			if err != syscall.ENOENT && err != syscall.ESTALE {
				//_raise_exc(e)
			}
		}
		if err := syscall.Link(hardlink_path, inode_test); err != nil {
			if err != syscall.ENOENT && err != syscall.ESTALE {
				//_raise_exc(e)
			}
		} else {
			f1, e1 := filepath.EvalSymlinks(hardlink_path)
			f2, e2 := filepath.EvalSymlinks(inode_test)
			if (e1 != nil && e2 != nil) || (f1 == f2) {
				_, err := os.Stat(lock_path)
				return os.IsNotExist(err)
			}
		}
		if err := syscall.Unlink(inode_test); err != nil {
			if err != syscall.ENOENT && err != syscall.ESTALE {
				//_raise_exc(e)
			}
		}
		return true
	}
	if err := syscall.Unlink(hardlink_path); err != nil {
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//_raise_exc(e)
		}
	}
	return false
}

func _fstat_nlink(fd int) (int, error) {
	var st_nlink *syscall.Stat_t
	if err := syscall.Fstat(fd, st_nlink); err != nil {
		if err == syscall.ENOENT || err == syscall.ESTALE {
			return 0, nil
		}
		return 0, err
	} else {
		return int(st_nlink.Nlink), nil
	}
}

func Unlockfile(s *LockFileS) bool {
	lockfilename := s.string
	myfd := s.int
	unlinkfile := s.bool
	locking_method := s.f
	if myfd == HARDLINK_FD {
		unhardlink_lockfile(lockfilename, unlinkfile)
		return true
	}

	if _, err := os.Stat(lockfilename); err != nil {
		msg.WriteMsg(fmt.Sprintf("lockfile does not exist '%s'\n", lockfilename), 1, nil)
		if myfd != 0 {
			syscall.Close(myfd)
			delete(_open_fds, myfd)
		}
		return false
	}

	var err error = nil
	if myfd == 0 {
		myfd, err = syscall.Open(lockfilename, os.O_WRONLY, 0660)
		if err == nil {
			unlinkfile = true
		}
	}
	if err == nil {
		err = locking_method(myfd, syscall.LOCK_UN)
	}
	if err != nil {
		syscall.Close(myfd)
		delete(_open_fds, myfd)
		//raise IOError(_("Failed to unlock file '%s'\n") % lockfilename)

	}
	if unlinkfile {
		if err := locking_method(myfd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			msg.WriteMsg("Failed to get lock... someone took it.\n", 1, nil)
			msg.WriteMsg(err.Error()+"\n", 1, nil)
		}
		msg.WriteMsg("Got the lockfile...\n", 1, nil)
		n, err := _fstat_nlink(myfd)
		if err != nil {
			msg.WriteMsg("Failed to get lock... someone took it.\n", 1, nil)
			msg.WriteMsg(err.Error()+"\n", 1, nil)
		}
		if n == 1 {
			if err := syscall.Unlink(lockfilename); err != nil {
				msg.WriteMsg("Failed to get lock... someone took it.\n", 1, nil)
				msg.WriteMsg(err.Error()+"\n", 1, nil)
			}
			msg.WriteMsg("Unlinked lockfile...\n", 1, nil)
			if err := locking_method(myfd, syscall.LOCK_UN); err != nil {
				msg.WriteMsg("Failed to get lock... someone took it.\n", 1, nil)
				msg.WriteMsg(err.Error()+"\n", 1, nil)
			}
		} else {
			msg.WriteMsg(fmt.Sprintf("lockfile does not exist '%s'\n", lockfilename), 1, nil)
			if err := syscall.Close(myfd); err != nil {
				msg.WriteMsg("Failed to get lock... someone took it.\n", 1, nil)
				msg.WriteMsg(err.Error()+"\n", 1, nil)
			}
			delete(_open_fds, myfd)
			return false
		}
	}
	syscall.Close(myfd)
	delete(_open_fds, myfd)
	return true
}

func hardlock_name(p string) string {
	base, tail := path.Split(p)
	var un *syscall.Utsname
	syscall.Uname(un)
	return path.Join(base, fmt.Sprintf(".%s.hardlock-%v-%v", tail, un.Nodename, os.Getpid()))
}

func hardlink_is_mine(link, lock string) bool {
	var lock_st *syscall.Stat_t
	if err := syscall.Stat(lock, lock_st); err != nil {
		return false
	}
	if lock_st.Nlink == 2 {
		var link_st *syscall.Stat_t
		syscall.Stat(link, link_st)
		return lock_st.Ino == link_st.Ino && lock_st.Dev == link_st.Dev
	}
	return false
}

func hardlink_lockfile(lockfilename string, waiting_msg string, flags int) bool { // "", 0

	var out *output.EOutput = nil
	displayed_waiting_msg := false
	preexisting := false
	if _, err := os.Stat(lockfilename); err != nil {
		preexisting = true
	}
	myhardlock := hardlock_name(lockfilename)

	gid := *data.Portage_gid

	if err := syscall.Unlink(myhardlock); err != nil {
		if err == syscall.ENOENT || err == syscall.ESTALE {
		} else {
			// raise
		}
	}

	for {
		myfd, err := syscall.Open(lockfilename, syscall.O_CREAT|os.O_RDWR, 0660)
		if err != nil {
			//func_call = "open('%s')" % lockfilename
			//if e.errno == OperationNotPermitted.errno:
			//raise OperationNotPermitted(func_call)
			//elif e.errno == PermissionDenied.errno:
			//raise PermissionDenied(func_call)
			//elif e.errno == ReadOnlyFileSystem.errno:
			//raise ReadOnlyFileSystem(func_call)
			//else:
			//raise
		} else {
			var myfd_st *syscall.Stat_t
			if err := syscall.Fstat(myfd, myfd_st); err != nil {
				if err != syscall.ENOENT && err != syscall.ESTALE {
					msg.WriteMsg(fmt.Sprintf("%s: fchown('%s', -1, %d)\n", err, lockfilename, data.Portage_gid), -1, nil)
					msg.WriteMsg(fmt.Sprintf("Cannot chown a lockfile: '%s'\n", lockfilename), -1, nil)
					n, _ := os.Getgroups()
					msg.WriteMsg(fmt.Sprintf("Group IDs of current user: %+v\n", n), -1, nil)
				} else {
					continue
				}
			} else if !preexisting {
				if *data.Secpass >= 1 && myfd_st.Gid != gid {
					if err := syscall.Fchown(myfd, -1, int(gid)); err != nil {
						if err != syscall.ENOENT && err != syscall.ESTALE {
							msg.WriteMsg(fmt.Sprintf("%s: fchown('%s', -1, %d)\n", err, lockfilename, data.Portage_gid), -1, nil)
							msg.WriteMsg(fmt.Sprintf("Cannot chown a lockfile: '%s'\n", lockfilename), -1, nil)
							n, _ := os.Getgroups()
							msg.WriteMsg(fmt.Sprintf("Group IDs of current user: %+v\n", n), -1, nil)
						} else {
							continue
						}
					}
				}
			}
			syscall.Close(myfd)

			if myfd_st != nil && myfd_st.Nlink < 2 {
				if err := syscall.Link(lockfilename, myhardlock); err != nil {
					//func_call = "link('%s', '%s')" % (lockfilename, myhardlock)
					//if e.errno == OperationNotPermitted.errno:
					//raise OperationNotPermitted(func_call)
					//elif e.errno == PermissionDenied.errno:
					//raise PermissionDenied(func_call)
					//elif e.errno in (errno.ESTALE, errno.ENOENT):
					continue
					//else:
					//raise
				} else {
					if hardlink_is_mine(myhardlock, lockfilename) {
						if out != nil {
							out.Eend(os.O_EXCL, "")
						}
						break
					}

					if err := syscall.Unlink(myhardlock); err != nil {
						if err != syscall.ENOENT && err != syscall.ESTALE {
							//raise
						}
					}
					//raise FileNotFound(myhardlock)
				}
			}
		}
	}
	if flags&syscall.O_NONBLOCK != 0 {
		//raise TryAgain(lockfilename)
	}

	if out == nil && !quiet {
		out = output.NewEOutput(false)
	}
	if out != nil && !displayed_waiting_msg {
		displayed_waiting_msg = true
		if waiting_msg == "" {
			waiting_msg = fmt.Sprintf("waiting for lock on %s\n", lockfilename)
		}
		out.Ebegin(waiting_msg)
	}
	time.Sleep(_HARDLINK_POLL_LATENCY)

	return true
}

func unhardlink_lockfile(lockfilename string, unlinkfile bool) { // true
	myhardlock := hardlock_name(lockfilename)
	if unlinkfile && hardlink_is_mine(myhardlock, lockfilename) {
		syscall.Unlink(lockfilename)
	}
	syscall.Unlink(myhardlock)
}

func hardlock_cleanup(path string, remove_all_locks bool) []string { // false
	var un *syscall.Utsname
	syscall.Uname(un)
	myhost := un.Nodename

	mydl, _ := filepath.Glob(path + "/*")

	results := []string{}
	mycount := 0

	mylist := map[string]map[string][]string{}
	for _, x := range mydl {
		if _, err := os.Stat(path + "/" + x); err != nil {
			parts := strings.Split(x, ".hardlock-")
			if len(parts) == 2 {
				filename := parts[0][1:]
				hostpid := strings.Split(parts[1], "-")
				host := strings.Join(hostpid[:len(hostpid)-1], "-")
				pid := hostpid[len(hostpid)-1]
				if _, ok := mylist[filename]; !ok {
					mylist[filename] = map[string][]string{}
				}
				if _, ok := mylist[filename][host]; !ok {
					mylist[filename][host] = []string{}
				}
				mylist[filename][host] = append(mylist[filename][host], pid)
				mycount += 1
			}
		}
	}
	results = append(results, fmt.Sprintf("Found %v locks", mycount))

	for x := range mylist {
		if _, ok := mylist[x][fmt.Sprintf("%v", myhost)]; ok || remove_all_locks {

		}
		mylockname := hardlock_name(path + "/" + x)
		if _, err := os.Stat(path + "/" + x); hardlink_is_mine(mylockname, path+"/"+x) || err != nil || remove_all_locks {
			for y := range mylist[x] {
				for _, z := range mylist[x][y] {
					filename := path + "/." + x + ".hardlock-" + y + "-" + z
					if filename == mylockname {
						continue
					}
					if err := syscall.Unlink(filename); err == nil {
						results = append(results, "Unlinked: "+filename)
					}
				}
				if err := syscall.Unlink(path + "/" + x); err == nil {
					results = append(results, "Unlinked: "+path+"/"+x)
					if err := syscall.Unlink(mylockname); err == nil {
						results = append(results, "Unlinked: "+mylockname)
					}
				}
			}
		} else {
			if err := syscall.Unlink(mylockname); err == nil {
				results = append(results, "Unlinked: "+mylockname)
			}
		}
	}

	return results
}
