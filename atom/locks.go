package atom

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
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

func lockdir(mydir string, flags int){ // 0
	return lockfile(mydir, true, false, "", flags)
}

func unlockdir(mylock){
	return unlockfile(mylock)
}

func lockfile(mypath string, wantnewlockfile, unlinkfile bool, waiting_msg string, flags int){ // false, false, "", 0
	lock = None
	while lock is None{
		lock = _lockfile_iteration(mypath, wantnewlockfile, unlinkfile, waiting_msg, flags)
		if lock is None{
			WriteMsg("lockfile removed by previous lock holder, retrying\n", 1, nil)
		}
	}
	return lock
}

func _lockfile_iteration(mypath string, wantnewlockfile, unlinkfile bool, waiting_msg string, flags int) { // false, false, "", 0
	if mypath == "" {

	}
	gid := *portage_gid
	if mypath[len(mypath)-1] == '/' {
		mypath = mypath[:len(mypath)-1]
	}
	lockfilename_path := mypath
	lockfilename := ""
	if wantnewlockfile{
		base, tail := path.Split(mypath)
		lockfilename = path.Join(base, "." + tail + ".portage_lockfile")
		lockfilename_path = lockfilename
		unlinkfile   = true
	} else{
		lockfilename = mypath
	}
	if st ,err := os.Stat(path.Dir(mypath)); err!= nil || !st.IsDir(){
	}
	lfn, err := os.Stat(lockfilename)
	preexisting := err!= nil
	old_mask := syscall.Umask(000)
	for{
		myfd, err := os.OpenFile(lockfilename, os.O_CREATE|os.O_RDWR, 0660)
		if (err == syscall.ENONET || err == syscall.ESTALE )&& lfn.IsDir() {
			//_raise_exc(err)
		} else {
			break
		}
	}

	if ! preexisting{
		if st, err :=os.Stat(lockfilename); *secpass >= 1 && err== nil &&st.Sys() != portage_gid{

		}
		if err := syscall.Chown(lockfilename, -1, gid); err != nil {
			if err == syscall.ENONET || err == syscall.ESTALE{
				return lockfile(mypath,
					wantnewlockfile=wantnewlockfile,
					unlinkfile=unlinkfile, waiting_msg=waiting_msg,
					flags=flags)
			} else {
				WriteMsg(fmt.Sprintf("%s: chown('%s', -1, %d)\n", err, lockfilename, gid), -1, nil)
				WriteMsg(fmt.Sprintf("Cannot chown a lockfile: '%s'\n", lockfilename),  -1, nil)
				s , _ := os.Getgroups()
				p := []string{}
				for _, v := range s {
					p =append(p, string(v))
				}
				WriteMsg(fmt.Sprintf("Group IDs of current user: %s\n", 		strings.Join(p,	" ")), -1, nil)
			}
		}
	}
	syscall.Umask(old_mask)
	locking_method = _eintr_func_wrapper(_get_lock_fn())
try:
	if "__PORTAGE_TEST_HARDLINK_LOCKS" in os.environ:
	raise IOError(errno.ENOSYS, "Function not implemented")
	locking_method(myfd, fcntl.LOCK_EX|fcntl.LOCK_NB)
	except IOError as e:
	if not hasattr(e, "errno"):
	raise
	if e.errno in (errno.EACCES, errno.EAGAIN, errno.ENOLCK):
	# resource temp unavailable; eg, someone beat us to the lock.
	if flags & os.O_NONBLOCK:
	os.close(myfd)
	raise TryAgain(mypath)

	global _quiet
	if _quiet:
	out = None
	else:
	out = portage.output.EOutput()
	if waiting_msg is None:
	if isinstance(mypath, int):
	waiting_msg = _("waiting for lock on fd %i") % myfd
	else:
	waiting_msg = _("waiting for lock on %s") % lockfilename
	if out is not None:
	out.ebegin(waiting_msg)
	# try for the exclusive lock now.
		enolock_msg_shown = False
	while True:
try:
	locking_method(myfd, fcntl.LOCK_EX)
	except EnvironmentError as e:
	if e.errno == errno.ENOLCK:
	# This is known to occur on Solaris NFS (see
	# bug #462694). Assume that the error is due
	# to temporary exhaustion of record locks,
	# and loop until one becomes available.
	if not enolock_msg_shown:
	enolock_msg_shown = True
	if isinstance(mypath, int):
	context_desc = _("Error while waiting "
	"to lock fd %i") % myfd
	else:
	context_desc = _("Error while waiting "
	"to lock '%s'") % lockfilename
	writemsg("\n!!! %s: %s\n" % (context_desc, e),
		noiselevel=-1)

	time.sleep(_HARDLINK_POLL_LATENCY)
	continue

	if out is not None:
	out.eend(1, str(e))
	raise
	else:
	break

	if out is not None:
	out.eend(os.EX_OK)
	elif e.errno in (errno.ENOSYS,):
	# We're not allowed to lock on this FS.
	if not isinstance(lockfilename, int):
	# If a file object was passed in, it's not safe
	# to close the file descriptor because it may
	# still be in use.
		os.close(myfd)
	lockfilename_path = _unicode_decode(lockfilename_path,
		encoding=_encodings['fs'], errors='strict')
	if not isinstance(lockfilename_path, basestring):
	raise
	link_success = hardlink_lockfile(lockfilename_path,
		waiting_msg=waiting_msg, flags=flags)
	if not link_success:
	raise
	lockfilename = lockfilename_path
	locking_method = None
	myfd = HARDLINK_FD
	else:
	raise


	if isinstance(lockfilename, basestring) and myfd != HARDLINK_FD and unlinkfile:
try:
	removed = _lockfile_was_removed(myfd, lockfilename)
	except Exception:
	# Do not leak the file descriptor here.
		os.close(myfd)
	raise
	else:
	if removed:
	# Removed by previous lock holder... Caller will retry...
	os.close(myfd)
	return None

	if myfd != HARDLINK_FD:

	# FD_CLOEXEC is enabled by default in Python >=3.4.
	if sys.hexversion < 0x3040000:
	try:
	fcntl.FD_CLOEXEC
	except AttributeError:
	pass
	else:
	fcntl.fcntl(myfd, fcntl.F_SETFD,
	fcntl.fcntl(myfd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)

	_open_fds.add(myfd)

	writemsg(str((lockfilename, myfd, unlinkfile)) + "\n", 1)
	return (lockfilename, myfd, unlinkfile, locking_method)
}

func _fstat_nlink(fd){
try:
	return os.fstat(fd).st_nlink
	except EnvironmentError as e:
	if e.errno in (errno.ENOENT, errno.ESTALE):
	# Some filesystems such as CIFS return
	# ENOENT which means st_nlink == 0.
	return 0
	raise
}

func unlockfile(mytuple){
	if len(mytuple) == 3:
	lockfilename, myfd, unlinkfile = mytuple
	locking_method = fcntl.flock
	elif len(mytuple) == 4:
	lockfilename, myfd, unlinkfile, locking_method = mytuple
	else:
	raise InvalidData

	if(myfd == HARDLINK_FD):
	unhardlink_lockfile(lockfilename, unlinkfile=unlinkfile)
	return True

	# myfd may be None here due to myfd = mypath in lockfile()
	if isinstance(lockfilename, basestring) and \
	not os.path.exists(lockfilename):
	writemsg(_("lockfile does not exist '%s'\n") % lockfilename, 1)
	if myfd is not None:
	os.close(myfd)
	_open_fds.remove(myfd)
	return False

try:
	if myfd is None:
	myfd = os.open(lockfilename, os.O_WRONLY, 0o660)
	unlinkfile = 1
	locking_method(myfd, fcntl.LOCK_UN)
	except OSError:
	if isinstance(lockfilename, basestring):
	os.close(myfd)
	_open_fds.remove(myfd)
	raise IOError(_("Failed to unlock file '%s'\n") % lockfilename)

try:
	# This sleep call was added to allow other processes that are
	# waiting for a lock to be able to grab it before it is deleted.
	# lockfile() already accounts for this situation, however, and
	# the sleep here adds more time than is saved overall, so am
	# commenting until it is proved necessary.
	#time.sleep(0.0001)
	if unlinkfile:
	locking_method(myfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
	# We won the lock, so there isn't competition for it.
	# We can safely delete the file.
		writemsg(_("Got the lockfile...\n"), 1)
	if _fstat_nlink(myfd) == 1:
	os.unlink(lockfilename)
	writemsg(_("Unlinked lockfile...\n"), 1)
	locking_method(myfd, fcntl.LOCK_UN)
	else:
	writemsg(_("lockfile does not exist '%s'\n") % lockfilename, 1)
	os.close(myfd)
	_open_fds.remove(myfd)
	return False
	except SystemExit:
	raise
	except Exception as e:
	writemsg(_("Failed to get lock... someone took it.\n"), 1)
	writemsg(str(e) + "\n", 1)

	# why test lockfilename?  because we may have been handed an
	# fd originally, and the caller might not like having their
	# open fd closed automatically on them.
	if isinstance(lockfilename, basestring):
	os.close(myfd)
	_open_fds.remove(myfd)

	return true
}
