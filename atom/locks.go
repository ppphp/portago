package atom

import (
	"os"
	"syscall"
)

const (
	HARDLINK_FD=-2
	_HARDLINK_POLL_LATENCY = 3
	)

var(
	quiet =false
	_lock_fn func(int,int)error= nil
)

func _get_lock_fn()func(int,int)error{
	if _lock_fn!=nil{
		return _lock_fn
	}
	_test_lock := func(fd int, lock_path string){
		syscall.Close(fd)
		f, _ := os.OpenFile(lock_path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0777)
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			if err == syscall.EAGAIN{
				os.Exit(0)
			}
		}else {
			os.Exit(1)
		}
	}
	fd, lock_path := tempfile.mkstemp()
try:
try:
	fcntl.lockf(fd, fcntl.LOCK_EX)
	except EnvironmentError:
	pass
	else:
	proc = multiprocessing.Process(target=_test_lock,
		args=(fd, lock_path))
	proc.start()
	proc.join()
	if proc.exitcode == os.EX_OK:
	# Use fcntl.lockf because the test passed.
		_lock_fn = fcntl.lockf
	return _lock_fn
finally:
	os.close(fd)
	os.unlink(lock_path)

	# Fall back to fcntl.flock.
		_lock_fn = fcntl.flock
	return _lock_fn
	syscall.Flock
}
