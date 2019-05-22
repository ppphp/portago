package atom

import (
	"io/ioutil"
	"os"
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
