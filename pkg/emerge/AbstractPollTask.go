package emerge

import (
	"os"
	"syscall"
)

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
	tasks := []IFuture{a.async_wait()}
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

func NewAbstractPollTask() *AbstractPollTask {
	a := &AbstractPollTask{}
	a._bufsize = 4096
	a.AsynchronousTask = NewAsynchronousTask()
	return a
}
