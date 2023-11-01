package emerge

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

func (a *AsynchronousTask)  async_wait() interfaces.IFuture {
	waiter := a.scheduler.create_future()
	exit_listener := func(a *AsynchronousTask) bool { return waiter.cancelled() || waiter.set_result(a.returncode) }
	a.addExitListener(exit_listener)
	waiter.add_done_callback(func(waiter interfaces.IFuture, err error)  {
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
