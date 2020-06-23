package atom

type AsynchronousTask struct {
	returncode *int
}

func (a *AsynchronousTask) start() {
	a._start()
	a._start_hook()
}

func (a *AsynchronousTask) _start() {}

func (a *AsynchronousTask) _start_hook() {}

func (a *AsynchronousTask) wait() *int {
	if a.returncode == nil {

	}
	a._wait_hook()
	return a.returncode
}

func (a *AsynchronousTask) _wait_hook() {}
