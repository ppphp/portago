package interfaces

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
