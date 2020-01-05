package emerge

type AsyncScheduler struct {
	*AsynchronousTask
	*PoolScheduler
}
