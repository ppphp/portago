package atom

type AsyncScheduler struct {
	*AsynchronousTask
	*PoolScheduler
}
