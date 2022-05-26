package emerge

type CompositeTask struct {
	*AsynchronousTask

	// slot
	_current_task ITask

	_TASK_QUEUED int
}

func (c*CompositeTask)_cancel() {
	if c._current_task != nil {
		if c._current_task is
		c._TASK_QUEUED{
			i := 1
			c.returncode = &i
			c._current_task = nil
			c._async_wait()
		} else {
			c._current_task.cancel()
		}
	} else if c.returncode == nil {
		c._was_cancelled()
		c._async_wait()
	}
}

func(c*CompositeTask) _poll() *int {
	prev = nil
	for true {
		task := c._current_task
		if task == nil ||
			task
			is
		c._TASK_QUEUED ||
			task
		is
		prev{
			break
		}
		task.poll()
		prev = task
	}
	return c.returncode
}

func(c*CompositeTask) _assert_current(task *SpawnProcess) {
	if task != c._current_task {
		raise
		AssertionError("Unrecognized task: %s" % (task, ))
	}
}

func(c*CompositeTask) _default_exit( task *SpawnProcess) int {
	c._assert_current(task)
	if task.returncode != nil && *task.returncode == 0 {
		c.returncode = task.returncode
		c.cancelled = task.cancelled
		c._current_task = nil
		return *task.returncode
	}
}

func(c*CompositeTask) _final_exit( task) *int{
	c._default_exit(task)
	c._current_task = nil
	c.returncode = task.returncode
	return c.returncode
}

func(c*CompositeTask) _default_final_exit( task) int {
	c._final_exit(task)
	return c.wait()
}

func(c*CompositeTask) _start_task(task ITask, exit_handler func(*int)) {
	//try{
	//task.scheduler = c.scheduler
	//except AttributeError{
	//pass
	task.addExitListener(exit_handler)
	c._current_task = task
	task.start()
}

func(c*CompositeTask) _task_queued(task *EbuildPhase) {
	task.addStartListener(c._task_queued_start_handler)
	c._current_task = c._TASK_QUEUED
}

func(c*CompositeTask) _task_queued_start_handler( task ITask) {
	c._current_task = task
}

func(c*CompositeTask) _task_queued_wait() bool {
	return c._current_task != c._TASK_QUEUED ||
		c.cancelled || c.returncode != nil
}

func NewCompositeTask()*CompositeTask {
	c := &CompositeTask{}
	c._TASK_QUEUED = -1
	c.AsynchronousTask = NewAsynchronousTask()
	return c
}
