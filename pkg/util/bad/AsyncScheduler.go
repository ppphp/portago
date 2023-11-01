package bad

import (
	"time"

	"github.com/ppphp/portago/pkg/emerge"
)

type AsyncScheduler struct {
	*emerge.AsynchronousTask
	*emerge.PollScheduler
	maxJobs        int
	maxLoad        interface{}
	errorCount     int
	runningTasks   map[*Task]bool
	remainingTasks bool
	loadavgCheckId *time.Timer
}

func NewAsyncScheduler(maxJobs int, maxLoad interface{}, kwargs map[string]interface{}) *AsyncScheduler {
	if maxJobs == 0 {
		maxJobs = 1
	}
	return &AsyncScheduler{
		maxJobs:        maxJobs,
		maxLoad:        maxLoad,
		errorCount:     0,
		runningTasks:   make(map[*Task]bool),
		remainingTasks: true,
	}
}

func (s *AsyncScheduler) Scheduler() interface{} {
	return s._event_loop
}

func (s *AsyncScheduler) Poll() int {
	if !s._is_work_scheduled() && !s._keep_scheduling() {
		if s.errorCount > 0 {
			s.returncode = 1
		} else {
			s.returncode = 0
		}
		s._async_wait()
	}
	return s.returncode
}

func (s *AsyncScheduler) Cancel() {
	s._terminated.set()
	s._termination_check()
}

func (s *AsyncScheduler) TerminateTasks() {
	for task := range s.runningTasks {
		task.Cancel()
	}
}

func (s *AsyncScheduler) NextTask() *Task {
	panic("Not implemented")
}

func (s *AsyncScheduler) KeepScheduling() bool {
	return s.remainingTasks && !s._terminated.is_set()
}

func (s *AsyncScheduler) RunningJobCount() int {
	return len(s.runningTasks)
}

func (s *AsyncScheduler) ScheduleTasks() {
	for s.KeepScheduling() && s.CanAddJob() {
		task := s.NextTask()
		if task == nil {
			s.remainingTasks = false
		} else {
			s.runningTasks[task] = true
			task.Scheduler = s._sched_iface
			task.AddExitListener(s.TaskExit)
			task.Start()
		}
	}

	if s.loadavgCheckId != nil {
		s.loadavgCheckId.Stop()
		s.loadavgCheckId = time.AfterFunc(s._loadavg_latency, s.Schedule)
	}

	s.Poll()
}

func (s *AsyncScheduler) TaskExit(task *Task) {
	delete(s.runningTasks, task)
	if task.returncode != 0 {
		s.errorCount += 1
	}
	s.Schedule()
}

func (s *AsyncScheduler) Start() {
	if s.maxLoad != nil && s._loadavg_latency != nil && (s.maxJobs == true || s.maxJobs > 1) {
		s.loadavgCheckId = time.AfterFunc(s._loadavg_latency, s.Schedule)
	}
	s.Schedule()
}

func (s *AsyncScheduler) Cleanup() {
	s.PollScheduler.clean_up()
	if s.loadavgCheckId != nil {
		s.loadavgCheckId.Stop()
		s.loadavgCheckId = nil
	}
}

func (s *AsyncScheduler) AsyncWait() {
	s.Cleanup()
	s.AsynchronousTask.async_wait()
}
