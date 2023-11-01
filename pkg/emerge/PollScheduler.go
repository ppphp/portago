package emerge

import "sync"

type PollScheduler struct {
	_scheduling, _terminated_tasks, _background bool
	_term_rlock                                 sync.Mutex
	_max_jobs                                   int
	_max_load                                   float64
	_sched_iface                                *SchedulerInterface
_loadavg_latency *int
}



func(p*PollScheduler) _is_background() bool{
	return p._background
}

func(p*PollScheduler)  _cleanup() {
	p._term_rlock.Lock()
	if p._term_check_handle not
	in(nil, false)
	{
		p._term_check_handle.cancel()
		p._term_check_handle = false
	}
	p._term_rlock.Unlock()
}

func(p*PollScheduler)  terminate() {
	p._term_rlock.Lock()
	if p._term_check_handle ==nil {
		p._terminated.set()
		p._term_check_handle = p._event_loop.call_soon_threadsafe(
			p._termination_check, true)
	}
	p._term_rlock.Unlock()
}

// false
func(p*PollScheduler)  _termination_check( retry bool) {
	if p._terminated.is_set() &&!p._terminated_tasks{
		if ! p._scheduling {
			p._scheduling = true
		//try:
			p._terminated_tasks = true
			p._terminate_tasks()
		//finally:
			p._scheduling = false
		}else if retry {
			p._term_rlock.Lock()
			p._term_check_handle = p._event_loop.call_soon(
				p._termination_check, true)
			p._term_rlock.Unlock()
		}
	}
}

func(p*PollScheduler)  _terminate_tasks() {
	//raise NotImplementedError()
}

func(p*PollScheduler)  _keep_scheduling() bool{
	return false
}

func(p*PollScheduler)  _schedule_tasks() {
	//pass
}

func(p*PollScheduler)  _schedule() bool {
	if p._scheduling {
		return true
	}
	p._scheduling = true
	p._schedule_tasks()
	p._scheduling = false
	return true
}

func(p*PollScheduler)  _is_work_scheduled() bool {
	return p._running_job_count() != 0
}

func(p*PollScheduler)  _running_job_count() int {
	//raise NotImplementedError(p)
	return 0
}

func(p*PollScheduler)  _can_add_job() bool{
	if p._terminated_tasks {
		return false
	}

	max_jobs := p._max_jobs
	max_load := p._max_load

	if p._max_jobs == 0 &&p._running_job_count() >= p._max_jobs{
		return false
	}

	if max_load !=0 &&
	(max_jobs != 0 || max_jobs > 1) &&
	p._running_job_count() >= 1 {
		avg1, _, _, err := getloadavg()
		if err != nil {
			//except OSError:
			return false
		}

		if avg1 >= max_load {
			return false
		}
	}

	return true
}

// false, nil
func NewPollScheduler( main bool, event_loop=nil)*PollScheduler {
	p := &PollScheduler{}
	p._term_rlock = sync.Mutex{}
	p._terminated = threading.Event()
	p._terminated_tasks = false
	p._term_check_handle = nil
	p._max_jobs = 1
	p._max_load = 0
	p._scheduling = false
	p._background = false
	if event_loop != nil {
		p._event_loop = event_loop
	}else if main {
		p._event_loop = global_event_loop()
	}else {
		p._event_loop = asyncio._safe_loop()
	}
	p._sched_iface = NewSchedulerInterface(p._event_loop, p._is_background)
	return p
}
