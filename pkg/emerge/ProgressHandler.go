package emerge

import "time"

type ProgressHandler struct {
	curval, maxval            int
	min_latency, _last_update float64
}

func NewProgressHandler() *ProgressHandler {
	p := &ProgressHandler{}
	p.curval = 0
	p.maxval = 0
	p._last_update = 0
	p.min_latency = 0.2
	return p
}

func (p *ProgressHandler) onProgress(maxval, curval int) {
	p.maxval = maxval
	p.curval = curval
	cur_time := float64(time.Now().UnixMilli()) / 1000
	if cur_time-p._last_update >= p.min_latency {
		p._last_update = cur_time
		p.display()
	}
}

func (p *ProgressHandler) display() {
	//raise NotImplementedError(p)
}
