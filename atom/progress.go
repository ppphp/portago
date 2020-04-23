package atom

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

type ProgressHandler struct {
	curval, maxval      int64
	last_update         time.Time
	min_display_latency time.Duration
}

func (p *ProgressHandler) reset() {
	p.curval = 0
	p.maxval = 0
	p.last_update = time.Unix(0, 0)
	p.min_display_latency = 200 * time.Millisecond
}

func (p *ProgressHandler) onProgress(maxval, curval int64) {
	p.maxval = maxval
	p.curval = curval
	cur_time := time.Now()
	if cur_time.Sub(p.last_update) >= p.min_display_latency {
		p.last_update = cur_time
		p.display()
	}
}

func (p *ProgressHandler) display() {
	panic("not implemented")
}

func NewProgressHandler() *ProgressHandler {
	p := &ProgressHandler{}
	p.reset()
	return p
}

type ProgressBar2 struct {
	*ProgressHandler
	isatty          bool
	fd              *os.File
	title           string
	maxval          int
	label           string
	max_desc_length int
	progressBar     *TermProgressBar
	c               chan os.Signal
	cancel          chan bool
}

func NewProgressBar2(isatty bool, fd *os.File, title string, maxval int, label string, max_desc_length int) *ProgressBar2 { // os.Stdout, "", 0, "", 25
	p := &ProgressBar2{}
	p.isatty = isatty
	p.fd = fd
	p.title = title
	p.maxval = maxval
	p.label = label
	p.max_desc_length = max_desc_length

	p.ProgressHandler = NewProgressHandler()
	p.progressBar = nil
	return p
}

func (p *ProgressBar2) start() func(int64, int64) {
	if p.isatty {
		p.progressBar = NewTermProgressBar(p.fd, p.title, p.maxval, p.label, p.max_desc_length)
		p.c = make(chan os.Signal, 0)
		p.cancel = make(chan bool, 0)
		signal.Notify(p.c, syscall.SIGWINCH)
		go func() {
			for {
				select {
				case <-p.c:
					p.sigwinch_handler(0, 0)
				case <-p.cancel:
					return
				}
			}
		}()
	}
	return p.onProgress
}

func (p *ProgressBar2) set_label(_label string) {
	p.label = _label
}

func (p *ProgressBar2) display() {
	p.progressBar.set(int(p.curval), int(p.maxval))
}

func (p *ProgressBar2) sigwinch_handler(signum, frame int) {
	_, p.progressBar.term_columns, _ = get_term_size(0)
}

func (p *ProgressBar2) stop() {
	p.cancel <- true
}
