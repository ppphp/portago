package atom

import (
	"github.com/ppphp/portago/pkg/output"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type ProgressHandler1 struct {
	curval, maxval      int64
	last_update         time.Time
	min_display_latency time.Duration
}

func (p *ProgressHandler1) Reset() {
	p.curval = 0
	p.maxval = 0
	p.last_update = time.Unix(0, 0)
	p.min_display_latency = 200 * time.Millisecond
}

func (p *ProgressHandler1) onProgress(maxval, curval int64) {
	p.maxval = maxval
	p.curval = curval
	cur_time := time.Now()
	if cur_time.Sub(p.last_update) >= p.min_display_latency {
		p.last_update = cur_time
		p.display()
	}
}

func (p *ProgressHandler1) display() {
	panic("not implemented")
}

func NewProgressHandler1() *ProgressHandler1 {
	p := &ProgressHandler1{}
	p.Reset()
	return p
}

type ProgressBar2 struct {
	*ProgressHandler1
	isatty          bool
	fd              *os.File
	title           string
	maxval          int
	label           string
	max_desc_length int
	progressBar     *output.TermProgressBar
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

	p.ProgressHandler1 = NewProgressHandler1()
	p.progressBar = nil
	return p
}

func (p *ProgressBar2) Start() func(int64, int64) {
	if p.isatty {
		p.progressBar = output.NewTermProgressBar(p.fd, p.title, p.maxval, p.label, p.max_desc_length)
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

func (p *ProgressBar2) SetLabel(_label string) {
	p.label = _label
}

func (p *ProgressBar2) Display() {
	p.progressBar.set(int(p.curval), int(p.maxval))
}

func (p *ProgressBar2) sigwinch_handler(signum, frame int) {
	_, p.progressBar.term_columns, _ = output.get_term_size(0)
}

func (p *ProgressBar2) Stop() {
	p.cancel <- true
}
