package emerge

import (
	"fmt"
	"github.com/ppphp/portago/pkg/checksum"
	"strings"
	"syscall"
)

type FileDigester struct {
	*ForkProcess

	// slot
	hash_names          []string
	file_path           string
	digests             map[string]string
	_digest_pw          int
	_digest_pipe_reader *PipeReader
}

func (f *FileDigester) _start() {
	p2 := make([]int, 2)
	syscall.Pipe(p2)
	pr, pw := p2[0], p2[1]
	f.fd_pipes = map[int]int{}
	f.fd_pipes[pw] = pw
	f._digest_pw = pw
	f._digest_pipe_reader = NewPipeReader(map[string]int{"input": pr}, f.scheduler)
	f._digest_pipe_reader.addExitListener(f._digest_pipe_reader_exit)
	f._digest_pipe_reader.start()
	f.ForkProcess._start()
	syscall.Close(pw)
}

func (f *FileDigester) _run() int {
	digests := checksum.PerformMultipleChecksums(f.file_path, f.hash_names, false)

	bs := []string{}
	for k, v := range digests {
		bs = append(bs, fmt.Sprintf("%s=%s\n", k, string(v)))
	}
	buf := strings.Join(bs, "")

	for len(buf) > 0 {
		n, _ := syscall.Write(f._digest_pw, []byte(buf))
		buf = buf[n:]
	}

	return 0
}

func (f *FileDigester) _parse_digests(data) {
	digests := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, "=", 1)
		if len(parts) == 2 {
			digests[parts[0]] = parts[1]
		}
	}

	f.digests = digests
}

func (f *FileDigester) _async_waitpid() {
	if f._digest_pipe_reader == nil {
		f.ForkProcess._async_waitpid()
	}
}

func (f *FileDigester) _digest_pipe_reader_exit(pipe_reader) {
	f._parse_digests(pipe_reader.getvalue())
	f._digest_pipe_reader = nil
	if f.pid == nil {
		f._unregister()
		f._async_wait()
	} else {
		f._async_waitpid()
	}
}

func (f *FileDigester) _unregister() {
	f.ForkProcess._unregister()

	pipe_reader := f._digest_pipe_reader
	if pipe_reader != nil {
		f._digest_pipe_reader = nil
		pipe_reader.removeExitListener(f._digest_pipe_reader_exit)
		pipe_reader.cancel()
	}
}

func NewFileDigester(file_path string, hash_names []string, background bool, logfile string, scheduler *SchedulerInterface) *FileDigester {
	f := &FileDigester{}
	f.file_path = file_path
	f.hash_names = hash_names
	f.background = background
	f.logfile = logfile
	f.scheduler = scheduler
	return f
}
