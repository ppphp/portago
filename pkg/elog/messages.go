package elog

import (
	"fmt"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util/msg"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var _log_levels = map[string]bool{
	"ERROR": true,
	"INFO":  true,
	"LOG":   true,
	"QA":    true,
	"WARN":  true,
}

func collect_ebuild_messages(path string) map[string][]struct {
	s  string
	ss []string
} {
	mylogfiles, err := myutil.ListDir(path)
	if err != nil {
		//except OSError:
		//pass
	}
	if len(mylogfiles) == 0 {
		return map[string][]struct {
			s  string
			ss []string
		}{}
	}
	myutil.ReverseSlice(mylogfiles)
	logentries := map[string][]struct {
		s  string
		ss []string
	}{}
	for _, msgfunction := range mylogfiles {
		filename := filepath.Join(path, msgfunction)
		if !_const.EBUILD_PHASES[msgfunction] {
			msg.WriteMsg(fmt.Sprintf("!!! can't process invalid log file: %s\n", filename),
				-1, nil)
			continue
		}
		if _, ok := logentries[msgfunction]; !ok {
			logentries[msgfunction] = []struct {
				s  string
				ss []string
			}{}
		}
		lastmsgtype := ""
		msgcontent := []string{}
		f, _ := ioutil.ReadFile(filename)
		for _, l := range strings.Split(string(f), "\n") {
			if len(l) == 0 {
				continue
			}
			msgtype, msg1 := strings.SplitN(l, " ", 1)[0], strings.SplitN(l, " ", 1)[1]
			if !_log_levels[msgtype] {
				msg.WriteMsg(fmt.Sprintf("!!! malformed entry in "+
					"log file: '%s': %s\n", filename, l), -1, nil)
				continue
			}
			if lastmsgtype == "" {
				lastmsgtype = msgtype
			}

			if msgtype == lastmsgtype {
				msgcontent = append(msgcontent, msg1)
			} else {
				if len(msgcontent) > 0 {
					logentries[msgfunction] = append(logentries[msgfunction], struct {
						s  string
						ss []string
					}{lastmsgtype, msgcontent})
				}
				msgcontent = []string{msg1}
			}
			lastmsgtype = msgtype
		}
		if len(msgcontent) > 0 {
			logentries[msgfunction] = append(logentries[msgfunction], struct {
				s  string
				ss []string
			}{lastmsgtype, msgcontent})
		}
	}

	for _, f := range mylogfiles {
		if err := syscall.Unlink(filepath.Join(path, f)); err != nil {
			//except OSError:
			//pass
		}
	}
	return logentries
}

var _msgbuffer = map[string]map[string][]struct {
	s  string
	ss []string
}{}

// "other", "", "", nil
func _elog_base(level, msg, phase, key, color string, out io.Writer) {

	if out == nil {
		out = os.Stdout
	}

	if color == "" {
		color = "GOOD"
	}

	formatted_msg := output.Colorize(color, " * ") + msg + "\n"

	out.Write([]byte(formatted_msg))

	if _, ok := _msgbuffer[key]; !ok {
		_msgbuffer[key] = map[string][]struct {
			s  string
			ss []string
		}{}
	}
	if _, ok := _msgbuffer[key][phase]; !ok {
		_msgbuffer[key][phase] = []struct {
			s  string
			ss []string
		}{}
	}
	_msgbuffer[key][phase] = append(_msgbuffer[key][phase], struct {
		s  string
		ss []string
	}{level, []string{msg}})
}

// "", nil
func collect_messages(key string, phasefilter []string) map[string]map[string][]struct {
	s  string
	ss []string
} {
	var rValue map[string]map[string][]struct {
		s  string
		ss []string
	}
	if key == "" {
		rValue = _msgbuffer
		_reset_buffer()
	} else {
		rValue = map[string]map[string][]struct {
			s  string
			ss []string
		}{}
		if _, ok := _msgbuffer[key]; ok {
			if phasefilter == nil {
				rValue[key] = _msgbuffer[key]
				delete(_msgbuffer, key)
			} else {
				rValue[key] = map[string][]struct {
					s  string
					ss []string
				}{}
				for _, phase := range phasefilter {
					rValue[key][phase] = _msgbuffer[key][phase]
					delete(_msgbuffer[key], phase)
				}
				if len(_msgbuffer[key]) == 0 {
					delete(_msgbuffer, key)
				}
			}
		}
	}
	return rValue
}

func _reset_buffer() {
	_msgbuffer = map[string]map[string][]struct {
		s  string
		ss []string
	}{}
}

// "other", "",nil
func Einfo(msg, phase, key string, out io.Writer) {
	_elog_base("INFO", msg, phase, key, "GOOD", out)
}

// "other", "",nil
func elog(msg, phase, key string, out io.Writer) {
	_elog_base("LOG", msg, phase, key, "GOOD", out)
}

// "other", "",nil
func ewarn(msg, phase, key string, out io.Writer) {
	_elog_base("WARN", msg, phase, key, "WARN", out)
}

// "other", "",nil
func eqawarn(msg, phase, key string, out io.Writer) {
	_elog_base("QA", msg, phase, key, "WARN", out)
}

// "other", "",nil
func Eerror(msg, phase, key string, out io.Writer) {
	_elog_base("ERROR", msg, phase, key, "BAD", out)
}
