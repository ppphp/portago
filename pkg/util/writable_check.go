package util

import (
	"fmt"
	"github.com/ppphp/portago/pkg/util/msg"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"syscall"
)

func get_ro_checker() func(map[string]bool) map[string]bool {
	if v, ok := _CHECKERS[runtime.GOOS]; ok {
		return v
	} else {
		return empty_ro_checker
	}
}

func linux_ro_checker(dir_list map[string]bool) map[string]bool {
	ro_filesystems := map[string]bool{}
	invalids := []string{}

	f, err := ioutil.ReadFile("/proc/self/mountinfo")
	if err != nil {
		//except EnvironmentError:
		msg.WriteMsgLevel("!!! /proc/self/mountinfo cannot be read", 30, -1)
		return map[string]bool{}
	}

	for _, line := range strings.Split(string(f), "\n") {
		mount := strings.SplitN(line, " - ", 2)
		v := strings.Fields(mount[0])
		if len(v) < 6 {
			//except ValueError:
			invalids = append(invalids, line)
			continue
		}
		_dir, attr1 := v[4], v[5]
		attr2 := ""
		if len(mount) > 1 {
			v := strings.Fields(mount[1])
			if len(v) < 2 {
				invalids = append(invalids, line)
				continue
			} else if len(v) == 2 {
				attr2 = v[1]
			} else {
				attr2 = v[1]
			}
		} else {
			invalids = append(invalids, line)
			continue
		}
		if strings.HasPrefix(attr1, "ro") || strings.HasPrefix(attr2, "ro") {
			ro_filesystems[_dir] = true
		}
	}

	for _, line := range invalids {
		msg.WriteMsgLevel(fmt.Sprintf("!!! /proc/self/mountinfo contains unrecognized line: %s\n",
			strings.TrimRight(line, "\n")), 30, -1)
	}

	ro_devs := map[uint64]string{}
	for x := range ro_filesystems {
		st, err := os.Stat(x)
		if err != nil {
			//except OSError:
			//pass
		} else {
			ro_devs[st.Sys().(*syscall.Stat_t).Dev] = x
		}
	}

	ro_filesystems = map[string]bool{}
	for x := range dir_list {

		st, err := os.Stat(x)
		if err != nil {
			//except OSError:
			//pass
		} else {
			dev := st.Sys().(*syscall.Stat_t).Dev
			ro_filesystems[ro_devs[dev]] = true
		}
	}

	return ro_filesystems
}

func empty_ro_checker(dir_list map[string]bool) map[string]bool {
	return map[string]bool{}
}

var _CHECKERS = map[string]func(map[string]bool) map[string]bool{
	"linux": linux_ro_checker,
}
