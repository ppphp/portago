package elog

import (
	"fmt"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/ebuild"
	"log/syslog"
	"strings"
)

var _pri = map[string]syslog.Priority{
	"INFO":  syslog.LOG_INFO,
	"WARN":  syslog.LOG_WARNING,
	"ERROR": syslog.LOG_ERR,
	"LOG":   syslog.LOG_NOTICE,
	"QA":    syslog.LOG_WARNING,
}

func syslog_process(mysettings *ebuild.Config, key string, logentries map[string][]struct {
	s  string
	ss []string
}, fulltext string) {
	w, _ := syslog.New(syslog.LOG_ERR|syslog.LOG_WARNING|syslog.LOG_INFO|syslog.LOG_NOTICE|syslog.LOG_LOCAL5, "portage")
	for phase := range _const.EBUILD_PHASES {
		if _, ok := logentries[phase]; !ok {
			continue
		}
		for _, v := range logentries[phase] {
			msgtype, msgcontent := v.s, v.ss
			for _, line := range msgcontent {
				line := fmt.Sprintf("%s: %s: %s", key, phase, line)
				switch _pri[msgtype] {
				case syslog.LOG_INFO:
					w.Info(strings.TrimRight(line, "\n"))
				case syslog.LOG_WARNING:
					w.Warning(strings.TrimRight(line, "\n"))
				case syslog.LOG_ERR:
					w.Err(strings.TrimRight(line, "\n"))
				case syslog.LOG_NOTICE:
					w.Notice(strings.TrimRight(line, "\n"))
				}
			}
		}
	}
	w.Close()
}
