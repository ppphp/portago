package elog

import (
	"fmt"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"os"
	"strings"
)

var _echo_items = []*struct{s1,s2 string; ss map[string][]struct {s  string;ss []string}; s3 string}{}

func echo_process(mysettings *config.Config, key string, logentries map[string][]struct {s string;ss []string}, fulltext string) {
	logfile := ""
	if key == mysettings.mycpv.string && myutil.Inmss(mysettings.ValueDict,"PORTAGE_LOGDIR") && myutil.Inmss(mysettings.ValueDict,"PORTAGE_LOG_FILE") {
		logfile = mysettings.ValueDict["PORTAGE_LOG_FILE"]
	}
	_echo_items =append(_echo_items,&struct{s1,s2 string; ss map[string][]struct {s string;ss []string}; s3 string}{mysettings.ValueDict["ROOT"], key, logentries, logfile})
}

func echo_finalize() {
	stderr := os.Stderr
	//try:
	os.Stderr = os.Stdout
	_echo_finalize()
	//finally:
	os.Stderr = stderr
}

func _echo_finalize() {
	printer := output.NewEOutput(false)
	for _, v := range _echo_items {
		root, key, logentries, logfile := v.s1, v.s2, v.ss, v.s3
		print()
		if root == "/" {
			printer.Einfo(fmt.Sprintf("Messages for package %s:",
				output.Colorize("INFORM", key))
		}else {
			printer.Einfo(fmt.Sprintf("Messages for package %s merged to %s:",
				output.Colorize("INFORM", key),  root))
		}
		if logfile !="" {
			printer.Einfo(fmt.Sprintf("Log file: %s", output.Colorize("INFORM", logfile)))
		}
		print()
		for phase:= range _const.EBUILD_PHASES {
			if _, ok := logentries[phase];!ok {
				continue
			}
			for _, v := range logentries[phase]{
				msgtype, msgcontent := v.s, v.ss
				fmap :=map[string]func(string){
					"INFO": printer.Einfo,
					"WARN": printer.Ewarn,
					"ERROR": printer.Eerror,
					"LOG": printer.Einfo,
					"QA": printer.Ewarn,
				}
				for _, line:= range msgcontent{
					fmap[msgtype](strings.Trim(line, "\n"))
				}
			}
		}
	}
	_echo_items = []*struct{s1,s2 string; ss map[string][]struct {s string;ss []string}; s3 string}{}
	return
}
