package elog

import (
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/process"
	"strings"
)

func custom_process(mysettings *config.Config, key string, logentries map[string][]struct {
	s  string
	ss []string
}, fulltext string) {
	elogfilename := save_process(mysettings, key, logentries, fulltext)

	if mysettings.ValueDict["PORTAGE_ELOG_COMMAND"] == "" {
		//raise portage.exception.MissingParameter("!!! Custom logging requested but PORTAGE_ELOG_COMMAND is not defined")
	} else {
		mylogcmd := mysettings.ValueDict["PORTAGE_ELOG_COMMAND"]
		mylogcmd = strings.ReplaceAll(mylogcmd, "${LOGFILE}", elogfilename)
		mylogcmd = strings.ReplaceAll(mylogcmd, "${PACKAGE}", key)
		retval, _ := process.Spawn_bash(mylogcmd, false, "", nil)
		if len(retval) != 1 || retval[0] != 0 {
			//raise portage.exception.PortageException("!!! PORTAGE_ELOG_COMMAND failed with exitcode %d" % retval)
		}
	}
	return
}
