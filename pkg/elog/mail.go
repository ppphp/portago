package elog

import (
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/mail"
	"github.com/ppphp/portago/pkg/myutil"
	"strings"
)

func mail_process(mysettings *ebuild.Config, key string, logentries map[string][]struct {
	s  string
	ss []string
}, fulltext string) {
	myrecipient := "root@localhost"
	if myutil.Inmss(mysettings.ValueDict, "PORTAGE_ELOG_MAILURI") {
		myrecipient = strings.Fields(mysettings.ValueDict["PORTAGE_ELOG_MAILURI"])[0]
	}
	myfrom := mysettings.ValueDict["PORTAGE_ELOG_MAILFROM"]
	myfrom = strings.ReplaceAll(myfrom, "${HOST}", socket.getfqdn())
	mysubject := mysettings.ValueDict["PORTAGE_ELOG_MAILSUBJECT"]
	mysubject = strings.ReplaceAll(mysubject, "${PACKAGE}", key)
	mysubject = strings.ReplaceAll(mysubject, "${HOST}", socket.getfqdn())

	action := "merged"
	for phase := range logentries {
		if phase == "postrm" || phase == "prerm" {
			action = "unmerged"
		}
	}
	if action == "unmerged" {
		for phase := range logentries {
			if phase != "postrm" && phase != "prerm" && phase != "postrm" {
				action = "unknown"
			}
		}
	}

	mysubject = strings.ReplaceAll(mysubject, "${ACTION}", action)

	mymessage := mail.Create_message(myfrom, myrecipient, mysubject, fulltext)
	//try:
	mail.Send_mail(mysettings, mymessage)
	//except exception.PortageException as e:
	//msg.WriteMsg("%s\n"%str(e), noiselevel = -1)

	return
}
