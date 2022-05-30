package mail

import (
	"fmt"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/myutil"
	"mime"
	"os"
	"path/filepath"
	"strings"
)

func _force_ascii_if_necessary(s string ) string {
	return s
}


func TextMessage(_text string) string {
	var we mime.WordEncoder

	//from
	//email.mime.text import
	//MIMEText
	//
	//mimetext = MIMEText(_text)
	//mimetext.set_charset("UTF-8")
	return we.Encode("UTF-8", _text)
}

// nil
func Create_message(sender, recipient, subject, body string, attachments=None) string {

	from
	email.header import
	Header
	from
	email.mime.base import
	MIMEBase
	as
	BaseMessage
	from
	email.mime.multipart import
	MIMEMultipart
	as
	MultipartMessage
	from
	email.utils import
	formatdate

	if attachments is
None:
	mymessage = TextMessage(body)
	else:
	mymessage = MultipartMessage()
	mymessage.attach(TextMessage(body))
	for x
	in
attachments:
	if isinstance(x, BaseMessage):
	mymessage.attach(x)
	elif
	isinstance(x, str):
	mymessage.attach(TextMessage(x))
	else:
	raise
	portage.exception.PortageException(
		_(f
	"Can't handle type of attachment: {type(x)}")
)

	mymessage.set_unixfrom(sender)
	mymessage["To"] = recipient
	mymessage["From"] = sender

	mymessage["Subject"] = Header(_force_ascii_if_necessary(subject))
	mymessage["Date"] = formatdate(localtime = True)

	return mymessage
}

func Send_mail(mysettings *ebuild.Config, message string) {

	import smtplib

	mymailhost := "localhost"
	mymailport := 25
	mymailuser := ""
	mymailpasswd := ""
	myrecipient := "root@localhost"

	if strings.Contains(mysettings.ValueDict["PORTAGE_ELOG_MAILURI"], " ") {
		m := strings.Fields(mysettings.ValueDict["PORTAGE_ELOG_MAILURI"])
		myrecipient, mymailuri := m[0], m[1]
		if strings.Contains(mymailuri, "@") {
			myauthdata, myconndata := mymailuri.rsplit("@", 1)
		try:
			mymailuser, mymailpasswd := myauthdata.split(":")
			except
		ValueError:
			print(
				_("!!! invalid SMTP AUTH configuration, trying unauthenticated ...")
			)
		} else {
			myconndata = mymailuri
		}
		if strings.Contains(myconndata, ":") {
			mymailhost, mymailport = myconndata.split(":")
		} else {
			mymailhost = myconndata
		}
	} else {
		myrecipient = mysettings.ValueDict["PORTAGE_ELOG_MAILURI"]
	}

	myfrom := message.get("From")

	if strings.HasPrefix(mymailhost, string(filepath.Separator)) && myutil.PathExists(mymailhost) {

		fd, _ := os.OpenFile(fmt.Sprintf("%s -f %s %s", mymailhost, myfrom, myrecipient), os.O_WRONLY, 0644)
		fd.Write([]byte(_force_ascii_if_necessary(message)))
		if fd.Close() != nil {
			os.Stderr.WriteString(fmt.Sprintf("!!! {mymailhost} returned with a non-zero exit code. This generally indicates an error.\n"))
		}
	} else {
	try:
		if int(mymailport) > 100000 {
			myconn = smtplib.SMTP(mymailhost, int(mymailport)-100000)
			myconn.ehlo()
			if not myconn.has_extn("STARTTLS"):
			raise
			portage.exception.PortageException(
				_(
					"!!! TLS support requested for logmail but not supported by server"
				)
			)
			myconn.starttls()
			myconn.ehlo()
		}else {
			myconn = smtplib.SMTP(mymailhost, mymailport)
		}
		if mymailuser != "" && mymailpasswd != "" {
			myconn.login(mymailuser, mymailpasswd)
		}

		message_str := _force_ascii_if_necessary(message.as_string())
		myconn.sendmail(myfrom, myrecipient, message_str)
		myconn.quit()
		//except smtplib.SMTPException as e:
		//raise portage.exception.PortageException(
		//	_(f"!!! An error occurred while trying to send logmail:\n{e}"))
		//except socket.error as e:
		//raise portage.exception.PortageException(
		//	_(f"!!! A network error occurred while trying to send logmail:\n{e}\nSure you configured PORTAGE_ELOG_MAILURI correctly?" ) )
	}
}
