package elog

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/exception"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"io"
	"io/ioutil"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func filter_loglevels(logentries map[string][]struct{s string;ss []string}, loglevels map[string]bool)  map[string][]struct {s  string;ss []string }{
	rValue := map[string][]struct {
		s  string;
		ss []string
	}{}
	for i := range loglevels {
		delete(loglevels, i)
		loglevels[strings.ToUpper(i)] = true
	}
	for phase := range logentries {
		for _, v := range logentries[phase] {
			msgtype, msgcontent := v.s, v.ss
			if loglevels[strings.ToUpper(msgtype)] || loglevels["*"] {
				if _, ok := rValue[phase]; !ok {
					rValue[phase] = []struct {
						s  string
						ss []string
					}{}
				}
				rValue[phase] = append(rValue[phase], struct {
					s  string;
					ss []string
				}{msgtype, msgcontent})
			}
		}
	}
	return rValue
}


func _preload_elog_modules(settings *ebuild.Config) {
	logsystems := strings.Fields(settings.ValueDict["PORTAGE_ELOG_SYSTEM"])
	for _, s:= range logsystems{
		if strings.Contains(s, ":") {
			s = strings.SplitN(s, ":", 2)[0]
		}
		s = strings.ReplaceAll(s, "-", "_")
	//try:
	//	_load_mod("portage.elog.mod_" + s)
	//	except
	//ImportError:
	//	pass
	}
}

func _merge_logentries(a, b map[string][]struct {
	s  string
	ss []string
}) map[string][]struct{s string;ss []string} {
	rValue := map[string][]struct {
		s  string;
		ss []string
	}{}
	phases := map[string]bool{}
	for k := range a {
		phases[k] = true
	}
	for k := range b {
		phases[k] = true
	}
	for p := range phases {
		merged_msgs := []struct {
			s  string
			ss []string
		}{}
		rValue[p] = merged_msgs
		for _, d := range []map[string][]struct {
			s  string
			ss []string
		}{a, b} {
			msgs := d[p]
			if len(msgs) > 0 {
				merged_msgs = append(merged_msgs, msgs...)
			}
		}
	}
	return rValue
}

func _combine_logentries(logentries map[string][]struct {s  string;ss []string} ) string {
	rValue := []string{}
	for phase := range _const.EBUILD_PHASES {
		if _, ok := logentries[phase]; !ok {
			continue
		}
		previous_type := ""
		for _, v := range logentries[phase] {
			msgtype, msgcontent := v.s, v.ss
			if previous_type != msgtype {
				previous_type = msgtype
				rValue = append(rValue, fmt.Sprintf("%s: %s", msgtype, phase))
			}
			for _, line := range msgcontent {
				rValue = append(rValue, strings.TrimRight(line, "\n"))
			}
		}
	}
	if len(rValue) > 0 {
		rValue = append(rValue, "")
	}
	return strings.Join(rValue, "\n")
}

//_elog_mod_imports = {}
//func _load_mod(name) {
//	global
//	_elog_mod_imports
//	m = _elog_mod_imports.get(name)
//	if m == nil:
//	m = __import__(name)
//	for comp
//	in
//	name.split(".")[1:]:
//	m = getattr(m, comp)
//	_elog_mod_imports[name] = m
//	return m
//}

var _elog_listeners = []func(*ebuild.Config, string, interface{}, interface{})
func add_listener(listener func(*ebuild.Config, string, interface{}, interface{})) {
	_elog_listeners = append(_elog_listeners, listener)
}

func remove_listener(listener func(*ebuild.Config, string, interface{}, interface{})) {
	el:= []func(*ebuild.Config, string, interface{}, interface{}){}
	for _, e :=range _elog_listeners {
		for &e != &listener {
			el =append(el, e)
		}
	}
}

var _elog_atexit_handlers = []

// nil
func elog_process(cpv string, mysettings *ebuild.Config, phasefilter []string) {

	logsystems1 := strings.Fields(mysettings.ValueDict["PORTAGE_ELOG_SYSTEM"])
	for _, s := range logsystems1 {
		if strings.Contains(s, ":") {
			s= strings.SplitN(s, ":", 1)[0]
			levelss :=  strings.SplitN(s, ":", 1)[1]
			levels = strings.Split(levelss, ",")
		}
		s = strings.ReplaceAll(s, "-", "_")

	//try:
	//	_load_mod("portage.elog.mod_" + s)
	//	except
	//ImportError:
	//	pass
	}
	ebuild_logentries := map[string][]struct {
		s  string
		ss []string
	}{}
	if myutil.Inmss(mysettings.ValueDict, "T") {
		ebuild_logentries = collect_ebuild_messages(filepath.Join(mysettings.ValueDict["T"], "logging"))
	}
	all_logentries := collect_messages(cpv, phasefilter)
	if _, ok := all_logentries[cpv]; ok {
		all_logentries[cpv] = _merge_logentries(all_logentries[cpv], ebuild_logentries)
	} else {
		all_logentries[cpv] = ebuild_logentries
	}

	my_elog_classes := map[string]bool{}
	for _, k := range strings.Fields(mysettings.ValueDict["PORTAGE_ELOG_CLASSES"]) {
		my_elog_classes[k] = true
	}
	logsystems := map[string]map[string]bool{}
	for _, token := range strings.Fields(mysettings.ValueDict["PORTAGE_ELOG_SYSTEM"]) {
		s := token
		levels := []string{}
		if strings.Contains(token, ":") {
			s = strings.SplitN(token, ":", 1)[0]
			level := strings.SplitN(token, ":", 1)[1]
			levels = strings.Split(level, ",")
		}
		levels_set := logsystems[s]
		if levels_set == nil {
			levels_set = map[string]bool{}
			logsystems[s] = levels_set
		}
		for _, k := range levels {
			levels_set[k] = true
		}
	}

	for key := range all_logentries {
		default_logentries := filter_loglevels(all_logentries[key], my_elog_classes)
		if len(default_logentries) == 0 && (!strings.Contains(mysettings.ValueDict["PORTAGE_ELOG_SYSTEM"], ":")) {
			continue
		}

		default_fulllog := _combine_logentries(default_logentries)

		for _, listener := range _elog_listeners {
			listener(mysettings, key, default_logentries, default_fulllog)
		}

		for s, levels := range logsystems {

			mod_logentries := default_logentries
			mod_fulllog := default_fulllog

			if len(levels) > 0 {
				mod_logentries = filter_loglevels(all_logentries[key], levels)
				mod_fulllog = _combine_logentries(mod_logentries)
			}
			if len(mod_logentries) == 0 {
				continue
			}
			s = strings.ReplaceAll(s, "-", "_")
		//try:
		//	AlarmSignal.register(60)
			switch s {
			case "custom":
				custom_process(mysettings, key, mod_logentries, mod_fulllog)
			case "echo":
				echo_process(mysettings, key, mod_logentries, mod_fulllog)
			case "mail":
				mail_process(mysettings, key, mod_logentries, mod_fulllog)
			case "mail_summary":
				mail_summary_process(mysettings, key, mod_logentries, mod_fulllog)
			case "save":
				save_process(mysettings, key, mod_logentries, mod_fulllog)
			case "save_summary":
				save_summary_process(mysettings, key, mod_logentries, mod_fulllog)
			case "syslog":
				syslog_process(mysettings, key, mod_logentries, mod_fulllog)
			}
		//finally:
		//	AlarmSignal.unregister()
			switch s {
			case "echo":

			}
			if hasattr(m, "finalize") &&
				!
					m.finalize
				in
		_elog_atexit_handlers:
			_elog_atexit_handlers = append(_elog_atexit_handlers, m.finalize)
			process.atexit_register(m.finalize)
			except(ImportError, AttributeError)
			as
		e:
			msg.WriteMsg(_("!!! Error while importing logging modules "
			"while loading \"mod_%s\":\n") % str(s))
			msg.WriteMsg("%s\n"%str(e), noiselevel = -1)
			except
		AlarmSignal:
			msg.WriteMsg("Timeout in elog_process for system '%s'\n"%s,
				noiselevel = -1)
			except
			exception.PortageException
			as
		e:
			msg.WriteMsg("%s\n"%str(e), noiselevel = -1)
		}
	}
}

var _log_levels = map[string]bool{
	"ERROR": true,
	"INFO":  true,
	"LOG":   true,
	"QA":    true,
	"WARN":  true,
}

func collect_ebuild_messages(path string)map[string][]struct{s string; ss []string} {
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
		s  string;
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
				s  string;
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
			msgtype, msg := strings.SplitN(l, " ", 1)[0], strings.SplitN(l, " ", 1)[1]
			if !_log_levels[msgtype] {
				msg.WriteMsg(fmt.Sprintf("!!! malformed entry in "+
					"log file: '%s': %s\n", filename, l), -1, nil)
				continue
			}
			if lastmsgtype == "" {
				lastmsgtype = msgtype
			}

			if msgtype == lastmsgtype {
				msgcontent = append(msgcontent, msg)
			} else {
				if len(msgcontent) > 0 {
					logentries[msgfunction] = append(logentries[msgfunction], struct {
						s  string;
						ss []string
					}{lastmsgtype, msgcontent})
				}
				msgcontent = []string{msg}
			}
			lastmsgtype = msgtype
		}
		if len(msgcontent) > 0 {
			logentries[msgfunction] = append(logentries[msgfunction], struct {
				s  string;
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

var _msgbuffer = map[string]map[string][]struct{s string; ss []string}{}
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
		_msgbuffer[key] = map[string][]struct{s string;ss []string}{}
	}
	if _, ok := _msgbuffer[key][phase]; !ok {
		_msgbuffer[key][phase] = []struct{s string;ss []string}{}
	}
	_msgbuffer[key][phase]=append(_msgbuffer[key][phase],struct{s string;ss []string}{level, []string{msg}})
}

// "", nil
func collect_messages(key string, phasefilter []string) map[string]map[string][]struct{s string;ss []string} {
	var rValue map[string]map[string][]struct{s string;ss []string}
	if key == "" {
		rValue = _msgbuffer
		_reset_buffer()
	} else {
		rValue = map[string]map[string][]struct{s string;ss []string}{}
		if _, ok := _msgbuffer[key]; ok {
			if phasefilter == nil {
				rValue[key] = _msgbuffer[key]
				delete(_msgbuffer, key)
			} else {
				rValue[key] = map[string][]struct{s string;ss []string}{}
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
func Einfo(msg, phase, key string, out io.Writer){
	_elog_base( "INFO", msg, phase, key,"GOOD", out)
}

// "other", "",nil
func elog(msg, phase, key string, out io.Writer){
	_elog_base( "LOG", msg, phase, key,"GOOD", out)
}

// "other", "",nil
func ewarn(msg, phase, key string, out io.Writer){
	_elog_base( "WARN", msg, phase, key,"WARN", out)
}

// "other", "",nil
func eqawarn(msg, phase, key string, out io.Writer){
	_elog_base( "QA", msg, phase, key,"WARN", out)
}

// "other", "",nil
func eerror(msg, phase, key string, out io.Writer){
	_elog_base( "ERROR", msg, phase, key,"BAD", out)
}

// -------------------------------------------------- custom

func custom_process(mysettings *ebuild.Config, key string, logentries map[string][]struct {s string;ss []string}, fulltext string) {
	elogfilename := save_process(mysettings, key, logentries, fulltext)

	if mysettings.ValueDict["PORTAGE_ELOG_COMMAND"]== "" {
		//raise portage.exception.MissingParameter("!!! Custom logging requested but PORTAGE_ELOG_COMMAND is not defined")
	}else {
		mylogcmd := mysettings.ValueDict["PORTAGE_ELOG_COMMAND"]
		mylogcmd = strings.ReplaceAll(mylogcmd, "${LOGFILE}", elogfilename)
		mylogcmd = strings.ReplaceAll(mylogcmd,"${PACKAGE}", key)
		retval = portage.process.spawn_bash(mylogcmd)
		if retval != 0 {
			//raise portage.exception.PortageException("!!! PORTAGE_ELOG_COMMAND failed with exitcode %d" % retval)
		}
	}
	return
}

// -------------------------------------------------- echo


var _echo_items = []*struct{s1,s2 string; ss map[string][]struct {s  string;ss []string}; s3 string}
func echo_process(mysettings *ebuild.Config, key string, logentries map[string][]struct {s string;ss []string}, fulltext string) {
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
					"WARN": printer.ewarn,
					"ERROR": printer.eerror,
					"LOG": printer.Einfo,
					"QA": printer.ewarn,
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

// --------------------------mail

func mail_process(mysettings *ebuild.Config, key string, logentries map[string][]struct {s string;ss []string}, fulltext string) {
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

	mymessage := portage.mail.create_message(myfrom, myrecipient, mysubject, fulltext)
try:
	portage.mail.send_mail(mysettings, mymessage)
	except
	exception.PortageException
	as e:
	msg.WriteMsg("%s\n"%str(e), noiselevel = -1)

	return
}

// --------------------------mail summary

var _config_keys = []string{"PORTAGE_ELOG_MAILURI", "PORTAGE_ELOG_MAILFROM",
"PORTAGE_ELOG_MAILSUBJECT",}
var mail_summary_items = map[string]*struct{ms1, ms2 map[string]string}{}
func mail_summary_process(mysettings *ebuild.Config, key string, logentries map[string][]struct {s string;ss []string}, fulltext string) {
	time_str := time.Now().Format("20060102-150405 07:00") //%Y%m%d-%H%M%S %Z
	header := fmt.Sprintf(">>> Messages generated for package %s by process %d on %s:\n\n", key, os.Getpid(),  time_str)
	config_root := mysettings.ValueDict["PORTAGE_CONFIGROOT"]
	config_dict := map[string] string{}
	for _,  k:= range _config_keys {
		v := mysettings.ValueDict[k]
		if v != "" {
			config_dict[k] = v
		}
	}
	if _, ok := mail_summary_items[config_root]; !ok {
		mail_summary_items[config_root] = &struct{ms1, ms2 map[string]string}{config_dict, map[string]string{}}
	}
	v := mail_summary_items[config_root]
	items :=  v.ms2
	items[key] = header + fulltext
}

func mail_summary_finalize() {
	for mysettings, items := range mail_summary_items {
		_mail_summary_finalize(mysettings, items)
	}
	mail_summary_items = map[string]*struct{ ms1, ms2 map[string]string }{}
}

func _mail_summary_finalize(mysettings , items map[string]string) {
	count := ""
	if len(items) == 0 {
		return
	} else if
	len(items) == 1 {
		count = "one package"
	} else {
		count = "multiple packages"
	}
	myrecipient := "root@localhost"
	if myutil.Inmss(mysettings, "PORTAGE_ELOG_MAILURI") {
		myrecipient = strings.Fields(mysettings["PORTAGE_ELOG_MAILURI"])[0]
	}
	myfrom := mysettings["PORTAGE_ELOG_MAILFROM"]
	myfrom = strings.ReplaceAll(myfrom, "${HOST}", socket.getfqdn())
	mysubject := mysettings["PORTAGE_ELOG_MAILSUBJECT"]
	mysubject = strings.ReplaceAll(mysubject, "${PACKAGE}", count)
	mysubject = strings.ReplaceAll(mysubject, "${HOST}", socket.getfqdn())

	mybody := fmt.Sprintf("elog messages for the following packages generated by "+
		"process %d on host %s:\n", os.Getpid(), socket.getfqdn())
	for key := range items {
		mybody += fmt.Sprintf("- %s\n", key)
	}

	mymessage = portage.mail.create_message(myfrom, myrecipient, mysubject,
		mybody, attachments = list(items.values()))

try:
try:
	AlarmSignal.register(60)
	portage.mail.send_mail(mysettings, mymessage)
finally:
	AlarmSignal.unregister()
	except
AlarmSignal:
	msg.WriteMsg("Timeout in finalize() for elog system 'mail_summary'\n",
		noiselevel = -1)
	except
	exception.PortageException
	as
e:
	msg.WriteMsg("%s\n" % (e, ), noiselevel = -1)

	return
}

// ---------------------save


func save_process(mysettings *ebuild.Config, key string, logentries map[string][]struct {s string;ss []string}, fulltext string) {
	logdir := ""
	if mysettings.ValueDict["PORTAGE_LOGDIR"]!= "" {
		logdir = msg.NormalizePath(mysettings.ValueDict["PORTAGE_LOGDIR"])
	}else {
		logdir = filepath.Join(string(os.PathSeparator), strings.TrimLeft(mysettings.ValueDict["EPREFIX"], string(os.PathSeparator)),
			"var", "log", "portage")
	}

	if ! myutil.PathIsDir(logdir) {
		uid := -1
		if *data.Secpass >= 2 {
			uid = *data.Portage_uid
		}
		util.EnsureDirs(logdir, uint32(uid), *data.Portage_gid, 02770, -1,nil,true)
	}

	cat, pf := atom.catsplit(key)[0], atom.catsplit(key)[1]

	elogfilename := pf + ":" + time.Now().Format("20060102-150405")

	log_subdir := ""
	if mysettings.Features.Features[ "split-elog"] {
		log_subdir = filepath.Join(logdir, "elog", cat)
		elogfilename = filepath.Join(log_subdir, elogfilename)
	}else {
		log_subdir = filepath.Join(logdir, "elog")
		elogfilename = filepath.Join(log_subdir, cat+":"+elogfilename)
	}
	atom._ensure_log_subdirs(logdir, log_subdir)

try:
	with
	io.open(_unicode_encode(elogfilename,
		encoding = _encodings['fs'], errors = 'strict'), mode = 'w',
		encoding=_encodings['content'],
		errors = 'backslashreplace') as
elogfile:
	elogfile.write(_unicode_decode(fulltext))
	except
	IOError
	as
e:
	func_call = "open('%s', 'w')" % elogfilename
	if e.errno == syscall.EACCES:
	raise
	portage.exception.PermissionDenied(func_call)
	elif
	e.errno == syscall.EPERM:
	raise
	portage.exception.OperationNotPermitted(func_call)
	elif
	e.errno == syscall.EROFS:
	raise
	portage.exception.ReadOnlyFileSystem(func_call)
	else:
	raise

	elogdir_st = os.Stat(log_subdir)
	elogdir_gid = elogdir_st.st_gid
	elogdir_grp_mode = 0o060 & elogdir_st.st_mode

	logfile_uid = -1
	if portage.data.Secpass >= 2:
	logfile_uid = elogdir_st.st_uid
	util.applyPermissions(elogfilename, logfile_uid, elogdir_gid,
		elogdir_grp_mode, 0, nil, nil)

	return elogfilename
}


// ------------------------save summary


func save_summary_process(mysettings *ebuild.Config, key string, logentries map[string][]struct {s string;ss []string}, fulltext string) {
	logdir := ""
	if mysettings.ValueDict["PORTAGE_LOGDIR"] != "" {
		logdir = msg.NormalizePath(mysettings.ValueDict["PORTAGE_LOGDIR"])
	}else {
		logdir = filepath.Join(string(os.PathSeparator), strings.TrimLeft(mysettings.ValueDict["EPREFIX"], string(os.PathSeparator)),
			"var", "log", "portage")
	}

	if ! myutil.PathIsDir(logdir) {
		logdir_uid := -1
		if *data.Secpass >= 2 {
			logdir_uid = *data.Portage_uid
		}
		util.EnsureDirs(logdir, uint32(logdir_uid), *data.Portage_gid, 02770, -1, nil, false)
	}
	elogdir := filepath.Join(logdir, "elog")
	atom._ensure_log_subdirs(logdir, elogdir)

	elogfilename := elogdir + "/summary.log"
try:
	elogfile = io.open(_unicode_encode(elogfilename,
		encoding = _encodings['fs'], errors = 'strict'),
	mode = 'a', encoding=_encodings['content'],
		errors = 'backslashreplace')
	except
	IOError
	as
e:
	func_call = "open('%s', 'a')" % elogfilename
	if e.errno == syscall.EACCES:
	raise
	portage.exception.PermissionDenied(func_call)
	elif
	e.errno == syscall.EPERM:
	raise
	portage.exception.OperationNotPermitted(func_call)
	elif
	e.errno == syscall.EROFS:
	raise
	portage.exception.ReadOnlyFileSystem(func_call)
	else:
	raise

	elogdir_st = os.Stat(elogdir)
	elogdir_gid = elogdir_st.st_gid
	elogdir_grp_mode = 0o060 & elogdir_st.st_mode

	logfile_uid = -1
	if portage.data.Secpass >= 2:
	logfile_uid = elogdir_st.st_uid
	apply_permissions(elogfilename, data.uid = logfile_uid, gid = elogdir_gid,
		mode = elogdir_grp_mode, mask=0)

	time_fmt = "%Y-%m-%d %H:%M:%S %Z"
	if sys.hexversion < 0x3000000:
	time_fmt = _unicode_encode(time_fmt)
	time_str = time.strftime(time_fmt, time.localtime(time.time()))
	time_str = _unicode_decode(time_str,
		encoding = _encodings['content'], errors = 'replace')
	elogfile.write(_(">>> Messages generated by process "
	"%(pid)d on %(time)s for package %(pkg)s:\n\n") %
	{"pid": os.getpid(), "time": time_str, "pkg": key})
	elogfile.write(_unicode_decode(fulltext))
	elogfile.write("\n")
	elogfile.close()

	return elogfilename
}

// -----------------------syslog


var _pri = map[string]syslog.Priority{
	"INFO":  syslog.LOG_INFO,
	"WARN":  syslog.LOG_WARNING,
	"ERROR": syslog.LOG_ERR,
	"LOG":   syslog.LOG_NOTICE,
	"QA":    syslog.LOG_WARNING,
}

func syslog_process(mysettings *ebuild.Config, key string, logentries map[string][]struct {s string;ss []string}, fulltext string) {
	w, _ := syslog.New(syslog.LOG_ERR|syslog.LOG_WARNING|syslog.LOG_INFO|syslog.LOG_NOTICE| syslog.LOG_LOCAL5,"portage")
	for phase := range _const.EBUILD_PHASES {
		if _, ok := logentries[phase]; !ok {
			continue
		}
		for _, v:= range logentries[phase] {
			msgtype, msgcontent := v.s, v.ss
			for _, line := range msgcontent {
				line := fmt.Sprintf("%s: %s: %s" ,key, phase, line)
				w.Write(_pri[msgtype], strings.TrimRight(line, "\n"))
			}
		}
	}
	w.Close()
}
