package atom

import (
	"fmt"
	"io/ioutil"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func filter_loglevels(logentries, loglevels []string) {
	rValue := map[]{}
	for i := range loglevels {
		loglevels[i] = strings.ToUpper(loglevels[i])
	}
	for phase
	in
logentries:
	for msgtype, msgcontent
	in
	logentries[phase]:
	if msgtype.upper() in
	loglevels
	or
	"*"
	in
loglevels:
	if phase !
	in
rValue:
	rValue[phase] = []
	rValue[phase] = append(, (msgtype, msgcontent))
	return rValue
}


func _preload_elog_modules(settings *Config) {
	logsystems := strings.Fields(settings.ValueDict["PORTAGE_ELOG_SYSTEM"])
	for _, s:= range logsystems{
		if strings.Contains(s, ":") {
			s = strings.SplitN(s, ":", 2)[0]
		}
		s = strings.ReplaceAll(s, "-", "_")
	try:
		_load_mod("portage.elog.mod_" + s)
		except
	ImportError:
		pass
	}
}

func _merge_logentries(a, b) {
	rValue =
	{
	}
	phases = set(a)
	phases.update(b)
	for p
	in
phases:
	merged_msgs = []
	rValue[p] = merged_msgs
	for d
	in
	a, b:
	msgs = d.get(p)
	if msgs:
	merged_msgs.extend(msgs)
	return rValue
}

func _combine_logentries(logentries) {
	rValue = []
	for phase
	in
EBUILD_PHASES:
	if ! phase
	in
logentries:
	continue
	previous_type = None
	for msgtype, msgcontent
	in
	logentries[phase]:
	if previous_type != msgtype:
	previous_type = msgtype
	rValue=append(,"%s: %s"%(msgtype, phase))
	if isinstance(msgcontent, basestring):
	rValue=append(,msgcontent.rstrip("\n"))
	else:
	for line
	in
msgcontent:
	rValue=append(,line.rstrip("\n"))
	if rValue:
	rValue=append(,"")
	return "\n".join(rValue)
}

_elog_mod_imports = {}
func _load_mod(name) {
	global
	_elog_mod_imports
	m = _elog_mod_imports.get(name)
	if m == nil:
	m = __import__(name)
	for comp
	in
	name.split(".")[1:]:
	m = getattr(m, comp)
	_elog_mod_imports[name] = m
	return m
}

var _elog_listeners = []
func add_listener(listener) {
	_elog_listeners = append(_elog_listeners, listener)
}

func remove_listener(listener) {
	el:= []{}
	for _, e :=range _elog_listeners{
		for e != listener {
			el =append(el, e)
		}
	}
}

var _elog_atexit_handlers = []

// nil
func elog_process(cpv, mysettings, phasefilter=None) {
	global
	_elog_atexit_handlers

	logsystems = mysettings.ValueDict["PORTAGE_ELOG_SYSTEM", "").split()
	for s
	in
logsystems:
	if ":" in
s:
	s, levels = s.split(":", 1)
	levels = levels.split(",")
	s = s.replace("-", "_")
try:
	_load_mod("portage.elog.mod_" + s)
	except
ImportError:
	pass

	if "T" in
mysettings:
	ebuild_logentries = collect_ebuild_messages(
		filepath.Join(mysettings.ValueDict["T"], "logging"))
	else:
	ebuild_logentries =
	{
	}
	all_logentries = collect_messages(key = cpv, phasefilter = phasefilter)
	if cpv in
all_logentries:
	all_logentries[cpv] = \
	_merge_logentries(all_logentries[cpv], ebuild_logentries)
	else:
	all_logentries[cpv] = ebuild_logentries

	my_elog_classes = set(mysettings.ValueDict["PORTAGE_ELOG_CLASSES", "").split())
	logsystems =
	{
	}
	for token
	in
	mysettings.ValueDict["PORTAGE_ELOG_SYSTEM", "").split():
	if ":" in
token:
	s, levels = token.split(":", 1)
	levels = levels.split(",")
	else:
	s = token
	levels = ()
	levels_set = logsystems.get(s)
	if levels_set == nil:
	levels_set = set()
	logsystems[s] = levels_set
	levels_set.update(levels)

	for key
	in
all_logentries:
	default_logentries = filter_loglevels(all_logentries[key], my_elog_classes)

	if len(default_logentries) == 0 &&(!
	":"
	in
	mysettings.ValueDict["PORTAGE_ELOG_SYSTEM"]):
	continue

	default_fulllog = _combine_logentries(default_logentries)

	for listener
	in
_elog_listeners:
	listener(mysettings, str(key), default_logentries, default_fulllog)

	for s, levels
	in
	logsystems.items():
	if levels:
	mod_logentries = filter_loglevels(all_logentries[key], levels)
	mod_fulllog = _combine_logentries(mod_logentries)
	else:
	mod_logentries = default_logentries
	mod_fulllog = default_fulllog
	if len(mod_logentries) == 0:
	continue
	s = s.replace("-", "_")
try:
	m = _load_mod("portage.elog.mod_" + s)
try:
	AlarmSignal.register(60)
	m.process(mysettings, str(key), mod_logentries, mod_fulllog)
finally:
	AlarmSignal.unregister()
	if hasattr(m, "finalize") &&
	!
	m.finalize
	in
_elog_atexit_handlers:
	_elog_atexit_handlers=append(,m.finalize)
	atexit_register(m.finalize)
	except(ImportError, AttributeError)
	as
e:
	WriteMsg(_("!!! Error while importing logging modules "
	"while loading \"mod_%s\":\n") % str(s))
	WriteMsg("%s\n"%str(e), noiselevel = -1)
	except
AlarmSignal:
	WriteMsg("Timeout in elog_process for system '%s'\n"%s,
		noiselevel = -1)
	except
	PortageException
	as
e:
	WriteMsg("%s\n"%str(e), noiselevel = -1)
}


var _log_levels = map[string]bool{
	"ERROR": true,
	"INFO":  true,
	"LOG":   true,
	"QA":    true,
	"WARN":  true,
}

func collect_ebuild_messages(path string)map[string][]struct{s string; ss []string} {
	mylogfiles, err := listDir(path)
	if err != nil {
		//except OSError:
		//pass
	}
	if len(mylogfiles) == 0 {
		return map[string][]struct {
			s  string;
			ss []string
		}{}
	}
	ReverseSlice(mylogfiles)
	logentries := map[string][]struct {
		s  string;
		ss []string
	}{}
	for _, msgfunction := range mylogfiles {
		filename := filepath.Join(path, msgfunction)
		if !EBUILD_PHASES[msgfunction] {
			WriteMsg(fmt.Sprintf("!!! can't process invalid log file: %s\n", filename),
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
				WriteMsg(fmt.Sprintf("!!! malformed entry in "+
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

_msgbuffer = {}
func _elog_base(level, msg, phase="other", key=None, color=None, out=None) {

	global
	_msgbuffer

	if out == nil:
	out = sys.stdout

	if color == nil:
	color = "GOOD"

	msg = _unicode_decode(msg,
		encoding = _encodings['content'], errors = 'replace')

	formatted_msg = colorize(color, " * ") + msg + "\n"

	if out in(sys.stdout, sys.stderr):
	formatted_msg = _unicode_encode(formatted_msg,
		encoding = _encodings['stdio'], errors = 'backslashreplace')
	if sys.hexversion >= 0x3000000:
	out = out.buffer

	out.write(formatted_msg)

	if key !
	in
_msgbuffer:
	_msgbuffer[key] =
	{
	}
	if phase !
	in
	_msgbuffer[key]:
	_msgbuffer[key][phase] = []
	_msgbuffer[key][phase]=append(,(level, msg))
}

func collect_messages(key=None, phasefilter=None) {
	global
	_msgbuffer

	if key == nil:
	rValue = _msgbuffer
	_reset_buffer()
	else:
	rValue =
	{
	}
	if key in
_msgbuffer:
	if phasefilter == nil:
	rValue[key] = _msgbuffer.pop(key)
	else:
	rValue[key] =
	{
	}
	for phase
	in
phasefilter:
try:
	rValue[key][phase] = _msgbuffer[key].pop(phase)
	except
KeyError:
	pass
	if ! _msgbuffer[key]:
	del
	_msgbuffer[key]
	return rValue
}

func _reset_buffer() {
	global
	_msgbuffer

	_msgbuffer =
	{
	}
}

_functions = { "einfo": ("INFO", "GOOD"),
"elog": ("LOG", "GOOD"),
"ewarn": ("WARN", "WARN"),
"eqawarn": ("QA", "WARN"),
"eerror": ("ERROR", "BAD"),
}

type _make_msgfunction struct{
	_color, _level string
}

func NewMakeMsgFunction(level, color)*_make_msgfunction{
	m := &_make_msgfunction{}
	m._level = level
	m._color = color
	return m
}

func (m *_make_msgfunction) __call__(msg, phase="other", key=None, out=None) {
	_elog_base(m._level, msg, phase = phase,
		key = key, color = self._color, out=out)
}

for f in _functions{
setattr(sys.modules[__name__], f, _make_msgfunction(_functions[f][0], _functions[f][1]))
del f, _functions
}

// -------------------------------------------------- custom

func process(mysettings, key, logentries, fulltext) {
	elogfilename = portage.elog.mod_save.process(mysettings, key, logentries, fulltext)

	if ! mysettings.ValueDict["PORTAGE_ELOG_COMMAND"):
	raise
	portage.exception.MissingParameter("!!! Custom logging requested but PORTAGE_ELOG_COMMAND is not defined")
	else:
	mylogcmd = mysettings.ValueDict["PORTAGE_ELOG_COMMAND"]
	mylogcmd = mylogcmd.replace("${LOGFILE}", elogfilename)
	mylogcmd = mylogcmd.replace("${PACKAGE}", key)
	retval = portage.process.spawn_bash(mylogcmd)
	if retval != 0:
	raise
	portage.exception.PortageException("!!! PORTAGE_ELOG_COMMAND failed with exitcode %d" % retval)
	return
}

// -------------------------------------------------- echo


_items = []
func process(mysettings, key, logentries, fulltext) {
	global
	_items
	logfile = None
	if (key == mysettings.mycpv &&
	"PORTAGE_LOGDIR"
	in
	mysettings
	&&
	"PORTAGE_LOG_FILE"
	in
	mysettings):
	logfile = mysettings.ValueDict["PORTAGE_LOG_FILE"]
	_items=append(,(mysettings.ValueDict["ROOT"], key, logentries, logfile))
}

func finalize() {
	sys.stdout.flush()
	sys.stderr.flush()
	stderr = sys.stderr
try:
	sys.stderr = sys.stdout
	_finalize()
finally:
	sys.stderr = stderr
	sys.stdout.flush()
	sys.stderr.flush()
}

func _finalize() {
	global
	_items
	printer = EOutput()
	for root, key, logentries, logfile
	in
_items:
	print()
	if root == "/":
	printer.einfo(_("Messages for package %s:") %
		colorize("INFORM", key))
	else:
	printer.einfo(_("Messages for package %(pkg)s merged to %(root)s:") %
	{
		"pkg": colorize("INFORM", key), "root": root
	})
	if logfile !=nil:
	printer.einfo(_("Log file: %s") % colorize("INFORM", logfile))
	print()
	for phase
	in
EBUILD_PHASES:
	if phase !
	in
logentries:
	continue
	for msgtype, msgcontent
	in
	logentries[phase]:
	fmap =
	{
		"INFO": printer.einfo,
		"WARN": printer.ewarn,
		"ERROR": printer.eerror,
		"LOG": printer.einfo,
		"QA": printer.ewarn
	}
	if isinstance(msgcontent, basestring):
	msgcontent = [msgcontent]
	for line
	in
msgcontent:
	fmap[msgtype](line.strip("\n"))
	_items = []
	return
}

// --------------------------mail

func process(mysettings, key, logentries, fulltext) {
	if "PORTAGE_ELOG_MAILURI" in
mysettings:
	myrecipient = mysettings.ValueDict["PORTAGE_ELOG_MAILURI"].split()[0]
	else:
	myrecipient = "root@localhost"

	myfrom = mysettings.ValueDict["PORTAGE_ELOG_MAILFROM"]
	myfrom = myfrom.replace("${HOST}", socket.getfqdn())
	mysubject = mysettings.ValueDict["PORTAGE_ELOG_MAILSUBJECT"]
	mysubject = mysubject.replace("${PACKAGE}", key)
	mysubject = mysubject.replace("${HOST}", socket.getfqdn())

	action = _("merged")
	for phase
	in
logentries:
	if phase in
	["postrm", "prerm"]:
action = _("unmerged")
if action == _("unmerged"):
for phase in logentries:
if phase ! in ["postrm", "prerm", "other"]:
action = _("unknown")

mysubject = mysubject.replace("${ACTION}", action)

mymessage = portage.mail.create_message(myfrom, myrecipient, mysubject, fulltext)
try:
portage.mail.send_mail(mysettings, mymessage)
except PortageException as e:
WriteMsg("%s\n" % str(e), noiselevel = -1)

return
}

// --------------------------mail summary

_config_keys = ('PORTAGE_ELOG_MAILURI', 'PORTAGE_ELOG_MAILFROM',
'PORTAGE_ELOG_MAILSUBJECT',)
_items = {}
func process(mysettings, key, logentries, fulltext) {
	global
	_items
	time_str = _unicode_decode(
		time.strftime("%Y%m%d-%H%M%S %Z", time.localtime(time.time())),
		encoding = _encodings['content'], errors = 'replace')
	header = _(">>> Messages generated for package %(pkg)s by process %(pid)d on %(time)s:\n\n") % \
	{
		"pkg": key, "pid": os.getpid(), "time": time_str
	}
	config_root = mysettings.ValueDict["PORTAGE_CONFIGROOT"]

	config_dict =
	{
	}
	for k
	in
_config_keys:
	v = mysettings.ValueDict[k)
	if v !=nil:
	config_dict[k] = v

	config_dict, items = _items.setdefault(config_root, (config_dict,
	{
	}))
	items[key] = header + fulltext
}

func finalize() {
	global
	_items
	for mysettings, items
	in
	_items.values():
	_finalize(mysettings, items)
	_items.clear()
}

func _finalize(mysettings, items) {
	if len(items) == 0:
	return
	elif
	len(items) == 1:
	count = _("one package")
	else:
	count = _("multiple packages")
	if "PORTAGE_ELOG_MAILURI" in
mysettings:
	myrecipient = mysettings.ValueDict["PORTAGE_ELOG_MAILURI"].split()[0]
	else:
	myrecipient = "root@localhost"

	myfrom = mysettings.ValueDict["PORTAGE_ELOG_MAILFROM", "")
	myfrom = myfrom.replace("${HOST}", socket.getfqdn())
	mysubject = mysettings.ValueDict["PORTAGE_ELOG_MAILSUBJECT", "")
	mysubject = mysubject.replace("${PACKAGE}", count)
	mysubject = mysubject.replace("${HOST}", socket.getfqdn())

	mybody = _("elog messages for the following packages generated by "
	"process %(pid)d on host %(host)s:\n") % {"pid": os.getpid(), "host": socket.getfqdn()}
	for key
	in
items:
	mybody += "- %s\n" % key

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
	WriteMsg("Timeout in finalize() for elog system 'mail_summary'\n",
		noiselevel = -1)
	except
	PortageException
	as
e:
	WriteMsg("%s\n" % (e, ), noiselevel = -1)

	return
}

// ---------------------save


func process(mysettings, key, logentries, fulltext) {

	if mysettings.ValueDict["PORTAGE_LOGDIR"):
	logdir = NormalizePath(mysettings.ValueDict["PORTAGE_LOGDIR"])
	else:
	logdir = filepath.Join(string(os.PathSeparator), mysettings.ValueDict["EPREFIX"].lstrip(string(os.PathSeparator)),
		"var", "log", "portage")

	if ! pathIsDir(logdir):
	uid = -1
	if portage.data.secpass >= 2:
	uid = portage_uid
	ensure_dirs(logdir, uid = uid, gid = portage_gid, mode = 0o2770)

	cat, pf = portage.catsplit(key)

	elogfilename = pf + ":" + _unicode_decode(
		time.strftime("%Y%m%d-%H%M%S", time.gmtime(time.time())),
		encoding = _encodings['content'], errors = 'replace') + ".log"

	if "split-elog" in
	mysettings.features:
	log_subdir = filepath.Join(logdir, "elog", cat)
	elogfilename = filepath.Join(log_subdir, elogfilename)
	else:
	log_subdir = filepath.Join(logdir, "elog")
	elogfilename = filepath.Join(log_subdir, cat+':'+elogfilename)
	_ensure_log_subdirs(logdir, log_subdir)

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
	if portage.data.secpass >= 2:
	logfile_uid = elogdir_st.st_uid
	applyPermissions(elogfilename, logfile_uid, elogdir_gid,
		elogdir_grp_mode, 0, nil, nil)

	return elogfilename
}


// ------------------------save summary


func process(mysettings, key, logentries, fulltext) {
	if mysettings.ValueDict["PORTAGE_LOGDIR"]:
	logdir = NormalizePath(mysettings.ValueDict["PORTAGE_LOGDIR"])
	else:
	logdir = filepath.Join(string(os.PathSeparator), mysettings.ValueDict["EPREFIX"].lstrip(string(os.PathSeparator)),
		"var", "log", "portage")

	if ! pathIsDir(logdir):
	logdir_uid = -1
	if portage.data.secpass >= 2:
	logdir_uid = portage_uid
	ensure_dirs(logdir, uid = logdir_uid, gid = portage_gid, mode = 0o2770)

	elogdir = filepath.Join(logdir, "elog")
	_ensure_log_subdirs(logdir, elogdir)

	elogfilename = elogdir + "/summary.log"
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
	if portage.data.secpass >= 2:
	logfile_uid = elogdir_st.st_uid
	apply_permissions(elogfilename, uid = logfile_uid, gid = elogdir_gid,
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

func process(mysettings, key, logentries, fulltext) {
	syslog.openlog("portage", syslog.LOG_ERR|syslog.LOG_WARNING|syslog.LOG_INFO|syslog.LOG_NOTICE, syslog.LOG_LOCAL5)
	for phase
	in
EBUILD_PHASES:
	if ! phase
	in
logentries:
	continue
	for msgtype, msgcontent
	in
	logentries[phase]:
	if isinstance(msgcontent, basestring):
	msgcontent = [msgcontent]
	for line
	in
msgcontent:
	line = "%s: %s: %s" % (key, phase, line)
	if sys.hexversion < 0x3000000 &&
	!
	isinstance(line, bytes):
	line = line.encode(_encodings['content'],
		'backslashreplace')
	syslog.syslog(_pri[msgtype], line.rstrip("\n"))
	syslog.closelog()
}
