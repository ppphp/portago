package elog

import (
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/util/permissions"
	"github.com/ppphp/portago/pkg/versions"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func save_process(mysettings *config.Config, key string, logentries map[string][]struct {s string;ss []string}, fulltext string) string {
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

	cat, pf := versions.CatSplit(key)[0], versions.CatSplit(key)[1]

	elogfilename := pf + ":" + time.Now().Format("20060102-150405")

	log_subdir := ""
	if mysettings.Features.Features["split-elog"] {
		log_subdir = filepath.Join(logdir, "elog", cat)
		elogfilename = filepath.Join(log_subdir, elogfilename)
	}else {
		log_subdir = filepath.Join(logdir, "elog")
		elogfilename = filepath.Join(log_subdir, cat+":"+elogfilename)
	}
	ebuild.Ensure_log_subdirs(logdir, log_subdir)

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
	if *data.Secpass >= 2:
	logfile_uid = elogdir_st.st_uid
	permissions.ApplyPermissions(elogfilename, logfile_uid, elogdir_gid,
		elogdir_grp_mode, 0, nil, nil)

	return elogfilename
}
