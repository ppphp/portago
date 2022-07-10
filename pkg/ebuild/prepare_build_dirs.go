package ebuild

import (
	"compress/gzip"
	"fmt"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/bad"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/util/permissions"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// myroot ignored, nil, false
func Prepare_build_dirs(settings *config.Config, cleanup bool) int {
	if settings == nil {
		//raise TypeError("settings argument is required")
	}

	mysettings := settings
	clean_dirs := []string{mysettings.ValueDict["HOME"]}

	if cleanup && !mysettings.Features.Features["keeptemp"] {
		clean_dirs = append(clean_dirs, mysettings.ValueDict["T"])
	}

	for _, clean_dir := range clean_dirs {
		if err := os.RemoveAll(clean_dir); err != nil {
			//except OSError as oe:
			if syscall.ENOENT == err {
				//pass
			} else if syscall.EPERM == err {
				msg.WriteMsg(fmt.Sprintf("%s\n", err), -1, nil)
				msg.WriteMsg(fmt.Sprintf("Operation Not Permitted: rmtree('%s')\n",
					clean_dir), -1, nil)
				return 1
			} else {
				bad.Raise_exc(err)
			}
		}
	}

	//makedirs:=func(dir_path string) bool {
	//	if err := os.MkdirAll(dir_path, 0755); err != nil {
	//		//except OSError as oe:
	//		if syscall.EEXIST == err {
	//			//pass
	//		} else if
	//		syscall.EPERM == err {
	//			WriteMsg(fmt.Sprintf("%s\n", err), -1, nil)
	//			WriteMsg(fmt.Sprintf("Operation Not Permitted: makedirs('%s')\n",
	//			dir_path),  -1, nil)
	//			return false
	//		} else {
	//			//raise
	//		}
	//	}
	//	return true
	//}

	mysettings.ValueDict["PKG_LOGDIR"] = filepath.Join(mysettings.ValueDict["T"], "logging")

	mydirs := []string{filepath.Dir(mysettings.ValueDict["PORTAGE_BUILDDIR"])}
	mydirs = append(mydirs, filepath.Dir(mydirs[len(mydirs)-1]))

	//try:
	for _, mydir := range mydirs {
		util.EnsureDirs(mydir, -1, -1, -1, -1, nil, true)
		//try:
		permissions.Apply_secpass_permissions(mydir, *data.Portage_gid, uint32(*data.Portage_uid), 0700, 0, nil, true)
		//except PortageException:
		//if not pathIsDir(mydir):
		//raise
		for _, dir_key := range []string{"HOME", "PKG_LOGDIR", "T"} {
			util.EnsureDirs(mysettings.ValueDict[dir_key], -1, -1, 0755, -1, nil, true)
			permissions.Apply_secpass_permissions(mysettings.ValueDict[dir_key], uint32(*data.Portage_uid), *data.Portage_gid, -1, -1, nil, true)
		}
	}
	//except PermissionDenied as e:
	//writemsg(_("Permission Denied: %s\n")%str(e), noiselevel = -1)
	//return 1
	//except OperationNotPermitted as e:
	//writemsg(_("Operation Not Permitted: %s\n")%str(e), noiselevel = -1)
	//return 1
	//except FileNotFound as e:
	//writemsg(_("File Not Found: '%s'\n")%str(e), noiselevel = -1)
	//return 1

	if err := syscall.Unlink(filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], ".dir_hooks")); err != nil {
		//except OSError:
		//pass
	}

	_prepare_workdir(mysettings)
	if !myutil.Ins([]string{"info", "fetch", "pretend"}, mysettings.ValueDict["EBUILD_PHASE"]) {
		_prepare_features_dirs(mysettings)
	}
	return 0
}

func _adjust_perms_msg(settings *config.Config, msg1 string) {

	write := func(msg1 string) {
		msg.WriteMsg(msg1, -1, nil)
	}

	background := settings.ValueDict["PORTAGE_BACKGROUND"] == "1"
	log_path := settings.ValueDict["PORTAGE_LOG_FILE"]
	var log_file io.Writer
	var log_file_real io.ReadWriteCloser

	if background && log_path != "" {
		var err error
		log_file_real, err = os.OpenFile(log_path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			//except IOError:
			write = func(msg string) {
				//pass
			}
		} else {
			log_file = log_file_real
			if strings.HasSuffix(log_path, ".gz") {
				log_file = gzip.NewWriter(log_file_real)
			}
			write = func(msg string) {
				log_file.Write([]byte((msg)))
			}
		}
	}
	//try:
	write(msg1)
	//finally:
	log_file_real.Close()
}
