package atom

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var disable = true
var _emerge_log_dir = "/var/log"

// ""
func emergelog(xterm_titles bool, mystr string, short_msg string) {
	if disable {
		return
	}
	if xterm_titles && len(short_msg) > 0 {
		if h, ok := os.LookupEnv("HOSTNAME"); ok {
			short_msg = h + ": " + short_msg
		}
		XtermTitle(short_msg, false)
	}

	//try:
	file_path := filepath.Join(_emerge_log_dir, "emerge.log")
	_, err := os.Stat(file_path)
	existing_log := err != nil
	mylogfile, _ := os.OpenFile(file_path, os.O_APPEND|os.O_WRONLY, 0644)
	if !existing_log {
		apply_secpass_permissions(
			file_path, uint32(*portage_uid), *portage_gid, 0660, -1, nil, true,
		)
	}
	mylock, _ := Lockfile(file_path, false, false, "", 0)
	_, err1 := mylogfile.Write([]byte(fmt.Sprintf("%.0f: %s\n", time.Now().Unix(), mystr)))
	if err1 == nil {
		mylogfile.Close()
	}
	Unlockfile(mylock)
	//except (IOError, OSError, portage.exception.PortageException) as e:
	//if secpass >= 1:
	//portage.util.writemsg("emergelog(): %s\n" % (e,), noiselevel=-1)
}
