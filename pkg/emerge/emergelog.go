package emerge

import "os"

var disable = true
var _emerge_log_dir = "/var/log"

func emergelog(xterm_titles bool, mystr string, short_msg string) { // ""
	if disable {
		return
	}
	if xterm_titles && len(short_msg) > 0 {
		if h, ok := os.LookupEnv("HOSTNAME"); ok {
			short_msg = h + ": " + short_msg
		}
		//xtermTitle(short_msg)
	}

}
