package sync

import (
	"fmt"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util/grab"
	"github.com/ppphp/portago/pkg/util/msg"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func have_english_locale() bool {
	lang := time.Local.String()

	if lang != "" {
		lang = strings.ToLower(lang)
		lang = strings.SplitN(lang, "_", 1)[0]
	}
	return lang == "" || (lang == "c" || lang == "en")
}


func whenago(seconds int) string {
	sec := int(seconds)
	mins := 0
	days := 0
	hrs := 0
	years := 0
	out := []string{}

	if sec > 60 {
		mins = sec / 60
		sec = sec % 60
	}
	if mins > 60 {
		hrs = mins / 60
		mins = mins % 60
	}
	if hrs > 24 {
		days = hrs / 24
		hrs = hrs % 24
	}
	if days > 365 {
		years = days / 365
		days = days % 365
	}

	if years != 0{
		out = append(out, fmt.Sprintf("%dy ", years))
	}
	if days != 0{
		out = append(out, fmt.Sprintf("%dd ", days))
	}
	if hrs != 0{
		out = append(out, fmt.Sprintf("%dh ", hrs))
	}
	if mins!= 0 {
		out = append(out, fmt.Sprintf("%dm ", mins))
	}
	if sec != 0{
		out = append(out, fmt.Sprintf("%ds ", sec))
	}

	return strings.Join(out, "")
}

func Old_tree_timestamp_warn(portdir string, settings *config.Config) bool{
	unixtime := time.Now().Unix()
	default_warnsync := 30

	timestamp_file := filepath.Join(portdir, "metadata/timestamp.x")
//try:
	lastsync := grab.GrabFile(timestamp_file, 0, false, false)
	//except PortageException:
	//return false

	if len(lastsync)==0 {
		return false
	}

	lastsync1 := strings.Fields(lastsync[0][0])
	if len(lastsync1) == 0 {
		return false
	}

	lastsync2, err := strconv.Atoi(lastsync1[0])
	if err != nil {
		return false
	}

	var_name := "PORTAGE_SYNC_STALE"

	ws, ok := settings.ValueDict[var_name]
	if !ok {
		ws = fmt.Sprint(default_warnsync)
	}
	warnsync, err := strconv.ParseFloat(ws, 64)
	if err!= nil {
		msg.WriteMsgLevel(fmt.Sprintf("!!! %s contains non-numeric value: %s\n", var_name,settings.ValueDict[var_name]), 40, -1, )
		return false
	}

	if warnsync <= 0 {
		return false
	}

	if (int(unixtime) - int(86400*warnsync)) > lastsync2 {
		out := output.NewEOutput(false)
		if have_english_locale() {
			out.Ewarn(fmt.Sprintf(
			"Last emerge --sync was %v ago.",whenago(int(unixtime) - lastsync2)))
		}else {
			out.Ewarn(
				fmt.Sprintf("Last emerge --sync was %s.",
					time.Unix(int64(lastsync2), 0).String()))
		}
		return true
	}
	return false
}
