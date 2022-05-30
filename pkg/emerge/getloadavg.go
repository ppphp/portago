package emerge

import (
	"errors"
	"io/ioutil"
	"strconv"
	"strings"
)

func getloadavg() (float64, float64, float64, error) {
	f, err := ioutil.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	loadavg_str := strings.Split(string(f), "\n")[0]
	loadavg_split := strings.Fields(loadavg_str)
	if len(loadavg_split) < 3 {
		//raise OSError('unknown')
		return 0, 0, 0, errors.New("unknown")
	}
	f0, err := strconv.ParseFloat(loadavg_split[0], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	f1, err := strconv.ParseFloat(loadavg_split[1], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	f2, err := strconv.ParseFloat(loadavg_split[2], 64)
	if err != nil {
		return 0, 0, 0, err
	}
	return f0, f1, f2, nil
}
