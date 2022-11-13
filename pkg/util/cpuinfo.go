package util

import (
	"regexp"
	"runtime"
	"strconv"
)

func GetCPUCount() int {
	return runtime.NumCPU()
}

func makeopts_to_job_count(makeopts string) int {
	if makeopts == "" {
		return GetCPUCount()
	}

	jobs := regexp.MustCompile(".*(j|--jobs=\\s)\\s*([0-9]+)").FindAllString(makeopts, -1)

	if len(jobs) == 0 {
		return GetCPUCount()
	}

	j, _ := strconv.Atoi(jobs[1])
	return j
}
