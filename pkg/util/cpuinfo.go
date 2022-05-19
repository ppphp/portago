package util

import "runtime"

func GetCPUCount() int {
	return runtime.NumCPU()
}
