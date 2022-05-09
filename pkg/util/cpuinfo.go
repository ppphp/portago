package util

import "runtime"

func getCPUCount() int {
	return runtime.NumCPU()
}
