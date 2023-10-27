package dbapi

import (
	"syscall"
)

type SyncfsProcess struct {
	ForkProcess
	paths []string
}

func (p *SyncfsProcess) _get_syncfs() uintptr {
	lib, err := syscall.LoadLibrary("c")
	if err != nil {
		return 0
	}
	syncfs, err := syscall.GetProcAddress(lib, "syncfs")
	if err != nil {
		return 0
	}
	return syncfs
}

func (p *SyncfsProcess) _run() int {
	syncfs_failed := false
	syncfs := p._get_syncfs()

	if syncfs != 0 {
		for _, path := range p.paths {
			fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
			if err != nil {
				continue
			}
			if _, _, err := syscall.Syscall(syncfs, uintptr(fd), 0, 0); err != 0 {
				syncfs_failed = true
			}
			syscall.Close(fd)
		}
	}

	if syncfs == 0 || syncfs_failed {
		return 1
	}
	return 0
}
