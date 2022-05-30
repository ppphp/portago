package util

import (
	"os"
	"path/filepath"
)

func FirstExisting(p string) string {
	for _, pa := range IterParents(p) {
		_, err := os.Lstat(pa)
		if err != nil {
			continue
		}
		return pa
	}
	return string(os.PathSeparator)
}

func IterParents(p string) []string {
	d := []string{}
	d = append(d, p)
	for p != string(os.PathSeparator) {
		p = filepath.Dir(p)
		d = append(d, p)
	}
	return d
}

// _path.py

// return access
func ExistsRaiseEaccess(path string) bool {
	_, err := os.Stat(path)
	return err != os.ErrPermission
}

// if access return
func IsdirRaiseEaccess(path string) bool {
	f, err := os.Stat(path)
	if err != nil {
		if err == os.ErrPermission {
			//raise PermissionDenied("stat('%s')" % path)
		}
		return false
	}
	return f.IsDir()
}
