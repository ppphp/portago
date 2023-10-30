package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type FsBased struct {
	database
	gid   int
	perms int
}

func NewFsBased(args ...interface{}) *FsBased {
	config := args[len(args)-1].(map[string]interface{})
	fs := &FsBased{
		gid:   -1,
		perms: 0o644,
	}
	for _, v := range []string{"gid", "perms"} {
		if x, ok := config[v]; ok {
			switch v {
			case "gid":
				fs.gid = int(x.(float64))
			case "perms":
				fs.perms = int(x.(float64))
			}
			delete(config, v)
		}
	}
	fs.database = *NewDatabase(args...)
	if fs.label[0] == os.PathSeparator {
		fs.label = os.PathSeparator + filepath.ToSlash(filepath.Clean(fs.label))
	}
	return fs
}

func (fs *FsBased) _ensure_access(path string, mtime int) bool {
	if err := apply_permissions(path, fs.gid, fs.perms); err != nil {
		return false
	}
	if mtime != -1 {
		os.Chtimes(path, mtime, mtime)
	}
	return true
}

func (fs *FsBased) _ensure_dirs(path string) {
	if path != "" {
		path = filepath.Dir(path)
		base := fs.location
	} else {
		path = fs.location
		base = "/"
	}
	for _, d := range strings.Split(strings.Trim(path, os.PathSeparator), os.PathSeparator) {
		base = filepath.Join(base, d)
		if ensure_dirs(base) {
			mode := fs.perms
			if mode == -1 {
				mode = 0
			}
			mode |= 0o755
			apply_permissions(base, mode, fs.gid)
		}
	}
}

func (fs *FsBased) _prune_empty_dirs() {
	all_dirs := []string{}
	filepath.Walk(fs.location, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			all_dirs = append(all_dirs, path)
		}
		return nil
	})
	for len(all_dirs) > 0 {
		if err := os.Remove(all_dirs[len(all_dirs)-1]); err != nil {
			break
		}
		all_dirs = all_dirs[:len(all_dirs)-1]
	}
}

func gen_label(base, label string) string {
	if strings.IndexByte(label, os.PathSeparator) == -1 {
		return label
	}
	label = strings.Trim(label, "\"'")
	label = filepath.ToSlash(filepath.Clean(label))
	tail := filepath.Base(label)
	return fmt.Sprintf("%s-%X", tail, abs(hash(label)))
}
