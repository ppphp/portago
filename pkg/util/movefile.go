package util

import (
	"bytes"
	"fmt"
	"github.com/pkg/xattr"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

func _apply_stat(srcStat os.FileInfo, dest string) error {
	err := os.Chown(dest, int(srcStat.Sys().(*syscall.Stat_t).Uid), int(srcStat.Sys().(*syscall.Stat_t).Gid))
	if err != nil {
		return err
	}
	return os.Chmod(dest, os.FileMode(srcStat.Sys().(*syscall.Stat_t).Mode))
}

func TextWrap(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}

var _xattr_excluder_cache = map[string]*_xattr_excluder{}

func _get_xattr_excluder(pattern string) *_xattr_excluder {
	value, ok := _xattr_excluder_cache[pattern]
	if !ok {
		value = New_xattr_excluder(pattern)
		_xattr_excluder_cache[pattern] = value
	}

	return value
}

type _xattr_excluder struct {
	_pattern_split []string
}

func New_xattr_excluder(pattern string) *_xattr_excluder {
	x := &_xattr_excluder{}
	if pattern == "" {
		x._pattern_split = nil
	} else {
		patterns := strings.Fields(pattern)
		if len(patterns) == 0 {
			x._pattern_split = nil
		} else {
			sort.Strings(patterns)
			x._pattern_split = patterns
		}
	}
	return x
}

func (x *_xattr_excluder) __call__(attr string) bool {
	if x._pattern_split == nil {
		return false
	}

	for _, x := range x._pattern_split {
		if m, _ := filepath.Match(attr, x); m {
			return true
		}
	}

	return false
}

// nil
func _copyxattr(src, dest, excludeS string) error {
	attrs, err := xattr.List(src)
	if err != nil {
		//if err != OperationNotSupported.errno:
		//raise
		attrs = []string{}
	}

	var exclude *_xattr_excluder
	if len(attrs) > 0 {
		exclude = _get_xattr_excluder(excludeS)
	}

	for _, attr := range attrs {
		if exclude.__call__(attr) {
			continue
		}
		raise_exception := false
		as, err := xattr.Get(src, attr)
		if err == nil {
			err = xattr.Set(dest, attr, as)
			raise_exception = false
		}
		if err != nil {
			//except(OSError, IOError):
			raise_exception = true
		}

		if raise_exception {
			//raise
			//OperationNotSupported(_("Filesystem containing file '%s' "
			//"does not support extended attribute '%s'") %
			//(_unicode_decode(dest), _unicode_decode(attr)))

			return fmt.Errorf("Filesystem containing file '%s' does not support extended attribute '%s'", dest, attr)
		}
	}
	return nil
}
