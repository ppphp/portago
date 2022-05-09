package util

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type _defaultdict_tree struct{
	dd map[string]_defaultdict_tree
	pt []*_pattern
}

type InstallMask struct {
	_unanchored []*_pattern
	_anchored map[string][]*_pattern
}

type _pattern struct{
	orig_index int
	is_inclusive bool
	pattern string
	leading_slash bool
}

func NewInstallMask( install_mask string)*InstallMask {
	i := &InstallMask{}
	i._unanchored = []*_pattern{}

	i._anchored = _defaultdict_tree{}
	for orig_index, pattern := range strings.Fields(install_mask) {
		is_inclusive := !strings.HasPrefix(pattern, "-")
		if !is_inclusive {
			pattern = pattern[1:]
		}
		pattern_obj := &_pattern{orig_index, is_inclusive, pattern, strings.HasPrefix(pattern, "/")}
		if pattern_obj.leading_slash {
			current_dir := i._anchored
			for _, component:= range strings.Split(pattern, "/"){
				if component== ""{
					continue
				}
				if strings.Contains(component, "*"){
					break
				} else {
					current_dir = current_dir[component]
				}
				if _, ok := current_dir["."]; !ok {
					current_dir["."] = []*_pattern{}
				}

				current_dir["."]=append(current_dir["."], pattern_obj)
			}
		} else {
			i._unanchored = append(i._unanchored, pattern_obj)
		}
	}
	return i
}

func(i*InstallMask) _iter_relevant_patterns( path string) []*_pattern {
	current_dir := i._anchored
	components := []string{}
	for _, v := range strings.Split(path, "/"){
		components = append(components,v)
	}
	patterns := []*_pattern{}
	patterns= append(patterns, current_dir["."]...)
	for _, component:= range components {
		next_dir := current_dir[component]
		if next_dir == nil{
			break
		}
		current_dir = next_dir
		patterns = append(patterns, current_dir["."]...)
	}

	if len(patterns) > 0 {
		patterns= append(patterns, i._unanchored...)
		in := false
		for _, pattern := range patterns{
			if !pattern.is_inclusive{
				in = true
				break
			}
		}
		if in{
			patterns.sort(key = operator.attrgetter('orig_index'))
		}
		return patterns
	}

	return i._unanchored
}

func(i*InstallMask) match( path string) bool {
	ret := false

	for _, pattern_obj := range i._iter_relevant_patterns(path) {
		is_inclusive, pattern := pattern_obj.is_inclusive, pattern_obj.pattern
		if pattern_obj.leading_slash {
			if strings.HasSuffix(path,"/") {
				pattern = strings.TrimRight(pattern,"/") + "/"
			}
			if (fnmatch.fnmatch(path, pattern[1:]) ||
				fnmatch.fnmatch(path, pattern[1:].rstrip('/')+'/*')){
				ret = is_inclusive
			}
		} else {
			if fnmatch.fnmatch(filepath.Base(path), pattern) {
				ret = is_inclusive
			}
		}
	}
	return ret
}

var _exc_map = map[error]error{
	syscall.EISDIR: IsADirectory,
	syscall.ENOENT: FileNotFound,
	syscall.EPERM: OperationNotPermitted,
	syscall.EACCES: PermissionDenied,
	syscall.EROFS: ReadOnlyFileSystem,
}


func _raise_exc(e error){
	wrapper_cls := _exc_map[e]
	if wrapper_cls == nil {
		//raise
	}
	//wrapper = wrapper_cls(_unicode(e))
	//wrapper.__cause__ = e
	//raise wrapper
}

// nil
func install_mask_dir(base_dir string, install_mask *InstallMask, onerror func(error)) {
	if onerror == nil {
		onerror = _raise_exc
	}
	base_dir = NormalizePath(base_dir)
	base_dir_len := len(base_dir) + 1
	dir_stack := []string{}

	filepath.Walk(base_dir, func(path string, info os.FileInfo, err error) error {
		dir_stack = append(dir_stack, path)
		if !info.IsDir() {
			abs_path := filepath.Join(path, info.Name())
			relative_path := abs_path[base_dir_len:]
			if install_mask.match(relative_path) {
				if err := syscall.Unlink(abs_path); err != nil {
					//except OSError as e:
					onerror(err)
				}
			}
		}
		return nil
	})

	for len(dir_stack) > 0{
		dir_path := dir_stack[len(dir_stack)-1]
		dir_stack = dir_stack[:len(dir_stack)-1]

		if install_mask.match(dir_path[base_dir_len:] + "/") {
			if err := os.RemoveAll(dir_path); err != nil {
				//except OSError:
				//pass
			}
		}
	}
}
