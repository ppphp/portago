package util

import (
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/myutil"
	"os"
	"path/filepath"
	"syscall"
)

// true
func cacheddir(myOriginalPath string, ignoreCvs bool, ignoreList []string, EmptyOnError, followSymlinks bool) ([]string, []int) {
	myPath := NormalizePath(myOriginalPath)
	pathStat, err := os.Stat(myPath)
	if err != nil {
		//except EnvironmentError as e:
		//if err == PermissionDenied.errno:
		//raise PermissionDenied(myPath)
		//del e
		//return [], []
		//except PortageException:
		return []string{}, []int{}
	}
	if !pathStat.IsDir() {
		//raise DirectoryNotFound(myPath)
	}
	d, err := os.Open(myPath)
	var fpaths []os.FileInfo
	if err == nil {
		fpaths, err = d.Readdir(-1)
	}
	if err != nil {
		//except EnvironmentError as e:
		//if err != syscall.EACCES:
		//raise
		//del e
		//raise PermissionDenied(myPath)
	}
	ftype := []int{}
	for _, x := range fpaths {
		var err error
		if followSymlinks {
			pathStat, err = os.Stat(myPath + "/" + x.Name())
		} else {
			pathStat, err = os.Lstat(myPath + "/" + x.Name())
		}
		if err == nil {
			if pathStat.Mode()&syscall.S_IFREG != 0 { // is reg
				ftype = append(ftype, 0)
			} else if pathStat.IsDir() {
				ftype = append(ftype, 1)
			} else if pathStat.Mode()&syscall.S_IFLNK != 0 {
				ftype = append(ftype, 2)
			} else {
				ftype = append(ftype, 3)
			}
		}

		if err != nil {
			//except (IOError, OSError){
			ftype = append(ftype, 3)
		}
	}

	retList := []string{}
	retFtype := []int{}
	if len(ignoreList) > 0 || ignoreCvs {
		for i, filePath := range fpaths {
			fileType := ftype[i]

			if myutil.Ins(ignoreList, filePath.Name()) {
			} else if ignoreCvs {
				if filePath.Name()[:2] != ".#" && !(fileType == 1 && _const.VcsDirs[filePath.Name()]) {
					retList = append(retList, filePath.Name())
					retFtype = append(retFtype, fileType)
				}
			}
		}
	} else {
		for _, f := range fpaths {
			retList = append(retList, f.Name())
		}
		retFtype = ftype
	}
	return retList, retFtype
}

// false, false, false, []string{}, true, false, false
func listdir(myPath string, recursive, filesOnly, ignoreCvs bool, ignorelist []string, followSymlinks, EmptyOnError, dirsOnly bool) []string {
	fpaths, ftype := cacheddir(myPath, ignoreCvs, ignorelist, EmptyOnError, followSymlinks)
	if fpaths == nil {
		fpaths = []string{}
	}
	if ftype == nil {
		ftype = []int{}
	}

	if !(filesOnly || dirsOnly || recursive) {
		return fpaths
	}

	if recursive {
		stack := []struct {
			string
			int
		}{}
		for i := range fpaths {
			stack = append(stack, struct {
				string
				int
			}{string: fpaths[i], int: ftype[i]})
		}
		fpaths = []string{}
		ftype = []int{}
		for len(stack) > 0 {
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			filePath, fileType := f.string, f.int
			fpaths = append(fpaths, filePath)
			ftype = append(ftype, fileType)
			if fileType == 1 {
				subdirList, subdirTypes := cacheddir(
					filepath.Join(myPath, filePath), ignoreCvs,
					ignorelist, EmptyOnError, followSymlinks)
				for i := range subdirList {
					x := subdirList[i]
					xType := subdirTypes[i]
					stack = append(stack, struct {
						string
						int
					}{filepath.Join(filePath, x), xType})
				}
			}
		}
	}

	if filesOnly {
		f := []string{}
		for i := range fpaths {
			x := fpaths[i]
			xType := ftype[i]
			if xType == 0 {
				f = append(f, x)
			}
		}
		fpaths = f
	} else if dirsOnly {
		f := []string{}
		for i := range fpaths {
			x := fpaths[i]
			xType := ftype[i]
			if xType == 1 {
				f = append(f, x)
			}
		}
		fpaths = f
	}

	return fpaths
}
