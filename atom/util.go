package atom

// a colleciton of util in lib/portage/util

import (
	"bytes"
	"fmt"
	"github.com/google/shlex"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

var noiseLimit = 0

func writeMsg(mystr string, noiseLevel int, fd *os.File) {
	if fd == nil {
		fd = os.Stderr
	}
	if noiseLevel <= noiseLimit {
		fd.Write([]byte(mystr))
	}
}

func writeMsgStdout(mystr string, noiseLevel int) {
	writeMsg(mystr, noiseLevel, os.Stdout)
}

func writeMsgLevel(msg string, level, noiselevel int) {
	var fd *os.File
	if level >= 30 {
		fd = os.Stderr
	} else {
		fd = os.Stdout
	}
	writeMsg(msg, noiselevel, fd)
}

func grabFile(myFileName string, compatLevel int, recursive, rememberSourceFile bool) [][2]string {
	myLines := grabLines(myFileName, recursive, true)
	var newLines [][2]string

	for _, line := range myLines {
		x := line[0]
		sourceFile := line[1]
		myLine := strings.Fields(x)
		if x != "" && x[0] != '#' {
			tmp := []string{}
			for _, item := range myLine {
				if item[:1] != "#" {
					tmp = append(tmp, item)
				} else {
					break
				}
			}
			myLine = tmp
		}

		m := strings.Join(myLine, " ")
		if m == ""{
			continue
		}
		if m[0] == '#' {
			mylineTest := strings.SplitN(m,"<==", 1)
			if len(mylineTest) == 2 {
				myLinePotential := mylineTest[1]
				mylineTest = strings.Split(mylineTest[0], "##COMPAT==>")
				if len(mylineTest) == 2 {
					l, _ := strconv.Atoi(mylineTest[1])
					if compatLevel >= l {
						if rememberSourceFile {
							newLines = append(newLines, [2]string{myLinePotential, sourceFile})
						} else {
							newLines = append(newLines, [2]string{myLinePotential})
						}
					}
				}
				continue
			}
		}
		if rememberSourceFile {
			newLines = append(newLines, [2]string{m, sourceFile})
		} else {
			newLines = append(newLines, [2]string{m, ""})
		}
	}
	return newLines
}

func recursiveBasenameFileter(f string) bool {
	return (!strings.HasPrefix(f, ".")) && (!strings.HasSuffix(f, "~"))
}

func recursiveFileList(p string) []string {
	d, f := path.Split(p)
	stack := [][2]string{{d, f}}
	ret := make([]string, 0)
	for len(stack) > 0 {
		parent := stack[len(stack)-1][0]
		fname := stack[len(stack)-1][1]
		stack = stack[:len(stack)-1]
		fullPath := path.Join(parent, fname)
		st, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		if st.Mode().IsDir() {
			if VcsDirs[fname] || !recursiveBasenameFileter(fname) {
				continue
			}
			children, err := ioutil.ReadDir(fullPath)
			if err != nil {
				continue
			}
			for _, v := range children {
				stack = append(stack, [2]string{fullPath, v.Name()})
			}
		} else if st.Mode().IsRegular() {
			if !recursiveBasenameFileter(fname) {
				ret = append(ret, fullPath)
			}
		}
	}
	return ret
}

func doStat(fname string, followLinks bool) (os.FileInfo, error) {
	if followLinks {
		return os.Stat(fname)
	} else {
		return os.Lstat(fname)
	}
}

func grabLines(fname string, recursive, rememberSourceFile bool) [][2]string {
	mylines := make([][2]string, 0)
	if recursive {
		for _, f := range recursiveFileList(fname) {
			mylines = append(mylines, grabLines(f, false, rememberSourceFile)...)
		}
	} else {
		f, _ := os.Open(fname)
		s, _ := ioutil.ReadAll(f)
		lines := strings.Split(string(s), "\n")
		for _, l := range lines {
			if rememberSourceFile {
				mylines = append(mylines, [2]string{l, fname})
			} else {
				mylines = append(mylines, [2]string{l, ""})
			}
		}
	}
	return mylines
}

func stackDictlist(originalDicts []map[string][]string, incremental int, incrementals []string, ignoreNone int) map[string][]string{
	finalDict := map[string][]string{}
	for _, mydict := range originalDicts {
		if mydict == nil {
			continue
		}
		for y := range mydict {
			if _, ok := finalDict[y]; !ok {
				finalDict[y] = []string{}
			}
			for _, thing := range mydict[y] {
				if thing != "" {
					c := false
					for _, v := range incrementals {
						if v == y {
							c=true
							break
						}
					}
					if incremental != 0 || c {
						if thing == "-*" {
							finalDict[y] = []string{}
							continue
						} else if thing[:1] == "-" {
							tmp := []string{}
							for _, v := range finalDict[y] {
								if thing[:1] != v {
									tmp = append(tmp, v)
								}
							}
							finalDict[y] = tmp
							continue
						}
					}
					c2 := false
					for _, v := range finalDict[y]{
						if v == thing {
							c2 = true
							break
						}
					}
					if c2 {
						finalDict[y] = append(finalDict[y], thing)
					}
				}
			}
			if _, ok := finalDict[y]; ok && finalDict[y] != nil {
				delete(finalDict, y)
			}
		}
	}
	return finalDict
}

func stackDicts(dicts []map[string]string, incremental int, incrementals []string, ignoreNone int) map[string]string{
	finalDict := map[string]string {}
	for _, mydict := range dicts {
		if mydict == nil {
			continue
		}
		for k,v := range mydict {
			c := false
			for _, r := range incrementals {
				if r ==k {
					c = true
					break
				}
			}
			if _, ok := finalDict[k]; ok && incremental!= 0 && c {
				finalDict[k] += " "+v
			} else {}
			finalDict[k] = v
		}
	}
	return finalDict
}

func appendRepo(atomList []string, repoName string, rememberSourceFile bool) {
	if rememberSourceFile {

	}else {

	}
}

type SB struct{
	S string
	B bool
}

func stackLists(lists [][]SB, incremental int, rememberSourceFile, warnForUnmatchedRemoval, strictWarnForUnmatchedRemoval, ignoreRepo bool) {
	matchedRemovals := map[string]bool {}
	unmatchedRemovals := map[string]bool {}
	newList := []string{}
	for _, subList :=range lists{
		for _, token := range subList {
			tokenKey := token
			sourceFile := false
			t := token.S
			if rememberSourceFile {
				sourceFile = token.B
			} else {
				sourceFile = false
			}
			if t == "" {
				continue
			}
			if incremental != 0 {
				if t == "-*" {
					newList = []string{}
				} else if t[:1] == "-" {
					matched := false
					if ignoreRepo && !strings.Contains(t, "::") {
						toBeRemoved := []string{}
						tokenSlice := token[1:]
						for _, atom := range newList {
							atomWithoutRepo := atom
							if atom
						}
					}
				}
			}
		}
	}

}

type sss struct {
	S string
	SS []string
}
func findUpdatedConfigFiles(targetRoot string, configProtect []string) []sss {
	var ssss []sss
	if configProtect != nil {
		for _, x  := range configProtect {
			x = path.Join(targetRoot, strings.TrimPrefix(x, string(os.PathSeparator)))
			s, _ := os.Lstat(x)
			myMode := s.Mode()
			if myMode&unix.W_OK == 0 {
				continue
			}
			if myMode & os.ModeSymlink != 0 {
				realMode, _ := os.Stat(x)
				if realMode.IsDir() {
					myMode = realMode.Mode()
				}
			}
			myCommand := ""
			if myMode.IsDir() {
				myCommand = fmt.Sprintf("find '%s' -name '.*' -type d -prune -o -name '._cfg????_*'", x)
			} else {
				d, f := path.Split(strings.TrimSuffix(x, string(os.PathSeparator)))
				myCommand = fmt.Sprintf("find '%s' -maxdepth 1 -name '._cfg????_%s'", d, f)
			}
			myCommand += " ! -name '.*~' ! -iname '.*.bak' -print0"
			cmd, _ := shlex.Split(myCommand)
			if FindBinary(cmd[0]) == "" {
				return nil
			}
			c := exec.Command(FindBinary(cmd[0]), cmd[1:]...)
			var out, err bytes.Buffer
			c.Stdout = &out
			c.Stderr = &err
			if err := c.Run(); err != nil {
				return nil
			}
			o := out.String()
			files := strings.Split(o, `\0`)
			if files[len(files) - 1] == ""{
				files = files[:len(files)-1]
			}
			if len(files) > 0 {
				if myMode.IsDir() {
					ssss = append(ssss, sss{S:x, SS:files})
				} else {
					ssss = append(ssss, sss{S:x, SS:nil})
				}
			}
		}
	}
	return ssss
}

var ldSoIncludeRe = regexp.MustCompile(`^include\s+(\S.*)`)
func readLdSoConf(p string) []string {
	conf := []string{}
	for _, l := range grabFile(p, 0, false, false) {
		includeMatch := ldSoIncludeRe.MatchString(l[0])
		if includeMatch {
			subpath := path.Join(path.Dir(p),
				ldSoIncludeRe.FindStringSubmatch(l[0])[1])
			fg, _ := filepath.Glob(subpath)
			for _, q := range fg {
				for _, r := range readLdSoConf(q){
					conf = append(conf, r)
				}
			}
		}
		conf = append(conf, l[0])
	}
	return conf
}

func getLibPaths(root string, env map[string]string) []string {
	rval := []string{}
	if env == nil {
		rval = strings.Split(os.Getenv("LD_LIBRARY_PATH"), ":")
	} else {
		rval = strings.Split(env["LD_LIBRARY_PATH"], ":")
	}
	rval = append(rval, readLdSoConf(path.Join(root, "etc", "ld.so.conf"))...)
	rval = append(rval, "/usr/lib", "/lib")
	p := []string{}
	for _, x := range rval {
		p = append(p, NormalizePath(x))
	}
	return p
}

func uniqueArray(a []interface{}) []interface{} {
	m := make(map[interface{}]bool)
	for _, v := range a {
		m[v] = true
	}
	r := make([]interface{}, 0)
	for k := range m {
		r = append(r, k)
	}
	return r
}

func getCPUCount() int {
	return runtime.NumCPU()
}

// TODO: unix support by sysctl
func getVMInfo() map[string]uint64 {
	m := make(map[string]uint64)
	ms := runtime.MemStats{}
	runtime.ReadMemStats(&ms)
	m["ram.total"] = ms.TotalAlloc
	m["ram.free"] = ms.Frees
	si := syscall.Sysinfo_t{}
	_ = syscall.Sysinfo(&si)
	m["swap.total"] = si.Totalswap
	m["swap.total"] = si.Freeswap
	return m
}

// return access
func existsRaiseEaccess(path string) bool {
	_, err := os.Stat(path)
	return err != os.ErrPermission
}

// if access return
func isdirRaiseEaccess(path string) bool {
	f, err := os.Stat(path)
	if err != os.ErrPermission {
		return false
	}
	return f.IsDir()
}

type slotObject struct {
	weakRef string
}

func NormalizePath(mypath string) string {
	return path.Clean(mypath)
}

func applyPermissions(filename string, uid, gid, mode, mask int, statCached os.FileInfo, followLinks bool) {
	modified := false
	if statCached == nil{
		statCached, _ = doStat(filename, followLinks)
	}
	if (uid != -1 && uid != int(statCached.Sys().(*syscall.Stat_t).Uid))||(gid != -1 && gid != int(statCached.Sys().(*syscall.Stat_t).Gid))){
		if followLinks {
			syscall.Chown(filename, uid, gid)
		} else {
			os.Lchown(filename, uid, gid)
		}
		modified = true
	}// TODO check errno
	newMode := -1
	stMode :=  statCached.Mode()&07777
	if mask >=0 {
		if mode == -1 {
			mode = 0
		} else {
			mode = mode &07777
		}
		if (stMode&os.FileMode(mask) != os.FileMode(mode) ) || ((os.FileMode(mask)^stMode)&stMode != stMode) {
			newMode = mode | stMode
		}
	}
}

func ensureDirs(dirpath string, kwargs string) string {
	createdDir := false
	if err := os.MkdirAll(dirpath, 0755); err == nil {
		createdDir = true
	} // TODO check errno

}

func NewProjectFilename(mydest, newmd5 string, force bool) string{
	protNum := -1
	lastFile := ""
	if _, err := os.Open(mydest);!force&&!os.IsNotExist(err){
		return mydest
	}
	realFilename := path.Base(mydest)
	realDirname := path.Dir(mydest)
	files, _ := ioutil.ReadDir(realDirname)
	for _,pfile := range files {
		if pfile.Name()[0:5] != "._cfg" {
			continue
		}
		if pfile.Name()[10:] != realFilename{
			continue
		}
		newProtNum, _ := strconv.Atoi(pfile.Name()[5:9])
		if newProtNum > protNum {
			protNum = newProtNum
			lastFile = pfile.Name()
		}
	}
	protNum ++
	newPfile := NormalizePath(path.Join(realDirname, ".cfg"+fmt.Sprintf("%04s",string(protNum))+"_"+realFilename))
	oldPfile := NormalizePath(path.Join(realDirname, lastFile))
	if len(lastFile) != 0 && len(newmd5) != 0{
		oldPfileSt,err := os.Lstat(oldPfile)
		if err != nil {
			if oldPfileSt.Mode() & os.ModeSymlink != 0{
				pfileLink, err := os.Readlink(oldPfile)
				if err != nil {
					if pfileLink == newmd5{
						return oldPfile
					}
				}
			} else {
				//lastPfileMd5 := string(performMd5Merge(oldPfile, 0))
			}
		}
	}
	return newPfile
}
