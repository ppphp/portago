package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/process"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/noaway/dateparse"
	"github.com/pkg/xattr"
	"github.com/ppphp/configparser"
	"github.com/ppphp/shlex"
)

var noiseLimit = 0

//0, nil
func WriteMsg(myStr string, noiseLevel int, fd *os.File) {
	if fd == nil {
		fd = os.Stderr
	}
	if noiseLevel <= noiseLimit {
		fd.Write([]byte(myStr))
	}
}

// 0
func WriteMsgStdout(myStr string, noiseLevel int) {
	WriteMsg(myStr, noiseLevel, os.Stdout)
}

// 0, 0
func WriteMsgLevel(msg string, level, noiseLevel int) {
	var fd *os.File
	if level >= 30 {
		fd = os.Stderr
	} else {
		fd = os.Stdout
	}
	WriteMsg(msg, noiseLevel, fd)
}

func NormalizePath(myPath string) string {
	return path.Clean(myPath)
}

// 0, false, false
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
		if m == "" {
			continue
		}
		if m[0] == '#' {
			myLineTest := strings.SplitN(m, "<==", 1)
			if len(myLineTest) == 2 {
				myLinePotential := myLineTest[1]
				myLineTest = strings.Split(myLineTest[0], "##COMPAT==>")
				if len(myLineTest) == 2 {
					l, _ := strconv.Atoi(myLineTest[1])
					if compatLevel >= l {
						if rememberSourceFile {
							newLines = append(newLines, [2]string{myLinePotential, sourceFile})
						} else {
							newLines = append(newLines, [2]string{myLinePotential})
						}
					}
				}
				continue
			} else {
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

func mapDictListVals(f func(string) string, mydict map[string][]string) {
	newDl := map[string][]string{}
	for key := range mydict {
		newDl[key] = []string{}
		for _, x := range mydict[key] {
			newDl[key] = append(newDl[key], f(x))
		}
	}
}

// false, []string{}, false
func stackDictList(originalDicts []map[string][]string, incremental int, incrementalS []string, ignoreNone int) map[string][]string {
	finalDict := map[string][]string{}
	for _, myDict := range originalDicts {
		if myDict == nil {
			continue
		}
		for y := range myDict {
			if _, ok := finalDict[y]; !ok {
				finalDict[y] = []string{}
			}
			for _, thing := range myDict[y] {
				if thing != "" {
					c := false
					for _, v := range incrementalS {
						if v == y {
							c = true
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
					for _, v := range finalDict[y] {
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

func stackDicts(dicts []map[string]string, incremental int, incrementals map[string]bool, ignoreNone int) map[string]string { // 0[]0
	finalDict := map[string]string{}
	for _, myDict := range dicts {
		if myDict == nil {
			continue
		}
		for k, v := range myDict {
			c := false
			for r := range incrementals {
				if r == k {
					c = true
					break
				}
			}
			if _, ok := finalDict[k]; ok && incremental != 0 && c {
				finalDict[k] += " " + v
			} else {
			}
			finalDict[k] = v
		}
	}
	return finalDict
}

type SB struct {
	S string
	B bool
}

type AS struct {
	A *atom.Atom
	S string
}

func appendRepo(atomList map[*atom.Atom]string, repoName string, rememberSourceFile bool) []AS {
	sb := []AS{}
	if rememberSourceFile {
		for atom, source := range atomList {
			if atom.repo != "" && atom != nil {
				sb = append(sb, AS{atom, source})
			} else if a := atom.withRepo(repoName); a != nil {
				sb = append(sb, AS{a, source})
			} else {
				sb = append(sb, AS{nil, source})
			}
		}
	} else {
		for atom := range atomList {
			if atom.repo != "" && atom != nil {
				sb = append(sb, AS{atom, ""})
			} else if a := atom.withRepo(repoName); a != nil {
				sb = append(sb, AS{a, ""})
			} else {
				sb = append(sb, AS{nil, ""})
			}
		}
	}
	return sb
}

func stackLists(lists [][][2]string, incremental int, rememberSourceFile, warnForUnmatchedRemoval, strictWarnForUnmatchedRemoval, ignoreRepo bool) map[*atom.Atom]string { //1,false,false,false,false
	matchedRemovals := map[[2]string]bool{}
	unmatchedRemovals := map[string][]string{}
	newList := map[*atom.Atom]string{}
	for _, subList := range lists {
		for _, t := range subList {
			tokenKey := t
			token := t[0]
			sourceFile := ""
			if rememberSourceFile {
				sourceFile = t[1]
			} else {
				sourceFile = ""
			}
			if token == "" {
				continue
			}
			if incremental != 0 {
				if token == "-*" {
					newList = map[*atom.Atom]string{}
				} else if token[:1] == "-" {
					matched := false
					if ignoreRepo && !strings.Contains(token, "::") {
						toBeRemoved := []*atom.Atom{}
						tokenSlice := token[1:]
						for atom := range newList {
							atomWithoutRepo := atom.value
							if atom.repo != "" {
								atomWithoutRepo = strings.Replace(atom.value, "::"+atom.repo, "", 1)
							}
							if atomWithoutRepo == tokenSlice {
								toBeRemoved = append(toBeRemoved, atom)
							}
						}
						if len(toBeRemoved) != 0 {
							for _, atom := range toBeRemoved {
								delete(newList, atom)
							}
							matched = true
						}
					} else {
						for v := range newList {
							if v.value == token[1:] {
								delete(newList, v)
								matched = true
							}
						}
					}
					if !matched {
						if sourceFile != "" && (strictWarnForUnmatchedRemoval || !matchedRemovals[tokenKey]) {
							if unmatchedRemovals[sourceFile] == nil {
								unmatchedRemovals[sourceFile] = []string{token}
							} else {
								unmatchedRemovals[sourceFile] = append(unmatchedRemovals[sourceFile], token)
							}
						}
					} else {
						matchedRemovals[tokenKey] = true
					}
				} else {
					newList[&atom.Atom{value: token}] = sourceFile
				}
			} else {
				newList[&atom.Atom{value: token}] = sourceFile
			}
		}
	}
	if warnForUnmatchedRemoval {
		for sourceFile, tokens := range unmatchedRemovals {
			if len(tokens) > 3 {
				selected := []string{tokens[len(tokens)-1], tokens[len(tokens)-2], tokens[len(tokens)-3]}
				tokens = tokens[:len(tokens)-3]
				WriteMsg(fmt.Sprintf("--- Unmatched removal atoms in %s: %s and %v more\n", sourceFile, strings.Join(selected, ", "), len(tokens)), -1, nil)
			} else {
				WriteMsg(fmt.Sprintf("--- Unmatched removal Atom(s) in %s: %s\n", sourceFile, strings.Join(tokens, ", ")), -1, nil)
			}
		}
	}
	return newList
}

// false, false, false, true, false
func grabDict(myFileName string, justStrings, empty, recursive, incremental, newLines bool) map[string][]string {
	newDict := map[string][]string{}
	for _, x := range grabLines(myFileName, recursive, false) {
		v := x[0]
		if strings.HasPrefix(v, "#") {
			continue
		}
		myLine := strings.Fields(v)
		myLineTemp := []string{}
		for _, item := range myLine {
			if item[:1] != "#" {
				myLineTemp = append(myLineTemp, item)
			} else {
				break
			}
		}
		myLine = myLineTemp
		if len(myLine) < 2 && !empty {
			continue
		}
		if len(myLine) < 1 && empty {
			continue
		}
		if newLines {
			myLine = append(myLine, "\n")
		}
		if incremental {
			if _, ok := newDict[myLine[0]]; !ok {
				newDict[myLine[0]] = []string{}
			}
			newDict[myLine[0]] = myLine[1:]
		} else {
			newDict[myLine[0]] = myLine[1:]
		}
	}
	if justStrings {
		for k, v := range newDict {
			newDict[k] = []string{strings.Join(v, " ")}
		}
	}
	return newDict
}

var eapiFileCache = map[string]string{}

func readCorrespondingEapiFile(filename, defaults string) string { // "0"
	eapiFile := path.Join(path.Dir(filename), "eapi")
	eapi, ok := eapiFileCache[eapiFile]
	if ok {
		if eapi != "" {
			return eapi
		} else {
			return defaults
		}
	}
	eapi = ""
	f, err := os.Open(eapiFile)
	if err == nil {
		r, err := ioutil.ReadAll(f)
		if err == nil {
			lines := strings.Split(string(r), "\n")
			if len(lines) == 2 {
				eapi = strings.TrimSuffix(lines[0], "\n")
			} else {
				WriteMsg(fmt.Sprintf("--- Invalid 'eapi' file (doesn't contain exactly one line): %s\n", eapiFile), -1, nil)
			}
		}
	}

	eapiFileCache[eapiFile] = eapi
	if eapi == "" {
		return defaults
	}
	return eapi
}

func grabDictPackage(myfilename string, juststrings, recursive, newlines bool, allowWildcard, allowRepo, allowBuildId, allowUse, verifyEapi bool, eapi, eapiDefault string) map[*atom.Atom][]string { //000ffftf none 0
	fileList := []string{}
	if recursive {
		fileList = RecursiveFileList(myfilename)
	} else {
		fileList = []string{myfilename}
	}
	atoms := map[*atom.Atom][]string{}
	var d map[string][]string
	for _, filename := range fileList {
		d = grabDict(filename, false, true, false, true, newlines)
		if len(d) == 0 {
			continue
		}
		if verifyEapi && eapi == "" {
			eapi = readCorrespondingEapiFile(myfilename, eapiDefault)
		}
		for k, v := range d {
			a, err := atom.NewAtom(k, nil, allowWildcard, &allowRepo, nil, eapi, nil, &allowBuildId)
			if err != nil {
				WriteMsg(fmt.Sprintf("--- Invalid Atom in %s: %s\n", filename, err), -1, nil)
			} else {
				if !allowUse && a.Use != nil {
					WriteMsg(fmt.Sprintf("--- Atom is not allowed to have USE flag(s) in %s: %s\n", filename, k), -1, nil)
					continue
				}
				if atoms[a] == nil {
					atoms[a] = v
				} else {
					atoms[a] = append(atoms[a], v...)
				}
			}
		}
	}
	if juststrings {
		for k, v := range atoms {
			atoms[k] = []string{strings.Join(v, " ")}
		}
	}
	return atoms
}

func grabFilePackage(myFileName string, compatLevel int, recursive, allowWildcard, allowRepo, allowBuildId, rememberSourceFile, verifyEapi bool, eapi, eapiDefault string) [][2]string { // 0,false,false,false,false,false,false,nil,0
	pkgs := grabFile(myFileName, compatLevel, recursive, true)
	if len(pkgs) == 0 {
		return pkgs
	}
	if verifyEapi && eapi == "" {
		eapi = readCorrespondingEapiFile(myFileName, eapiDefault)
	}
	myBaseName := path.Base(myFileName)
	isPackagesFile := myBaseName == "packages"
	atoms := [][2]string{}
	for _, v := range pkgs {
		pkg := v[0]
		sourceFile := v[1]
		pkgOrig := pkg
		if pkg[:1] == "-" {
			if isPackagesFile && pkg == "-*" {
				if rememberSourceFile {
					atoms = append(atoms, [2]string{pkg, sourceFile})
				} else {
					atoms = append(atoms, [2]string{pkg, ""})
				}
			}
		}
		if isPackagesFile && pkg[:1] == "*" {
			pkg = pkg[1:]
		}

		if _, err := atom.NewAtom(pkg, nil, allowWildcard, &allowRepo, nil, eapi, nil, &allowBuildId); err != nil {
			WriteMsg(fmt.Sprintf("--- Invalid Atom in %s: %s\n", sourceFile, err), -1, nil)
		} else {
			if pkgOrig == pkg {
				if rememberSourceFile {
					atoms = append(atoms, [2]string{pkg, sourceFile})
				} else {
					atoms = append(atoms, [2]string{pkg, ""})
				}
			} else {
				if rememberSourceFile {
					atoms = append(atoms, [2]string{pkgOrig, sourceFile})
				} else {
					atoms = append(atoms, [2]string{pkgOrig, ""})
				}
			}
		}
	}
	return atoms
}

func recursiveBasenameFilter(f string) bool {
	return (!strings.HasPrefix(f, ".")) && (!strings.HasSuffix(f, "~"))
}

func RecursiveFileList(p string) []string {
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
			if _const.VcsDirs[fname] || !recursiveBasenameFilter(fname) {
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
			if recursiveBasenameFilter(fname) {
				ret = append(ret, fullPath)
			}
		}
	}
	return ret
}

func grabLines(fname string, recursive, rememberSourceFile bool) [][2]string { // 0f
	myLines := make([][2]string, 0)
	if recursive {
		for _, f := range RecursiveFileList(fname) {
			myLines = append(myLines, grabLines(f, false, rememberSourceFile)...)
		}
	} else {
		f, _ := os.Open(fname)
		s, _ := ioutil.ReadAll(f)
		lines := strings.Split(string(s), "\n")
		for _, l := range lines {
			if rememberSourceFile {
				myLines = append(myLines, [2]string{l, fname})
			} else {
				myLines = append(myLines, [2]string{l, ""})
			}
		}
	}
	return myLines
}

func doStat(fname string, followLinks bool) (os.FileInfo, error) {
	if followLinks {
		return os.Stat(fname)
	} else {
		return os.Lstat(fname)
	}
}

type ConfigProtect struct {
	myroot                                        string
	protect, protect_list, mask_list, protectmask []string
	case_insensitive                              bool
	_dirs                                         map[string]bool
}

func (c *ConfigProtect) updateprotect() {
	c.protect = []string{}
	c._dirs = map[string]bool{}
	for _, x := range c.protect_list {
		ppath := NormalizePath(
			filepath.Join(c.myroot, strings.TrimLeft(x, string(os.PathSeparator))))
		if st, _ := os.Stat(filepath.Dir(ppath)); st != nil && st.IsDir() {
			c.protect = append(c.protect, ppath)
		}
		if st, err := os.Stat(ppath); err != nil {
			//except OSError:
			//pass
		} else if st.IsDir() {
			c._dirs[ppath] = true
		}
	}

	c.protectmask = []string{}
	for _, x := range c.mask_list {
		ppath := NormalizePath(
			filepath.Join(c.myroot, strings.TrimLeft(x, string(os.PathSeparator))))
		if c.case_insensitive {
			ppath = strings.ToLower(ppath)
			st, err := os.Lstat(ppath)
			if err == nil {
				if st.IsDir() {
					c._dirs[ppath] = true
				}
			}
			c.protectmask = append(c.protectmask, ppath)
			st, err = os.Stat(ppath)
			if err == nil {
				c._dirs[ppath] = true
			}
			if err != nil {
				//except OSError:
				//	pass
			}
		}
	}
}

func (c *ConfigProtect) IsProtected(obj string) bool {
	masked := 0
	protected := 0
	sep := string(os.PathSeparator)
	if c.case_insensitive {
		obj = strings.ToLower(obj)
	}
	for _, ppath := range c.protect {
		if len(ppath) > masked && strings.HasPrefix(obj, ppath) {
			if c._dirs[ppath] {
				if obj != ppath && strings.HasPrefix(obj, ppath+sep) {
					continue
				} else if obj != ppath {
					continue
				}
				protected = len(ppath)
				for _, pmpath := range c.protectmask {
					if len(pmpath) >= protected && strings.HasPrefix(obj, pmpath) {
						if c._dirs[pmpath] {
							if obj != pmpath &&
								!strings.HasPrefix(obj, pmpath+sep) {
								continue
							}
						} else if obj != pmpath {
							continue
						}
						masked = len(pmpath)
					}
				}
			}
		}
	}
	return protected > masked
}

// false
func NewConfigProtect(myroot string, protectList, maskList []string,
	caseInsensitive bool) *ConfigProtect {
	c := &ConfigProtect{}

	c.myroot = myroot
	c.protect_list = protectList
	c.mask_list = maskList
	c.case_insensitive = caseInsensitive
	c.updateprotect()
	return c
}

// "", false
func new_protect_filename(myDest, newMd5 string, force bool) string {
	protNum := -1
	lastPfile := ""
	if st, _ := os.Stat(myDest); !force && st == nil {
		return myDest
	}

	realFilename := filepath.Base(myDest)
	realDirname := filepath.Dir(myDest)
	rds, _ := ioutil.ReadDir(realDirname)
	for _, pfile := range rds {
		if pfile.Name()[0:5] != "._cfg" {
			continue
		}
		if pfile.Name()[10:] != realFilename {
			continue
		}
		newProtNum, err := strconv.Atoi(pfile.Name()[5:9])
		if err != nil {
			//except ValueError:
			continue
		} else {
			if newProtNum > protNum {
				protNum = newProtNum
				lastPfile = pfile.Name()
			}
		}
	}

	protNum = protNum + 1
	newPfile := NormalizePath(filepath.Join(realDirname,
		"._cfg"+fmt.Sprintf("%04d", protNum)+"_"+realFilename))
	oldPfile := NormalizePath(filepath.Join(realDirname, lastPfile))
	if lastPfile != "" && newMd5 != "" {
		oldPfileSt, err := os.Lstat(oldPfile)
		if err != nil {
			//except OSError as e:
			if err != syscall.ENOENT {
				//raise
			}
		} else {
			if oldPfileSt.Mode()&os.ModeSymlink != 0 {
				pfileLink, err := os.Readlink(oldPfile)
				if err != nil {
					//except OSError:
					if err != syscall.ENOENT {
						//raise
					}
				}
				if pfileLink == newMd5 {
					return oldPfile
				}
			} else {
				lastPfileMd5 := atom.performMd5Merge(oldPfile, false)
				//except FileNotFound:
				//pass
				//else{
				if string(lastPfileMd5) == newMd5 {
					return oldPfile
				}
			}
		}
	}
	return newPfile
}

type sss struct {
	S  string
	SS []string
}

func findUpdatedConfigFiles(targetRoot string, configProtect []string) []sss {
	var ssss []sss
	if configProtect != nil {
		for _, x := range configProtect {
			x = path.Join(targetRoot, strings.TrimPrefix(x, string(os.PathSeparator)))
			s, _ := os.Lstat(x)
			myMode := s.Mode()
			if myMode&syscall.O_WRONLY == 0 {
				continue
			}
			if myMode&os.ModeSymlink != 0 {
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
			cmd, _ := shlex.Split(strings.NewReader(myCommand), false, false)
			if process.FindBinary(cmd[0]) == "" {
				return nil
			}
			c := exec.Command(process.FindBinary(cmd[0]), cmd[1:]...)
			var out, err bytes.Buffer
			c.Stdout = &out
			c.Stderr = &err
			if err := c.Run(); err != nil {
				return nil
			}
			o := out.String()
			files := strings.Split(o, `\0`)
			if files[len(files)-1] == "" {
				files = files[:len(files)-1]
			}
			if len(files) > 0 {
				if myMode.IsDir() {
					ssss = append(ssss, sss{S: x, SS: files})
				} else {
					ssss = append(ssss, sss{S: x, SS: nil})
				}
			}
		}
	}
	return ssss
}

type getConfigShlex struct {
	*shlex.Shlex
	source          string
	varExpandMap    map[string]string
	portageTolerant bool
}

func (g *getConfigShlex) allowSourcing(varExpandMap map[string]string) {
	g.source = "source"
	g.varExpandMap = varExpandMap
}

func (g *getConfigShlex) SourceHook(newfile string) (string, *os.File, error) {
	newfile = varExpand(newfile, g.varExpandMap, nil)
	return g.Shlex.SourceHook(newfile)
}

func NewGetConfigShlex(instream io.Reader, infile string, posix bool, punctuation_chars string, portageTolerant bool) *getConfigShlex {
	g := &getConfigShlex{portageTolerant: portageTolerant}
	g.Shlex = shlex.NewShlex(instream, infile, posix, punctuation_chars)

	return g
}

var invalidVarNameRe = regexp.MustCompile("^\\d|\\W")

// false, false, true, false, nil
func getConfig(myCfg string, tolerant, allowSourcing, expand, recursive bool, expandMap map[string]string) map[string]string {
	if len(expandMap) > 0 {
		expand = true
	} else {
		expandMap = map[string]string{}
	}
	myKeys := map[string]string{}

	if recursive {
		if !expand {
			expandMap = map[string]string{}
		}
		fname := ""
		for _, fname = range RecursiveFileList(myCfg) {
			newKeys := getConfig(fname, tolerant, allowSourcing, true, false, expandMap)
			for k, v := range newKeys {
				myKeys[k] = v
			}
		}
		if fname == "" {
			return nil
		}
		return myKeys
	}

	f, err := os.Open(myCfg)
	if err != nil {
		return nil
	}
	f.Close()
	c, err := ioutil.ReadAll(f)
	if err != nil {
		return nil
	}
	content := string(c)

	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if strings.Contains(content, "\r") {
		WriteMsg(fmt.Sprintf("!!! Please use dos2unix to convert line endings in config file: '%s'\n", myCfg), -1, nil)
	}
	lex := NewGetConfigShlex(strings.NewReader(content), myCfg, true, "", tolerant)
	lex.Wordchars = "abcdfeghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%*_\\:;?,./-+{}"
	lex.Quotes = "\"'"
	if allowSourcing {
		lex.allowSourcing(expandMap)
	}
	for {
		key, _ := lex.GetToken()
		if key == "export" {
			key, _ = lex.GetToken()
		}
		if key == "" {
			break
		}
		equ, _ := lex.GetToken()
		if equ == "" {
			msg := "Unexpected EOF" //TODO error_leader
			if !tolerant {
				//raise ParseError(msg)
			} else {
				WriteMsg(fmt.Sprintf("%s\n", msg), -1, nil)
				return myKeys
			}
		} else if equ != "=" {
			msg := fmt.Sprintf("Invalid token '%s' (not '=')", equ) //TODO error_leader
			if !tolerant {
				//raise ParseError(msg)
			} else {
				WriteMsg(fmt.Sprintf("%s\n", msg), -1, nil)
				return myKeys
			}
		}
		val, _ := lex.GetToken() /* TODO: fix it
		if val == "" {
			msg := fmt.Sprintf("Unexpected end of config file: variable '%s'", key) //TODO error_leader
			if !tolerant {
				//raise ParseError(msg)
			} else {
				WriteMsg(fmt.Sprintf("%s\n", msg), -1, nil)
				return myKeys
			}
		}*/
		if invalidVarNameRe.MatchString(key) {
			msg := fmt.Sprintf("Invalid variable name '%s'", key) //TODO error_leader
			if !tolerant {
				//raise ParseError(msg)
			} else {
				WriteMsg(fmt.Sprintf("%s\n", msg), -1, nil)
				continue
			}
		}
		if expand {
			myKeys[key] = varExpand(val, expandMap, "") //TODO lex.error_leader
			expandMap[key] = myKeys[key]
		} else {
			myKeys[key] = val
		}
	}
	return myKeys
}

var (
	varexpandWordChars        = map[uint8]bool{'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true, 'g': true, 'h': true, 'i': true, 'j': true, 'k': true, 'l': true, 'm': true, 'n': true, 'o': true, 'p': true, 'q': true, 'r': true, 's': true, 't': true, 'u': true, 'v': true, 'w': true, 'x': true, 'y': true, 'z': true, 'A': true, 'B': true, 'C': true, 'D': true, 'E': true, 'F': true, 'G': true, 'H': true, 'I': true, 'J': true, 'K': true, 'L': true, 'M': true, 'N': true, 'O': true, 'P': true, 'Q': true, 'R': true, 'S': true, 'T': true, 'U': true, 'V': true, 'W': true, 'X': true, 'Y': true, 'Z': true, '0': true, '1': true, '2': true, '3': true, '4': true, '5': true, '6': true, '7': true, '8': true, '9': true, '_': true}
	varexpandUnexpectedEofMsg = "unexpected EOF while looking for matching `}'"
)

// nil, nil
func varExpand(myString string, myDict map[string]string, errorLeader func() string) string {
	if myDict == nil {
		myDict = map[string]string{}
	}
	var numVars, inSingle, inDouble, pos int
	length := len(myString)
	newString := []string{}
	for pos < length {
		current := myString[pos]
		if current == '\'' {
			if inDouble > 0 {
				newString = append(newString, "'")
			} else {
				newString = append(newString, "'")
				inSingle = 1 - inSingle
			}
			pos += 1
			continue
		} else if current == '"' {
			if inSingle > 0 {
				newString = append(newString, "\"")
			} else {
				newString = append(newString, "\"")
				inDouble = 1 - inDouble
			}
			pos += 1
			continue
		}
		if inSingle <= 0 {
			if current == '\n' {
				newString = append(newString, " ")
				pos += 1
			} else if current == '\\' {
				if pos+1 >= len(myString) {
					newString = append(newString, string(current))
					break
				} else {
					current = myString[pos+1]
					pos += 2
					if current == '$' {
						newString = append(newString, string(current))
					} else if current == '\\' {
						newString = append(newString, string(current))
						if pos < length && (myString[pos] == '\'' || myString[pos] == '"' || myString[pos] == '$') {
							newString = append(newString, string(myString[pos]))
							pos += 1
						}
					} else if current == '\n' {
					} else {
						newString = append(newString, myString[pos-2:pos])
					}
					continue
				}
			} else if current == '$' {
				pos += 1
				if pos == length {
					newString = append(newString, string(current))
					continue
				}
				braced := false
				if myString[pos] == '{' {
					pos += 1
					if pos == length {
						msg := varexpandUnexpectedEofMsg
						if errorLeader != nil {
							msg = errorLeader() + msg
						}
						WriteMsg(msg+"\n", -1, nil)
						return ""
					}
					braced = true
				} else {
					braced = false
				}
				myvStart := pos
				for varexpandWordChars[myString[pos]] {
					if pos+1 >= len(myString) {
						if braced {
							msg := varexpandUnexpectedEofMsg
							if errorLeader != nil {
								msg = errorLeader() + msg
							}
							WriteMsg(msg+"\n", -1, nil)
							return ""
						} else {
							pos += 1
							break
						}
					}
					pos += 1
				}
				myVarName := myString[myvStart:pos]
				if braced {
					if myString[pos] != '{' {
						msg := varexpandUnexpectedEofMsg
						if errorLeader != nil {
							msg = errorLeader() + msg
						}
						WriteMsg(msg+"\n", -1, nil)
						return ""
					} else {
						pos += 1
					}
				}
				if len(myVarName) == 0 {
					msg := "$"
					if braced {
						msg += "{}"
					}
					msg += ": bad substitution"
					if errorLeader != nil {
						msg = errorLeader() + msg
					}
					WriteMsg(msg+"\n", -1, nil)
					return ""
				}
				numVars += 1
				if _, ok := myDict[myVarName]; ok {
					newString = append(newString, myDict[myVarName])
				}
			} else {
				newString = append(newString, string(current))
				pos += 1
			}
		} else {
			newString = append(newString, string(current))
			pos += 1
		}
	}
	return strings.Join(newString, "")
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
				for _, r := range readLdSoConf(q) {
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
	if err != nil {
		if err == os.ErrPermission {
			//raise PermissionDenied("stat('%s')" % path)
		}
		return false
	}
	return f.IsDir()
}

type slotObject struct {
	weakRef string
}

// -1,-1,-1,-1,nil,true
func applyPermissions(filename string, uid, gid uint32, mode, mask os.FileMode, statCached os.FileInfo, followLinks bool) bool {
	modified := false
	if statCached == nil {
		statCached, _ = doStat(filename, followLinks)
	}
	if (int(uid) != -1 && uid != statCached.Sys().(*syscall.Stat_t).Uid) || (int(gid) != -1 && gid != statCached.Sys().(*syscall.Stat_t).Gid) {
		if followLinks {
			os.Chown(filename, int(uid), int(gid))
		} else {
			os.Lchown(filename, int(uid), int(gid))
		}
		modified = true
	} // TODO check errno
	newMode := os.FileMode(0) // uint32(-1)
	stMode := statCached.Mode() & 07777
	if mask >= 0 {
		if int(mode) == -1 {
			mode = 0
		} else {
			mode = mode & 07777
		}
		if (stMode&mask != mode) || ((mask^stMode)&stMode != stMode) {
			newMode = mode | stMode
			newMode = (mask ^ newMode) & newMode
		}
	} else if int(mode) != -1 {
		mode = mode & 07777
		if mode != stMode {
			newMode = mode
		}
	}
	if modified && int(stMode) == -1 && (int(stMode)&syscall.S_ISUID != 0 || int(stMode)&syscall.S_ISGID != 0) {
		if int(mode) == -1 {
			newMode = stMode
		} else {
			mode = mode & 0777
			if mask >= 0 {
				newMode = mode | stMode
				newMode = (mask ^ newMode) & newMode
			} else {
				newMode = mode
			}
		}
	}
	if !followLinks && statCached.Mode()&os.ModeSymlink != 0 {
		newMode = -1
	}
	if int(newMode) != -1 {
		os.Chmod(filename, os.FileMode(newMode))
	}
	return modified
}

// -1, nil, true
func apply_stat_permissions(filename string, newStat os.FileInfo, mask os.FileMode, statCached os.FileInfo, followLinks bool) bool {
	st := newStat.Sys().(*syscall.Stat_t)
	return apply_secpass_permissions(filename, st.Uid, st.Gid, newStat.Mode(), mask, statCached, followLinks)
}

// -1, -1, -1, -1, nil, true
func apply_secpass_permissions(filename string, uid, gid uint32, mode, mask os.FileMode, statCached os.FileInfo, followLinks bool) bool {

	if statCached == nil {
		statCached, _ = doStat(filename, followLinks)
	}

	allApplied := true

	if (int(uid) != -1 || int(gid) != -1) && atom.secpass != nil && *atom.secpass < 2 {
		if int(uid) != -1 && uid != statCached.Sys().(*syscall.Stat_t).Uid {
			allApplied = false
			uid = -1
		}
		gs, _ := os.Getgroups()
		in := false
		for _, g := range gs {
			if g == int(gid) {
				in = true
				break
			}
		}
		if int(uid) != -1 && gid != statCached.Sys().(*syscall.Stat_t).Gid && !in {
			allApplied = false
			gid = -1
		}
	}

	applyPermissions(filename, uid, gid, mode, mask,
		statCached, followLinks)
	return allApplied
}

type atomic_ofstream struct {
	_aborted   bool
	_real_name string
	_file      *os.File
}

func (a *atomic_ofstream) _get_target() *os.File {
	return a._file
}

func (a *atomic_ofstream) Write(s []byte) (int, error) {
	f := a._file
	return f.Write(s)
}

func (a *atomic_ofstream) Close() error {
	f := a._file
	realName := a._real_name
	if err := f.Close(); err != nil {
		return err
	}
	if !a._aborted {
		st, _ := os.Stat(realName)
		apply_stat_permissions(f.Name(), st, -1, nil, true)
		if err := os.Rename(f.Name(), realName); err != nil {
			return err
		}
	}
	if err := syscall.Unlink(f.Name()); err != nil {
		return err
	}
	return nil
}

func (a *atomic_ofstream) abort() {
	if !a._aborted {
		a._aborted = true
		a.Close()
	}
}

func (a *atomic_ofstream) __del__() {}

// "w", true
func NewAtomic_ofstream(filename string, mode int, follow_links bool) *atomic_ofstream {
	a := &atomic_ofstream{}

	if follow_links {
		canonicalPath, _ := filepath.EvalSymlinks(filename)
		a._real_name = canonicalPath
		tmpName := fmt.Sprintf("%s.%i", canonicalPath, os.Getpid())
		var err error
		a._file, err = os.OpenFile(tmpName, mode, 0644)
		if err == nil {
			return a
		}
		if err != nil {
			if canonicalPath == filename {
				//raise
			}
		}
	}
	a._real_name = filename
	tmpName := fmt.Sprintf("%s.%i", filename, os.Getpid())

	a._file, _ = os.OpenFile(tmpName, mode, 0644)
	return a
}

// 0 (i dont know), true
func write_atomic(filePath string, content string, mode int, followLinks bool) {
	f := NewAtomic_ofstream(filePath, mode, followLinks)
	f.Write([]byte(content))
	f.Close()
	//except (IOError, OSError) as e:
	//if f:
	//f.abort()
	//func_call = "write_atomic('%s')" % file_path
	//if err == syscall.EPERM:
	//raise OperationNotPermitted(func_call)
	//else if err == syscall.EACCES:
	//raise PermissionDenied(func_call)
	//else if err == syscall.EROFS:
	//raise ReadOnlyFileSystem(func_call)
	//else if err == syscall.ENOENT:
	//raise FileNotFound(file_path)
	//else:
	//raise
}

// -1,-1,-1,-1,nil,true
func ensureDirs(dirPath string, uid, gid uint32, mode, mask os.FileMode, statCached os.FileInfo, followLinks bool) bool {
	createdDir := false
	if err := os.MkdirAll(dirPath, 0755); err == nil {
		createdDir = true
	} // TODO check errno
	permsModified := false
	if int(uid) != -1 || int(gid) != -1 || int(mode) != -1 || int(mask) != -1 || statCached != nil || followLinks {
		permsModified = applyPermissions(dirPath, uid, gid, mode, mask, statCached, followLinks)
	} else {
		permsModified = false
	}
	return createdDir || permsModified
}

func NewProjectFilename(myDest, newMd5 string, force bool) string {
	protNum := -1
	lastFile := ""
	if _, err := os.Open(myDest); !force && !os.IsNotExist(err) {
		return myDest
	}
	realFilename := path.Base(myDest)
	realDirname := path.Dir(myDest)
	files, _ := ioutil.ReadDir(realDirname)
	for _, pfile := range files {
		if pfile.Name()[0:5] != "._cfg" {
			continue
		}
		if pfile.Name()[10:] != realFilename {
			continue
		}
		newProtNum, _ := strconv.Atoi(pfile.Name()[5:9])
		if newProtNum > protNum {
			protNum = newProtNum
			lastFile = pfile.Name()
		}
	}
	protNum++
	newPFile := NormalizePath(path.Join(realDirname, ".cfg"+fmt.Sprintf("%04s", string(protNum))+"_"+realFilename))
	oldPFile := NormalizePath(path.Join(realDirname, lastFile))
	if len(lastFile) != 0 && len(newMd5) != 0 {
		oldPfileSt, err := os.Lstat(oldPFile)
		if err != nil {
			if oldPfileSt.Mode()&os.ModeSymlink != 0 {
				pfileLink, err := os.Readlink(oldPFile)
				if err != nil {
					if pfileLink == newMd5 {
						return oldPFile
					}
				}
			} else {
				//lastPfileMd5 := string(performMd5Merge(oldPFile, 0))
			}
		}
	}
	return newPFile
}

func ReadConfigs(parser configparser.ConfigParser, paths []string) error {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		if err := parser.ReadFile(f, p); err != nil {
			return err
		}
	}
	return nil
}

func ExpandEnv() map[string]string {
	m := map[string]string{}
	for _, v := range os.Environ() {
		s := strings.SplitN(v, "=", 2)
		if len(s) == 2 {
			m[s[0]] = s[1]
		}
	}
	return m
}

var _compressors = map[string]map[string]string{
	"bzip2": {
		"compress":       "${PORTAGE_BZIP2_COMMAND} ${BINPKG_COMPRESS_FLAGS}",
		"decompress":     "${PORTAGE_BUNZIP2_COMMAND}",
		"decompress_alt": "${PORTAGE_BZIP2_COMMAND} -d",
		"package":        "app-arch/bzip2",
	},
	"gzip": {
		"compress":   "gzip ${BINPKG_COMPRESS_FLAGS}",
		"decompress": "gzip -d",
		"package":    "app-arch/gzip",
	},
	"lz4": {
		"compress":   "lz4 ${BINPKG_COMPRESS_FLAGS}",
		"decompress": "lz4 -d",
		"package":    "app-arch/lz4",
	},
	"lzip": {
		"compress":   "lzip ${BINPKG_COMPRESS_FLAGS}",
		"decompress": "lzip -d",
		"package":    "app-arch/lzip",
	},
	"lzop": {
		"compress":   "lzop ${BINPKG_COMPRESS_FLAGS}",
		"decompress": "lzop -d",
		"package":    "app-arch/lzop",
	},
	"xz": {
		"compress":   "xz ${BINPKG_COMPRESS_FLAGS}",
		"decompress": "xz -d",
		"package":    "app-arch/xz-utils",
	},
	"zstd": {
		"compress":   "zstd ${BINPKG_COMPRESS_FLAGS}",
		"decompress": "zstd -d --long=31",
		"package":    "app-arch/zstd",
	},
}

var compressionRe = regexp.MustCompile("^((?P<bzip2>\\x42\\x5a\\x68\\x39)|(?P<gzip>\\x1f\\x8b)|(?P<lz4>(?:\\x04\\x22\\x4d\\x18|\\x02\\x21\\x4c\\x18))|(?P<lzip>LZIP)|(?P<lzop>\\x89LZO\\x00\x0d\x0a\\x1a\x0a)|(?P<xz>\\xfd\\x37\\x7a\\x58\\x5a\\x00)|(?P<zstd>([\\x22-\\x28]\\xb5\\x2f\\xfd)))")

const _max_compression_re_len = 9

func compression_probe(f string) string {
	s, _ := os.Open(f)
	return _compression_probe_file(s)
}

func _compression_probe_file(f *os.File) string {
	b := make([]byte, _max_compression_re_len)
	f.Read(b)
	m := compressionRe.Match(b)
	if m {
		match := compressionRe.FindSubmatch(b)
		for i, n := range compressionRe.SubexpNames() {
			if i > 0 && i <= len(match) && len(match[i]) != 0 {
				return n
			}
		}
	}
	return ""
}

type preservedLibsRegistry struct {
	_json_write       bool
	_json_write_opts  map[string]bool
	_root, _filename  string
	_data, _data_orig map[string]*struct {
		cpv, counter string
		paths        []string
	}
	_lock *atom.LockFileS
}

func (p *preservedLibsRegistry) lock() {
	if p._lock != nil {
		//raise AssertionError("already locked")
	}
	p._lock, _ = atom.Lockfile(p._filename, false, false, "", 0)
}

func (p *preservedLibsRegistry) unlock() {
	if p._lock == nil {
		//raise AssertionError("not locked")
	}
	atom.Unlockfile(p._lock)
	p._lock = nil
}

func (p *preservedLibsRegistry) load() {
	p._data = nil
	content, err := ioutil.ReadFile(p._filename)
	if err != nil {
		//except EnvironmentError as e:
		//if not hasattr(e, 'errno'):
		//raise
		//elif err == syscall.ENOENT:
		//pass
		//elif err == PermissionDenied.errno:
		//raise PermissionDenied(self._filename)
		//else:
		//raise
	}
	if len(content) > 0 {
		if err := json.Unmarshal(content, &p._data); err != nil {
			//except SystemExit:
			//raise
			//except Exception as e:
			//try:
			//	p._data = pickle.loads(content)
			//	except SystemExit:
			//	raise
			//	except Exception:
			WriteMsgLevel(fmt.Sprintf("!!! Error loading '%s': %s\n", p._filename, err), 40, -1)
		}
	}

	if p._data == nil {
		p._data = map[string]*struct {
			cpv, counter string
			paths        []string
		}{}
	} else {
		for k, v := range p._data {
			p._data[k] = &struct {
				cpv, counter string
				paths        []string
			}{v.cpv, v.counter, v.paths}
		}
	}

	p._data_orig = map[string]*struct {
		cpv, counter string
		paths        []string
	}{}
	for k, v := range p._data {
		p._data_orig[k] = v
	}
	p.pruneNonExisting()
}

func (p *preservedLibsRegistry) store() {

	if os.Getenv("SANDBOX_ON") == "1" || &p._data == &p._data_orig {
		return
	}
	f := NewAtomic_ofstream(p._filename, os.O_RDWR|os.O_CREATE, true)
	//if self._json_write:
	v, _ := json.Marshal(p._data)
	f.Write(v)
	//else:
	//pickle.dump(self._data, f, protocol=2)
	f.Close()
	//except EnvironmentError as e:
	//if err != PermissionDenied.errno:
	//WriteMsgLevel("!!! %s %s\n" % (e, self._filename),
	//	level=logging.ERROR, noiselevel=-1)
	//else:
	p._data_orig = map[string]*struct {
		cpv, counter string
		paths        []string
	}{}
	for k, v := range p._data {
		p._data_orig[k] = v
	}
}

func (p *preservedLibsRegistry) _normalize_counter(counter string) string {
	return strings.TrimSpace(counter)
}

func (p *preservedLibsRegistry) register(cpv, slot, counter string, paths []string) {

	cp := atom.cpvGetKey(cpv, "")
	cps := cp + ":" + slot
	counter = p._normalize_counter(counter)
	if _, ok := p._data[cps]; len(paths) == 0 && ok && p._data[cps].cpv == cpv && p._normalize_counter(p._data[cps].counter) == counter {
		delete(p._data, cps)
	} else if len(paths) > 0 {
		p._data[cps] = &struct {
			cpv, counter string
			paths        []string
		}{cpv, counter, paths}
	}
}

func (p *preservedLibsRegistry) unregister(cpv, slot, counter string) {
	p.register(cpv, slot, counter, []string{})
}

func (p *preservedLibsRegistry) pruneNonExisting() {
	for cps := range p._data {

		cpv, counter, _paths := p._data[cps].cpv, p._data[cps].counter, p._data[cps].paths

		paths := []string{}
		hardlinks := map[string]bool{}
		symlinks := map[string]string{}
		for _, f := range _paths {
			f_abs := filepath.Join(p._root, strings.TrimLeft(f, string(os.PathSeparator)))
			lst, err := os.Lstat(f_abs)
			if err != nil {
				//except OSError:
				continue
			}
			if lst.Mode()&syscall.S_IFLNK != 0 {
				symlinks[f], err = filepath.EvalSymlinks(f_abs)
				if err != nil {
					//except OSError:
					continue
				}
			} else if lst.Mode()&syscall.S_IFREG != 0 {
				hardlinks[f] = true
				paths = append(paths, f)
			}
		}

		for f, target := range symlinks {
			if hardlinks[atom.absSymlink(f, target)] {
				paths = append(paths, f)
			}
		}

		if len(paths) > 0 {
			p._data[cps] = &struct {
				cpv, counter string
				paths        []string
			}{cpv, counter, paths}
		} else {
			delete(p._data, cps)
		}
	}
}

func (p *preservedLibsRegistry) hasEntries() bool {
	if p._data == nil {
		p.load()
	}
	return len(p._data) > 0
}

func (p *preservedLibsRegistry) getPreservedLibs() map[string][]string {
	if p._data == nil {
		p.load()
	}
	rValue := map[string][]string{}
	for cps := range p._data {
		rValue[p._data[cps].cpv] = p._data[cps].paths
	}
	return rValue
}

func NewPreservedLibsRegistry(root, filename string) *preservedLibsRegistry {
	p := &preservedLibsRegistry{_json_write: true, _json_write_opts: map[string]bool{
		"ensure_ascii": false,
		"indent":       true,
		"sort_keys":    true,
	}}
	p._root = root
	p._filename = filename

	return p
}

type linkageMapELF struct {
	_needed_aux_key   string
	_soname_map_class struct {
		consumers, providers []string
	}
	_dbapi                                                            *atom.vardbapi
	_root                                                             string
	_libs map[string][] string
	_obj_properties map[string]*_obj_properties_class
	_defpath map[string]bool
	_obj_key_cache, _path_key_cache map[string]*_ObjectKey
}

type _obj_properties_class struct{
	//slot
	arch,soname,owner string
	needed,runpaths []string
	alt_paths map[string]bool
}

func New_obj_properties_class(arch string, needed, runpaths []string, soname string, alt_paths map[string]bool, owner string)*_obj_properties_class {
	o := &_obj_properties_class{}
	o.arch = arch
	o.needed = needed
	o.runpaths = runpaths
	o.soname = soname
	o.alt_paths = alt_paths
	o.owner = owner
	return o
}

func (o*linkageMapELF) _clear_cache() {
	o._libs= map[string]string{}
	o._obj_properties= map[string]*_obj_properties_class{}
	o._obj_key_cache= map[string]*_ObjectKey{}
	o._defpath= map[string]bool{}
	o._path_key_cache= map[string]*_ObjectKey{}
}

func (o*linkageMapELF) _path_key( path string)  *_ObjectKey {
	key := o._path_key_cache[path]
	if key == nil {
		key = New_ObjectKey(path, o._root)
	}
	o._path_key_cache[path] = key
	return key
}

func (o*linkageMapELF) _obj_key(path string) *_ObjectKey {
	key := o._obj_key_cache[path]
	if key == nil {
		key = New_ObjectKey(path, o._root)
	}
	o._obj_key_cache[path] = key
	return key
}


type _ObjectKey struct{
	_key interface{}
}

func(o*_ObjectKey) __hash__() {
	return hash(o._key)
}

func(o*_ObjectKey) __eq__( other *_ObjectKey) bool {
	return o._key == other._key
}

func(o*_ObjectKey) _generate_object_key(obj, root string) interface{} {

	abs_path := filepath.Join(root, strings.TrimLeft(obj, string(os.PathSeparator)))
	object_stat, err := os.Stat(abs_path)
	if err != nil {
		//except OSError:
		rp, _ := filepath.EvalSymlinks(abs_path)
		return rp
	}
	return [2]uint64{object_stat.Sys().(*syscall.Stat_t).Dev, object_stat.Sys().(*syscall.Stat_t).Ino}
}

func(o*_ObjectKey) file_exists() bool{
	_, ok := o._key.([2]uint64)
	return ok
}

func New_ObjectKey(obj, root string)*_ObjectKey {
	o := &_ObjectKey{}
	o._key = o._generate_object_key(obj, root)
	return o
}

type _LibGraphNode struct{
	*_ObjectKey
	// slot
	alt_paths map[string]bool
}

func( l*_LibGraphNode) __str__() string {
	return str(atom.sortedmsb(l.alt_paths))
}

func New_LibGraphNode( key *_ObjectKey) *_LibGraphNode {
	l := &_LibGraphNode{}
	l._key = key._key
	l.alt_paths = map[string]bool{}
	return l
}

// nil, "", nil
func (o*linkageMapELF) rebuild(exclude_pkgs []*atom.PkgStr, include_file string, preserve_paths map[string]bool) {

	root := o._root
	root_len := len(root) - 1
	o._clear_cache()
	for _, k := range getLibPaths(o._dbapi.settings.ValueDict["EROOT"],
		o._dbapi.settings.ValueDict) {
		o._defpath[k] = true
	}
	libs := o._libs
	obj_properties := o._obj_properties

	lines := []*struct {
		p      *atom.PkgStr;
		s1, s2 string
	}{}

	if include_file != "" {
		for _, line := range grabFile(include_file, 0, false, false) {
			lines = append(lines, &struct {
				p      *atom.PkgStr;
				s1, s2 string
			}{nil, include_file, line[0]})
		}
	}

	aux_keys := map[string]bool{o._needed_aux_key: true}
	can_lock := atom.osAccess(filepath.Dir(o._dbapi._dbroot), unix.W_OK)
	if can_lock {
		o._dbapi.lock()
	}
	//try:
	for _, cpv := range o._dbapi.cpv_all(1) {
		in := false
		for _, k := range exclude_pkgs {
			if k.string == cpv.string {
				in = true
				break
			}
		}
		if exclude_pkgs != nil && in {
			continue
		}
		needed_file := o._dbapi.getpath(cpv.string, o._needed_aux_key)
		for _, line := range strings.Split(o._dbapi.aux_get(cpv.string, aux_keys, "")[0], "\n") {
			lines = append(lines, &struct {
				p      *atom.PkgStr;
				s1, s2 string
			}{cpv, needed_file, line})
		}
	}
	//finally:
	if can_lock {
		o._dbapi.unlock()
	}

	plibs := map[string]*atom.PkgStr{}
	if preserve_paths != nil{
		for x := range preserve_paths {
			plibs[x] = nil
		}
	}
	if o._dbapi._plib_registry!= nil && o._dbapi._plib_registry.hasEntries() {
		for cpv, items := range o._dbapi._plib_registry.getPreservedLibs() {
			in := false
			for _, k := range exclude_pkgs {
				if k.string == cpv {
					in = true
					break
				}
			}
			if exclude_pkgs != nil && in {
				continue
			}

			for _, x := range items {
				plibs[x]= cpv
			}
		}
	}
	if len(plibs) > 0 {
		ep := _const.EPREFIX
		if ep == "" {
			ep = "/"
		}
		args := []string{filepath.Join(ep, "usr/bin/scanelf"), "-qF", "%a;%F;%S;%r;%n"}
		for x := range plibs {
			args = append(args, filepath.Join(root, strings.TrimLeft(x, "."+string(os.PathSeparator))))
		}

		cmd := exec.Command(args[0], args[1:]...)
		b := &bytes.Buffer{}
		cmd.Stdout = b
		if err := cmd.Run(); err != nil {
			//except EnvironmentError as e:
			if err != syscall.ENOENT {
				//raise
			}
			//raise CommandNotFound(args[0])
		} else {
			for _, l := range strings.Split(b.String(), "\n") {
				//try:
				//	l = _unicode_decode(l,
				//		encoding = _encodings['content'], errors = 'strict')
				//	except
				//UnicodeDecodeError:
				//	l = _unicode_decode(l,
				//		encoding = _encodings['content'], errors = 'replace')
				//	WriteMsgLevel(_("\nError decoding characters " \
				//	"returned from scanelf: %s\n\n") % (l, ),
				//	level = logging.ERROR, noiselevel = -1)
				l = strings.TrimRight(l[3:], "\n")
				if l == "" {
					continue
				}
				entry, err := NewNeededEntry().parse("scanelf", l)
				if err != nil {
					//except InvalidData as e:
					WriteMsgLevel(fmt.Sprintf("\n%s\n\n", err, ),
						40, -1)
					continue
				}
				f, err := os.Open(entry.filename)
				if err != nil {
					//except EnvironmentError as e:
					if err != syscall.ENOENT {
						//raise
					}
					continue
				}
				elf_header := atom.ReadELFHeader(f)

				if entry.soname == "" {
					cmd := exec.Command("file", entry.filename)
					var out, err bytes.Buffer
					cmd.Stdout=&out
					cmd.Stderr=&err
					if err := cmd.Run(); err != nil {
						//except EnvironmentError:
					} else {
						if strings.Contains(out.String(), "SB shared object"){
							entry.soname = filepath.Base(entry.filename)
						}
					}
				}

				entry.multilib_category = atom.compute_multilib_category(elf_header)
				entry.filename = entry.filename[root_len:]
				owner := plibs[entry.filename]
				delete(plibs, entry.filename)
				lines=append(lines, &struct {p *atom.PkgStr;s1, s2 string}{owner, "scanelf", entry.__str__()})
			}
		}
	}

	if len(plibs) > 0 {
		for x, cpv := range plibs {
			lines=append(lines, &struct {p *atom.PkgStr;s1, s2 string}{cpv, "plibs", strings.Join([]string{"", x, "", "", ""},";")})
		}
	}

	frozensets =
	{
	}
	owner_entries := map[string][]*NeededEntry{}

	for {
		if len(lines) == 0 {
			//except IndexError:
			break
		}
		line := lines[len(lines)-1]
		lines = lines[:len(lines)-1]
		owner, location, l := line.p, line.s1, line.s2
		l = strings.TrimRight(l, "\n")
		if l == "" {
			continue
		}
		if strings.Contains(l, string([]byte{0})) {
			WriteMsgLevel(fmt.Sprintf("\nLine contains null byte(s) "+
				"in %s: %s\n\n", location, l), 40, -1)
			continue
		}
		entry ,err := NewNeededEntry().parse(location, l)
		if err != nil {
			//except InvalidData as e:
			WriteMsgLevel(fmt.Sprintf("\n%s\n\n", err), 40, -1)
			continue
		}

		if entry.multilib_category == "" {
			entry.multilib_category = _approx_multilib_categories.get(
				entry.arch, entry.arch)
		}

		entry.filename = NormalizePath(entry.filename)
		expand := map[string]string{
			"ORIGIN": filepath.Dir(entry.filename),
		}
		runpaths:=map[string]bool{}
		for _, x := range entry.runpaths{
			runpaths[NormalizePath(varExpand(x, expand, func() string {return fmt.Sprintf("%s: " , location)})] = true
		}
		entry.runpaths = []string{}
		for   k := range runpaths{
			entry.runpaths = append(entry.runpaths, k)
		}
		owner_entries[owner.string] = append(owner_entries[owner.string], entry)
	}

	for owner, entries:= range owner_entries {
		if owner == "" {
			continue
		}

		providers :=
		{
		}
		for _, entry := range entries {
			if entry.soname != "" {
				providers[atom.NewSonameAtom(entry.multilib_category, entry.soname)] = entry
			}
		}

		for _, entry := range entries {
			implicit_runpaths = []
			for soname
				in
			entry.needed:
			soname_atom := NewSonameAtom(entry.multilib_category, soname)
			provider = providers.get(soname_atom)
			if provider is
		None:
			continue
			provider_dir = filepath.Dir(provider.filename)
			if provider_dir not
			in
			entry.runpaths:
			implicit_runpaths.append(provider_dir)

			if implicit_runpaths:
			entry.runpaths = frozenset(
				itertools.chain(entry.runpaths, implicit_runpaths))
			entry.runpaths = frozensets.setdefault(
				entry.runpaths, entry.runpaths)
		}
	}

	for owner, entries := range owner_entries {
		for _, entry := range entries{
			arch := entry.multilib_category
			obj := entry.filename
			soname := entry.soname
			path := entry.runpaths
			neededmsb := map[string]bool{}
			for _, k := range entry.needed{
				neededmsb[k]=true
			}
			needed := []string{}
			for k := range neededmsb {
				needed =append(needed, k)
			}
			obj_key := o._obj_key(obj)
			indexed := true
			myprops := obj_properties[obj_key]
			if myprops == nil {
				indexed = false
				myprops = New_obj_properties_class(
					arch, needed, path, soname, [], owner)
				obj_properties[obj_key] = myprops
			}
			myprops.alt_paths=append(myprops.alt_paths,obj)

			if indexed{
				continue
			}

			arch_map := libs[arch]
			if arch_map == nil {
				arch_map =
				{
				}
				libs[arch] = arch_map
			}
			if soname {
				soname_map := arch_map[soname]
				if soname_map == nil {
					soname_map = o._soname_map_class(
						providers = [], consumers = [])
					arch_map[soname] = soname_map
				}
				soname_map.providers=append(soname_map.providers,obj_key)
			}
			for _, needed_soname:= range needed {
				soname_map = arch_map.get(needed_soname)
				if soname_map == nil {
					soname_map = o._soname_map_class(
						providers = [], consumers = [])
				}
				arch_map[needed_soname] = soname_map
				soname_map.consumers=append(soname_map.consumers,obj_key)
			}
		}
	}

	for arch, sonames:= range libs {
		for _, soname_node := range sonames {
			soname_node.providers = tuple(set(soname_node.providers))
			soname_node.consumers = tuple(set(soname_node.consumers))
		}
	}
}

type _LibraryCache struct {
	o *linkageMapELF
	cache map[]
}

func NewLibraryCache(o *linkageMapELF) *_LibraryCache {
	l := &_LibraryCache{}
	l.o = o
	l.cache =
	{
	}
	return l
}

func (l *_LibraryCache)get(obj) {

	if obj in
	l.cache{
		return l.cache[obj]
	} else {
		obj_key := l.o._obj_key(obj)
		if obj_key.file_exists() {
			obj_props := l.o._obj_properties[obj_key]
			if obj_props == nil {
				arch = None
				soname = None
			} else {
				arch = obj_props.arch
				soname = obj_props.soname
				return l.cache.setdefault(obj, \
				(arch, soname, obj_key, true))
			}
		} else {
			return l.cache.setdefault(obj, \
			(None, None, obj_key, false))
		}
	}
}

// false
func (o*linkageMapELF) listBrokenBinaries( debug bool) {

	rValue :=
	{
	}
	cache := NewLibraryCache(o)
	providers := o.listProviders()

	for obj_key, sonames
	in
	providers.items() {
		obj_props := o._obj_properties[obj_key]
		arch := obj_props.arch
		path := obj_props.runpaths
		objs := obj_props.alt_paths
		path := path.union(o._defpath)
		for soname, libraries
			in
		sonames.items() {
			validLibraries = set()
			for directory
				in
			path:
			cachedArch, cachedSoname, cachedKey, cachedExists = \
			cache.get(filepath.Join(directory, soname))
			if cachedSoname == soname && cachedArch == arch{
				validLibraries.add(cachedKey)
				if debug &&
				cachedKey
				not
				in \
				set(map(o._obj_key_cache.get,
				libraries)){
				WriteMsgLevel(
				_("Found provider outside of findProviders:") + \
				(" %s -> %s %s\n" % (filepath.Join(directory, soname),
				o._obj_properties[cachedKey].alt_paths, libraries)),
				level = logging.DEBUG,
				noiselevel = -1)
				}
				break
			}
			if debug && cachedArch == arch &&
			cachedKey
			in
			o._obj_properties{
				WriteMsgLevel(fmt.Sprintf("Broken symlink or missing/bad soname: "+
					"%s -> %s with soname %s but expecting %s",
					filepath.Join(directory, soname), o._obj_properties[cachedKey],
					cachedSoname, soname)+"\n", 20, -1)
			}
			if not validLibraries:
			for obj
				in
			objs {
				rValue.setdefault(obj, set()).add(soname)
			}
			for lib
				in
			libraries {
				rValue.setdefault(lib, set()).add(soname)
				if debug {
					if not atom.pathIsFile(lib) {
						WriteMsgLevel(fmt.Sprintf("Missing library:"+" %s\n", lib, ), 20, -1)
					}else {
						WriteMsgLevel(fmt.Sprintf("Possibly missing symlink:"+
						"%s\n", filepath.Join(filepath.Dir(lib), soname)), 20, -1)
					}
				}
			}
		}
	}
	return rValue
}

func (o*linkageMapELF) listProviders() {
	rValue :=
	{
	}
	if len( o._libs)==0 {
		o.rebuild(nil, "", nil)
	}
	for obj_key:= range o._obj_properties {
		rValue.setdefault(obj_key, o.findProviders(obj_key))
	}
	return rValue
}

func (o*linkageMapELF) isMasterLink( obj string) {
	os = _os_merge
	obj_key := o._obj_key(obj)
	if obj_key not
	in
	o._obj_properties{
		raise
		KeyError("%s (%s) not in object list"%(obj_key, obj))
	}
	basename := filepath.Base(obj)
	soname := o._obj_properties[obj_key].soname
	return len(basename) < len(soname)&& strings.HasSuffix(basename, ".so")&& strings.HasPrefix(soname, basename[:len(basename)-3])
}

func (o*linkageMapELF) listLibraryObjects() {
	rValue := []
	if len(o._libs) == 0 {
		o.rebuild()
	}
	for arch_map
	in
	o._libs.values() {
		for soname_map
			in
		arch_map.values() {
			for obj_key
				in
			soname_map.providers {
				rValue=append(rValue, o._obj_properties[obj_key].alt_paths...)
			}
		}
	}
	return rValue
}

func (o*linkageMapELF) getOwners( obj) {
	if not o._libs:
	o.rebuild()
	if isinstance(obj, o._ObjectKey):
	obj_key = obj
	else:
	obj_key = o._obj_key_cache.get(obj)
	if obj_key is
None:
	raise
	KeyError("%s not in object list" % obj)
	obj_props = o._obj_properties.get(obj_key)
	if obj_props is
None:
	raise
	KeyError("%s not in object list" % obj_key)
	if obj_props.owner is
None:
	return ()
	return (obj_props.owner,)
}

func (o*linkageMapELF) getSoname( obj) {
	if not o._libs:
	o.rebuild()
	if isinstance(obj, o._ObjectKey):
	obj_key = obj
	if obj_key not
	in
	o._obj_properties:
	raise
	KeyError("%s not in object list" % obj_key)
	return o._obj_properties[obj_key].soname
	if obj not
	in
	o._obj_key_cache:
	raise
	KeyError("%s not in object list" % obj)
	return o._obj_properties[o._obj_key_cache[obj]].soname
}

func (o*linkageMapELF) findProviders( obj) {

	os = _os_merge

	rValue =
	{
	}

	if len(o._libs) == 0 {
		o.rebuild(nil, "", nil)
	}

	if isinstance(obj, o._ObjectKey):
	obj_key = obj
	if obj_key not
	in
	o._obj_properties:
	raise
	KeyError("%s not in object list" % obj_key)
	else:
	obj_key = o._obj_key(obj)
	if obj_key not
	in
	o._obj_properties:
	raise
	KeyError("%s (%s) not in object list"%(obj_key, obj))

	obj_props = o._obj_properties[obj_key]
	arch = obj_props.arch
	needed = obj_props.needed
	path = obj_props.runpaths
	path_keys = set(o._path_key(x)
	for x
	in
	path.union(o._defpath))
	for soname
	in
needed:
	rValue[soname] = set()
	if arch not
	in
	o._libs
	or
	soname
	not
	in
	o._libs[arch]:
	continue
	for provider_key
	in
	o._libs[arch][soname].providers:
	providers = o._obj_properties[provider_key].alt_paths
	for provider
	in
providers:
	if o._path_key(filepath.Dir(provider)) in
path_keys:
	rValue[soname].add(provider)
	return rValue
}

// nil, true
func (o*linkageMapELF) findConsumers( obj string, exclude_providers []func(string)bool, greedy bool) {

	os = _os_merge

	if len(o._libs)==0 {
		o.rebuild(nil, "", nil)
	}

	if isinstance(obj, o._ObjectKey) {
		obj_key = obj
		if obj_key not
		in
		o._obj_properties:
		raise
		KeyError("%s not in object list" % obj_key)
		objs = o._obj_properties[obj_key].alt_paths
	}else {
		objs = set([obj])
		obj_key = o._obj_key(obj)
		if obj_key not
		in
		o._obj_properties:
		raise
		KeyError("%s (%s) not in object list"%(obj_key, obj))
	}

	if not isinstance(obj, o._ObjectKey) {
		soname = o._obj_properties[obj_key].soname
		soname_link = filepath.Join(o._root,
			filepath.Dir(obj).lstrip(os.path.sep), soname)
		obj_path = filepath.Join(o._root, obj.lstrip(string(os.PathSeparator)))
	try:
		soname_st = os.stat(soname_link)
		obj_st = os.stat(obj_path)
		except
	OSError:
		pass
		else:
		if (obj_st.st_dev, obj_st.st_ino) != \
		(soname_st.st_dev, soname_st.st_ino):
		return set()
	}

	obj_props = o._obj_properties[obj_key]
	arch = obj_props.arch
	soname = obj_props.soname

	soname_node = None
	arch_map = o._libs.get(arch)
	if arch_map is
	not
None{
	soname_node = arch_map.get(soname)
}

	defpath_keys = set(o._path_key(x)
	for x
	in
	o._defpath)
	satisfied_consumer_keys = set()
	if soname_node is
	not
None{
	if exclude_providers is
	not
	None
	or
	not
	greedy:
	relevant_dir_keys = set()
	for provider_key
	in
	soname_node.providers:
	if not greedy
	and
	provider_key == obj_key:
	continue
	provider_objs = o._obj_properties[provider_key].alt_paths
	for p
	in
	provider_objs:
	provider_excluded = false
	if exclude_providers is
	not
	None:
	for excluded_provider_isowner
	in
	exclude_providers:
	if excluded_provider_isowner(p):
	provider_excluded = true
	break
	if not provider_excluded:
	relevant_dir_keys.add(
	o._path_key(filepath.Dir(p)))

	if relevant_dir_keys:
	for consumer_key
	in
	soname_node.consumers:
	path = o._obj_properties[consumer_key].runpaths
	path_keys = defpath_keys.copy()
	path_keys.update(o._path_key(x)
	for x
	in
	path)
	if relevant_dir_keys.intersection(path_keys):
	satisfied_consumer_keys.add(consumer_key)
}

	rValue = set()
	if soname_node != nil {
		objs_dir_keys = set(o._path_key(filepath.Dir(x))
		for x
			in
		objs)
		for consumer_key
			in
		soname_node.consumers {
			if consumer_key in
			satisfied_consumer_keys{
				continue
			}
			consumer_props = o._obj_properties[consumer_key]
			path = consumer_props.runpaths
			consumer_objs = consumer_props.alt_paths
			path_keys = defpath_keys.union(o._path_key(x)
			for x
				in
			path)
			if objs_dir_keys.intersection(path_keys) {
				rValue.update(consumer_objs)
			}
		}
	}
	return rValue
}

func NewLinkageMapELF(vardbapi *atom.vardbapi) *linkageMapELF {
	l := &linkageMapELF{}
	l._dbapi = vardbapi
	l._root = l._dbapi.settings.ValueDict["ROOT"]
	l._libs = map[string]string{}
	l._obj_properties = map[string]string{}
	l._obj_key_cache = map[string]*_ObjectKey{}
	l._defpath = map[string]bool{}
	l._path_key_cache = map[string]*_ObjectKey{}
	return l
}


type digraph struct {
	nodes interface{}
	order []
}

func NewDigraph() *digraph {
	d := &digraph{}

	d.nodes =
	{
	}
	d.order = []
	return d
}

// 0
func(d*digraph) add(node, parent, priority=0) {
	if node not
	in
	d.nodes:
	d.nodes[node] = (
	{
	}, {
	}, node)
	d.order.append(node)

	if not parent:
	return

	if parent not
	in
	d.nodes:
	d.nodes[parent] = (
	{
	}, {
	}, parent)
	d.order.append(parent)

	priorities = d.nodes[node][1].get(parent)
	if priorities is
None:
	priorities = []
	d.nodes[node][1][parent] = priorities
	d.nodes[parent][0][node] = priorities

	if not priorities
	or
	priorities[-1]
	is
	not
priority:
	bisect.insort(priorities, priority)
}

func(d*digraph) discard( node) {
try:
	d.remove(node)
	except
KeyError:
	pass
}

func(d*digraph) remove( node) {

	if node not
	in
	d.nodes:
	raise
	KeyError(node)

	for parent
	in
	d.nodes[node][1]:
	del
	d.nodes[parent][0][node]
	for child
	in
	d.nodes[node][0]:
	del
	d.nodes[child][1][node]

	del
	d.nodes[node]
	d.order.remove(node)
}

func(d*digraph) update( other) {
	for node
	in
	other.order:
	children, parents, node = other.nodes[node]
	if parents:
	for parent, priorities
	in
	parents.items():
	for priority
	in
priorities:
	d.add(node, parent, priority = priority) else:
	d.add(node, None)
}

func(d*digraph) clear() {
	d.nodes.clear()
	del
	d.order[:]
}

func(d*digraph) difference_update( t) {
	if isinstance(t, (list, tuple)) or \
	not
	hasattr(t, "__contains__"):
	t = frozenset(t)
	order = []
	for node
	in
	d.order:
	if node not
	in
t:
	order.append(node)
	continue
	for parent
	in
	d.nodes[node][1]:
	del
	d.nodes[parent][0][node]
	for child
	in
	d.nodes[node][0]:
	del
	d.nodes[child][1][node]
	del
	d.nodes[node]
	d.order = order
}

func(d*digraph) has_edge(child, parent) bool {
try:
	return child
	in
	d.nodes[parent][0]
	except
KeyError:
	return false
}

func(d*digraph) remove_edge(child, parent) {

	for k
	in
	parent, child:
	if k not
	in
	d.nodes:
	raise
	KeyError(k)

	if child not
	in
	d.nodes[parent][0]:
	raise
	KeyError(child)
	if parent not
	in
	d.nodes[child][1]:
	raise
	KeyError(parent)

	del
	d.nodes[child][1][parent]
	del
	d.nodes[parent][0][child]
}

func(d*digraph) __iter__() {
	return iter(d.order)
}

func(d*digraph) contains(node) {
	return node
	in
	d.nodes
}

func(d*digraph) get( key, default=None) {
	node_data = d.nodes.get(key, d)
	if node_data is
d:
	return default
return node_data[2]
}

func(d*digraph) all_nodes() {
	return d.order[:]
}

func(d*digraph) child_nodes(node, ignore_priority=None) {
	if ignore_priority is
None:
	return list(d.nodes[node][0])
	children = []
	if hasattr(ignore_priority, '__call__'):
	for child, priorities
	in
	d.nodes[node][0].items():
	for priority
	in
	reversed(priorities):
	if not ignore_priority(priority):
	children.append(child)
	break
	else:
	for child, priorities
	in
	d.nodes[node][0].items():
	if ignore_priority < priorities[-1]:
	children.append(child)
	return children
}

func(d*digraph) parent_nodes(node, ignore_priority=None) {
	if ignore_priority is
None:
	return list(d.nodes[node][1])
	parents = []
	if hasattr(ignore_priority, '__call__'):
	for parent, priorities
	in
	d.nodes[node][1].items():
	for priority
	in
	reversed(priorities):
	if not ignore_priority(priority):
	parents.append(parent)
	break
	else:
	for parent, priorities
	in
	d.nodes[node][1].items():
	if ignore_priority < priorities[-1]:
	parents.append(parent)
	return parents
}

func(d*digraph) leaf_nodes(ignore_priority=None) {

	leaf_nodes = []
	if ignore_priority is
None:
	for node
	in
	d.order:
	if not d.nodes[node][0]:
	leaf_nodes.append(node)
	elif
	hasattr(ignore_priority, '__call__'):
	for node
	in
	d.order:
	is_leaf_node = true
	for child, priorities
	in
	d.nodes[node][0].items():
	for priority
	in
	reversed(priorities):
	if not ignore_priority(priority):
	is_leaf_node = false
	break
	if not is_leaf_node:
	break
	if is_leaf_node:
	leaf_nodes.append(node)
	else:
	for node
	in
	d.order:
	is_leaf_node = true
	for child, priorities
	in
	d.nodes[node][0].items():
	if ignore_priority < priorities[-1]:
	is_leaf_node = false
	break
	if is_leaf_node:
	leaf_nodes.append(node)
	return leaf_nodes
}

// nil
func(d*digraph) root_nodes(ignore_priority=None) {

	root_nodes = []
	if ignore_priority is
None:
	for node
	in
	d.order:
	if not d.nodes[node][1]:
	root_nodes.append(node)
	elif
	hasattr(ignore_priority, '__call__'):
	for node
	in
	d.order:
	is_root_node = true
	for parent, priorities
	in
	d.nodes[node][1].items():
	for priority
	in
	reversed(priorities):
	if not ignore_priority(priority):
	is_root_node = false
	break
	if not is_root_node:
	break
	if is_root_node:
	root_nodes.append(node)
	else:
	for node
	in
	d.order:
	is_root_node = true
	for parent, priorities
	in
	d.nodes[node][1].items():
	if ignore_priority < priorities[-1]:
	is_root_node = false
	break
	if is_root_node:
	root_nodes.append(node)
	return root_nodes
}

func(d*digraph) __bool__() {
	return bool(d.nodes)
}

func(d*digraph) is_empty() {
	return len(d.nodes) == 0
}

func(d*digraph) clone() {
	clone := NewDigraph()
	clone.nodes =
	{
	}
	memo =
	{
	}
	for children, parents, node
	in
	d.nodes.values():
	children_clone =
	{
	}
	for child, priorities
	in
	children.items():
	priorities_clone = memo.get(id(priorities))
	if priorities_clone is
None:
	priorities_clone = priorities[:]
	memo[id(priorities)] = priorities_clone
	children_clone[child] = priorities_clone
	parents_clone =
	{
	}
	for parent, priorities
	in
	parents.items():
	priorities_clone = memo.get(id(priorities))
	if priorities_clone is
None:
	priorities_clone = priorities[:]
	memo[id(priorities)] = priorities_clone
	parents_clone[parent] = priorities_clone
	clone.nodes[node] = (children_clone, parents_clone, node)
	clone.order = d.order[:]
	return clone
}

func(d*digraph) delnode( node) {
try:
	d.remove(node)
	except
KeyError:
	pass
}

func(d*digraph) firstzero() {
	leaf_nodes = d.leaf_nodes()
	if leaf_nodes:
	return leaf_nodes[0]
	return None
}

func(d*digraph) hasallzeros( ignore_priority=None) {
	return len(d.leaf_nodes(ignore_priority = ignore_priority)) == \
	len(d.order)

	func(d *digraph) debug_print():
	def
	output(s):
	writemsg(s, noiselevel = -1)
	for node
	in
	d.nodes:
	output("%s " % (node, ))
	if d.nodes[node][0]:
	output("depends on\n")
	else:
	output("(no children)\n")
	for child, priorities
	in
	d.nodes[node][0].items():
	output("  %s (%s)\n"%(child, priorities[-1], ))
}

func(d*digraph) bfs( start, ignore_priority=None) {
	if start not
	in
d:
	raise
	KeyError(start)

	queue, enqueued = deque([(None, start)]), set([start])
while queue:
parent, n = queue.popleft()
yield parent, n
new = set(d.child_nodes(n, ignore_priority)) - enqueued
enqueued |= new
queue.extend([(n, child) for child in new])
}

func(d*digraph) shortest_path( start, end, ignore_priority=None) {
	if start not
	in
d:
	raise
	KeyError(start)
	elif
	end
	not
	in
d:
	raise
	KeyError(end)

	paths =
	{
	None:
		[]
	}
	for parent, child
	in
	d.bfs(start, ignore_priority):
	paths[child] = paths[parent] + [child]
	if child == end:
	return paths[child]
	return None
}

func(d*digraph) get_cycles( ignore_priority=None, max_length=None) {
	all_cycles = []
	for node
	in
	d.nodes:
	shortest_path = None
	candidates = []
	for child
	in
	d.child_nodes(node, ignore_priority):
	path = d.shortest_path(child, node, ignore_priority)
	if path is
None:
	continue
	if not shortest_path
	or
	len(shortest_path) >= len(path):
	shortest_path = path
	candidates.append(path)
	if shortest_path and \
	(not
	max_length
	or
	len(shortest_path) <= max_length):
	for path
	in
candidates:
	if len(path) == len(shortest_path):
	all_cycles.append(path)
	return all_cycles
}

func urlopen(Url string, ifModifiedSince string) *http.Response { // false
	parseResult, _ := url.Parse(Url)
	if parseResult.Scheme != "http" && parseResult.Scheme != "https" {
		resp, _ := http.Get(Url)
		return resp
	} else {
		netloc := parseResult.Host
		u := url.URL{
			Scheme:   parseResult.Scheme,
			Host:     netloc,
			Path:     parseResult.Path,
			RawQuery: parseResult.RawQuery,
			Fragment: parseResult.Fragment,
		}
		Url = u.String()
		request, _ := http.NewRequest("GET", Url, nil)
		request.Header.Add("User-Agent", "Gentoo Portage")
		if ifModifiedSince != "" {
			request.Header.Add("If-Modified-Since", timestampToHttp(ifModifiedSince))
		}
		if parseResult.User != nil {
			pswd, _ := parseResult.User.Password()
			request.SetBasicAuth(parseResult.User.Username(), pswd)
		}
		hdl, _ := http.DefaultClient.Do(request)
		hdl.Header.Add("timestamp", httpToTimestamp(hdl.Header.Get("last-modified")))
		return hdl
	}
}

func timestampToHttp(timestamp string) string {
	ts, _ := strconv.Atoi(timestamp)
	dt := time.Unix(int64(ts), 0)
	return dt.Format("Mon Jan 02 15:04:05 -0700 2006")
}

func httpToTimestamp(httpDatetimeString string) string {
	t, _ := dateparse.ParseAny(httpDatetimeString)
	return string(t.Unix())
}

// 0, nil, nil, nil
func _movefile(src, dest string, newmtime int64, sstat os.FileInfo, mysettings *atom.Config, hardlink_candidates []string) int64 {
	if mysettings == nil {
		mysettings = atom.Settings()
	}

	xattr_enabled := mysettings.Features.Features["xattr"]

	selinux_enabled := mysettings.selinux_enabled()
	//// TODO: selinux
	//if selinux_enabled{
	//	selinux = _unicode_module_wrapper(_selinux, encoding = encoding)
	//	_copyfile = selinux.copyfile
	//	_rename = selinux.rename
	//} else{
	_copyfile := copyfile
	_rename := os.Rename
	//}

	if sstat == nil {
		var err error
		sstat, err = os.Lstat(src)
		if err != nil {
			//raise
		}
	}
	destexists := 1
	dstat, err := os.Lstat(dest)
	if err != nil {
		dstat, _ = os.Lstat(filepath.Dir(dest))
	}
	destexists = 0

	// TODO: bsd
	//if bsd_chflags{
	//	if destexists && dstat.st_flags != 0{
	//		bsd_chflags.lchflags(dest, 0)
	//	}
	//	pflags = os.stat(filepath.Dir(dest)).st_flags
	//	if pflags != 0{
	//		bsd_chflags.chflags(filepath.Dir(dest), 0)
	//	}
	//}

	if destexists != 0 {
		if dstat.Mode()&os.ModeSymlink != 0 {
			if err := syscall.Unlink(dest); err == nil {
				destexists = 0
			} else {
				//except SystemExit as e:
				//raise
				//except Exception as e:
				//pass
			}
		}
	}

	if sstat.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err == nil {
			if mysettings != nil {
				if _, ok := mysettings.ValueDict["D"]; ok && strings.HasPrefix(target, mysettings.ValueDict["D"]) {
					target = target[len(mysettings.ValueDict["D"])-1:]
				}
			}
			if destexists != 0 && !dstat.IsDir() {
				err = syscall.Unlink(dest)
			}
		}
		if err == nil {
			var err1 error
			//if selinux_enabled{
			//	selinux.symlink(target, dest, src)
			//}else{
			err1 = os.Symlink(target, dest)
			//}
			if err != syscall.ENOENT && err != syscall.EEXIST {
				err = err1
			} else {
				r, err2 := os.Readlink(dest)
				if err2 != nil {
					err = err2
				} else if r != target {
					err = err1
				}
			}
		}
		err = os.Lchown(dest, int(sstat.Sys().(*syscall.Stat_t).Uid), int(sstat.Sys().(*syscall.Stat_t).Gid))

		if err == nil {
			if err := syscall.Unlink(src); err != nil {
				//except OSError:
				//pass
			}
		}

		if err := syscall.Utime(dest, &syscall.Utimbuf{sstat.Sys().(*syscall.Stat_t).Mtim.Nsec, sstat.Sys().(*syscall.Stat_t).Mtim.Nsec}); err != nil { //follow_symlinks = false
			//except NotImplementedError:
			//return os.stat(dest, follow_symlinks = false).st_mtime_ns else:
		} else {
			return sstat.Sys().(*syscall.Stat_t).Mtim.Nsec
		}
		//return os.lstat(dest)[stat.ST_MTIME]
		if err != nil {
			//except SystemExit as e:
			//raise
			//except Exception as e:
			WriteMsg(fmt.Sprintf("!!! failed to properly create symlink:"), -1, nil)
			WriteMsg(fmt.Sprintf("!!! %s -> %s\n", dest, target), -1, nil)
			WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
			return 0
		}
	}

	hardlinked := false
	if len(hardlink_candidates) > 0 {
		head, tail := filepath.Split(dest)
		hardlink_tmp := filepath.Join(head, fmt.Sprintf(".%s._portage_merge_.%s", tail, os.Getpid()))

		if err := syscall.Unlink(hardlink_tmp); err != nil {
			if err != syscall.ENOENT {
				WriteMsg(fmt.Sprintf("!!! Failed to remove hardlink temp file: %s\n", hardlink_tmp), -1, nil)
				WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
				return 0
			}
			//del e
		}
		for _, hardlink_src := range hardlink_candidates {
			if err := os.Link(hardlink_src, hardlink_tmp); err != nil {
				continue
			} else {
				if err := os.Rename(hardlink_tmp, dest); err != nil {
					WriteMsg(fmt.Sprintf("!!! Failed to rename %s to %s\n", hardlink_tmp, dest), -1, nil)
					WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
					return 0
				}
				hardlinked = true
				if err := syscall.Unlink(src); err != nil {
					//pass
				}
				break
			}
		}
	}

	renamefailed := 1
	if hardlinked {
		renamefailed = 0
	}
	if !hardlinked && (selinux_enabled || sstat.Sys().(*syscall.Stat_t).Dev == dstat.Sys().(*syscall.Stat_t).Dev) {

		var err error
		// TODO: SELINUX
		//if selinux_enabled{
		//	selinux.rename(src, dest)
		//}else {
		err = os.Rename(src, dest)
		//}
		if err == nil {
			renamefailed = 0
		}
		if err != nil {
			if err != syscall.EXDEV {
				WriteMsg(fmt.Sprintf("!!! Failed to move %s to %s\n", src, dest), -1, nil)
				WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
				return 0
			}
		}
	}
	if renamefailed != 0 {
		if sstat.Mode()&0100000 != 0 {
			dest_tmp := dest + "#new"
			err := _copyfile(src, dest_tmp)
			if err == nil {
				err = _apply_stat(sstat, dest_tmp)
			}
			if err == nil {
				if xattr_enabled {
					if err := _copyxattr(src, dest_tmp, mysettings.ValueDict["PORTAGE_XATTR_EXCLUDE"]); err != nil {
						//except SystemExit:
						//raise
						//except:
						msg := "Failed to copy extended attributes. " +
							"In order to avoid this error, set " +
							"FEATURES=\"-xattr\" in make.conf."
						for _, line := range TextWrap(msg, 65) {
							WriteMsg(fmt.Sprintf("!!! %s\n", line), -1, nil)
						}
					}
				}
			}
			if err == nil {
				err = _rename(dest_tmp, dest)
			}
			if err == nil {
				err = syscall.Unlink(src)
			}
			if err != nil {
				//except SystemExit as e:
				//raise
				//except Exception as e:
				//writemsg("!!! %s\n" % _('copy %(src)s -> %(dest)s failed.') %
				//{"src": src, "dest": dest}, noiselevel = -1)
				//writemsg("!!! %s\n" % (e, ), noiselevel = -1)
				return 0
			}
		} else {
			a, _ := atom.spawn([]string{_const.MoveBinary, "-f", src, dest}, ExpandEnv(), "", nil, false, 0, 0, nil, 0, "", "", true, nil, false, false, false, false, false, "")
			if len(a) != 0 && a[0] != syscall.F_OK {
				WriteMsg(fmt.Sprintf("!!! Failed to move special file:\n"), -1, nil)
				WriteMsg(fmt.Sprintf("!!! '%s' to '%s'\n", src, dest), -1, nil)
				WriteMsg(fmt.Sprintf("!!! %s\n", a), -1, nil)
				return 0
			}
		}
	}

	if hardlinked {
		st, err1 := os.Stat(dest)
		if err1 == nil {
			newmtime = st.ModTime().UnixNano()
		}
		err = err1
	} else {
		if newmtime != 0 {
			err = syscall.Utime(dest, &syscall.Utimbuf{newmtime, newmtime})
		} else {
			newmtime = sstat.ModTime().UnixNano()
			if renamefailed != 0 {
				err = syscall.Utime(dest, &syscall.Utimbuf{newmtime, newmtime})
			}
		}
	}
	if err != nil {
		st, err := os.Stat(dest)
		if err == nil {
			newmtime = st.ModTime().UnixNano()
		} else {
			WriteMsg(fmt.Sprintf("!!! Failed to stat in movefile()\n"), -1, nil)
			WriteMsg(fmt.Sprintf("!!! %s\n", dest), -1, nil)
			WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
			return 0
		}
	}

	// TODO: bsd
	//if bsd_chflags{
	//if pflags{
	//bsd_chflags.chflags(path.Dir(dest), pflags)
	//}
	//}

	return newmtime
}

func copyfile(src, dest string) error {
	a, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dest, a, 0644)
}

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

type MtimeDB struct {
	dict        map[string]interface{}
	filename    string
	_json_write bool

	_clean_data map[string]interface{}
}

func (m *MtimeDB) _load(filename string) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		//except EnvironmentError as e:
		if err == syscall.ENOENT || err == syscall.EACCES {
			//pass
		} else {
			WriteMsg(fmt.Sprintf("!!! Error loading '%s': %s\n", filename, err), -1, nil)
		}
	}

	var d map[string]interface{} = nil
	if len(content) > 0 {
		if err := json.Unmarshal(content, &d); err != nil {
			WriteMsg(fmt.Sprintf("!!! Error loading '%s': %s\n", filename, err), -1, nil)
		}
	}

	if d == nil {
		d = map[string]interface{}{}
	}

	if _, ok := d["old"]; ok {
		d["updates"] = d["old"]
		delete(d, "old")
	}
	if _, ok := d["cur"]; ok {
		delete(d, "cur")
	}

	if _, ok := d["starttime"]; !ok {
		d["version"] = 0
	}
	if _, ok := d["version"]; !ok {
		d["version"] = ""
	}
	for _, k := range []string{"info", "ldpath", "updates"} {
		if _, ok := d[k]; !ok {
			d[k] = map[string]interface{}{}
		}
	}

	mtimedbkeys := map[string]bool{"info": true, "ldpath": true, "resume": true, "resume_backup": true,
		"starttime": true, "updates": true, "version": true}

	for k := range d {
		if !mtimedbkeys[k] {
			WriteMsg(fmt.Sprintf("Deleting invalid mtimedb key: %s\n", k), -1, nil)
			delete(d, k)
		}
	}
	for k, v := range d {
		m.dict[k] = v
	}
	d = myutil.CopyMap(m._clean_data)
}

func (m *MtimeDB) Commit() {
	if m.filename == "" {
		return
	}
	d := map[string]interface{}{}
	for k, v := range m.dict {
		d[k] = v
	}
	if !reflect.DeepEqual(d, m._clean_data) {
		d["version"] = fmt.Sprint(atom.VERSION)
		//try:
		f := NewAtomic_ofstream(m.filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, true)
		//except
		//EnvironmentError:
		//	pass
		//	else:
		if m._json_write {
			jd, _ := json.MarshalIndent(d, "", "\t")
			f.Write(jd)
		}
		f.Close()
		apply_secpass_permissions(m.filename,
			uint32(atom.uid), *atom.portage_gid, 0o644, -1, nil, true)
		m._clean_data = myutil.CopyMap(d)
	}
}
func NewMtimeDB(filename string) *MtimeDB {
	m := &MtimeDB{}

	m._json_write = true

	m.dict = map[string]interface{}{}
	m.filename = filename
	m._load(filename)
	return m
}

type NeededEntry struct {
	// slots
	arch, filename, multilib_category, soname string
	needed, runpaths                          []string

	_MIN_FIELDS, _MULTILIB_CAT_INDEX int
}

func (n *NeededEntry) parse(filename, line string) (*NeededEntry, error) {

	fields := strings.Split(line, ";")
	if len(fields) < n._MIN_FIELDS {
		//raise InvalidData(_("Wrong number of fields "
		//"in %s: %s\n\n") % (filename, line))
		return nil, fmt.Errorf("Wrong number of fields in %s: %s\n\n", filename, line)
	}

	n2 := NewNeededEntry()
	if len(fields) > n._MULTILIB_CAT_INDEX && fields[n._MULTILIB_CAT_INDEX] != "" {
		n2.multilib_category = fields[n._MULTILIB_CAT_INDEX]
	} else {
		n2.multilib_category = ""
	}

	fields = fields[:n._MIN_FIELDS]
	n2.arch, n2.filename, n2.soname = fields[0], fields[1], fields[2]
	rpaths, needed := fields[3], fields[4]
	n2.runpaths = []string{}
	for _, v := range strings.Split(rpaths, ":") {
		if v != "" {
			n2.runpaths = append(n2.runpaths, v)
		}
	}
	n2.needed = []string{}
	for _, v := range strings.Split(needed, ",") {
		if v != "" {
			n2.runpaths = append(n2.needed, v)
		}
	}

	return n2, nil
}

func (n *NeededEntry) __str__() string {
	return n.arch + ";" +
		n.filename + ";" +
		n.soname + ";" +
		strings.Join(n.runpaths, ":") + ";" +
		strings.Join(n.needed, ",") + ";" +
		n.multilib_category + "\n"
}

func NewNeededEntry() *NeededEntry {
	n := &NeededEntry{}

	n._MIN_FIELDS = 5
	n._MULTILIB_CAT_INDEX = 5

	return n
}

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

// 1, "", nil, nil, nil, nil, nil
func env_update(makelinks int, target_root string, prev_mtimes=None, contents map[string][]string,
env *atom.Config, writemsg_level func(string, int, int), vardbapi *atom.vardbapi) {
	if vardbapi == nil {
		vardbapi = atom.NewVarTree(nil, env).dbapi
	}

	vardbapi._fs_lock()
	defer vardbapi._fs_unlock()
	_env_update(makelinks, target_root, prev_mtimes, contents,
		env, writemsg_level)
}

func _env_update(makelinks int, target_root string, prev_mtimes map[string]int, contents map[string][]string, envC *atom.Config,
writemsg_level func(string, int, int)) {
	if writemsg_level == nil {
		writemsg_level = WriteMsgLevel
	}
	if target_root == "" {
		target_root = atom.Settings().ValueDict["ROOT"]
	}
	if prev_mtimes == nil {
		prev_mtimes = portage.mtimedb["ldpath"]
	}
	var settings *atom.Config
	if envC == nil {
		settings = atom.Settings()
	} else {
		settings = envC
	}

	eprefix := settings.ValueDict["EPREFIX"]
	eprefix_lstrip := strings.TrimLeft(eprefix, string(os.PathSeparator))
	eroot := strings.TrimRight(NormalizePath(filepath.Join(target_root, eprefix_lstrip)), string(os.PathSeparator)) + string(os.PathSeparator)
	envd_dir := filepath.Join(eroot, "etc", "env.d")
	ensureDirs(envd_dir, -1, -1, 0755, -1, nil, true)
	fns := listdir(envd_dir, false, false, false, []string{}, true, true, false)
	sort.Strings(fns)
	templist := []string{}
	for _, x := range fns {
		if len(x) < 3 {
			continue
		}
		if !unicode.IsDigit(rune(x[0])) || !unicode.IsDigit(rune(x[1])) {
			continue
		}
		if strings.HasPrefix(x, ".") || strings.HasSuffix(x, "~") || strings.HasSuffix(x, ".bak") {
			continue
		}
		templist = append(templist, x)
	}
	fns = templist

	templist = nil

	space_separated := map[string]bool{"CONFIG_PROTECT": true, "CONFIG_PROTECT_MASK": true}
	colon_separated := map[string]bool{"ADA_INCLUDE_PATH": true, "ADA_OBJECTS_PATH": true,
		"CLASSPATH": true, "INFODIR": true, "INFOPATH": true, "KDEDIRS": true, "LDPATH": true, "MANPATH": true,
		"PATH": true, "PKG_CONFIG_PATH": true, "PRELINK_PATH": true, "PRELINK_PATH_MASK": true,
		"PYTHONPATH": true, "ROOTPATH": true}

	config_list := []map[string]string{}

	for _, x := range fns {
		file_path := filepath.Join(envd_dir, x)
		//try:
		myconfig := getConfig(file_path, false, false, false, false, nil)
		//except ParseError as e:
		//writemsg("!!! '%s'\n"%str(e), noiselevel = -1)
		//del e
		//continue
		if myconfig == nil {
			WriteMsg(fmt.Sprintf("!!! File Not Found: '%s'\n", file_path), -1, nil)
			continue
		}

		config_list = append(config_list, myconfig)
		if myutil.Inmss(myconfig, "SPACE_SEPARATED") {
			for _, v := range strings.Fields(myconfig["SPACE_SEPARATED"]) {
				space_separated[v] = true
			}
			delete(myconfig, "SPACE_SEPARATED")
		}
		if myutil.Inmss(myconfig, "COLON_SEPARATED") {
			for _, v := range strings.Fields(myconfig["COLON_SEPARATED"]) {
				colon_separated[v] = true
			}
			delete(myconfig, "COLON_SEPARATED")
		}
	}

	env := map[string]string{}
	specials := map[string][]string{}
	for v := range space_separated {
		mylist := []string{}
		for _, myconfig := range config_list {
			if myutil.Inmss(myconfig, v) {
				for _, item := range strings.Fields(myconfig[v]) {
					if item != "" && !myutil.Ins(mylist, item) {
						mylist = append(mylist, item)
					}
				}
				delete(myconfig, v)
			}
		}
		if len(mylist) > 0 {
			env[v] = strings.Join(mylist, " ")
			specials[v] = mylist
		}
	}

	env := map[string]string{}
	specials := map[string][]string{}
	for v := range colon_separated {
		mylist := []string{}
		for _, myconfig := range config_list {
			if myutil.Inmss(myconfig, v) {
				for _, item := range strings.Fields(myconfig[v]) {
					if item != "" && !myutil.Ins(mylist, item) {
						mylist = append(mylist, item)
					}
				}
				delete(myconfig, v)
			}
		}
		if len(mylist) > 0 {
			env[v] = strings.Join(mylist, " ")
			specials[v] = mylist
		}
	}

	for _, myconfig := range config_list {
		for k, v := range myconfig {
			env[k] = v
		}
	}

	ldsoconf_path := filepath.Join(eroot, "etc", "ld.so.conf")

	oldld := []string{}
	myld, err := ioutil.ReadFile(ldsoconf_path)
	if err == nil {
		myldlines := strings.Split(string(myld), "\n")
		for _, x := range myldlines {
			if x[:1] == "#" {
				continue
			}
			oldld = append(oldld, x[:len(x)-1])
		}
	} else {
		//except (IOError, OSError) as e:
		if err != syscall.ENOENT {
			//raise
		}
	}

	newld := specials["LDPATH"]
	if len(oldld) != len(newld) {
		eq := true
		for i := range oldld {
			if oldld[i] != newld[i] {
				eq = false
				break
			}
		}
		if eq {
			myfd := NewAtomic_ofstream(ldsoconf_path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, true)
			myfd.Write([]byte("# ld.so.conf autogenerated by env-update; make all changes to\n"))
			myfd.Write([]byte("# contents of /etc/env.d directory\n"))
			for _, x := range specials["LDPATH"] {
				myfd.Write([]byte(x + "\n"))
			}
			myfd.Close()
		}
	}

	potential_lib_dirs := map[string]bool{}
	for _, lib_dir_glob := range []string{"usr/lib*", "lib*"} {
		x := filepath.Join(eroot, lib_dir_glob)
		glb, _ := filepath.Glob(x)
		for _, y := range glb {
			if filepath.Base(y) != "libexec" {
				potential_lib_dirs[y[len(eroot):]] = true
			}
		}
	}

	if atom.prelinkCapable {
		prelink_d := filepath.Join(eroot, "etc", "prelink.conf.d")
		ensureDirs(prelink_d, -1, -1, -1, -1, nil, true)
		newprelink := NewAtomic_ofstream(filepath.Join(prelink_d, "portage.conf"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
		newprelink.Write([]byte("# prelink.conf autogenerated by env-update; make all changes to\n"))
		newprelink.Write([]byte("# contents of /etc/env.d directory\n"))

		for _, x := range append(atom.sortedmsb(potential_lib_dirs), "bin", "sbin") {
			newprelink.Write([]byte(fmt.Sprintf("-l /%s\n", x, )))
		}
		prelink_paths := map[string]bool{}
		for _, v := range specials["LDPATH"] {
			prelink_paths[v] = true
		}
		for _, v := range specials["PATH"] {
			prelink_paths[v] = true
		}
		for _, v := range specials["PRELINK_PATH"] {
			prelink_paths[v] = true
		}
		prelink_path_mask := specials["PRELINK_PATH_MASK"]
		for x := range prelink_paths {
			if x == "" {
				continue
			}
			if x[len(x)-1:] != "/" {
				x += "/"
			}
			plmasked := 0
			for _, y := range prelink_path_mask {
				if y == "" {
					continue
				}
				if y[len(y)-1] != '/' {
					y += "/"
				}
				if y == x[0:len(y)] {
					plmasked = 1
					break
				}
			}
			if plmasked == 0 {
				newprelink.Write([]byte(fmt.Sprintf("-h %s\n", x, )))
			}
		}
		for _, x := range prelink_path_mask {
			newprelink.Write([]byte(fmt.Sprintf("-b %s\n", x, )))
		}
		newprelink.Close()

		prelink_conf := filepath.Join(eroot, "etc", "prelink.conf")

		f, err := ioutil.ReadFile(prelink_conf)
		if err != syscall.ENOENT {
			//raise
		}
		if strings.Split(string(f), "\n")[0] == "# prelink.conf autogenerated by env-update; make all changes to\\n" {

			f := NewAtomic_ofstream(prelink_conf, os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
			f.Write([]byte("-c /etc/prelink.conf.d/*.conf\n"))
			f.Close()
		}
	}

	current_time := time.Now().Nanosecond()
	mtime_changed := false

	lib_dirs := map[string]bool{}
	spld := map[string]bool{}
	for _, k := range specials["LD_PATH"] {
		spld[k] = true
	}
	for k := range potential_lib_dirs {
		spld[k] = true
	}

	for lib_dir := range spld {
		x := filepath.Join(eroot, strings.TrimLeft(lib_dir, string(os.PathSeparator)))
		st, err := os.Stat(x)
		if err != nil {
			//except OSError as oe:
			if err == syscall.ENOENT {
				delete(prev_mtimes, x)
				continue
			}
			//raise
		} else {
			lib_dirs[NormalizePath(x)] = true
		}
		newldpathtime := st.ModTime().Nanosecond()
		if newldpathtime == current_time {
			newldpathtime -= 1
			syscall.Utime(x, &syscall.Utimbuf{int64(newldpathtime), int64(newldpathtime)})
			prev_mtimes[x] = newldpathtime
			mtime_changed = true
		} else if _, ok := prev_mtimes[x]; ok {
			if prev_mtimes[x] == newldpathtime {
				//pass
			} else {
				prev_mtimes[x] = newldpathtime
				mtime_changed = true
			}
		} else {
			prev_mtimes[x] = newldpathtime
			mtime_changed = true
		}
	}

	if makelinks != 0 && !mtime_changed && contents != nil {
		libdir_contents_changed := false
		for mypath, mydata := range contents {
			if mydata[0] != "obj" && mydata[0] != "sym" {
				continue
			}
			head, _ := filepath.Split(mypath)
			if lib_dirs[head] {
				libdir_contents_changed = true
				break
			}
		}
		if !libdir_contents_changed {
			makelinks = 0
		}
	}

	ldconfig := ""
	if myutil.Inmss(settings.ValueDict, "CHOST") && myutil.Inmss(settings.ValueDict, "CBUILD") && settings["CHOST"] != settings["CBUILD"] {
		ldconfig = process.FindBinary(fmt.Sprintf("%s-ldconfig", settings.ValueDict["CHOST"]))
	} else {
		ldconfig = filepath.Join(eroot, "sbin", "ldconfig")
	}

	if ldconfig == "" {
		//pass
	} else if !(atom.osAccess(ldconfig, unix.X_OK) && atom.pathIsFile(ldconfig)) {
		ldconfig = ""
	}

	if makelinks != 0 && ldconfig != "" {
		if atom.ostype == "Linux" || strings.HasSuffix(strings.ToLower(atom.ostype), "gnu") {
			writemsg_level(fmt.Sprintf(">>> Regenerating %setc/ld.so.cache...\n",
				target_root, ), 0, 0)
			exec.Command("sh", "-c", fmt.Sprintf("cd / ; %s -X -r '%s'", ldconfig, target_root))
		} else if atom.ostype == "FreeBSD" || atom.ostype == "DragonFly" {
			writemsg_level(fmt.Sprintf(">>> Regenerating %svar/run/ld-elf.so.hints...\n",
				target_root), 0, 0)
			exec.Command("sh", "-c", fmt.Sprintf("cd / ; %s -elf -i "+
				"-f '%svar/run/ld-elf.so.hints' '%setc/ld.so.conf'", ldconfig, target_root, target_root))
		}
	}

	delete(specials, "LDPATH")

	penvnotice := "# THIS FILE IS AUTOMATICALLY GENERATED BY env-update.\n"
	penvnotice += "# DO NOT EDIT THIS FILE. CHANGES TO STARTUP PROFILES\n"
	cenvnotice := penvnotice[:]
	penvnotice += "# GO INTO /etc/profile NOT /etc/profile.env\n\n"
	cenvnotice += "# GO INTO /etc/csh.cshrc NOT /etc/csh.env\n\n"

	outfile := NewAtomic_ofstream(filepath.Join(eroot, "etc", "profile.env"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, true)
	outfile.Write([]byte(penvnotice))
	env_keys := []string{}
	for x := range env {
		if x != "LDPATH" {
			env_keys = append(env_keys, x)
		}
	}
	sort.Strings(env_keys)
	for _, k := range env_keys {
		v := env[k]
		if strings.HasPrefix(v, "$") && !strings.HasPrefix(v, "${") {
			outfile.Write([]byte(fmt.Sprintf("export %s=$'%s'\n", k, v[1:])))
		} else {
			outfile.Write([]byte(fmt.Sprintf("export %s='%s'\n", k, v)))
		}
	}
	outfile.Close()

	outfile = NewAtomic_ofstream(filepath.Join(eroot, "etc", "csh.env"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, true)
	outfile.Write([]byte(cenvnotice))
	for _, x := range env_keys {
		outfile.Write([]byte(fmt.Sprintf("setenv %s '%s'\n", x, env[x])))
	}
	outfile.Close()
}

func ExtractKernelVersion(base_dir string) (string,error) {
	pathname := filepath.Join(base_dir, "Makefile")
	f, err := ioutil.ReadFile(pathname)
	if err != nil {
		//except OSError as details:
		//return (None, str(details))
		//except IOError as details:
		return "", err
	}

	lines := strings.Split(string(f), "\n")[:4]
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}

	version := ""

	for _, line := range lines {
		items := strings.Split(line, "=")

		for i := range items {
			items[i] = strings.TrimSpace(items[i])
		}
		if items[0] == "VERSION" ||
			items[0] == "PATCHLEVEL" {
			version += items[1]
			version += "."
		} else if items[0] == "SUBLEVEL" {
			version += items[1]
		} else if items[0] == "EXTRAVERSION" &&
			items[len(items)-1] != items[0] {
			version += items[1]
		}
	}

	localversions, _ := atom.listDir(base_dir)
	for x := len(localversions) - 1; x >= 0; x-- {
		if localversions[x][:12] != "localversion" {
			lvs := []string{}
			for i, k := range localversions {
				if i != x {
					lvs = append(lvs, k)
				}
			}
			localversions = lvs
		}
	}
	sort.Strings(localversions)

	for _, lv := range localversions {
		gf := grabFile(base_dir+"/"+lv, 0, false, false)
		fs := []string{}
		for _, k := range gf {
			fs = append(fs, k[0])
		}
		version += strings.Join(strings.Fields(strings.Join(fs, " ")), "")
	}

	loader := atom.NewKeyValuePairFileLoader(filepath.Join(base_dir, ".config"), nil, nil)
	kernelconfig, loader_errors := loader.load()
	if len(loader_errors) > 0 {
		for file_path, file_errors := range loader_errors {
			for _, error_str := range file_errors {
				WriteMsgLevel(fmt.Sprintf("%s: %s\n", file_path, error_str), 40, -1)
			}
		}
	}

	if len(kernelconfig) > 0 && myutil.Inmsss(kernelconfig, "CONFIG_LOCALVERSION") {
		ss, _ := shlex.Split(strings.NewReader(kernelconfig["CONFIG_LOCALVERSION"][0]), false, true)
		version += strings.Join(ss, "")
	}

	return version, nil
}
