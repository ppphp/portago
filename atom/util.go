package atom

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/noaway/dateparse"
	"github.com/pkg/xattr"
	"github.com/ppphp/configparser"
	"github.com/ppphp/shlex"
)

var noiseLimit = 0

func WriteMsg(mystr string, noiseLevel int, fd *os.File) { //0n
	if fd == nil {
		fd = os.Stderr
	}
	if noiseLevel <= noiseLimit {
		fd.Write([]byte(mystr))
	}
}

func writeMsgStdout(mystr string, noiseLevel int) { //0
	WriteMsg(mystr, noiseLevel, os.Stdout)
}

func WriteMsgLevel(msg string, level, noiselevel int) { //00
	var fd *os.File
	if level >= 30 {
		fd = os.Stderr
	} else {
		fd = os.Stdout
	}
	WriteMsg(msg, noiselevel, fd)
}

func NormalizePath(myPath string) string {
	return path.Clean(myPath)
}

func grabFile(myFileName string, compatLevel int, recursive, rememberSourceFile bool) [][2]string { // 00f
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
			mylineTest := strings.SplitN(m, "<==", 1)
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

func stackDictlist(originalDicts []map[string][]string, incremental int, incrementals []string, ignoreNone int) map[string][]string { // false, []string{}, false
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
	for _, mydict := range dicts {
		if mydict == nil {
			continue
		}
		for k, v := range mydict {
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
	A *Atom
	S string
}

func appendRepo(atomList map[*Atom]string, repoName string, rememberSourceFile bool) []AS {
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

func stackLists(lists [][][2]string, incremental int, rememberSourceFile, warnForUnmatchedRemoval, strictWarnForUnmatchedRemoval, ignoreRepo bool) map[*Atom]string { //1,false,false,false,false
	matchedRemovals := map[[2]string]bool{}
	unmatchedRemovals := map[string][]string{}
	newList := map[*Atom]string{}
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
					newList = map[*Atom]string{}
				} else if token[:1] == "-" {
					matched := false
					if ignoreRepo && !strings.Contains(token, "::") {
						toBeRemoved := []*Atom{}
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
					newList[&Atom{value: token}] = sourceFile
				}
			} else {
				newList[&Atom{value: token}] = sourceFile
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

func grabDict(myFileName string, justStrings, empty, recursive, incremental, newLines bool) map[string][]string { // false, false, false, true, false
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

func grabDictPackage(myfilename string, juststrings, recursive, newlines bool, allowWildcard, allowRepo, allowBuildId, allowUse, verifyEapi bool, eapi, eapiDefault string) map[*Atom][]string { //000ffftf none 0
	fileList := []string{}
	if recursive {
		fileList = recursiveFileList(myfilename)
	} else {
		fileList = []string{myfilename}
	}
	atoms := map[*Atom][]string{}
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
			a, err := NewAtom(k, nil, allowWildcard, &allowRepo, nil, eapi, nil, &allowBuildId)
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

func grabFilePackage(myfilename string, compatLevel int, recursive, allowWildcard, allowRepo, allowBuildId, rememberSourceFile, verifyEapi bool, eapi, eapiDefault string) [][2]string { // 0,false,false,false,false,false,false,nil,0
	pkgs := grabFile(myfilename, compatLevel, recursive, true)
	if len(pkgs) == 0 {
		return pkgs
	}
	if verifyEapi && eapi == "" {
		eapi = readCorrespondingEapiFile(myfilename, eapiDefault)
	}
	myBaseName := path.Base(myfilename)
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

		if _, err := NewAtom(pkg, nil, allowWildcard, &allowRepo, nil, eapi, nil, &allowBuildId); err != nil {
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
			if VcsDirs[fname] || !recursiveBasenameFilter(fname) {
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

func doStat(fname string, followLinks bool) (os.FileInfo, error) {
	if followLinks {
		return os.Stat(fname)
	} else {
		return os.Lstat(fname)
	}
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
	newfile = varExpand(newfile, g.varExpandMap, "")
	return g.Shlex.SourceHook(newfile)
}

func NewGetConfgShlex(instream io.Reader, infile string, posix bool, punctuation_chars string, portageTolerant bool) *getConfigShlex {
	g := &getConfigShlex{portageTolerant: portageTolerant}
	g.Shlex = shlex.NewShlex(instream, infile, posix, punctuation_chars)

	return g
}

var invalidVarNameRe = regexp.MustCompile("^\\d|\\W")

func getConfig(mycfg string, tolerant, allowSourcing, expand, recursive bool, expandMap map[string]string) map[string]string {
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
		for _, fname = range recursiveFileList(mycfg) {
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

	f, err := os.Open(mycfg)
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
		WriteMsg(fmt.Sprintf("!!! Please use dos2unix to convert line endings in config file: '%s'\n", mycfg), -1, nil)
	}
	lex := NewGetConfgShlex(strings.NewReader(content), mycfg, true, "", tolerant)
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

func varExpand(myString string, mydict map[string]string, errorLeader string) string {
	if mydict == nil {
		mydict = map[string]string{}
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
						if errorLeader != "" {
							msg = errorLeader + msg
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
							if errorLeader != "" {
								msg = errorLeader + msg
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
						if errorLeader != "" {
							msg = errorLeader + msg
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
					if errorLeader != "" {
						msg = errorLeader + msg
					}
					WriteMsg(msg+"\n", -1, nil)
					return ""
				}
				numVars += 1
				if _, ok := mydict[myVarName]; ok {
					newString = append(newString, mydict[myVarName])
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
func apply_stat_permissions(filename string, newstat os.FileInfo, mask os.FileMode, stat_cached os.FileInfo, follow_links bool) bool {
	st := newstat.Sys().(*syscall.Stat_t)
	return apply_secpass_permissions(filename, st.Uid, st.Gid, newstat.Mode(), mask, stat_cached, follow_links)
}

// -1, -1, -1, -1, nil, true
func apply_secpass_permissions(filename string, uid, gid uint32, mode, mask os.FileMode, stat_cached os.FileInfo, follow_links bool) bool {

	if stat_cached == nil {
		stat_cached, _ = doStat(filename, follow_links)
	}

	all_applied := true

	if (int(uid) != -1 || int(gid) != -1) && secpass != nil && *secpass < 2 {
		if int(uid) != -1 && uid != stat_cached.Sys().(*syscall.Stat_t).Uid {
			all_applied = false
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
		if int(uid) != -1 && gid != stat_cached.Sys().(*syscall.Stat_t).Gid && !in {
			all_applied = false
			gid = -1
		}
	}

	applyPermissions(filename, uid, gid, mode, mask,
		stat_cached, follow_links)
	return all_applied
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
	real_name := a._real_name
	if err := f.Close(); err != nil {
		return err
	}
	if !a._aborted {
		st, _ := os.Stat(real_name)
		apply_stat_permissions(f.Name(), st, -1, nil, true)
		if err := os.Rename(f.Name(), real_name); err != nil {
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
		canonical_path, _ := filepath.EvalSymlinks(filename)
		a._real_name = canonical_path
		tmp_name := fmt.Sprintf("%s.%i", canonical_path, os.Getpid())
		var err error
		a._file, err = os.OpenFile(tmp_name, mode, 0644)
		if err == nil {
			return a
		}
		if err != nil {
			if canonical_path == filename {
				//raise
			}
		}
	}
	a._real_name = filename
	tmp_name := fmt.Sprintf("%s.%i", filename, os.Getpid())

	a._file, _ = os.OpenFile(tmp_name, mode, 0644)
	return a
}

// 0 (i dont know), true
func write_atomic(file_path string, content string, mode int, follow_links bool) {
	f := NewAtomic_ofstream(file_path, mode, follow_links)
	f.Write([]byte(content))
	f.Close()
	//except (IOError, OSError) as e:
	//if f:
	//f.abort()
	//func_call = "write_atomic('%s')" % file_path
	//if e.errno == errno.EPERM:
	//raise OperationNotPermitted(func_call)
	//elif e.errno == errno.EACCES:
	//raise PermissionDenied(func_call)
	//elif e.errno == errno.EROFS:
	//raise ReadOnlyFileSystem(func_call)
	//elif e.errno == errno.ENOENT:
	//raise FileNotFound(file_path)
	//else:
	//raise
}

// -1,-1,-1,-1,nil,true
func ensureDirs(dirpath string, uid, gid uint32, mode, mask os.FileMode, statCached os.FileInfo, followLinks bool) bool {
	createdDir := false
	if err := os.MkdirAll(dirpath, 0755); err == nil {
		createdDir = true
	} // TODO check errno
	permsModified := false
	if int(uid) != -1 || int(gid) != -1 || int(mode) != -1 || int(mask) != -1 || statCached != nil || followLinks {
		permsModified = applyPermissions(dirpath, uid, gid, mode, mask, statCached, followLinks)
	} else {
		permsModified = false
	}
	return createdDir || permsModified
}

func NewProjectFilename(mydest, newmd5 string, force bool) string {
	protNum := -1
	lastFile := ""
	if _, err := os.Open(mydest); !force && !os.IsNotExist(err) {
		return mydest
	}
	realFilename := path.Base(mydest)
	realDirname := path.Dir(mydest)
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
	if len(lastFile) != 0 && len(newmd5) != 0 {
		oldPfileSt, err := os.Lstat(oldPFile)
		if err != nil {
			if oldPfileSt.Mode()&os.ModeSymlink != 0 {
				pfileLink, err := os.Readlink(oldPFile)
				if err != nil {
					if pfileLink == newmd5 {
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

func readConfigs(parser configparser.ConfigParser, paths []string) error {
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
	_json_write      bool
	_json_write_opts map[string]bool
	_root, _filename string
	_data, _lock     interface{}
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
	_dbapi                                                            *vardbapi
	_root                                                             string
	_libs, _obj_properties, _obj_key_cache, _defpath, _path_key_cache map[string]string
}

func NewLinkageMapELF(vardbapi *vardbapi) *linkageMapELF {
	l := &linkageMapELF{}
	l._dbapi = vardbapi
	l._root = l._dbapi.settings.ValueDict["ROOT"]
	l._libs = map[string]string{}
	l._obj_properties = map[string]string{}
	l._obj_key_cache = map[string]string{}
	l._defpath = map[string]string{}
	l._path_key_cache = map[string]string{}
	return l
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

// nil, nil, 0, nil
func _movefile(src, dest string, newmtime int64, sstat os.FileInfo, mysettings *Config, hardlink_candidates []string) int64 {
	if mysettings == nil {
		mysettings = Settings()
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
	//	pflags = os.stat(os.path.dirname(dest)).st_flags
	//	if pflags != 0{
	//		bsd_chflags.chflags(os.path.dirname(dest), 0)
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

		if err := syscall.Utime(dest, &syscall.Utimbuf{sstat.Sys().(*syscall.Stat_t).Mtim.Nsec, sstat.Sys().(*syscall.Stat_t).Mtim.Nsec}); err != nil { //follow_symlinks = False
			//except NotImplementedError:
			//return os.stat(dest, follow_symlinks = False).st_mtime_ns else:
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
			a, _ := spawn([]string{MoveBinary, "-f", src, dest}, ExpandEnv(), "", nil, false, 0, 0, nil, 0, "", "", true, nil, false, false, false, false, false, "")
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

func _apply_stat(src_stat os.FileInfo, dest string) error {
	err := os.Chown(dest, int(src_stat.Sys().(*syscall.Stat_t).Uid), int(src_stat.Sys().(*syscall.Stat_t).Gid))
	if err != nil {
		return err
	}
	return os.Chmod(dest, os.FileMode(src_stat.Sys().(*syscall.Stat_t).Mode))
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
		//if e.errno != OperationNotSupported.errno:
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
