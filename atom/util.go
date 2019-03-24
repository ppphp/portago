package atom

// a colleciton of util in lib/portage/util

import (
	"bytes"
	"fmt"
	"github.com/google/shlex"
	"github.com/ppphp/configparser"
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

func writeMsgLevel(msg string, level, noiselevel int) { //00
	var fd *os.File
	if level >= 30 {
		fd = os.Stderr
	} else {
		fd = os.Stdout
	}
	WriteMsg(msg, noiselevel, fd)
}

func NormalizePath(mypath string) string {
	return path.Clean(mypath)
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

func stackDictlist(originalDicts []map[string][]string, incremental int, incrementals []string, ignoreNone int) map[string][]string { //0[]0
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

func appendRepo(atomList []AS, repoName string, rememberSourceFile bool) []SB {
	sb := []SB{}
	if rememberSourceFile {
		for _, v := range atomList {
			atom := v.A
			source := v.S
			sb = append(sb, SB{B: atom.repo != "" && atom != nil || atom.withRepo(repoName) != nil, S: source})
		}
	} else {
		for _, v := range atomList {
			atom := v.A
			sb = append(sb, SB{B: atom.repo != "" && atom != nil || atom.withRepo(repoName) != nil, S: ""})
		}
	}
	return sb
}

func stackLists(lists [][][2]string, incremental int, rememberSourceFile, warnForUnmatchedRemoval, strictWarnForUnmatchedRemoval, ignoreRepo bool) map[*Atom]string { //1ffff
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
				WriteMsg(fmt.Sprintf("--- Unmatched removal atoms in %s: %s and %s more\n", sourceFile, strings.Join(selected, ", "), len(tokens)), -1, nil)
			} else {
				WriteMsg(fmt.Sprintf("--- Unmatched removal Atom(s) in %s: %s\n", sourceFile, strings.Join(tokens, ", ")), -1, nil)
			}
		}
	}
	return newList
}

func grabDict(myFileName string, justStrings, empty, recursive, incremental, newLines bool) map[string][]string { // 00010
	newDict := map[string][]string{}
	for _, x := range grabLines(myFileName, recursive, false) {
		v := x[0]
		if v[0] == '#' {
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
	f, _ := os.Open(eapiFile)
	r, _ := ioutil.ReadAll(f)
	lines := strings.Split(string(r), "\n")
	if len(lines) == 1 {
		eapi = strings.TrimSuffix(lines[0], "\n")
	} else {
		WriteMsg(fmt.Sprintf("--- Invalid 'eapi' file (doesn't contain exactly one line): %s\n", eapiFile), -1, nil)
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
				if !allowUse && a.use != nil {
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

func grabFilePackage(myfilename string, compatLevel, recursive int, allowWildcard, allowRepo, allowBuildId, rememberSourceFile, verifyEapi bool, eapi, eapiDefault string) [][2]string { // 00fffffn0
	pkgs := grabFile(myfilename, compatLevel, recursive != 0, true)
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
			if myMode&unix.W_OK == 0 {
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
	source          string
	varExpandMap    map[string]string
	portageTolerant bool
}

func (g *getConfigShlex) allowSourcing(varExpandMap map[string]string) {
	g.source = "source"
	g.varExpandMap = varExpandMap
}

func NewGetConfgShlex(portageTolerant bool) *getConfigShlex {
	//shlex.shlex.__init__(self, **kwargs)
	return &getConfigShlex{portageTolerant: portageTolerant}
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

	f, _ := os.Open(mycfg)
	c, _ := ioutil.ReadAll(f)
	content := string(c)
	f.Close()

	if content != "" && content[len(content)-1] != '\n' {
		content += "\n"
	}
	if strings.Contains(content, "\r") {
		WriteMsg(fmt.Sprintf("!!! Please use dos2unix to convert line endings in config file: '%s'\n", mycfg), -1, nil)
	}
	//lex := NewGetConfgShlex(tolerant)
	lex := shlex.NewLexer(f)
	//lex.wordchars = portage._native_string(string.digits + string.ascii_letters + r"~!@#$%*_\:;?,./-+{}")
	//lex.quotes = portage._native_string("\"'")
	//if allowSourcing {
	//	lex.allowSourcing(expandMap)
	//}
	for {
		key, _ := lex.Next()
		if key == "export" {
			key, _ = lex.Next()
		}
		if key == "" {
			break
		}
		equ, _ := lex.Next()
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
		val, _ := lex.Next()
		if val == "" {
			msg := fmt.Sprintf("Unexpected end of config file: variable '%s'", key) //TODO error_leader
			if !tolerant {
				//raise ParseError(msg)
			} else {
				WriteMsg(fmt.Sprintf("%s\n", msg), -1, nil)
				return myKeys
			}
		}
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
	var numVars, insing, indoub, pos int
	length := len(myString)
	newString := []string{}
	for pos < length {
		current := myString[pos]
		if current == ' ' {
			if indoub > 0 {
				newString = append(newString, "'")
			} else {
				newString = append(newString, "'")
				insing = 1 - insing
			}
			pos += 1
			continue
		} else if current == '"' {
			if insing > 0 {
				newString = append(newString, "\"")
			} else {
				newString = append(newString, "\"")
				indoub = 1 - indoub
			}
			continue
		}
		if insing <= 0 {
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
					newString = append(newString, string(myVarName))
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
	if err != os.ErrPermission {
		return false
	}
	return f.IsDir()
}

type slotObject struct {
	weakRef string
}

func applyPermissions(filename string, uid, gid, mode, mask int, statCached os.FileInfo, followLinks bool) bool {
	modified := false
	if statCached == nil {
		statCached, _ = doStat(filename, followLinks)
	}
	if (uid != -1 && uid != int(statCached.Sys().(*syscall.Stat_t).Uid)) || (gid != -1 && gid != int(statCached.Sys().(*syscall.Stat_t).Gid)) {
		if followLinks {
			syscall.Chown(filename, uid, gid)
		} else {
			os.Lchown(filename, uid, gid)
		}
		modified = true
	} // TODO check errno
	newMode := -1
	stMode := int(uint32(statCached.Mode()) & 07777)
	if mask >= 0 {
		if mode == -1 {
			mode = 0
		} else {
			mode = mode & 07777
		}
		if (stMode&mask != mode) || ((mask^int(uint32(stMode)))&stMode != stMode) {
			newMode = mode | int(uint32(stMode))
			newMode = (mask ^ newMode) & newMode
		}
	} else if mode != -1 {
		mode = mode & 07777
		if mode != int(uint32(stMode)) {
			newMode = mode
		}
	}
	if modified && int(uint32(stMode)) == -1 && (int(uint32(stMode))&unix.S_ISUID != 0 || int(uint32(stMode))&unix.S_ISGID != 0) {
		if mode == -1 {
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
	if newMode != -1 {
		os.Chmod(filename, os.FileMode(newMode))
	}
	return modified
}

func ensureDirs(dirpath string, uid, gid, mode, mask int, statCached os.FileInfo, followLinks bool) bool {
	createdDir := false
	if err := os.MkdirAll(dirpath, 0755); err == nil {
		createdDir = true
	} // TODO check errno
	permsModified := false
	if uid != -1 || gid != -1 || mode != -1 || mask != -1 || statCached != nil || followLinks {
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
	newPfile := NormalizePath(path.Join(realDirname, ".cfg"+fmt.Sprintf("%04s", string(protNum))+"_"+realFilename))
	oldPfile := NormalizePath(path.Join(realDirname, lastFile))
	if len(lastFile) != 0 && len(newmd5) != 0 {
		oldPfileSt, err := os.Lstat(oldPfile)
		if err != nil {
			if oldPfileSt.Mode()&os.ModeSymlink != 0 {
				pfileLink, err := os.Readlink(oldPfile)
				if err != nil {
					if pfileLink == newmd5 {
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

func readConfigs(parser *configparser.Configuration, paths []string) {
	for _, p := range paths {
		parser.ReadFile(p)
	}
}

func expandEnv() map[string]string {
	m := map[string]string{}
	for _, v := range os.Environ() {
		s := strings.SplitN(v, "=", 2)
		if len(s) == 2 {
			m[s[0]] = s[1]
		}
	}
	return m
}
