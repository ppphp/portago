package util

import (
	"bytes"
	"fmt"
	"github.com/ppphp/portago/pkg/checksum"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/util/grab"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/util/permissions"
	"github.com/ppphp/shlex"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

type SB struct {
	S string
	B bool
}

type AS[T interfaces.ISettings] struct {
	A *dep.Atom[T]
	S string
}

func AppendRepo[T interfaces.ISettings](atomList map[*dep.Atom[T]]string, repoName string, rememberSourceFile bool) []AS[T] {
	sb := []AS[T]{}
	if rememberSourceFile {
		for atom, source := range atomList {
			if atom.Repo != "" && atom != nil {
				sb = append(sb, AS[T]{atom, source})
			} else if a := atom.WithRepo(repoName); a != nil {
				sb = append(sb, AS[T]{a, source})
			} else {
				sb = append(sb, AS[T]{nil, source})
			}
		}
	} else {
		for atom := range atomList {
			if atom.Repo != "" && atom != nil {
				sb = append(sb, AS[T]{atom, ""})
			} else if a := atom.WithRepo(repoName); a != nil {
				sb = append(sb, AS[T]{a, ""})
			} else {
				sb = append(sb, AS[T]{nil, ""})
			}
		}
	}
	return sb
}

func StackLists[T interfaces.ISettings](lists [][][2]string, incremental int, rememberSourceFile, warnForUnmatchedRemoval, strictWarnForUnmatchedRemoval, ignoreRepo bool) map[*dep.Atom[T]]string { //1,false,false,false,false
	matchedRemovals := map[[2]string]bool{}
	unmatchedRemovals := map[string][]string{}
	newList := map[*dep.Atom[T]]string{}
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
					newList = map[*dep.Atom[T]]string{}
				} else if token[:1] == "-" {
					matched := false
					if ignoreRepo && !strings.Contains(token, "::") {
						toBeRemoved := []*dep.Atom[T]{}
						tokenSlice := token[1:]
						for atom := range newList {
							atomWithoutRepo := atom.Value
							if atom.Repo != "" {
								atomWithoutRepo = strings.Replace(atom.Value, "::"+atom.Repo, "", 1)
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
							if v.Value == token[1:] {
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
					newList[&dep.Atom[T]{Value: token}] = sourceFile
				}
			} else {
				newList[&dep.Atom[T]{Value: token}] = sourceFile
			}
		}
	}
	if warnForUnmatchedRemoval {
		for sourceFile, tokens := range unmatchedRemovals {
			if len(tokens) > 3 {
				selected := []string{tokens[len(tokens)-1], tokens[len(tokens)-2], tokens[len(tokens)-3]}
				tokens = tokens[:len(tokens)-3]
				msg.WriteMsg(fmt.Sprintf("--- Unmatched removal atoms in %s: %s and %v more\n", sourceFile, strings.Join(selected, ", "), len(tokens)), -1, nil)
			} else {
				msg.WriteMsg(fmt.Sprintf("--- Unmatched removal Atom(s) in %s: %s\n", sourceFile, strings.Join(tokens, ", ")), -1, nil)
			}
		}
	}
	return newList
}

var eapiFileCache = map[string]string{}

func ReadCorrespondingEapiFile(filename, defaults string) string { // "0"
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
				msg.WriteMsg(fmt.Sprintf("--- Invalid 'eapi' file (doesn't contain exactly one line): %s\n", eapiFile), -1, nil)
			}
		}
	}

	eapiFileCache[eapiFile] = eapi
	if eapi == "" {
		return defaults
	}
	return eapi
}

//false, false, false, false, false, false, true, false, nil, 0
func GrabDictPackage[T interfaces.ISettings](myfilename string, juststrings, recursive, newlines bool, allowWildcard, allowRepo, allowBuildId, allowUse, verifyEapi bool, eapi, eapiDefault string) map[*dep.Atom[T]][]string {
	fileList := []string{}
	if recursive {
		fileList = grab.RecursiveFileList(myfilename)
	} else {
		fileList = []string{myfilename}
	}
	atoms := map[*dep.Atom[T]][]string{}
	var d map[string][]string
	for _, filename := range fileList {
		d = grab.GrabDict(filename, false, true, false, true, newlines)
		if len(d) == 0 {
			continue
		}
		if verifyEapi && eapi == "" {
			eapi = ReadCorrespondingEapiFile(myfilename, eapiDefault)
		}
		for k, v := range d {
			a, err := dep.NewAtom[T](k, nil, allowWildcard, &allowRepo, nil, eapi, nil, &allowBuildId)
			if err != nil {
				msg.WriteMsg(fmt.Sprintf("--- Invalid Atom in %s: %s\n", filename, err), -1, nil)
			} else {
				if !allowUse && a.Use != nil {
					msg.WriteMsg(fmt.Sprintf("--- Atom is not allowed to have USE flag(s) in %s: %s\n", filename, k), -1, nil)
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

func GrabFilePackage[T interfaces.ISettings](myFileName string, compatLevel int, recursive, allowWildcard, allowRepo, allowBuildId, rememberSourceFile, verifyEapi bool, eapi, eapiDefault string) [][2]string { // 0,false,false,false,false,false,false,nil,0
	pkgs := grab.GrabFile(myFileName, compatLevel, recursive, true)
	if len(pkgs) == 0 {
		return pkgs
	}
	if verifyEapi && eapi == "" {
		eapi = ReadCorrespondingEapiFile(myFileName, eapiDefault)
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

		if _, err := dep.NewAtom[T](pkg, nil, allowWildcard, &allowRepo, nil, eapi, nil, &allowBuildId); err != nil {
			msg.WriteMsg(fmt.Sprintf("--- Invalid Atom in %s: %s\n", sourceFile, err), -1, nil)
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
		ppath := msg.NormalizePath(
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
		ppath := msg.NormalizePath(
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
	newPfile := msg.NormalizePath(filepath.Join(realDirname,
		"._cfg"+fmt.Sprintf("%04d", protNum)+"_"+realFilename))
	oldPfile := msg.NormalizePath(filepath.Join(realDirname, lastPfile))
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
				lastPfileMd5 := checksum.PerformMd5Merge(oldPfile, false)
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

type Sss struct {
	S  string
	SS []string
}

func findUpdatedConfigFiles(targetRoot string, configProtect []string) []Sss {
	var ssss []Sss
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
					ssss = append(ssss, Sss{S: x, SS: files})
				} else {
					ssss = append(ssss, Sss{S: x, SS: nil})
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
	newfile = VarExpand(newfile, g.varExpandMap, nil)
	return g.Shlex.SourceHook(newfile)
}

func NewGetConfigShlex(instream io.Reader, infile string, posix bool, punctuation_chars string, portageTolerant bool) *getConfigShlex {
	g := &getConfigShlex{portageTolerant: portageTolerant}
	g.Shlex = shlex.NewShlex(instream, infile, posix, punctuation_chars)

	return g
}

var invalidVarNameRe = regexp.MustCompile("^\\d|\\W")

// false, false, true, false, nil
func GetConfig(myCfg string, tolerant, allowSourcing, expand, recursive bool, expandMap map[string]string) map[string]string {
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
		for _, fname = range grab.RecursiveFileList(myCfg) {
			newKeys := GetConfig(fname, tolerant, allowSourcing, true, false, expandMap)
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
		msg.WriteMsg(fmt.Sprintf("!!! Please use dos2unix to convert line endings in config file: '%s'\n", myCfg), -1, nil)
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
			msg1 := "Unexpected EOF" //TODO error_leader
			if !tolerant {
				//raise ParseError(msg)
			} else {
				msg.WriteMsg(fmt.Sprintf("%s\n", msg1), -1, nil)
				return myKeys
			}
		} else if equ != "=" {
			msg1 := fmt.Sprintf("Invalid token '%s' (not '=')", equ) //TODO error_leader
			if !tolerant {
				//raise ParseError(msg)
			} else {
				msg.WriteMsg(fmt.Sprintf("%s\n", msg1), -1, nil)
				return myKeys
			}
		}
		val, _ := lex.GetToken() /* TODO: fix it
		if val == "" {
			msg := fmt.Sprintf("Unexpected end of config file: variable '%s'", key) //TODO error_leader
			if !tolerant {
				//raise ParseError(msg)
			} else {
				msg.WriteMsg(fmt.Sprintf("%s\n", msg), -1, nil)
				return myKeys
			}
		}*/
		if invalidVarNameRe.MatchString(key) {
			msg1 := fmt.Sprintf("Invalid variable name '%s'", key) //TODO error_leader
			if !tolerant {
				//raise ParseError(msg)
			} else {
				msg.WriteMsg(fmt.Sprintf("%s\n", msg1), -1, nil)
				continue
			}
		}
		if expand {
			myKeys[key] = VarExpand(val, expandMap, nil) //TODO lex.error_leader
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
func VarExpand(myString string, myDict map[string]string, errorLeader func() string) string {
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
						msg1 := varexpandUnexpectedEofMsg
						if errorLeader != nil {
							msg1 = errorLeader() + msg1
						}
						msg.WriteMsg(msg1+"\n", -1, nil)
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
							msg1 := varexpandUnexpectedEofMsg
							if errorLeader != nil {
								msg1 = errorLeader() + msg1
							}
							msg.WriteMsg(msg1+"\n", -1, nil)
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
						msg1 := varexpandUnexpectedEofMsg
						if errorLeader != nil {
							msg1 = errorLeader() + msg1
						}
						msg.WriteMsg(msg1+"\n", -1, nil)
						return ""
					} else {
						pos += 1
					}
				}
				if len(myVarName) == 0 {
					msg1 := "$"
					if braced {
						msg1 += "{}"
					}
					msg1 += ": bad substitution"
					if errorLeader != nil {
						msg1 = errorLeader() + msg1
					}
					msg.WriteMsg(msg1+"\n", -1, nil)
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
	for _, l := range grab.GrabFile(p, 0, false, false) {
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
		p = append(p, msg.NormalizePath(x))
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

type slotObject struct {
	weakRef string
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
		var m1 os.FileMode
		m1--
		permissions.Apply_stat_permissions(f.Name(), st, m1, nil, true)
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
func Write_atomic(filePath string, content string, mode int, followLinks bool) {
	f := NewAtomic_ofstream(filePath, mode, followLinks)
	f.Write([]byte(content))
	f.Close()
	//except (IOError, OSError) as e:
	//if f:
	//f.abort()
	//func_call = "Write_atomic('%s')" % file_path
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
func EnsureDirs(dirPath string, uid, gid uint32, mode, mask os.FileMode, statCached os.FileInfo, followLinks bool) bool {
	createdDir := false
	if err := os.MkdirAll(dirPath, 0755); err == nil {
		createdDir = true
	} // TODO check errno
	permsModified := false
	if int(uid) != -1 || int(gid) != -1 || int(mode) != -1 || int(mask) != -1 || statCached != nil || followLinks {
		permsModified = permissions.ApplyPermissions(dirPath, uid, gid, mode, mask, statCached, followLinks)
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
	newPFile := msg.NormalizePath(path.Join(realDirname, ".cfg"+fmt.Sprintf("%04s", string(protNum))+"_"+realFilename))
	oldPFile := msg.NormalizePath(path.Join(realDirname, lastFile))
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

var Compressors = map[string]map[string]string{
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

/*
// 0, nil, nil, nil
func _movefile(src, dest string, newmtime int64, sstat os.FileInfo, mysettings *ebuild.Config, hardlink_candidates []string) int64 {
	if mysettings == nil {
		mysettings = portage.Settings()
	}

	xattr_enabled := mysettings.Features.Features["xattr"]

	selinux_enabled := mysettings.Selinux_enabled()
	//// TODO: selinux
	//if selinux_enabled{
	//	selinux = _unicode_module_wrapper(_selinux, encoding = encoding)
	//	_copyfile = selinux.copyfile
	//	_rename = selinux.rename
	//} else{
	_copyfile := src1.Copyfile
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
			msg.WriteMsg(fmt.Sprintf("!!! failed to properly create symlink:"), -1, nil)
			msg.WriteMsg(fmt.Sprintf("!!! %s -> %s\n", dest, target), -1, nil)
			msg.WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
			return 0
		}
	}

	hardlinked := false
	if len(hardlink_candidates) > 0 {
		head, tail := filepath.Split(dest)
		hardlink_tmp := filepath.Join(head, fmt.Sprintf(".%s._portage_merge_.%s", tail, os.Getpid()))

		if err := syscall.Unlink(hardlink_tmp); err != nil {
			if err != syscall.ENOENT {
				msg.WriteMsg(fmt.Sprintf("!!! Failed to remove hardlink temp file: %s\n", hardlink_tmp), -1, nil)
				msg.WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
				return 0
			}
			//del e
		}
		for _, hardlink_src := range hardlink_candidates {
			if err := os.Link(hardlink_src, hardlink_tmp); err != nil {
				continue
			} else {
				if err := os.Rename(hardlink_tmp, dest); err != nil {
					msg.WriteMsg(fmt.Sprintf("!!! Failed to rename %s to %s\n", hardlink_tmp, dest), -1, nil)
					msg.WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
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
				msg.WriteMsg(fmt.Sprintf("!!! Failed to move %s to %s\n", src, dest), -1, nil)
				msg.WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
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
						msg1 := "Failed to copy extended attributes. " +
							"In order to avoid this error, set " +
							"FEATURES=\"-xattr\" in make.conf."
						for _, line := range TextWrap(msg1, 65) {
							msg.WriteMsg(fmt.Sprintf("!!! %s\n", line), -1, nil)
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
				//msg.WriteMsg("!!! %s\n" % _('copy %(src)s -> %(dest)s failed.') %
				//{"src": src, "dest": dest}, noiselevel = -1)
				//msg.WriteMsg("!!! %s\n" % (e, ), noiselevel = -1)
				return 0
			}
		} else {
			a, _ := process.Spawn([]string{_const.MoveBinary, "-f", src, dest}, msg.ExpandEnv(), "", nil, false, 0, 0, nil, 0, "", "", true, nil, false, false, false, false, false, "")
			if len(a) != 0 && a[0] != syscall.F_OK {
				msg.WriteMsg(fmt.Sprintf("!!! Failed to move special file:\n"), -1, nil)
				msg.WriteMsg(fmt.Sprintf("!!! '%s' to '%s'\n", src, dest), -1, nil)
				msg.WriteMsg(fmt.Sprintf("!!! %s\n", a), -1, nil)
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
			msg.WriteMsg(fmt.Sprintf("!!! Failed to stat in movefile()\n"), -1, nil)
			msg.WriteMsg(fmt.Sprintf("!!! %s\n", dest), -1, nil)
			msg.WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
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
*/

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
