package atom

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var VERSION = "HEAD"

var shellQuoteRe = regexp.MustCompile("[\\s><=*\\\\\\\"'$`]")
var initializingGlobals *bool

func ShellQuote(s string) string {

	if shellQuoteRe.MatchString(s) {
		return s
	}
	for _, letter := range "\\\"$`" {
		if strings.Contains(s, string(letter)) {
			s = strings.Replace(s, string(letter), "\\"+string(letter), -1)
		}
	}
	return "\"" + s + "\""
}

var notInstalled bool

func init() {
	ni, err := os.Stat(path.Join(PORTAGE_BASE_PATH, ".portage_not_installed"))
	if err != nil || !ni.IsDir() {
		notInstalled = true
	}
}

var InternalCaller = false
var syncMode = false

func getStdin() *os.File {
	return os.Stdin
}

func getcwd() string {
	s, err := os.Getwd()
	if err != nil {
		os.Chdir("/")
		return "/"
	} else {
		return s
	}
}
func init() {
	getcwd()
}

var auxdbkeys = map[string]bool{
	"DEPEND": true, "RDEPEND": true, "SLOT": true, "SRC_URI": true,
	"RESTRICT": true, "HOMEPAGE": true, "LICENSE": true, "DESCRIPTION": true,
	"KEYWORDS": true, "INHERITED": true, "IUSE": true, "REQUIRED_USE": true,
	"PDEPEND": true, "BDEPEND": true, "EAPI": true,
	"PROPERTIES": true, "DEFINED_PHASES": true, "HDEPEND": true, "UNUSED_04": true,
	"UNUSED_03": true, "UNUSED_02": true, "UNUSED_01": true,
}
var auxdbkeylen = len(auxdbkeys)

func absSymlink(symlink, target string) string {
	mylink := ""
	if target != "" {
		mylink = target
	} else {
		mylink, _ = os.Readlink(symlink)
	}
	if mylink[0] != '/' {
		mydir := path.Dir(symlink)
		mylink = mydir + "/" + mylink
	}
	return path.Clean(mylink)
}

var doebuildManifestExemptDepend = 0

func parseEapiEbuildHead(f []string) (string, int) {
	eapi := ""
	eapiLineno := 0
	lineno := 0
	for _, line := range f {
		lineno += 1
		if !commentOrBlankLine.MatchString(line) {
			eapiLineno = lineno
			if pmsEapiRe.MatchString(line) {
				eapi = pmsEapiRe.FindAllString(line, -1)[2]
			}
			break
		}
	}
	return eapi, eapiLineno
}

type newsManager struct {
	news_path, unread_path, language_id, config, vdb, portdb, _uid, _gid, _file_mode, _dir_mode, _mode_mask string
}

//func NewNewsManager(portdb, vardb, news_path, unread_path, language_id string)*newsManager { // 'en'
//	n := &newsManager{portdb:portdb, unread_path:unread_path, language_id:language_id, config: vardb.setting, vdb: vardb, portdb:portdb}
//}

type hashPath struct {
	location, eclassDir string
}

func (h *hashPath) mtime() time.Time {
	s, _ := os.Stat(h.location)
	return s.ModTime()
}

func NewHashPath(location string) *hashPath {
	return &hashPath{location: location}
}

type cache struct {
	eclasses                                           map[string]*hashPath
	eclassLocations                                    map[string]string
	eclassLocationsStr, portTreeRoot, masterEclassRoot string
	portTrees                                          []string
}

func (c *cache) updateEclasses() {
	c.eclasses = map[string]*hashPath{}
	c.eclassLocations = map[string]string{}
	masterEclasses := map[string]time.Time{}
	eclassLen := len(".eclass")
	for _, y := range c.portTrees {
		x := NormalizePath(path.Join(y, "eclass"))
		eclassFileNames, _ := filepath.Glob(x + "/*")
		for _, y := range eclassFileNames {
			if !strings.HasSuffix(y, ".eclass") {
				continue
			}
			obj := NewHashPath(path.Join(x, y))
			obj.eclassDir = x
			mtime := obj.mtime()
			ys := y[:len(y)-eclassLen]
			if x == c.masterEclassRoot {
				masterEclasses[ys] = mtime
				c.eclasses[ys] = obj
				c.eclassLocations[ys] = x
				continue
			}
			masterMTime, ok := masterEclasses[ys]
			if ok {
				if masterMTime == mtime {
					continue
				}
			}
			c.eclasses[ys] = obj
			c.eclassLocations[ys] = x
		}
	}
}

func (c *cache) copy() *cache {
	d := &cache{eclasses: map[string]*hashPath{}, eclassLocations: map[string]string{}, portTreeRoot: c.portTreeRoot, portTrees: c.portTrees, masterEclassRoot: c.masterEclassRoot}
	for k, v := range c.eclasses {
		d.eclasses[k] = v
	}
	for k, v := range c.eclassLocations {
		d.eclassLocations[k] = v
	}
	return d
}

func (c *cache) append(other *cache) {
	c.portTrees = append(c.portTrees, other.portTrees...)
	for k, v := range other.eclasses {
		c.eclasses[k] = v
	}
	for k, v := range other.eclassLocations {
		c.eclassLocations[k] = v
	}
	c.eclassLocationsStr = ""
}

func NewCache(portTreeRoot, overlays string) *cache {
	c := &cache{}
	if overlays != "" {
		//warnings.warn("overlays parameter of portage.eclass_cache.cache constructor is deprecated and no longer used",
		//	DeprecationWarning, stacklevel=2)
	}
	c.eclasses = map[string]*hashPath{}
	c.eclassLocations = map[string]string{}
	c.eclassLocationsStr = ""
	if portTreeRoot != "" {
		c.portTreeRoot = portTreeRoot
		c.portTrees = []string{NormalizePath(c.portTreeRoot)}
		c.masterEclassRoot = path.Join(c.portTrees[0], "eclass")
	}
	return c
}

func unprivilegedMode(eroot string, erootSt os.FileInfo) bool {
	st, err := os.Stat(eroot)
	if err != nil {
		return false
	}
	return os.Getuid() != 0 && st.Mode()&2 != 0 && erootSt.Mode()&00002 == 0
}

type _trees_dict struct {
	valueDict map[string]func()
	_running_eroot,_target_eroot string
}

func NewTreesDict(dict map[string]string) *_trees_dict {
	return &_trees_dict{valueDict: dict}
}

func createTrees(config_root, target_root string, ts map[string]string, env map[string]string, sysroot, eprefix string) *_trees_dict {
	var trees *_trees_dict = nil
	if ts == nil {
		trees = NewTreesDict(nil)
	} else {
		trees = NewTreesDict(ts)
	}

	if env == nil {
		env = expandEnv()
	}

	settings := NewConfig(nil, "", "", nil, config_root, target_root, sysroot, eprefix, false, env, false, nil)
	settings.lock()

	depcachedir := settings.valueDict["PORTAGE_DEPCACHEDIR"]
	trees._target_eroot = settings.valueDict["EROOT"]
	type st struct {
		s string
		t *Config
	}
	myroots := []st{{settings.valueDict["EROOT"], settings}}
	if settings.valueDict["ROOT"] == "/" && settings.valueDict["EPREFIX"] == EPREFIX {
		trees._running_eroot = trees._target_eroot
	} else {
		clean_env := map[string]string{}

		for _, k := range []string{"PATH", "PORTAGE_GRPNAME",
			"PORTAGE_REPOSITORIES", "PORTAGE_USERNAME", "PYTHONPATH",
			"SSH_AGENT_PID", "SSH_AUTH_SOCK", "TERM", "ftp_proxy",
			"http_proxy", "no_proxy", "__PORTAGE_TEST_HARDLINK_LOCKS"} {
			v, ok := settings.valueDict[k]
			if ok {
				clean_env[k] = v
			}
		}

		if depcachedir != "" {
			clean_env["PORTAGE_DEPCACHEDIR"] = depcachedir
		}
		settings = NewConfig(nil, "", "", nil, "", "/", "/", "", false, clean_env, false, nil)
		settings.lock()
		trees._running_eroot = settings.valueDict["EROOT"]
		myroots = append(myroots, st{settings.valueDict["EROOT"], settings})
	}

	//for _,v:= range myroots{
	//	myroot, mysettings := v.s, v.t
	//	trees.valueDict[myroot] = trees.valueDict[myroot]
	//	trees[myroot]["virtuals"] =  mysettings.getvirtuals
	//	trees[myroot]["vartree"]= vartree, categories=mysettings.categories,
	//		settings=mysettings)
	//	trees[myroot].addLazySingleton("porttree",
	//		portagetree, settings=mysettings)
	//	trees[myroot].addLazySingleton("bintree",
	//		binarytree, pkgdir=mysettings["PKGDIR"], settings=mysettings)
	//}
	return trees
}

var _legacy_global_var_names = []string{"archlist", "db", "features",
	"groups", "mtimedb", "mtimedbfile", "pkglines",
	"portdb", "profiledir", "root", "selinux_enabled",
	"settings", "thirdpartymirrors"}
var archlist, db, features, groups, mtimedb, mtimedbfile, pkglines, portdb, profiledir, root, selinux_enabled, settings, thirdpartymirrors int

var _legacy_globals_constructed map[string]bool

func _reset_legacy_globals() {
	_legacy_globals_constructed = map[string]bool{}
	archlist, db, features, groups, mtimedb, mtimedbfile, pkglines, portdb, profiledir, root, selinux_enabled, settings, thirdpartymirrors = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
}

func _disable_legacy_globals() {
	archlist, db, features, groups, mtimedb, mtimedbfile, pkglines, portdb, profiledir, root, selinux_enabled, settings, thirdpartymirrors = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
}
