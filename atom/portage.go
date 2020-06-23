package atom

import (
	"fmt"
	"github.com/ppphp/shlex"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
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
var SyncMode = false

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

func ParseEapiEbuildHead(f []string) (string, int) {
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

// my data structure, a lazy Tree
type Tree struct {
	_virtuals map[string][]string
	_vartree  *varTree
	_porttree *PortageTree
	_bintree  *BinaryTree
	virtuals  func() map[string][]string
	vartree   func() *varTree
	porttree  func() *PortageTree
	bintree   func() *BinaryTree

	RootConfig *RootConfig

}

func (t *Tree) Virtuals() map[string][]string {
	if t._virtuals != nil {
		t._virtuals = t.virtuals()
	}
	return t._virtuals
}

func (t *Tree) VarTree() *varTree {
	if t._vartree != nil {
		t._vartree = t.vartree()
	}
	return t._vartree
}

func (t *Tree) PortTree() *PortageTree {
	if t._porttree != nil {
		t._porttree = t.porttree()
	}
	return t._porttree
}

func (t *Tree) BinTree() *BinaryTree {
	if t._bintree != nil {
		t._bintree = t.bintree()
	}
	return t._bintree
}

type TreesDict struct {
	valueDict                     map[string]*Tree
	_running_eroot, _target_eroot string
}

func (t *TreesDict) Values() map[string]*Tree {
	return t.valueDict
}

func NewTreesDict(dict *TreesDict) *TreesDict {
	t := &TreesDict{}
	if dict != nil {
		*t = *dict
	}
	return t
}

func CreateTrees(config_root, target_root string, ts *TreesDict, env map[string]string, sysroot, eprefix string) *TreesDict {
	var trees *TreesDict = nil
	if ts == nil {
		trees = NewTreesDict(nil)
	} else {
		trees = NewTreesDict(ts)
	}

	if env == nil {
		env = ExpandEnv()
	}

	settings := NewConfig(nil, nil, "", nil, config_root, target_root, sysroot, eprefix, true, env, false, nil)
	settings.Lock()

	depcachedir := settings.ValueDict["PORTAGE_DEPCACHEDIR"]
	trees._target_eroot = settings.ValueDict["EROOT"]
	type st struct {
		s string
		t *Config
	}
	myroots := []st{{settings.ValueDict["EROOT"], settings}}
	if settings.ValueDict["ROOT"] == "/" && settings.ValueDict["EPREFIX"] == EPREFIX {
		trees._running_eroot = trees._target_eroot
	} else {
		clean_env := map[string]string{}

		for _, k := range []string{"PATH", "PORTAGE_GRPNAME",
			"PORTAGE_REPOSITORIES", "PORTAGE_USERNAME", "PYTHONPATH",
			"SSH_AGENT_PID", "SSH_AUTH_SOCK", "TERM", "ftp_proxy",
			"http_proxy", "no_proxy", "__PORTAGE_TEST_HARDLINK_LOCKS"} {
			v, ok := settings.ValueDict[k]
			if ok {
				clean_env[k] = v
			}
		}

		if depcachedir != "" {
			clean_env["PORTAGE_DEPCACHEDIR"] = depcachedir
		}
		settings = NewConfig(nil, nil, "", nil, "", "/", "/", "", false, clean_env, false, nil)
		settings.Lock()
		trees._running_eroot = settings.ValueDict["EROOT"]
		myroots = append(myroots, st{settings.ValueDict["EROOT"], settings})
	}

	for _, v := range myroots {
		myroot, mysettings := v.s, v.t
		if trees.valueDict == nil {
			trees.valueDict = map[string]*Tree{}
		}
		if trees.valueDict[myroot] == nil {
			trees.valueDict[myroot] = &Tree{}
		}
		trees.valueDict[myroot].virtuals = mysettings.getVirtuals
		trees.valueDict[myroot].vartree = func() *varTree {
			return NewVarTree(mysettings.categories, mysettings)
		}
		//	trees[myroot].addLazySingleton("porttree",
		//		PortageTree, Settings=mysettings)
		//	trees[myroot].addLazySingleton("bintree",
		//		BinaryTree, pkgdir=mysettings["PKGDIR"], Settings=mysettings)
	}
	return trees
}

// should be lazy version in portage but not meaningful
// VERSION = _LazyVersion()

var _legacy_global_var_names = []string{"archlist", "db", "features",
	"groups", "mtimedb", "mtimedbfile", "pkglines",
	"portdb", "profiledir", "root", "selinux_enabled",
	"Settings", "thirdpartymirrors"} // no use
var mtimedb, portdb int

var _portdb *portdbapi = nil
var _db *TreesDict = nil
var _settings *Config = nil
var _root, _mtimedbfile *string = nil, nil

var _legacy_globals_constructed map[string]bool

func Portdb() *portdbapi {
	if _portdb != nil {
		return _portdb
	}
	_get_legacy_global()
	return _portdb
}

func Db() *TreesDict {
	if _db != nil {
		return _db
	}
	_get_legacy_global()
	return _db
}

func Settings() *Config {
	if _settings != nil {
		return _settings
	}
	_get_legacy_global()
	return _settings
}

func Root() string {
	if _root != nil {
		return *_root
	}
	_get_legacy_global()
	return *_root
}

func Mtimedbfile() string {
	if _mtimedbfile != nil {
		return *_mtimedbfile
	}
	_mtimedbfile = new(string)
	*_mtimedbfile = path.Join(Settings().ValueDict["EROOT"], CachePath, "mtimedb")
	return *_mtimedbfile
}

func _get_legacy_global() { // a fake copy, just init no return
	_portdb = Db().valueDict[Root()].PortTree().dbapi
	initializingGlobals = new(bool)
	*initializingGlobals = true
	_db = CreateTrees(os.Getenv("PORTAGE_CONFIGROOT"), os.Getenv("ROOT"), nil, nil, os.Getenv("SYSROOT"), os.Getenv("EPREFIX"))
	initializingGlobals = nil
	_settings = _db.valueDict[_db._target_eroot].VarTree().settings
	_root = new(string)
	*_root = _db._target_eroot
}

func ResetLegacyGlobals() {
	_legacy_globals_constructed = map[string]bool{}
	//mtimedb, mtimedbfile, portdb, _root, _settings =
}

func DisableLegacyGlobals() {
	//mtimedb, mtimedbfile, portdb, _root, _settings =
}

var ignored_dbentries = map[string]bool{"CONTENTS": true, "environment.bz2": true}

func update_dbentry(updateCmd []string, mycontent string, eapi string, parent *PkgStr) string { // "", nil
	if parent != nil {
		eapi = parent.eapi
	}
	if updateCmd[0] == "move" {
		oldValue := updateCmd[1]
		newValue := updateCmd[2]
		if strings.Contains(mycontent, oldValue) && isValidAtom(newValue, false, false, false, "", false) {
			splitContent := regexp.MustCompile("(\\s+)").Split(mycontent, -1)
			modified := false
			for i, token := range splitContent {
				if !strings.Contains(token, oldValue) {
					continue
				}
				atom, err := NewAtom(token, nil, false, nil, nil, eapi, nil, nil)
				if err != nil {
					continue
				}
				if atom.cp != oldValue {
					continue
				}
				newAtom, _ := NewAtom(strings.Replace(token, oldValue, newValue.value, 1), nil, false, nil, nil, eapi, nil, nil)
				if newAtom.Blocker != nil && parent != nil && parent.cp == newAtom.cp && len(matchFromList(newAtom, []*PkgStr{parent})) > 0 {
					continue
				}
				splitContent[i] = newAtom.value
				modified = true
			}

			if modified {
				mycontent = strings.Join(splitContent, "")
			}
		}
	} else if updateCmd[0] == "slotmove" && updateCmd[1].Operator == "" {
		origAtom, origslot, newslot := updateCmd[1], updateCmd[2], updateCmd[3]
		origCp := origAtom.cp
		if origAtom.version == "" && strings.Contains(mycontent, origCp) {
			splitContent := regexp.MustCompile("(\\s+)").Split(mycontent, -1)
			modified := false
			for i, token := range splitContent {

				if !strings.Contains(token, origCp) {
					continue
				}
				atom, err := NewAtom(token, nil, false, nil, nil, eapi, nil, nil)
				if err != nil {
					continue
				}
				if atom.cp != origCp {
					continue
				}
				if atom.slot == "" || atom.slot != origslot.value {
					continue
				}
				slotPart := newslot.value
				if atom.subSlot != "" {
					subSlot := ""
					if atom.subSlot == origslot.value {
						subSlot = newslot.value
					} else {
						subSlot = atom.subSlot
					}
					slotPart += "/" + subSlot
				}
				if atom.slotOperator != "" {
					slotPart += atom.slotOperator
				}
				splitContent[i] = atom.withSlot(slotPart).value
				modified = true
			}
			if modified {
				mycontent = strings.Join(splitContent, "")
			}
		}
	}
	return mycontent
}

// "", nil
func update_dbentries(updateIter [][]string, mydata map[string]string, eapi string, parent *PkgStr) map[string]string {
	updatedItems := map[string]string{}
	for k, mycontent := range mydata {
		if !ignored_dbentries[k] {
			origContent := mycontent
			for _, updateCmd := range updateIter {
				mycontent = update_dbentry(updateCmd, mycontent, eapi, parent)
			}
			if mycontent != origContent {
				updatedItems[k] = mycontent
			}
		}
	}
	return updatedItems
}

// nil
func grab_updates(updpath string, prev_mtimes map[string]string) []struct{p string; s os.FileInfo; c string} {
	mylist, err := listDir(updpath)
	if err != nil {
		//except OSError as oe:
		if err == syscall.ENOENT {
			//raise DirectoryNotFound(updpath)
		}
		//raise
	}
	if prev_mtimes == nil {
		prev_mtimes = map[string]string{}
	}

	ml := []string{}
	for _, myfile := range mylist {
		if len(myfile) == 7 && myfile[1:3] == "Q-" {
			ml = append(ml, myfile)
		}
	}
	mylist = ml
	if len(mylist) == 0 {
		return []struct {
			p string
			s os.FileInfo
			c string
		}{}
	}

	sort.Slice(mylist, func(i, j int) bool {
		if mylist[i][3:] < mylist[j][3:] {
			return true
		} else if mylist[i][3:] > mylist[j][3:] {
			return false
		} else {
			if mylist[i][:2] < mylist[j][:2] {
				return true
			} else {
				return false
			}
		}
	})

	update_data := []struct {
		p string
		s os.FileInfo
		c string
	}{}
	for _, myfile := range mylist {
		file_path := filepath.Join(updpath, myfile)
		mystat, _ := os.Stat(file_path)
		if len(update_data) > 0 || !Inmss(prev_mtimes, file_path) ||
			prev_mtimes[file_path] != fmt.Sprint(mystat.ModTime().UnixNano()) {
			f, _ := os.Open(file_path)
			content, _ := ioutil.ReadAll(f)
			f.Close()
			update_data = append(update_data, struct {
				p string;
				s os.FileInfo;
				c string
			}{file_path, mystat, string(content)})
		}
	}
	return update_data
}

func parse_updates(mycontent string) ([][]string, []string) {
	eapi_attrs := getEapiAttrs("")
	slot_re := getSlotRe(eapi_attrs)
	myupd := [][]string{}
	errors := []string{}
	mylines := strings.Split(mycontent, "\n")
	for _, myline := range mylines {
		mysplit := strings.Fields(myline)
		if len(mysplit) == 0 {
			continue
		}
		if mysplit[0] != "move" && mysplit[0] != "slotmove" {
			errors = append(errors, fmt.Sprintf("ERROR: Update type not recognized '%s'", myline))
			continue
		}
		if mysplit[0] == "move" {
			if len(mysplit) != 3 {
				errors = append(errors, fmt.Sprintf("ERROR: Update command invalid '%s'", myline))
				continue
			}
			valid := true
			for _, i := range []int{1, 2} {
				atom1, err := NewAtom(mysplit[i], nil, false, nil, nil, "", nil, nil)
				if err != nil {
					//except InvalidAtom:
				} else {
					if atom1.Blocker != nil || atom1.value != atom1.cp {
						atom1 = nil
					}
				}
				if atom1 != nil {
					mysplit[i] = atom1
				} else {
					errors = append(errors, fmt.Sprintf("ERROR: Malformed update entry '%s'", myline))
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
		}

		if mysplit[0] == "slotmove" {
			if len(mysplit) != 4 {
				errors = append(errors, fmt.Sprintf("ERROR: Update command invalid '%s'", myline))
				continue
			}
			pkg, origslot, newslot := mysplit[1], mysplit[2], mysplit[3]
			atom1, err := NewAtom(pkg, nil, false, nil, nil, "", nil, nil)
			if err != nil {
				//except InvalidAtom:
			} else {
				if atom1.Blocker != nil {
					atom1 = nil
				}
			}
			if atom1 != nil {
				mysplit[1] = atom1
			} else {
				errors = append(errors, fmt.Sprintf("ERROR: Malformed update entry '%s'", myline))
				continue
			}

			invalid_slot := false
			for _, slot := range []string{origslot, newslot} {
				if !slot_re.MatchString(slot) {
					invalid_slot = true
					break
				}
				if strings.Contains(slot, "/") {
					invalid_slot = true
					break
				}
			}

			if invalid_slot {
				errors = append(errors, fmt.Sprintf("ERROR: Malformed update entry '%s'", myline))
				continue
			}
		}

		myupd = append(myupd, mysplit)
	}
	return myupd, errors
}

// nil, false
func update_config_files(config_root string, protect, protect_mask []string, update_iter map[string][][]*Atom ,
match_callback func(string,string,string)bool, case_insensitive bool) {
	repo_dict := update_iter
	if match_callback == nil {
		match_callback = func(repo_name, atoma, atomb string) bool {
			return true
		}
	}
	config_root = NormalizePath(config_root)
	update_files := map[string] int {}
	file_contents := map[string][]{}
	myxfiles := []string{
		"package.accept_keywords", "package.env",
		"package.keywords", "package.license",
		"package.mask", "package.properties",
		"package.unmask", "package.use", "sets",
	}
	for _, x := range []string{
		"packages", "package.accept_keywords",
		"package.keywords", "package.mask",
		"package.unmask", "package.use",
		"package.use.force", "package.use.mask",
		"package.use.stable.force", "package.use.stable.mask",
	} {
		myxfiles = append(myxfiles, filepath.Join("profile", x))
	}
	abs_user_config := filepath.Join(config_root, UserConfigPath)
	recursivefiles := []string{}
	for _, x := range myxfiles {
		config_file := filepath.Join(abs_user_config, x)
		if pathIsDir(config_file) {
			filepath.Walk(config_file, func(path string, info os.FileInfo, err error) error {
				if info.IsDir() {
					if strings.HasPrefix(info.Name(), ".") || VcsDirs[info.Name()] {
						return filepath.SkipDir
					}
				} else {
					if strings.HasPrefix(info.Name(), ".") {
						return nil
					}
					recursivefiles = append(recursivefiles,
						filepath.Join(path, info.Name())[len(abs_user_config)+1:])
				}
				return nil
			})
		} else {
			recursivefiles = append(recursivefiles, x)
		}
	}
	myxfiles = recursivefiles
	for _, x := range myxfiles {
		f, err := ioutil.ReadFile(filepath.Join(abs_user_config, x))
		if err != nil {
			//except IOError:
			continue
		}
		file_contents[x] = strings.Split(string(f), "\n")
	}

	ignore_line_re := regexp.MustCompile("^#|^\\s*$")
	update_items := [][]{}
	if repo_dict == nil {
		update_items = [][]{nil, update_iter}
	} else {
		for x:= range repo_dict {
			if x[0] != "DEFAULT" {
				update_items = append(update_items, x)
			}
		}
	}
	for repo_name, update_iter := range update_items {
		for _, update_cmd := range update_iter {
			for x, contents := range file_contents {
				skip_next := false
				for pos, line := range contents {
					if skip_next {
						skip_next = false
						continue
					}
					if ignore_line_re.MatchString(line) {
						continue
					}
					atom1 := strings.Fields(line)[0]
					if atom1[:1] == "-" {
						atom1 = atom1[1:]
					}
					if atom1[:1] == "*" {
						atom1 = atom1[1:]
					}
					if !isValidAtom(atom1, false, false, false, "", false) {
						continue
					}
					new_atom := update_dbentry(update_cmd, atom1)
					if atom1 != new_atom {
						if match_callback(repo_name, atom1, new_atom string()) {
							contents[pos] = "# %s\n" %
								" ".join("%s"%(x, )
							for x
								in
							update_cmd)
							contents.insert(pos+1,
								strings.ReplaceAll(line, atom,
								new_atom, 1))
							skip_next = true
							update_files[x] = 1
							os.Stdout.Write([]byte("p"))
						}
					}
				}
			}
		}
	}

	protect_obj := NewConfigProtect(config_root, protect, protect_mask, case_insensitive)
	for x := range update_files {
		updating_file := filepath.Join(abs_user_config, x)
		if protect_obj.IsProtected(updating_file) {
			updating_file = new_protect_filename(updating_file, "", false)
		}
		//try:
		write_atomic(updating_file, strings.Join(file_contents[x], ""), 0, true)
		//except PortageException as e:
		//writemsg("\n!!! %s\n"%str(e), noiselevel = -1)
		//writemsg(_("!!! An error occurred while updating a config file:") + false
		//" '%s'\n" % updating_file, noiselevel = -1)
		//continue
	}
}

func dep_transform(mydep, oldkey, newkey string)  string {
	if depGetKey(mydep) == oldkey {
		return strings.Replace(mydep,oldkey, newkey, 1)
	}
	return mydep
}

// false, true
func Global_updates(trees *TreesDict, prev_mtimes map[string]string, quiet, if_mtime_changed bool) bool {
	if _, ok := os.LookupEnv("SANDBOX_ACTIVE"); *secpass < 2 ||  ok ||len(trees.Values()) != 1{
		return false
	}
	return _do_global_updates(trees, prev_mtimes,
		quiet, if_mtime_changed)
}

// false, true
func _do_global_updates(trees *TreesDict, prev_mtimes map[string]string, quiet, if_mtime_changed bool) bool {
	root := trees._running_eroot
	mysettings := trees.Values()[root].VarTree().settings
	portdb := trees.Values()[root].PortTree().dbapi
	vardb := trees.Values()[root].VarTree().dbapi
	bindb := trees.Values()[root].BinTree().dbapi

	world_file := filepath.Join(mysettings.ValueDict["EROOT"], WorldFile)
	world_list := grabFile(world_file, 0, false, false)
	world_modified := false
	world_warnings := map[[2]*Atom]bool{}
	updpath_map := map[string][]{}
	repo_map := map[string][][]*Atom{}
	timestamps :=
	{
	}

	retupd := false
	update_notice_printed := false
	for _, repo_name:= range portdb.getRepositories("") {
		repo := portdb.getRepositoryPath(repo_name)
		updpath := filepath.Join(repo, "profiles", "updates")
		if !pathIsDir(updpath) {
			continue
		}

		if updpath in
		updpath_map{
			repo_map[repo_name] = updpath_map[updpath]
			continue
		}

		//try:
		var update_data []struct {
			p string
			s os.FileInfo
			c string
		}
		if if_mtime_changed {
			update_data = grab_updates(updpath, prev_mtimes)
		} else {
			update_data = grab_updates(updpath, nil)
		}
		//except
		//DirectoryNotFound:
		//	continue
		myupd := [][]*Atom{}
		updpath_map[updpath] = myupd
		repo_map[repo_name] = myupd
		if len(update_data) > 0 {
			for _, v := range update_data {
				mykey, mystat, mycontent := v.p, v.s, v.c
				if !update_notice_printed {
					update_notice_printed = true
					WriteMsgStdout("\n", 0)
					WriteMsgStdout(colorize("GOOD", "Performing Global Updates\n"), 0)
					WriteMsgStdout("(Could take a couple of minutes if you have a lot of binary packages.)\n", 0)
					if !quiet {
						WriteMsgStdout(fmt.Sprintf("  %s='update pass'  %s='binary update'  "+
							"%s='/var/db update'  %s='/var/db move'\n"+
							"  %s='/var/db SLOT move'  %s='binary move'  "+
							"%s='binary SLOT move'\n  %s='update /etc/portage/package.*'\n",
							Bold("."), Bold("*"), Bold("#"), Bold("@"), Bold("s"), Bold("%"), Bold("S"), Bold("p")), 0)
					}
				}
				valid_updates, errors := parse_updates(mycontent)
				myupd = append(myupd, valid_updates...)
				if !quiet {
					WriteMsgStdout(Bold(mykey), 0)
					WriteMsgStdout(strings.Repeat(".", len(valid_updates))+"\n", 0)
				}
				if len(errors) == 0 {
					timestamps[mykey] = mystat.ModTime()
				} else {
					for _, msg := range errors {
						WriteMsg(fmt.Sprintf("%s\n", msg), -1, nil)
					}
				}
			}
			if len(myupd) > 0 {
				retupd = true
			}
		}
	}

	if retupd {
		if st, _ := os.Stat(bindb.bintree.pkgdir); st != nil && st.Mode()&os.ModePerm != 0 {
			bindb.bintree.Populate(false, true, []string{})
		} else {
			bindb = nil
		}
	}

	master_repoO := portdb.repositories.mainRepo()
	master_repo := ""
	if master_repoO != nil {
		master_repo = master_repoO.Name
	}
	if _, ok := repo_map[master_repo]; ok {
		repo_map["DEFAULT"] = repo_map[master_repo]
	}

	for repo_name, myupd := range repo_map {
		if repo_name == "DEFAULT" {
			continue
		}
		if len(myupd) == 0 {
			continue
		}

		repo_match := func(repository string) bool {
			_, ok := repo_map[repository]
			return repository == repo_name || (repo_name == master_repo && !ok)
		}

		_world_repo_match := func(atoma, atomb *Atom) bool {
			matches := vardb.match(atoma, 1)
			if len(matches) == 0 {
				matches = vardb.match(atomb, 1)
			}
			if len(matches) > 0 && repo_match(vardb.aux_get(Best(matches), map[string]bool{"repository": true}, "")[0]) {
				if len(portdb.match(atoma, 1)) != 0 {
					world_warnings[[2]*Atom{atoma, atomb}] = true
				}
				return true
			} else {
				return false
			}
		}

		for _, update_cmd := range myupd {
			for pos, atom := range world_list {
				new_atom := update_dbentry(update_cmd, atom)
				if atom != new_atom {
					if _world_repo_match(atom, new_atom) {
						world_list[pos] = new_atom
						world_modified = true
					}
				}
			}
		}

		for update_cmd
			in
		myupd {
			if update_cmd[0] == "move" {
				moves := vardb.move_ent(update_cmd,  repo_match)
				if moves > 0 {
					WriteMsgStdout(strings.Repeat("@", moves))
				}
				if bindb != nil {
					moves = bindb.move_ent(update_cmd,  repo_match)
					if moves > 0 {
						WriteMsgStdout(strings.Repeat("%", moves))
					}
				}
			} else if update_cmd[0] == "slotmove" {
				moves := vardb.move_slot_ent(update_cmd, repo_match)
				if moves > 0 {
					WriteMsgStdout(strings.Repeat("s", moves), 0)
				}
				if bindb != nil {
					moves = bindb.move_slot_ent(update_cmd, repo_match)
					if moves > 0 {
						WriteMsgStdout(strings.Repeat("S", moves), 0)
					}
				}
			}
		}
	}
	if world_modified {

		world_list.sort()
		write_atomic(world_file,
			"".join("%s\n"%(x, )
		for x
			in
		world_list))
		if len(world_warnings) > 0 {
			//pass
		}
	}

	if retupd {
		_config_repo_match := func(repo_name, atoma, atomb string) bool {
			matches := vardb.match(atoma)
			if len(matches) == 0 {
				matches = vardb.match(atomb)
				if len(matches) == 0 {
					return false
				}
			}
			repository := vardb.aux_get(Best(matches, ""), map[string]bool{"repository": true}, "")[0]
			return repository == repo_name ||
				(repo_name == master_repo &&
					repository
			not
			in
			repo_map)
		}
		s1, _ := shlex.Split(strings.NewReader(mysettings.ValueDict["CONFIG_PROTECT"]), false, true)
		s2, _ := shlex.Split(strings.NewReader(mysettings.ValueDict["CONFIG_PROTECT_MASK"]), false, true)

		update_config_files(root, s1, s2,
			repo_map, _config_repo_match,
			mysettings.Features.Features["case-insensitive-fs"])

		if timestamps {
			for mykey, mtime
				in
			timestamps.items() {
				prev_mtimes[mykey] = mtime
			}
		}

		do_upgrade_packagesmessage := false
		onUpdate := func(_maxval, curval int) {
			if curval > 0 {
				WriteMsgStdout("#", 0)
			}
		}
		if quiet {
			onUpdate = nil
		}
		vardb.update_ents(repo_map, nil, onUpdate)
		if bindb != nil {
			onUpdate := func(_maxval, curval int) {
				if curval > 0 {
					WriteMsgStdout("*", 0)
				}
			}
			if quiet {
				onUpdate = nil
			}
			bindb.update_ents(repo_map, nil, onUpdate)
		}

		WriteMsgStdout("\n\n", 0)

		if do_upgrade_packagesmessage && bindb != nil && len(bindb.cpv_all()) > 0 {
			WriteMsgStdout(" ** Skipping packages. Run 'fixpackages' or set it in FEATURES to fix the tbz2's in the packages directory.\n", 0)
			WriteMsgStdout(Bold(_("Note: This can take a very long time.")), 0)
			WriteMsgStdout("\n", 0)
		}

	}

	return retupd
}
