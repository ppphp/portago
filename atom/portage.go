package atom

import (
	"fmt"
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
		//		PortageTree, settings=mysettings)
		//	trees[myroot].addLazySingleton("bintree",
		//		BinaryTree, pkgdir=mysettings["PKGDIR"], settings=mysettings)
	}
	return trees
}

// should be lazy version in portage but not meaningful
// VERSION = _LazyVersion()

var _legacy_global_var_names = []string{"archlist", "db", "features",
	"groups", "mtimedb", "mtimedbfile", "pkglines",
	"portdb", "profiledir", "root", "selinux_enabled",
	"settings", "thirdpartymirrors"} // no use
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

func update_dbentry(updateCmd []*Atom, mycontent string, eapi string, parent *PkgStr) string { // "", nil
	if parent != nil {
		eapi = parent.eapi
	}
	if updateCmd[0].value == "move" {
		oldValue := updateCmd[1]
		newValue := updateCmd[2]
		if strings.Contains(mycontent, oldValue.value) && isValidAtom(newValue.value, false, false, false, "", false) {
			splitContent := regexp.MustCompile("(\\s+)").Split(mycontent, -1)
			modified := false
			for i, token := range splitContent {
				if !strings.Contains(token, oldValue.value) {
					continue
				}
				atom, err := NewAtom(token, nil, false, nil, nil, eapi, nil, nil)
				if err != nil {
					continue
				}
				if atom.cp != oldValue.value {
					continue
				}
				newAtom, _ := NewAtom(strings.Replace(token, oldValue.value, newValue.value, 1), nil, false, nil, nil, eapi, nil, nil)
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
	} else if updateCmd[0].value == "slotmove" && updateCmd[1].Operator == "" {
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
func update_dbentries(updateIter [][]*Atom, mydata map[string]string, eapi string, parent *PkgStr) map[string]string {
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

func fixdbentries(update_iter, dbdir, eapi=None, parent=None) {

	warnings.warn("portage.update.fixdbentries() is deprecated",
		DeprecationWarning, stacklevel = 2)

	mydata =
	{
	}
	for myfile
	in
	[f
	for f
	in
	os.listdir(dbdir)
	if f not
	in
	ignored_dbentries]:
file_path = os.path.join(dbdir, myfile)
with io.open(_unicode_encode(file_path,
encoding = _encodings['fs'], errors = 'strict'),
mode = 'r', encoding= _encodings['repo.content'],
errors = 'replace') as f:
mydata[myfile] = f.read()
updated_items = update_dbentries(update_iter, mydata,
eapi = eapi, parent = parent)
for myfile, mycontent in updated_items.items():
file_path = os.path.join(dbdir, myfile)
write_atomic(file_path, mycontent, encoding = _encodings['repo.content'])
return len(updated_items) > 0
}

func grab_updates(updpath, prev_mtimes=None) {
try:
	mylist = os.listdir(updpath)
	except
	OSError
	as
oe:
	if oe.errno == errno.ENOENT:
	raise
	DirectoryNotFound(updpath)
	raise
	if prev_mtimes is
None:
	prev_mtimes =
	{
	}
	mylist = [myfile
	for myfile
	in
	mylist
	if len(myfile) == 7 and
	myfile[1:3] == "Q-"]
if len(mylist) == 0:
return []

mylist.sort(key = lambda x: (x[3:], x[:2]))

update_data = []
for myfile in mylist:
file_path = os.path.join(updpath, myfile)
mystat = os.stat(file_path)
if update_data or \
file_path not in prev_mtimes or \
long(prev_mtimes[file_path]) != mystat[stat.ST_MTIME]:
f = io.open(_unicode_encode(file_path,
encoding = _encodings['fs'], errors = 'strict'),
mode = 'r', encoding = _encodings['repo.content'], errors = 'replace')
content = f.read()
f.close()
update_data.append((file_path, mystat, content))
return update_data
}

func parse_updates(mycontent) {
	eapi_attrs = _get_eapi_attrs(None)
	slot_re = _get_slot_re(eapi_attrs)
	myupd = []
	errors = []
	mylines = mycontent.splitlines()
	for myline
	in
mylines:
	mysplit = myline.split()
	if len(mysplit) == 0:
	continue
	if mysplit[0] not
	in("move", "slotmove"):
	errors.append(_("ERROR: Update type not recognized '%s'") % myline)
	continue
	if mysplit[0] == "move":
	if len(mysplit) != 3:
	errors.append(_("ERROR: Update command invalid '%s'") % myline)
	continue
	valid = True
	for i
	in(1, 2):
try:
	atom = Atom(mysplit[i])
	except
InvalidAtom:
	atom = None
	else:
	if atom.blocker or
	atom != atom.cp:
	atom = None
	if atom is
	not
None:
	mysplit[i] = atom
	else:
	errors.append(
		_("ERROR: Malformed update entry '%s'") % myline)
	valid = False
	break
	if not valid:
	continue

	if mysplit[0] == "slotmove":
	if len(mysplit) != 4:
	errors.append(_("ERROR: Update command invalid '%s'") % myline)
	continue
	pkg, origslot, newslot = mysplit[1], mysplit[2], mysplit[3]
try:
	atom = Atom(pkg)
	except
InvalidAtom:
	atom = None
	else:
	if atom.blocker:
	atom = None
	if atom is
	not
None:
	mysplit[1] = atom
	else:
	errors.append(_("ERROR: Malformed update entry '%s'") % myline)
	continue

	invalid_slot = False
	for slot
	in(origslot, newslot):
	m = slot_re.match(slot)
	if m is
None:
	invalid_slot = True
	break
	if "/" in
slot:
	invalid_slot = True
	break

	if invalid_slot:
	errors.append(_("ERROR: Malformed update entry '%s'") % myline)
	continue

	myupd.append(mysplit)
	return myupd, errors
}

func update_config_files(config_root, protect, protect_mask, update_iter,
match_callback=None, case_insensitive=False) {

	repo_dict = None
	if isinstance(update_iter, dict):
	repo_dict = update_iter
	if match_callback is
None:
	def
	match_callback(repo_name, atoma, atomb):
	return True
	config_root = normalize_path(config_root)
	update_files =
	{
	}
	file_contents =
	{
	}
	myxfiles = [
		"package.accept_keywords", "package.env",
		"package.keywords", "package.license",
		"package.mask", "package.properties",
		"package.unmask", "package.use", "sets"
]
myxfiles += [os.path.join("profile", x) for x in (
"packages", "package.accept_keywords",
"package.keywords", "package.mask",
"package.unmask", "package.use",
"package.use.force", "package.use.mask",
"package.use.stable.force", "package.use.stable.mask"
)]
abs_user_config = os.path.join(config_root, USER_CONFIG_PATH)
recursivefiles = []
for x in myxfiles:
config_file = os.path.join(abs_user_config, x)
if os.path.isdir(config_file):
for parent, dirs, files in os.walk(config_file):
try:
parent = _unicode_decode(parent,
encoding= _encodings['fs'], errors = 'strict')
except UnicodeDecodeError:
continue
for y_enc in list(dirs):
try:
y = _unicode_decode(y_enc,
encoding = _encodings['fs'], errors= 'strict')
except UnicodeDecodeError:
dirs.remove(y_enc)
continue
if y.startswith(".") or y in VCS_DIRS:
dirs.remove(y_enc)
for y in files:
try:
y = _unicode_decode(y,
encoding =_encodings['fs'], errors = 'strict')
except UnicodeDecodeError:
continue
if y.startswith("."):
continue
recursivefiles.append(
os.path.join(parent, y)[len(abs_user_config) + 1:])
else:
recursivefiles.append(x)
myxfiles = recursivefiles
for x in myxfiles:
f = None
try:
f = io.open(
_unicode_encode(os.path.join(abs_user_config, x),
encoding = _encodings['fs'], errors = 'strict'),
mode = 'r', encoding= _encodings['content'],
errors = 'replace')
file_contents[x] = f.readlines()
except IOError:
continue
finally:
if f is not None:
f.close()

ignore_line_re = re.compile(r'^#|^\s*$')
if repo_dict is None:
update_items = [(None, update_iter)] else:
update_items = [x for x in repo_dict.items() if x[0] != 'DEFAULT']
for repo_name, update_iter in update_items:
for update_cmd in update_iter:
for x, contents in file_contents.items():
skip_next = False
for pos, line in enumerate(contents):
if skip_next:
skip_next = False
continue
if ignore_line_re.match(line):
continue
atom = line.split()[0]
if atom[:1] == "-":
atom = atom[1:]
if atom[:1] == "*":
atom = atom[1:]
if not isvalidatom(atom):
continue
new_atom = update_dbentry(update_cmd, atom)
if atom != new_atom:
if match_callback(repo_name, atom, new_atom):
contents[pos] = "# %s\n" % \
" ".join("%s" % (x,) for x in update_cmd)
contents.insert(pos + 1,
line.replace("%s" % (atom, ),
"%s" % (new_atom, ), 1))
skip_next = True
update_files[x] = 1
sys.stdout.write("p")
sys.stdout.flush()

protect_obj = ConfigProtect(
config_root, protect, protect_mask,
case_insensitive = case_insensitive)
for x in update_files:
updating_file = os.path.join(abs_user_config, x)
if protect_obj.isprotected(updating_file):
updating_file = new_protect_filename(updating_file)
try:
write_atomic(updating_file, "".join(file_contents[x]))
except PortageException as e:
writemsg("\n!!! %s\n" % str(e), noiselevel = -1)
writemsg(_("!!! An error occurred while updating a config file:") + \
" '%s'\n" % updating_file, noiselevel = -1)
continue
}

func dep_transform(mydep, oldkey, newkey string)  string {
	if depGetKey(mydep) == oldkey {
		return strings.Replace(mydep,oldkey, newkey, 1)
	}
	return mydep
}

// false, true
func _global_updates(trees *TreesDict, prev_mtimes, quiet, if_mtime_changed bool) bool {

	if _, ok := os.LookupEnv("SANDBOX_ACTIVE"); *secpass < 2 ||  ok ||len(trees.Values()) != 1{
		return false
	}

	return _do_global_updates(trees, prev_mtimes,
		quiet, if_mtime_changed)
}

// false, true
func _do_global_updates(trees *TreesDict, prev_mtimes, quiet, if_mtime_changed bool) {
	root := trees._running_eroot
	mysettings := trees.Values()[root].VarTree().settings
	portdb := trees.Values()[root].PortTree().dbapi
	vardb := trees.Values()[root].VarTree().dbapi
	bindb := trees.Values()[root].BinTree().dbapi

	world_file := filepath.Join(mysettings.ValueDict["EROOT"], WorldFile)
	world_list := grabFile(world_file, 0, false, false)
	world_modified := false
	world_warnings := map[string]bool{}
	updpath_map :=map[string][]{}
	repo_map :=map[string]{}
	timestamps :={}

	retupd := false
	update_notice_printed := false
	for repo_name
		in
	portdb.getRepositories() {
		repo := portdb.getRepositoryPath(repo_name)
		updpath := filepath.Join(repo, "profiles", "updates")
		if ! pathIsDir(updpath) {
			continue
		}

		if updpath in
	updpath_map{
		repo_map[repo_name] = updpath_map[updpath]
		continue
	}

	//try:
		if if_mtime_changed {
			update_data := grab_updates(updpath, prev_mtimes = prev_mtimes)
		} else {
			update_data := grab_updates(updpath)
		}
		//except
	//DirectoryNotFound:
	//	continue
		myupd := []
		updpath_map[updpath] = myupd
		repo_map[repo_name] = myupd
		if len(update_data) > 0{
			for mykey, mystat, mycontent
				in
			update_data{
				if ! update_notice_printed{
					update_notice_printed = true
					WriteMsgStdout("\n",0)
					WriteMsgStdout(colorize("GOOD", "Performing Global Updates\n"),0)
					WriteMsgStdout("(Could take a couple of minutes if you have a lot of binary packages.)\n", 0)
					if ! quiet{
						WriteMsgStdout(_("  %s='update pass'  %s='binary update'  "
						"%s='/var/db update'  %s='/var/db move'\n"
						"  %s='/var/db SLOT move'  %s='binary move'  "
						"%s='binary SLOT move'\n  %s='update /etc/portage/package.*'\n") %
						(Bold("."), Bold("*"), Bold("#"), Bold("@"), Bold("s"), Bold("%"), Bold("S"), Bold("p")))
					}
				}
				valid_updates, errors = parse_updates(mycontent)
				myupd =append(myupd, valid_updates...)
				if ! quiet {
					WriteMsgStdout(Bold(mykey))
					WriteMsgStdout(len(valid_updates)*"." + "\n")
				}
				if len(errors) == 0 {
					timestamps[mykey] = mystat[stat.ST_MTIME]
				}else{
					for _, msg := range errors {
						WriteMsg(fmt.Sprintf("%s\n", msg), -1, nil)
					}
				}
			}
			if len(myupd) > 0{
				retupd = true
			}
		}
	}

	if retupd{
		if os.access(bindb.bintree.pkgdir, os.W_OK) {
			bindb.bintree.Populate(false, true, []string{})
		}else {
			bindb = nil
		}
	}

	master_repoO := portdb.repositories.mainRepo()
	master_repo := ""
	if master_repoO != nil {
		master_repo = master_repoO.Name
	}
	if master_repo in
repo_map{
	repo_map["DEFAULT"] = repo_map[master_repo]
}

	for repo_name, myupd := range repo_map {
		if repo_name == "DEFAULT" {
			continue
		}
		if not myupd {
			continue
		}

		repo_match:=func (repository) {
			return repository == repo_name
			||
			(repo_name == master_repo
			&&
			repository
			not
			in
			repo_map)
		}

		_world_repo_match:=func(atoma, atomb) {
			matches = vardb.match(atoma)
			if not matches:
			matches = vardb.match(atomb)
			if matches &&
			repo_match(vardb.aux_get(best(matches), ['repository'])[0]) {
				if portdb.match(atoma) {
					world_warnings.add((atoma, atomb))
				}
				return true
			}else {
				return false
			}
		}

		for update_cmd
			in
		myupd:
		for pos, atom
			in
		enumerate(world_list):
		new_atom = update_dbentry(update_cmd, atom)
		if atom != new_atom:
		if _world_repo_match(atom, new_atom):
		world_list[pos] = new_atom
		world_modified = true

		for update_cmd
			in
		myupd:
		if update_cmd[0] == "move":
		moves = vardb.move_ent(update_cmd, repo_match = repo_match)
		if moves:
		WriteMsgStdout(moves * "@")
		if bindb:
		moves = bindb.move_ent(update_cmd, repo_match = repo_match)
		if moves:
		WriteMsgStdout(moves * "%")
		elif
		update_cmd[0] == "slotmove":
		moves = vardb.move_slot_ent(update_cmd, repo_match = repo_match)
		if moves:
		WriteMsgStdout(moves * "s")
		if bindb:
		moves = bindb.move_slot_ent(update_cmd, repo_match = repo_match)
		if moves:
		WriteMsgStdout(moves * "S")

	}
	if world_modified{

		world_list.sort()
		write_atomic(world_file,
			"".join("%s\n"%(x, )
		for x
			in
		world_list))
		if world_warnings:
		pass
	}

	if retupd{

		def
		_config_repo_match(repo_name, atoma, atomb):
		matches = vardb.match(atoma)
		if not matches:
		matches = vardb.match(atomb)
		if not matches:
		return false
		repository = vardb.aux_get(best(matches), ['repository'])[0]
		return repository == repo_name
		or
		(repo_name == master_repo
		and
		repository
		not
		in
		repo_map)

		update_config_files(root,
			shlex_split(mysettings.get("CONFIG_PROTECT", "")),
			shlex_split(mysettings.get("CONFIG_PROTECT_MASK", "")),
			repo_map, match_callback = _config_repo_match,
			case_insensitive = "case-insensitive-fs"
		in
		mysettings.features)

		if timestamps:
		for mykey, mtime
			in
		timestamps.items():
		prev_mtimes[mykey] = mtime

		do_upgrade_packagesmessage = false
		def
		onUpdate(_maxval, curval):
		if curval > 0:
		WriteMsgStdout("#")
		if quiet:
		onUpdate = None
		vardb.update_ents(repo_map, onUpdate = onUpdate)
		if bindb:
		def
		onUpdate(_maxval, curval):
		if curval > 0:
		WriteMsgStdout("*")
		if quiet:
		onUpdate = None
		bindb.update_ents(repo_map, onUpdate = onUpdate)

		WriteMsgStdout("\n\n")

		if do_upgrade_packagesmessage and
		bindb
		and
		bindb.cpv_all():
		WriteMsgStdout(_(" ** Skipping packages. Run 'fixpackages' or set it in FEATURES to fix the tbz2's in the packages directory.\n"))
		WriteMsgStdout(Bold(_("Note: This can take a very long time.")))
		WriteMsgStdout("\n")

	}

	return retupd
}
