package atom

import (
	"encoding/json"
	"fmt"
	"github.com/ppphp/configparser"
	"github.com/ppphp/shlex"
	"golang.org/x/sys/unix"
	"io/fs"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const _download_suffix = ".__download__"

var _userpriv_spawn_kwargs = struct {
	uid    *int
	gid    *int32
	umask  int
	groups []int
}{uid: portage_uid, gid: portage_gid, umask: 0o02, groups: userpriv_groups}

func _hide_url_passwd(url string) string {
	r1 := regexp.MustCompile("//([^:\\s]+):[^@\\s]+@")
	return r1.ReplaceAllString(url, "//\\1:*password*@")
}

func _want_userfetch(settings *Config) bool {
	return settings.Features.Features["userfetch"] && *secpass >= 2 && os.Getuid() == 0
}

func _drop_privs_userfetch(settings *Config) {
try:
	_ensure_distdir(settings, settings.ValueDict["DISTDIR"])
	except
PortageException:
	if !pathIsDir(settings.ValueDict["DISTDIR"]) {
		raise
	}
	syscall.Setgid(int(*_userpriv_spawn_kwargs.gid))
	syscall.Setgroups(_userpriv_spawn_kwargs.groups)
	syscall.Setuid(*_userpriv_spawn_kwargs.uid)
	syscall.Umask(_userpriv_spawn_kwargs.umask)
	*secpass = 1
}

func _spawn_fetch(settings *Config, args []string, **kwargs) {

	global
	_userpriv_spawn_kwargs

	if "fd_pipes" not
	in
kwargs:

	kwargs["fd_pipes"] =
	{
		0: portage._get_stdin().fileno(),
		1: sys.__stdout__.fileno(),
		2: sys.__stdout__.fileno(),
	}

	logname = None
	if (
		"userfetch" in
	settings.features
	and
	os.getuid() == 0
	and
	portage_gid
	and
	portage_uid
	and
	hasattr(os, "setgroups")
	):
	kwargs.update(_userpriv_spawn_kwargs)
	logname = portage.data._portage_username

	spawn_func = spawn

	if settings.selinux_enabled():
	spawn_func = selinux.spawn_wrapper(spawn_func, settings["PORTAGE_FETCH_T"])

	if args[0] != BASH_BINARY:
	args = append([]string{BASH_BINARY, "-c", 'exec "$@"', args[0]}, args...)

	phase_backup = settings.get("EBUILD_PHASE")
	settings["EBUILD_PHASE"] = "fetch"
	env = settings.environ()
	if logname != nil:
	env["LOGNAME"] = logname
try:
	rval = spawn_func(args, env = env, **kwargs)
finally:
	if phase_backup is
None:
	settings.pop("EBUILD_PHASE", None) else:
	settings["EBUILD_PHASE"] = phase_backup

	return rval
}

var _userpriv_test_write_file_cache = map[string]int{}

const _userpriv_test_write_cmd_script = ">> %s 2>/dev/null ; rval=$? ; " + "rm -f  %s ; exit $rval"

func _userpriv_test_write_file(settings *Config, file_path string) int {
	rval, ok := _userpriv_test_write_file_cache[file_path]
	if ok {
		return rval
	}

	args := []string{
		BashBinary,
		"-c",
		fmt.Sprintf(_userpriv_test_write_cmd_script, ShellQuote(file_path), ShellQuote(file_path)),
	}

	returncode := _spawn_fetch(settings, args)

	rval = returncode == 0
	_userpriv_test_write_file_cache[file_path] = rval
	return rval
}

func _ensure_distdir(settings *Config, distdir string) {
	dirmode := 0o070
	filemode := 0o60
	modemask := 0o2
	dir_gid := int(*portage_gid)
	if Inmss(settings.ValueDict, "FAKED_MODE") {
		dir_gid = 0
	}

	userfetch := *secpass >= 2 && settings.Features.Features["userfetch"]
	userpriv := *secpass >= 2 && settings.Features.Features["userpriv"]
	write_test_file := filepath.Join(distdir, ".__portage_test_write__")

	st, _ := os.Stat(distdir)

	if st != nil && st.IsDir() {
		if !(userfetch || userpriv) {
			return
		}
		if _userpriv_test_write_file(settings, write_test_file) != 0 {
			return
		}
	}

	delete(_userpriv_test_write_file_cache, write_test_file)
	if ensureDirs(distdir, 0-1, uint32(dir_gid), dirmode, mask, nil, true) {
		if st == nil {
			return
		}
		WriteMsg(fmt.Sprintf("Adjusting permissions recursively: '%s'\n", distdir), -1, nil)
		if !apply_recursive_permissions(
			distdir,
			gid = dir_gid,
			dirmode = dirmode,
			dirmask = modemask,
			filemode = filemode,
			filemask = modemask,
			onerror = _raise_exc,
	){
			raise
			OperationNotPermitted(
				_("Failed to apply recursive permissions for the portage group."),
			)
		}
	}
}

func _checksum_failure_temp_file(settings *Config, distdir, basename string) string {

	filename := filepath.Join(distdir, basename)
	normal_basename := basename
	if strings.HasSuffix(basename, _download_suffix) {
		normal_basename = basename[:len(basename)-len(_download_suffix)]
	}

	st, _ := os.Stat(filename)
	size := st.Size()
	var checksum []byte
	tempfile_re := regexp.MustCompile(regexp.QuoteMeta(normal_basename) +
		"\\._checksum_failure_\\..*")
	ld, _ := listDir(distdir)
	for _, temp_filename := range ld {
		if !tempfile_re.MatchString(temp_filename) {
			continue
		}
		temp_filename = filepath.Join(distdir, temp_filename)
		st, err := os.Stat(temp_filename)
		if err != nil {
			//except OSError:
			continue
		}
		if size != st.Size() {
			continue
		}
		//try:
		temp_checksum := performMd5(temp_filename, false)
		//except FileNotFound:
		//continue
		if checksum == nil {
			checksum = performMd5(filename, false)
		}
		if string(checksum) == string(temp_checksum) {
			syscall.Unlink(filename)
			return temp_filename
		}
	}

	f, _ := os.CreateTemp(distdir, normal_basename+"._checksum_failure_.")
	temp_filename := f.Name()
	f.Close()
	_movefile(filename, temp_filename, 0, nil, settings, nil)
	return temp_filename
}

// 1
func _check_digests(filename string, digests map[string]string, show_errors int) bool {
	verified_ok, reason0, reason1, reason2 := verifyAll(filename, digests, false, 0)
	if !verified_ok {
		if show_errors != 0 {
			WriteMsg(fmt.Sprintf("!!! Previously fetched"+
				" file: '%s'\n", filename), -1, nil)
			WriteMsg(fmt.Sprintf("!!! Reason: %s\n", reason0), -1, nil)
			WriteMsg(fmt.Sprintf("!!! Got:      %s\n"+
				"!!! Expected: %s\n", reason1, reason2), -1, nil)
		}
		return false
	}
	return true
}

// 1, nil
func _check_distfile(filename string, digests map[string]string, eout *eOutput, show_errors int, hash_filter *hashFilter) (bool, os.FileInfo) {
	if digests == nil {
		digests = map[string]string{}
	}
	size, ok := digests["size"]
	if ok && len(digests) == 1 {
		digests = nil
	}

	st, err := os.Stat(filename)
	if err != nil {
		//except OSError:
		return false, nil
	}
	if ok && size != fmt.Sprint(st.Size()) {
		return false, st
	}
	if len(digests) == 0 {
		if ok {
			eout.ebegin(fmt.Sprintf("%s size ;-)", filepath.Base(filename)))
			eout.eend(0, "")
		} else if st.Size() == 0 {
			return false, st
		}
	} else {
		digests = filterUnaccelaratedHashes(digests)
		if hash_filter != nil {
			digests = applyHashFilter(digests, hash_filter)
		}
		if _check_digests(filename, digests, show_errors) {
			eout.ebegin(fmt.Sprintf("%s %s ;-)", filepath.Base(filename), strings.Join(sortedmss(digests), " ")))
			eout.eend(0, "")
		} else {
			return false, st
		}
	}
	return true, st
}

var _fetch_resume_size_re = regexp.MustCompile("(^[\\d]+)([KMGTPEZY]?$)")

var _size_suffix_map = map[string]int{
	"":  0,
	"K": 10,
	"M": 20,
	"G": 30,
	"T": 40,
	"P": 50,
	"E": 60,
	"Z": 70,
	"Y": 80,
}

type DistfileName struct {
	string
	digests map[string]string
}

// nil
func NewDistfileName(s string, digests map[string]string) *DistfileName {
	d := &DistfileName{}
	d.string = s
	d.digests = digests
	if d.digests == nil {
		d.digests = map[string]string{}
	}
	return d
}

func (d *DistfileName) digests_equal(other DistfileName) bool {
	matches := []string{}
	for algo, digest := range d.digests {
		other_digest, ok := other.digests[algo]
		if ok {
			if other_digest == digest {
				matches = append(matches, algo)
			} else {
				return false
			}
		}
	}
	return len(matches) != 0
}

type FlatLayout struct {
}

func (f *FlatLayout) get_path(filename string) string {
	return filename
}

func (f *FlatLayout) get_filenames(distdir string) []string {
	//os.walk(distdir, onerror = _raise_exc):
	ffs := []string{}
	filepath.Walk(distdir, func(path string, info fs.FileInfo, err error) error {
		ffs = append(ffs, path)
		return err
	})
	return ffs
}

// @staticmethod
func (f *FlatLayout) verify_args(args []string) bool {
	return len(args) == 1
}

type FilenameHashLayout struct {
	cutoffs []int
	algo    string
}

func NewFilenameHashLayout(algo, cutoffs string) *FilenameHashLayout {
	f := &FilenameHashLayout{}
	f.algo = algo
	f.cutoffs = []int{}
	for _, x := range strings.Split(cutoffs, ":") {
		f.cutoffs = append(f.cutoffs, toi(x))
	}
	return f
}

func (f *FilenameHashLayout) get_path(filename string) string {
	fnhash := string(checksumStr(filename, f.algo))
	ret := ""
	for _, c := range f.cutoffs {
		//assert c%4 == 0
		c = c / 4
		ret += fnhash[:c] + "/"
		fnhash = fnhash[c:]
	}
	return ret + filename
}

func (f *FilenameHashLayout) get_filenames(distdir string) []string {
	pattern := ""
	for _, c := range f.cutoffs {
		//assert c%4 == 0
		c = c / 4
		pattern += strings.Repeat("[0-9a-f]", c) + "/"
	}
	pattern += "*"
	pts := []string{}
	s, _ := filepath.Glob(filepath.Join(distdir, pattern))
	for _, p := range s {
		pts = append(pts, filepath.Base(p))
	}
	return pts
}

//@staticmethod
func (f *FilenameHashLayout) verify_args(args []string) bool {
	if len(args) != 3 {
		return false
	}
	if !getValidChecksumKeys()[args[1]] {
		return false
	}
	done := true
	for _, c := range strings.Split(args[2], ":") {
		c1, err := strconv.Atoi(c)
		if err != nil {
			//except ValueError:
			done = false
			break
		} else {
			if c1%4 != 0 {
				done = false
				break
			}
		}
	}
	if done {
		return true
	}
	return false
}

type ContentHashLayout struct {
	*FilenameHashLayout
}

func (c *ContentHashLayout) get_path(filename string) string {
	remaining := filename.digests[c.algo]
	fnhash := remaining
	ret := ""
	for _, c := range c.cutoffs {
		//assert c%4 == 0
		c = c / 4
		ret += remaining[:c] + "/"
		remaining = remaining[c:]
	}
	return ret + fnhash
}

func (c *ContentHashLayout) get_filenames(distdir string) []*DistfileName {
	dfs := []*DistfileName{}
	for _, filename := range c.FilenameHashLayout.get_filenames(distdir) {
		NewDistfileName(filename, map[string]string{c.algo: filename})
	}
	return dfs
}

//@staticmethod
// nil
func (c *ContentHashLayout) verify_args(args []string, filename=None) bool {
	if len(args) != 3 {
		return false
	}
	supported_algos := filename.digests
	if filename == nil {
		supported_algos = get_valid_checksum_keys()
	}
	algo := strings.ToUpper(args[1])
	if algo not
	in
	supported_algos{
		return false
	}
	return NewFilenameHashLayout("", "").verify_args(args)
}

func NewContentHashLayout(algo, cutoffs string) *ContentHashLayout {
	c := &ContentHashLayout{}
	c.FilenameHashLayout = NewFilenameHashLayout(algo, cutoffs)
	return c
}

type MirrorLayoutConfig struct {
	structure [][]string
}

func NewMirrorLayoutConfig() *MirrorLayoutConfig {
	m := &MirrorLayoutConfig{}
	m.structure = [][]string{}
	return m
}

func (m *MirrorLayoutConfig) read_from_file(f string) {
	cp := configparser.NewConfigParser(configparser.DefaultArgument)
	readConfigs(cp, []string{f})
	vals := [][]string{}
	for i := 0; ; i++ {
		//try:
		s, err := cp.Gett("structure", fmt.Sprint(i))
		if err != nil {
			//except ConfigParserError:
			break
		}
		vals = append(vals, strings.Fields(s))
	}
	m.structure = vals
}

func (m *MirrorLayoutConfig) serialize() [][]string {
	return m.structure
}

func (m *MirrorLayoutConfig) deserialize(data [][]string) {
	m.structure = data
}

//@staticmethod
// nil
func (m *MirrorLayoutConfig) validate_structure(val []string, filename string) bool {
	if val[0] == "flat" {
		return (&FlatLayout{}).verify_args(val)
	} else if val[0] == "filename-hash" {
		return NewFilenameHashLayout("", "").verify_args(val)
	} else if val[0] == "content-hash" {
		return NewContentHashLayout("", "").verify_args(val, filename)
	}
	return false
}

// nil
func (m *MirrorLayoutConfig) get_best_supported_layout(filename string) {
	for _, val := range m.structure {
		if m.validate_structure(val, "") {
			if val[0] == "flat" {
				return NewFlatLayout(*val[1:])
			} else if val[0] == "filename-hash" {
				return NewFilenameHashLayout(*val[1:])
			} else if val[0] == "content-hash" {
				return NewContentHashLayout(*val[1:])
			}
		}
	}
	return FlatLayout()
}

func (m *MirrorLayoutConfig) get_all_layouts() {
	ret := []Layout{}
	for _, val := range m.structure {
		if !m.validate_structure(val) {
			//raise ValueError("Unsupported structure: {}".format(val))
		}
		if val[0] == "flat" {
			ret = append(ret, FlatLayout(*val[1:]))
		} else if val[0] == "filename-hash" {
			ret = append(ret, FilenameHashLayout(*val[1:]))
		} else if val[0] == "content-hash" {
			ret = append(ret, ContentHashLayout(*val[1:]))
		}
	}
	if len(ret) == 0 {
		ret = append(ret, FlatLayout())
	}
	return ret
}

// ""
func get_mirror_url(mirror_url string, filename string, mysettings *Config, cache_path string) string {

	mirror_conf := NewMirrorLayoutConfig()

	cache :=
	{
	}
	if cache_path != "" {
		f, err := os.Open(cache_path)
		if err == nil {
			err := json.NewDecoder(f).Decode(&cache)
			if err != nil {
			}
		}
		//except(IOError, ValueError):
		//pass
	}

	ts, data := cache.get(mirror_url, (0, None))
	if ts >= time.Now().Unix()-86400 {
		mirror_conf.deserialize(data)
	} else {
		tmpfile := ".layout.conf.%s" % urlparse(mirror_url).hostname
	try:
		if strings.HasPrefix(mirror_url, "/"):
		tmpfile = filepath.Join(mirror_url, "layout.conf")
		mirror_conf.read_from_file(tmpfile)
		else if
		fetch( {
		tmpfile:
			(mirror_url + "/distfiles/layout.conf",)
		},
		mysettings,
			force = 1,
			try_mirrors=0,
	):
		tmpfile = filepath.Join(mysettings["DISTDIR"], tmpfile)
		mirror_conf.read_from_file(tmpfile)
		else:
		raise
		IOError()
		except(ConfigParserError, IOError, UnicodeDecodeError):
		pass
		else:
		cache[mirror_url] = (time.time(), mirror_conf.serialize())
		if cache_path is
		not
	None:
		f = atomic_ofstream(cache_path, "w")
		json.dump(cache, f)
		f.close()
	}

	path := mirror_conf.get_best_supported_layout(filename).get_path(filename)
	up, _ := url.Parse(mirror_url)
	if inSliceS([]string{"ftp", "http", "https"}, up.Scheme) {
		path = url.PathEscape(path)
	}
	if mirror_url[:1] == "/" {
		return filepath.Join(mirror_url, path)
	} else {
		return mirror_url + "/distfiles/" + path
	}
}

// 0,0,".locks", 1,1,nil, true, false
func fetch(myuris map[string]map[string]bool, mysettings *Config, listonly,
	fetchonly int, locks_in_subdir string, use_locks, try_mirrors int,
	digests map[string]map[string]bool, allow_missing_digests, force bool, ) {

	if force && len(digests) > 0 {
		//raise PortageException(
		//	_("fetch: force=True is not allowed when digests are provided")
		//)
	}

	if len(myuris) == 0 {
		return 1
	}

	features := mysettings.Features
	restrict := strings.Fields(mysettings.ValueDict["PORTAGE_RESTRICT"])
	userfetch := *secpass >= 2 && features.Features["userfetch"]

	restrict_mirror := Ins(restrict, "mirror") || Ins(restrict, "nomirror")
	if restrict_mirror {
		if features.Features["mirror"] && !features.Features["lmirror"] {
			print(">>> \"mirror\" mode desired and \"mirror\" restriction found; skipping fetch.")
			return 1
		}
	}

	checksum_failure_max_tries := 5
	v := checksum_failure_max_tries
	mv, ok := mysettings.ValueDict["PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"]
	if !ok {
		mv = fmt.Sprint(checksum_failure_max_tries)
	}

	v, err := strconv.Atoi(mv)
	if err != nil {
		//except(ValueError, OverflowError):
		WriteMsg(fmt.Sprintf("!!! Variable PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"+
			" contains non-integer value: '%s'\n",
			mysettings.ValueDict["PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"]), -1, nil)
		WriteMsg(fmt.Sprintf("!!! Using PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS "+
			"default value: %s\n", checksum_failure_max_tries), -1, nil)
		v = checksum_failure_max_tries
	}
	if v < 1 {
		WriteMsg(fmt.Sprintf("!!! Variable PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"+
			" contains value less than 1: '%s'\n", v), -1, nil)
		WriteMsg(fmt.Sprintf("!!! Using PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS "+
			"default value: %s\n", checksum_failure_max_tries), -1, nil)
		v = checksum_failure_max_tries
	}
	checksum_failure_max_tries = v

	fetch_resume_size_default := "350K"
	fetch_resume_size, ok := mysettings.ValueDict["PORTAGE_FETCH_RESUME_MIN_SIZE"]
	if ok {
		fetch_resume_size = strings.Join(strings.Fields(fetch_resume_size), "")
		if len(fetch_resume_size) == 0 {
			fetch_resume_size = fetch_resume_size_default
		}
		match := _fetch_resume_size_re.FindAllString(fetch_resume_size, -1)
		if _, ok := _size_suffix_map[strings.ToUpper(match[2])]; match == nil || !ok {
			WriteMsg(fmt.Sprintf("!!! Variable PORTAGE_FETCH_RESUME_MIN_SIZE"+
				" contains an unrecognized format: '%s'\n",
				mysettings.ValueDict["PORTAGE_FETCH_RESUME_MIN_SIZE"]), -1, nil)
			WriteMsg(
				fmt.Sprintf("!!! Using PORTAGE_FETCH_RESUME_MIN_SIZE "+
					"default value: %s\n", fetch_resume_size_default),
				-1, nil)
			ok = false
		}
	}
	if !ok {
		fetch_resume_size = fetch_resume_size_default
		match = _fetch_resume_size_re.match(fetch_resume_size)
	}
	fetch_resume_size = (
		int(match.group(1)) * 2 * *_size_suffix_map[match.group(2).upper()]
	)

	checksum_failure_primaryuri := 2
	thirdpartymirrors := mysettings.thirdpartymirrors()

	parallel_fetchonly := Inmss(mysettings.ValueDict, "PORTAGE_PARALLEL_FETCHONLY")
	if parallel_fetchonly {
		fetchonly = 1
	}

	check_config_instance(mysettings)

	custommirrors := grabDict(filepath.Join(mysettings.ValueDict["PORTAGE_CONFIGROOT"], CustomMirrorsFile), false, false, true, true, false)

	if listonly != 0 || !features.Features["distlocks"] {
		use_locks = 0
	}

	distdir_writable := osAccess(mysettings.ValueDict["DISTDIR"], unix.W_OK)
	fetch_to_ro := 0
	if features.Features["skiprocheck"] {
		fetch_to_ro = 1
	}

	if !distdir_writable && fetch_to_ro != 0 {
		if use_locks != 0 {
			WriteMsg(colorize("BAD",
				"!!! For fetching to a read-only filesystem, "+
					"locking should be turned off.\n"), -1, nil)
			WriteMsg("!!! This can be done by adding -distlocks to "+
				"FEATURES in /etc/portage/make.conf\n", -1, nil)
		}
	}

	local_mirrors := []string{}
	public_mirrors := []string{}
	fsmirrors := []string{}
	if try_mirrors {
		for _, x := range custommirrors["local"] {
			if strings.HasPrefix(x, "/") {
				fsmirrors = append(fsmirrors, x)
			} else {
				local_mirrors = append(local_mirrors, x)
			}
		}
		for _, x := range strings.Fields(mysettings.ValueDict["GENTOO_MIRRORS"]) {
			if len(x) == 0 {
				continue
			}
			if strings.HasPrefix(x, "/") {
				fsmirrors = append(fsmirrors, strings.TrimRight(x, "/"))
			} else {
				public_mirrors = append(public_mirrors, strings.TrimRight(x, "/"))
			}
		}
	}

	hash_filter := NewHashFilter(mysettings.ValueDict["PORTAGE_CHECKSUM_FILTER"])
	if hash_filter.trasparent {
		hash_filter = nil
	}
	skip_manifest := mysettings.ValueDict["EBUILD_SKIP_MANIFEST"] == "1"
	if skip_manifest {
		allow_missing_digests = true
	}
	pkgdir, ok := mysettings.ValueDict["O"]
	mydigests := digests
	if digests == nil && !(!ok || skip_manifest) {
		mydigests =
			mysettings.Repositories.getRepoForLocation(
				filepath.Dir(filepath.Dir(pkgdir))).
				load_manifest(pkgdir, mysettings.ValueDict["DISTDIR"], nil, false).
				getTypeDigests("DIST")
	} else if digests == nil || skip_manifest {
		mydigests = map[string]map[string]bool{}
	}

	ro_distdirs := []string{}
	ss, _ := shlex.Split(strings.NewReader(mysettings.ValueDict["PORTAGE_RO_DISTDIRS"]), false, true)
	for _, x := range ss {
		if pathIsDir(x) {
			ro_distdirs = append(ro_distdirs, x)
		}
	}

	restrict_fetch := Ins(restrict, "fetch")
	force_mirror := features.Features["force-mirror"] && !restrict_mirror

	type ds struct {
		d *DistfileName
		s string
	}
	file_uri_tuples := []ds{}
	if false { //hasattr(myuris, "items") {
		//	for myfile, uri_set
		//		in
		//	myuris.items():
		//	for myuri
		//		in
		//	uri_set:
		//	file_uri_tuples.append(
		//		(DistfileName(myfile, digests = mydigests.get(myfile)), myuri)
		//)
		//	if not uri_set:
		//	file_uri_tuples.append(
		//		(DistfileName(myfile, digests = mydigests.get(myfile)), None)
		//)
	} else {
		for myuri := range myuris {
			u, _ := url.Parse(myuri)
			if u.Scheme != "" {
				file_uri_tuples = append(file_uri_tuples, ds{
					NewDistfileName(filepath.Base(myuri),
						mydigests[filepath.Base(myuri)]), myuri})
			} else {
				file_uri_tuples = append(file_uri_tuples, ds{
					NewDistfileName(
						filepath.Base(myuri),
						mydigests[filepath.Base(myuri)],
					), ""})
			}
		}
	}

	filedict := OrderedDict()
	primaryuri_dict := map[*DistfileName][]string{}
	thirdpartymirror_uris := map[*DistfileName][]string{}
	for _, val := range file_uri_tuples {
		myfile, myuri := val.d, val.s

		override_mirror := false
		if myuri != "" {
			override_mirror = strings.HasPrefix(myuri, "mirror+")
		}
		override_fetch := override_mirror

		if !override_fetch {
			if myuri != "" {
				override_fetch = strings.HasPrefix(myuri, "fetch+")
			}
		}
		if override_fetch {
			myuri = strings.Split(myuri, "+")[1]
		}

		if _, ok := filedict[myfile]; !ok {
			filedict[myfile] = []string{}
			mirror_cache := ""
			if distdir_writable {
				mirror_cache = filepath.Join(mysettings.ValueDict["DISTDIR"], ".mirror-cache.json")
			}

			file_restrict_mirror := (restrict_fetch || restrict_mirror) && !override_mirror

			location_lists := [][]string{local_mirrors}
			if !file_restrict_mirror {
				location_lists = append(location_lists, public_mirrors)
			}

			for _, v := range location_lists {
				for _, vv := range v {
					filedict[myfile] = append(filedict[myfile],
						get_mirror_url(vv, myfile, mysettings, mirror_cache))

				}
			}
		}
		if myuri == "" {
			continue
		}
		if myuri[:9] == "mirror://" {
			eidx := strings.Index(myuri[9:], "/")
			if eidx != -1 {
				mirrorname := myuri[9:eidx]
				path := myuri[eidx+1:]

				if _, ok := custommirrors[mirrorname]; ok {
					for _, cmirr := range custommirrors[mirrorname] {
						filedict[myfile] = append(filedict[myfile], strings.TrimRight(cmirr, "/")+"/"+path)
					}

					if _, ok := thirdpartymirrors[mirrorname]; ok {

						uris := []string{}
						for _, locmirr := range thirdpartymirrors[mirrorname] {
							uris = append(uris, strings.TrimRight(locmirr, "/")+"/"+path)
						}
						rand.Shuffle(len(uris), func(i, j int) {
							uris[i], uris[j] = uris[j], uris[i]
						})
						filedict[myfile] = append(filedict[myfile], uris...)
						if _, ok := thirdpartymirror_uris[myfile]; !ok {
							thirdpartymirror_uris[myfile] = append(thirdpartymirror_uris[myfile], uris...)
						}
					}

					if !Inmsss(custommirrors, mirrorname) && !Inmsss(thirdpartymirrors, mirrorname) {
						WriteMsg(fmt.Sprintf("!!! No known mirror by the name: %s\n", mirrorname), 0, nil)
					}
				} else {
					WriteMsg("Invalid mirror definition in SRC_URI:\n", -1, nil)
					WriteMsg(fmt.Sprintf("  %s\n", myuri), -1, nil)
				}
			} else {
				if (restrict_fetch && !override_fetch) || force_mirror {
					continue
				}
				primaryuris, ok := primaryuri_dict[myfile]
				if !ok {
					primaryuris = []string{}
					primaryuri_dict[myfile] = primaryuris
				}
				primaryuris = append(primaryuris, myuri)
			}
		}

		for _, uris := range primaryuri_dict {
			reversed(uris)
		}

		for myfile, uris := range thirdpartymirror_uris {
			if _, ok := primaryuri_dict[myfile]; !ok {
				primaryuri_dict[myfile] = []string{}
			}
			primaryuri_dict[myfile] = append(primaryuri_dict[myfile], uris...)
		}

		if Ins(restrict, "primaryuri") {
			for myfile, uris := range filedict {
				filedict[myfile] = primaryuri_dict[myfile] + uris
			}
		} else {
			for myfile := range filedict {
				filedict[myfile] += primaryuri_dict[myfile]
			}
		}

		can_fetch := true

		if listonly {
			can_fetch = false
		}

		if can_fetch && fetch_to_ro == 0 {
			//try:
			_ensure_distdir(mysettings, mysettings.ValueDict["DISTDIR"])
			//except PortageException as e:
			//if not pathIsDir(mysettings["DISTDIR"]):
			//WriteMsg("!!! %s\n"%str(e), noiselevel = -1)
			//WriteMsg(
			//	_("!!! Directory Not Found: DISTDIR='%s'\n")
			//% mysettings["DISTDIR"],
			//	-1, nil
			//)
			//WriteMsg(_("!!! Fetching will fail!\n"), noiselevel = -1)
		}

		if can_fetch && !fetch_to_ro && !osAccess(mysettings["DISTDIR"], unix.W_OK) {
			WriteMsg(fmt.Sprintf("!!! No write access to '%s'\n", mysettings.ValueDict["DISTDIR"]), -1, nil)
			can_fetch = false
		}

		distdir_writable = can_fetch && !fetch_to_ro
		failed_files := set()
		restrict_fetch_msg := false
		valid_hashes := CopyMapSB(getValidChecksumKeys())
		delete(valid_hashes, "size")

		for myfile
			in
		filedict:
		fetched = 0

		orig_digests = mydigests.get(myfile,
		{
		})

		if not(allow_missing_digests or
		listonly):
		verifiable_hash_types = set(orig_digests).intersection(valid_hashes)
		if not verifiable_hash_types:
		expected = " ".join(sorted(valid_hashes))
		got = set(orig_digests)
		got.discard("size")
		got = " ".join(sorted(got))
		reason = (
			_("Insufficient data for checksum verification"),
			got,
			expected,
	)
		WriteMsg(
			_("!!! Fetched file: %s VERIFY FAILED!\n")%myfile, noiselevel = -1
		)
		WriteMsg(_("!!! Reason: %s\n")%reason[0], noiselevel = -1)
		WriteMsg(
			_("!!! Got:      %s\n!!! Expected: %s\n")%(reason[1], reason[2]),
			-1, nil
		)

		if fetchonly:
		failed_files.add(myfile)
		continue
		else:
		return 0

		size = orig_digests.get("size")
		if size == 0:
		del
		mydigests[myfile]
		orig_digests.clear()
		size = None
		pruned_digests = orig_digests
		if parallel_fetchonly:
		pruned_digests =
		{
		}
		if size != nil:
		pruned_digests["size"] = size

		myfile_path = filepath.Join(mysettings["DISTDIR"], myfile)
		download_path = myfile_path
		if fetch_to_ro
		else
		myfile_path + _download_suffix
		has_space = True
		has_space_superuser = True
		file_lock = None
		if listonly:
		WriteMsg_stdout("\n", noiselevel = -1) else:
		vfs_stat = None
		if size != nil and
		hasattr(os, "statvfs"):
	try:
		vfs_stat = os.statvfs(mysettings["DISTDIR"])
		except
		OSError
		as
	e:
		WriteMsg_level(
			"!!! statvfs('%s'): %s\n"%(mysettings["DISTDIR"], e),
			-1, nil
		level = logging.ERROR,
	)
		del
		e

		if vfs_stat != nil:
	try:
		mysize = os.stat(myfile_path).st_size
		except
		OSError
		as
	e:
		if e.errno not
		in(errno.ENOENT, errno.ESTALE):
		raise
		del
		e
		mysize = 0
		if (size - mysize + vfs_stat.f_bsize) >= (
			vfs_stat.f_bsize * vfs_stat.f_bavail
	):

		if (size - mysize + vfs_stat.f_bsize) >= (
			vfs_stat.f_bsize * vfs_stat.f_bfree
	):
		has_space_superuser = False

		if not has_space_superuser:
		has_space = False
		else if portage.data.secpass < 2:
		has_space = False else if userfetch:
		has_space = False

		if distdir_writable and
	use_locks:

		lock_kwargs =
		{
		}
		if fetchonly:
		lock_kwargs["flags"] = os.O_NONBLOCK

	try:
		file_lock = lockfile(myfile_path, wantnewlockfile = 1, **lock_kwargs)
		except
	TryAgain:
		WriteMsg(
			_(
				">>> File '%s' is already locked by "
		"another fetcher. Continuing...\n"
		)
		% myfile,
			-1, nil
		)
		continue
	try:
		if not listonly:

		eout = EOutput()
		eout.quiet = mysettings.get("PORTAGE_QUIET") == "1"
		match, mystat = _check_distfile(
			myfile_path, pruned_digests, eout, hash_filter = hash_filter
		)
		if match and
		not
	force:
		if distdir_writable and
		not
		os.path.islink(myfile_path):
	try:
		apply_secpass_permissions(
			myfile_path,
			gid = portage_gid,
			mode = 0o664,
			mask = 0o2,
			stat_cached = mystat,
	)
		except
		PortageException
		as
	e:
		if not osAccess(myfile_path, os.R_OK):
		WriteMsg(
			_("!!! Failed to adjust permissions:"
		" %s\n")
		% str(e),
			-1, nil
		)
		del
		e
		continue

		if distdir_writable and
		mystat
		is
		None
		or
		os.path.islink(myfile_path):
	try:
		os.unlink(myfile_path)
		except
		OSError
		as
	e:
		if e.errno not
		in(errno.ENOENT, errno.ESTALE):
		raise
		mystat = None

		if mystat != nil:
		if stat.S_ISDIR(mystat.st_mode):
		WriteMsg_level(
			_(
				"!!! Unable to fetch file since "
		"a directory is in the way: \n"
		"!!!   %s\n"
		)
		% myfile_path,
			level = logging.ERROR,
			-1, nil
		)
		return 0

		if distdir_writable and
		not
	force:
		temp_filename = _checksum_failure_temp_file(
			mysettings, mysettings["DISTDIR"], myfile,
		)
		WriteMsg_stdout(
			_("Refetching... "
		"File renamed to '%s'\n\n")
		% temp_filename,
			-1, nil
		)

	try:
		mystat = os.stat(download_path)
		except
		OSError
		as
	e:
		if e.errno not
		in(errno.ENOENT, errno.ESTALE):
		raise
		mystat = None

		if mystat != nil:
		if mystat.st_size == 0:
		if distdir_writable:
	try:
		os.unlink(download_path)
		except
	OSError:
		pass else if distdir_writable and
		size != nil:
		if mystat.st_size < fetch_resume_size and
		mystat.st_size < size:
		WriteMsg(
			_(
				">>> Renaming distfile with size "
		"%d (smaller than "
		"PORTAGE_FETCH_RESU"
		"ME_MIN_SIZE)\n"
		)
		% mystat.st_size
		)
		temp_filename = _checksum_failure_temp_file(
			mysettings,
			mysettings["DISTDIR"],
			filepath.Base(download_path),
		)
		WriteMsg_stdout(
			_("Refetching... "
		"File renamed to '%s'\n\n")
		% temp_filename,
			-1, nil
		) else if mystat.st_size >= size:
		temp_filename = _checksum_failure_temp_file(
			mysettings,
			mysettings["DISTDIR"],
			filepath.Base(download_path),
		)
		WriteMsg_stdout(
			_("Refetching... "
		"File renamed to '%s'\n\n")
		% temp_filename,
			-1, nil
		)

		if distdir_writable and
	ro_distdirs:
		readonly_file = None
		for x
			in
		ro_distdirs:
		filename = get_mirror_url(x, myfile, mysettings)
		match, mystat = _check_distfile(
			filename, pruned_digests, eout, hash_filter = hash_filter
		)
		if match:
		readonly_file = filename
		break
		if readonly_file != nil:
	try:
		os.unlink(myfile_path)
		except
		OSError
		as
	e:
		if e.errno not
		in(errno.ENOENT, errno.ESTALE):
		raise
		del
		e
		os.symlink(readonly_file, myfile_path)
		continue

		if not has_space:
		WriteMsg(
			_("!!! Insufficient space to store %s in %s\n")
		% (myfile, mysettings["DISTDIR"]),
		-1, nil
		)

		if has_space_superuser:
		WriteMsg(
			_(
				"!!! Insufficient privileges to use "
		"remaining space.\n"
		),
		-1, nil
		)
		if userfetch:
		WriteMsg(
			_(
				'!!! You may set FEATURES="-userfetch"'
		" in /etc/portage/make.conf in order to fetch with\n"
		"!!! superuser privileges.\n"
		),
		-1, nil
		)

		if fsmirrors and
		not
		os.path.exists(myfile_path)
		and
	has_space:
		for mydir
			in
		fsmirrors:
		mirror_file = get_mirror_url(mydir, myfile, mysettings)
	try:
		shutil.copyfile(mirror_file, download_path)
		WriteMsg(_("Local mirror has file: %s\n") % myfile)
		break
		except(IOError, OSError)
		as
	e:
		if e.errno not
		in(errno.ENOENT, errno.ESTALE):
		raise
		del
		e

	try:
		mystat = os.stat(download_path)
		except
		OSError
		as
	e:
		if e.errno not
		in(errno.ENOENT, errno.ESTALE):
		raise
		del
		e else:
		if not os.path.islink(download_path):
	try:
		apply_secpass_permissions(
			download_path,
			gid = portage_gid,
			mode = 0o664,
			mask = 0o2,
			stat_cached = mystat,
	)
		except
		PortageException
		as
	e:
		if not osAccess(download_path, os.R_OK):
		WriteMsg(
			_("!!! Failed to adjust permissions:"
		" %s\n")
		% (e, ),
		-1, nil
		)

		if mystat.st_size == 0:
		if distdir_writable:
	try:
		os.unlink(download_path)
		except
	EnvironmentError:
		pass else if not orig_digests:
		if not force:
		fetched = 1 else:
		if (
			mydigests[myfile].get("size") != nil
			and
		mystat.st_size < mydigests[myfile]["size"]
		and
		not
		restrict_fetch
		):
		fetched = 1 else if (
			parallel_fetchonly
			and
		mystat.st_size == mydigests[myfile]["size"]
		):
		eout = EOutput()
		eout.quiet = mysettings.get("PORTAGE_QUIET") == "1"
		eout.ebegin("%s size ;-)" % (myfile))
		eout.eend(0)
		continue else:
		digests = _filter_unaccelarated_hashes(mydigests[myfile])
		if hash_filter != nil:
		digests = _apply_hash_filter(digests, hash_filter)
		verified_ok, reason = verify_all(download_path, digests)
		if not verified_ok:
		WriteMsg(
			_("!!! Previously fetched"
		" file: '%s'\n")
		% myfile,
			-1, nil
		)
		WriteMsg(
			_("!!! Reason: %s\n")%reason[0], noiselevel = -1
		)
		WriteMsg(
			_("!!! Got:      %s\n"
		"!!! Expected: %s\n")
		% (reason[1], reason[2]),
		-1, nil
		)
		if reason[0] == _(
			"Insufficient data for checksum verification",
		):
		return 0
		if distdir_writable:
		temp_filename = _checksum_failure_temp_file(
			mysettings,
			mysettings["DISTDIR"],
			filepath.Base(download_path),
		)
		WriteMsg_stdout(
			_("Refetching... "
		"File renamed to '%s'\n\n")
		% temp_filename,
			-1, nil
		) else:
		if not fetch_to_ro:
		_movefile(
			download_path,
			myfile_path,
			mysettings = mysettings,
	)
		eout = EOutput()
		eout.quiet = (
			mysettings.get("PORTAGE_QUIET", None) == "1"
		)
		if digests:
		digests = list(digests)
		digests.sort()
		eout.ebegin(
			"%s %s ;-)"%(myfile, " ".join(digests))
		)
		eout.eend(0)
		continue

		uri_list = filedict[myfile][:]
		uri_list.reverse()
		checksum_failure_count = 0
		tried_locations = set()
		while
	uri_list:
		loc = uri_list.pop()
		if isinstance(loc, functools.partial):
		loc = loc()
		if loc in
	tried_locations:
		continue
		tried_locations.add(loc)
		if listonly:
		WriteMsg_stdout(loc+" ", noiselevel = -1)
		continue
		protocol = loc[0:loc.find("://")]

		global_config_path = GLOBAL_CONFIG_PATH
		if portage.
		const.EPREFIX:
		global_config_path = filepath.Join(
			portage.
		const.EPREFIX, GLOBAL_CONFIG_PATH.lstrip(os.sep)
		)

		missing_file_param = False
		fetchcommand_var = "FETCHCOMMAND_" + protocol.upper()
		fetchcommand = mysettings.get(fetchcommand_var)
		if fetchcommand is
	None:
		fetchcommand_var = "FETCHCOMMAND"
		fetchcommand = mysettings.get(fetchcommand_var)
		if fetchcommand is
	None:
		WriteMsg_level(
			_(
				"!!! %s is unset. It should "
		"have been defined in\n!!! %s/make.globals.\n"
		)
		% (fetchcommand_var, global_config_path),
		level = logging.ERROR,
			-1, nil
		)
		return 0
		if "${FILE}" not
		in
	fetchcommand:
		WriteMsg_level(
			_(
				"!!! %s does not contain the required ${FILE}"
		" parameter.\n"
		)
		% fetchcommand_var,
			level = logging.ERROR,
			-1, nil
		)
		missing_file_param = True

		resumecommand_var = "RESUMECOMMAND_" + protocol.upper()
		resumecommand = mysettings.get(resumecommand_var)
		if resumecommand is
	None:
		resumecommand_var = "RESUMECOMMAND"
		resumecommand = mysettings.get(resumecommand_var)
		if resumecommand is
	None:
		WriteMsg_level(
			_(
				"!!! %s is unset. It should "
		"have been defined in\n!!! %s/make.globals.\n"
		)
		% (resumecommand_var, global_config_path),
		level = logging.ERROR,
			-1, nil
		)
		return 0
		if "${FILE}" not
		in
	resumecommand:
		WriteMsg_level(
			_(
				"!!! %s does not contain the required ${FILE}"
		" parameter.\n"
		)
		% resumecommand_var,
			level = logging.ERROR,
			noiselevel =-1,
	)
		missing_file_param = True

		if missing_file_param:
		WriteMsg_level(
			_(
				"!!! Refer to the make.conf(5) man page for "
		"information about how to\n!!! correctly specify "
		"FETCHCOMMAND and RESUMECOMMAND.\n"
		),
		level = logging.ERROR,
			-1, nil
		)
		if myfile != filepath.Base(loc):
		return 0

		if not can_fetch:
		if fetched != 2:
	try:
		mysize = os.stat(download_path).st_size
		except
		OSError
		as
	e:
		if e.errno not
		in(errno.ENOENT, errno.ESTALE):
		raise
		del
		e
		mysize = 0

		if mysize == 0:
		WriteMsg(
			_("!!! File %s isn't fetched but unable to get it.\n")
		% myfile,
			noiselevel = -1,
	) else if size is
		None
		or
		size > mysize:
		WriteMsg(
			_(
				"!!! File %s isn't fully fetched, but unable to complete it\n",
			)
		% myfile,
			-1, nil
		) else:
		WriteMsg(
			_(
				"!!! File %s is incorrect size, "
		"but unable to retry.\n"
		)
		% myfile,
			noiselevel = -1,
	)
		return 0
		continue

		if fetched != 2 and
	has_space:
		if fetched == 1:
	try:
		mystat = os.stat(download_path)
		except
		OSError
		as
	e:
		if e.errno not
		in(errno.ENOENT, errno.ESTALE):
		raise
		del
		e
		fetched = 0 else:
		if distdir_writable and
		mystat.st_size < fetch_resume_size:
		WriteMsg(
			_(
				">>> Deleting distfile with size "
		"%d (smaller than "
		"PORTAGE_FETCH_RESU"
		"ME_MIN_SIZE)\n"
		)
		% mystat.st_size
		)
	try:
		os.unlink(download_path)
		except
		OSError
		as
	e:
		if e.errno not
		in(errno.ENOENT, errno.ESTALE):
		raise
		del
		e
		fetched = 0
		if fetched == 1:
		WriteMsg(_(">>> Resuming download...\n"))
		locfetch = resumecommand
		command_var = resumecommand_var else:
		locfetch = fetchcommand
		command_var = fetchcommand_var
		WriteMsg_stdout(_(">>> Downloading '%s'\n") % _hide_url_passwd(loc))
		variables =
		{
			"URI": loc, "FILE": filepath.Base(download_path)
		}

	try:
		variables["DIGESTS"] = " ".join(
		[
		"%s:%s" % (k.lower(), v)
		for k, v
			in
		mydigests[myfile].items()
		if k != "size"
]
)
except KeyError:
pass

for k in ("DISTDIR", "PORTAGE_SSH_OPTS"):
v = mysettings.get(k)
if v != nil:
variables[k] = v

myfetch = varexpand(locfetch, mydict = variables)
myfetch = shlex_split(myfetch)

myret = -1
try:

myret = _spawn_fetch(mysettings, myfetch)

finally:
try:
apply_secpass_permissions(
download_path, gid = portage_gid, mode = 0o664, mask = 0o2
)
except FileNotFound:
pass
except PortageException as e:
if not osAccess(download_path, os.R_OK):
WriteMsg(
_("!!! Failed to adjust permissions:" " %s\n")
% str(e),
-1, nil
)
del e

try:
mystat = os.lstat(download_path)
if mystat.st_size == 0 or (
stat.S_ISLNK(mystat.st_mode)
and not os.path.exists(download_path)
):
os.unlink(download_path)
fetched = 0
continue
except EnvironmentError:
pass

if mydigests != nil and myfile in mydigests:
try:
mystat = os.stat(download_path)
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
del e
fetched = 0 else:

if stat.S_ISDIR(mystat.st_mode):
WriteMsg_level(
_(
"!!! The command specified in the "
"%s variable appears to have\n!!! "
"created a directory instead of a "
"normal file.\n"
)
% command_var,
level = logging.ERROR,
-1, nil
)
WriteMsg_level(
_(
"!!! Refer to the make.conf(5) "
"man page for information about how "
"to\n!!! correctly specify "
"FETCHCOMMAND and RESUMECOMMAND.\n"
),
level = logging.ERROR,
noiselevel = -1,
)
return 0

if (
myret != os.EX_OK
and mystat.st_size < mydigests[myfile]["size"]
):
# Fetch failed... Try the next one... Kill 404 files though.
if (
(mystat[stat.ST_SIZE] < 100000)
and (len(myfile) > 4)
and not (
(myfile[-5:] == ".html")
or (myfile[-4:] == ".htm")
)
):
html404 = re.compile(
"<title>.*(not found|404).*</title>",
re.I | re.M,
)
with io.open(
_unicode_encode(
download_path,
encoding = _encodings["fs"],
errors = "strict",
),
mode = "r",
encoding = _encodings["content"],
errors = "replace",
) as f:
if html404.search(f.read()):
try:
os.unlink(download_path)
WriteMsg(
_(
">>> Deleting invalid distfile. (Improper 404 redirect from server.)\n"
)
)
fetched = 0
continue
except (IOError, OSError):
pass
fetched = 1
continue
if True:
digests = _filter_unaccelarated_hashes(
mydigests[myfile]
)
if hash_filter != nil:
digests = _apply_hash_filter(digests, hash_filter)
verified_ok, reason = verify_all(download_path, digests)
if not verified_ok:
WriteMsg(
_("!!! Fetched file: %s VERIFY FAILED!\n")
% myfile,
-1, nil
)
WriteMsg(
_("!!! Reason: %s\n") % reason[0], noiselevel = -1
)
WriteMsg(
_("!!! Got:      %s\n!!! Expected: %s\n")
% (reason[1], reason[2]),
-1, nil
)
if reason[0] == _(
"Insufficient data for checksum verification"
):
return 0
if distdir_writable:
temp_filename = _checksum_failure_temp_file(
mysettings,
mysettings["DISTDIR"],
filepath.Base(download_path),
)
WriteMsg_stdout(
_(
"Refetching... "
"File renamed to '%s'\n\n"
)
% temp_filename,
-1, nil
)
fetched = 0
checksum_failure_count += 1
if (
checksum_failure_count
== checksum_failure_primaryuri
):
primaryuris = primaryuri_dict.get(myfile)
if primaryuris:
uri_list.extend(reversed(primaryuris))
if (
checksum_failure_count
>= checksum_failure_max_tries
):
break else:
if not fetch_to_ro:
_movefile(
download_path,
myfile_path,
mysettings = mysettings,
)
eout = EOutput()
eout.quiet = (
mysettings.get("PORTAGE_QUIET", None) == "1"
)
if digests:
eout.ebegin(
"%s %s ;-)"
% (myfile, " ".join(sorted(digests)))
)
eout.eend(0)
fetched = 2
break else:
if not myret:
if not fetch_to_ro:
_movefile(
download_path, myfile_path, mysettings = mysettings
)
fetched = 2
break else if mydigests != None:
WriteMsg(
_("No digest file available and download failed.\n\n"),
noiselevel = -1,
)
finally:
if use_locks and file_lock:
unlockfile(file_lock)
file_lock = None

if listonly:
WriteMsg_stdout("\n", noiselevel = -1)
if fetched != 2:
if restrict_fetch and not restrict_fetch_msg:
restrict_fetch_msg = True
msg = _(
"\n!!! %s/%s"
" has fetch restriction turned on.\n"
"!!! This probably means that this "
"ebuild's files must be downloaded\n"
"!!! manually.  See the comments in"
" the ebuild for more information.\n\n"
) % (mysettings["CATEGORY"], mysettings["PF"])
WriteMsg_level(msg, level = logging.ERROR, noiselevel = -1) else if restrict_fetch:
pass else if listonly:
pass else if not filedict[myfile]:
WriteMsg(
_("Warning: No mirrors available for file" " '%s'\n") % (myfile),
-1, nil
) else:
WriteMsg(
_("!!! Couldn't download '%s'. Aborting.\n") % myfile, noiselevel = -1
)

if listonly:
failed_files.add(myfile)
continue else if fetchonly:
failed_files.add(myfile)
continue
return 0
if failed_files:
return 0
return 1
}
