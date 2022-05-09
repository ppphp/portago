package atom

import (
	"encoding/json"
	"fmt"
	"github.com/ppphp/configparser"
	"github.com/ppphp/portago/pkg/checksum"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/shlex"
	"golang.org/x/sys/unix"
	"io/fs"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
}{uid: data.portage_uid, gid: data.portage_gid, umask: 0o02, groups: data.userpriv_groups}

func _hide_url_passwd(url string) string {
	r1 := regexp.MustCompile("//([^:\\s]+):[^@\\s]+@")
	return r1.ReplaceAllString(url, "//\\1:*password*@")
}

func _want_userfetch(settings *Config) bool {
	return settings.Features.Features["userfetch"] && *data.secpass >= 2 && os.Getuid() == 0
}

func _drop_privs_userfetch(settings *Config) {
	//try:
	_ensure_distdir(settings, settings.ValueDict["DISTDIR"])
	//except PortageException:
	if !myutil.pathIsDir(settings.ValueDict["DISTDIR"]) {
		raise
	}
	syscall.Setgid(int(*_userpriv_spawn_kwargs.gid))
	syscall.Setgroups(_userpriv_spawn_kwargs.groups)
	syscall.Setuid(*_userpriv_spawn_kwargs.uid)
	syscall.Umask(_userpriv_spawn_kwargs.umask)
	*data.secpass = 1
}

func _spawn_fetch(settings *Config, args []string, **kwargs) int {

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

	var logname *string
	if settings.Features.Features["userfetch"] && os.Getuid() == 0 && data.portage_gid != nil && *data.portage_gid != 0 && data.portage_uid != nil && *data.portage_uid != 0 {
		kwargs.update(_userpriv_spawn_kwargs)
		logname = data._portage_username
	}

	spawn_func := process.spawn

	if settings.selinux_enabled() {
		spawn_func = selinux.spawn_wrapper(spawn_func, settings.ValueDict["PORTAGE_FETCH_T"])

		if args[0] != _const.BashBinary {
			args = append([]string{_const.BashBinary, "-c", `exec "$@"`, args[0]}, args...)
		}
	}

	phase_backup := settings.ValueDict["EBUILD_PHASE"]
	settings.ValueDict["EBUILD_PHASE"] = "fetch"
	env := settings.environ()
	if logname != nil {
		env["LOGNAME"] = *logname
	}
	//try:
	rval := spawn_func(args, env = env, **kwargs)
	//finally:
	if phase_backup == "" {
		delete(settings.ValueDict, "EBUILD_PHASE")
	} else {
		settings.ValueDict["EBUILD_PHASE"] = phase_backup
	}

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
		_const.BashBinary,
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
	dir_gid := int(*data.portage_gid)
	if myutil.Inmss(settings.ValueDict, "FAKED_MODE") {
		dir_gid = 0
	}

	userfetch := *data.secpass >= 2 && settings.Features.Features["userfetch"]
	userpriv := *data.secpass >= 2 && settings.Features.Features["userpriv"]
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
	if util.ensureDirs(distdir, 0-1, uint32(dir_gid), dirmode, mask, nil, true) {
		if st == nil {
			return
		}
		util.WriteMsg(fmt.Sprintf("Adjusting permissions recursively: '%s'\n", distdir), -1, nil)
		if !apply_recursive_permissions(
			distdir,
			gid = dir_gid,
			dirmode = dirmode,
			dirmask = modemask,
			filemode = filemode,
			filemask = modemask,
			onerror = util._raise_exc,
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
	ld, _ := myutil.listDir(distdir)
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
		temp_checksum := checksum.performMd5(temp_filename, false)
		//except FileNotFound:
		//continue
		if checksum == nil {
			checksum = checksum.performMd5(filename, false)
		}
		if string(checksum) == string(temp_checksum) {
			syscall.Unlink(filename)
			return temp_filename
		}
	}

	f, _ := os.CreateTemp(distdir, normal_basename+"._checksum_failure_.")
	temp_filename := f.Name()
	f.Close()
	util._movefile(filename, temp_filename, 0, nil, settings, nil)
	return temp_filename
}

// 1
func _check_digests(filename string, digests map[string]string, show_errors int) bool {
	verified_ok, reason0, reason1, reason2 := checksum.verifyAll(filename, digests, false, 0)
	if !verified_ok {
		if show_errors != 0 {
			util.WriteMsg(fmt.Sprintf("!!! Previously fetched"+
				" file: '%s'\n", filename), -1, nil)
			util.WriteMsg(fmt.Sprintf("!!! Reason: %s\n", reason0), -1, nil)
			util.WriteMsg(fmt.Sprintf("!!! Got:      %s\n"+
				"!!! Expected: %s\n", reason1, reason2), -1, nil)
		}
		return false
	}
	return true
}

// 1, nil
func _check_distfile(filename string, digests map[string]string, eout *output.eOutput, show_errors int, hash_filter *checksum.hashFilter) (bool, os.FileInfo) {
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
		digests = checksum.filterUnaccelaratedHashes(digests)
		if hash_filter != nil {
			digests = checksum.applyHashFilter(digests, hash_filter)
		}
		if _check_digests(filename, digests, show_errors) {
			eout.ebegin(fmt.Sprintf("%s %s ;-)", filepath.Base(filename), strings.Join(myutil.sortedmss(digests), " ")))
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
		f.cutoffs = append(f.cutoffs, myutil.toi(x))
	}
	return f
}

func (f *FilenameHashLayout) get_path(filename string) string {
	fnhash := string(checksum.checksumStr(filename, f.algo))
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
	if !checksum.getValidChecksumKeys()[args[1]] {
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
	util.readConfigs(cp, []string{f})
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
func (m *MirrorLayoutConfig) get_best_supported_layout(filename string) *FlatLayout {
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
	return NewFlatLayout()
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

	cache := map[string]struct {
		T  int64
		SS [][]string
	}{}
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

	ts, data := cache[mirror_url].T, cache[mirror_url].SS
	if ts >= time.Now().Unix()-86400 {
		mirror_conf.deserialize(data)
	} else {
		u, _ := url.Parse(mirror_url)
		tmpfile := fmt.Sprintf(".layout.conf.%s", u.Hostname())
		//try:
		if strings.HasPrefix(mirror_url, "/") {
			tmpfile = filepath.Join(mirror_url, "layout.conf")
			mirror_conf.read_from_file(tmpfile)
		} else if fetch(map[string]map[string]bool{tmpfile: {mirror_url + "/distfiles/layout.conf": true},
		},
			mysettings, 0, 0, ".locks", 1, 0, nil, true, true) != 0 {
			tmpfile = filepath.Join(mysettings.ValueDict["DISTDIR"], tmpfile)
			mirror_conf.read_from_file(tmpfile)
		} else {
			//raise IOError()
		}
		//except(ConfigParserError, IOError, UnicodeDecodeError):
		//pass
		//else:
		cache[mirror_url] = struct {
			T  int64
			SS [][]string
		}{time.Now().Unix(), mirror_conf.serialize()}
		if cache_path != "" {
			f := util.NewAtomic_ofstream(cache_path, os.O_WRONLY, true)
			json.NewEncoder(f).Encode(f)
			f.Close()
		}
	}

	path := mirror_conf.get_best_supported_layout(filename).get_path(filename)
	up, _ := url.Parse(mirror_url)
	if myutil.Ins([]string{"ftp", "http", "https"}, up.Scheme) {
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
	digests map[string]map[string]bool, allow_missing_digests, force bool, ) int {

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
	userfetch := *data.secpass >= 2 && features.Features["userfetch"]

	restrict_mirror := myutil.Ins(restrict, "mirror") || myutil.Ins(restrict, "nomirror")
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
		util.WriteMsg(fmt.Sprintf("!!! Variable PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"+
			" contains non-integer value: '%s'\n",
			mysettings.ValueDict["PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"]), -1, nil)
		util.WriteMsg(fmt.Sprintf("!!! Using PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS "+
			"default value: %s\n", checksum_failure_max_tries), -1, nil)
		v = checksum_failure_max_tries
	}
	if v < 1 {
		util.WriteMsg(fmt.Sprintf("!!! Variable PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"+
			" contains value less than 1: '%s'\n", v), -1, nil)
		util.WriteMsg(fmt.Sprintf("!!! Using PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS "+
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
			util.WriteMsg(fmt.Sprintf("!!! Variable PORTAGE_FETCH_RESUME_MIN_SIZE"+
				" contains an unrecognized format: '%s'\n",
				mysettings.ValueDict["PORTAGE_FETCH_RESUME_MIN_SIZE"]), -1, nil)
			util.WriteMsg(
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

	parallel_fetchonly := myutil.Inmss(mysettings.ValueDict, "PORTAGE_PARALLEL_FETCHONLY")
	if parallel_fetchonly {
		fetchonly = 1
	}

	check_config_instance(mysettings)

	custommirrors := util.grabDict(filepath.Join(mysettings.ValueDict["PORTAGE_CONFIGROOT"], _const.CustomMirrorsFile), false, false, true, true, false)

	if listonly != 0 || !features.Features["distlocks"] {
		use_locks = 0
	}

	distdir_writable := myutil.osAccess(mysettings.ValueDict["DISTDIR"], unix.W_OK)
	fetch_to_ro := 0
	if features.Features["skiprocheck"] {
		fetch_to_ro = 1
	}

	if !distdir_writable && fetch_to_ro != 0 {
		if use_locks != 0 {
			util.WriteMsg(output.colorize("BAD",
				"!!! For fetching to a read-only filesystem, "+
					"locking should be turned off.\n"), -1, nil)
			util.WriteMsg("!!! This can be done by adding -distlocks to "+
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

	hash_filter := checksum.NewHashFilter(mysettings.ValueDict["PORTAGE_CHECKSUM_FILTER"])
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
		if myutil.pathIsDir(x) {
			ro_distdirs = append(ro_distdirs, x)
		}
	}

	restrict_fetch := myutil.Ins(restrict, "fetch")
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

	filedict := map[string][]string{} //OrderedDict()
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
						get_mirror_url(vv, myfile.string, mysettings, mirror_cache))

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

					if !myutil.Inmsss(custommirrors, mirrorname) && !myutil.Inmsss(thirdpartymirrors, mirrorname) {
						util.WriteMsg(fmt.Sprintf("!!! No known mirror by the name: %s\n", mirrorname), 0, nil)
					}
				} else {
					util.WriteMsg("Invalid mirror definition in SRC_URI:\n", -1, nil)
					util.WriteMsg(fmt.Sprintf("  %s\n", myuri), -1, nil)
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
	}

	for _, uris := range primaryuri_dict {
		myutil.reversed(uris)
	}

	for myfile, uris := range thirdpartymirror_uris {
		if _, ok := primaryuri_dict[myfile]; !ok {
			primaryuri_dict[myfile] = []string{}
		}
		primaryuri_dict[myfile] = append(primaryuri_dict[myfile], uris...)
	}

	if myutil.Ins(restrict, "primaryuri") {
		for myfile, uris := range filedict {
			filedict[myfile] = primaryuri_dict[myfile] + uris
		}
	} else {
		for myfile := range filedict {
			filedict[myfile] += primaryuri_dict[myfile]
		}
	}

	can_fetch := true

	if listonly != 0 {
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

	if can_fetch && fetch_to_ro == 0 && !myutil.osAccess(mysettings.ValueDict["DISTDIR"], unix.W_OK) {
		util.WriteMsg(fmt.Sprintf("!!! No write access to '%s'\n", mysettings.ValueDict["DISTDIR"]), -1, nil)
		can_fetch = false
	}

	distdir_writable = can_fetch && fetch_to_ro == 0
	failed_files := map[string]bool{}
	restrict_fetch_msg := false
	valid_hashes := myutil.CopyMapSB(checksum.getValidChecksumKeys())
	delete(valid_hashes, "size")

	for myfile := range filedict {
		fetched := 0

		orig_digests := mydigests[myfile]

		if !(allow_missing_digests || listonly != 0) {
			verifiable_hash_types := map[string]bool{}
			for v := range orig_digests {
				if valid_hashes[v] {
					verifiable_hash_types[v] = true
				}
			}
			if len(verifiable_hash_types) == 0 {
				expected := strings.Join(myutil.sortedmsb(valid_hashes), " ")
				got := myutil.CopyMapSB(orig_digests)
				delete(got, "size")
				gots := strings.Join(myutil.sortedmsb(got), " ")
				reason := [3]string{
					"Insufficient data for checksum verification",
					gots,
					expected,
				}
				util.WriteMsg(fmt.Sprintf("!!! Fetched file: %s VERIFY FAILED!\n", myfile), -1, nil)
				util.WriteMsg(fmt.Sprintf("!!! Reason: %s\n", reason[0]), -1, nil)
				util.WriteMsg(fmt.Sprintf("!!! Got:      %s\n!!! Expected: %s\n", reason[1], reason[2]), -1, nil)

				if fetchonly != 0 {
					failed_files[myfile] = true
					continue
				} else {
					return 0
				}
			}
		}

		size := orig_digests.get("size")
		if size == 0 {
			delete(mydigests, myfile)
			orig_digests = map[string]bool{}
			size = None
		}
		pruned_digests := orig_digests
		if parallel_fetchonly {
			pruned_digests =
			{
			}
			if size != nil {
				pruned_digests["size"] = size
			}
		}

		myfile_path := filepath.Join(mysettings.ValueDict["DISTDIR"], myfile)
		download_path := myfile_path
		if fetch_to_ro == 0 {
			download_path = myfile_path + _download_suffix
		}
		has_space := true
		has_space_superuser := true
		var file_lock *LockFileS
		if listonly != 0 {
			util.WriteMsgStdout("\n", -1)
		} else {
			var vfs_stat *syscall.Statfs_t
			if size != nil {
				// statvfs
				err := syscall.Statfs(mysettings.ValueDict["DISTDIR"], vfs_stat)
				if err != nil {
					//except OSError as e:
					util.WriteMsgLevel(fmt.Sprintf("!!! statvfs('%s'): %s\n", mysettings.ValueDict["DISTDIR"], err),
						-1, 40)
					//del e
				}
			}

			if vfs_stat != nil {
				st, err := os.Stat(myfile_path)
				var mysize int64
				if err != nil {
					//except OSError as e:
					//if e.errno not in(errno.ENOENT, errno.ESTALE):
					//raise
					//del e
				} else {
					mysize = st.Size()
				}
				if (size - mysize + vfs_stat.Bsize) >= (
					vfs_stat.Bsize * int64(vfs_stat.Bavail)) {

					if (size - mysize + vfs_stat.Bsize) >= (
						vfs_stat.Bsize * int64(vfs_stat.Bfree)) {
						has_space_superuser = false
					}

					if !has_space_superuser {
						has_space = false
					} else if *data.secpass < 2 {
						has_space = false
					} else if userfetch {
						has_space = false
					}
				}
			}

			if distdir_writable && use_locks != 0 {
				flags := 0
				if fetchonly != 0 {
					flags = unix.O_NONBLOCK
				}

				file_lock, err = Lockfile(myfile_path, true, false, "", flags)
				if err != nil {
					//except TryAgain:
					util.WriteMsg(
						fmt.Sprintf(">>> File '%s' is already locked by "+
							"another fetcher. Continuing...\n", myfile), -1, nil)
					continue
				}
			}
		}
		cont := false
		retb := false
		retv := 0
		func() {
			defer func() {
				if use_locks != 0 && file_lock != nil {
					Unlockfile(file_lock)
					file_lock = nil
				}
			}()
			if listonly == 0 {
				eout := output.NewEOutput(false)
				eout.quiet = mysettings.ValueDict["PORTAGE_QUIET"] == "1"
				match, mystat := _check_distfile(
					myfile_path, pruned_digests, eout, 1, hash_filter)
				if match && !force {
					st, err := os.Stat(myfile_path)
					if distdir_writable && (err != nil || st.Mode()&os.ModeSymlink == os.ModeSymlink) {
						//try:
						util.apply_secpass_permissions(
							myfile_path, -1, *data.portage_gid, 0664, 02, mystat, true)
						//except PortageException as e:
						//if ! osAccess(myfile_path, unix.R_OK) {
						//	WriteMsg(
						//		fmt.Sprintf("!!! Failed to adjust permissions:"
						//	" %s\n", e),
						//		-1, nil)
						//}
						//del e
					}
					cont = true
					return
				}
				st, err := os.Stat(myfile_path)

				if distdir_writable && mystat != nil || (err != nil || st.Mode()&os.ModeSymlink == os.ModeSymlink) {
					if err := syscall.Unlink(myfile_path); err != nil {
						//except OSError as e:
						//if e.errno not in(errno.ENOENT, errno.ESTALE):
						//raise
					}
					mystat = nil
				}

				if mystat != nil {
					if mystat.IsDir() {
						util.WriteMsgLevel(
							fmt.Sprintf(
								"!!! Unable to fetch file since "+
									"a directory is in the way: \n"+
									"!!!   %s\n", myfile_path), 40, -1)
						retb = true
						retv = 0
						return
					}

					if distdir_writable && !force {
						temp_filename := _checksum_failure_temp_file(
							mysettings, mysettings.ValueDict["DISTDIR"], myfile,
						)
						util.WriteMsgStdout(
							fmt.Sprintf("Refetching... "+
								"File renamed to '%s'\n\n", temp_filename), -1)
					}
				}

				mystat, err = os.Stat(download_path)
				if err != nil {
					//except OSError as e:
					//if e.errno not in(errno.ENOENT, errno.ESTALE):
					//raise
					mystat = nil
				}

				if mystat != nil {
					if mystat.Size() == 0 {
						if distdir_writable {
							if err := syscall.Unlink(download_path); err != nil {
								//except OSError:
								//pass
							}
						}
					} else if distdir_writable && size != nil {
						if mystat.Size() < fetch_resume_size && mystat.Size() < size {
							util.WriteMsg(
								fmt.Sprintf(
									">>> Renaming distfile with size "+
										"%d (smaller than "+
										"PORTAGE_FETCH_RESU"+
										"ME_MIN_SIZE)\n", mystat.Size()), 0, nil)
							temp_filename := _checksum_failure_temp_file(
								mysettings,
								mysettings.ValueDict["DISTDIR"],
								filepath.Base(download_path),
							)
							util.WriteMsgStdout(fmt.Sprintf("Refetching... "+
								"File renamed to '%s'\n\n", temp_filename), -1)
						} else if mystat.Size() >= size {
							temp_filename := _checksum_failure_temp_file(
								mysettings, mysettings.ValueDict["DISTDIR"],
								filepath.Base(download_path),
							)
							util.WriteMsgStdout(fmt.Sprintf("Refetching... "+
								"File renamed to '%s'\n\n", temp_filename), -1)
						}
					}
				}

				if distdir_writable && len(ro_distdirs) > 0 {
					var readonly_file = ""
					for _, x := range ro_distdirs {
						filename := get_mirror_url(x, myfile, mysettings, "")
						match, mystat = _check_distfile(
							filename, pruned_digests, eout, 1, hash_filter)
						if match {
							readonly_file = filename
							break
						}
					}
					if readonly_file != "" {
						if err := syscall.Unlink(myfile_path); err != nil {
							//except OSError as e:
							//if e.errno not in(errno.ENOENT, errno.ESTALE):
							//raise
							//del e
						}
						syscall.Symlink(readonly_file, myfile_path)
						cont = true
						return
					}
				}

				if !has_space {
					util.WriteMsg(
						fmt.Sprintf("!!! Insufficient space to store %s in %s\n",
							myfile, mysettings.ValueDict["DISTDIR"]),
						-1, nil)

					if has_space_superuser {
						util.WriteMsg("!!! Insufficient privileges to use "+
							"remaining space.\n", -1, nil)
						if userfetch {
							util.WriteMsg(`!!! You may set FEATURES="-userfetch"`+
								" in /etc/portage/make.conf in order to fetch with\n"+
								"!!! superuser privileges.\n", -1, nil)
						}
					}
				}

				if len(fsmirrors) > 0 && !myutil.pathExists(myfile_path) && has_space {
					for _, mydir := range fsmirrors {
						mirror_file := get_mirror_url(mydir, myfile, mysettings, "")
						if err := util.copyfile(mirror_file, download_path); err != nil {
							//except(IOError, OSError) as e:
							//if e.errno not in(errno.ENOENT, errno.ESTALE):
							//raise
							//del e
						}
						util.WriteMsg(fmt.Sprintf("Local mirror has file: %s\n", myfile), 0, nil)
						break
					}
				}

				mystat, err = os.Stat(download_path)
				if err != nil {
					//except OSError as e:
					//if e.errno not in(errno.ENOENT, errno.ESTALE):
					//raise
					//del e
				} else {
					mystat, err = os.Stat(download_path)
					if err == nil && mystat.Mode()&os.ModeSymlink == os.ModeSymlink {

						if err := util.apply_secpass_permissions(
							download_path, -1,
							*data.portage_gid,
							0664, 02, mystat, true); err != nil {
							//except PortageException as e:
							if !myutil.osAccess(download_path, unix.R_OK) {
								util.WriteMsg(
									fmt.Sprintf("!!! Failed to adjust permissions:"+
										" %s\n", err), -1, nil)
							}
						}
					}

					if mystat.Size() == 0 {
						if distdir_writable {
							if err := syscall.Unlink(download_path); err != nil {
								//except EnvironmentError:
								//pass
							}
						}
					} else if len(orig_digests) == 0 {
						if !force {
							fetched = 1
						}
					} else {
						if mydigests[myfile].get("size") != nil &&
							mystat.Size() < mydigests[myfile]["size"] && !restrict_fetch {
							fetched = 1
						} else if parallel_fetchonly &&
							mystat.Size() == mydigests[myfile]["size"] {
							eout = output.NewEOutput(false)
							eout.quiet = mysettings.ValueDict["PORTAGE_QUIET"] == "1"
							eout.ebegin(fmt.Sprintf("%s size ;-)", myfile))
							eout.eend(0, "")
							cont = true
							return
						} else {
							digests = checksum.filterUnaccelaratedHashes(mydigests[myfile])
							if hash_filter != nil {
								digests = checksum.applyHashFilter(digests, hash_filter)
							}
							verified_ok, r0, r1, r2 := checksum.verifyAll(download_path, digests, false, 0)
							if !verified_ok {
								util.WriteMsg(
									fmt.Sprintf("!!! Previously fetched file: '%s'\n", myfile), -1, nil)
								util.WriteMsg(
									fmt.Sprintf("!!! Reason: %s\n", r0), -1, nil)
								util.WriteMsg(
									fmt.Sprintf("!!! Got:      %s\n!!! Expected: %s\n", r1, r2), -1, nil)
								if r0 == "Insufficient data for checksum verification" {
									retb = true
									retv = 0
									return
								}
								if distdir_writable {
									temp_filename := _checksum_failure_temp_file(
										mysettings,
										mysettings.ValueDict["DISTDIR"],
										filepath.Base(download_path),
									)
									util.WriteMsgStdout(
										fmt.Sprintf("Refetching... File renamed to '%s'\n\n", temp_filename), -1)
								}
							} else {
								if fetch_to_ro == 0 {
									util._movefile(
										download_path,
										myfile_path, 0, nil,
										mysettings, nil)
								}
								eout = output.NewEOutput(false)
								eout.quiet = mysettings.ValueDict["PORTAGE_QUIET"] == "1"

								if len(digests) > 0 {
									ds := []string{}
									for k := range digests {
										ds = append(ds, k)
									}
									sort.Strings(ds)
									eout.ebegin(fmt.Sprintf("%s %s ;-)", myfile, strings.Join(ds, " ")))
									eout.eend(0, "")
								}
								cont = true
								return
							}
						}
					}
				}
			}

			uri_list := []string{}
			copy(uri_list, filedict[myfile][:])
			myutil.ReverseSlice(uri_list)
			checksum_failure_count := 0
			tried_locations := map[string]bool{}
			for len(uri_list) > 0 {
				loc := uri_list[len(uri_list)-1]
				uri_list = uri_list[:len(uri_list)-1]
				//if isinstance(loc, functools.partial) {
				//	loc = loc()
				//}
				if tried_locations[loc] {
					continue
				}
				tried_locations[loc] = true
				if listonly != 0 {
					util.WriteMsgStdout(loc+" ", -1)
					continue
				}
				protocol := loc[0:strings.Index(loc, "://")]

				global_config_path := _const.GlobalConfigPath
				if len(_const.EPREFIX) > 0 {
					global_config_path = filepath.Join(
						_const.EPREFIX, strings.TrimLeft(_const.GlobalConfigPath, string(filepath.Separator)))
					)
				}

				missing_file_param := false
				fetchcommand_var := "FETCHCOMMAND_" + strings.ToUpper(protocol)
				fetchcommand, ok := mysettings.ValueDict[fetchcommand_var]
				if !ok {
					fetchcommand_var = "FETCHCOMMAND"
					fetchcommand, ok = mysettings.ValueDict[fetchcommand_var]
					if !ok {
						util.WriteMsgLevel(
							fmt.Sprintf("!!! %s is unset. It should "+
								"have been defined in\n!!! %s/make.globals.\n",
								fetchcommand_var, global_config_path),
							40, -1)
						retb = true
						retv = 0
						return
					}
				}
				if !strings.Contains(fetchcommand, "${FILE}") {
					util.WriteMsgLevel(fmt.Sprintf(
						"!!! %s does not contain the required ${FILE}"+
							" parameter.\n", fetchcommand_var), 40, -1)
					missing_file_param = true
				}

				resumecommand_var := "RESUMECOMMAND_" + strings.ToUpper(protocol)
				resumecommand, ok := mysettings.ValueDict[resumecommand_var]
				if !ok {
					resumecommand_var = "RESUMECOMMAND"
					resumecommand, ok = mysettings.ValueDict[resumecommand_var]
					if !ok {
						util.WriteMsgLevel(fmt.Sprintf(
							"!!! %s is unset. It should "+
								"have been defined in\n!!! %s/make.globals.\n",
							resumecommand_var, global_config_path),
							40, -1)
						retb = true
						retv = 0
						return
					}
				}
				if !strings.Contains(resumecommand, "${FILE}") {
					util.WriteMsgLevel(fmt.Sprintf(

						"!!! %s does not contain the required ${FILE}"+
							" parameter.\n", resumecommand_var),
						40, -1)
					missing_file_param = true
				}

				if missing_file_param {
					util.WriteMsgLevel(
						"!!! Refer to the make.conf(5) man page for "+
							"information about how to\n!!! correctly specify "+
							"FETCHCOMMAND and RESUMECOMMAND.\n", 40, -1)
					if myfile != filepath.Base(loc) {
						retb = true
						retv = 0
						return
					}
				}

				if !can_fetch {
					if fetched != 2 {
						st, err := os.Stat(download_path)
						var mysize int64
						if err != nil {
							//except OSError as e:
							//if e.errno not in(errno.ENOENT, errno.ESTALE):
							//raise
							//del e
						} else {
							mysize = st.Size()
						}

						if mysize == 0 {
							util.WriteMsg(
								fmt.Sprintf("!!! File %s isn't fetched but unable to get it.\n"), myfile),
								-1, nil                    )
						} else if size == nil || size > mysize {
							util.WriteMsg(
								fmt.Sprintf(
									"!!! File %s isn't fully fetched, but unable to complete it\n",, myfile),
								-1, nil)
						} else {
							util.WriteMsg(fmt.Sprintf("!!! File %s is incorrect size, "+
								"but unable to retry.\n",
								myfile), -1, nil)
						}
						retb = true
						retv = 0
						return
					}
					continue
				}

				if fetched != 2 && has_space {
					if fetched == 1 {
						mystat, err := os.Stat(download_path)
						if err != nil {
							//except OSError as e:
							//if e.errno not in(errno.ENOENT, errno.ESTALE):
							//raise
							//del e
							fetched = 0
						} else {
							if distdir_writable && mystat.Size() < fetch_resume_size {
								util.WriteMsg(
									fmt.Sprintf(
										">>> Deleting distfile with size "+
											"%d (smaller than "+
											"PORTAGE_FETCH_RESU"+
											"ME_MIN_SIZE)\n", mystat.Size()), -1, nil)
								if err := syscall.Unlink(download_path); err != nil {
									//except OSError as e:
									//if e.errno not in(errno.ENOENT, errno.ESTALE):
									//raise
									//del e
								}
								fetched = 0
							}
						}
					}
					locfetch := fetchcommand
					command_var := fetchcommand_var
					if fetched == 1 {
						util.WriteMsg(">>> Resuming download...\n", -1, nil)
						locfetch = resumecommand
						command_var = resumecommand_var
					}
					util.WriteMsgStdout(fmt.Sprintf(">>> Downloading '%s'\n", _hide_url_passwd(loc)), 0)
					variables :=
					{
						"URI": loc, "FILE": filepath.Base(download_path)
					}

					//try:
					sss := []string{}

					for k, v := range mydigests[myfile] {
						if k != "size" {
							sss = append(sss, fmt.Sprintf("%s:%s", strings.ToLower(k), v))
						}
					}
					variables["DIGESTS"] = strings.Join(sss, " ")
					//except KeyError:
					//pass

					for _, k := range []string{"DISTDIR", "PORTAGE_SSH_OPTS"} {
						v, ok := mysettings.ValueDict[k]
						if ok {
							variables[k] = v
						}
					}

					myfetch1 := util.varExpand(locfetch, variables, nil)
					myfetch, _ := shlex.Split(strings.NewReader(myfetch1), false, true)

					myret := -1
					//try:

					myret = _spawn_fetch(mysettings, myfetch)

					//finally:
					//try:
					util.apply_secpass_permissions(
						download_path, -1, *data.portage_gid, 0664, 02, nil, true)
					//except FileNotFound:
					//pass
					//except PortageException as e:
					//if not osAccess(download_path, os.R_OK):
					//WriteMsg(
					//	_("!!! Failed to adjust permissions:"
					//" %s\n")
					//% str(e),
					//	-1, nil
					//)
					//del e

					mystat, err := os.Lstat(download_path)
					if err != nil {
						//except EnvironmentError:
						//pass
					} else {
						if mystat.Size() == 0 || (mystat.Mode()&os.ModeSymlink == os.ModeSymlink && !myutil.pathExists(download_path)) {
							syscall.Unlink(download_path)
							fetched = 0
							continue
						}
					}

					if mydigests != nil && myutil.Inmssb(mydigests, myfile) {
						mystat, err := os.Stat(download_path)
						if err != nil {
							//except OSError as e:
							//if e.errno not in(errno.ENOENT, errno.ESTALE):
							//raise
							//del e
							fetched = 0
						} else {

							if mystat.IsDir() {
								util.WriteMsgLevel(
									fmt.Sprintf("!!! The command specified in the "+
										"%s variable appears to have\n!!! "+
										"created a directory instead of a "+
										"normal file.\n", command_var), 40, -1)
								util.WriteMsgLevel(
									"!!! Refer to the make.conf(5) "+
										"man page for information about how "+
										"to\n!!! correctly specify "+
										"FETCHCOMMAND and RESUMECOMMAND.\n", 40, -1)
								retb = true
								retv = 0
								return
							}

							if myret != 0 && mystat.Size() < mydigests[myfile]["size"] {
								if (mystat.Size() < 100000) && (len(myfile) > 4) && !((myfile[-5:] == ".html") || (myfile[-4:] == ".htm"))){
									html404 := regexp.MustCompile(
										"<title>.*(not found|404).*</title>",
										//re.I|re.M,
									)
									f, err := os.ReadFile(download_path)
									if err == nil {
										if html404.FindString(string(f)) != "" {
											if err := syscall.Unlink(download_path); err == nil {
												util.WriteMsg(">>> Deleting invalid distfile. (Improper 404 redirect from server.)\n",, 0, nil)

												fetched = 0
												continue
											} else {
												//except(IOError, OSError):
												//pass
											}
										}
									}
								}
								fetched = 1
								continue
							}
							digests = checksum.filterUnaccelaratedHashes(mydigests[myfile])
							if hash_filter != nil {
								digests = checksum.applyHashFilter(digests, hash_filter)
							}
							verified_ok, r0, r1, r2 := checksum.verifyAll(download_path, digests)
							if !verified_ok {
								util.WriteMsg(fmt.Sprintf("!!! Fetched file: %s VERIFY FAILED!\n", myfile), -1, nil)
								util.WriteMsg(fmt.Sprintf("!!! Reason: %s\n", r0), -1, nil)
								util.WriteMsg(fmt.Sprintf("!!! Got:      %s\n!!! Expected: %s\n", r1, r2), -1, nil)
								if r0 == "Insufficient data for checksum verification" {
									retb = true
									retv = 0
									return
								}
								if distdir_writable {
									temp_filename := _checksum_failure_temp_file(
										mysettings,
										mysettings.ValueDict["DISTDIR"],
										filepath.Base(download_path),
									)
									util.WriteMsgStdout(fmt.Sprintf(
										"Refetching... "+
											"File renamed to '%s'\n\n",
										temp_filename), -1)
								}
								fetched = 0
								checksum_failure_count += 1
								if checksum_failure_count == checksum_failure_primaryuri {
									primaryuris := primaryuri_dict[myfile]
									if len(primaryuris) > 0 {
										uri_list = append(uri_list, myutil.reversed(primaryuris)...)
									}
								}
								if checksum_failure_count >= checksum_failure_max_tries {
									break
								}
							} else {
								if fetch_to_ro == 0 {
									util._movefile(download_path, myfile_path, 0, nil, mysettings, nil)
								}
								eout := output.NewEOutput(false)
								eout.quiet = mysettings.ValueDict["PORTAGE_QUIET"] == "1"

								if len(digests) > 0 {
									eout.ebegin(fmt.Sprintf("%s %s ;-)", myfile, strings.Join(myutil.sortedmsb(digests), " ")))
									eout.eend(0, "")
								}
								fetched = 2
								break
							}
						}
					} else {
						if myret == 0 {
							if fetch_to_ro == 0 {
								util._movefile(download_path, myfile_path, 0, nil, mysettings, nil)
								fetched = 2
								break
							}
						} else if mydigests != nil {
							util.WriteMsg(
								"No digest file available and download failed.\n\n",
								-1, nil)
						}
					}
				}
			}
		}()
		if retb {
			return retv
		}
		if cont {
			continue
		}

		if listonly != 0 {
			util.WriteMsgStdout("\n", -1)
		}
		if fetched != 2 {
			if restrict_fetch && !restrict_fetch_msg {
				restrict_fetch_msg = true
				msg := fmt.Sprintf(
					"\n!!! %s/%s"+
						" has fetch restriction turned on.\n"+
						"!!! This probably means that this "+
						"ebuild's files must be downloaded\n"+
						"!!! manually.  See the comments in"+
						" the ebuild for more information.\n\n",
					mysettings.ValueDict["CATEGORY"], mysettings.ValueDict["PF"])
				util.WriteMsgLevel(msg, 40, -1)
			} else if restrict_fetch {
				//pass
			} else if listonly != 0 {
				//pass
			} else if len(filedict[myfile]) == 0 {
				util.WriteMsg(
					fmt.Sprintf("Warning: No mirrors available for file"+" '%s'\n", myfile), -1, nil)
			} else {
				util.WriteMsg(
					fmt.Sprintf("!!! Couldn't download '%s'. Aborting.\n", myfile), -1, nil)
			}

			if listonly != 0 {
				failed_files[myfile] = true
				continue
			} else if fetchonly != 0 {
				failed_files[myfile] = true
				continue
			}
			return 0
		}
	}
	if len(failed_files) != 0 {
		return 0
	}
	return 1
}
