package atom

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const _download_suffix = ".__download__"

var _userpriv_spawn_kwargs = struct{
	uid *int
	gid *int32
	umask int
	groups []int
}{uid: portage_uid, gid: portage_gid, umask:0o02, groups:userpriv_groups}


func _hide_url_passwd(url string) string {
	r1 := regexp.MustCompile("//([^:\\s]+):[^@\\s]+@")
	return r1.ReplaceAllString(url,"//\\1:*password*@")
}


func _want_userfetch(settings *Config)bool {
	return settings.Features.Features["userfetch"] && *secpass >= 2 && os.Getuid() == 0
}


func _drop_privs_userfetch(settings *Config) {
try:
	_ensure_distdir(settings, settings.ValueDict["DISTDIR"])
	except
PortageException:
	if ! pathIsDir(settings.ValueDict["DISTDIR"]) {
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
if logname is not None:
env["LOGNAME"] = logname
try:
rval = spawn_func(args, env= env, **kwargs)
finally:
if phase_backup is None:
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
	if Inmss(settings.ValueDict,"FAKED_MODE") {
		dir_gid = 0
	}

	userfetch := *secpass >= 2&& settings.Features.Features["userfetch"]
	userpriv := *secpass >= 2&&settings.Features.Features["userpriv"]
	write_test_file := filepath.Join(distdir, ".__portage_test_write__")

	st, _:= os.Stat(distdir)

	if st != nil && st.IsDir() {
		if !(userfetch || userpriv) {
			return
		}
		if _userpriv_test_write_file(settings, write_test_file) != 0 {
			return
		}
	}

	delete(_userpriv_test_write_file_cache, write_test_file)
	if ensureDirs(distdir, 0-1, uint32(dir_gid), dirmode, mask , nil, true) {
		if st == nil {
			return
		}
		WriteMsg(fmt.Sprintf("Adjusting permissions recursively: '%s'\n", distdir), -1, nil)
		if ! apply_recursive_permissions(
			distdir,
			gid = dir_gid,
			dirmode = dirmode,
			dirmask=modemask,
			filemode = filemode,
			filemask=modemask,
			onerror = _raise_exc,
	){
			raise
			OperationNotPermitted(
				_("Failed to apply recursive permissions for the portage group.")
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
func _check_distfile(filename string, digests map[string]string, eout*eOutput, show_errors int, hash_filter *hashFilter) (bool, os.FileInfo) {
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
func NewDistfileName(digests map[string]string) *DistfileName{
	d:=&DistfileName{}
	d.digests = digests
	if d.digests == nil {
		d.digests = map[string]string{}
	}
	return d
}

func (d*DistfileName) digests_equal(other DistfileName)bool {
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

func (f *FlatLayout) get_filenames( distdir string) []string {
	//os.walk(distdir, onerror = _raise_exc):
	ffs := []string{}
	filepath.Walk(distdir, func(path string, info fs.FileInfo, err error) error {
		ffs =append(ffs, path)
		return err
	})
	return ffs
}

// @staticmethod
func (f *FlatLayout) verify_args(args []string)bool {
	return len(args) == 1
}


class FilenameHashLayout:
def __init__(self, algo, cutoffs):
self.algo = algo
self.cutoffs = [int(x) for x in cutoffs.split(":")]

def get_path(self, filename):
fnhash = checksum_str(filename.encode("utf8"), self.algo)
ret = ""
for c in self.cutoffs:
assert c % 4 == 0
c = c // 4
ret += fnhash[:c] + "/"
fnhash = fnhash[c:]
return ret + filename

def get_filenames(self, distdir):
pattern = ""
for c in self.cutoffs:
assert c % 4 == 0
c = c // 4
pattern += c * "[0-9a-f]" + "/"
pattern += "*"
for x in glob.iglob(
portage._unicode_encode(os.path.join(distdir, pattern), errors="strict")
):
try:
yield portage._unicode_decode(x, errors="strict").rsplit("/", 1)[1]
except UnicodeDecodeError:
pass

@staticmethod
def verify_args(args):
if len(args) != 3:
return False
if args[1] not in get_valid_checksum_keys():
return False
for c in args[2].split(":"):
try:
c = int(c)
except ValueError:
break
else:
if c % 4 != 0:
break
else:
return True
return False


class ContentHashLayout(FilenameHashLayout):

def get_path(self, filename):
fnhash = remaining = filename.digests[self.algo]
ret = ""
for c in self.cutoffs:
assert c % 4 == 0
c = c // 4
ret += remaining[:c] + "/"
remaining = remaining[c:]
return ret + fnhash

def get_filenames(self, distdir):
for filename in super(ContentHashLayout, self).get_filenames(distdir):
yield DistfileName(filename, digests=dict([(self.algo, filename)]))

@staticmethod
def verify_args(args, filename=None):
if len(args) != 3:
return False
if filename is None:
supported_algos = get_valid_checksum_keys()
else:
supported_algos = filename.digests
algo = args[1].upper()
if algo not in supported_algos:
return False
return FilenameHashLayout.verify_args(args)


class MirrorLayoutConfig:

def __init__(self):
self.structure = ()

def read_from_file(self, f):
cp = SafeConfigParser()
read_configs(cp, [f])
vals = []
for i in itertools.count():
try:
vals.append(tuple(cp.get("structure", "%d" % i).split()))
except ConfigParserError:
break
self.structure = tuple(vals)

def serialize(self):
return self.structure

def deserialize(self, data):
self.structure = data

@staticmethod
def validate_structure(val, filename=None):
if val[0] == "flat":
return FlatLayout.verify_args(val)
elif val[0] == "filename-hash":
return FilenameHashLayout.verify_args(val)
elif val[0] == "content-hash":
return ContentHashLayout.verify_args(val, filename=filename)
return False

def get_best_supported_layout(self, filename=None):
for val in self.structure:
if self.validate_structure(val, filename=filename):
if val[0] == "flat":
return FlatLayout(*val[1:])
elif val[0] == "filename-hash":
return FilenameHashLayout(*val[1:])
elif val[0] == "content-hash":
return ContentHashLayout(*val[1:])
return FlatLayout()

def get_all_layouts(self):
ret = []
for val in self.structure:
if not self.validate_structure(val):
raise ValueError("Unsupported structure: {}".format(val))
if val[0] == "flat":
ret.append(FlatLayout(*val[1:]))
elif val[0] == "filename-hash":
ret.append(FilenameHashLayout(*val[1:]))
elif val[0] == "content-hash":
ret.append(ContentHashLayout(*val[1:]))
if not ret:
ret.append(FlatLayout())
return ret


def get_mirror_url(mirror_url, filename, mysettings, cache_path=None):

mirror_conf = MirrorLayoutConfig()

cache = {}
if cache_path is not None:
try:
with open(cache_path, "r") as f:
cache = json.load(f)
except (IOError, ValueError):
pass

ts, data = cache.get(mirror_url, (0, None))
if ts >= time.time() - 86400:
mirror_conf.deserialize(data)
else:
tmpfile = ".layout.conf.%s" % urlparse(mirror_url).hostname
try:
if mirror_url[:1] == "/":
tmpfile = os.path.join(mirror_url, "layout.conf")
mirror_conf.read_from_file(tmpfile)
elif fetch(
{tmpfile: (mirror_url + "/distfiles/layout.conf",)},
mysettings,
force=1,
try_mirrors=0,
):
tmpfile = os.path.join(mysettings["DISTDIR"], tmpfile)
mirror_conf.read_from_file(tmpfile)
else:
raise IOError()
except (ConfigParserError, IOError, UnicodeDecodeError):
pass
else:
cache[mirror_url] = (time.time(), mirror_conf.serialize())
if cache_path is not None:
f = atomic_ofstream(cache_path, "w")
json.dump(cache, f)
f.close()

path = mirror_conf.get_best_supported_layout(filename=filename).get_path(filename)
if urlparse(mirror_url).scheme in ("ftp", "http", "https"):
path = urlquote(path)
if mirror_url[:1] == "/":
return os.path.join(mirror_url, path)
else:
return mirror_url + "/distfiles/" + path


def fetch(
myuris,
mysettings,
listonly=0,
fetchonly=0,
locks_in_subdir=".locks",
use_locks=1,
try_mirrors=1,
digests=None,
allow_missing_digests=True,
force=False,
):

if force and digests:
raise PortageException(
_("fetch: force=True is not allowed when digests are provided")
)

if not myuris:
return 1

features = mysettings.features
restrict = mysettings.get("PORTAGE_RESTRICT", "").split()
userfetch = portage.data.secpass >= 2 and "userfetch" in features

restrict_mirror = "mirror" in restrict or "nomirror" in restrict
if restrict_mirror:
if ("mirror" in features) and ("lmirror" not in features):
print(
_(
'>>> "mirror" mode desired and "mirror" restriction found; skipping fetch.'
)
)
return 1

checksum_failure_max_tries = 5
v = checksum_failure_max_tries
try:
v = int(
mysettings.get(
"PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS", checksum_failure_max_tries
)
)
except (ValueError, OverflowError):
writemsg(
_(
"!!! Variable PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"
" contains non-integer value: '%s'\n"
)
% mysettings["PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"],
noiselevel=-1,
)
writemsg(
_("!!! Using PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS " "default value: %s\n")
% checksum_failure_max_tries,
noiselevel=-1,
)
v = checksum_failure_max_tries
if v < 1:
writemsg(
_(
"!!! Variable PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS"
" contains value less than 1: '%s'\n"
)
% v,
noiselevel=-1,
)
writemsg(
_("!!! Using PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS " "default value: %s\n")
% checksum_failure_max_tries,
noiselevel=-1,
)
v = checksum_failure_max_tries
checksum_failure_max_tries = v
del v

fetch_resume_size_default = "350K"
fetch_resume_size = mysettings.get("PORTAGE_FETCH_RESUME_MIN_SIZE")
if fetch_resume_size is not None:
fetch_resume_size = "".join(fetch_resume_size.split())
if not fetch_resume_size:
fetch_resume_size = fetch_resume_size_default
match = _fetch_resume_size_re.match(fetch_resume_size)
if match is None or (match.group(2).upper() not in _size_suffix_map):
writemsg(
_(
"!!! Variable PORTAGE_FETCH_RESUME_MIN_SIZE"
" contains an unrecognized format: '%s'\n"
)
% mysettings["PORTAGE_FETCH_RESUME_MIN_SIZE"],
noiselevel=-1,
)
writemsg(
_("!!! Using PORTAGE_FETCH_RESUME_MIN_SIZE " "default value: %s\n")
% fetch_resume_size_default,
noiselevel=-1,
)
fetch_resume_size = None
if fetch_resume_size is None:
fetch_resume_size = fetch_resume_size_default
match = _fetch_resume_size_re.match(fetch_resume_size)
fetch_resume_size = (
int(match.group(1)) * 2 ** _size_suffix_map[match.group(2).upper()]
)

checksum_failure_primaryuri = 2
thirdpartymirrors = mysettings.thirdpartymirrors()

parallel_fetchonly = "PORTAGE_PARALLEL_FETCHONLY" in mysettings
if parallel_fetchonly:
fetchonly = 1

check_config_instance(mysettings)

custommirrors = grabdict(
os.path.join(mysettings["PORTAGE_CONFIGROOT"], CUSTOM_MIRRORS_FILE), recursive=1
)

if listonly or ("distlocks" not in features):
use_locks = 0

distdir_writable = os.access(mysettings["DISTDIR"], os.W_OK)
fetch_to_ro = 0
if "skiprocheck" in features:
fetch_to_ro = 1

if not distdir_writable and fetch_to_ro:
if use_locks:
writemsg(
colorize(
"BAD",
_(
"!!! For fetching to a read-only filesystem, "
"locking should be turned off.\n"
),
),
noiselevel=-1,
)
writemsg(
_(
"!!! This can be done by adding -distlocks to "
"FEATURES in /etc/portage/make.conf\n"
),
noiselevel=-1,
)

local_mirrors = []
public_mirrors = []
fsmirrors = []
if try_mirrors:
for x in custommirrors.get("local", []):
if x.startswith("/"):
fsmirrors.append(x)
else:
local_mirrors.append(x)
for x in mysettings["GENTOO_MIRRORS"].split():
if not x:
continue
if x.startswith("/"):
fsmirrors.append(x.rstrip("/"))
else:
public_mirrors.append(x.rstrip("/"))

hash_filter = _hash_filter(mysettings.get("PORTAGE_CHECKSUM_FILTER", ""))
if hash_filter.transparent:
hash_filter = None
skip_manifest = mysettings.get("EBUILD_SKIP_MANIFEST") == "1"
if skip_manifest:
allow_missing_digests = True
pkgdir = mysettings.get("O")
if digests is None and not (pkgdir is None or skip_manifest):
mydigests = (
mysettings.repositories.get_repo_for_location(
os.path.dirname(os.path.dirname(pkgdir))
)
.load_manifest(pkgdir, mysettings["DISTDIR"])
.getTypeDigests("DIST")
)
elif digests is None or skip_manifest:
# no digests because fetch was not called for a specific package
mydigests = {}
else:
mydigests = digests

ro_distdirs = [
x
for x in shlex_split(mysettings.get("PORTAGE_RO_DISTDIRS", ""))
if os.path.isdir(x)
]

restrict_fetch = "fetch" in restrict
force_mirror = "force-mirror" in features and not restrict_mirror

file_uri_tuples = []
if hasattr(myuris, "items"):
for myfile, uri_set in myuris.items():
for myuri in uri_set:
file_uri_tuples.append(
(DistfileName(myfile, digests=mydigests.get(myfile)), myuri)
)
if not uri_set:
file_uri_tuples.append(
(DistfileName(myfile, digests=mydigests.get(myfile)), None)
)
else:
for myuri in myuris:
if urlparse(myuri).scheme:
file_uri_tuples.append(
(
DistfileName(
os.path.basename(myuri),
digests=mydigests.get(os.path.basename(myuri)),
),
myuri,
)
)
else:
file_uri_tuples.append(
(
DistfileName(
os.path.basename(myuri),
digests=mydigests.get(os.path.basename(myuri)),
),
None,
)
)

filedict = OrderedDict()
primaryuri_dict = {}
thirdpartymirror_uris = {}
for myfile, myuri in file_uri_tuples:
override_mirror = (myuri or "").startswith("mirror+")
override_fetch = override_mirror or (myuri or "").startswith("fetch+")
if override_fetch:
myuri = myuri.partition("+")[2]

if myfile not in filedict:
filedict[myfile] = []
if distdir_writable:
mirror_cache = os.path.join(mysettings["DISTDIR"], ".mirror-cache.json")
else:
mirror_cache = None

file_restrict_mirror = (
restrict_fetch or restrict_mirror
) and not override_mirror

location_lists = [local_mirrors]
if not file_restrict_mirror:
location_lists.append(public_mirrors)

for l in itertools.chain(*location_lists):
filedict[myfile].append(
functools.partial(
get_mirror_url, l, myfile, mysettings, mirror_cache
)
)
if myuri is None:
continue
if myuri[:9] == "mirror://":
eidx = myuri.find("/", 9)
if eidx != -1:
mirrorname = myuri[9:eidx]
path = myuri[eidx + 1 :]

if mirrorname in custommirrors:
for cmirr in custommirrors[mirrorname]:
filedict[myfile].append(cmirr.rstrip("/") + "/" + path)

if mirrorname in thirdpartymirrors:
uris = [
locmirr.rstrip("/") + "/" + path
for locmirr in thirdpartymirrors[mirrorname]
]
random.shuffle(uris)
filedict[myfile].extend(uris)
thirdpartymirror_uris.setdefault(myfile, []).extend(uris)

if (
mirrorname not in custommirrors
and mirrorname not in thirdpartymirrors
):
writemsg(_("!!! No known mirror by the name: %s\n") % (mirrorname))
else:
writemsg(_("Invalid mirror definition in SRC_URI:\n"), noiselevel=-1)
writemsg("  %s\n" % (myuri), noiselevel=-1)
else:
if (restrict_fetch and not override_fetch) or force_mirror:
continue
primaryuris = primaryuri_dict.get(myfile)
if primaryuris is None:
primaryuris = []
primaryuri_dict[myfile] = primaryuris
primaryuris.append(myuri)

for uris in primaryuri_dict.values():
uris.reverse()

for myfile, uris in thirdpartymirror_uris.items():
primaryuri_dict.setdefault(myfile, []).extend(uris)

if "primaryuri" in restrict:
for myfile, uris in filedict.items():
filedict[myfile] = primaryuri_dict.get(myfile, []) + uris
else:
for myfile in filedict:
filedict[myfile] += primaryuri_dict.get(myfile, [])

can_fetch = True

if listonly:
can_fetch = False

if can_fetch and not fetch_to_ro:
try:
_ensure_distdir(mysettings, mysettings["DISTDIR"])
except PortageException as e:
if not os.path.isdir(mysettings["DISTDIR"]):
writemsg("!!! %s\n" % str(e), noiselevel=-1)
writemsg(
_("!!! Directory Not Found: DISTDIR='%s'\n")
% mysettings["DISTDIR"],
noiselevel=-1,
)
writemsg(_("!!! Fetching will fail!\n"), noiselevel=-1)

if can_fetch and not fetch_to_ro and not os.access(mysettings["DISTDIR"], os.W_OK):
writemsg(
_("!!! No write access to '%s'\n") % mysettings["DISTDIR"], noiselevel=-1
)
can_fetch = False

distdir_writable = can_fetch and not fetch_to_ro
failed_files = set()
restrict_fetch_msg = False
valid_hashes = set(get_valid_checksum_keys())
valid_hashes.discard("size")

for myfile in filedict:
fetched = 0

orig_digests = mydigests.get(myfile, {})

if not (allow_missing_digests or listonly):
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
writemsg(
_("!!! Fetched file: %s VERIFY FAILED!\n") % myfile, noiselevel=-1
)
writemsg(_("!!! Reason: %s\n") % reason[0], noiselevel=-1)
writemsg(
_("!!! Got:      %s\n!!! Expected: %s\n") % (reason[1], reason[2]),
noiselevel=-1,
)

if fetchonly:
failed_files.add(myfile)
continue
else:
return 0

size = orig_digests.get("size")
if size == 0:
# Zero-byte distfiles are always invalid, so discard their digests.
del mydigests[myfile]
orig_digests.clear()
size = None
pruned_digests = orig_digests
if parallel_fetchonly:
pruned_digests = {}
if size is not None:
pruned_digests["size"] = size

myfile_path = os.path.join(mysettings["DISTDIR"], myfile)
download_path = myfile_path if fetch_to_ro else myfile_path + _download_suffix
has_space = True
has_space_superuser = True
file_lock = None
if listonly:
writemsg_stdout("\n", noiselevel=-1)
else:
vfs_stat = None
if size is not None and hasattr(os, "statvfs"):
try:
vfs_stat = os.statvfs(mysettings["DISTDIR"])
except OSError as e:
writemsg_level(
"!!! statvfs('%s'): %s\n" % (mysettings["DISTDIR"], e),
noiselevel=-1,
level=logging.ERROR,
)
del e

if vfs_stat is not None:
try:
mysize = os.stat(myfile_path).st_size
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
del e
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
elif portage.data.secpass < 2:
has_space = False
elif userfetch:
has_space = False

if distdir_writable and use_locks:

lock_kwargs = {}
if fetchonly:
lock_kwargs["flags"] = os.O_NONBLOCK

try:
file_lock = lockfile(myfile_path, wantnewlockfile=1, **lock_kwargs)
except TryAgain:
writemsg(
_(
">>> File '%s' is already locked by "
"another fetcher. Continuing...\n"
)
% myfile,
noiselevel=-1,
)
continue
try:
if not listonly:

eout = EOutput()
eout.quiet = mysettings.get("PORTAGE_QUIET") == "1"
match, mystat = _check_distfile(
myfile_path, pruned_digests, eout, hash_filter=hash_filter
)
if match and not force:
if distdir_writable and not os.path.islink(myfile_path):
try:
apply_secpass_permissions(
myfile_path,
gid=portage_gid,
mode=0o664,
mask=0o2,
stat_cached=mystat,
)
except PortageException as e:
if not os.access(myfile_path, os.R_OK):
writemsg(
_("!!! Failed to adjust permissions:" " %s\n")
% str(e),
noiselevel=-1,
)
del e
continue

if distdir_writable and mystat is None or os.path.islink(myfile_path):
try:
os.unlink(myfile_path)
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
mystat = None

if mystat is not None:
if stat.S_ISDIR(mystat.st_mode):
writemsg_level(
_(
"!!! Unable to fetch file since "
"a directory is in the way: \n"
"!!!   %s\n"
)
% myfile_path,
level=logging.ERROR,
noiselevel=-1,
)
return 0

if distdir_writable and not force:
temp_filename = _checksum_failure_temp_file(
mysettings, mysettings["DISTDIR"], myfile
)
writemsg_stdout(
_("Refetching... " "File renamed to '%s'\n\n")
% temp_filename,
noiselevel=-1,
)

try:
mystat = os.stat(download_path)
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
mystat = None

if mystat is not None:
if mystat.st_size == 0:
if distdir_writable:
try:
os.unlink(download_path)
except OSError:
pass
elif distdir_writable and size is not None:
if mystat.st_size < fetch_resume_size and mystat.st_size < size:
writemsg(
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
os.path.basename(download_path),
)
writemsg_stdout(
_("Refetching... " "File renamed to '%s'\n\n")
% temp_filename,
noiselevel=-1,
)
elif mystat.st_size >= size:
temp_filename = _checksum_failure_temp_file(
mysettings,
mysettings["DISTDIR"],
os.path.basename(download_path),
)
writemsg_stdout(
_("Refetching... " "File renamed to '%s'\n\n")
% temp_filename,
noiselevel=-1,
)

if distdir_writable and ro_distdirs:
readonly_file = None
for x in ro_distdirs:
filename = get_mirror_url(x, myfile, mysettings)
match, mystat = _check_distfile(
filename, pruned_digests, eout, hash_filter=hash_filter
)
if match:
readonly_file = filename
break
if readonly_file is not None:
try:
os.unlink(myfile_path)
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
del e
os.symlink(readonly_file, myfile_path)
continue

if not has_space:
writemsg(
_("!!! Insufficient space to store %s in %s\n")
% (myfile, mysettings["DISTDIR"]),
noiselevel=-1,
)

if has_space_superuser:
writemsg(
_(
"!!! Insufficient privileges to use "
"remaining space.\n"
),
noiselevel=-1,
)
if userfetch:
writemsg(
_(
'!!! You may set FEATURES="-userfetch"'
" in /etc/portage/make.conf in order to fetch with\n"
"!!! superuser privileges.\n"
),
noiselevel=-1,
)

if fsmirrors and not os.path.exists(myfile_path) and has_space:
for mydir in fsmirrors:
mirror_file = get_mirror_url(mydir, myfile, mysettings)
try:
shutil.copyfile(mirror_file, download_path)
writemsg(_("Local mirror has file: %s\n") % myfile)
break
except (IOError, OSError) as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
del e

try:
mystat = os.stat(download_path)
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
del e
else:
if not os.path.islink(download_path):
try:
apply_secpass_permissions(
download_path,
gid=portage_gid,
mode=0o664,
mask=0o2,
stat_cached=mystat,
)
except PortageException as e:
if not os.access(download_path, os.R_OK):
writemsg(
_("!!! Failed to adjust permissions:" " %s\n")
% (e,),
noiselevel=-1,
)

if mystat.st_size == 0:
if distdir_writable:
try:
os.unlink(download_path)
except EnvironmentError:
pass
elif not orig_digests:
if not force:
fetched = 1
else:
if (
mydigests[myfile].get("size") is not None
and mystat.st_size < mydigests[myfile]["size"]
and not restrict_fetch
):
fetched = 1  # Try to resume this download.
elif (
parallel_fetchonly
and mystat.st_size == mydigests[myfile]["size"]
):
eout = EOutput()
eout.quiet = mysettings.get("PORTAGE_QUIET") == "1"
eout.ebegin("%s size ;-)" % (myfile,))
eout.eend(0)
continue
else:
digests = _filter_unaccelarated_hashes(mydigests[myfile])
if hash_filter is not None:
digests = _apply_hash_filter(digests, hash_filter)
verified_ok, reason = verify_all(download_path, digests)
if not verified_ok:
writemsg(
_("!!! Previously fetched" " file: '%s'\n")
% myfile,
noiselevel=-1,
)
writemsg(
_("!!! Reason: %s\n") % reason[0], noiselevel=-1
)
writemsg(
_("!!! Got:      %s\n" "!!! Expected: %s\n")
% (reason[1], reason[2]),
noiselevel=-1,
)
if reason[0] == _(
"Insufficient data for checksum verification"
):
return 0
if distdir_writable:
temp_filename = _checksum_failure_temp_file(
mysettings,
mysettings["DISTDIR"],
os.path.basename(download_path),
)
writemsg_stdout(
_("Refetching... " "File renamed to '%s'\n\n")
% temp_filename,
noiselevel=-1,
)
else:
if not fetch_to_ro:
_movefile(
download_path,
myfile_path,
mysettings=mysettings,
)
eout = EOutput()
eout.quiet = (
mysettings.get("PORTAGE_QUIET", None) == "1"
)
if digests:
digests = list(digests)
digests.sort()
eout.ebegin(
"%s %s ;-)" % (myfile, " ".join(digests))
)
eout.eend(0)
continue

uri_list = filedict[myfile][:]
uri_list.reverse()
checksum_failure_count = 0
tried_locations = set()
while uri_list:
loc = uri_list.pop()
if isinstance(loc, functools.partial):
loc = loc()
if loc in tried_locations:
continue
tried_locations.add(loc)
if listonly:
writemsg_stdout(loc + " ", noiselevel=-1)
continue
protocol = loc[0 : loc.find("://")]

global_config_path = GLOBAL_CONFIG_PATH
if portage.const.EPREFIX:
global_config_path = os.path.join(
portage.const.EPREFIX, GLOBAL_CONFIG_PATH.lstrip(os.sep)
)

missing_file_param = False
fetchcommand_var = "FETCHCOMMAND_" + protocol.upper()
fetchcommand = mysettings.get(fetchcommand_var)
if fetchcommand is None:
fetchcommand_var = "FETCHCOMMAND"
fetchcommand = mysettings.get(fetchcommand_var)
if fetchcommand is None:
writemsg_level(
_(
"!!! %s is unset. It should "
"have been defined in\n!!! %s/make.globals.\n"
)
% (fetchcommand_var, global_config_path),
level=logging.ERROR,
noiselevel=-1,
)
return 0
if "${FILE}" not in fetchcommand:
writemsg_level(
_(
"!!! %s does not contain the required ${FILE}"
" parameter.\n"
)
% fetchcommand_var,
level=logging.ERROR,
noiselevel=-1,
)
missing_file_param = True

resumecommand_var = "RESUMECOMMAND_" + protocol.upper()
resumecommand = mysettings.get(resumecommand_var)
if resumecommand is None:
resumecommand_var = "RESUMECOMMAND"
resumecommand = mysettings.get(resumecommand_var)
if resumecommand is None:
writemsg_level(
_(
"!!! %s is unset. It should "
"have been defined in\n!!! %s/make.globals.\n"
)
% (resumecommand_var, global_config_path),
level=logging.ERROR,
noiselevel=-1,
)
return 0
if "${FILE}" not in resumecommand:
writemsg_level(
_(
"!!! %s does not contain the required ${FILE}"
" parameter.\n"
)
% resumecommand_var,
level=logging.ERROR,
noiselevel=-1,
)
missing_file_param = True

if missing_file_param:
writemsg_level(
_(
"!!! Refer to the make.conf(5) man page for "
"information about how to\n!!! correctly specify "
"FETCHCOMMAND and RESUMECOMMAND.\n"
),
level=logging.ERROR,
noiselevel=-1,
)
if myfile != os.path.basename(loc):
return 0

if not can_fetch:
if fetched != 2:
try:
mysize = os.stat(download_path).st_size
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
del e
mysize = 0

if mysize == 0:
writemsg(
_("!!! File %s isn't fetched but unable to get it.\n")
% myfile,
noiselevel=-1,
)
elif size is None or size > mysize:
writemsg(
_(
"!!! File %s isn't fully fetched, but unable to complete it\n"
)
% myfile,
noiselevel=-1,
)
else:
writemsg(
_(
"!!! File %s is incorrect size, "
"but unable to retry.\n"
)
% myfile,
noiselevel=-1,
)
return 0
continue

if fetched != 2 and has_space:
if fetched == 1:
try:
mystat = os.stat(download_path)
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
del e
fetched = 0
else:
if distdir_writable and mystat.st_size < fetch_resume_size:
writemsg(
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
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
del e
fetched = 0
if fetched == 1:
writemsg(_(">>> Resuming download...\n"))
locfetch = resumecommand
command_var = resumecommand_var
else:
locfetch = fetchcommand
command_var = fetchcommand_var
writemsg_stdout(_(">>> Downloading '%s'\n") % _hide_url_passwd(loc))
variables = {"URI": loc, "FILE": os.path.basename(download_path)}

try:
variables["DIGESTS"] = " ".join(
[
"%s:%s" % (k.lower(), v)
for k, v in mydigests[myfile].items()
if k != "size"
]
)
except KeyError:
pass

for k in ("DISTDIR", "PORTAGE_SSH_OPTS"):
v = mysettings.get(k)
if v is not None:
variables[k] = v

myfetch = varexpand(locfetch, mydict=variables)
myfetch = shlex_split(myfetch)

myret = -1
try:

myret = _spawn_fetch(mysettings, myfetch)

finally:
try:
apply_secpass_permissions(
download_path, gid=portage_gid, mode=0o664, mask=0o2
)
except FileNotFound:
pass
except PortageException as e:
if not os.access(download_path, os.R_OK):
writemsg(
_("!!! Failed to adjust permissions:" " %s\n")
% str(e),
noiselevel=-1,
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

if mydigests is not None and myfile in mydigests:
try:
mystat = os.stat(download_path)
except OSError as e:
if e.errno not in (errno.ENOENT, errno.ESTALE):
raise
del e
fetched = 0
else:

if stat.S_ISDIR(mystat.st_mode):
writemsg_level(
_(
"!!! The command specified in the "
"%s variable appears to have\n!!! "
"created a directory instead of a "
"normal file.\n"
)
% command_var,
level=logging.ERROR,
noiselevel=-1,
)
writemsg_level(
_(
"!!! Refer to the make.conf(5) "
"man page for information about how "
"to\n!!! correctly specify "
"FETCHCOMMAND and RESUMECOMMAND.\n"
),
level=logging.ERROR,
noiselevel=-1,
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
encoding=_encodings["fs"],
errors="strict",
),
mode="r",
encoding=_encodings["content"],
errors="replace",
) as f:
if html404.search(f.read()):
try:
os.unlink(download_path)
writemsg(
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
if hash_filter is not None:
digests = _apply_hash_filter(digests, hash_filter)
verified_ok, reason = verify_all(download_path, digests)
if not verified_ok:
writemsg(
_("!!! Fetched file: %s VERIFY FAILED!\n")
% myfile,
noiselevel=-1,
)
writemsg(
_("!!! Reason: %s\n") % reason[0], noiselevel=-1
)
writemsg(
_("!!! Got:      %s\n!!! Expected: %s\n")
% (reason[1], reason[2]),
noiselevel=-1,
)
if reason[0] == _(
"Insufficient data for checksum verification"
):
return 0
if distdir_writable:
temp_filename = _checksum_failure_temp_file(
mysettings,
mysettings["DISTDIR"],
os.path.basename(download_path),
)
writemsg_stdout(
_(
"Refetching... "
"File renamed to '%s'\n\n"
)
% temp_filename,
noiselevel=-1,
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
break
else:
if not fetch_to_ro:
_movefile(
download_path,
myfile_path,
mysettings=mysettings,
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
break
else:
if not myret:
if not fetch_to_ro:
_movefile(
download_path, myfile_path, mysettings=mysettings
)
fetched = 2
break
elif mydigests != None:
writemsg(
_("No digest file available and download failed.\n\n"),
noiselevel=-1,
)
finally:
if use_locks and file_lock:
unlockfile(file_lock)
file_lock = None

if listonly:
writemsg_stdout("\n", noiselevel=-1)
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
writemsg_level(msg, level=logging.ERROR, noiselevel=-1)
elif restrict_fetch:
pass
elif listonly:
pass
elif not filedict[myfile]:
writemsg(
_("Warning: No mirrors available for file" " '%s'\n") % (myfile),
noiselevel=-1,
)
else:
writemsg(
_("!!! Couldn't download '%s'. Aborting.\n") % myfile, noiselevel=-1
)

if listonly:
failed_files.add(myfile)
continue
elif fetchonly:
failed_files.add(myfile)
continue
return 0
if failed_files:
return 0
return 1
