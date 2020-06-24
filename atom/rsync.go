package atom

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const(
	SERVER_OUT_OF_DATE = -1
	EXCEEDED_MAX_RETRIES = -2
)

type RsyncSync struct {
	*newBase
	max_age     int
	verify_jobs int
}

func(r *RsyncSync) name() string {
	return "RsyncSync"
}

func(r *RsyncSync) __init__() {
	r.newBase = NewNewBase("rsync", RsyncPackageAtom)
}

func(r *RsyncSync) update() {
	opts := r.options["emerge_config"].opts
	r.usersync_uid = r.options["usersync_uid"]
	enter_invalid := "--ask-enter-invalid"
	in
	opts
	quiet := "--quiet"
	in
	opts
	out := NewEOutput(quiet)
	syncuri := r.repo.SyncUri
	if strings.ToLower(r.repo.moduleSpecificOptions["sync-rsync-vcs-ignore"]) == "true" {
		vcs_dirs = ()
	} else {
		vcs_dirs = frozenset(VcsDirs)
		vcs_dirs = vcs_dirs.intersection(os.listdir(r.repo.Location))
	}

	for vcs_dir
		in
	vcs_dirs {
		WriteMsgLevel(fmt.Sprintf("!!! %s appears to be under revision "+
			"control (contains %s).\n!!! Aborting rsync sync "+
			"(override with \"sync-rsync-vcs-ignore = true\" in repos.conf).\n".
				r.repo.location, vcs_dir), 40, -1)
		return 1, false
	}
	r.timeout = 180

	rsync_opts := []string{}
	if r.settings.ValueDict["PORTAGE_RSYNC_OPTS"] == "" {
		rsync_opts = r._set_rsync_defaults()
	} else {
		rsync_opts = r._validate_rsync_opts(rsync_opts, syncuri)
	}
	r.rsync_opts = r._rsync_opts_extend(opts, rsync_opts)

	r.extra_rsync_opts = list()
	if r.repo.moduleSpecificOptions["sync-rsync-extra-opts"]  != ""{
		r.extra_rsync_opts.extend(portage.util.shlex_split(
			r.repo.moduleSpecificOptions["sync-rsync-extra-opts"]))
	}

	exitcode := 0
	verify_failure := false

	r.verify_metamanifest =
		r.repo.moduleSpecificOptions[
			"sync-rsync-verify-metamanifest"] ==
			"yes" || r.repo.moduleSpecificOptions[
			"sync-rsync-verify-metamanifest"] == "true"
	verify_jobs := r.repo.moduleSpecificOptions["sync-rsync-verify-jobs"]
	if verify_jobs != "" {
		var err error
		r.verify_jobs, err = strconv.Atoi(r.verify_jobs)
		if err != nil || r.verify_jobs < 0 {
			//raise ValueError(r.verify_jobs)
			//except ValueError:
			WriteMsgLevel(fmt.Sprintf("!!! sync-rsync-verify-jobs not a positive integer: %s\n",r.verify_jobs, ), 30, -1)
			r.verify_jobs = 0
		} else{
			if r.verify_jobs == 0 {
				r.verify_jobs = 0
			}
		}
	}
	max_age := r.repo.moduleSpecificOptions["sync-rsync-verify-max-age"]
	if max_age != "" {
		var err error
		r.max_age,err = strconv.Atoi(max_age)
		if err != nil || r.max_age < 0{
		//except ValueError:
		WriteMsgLevel(fmt.Sprintf("!!! sync-rsync-max-age must be a non-negative integer: %s\n",r.max_age, ), 30, -1)
		r.max_age = 0
	}else {
		r.max_age = 0
	}

	openpgp_env = None
	if r.verify_metamanifest and
	gemato
	is
	not
None:
	if r.repo.sync_openpgp_key_path is
	not
None:
	openpgp_env = gemato.openpgp.OpenPGPEnvironment()
	else:
	openpgp_env = gemato.openpgp.OpenPGPSystemEnvironment()

try:
	if openpgp_env is
	not
	None
	and
	r.repo.sync_openpgp_key_path
	is
	not
None:
try:
	out.einfo("Using keys from %s" % (r.repo.sync_openpgp_key_path, ))
	with
	io.open(r.repo.sync_openpgp_key_path, "rb")
	as
f:
	openpgp_env.import_key(f)
	r._refresh_keys(openpgp_env)
	except(GematoException, asyncio.TimeoutError)
	as
e:
	WriteMsgLevel("!!! Manifest verification impossible due to keyring problem:\n%s\n"
	% (e,),
	level = logging.ERROR, noiselevel=-1)
	return (1, false)

	r.servertimestampfile = filepath.Join(
		r.repo.location, "metadata", "timestamp.chk")

	content = portage.util.grabfile(r.servertimestampfile)
	timestamp = 0
	if content:
try:
	timestamp = time.mktime(time.strptime(content[0],
		TIMESTAMP_FORMAT))
	except(OverflowError, ValueError):
	pass
	del
	content

try:
	r.rsync_initial_timeout = \
	int(r.settings.get("PORTAGE_RSYNC_INITIAL_TIMEOUT", "15"))
	except
ValueError:
	r.rsync_initial_timeout = 15

try:
	maxretries = int(r.settings.ValueDict["PORTAGE_RSYNC_RETRIES"])
	except
	SystemExit
	as
e:
	raise
except:
	maxretries = -1

	if syncuri.startswith("file://"):
	r.proto = "file"
	dosyncuri = syncuri[7:]
	unchanged, is_synced, exitcode, updatecache_flg = r._do_rsync(
		dosyncuri, timestamp, opts)
	r._process_exitcode(exitcode, dosyncuri, out, 1)
	if exitcode == 0:
	if unchanged:
	r.repo_storage.abort_update()
	else:
	r.repo_storage.commit_update()
	r.repo_storage.garbage_collection()
	return (exitcode, updatecache_flg)

	retries = 0
try:
	r.proto, user_name, hostname, port = re.split(
		r
	"(rsync|ssh)://([^:/]+@)?(\[[:\da-fA-F]*\]|[^:/]*)(:[0-9]+)?",
		syncuri, maxsplit = 4)[1:5]
except ValueError:
WriteMsgLevel("!!! sync-uri is invalid: %s\n" % syncuri,
noiselevel = -1, level = logging.ERROR)
return (1, false)

r.ssh_opts = r.settings.get("PORTAGE_SSH_OPTS")

if port is None:
port = ""
if user_name is None:
user_name = ""
if re.match(r"^\[[:\da-fA-F]*\]$", hostname) is None:
getaddrinfo_host = hostname else:
getaddrinfo_host = hostname[1:-1]
updatecache_flg = false
all_rsync_opts = set(r.rsync_opts)
all_rsync_opts.update(r.extra_rsync_opts)

family = socket.AF_UNSPEC
if "-4" in all_rsync_opts or "--ipv4" in all_rsync_opts:
family = socket.AF_INET
else if socket.has_ipv6 and \
("-6" in all_rsync_opts or "--ipv6" in all_rsync_opts):
family = socket.AF_INET6

addrinfos = None
uris = []

try:
addrinfos = getaddrinfo_validate(
socket.getaddrinfo(getaddrinfo_host, None,
family, socket.SOCK_STREAM))
except socket.error as e:
WriteMsgLevel(
"!!! getaddrinfo failed for "%s": %s\n"
% (_unicode_decode(hostname), _unicode(e)),
noiselevel= -1, level = logging.ERROR)

if addrinfos:

AF_INET = socket.AF_INET
AF_INET6 = None
if socket.has_ipv6:
AF_INET6 = socket.AF_INET6

ips_v4 = []
ips_v6 = []

for addrinfo in addrinfos:
if addrinfo[0] == AF_INET:
ips_v4=append("%s" % addrinfo[4][0])
else if AF_INET6 is not None and addrinfo[0] == AF_INET6:
ips_v6=append("[%s]" % addrinfo[4][0])

random.shuffle(ips_v4)
random.shuffle(ips_v6)

if AF_INET6 is not None and addrinfos and \
addrinfos[0][0] == AF_INET6:
ips = ips_v6 + ips_v4
else:
ips = ips_v4 + ips_v6

for ip in ips:
uris=append(syncuri.replace(
"//" + user_name + hostname + port + "/",
"//" + user_name + ip + port + "/", 1))

if not uris:
uris=append(syncuri)
else if len(uris) == 1:
uris = [syncuri]

uris.reverse()
uris_orig = uris[:]

effective_maxretries = maxretries
if effective_maxretries < 0:
effective_maxretries = len(uris) - 1

local_state_unchanged = True
while (1):
if uris:
dosyncuri = uris.pop()
else if maxretries < 0 or retries > maxretries:
writemsg("!!! Exhausted addresses for %s\n"
% _unicode_decode(hostname), noiselevel = -1)
return (1, false) else:
uris.extend(uris_orig)
dosyncuri = uris.pop()

if (retries==0):
if "--ask" in opts:
uq = UserQuery(opts)
if uq.query("Do you want to sync your ebuild repository " + \
"with the mirror at\n" + blue(dosyncuri) + bold("?"),
enter_invalid) == "No":
print()
print("Quitting.")
print()
sys.exit(128 + signal.SIGINT)
r.logger(r.xterm_titles,
">>> Starting rsync with " + dosyncuri)
if "--quiet" not in opts:
print(">>> Starting rsync with "+dosyncuri+"...") else:
r.logger(r.xterm_titles,
">>> Starting retry %d of %d with %s" % \
(retries, effective_maxretries, dosyncuri))
writemsg_stdout(
"\n\n>>> Starting retry %d of %d with %s\n" % \
(retries, effective_maxretries, dosyncuri), noiselevel = -1)

if dosyncuri.startswith("ssh://"):
dosyncuri = dosyncuri[6:].replace("/", ":/", 1)

unchanged, is_synced, exitcode, updatecache_flg = r._do_rsync(
dosyncuri, timestamp, opts)
if not unchanged:
local_state_unchanged = false
if is_synced:
break

retries = retries+1

if maxretries < 0 or retries <= maxretries:
print(">>> Retrying...") else:
exitcode = EXCEEDED_MAX_RETRIES
break

r._process_exitcode(exitcode, dosyncuri, out, maxretries)

if local_state_unchanged:
download_dir = r.repo.location else:
download_dir = r.download_dir

if exitcode == 0 and r.verify_metamanifest:
if gemato is None:
WriteMsgLevel("!!! Unable to verify: gemato-11.0+ is required\n",
level = logging.ERROR, noiselevel =-1)
exitcode = 127 else:
try:
m = gemato.recursiveloader.ManifestRecursiveLoader(
filepath.Join(download_dir, "Manifest"),
verify_openpgp = True,
openpgp_env = openpgp_env,
max_jobs= r.verify_jobs)
if not m.openpgp_signed:
raise RuntimeError("OpenPGP signature not found on Manifest")

ts = m.find_timestamp()
if ts is None:
raise RuntimeError("Timestamp not found in Manifest")
if (r.max_age != 0 and
(datetime.datetime.utcnow() - ts.ts).days > r.max_age):
out.quiet = false
out.ewarn("Manifest is over %d days old, this is suspicious!" % (r.max_age, ))
out.ewarn("You may want to try using another mirror and/or reporting this one:")
out.ewarn("  %s" % (dosyncuri, ))
out.ewarn("")
out.quiet = quiet

out.einfo("Manifest timestamp: %s UTC" % (ts.ts,))
out.einfo("Valid OpenPGP signature found:")
out.einfo("- primary key: %s" % (
m.openpgp_signature.primary_key_fingerprint))
out.einfo("- subkey: %s" % (
m.openpgp_signature.fingerprint))
out.einfo("- timestamp: %s UTC" % (
m.openpgp_signature.timestamp))

if not local_state_unchanged:
out.ebegin("Verifying %s" % (download_dir, ))
m.assert_directory_verifies()
out.eend(0)
except GematoException as e:
WriteMsgLevel("!!! Manifest verification failed:\n%s\n"
% (e, ),
level= logging.ERROR, noiselevel = -1)
exitcode = 1
verify_failure = True

if exitcode == 0 and not local_state_unchanged:
r.repo_storage.commit_update()
r.repo_storage.garbage_collection()

return (exitcode, updatecache_flg)
finally:
if not verify_failure:
r.repo_storage.abort_update()
if openpgp_env is not None:
openpgp_env.close()
}

func(r *RsyncSync) _process_exitcode(exitcode int, syncuri string, out *eOutput, maxretries int) {
	if (exitcode == 0) {
		//pass
	} else if exitcode == SERVER_OUT_OF_DATE {
		exitcode = 1
	} else if exitcode == EXCEEDED_MAX_RETRIES {
		os.Stderr.Write([]byte(fmt.Sprintf(">>> Exceeded PORTAGE_RSYNC_RETRIES: %s\n" , maxretries)))
		exitcode = 1
	} else if (exitcode > 0) {
		msg := []string{}
		if exitcode == 1 {
			msg=append(msg,"Rsync has reported that there is a syntax error. Please ensure")
			msg=append(msg,fmt.Sprintf("that sync-uri attribute for repository '%s' is proper." ,r.repo.Name))
			msg=append(msg,fmt.Sprintf("sync-uri: '%s'", r.repo.SyncUri))
		}else if exitcode == 11 {
			msg=append(msg,"Rsync has reported that there is a File IO error. Normally")
			msg=append(msg,"this means your disk is full, but can be caused by corruption")
			msg=append(msg,fmt.Sprintf("on the filesystem that contains repository '%s'. Please investigate" , r.repo.Name))
			msg=append(msg,"and try again after the problem has been fixed.")
			msg=append(msg,fmt.Sprintf("Location of repository: '%s'" , r.repo.Location))
		}else if exitcode == 20 {
			msg=append(msg,"Rsync was killed before it finished.")
		}else {
			msg=append(msg,"Rsync has not successfully finished. It is recommended that you keep")
			msg=append(msg,"trying or that you use the 'emerge-webrsync' option if you are unable")
			msg=append(msg,"to use rsync due to firewall or other restrictions. This should be a")
			msg=append(msg,"temporary problem unless complications exist with your network")
			msg=append(msg,"(and possibly your system's filesystem) configuration.")
		}
		for _, line:= range msg {
			out.eerror(line)
		}
	}
}

func(r *RsyncSync) new(r, * *kwargs) (int, bool) {
	if kwargs {
		r._kwargs(kwargs)
	}
try:
	if ! pathExists(r.repo.Location) {
		os.MkdirAll(r.repo.Location, 0755)
		r.logger(r.r.xterm_titles,
			fmt.Sprintf("Created New Directory %s ",r.repo.Location))
	}
	except
IOError:
	return 1, false
	return r.update()
}

func(r *RsyncSync) retrieve_head( **kwargs) (int, bool){
	if kwargs:
	r._kwargs(kwargs)
	last_sync = portage.grabfile(filepath.Join(r.repo.location, "metadata", "timestamp.commit"))
	ret = (1, false)
	if last_sync:
try:
	ret = (0, last_sync[0].split()[0])
	except
IndexError:
	pass
	return ret
}

func(r *RsyncSync) _set_rsync_defaults() []string {
	WriteMsg("PORTAGE_RSYNC_OPTS empty or unset, using hardcoded defaults\n", 0, nil)
	rsync_opts := []string{
		"--recursive",
		"--links",
		"--safe-links",
		"--perms",
		"--times",
		"--omit-dir-times",
		"--compress",
		"--force",
		"--whole-file",
		"--delete",
		"--stats",
		"--human-readable",
		"--timeout=" + fmt.Sprint(r.timeout),
		"--exclude=/distfiles",
		"--exclude=/local",
		"--exclude=/packages",
	}
	return rsync_opts
}

func(r *RsyncSync) _validate_rsync_opts( rsync_opts, syncuri) {

	WriteMsg("Using PORTAGE_RSYNC_OPTS instead of hardcoded defaults\n", 1)
	rsync_opts.extend(portage.util.shlex_split(
		r.settings.get("PORTAGE_RSYNC_OPTS", "")))
	for opt
	in("--recursive", "--times"):
	if opt not
	in
rsync_opts:
	WriteMsg(yellow("WARNING:") + " adding required option " + \
	"%s not included in PORTAGE_RSYNC_OPTS\n" % opt)
	rsync_opts=append(opt)

	for exclude
	in("distfiles", "local", "packages"):
	opt = "--exclude=/%s" % exclude
	if opt not
	in
rsync_opts:
	WriteMsg(("WARNING:") + \
	" adding required option %s not included in "%opt + \
	"PORTAGE_RSYNC_OPTS (can be overridden with --exclude='!')\n")
	rsync_opts=append(opt)

	if syncuri.rstrip("/").endswith(".gentoo.org/gentoo-portage"):
	func(r *RsyncSync) rsync_opt_startswith(opt_prefix):
	for x
	in
rsync_opts:
	if x.startswith(opt_prefix):
	return (1, false)
	return (0, false)

	if not rsync_opt_startswith("--timeout="):
	rsync_opts=append("--timeout=%d" % r.timeout)

	for opt
	in("--compress", "--whole-file"):
	if opt not
	in
rsync_opts:
	WriteMsg(yellow("WARNING:") + " adding required option " + \
	"%s not included in PORTAGE_RSYNC_OPTS\n" % opt)
	rsync_opts=append(opt)
	return rsync_opts
}

func(r *RsyncSync) _rsync_opts_extend(opts interface{}, rsync_opts []string) []string{
	if "--quiet" in
opts{
	rsync_opts = append(rsync_opts, "--quiet")
}else {
		rsync_opts = append(rsync_opts, "--verbose")
	}

	if "--verbose" in
opts{
	rsync_opts = append(rsync_opts, "--progress")
}

	if "--debug" in
opts{
	rsync_opts = append(rsync_opts, "--checksum")
}
	return rsync_opts
}

func(r *RsyncSync) _do_rsync( syncuri, timestamp, opts) {
	updatecache_flg := false
	is_synced := false
	if timestamp != 0 and
	"--quiet"
	not
	in
opts:
	print(">>> Checking server timestamp ...")

	rsynccommand = [r.bin_command] + r.rsync_opts + r.extra_rsync_opts

	if r.proto == "ssh" and
	r.ssh_opts:
	rsynccommand=append("--rsh=ssh " + r.ssh_opts)

	if "--debug" in
opts:
	print(rsynccommand)

	local_state_unchanged = false
	exitcode = 0
	servertimestamp = 0

	if r.usersync_uid is
	not
None:
	tmpdir = filepath.Join(r.settings.ValueDict["PORTAGE_TMPDIR"], "portage")
	ensure_dirs_kwargs =
	{
	}
	if portage.secpass >= 1:
	ensure_dirs_kwargs["gid"] = portage.portage_gid
	ensure_dirs_kwargs["mode"] = 0o70
	ensure_dirs_kwargs["mask"] = 0
	portage.util.ensure_dirs(tmpdir, **ensure_dirs_kwargs)
	else:
	tmpdir = None
	fd, tmpservertimestampfile = \
	tempfile.mkstemp(dir = tmpdir)
	os.close(fd)
	if r.usersync_uid is
	not
None:
	portage.util.apply_permissions(tmpservertimestampfile,
		uid = r.usersync_uid)
	command = rsynccommand[:]
	command=append("--inplace")
	command=append(syncuri.rstrip("/") + \
	"/metadata/timestamp.chk")
	command=append(tmpservertimestampfile)
	content = None
	pids = []
try:
try:
	if r.rsync_initial_timeout:
	portage.exception.AlarmSignal.register(
		r.rsync_initial_timeout)

	pids.extend(portage.process.spawn(
		command, returnpid = True,
		**r.spawn_kwargs))
	exitcode = os.waitpid(pids[0], 0)[1]
	if r.usersync_uid is
	not
None:
	portage.util.apply_permissions(tmpservertimestampfile,
		uid = os.getuid())
	content = portage.grabfile(tmpservertimestampfile)
finally:
	if r.rsync_initial_timeout:
	portage.exception.AlarmSignal.unregister()
try:
	os.unlink(tmpservertimestampfile)
	except
OSError:
	pass
	except
	portage.exception.AlarmSignal:
	print("timed out")
	if pids and
	os.waitpid(pids[0], os.WNOHANG)[0] == 0:
	os.kill(pids[0], signal.SIGTERM)
	os.waitpid(pids[0], 0)
	exitcode = 30
	else:
	if exitcode != 0:
	if exitcode & 0xff:
	exitcode = (exitcode & 0xff) << 8
	else:
	exitcode = exitcode >> 8

	if content:
try:
	servertimestamp = time.mktime(time.strptime(
		content[0], TIMESTAMP_FORMAT))
	except(OverflowError, ValueError):
	pass
	del
	command, pids, content

	if exitcode == 0:
	if (servertimestamp != 0) and(servertimestamp == timestamp):
	local_state_unchanged = True
	is_synced = True
	r.logger(r.xterm_titles,
		">>> Cancelling sync -- Already current.")
	print()
	print(">>>")
	print(">>> Timestamps on the server and in the local repository are the same.")
	print(">>> Cancelling all further sync action. You are already up to date.")
	print(">>>")
	print(">>> In order to force sync, remove '%s'." % r.servertimestampfile)
	print(">>>")
	print()
	else if(servertimestamp != 0)
	and(servertimestamp < timestamp):
	r.logger(r.xterm_titles,
		">>> Server out of date: %s"%syncuri)
	print()
	print(">>>")
	print(">>> SERVER OUT OF DATE: %s" % syncuri)
	print(">>>")
	print(">>> In order to force sync, remove '%s'." % r.servertimestampfile)
	print(">>>")
	print()
	exitcode = SERVER_OUT_OF_DATE
	else if(servertimestamp == 0)
	or(servertimestamp > timestamp):
	command = rsynccommand[:]

	submodule_paths = r._get_submodule_paths()
	if submodule_paths:
	command=append("--relative")
	for path
	in
submodule_paths:
	command=append(syncuri + "/./" + path)
	else:
	command=append(syncuri + "/")

	command=append(r.download_dir)

	exitcode = None
try:
	exitcode = portage.process.spawn(command,
		**r.spawn_kwargs)
finally:
	if exitcode is
None:
	exitcode = 128 + signal.SIGINT

	if exitcode not
	in(0, 1, 2, 5, 35):
	timestamp = 0
try:
	os.unlink(r.servertimestampfile)
	except
OSError:
	pass
	else:
	updatecache_flg = True

	if exitcode in
	[0, 1, 3, 4, 11, 14, 20, 21]:
is_synced = True
else if exitcode in [1, 3, 4, 11, 14, 20, 21]:
is_synced = True else:
pass

return local_state_unchanged, is_synced, exitcode, updatecache_flg
}
