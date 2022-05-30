package sync

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/shlex"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const(
	SERVER_OUT_OF_DATE = -1
	EXCEEDED_MAX_RETRIES = -2
)

type RsyncSync struct {
	*atom.newBase
	max_age               int
	verify_jobs           int
	timeout               int
	rsync_opts            []string
	verify_metamanifest   bool
	extra_rsync_opts      []string
	bin_command           string
	servertimestampfile   string
	rsync_initial_timeout int
	proto, ssh_opts       string
}

func(r *RsyncSync) name() string {
	return "RsyncSync"
}

func NewRsyncSync() *RsyncSync {
	r := &RsyncSync{}
	r.newBase = NewNewBase("rsync", _const.RsyncPackageAtom)
	return r
}

func(r *RsyncSync) update() (int,bool) {
	opts := r.options["emerge_config"].opts
	r.usersync_uid = r.options["usersync_uid"]
	enter_invalid := "--ask-enter-invalid"
	in
	opts
	quiet := "--quiet"
	in
	opts
	out := output.NewEOutput(quiet)
	syncuri := r.repo.SyncUri
	vcs_dirs := map[string]bool{}
	if strings.ToLower(r.repo.moduleSpecificOptions["sync-rsync-vcs-ignore"]) == "true" {
	} else {
		vcs_dirs = myutil.CopyMapSB(_const.VcsDirs)
		old, _ := myutil.ListDir(r.repo.Location)
		for k := range vcs_dirs {
			if !myutil.Ins(old, k) {
				delete(vcs_dirs, k)
			}
		}
	}

	for vcs_dir := range vcs_dirs {
		msg.WriteMsgLevel(fmt.Sprintf("!!! %s appears to be under revision "+
			"control (contains %s).\n!!! Aborting rsync sync "+
			"(override with \"sync-rsync-vcs-ignore = true\" in repos.conf).\n",
			r.repo.Location, vcs_dir), 40, -1)
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

	r.extra_rsync_opts = []string{}
	if r.repo.moduleSpecificOptions["sync-rsync-extra-opts"] != "" {
		ss, _ := shlex.Split(strings.NewReader(
			r.repo.moduleSpecificOptions["sync-rsync-extra-opts"]), false, true)
		r.extra_rsync_opts = append(r.extra_rsync_opts, ss...)
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
		r.verify_jobs, err = strconv.Atoi(verify_jobs)
		if err != nil || r.verify_jobs < 0 {
			//raise ValueError(r.verify_jobs)
			//except ValueError:
			msg.WriteMsgLevel(fmt.Sprintf("!!! sync-rsync-verify-jobs not a positive integer: %s\n", r.verify_jobs, ), 30, -1)
			r.verify_jobs = 0
		} else {
			if r.verify_jobs == 0 {
				r.verify_jobs = 0
			}
		}
	}
	max_age := r.repo.moduleSpecificOptions["sync-rsync-verify-max-age"]
	if max_age != "" {
		var err error
		r.max_age, err = strconv.Atoi(max_age)
		if err != nil || r.max_age < 0 {
			//except ValueError:
			msg.WriteMsgLevel(fmt.Sprintf("!!! sync-rsync-max-age must be a non-negative integer: %s\n", r.max_age, ), 30, -1)
			r.max_age = 0
		}
	} else {
		r.max_age = 0
	}

	//	openpgp_env = None
	//	if r.verify_metamanifest and
	//	gemato
	//	is
	//	not
	//None:
	//	if r.repo.syncOpenpgpKeyPath is
	//	not
	//None:
	//	openpgp_env = gemato.openpgp.OpenPGPEnvironment()
	//	else:
	//	openpgp_env = gemato.openpgp.OpenPGPSystemEnvironment()
	//

	defer func() {
		if !verify_failure {
			r.repoStorage().abort_update()
		}
		//if openpgp_env is not None:
		//openpgp_env.close()
	}()

	//try:
	//	if openpgp_env is
	//	not
	//	None
	//	&&r.repo.syncOpenpgpKeyPath!= nil:
	//try:
	//	out.einfo("Using keys from %s" % (r.repo.syncOpenpgpKeyPath, ))
	//	with
	//	io.open(r.repo.syncOpenpgpKeyPath, "rb")
	//	as
	//f:
	//	openpgp_env.import_key(f)
	//	r._refresh_keys(openpgp_env)
	//	except(GematoException, asyncio.TimeoutError)
	//	as
	//e:
	//	WriteMsgLevel("!!! Manifest verification impossible due to keyring problem:\n%s\n"
	//	% (e,),
	//	level = 40, noiselevel=-1)
	//	return (1, false)
	//
	r.servertimestampfile = filepath.Join(
		r.repo.Location, "metadata", "timestamp.chk")

	content := util.GrabFile(r.servertimestampfile, 0, false, false)
	timestamp := int64(0)
	if len(content) == 0 {
		timestampT, err := time.Parse(content[0][0], time.RFC1123) // TimestampFormat)
		if err != nil {
			//except(OverflowError, ValueError):
			//pass
		} else {
			timestamp = timestampT.UnixNano()
		}
	}

	content = nil

	pri, ok := r.settings.ValueDict["PORTAGE_RSYNC_INITIAL_TIMEOUT"]
	if !ok {
		pri = "15"
	}

	var err error
	r.rsync_initial_timeout, err = strconv.Atoi(pri)
	if err != nil {
		//except ValueError:
		r.rsync_initial_timeout = 15
	}

	maxretries, err := strconv.Atoi(r.settings.ValueDict["PORTAGE_RSYNC_RETRIES"])
	if err != nil {
		//except SystemExit as e:
		//raise
		//except:
		maxretries = -1
	}

	if strings.HasPrefix(syncuri, "file://") {
		r.proto = "file"
		dosyncuri := syncuri[7:]
		unchanged, is_synced, exitcode, updatecache_flg := r._do_rsync(
			dosyncuri, timestamp, opts)
		r._process_exitcode(exitcode, dosyncuri, out, 1)
		if exitcode == 0 {
			if unchanged {
				r.repo_storage.abort_update()
			} else {
				r.repo_storage.commit_update()
				r.repo_storage.garbage_collection()
			}
		}
		return exitcode, updatecache_flg
	}

	retries := 0
	ruhp := regexp.MustCompile("(rsync|ssh)://([^:/]+@)?(\\[[:\\da-fA-F]*\\]|[^:/]*)(:[0-9]+)?")
	r.proto = ruhp.FindStringSubmatch(syncuri)[1]
	user_name, hostname, port := ruhp.FindStringSubmatch(syncuri)[2], ruhp.FindStringSubmatch(syncuri)[3], ruhp.FindStringSubmatch(syncuri)[4]
	//except ValueError:
	//WriteMsgLevel("!!! sync-uri is invalid: %s\n" % syncuri,
	//noiselevel = -1, level = 40)
	//return (1, false)

	r.ssh_opts = r.settings.ValueDict["PORTAGE_SSH_OPTS"]

	if port == "" {
		port = ""
	}
	if user_name == "" {
		user_name = ""
	}

	getaddrinfo_host := ""
	if ok, _ := regexp.MatchString("^\\[[:\\da-fA-F]*\\]$", hostname); !ok {
		getaddrinfo_host = hostname
	} else {
		getaddrinfo_host = hostname[1 : len(hostname)-1]
	}

	all_rsync_opts := map[string]bool{}
	for _, k := range r.rsync_opts {
		all_rsync_opts[k] = true
	}
	for _, k := range r.extra_rsync_opts {
		all_rsync_opts[k] = true
	}

	uris := []string{}

	addrinfos, err := net.LookupIP(getaddrinfo_host)
	if err != nil {
		//except socket.error as e:
		msg.WriteMsgLevel(fmt.Sprintf("!!! getaddrinfo failed for \"%s\": %s\n",
			hostname, err), -1, 40)
	}

	if len(addrinfos) > 0 {

		ips_v4 := []string{}
		ips_v6 := []string{}

		for _, addrinfo := range addrinfos {
			if addrinfo.To4() != nil {
				ips_v4 = append(ips_v4, fmt.Sprintf("%s", addrinfo.String()))
			} else if addrinfo.To4() == nil {
				ips_v6 = append(ips_v6, fmt.Sprintf("[%s]", addrinfo.String()))
			}
		}

		rand.Shuffle(len(ips_v4), func(i, j int) {
			ips_v4[i], ips_v4[j] = ips_v4[j], ips_v4[i]
		})
		rand.Shuffle(len(ips_v6), func(i, j int) {
			ips_v6[i], ips_v6[j] = ips_v6[j], ips_v6[i]
		})

		ips := []string{}
		if len(addrinfos) > 0 && addrinfos[0].To4() == nil {
			ips = append(append([]string{}, ips_v6...), ips_v4...)
		} else {
			ips = append(append([]string{}, ips_v4...), ips_v6...)
		}

		for _, ip := range ips {
			uris = append(uris, strings.Replace(syncuri,
				"//"+user_name+hostname+port+"/",
				"//"+user_name+ip+port+"/", 1))
		}

	}
	if len(uris) == 0 {
		uris = append(uris, syncuri)
	} else if len(uris) == 1 {
		uris = []string{syncuri}
	}

	myutil.ReverseSlice(uris)
	uris_orig := []string{}
	copy(uris_orig, uris)

	effective_maxretries := maxretries
	if effective_maxretries < 0 {
		effective_maxretries = len(uris) - 1
	}

	local_state_unchanged := true
	dosyncuri := ""
	for {
		if len(uris) > 0 {
			dosyncuri = uris[len(uris)-1]
			uris = uris[:len(uris)-1]
		} else if maxretries < 0 ||
			retries > maxretries {
			util.WriteMsg(fmt.Sprintf("!!! Exhausted addresses for %s\n", hostname), -1, nil)
			return 1, false
		} else {
			uris = append(uris, uris_orig...)
			dosyncuri = uris[len(uris)-1]
			uris = uris[:len(uris)-1]
		}

		if (retries == 0) {
			if "--ask" in opts{
				uq := NewUserQuery(opts)
				if uq.query("Do you want to sync your ebuild repository " +
				"with the mirror at\n" + Blue(dosyncuri) + Bold("?"),
				enter_invalid, nil, nil) == "No"{
				print()
				print("Quitting.")
				print()
				os.exit(128 + unix.SIGINT)
			}
			}
			r.logger(r.xtermTitles,
				">>> Starting rsync with "+dosyncuri)
			if "--quiet" not
			in
			opts{
				print(">>> Starting rsync with " + dosyncuri + "...")
			}
		} else {
			r.logger(r.xtermTitles,
				fmt.Sprintf(">>> Starting retry %d of %d with %s",
					retries, effective_maxretries, dosyncuri))
			util.WriteMsgStdout(fmt.Sprintf("\n\n>>> Starting retry %d of %d with %s\n",
				retries, effective_maxretries, dosyncuri), -1)
		}

		if strings.HasPrefix(dosyncuri, "ssh://") {
			dosyncuri = strings.Replace(dosyncuri[6:], "/", ":/", 1)
		}

		unchanged, is_synced, exitcode, updatecache_flg := r._do_rsync(
			dosyncuri, timestamp, opts)
		if !unchanged {
			local_state_unchanged = false
		}
		if is_synced {
			break
		}

		retries = retries + 1

		if maxretries < 0 || retries <= maxretries {
			print(">>> Retrying...")
		} else {
			exitcode = EXCEEDED_MAX_RETRIES
			break
		}
	}

	r._process_exitcode(exitcode, dosyncuri, out, maxretries)

	download_dir := ""
	if local_state_unchanged {
		download_dir = r.repo.Location
	} else {
		download_dir = r.downloadDir
	}

	if exitcode == 0 && r.verify_metamanifest {
		//if gemato is None:
		//WriteMsgLevel("!!! Unable to verify: gemato-11.0+ is required\n",
		//level = 40, noiselevel =-1)
		//exitcode = 127 else:
		//try:
		//m = gemato.recursiveloader.ManifestRecursiveLoader(
		//filepath.Join(download_dir, "Manifest"),
		//verify_openpgp = true,
		//openpgp_env = openpgp_env,
		//max_jobs= r.verify_jobs)
		//if not m.openpgp_signed:
		//raise RuntimeError("OpenPGP signature not found on Manifest")
		//
		//ts = m.find_timestamp()
		//if ts is None:
		//raise RuntimeError("Timestamp not found in Manifest")
		//if (r.max_age != 0 and
		//(datetime.datetime.utcnow() - ts.ts).days > r.max_age):
		//out.quiet = false
		//out.ewarn("Manifest is over %d days old, this is suspicious!" % (r.max_age, ))
		//out.ewarn("You may want to try using another mirror and/or reporting this one:")
		//out.ewarn("  %s" % (dosyncuri, ))
		//out.ewarn("")
		//out.quiet = quiet
		//
		//out.einfo("Manifest timestamp: %s UTC" % (ts.ts,))
		//out.einfo("Valid OpenPGP signature found:")
		//out.einfo("- primary key: %s" % (
		//m.openpgp_signature.primary_key_fingerprint))
		//out.einfo("- subkey: %s" % (
		//m.openpgp_signature.fingerprint))
		//out.einfo("- timestamp: %s UTC" % (
		//m.openpgp_signature.timestamp))
		//
		//if not local_state_unchanged:
		//out.ebegin("Verifying %s" % (download_dir, ))
		//m.assert_directory_verifies()
		//out.eend(0)
		//except GematoException as e:
		//WriteMsgLevel("!!! Manifest verification failed:\n%s\n"
		//% (e, ),
		//level= 40, noiselevel = -1)
		//exitcode = 1
		//verify_failure = true
	}

	if exitcode == 0 && !local_state_unchanged {
		r.repo_storage.commit_update()
		r.repo_storage.garbage_collection()
	}

	return exitcode, updatecache_flg
}

func(r *RsyncSync) _process_exitcode(exitcode int, syncuri string, out *output.eOutput, maxretries int) {
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

func(r *RsyncSync) new(* *kwargs) (int, bool) {
	if kwargs {
		r._kwargs(kwargs)
	}
try:
	if ! myutil.pathExists(r.repo.Location) {
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
	last_sync = portage.GrabFile(filepath.Join(r.repo.Location, "metadata", "timestamp.commit"))
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
	util.WriteMsg("PORTAGE_RSYNC_OPTS empty or unset, using hardcoded defaults\n", 0, nil)
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

func(r *RsyncSync) _validate_rsync_opts( rsync_opts []string, syncuri string) []string {

	util.WriteMsg("Using PORTAGE_RSYNC_OPTS instead of hardcoded defaults\n", 1, nil)
	ss, _ := shlex.Split(strings.NewReader(
		r.settings.ValueDict["PORTAGE_RSYNC_OPTS"]), false, true)
	rsync_opts = append(rsync_opts, ss...)
	for _, opt := range []string{"--recursive", "--times"} {
		if !myutil.Ins(rsync_opts, opt) {
			util.WriteMsg(yellow("WARNING:")+fmt.Sprint(" adding required option "+
				"%s not included in PORTAGE_RSYNC_OPTS\n", opt), 0, nil)
			rsync_opts = append(rsync_opts, opt)
		}
	}

	for _, exclude := range []string{"distfiles", "local", "packages"} {
		opt := fmt.Sprintf("--exclude=/%s", exclude)
		if !myutil.Ins(rsync_opts, opt) {
			util.WriteMsg(("WARNING:")+fmt.Sprintf(
				" adding required option %s not included in ", opt)+
				"PORTAGE_RSYNC_OPTS (can be overridden with --exclude='!')\n", 0, nil)
			rsync_opts = append(rsync_opts, opt)
		}
	}

	if strings.HasSuffix(strings.TrimRight(syncuri, "/"), ".gentoo.org/gentoo-portage") {
		rsync_opt_startswith := func(opt_prefix string) (int, bool) {
			for _, x := range rsync_opts {
				if strings.HasPrefix(x, opt_prefix) {
					return 1, false
				}
			}
			return 0, false
		}

		if _, ok := rsync_opt_startswith("--timeout="); !ok {
			rsync_opts = append(rsync_opts, fmt.Sprintf("--timeout=%d", r.timeout))
		}

		for _, opt := range []string{"--compress", "--whole-file"} {
			if !myutil.Ins(rsync_opts, opt) {
				util.WriteMsg(yellow("WARNING:")+" adding required option "+
					fmt.Sprintf("%s not included in PORTAGE_RSYNC_OPTS\n", opt), 0, nil)
				rsync_opts = append(rsync_opts, opt)
			}
		}
	}
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

func(r *RsyncSync) _do_rsync( syncuri string, timestamp int64, opts interface{}) (bool, bool,int, bool) {
	updatecache_flg := false
	is_synced := false
	if timestamp != 0 &&
		"--quiet"
		not
	in
	opts{
		print(">>> Checking server timestamp ...")
	}

	rsynccommand := append(append([]string{r.bin_command}, r.rsync_opts...), r.extra_rsync_opts...)

	if r.proto == "ssh" && r.ssh_opts {
		rsynccommand = append(rsynccommand, "--rsh=ssh "+r.ssh_opts)
	}

	if "--debug" in
	opts{
		print(rsynccommand)
	}

	local_state_unchanged := false
	exitcode := 0
	servertimestamp := int64(0)

	tmpdir := ""
	if r.usersync_uid != nil {
		tmpdir = filepath.Join(r.settings.ValueDict["PORTAGE_TMPDIR"], "portage")
		var gid uint32
		var mode, mask os.FileMode
		if *data.secpass >= 1 {
			gid = *data.portage_gid
			mode = 070
			mask = 0
		}
		util.ensureDirs(tmpdir, -1, gid, mode, mask, nil, true)
	}
	fd, _ := ioutil.TempFile(tmpdir, "*")
	fd.Close()
	tmpservertimestampfile := filepath.Join(tmpdir, fd.Name())
	if r.usersync_uid != nil {
		util.applyPermissions(tmpservertimestampfile, r.usersync_uid, -1, -1, -1, nil, true)
	}
	command := rsynccommand[:]
	command = append(command, "--inplace")
	command = append(command, strings.TrimRight(syncuri, "/")+"/metadata/timestamp.chk")
	command = append(command, tmpservertimestampfile)
	var content [][2]string
	pids := []int{}
try:
try:
	if r.rsync_initial_timeout {
		portage.exception.AlarmSignal.register(
			r.rsync_initial_timeout)
	}

	pds, _ := process.spawn(
		command, returnpid = true,
		**r.spawn_kwargs)
	pids = append(pids, pds...)
	exitcode, _ = syscall.Wait4(pids[0], nil,  0, nil)
	if r.usersync_uid != nil {
		util.applyPermissions(tmpservertimestampfile, uint32(os.Getuid()) ,-1,-1,-1,nil,true)
	}
	content = util.GrabFile(tmpservertimestampfile, 0, false, false)
finally:
	if r.rsync_initial_timeout != 0 {
		portage.exception.AlarmSignal.unregister()
	}
	if err := syscall.Unlink(tmpservertimestampfile); err != nil {
		//except OSError:
		//pass
		//except portage.exception.AlarmSignal:
		print("timed out")
	}
	if len(pids) > 0 {
		if p, err := syscall.Wait4(pids[0], nil, syscall.WNOHANG, nil); err != nil && p == 0 {
			syscall.Kill(pids[0], syscall.SIGTERM)
			syscall.Wait4(pids[0], nil, 0, nil)
		}

		exitcode = 30
	} else {
		if exitcode != 0 {
			if exitcode&0xff != 0 {
				exitcode = (exitcode & 0xff) << 8
			} else {
				exitcode = exitcode >> 8
			}
		}
	}

	if len(content) > 0 {
		servertimestampT, err := time.Parse(content[0][0], time.RFC1123Z)
		//content[0], TIMESTAMP_FORMAT))
		if err != nil {
			//except(OverflowError, ValueError):
			//pass
		} else {
			servertimestamp = servertimestampT.UnixNano()
		}
	}
	command, pids, content = nil, nil, nil

	if exitcode == 0 {
		if (servertimestamp != 0) && (servertimestamp == timestamp) {
			local_state_unchanged = true
			is_synced = true
			r.logger(r.xtermTitles,
				">>> Cancelling sync -- Already current.")
			print()
			print(">>>")
			print(">>> Timestamps on the server and in the local repository are the same.")
			print(">>> Cancelling all further sync action. You are already up to date.")
			print(">>>")
			print(fmt.Sprintf(">>> In order to force sync, remove '%s'." ,r.servertimestampfile))
			print(">>>")
			print()
		} else if (servertimestamp != 0) && (servertimestamp < timestamp) {
			r.logger(r.xtermTitles,
				fmt.Sprintf(">>> Server out of date: %s",syncuri))
			print()
			print(">>>")
			print(fmt.Sprintf(">>> SERVER OUT OF DATE: %s" , syncuri))
			print(">>>")
			print(fmt.Sprintf(">>> In order to force sync, remove '%s'." , r.servertimestampfile))
			print(">>>")
			print()
			exitcode = SERVER_OUT_OF_DATE
		} else if (servertimestamp == 0) || (servertimestamp > timestamp) {
			command = rsynccommand[:]

			submodule_paths := r._get_submodule_paths()
			if submodule_paths {
				command = append(command, "--relative")
				for path
					in
				submodule_paths {
					command = append(command, syncuri+"/./"+path)
				}
			} else {
				command = append(command, syncuri + "/")
			}

			command = append(command, r.downloadDir)

			exitcode := process.spawn(command,
				**r.spawn_kwargs)
			if exitcode is
		None{
			exitcode = 128 + signal.SIGINT
		}

			if exitcode != 0&&exitcode != 1&&exitcode != 2&&exitcode != 5&&exitcode != 35 {
				if err := syscall.Unlink(r.servertimestampfile); err != nil {
					//except OSError:
					//pass
				} else {
					updatecache_flg = true
				}
			}

			if exitcode == 0 || exitcode == 1 || exitcode == 3 || exitcode == 4 || exitcode == 11 || exitcode == 14 || exitcode == 20 || exitcode == 21 {
				is_synced = true
			}
		}
	} else if exitcode == 1 || exitcode == 3 || exitcode == 4 || exitcode == 11 || exitcode == 14 || exitcode == 20 || exitcode == 21 {
		is_synced = true
	} else {
		//pass
	}
	return local_state_unchanged, is_synced, exitcode, updatecache_flg
}
