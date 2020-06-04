package atom

import (
	"bufio"
	"fmt"
	"github.com/ppphp/shlex"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

var (
	pmsEapiRe          = regexp.MustCompile(`^[ \t]*EAPI=(['"]?)([A-Za-z0-9+_.-]*)\\1[ \t]*([ \t]#.*)?$`)
	commentOrBlankLine = regexp.MustCompile(`^\s*(#.*)?$`)
)

//func init() {
//	err := ebuild("./tmp/app-misc/hello/hello-2.10.ebuild", []string{"merge"}, nil)
//	if err != nil {
//		println(err.Error())
//	}
//}

// the entrance of the ebuild
func ebuild(pkg string, action []string, config map[string]string) error {
	if len(action) == 0 {
		return nil
	}
	santinizeFds()
	if !strings.HasSuffix(pkg, ".ebuild") {
		return nil
	}
	p := path.Join(os.Getenv("PWD"), pkg)
	//d := path.Dir(p)
	//vdbPath := "/var/db/pkg"
	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	eapi := ""
	for scanner.Scan() {
		b := scanner.Bytes()
		if commentOrBlankLine.Match(b) {
			continue
		}
		if eapi = string(pmsEapiRe.Find(b)); eapi != "" {
			break
		}
	}

	for _, a := range action {
		if a == "merge" {
			doPhase(p, "clean")
		}
	}

	return nil
	//cpv := fmt.Sprintf("%v/%v",  strings.TrimSuffix(p, ".ebuild"))
}

func santinizeFds() {

}

//func doEbuild(ebuild, do string) {
//
//}

func iterIuseVars(env map[string]string) [][2]string {
	kv := make([][2]string, 0)

	for _, k := range []string{"IUSE_IMPLICIT", "USE_EXPAND_IMPLICIT", "USE_EXPAND_UNPREFIXED", "USE_EXPAND"} {
		if v, ok := env[k]; ok {
			kv = append(kv, [2]string{k, v})
		}
	}
	re := regexp.MustCompile("\\s+")
	useExpandImplicit := re.Split(env["USE_EXPAND_IMPLICIT"], -1)
	for _, v := range append(re.Split(env["USE_EXPAND_UNPREFIXED"], -1), re.Split(env["USE_EXPAND"], -1)...) {
		equal := false
		for _, k := range useExpandImplicit {
			if k == v {
				equal = true
				break
			}
		}
		if equal {
			k := "USE_EXPAND_VALUES_" + v
			v, ok := env[k]
			if ok {
				kv = append(kv, [2]string{k, v})
			}
		}
	}

	return kv
}

func firstExisting(p string) string {
	for _, pa := range iterParents(p) {
		_, err := os.Lstat(pa)
		if err != nil {
			continue
		}
		return pa
	}
	return string(os.PathSeparator)
}

func iterParents(p string) []string {
	d := []string{}
	d = append(d, p)
	for p != string(os.PathSeparator) {
		p = path.Dir(p)
		d = append(d, p)
	}
	return d
}

// nil, nil, nil
func digestgen(myarchives interface{}, mysettings *Config, myportdb *portdbapi) int {
	if mysettings != nil|| myportdb == nil {
		//raise TypeError("portage.digestgen(): 'mysettings' and 'myportdb' parameter are required.")
	}
	doebuildManifestExemptDepend += 1
	defer func() {doebuildManifestExemptDepend -= 1}()
	distfiles_map := map[string][]string{}
	fetchlist_dict := NewFetchlistDict(mysettings.ValueDict["O"], mysettings, myportdb)
	for cpv:= range fetchlist_dict{
			//try:
		for myfile := range fetchlist_dict[cpv] {
			distfiles_map[myfile] = append(distfiles_map[myfile], cpv)
		}
			//except InvalidDependString as e:
			//	writemsg("!!! %s\n" % str(e), noiselevel=-1)
			//	del e
			//	return 0
	}
	mytree := filepath.Dir(filepath.Dir(mysettings.ValueDict["O"]))
//try:
	rc := mysettings.Repositories.getRepoForLocation(mytree)
	//except KeyError:
	//mytree = os.path.realpath(mytree)
	//mf = mysettings.repositories.get_repo_for_location(mytree)

	repo_required_hashes := rc.manifestRequiredHashes
	if repo_required_hashes == nil {
		repo_required_hashes = CopyMapSB(MANIFEST2_HASH_DEFAULTS)
	}
	mf := rc.load_manifest(mysettings.ValueDict["O"], mysettings.ValueDict["DISTDIR"],
		fetchlist_dict, false)

	if !mf.allow_create {
		WriteMsgStdout(fmt.Sprintf(">>> Skipping creating Manifest for %s; "+
		"repository is configured to not use them\n", mysettings.ValueDict["O"]), 0)
		return 1
	}

	required_hash_types := map[string]bool{}
	required_hash_types["size"] = true
	for k := range repo_required_hashes {
		required_hash_types[k]= true
	}
	dist_hashes := mf.fhashdict["DIST"]
	if dist_hashes == nil {
		dist_hashes = map[string]map[string]string{}
	}

	missing_files := []string{}
	for myfile:= range distfiles_map {

		myhashes := dist_hashes[myfile]
		if len(myhashes) == 0 {
			st, err := os.Stat(filepath.Join(mysettings.ValueDict["DISTDIR"], myfile))
			if err != nil {
				//except OSError:
				//st = None
			}
			if st == nil || st.Size() == 0 {
				missing_files = append(missing_files, myfile)
			}
			continue
		}
		size := myhashes["size"]

		st, err := os.Stat(filepath.Join(mysettings.ValueDict["DISTDIR"], myfile))
		if err != nil {
			//except OSError as e:
			if err != syscall.ENOENT {
				//raise
			}
			//del e
			if size == "" {
				missing_files = append(missing_files, myfile)
				continue
			}
			if required_hash_types.difference(myhashes) {
				missing_files = append(missing_files, myfile)
				continue
			}
		} else {

			if st.Size() == 0 || size != "" && size != fmt.Sprint(st.Size()) {
				missing_files = append(missing_files, myfile)
				continue
			}
		}
	}

	for _, myfile := range missing_files{
		uris := map[string]bool{}
		all_restrict := map[string]bool{}
		for _, cpv := range distfiles_map[myfile]{
			uris.update(myportdb.getFetchMap(
				cpv, mytree = mytree)[myfile])
			restrict = myportdb.aux_get(cpv, ['RESTRICT'], mytree = mytree)[0]
			all_restrict.update(useReduce(restrict,
				flat = true, matchnone = true))

			cat, pf := catsplit(cpv)[0], catsplit(cpv)[1]
			mysettings.ValueDict["CATEGORY"] = cat
			mysettings.ValueDict["PF"] = pf
		}

		mysettings.ValueDict["PORTAGE_RESTRICT"] = joinMB(all_restrict, " ")

	//try:
		st,err  := os.Stat(filepath.Join(mysettings.ValueDict["DISTDIR"], myfile))
		if err != nil {
			//except OSError:
			//st = None
		}
		
		if not fetch( {
		myfile:
			uris
		}, mysettings):
		myebuild = filepath.Join(mysettings.ValueDict["O"],
			catsplit(cpv)[1]+".ebuild")
		spawn_nofetch(myportdb, myebuild)
		WriteMsg(fmt.Sprintf("!!! Fetch failed for %s, can't update Manifest\n",
		 myfile),  -1, nil)
		if Inmsmss(
		dist_hashes, myfile)&& st!= nil&&st.Size() > 0{
			cmd := colorize("INFORM", fmt.Sprintf("ebuild --force %s manifest", filepath.Base(myebuild)))
			WriteMsg(fmt.Sprintf(
				"!!! If you would like to forcefully replace the existing Manifest entry\n"+
			"!!! for %s, use the following command:\n", myfile) +
			 fmt.Sprintf("!!!    %s\n" , cmd),
			 -1, nil)
		}
		return 0
	}

	WriteMsgStdout(fmt.Sprintf(">>> Creating Manifest for %s\n", mysettings.ValueDict["O"]), 0)
//try:
	mf.create(false, true,
	mysettings.Features.Features["assume-digests"], nil)
	//except FileNotFound as e:
	//WriteMsg(_("!!! File %s doesn't exist, can't update Manifest\n")
	//% e, noiselevel = -1)
	//return 0
	//except PortagePackageException as e:
	//WriteMsg(("!!! %s\n") % (e, ), noiselevel = -1)
	//return 0
//try:
	mf.write(false, false)
	//except PermissionDenied as e:
	//WriteMsg(_("!!! Permission Denied: %s\n") % (e, ), noiselevel = -1)
	//return 0
	if  !mysettings.Features.Features["assume-digests"]{
		distlist := []string{}
		for  k := range mf.fhashdict["DIST"]{
			distlist =append(distlist, k)
		}
		sort.Strings(distlist)
		auto_assumed:= []string{}
		for _, filename:= range distlist {
			if ! pathExists(
				filepath.Join(mysettings.ValueDict["DISTDIR"], filename)) {
				auto_assumed =append(auto_assumed, filename)
			}
		}
		if len(auto_assumed) > 0{
			sp := strings.Split(mysettings.ValueDict["O"],string(os.PathSeparator))
			cp := strings.Join(sp[len(sp)-2:], string(os.PathSeparator))
			pkgs := myportdb.cp_list(cp, mytree = mytree)
			pkgs.sort()
			WriteMsgStdout("  digest.assumed" + colorize("WARN",
				fmt.Sprintf("%18d", len(auto_assumed))) + "\n", 0)
			for _, pkg_key := range pkgs{
				fetchlist = myportdb.getFetchMap(pkg_key, mytree = mytree)
				pv := strings.Split(pkg_key, "/")[1]
				for _, filename := range auto_assumed {
					if filename in
					fetchlist{
						WriteMsgStdout(fmt.Sprintf(
							"   %s::%s\n", pv, filename), 0)
					}
				}
			}
		}
	}
	return 1
}

var (
	_unsandboxed_phases = map[string]bool{
		"clean": true, "cleanrm": true, "config": true,
		"help": true, "info": true, "postinst": true,
		"preinst": true, "pretend": true, "postrm": true,
		"prerm": true, "setup": true,
	}

_ipc_phases = map[string]bool{
	"setup": true, "pretend": true, "config": true, "info": true,
	"preinst": true, "postinst": true, "prerm": true, "postrm": true,
}

_global_pid_phases = map[string]bool{
"config":true, "depend":true, "preinst":true, "prerm":true, "postinst":true, "postrm":true,}

_phase_func_map = map[string]string{
	"config":    "pkg_config",
	"setup":     "pkg_setup",
	"nofetch":   "pkg_nofetch",
	"unpack":    "src_unpack",
	"prepare":   "src_prepare",
	"configure": "src_configure",
	"compile":   "src_compile",
	"test":      "src_test",
	"install":   "src_install",
	"preinst":   "pkg_preinst",
	"postinst":  "pkg_postinst",
	"prerm":     "pkg_prerm",
	"postrm":    "pkg_postrm",
	"info":      "pkg_info",
	"pretend":   "pkg_pretend",
}

_vdb_use_conditional_keys = append([]string{"BDEPEND", "DEPEND", "HDEPEND", "PDEPEND", "RDEPEND"}, 
"LICENSE", "PROPERTIES", "RESTRICT",)
)

func _doebuild_spawn(phase string, settings *Config, actionmap=None, **kwargs)([]int,error) {

	if _unsandboxed_phases[phase] {
		kwargs["free"] = true
	}

	kwargs["ipc"] = !settings.Features.Features["ipc-sandbox"] || _ipc_phases[phase]
	kwargs["mountns"] = settings.Features.Features["mount-sandbox"]
	kwargs["networked"] = !settings.Features.Features["network-sandbox"] || (phase == "unpack" &&
		Ins(strings.Fields(settings.configDict["pkg"]["PROPERTIES"]), "live")) ||
		_ipc_phases[phase] ||
		Ins(strings.Fields(settings.ValueDict["PORTAGE_RESTRICT"]), "network-sandbox")
	kwargs["pidns"] = settings.Features.Features["pid-sandbox"] &&
		!_global_pid_phases[phase]

	if phase == "depend" {
		kwargs["droppriv"] = settings.Features.Features["userpriv"]
		kwargs["close_fds"] = false
	}
	cmd := ""
	if actionmap != nil && actionmap[phase]{
		kwargs.update(actionmap[phase]["args"])
		cmd = fmt.Sprintf(actionmap[phase]["cmd"], phase)
	} else {
		ebuild_sh_arg := phase
		if phase == "cleanrm" {
			ebuild_sh_arg = "clean"
		}
		cmd = fmt.Sprintf("%s %s", ShellQuote(
			filepath.Join(settings.ValueDict["PORTAGE_BIN_PATH"],
				filepath.Base(EBUILD_SH_BINARY))),
			ebuild_sh_arg)
	}

		settings.ValueDict["EBUILD_PHASE"] = phase
		defer delete(settings.ValueDict, "EBUILD_PHASE")
		return spawn(cmd, settings, **kwargs)
}

// nil, false, nil,
func _spawn_phase(phase string, settings *Config, actionmap=None, returnpid bool,
logfile=None, **kwargs) ([]int, error){

	if returnpid {
		return _doebuild_spawn(phase, settings, actionmap,
			returnpid = returnpid, logfile=logfile, **kwargs)
	}

	ebuild_phase := NewEbuildPhase(actionmap = actionmap, background = false,
		phase=phase, scheduler = SchedulerInterface(asyncio._safe_loop()),
		settings=settings, **kwargs)

	ebuild_phase.start()
	ebuild_phase.wait()
	return []int{*ebuild_phase.returncode}, nil
}

// ""
func _doebuild_path(settings *Config, eapi string) {

	portage_bin_path := []string{settings.ValueDict["PORTAGE_BIN_PATH"]}
	if portage_bin_path[0] != PORTAGE_BIN_PATH {

		portage_bin_path = append(portage_bin_path, PORTAGE_BIN_PATH)
	}
	prerootpath := []string{}
	for _, x := range strings.Split(settings.ValueDict["PREROOTPATH"], ":") {
		if x != "" {
			prerootpath = append(prerootpath, x)
		}
	}
	rootpath := []string{}
	for _, x := range strings.Split(settings.ValueDict["ROOTPATH"], ":") {
		if x != "" {
			rootpath = append(rootpath, x)
		}
	}
	rootpath_set := map[string]bool{}
	for _, v := range (rootpath) {
		rootpath_set[v] = true
	}
	overrides := []string{}
	for _, x := range strings.Split(settings.ValueDict[
		"__PORTAGE_TEST_PATH_OVERRIDE"], ":") {
		if x != "" {
			overrides = append(overrides, x)
		}

	}

	prefixes := []string{}

	if EPREFIX != settings.ValueDict["EPREFIX"] && settings.ValueDict["ROOT"] == string(os.PathSeparator) {
		prefixes = append(prefixes, settings.ValueDict["EPREFIX"])
	}
	prefixes = append(prefixes, EPREFIX)

	path := overrides

	if settings.Features.Features["xattr"] {
		for _, x := range portage_bin_path {
			path = append(path, filepath.Join(x, "ebuild-helpers", "xattr"))
		}
	}

	if uid != 0 &&
		settings.Features.Features["unprivileged"] &&
		!settings.Features.Features["fakeroot"] {
		for _, x := range portage_bin_path {
			path = append(path, filepath.Join(x,
				"ebuild-helpers", "unprivileged"))
		}
	}

	if v, ok := settings.ValueDict["USERLAND"]; ok && v != "GNU" {
		for _, x := range portage_bin_path {
			path = append(path, filepath.Join(x, "ebuild-helpers", "bsd"))
		}
	}

	for _, x := range portage_bin_path {
		path = append(path, filepath.Join(x, "ebuild-helpers"))
	}
	path = append(path, prerootpath...)

	for _, prefix := range prefixes {
		if prefix == "" {
			prefix = "/"
		}
		for _, x := range []string{"usr/local/sbin", "usr/local/bin", "usr/sbin", "usr/bin", "sbin", "bin"} {
			x_abs := filepath.Join(prefix, x)
			if !rootpath_set[x_abs] {
				path = append(path, x_abs)
			}
		}
	}

	path = append(path, rootpath...)
	settings.ValueDict["PATH"] = strings.Join(path, ":")
}

// nil, nil, false, nil, nil
func doebuild_environment(myebuild , mydo string, myroot=None, settings *Config,
debug bool, use_cache=None, db *vardbapi) {

	if settings == nil {
		//raise TypeError("settings argument is required")
	}

	if db == nil {
		//raise TypeError("db argument is required")
	}

	mysettings := settings
	mydbapi := db
	ebuild_path, _ := filepath.Abs(myebuild)
	pkg_dir := filepath.Dir(ebuild_path)
	mytree := filepath.Dir(filepath.Dir(pkg_dir))
	mypv := filepath.Base(ebuild_path)[:len(filepath.Base(ebuild_path))-7]
	mysplit := pkgSplit(mypv, mysettings.configDict["pkg"]["EAPI"])
	if mysplit == [3]string{} {
		//raise IncorrectParameter(
		//_("Invalid ebuild path: '%s'") % myebuild)
	}

	cat := ""
	mycpv := ""
	if _, ok := mysettings.configDict["pkg"]["CATEGORY"]; mysettings.mycpv != nil &&
		mysettings.configDict["pkg"]["PF"] == mypv && ok {

		cat = mysettings.configDict["pkg"]["CATEGORY"]
		mycpv = mysettings.mycpv.string
	} else if filepath.Base(pkg_dir) == mysplit[0] || filepath.Base(pkg_dir) == mypv {
		cat = filepath.Base(filepath.Dir(pkg_dir))
		mycpv = cat + "/" + mypv
	} else {
		raise AssertionError("unable to determine CATEGORY")
	}

	tmpdir := mysettings.ValueDict["PORTAGE_TMPDIR"]

	if mydo == "depend" {
		if mycpv != mysettings.mycpv {
			mysettings.SetCpv(mycpv, nil)
		}
	} else {

		if _, ok := mysettings.configDict["pkg"]["EAPI"]; mycpv != mysettings.mycpv.string ||
			!ok {

			mysettings.reload()
			mysettings.reset()
			mysettings.SetCpv(mycpv, mydbapi)
		}
	}

	mysettings.ValueDict["PORTAGE_TMPDIR"], _ = filepath.EvalSymlinks(tmpdir)

	delete(mysettings.ValueDict, "EBUILD_PHASE")
	mysettings.ValueDict["EBUILD_PHASE"] = mydo

	//mysettings.ValueDict["PORTAGE_PYTHON"] = _python_interpreter

	mysettings.ValueDict["PORTAGE_SIGPIPE_STATUS"] = fmt.Sprint(128 + unix.SIGPIPE)

	mysettings.ValueDict["BASH_ENV"] = InvalidEnvFile

	if debug {

		mysettings.ValueDict["PORTAGE_DEBUG"] = "1"

		mysettings.ValueDict["EBUILD"] = ebuild_path
		mysettings.ValueDict["O"] = pkg_dir
		mysettings.configDict["pkg"]["CATEGORY"] = cat
		mysettings.ValueDict["PF"] = mypv
	}

	if hasattr(mydbapi, "repositories") {
		repo := mydbapi.repositories.get_repo_for_location(mytree)
		mysettings.ValueDict["PORTDIR"] = repo.eclass_db.porttrees[0]
		mysettings.ValueDict["PORTAGE_ECLASS_LOCATIONS"] = repo.eclass_db.eclass_locations_string
		mysettings.configDict["pkg"]["PORTAGE_REPO_NAME"] = repo.name
	}

	mysettings.ValueDict["PORTDIR"], _ = filepath.EvalSymlinks(mysettings.ValueDict["PORTDIR"])
	delete(mysettings.ValueDict, "PORTDIR_OVERLAY")
	mysettings.ValueDict["DISTDIR"], _ = filepath.EvalSymlinks(mysettings.ValueDict["DISTDIR"])
	mysettings.ValueDict["RPMDIR"], _ = filepath.EvalSymlinks(mysettings.ValueDict["RPMDIR"])

	mysettings.ValueDict["ECLASSDIR"] = mysettings.ValueDict["PORTDIR"] + "/eclass"

	mysettings.ValueDict["PORTAGE_BASHRC_FILES"] = "\n".join(mysettings.pbashrc)

	mysettings.ValueDict["P"] = mysplit[0] + "-" + mysplit[1]
	mysettings.ValueDict["PN"] = mysplit[0]
	mysettings.ValueDict["PV"] = mysplit[1]
	mysettings.ValueDict["PR"] = mysplit[2]

	if noiseLimit < 0 {
		mysettings.ValueDict["PORTAGE_QUIET"] = "1"
	}

	if mysplit[2] == "r0" {
		mysettings.ValueDict["PVR"] = mysplit[1]
	} else {
		mysettings.ValueDict["PVR"] = mysplit[1] + "-" + mysplit[2]
	}

	mysettings.ValueDict["BUILD_PREFIX"] = mysettings.ValueDict["PORTAGE_TMPDIR"] + "/portage"
	mysettings.ValueDict["PKG_TMPDIR"] = mysettings.ValueDict["BUILD_PREFIX"] + "/._unmerge_"

	if mydo in("unmerge", "prerm", "postrm", "cleanrm") {
		mysettings.ValueDict["PORTAGE_BUILDDIR"] = filepath.Join(
			mysettings.ValueDict["PKG_TMPDIR"],
			mysettings.ValueDict["CATEGORY"], mysettings.ValueDict["PF"])
	} else {
		mysettings.ValueDict["PORTAGE_BUILDDIR"] = filepath.Join(
			mysettings.ValueDict["BUILD_PREFIX"],
			mysettings.ValueDict["CATEGORY"], mysettings.ValueDict["PF"])
	}

	mysettings.ValueDict["HOME"] = filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], "homedir")
	mysettings.ValueDict["WORKDIR"] = filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], "work")
	mysettings.ValueDict["D"] = filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], "image") + string(os.PathSeparator)
	mysettings.ValueDict["T"] = filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], "temp")
	mysettings.ValueDict["SANDBOX_LOG"] = filepath.Join(mysettings.ValueDict["T"], "sandbox.log")
	mysettings.ValueDict["FILESDIR"] = filepath.Join(settings.ValueDict["PORTAGE_BUILDDIR"], "files")

	eprefix_lstrip := strings.TrimLeft(mysettings.ValueDict["EPREFIX"], string(os.PathSeparator))
	mysettings.ValueDict["ED"] = strings.TrimRight(filepath.Join(
		mysettings.ValueDict["D"], eprefix_lstrip), string(os.PathSeparator)) + string(os.PathSeparator)

	mysettings.ValueDict["PORTAGE_BASHRC"] = filepath.Join(
		mysettings.ValueDict["PORTAGE_CONFIGROOT"], EbuildShEnvFile)
	mysettings.ValueDict["PM_EBUILD_HOOK_DIR"] = filepath.Join(
		mysettings.ValueDict["PORTAGE_CONFIGROOT"], EbuildShEnvDir)

	mysettings.ValueDict["PORTAGE_COLORMAP"] = ColorMap()

	if _, ok := mysettings.ValueDict["COLUMNS"]; !ok {
		columns := os.Getenv("COLUMNS")
		if columns == "" {
			_, columnsi, _ := get_term_size(0)
			if columnsi < 1 {
				columnsi = 80
			}
			columns = fmt.Sprint(columnsi)
			os.Setenv("COLUMNS", columns)
		}
		mysettings.ValueDict["COLUMNS"] = columns
	}

	eapi := mysettings.configDict["pkg"]["EAPI"]
	_doebuild_path(mysettings, eapi)

	if !eapiIsSupported(eapi) {
		//raise UnsupportedAPIException(mycpv, eapi)
	}

	if _, ok :=mysettings.configDict["pkg"]["PORTAGE_REPO_NAME"]; eapiExportsRepository(eapi) &&  ok{
		mysettings.configDict["pkg"]["REPOSITORY"] = mysettings.configDict["pkg"]["PORTAGE_REPO_NAME"]
	}

	if mydo != "depend" {
		_, ok1 := mysettings.configDict["pkg"]["A"]
		_, ok2 := mysettings.configDict["pkg"]["AA"]
		if hasattr(mydbapi, "getFetchMap") &&
			(!ok1 || !ok2) {
			src_uri := mysettings.configDict["pkg"]["SRC_URI"]
			if src_uri == "" {
				src_uri, = mydbapi.aux_get(mysettings.mycpv,
					["SRC_URI"], mytree = mytree)
			}
			metadata = map[string]string{
				"EAPI":    eapi,
				"SRC_URI": src_uri,
			}
			use := map[string]bool{}
			for _, v := range strings.Fields(mysettings.ValueDict["PORTAGE_USE"]) {
				use[v] = true
			}
			//try{
			uri_map := _parse_uri_map(mysettings.mycpv, metadata, use)
			//except InvalidDependString{
			//mysettings.configDict["pkg"]["A"] = ""
			//}else{
			mysettings.configDict["pkg"]["A"] = strings.Join(uri_map, " ")
		}

		//try{
		uri_map := _parse_uri_map(nil, metadata, nil)
		//except InvalidDependString{
		//mysettings.configDict["pkg"]["AA"] = ""
		//}else{
		um := []string{}
		for u := range uri_map {
			um = append(um, u)
		}
		mysettings.configDict["pkg"]["AA"] = strings.Join(um, " ")

		ccache := mysettings.Features.Features["ccache"]
		distcc := mysettings.Features.Features["distcc"]
		icecream := mysettings.Features.Features["icecream"]

		if (ccache || distcc || icecream) && Ins([]string{"unpack",
			"prepare", "configure", "test", "install"}, mydo) {
			libdir := ""
			default_abi := mysettings.ValueDict["DEFAULT_ABI"]
			if default_abi != "" {
				libdir = mysettings.ValueDict["LIBDIR_"+default_abi]
			}
			if libdir == "" {
				libdir = "lib"
			}

			possible_libexecdirs := []string{libdir, "lib", "libexec"}
			masquerades := [][2]string{}
			if distcc {
				masquerades = append(masquerades, [2]string{"distcc", "distcc"})
			}
			if icecream {
				masquerades = append(masquerades, [2]string{"icecream", "icecc"})
			}
			if ccache {
				masquerades = append(masquerades, [2]string{"ccache", "ccache"})
			}

			for _, v := range masquerades {
				feature, m := v[0], v[1]
				for _, l:= range possible_libexecdirs{
					p := filepath.Join(string(os.PathSeparator), eprefix_lstrip,
					"usr", l, m, "bin")
					if st, _ := os.Stat(p); st != nil && st.IsDir() {
						mysettings.ValueDict["PATH"] = p + ":" + mysettings.ValueDict["PATH"]
						break
					}
				} else {
					WriteMsg(fmt.Sprintf("Warning: %s requested but no masquerade dir "+
						"can be found in /usr/lib*/%s/bin\n", m, m), 0, nil)
					delete(mysettings.Features.Features, feature)
				}
			}
		}

		if _, ok := mysettings.ValueDict["MAKEOPTS"]; !ok {
			nproc := getCPUCount()
			if nproc != 0 {
				mysettings.ValueDict["MAKEOPTS"] = fmt.Sprintf("-j%d", nproc)
			}
		}

		if !eapiExportsKv(eapi) {
			delete(mysettings.ValueDict, "KV")
		} else if _, ok := mysettings.ValueDict["KV"]; !ok &&
			Ins([]string{"compile", "config", "configure", "info",
				"install", "nofetch", "postinst", "postrm", "preinst",
				"prepare", "prerm", "setup", "test", "unpack"}, mydo) {
			mykv, err1 := ExtractKernelVersion(
				filepath.Join(mysettings.ValueDict["EROOT"], "usr/src/linux"))
			if mykv != "" {
				mysettings.ValueDict["KV"] = mykv
			} else {
				mysettings.ValueDict["KV"] = ""
			}
			mysettings.BackupChanges("KV")
		}

		binpkg_compression, ok := mysettings.ValueDict["BINPKG_COMPRESS"]
		if !ok {
			binpkg_compression = "bzip2"
		}
		//try{
		compression := _compressors[binpkg_compression]
		//except KeyError as e{
		//if binpkg_compression{
		//WriteMsg(fmt.Sprintf("Warning: Invalid or unsupported compression method: %s\n" % e.args[0])
		//}else{

		mysettings.ValueDict["PORTAGE_COMPRESSION_COMMAND"] = "cat"
		//}else{
		//try{
		compression_binarys, _ := shlex.Split(strings.NewReader(varExpand(compression["compress"], settings.ValueDict, "")), false, true)
		compression_binary := compression_binarys[0]
		//except IndexError as e{
		//WriteMsg(fmt.Sprintf("Warning: Invalid or unsupported compression method: %s\n" % e.args[0])
		//}else{
		if FindBinary(compression_binary) == "" {
			missing_package := compression["package"]
			WriteMsg(fmt.Sprintf("Warning: File compression unsupported %s. Missing package: %s\n", binpkg_compression, missing_package), 0, nil)
			//}else{
			ss, _ := shlex.Split(strings.NewReader(compression["compress"]), false, true)
			cmds := []string{}
			for _, x := range ss {
				cmds = append(cmds, varExpand(x, settings.ValueDict, ""))
			}
			cmd := []string{}
			for _, c := range cmds {
				if c != "" {
					cmd = append(cmd, c)
				}
			}

			mysettings.ValueDict["PORTAGE_COMPRESSION_COMMAND"] = strings.Join(cmd, " ")
		}
	}
}

var (
	_doebuild_manifest_cache *Manifest= nil
_doebuild_broken_ebuilds = map[string]bool{}
_doebuild_broken_manifests = map[string]bool{}
_doebuild_commands_without_builddir = []string{
	"clean", "cleanrm", "depend", "digest",
	"fetch", "fetchall", "help", "manifest",
}
)

// 0, 0, 0, 0, 1, 0, "", nil, nil, nil, nil, false
func doebuild(myebuild, mydo string, settings *Config, debug, listonly,
fetchonly, cleanup, use_cache, fetchall int, tree string,
mydbapi *vardbapi, vartree *varTree, prev_mtimes=None,
fd_pipes=None, returnpid bool) int {
if settings == nil{
//raise TypeError("settings parameter is required")
}
mysettings := settings
myroot := settings.ValueDict["EROOT"]

if tree== "" {
	WriteMsg("Warning: tree not specified to doebuild\n", -1, nil)
	tree = "porttree"
}

actionmap_deps:=map[string][]string{
"pretend"  : {},
"setup":  {"pretend"},
"unpack": {"setup"},
"prepare": {"unpack"},
"configure": {"prepare"},
"compile":{"configure"},
"test":   {"compile"},
"install":{"test"},
"instprep":{"install"},
"rpm":    {"install"},
"package":{"install"},
"merge"  :{"install"},
}

if mydbapi == nil {
	switch tree {
	case "vartree":
		mydbapi = Db().Values()[myroot].VarTree().dbapi
	case "porttree":
		mydbapi = Db().Values()[myroot].PortTree().dbapi
	case "bintree":
		mydbapi = Db().Values()[myroot].BinTree().dbapi
	}
}

if vartree == nil && Ins([]string{"merge", "qmerge", "unmerge"}, mydo) {
	vartree = Db().Values()[myroot].VarTree()
}

features := mysettings.Features.Features

clean_phases := []string{"clean", "cleanrm"}
validcommands := []string{"help","clean","prerm","postrm","cleanrm","preinst","postinst",
"config", "info", "setup", "depend", "pretend",
"fetch", "fetchall", "digest",
"unpack", "prepare", "configure", "compile", "test",
"install", "instprep", "rpm", "qmerge", "merge",
"package", "unmerge", "manifest", "nofetch",}

if ! Ins(validcommands,mydo) {
	sort.Strings(validcommands)
	WriteMsg(fmt.Sprintf("!!! doebuild: '%s' is not one of the following valid commands:", mydo), -1, nil)
	for vcount := range validcommands {
		if vcount%6 == 0 {
			WriteMsg("\n!!! ", -1, nil)
		}
		WriteMsg(fmt.Sprintf("%11s", validcommands[vcount]), -1, nil)
	}
	WriteMsg("\n", -1, nil)
	return 1
}

if returnpid && mydo != "depend" {
	warnings.warn("portage.doebuild() called "
	"with returnpid parameter enabled. This usage will "
	"not be supported in the future.",
		DeprecationWarning, stacklevel = 2)
}

if mydo == "fetchall" {
	fetchall = 1
	mydo = "fetch"
}

if !Ins(clean_phases,mydo) && ! pathExists(myebuild) {
	WriteMsg(fmt.Sprintf("!!! doebuild: %s not found for %s\n", myebuild, mydo), -1, nil)
	return 1
}

pkgdir := filepath.Dir(myebuild)
manifest_path := filepath.Join(pkgdir, "Manifest")
var repo_config *RepoConfig = nil
if tree == "porttree"{
repo_config = mysettings.Repositories.getRepoForLocation(
filepath.Dir(filepath.Dir(pkgdir)))
}

var mf  *Manifest= nil
if  features["strict"] &&
 ! features["digest"] &&
tree == "porttree" &&
! repo_config.thinManifest &&
! Ins([]string{"digest", "manifest", "help"}, mydo) &&
doebuildManifestExemptDepend==0 &&
! (repo_config.allowMissingManifest && ! pathExists(manifest_path)) {

	if _doebuild_broken_ebuilds[myebuild] {
		return 1
	}

	if _doebuild_manifest_cache == nil ||
		_doebuild_manifest_cache.getFullname() != manifest_path {
		_doebuild_manifest_cache = nil
		if !pathExists(manifest_path) {
			out := NewEOutput(false)
			out.eerror(fmt.Sprintf("Manifest not found for '%s'", myebuild, ))
			_doebuild_broken_ebuilds[myebuild] = true
			return 1
		}
		mf = repo_config.load_manifest(pkgdir, mysettings.ValueDict["DISTDIR"], nil, false)

	} else {
		mf = _doebuild_manifest_cache
	}

	//try{
	mf.checkFileHashes("EBUILD", filepath.Base(myebuild), false, nil)
	//except KeyError{
	//if ! (mf.allow_missing and
	//filepath.Base(myebuild) ! in mf.fhashdict["EBUILD"]){
	//out = NewEOutput(false)
	//out.eerror(fmt.Sprintf(("Missing digest for '%s'") % (myebuild,))
	//_doebuild_broken_ebuilds.add(myebuild)
	//return 1
	//except File!Found{
	//out = NewEOutput(false)
	//out.eerror(fmt.Sprintf(("A file listed in the Manifest "
	//"could not be found: '%s'") % (myebuild,))
	//_doebuild_broken_ebuilds.add(myebuild)
	//return 1
	//except DigestException as e{
	//out = NewEOutput(false)
	//out.eerror(_("Digest verification failed:"))
	//out.eerror(fmt.Sprintf("%s" % e.value[0])
	//out.eerror(fmt.Sprintf(("Reason: %s") % e.value[1])
	//out.eerror(fmt.Sprintf(("Got: %s") % e.value[2])
	//out.eerror(fmt.Sprintf(("Expected: %s") % e.value[3])
	//_doebuild_broken_ebuilds.add(myebuild)
	//return 1

	if _doebuild_broken_manifests[mf.getFullname()] {
		return 1
	}

	if mf != _doebuild_manifest_cache && !mf.allow_missing {
		fs, _ := ioutil.ReadDir(pkgdir)
		for _, f := range fs {
			pf := ""
			if f.Name()[len(f.Name())-7:] == ".ebuild" {
				pf = f.Name()[:len(f.Name())-7]
				if pf != "" && !mf.hasFile("EBUILD", f.Name()) {
					fn := filepath.Join(pkgdir, f.Name())
					if !_doebuild_broken_ebuilds[fn] {
						out := NewEOutput(false)
						out.eerror(fmt.Sprintf("A file is not listed in the "+
							"Manifest: '%s'", fn, ))
					}
					_doebuild_broken_manifests[manifest_path] = true
					return 1
				}
			}
		}
	}

	_doebuild_manifest_cache = mf
}

logfile:=""
builddir_lock = None
tmpdir := ""
tmpdir_orig := ""

//try{
defer func() {

	if builddir_lock != nil {
		builddir_lock.scheduler.run_until_complete(
			builddir_lock.async_unlock())
	}
	if tmpdir != "" {
		mysettings.ValueDict["PORTAGE_TMPDIR"] = tmpdir_orig
		os.RemoveAll(tmpdir)
	}

	delete(mysettings.ValueDict, "REPLACING_VERSIONS")

	if logfile != "" && !returnpid {
		//try{
		if st, _ := os.Stat(logfile); st != nil && st.Size() == 0 {
			syscall.Unlink(logfile)
		}
		//except OSError{
		//pass
	}

	if Ins([]string{"digest", "manifest", "help"}, mydo) {
		doebuildManifestExemptDepend -= 1
	}
}()

if Ins([]string{"digest", "manifest", "help"}, mydo) {
	doebuildManifestExemptDepend += 1
}

if ! returnpid && mydo =="info" {
	tmpdir = tempfile.mkdtemp()
	tmpdir_orig = mysettings.ValueDict["PORTAGE_TMPDIR"]
	mysettings.ValueDict["PORTAGE_TMPDIR"] = tmpdir
}

doebuild_environment(myebuild, mydo, myroot, mysettings, debug!= 0,
use_cache, mydbapi)

if Ins( clean_phases, mydo) {
	builddir_lock = nil
	if !returnpid &&
		!Inmss(mysettings.ValueDict, "PORTAGE_BUILDDIR_LOCKED") {
		builddir_lock = EbuildBuildDir(
			scheduler = asyncio._safe_loop(),
			settings = mysettings)
		builddir_lock.scheduler.run_until_complete(
			builddir_lock.async_lock())
	}
	defer func() {

		if builddir_lock != nil {
			builddir_lock.scheduler.run_until_complete(
				builddir_lock.async_unlock())
		}
	}()
	return _spawn_phase(mydo, mysettings,
		fd_pipes = fd_pipes, returnpid = returnpid)
}

if mydo == "depend" {
	WriteMsg(fmt.Sprintf("!!! DEBUG: dbkey: %s\n", dbkey), 2)
	if returnpid {
		return _spawn_phase(mydo, mysettings,
			fd_pipes = fd_pipes, returnpid = returnpid)
	} else if dbkey != ""{
		mysettings.ValueDict["dbkey"] = dbkey
	} else {
		mysettings.ValueDict["dbkey"] =
			filepath.Join(mysettings.depcachedir, "aux_db_key_temp")
	}

	return _spawn_phase(mydo, mysettings,
		fd_pipes = fd_pipes, returnpid = returnpid)

}else if mydo == "nofetch" {

	if returnpid {
		WriteMsg(fmt.Sprintf("!!! doebuild: %s\n",
			fmt.Sprintf("returnpid is not supported for phase '%s'\n", mydo)),
			-1, nil)
	}
	return spawn_nofetch(mydbapi, myebuild, settings = mysettings,
		fd_pipes = fd_pipes)
}

if tree == "porttree" {
	if !returnpid {
		rval := _validate_deps(mysettings, myroot, mydo, mydbapi)
		if rval != 0 {
			return rval
		}
	}
}else {

	if mysettings.Features.Features["noauto"] {
		mysettings.Features.Discard("noauto")
	}
}

if tmpdir == nil &&
 ! Ins( _doebuild_commands_without_builddir,mydo) {
	rval := _check_temp_dir(mysettings)
	if rval != 0 {
		return rval
	}
}

if mydo == "unmerge" {
	if returnpid {
		WriteMsg(fmt.Sprintf("!!! doebuild: %s\n",
			fmt.Sprintf("returnpid is not supported for phase '%s'\n", mydo)),
			-1, nil)
	}
	return unmerge(mysettings.ValueDict["CATEGORY"],
		mysettings.ValueDict["PF"], myroot, mysettings, vartree = vartree)
}

phases_to_run := map[string]bool{}
if returnpid || mysettings.Features.Features["noauto"] || ! Inmsss(actionmap_deps,mydo){
phases_to_run[mydo]=true
}else{
		phase_stack := []string{mydo}
		for len(phase_stack) > 0 {
			x := phase_stack[len(phase_stack)-1]
			phase_stack = phase_stack[:len(phase_stack)-1]
			if phases_to_run[x] {
				continue
			}
			phases_to_run[x] = true
			phase_stack = append(phase_stack, actionmap_deps[x]...)
		}
	}

alist := map[string]bool{}
for _ ,v := range strings.Fields(mysettings.configDict["pkg"]["A"]){
alist[v]=true
}

unpacked := false
if tree != "porttree" ||
 Ins( _doebuild_commands_without_builddir, mydo){
//pass
}else if !  phases_to_run["unpack" ]{
unpacked = pathExists(filepath.Join(
mysettings.ValueDict["PORTAGE_BUILDDIR"], ".unpacked"))
}else {
	workdir_st, err := os.Stat(mysettings.ValueDict["WORKDIR"])
	if err != nil {
		//except OSError{
		//pass
	} else {
		newstuff := false
		if !pathExists(filepath.Join(
			mysettings.ValueDict["PORTAGE_BUILDDIR"], ".unpacked")) {
			WriteMsgStdout(fmt.Sprintf(
				">>> Not marked as unpacked; recreating WORKDIR...\n"), 0)
			newstuff = true
		} else {
			for x := range alist {
				WriteMsgStdout(fmt.Sprintf(">>> Checking %s's mtime...\n", x), 0)
				x_st, err := os.Stat(filepath.Join(
					mysettings.ValueDict["DISTDIR"], x))
				if err != nil {
					//except OSError{
					x_st = nil
				}

				if x_st != nil && x_st.ModTime().Nanosecond() > workdir_st.ModTime().Nanosecond() {
					WriteMsgStdout(fmt.Sprintf(">>> Timestamp of "+
						"%s has changed; recreating WORKDIR...\n", x), 0)
					newstuff = true
					break
				}
			}
		}

		if newstuff {
			if builddir_lock == nil && !Inmss(mysettings.ValueDict, "PORTAGE_BUILDDIR_LOCKED") {
				builddir_lock = EbuildBuildDir(
					scheduler = asyncio._safe_loop(),
					settings = mysettings)
				builddir_lock.scheduler.run_until_complete(
					builddir_lock.async_lock())
			}
			//try{
			_spawn_phase("clean", mysettings)
			//finally{
			if builddir_lock != nil {
				builddir_lock.scheduler.run_until_complete(
					builddir_lock.async_unlock())
				builddir_lock = nil
			}
		} else {
			WriteMsgStdout((">>> WORKDIR is up-to-date, keeping...\n"), 0)
			unpacked = true
		}
	}
}

have_build_dirs := false
if ! Ins([]string{"digest", "fetch", "help", "manifest"}, mydo) {
	if !returnpid && !Inmss(mysettings.ValueDict, "PORTAGE_BUILDDIR_LOCKED") {
		builddir_lock = EbuildBuildDir(
			scheduler = asyncio._safe_loop(),
			settings = mysettings)
		builddir_lock.scheduler.run_until_complete(
			builddir_lock.async_lock())
	}
	mystatus := prepare_build_dirs(myroot, mysettings, cleanup)
	if mystatus {
		return mystatus
	}
	have_build_dirs = true

	if !returnpid {
		logfile = mysettings.ValueDict["PORTAGE_LOG_FILE"]
	}
}

if have_build_dirs {
	rval := _prepare_env_file(mysettings)
	if rval != 0 {
		return rval
	}
}

if eapiExportsMergeType(mysettings.ValueDict["EAPI"]) &&
 ! Inmss( mysettings.configDict["pkg"],"MERGE_TYPE") {
	if tree == "porttree" {
		mysettings.configDict["pkg"]["MERGE_TYPE"] = "source"
	} else if tree == "bintree" {
		mysettings.configDict["pkg"]["MERGE_TYPE"] = "binary"
	}
}

if tree == "porttree"{
mysettings.configDict["pkg"]["EMERGE_FROM"] = "ebuild"
}else if tree == "bintree" {
	mysettings.configDict["pkg"]["EMERGE_FROM"] = "binary"
}

if eapiExportsReplaceVars(mysettings.ValueDict["EAPI"]) &&
( Ins ([]string{"postinst", "preinst", "pretend", "setup"},mydo) ||
( !  features["noauto"] && ! returnpid &&
( insss(actionmap_deps,mydo) ||  Ins ([]string{"merge", "package", "qmerge"},mydo)))){
if ! vartree{
WriteMsg("Warning: vartree not given to doebuild. " +
"Cannot set REPLACING_VERSIONS in pkg_{pretend,setup}\n", 0 , nil)
}else{
vardb := vartree.dbapi
cpv := mysettings.mycpv
cpv_slot := fmt.Sprintf("%s%s%s" , cpv.cp, portage.dep._slot_separator, cpv.slot)
mysettings.ValueDict["REPLACING_VERSIONS"] := strings.Join(
set(portage.versions.cpv_getversion(match)
for match in vardb.match(cpv_slot) +
vardb.match("="+cpv))," ")
}
}

if Ins ([]string{"config", "help", "info", "postinst",
"preinst", "pretend", "postrm", "prerm"}, mydo) {
	if mydo == "preinst" || mydo == "postinst" {
		env_file := filepath.Join(filepath.Dir(mysettings.ValueDict["EBUILD"]),
			"environment.bz2")
		if os.path.isfile(env_file) {
			mysettings.ValueDict["PORTAGE_UPDATE_ENV"] = env_file
		}
	}
	defer delete(mysettings, "PORTAGE_UPDATE_ENV")
	return _spawn_phase(mydo, mysettings,
		fd_pipes = fd_pipes, logfile = logfile, returnpid=returnpid)
}

mycpv := (mysettings.ValueDict["CATEGORY"] + "/" + mysettings.ValueDict["PF"])

need_distfiles := tree == "porttree" && ! unpacked &&
((mydo == "fetch"||mydo== "unpack") ||
	(mydo != "digest"&&mydo != "manifest") &&  !  features["noauto"])
if need_distfiles {
	src_uri := mysettings.configDict["pkg"]["SRC_URI"]
	if src_uri == "" {
		src_uri, = mydbapi.aux_get(mysettings.mycpv,
			map[string]bool{"SRC_URI": true}, mytree = filepath.Dir(filepath.Dir(
			filepath.Dir(myebuild))))
	}
	metadata = map[string]string{
		"EAPI":    mysettings.ValueDict["EAPI"],
		"SRC_URI": src_uri,
	}
	use := map[string]bool{}
	for _, v := range strings.Fields(mysettings.ValueDict["PORTAGE_USE"]) {
		use[v] = true
	}
	//try{
	alist := _parse_uri_map(mysettings.mycpv, metadata, use)
	aalist := _parse_uri_map(mysettings.mycpv, metadata, nil)
	//except InvalidDependString as e{
	//WriteMsg(fmt.Sprintf("!!! %s\n" % str(e), -1,nil)
	//WriteMsg(fmt.Sprintf(("!!! Invalid SRC_URI for '%s'.\n") % mycpv,
	//-1,nil)
	//del e
	//return 1
	var fetchme map[string]map[string]bool
	if features["mirror"] || fetchall != 0 {
		fetchme = aalist
	} else {
		fetchme = alist
	}

	var dist_digests map[string]map[string]string = nil
	if mf != nil {
		dist_digests = mf.getTypeDigests("DIST")
	}

	_fetch_subprocess := func(fetchme, mysettings *Config, listonly, dist_digests) {

		if _want_userfetch(mysettings) {
			_drop_privs_userfetch(mysettings)
		}

		return fetch(fetchme, mysettings, listonly = listonly,
			fetchonly = fetchonly, allow_missing_digests=false,
			digests = dist_digests)
	}

	loop = asyncio._safe_loop()
	if loop.is_running() {

		success = fetch(fetchme, mysettings, listonly = listonly,
			fetchonly = fetchonly, allow_missing_digests=false,
			digests = dist_digests)
	} else {
		success = loop.run_until_complete(
			loop.run_in_executor(ForkExecutor(loop = loop),
		_fetch_subprocess, fetchme, mysettings, listonly, dist_digests))
	}
	if !success {
		if !listonly {
			spawn_nofetch(mydbapi, myebuild, settings = mysettings,
				fd_pipes = fd_pipes)
		}
		return 1
	}
}


	checkme := map[string]map[string]bool{}
if need_distfiles{

//checkme = []
}else if unpacked{

//checkme = []
}else {
	checkme = alist
}

if mydo == "fetch" && listonly!=0 {
	return 0
}

//try{
if mydo == "manifest"{
mf = nil
_doebuild_manifest_cache = nil
return ! digestgen(mysettings=mysettings, myportdb=mydbapi)
}else if mydo == "digest"{
mf = nil
_doebuild_manifest_cache = nil
return ! digestgen(mysettings=mysettings, myportdb=mydbapi)
}else if  mysettings.Features.Features["digest"] {
	mf = nil
	_doebuild_manifest_cache = nil
	digestgen(mysettings = mysettings, myportdb = mydbapi)
}
//except PermissionDenied as e{
//WriteMsg(fmt.Sprintf(("!!! Permission Denied: %s\n") % (e,), -1,nil)
//if mydo =="digest" || mydo == "manifest"):
//return 1

if mydo == "fetch" {
	return 0
}

if tree == "porttree" && ! digestcheck(checkme, mysettings,   features["strict"], mf=mf){
		return 1
	}

if tree == "porttree" && ((mydo != "setup" && ! features["noauto" ]) || mydo == "install" ||mydo ==  "unpack")){
		_prepare_fake_distdir(mysettings, alist)
	}

actionmap := _spawn_actionmap(mysettings)

for _, x := range  actionmap {
	if len(actionmap_deps[x]) > 0 {
		actionmap[x]["dep"] = strings.Join(actionmap_deps[x], " ")
	}
}

regular_actionmap_phase := mydo in actionmap

if len(regular_actionmap_phase) > 0 {
	var bintree *BinaryTree
	if mydo == "package" {

		if Db() != nil {
			bintree = Db().Values()[mysettings.ValueDict["EROOT"]].BinTree()
			mysettings.ValueDict["PORTAGE_BINPKG_TMPFILE"] =
				bintree.getname(mysettings.mycpv, false) +
					fmt.Sprintf(".%s", os.Getpid(), )
			bintree._ensure_dir(filepath.Dir(
				mysettings.ValueDict["PORTAGE_BINPKG_TMPFILE"]))
		} else {
			parent_dir := filepath.Join(mysettings.ValueDict["PKGDIR"],
				mysettings.ValueDict["CATEGORY"])
			ensureDirs(parent_dir, -1, -1, -1, -1, nil, true)
			if !os.access(parent_dir, os.W_OK) {
				raise
				PermissionDenied("access('%s', os.W_OK)" % parent_dir)
			}
		}
	}
	retval := spawnebuild(mydo,
		actionmap, mysettings, debug, logfile = logfile,
		fd_pipes = fd_pipes, returnpid=returnpid)

	if returnpid && isinstance(retval, list) {
		return retval
	}

	if retval == 0 {
		if mydo == "package" && bintree != nil {
			pkg = bintree.inject(mysettings.mycpv,
				filename = mysettings.ValueDict["PORTAGE_BINPKG_TMPFILE"])
			if pkg != nil {
				infoloc := filepath.Join(
					mysettings.ValueDict["PORTAGE_BUILDDIR"], "build-info")
				build_info := map[string]string{
					"BINPKGMD5": fmt.Sprintf("%s\n", pkg._metadata["MD5"]),
				}
				if pkg.build_id != nil {
					build_info["BUILD_ID"] = fmt.Sprintf("%s\n", pkg.build_id)
				}
				for k, v := range build_info {
					with
					io.open(_unicode_encode(
						filepath.Join(infoloc, k),
						encoding = _encodings["fs"], errors = "strict"),
					mode = "w", encoding=_encodings["repo.content"],
						errors = "strict") as
					f{
						f.write(v)
					}
				}
			}
		}
	} else {
		if Inmss(mysettings.ValueDict, "PORTAGE_BINPKG_TMPFILE") {
			if err := syscall.Unlink(mysettings.ValueDict["PORTAGE_BINPKG_TMPFILE"]); err != nil {
				//except OSError{
				//pass
			}
		}
	}
}else if returnpid {
	WriteMsg(fmt.Sprintf("!!! doebuild: %s\n",
		fmt.Sprintf("returnpid is not supported for phase '%s'\n", mydo)),
		-1, nil)
}

if regular_actionmap_phase!= ""{
//pass
}else if mydo == "qmerge"{

if ! pathExists(filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], ".installed")) {
	WriteMsg(("!!! mydo=qmerge, but the install phase has not been run\n"),
		-1, nil)
	return 1
}

if  ! mysettings.Features.Features["noclean"] {
	mysettings.Features.Features["noclean"] = true
}
_handle_self_update(mysettings, vartree.dbapi)

retval = merge(
mysettings.ValueDict["CATEGORY"], mysettings.ValueDict["PF"], mysettings.ValueDict["D"],
filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], "build-info"),
myroot, mysettings, myebuild=mysettings.ValueDict["EBUILD"], mytree=tree,
mydbapi=mydbapi, vartree=vartree, prev_mtimes=prev_mtimes,
fd_pipes=fd_pipes)
}else if mydo=="merge" {
	retval := spawnebuild("install", actionmap, mysettings, debug,
		alwaysdep = 1, logfile = logfile, fd_pipes=fd_pipes,
		returnpid = returnpid)
	if retval != 0 {
		elog_process(mysettings.mycpv, mysettings)
	}
	if retval == 0 {
		_handle_self_update(mysettings, vartree.dbapi)
		retval = merge(mysettings.ValueDict["CATEGORY"], mysettings.ValueDict["PF"],
			mysettings.ValueDict["D"], filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"],
				"build-info"), myroot, mysettings,
			myebuild = mysettings.ValueDict["EBUILD"], mytree = tree, mydbapi=mydbapi,
			vartree = vartree, prev_mtimes=prev_mtimes,
			fd_pipes = fd_pipes)
	}
}else{
WriteMsgStdout(fmt.Sprintf(("!!! Unknown mydo: %s\n") % mydo, -1,nil)
return 1
	}

return retval
}

func _check_temp_dir(settings *Config) {
	if !Inmss(settings.ValueDict, "PORTAGE_TMPDIR") ||
		!pathIsDir(settings.ValueDict["PORTAGE_TMPDIR"]) {
		WriteMsg(fmt.Sprintf(("The directory specified in your "+
			"PORTAGE_TMPDIR variable, '%s',\n"+
			"does not exist.  Please create this directory or "+
			"correct your PORTAGE_TMPDIR setting.\n"),
			settings.ValueDict["PORTAGE_TMPDIR"]), -1, nil)
		return 1
	}

	checkdir := firstExisting(filepath.Join(settings.ValueDict["PORTAGE_TMPDIR"], "portage"))

	if !os.access(checkdir, os.W_OK) {
		WriteMsg(fmt.Sprintf("%s is not writable.\n"+
			"Likely cause is that you've mounted it as readonly.\n", checkdir),
			-1, nil)
		return 1
	}

	with
	tempfile.NamedTemporaryFile(prefix = "exectest-", dir = checkdir) as
	fd{
		os.Chmod(fd.name, 0755)
		if ! os.access(fd.name, os.X_OK){
		WriteMsg(fmt.Sprintf("Can not execute files in %s\n"+
		"Likely cause is that you've mounted it with one of the\n"+
		"following mount options: 'noexec', 'user', 'users'\n\n"+
		"Please make sure that portage can execute files in this directory.\n", checkdir),
		-1, nil)
		return 1
	}
	}

	return 0
}

func _prepare_env_file(settings *Config) {

	env_extractor = BinpkgEnvExtractor(background = false,
		scheduler = asyncio._safe_loop(),
		settings=settings)

	if env_extractor.dest_env_exists() {

		return 0
	}

	if !env_extractor.saved_env_exists() {

		return 0
	}

	env_extractor.start()
	env_extractor.wait()
	return env_extractor.returncode
}

func _spawn_actionmap(settings *Config) {
	features := settings.Features.Features
	restrict := strings.Fields(settings.ValueDict["PORTAGE_RESTRICT"])
	nosandbox := ((features["userpriv"]) &&
		(!features["usersandbox"]) &&
		!Ins(restrict, "userpriv") &&
		!Ins(restrict, "nouserpriv"))

	if !sandbox_capable {
		nosandbox = true
	}

	sesandbox := settings.selinux_enabled() &&
		features["sesandbox"]

	droppriv := features["userpriv"] &&
		!Ins(restrict, "userpriv") &&
		*secpass >= 2

	fakeroot := features["fakeroot"]

	portage_bin_path := settings.ValueDict["PORTAGE_BIN_PATH"]
	ebuild_sh_binary := filepath.Join(portage_bin_path,
		filepath.Base(EBUILD_SH_BINARY))
	misc_sh_binary := filepath.Join(portage_bin_path,
		filepath.Base(MISC_SH_BINARY))
	ebuild_sh := ShellQuote(ebuild_sh_binary) + " %s"
	misc_sh := ShellQuote(misc_sh_binary) + " __dyn_%s"

	actionmap := map[string]struct {
		cmd  string
		args map[string]interface{}
	}{
		"pretend":   {cmd: ebuild_sh, args: {"droppriv": 0, "free": 1, "sesandbox": 0, "fakeroot": 0}},
		"setup":     {cmd: ebuild_sh, args: {"droppriv": 0, "free": 1, "sesandbox": 0, "fakeroot": 0}},
		"unpack":    {cmd: ebuild_sh, args: {"droppriv": droppriv, "free": 0, "sesandbox": sesandbox, "fakeroot": 0}},
		"prepare":   {cmd: ebuild_sh, args: {"droppriv": droppriv, "free": 0, "sesandbox": sesandbox, "fakeroot": 0}},
		"configure": {cmd: ebuild_sh, args: {"droppriv": droppriv, "free": nosandbox, "sesandbox": sesandbox, "fakeroot": 0}},
		"compile":   {cmd: ebuild_sh, args: {"droppriv": droppriv, "free": nosandbox, "sesandbox": sesandbox, "fakeroot": 0}},
		"test":      {cmd: ebuild_sh, args: {"droppriv": droppriv, "free": nosandbox, "sesandbox": sesandbox, "fakeroot": 0}},
		"install":   {cmd: ebuild_sh, args: {"droppriv": 0, "free": 0, "sesandbox": sesandbox, "fakeroot": fakeroot}},
		"instprep":  {cmd: misc_sh, args: {"droppriv": 0, "free": 0, "sesandbox": sesandbox, "fakeroot": fakeroot}},
		"rpm":       {cmd: misc_sh, args: {"droppriv": 0, "free": 0, "sesandbox": 0, "fakeroot": fakeroot}},
		"package":   {cmd: misc_sh, args: {"droppriv": 0, "free": 0, "sesandbox": 0, "fakeroot": fakeroot}},
	}

	return actionmap
}

func _validate_deps(mysettings *Config, myroot, mydo, mydbapi){
invalid_dep_exempt_phases := map[string]bool{"clean":true, "cleanrm":true, "help":true, "prerm":true, "postrm":true}
all_keys := CopyMapSB(NewPackage(false, nil, false, nil, nil, "").metadataKeys)
all_keys["SRC_URI"]=true
metadata := mysettings.configDict["pkg"]
if all(k in metadata for k in ("PORTAGE_REPO_NAME", "SRC_URI")){
metadata = dict(((k, metadata[k]) for k in all_keys if k in metadata),
repository=metadata["PORTAGE_REPO_NAME"])
}else{
metadata = dict(zip(all_keys,
mydbapi.aux_get(mysettings.mycpv, all_keys,
myrepo=mysettings.ValueDict["PORTAGE_REPO_NAME"))))

class FakeTree(object){
func __init__(self, mydb){
self.dbapi = mydb

root_config := NewRootConfig(mysettings, {"porttree":FakeTree(mydbapi)}, None)

pkg := NewPackage(false, mysettings.mycpv, false, metadata, root_config, "ebuild")

msgs = []
if pkg.invalid{
for k, v in pkg.invalid.items(){
for msg in v{
msgs=append(fmt.Sprintf("  %s\n" % (msg,))

if msgs{
WriteMsgLevel(fmt.Sprintf(("Error(s) in metadata for '%s':\n") %
(mysettings.mycpv,), level=logging.ERROR, -1,nil)
for _, x := range  msgs{
WriteMsgLevel(x,
level=logging.ERROR, -1,nil)
if mydo ! in invalid_dep_exempt_phases{
return 1

if ! pkg.built &&
mydo ! in ("digest", "help", "manifest") &&
pkg._metadata["REQUIRED_USE"] &&
eapi_has_required_use(pkg.eapi){
result = check_required_use(pkg._metadata["REQUIRED_USE"],
pkg.use.enabled, pkg.iuse.is_valid_flag, eapi=pkg.eapi)
if ! result{
reduced_noise = result.tounicode()
WriteMsg(fmt.Sprintf("\n  %s\n" % _("The following REQUIRED_USE flag" +
" constraints are unsatisfied:"), -1,nil)
WriteMsg(fmt.Sprintf("    %s\n" % reduced_noise,
-1,nil)
normalized_required_use =
strings.Join(strings.Fields(pkg._metadata["REQUIRED_USE"])," ")
if reduced_noise != normalized_required_use{
WriteMsg(fmt.Sprintf("\n  %s\n" % _("The above constraints " +
"are a subset of the following complete expression:"),
-1,nil)
WriteMsg(fmt.Sprintf("    %s\n" %
human_readable_required_use(normalized_required_use),
-1,nil)
WriteMsg("\n", -1,nil)
return 1

return 0

func spawn(mystring string, mysettings  *Config, debug=false, free=false, droppriv=false,
sesandbox=false, fakeroot=false, networked=true, ipc=true,
mountns=false, pidns=false, **keywords){
check_config_instance(mysettings)

fd_pipes = keywords.get("fd_pipes")
if fd_pipes == nil{
fd_pipes = {
0:portage._get_stdin().fileno(),
1:sys.__stdout__.fileno(),
2:sys.__stderr__.fileno(),
}

stdout_filenos = (sys.__stdout__.fileno(), sys.__stderr__.fileno())
for fd in fd_pipes.values(){
if fd in stdout_filenos{
sys.__stdout__.flush()
sys.__stderr__.flush()
break

features = mysettings.Features.Features[]

if uid == 0 && platform.system() == "Linux"{
keywords["unshare_net"] = ! networked
keywords["unshare_ipc"] = ! ipc
keywords["unshare_mount"] = mountns
keywords["unshare_pid"] = pidns

if ! networked && mysettings.ValueDict["EBUILD_PHASE") != "nofetch" &&
("network-sandbox-proxy" in features || "distcc" in features){

try{
proxy = get_socks5_proxy(mysettings)
except NotImplementedError{
pass
}else{
mysettings.ValueDict["PORTAGE_SOCKS5_PROXY"] = proxy
mysettings.ValueDict["DISTCC_SOCKS_PROXY"] = proxy

fakeroot = fakeroot && uid != 0 && portage.process.fakeroot_capable
portage_build_uid = os.getuid()
portage_build_gid = os.getgid()
logname = None
if uid == 0 && portage_uid && portage_gid && hasattr(os, "setgroups"){
if droppriv{
logname = portage.data._portage_username
keywords.update({
"uid": portage_uid,
"gid": portage_gid,
"groups": userpriv_groups,
"umask": 0o22
})

stdout_fd = fd_pipes.get(1)
if stdout_fd != nil{
try{
subprocess_tty = _os.ttyname(stdout_fd)
except OSError{
pass
}else{
try{
parent_tty = _os.ttyname(sys.__stdout__.fileno())
except OSError{
parent_tty = None

if subprocess_tty != parent_tty{
_os.chown(subprocess_tty,
int(portage_uid), int(portage_gid))

if "userpriv" in features &&  ! ins(strings.Fields(mysettings.ValueDict["PORTAGE_RESTRICT"], "userpriv") && secpass >= 2{

portage_build_uid = int(portage_uid)
portage_build_gid = int(portage_gid)

if "PORTAGE_BUILD_USER" ! in mysettings{
user = None
try{
user = pwd.getpwuid(portage_build_uid).pw_name
except KeyError{
if portage_build_uid == 0{
user = "root"
}else if portage_build_uid == portage_uid{
user = portage.data._portage_username
if user != nil{
mysettings.ValueDict["PORTAGE_BUILD_USER"] = user

if "PORTAGE_BUILD_GROUP" ! in mysettings{
group = None
try{
group = grp.getgrgid(portage_build_gid).gr_name
except KeyError{
if portage_build_gid == 0{
group = "root"
}else if portage_build_gid == portage_gid{
group = portage.data._portage_grpname
if group != nil{
mysettings.ValueDict["PORTAGE_BUILD_GROUP"] = group

if ! free{
free=((droppriv && "usersandbox" ! in features) ||
(! droppriv && "sandbox" ! in features &&
"usersandbox" ! in features && ! fakeroot))

if ! free && ! (fakeroot || portage.process.sandbox_capable){
free = true

if mysettings.mycpv != nil{
keywords["opt_name"] = fmt.Sprintf("[%s]" % mysettings.mycpv
}else{
keywords["opt_name"] = fmt.Sprintf("[%s/%s]" %
(mysettings.ValueDict["CATEGORY",""), mysettings.ValueDict["PF",""))

if free || "SANDBOX_ACTIVE" in os.environ{
keywords["opt_name"] += " bash"
spawn_func = portage.process.spawn_bash
}else if fakeroot{
keywords["opt_name"] += " fakeroot"
keywords["fakeroot_state"] = filepath.Join(mysettings.ValueDict["T"], "fakeroot.state")
spawn_func = portage.process.spawn_fakeroot
}else{
keywords["opt_name"] += " sandbox"
spawn_func = portage.process.spawn_sandbox

if sesandbox{
spawn_func = selinux.spawn_wrapper(spawn_func,
mysettings.ValueDict["PORTAGE_SANDBOX_T"])

logname_backup = None
if logname != nil{
logname_backup = mysettings.configDict["env"].get("LOGNAME")
mysettings.configDict["env"]["LOGNAME"] = logname

try{
if keywords.get("returnpid"){
return spawn_func(mystring, env=mysettings.environ(),
**keywords)

proc = EbuildSpawnProcess(
background=false, args=mystring,
scheduler=SchedulerInterface(asyncio._safe_loop()),
spawn_func=spawn_func,
settings=mysettings, **keywords)

proc.start()
proc.wait()

return proc.returncode

finally{
if logname == nil{
pass
}else if logname_backup == nil{
mysettings.configDict["env"].pop("LOGNAME", None)
}else{
mysettings.configDict["env"]["LOGNAME"] = logname_backup

func spawnebuild(mydo, actionmap, mysettings *Config, debug, alwaysdep=0,
logfile=None, fd_pipes=None, returnpid=false){

if returnpid{
warnings.warn("portage.spawnebuild() called "
"with returnpid parameter enabled. This usage will "
"not be supported in the future.",
DeprecationWarning, stacklevel=2)

if ! returnpid &&
(alwaysdep || "noauto" ! in mysettings.Features.Features[]){

if "dep" in actionmap[mydo]{
retval = spawnebuild(actionmap[mydo]["dep"], actionmap,
mysettings, debug, alwaysdep=alwaysdep, logfile=logfile,
fd_pipes=fd_pipes, returnpid=returnpid)
if retval{
return retval

eapi = mysettings.ValueDict["EAPI"]

if mydo in ("configure", "prepare") && ! eapi_has_src_prepare_and_src_configure(eapi){
return 0

if mydo == "pretend" && ! eapi_has_pkg_pretend(eapi){
return 0

if ! (mydo == "install" && "noauto" in mysettings.Features.Features[]){
check_file = filepath.Join(
mysettings.ValueDict["PORTAGE_BUILDDIR"], fmt.Sprintf(".%sed" % strings.TrimRight(mydo,"e"))
if pathExists(check_file){
WriteMsgStdout(fmt.Sprintf((">>> It appears that "
"'%(action)s' has already executed for '%(pkg)s'; skipping.\n") %
{"action":mydo, "pkg":mysettings.ValueDict["PF"]})
WriteMsgStdout(fmt.Sprintf((">>> Remove '%(file)s' to force %(action)s.\n") %
{"file":check_file, "action":mydo})
return 0

return _spawn_phase(mydo, mysettings,
actionmap=actionmap, logfile=logfile,
fd_pipes=fd_pipes, returnpid=returnpid)

_post_phase_cmds = {

"install" : [
"install_qa_check",
"install_symlink_html_docs",
"install_hooks"],

"preinst" : (
(

{
"ld_preload_sandbox": false,
"selinux_only": true,
},
[
"preinst_selinux_labels",
],
),
(
{},
[
"preinst_sfperms",
"preinst_suid_scan",
"preinst_qa_check",
],
),
),
"postinst" : [
"postinst_qa_check"],
}

func _post_phase_userpriv_perms(mysettings *Config){
if "userpriv" in mysettings.Features.Features[] && secpass >= 2{

for path in (mysettings.ValueDict["HOME"], mysettings.ValueDict["T"]){
apply_recursive_permissions(path,
uid=portage_uid, gid=portage_gid, dirmode=0o700, dirmask=0,
filemode=0o600, filemask=0)

func _check_build_log(mysettings *Config, out=None){

logfile = mysettings.ValueDict["PORTAGE_LOG_FILE")
if logfile == nil{
return
try{
f = open(_unicode_encode(logfile, encoding=_encodings["fs"],
errors="strict"), mode="rb")
except EnvironmentError{
return

f_real = None
if logfile.endswith(".gz"){
f_real = f
f =  gzip.GzipFile(filename="", mode="rb", fileobj=f)

am_maintainer_mode = []
bash_command_!_found = []
bash_command_!_found_re = re.compile(
r"(.*): line (\d*): (.*): command not found$")
command_not_found_exclude_re = re.compile(r"/configure: line ")
helper_missing_file = []
helper_missing_file_re = re.compile(
r"^!!! (do|new).*: .* does not exist$")

configure_opts_warn = []
configure_opts_warn_re = re.compile(
r"^configure: WARNING: [Uu]nrecognized options: (.*)")

qa_configure_opts = ""
try{
with io.open(_unicode_encode(filepath.Join(
mysettings.ValueDict["PORTAGE_BUILDDIR"],
"build-info", "QA_CONFIGURE_OPTIONS"),
encoding=_encodings["fs"], errors="strict"),
mode="r", encoding=_encodings["repo.content"],
errors="replace") as qa_configure_opts_f{
qa_configure_opts = qa_configure_opts_f.read()
except IOError as e{
if e.errno ! in (errno.ENOENT, errno.ESTALE){
raise

qa_configure_opts = strings.Fields(qa_configure_opts)
if qa_configure_opts{
if len(qa_configure_opts) > 1{
qa_configure_opts = "|".join(fmt.Sprintf("(%s)" % x for _, x := range  qa_configure_opts)
qa_configure_opts = fmt.Sprintf("^(%s)$" % qa_configure_opts
}else{
qa_configure_opts = fmt.Sprintf("^%s$" % qa_configure_opts[0]
qa_configure_opts = re.compile(qa_configure_opts)

qa_am_maintainer_mode = []
try{
with io.open(_unicode_encode(filepath.Join(
mysettings.ValueDict["PORTAGE_BUILDDIR"],
"build-info", "QA_AM_MAINTAINER_MODE"),
encoding=_encodings["fs"], errors="strict"),
mode="r", encoding=_encodings["repo.content"],
errors="replace") as qa_am_maintainer_mode_f{
qa_am_maintainer_mode = []string{}
 for _, x := range
qa_am_maintainer_mode_f.read().splitlines() if x]
except IOError as e{
if e.errno ! in (errno.ENOENT, errno.ESTALE){
raise

if qa_am_maintainer_mode{
if len(qa_am_maintainer_mode) > 1{
qa_am_maintainer_mode =
"|".join(fmt.Sprintf("(%s)" % x for _, x := range  qa_am_maintainer_mode)
qa_am_maintainer_mode = fmt.Sprintf("^(%s)$" % qa_am_maintainer_mode
}else{
qa_am_maintainer_mode =fmt.Sprintf(fmt.Sprintf( "^%s$" % qa_am_maintainer_mode[0]
qa_am_maintainer_mode = re.compile(qa_am_maintainer_mode)

am_maintainer_mode_re = re.compile(r"/missing --run ")
am_maintainer_mode_exclude_re =
re.compile(r"(/missing --run (autoheader|autotest|help2man|makeinfo)|^\s*Automake:\s)")

make_jobserver_re =
re.compile(r"g?make\[\d+\]: warning: jobserver unavailable:")
make_jobserver = []

func _eerror(lines){
for line in lines{
eerror(line, phase="install", key=mysettings.mycpv, out=out)

try{
for line in f{
line = _unicode_decode(line)
if am_maintainer_mode_re.search(line) != nil &&
am_maintainer_mode_exclude_re.search(line) == nil &&
(! qa_am_maintainer_mode or
qa_am_maintainer_mode.search(line) == nil){
am_maintainer_mode=append(strings.TrimRight(line,"\n"))

if bash_command_not_found_re.match(line) != nil &&
command_not_found_exclude_re.search(line) == nil{
bash_command_not_found=append(strings.TrimRight(line,"\n"))

if helper_missing_file_re.match(line) != nil{
helper_missing_file=append(strings.TrimRight(line,"\n"))

m = configure_opts_warn_re.match(line)
if m != nil{
for _, x := range  strings.Split(m.group(1),", "){
if ! qa_configure_opts || qa_configure_opts.match(x) == nil{
configure_opts_warn=append(x)

if make_jobserver_re.match(line) != nil{
make_jobserver=append(strings.TrimRight(line,"\n"))

except (EOFError, zlib.error) as e{
_eerror([fmt.Sprintf("portage encountered a zlib error: '%s'" % (e,),
		fmt.Sprintf("while reading the log file: '%s'" % logfile])
finally{
f.close()

func _eqawarn(lines){
for line in lines{
eqawarn(line, phase="install", key=mysettings.mycpv, out=out)
wrap_width = 70

if am_maintainer_mode{
msg = [_("QA Notice: Automake \"maintainer mode\" detected:")]
msg=append("")
msg= append("\t" + line for line in am_maintainer_mode)
msg=append("")
msg= append(wrap(_(
"If you patch Makefile.am, "
"configure.in,  or configure.ac then you "
"should use autotools.eclass and "
"eautomake or eautoreconf. Exceptions "
"are limited to system packages "
"for which it is impossible to run "
"autotools during stage building. "
"See https://wiki.gentoo.org/wiki/Project:Quality_Assurance/Autotools_failures"
" for more information."),
wrap_width))
_eqawarn(msg)

if bash_command_not_found{
msg = [_("QA Notice: command not found:")]
msg=append("")
msg= append("\t" + line for line in bash_command_not_found)
_eqawarn(msg)

if helper_missing_file{
msg = [_("QA Notice: file does not exist:")]
msg=append("")
msg= append("\t" + line[4:] for line in helper_missing_file)
_eqawarn(msg)

if configure_opts_warn{
msg = [_("QA Notice: Unrecognized configure options:")]
msg=append("")
msg= append(fmt.Sprintf("\t%s" % x for _, x := range  configure_opts_warn)
_eqawarn(msg)

if make_jobserver{
msg = [_("QA Notice: make jobserver unavailable:")]
msg=append("")
msg= append("\t" + line for line in make_jobserver)
_eqawarn(msg)

f.close()
if f_real != nil{
f_real.close()

func _post_src_install_write_metadata(settings *Config){

eapi_attrs = _get_eapi_attrs(settings.configdict["pkg"]["EAPI"])

build_info_dir = filepath.Join(settings.ValueDict["PORTAGE_BUILDDIR"], "build-info")

metadata_keys = ["IUSE"]
if eapi_attrs.iuse_effective{
metadata_keys=append("IUSE_EFFECTIVE")

for k in metadata_keys{
v = settings.configdict["pkg"].get(k)
if v != nil{
write_atomic(filepath.Join(build_info_dir, k), v + "\n")

for k in ("CHOST",){
v = settings.ValueDict[k)
if v != nil{
write_atomic(filepath.Join(build_info_dir, k), v + "\n")

with io.open(_unicode_encode(filepath.Join(build_info_dir,
"BUILD_TIME"), encoding=_encodings["fs"], errors="strict"),
mode="w", encoding=_encodings["repo.content"],
errors="strict") as f{
f.write(fmt.Sprintf("%.0f\n" % (time.time(),))

use = map[string]bool{}
for_, v := range (strings.Fields(settings.ValueDict["PORTAGE_USE"])){
	use[v]=true
}
for k in _vdb_use_conditional_keys{
v = settings.configdict["pkg"].get(k)
filename = filepath.Join(build_info_dir, k)
if v == nil{
try{
os.unlink(filename)
except OSError{
pass
continue

if k.endswith("DEPEND"){
if eapi_attrs.slot_operator{
continue
token_class = Atom
}else{
token_class = None

v = use_reduce(v, uselist=use, token_class=token_class)
v = paren_enclose(v)
if ! v{
try{
os.unlink(filename)
except OSError{
pass
continue
with io.open(_unicode_encode(filepath.Join(build_info_dir,
k), encoding=_encodings["fs"], errors="strict"),
mode="w", encoding=_encodings["repo.content"],
errors="strict") as f{
f.write(fmt.Sprintf("%s\n" % v)

if eapi_attrs.slot_operator{
deps = evaluate_slot_operator_equal_deps(settings, use, QueryCommand.get_db())
for k, v in deps.items(){
filename = filepath.Join(build_info_dir, k)
if ! v{
try{
os.unlink(filename)
except OSError{
pass
continue
with io.open(_unicode_encode(filepath.Join(build_info_dir,
k), encoding=_encodings["fs"], errors="strict"),
mode="w", encoding=_encodings["repo.content"],
errors="strict") as f{
f.write(fmt.Sprintf("%s\n" % v)

func _preinst_bsdflags(mysettings *Config){
if bsd_chflags{

os.system(fmt.Sprintf("mtree -c -p %s -k flags > %s" %
(_shell_quote(mysettings.ValueDict["D"]),
_shell_quote(filepath.Join(mysettings.ValueDict["T"], "bsdflags.mtree"))))

os.system(fmt.Sprintf("chflags -R noschg,nouchg,nosappnd,nouappnd %s" %
(_shell_quote(mysettings.ValueDict["D"]),))
os.system(fmt.Sprintf("chflags -R nosunlnk,nouunlnk %s 2>/dev/null" %
(_shell_quote(mysettings.ValueDict["D"]),))

func _postinst_bsdflags(mysettings *Config){
if bsd_chflags{

os.system(fmt.Sprintf("mtree -e -p %s -U -k flags < %s > /dev/null" %
(_shell_quote(mysettings.ValueDict["ROOT"]),
_shell_quote(filepath.Join(mysettings.ValueDict["T"], "bsdflags.mtree"))))

func _post_src_install_uid_fix(mysettings *Config, out){

os = _os_merge

inst_uid = int(mysettings.ValueDict["PORTAGE_INST_UID"])
inst_gid = int(mysettings.ValueDict["PORTAGE_INST_GID"])

_preinst_bsdflags(mysettings)

destdir = mysettings.ValueDict["D"]
ed_len = len(mysettings.ValueDict["ED"])
unicode_errors = []
desktop_file_validate =
portage.process.find_binary("desktop-file-validate") != nil
xdg_dirs = strings.Fields(mysettings.ValueDict["XDG_DATA_DIRS", "/usr/share"),"{")
xdg_dirs = tuple(filepath.Join(i, "applications") + string(os.PathSeparator)
for i in xdg_dirs if i)

qa_desktop_file = ""
try{
with io.open(_unicode_encode(filepath.Join(
mysettings.ValueDict["PORTAGE_BUILDDIR"],
"build-info", "QA_DESKTOP_FILE"),
encoding=_encodings["fs"], errors="strict"),
mode="r", encoding=_encodings["repo.content"],
errors="replace") as f{
qa_desktop_file = f.read()
except IOError as e{
if e.errno ! in (errno.ENOENT, errno.ESTALE){
raise

qa_desktop_file = strings.Fields(qa_desktop_file)
if qa_desktop_file{
if len(qa_desktop_file) > 1{
qa_desktop_file = "|".join(fmt.Sprintf("(%s)" % x for _, x := range  qa_desktop_file)
qa_desktop_file = fmt.Sprintf("^(%s)$" % qa_desktop_file
}else{
qa_desktop_file = fmt.Sprintf("^%s$" % qa_desktop_file[0]
qa_desktop_file = re.compile(qa_desktop_file)

while true{

unicode_error = false
size = 0
counted_inodes = set()
fixlafiles_announced = false
fixlafiles = "fixlafiles" in mysettings.Features.Features[]
desktopfile_errors = []

for parent, dirs, files in os.walk(destdir){
try{
parent = _unicode_decode(parent,
encoding=_encodings["merge"], errors="strict")
except UnicodeDecodeError{
new_parent = _unicode_decode(parent,
encoding=_encodings["merge"], errors="replace")
new_parent = _unicode_encode(new_parent,
encoding="ascii", errors="backslashreplace")
new_parent = _unicode_decode(new_parent,
encoding=_encodings["merge"], errors="replace")
os.rename(parent, new_parent)
unicode_error = true
unicode_errors=append(new_parent[ed_len:])
break

for fname in chain(dirs, files){
try{
fname = _unicode_decode(fname,
encoding=_encodings["merge"], errors="strict")
except UnicodeDecodeError{
fpath = _filepath.Join(
parent.encode(_encodings["merge"]), fname)
new_fname = _unicode_decode(fname,
encoding=_encodings["merge"], errors="replace")
new_fname = _unicode_encode(new_fname,
encoding="ascii", errors="backslashreplace")
new_fname = _unicode_decode(new_fname,
encoding=_encodings["merge"], errors="replace")
new_fpath = filepath.Join(parent, new_fname)
os.rename(fpath, new_fpath)
unicode_error = true
unicode_errors=append(new_fpath[ed_len:])
fname = new_fname
fpath = new_fpath
}else{
fpath = filepath.Join(parent, fname)

fpath_relative = fpath[ed_len - 1:]
if desktop_file_validate && fname.endswith(".desktop") &&
os.path.isfile(fpath) &&
fpath_relative.startswith(xdg_dirs) &&
! (qa_desktop_file && qa_desktop_file.match(fpath_relative.strip(string(os.PathSeparator))) != nil){

desktop_validate = validate_desktop_entry(fpath)
if desktop_validate{
desktopfile_errors= append(desktop_validate)

if fixlafiles &&
fname.endswith(".la") && os.path.isfile(fpath){
f = open(_unicode_encode(fpath,
encoding=_encodings["merge"], errors="strict"),
mode="rb")
has_lafile_header = b".la - a libtool library file"
in f.readline()
f.seek(0)
contents = f.read()
f.close()
try{
needs_update, new_contents = rewrite_lafile(contents)
except portage.exception.InvalidData as e{
needs_update = false
if ! fixlafiles_announced{
fixlafiles_announced = true
WriteMsg("Fixing .la files\n", fd=out)

msg = fmt.Sprintf("   %s is not a valid libtool archive, skipping\n" % fpath[len(destdir):]
qa_msg = fmt.Sprintf("QA Notice: invalid .la file found: %s, %s" % (fpath[len(destdir):], e)
if has_lafile_header{
WriteMsg(msg, fd=out)
eqawarn(qa_msg, key=mysettings.mycpv, out=out)

if needs_update{
if ! fixlafiles_announced{
fixlafiles_announced = true
WriteMsg("Fixing .la files\n", fd=out)
WriteMsg(fmt.Sprintf("   %s\n" % fpath[len(destdir):], fd=out)

write_atomic(_unicode_encode(fpath,
encoding=_encodings["merge"], errors="strict"),
new_contents, mode="wb")

mystat = os.Lstat(fpath)
if stat.S_ISREG(mystat.st_mode) &&
mystat.st_ino ! in counted_inodes{
counted_inodes.add(mystat.st_ino)
size += mystat.st_size
if mystat.st_uid != portage_uid &&
mystat.st_gid != portage_gid{
continue
myuid = -1
mygid = -1
if mystat.st_uid == portage_uid{
myuid = inst_uid
if mystat.st_gid == portage_gid{
mygid = inst_gid
apply_secpass_permissions(
_unicode_encode(fpath, encoding=_encodings["merge"]),
uid=myuid, gid=mygid,
mode=mystat.st_mode, stat_cached=mystat,
follow_links=false)

if unicode_error{
break

if ! unicode_error{
break

if desktopfile_errors{
for l in _merge_desktopfile_error(desktopfile_errors){
l = l.replace(mysettings.ValueDict["ED"], "/")
eqawarn(l, phase="install", key=mysettings.mycpv, out=out)

if unicode_errors{
for l in _merge_unicode_error(unicode_errors){
eqawarn(l, phase="install", key=mysettings.mycpv, out=out)

build_info_dir = filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"],
"build-info")

f = io.open(_unicode_encode(filepath.Join(build_info_dir,
"SIZE"), encoding=_encodings["fs"], errors="strict"),
mode="w", encoding=_encodings["repo.content"],
errors="strict")
f.write(fmt.Sprintf("%d\n" % size)
f.close()

_reapply_bsdflags_to_image(mysettings)

func _reapply_bsdflags_to_image(mysettings *Config){

if bsd_chflags{
os.system(fmt.Sprintf("mtree -e -p %s -U -k flags < %s > /dev/null" %
(_shell_quote(mysettings.ValueDict["D"]),
_shell_quote(filepath.Join(mysettings.ValueDict["T"], "bsdflags.mtree"))))

func _post_src_install_soname_symlinks(mysettings *Config, out){

image_dir = mysettings.ValueDict["D"]
needed_filename = filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"],
"build-info", "NEEDED.ELF.2")

f = None
try{
f = io.open(_unicode_encode(needed_filename,
encoding=_encodings["fs"], errors="strict"),
mode="r", encoding=_encodings["repo.content"],
errors="replace")
lines = f.readlines()
except IOError as e{
if e.errno ! in (errno.ENOENT, errno.ESTALE){
raise
return
finally{
if f != nil{
f.close()

metadata = {}
for k in ("QA_PREBUILT", "QA_SONAME_NO_SYMLINK"){
try{
with io.open(_unicode_encode(filepath.Join(
mysettings.ValueDict["PORTAGE_BUILDDIR"],
"build-info", k),
encoding=_encodings["fs"], errors="strict"),
mode="r", encoding=_encodings["repo.content"],
errors="replace") as f{
v = f.read()
except IOError as e{
if e.errno ! in (errno.ENOENT, errno.ESTALE){
raise
}else{
metadata[k] = v

qa_prebuilt = metadata.get("QA_PREBUILT", "").strip()
if qa_prebuilt{
qa_prebuilt = re.compile("|".join(
fnmatch.translate(strings.TrimLeft(x,string(os.PathSeparator)))
for _, x := range  portage.util.shlex_split(qa_prebuilt)))

qa_soname_no_symlink = strings.Fields(metadata["QA_SONAME_NO_SYMLINK"])
if qa_soname_no_symlink{
if len(qa_soname_no_symlink) > 1{
qa_soname_no_symlink = "|".join(fmt.Sprintf("(%s)" % x for _, x := range  qa_soname_no_symlink)
qa_soname_no_symlink = fmt.Sprintf("^(%s)$" % qa_soname_no_symlink
}else{
qa_soname_no_symlink = fmt.Sprintf("^%s$" % qa_soname_no_symlink[0]
qa_soname_no_symlink = re.compile(qa_soname_no_symlink)

libpaths = set(portage.util.getlibpaths(
mysettings.ValueDict["ROOT"], env=mysettings))
libpath_inodes = set()
for libpath in libpaths{
libdir = filepath.Join(mysettings.ValueDict["ROOT"], strings.TrimLeft(libpath,string(os.PathSeparator)))
try{
s = os.Stat(libdir)
except OSError{
continue
}else{
libpath_inodes.add((s.st_dev, s.st_ino))

is_libdir_cache = {}

func is_libdir(obj_parent){
try{
return is_libdir_cache[obj_parent]
except KeyError{
pass

rval = false
if obj_parent in libpaths{
rval = true
}else{
parent_path = filepath.Join(mysettings.ValueDict["ROOT"],
	strings.TrimLeft(obj_parent,string(os.PathSeparator)))
try{
s = os.Stat(parent_path)
except OSError{
pass
}else{
if (s.st_dev, s.st_ino) in libpath_inodes{
rval = true

is_libdir_cache[obj_parent] = rval
return rval

build_info_dir = filepath.Join(
mysettings.ValueDict["PORTAGE_BUILDDIR"], "build-info")
try{
with io.open(_unicode_encode(filepath.Join(build_info_dir,
"PROVIDES_EXCLUDE"), encoding=_encodings["fs"],
errors="strict"), mode="r", encoding=_encodings["repo.content"],
errors="replace") as f{
provides_exclude = f.read()
except IOError as e{
if e.errno ! in (errno.ENOENT, errno.ESTALE){
raise
provides_exclude = ""

try{
with io.open(_unicode_encode(filepath.Join(build_info_dir,
"REQUIRES_EXCLUDE"), encoding=_encodings["fs"],
errors="strict"), mode="r", encoding=_encodings["repo.content"],
errors="replace") as f{
requires_exclude = f.read()
except IOError as e{
if e.errno ! in (errno.ENOENT, errno.ESTALE){
raise
requires_exclude = ""

missing_symlinks = []
unrecognized_elf_files = []
soname_deps = SonameDepsProcessor(
provides_exclude, requires_exclude)

needed_file = portage.util.atomic_ofstream(needed_filename,
encoding=_encodings["repo.content"], errors="strict")

for l in lines{
l = strings.TrimRight(l,"\n")
if ! l{
continue
try{
entry = NeededEntry.parse(needed_filename, l)
except InvalidData as e{
portage.util.writemsg_level(fmt.Sprintf("\n%s\n\n" % (e,),
level=logging.ERROR, -1,nil)
continue

filename = filepath.Join(image_dir,
strings.TrimLeft(entry.filename,string(os.PathSeparator)))
with open(_unicode_encode(filename, encoding=_encodings["fs"],
errors="strict"), "rb") as f{
elf_header = ELFHeader.read(f)

entry.multilib_category = compute_multilib_category(elf_header)
needed_file.write(_unicode(entry))

if entry.multilib_category == nil{
if ! qa_prebuilt || qa_prebuilt.match(
entry.filename[len(strings.TrimLeft(mysettings.ValueDict["EPREFIX"]):],
string(os.PathSeparator))) == nil{
unrecognized_elf_files=append(entry)
}else{
soname_deps.add(entry)

obj = entry.filename
soname = entry.soname

if ! soname{
continue
if ! is_libdir(filepath.Dir(obj)){
continue
if qa_soname_no_symlink && qa_soname_no_symlink.match(obj.strip(string(os.PathSeparator))) != nil{
continue

obj_file_path = filepath.Join(image_dir, strings.TrimLeft(obj,string(os.PathSeparator)))
sym_file_path = filepath.Join(filepath.Dir(obj_file_path), soname)
try{
os.Lstat(sym_file_path)
except OSError as e{
if e.errno ! in (errno.ENOENT, errno.ESTALE){
raise
}else{
continue

missing_symlinks=append((obj, soname))

needed_file.close()

if soname_deps.requires != nil{
with io.open(_unicode_encode(filepath.Join(build_info_dir,
"REQUIRES"), encoding=_encodings["fs"], errors="strict"),
mode="w", encoding=_encodings["repo.content"],
errors="strict") as f{
f.write(soname_deps.requires)

if soname_deps.provides != nil{
with io.open(_unicode_encode(filepath.Join(build_info_dir,
"PROVIDES"), encoding=_encodings["fs"], errors="strict"),
mode="w", encoding=_encodings["repo.content"],
errors="strict") as f{
f.write(soname_deps.provides)

if unrecognized_elf_files{
qa_msg = ["QA Notice: Unrecognized ELF file(s):"]
qa_msg=append("")
qa_msg= append(fmt.Sprintf("\t%s" % strings.TrimRight(_unicode(entry), "")
for entry in unrecognized_elf_files)
qa_msg=append("")
for line in qa_msg{
eqawarn(line, key=mysettings.mycpv, out=out)

if ! missing_symlinks{
return

qa_msg = ["QA Notice: Missing soname symlink(s):"]
qa_msg=append("")
qa_msg= append(fmt.Sprintf("\t%s -> %s" % (filepath.Join(
	strings.TrimLeft(filepath.Dir(obj),string(os.PathSeparator)), soname),
filepath.Base(obj))
for obj, soname in missing_symlinks)
qa_msg=append("")
for line in qa_msg{
eqawarn(line, key=mysettings.mycpv, out=out)

func _merge_desktopfile_error(errors){
lines = []

msg = _("QA Notice: This package installs one or more .desktop files "
"that do not pass validation.")
lines= append(wrap(msg, 72))

lines=append("")
errors.sort()
lines= append("\t" + x for _, x := range  errors)
lines=append("")

return lines

func _merge_unicode_error(errors){
lines = []

msg = _("QA Notice: This package installs one or more file names "
"containing characters that are not encoded with the UTF-8 encoding.")
lines= append(wrap(msg, 72))

lines=append("")
errors.sort()
lines= append("\t" + x for _, x := range  errors)
lines=append("")

return lines

func _prepare_self_update(settings *Config){

if portage._bin_path != portage.const.PORTAGE_BIN_PATH{
return

_preload_elog_modules(settings)
portage.proxy.lazyimport._preload_portage_submodules()

build_prefix = filepath.Join(settings.ValueDict["PORTAGE_TMPDIR"], "portage")
portage.util.ensure_dirs(build_prefix)
base_path_tmp = tempfile.mkdtemp(
"", "._portage_reinstall_.", build_prefix)
portage.process.atexit_register(os.RemoveAll, base_path_tmp)

orig_bin_path = portage._bin_path
portage._bin_path = filepath.Join(base_path_tmp, "bin")
shutil.copytree(orig_bin_path, portage._bin_path, symlinks=true)

orig_pym_path = portage._pym_path
portage._pym_path = filepath.Join(base_path_tmp, "lib")
os.mkdir(portage._pym_path)
for pmod in PORTAGE_PYM_PACKAGES{
shutil.copytree(filepath.Join(orig_pym_path, pmod),
filepath.Join(portage._pym_path, pmod),
symlinks=true)

for dir_path in (base_path_tmp, portage._bin_path, portage._pym_path){
os.chmod(dir_path, 0o755)

func _handle_self_update(settings *Config, vardb){
cpv = settings.mycpv
if settings.ValueDict["ROOT"] == "/" &&
portage.dep.match_from_list(
portage.const.PORTAGE_PACKAGE_ATOM, [cpv]){
_prepare_self_update(settings)
return true
return false
)
