package ebuild

import (
	"compress/gzip"
	"fmt"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/dep"
	eapi2 "github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/elog"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/emerge/structs"
	"github.com/ppphp/portago/pkg/manifest"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/portage/vars"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/repository"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/util/permissions"
	"github.com/ppphp/portago/pkg/versions"
	"github.com/ppphp/shlex"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

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
		"config": true, "depend": true, "preinst": true, "prerm": true, "postinst": true, "postrm": true}

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
		"LICENSE", "PROPERTIES", "RESTRICT")
)

// nil
func _doebuild_spawn(phase string, settings *config.Config, actionmap Actionmap, **kwargs)([]int,error) {

	if _unsandboxed_phases[phase] {
		kwargs["free"] = true
	}

	kwargs["ipc"] = !settings.Features.Features["ipc-sandbox"] || _ipc_phases[phase]
	kwargs["mountns"] = settings.Features.Features["mount-sandbox"]
	kwargs["networked"] = !settings.Features.Features["network-sandbox"] || (phase == "unpack" &&
		myutil.Ins(strings.Fields(settings.configDict["pkg"]["PROPERTIES"]), "live")) ||
		_ipc_phases[phase] ||
		myutil.Ins(strings.Fields(settings.ValueDict["PORTAGE_RESTRICT"]), "network-sandbox")
	kwargs["pidns"] = settings.Features.Features["pid-sandbox"] &&
		!_global_pid_phases[phase]

	if phase == "depend" {
		kwargs["droppriv"] = settings.Features.Features["userpriv"]
		kwargs["close_fds"] = false
	}
	cmd := ""
	if actionmap != nil && actionmap[phase] != nil {
		kwargs.update(actionmap[phase].args)
		cmd = fmt.Sprintf(actionmap[phase].cmd, phase)
	} else {
		ebuild_sh_arg := phase
		if phase == "cleanrm" {
			ebuild_sh_arg = "clean"
		}
		cmd = fmt.Sprintf("%s %s", vars.ShellQuote(
			filepath.Join(settings.ValueDict["PORTAGE_BIN_PATH"],
				filepath.Base(_const.EBUILD_SH_BINARY))),
			ebuild_sh_arg)
	}

	settings.ValueDict["EBUILD_PHASE"] = phase
	defer delete(settings.ValueDict, "EBUILD_PHASE")
	return spawnE(cmd, settings, **kwargs)
}

// nil, false, "",
func _spawn_phase(phase string, settings *config.Config, actionmap Actionmap, returnpid bool,
	logfile string, **kwargs) ([]int, error){

	if returnpid {
		return _doebuild_spawn(phase, settings, actionmap,
			returnpid = returnpid, logfile=logfile, **kwargs)
	}

	ebuild_phase := emerge.NewEbuildPhase(actionmap, false,
		phase, emerge.NewSchedulerInterface(asyncio._safe_loop()),
		settings, nil, **kwargs)

	ebuild_phase.start()
	ebuild_phase.wait()
	return []int{*ebuild_phase.returncode}, nil
}

// ""
func _doebuild_path(settings *config.Config, eapi string) {

	portage_bin_path := []string{settings.ValueDict["PORTAGE_BIN_PATH"]}
	if portage_bin_path[0] != _const.PORTAGE_BIN_PATH {

		portage_bin_path = append(portage_bin_path, _const.PORTAGE_BIN_PATH)
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

	if _const.EPREFIX != settings.ValueDict["EPREFIX"] && settings.ValueDict["ROOT"] == string(os.PathSeparator) {
		prefixes = append(prefixes, settings.ValueDict["EPREFIX"])
	}
	prefixes = append(prefixes, _const.EPREFIX)

	path := overrides

	if settings.Features.Features["xattr"] {
		for _, x := range portage_bin_path {
			path = append(path, filepath.Join(x, "ebuild-helpers", "xattr"))
		}
	}

	if data.uid != 0 &&
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
func doebuild_environment(myebuild , mydo string, myroot=None, settings *config.Config,
	debug bool, use_cache=None, db dbapi.IDbApi) {

	if settings == nil {
		//raise TypeError("Settings argument is required")
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
	mysplit := versions.pkgSplit(mypv, mysettings.configDict["pkg"]["EAPI"])
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
			mysettings.remapset()
			mysettings.SetCpv(mycpv, mydbapi)
		}
	}

	mysettings.ValueDict["PORTAGE_TMPDIR"], _ = filepath.EvalSymlinks(tmpdir)

	delete(mysettings.ValueDict, "EBUILD_PHASE")
	mysettings.ValueDict["EBUILD_PHASE"] = mydo

	//mysettings.ValueDict["PORTAGE_PYTHON"] = _python_interpreter

	mysettings.ValueDict["PORTAGE_SIGPIPE_STATUS"] = fmt.Sprint(128 + unix.SIGPIPE)

	mysettings.ValueDict["BASH_ENV"] = _const.InvalidEnvFile

	if debug {

		mysettings.ValueDict["PORTAGE_DEBUG"] = "1"

		mysettings.ValueDict["EBUILD"] = ebuild_path
		mysettings.ValueDict["O"] = pkg_dir
		mysettings.configDict["pkg"]["CATEGORY"] = cat
		mysettings.ValueDict["PF"] = mypv
	}

	if hasattr(mydbapi, "repositories") {
		repo := mydbapi.repositories.get_repo_for _location(mytree)
		mysettings.ValueDict["PORTDIR"] = repo.eclass_db.porttrees[0]
		mysettings.ValueDict["PORTAGE_ECLASS_LOCATIONS"] = repo.eclass_db.eclass_locations_string
		mysettings.configDict["pkg"]["PORTAGE_REPO_NAME"] = repo.name
	}

	mysettings.ValueDict["PORTDIR"], _ = filepath.EvalSymlinks(mysettings.ValueDict["PORTDIR"])
	delete(mysettings.ValueDict, "PORTDIR_OVERLAY")
	mysettings.ValueDict["DISTDIR"], _ = filepath.EvalSymlinks(mysettings.ValueDict["DISTDIR"])
	mysettings.ValueDict["RPMDIR"], _ = filepath.EvalSymlinks(mysettings.ValueDict["RPMDIR"])

	mysettings.ValueDict["ECLASSDIR"] = mysettings.ValueDict["PORTDIR"] + "/eclass"

	mysettings.ValueDict["PORTAGE_BASHRC_FILES"] = myutil.joinMB(mysettings.pbashrc, "\n")

	mysettings.ValueDict["P"] = mysplit[0] + "-" + mysplit[1]
	mysettings.ValueDict["PN"] = mysplit[0]
	mysettings.ValueDict["PV"] = mysplit[1]
	mysettings.ValueDict["PR"] = mysplit[2]

	if util.noiseLimit < 0 {
		mysettings.ValueDict["PORTAGE_QUIET"] = "1"
	}

	if mysplit[2] == "r0" {
		mysettings.ValueDict["PVR"] = mysplit[1]
	} else {
		mysettings.ValueDict["PVR"] = mysplit[1] + "-" + mysplit[2]
	}

	mysettings.ValueDict["BUILD_PREFIX"] = mysettings.ValueDict["PORTAGE_TMPDIR"] + "/portage"
	mysettings.ValueDict["PKG_TMPDIR"] = mysettings.ValueDict["BUILD_PREFIX"] + "/._unmerge_"

	if myutil.Ins([]string{"unmerge", "prerm", "postrm", "cleanrm"},mydo) {
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
		mysettings.ValueDict["PORTAGE_CONFIGROOT"], _const.EbuildShEnvFile)
	mysettings.ValueDict["PM_EBUILD_HOOK_DIR"] = filepath.Join(
		mysettings.ValueDict["PORTAGE_CONFIGROOT"], _const.EbuildShEnvDir)

	mysettings.ValueDict["PORTAGE_COLORMAP"] = output.ColorMap()

	if _, ok := mysettings.ValueDict["COLUMNS"]; !ok {
		columns := os.Getenv("COLUMNS")
		if columns == "" {
			_, columnsi, _ := output.get_term_size(0)
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

	if !eapi2.EapiIsSupported(eapi) {
		//raise UnsupportedAPIException(mycpv, eapi)
	}

	if _, ok :=mysettings.configDict["pkg"]["PORTAGE_REPO_NAME"]; eapi2.EapiExportsRepository(eapi) &&  ok{
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
					[]string{"SRC_URI"}, mytree = mytree)
			}
			metadata := map[string]string{
				"EAPI":    eapi,
				"SRC_URI": src_uri,
			}
			use := map[string]bool{}
			for _, v := range strings.Fields(mysettings.ValueDict["PORTAGE_USE"]) {
				use[v] = true
			}
			//try{
			uri_map := dbapi._parse_uri_map(mysettings.mycpv, metadata, use)
			//except InvalidDependString{
			//mysettings.configDict["pkg"]["A"] = ""
			//}else{
			um := []string{}
			for u := range uri_map {
				um = append(um, u)
			}
			mysettings.configDict["pkg"]["A"] = strings.Join(um, " ")
			//try{
			uri_map = dbapi._parse_uri_map(nil, metadata, nil)
			//except InvalidDependString{
			//mysettings.configDict["pkg"]["AA"] = ""
			//}else{
			um = []string{}
			for u := range uri_map {
				um = append(um, u)
			}
			mysettings.configDict["pkg"]["AA"] = strings.Join(um, " ")
		}


		ccache := mysettings.Features.Features["ccache"]
		distcc := mysettings.Features.Features["distcc"]
		icecream := mysettings.Features.Features["icecream"]

		if (ccache || distcc || icecream) && myutil.Ins([]string{"unpack",
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
				in := true
				for _, l:= range possible_libexecdirs{
					p := filepath.Join(string(os.PathSeparator), eprefix_lstrip,
						"usr", l, m, "bin")
					if st, _ := os.Stat(p); st != nil && st.IsDir() {
						mysettings.ValueDict["PATH"] = p + ":" + mysettings.ValueDict["PATH"]
						in = false
						break
					}
				}
				if in {
					msg.WriteMsg(fmt.Sprintf("Warning: %s requested but no masquerade dir "+
						"can be found in /usr/lib*/%s/bin\n", m, m), 0, nil)
					delete(mysettings.Features.Features, feature)
				}
			}
		}

		if _, ok := mysettings.ValueDict["MAKEOPTS"]; !ok {
			nproc := util.GetCPUCount()
			if nproc != 0 {
				mysettings.ValueDict["MAKEOPTS"] = fmt.Sprintf("-j%d", nproc)
			}
		}

		if !eapi2.eapiExportsKv(eapi) {
			delete(mysettings.ValueDict, "KV")
		} else if _, ok := mysettings.ValueDict["KV"]; !ok &&
			myutil.Ins([]string{"compile", "config", "configure", "info",
				"install", "nofetch", "postinst", "postrm", "preinst",
				"prepare", "prerm", "setup", "test", "unpack"}, mydo) {
			mykv, err1 := util.ExtractKernelVersion(
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
		compression := util.Compressors[binpkg_compression]
		//except KeyError as e{
		//if binpkg_compression{
		//WriteMsg(fmt.Sprintf("Warning: Invalid or unsupported compression method: %s\n" % e.args[0])
		//}else{

		mysettings.ValueDict["PORTAGE_COMPRESSION_COMMAND"] = "cat"
		//}else{nil
		//try{
		compression_binarys, _ := shlex.Split(strings.NewReader(util.VarExpand(compression["compress"], settings.ValueDict, nil)), false, true)
		compression_binary := compression_binarys[0]
		//except IndexError as e{
		//WriteMsg(fmt.Sprintf("Warning: Invalid or unsupported compression method: %s\n" % e.args[0])
		//}else{
		if process.FindBinary(compression_binary) == "" {
			missing_package := compression["package"]
			msg.WriteMsg(fmt.Sprintf("Warning: File compression unsupported %s. Missing package: %s\n", binpkg_compression, missing_package), 0, nil)
			//}else{
			ss, _ := shlex.Split(strings.NewReader(compression["compress"]), false, true)
			cmds := []string{}
			for _, x := range ss {
				cmds = append(cmds, util.VarExpand(x, settings.ValueDict, nil))
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
	_doebuild_manifest_cache *manifest.Manifest = nil
	_doebuild_broken_ebuilds                        = map[string]bool{}
	_doebuild_broken_manifests = map[string]bool{}
	_doebuild_commands_without_builddir = []string{
		"clean", "cleanrm", "depend", "digest",
		"fetch", "fetchall", "help", "manifest",
	}
)

// 0, 0, 0, 0, 1, 0, "", nil, nil, nil, nil, false
func doebuild(myebuild, mydo string, settings *config.Config, debug, listonly,
	fetchonly, cleanup, use_cache, fetchall int, tree string,
	mydbapi dbapi.IDbApi, vartree *dbapi.varTree, prev_mtimes=None,
	fd_pipes map[int]int, returnpid bool) int {
	if settings == nil {
		//raise TypeError("Settings parameter is required")
	}
	mysettings := settings
	myroot := settings.ValueDict["EROOT"]

	if tree == "" {
		msg.WriteMsg("Warning: tree not specified to doebuild\n", -1, nil)
		tree = "porttree"
	}

	actionmap_deps := map[string][]string{
		"pretend":   {},
		"setup":     {"pretend"},
		"unpack":    {"setup"},
		"prepare":   {"unpack"},
		"configure": {"prepare"},
		"compile":   {"configure"},
		"test":      {"compile"},
		"install":   {"test"},
		"instprep":  {"install"},
		"rpm":       {"install"},
		"package":   {"install"},
		"merge":     {"install"},
	}

	if mydbapi == nil {
		switch tree {
		case "vartree":
			mydbapi = portage.Db().Values()[myroot].VarTree().dbapi
		case "porttree":
			mydbapi = portage.Db().Values()[myroot].PortTree().dbapi
		case "bintree":
			mydbapi = portage.Db().Values()[myroot].BinTree().dbapi
		}
	}

	if vartree == nil && myutil.Ins([]string{"merge", "qmerge", "unmerge"}, mydo) {
		vartree = portage.Db().Values()[myroot].VarTree()
	}

	features := mysettings.Features.Features

	clean_phases := []string{"clean", "cleanrm"}
	validcommands := []string{"help", "clean", "prerm", "postrm", "cleanrm", "preinst", "postinst",
		"config", "info", "setup", "depend", "pretend",
		"fetch", "fetchall", "digest",
		"unpack", "prepare", "configure", "compile", "test",
		"install", "instprep", "rpm", "qmerge", "merge",
		"package", "unmerge", "manifest", "nofetch",}

	if !myutil.Ins(validcommands, mydo) {
		sort.Strings(validcommands)
		msg.WriteMsg(fmt.Sprintf("!!! doebuild: '%s' is not one of the following valid commands:", mydo), -1, nil)
		for vcount := range validcommands {
			if vcount%6 == 0 {
				msg.WriteMsg("\n!!! ", -1, nil)
			}
			msg.WriteMsg(fmt.Sprintf("%11s", validcommands[vcount]), -1, nil)
		}
		msg.WriteMsg("\n", -1, nil)
		return 1
	}

	if mydo == "fetchall" {
		fetchall = 1
		mydo = "fetch"
	}

	if !myutil.Ins(clean_phases, mydo) && !myutil.PathExists(myebuild) {
		msg.WriteMsg(fmt.Sprintf("!!! doebuild: %s not found for %s\n", myebuild, mydo), -1, nil)
		return 1
	}

	pkgdir := filepath.Dir(myebuild)
	manifest_path := filepath.Join(pkgdir, "Manifest")
	var repo_config *repository.RepoConfig = nil
	if tree == "porttree" {
		repo_config = mysettings.Repositories.GetRepoForLocation(
			filepath.Dir(filepath.Dir(pkgdir)))
	}

	var mf *manifest.Manifest = nil
	if features["strict"] &&
		!features["digest"] &&
		tree == "porttree" &&
		!repo_config.thinManifest &&
		!myutil.Ins([]string{"digest", "manifest", "help"}, mydo) &&
		atom.doebuildManifestExemptDepend == 0 &&
		!(repo_config.allowMissingManifest && !myutil.PathExists(manifest_path)) {

		if _doebuild_broken_ebuilds[myebuild] {
			return 1
		}

		if _doebuild_manifest_cache == nil ||
			_doebuild_manifest_cache.getFullname() != manifest_path {
			_doebuild_manifest_cache = nil
			if !myutil.PathExists(manifest_path) {
				out := output.NewEOutput(false)
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
							out := output.NewEOutput(false)
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

	logfile := ""
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

		if myutil.Ins([]string{"digest", "manifest", "help"}, mydo) {
			atom.doebuildManifestExemptDepend -= 1
		}
	}()

	if myutil.Ins([]string{"digest", "manifest", "help"}, mydo) {
		atom.doebuildManifestExemptDepend += 1
	}

	if !returnpid && mydo == "info" {
		tmpdir, _ := ioutil.TempDir("", "")
		tmpdir_orig = mysettings.ValueDict["PORTAGE_TMPDIR"]
		mysettings.ValueDict["PORTAGE_TMPDIR"] = tmpdir
	}

	doebuild_environment(myebuild, mydo, myroot, mysettings, debug != 0,
		use_cache, mydbapi)

	if myutil.Ins(clean_phases, mydo) {
		builddir_lock = nil
		if !returnpid &&
			!myutil.Inmss(mysettings.ValueDict, "PORTAGE_BUILDDIR_LOCKED") {
			builddir_lock = emerge.NewEbuildBuildDir(asyncio._safe_loop(), mysettings)
			builddir_lock.scheduler.run_until_complete(
				builddir_lock.async_lock())
		}
		defer func() {

			if builddir_lock != nil {
				builddir_lock.scheduler.run_until_complete(
					builddir_lock.async_unlock())
			}
		}()
		return _spawn_phase(mydo, mysettings, nil, returnpid, "",
			fd_pipes = fd_pipes, )
	}

	if mydo == "depend" {
		msg.WriteMsg(fmt.Sprintf("!!! DEBUG: dbkey: %s\n", dbkey), 2, nil)
		if returnpid {
			return _spawn_phase(mydo, mysettings, nil, returnpid, "",
				fd_pipes = fd_pipes)
		} else if dbkey != "" {
			mysettings.ValueDict["dbkey"] = dbkey
		} else {
			mysettings.ValueDict["dbkey"] =
				filepath.Join(mysettings.depcachedir, "aux_db_key_temp")
		}

		return _spawn_phase(mydo, mysettings, nil, returnpid, "",
			fd_pipes = fd_pipes)

	} else if mydo == "nofetch" {

		if returnpid {
			msg.WriteMsg(fmt.Sprintf("!!! doebuild: %s\n",
				fmt.Sprintf("returnpid is not supported for phase '%s'\n", mydo)),
				-1, nil)
		}
		return spawn_nofetch(mydbapi, myebuild, mysettings, fd_pipes)
	}

	if tree == "porttree" {
		if !returnpid {
			rval := _validate_deps(mysettings, myroot, mydo, mydbapi)
			if rval != 0 {
				return rval
			}
		}
	} else {

		if mysettings.Features.Features["noauto"] {
			mysettings.Features.Discard("noauto")
		}
	}

	if tmpdir == "" &&
		!myutil.Ins(_doebuild_commands_without_builddir, mydo) {
		rval := _check_temp_dir(mysettings)
		if rval != 0 {
			return rval
		}
	}

	if mydo == "unmerge" {
		if returnpid {
			msg.WriteMsg(fmt.Sprintf("!!! doebuild: %s\n",
				fmt.Sprintf("returnpid is not supported for phase '%s'\n", mydo)),
				-1, nil)
		}
		return dbapi.unmerge(mysettings.ValueDict["CATEGORY"],
			mysettings.ValueDict["PF"], mysettings, vartree, nil, nil)
	}

	phases_to_run := map[string]bool{}
	if returnpid || mysettings.Features.Features["noauto"] || !myutil.Inmsss(actionmap_deps, mydo) {
		phases_to_run[mydo] = true
	} else {
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
	for _, v := range strings.Fields(mysettings.configDict["pkg"]["A"]) {
		alist[v] = true
	}

	unpacked := false
	if tree != "porttree" ||
		myutil.Ins(_doebuild_commands_without_builddir, mydo) {
		//pass
	} else if !phases_to_run["unpack"] {
		unpacked = myutil.PathExists(filepath.Join(
			mysettings.ValueDict["PORTAGE_BUILDDIR"], ".unpacked"))
	} else {
		workdir_st, err := os.Stat(mysettings.ValueDict["WORKDIR"])
		if err != nil {
			//except OSError{
			//pass
		} else {
			newstuff := false
			if !myutil.PathExists(filepath.Join(
				mysettings.ValueDict["PORTAGE_BUILDDIR"], ".unpacked")) {
				msg.WriteMsgStdout(fmt.Sprintf(
					">>> Not marked as unpacked; recreating WORKDIR...\n"), 0)
				newstuff = true
			} else {
				for x := range alist {
					msg.WriteMsgStdout(fmt.Sprintf(">>> Checking %s's mtime...\n", x), 0)
					x_st, err := os.Stat(filepath.Join(
						mysettings.ValueDict["DISTDIR"], x))
					if err != nil {
						//except OSError{
						x_st = nil
					}

					if x_st != nil && x_st.ModTime().Nanosecond() > workdir_st.ModTime().Nanosecond() {
						msg.WriteMsgStdout(fmt.Sprintf(">>> Timestamp of "+
							"%s has changed; recreating WORKDIR...\n", x), 0)
						newstuff = true
						break
					}
				}
			}

			if newstuff {
				if builddir_lock == nil && !myutil.Inmss(mysettings.ValueDict, "PORTAGE_BUILDDIR_LOCKED") {
					builddir_lock = emerge.NewEbuildBuildDir(
						asyncio._safe_loop(),
						mysettings)
					builddir_lock.scheduler.run_until_complete(
						builddir_lock.async_lock())
				}
				//try{
				_spawn_phase("clean", mysettings, nil, false, "")
				//finally{
				if builddir_lock != nil {
					builddir_lock.scheduler.run_until_complete(
						builddir_lock.async_unlock())
					builddir_lock = nil
				}
			} else {
				msg.WriteMsgStdout((">>> WORKDIR is up-to-date, keeping...\n"), 0)
				unpacked = true
			}
		}
	}

	have_build_dirs := false
	if !myutil.Ins([]string{"digest", "fetch", "help", "manifest"}, mydo) {
		if !returnpid && !myutil.Inmss(mysettings.ValueDict, "PORTAGE_BUILDDIR_LOCKED") {
			builddir_lock := emerge.NewEbuildBuildDir(asyncio._safe_loop(), mysettings)
			builddir_lock.scheduler.run_until_complete(builddir_lock.async_lock())
		}
		mystatus := Prepare_build_dirs(mysettings, cleanup)
		if mystatus != 0 {
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

	if eapi2.EapiExportsMergeType(mysettings.ValueDict["EAPI"]) &&
		!myutil.Inmss(mysettings.configDict["pkg"], "MERGE_TYPE") {
		if tree == "porttree" {
			mysettings.configDict["pkg"]["MERGE_TYPE"] = "source"
		} else if tree == "bintree" {
			mysettings.configDict["pkg"]["MERGE_TYPE"] = "binary"
		}
	}

	if tree == "porttree" {
		mysettings.configDict["pkg"]["EMERGE_FROM"] = "ebuild"
	} else if tree == "bintree" {
		mysettings.configDict["pkg"]["EMERGE_FROM"] = "binary"
	}

	if eapi2.EapiExportsReplaceVars(mysettings.ValueDict["EAPI"]) &&
		(myutil.Ins([]string{"postinst", "preinst", "pretend", "setup"}, mydo) ||
			(!features["noauto"] && !returnpid &&
				(myutil.Inmsss(actionmap_deps, mydo) || myutil.Ins([]string{"merge", "package", "qmerge"}, mydo)))) {
		if vartree == nil {
			msg.WriteMsg("Warning: vartree not given to doebuild. "+
				"Cannot set REPLACING_VERSIONS in pkg_{pretend,setup}\n", 0, nil)
		} else {
			vardb := vartree.dbapi
			cpv := mysettings.mycpv
			cpv_slot := fmt.Sprintf("%s%s%s", cpv.cp, dep.slotSeparator, cpv.slot)
			matches := map[string]bool{}
			for _, match := range append(vardb.match(cpv_slot, 1), vardb.match("="+cpv.string, 1)...) {
				matches[versions.cpvGetVersion(match.string, "")] = true
			}

			mysettings.ValueDict["REPLACING_VERSIONS"] = myutil.joinMB(matches, " ")
		}
	}

	if myutil.Ins([]string{"config", "help", "info", "postinst",
		"preinst", "pretend", "postrm", "prerm"}, mydo) {
		if mydo == "preinst" || mydo == "postinst" {
			env_file := filepath.Join(filepath.Dir(mysettings.ValueDict["EBUILD"]),
				"environment.bz2")
			if myutil.pathIsFile(env_file) {
				mysettings.ValueDict["PORTAGE_UPDATE_ENV"] = env_file
			}
		}
		defer delete(mysettings.ValueDict, "PORTAGE_UPDATE_ENV")
		return _spawn_phase(mydo, mysettings, "",returnpid,logfile,
			fd_pipes = fd_pipes)
	}

	mycpv := mysettings.ValueDict["CATEGORY"] + "/" + mysettings.ValueDict["PF"]

	need_distfiles := tree == "porttree" && !unpacked &&
		((mydo == "fetch" || mydo == "unpack") ||
			(mydo != "digest" && mydo != "manifest") && !features["noauto"])
	if need_distfiles {
		src_uri := mysettings.configDict["pkg"]["SRC_URI"]
		if src_uri == "" {
			src_uri, = mydbapi.aux_get(mysettings.mycpv,
				map[string]bool{"SRC_URI": true}, mytree = filepath.Dir(filepath.Dir(
				filepath.Dir(myebuild))))
		}
		metadata := map[string]string{
			"EAPI":    mysettings.ValueDict["EAPI"],
			"SRC_URI": src_uri,
		}
		use := map[string]bool{}
		for _, v := range strings.Fields(mysettings.ValueDict["PORTAGE_USE"]) {
			use[v] = true
		}
		//try{
		alist := dbapi._parse_uri_map(mysettings.mycpv, metadata, use)
		aalist := dbapi._parse_uri_map(mysettings.mycpv, metadata, nil)
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

		_fetch_subprocess := func(fetchme, mysettings *config.Config, listonly, dist_digests) {

			if atom._want_userfetch(mysettings) {
				atom._drop_privs_userfetch(mysettings)
			}

			return atom.fetch(fetchme, mysettings, listonly = listonly,
				fetchonly = fetchonly, allow_missing_digests=false,
				digests = dist_digests)
		}

		loop = asyncio._safe_loop()
		var success bool
		if loop.is_running() {

			success = atom.fetch(fetchme, mysettings, listonly = listonly,
				fetchonly = fetchonly, allow_missing_digests=false,
				digests = dist_digests)
		} else {
			success = loop.run_until_complete(
				loop.run_in_executor(ForkExecutor(loop = loop),
			_fetch_subprocess, fetchme, mysettings, listonly, dist_digests))
		}
		if !success {
			if !listonly {
				spawn_nofetch(mydbapi, myebuild, mysettings, fd_pipes)
			}
			return 1
		}
	}

	checkme := map[string]map[string]bool{}
	if need_distfiles {

		//checkme = []
	} else if unpacked {

		//checkme = []
	} else {
		checkme = alist
	}

	if mydo == "fetch" && listonly != 0 {
		return 0
	}

	//try{
	if mydo == "manifest" {
		mf = nil
		_doebuild_manifest_cache = nil
		return digestgen(nil, mysettings, mydbapi)
	} else if mydo == "digest" {
		mf = nil
		_doebuild_manifest_cache = nil
		return digestgen(nil, mysettings, mydbapi)
	} else if mysettings.Features.Features["digest"] {
		mf = nil
		_doebuild_manifest_cache = nil
		digestgen(nil, mysettings, mydbapi)
	}
	//except PermissionDenied as e{
	//WriteMsg(fmt.Sprintf(("!!! Permission Denied: %s\n") % (e,), -1,nil)
	//if mydo =="digest" || mydo == "manifest"):
	//return 1

	if mydo == "fetch" {
		return 0
	}

	if tree == "porttree" && Digestcheck(checkme, mysettings, features["strict"], mf) == 0 {
		return 1
	}

	if tree == "porttree" && ((mydo != "setup" && !features["noauto"]) || mydo == "install" || mydo == "unpack") {
		_prepare_fake_distdir(mysettings, alist)
	}

	actionmap := _spawn_actionmap(mysettings)

	for x := range actionmap {
		if len(actionmap_deps[x]) > 0 {
			actionmap[x].dep = strings.Join(actionmap_deps[x], " ")
		}
	}

	_, regular_actionmap_phase := actionmap[mydo]

	if regular_actionmap_phase{
		var bintree *dbapi.BinaryTree
		if mydo == "package" {

			if portage.Db() != nil {
				bintree = portage.Db().Values()[mysettings.ValueDict["EROOT"]].BinTree()
				mysettings.ValueDict["PORTAGE_BINPKG_TMPFILE"] =
					bintree.getname(mysettings.mycpv.string, false) +
						fmt.Sprintf(".%s", os.Getpid(), )
				bintree._ensure_dir(filepath.Dir(
					mysettings.ValueDict["PORTAGE_BINPKG_TMPFILE"]))
			} else {
				parent_dir := filepath.Join(mysettings.ValueDict["PKGDIR"],
					mysettings.ValueDict["CATEGORY"])
				util.EnsureDirs(parent_dir, -1, -1, -1, -1, nil, true)
				if st, _ := os.Stat(parent_dir) st != nil && st.Mode()&0222 == 0 {
					//raise PermissionDenied("access('%s', os.W_OK)" % parent_dir)
				}
			}
		}
		retval := spawnebuild(mydo, actionmap, mysettings, debug, 0, logfile, fd_pipes, returnpid)

		if returnpid && isinstance(retval, list) {
			return retval
		}

		if retval == 0 {
			if mydo == "package" && bintree != nil {
				pkg := bintree.inject(mysettings.mycpv.string, mysettings.ValueDict["PORTAGE_BINPKG_TMPFILE"])
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
						f, _ := os.OpenFile(filepath.Join(infoloc, k), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
						f.Write([]byte(v))
					}
				}
			}
		} else {
			if myutil.Inmss(mysettings.ValueDict, "PORTAGE_BINPKG_TMPFILE") {
				if err := syscall.Unlink(mysettings.ValueDict["PORTAGE_BINPKG_TMPFILE"]); err != nil {
					//except OSError{
					//pass
				}
			}
		}
	} else if returnpid {
		msg.WriteMsg(fmt.Sprintf("!!! doebuild: %s\n",
			fmt.Sprintf("returnpid is not supported for phase '%s'\n", mydo)),
			-1, nil)
	}

	retval := 0
	if regular_actionmap_phase {
		//pass
	} else if mydo == "qmerge" {

		if !myutil.PathExists(filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], ".installed")) {
			msg.WriteMsg(("!!! mydo=qmerge, but the install phase has not been run\n"),
				-1, nil)
			return 1
		}

		if !mysettings.Features.Features["noclean"] {
			mysettings.Features.Features["noclean"] = true
		}
		_handle_self_update(mysettings)

		retval = dbapi.merge(
			mysettings.ValueDict["CATEGORY"], mysettings.ValueDict["PF"], mysettings.ValueDict["D"],
			filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], "build-info"),
			mysettings, mysettings.ValueDict["EBUILD"], tree,
			mydbapi, vartree, prev_mtimes, nil, nil, fd_pipes)
	} else if mydo == "merge" {
		retval = spawnebuild("install", actionmap, mysettings, debug, 1, logfile, fd_pipes, returnpid)
		if retval != 0 {
			elog.elog_process(mysettings.mycpv.string, mysettings, nil)
		}
		if retval == 0 {
			_handle_self_update(mysettings)
			retval = dbapi.merge(mysettings.ValueDict["CATEGORY"], mysettings.ValueDict["PF"],
				mysettings.ValueDict["D"], filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"],
					"build-info"), mysettings, mysettings.ValueDict["EBUILD"],
				tree, mydbapi, vartree, prev_mtimes, nil, nil, fd_pipes)
		}
	} else {
		msg.WriteMsgStdout(fmt.Sprintf("!!! Unknown mydo: %s\n", mydo), -1)
		return 1
	}

	return retval
}

func _check_temp_dir(settings *config.Config)  int{
	if !myutil.Inmss(settings.ValueDict, "PORTAGE_TMPDIR") ||
		!myutil.pathIsDir(settings.ValueDict["PORTAGE_TMPDIR"]) {
		msg.WriteMsg(fmt.Sprintf(("The directory specified in your "+
			"PORTAGE_TMPDIR variable, '%s',\n"+
			"does not exist.  Please create this directory or "+
			"correct your PORTAGE_TMPDIR setting.\n"),
			settings.ValueDict["PORTAGE_TMPDIR"]), -1, nil)
		return 1
	}

	checkdir := firstExisting(filepath.Join(settings.ValueDict["PORTAGE_TMPDIR"], "portage"))

	if !myutil.OsAccess(checkdir, unix.W_OK) {
		msg.WriteMsg(fmt.Sprintf("%s is not writable.\n"+
			"Likely cause is that you've mounted it as readonly.\n", checkdir),
			-1, nil)
		return 1
	}

	fd, _ := ioutil.TempFile(checkdir,  "exectest-*")
	os.Chmod(fd.Name(), 0755)
	if ! myutil.OsAccess(fd.Name(), unix.X_OK) {
		msg.WriteMsg(fmt.Sprintf("Can not execute files in %s\n"+
			"Likely cause is that you've mounted it with one of the\n"+
			"following mount options: 'noexec', 'user', 'users'\n\n"+
			"Please make sure that portage can execute files in this directory.\n", checkdir),
			-1, nil)
		return 1
	}

	return 0
}

func _prepare_env_file(settings *config.Config) int {

	env_extractor := emerge.NewBinpkgEnvExtractor(false, asyncio._safe_loop(), settings)

	if env_extractor.dest_env_exists() {

		return 0
	}

	if !env_extractor.saved_env_exists() {

		return 0
	}

	env_extractor.start()
	env_extractor.wait()
	return *env_extractor.returncode
}

type ActionMapArgs struct {
	droppriv  bool
	free      bool
	sesandbox bool
	fakeroot  bool
}

type Actionmap map[string]*struct {
	cmd  string
	args ActionMapArgs
	dep  string
}

func _spawn_actionmap(settings *config.Config) Actionmap {
	features := settings.Features.Features
	restrict := strings.Fields(settings.ValueDict["PORTAGE_RESTRICT"])
	nosandbox := (features["userpriv"]) &&
		(!features["usersandbox"]) &&
		!myutil.Ins(restrict, "userpriv") &&
		!myutil.Ins(restrict, "nouserpriv")

	if !process.sandbox_capable {
		nosandbox = true
	}

	sesandbox := settings.Selinux_enabled() &&
		features["sesandbox"]

	droppriv := features["userpriv"] &&
		!myutil.Ins(restrict, "userpriv") &&
		*data.Secpass >= 2

	fakeroot := features["fakeroot"]

	portage_bin_path := settings.ValueDict["PORTAGE_BIN_PATH"]
	ebuild_sh_binary := filepath.Join(portage_bin_path,
		filepath.Base(_const.EBUILD_SH_BINARY))
	misc_sh_binary := filepath.Join(portage_bin_path,
		filepath.Base(_const.MISC_SH_BINARY))
	ebuild_sh := vars.ShellQuote(ebuild_sh_binary) + " %s"
	misc_sh := vars.ShellQuote(misc_sh_binary) + " __dyn_%s"

	actionmap := Actionmap{
		"pretend":   {cmd: ebuild_sh, args: ActionMapArgs{droppriv: false, free: true, sesandbox: false, fakeroot: false}},
		"setup":     {cmd: ebuild_sh, args: ActionMapArgs{droppriv: false, free: true, sesandbox: false, fakeroot: false}},
		"unpack":    {cmd: ebuild_sh, args: ActionMapArgs{droppriv: droppriv, free: false, sesandbox: sesandbox, fakeroot: false}},
		"prepare":   {cmd: ebuild_sh, args: ActionMapArgs{droppriv: droppriv, free: false, sesandbox: sesandbox, fakeroot: false}},
		"configure": {cmd: ebuild_sh, args: ActionMapArgs{droppriv: droppriv, free: nosandbox, sesandbox: sesandbox, fakeroot: false}},
		"compile":   {cmd: ebuild_sh, args: ActionMapArgs{droppriv: droppriv, free: nosandbox, sesandbox: sesandbox, fakeroot: false}},
		"test":      {cmd: ebuild_sh, args: ActionMapArgs{droppriv: droppriv, free: nosandbox, sesandbox: sesandbox, fakeroot: false}},
		"install":   {cmd: ebuild_sh, args: ActionMapArgs{droppriv: false, free: false, sesandbox: sesandbox, fakeroot: fakeroot}},
		"instprep":  {cmd: misc_sh, args: ActionMapArgs{droppriv: false, free: false, sesandbox: sesandbox, fakeroot: fakeroot}},
		"rpm":       {cmd: misc_sh, args: ActionMapArgs{droppriv: false, free: false, sesandbox: false, fakeroot: fakeroot}},
		"package":   {cmd: misc_sh, args: ActionMapArgs{droppriv: false, free: false, sesandbox: false, fakeroot: fakeroot}},
	}

	return actionmap
}

func _validate_deps(mysettings *config.Config, myroot, mydo string, mydbapi dbapi.IDbApi)int {
	invalid_dep_exempt_phases := map[string]bool{"clean": true, "cleanrm": true, "help": true, "prerm": true, "postrm": true}
	all_keys := myutil.CopyMapSB(structs.NewPackage(false, nil, false, nil, nil, "").metadataKeys)
	all_keys["SRC_URI"] = true
	metadata := mysettings.configDict["pkg"]
	if myutil.Inmss(metadata, "PORTAGE_REPO_NAME") || myutil.Inmss(metadata, "SRC_URI") {
		m2 := myutil.CopyMapSS(metadata)
		metadata = map[string]string{}
		for k := range all_keys {
			metadata[k] = m2[k]
		}

		md := map[string]string{}
		for k := range all_keys {
			if myutil.Inmss(metadata, k) {
				md[k] = metadata[k]
			}
		}
		md["repository"] = metadata["PORTAGE_REPO_NAME"]
		metadata = md
	} else {
		md := map[string]string{}
		for k := range all_keys {
			if myutil.Inmss(metadata, k) {
				md[k] = metadata[k]
			}
		}
		md["repository"] = metadata["PORTAGE_REPO_NAME"]
		metadata = md
		for i := range all_keys {
			metadata[all_keys[i]] = mydbapi.AuxGet(mysettings.mycpv, all_keys, mysettings.ValueDict["PORTAGE_REPO_NAME"])[i]
		}
	}

	type FakeTree struct {
		dbapi.IDbApi
	}

	NewFakeTree := func(mydb dbapi.IDbApi) *FakeTree {
		f := &FakeTree{}
		f.IDbApi = mydb
		return f
	}

	root_config := emerge.NewRootConfig(mysettings, &portage.Tree{_porttree: NewFakeTree(mydbapi)}, nil)

	pkg := structs.NewPackage(false, mysettings.mycpv, false, metadata, root_config, "ebuild")

	msgs := []string{}
	if pkg.invalid {
		for k, versions.v
			in
		pkg.invalid.items()
		{
			for msg
				in
			versions.v {
				msgs = append(msgs, fmt.Sprintf("  %s\n", msg, ))
			}
		}
	}

	if len(msgs) > 0 {
		msg.WriteMsgLevel(fmt.Sprintf("Error(s) in metadata for '%s':\n",
			mysettings.mycpv, ), 40, -1)
		for _, x := range msgs {
			msg.WriteMsgLevel(x,
				40, -1)
		}
		if !invalid_dep_exempt_phases[mydo] {
			return 1
		}
	}

	if !pkg.built &&
		!myutil.Ins([]string{"digest", "help", "manifest"}, mydo) &&
		pkg.metadata.valueDict["REQUIRED_USE"] != "" &&
		eapi2.eapiHasRequiredUse(pkg.eapi()) {
		result = check_required_use(pkg._metadata["REQUIRED_USE"],
			pkg.use.enabled, pkg.iuse.is_valid_flag, eapi = pkg.eapi)
		if !result {
			reduced_noise = result.tounicode()
			msg.WriteMsg(fmt.Sprintf("\n  %s\n"%_("The following REQUIRED_USE flag"+
				" constraints are unsatisfied:")), -1, nil)
			msg.WriteMsg(fmt.Sprintf("    %s\n", reduced_noise),
				-1, nil)
			normalized_required_use =
				strings.Join(strings.Fields(pkg._metadata["REQUIRED_USE"]), " ")
			if reduced_noise != normalized_required_use {
				msg.WriteMsg(fmt.Sprintf("\n  %s\n", "The above constraints "+
					"are a subset of the following complete expression:"),
					-1, nil)
				msg.WriteMsg(fmt.Sprintf("    %s\n",
					dep.humanReadableRequiredUse(normalized_required_use)),
					-1, nil)
			}
			msg.WriteMsg("\n", -1, nil)
		}
		return 1
	}

	return 0
}

// false, false, false, false, false, true, true, false, false, nil
func spawnE(mystring string, mysettings  *config.Config, debug, free, droppriv,
	sesandbox, fakeroot, networked, ipc, mountns, pidns bool, fd_pipes map[int]int, **keywords) {

	if fd_pipes == nil {
		fd_pipes = map[int]int{
			0:int(atom.getStdin().Fd()),
			1:syscall.Stdout,
			2:syscall.Stderr,
		}
	}

	//stdout_filenos := []int{syscall.Stdout, syscall.Stderr}
	for _, fd:= range fd_pipes{
		if fd ==syscall.Stdout||fd ==syscall.Stderr {
			//sys.__stdout__.flush()
			//sys.__stderr__.flush()
			break
		}
	}

	features := mysettings.Features.Features

	if data.uid == 0 && runtime.GOOS == "linux" {
		keywords["unshare_net"] = !networked
		keywords["unshare_ipc"] = !ipc
		keywords["unshare_mount"] = mountns
		keywords["unshare_pid"] = pidns

		if !networked && mysettings.ValueDict["EBUILD_PHASE"] != "nofetch" &&
			(features["network-sandbox-proxy"] || features["distcc"]) {

			//try{
			proxy := get_socks5_proxy(mysettings)
			//except NotImplementedError{
			//pass
			//}else{
			mysettings.ValueDict["PORTAGE_SOCKS5_PROXY"] = proxy
			mysettings.ValueDict["DISTCC_SOCKS_PROXY"] = proxy
		}
	}

	fakeroot = fakeroot && data.uid != 0 && process.fakeroot_capable
	portage_build_uid := os.Getuid()
	portage_build_gid := os.Getgid()
	logname := ""
	if data.uid == 0 && data.Portage_uid != nil && data.Portage_gid != nil && hasattr(os, "setgroups") {
		if droppriv {
			logname = *data._portage_username
			keywords.update(
			{
				"uid": data.Portage_uid,
				"gid": data.Portage_gid,
				"groups": data.userpriv_groups,
				"umask": 0o22
			})

			stdout_fd := fd_pipes[1]
			if stdout_fd != 0 {
				try{
					subprocess_tty = _os.ttyname(stdout_fd)
				}
				except
				OSError{
					pass
				} else {
					try{
						parent_tty = _os.ttyname(sys.__stdout__.fileno())
					}
					except
					OSError{
						parent_tty = None
					}

					if subprocess_tty != parent_tty {
						_os.chown(subprocess_tty,
							int(data.Portage_uid), int(data.Portage_gid))
					}
				}
			}

			if features["userpriv"] && !myutil.Ins(strings.Fields(mysettings.ValueDict["PORTAGE_RESTRICT"]), "userpriv") && *data.Secpass >= 2 {

				portage_build_uid = int(*data.Portage_uid)
				portage_build_gid = int(*data.Portage_gid)
			}
		}
	}

	if !myutil.Inmss(mysettings.ValueDict, "PORTAGE_BUILD_USER") {
		user := ""
		try{
			user = pwd.getpwuid(portage_build_uid).pw_name
		}
		except
		KeyError{
			if portage_build_uid == 0{
			user = "root"
		} else if portage_build_uid == portage_uid{
			user = portage.data._portage_username
		}
		}
		if user != "" {
			mysettings.ValueDict["PORTAGE_BUILD_USER"] = user
		}
	}

	if !myutil.Inmss(mysettings.ValueDict, "PORTAGE_BUILD_GROUP") {
		group := ""
		try{
			group = grp.getgrgid(portage_build_gid).gr_name
		}
		except
		KeyError{
			if portage_build_gid == 0{
			group = "root"
		} else if portage_build_gid == portage_gid{
			group = portage.data._portage_grpname
		}
		}
		if group != "" {
			mysettings.ValueDict["PORTAGE_BUILD_GROUP"] = group
		}
	}

	if !free {
		free = (droppriv && !features["usersandbox"]) || (!droppriv && !features["sandbox"] && !features["usersandbox"] && !fakeroot)
	}

	if !free && !(fakeroot || process.sandbox_capable) {
		free = true
	}

	if mysettings.mycpv != nil {
		keywords["opt_name"] = fmt.Sprintf("[%s]", mysettings.mycpv)
	} else {
		keywords["opt_name"] = fmt.Sprintf("[%s/%s]", mysettings.ValueDict["CATEGORY"], mysettings.ValueDict["PF"])
	}

	if _, ok := os.LookupEnv("SANDBOX_ACTIVE"); free || ok {
		keywords["opt_name"] += " bash"
		spawn_func = process.spawn_bash
	} else if fakeroot {
		keywords["opt_name"] += " fakeroot"
		keywords["fakeroot_state"] = filepath.Join(mysettings.ValueDict["T"], "fakeroot.state")
		spawn_func = portage.process.spawn_fakeroot
	} else {
		keywords["opt_name"] += " sandbox"
		spawn_func = portage.process.spawn_sandbox
	}

	if sesandbox {
		spawn_func = selinux.spawn_wrapper(spawn_func,
			mysettings.ValueDict["PORTAGE_SANDBOX_T"])
	}

	logname_backup := ""
	if logname != "" {
		logname_backup = mysettings.configDict["env"]["LOGNAME"]
		mysettings.configDict["env"]["LOGNAME"] = logname
	}

	defer func() {
		if logname == "" {
			//pass
		} else if logname_backup == "" {
			delete(mysettings.configDict["env"], "LOGNAME")
		} else {
			mysettings.configDict["env"]["LOGNAME"] = logname_backup
		}
	}()
	if keywords.get("returnpid") {
		return spawn_func(mystring, env = mysettings.environ(),fd_pipes
		**keywords)
	}

	proc := emerge.NewEbuildSpawnProcess(
		false, mystring,
		scheduler = emerge.SchedulerInterface(asyncio._safe_loop()),
		spawn_func = spawn_func,
		settings = mysettings, fd_pipes, **keywords)

	proc.start()
	proc.wait()

	return proc.returncode

}

// 0, nil, "", false
func spawnebuild(mydo string, actionmap Actionmap, mysettings *config.Config, debug, alwaysdep int,
	logfile string, fd_pipes map[int]int, returnpid bool) int {

	if returnpid {
		warnings.warn("portage.spawnebuild() called "
		"with returnpid parameter enabled. This usage will "
		"not be supported in the future.",
			DeprecationWarning, stacklevel = 2)
	}

	if !returnpid && (alwaysdep != 0|| !mysettings.Features.Features["noauto"]) {
		if actionmap[mydo].dep != "" {
			retval := spawnebuild(actionmap[mydo].dep, actionmap,
				mysettings, debug, alwaysdep, logfile,
				fd_pipes, returnpid)
			if retval != 0 {
				return retval
			}
		}
	}

	eapi := mysettings.ValueDict["EAPI"]

	if (mydo == "configure" || mydo == "prepare") && !eapi2.eapiHasSrcPrepareAndSrcConfigure(eapi) {
		return 0
	}

	if mydo == "pretend" && !eapi2.eapiHasPkgPretend(eapi) {
		return 0
	}

	if !(mydo == "install" && mysettings.Features.Features["noauto"]) {
		check_file := filepath.Join(
			mysettings.ValueDict["PORTAGE_BUILDDIR"], fmt.Sprintf(".%sed", strings.TrimRight(mydo, "e")))
		if myutil.PathExists(check_file) {
			msg.WriteMsgStdout(fmt.Sprintf((">>> It appears that "+
				"'%s' has already executed for '%s'; skipping.\n"),
				mydo, mysettings.ValueDict["PF"]), 0)
			msg.WriteMsgStdout(fmt.Sprintf(">>> Remove '%s' to force %s.\n",
				check_file, mydo), 0)
			return 0
		}
	}

	return _spawn_phase(mydo, mysettings,
		actionmap, returnpid, logfile,
		fd_pipes=fd_pipes, )
}

var _post_phase_cmds = {

"install": [
"install_qa_check",
"install_symlink_html_docs",
"install_hooks"],

"preinst": (
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
"postinst": [
"postinst_qa_check"],
}

func _post_phase_userpriv_perms(mysettings *config.Config) {
	if  mysettings.Features.Features["userpriv"] && *data.Secpass >= 2 {
		for _, path := range []string{mysettings.ValueDict["HOME"], mysettings.ValueDict["T"]}{
			apply_recursive_permissions(path,
				data.uid = data.Portage_uid, gid = data.Portage_gid, dirmode = 0o700, dirmask=0,
				filemode = 0o600, filemask=0)
		}
	}
}

// nil
func _check_build_log(mysettings *config.Config, out io.Writer) {

	logfile := mysettings.ValueDict["PORTAGE_LOG_FILE"]
	if logfile == "" {
		return
	}

	f_real, err := os.Open(logfile)
	if err != nil {
		return
	}

	var f io.Reader = f_real
	if strings.HasSuffix(logfile, ".gz") {
		f, _ = gzip.NewReader(f_real)
	}

	am_maintainer_mode := []string{}
	bash_command_not_found := []string{}
	bash_command_not_found_re := regexp.MustCompile("(.*): line (\\d*): (.*): command not found$")
	command_not_found_exclude_re := regexp.MustCompile("/configure: line ")
	helper_missing_file := []string{}
	helper_missing_file_re := regexp.MustCompile("^!!! (do|new).*: .* does not exist$")

	configure_opts_warn := []string{}
	configure_opts_warn_re := regexp.MustCompile("^configure: WARNING: [Uu]nrecognized options: (.*)")

	q, err := ioutil.ReadFile(filepath.Join(
		mysettings.ValueDict["PORTAGE_BUILDDIR"],
		"build-info", "QA_CONFIGURE_OPTIONS"))
	if err != nil {
		//except IOError as e:
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//raise
		}
	}

	qa_configure_opts := strings.Fields(string(q))

	var qcoRe *regexp.Regexp
	if len(qa_configure_opts) > 0 {
		qcos := ""
		if len(qa_configure_opts) > 1 {
			qco := []string{}
			for _, x := range qa_configure_opts {
				qco = append(qco, fmt.Sprintf("(%s)", x))
			}
			qcos = strings.Join(qco, "|")
			qcos = fmt.Sprintf("^(%s)$", qcos)
		} else {
			qcos = fmt.Sprintf("^%s$", qa_configure_opts[0])
		}
		qcoRe = regexp.MustCompile(qcos)
	}

	qa_am_maintainer_mode_f, err := ioutil.ReadFile(filepath.Join(
		mysettings.ValueDict["PORTAGE_BUILDDIR"],
		"build-info", "QA_AM_MAINTAINER_MODE"))
	if err != nil {
		//}except IOError as e{
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//raise
		}
	}

	qa_am_maintainer_mode := []string{}
	for _, x := range strings.Split(string(qa_am_maintainer_mode_f), "\n") {
		if x != "" {
			qa_am_maintainer_mode = append(qa_am_maintainer_mode, x)
		}
	}

	var qaamRe *regexp.Regexp
	if len(qa_am_maintainer_mode) > 0 {
		qaams := ""
		if len(qa_am_maintainer_mode) > 1 {
			qaa := []string{}
			for _, x := range qa_am_maintainer_mode {
				qaa = append(qaa, fmt.Sprintf("(%s)", x))
			}
			qaams = strings.Join(qaa, "|")
			qaams = fmt.Sprintf("^(%s)$", qaams)
		} else {
			qaams = fmt.Sprintf("^%s$", qa_am_maintainer_mode[0])
		}
		qaamRe = regexp.MustCompile(qaams)
	}

	am_maintainer_mode_re := regexp.MustCompile("/missing --run ")
	am_maintainer_mode_exclude_re := regexp.MustCompile("(/missing --run (autoheader|autotest|help2man|makeinfo)|^\\s*Automake:\\s)")

	make_jobserver_re := regexp.MustCompile("g?make\\[\\d+\\]: warning: jobserver unavailable:")
	make_jobserver := []string{}

	_eerror := func(lines []string) {
		for _, line := range lines {
			elog.eerror(line, "install", mysettings.mycpv.string, out)
		}
	}

	//try{
	fl, _ := ioutil.ReadAll(f)
	for _, line := range strings.Split(string(fl), "\n") {
		if am_maintainer_mode_re.MatchString(line) &&
			!am_maintainer_mode_exclude_re.MatchString(line) &&
			(qaamRe == nil ||
				!qaamRe.MatchString(line)) {
			am_maintainer_mode = append(am_maintainer_mode, strings.TrimRight(line, "\n"))
		}

		if bash_command_not_found_re.MatchString(line)  &&
			!command_not_found_exclude_re.MatchString(line)  {
			bash_command_not_found = append(bash_command_not_found, strings.TrimRight(line, "\n"))
		}

		if helper_missing_file_re.MatchString(line)  {
			helper_missing_file = append(helper_missing_file, strings.TrimRight(line, "\n"))
		}

		m := configure_opts_warn_re.FindStringSubmatch(line)
		if m != nil {
			for _, x := range strings.Split(m[1], ", ") {
				if qcoRe == nil || !qcoRe.MatchString(x) {
					configure_opts_warn = append(configure_opts_warn, x)
				}
			}
		}

		if !make_jobserver_re.MatchString(line)  {
			make_jobserver = append(make_jobserver, strings.TrimRight(line, "\n"))
		}
	}
	//}except (EOFError, zlib.error) as e{
	_eerror([]string{fmt.Sprintf("portage encountered a zlib error: '%s'", err, ),
		fmt.Sprintf("while reading the log file: '%s'", logfile)})
	//}finally{
	//f.close()
	//}

	_eqawarn := func(lines []string) {
		for _, line := range lines {
			elog.eqawarn(line, "install", mysettings.mycpv.string, out)
		}
	}
	wrap_width := 70

	if len(am_maintainer_mode) > 0 {
		msg := []string{"QA Notice: Automake \"maintainer mode\" detected:"}
		msg = append(msg, "")
		for _, line := range am_maintainer_mode {
			msg = append(msg, "\t"+line)
		}
		msg = append(msg, "")
		msg = append(myutil.SplitSubN(
			"If you patch Makefile.am, "+
				"configure.in,  or configure.ac then you "+
				"should use autotools.eclass and "+
				"eautomake or eautoreconf. Exceptions "+
				"are limited to system packages "+
				"for which it is impossible to run "+
				"autotools during stage building. "+
				"See https://wiki.gentoo.org/wiki/Project:Quality_Assurance/Autotools_failures"+
				" for more information.",
			wrap_width))
		_eqawarn(msg)
	}

	if len(bash_command_not_found) > 0 {
		msg := []string{"QA Notice: command not found:"}
		msg = append(msg, "")
		for _, line := range bash_command_not_found {
			msg = append(msg, "\t"+line)
		}
		_eqawarn(msg)
	}

	if len(helper_missing_file) > 0 {
		msg := []string{"QA Notice: file does not exist:"}
		msg = append(msg, "")
		for _, line := range helper_missing_file {
			msg = append(msg, "\t"+line[4:])
		}
		_eqawarn(msg)
	}

	if len(configure_opts_warn) > 0 {
		msg := []string{"QA Notice: Unrecognized configure options:"}
		msg = append(msg, "")
		for _, line := range configure_opts_warn {
			msg = append(msg, "\t"+line)
		}
		_eqawarn(msg)
	}

	if len(make_jobserver) > 0 {
		msg := []string{"QA Notice: make jobserver unavailable:"}
		msg = append(msg, "")
		for _, line := range make_jobserver {
			msg = append(msg, "\t"+line)
		}
		_eqawarn(msg)
	}

	//f.close()
	if f_real != nil {
		f_real.Close()
	}
}

func _post_src_install_write_metadata(settings *config.Config){

	eapi_attrs := eapi2.GetEapiAttrs(settings.configDict["pkg"]["EAPI"])

	build_info_dir := filepath.Join(settings.ValueDict["PORTAGE_BUILDDIR"], "build-info")

	metadata_keys := []string{"IUSE"}
	if eapi_attrs.iuseEffective {
		metadata_keys = append(metadata_keys, "IUSE_EFFECTIVE")
	}

	for _, k := range metadata_keys {
		v := settings.configDict["pkg"][k]
		if v != "" {
			util.write_atomic(filepath.Join(build_info_dir, k), v+"\n", 0, true)
		}
	}

	for _, k := range []string{"CHOST"} {
		v := settings.ValueDict[k]
		if v != "" {
			util.write_atomic(filepath.Join(build_info_dir, k), v+"\n", 0, true)
		}
	}

	f, _ := os.OpenFile(filepath.Join(build_info_dir, "BUILD_TIME"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	f.Write([]byte(fmt.Sprintf("%.0f\n" , time.Now(),)))

	use := map[string]bool{}
	for _, v := range (strings.Fields(settings.ValueDict["PORTAGE_USE"])){
		use[v]=true
	}
	for _, k := range _vdb_use_conditional_keys {
		v := settings.configDict["pkg"][k]
		filename := filepath.Join(build_info_dir, k)
		if v == "" {
			if err := syscall.Unlink(filename); err != nil {
				//}except OSError{
				//pass
			}
			continue
		}

		if strings.HasSuffix(k, "DEPEND") {
			if eapi_attrs.SlotOperator {
				continue
			}
			token_class = dep.Atom
		} else {
			token_class = nil
		}

		v2 := dep.useReduce(v, use, []string{}, false, []string{}, false, "", false, false, nil, token_class, false)
		v = dep.parenEncloses(v2, false, false)
		if v == "" {
			if err := syscall.Unlink(filename); err != nil {
				//}except OSError{
				//pass
			}
			continue
		}
		f, err := os.OpenFile(filepath.Join(build_info_dir, k), os.O_RDWR|os.O_CREATE, 0644)
		if err == nil {
			f.Write([]byte(fmt.Sprintf("%s\n", v)))
			f.Close()
		}
	}

	if eapi_attrs.SlotOperator{
		deps = evaluate_slot_operator_equal_deps(settings, use, QueryCommand.get_db())
		for k, versions.v
		in deps.items(){
			filename = filepath.Join(build_info_dir, k)
			if !versions.v {
				if err := syscall.Unlink(filename); err != nil {
					//}except OSError{
					//	pass
				}
				continue
			}
			with io.open(_unicode_encode(filepath.Join(build_info_dir,
				k), encoding=_encodings["fs"], errors="strict"),
			mode="w", encoding=_encodings["repo.content"],
				errors="strict") as f{
				f.Write([]byte(fmt.Sprintf("%s\n" , versions.v)))
			}
		}
	}
}

func _preinst_bsdflags(mysettings *config.Config){
	//if bsd_chflags{
	//
	//os.system(fmt.Sprintf("mtree -c -p %s -k flags > %s" %
	//(ShellQuote(mysettings.ValueDict["D"]),
	//ShellQuote(filepath.Join(mysettings.ValueDict["T"], "bsdflags.mtree"))))
	//
	//os.system(fmt.Sprintf("chflags -R noschg,nouchg,nosappnd,nouappnd %s" %
	//(ShellQuote(mysettings.ValueDict["D"]),))
	//os.system(fmt.Sprintf("chflags -R nosunlnk,nouunlnk %s 2>/dev/null" %
	//(ShellQuote(mysettings.ValueDict["D"]),))
	//}
}

func _postinst_bsdflags(mysettings *config.Config) {
	//if bsd_chflags {
	//	exec.Command("sh", "-c", fmt.Sprintf("mtree -e -p %s -U -k flags < %s > /dev/null",
	//		ShellQuote(mysettings.ValueDict["ROOT"]),
	//			ShellQuote(filepath.Join(mysettings.ValueDict["T"], "bsdflags.mtree"))))
	//}
}

func _post_src_install_uid_fix(mysettings *config.Config, out){

	inst_uid, _ := strconv.Atoi(mysettings.ValueDict["PORTAGE_INST_UID"])
	inst_gid, _ := strconv.Atoi(mysettings.ValueDict["PORTAGE_INST_GID"])

	_preinst_bsdflags(mysettings)

	destdir := mysettings.ValueDict["D"]
	ed_len := len(mysettings.ValueDict["ED"])
	unicode_errors := []string{}
	desktop_file_validate := process.FindBinary("desktop-file-validate") != ""
	xdg_dirs := strings.Split(mysettings.ValueDict["XDG_DATA_DIRS"],":")
	if len(xdg_dirs) == 0 {
		xdg_dirs = []string{"/usr/share"}
	}
	xd := []string{}
	for _, i := range xdg_dirs {
		if i != "" {
			xd = append(xd, filepath.Join(i, "applications")+string(os.PathSeparator))
		}
	}
	xdg_dirs = xd

	qdf, err := ioutil.ReadFile(filepath.Join(
		mysettings.ValueDict["PORTAGE_BUILDDIR"],
		"build-info", "QA_DESKTOP_FILE"))
	if err != nil {
		//except IOError as e:
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//raise
		}
	}

	qa_desktop_file := strings.Fields(string(qdf))
	var qdfRe *regexp.Regexp
	if len(qa_desktop_file) > 0 {
		qdfs := ""
		if len(qa_desktop_file) > 1 {
			qdfss := []string{}
			for _, x := range qa_desktop_file {
				qdfss = append(qdfss, fmt.Sprintf("(%s)", x))
			}
			qdfs = strings.Join(qdfss, "|")
			qdfs = fmt.Sprintf("^(%s)$", qdfs)
		} else {
			qdfs = fmt.Sprintf("^%s$", qa_desktop_file[0])
		}
		qdfRe = regexp.MustCompile(qdfs)
	}

	for {

		unicode_error := false
		size := 0
		counted_inodes := map[uint64]bool{}
		fixlafiles_announced := false
		fixlafiles :=   mysettings.Features.Features["fixlafiles"]
		desktopfile_errors := []string{}

		for parent, dirs, files in os.walk(destdir){

			for fname in chain(dirs, files){
				fpath = filepath.Join(parent, fname)
			}

			fpath_relative = fpath[ed_len - 1:]
			if desktop_file_validate && fname.endswith(".desktop") &&
				myutil.pathIsFile(fpath) &&
				fpath_relative.startswith(xdg_dirs) &&
				! (qdfRe != nil && qdfRe.MatchString(fpath_relative.strip(string(os.PathSeparator)))) {

				desktop_validate = validate_desktop_entry(fpath)
				if desktop_validate != "" {
					desktopfile_errors = append(desktopfile_errors,desktop_validate)
				}
			}

			if fixlafiles && strings.HasSuffix(fname, ".la") && myutil.pathIsFile(fpath){
				contents, _ := ioutil.ReadFile(fpath)
				has_lafile_header := myutil.Ins(strings.Split(string(contents), "\n"), ".la - a libtool library file")
				try{
					needs_update, new_contents = rewrite_lafile(contents)
				}except portage.exception.InvalidData as e{
					needs_update = false
					if ! fixlafiles_announced{
					fixlafiles_announced = true
					WriteMsg("Fixing .la files\n", fd = out)
				}

					msg = fmt.Sprintf("   %s is not a valid libtool archive, skipping\n" ,fpath[len(destdir):])
					qa_msg = fmt.Sprintf("QA Notice: invalid .la file found: %s, %s" ,fpath[len(destdir):], e)
					if has_lafile_header{
					WriteMsg(msg, fd = out)
					eqawarn(qa_msg, key = mysettings.mycpv, out= out)
				}
				}

				if needs_update{
					if ! fixlafiles_announced {
						fixlafiles_announced = true
						msg.WriteMsg("Fixing .la files\n"), fd = out)
					}
					msg.WriteMsg(fmt.Sprintf("   %s\n" , fpath[len(destdir):]), fd=out)

					util.write_atomic(fpath,
						new_contents, mode="wb")
				}
			}

			mystat, _ := os.Lstat(fpath)
			if unix.S_IFREG&mystat.Mode()!=0 &&
				! counted_inodes[mystat.Sys().(*syscall.Stat_t).Ino]{
				counted_inodes[mystat.Sys().(*syscall.Stat_t).Ino]=true
				size += mystat.Size()
			}
			if mystat.st_uid != data.Portage_uid &&
				mystat.st_gid != data.Portage_gid {
				continue
			}
			myuid := -1
			mygid := -1
			if mystat.Sys().(*syscall.Stat_t).Uid == uint32(*data.Portage_uid) {
				myuid = inst_uid
			}
			if mystat.Sys().(*syscall.Stat_t).Gid == *data.Portage_gid {
				mygid = inst_gid
			}
			permissions.Apply_secpass_permissions(fpath, myuid, mygid, mystat.Mode(), -1,  mystat, false)
		}

		if unicode_error {
			break
		}
	}

	if ! unicode_error {
		break
	}
}

if desktopfile_errors {
for l
in
_merge_desktopfile_error(desktopfile_errors)
{
l = l.replace(mysettings.ValueDict["ED"], "/")
eqawarn(l, phase = "install", key = mysettings.mycpv, out = out)
}
}

if unicode_errors {
for _, l:= range _merge_unicode_error(unicode_errors){
eqawarn(l, phase = "install", key = mysettings.mycpv, out = out)
}
}

build_info_dir = filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"],
"build-info")

f = io.open(_unicode_encode(filepath.Join(build_info_dir,
"SIZE"), encoding=_encodings["fs"], errors="strict"),
mode="w", encoding=_encodings["repo.content"],
errors="strict")
f.write(fmt.Sprintf("%d\n" , size))
f.close()

_reapply_bsdflags_to_image(mysettings)
}

func _reapply_bsdflags_to_image(mysettings *config.Config) {
	//if bsd_chflags {
	//	exec.Command("sh", "-c", fmt.Sprintf("mtree -e -p %s -U -k flags < %s > /dev/null",
	//		ShellQuote(mysettings.ValueDict["D"]),
	//		ShellQuote(filepath.Join(mysettings.ValueDict["T"], "bsdflags.mtree"))))
	//}
}

func _post_src_install_soname_symlinks(mysettings *config.Config, out io.Writer) {

	image_dir := mysettings.ValueDict["D"]
	needed_filename := filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"],
		"build-info", "NEEDED.ELF.2")

	f, err := ioutil.ReadFile(needed_filename)
	if err != nil {
		//}except IOError as e{
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//raise
		}
	}

	lines := strings.Split(string(f), "\n")

	metadata := map[string]string{}
	for _, k := range []string{"QA_PREBUILT", "QA_SONAME_NO_SYMLINK"} {
		f, err := ioutil.ReadFile(filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], "build-info", k))
		if err != nil {
			//except IOError as e{
			if err != syscall.ENOENT && err != syscall.ESTALE {
				//raise
			}
		} else {
			metadata[k] = string(f)
		}
	}

	qa_prebuilt := strings.TrimSpace(metadata["QA_PREBUILT"])

	var qpre *regexp.Regexp
	if qa_prebuilt != "" {
		ss, _ := shlex.Split(strings.NewReader(qa_prebuilt), false, true)
		ms := []string{}
		for _, x := range ss {
			ms = append(ms, fnmatch.translate(strings.TrimLeft(x, string(os.PathSeparator))))
		}
		qpre = regexp.MustCompile(strings.Join(ms, "|"))
	}

	qa_soname_no_symlink := strings.Fields(metadata["QA_SONAME_NO_SYMLINK"])
	var qsnsRe *regexp.Regexp
	if len(qa_soname_no_symlink) > 0 {
		qsnss := ""
		if len(qa_soname_no_symlink) > 1 {
			qsns := []string{}
			for _, x := range qa_soname_no_symlink {
				qsns = append(qsns, fmt.Sprintf("(%s)", x))
			}
			qsnss = strings.Join(qsns, "|")
			qsnss = fmt.Sprintf("^(%s)$", qsnss)
		} else {
			qsnss = fmt.Sprintf("^%s$", qa_soname_no_symlink[0])
		}
		qsnsRe = regexp.MustCompile(qsnss)
	}

	libpaths := map[string]bool{}
	for _, k := range util.getLibPaths(
		mysettings.ValueDict["ROOT"], mysettings.ValueDict) {
		libpaths[k] = true
	}
	libpath_inodes := map[[2]uint64]bool{}
	for libpath := range libpaths {
		libdir := filepath.Join(mysettings.ValueDict["ROOT"], strings.TrimLeft(libpath, string(os.PathSeparator)))
		s, err := os.Stat(libdir)
		if err != nil {
			//}except OSError{
			continue
		} else {
			libpath_inodes[[2]uint64{s.Sys().(*syscall.Stat_t).Dev, s.Sys().(*syscall.Stat_t).Ino}] = true
		}
	}

	is_libdir_cache := map[string]bool{}

	is_libdir := func(obj_parent string) bool {
		if v, ok := is_libdir_cache[obj_parent]; ok {
			return v
		}

		rval := false
		if libpaths[obj_parent] {
			rval = true
		} else {
			parent_path := filepath.Join(mysettings.ValueDict["ROOT"],
				strings.TrimLeft(obj_parent, string(os.PathSeparator)))
			s, err := os.Stat(parent_path)

			if err != nil {
				//except OSError{
				//	pass
			} else {
				if libpath_inodes[[2]uint64{s.Sys().(*syscall.Stat_t).Dev, s.Sys().(*syscall.Stat_t).Ino}] {
					rval = true
				}
			}
		}

		is_libdir_cache[obj_parent] = rval
		return rval
	}

	build_info_dir := filepath.Join(
		mysettings.ValueDict["PORTAGE_BUILDDIR"], "build-info")
	f, err = ioutil.ReadFile(filepath.Join(build_info_dir,
		"PROVIDES_EXCLUDE"))
	provides_exclude := string(f)
	if err != nil {
		//except IOError as e{
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//raise
		}
		provides_exclude = ""
	}

	f, err = ioutil.ReadFile(filepath.Join(build_info_dir,
		"REQUIRES_EXCLUDE"))
	requires_exclude := string(f)
	if err != nil {
		//except IOError as e{
		if err != syscall.ENOENT && err != syscall.ESTALE {
			//raise
		}
		requires_exclude = ""
	}

	missing_symlinks := [][2]string{}
	unrecognized_elf_files := []*util.NeededEntry{}
	soname_deps := SonameDepsProcessor(provides_exclude, requires_exclude)

	needed_file := util.NewAtomic_ofstream(needed_filename, os.O_RDWR|os.O_CREATE, 0644)

	for _, l := range lines {
		l = strings.TrimRight(l, "\n")
		if l == "" {
			continue
		}
		entry, err := util.NewNeededEntry().parse(needed_filename, l)
		if err != nil {
			//}except InvalidData as e{
			msg.WriteMsgLevel(fmt.Sprintf("\n%s\n\n", err, ),
				40, -1)
			continue
		}

		filename := filepath.Join(image_dir,
			strings.TrimLeft(entry.filename, string(os.PathSeparator)))
		f, _ := os.Open(filename)
		elf_header := ReadELFHeader(f)

		entry.multilib_category = compute_multilib_category(elf_header)
		needed_file.Write([]byte(entry.__str__()))

		if entry.multilib_category == "" {
			if qpre == nil || !qpre.MatchString(
				entry.filename[len(strings.TrimLeft(mysettings.ValueDict["EPREFIX"])):],
				string(os.PathSeparator)) {
				unrecognized_elf_files = append(unrecognized_elf_files, entry)
			}
		} else {
			soname_deps.add(entry)
		}

		obj := entry.filename
		soname := entry.soname

		if soname == "" {
			continue
		}
		if !is_libdir(filepath.Dir(obj)) {
			continue
		}
		if qsnsRe != nil && qsnsRe.MatchString(strings.Trim(obj, string(os.PathSeparator))) {
			continue
		}

		obj_file_path := filepath.Join(image_dir, strings.TrimLeft(obj, string(os.PathSeparator)))
		sym_file_path := filepath.Join(filepath.Dir(obj_file_path), soname)
		if _, err := os.Lstat(sym_file_path); err != nil {
			//}except OSError as e{
			if err != syscall.ENOENT && err == syscall.ESTALE {
				//raise
			}
		} else {
			continue
		}

		missing_symlinks = append(missing_symlinks, [2]string{obj, soname})
	}

	needed_file.Close()

	if soname_deps.requires != nil {
		f, err := os.OpenFile(filepath.Join(build_info_dir,
			"REQUIRES"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err == nil {
			f.Write(soname_deps.requires)
		}
	}

	if soname_deps.provides != nil {
		f, _ := os.OpenFile(filepath.Join(build_info_dir,
			"PROVIDES"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		f.Write(soname_deps.provides)
	}

	if len(unrecognized_elf_files) > 0 {
		qa_msg := []string{"QA Notice: Unrecognized ELF file(s):"}
		qa_msg = append(qa_msg, "")
		for _, entry := range unrecognized_elf_files {
			qa_msg = append(qa_msg, fmt.Sprintf("\t%s", strings.TrimRight(entry.__str__(), "")))
		}
		qa_msg = append(qa_msg, "")
		for _, line := range qa_msg {
			elog.eqawarn(line, "other", mysettings.mycpv.string, out)
		}
	}

	if len(missing_symlinks) == 0 {
		return
	}

	qa_msg := []string{"QA Notice: Missing soname symlink(s):"}
	qa_msg = append(qa_msg, "")
	for _, v := range missing_symlinks {
		obj, soname := v[0], v[1]
		qa_msg = append(qa_msg, fmt.Sprintf("\t%s -> %s", filepath.Join(
			strings.TrimLeft(filepath.Dir(obj), string(os.PathSeparator)), soname),
			filepath.Base(obj)))
	}
	qa_msg = append(qa_msg, "")
	for _, line := range qa_msg {
		elog.eqawarn(line, "other", mysettings.mycpv.string, out)
	}
}

func _merge_desktopfile_error(errors []string) []string {
	lines := []string{}

	msg := "QA Notice: This package installs one or more .desktop files " +
		"that do not pass validation."
	lines = append(lines, myutil.SplitSubN(msg, 72)...)

	lines = append(lines, "")
	sort.Strings(errors)
	for _, x := range errors {
		lines = append(lines, "\t"+x)
	}

	lines = append(lines, "")

	return lines
}

func _merge_unicode_error(errors []string) []string {
	lines := []string{}

	msg := "QA Notice: This package installs one or more file names " +
		"containing characters that are not encoded with the UTF-8 encoding."
	lines = append(lines, myutil.SplitSubN(msg, 72)...)

	lines = append(lines, "")
	sort.Strings(errors)
	for _, x := range errors {
		lines = append(lines, "\t"+x)
	}
	lines = append(lines, "")

	return lines
}

func _prepare_self_update(settings *config.Config) {

	if portage._bin_path != _const.PORTAGE_BIN_PATH {
		return
	}

	elog._preload_elog_modules(settings)
	portage.proxy.lazyimport._preload_portage_submodules()

	build_prefix := filepath.Join(settings.ValueDict["PORTAGE_TMPDIR"], "portage")
	util.EnsureDirs(build_prefix,-1,-1,-1,-1,nil,true)
	base_path_tmp := ioutil.TempDir(
		filepath.Join("", "._portage_reinstall_."), build_prefix)
	process.atexit_register(func() {
		os.RemoveAll(base_path_tmp)
	})

	orig_bin_path = portage._bin_path
	portage._bin_path = filepath.Join(base_path_tmp, "bin")
	shutil.copytree(orig_bin_path, portage._bin_path, symlinks = true)

	orig_pym_path = portage._pym_path
	portage._pym_path = filepath.Join(base_path_tmp, "lib")
	os.mkdir(portage._pym_path)
	for pmod := range _const.PORTAGE_PYM_PACKAGES {
		shutil.copytree(filepath.Join(orig_pym_path, pmod),
			filepath.Join(portage._pym_path, pmod),
			symlinks = true)
	}

	for _, dir_path:= range []string{base_path_tmp, portage._bin_path, portage._pym_path}{
		os.Chmod(dir_path, 0o755)
	}
}

func _handle_self_update(settings *config.Config) bool {
	cpv := settings.mycpv
	a, _ := dep.NewAtom(_const.PortagePackageAtom, nil, false, nil, nil, "", nil, nil)
	if settings.ValueDict["ROOT"] == "/" && len(dep.matchFromList(a, []*versions.PkgStr{cpv})) > 0 {
		_prepare_self_update(settings)
		return true
	}
	return false
}

func _prepare_features_dirs(mysettings *config.Config) {

	libdir := ""
	default_abi := mysettings.ValueDict["DEFAULT_ABI"]
	if default_abi!= "" {
		libdir = mysettings.ValueDict["LIBDIR_" + default_abi]
	}
	if libdir=="" {
		libdir = "lib"
	}

	features_dirs := map[string]struct{basedir_var, default_dir string;always_recurse bool;subdirs[]string}{
		"ccache": {
			basedir_var:    "CCACHE_DIR",
			default_dir:    filepath.Join(mysettings.ValueDict["PORTAGE_TMPDIR"], "ccache"),
			always_recurse: false,
		},
		"distcc": {
			basedir_var: "DISTCC_DIR",
			default_dir: filepath.Join(mysettings.ValueDict["BUILD_PREFIX"], ".distcc"),
			subdirs:     []string{"lock", "state"},
			always_recurse:true,
		},
	}
	dirmode := uint32(02070)
	filemode := 060
	modemask := 02
	restrict := strings.Fields(mysettings.ValueDict["PORTAGE_RESTRICT"])
	droppriv := *data.Secpass >= 2&& mysettings.Features.Features["userpriv"] && !myutil.Ins(restrict,"userpriv")
	for myfeature, kwargs := range features_dirs {
		if mysettings.Features.Features[myfeature] {
			failure := false
			basedir := mysettings.ValueDict[kwargs.basedir_var]
			if basedir ==""|| strings.TrimSpace(basedir)=="" {
				basedir = kwargs.default_dir
				mysettings.ValueDict[kwargs.basedir_var] = basedir
			}
			//try:
			mydirs := []string{mysettings.ValueDict[kwargs.basedir_var]}
			if kwargs.subdirs!= nil {
				for _, subdir:= range kwargs.subdirs {
					mydirs= append(mydirs, filepath.Join(basedir, subdir))
				}
			}
			for _,  mydir:= range mydirs {
				modified := util.EnsureDirs(mydir,-1,-1,-1,-1,nil,true)
				droppriv_fix := false
				if droppriv {
					st, _ := os.Stat(mydir)
					if st.Sys().(*syscall.Stat_t).Gid != *data.Portage_gid || !(dirmode == st.Sys().(*syscall.Stat_t).Mode & dirmode) {
						droppriv_fix = true
					}
					if ! droppriv_fix {
						lds, _, := myutil.ListDir(mydir)
						for _, filename := range lds{
							subdir_st, err := os.Lstat(
								filepath.Join(mydir, filename))
							if err != nil {
								//except OSError:
								continue
							}
							if subdir_st.Sys().(*syscall.Stat_t).Gid != *data.Portage_gid ||
								(st.IsDir() &&! (dirmode == uint32(st.Mode()) & dirmode)) {
								droppriv_fix = true
								break
							}
						}
					}
				}

				if droppriv_fix {
					_adjust_perms_msg(mysettings,
						output.Colorize("WARN", " * ")+
							fmt.Sprintf("Adjusting permissions "+
								"for FEATURES=userpriv: '%s'\n", mydir))
				}else if modified {
					_adjust_perms_msg(mysettings,
						output.Colorize("WARN", " * ")+
							fmt.Sprintf("Adjusting permissions "+
								"for FEATURES=%s: '%s'\n", myfeature, mydir)))
				}

				if modified || kwargs.always_recurse|| droppriv_fix {
					onerror:=func (e error) {
						raise
					}
					if ! apply_recursive_permissions(mydir,
						gid = data.Portage_gid, dirmode = dirmode, dirmask=modemask,
						filemode = filemode, filemask=modemask, onerror = onerror){
						raise
						OperationNotPermitted(
							_("Failed to apply recursive permissions for the portage group."))
					}
				}
			}
			//except DirectoryNotFound as e:
			//failure = true
			//writemsg(_("\n!!! Directory does not exist: '%s'\n") % \
			//(e,), noiselevel = -1)
			//writemsg(_("!!! Disabled FEATURES='%s'\n")%myfeature,
			//	noiselevel = -1)

			//except PortageException as e:
			//failure = true
			//writemsg("\n!!! %s\n"%str(e), noiselevel = -1)
			//writemsg(_("!!! Failed resetting perms on %s='%s'\n") % \
			//(kwargs["basedir_var"], basedir), noiselevel = -1)
			//writemsg(_("!!! Disabled FEATURES='%s'\n")%myfeature,
			//	noiselevel = -1)

			if failure {
				delete(mysettings.Features.Features, myfeature)
				time.Sleep(5*time.Second)
			}
		}
	}
}

func _prepare_workdir(mysettings *config.Config) {
	workdir_mode := 0700
	//try:
	mode := mysettings.ValueDict["PORTAGE_WORKDIR_MODE"]
	var parsed_mode int64
	if md, err := strconv.ParseInt(mode, 8, 64);err == nil {
		parsed_mode = md
	} else if mode == "" {
		//raise KeyError()
	} else {
		//raise ValueError()
	}
	if parsed_mode&07777 != parsed_mode {
		//raise ValueError("Invalid file mode: %s" % mode)
	} else {
		workdir_mode = int(parsed_mode)
	}
	//except KeyError as e:
	//writemsg(_("!!! PORTAGE_WORKDIR_MODE is unset, using %s.\n") % oct(workdir_mode))
	//except ValueError as e:
	//if len(str(e)) > 0:
	//writemsg("%s\n" % e)
	//writemsg(_("!!! Unable to parse PORTAGE_WORKDIR_MODE='%s', using %s.\n") % \
	//(mysettings["PORTAGE_WORKDIR_MODE"], oct(workdir_mode)))
	mysettings.ValueDict["PORTAGE_WORKDIR_MODE"] = strings.ReplaceAll(fmt.Sprintf("%o",workdir_mode), "o", "")


	md := os.FileMode(uint32(workdir_mode))
	var uid uint32
	if *data.Secpass >= 2 {
		uid = uint32(*data.Portage_uid)
	}else {
		uid = 0
		uid -= 1
	}
	var gid uint32
	if *data.Secpass >= 1 {
		gid = *data.Portage_gid
	}else {
		gid = 0
		gid -= 1
	}

	util.EnsureDirs(mysettings.ValueDict["PORTAGE_BUILDDIR"], uid,gid, md, -1 ,nil, true)
	util.EnsureDirs(mysettings.ValueDict["WORKDIR"], uid,gid, md, -1 ,nil, true)

	if mysettings.ValueDict["PORTAGE_LOGDIR"] == "" {
		delete(mysettings.ValueDict, "PORTAGE_LOGDIR")
	}
	if myutil.Inmss(mysettings.ValueDict, "PORTAGE_LOGDIR") {
		//try:
		modified := util.EnsureDirs(mysettings.ValueDict["PORTAGE_LOGDIR"],-1,-1,-1,-1,nil,true)
		if modified {
			permissions.Apply_secpass_permissions(mysettings.ValueDict["PORTAGE_LOGDIR"],
				uint32(*data.Portage_uid), *data.Portage_gid, 0o2770, -1, nil, true)
		}
		//except PortageException as e:
		//writemsg("!!! %s\n"%str(e), noiselevel = -1)
		//writemsg(_("!!! Permission issues with PORTAGE_LOGDIR='%s'\n") % \
		//mysettings["PORTAGE_LOGDIR"], noiselevel = -1)
		//writemsg(_("!!! Disabling logging.\n"), noiselevel = -1)
		//while "PORTAGE_LOGDIR" in mysettings:
		//del mysettings["PORTAGE_LOGDIR"]
	}

	compress_log_ext := ""
	if mysettings.Features.Features["compress-build-logs"] {
		compress_log_ext = ".gz"
	}

	logdir_subdir_ok := false
	if myutil.Inmss(mysettings.ValueDict, "PORTAGE_LOGDIR") && myutil.OsAccess(mysettings.ValueDict["PORTAGE_LOGDIR"], unix.W_OK) {
		logdir := msg.NormalizePath(mysettings.ValueDict["PORTAGE_LOGDIR"])
		logid_path := filepath.Join(mysettings.ValueDict["PORTAGE_BUILDDIR"], ".logid")
		if !myutil.PathExists(logid_path) {
			f, _ := os.OpenFile(logid_path, os.O_CREATE| os.O_RDWR, 0644)
			f.Close()
		}
		st, _ := os.Stat(logid_path)
		logid_time := st.ModTime().Format("20060102-150405")

		log_subdir := ""
		if mysettings.Features.Features["split-log"] {
			log_subdir = filepath.Join(logdir, "build", mysettings.ValueDict["CATEGORY"])
			mysettings.ValueDict["PORTAGE_LOG_FILE"] = filepath.Join(
				log_subdir, fmt.Sprintf("%s:%s.log%s",
					mysettings.ValueDict["PF"], logid_time, compress_log_ext))
		} else {
			log_subdir = logdir
			mysettings.ValueDict["PORTAGE_LOG_FILE"] = filepath.Join(logdir, fmt.Sprintf("%s:%s:%s.log%s",
				mysettings.ValueDict["CATEGORY"], mysettings.ValueDict["PF"], logid_time,
				compress_log_ext))
		}

		if log_subdir == logdir {
			logdir_subdir_ok = true
		} else {
			//try:
			Ensure_log_subdirs(logdir, log_subdir)
			//except PortageException as e:
			//writemsg("!!! %s\n" % (e, ), noiselevel = -1)

			if myutil.OsAccess(log_subdir, unix.W_OK) {
				logdir_subdir_ok = true
			} else {
				msg.WriteMsg(fmt.Sprintf("!!! %s: %s\n",
					"Permission Denied", log_subdir), -1, nil)
			}
		}
	}

	tmpdir_log_path := filepath.Join(
		mysettings.ValueDict["T"], fmt.Sprintf("build.log%s", compress_log_ext))
	if !logdir_subdir_ok {
		mysettings.ValueDict["PORTAGE_LOG_FILE"] = tmpdir_log_path
	} else {
		make_new_symlink := false
		target, err := filepath.EvalSymlinks(tmpdir_log_path)
		if err != nil {
			//except OSError:
			make_new_symlink = true
		} else {
			if target != mysettings.ValueDict["PORTAGE_LOG_FILE"] {
				make_new_symlink = true
			}
		}
		if make_new_symlink {
			if err := syscall.Unlink(tmpdir_log_path); err != nil {
				//except OSError:
				//pass
			}
			os.Symlink(mysettings.ValueDict["PORTAGE_LOG_FILE"], tmpdir_log_path)
		}
	}
}

func Ensure_log_subdirs(logdir, subdir string) {
	st, _ := os.Stat(logdir)
	uid := -1
	gid := st.Sys().(*syscall.Stat_t).Gid
	grp_mode := 02070 & st.Mode()

	if grp_mode != 0 && gid == *data.Portage_gid && *data.Secpass >= 2 {
		uid := *data.Portage_uid
		if st.Sys().(*syscall.Stat_t).Uid != uint32(*data.Portage_uid) {
			util.EnsureDirs(logdir, uint32(uid), -1, -1, -1, nil, true)
		}
	}

	logdir_split_len := len(strings.Split(logdir, string(os.PathSeparator)))
	subdir_split := strings.Split(subdir, string(os.PathSeparator))[logdir_split_len:]
	myutil.ReverseSlice(subdir_split)
	current := logdir
	for len(subdir_split) > 0 {
		ss := subdir_split[len(subdir_split)-1]
		subdir_split = subdir_split[:len(subdir_split)-1]
		current = filepath.Join(current, ss)
		util.EnsureDirs(current, uint32(uid), gid, grp_mode, 0, nil, true)
	}
}

func _prepare_fake_filesdir(settings *config.Config) {
	real_filesdir := settings.ValueDict["O"] + "/files"
	symlink_path := settings.ValueDict["FILESDIR"]


	link_target,err := filepath.EvalSymlinks(symlink_path)
	if err != nil {
		//except OSError:
		os.Symlink(real_filesdir, symlink_path)
	}else {
		if link_target != real_filesdir {
			syscall.Unlink(symlink_path)
			os.Symlink(real_filesdir, symlink_path)
		}
	}
}

func _prepare_fake_distdir(settings *config.Config, alist[]string){
	orig_distdir := settings.ValueDict["DISTDIR"]
	edpath := filepath.Join(settings.ValueDict["PORTAGE_BUILDDIR"], "distdir")
	util.EnsureDirs(edpath, -1, *data.Portage_gid, 0755, -1, nil,true)

	lds , _ := myutil.ListDir(edpath)
	for _, x:= range lds {
		symlink_path := filepath.Join(edpath, x)
		st, _ := os.Lstat(symlink_path)
		if myutil.Ins(alist, x) &&st.Mode()&unix.S_IFLNK!=0{
			continue
		}
		if st.IsDir() {
			os.RemoveAll(symlink_path)
		}else {
			syscall.Unlink(symlink_path)
		}
	}

	for _, x:= range alist {
		symlink_path := filepath.Join(edpath, x)
		target := filepath.Join(orig_distdir, x)

		link_target,err := filepath.EvalSymlinks(symlink_path)
		if err != nil {
			//except OSError:
			os.Symlink(target, symlink_path)
		}else {
			if link_target != target {
				syscall.Unlink(symlink_path)
				os.Symlink(target, symlink_path)
			}
		}
	}
}
