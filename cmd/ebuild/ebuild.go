package main

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/dbapi/FetchlistDict"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/emerge/structs"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/portage/vars"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/versions"
	"github.com/ppphp/shlex"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func exithandler() {
	s := make(chan os.Signal)
	signal.Notify(s, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE)
	for {
		select {
		case sig := <-s:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				os.Exit(int(sig.(syscall.Signal)+128))
			case syscall.SIGPIPE:
				os.Exit(0)
			}
		}
	}
}


func main() {
	go exithandler()

	process.SanitizeFds()

	//description := "See the ebuild(1) man page for more info"
	//usage := "Usage: ebuild <ebuild file> <command> [command] ..."
	pf := pflag.NewFlagSet("ebuild", pflag.ExitOnError)

	force_help := "When used together with the digest or manifest " +
		"command, this option forces regeneration of digests for all " +
		"distfiles associated with the current ebuild. Any distfiles " +
		"that do not already exist in ${DISTDIR} will be automatically fetched."

	var opts struct {
		force, debug, version, ignore_default_opts, skip_manifest bool
		color                                                     string
	}
	pf.BoolVar(&opts.force, "--force", false, force_help)
	pf.StringVar(&opts.color, "--color", "y", "enable or disable color output")
	pf.BoolVar(&opts.debug, "--debug", false, "show debug output")
	pf.BoolVar(&opts.version, "--version", false, "show version and exit")
	pf.BoolVar(&opts.ignore_default_opts, "--ignore-default-opts", false, "do not use the EBUILD_DEFAULT_OPTS environment variable")
	pf.BoolVar(&opts.skip_manifest, "--skip-manifest", false, "skip all manifest checks")
	pf.Parse(os.Args[1:])
	pargs := pf.Args()
	if opts.version {
		print("Portage", portage.VERSION)
		os.Exit(syscall.F_OK)
	}
	if len(pargs) < 2 {
		os.Stderr.Write([]byte(fmt.Sprintf("%s: error: %s\n)", os.Args[0], "missing required args")))
	}
	if !opts.ignore_default_opts {
		default_opts, _ := shlex.Split(strings.NewReader(
			portage.Settings().ValueDict["EBUILD_DEFAULT_OPTS"]), false, true)
		pf.Parse(append(default_opts, os.Args[1:]...))
		pargs = pf.Args()
	}
	debug := opts.debug
	force := opts.force
	if debug {
		os.Setenv("PORTAGE_DEBUG", "1")
		portage.ResetLegacyGlobals()
	}
	if opts.color != "y" &&
		(opts.color == "n" ||
			(portage.Settings().ValueDict["NOCOLOR"] != "yes" &&
				portage.Settings().ValueDict["NOCOLOR"] != "true") ||
			portage.Settings().ValueDict["TERM"] == "dumb" || !terminal.IsTerminal(int(os.Stdout.Fd()))) {
		output.NoColor()
		portage.Settings().Unlock()
		portage.Settings().ValueDict["NOCOLOR"] = "true"
		portage.Settings().BackupChanges("NOCOLOR")
		portage.Settings().Lock()
	}
	ebuild := pargs[0]
	pargs = pargs[1:]

	pf1 := ""
	if strings.HasSuffix(ebuild, ".ebuild") {
		pf1 = filepath.Base(ebuild)[:-7]
	}
	if pf1 == "" {
		err(fmt.Sprintf("%s{ does not end with '.ebuild'", ebuild))
	}
	if !filepath.IsAbs(ebuild) {
		mycwd, _ := os.Getwd()
		pwd := os.Getenv("PWD")
		if rp, _ := filepath.EvalSymlinks(pwd); pwd != "" && pwd != mycwd &&
			rp == mycwd {
			mycwd = util.NormalizePath(pwd)
			ebuild = filepath.Join(mycwd, ebuild)
		}
	}
	ebuild = util.NormalizePath(ebuild)
	ebuild_portdir, _ := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(filepath.Dir(ebuild))))
	ep := strings.Split(ebuild, string(os.PathSeparator))
	ebuild = filepath.Join(ebuild_portdir, ep[len(ep)-3], ep[len(ep)-2], ep[len(ep)-2])
	vdb_path, _ := filepath.EvalSymlinks(filepath.Join(portage.Settings().ValueDict["EROOT"], _const.VdbPath))
	if ebuild_portdir != vdb_path &&
		!myutil.Ins(portage.Portdb().porttrees, ebuild_portdir) {
		portdir_overlay := portage.Settings().ValueDict["PORTDIR_OVERLAY"]
		os.Setenv("PORTDIR_OVERLAY", portdir_overlay+" "+vars.ShellQuote(ebuild_portdir))

		print(fmt.Sprintf("Appending %s to PORTDIR_OVERLAY...", ebuild_portdir))
		portage.ResetLegacyGlobals()
	}

	myrepo := nil
	if ebuild_portdir != vdb_path {
		myrepo = portage.Portdb().getRepositoryName(ebuild_portdir)
	}
	if _, err1 := os.Stat(ebuild); err1 == os.ErrNotExist {
		err(fmt.Sprintf("%s: does not exist", ebuild))
	}
	ebuild_split := strings.Split(ebuild, "/")
	cpv := fmt.Sprintf("%s/%s", ebuild_split[len(ebuild_split)-3], pf)
	f, _ := ioutil.ReadFile(ebuild)
	eapi, _ := portage.ParseEapiEbuildHead(strings.Split(string(f), "\n"))
	if eapi == "" {
		eapi = "0"
	}
	if versions.CatPkgSplit(cpv, 1, eapi) == [4]string{} {
		err(fmt.Sprintf("%s: %s: does not follow correct package syntax", ebuild, cpv))
	}
	print(vdb_path)
	var mytree, pkg_type string
	if strings.HasPrefix(ebuild, vdb_path) {
		mytree = "vartree"
		pkg_type = "installed"
		portage_ebuild := portage.Db().Values()[portage.Root()].VarTree().dbapi.findname(cpv)
		if rp, _ := filepath.EvalSymlinks(portage_ebuild); rp != ebuild {
			err(fmt.Sprintf("Portage seems to think that %s is at %s", cpv, portage_ebuild))
		}
	} else {
		mytree = "porttree"
		pkg_type = "ebuild"
		portage_ebuild := portage.Portdb().findname(cpv, myrepo)
		if len(portage_ebuild) == 0 || portage_ebuild != ebuild {
			err(fmt.Sprintf("%s: does not seem to have a valid PORTDIR structure", ebuild))
		}
	}
	if len(pargs) > 1 && myutil.Ins(pargs, "config"){
		other_phases := map[string]bool{}
		for _, v := range pargs {
			other_phases[v] = true
		}
		for _, v := range []string{"clean", "config", "digest", "manifest"} {
			delete(other_phases, v)
		}
		if len(other_phases) > 0 {
			err("\"config\" must not be called with any other phase")
		}
	}

	portage.Settings().Validate()
	build_dir_phases := map[string]bool{"setup": true, "unpack": true, "prepare": true, "configure": true, "compile": true,
		"test": true, "install": true, "package": true, "rpm": true, "merge": true, "qmerge": true}
	ebuild_changed := false
	inter := map[string]bool{}
	for _, v := range pargs {
		if build_dir_phases[v] {
			inter[v] = true
		}
	}
	if mytree == "porttree" && len(inter) > 0 {
		ebuild_changed =
			portage.Portdb()._pull_valid_cache(cpv, ebuild, ebuild_portdir)[0] == ""
	}
	print(portage.Portdb())
	tmpsettings := portage.Portdb().doebuild_settings
	tmpsettings.ValueDict["PORTAGE_VERBOSE"] = "1"
	tmpsettings.BackupChanges("PORTAGE_VERBOSE")
	if opts.skip_manifest {
		tmpsettings.ValueDict["EBUILD_SKIP_MANIFEST"] = "1"
		tmpsettings.BackupChanges("EBUILD_SKIP_MANIFEST")
	}
	if opts.skip_manifest ||
		tmpsettings.Features.Features["digest"] ||
		myutil.Ins(pargs, "digest") ||
		myutil.Ins(pargs, "manifest") {
		atom._doebuild_manifest_exempt_depend += 1
	}
	if myutil.Ins(pargs, "test") {
		tmpsettings.ValueDict["EBUILD_FORCE_TEST"] = "1"
		tmpsettings.BackupChanges("EBUILD_FORCE_TEST")
		tmpsettings.Features.Features["test"] = true
		util.WriteMsg(fmt.Sprintf("Forcing test.\n"), -1, nil)
	}
	tmpsettings.Features.Discard("fail-clean")
	if myutil.Ins(pargs, "merge") && tmpsettings.Features.Features["noauto"] {
		print("Disabling noauto in features... merge disables it. (qmerge doesn't)")
		tmpsettings.Features.Discard("noauto")
	}
	if tmpsettings.Features.Features["digest"] {
		if len(pargs) > 0 && pargs[0] != "digest" && pargs[0] != "manifest" {
			pargs = append([]string{"digest"}, pargs...)
		}
		tmpsettings.Features.Discard("digest")
	}
	tmpsettings = ebuild.NewConfig(tmpsettings, nil, "", nil, "", "", "", "", true, nil, false, nil)
	//try{
	var mydbapi dbapi.IDbApi
	if mytree == "porttree" {
		mydbapi = portage.Db().Values()[portage.Settings().ValueDict["EROOT"]].PortTree().dbapi
	} else if mytree == "vartree" {
		mydbapi = portage.Db().Values()[portage.Settings().ValueDict["EROOT"]].VarTree().dbapi
	}

	metadata := dict(zip(structs.NewPackage(false, nil, false, nil, nil, "").metadata_keys,
		mydbapi.aux_get(
			cpv, structs.NewPackage(false, nil, false, nil, nil, "").metadata_keys, myrepo = myrepo)))
	if err != nil {
		//except PortageKeyError{
		syscall.Exit(1)
	}
	root_config := emerge.NewRootConfig(portage.Settings(),
		portage.Db().Values()[portage.Settings().ValueDict["EROOT"]], nil)
	pkg := structs.NewPackage(pkg_type != "ebuild", cpv,
		pkg_type == "installed",
		metadata, root_config,
		pkg_type)
	tmpsettings.SetCpv(pkg)
	checked_for_stale_env := false
	for _, arg := range pargs {
		//try{
		if !checked_for_stale_env && arg != "digest" && arg != "manifest" {
			stale_env_warning(pargs , tmpsettings, build_dir_phases , debug, ebuild_changed , ebuild )
			checked_for_stale_env = true
		}
		if (arg == "digest" || arg == "manifest") && force {
			discard_digests(ebuild, tmpsettings, portage.Portdb())
		}
		print(ebuild, arg, tmpsettings, debug, mytree, portage.Db().Values()[portage.Root()].VarTree())
		a := atom.doebuild(ebuild, arg, tmpsettings,
			debug, 0, 0, 0, 1, 0, mytree, nil, portage.Db().Values()[portage.Root()].VarTree(),
			nil, nil, false)
		//except KeyboardInterrupt{
		//print("Interrupted.")
		//a = 1
		//except PortageKeyError{
		//a = 1
		//except UnsupportedAPIException as e{
		//msg = textwrap.wrap(str(e), 70)
		//del e
		//for _, x := range msg{
		//atom.WriteMsg(fmt.Sprintf("!!! %s\n" % x, -1, nil)
		//a = 1
		//except PortagePackageException as e{
		//atom.WriteMsg(fmt.Sprintf("!!! %s\n" % (e,), -1, nil)
		//a = 1
		//except PermissionDenied as e{
		//atom.WriteMsg(fmt.Sprintf("!!! Permission Denied: %s\n" % (e,), -1, nil)
		//a = 1
		if a == nil {
			print("Could not run the required binary?")
			a = 127
		}
		if a != 0 {
			//global_event_loop().close()
			syscall.Exit(a)
		}
	}
	//global_event_loop().close()
}

func err(txt string) {
	util.WriteMsg(fmt.Sprintf("ebuild: %s\n" , txt ), -1, nil)
	os.Exit(1)
}

func discard_digests(myebuild string, mysettings *config.Config, mydbapi *atom.portdbapi) {
	//try{
	atom._doebuild_manifest_exempt_depend += 1
	defer atom._doebuild_manifest_exempt_depend -= 1

	pkgdir := filepath.Dir(myebuild)
	fetchlist_dict := FetchlistDict.NewFetchlistDict(pkgdir, mysettings, mydbapi)
	rc := mysettings.Repositories.getRepoForLocation(
		filepath.Dir(filepath.Dir(pkgdir)))
	mf := rc.load_manifest(pkgdir, mysettings.ValueDict["DISTDIR"],
		fetchlist_dict, false)
	mf.create(false, true, true, nil)
	distfiles := fetchlist_dict[cpv]
	for _, myfile := range distfiles {
		//try{
		delete(mf.fhashdict["DIST"], myfile)
		//except KeyError{
		//pass
	}
	mf.write()
	//finally{
}

func stale_env_warning(pargs []string, tmpsettings*config.Config, build_dir_phases map[string]bool, debug, ebuild_changed bool, ebuild string) {
	inter := map[string]bool{}
	for _, p :=range pargs{
		if !build_dir_phases[p]{
			inter[p] =true
		}
	}
	if !myutil.Ins(pargs, "clean") &&
		!tmpsettings.Features.Features["noauto"] &&
		len(inter)>0 {
		atom.doebuild_environment(ebuild, "setup", portage.Root(),
			tmpsettings, debug, 1, portage.Portdb())
		env_filename := filepath.Join(tmpsettings.ValueDict["T"], "environment")
		if _, err := os.Stat(env_filename) ;err != nil {
			msg := fmt.Sprintf("Existing ${T}/environment for '%s' will be sourced. "+
				"Run 'clean' to start with a fresh environment.",
				tmpsettings.ValueDict["PF"], )
			msgs := myutil.SplitSubN(msg, 70)
			for _, x := range msgs {
				util.WriteMsg(fmt.Sprintf(">>> %s\n", x), 0, nil)
			}
			if ebuild_changed{
				f, err := os.OpenFile(filepath.Join(tmpsettings.ValueDict["PORTAGE_BUILDDIR"],
					".ebuild_changed"), os.O_RDWR, 0644)
				if err == nil {
					f.Close()
				}
			}
		}
	}
}

