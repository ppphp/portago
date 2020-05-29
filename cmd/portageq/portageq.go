package main

import (
	"fmt"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/shlex"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/ppphp/portago/atom"
	"github.com/spf13/pflag"
)

func init() {
	signalHandler := func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		for {
			select {
			case sig := <-sigChan:
				switch sig {
				case syscall.SIGINT:
					os.Exit(128 + 2)
				case syscall.SIGTERM:
					os.Exit(128 + 9)
				}
			}
		}
	}
	go signalHandler()
	atom.InternalCaller = true
}

func eval_atom_use(atom *atom.Atom) *atom.Atom {
	if use, ok := os.LookupEnv("USE"); ok {
		u := map[string]bool{}
		for _, v := range strings.Fields(use) {
			u[v] = true
		}
		atom = atom.EvaluateConditionals(u)
	}
	return atom
}

type fuu struct {
	F              func([]string) int
	UseEroot       bool
	UsesConfigroot bool
	Docstrings     string
}

var globalFunctions = map[string]fuu{
	"colormap": {colormap, false, false, "Display the color.map as environment variables."},
	"distdir":  {distdir, false, false, "Returns the DISTDIR path."},
}

var (
	nonCommands = []string{"elog", "eval_atom_use", "exithandler", "match_orphaned", "main", "usage", "uses_eroot"}
	commands    = []string{}
)

var atomValidateStrict bool

func init() {
	if os.Getenv("EBUILD_PHASE") != "" {
		atomValidateStrict = true
	}
}

var eapi string
var elog func(string, []string)

func init() {
	if atomValidateStrict {
		eapi = os.Getenv("EAPI")
		elog = func(elog_funcname string, lines []string) {
			cmd := fmt.Sprintf("source '%s/isolated-functions.sh' ; ", os.Getenv("PORTAGE_BIN_PATH"))
			for _, line := range lines {
				cmd += fmt.Sprintf("%s %s ; ", elog_funcname, atom.ShellQuote(line))
			}
			c := exec.Command(atom.BashBinary, "-c", cmd)
			c.Run()
		}
	} else {
		elog = func(string, []string) {}
	}
}
type Opts struct {
	verbose, help, version,noFilter,noRegex,orphaned,noVersion bool
	repo string
	maintainerEmail []string
}
func main() {
	argv := os.Args[1:]
	noColor := os.Getenv("NOCOLOR")
	if noColor == "yes" || noColor == "true" {
		atom.NoColor()
	}
	var opts Opts
	pf := pflag.NewFlagSet("portageq", pflag.ExitOnError)
	pf.BoolVarP(&opts.verbose, "verbose", "v", false, "verbose form")
	pf.BoolVarP(&opts.help,"help", "h", false, "help message")
	pf.BoolVarP(&opts.version,"version", "", false, "version")
	pf.BoolVarP(&opts.noFilter,"no-filters", "", false, "no visibility filters (ACCEPT_KEYWORDS, package masking, etc)")
	pf.StringVarP(&opts.repo,"repo", "", "", "repository to use (all repositories are used by default)")
	pf.StringArrayVarP(&opts.maintainerEmail,"maintainer-email", "", nil, "comma-separated list of maintainer email regexes to search for")
	pf.BoolVarP(&opts.noRegex,"no-regex", "", false, "Use exact matching instead of regex matching for --maintainer-email")
	pf.BoolVarP(&opts.orphaned,"orphaned", "", false, "match only orphaned (maintainer-needed) packages")
	pf.BoolVarP(&opts.noVersion,"no-version", "n", false, "collapse multiple matching versions together")
	pf.Parse(argv)

	args := pf.Args()

	if opts.help {
		usage(argv)
		os.Exit(syscall.F_OK)
	} else if opts.version {
		print("Portage", atom.VERSION)
		os.Exit(syscall.F_OK)
	}

	cmd := ""
	if  len(args) != 0 {
		if _, ok := globalFunctions[args[0]]; ok{
			cmd = args[0]
		}
	}
	if cmd == "pquery" {
		cmd = ""
		args = args[1:]
	}
	if cmd == "" {
		return pquery(parser, opts, args)
	}

	if opts.verbose {
		args = append(args, "-v")
	}

	argv = append(argv[:1], args...)
	if len(argv) < 2 {
		usage(argv)
		os.Exit(64)
	}

	function := globalFunctions[cmd]
	usesEroot := function.UseEroot && len(argv) > 2
	if usesEroot {
		if s, err := os.Stat(argv[2]); err != nil || !s.IsDir() {
			os.Stderr.Write([]byte(fmt.Sprintf("Not a directory: '%s'\n", argv[2])))
			os.Stderr.Write([]byte("Run portageq with --help for info\n"))
			os.Exit(64)
		}
		eprefix := atom.TargetEprefix()
		eroot := atom.NormalizePath(argv[2])

		root := ""
		if eprefix != "" {
			if !strings.HasSuffix(eroot, eprefix) {
				os.Stderr.Write([]byte(fmt.Sprintf("ERROR: This version of portageq only supports <eroot>s ending in '%s'. The provided <eroot>, '%s', doesn't.\n", eprefix, eroot)))
				os.Exit(64)
			}
			root = eroot[:1-len(eprefix)]
		} else {
			root = eroot
		}
		os.Setenv("ROOT", root)
		if !function.UsesConfigroot {
			os.Setenv("PORTAGE_CONFIGROOT", eroot)
			atom.SyncMode = true
		}
	}

	args = argv[2:]
	if usesEroot {
		args[0] = atom.Settings().ValueDict["EROOT"]
	}

	retval := function.F(args)
	if retval != 0 {
		os.Exit(retval)
	}
}

func hasVersion(argv  []string) int {
	if (len(argv) < 2) {
		print("ERROR: insufficient parameters!")
		return 3
	}

	warnings := []string{}

	allow_repo := ! atomValidateStrict  || atom.EapiHasRepoDeps(eapi)
	atom1, err := atom.NewAtom(argv[1], nil, false, &allow_repo,nil, "", nil, nil )
	if err != nil {
	//except portage.exception.InvalidAtom:
	if atomValidateStrict {
		atom.WriteMsg(fmt.Sprintf("ERROR: Invalid atom: '%s'\n", argv[1]),
			-1, nil)
		return 2
	}else {
		atom1 = argv[1]
	}
	}else {
		if atomValidateStrict {
			atom1, err = atom.NewAtom(argv[1], nil, false, &allow_repo, nil, eapi, nil, nil)
			if err != nil {
				//except portage.exception.InvalidAtom as e:
				warnings = append(warnings, fmt.Sprintf("QA Notice: %s: %s", "has_version", err))
			}
		}
		atom1 = eval_atom_use(atom1)
	}

	if len(warnings)> 0 {
		elog("eqawarn", warnings)
	}

//try:
	mylist := atom.Db().Values()[argv[0]].VarTree().dbapi.match(atom1, 1)
	if len(mylist)>0{
	return 0
	}else {
		return 1
	}
	//except KeyError:
	//return 1
	//except portage.exception.InvalidAtom:
	//atom.WriteMsg(fmt.Sprintf("ERROR: Invalid atom: '%s'\n" % argv[1],
	//	-1)
	//return 2
}

func bestVersion(argv []string) int {
	if (len(argv) < 2) {
		print("ERROR: insufficient parameters!")
		return 3
	}

	warnings := []string{}

	allow_repo := !atomValidateStrict || atom.EapiHasRepoDeps(eapi)

	atom1, err := atom.NewAtom(argv[1], nil, false, &allow_repo, nil, "", nil, nil)
	if err != nil {
		//except portage.exception.InvalidAtom:
		if atomValidateStrict {
			atom.WriteMsg(fmt.Sprintf("ERROR: Invalid atom: '%s'\n", argv[1]),
				-1, nil)
			return 2

		} else {
			atom1 = argv[1]
		}
	} else {
		if atomValidateStrict {
			atom1, err = atom.NewAtom(argv[1], nil, false, &allow_repo, nil, eapi, nil, nil)
			if err != nil {
				//except portage.exception.InvalidAtom as e:
				warnings = append(warnings, fmt.Sprintf("QA Notice: %s: %s", "best_version", err))
			}
		}
		atom1 = eval_atom_use(atom1)
	}

	if len(warnings) > 0 {
		elog("eqawarn", warnings)
	}

	//try:
	mylist := atom.Db().Values()[argv[0]].VarTree().dbapi.match(atom)
	print(atom.best(mylist))
	return 0
	//except KeyError:
	//return 1
}

func massBestVersion(argv []string) int   {
	if (len(argv) < 2) {
		print("ERROR: insufficient parameters!")
		return 2
	}
//try:
	for _, pack := range argv[1:]{
	mylist := atom.Db().Values()[argv[0]].VarTree().dbapi.match(pack)
	print(fmt.Sprintf("%s:%s" ,pack, atom.best(mylist)))
	}
	//except KeyError:
	//return 1
	return 0
}

func metadata(argv []string) int{
if (len(argv) < 4){
os.Stderr.Write([]byte("ERROR: insufficient parameters!"))
return 2
}

eroot, pkgtype, pkgspec := argv[0], argv[1], argv[2]
metakeys := argv[3:]
type_map := map[string]string{
"ebuild": "porttree",
"binary": "bintree",
"installed": "vartree",
}
if _, ok := type_map[pkgtype]; !ok {
os.Stderr.Write([]byte(fmt.Sprintf("Unrecognized package type: '%s'" , pkgtype))
return 1
}
trees := atom.Db()
repo :=  atom.DepGetrepo(pkgspec)
pkgspec = atom.RemoveSlot(pkgspec)
var mydbapi atom.DBAPI
	switch type_map[pkgtype] {
	case "porttree":
		mydbapi=trees.Values()[eroot].PortTree().dbapi
	case "bintree":
		mydbapi=trees.Values()[eroot].BinTree().dbapi
	case "vartree":
		mydbapi=trees.Values()[eroot].VarTree().dbapi
	}
	//try:
values := mydbapi.auxGet(pkgspec, metakeys, repo)
atom.WriteMsgStdout(strings.Join(values, "\n")+"\n", -1)
//except KeyError:
//print(fmt.Sprintf("Package not found: '%s'" % pkgspec, file=os.Stderr)
//return 1
return 0
}

func contents(argv []string) int       {

	if len(argv) != 2{
	print(fmt.Sprintf("ERROR: expected 2 parameters, got %d!", len(argv)))
	return 2
	}

	root, cpv := argv[0], argv[1]
	vartree := atom.Db().Values()[root].VarTree()
	if ! vartree.dbapi.cpv_exists(cpv){
	os.Stderr.Write([]byte((fmt.Sprintf("Package not found: '%s'\n" , cpv))))
	return 1
	}
	cat, pkg := atom.catsplit(cpv)[0], atom.catsplit(cpv)[1]
	db := atom.NewDblink(cat, pkg, root, vartree.settings,
		"vartree", vartree, nil, nil, nil)
	atom.WriteMsgStdout(strings.Join(sorted(db.getcontents()), "\n") + "\n", -1)
	return 0 }

func owners(argv []string) int {

	if len(argv) < 2 {
		os.Stderr.Write([]byte(("ERROR: insufficient parameters!\n")))
		return 2
	}

	eroot := argv[0]
	vardb := atom.Db().Values()[eroot].VarTree().dbapi
	root := atom.Settings().ValueDict["ROOT"]

	cwd, err := os.Getwd()
	if err != nil {
		//except OSError:
		//pass
	}

	files := []string{}
	orphan_abs_paths := map[string]bool{}
	orphan_basenames := map[string]bool{}
	for _, f := range argv[1:] {
		f = atom.NormalizePath(f)
		is_basename := !strings.Contains(f, string(os.PathSeparator))
		if !is_basename && f[:1] != string(os.PathSeparator) {
			if cwd == "" {
				os.Stderr.Write([]byte(("ERROR: cwd does not exist!\n")))
				return 2
			}
			f = filepath.Join(cwd, f)
			f = atom.NormalizePath(f)
		}
		if !is_basename && !strings.HasPrefix(f, eroot) {
			os.Stderr.Write([]byte(("ERROR: file paths must begin with <eroot>!\n")))
			return 2
		}
		if is_basename {
			files = append(files, f)
			orphan_basenames[f] = true
		} else {
			files = append(files, f[len(root)-1:])
			orphan_abs_paths[f] = true
		}
	}

	owners := vardb._owners.get_owners(files)

	msg := []string{}
	for pkg, owned_files := range owners.items() {
		cpv := pkg.mycpv
		msg = append(msg, fmt.Sprintf("%s\n", cpv))
		stowned_files := []string{}
		copy(stowned_files, owned_files)
		sort.Strings(stowned_files)
		for _, f := range stowned_files {
			f_abs := filepath.Join(root, strings.TrimLeft(f, (string(os.PathSeparator))))
			msg = append(msg, fmt.Sprintf("\t%s\n", f_abs, ))
			delete(orphan_abs_paths, f_abs)
			if len(orphan_basenames) > 0 {
				delete(orphan_basenames, filepath.Base(f_abs))
			}
		}
	}

	atom.WriteMsgStdout(strings.Join(msg, ""), -1)

	if len(orphan_abs_paths)>0 || len(orphan_basenames)>0 {
		orphans := []string{}
		for k := range orphan_abs_paths{
			orphans = append(orphans, k)
		}
		for k := range orphan_basenames{
			orphans = append(orphans, k)
		}
		sort.Strings(orphans)
		msg := []string{}
		msg = append(msg, "None of the installed packages claim these files:\n")
		for _, f := range orphans {
			msg = append(msg, fmt.Sprintf("\t%s\n", f, ))
		}
		os.Stderr.Write([]byte(strings.Join(msg, "")))
	}

	if len(owners)>0 {
		return 0
	}
	return 1
}

func is_protected(argv []string) int       {

	if len(argv) != 2 {
		os.Stderr.Write([]byte((fmt.Sprintf("ERROR: expected 2 parameters, got %d!\n", len(argv)))))
		return 2
	}

	root, filename := argv[0], argv[1]

	err := os.Stderr
	cwd, err1 := os.Getwd()
	if err1 != nil {
		//except OSError:
		//pass
	}
	f := atom.NormalizePath(filename)
	if ! strings.HasPrefix(f,string(os.PathSeparator)) {
		if cwd == "" {
			err.Write([]byte("ERROR: cwd does not exist!\n"))

			return 2
		}
		f = filepath.Join(cwd, f)
		f = atom.NormalizePath(f)
	}

		if !strings.HasPrefix(f, root) {
			err.Write([]byte("ERROR: file paths must begin with <eroot>!\n"))
			return 2
		}

	from portage.util import ConfigProtect

	settings := atom.Settings()
	protect, _ := shlex.Split(settings.ValueDict["CONFIG_PROTECT"])
	protect_mask, _ := shlex.Split(
		settings.ValueDict["CONFIG_PROTECT_MASK"])
	protect_obj := ConfigProtect(root, protect, protect_mask,
		case_insensitive=( settings.Features.Features["case-insensitive-fs"]))
	if protect_obj.isprotected(f) {
		return 0
	}
	return 1
}

func filter_protected(argv []string) int       {

	if len(argv) != 1 {
		os.Stderr.Write([]byte((fmt.Sprintf("ERROR: expected 1 parameter, got %d!\n", len(argv)))))
		return 2
	}

	root := argv[0]
	out := os.Stdout
	err := os.Stderr
	cwd, err1 := os.Getwd()
	if err1 != nil {
		//except OSError:
		//pass
	}
	from portage.util import ConfigProtect

	settings := atom.Settings()
	protect := shlex.Split(settings.ValueDict["CONFIG_PROTECT"]
	protect_mask := shlex.Split(
		settings.ValueDict["CONFIG_PROTECT_MASK"])
	protect_obj := ConfigProtect(root, protect, protect_mask,
		case_insensitive=settings.Features.Features["case-insensitive-fs"])

	errors := 0

	lines, _ := ioutil.ReadAll(os.Stdin)
	for _, line :=range strings.Split(string(lines),"\n") {
		filename := strings.TrimRight(line, "\n")
		f := atom.NormalizePath(filename)
		if !strings.HasPrefix(f, string(os.PathSeparator)) {
			if cwd == "" {
				err.Write([]byte("ERROR: cwd does not exist!\n"))
				errors += 1
				continue
			}
			f = filepath.Join(cwd, f)
			f = atom.NormalizePath(f)
		}

		if !strings.HasPrefix(f, root) {
			err.Write([]byte("ERROR: file paths must begin with <eroot>!\n"))

			errors += 1
			continue
		}

		if protect_obj.isprotected(f) {
			out.Write([]byte(fmt.Sprintf("%s\n", filename)))
		}
	}

		if errors>0 {
			return 2
		}

	return 0
}

func bestVisible(argv []string) int       {

	if (len(argv) < 2) {
		atom.WriteMsg("ERROR: insufficient parameters!\n", -1, nil)
		return 2
	}

	pkgtype := "ebuild"
	var atom1 string
	if len(argv) > 2{
	pkgtype = argv[1]
	atom1 = argv[2]
	}else {
		atom1 = argv[1]
	}

	type_map := map[string]string{
		"ebuild":"porttree",
			"binary":"bintree",
			"installed":"vartree"}

	if  _, ok := type_map[pkgtype];!ok {
		atom.WriteMsg(fmt.Sprintf("Unrecognized package type: '%s'\n", pkgtype),
			-1, nil)
		return 2
	}

	eroot := argv[0]
	db := atom.Db().Values()[eroot][type_map[pkgtype]].dbapi

//try:
	atom2 := atom.dep_expandS(atom1, mydb=db, settings=atom.Settings())
	//except portage.exception.InvalidAtom:
	//atom.WriteMsg(fmt.Sprintf("ERROR: Invalid atom: '%s'\n" % atom,
	//	-1)
	//return 2

	root_config = RootConfig(atom.Settings(), atom.Db().Values()[eroot], None)

	var cpv_list []string
	if hasattr(db, "xmatch"){
	cpv_list = db.xmatch("match-all-cpv-only", atom)
	}else {
		cpv_list = db.match(atom)
	}

	if len(cpv_list) > 0 {

		atom.ReverseSlice(cpv_list)
	}
		atom_set := InternalPackageSet(initial_atoms=(atom2,))

		var repo_list []string
	if atom.repo == nil && hasattr(db, "getRepositories"){
	repo_list = db.getRepositories()
	}else {
		repo_list = []string{atom2.repo}
	}

	for cpv in cpv_list:
	for repo in repo_list:
try:
	metadata = dict(zip(Package.metadata_keys,
		db.aux_get(cpv, Package.metadata_keys, myrepo=repo)))
	except KeyError:
	continue
	pkg = Package(built=(pkgtype != "ebuild"), cpv=cpv,
		installed=(pkgtype=="installed"), metadata=metadata,
		root_config=root_config, type_name=pkgtype)
	if not atom_set.findAtomForPackage(pkg):
	continue

	if pkg.visible {
		atom.WriteMsgStdout(fmt.Sprintf("%s\n", pkg.cpv, ), -1)
		return 0
	}


		atom.WriteMsgStdout("\n", -1)

	return 1
}

func massBestVisible(argv []string) int   {

	type_map := map[string]string{
		"ebuild":"porttree",
			"binary":"bintree",
			"installed":"vartree",}

	if (len(argv) < 2) {
		print("ERROR: insufficient parameters!")
		return 2
	}
//try:
	root := argv[len(argv) -1]
	argv = argv[:len(argv) -1]
	pkgtype := "ebuild"
	if _, ok := type_map[ argv[0]]; ok {
		pkgtype = argv[len(argv) -1]
		argv = argv[:len(argv) -1]
	}
	for _, pack := range argv{
	atom.WriteMsgStdout(fmt.Sprintf("%s:" , pack), -1)
	bestVisible([]string{root, pkgtype, pack})
	}

	//except KeyError:
	//return 1
	return 0
}

func allBestVisible(argv []string) int    {
	if len(argv) < 1 {
		os.Stderr.Write([]byte(("ERROR: insufficient parameters!\n")))

		return 2
	}

	for _, pkg := range atom.Db().Values()[argv[0]].PortTree().dbapi.cp_all() {
		mybest := atom.best(atom.Db().Values()[argv[0]].PortTree().dbapi.match(pkg))
		if mybest != "" {
			print(mybest)
		}
	}
	return 0
}

func match(argv []string) int             {
	if len(argv) != 2{
	print(fmt.Sprintf("ERROR: expected 2 parameters, got %d!" , len(argv)))
	return 2
	}
	root, atom1 := argv[0], argv[1]
	if  atom1=="" {
		atom1 = "*/*"
	}

	vardb := atom.Db().Values()[root].VarTree().dbapi
	atom2, err := atom.NewAtom(atom1, allow_wildcard=true, allow_repo=true)
	if err != nil {
		//except portage.exception.InvalidAtom:
		atom2 = atom.dep_expandS(atom1, vardb,1, vardb.settings)
	}

	if atom2.extendedSyntax{
		var results []string
	if atom2.value == "*/*"{
	results = vardb.cpv_all()
	}else {
		results = []
		require_metadata := atom.slot || atom.repo
		for _, cpv := range vardb.cpv_all() {

			if !atom.matchFromList(atom, []*atom.pkgStr{cpv}) {
				continue
			}

			if require_metadata {
				//try:
				cpv := vardb._pkg_str(cpv, atom.repo)
				//except (KeyError, portage.exception.InvalidData):
				//continue
				if len(atom.matchFromList(atom, []*atom.pkgStr{cpv}) )==0{
					continue
				}
			}

			results = append(results, cpv)
		}
	}

	sort.Strings(results)
	}else {
		results = vardb.match(atom)
	}
	for _, cpv := range results {
		print(cpv)
	}

	return 0 }

func expand_virtual(argv []string) int    {

	if len(argv) != 2{
	atom.WriteMsg(fmt.Sprintf("ERROR: expected 2 parameters, got %d!\n" , len(argv)),
		-1, nil)
	return 2
	}

	root, atom1 := argv[0], argv[1]

try:
	results = list(expand_new_virt(
		atom.Db().Values()[root].VarTree().dbapi, atom1))
	except portage.exception.InvalidAtom:
	atom.WriteMsg(fmt.Sprintf("ERROR: Invalid atom: '%s'\n" , atom1),
		-1)
	return 2

	results.sort()
	for x in results:
	if not x.blocker:
	atom.WriteMsgStdout(fmt.Sprintf("%s\n" ,x,), 0)

	return 0
}

func vdbPath(argv []string) int           {
	out := os.Stdout
	out.Write([]byte(filepath.Join(atom.Settings().ValueDict["EROOT"], atom.VdbPath) + "\n"))
	return 0
}

func gentooMirrors(argv []string) int     {
	print(atom.Settings().ValueDict["GENTOO_MIRRORS"])
	return 0
}

func repositories_configuration(argv []string) int           {

	if len(argv) < 1 {
		os.Stderr.Write([]byte("ERROR: insufficient parameters!"))
		return 3
	}
	os.Stdout.Write([]byte(atom.Db().Values()[argv[0]].VarTree().settings.Repositories.configString()))

	return 0 }

func repos_config(argv []string) int           {
	return repositories_configuration(argv) }

func configProtect(argv []string) int     {

	print(atom.Settings().ValueDict["CONFIG_PROTECT"])
	return 0 }

func configProtectMask(argv []string) int {
	print(atom.Settings().ValueDict["CONFIG_PROTECT_MASK"])
	return 0 }

func pkgdir(argv []string) int            {
	print(atom.Settings().ValueDict["PKGDIR"])
	return 0 }

func distdir(argv []string) int {
	println(atom.Settings().ValueDict["DISTDIR"])
	return 0
}

func colormap([]string) int {
	fmt.Println(atom.ColorMap())
	return 0
}

func envvar(argv []string) int {
	var newArgs []string
	verbose := false
	for _, v := range argv {
		if v != "-v" {
			verbose = true
			newArgs = append(newArgs, v)
		}
	}
	if len(newArgs) == 0 {
		print("ERROR: insufficient parameters!")
		return 2
	}
	for _, a := range newArgs {
		for _, v := range []string{"PORTDIR", "PORTDIR_OVERLAY", "SYNC"} {
			if v == a {
				println("WARNING: 'portageq envvar " + a + "' is deprecated. Use any of 'get_repos, get_repo_path, repos_config' instead.")
			}
		}
		value := "" //atom.Settings.get(a)
		if value == "" {
			return 1
		}

		if verbose {
			println(a + "=" + atom.ShellQuote(value))
		} else {
			println(value)
		}
	}

	return 0
}

func get_repos(argv []string) int {
	if len(argv) < 1 {
		print("ERROR: insufficient parameters!")
		return 2
	}
	print(strings.Join(reversed(atom.Db().Values()[argv[0]].VarTree().settings.Repositories.preposOrder), " "))
	return 0 }

func master_repositories(argv []string) int {
	if len(argv) < 2 {
		os.Stderr.Write([]byte("ERROR: insufficient parameters!"))
		return 3
	}
	for _, arg := range argv[1:] {
		if !atom._repo_name_re.Match(arg) {
			os.Stderr.Write([]byte(fmt.Sprintf("ERROR: invalid repository: %s", arg)))
			return 2
		}
		//try:
		repo := atom.Db().Values()[argv[0]].VarTree().settings.Repositories.getitem(arg)
		//except KeyError:
		//print("")
		//return 1
		//}else{
		print(strings.Join(repo.masters, " "))
	}
	return 0 }

func master_repos(argv []string) int { return master_repositories(argv) }

func get_repo_path(argv []string) int {

	if len(argv) < 2 {
		os.Stderr.Write([]byte("ERROR: insufficient parameters!"))
		return 3
	}
	for _, arg := range argv[1:]{
	if !atom._repo_name_re.Match(arg){
		os.Stderr.Write([]byte(fmt.Sprintf("ERROR: invalid repository: %s" , arg))))
	return 2
	}
	path := atom.Db().Values()[argv[0]].VarTree().settings.Repositories.treeMap[arg]
	if path == "" {
		print("")
		return 1
	}
	print(path)
	}
	return 0 }

func available_eclasses(argv []string) int {

	if len(argv) < 2 {
		os.Stderr.Write([]byte("ERROR: insufficient parameters!"))
		return 3
	}
	for _ ,arg := range argv[1:] {
		if !atom._repo_name_re.Match(arg) {
			os.Stderr.Write([]byte(fmt.Sprintf("ERROR: invalid repository: %s", arg)))
			return 2
		}
		//try:
		repo := atom.Db().Values()[argv[0]].VarTree().settings.Repositories.getitem(arg)
		//except KeyError:
		//print("")
		//return 1
		//}else{
		print(strings.Join(sorted(repo.eclass_db.eclasses), " "))
	}
	return 0 }

func eclass_path(argv []string) int {
	if len(argv) < 3 {
		os.Stderr.Write([]byte("ERROR: insufficient parameters!"))
		return 3
	}
	if !atom._repo_name_re.Match(argv[1]):
	os.Stderr.Write([]byte(fmt.Sprintf("ERROR: invalid repository: %s" , argv[1])))
	return 2
//try:
	repo := atom.Db().Values()[argv[0]].VarTree().settings.Repositories.getitem(argv[1])
	//except KeyError:
	//print("")
	//return 1
	//}else{
	retval = 0
	for _, arg := range argv[2:]:
try:
	eclass = repo.eclass_db.eclasses[arg]
	except KeyError:
	print("")
	retval = 1
	}else{
	print(eclass.location)
	return retval }

func license_path(argv []string) int {
	if len(argv) < 3 {
		os.Stderr.Write([]byte("ERROR: insufficient parameters!"))
		return 3
	}
	if !atom._repo_name_re.Match(argv[1]) {
		os.Stderr.Write([]byte(fmt.Sprintf("ERROR: invalid repository: %s", argv[1])))
		return 2
	}
//try:
	repo := atom.Db().Values()[argv[0]].VarTree().settings.Repositories.getitem(argv[1])
	//except KeyError:
	//print("")
	//return 1
	//}else{
	retval := 0
	for _, arg := range argv[2:] {
		eclass_path := ""
		pathsr := []string{}
		for _, x := range append(append([]string{}, repo.masters...), repo) {
			pathsr = append(pathsr, filepath.Join(x.location, "licenses", arg))
		}
		paths := []string{}
		for _, p := range pathsr {
			paths = append([]string{p}, paths...)
		}

		for _, path := range paths {
			if st, err := os.Stat(path); err != nil && st != nil {
				eclass_path = path
				break
			}
		}
		if eclass_path == "" {
			retval = 1
		}
		print(eclass_path)
	}
	return retval
}

func list_preserved_libs(argv []string) int {
	if len(argv) != 1 {
		print("ERROR: wrong number of arguments")
		return 2
	}
	mylibs = atom.Db().Values()[argv[0]].VarTree().dbapi._plib_registry.getPreservedLibs()
	rValue := 1
	msg := []string{}
	for cpv in sorted(mylibs):
	msg= append(msg,cpv)
	for path in mylibs[cpv]:
	msg= append(msg," " + path)
	rValue = 0
	msg= append(msg,"\n")
	atom.WriteMsgStdout(strings.Join(msg, ""), -1)
	return rValue }

func MaintainerEmailMatcher(maintainer_emails []string) func()bool{
	_re := regexp.MustCompile(fmt.Sprintf("^(%s)$" , strings.Join(maintainer_emails, "|")))
	return func(metadata_xml)bool{
		match := false
		matcher := _re.MatchString
		for _, x := range metadata_xml.maintainers() {
			if x.email != "" && matcher(x.email) {
				match = true
				break
			}
		}
		return match
	}
}

func match_orphaned(metadata_xml) bool {

	if len(metadata_xml.maintainers())== 0 {
	return true
	}else {
		return false
	}
}

func pquery(opts , args []string) int {
	portdb := atom.Db().Values()[atom.Root()].PortTree().dbapi
	root_config := RootConfig(portdb.settings,
		atom.Db().Values()[atom.Root()], None)

	_pkg := func(cpv *atom.pkgStr, repo_name string)*atom.Package{
		metadata :=map[string]string{}
		//try:
		for i := range atom.NewPackage().metadata_keys {
			metadata[atom.NewPackage().metadata_keys[i]] = portdb.auxGet(cpv,
				Package.metadata_keys,
				repo_name)[i]
		}
		//except KeyError:
		//raise portage.exception.PackageNotFound(cpv)
		return atom.NewPackage(false, cpv,
			false, metadata,
			root_config,
			"ebuild")
	}

	need_metadata := false
	atoms := []*atom.Atom{}
	for _, arg := range args {
		atom1 := ""

		if !strings.Contains(strings.Split(arg, ":")[0], "/") {
			atom1 = emerge.insert_category_into_atom(arg, "*")
			if atom1 == "" {
				atom.WriteMsg(fmt.Sprintf("ERROR: Invalid atom: '%s'\n", arg),
					-1, nil)
				return 2
			}
		} else {
			atom1 = arg
		}

		t:= true
		atom2, err := atom.NewAtom(atom1, nil, true, &t, nil, "", nil, nil)
		if err != nil {
			//except portage.exception.InvalidAtom:
			atom.WriteMsg(fmt.Sprintf("ERROR: Invalid atom: '%s'\n", arg),
				-1, nil)
			return 2
		}

		if atom.slot != "" {
			need_metadata = true
		}

		atoms = append(atoms, atom2)
	}

	in:= false
	for _, a:= range atoms{
		if a.value == "*/*"{
			in=true
			break
		}
	}
	if in{
		atoms=nil
		need_metadata = false
	}

	if not opts.no_filters:
	need_metadata = true

	xml_matchers := []func()bool{}
	if opts.maintainer_email:
	maintainer_emails = []string{}
	for x in opts.maintainer_email:
	maintainer_emails=append(maintainer_emails, strings.Split(x, ","))
	if opts.no_regex:
	maintainer_emails := []string {}
	for _, x := range maintainer_emails{
		maintainer_emails = append(maintainer_emails, regexp.QuoteMeta(x))
	}
	xml_matchers= append(xml_matchers, MaintainerEmailMatcher(maintainer_emails))
	if opts.orphaned {
		xml_matchers = append(xml_matchers, match_orphaned)
	}

	if opts.repo != nil{
	repos = []string{portdb.repositories[opts.repo]}
	}else {
		repos = list(portdb.repositories)
	}

	if len(atoms)==0{
	names = None
	categories = list(portdb.categories)
	}else {
		category_wildcard := false
		name_wildcard := false
		categories = []string{}
		names := []string{}
		for _, atom1 := range atoms {
			category, name := atom.catsplit(atom1.cp)[0], atom.catsplit(atom1.cp)[1]
			categories = append(categories, category)
			names = append(names, name)
			if strings.Contains(category, "*") {
				category_wildcard = true
			}
			if strings.Contains(name, "*") {
				name_wildcard = true
			}
		}

		if category_wildcard {
			categories = list(portdb.categories)
		} else {
			categories = list(set(categories))
		}

		if name_wildcard {
			names = None
		} else {
			names = sorted(set(names))
		}
	}

	no_version = opts.no_version
	categories.sort()

	for category in categories:
	if names == nil{
	cp_list = portdb.cp_all(categories=(category,))
	}else {
		cp_list = []string{}
		for _, name := range names {
			cp_list = append(cp_list, category+"/"+name)
		}
	}
	for cp in cp_list:
	matches = []
	for repo in repos:
	match = true
	if xml_matchers:
	metadata_xml_path = filepath.Join(
	repo.location, cp, "metadata.xml")
	try:
	metadata_xml = MetaDataXML(metadata_xml_path, None)
	except (EnvironmentError, SyntaxError):
	match = false
	else
	for matcher in xml_matchers:
	if not matcher(metadata_xml):
	match = false
	break
	if not match:
	continue
	cpv_list = portdb.cp_list(cp, mytree=[repo.location])
	if atoms:
	for cpv in cpv_list:
	pkg = None
	for atom in atoms:
	if atom.repo != nil && \
	atom.repo != repo.name:
	continue
	if not atom.matchFromList(atom, [cpv]):
	continue
	if need_metadata:
	if pkg == nil:
	try:
	pkg = _pkg(cpv, repo.name)
	except portage.exception.PackageNotFound:
	continue

	if not (opts.no_filters || pkg.visible):
	continue
	if not atom.matchFromList(atom, [pkg]):
	continue
	matches= append(cpv)
	break
	if no_version && matches:
	break
	elif opts.no_filters:
	matches.extend(cpv_list)
	else
	for cpv in cpv_list:
	try:
	pkg = _pkg(cpv, repo.name)
	except portage.exception.PackageNotFound:
	continue
	else
	if pkg.visible:
	matches= append(cpv)
	if no_version:
	break

	if no_version && matches:
	break

	if not matches:
	continue

	if no_version{
	atom.WriteMsgStdout(fmt.Sprintf("%s\n" ,cp,), -1)
	}else {
		matches = list(set(matches))
	}
	portdb._cpv_sort_ascending(matches)
	for cpv in matches:
	atom.WriteMsgStdout(fmt.Sprintf("%s\n", cpv,), -1)

	return os.EX_OK
}

func usage(argv []string) {
	fmt.Println(">>> Portage information query tool")
	fmt.Printf(">>> %s\n", atom.VERSION)
	fmt.Println(">>> Usage: portageq <command> [<option> ...]")
	fmt.Println("")
	fmt.Println("Available commands:")
	help_mode := false
	for _, v := range argv {
		if "--help" == v {
			help_mode = true
		}
	}
	for name, f := range globalFunctions {
		lines := strings.Split(strings.TrimPrefix(f.Docstrings, "\n"), "\n")
		fmt.Println("   " + name + " " + strings.TrimSpace(lines[0]))
		if len(argv) > 1 {
			if !help_mode {
				lines = lines[:len(lines)-1]
			}
			for _, line := range lines[1:] {
				fmt.Println("      " + strings.TrimSpace(line))
			}
		}
	}

	fmt.Println()
	fmt.Println("Pkgcore pquery compatible options:")
	fmt.Println()
	//parser = argparse.ArgumentParser(add_help=false,
	//	usage="portageq pquery [options] [atom ...]")
	//add_pquery_arguments(parser)
	//parser.print_help()

	if len(argv) == 1 {
		fmt.Println("\nRun portageq with --help for info")
	}

}

func reversed (a []string)[]string{
	b:=[]string{}
	for _,v := range a{
		b = append([]string{v}, b...)
	}
	return b
}

func sorted (a []string)[]string{
	b:=[]string{}
	copy(b, a)
	sort.Strings(b)
	return b
}
