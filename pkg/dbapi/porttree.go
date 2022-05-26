package dbapi

import (
	"fmt"
	"github.com/ppphp/portago/pkg/cache"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/dep"
	eapi2 "github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/repository"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"github.com/ppphp/shlex"
	"golang.org/x/sys/unix"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type _better_cache struct {
	_scanned_cats map[string]bool
	_repo_list    []*repository.RepoConfig
	_items        map[string][]*repository.RepoConfig
}

func (b *_better_cache) __getitem__(catpkg string) []*repository.RepoConfig {
	result := b._items[catpkg]
	if result != nil {
		return result
	}

	cat := versions.catsplit(catpkg)[0]
	if _, ok := b._scanned_cats[cat]; !ok {
		b._scan_cat(cat)
	}
	return b._items[catpkg]
}

func (b *_better_cache) _scan_cat(cat string) {
	for _, repo := range b._repo_list {
		cat_dir := repo.Location + "/" + cat
		pkg_list, err := myutil.ListDir(cat_dir)
		if err != nil {
			//except OSError as e:
			if err != syscall.ENOTDIR && err != syscall.ENOENT && err != syscall.ESTALE {
				//raise
			}
			continue
		}
		for _, p := range pkg_list {
			if myutil.PathIsDir(cat_dir + "/" + p) {
				b._items[cat+"/"+p] = append(b._items[cat+"/"+p], repo)
			}
		}
	}
	b._scanned_cats[cat] = true
}

func NewBetterCache( repositories []*repository.RepoConfig)*_better_cache {
	b := &_better_cache{}
	b._items = map[string][]*repository.RepoConfig{}
	b._scanned_cats = map[string]bool{}

	b._repo_list = []*repository.RepoConfig{}

	r := []*repository.RepoConfig{}
	for k := len(repositories) - 1; k >= 0; k-- {
		r = append(r, repositories[k])
	}

	for _, repo := range r {
		if repo.Name != "" {
			b._repo_list = append(b._repo_list, repo)
		}
	}
	return b
}

type portdbapi struct {
	*dbapi
	_use_mutable             bool
	repositories             *repository.RepoConfigLoader
	treemap                  map[string]string
	doebuild_settings        *ebuild.Config
	depcachedir              string
	porttrees                []string
	_have_root_eclass_dir    bool
	xcache                   map[string]map[[2]string][]*versions.PkgStr
	frozen                   bool
	auxdb                    map[string]*cache.VolatileDatabase
	_pregen_auxdb, _ro_auxdb map[string]map[string]string
	_ordered_repo_name_list  []string
	_aux_cache_keys          map[string]bool
	_aux_cache               map[string]map[string]string
	_broken_ebuilds          map[string]bool
	_better_cache            *_better_cache
	_porttrees_repos         map[string]*repository.RepoConfig
}

func (p *portdbapi) _categories() map[string]bool {
	return p.settings.categories
}

func (p *portdbapi) _set_porttrees(porttrees []string) {
	for _, location := range porttrees {
		repo := p.repositories.GetRepoForLocation(location)
		p._porttrees_repos[repo.Name] = repo
	}
	p.porttrees = porttrees
}

func (p *portdbapi) _get_porttrees() []string {
	return p.porttrees
}

func (p *portdbapi) _event_loop() {
	return asyncio._safe_loop()
}

func (p *portdbapi) _create_pregen_cache(tree string) {
	conf := p.repositories.GetRepoForLocation(tree)
	cache := conf.get_pregenerated_cache(p._known_keys, true, false)
	if cache != nil {
		//try:
		cache.ec = p.repositories.GetRepoForLocation(tree).eclassDb
		//except AttributeError:
		//pass
		if not cache.complete_eclass_entries {
			//warnings.warn(
			//	("Repository '%s' used deprecated 'pms' cache format. "
			//"Please migrate to 'md5-dict' format.") % (conf.name,),
			//DeprecationWarning)
		}
	}
}

func (p *portdbapi) _init_cache_dirs() {
	util.EnsureDirs(p.depcachedir, -1, *data.Portage_gid,
		0o2070, 0o2, nil, true)
}

func (p *portdbapi) close_caches() {
	if p.auxdb == nil {
		return
	}
	for x := range p.auxdb {
		p.auxdb[x].sync(0)
	}
	p.auxdb = map[string]*cache.VolatileDatabase{}
}

func (p *portdbapi) flush_cache() {
	for _, x := range p.auxdb {
		x.sync(0)
	}
}

func (p *portdbapi) findLicensePath(license_name string) string {
	for _, x := range myutil.Reversed(p.porttrees) {
		license_path := filepath.Join(x, "licenses", license_name)
		if st, _ := os.Stat(license_path); st != nil && st.Mode()&0444 != nil {
			return license_path
		}
	}
	return ""
}

// "", ""
func (p *portdbapi) findname(mycpv, mytree, myrepo string) string {
	a, _ :=  p.findname2(mycpv, mytree, myrepo)
	return a
}

func (p *portdbapi) getRepositoryPath(repository_id string)string {
	return p.treemap[repository_id]
}

func (p *portdbapi) getRepositoryName(canonical_repo_path string) string {

	//try:
	return p.repositories.getNameForLocation(canonical_repo_path)
	//except KeyError:
	//return nil
}

// ""
func (p *portdbapi) getRepositories(catpkg string) []string {

	if catpkg != "" && p._better_cache != nil {
		ret := []string{}
		for _, repo := range p._better_cache.__getitem__(catpkg) {
			ret = append(ret, repo.Name)
		}
		return ret
	}
	return p._ordered_repo_name_list
}

func (p *portdbapi) getMissingRepoNames() map[string]bool{
	return p.settings.Repositories.missingRepoNames
}

func (p *portdbapi) getIgnoredRepos() []util.sss {
	return p.settings.Repositories.ignoredRepos
}

// nil, nil
func (p *portdbapi) findname2(mycpv, mytree, myrepo string) (string,int) {
	if mycpv == "" {
		return "", 0
	}

	if myrepo != "" {
		mytree = p.treemap[myrepo]
		if mytree == "" {
			return "", 0
		}
	} else if mytree != "" {
		myrepo = p.repositories.locationMap[mytree]
	}

	mysplit := strings.Split(mycpv, "/")
	psplit := versions.pkgSplit(mysplit[1], "")
	if psplit == [3]string{} || len(mysplit) != 2 {
		//raise InvalidPackageName(mycpv)
	}

	//try:
	//	cp = mycpv.cp
	//	except AttributeError:
	cp := mysplit[0] + "/" + psplit[0]

	var mytrees []string
	if p._better_cache == nil {
		if mytree != "" {
			mytrees = []string{mytree}
		} else {
			mytrees = myutil.Reversed(p.porttrees)
		}
	} else {
		//try:
		repos := p._better_cache.__getitem__(cp)
		//except KeyError:
		//return "", 0
		mytrees = []string{}
		for _, repo := range repos {
			if mytree != "" && mytree != repo.Location {
				continue
			}
			mytrees = append(mytrees, repo.Location)
		}
	}

	relative_path := mysplit[0] + string(os.PathSeparator) + psplit[0] + string(os.PathSeparator) + mysplit[1] + ".ebuild"

	if (myrepo != nil && myrepo == getattr(mycpv, "repo", nil) && p is getattr(mycpv, "_db", nil)){
		return (mytree + string(os.PathSeparator) + relative_path, mytree)
	}

	for _, x := range mytrees {
		filename := x + string(os.PathSeparator) + relative_path
		if myutil.osAccess(filename, unix.R_OK) {
			return filename, x
		}
	}
	return "", 0
}

func (p *portdbapi) _write_cache(versions.cpv, repo_path, metadata, ebuild_hash) {
try:
	cache := p.auxdb[repo_path]
	chf := cache.validation_chf
	metadata[fmt.Sprintf("_%s_", chf)] = getattr(ebuild_hash, chf)
	except CacheError:
	traceback.print_exc()
	cache = nil

	if cache != nil:
try:
	cache[versions.cpv] = metadata
	except CacheError:
	traceback.print_exc()
}

func (p *portdbapi) _pull_valid_cache(cpv, ebuild_path, repo_path string) {

try:
	ebuild_hash = eclass_cache.hashed_path(ebuild_path)
	ebuild_hash.mtime
	except FileNotFound:
	msg.WriteMsg(fmt.Sprintf("!!! aux_get(): ebuild for '%s' does not exist at:\n", cpv,),-1, nil)
	msg.WriteMsg(fmt.Sprintf("!!!            %s\n" , ebuild_path),-1, nil)
	raise PortageKeyError(cpv)

	auxdbs := []map[string]string{}
	pregen_auxdb := p._pregen_auxdb[repo_path]
	if pregen_auxdb != nil {
		auxdbs = append(auxdbs, pregen_auxdb)
	}
	ro_auxdb := p._ro_auxdb[repo_path]
	if ro_auxdb != nil {
		auxdbs = append(auxdbs, ro_auxdb)
	}
	auxdbs=append(auxdbs,p.auxdb[repo_path])
	eclass_db := p.repositories.GetRepoForLocation(repo_path).eclassDb

	for _, auxdb := range auxdbs {
		metadata, ok := auxdb[cpv]
		if !ok {
			//except KeyError:
			continue
		}
		except
	CacheError:
		if not auxdb.readonly:
	try:
		del
		auxdb[cpv]
		except(KeyError, CacheError):
		pass
		continue
		eapi = metadata.get("EAPI", "").strip()
		if not eapi:
		eapi = "0"
		metadata["EAPI"] = eapi
		if not eapi_is_supported(eapi):
		continue
		if auxdb.validate_entry(metadata, ebuild_hash, eclass_db):
		break
	}
	else:
	metadata = nil

	return (metadata, ebuild_hash)
}

// "", ""
func (p *portdbapi) aux_get(mycpv, mylist []string, mytree string, myrepo string) {
	loop = p._event_loop
	return loop.run_until_complete(
		p.async_aux_get(mycpv, mylist, mytree=mytree,
		myrepo=myrepo, loop=loop))
}

// "", "", nil
func (p *portdbapi) async_aux_get(mycpv string, mylist []string, mytree, myrepo string, loop=nil) {

	loop = asyncio._wrap_loop(loop)
	future = loop.create_future()
	cache_me := false
	if myrepo != "" {
		mytree := p.treemap[myrepo]
		if mytree == "" {
			future.set_exception(PortageKeyError(myrepo))
			return future
		}
	}

	if mytree != "" &&
		len(p.porttrees) == 1 &&
		mytree == p.porttrees[0] {
		mytree = ""
	}

	if mytree == "" {
		cache_me = true
	}

	pkimdpack := map[string]bool{}
	for _, k := range mylist {
		if p._known_keys[k] {
			pkimdpack[k] = true
		}
	}
	for k := range p._aux_cache_keys {
		delete(pkimdpack, k)
	}
	if mytree == "" && len(pkimdpack) == 0 {
		aux_cache := p._aux_cache[mycpv]
		if aux_cache != nil {
			res := []string{}
			for _, x := range mylist {
				res = append(res, x)
			}
			future.set_result(res)
			return future
		}
		cache_me = true
	}
	cp := strings.SplitN(mycpv, "/", 2)
	if len(cp) == 1 {
		//except ValueError:
		future.set_exception(PortageKeyError(mycpv))
		return future
	}
	cat, pkg := cp[0], cp[1]

	myebuild, mylocation := p.findname2(mycpv, mytree, "")

	if myebuild == "" {
		msg.WriteMsg(fmt.Sprintf("!!! aux_get(): %s\n",
			fmt.Sprintf("ebuild not found for '%s'", mycpv)), 1, nil)
		future.set_exception(PortageKeyError(mycpv))
		return future
	}

	mydata, ebuild_hash := p._pull_valid_cache(mycpv, myebuild, mylocation)

	if mydata != nil {
		p._aux_get_return(
			future, mycpv, mylist, myebuild, ebuild_hash,
			mydata, mylocation, cache_me, nil)
		return future
	}

	if myebuild in
	p._broken_ebuilds{
		future.set_exception(PortageKeyError(mycpv))
		return future
	}

	proc := emerge.NewEbuildMetadataPhase(mycpv, ebuild_hash, p, mylocation, loop, p.doebuild_settings)

	proc.addExitListener(functools.partial(p._aux_get_return,
		future, mycpv, mylist, myebuild, ebuild_hash, mydata, mylocation,
		cache_me))
	future.add_done_callback(functools.partial(p._aux_get_cancel, proc))
	proc.start()
	return future
}

func (p *portdbapi) _aux_get_cancel(proc, future) {
	if future.cancelled() && proc.returncode==nil {
		proc.cancel()
	}
}

func (p *portdbapi) _aux_get_return(future emerge.IFuture, mycpv, mylist, myebuild, ebuild_hash string,
	mydata map[string]string, mylocation string, cache_me bool, proc) {
	if future.cancelled() {
		return
	}
	if proc != nil {
		if proc.returncode != 0 {
			p._broken_ebuilds[myebuild] = true
			future.set_exception(PortageKeyError(mycpv))
			return
		}
		mydata = proc.metadata
	}
	mydata["repository"] = p.repositories.getNameForLocation(mylocation)
	mydata["_mtime_"] = ebuild_hash.mtime
	eapi := mydata["EAPI"]
	if eapi == "" {
		eapi = "0"
		mydata["EAPI"] = eapi
	}
	if eapi2.EapiIsSupported(eapi) {
		mydata["INHERITED"] = " ".join(mydata["_eclasses_"])
	}

	returnme := []string{}
	for _, x := range mylist {
		returnme = append(returnme, mydata[x])
	}

	if cache_me && p.frozen {
		aux_cache := map[string]string{}
		for x := range p._aux_cache_keys {
			aux_cache[x] = mydata[x]
		}
		p._aux_cache[mycpv] = aux_cache
	}

	future.set_result(returnme)
}

// nil, nil
func (p *portdbapi) getFetchMap(mypkg string, useflags []string, mytree string) []string {
	loop = p._event_loop
	return loop.run_until_complete(
		p.async_fetch_map(mypkg, useflags,
			mytree, loop=loop))
}

// coroutine
// nil, nil, nil
func (p *portdbapi) async_fetch_map(mypkg, useflags []string, mytree string, loop=nil) {

	loop = asyncio._wrap_loop(loop)
	result = loop.create_future()

	aux_get_done := func(aux_get_future) {
		if result.cancelled() {
			return
		}
		if aux_get_future.exception() is
		not
		nil{
			if isinstance(aux_get_future.exception(), PortageKeyError){
			result.set_exception(portage.exception.InvalidDependString(
			"getFetchMap(): aux_get() error reading " + mypkg + "; aborting."))
		} else{
			result.set_exception(future.exception())
		}
			return
		}

		eapi, myuris = aux_get_future.result()

		if !eapi2.EapiIsSupported(eapi) {
			result.set_exception(portage.exception.InvalidDependString(
				"getFetchMap(): '%s' has unsupported EAPI: '%s'"%
					(mypkg, eapi)))
			return
		}

	try:
		result.set_result(_parse_uri_map(mypkg, map[string]string{"EAPI": eapi, "SRC_URI": myuris,}, useflags))
		except
		Exception
		as
	e:
		result.set_exception(e)
	}

	aux_get_future := p.async_aux_get(
		mypkg, []string{"EAPI", "SRC_URI"}, mytree, "", loop = loop)
	result.add_done_callback(func(result){
		if result.cancelled(){
			return aux_get_future.cancel()
		} else {
			return nil
		}
	})
	aux_get_future.add_done_callback(aux_get_done)
	return result
}

// nil, 0, ""
func (p *portdbapi) getfetchsizes(mypkg string, useflags []string, debug int, myrepo string)map[string]int64 {
	myebuild, mytree := p.findname2(mypkg, "", myrepo)
	if myebuild == "" {
		//raise AssertionError(_("ebuild not found for '%s'") % mypkg)
	}
	pkgdir := filepath.Dir(myebuild)
	mf := p.repositories.GetRepoForLocation(
		filepath.Dir(filepath.Dir(pkgdir))).load_manifest(
		pkgdir, p.settings.ValueDict["DISTDIR"], nil, false)
	checksums := mf.getDigests()
	if len(checksums) == 0 {
		if debug != 0 {
			msg.WriteMsg(fmt.Sprintf("[empty/missing/bad digest]: %s\n", mypkg, ), -1, nil)
		}
		return map[string]int64{}
	}
	filesdict :=map[string]int64{}
	myfiles := p.getFetchMap(mypkg, useflags, mytree)
	for _, myfile := range myfiles {
		fetch_size, err := strconv.ParseInt(checksums[myfile]["size"], 10, 64)
		if err != nil {
			//except(KeyError, ValueError):
			if debug != 0 {
				msg.WriteMsg(fmt.Sprintf("[bad digest]: missing %s for %s\n", myfile, mypkg), 0, nil)
			}
			continue
		}
		file_path := filepath.Join(p.settings.ValueDict["DISTDIR"], myfile)
		mystat, err := os.Stat(file_path)
		if err != nil {
			//except OSError:
			//pass
		} else {
			if mystat.Size() != fetch_size {
				mystat = nil
			}
		}

		if mystat == nil {
			var err error
			mystat, err = os.Stat(file_path + atom._download_suffix)
			if err != nil {
				//except OSError:
				//pass
			}
		}

		existing_size := int64(0)
		if mystat == nil {
			ro_distdirs := p.settings.ValueDict["PORTAGE_RO_DISTDIRS"]
			ss, _ := shlex.Split(strings.NewReader(ro_distdirs), false, true)
			if ro_distdirs != "" {
				for _, x := range ss {
					mystat, err := os.Stat(filepath.Join(x, myfile))
					if err != nil {
						//except OSError:
						//pass
					} else {
						if mystat.Size() == fetch_size {
							existing_size = fetch_size
							break
						}
					}
				}
			}
		} else {
			existing_size = mystat.Size()
		}
		remaining_size := fetch_size - existing_size
		if remaining_size > 0 {
			filesdict[myfile] = remaining_size
		} else if remaining_size < 0 {
			filesdict[myfile], _ = strconv.ParseInt(checksums[myfile]["size"], 10, 64)
		}
	}
	return filesdict

}

// nil, nil, false, ""
func (p *portdbapi) fetch_check(mypkg string, useflags []string, mysettings *ebuild.Config, all bool, myrepo string) bool {
	if all {
		useflags = nil
	} else if useflags == nil {
		if mysettings != nil {
			useflags = strings.Fields(mysettings.ValueDict["USE"])
		}
	}
	mytree := ""
	if myrepo != "" {
		mytree := p.treemap[myrepo]
		if mytree == "" {
			return false
		}
	}

	myfiles := p.getFetchMap(mypkg, useflags, mytree)
	myebuild := p.findname(mypkg, "", myrepo)
	if myebuild == "" {
		//raise AssertionError(_("ebuild not found for '%s'") % mypkg)
	}
	pkgdir := filepath.Dir(myebuild)
	mf1 := p.repositories.GetRepoForLocation(filepath.Dir(filepath.Dir(pkgdir)))
	mf := mf1.load_manifest(pkgdir, p.settings.ValueDict["DISTDIR"], nil, false)
	mysums := mf.getDigests()

	failures := map[string]string{}
	for _, x := range myfiles {

		ok := false
		reason := ""
		if len(mysums) == 0 || !myutil.Inmsmss(mysums, x) {
			ok = false
			reason = "digest missing"
		} else {
			//try:
			ok, reason, _, _ = checksum.verifyAll(
				filepath.Join(p.settings.ValueDict["DISTDIR"], x), mysums[x], false, 0)
			//except FileNotFound as e:
			//ok = false
			//reason = fmt.Sprintf("File Not Found: '%s'", e, )
		}
		if !ok {
			failures[x] = reason
		}
	}
	if len(failures) > 0 {
		return false
	}
	return true
}

// ""
func (p *portdbapi) cpv_exists(mykey, myrepo string) int {
	cps2:= strings.Split(mykey, "/")
	cps := versions.CatPkgSplit(mykey, 0, "")
	if cps== [4]string{} {
		return 0
	}
	if p.findname(cps[0]+"/"+cps2[1], "", myrepo)!= "" {
		return 1
	}else{
		return 0
	}
}

// nil, nil, false, true
func (p *portdbapi) cp_all(categories map[string]bool, trees []string, reverse, sort bool) []string {

	d := map[string]bool{}
	if categories == nil {
		categories = p.settings.categories
	}
	if trees ==nil {
		trees = p.porttrees
	}
	for x:= range categories{
		for _, oroot:= range trees{
			for _, y := range util.ListDir(oroot+"/"+x, false, false, true, []string{}, true, true, true) {
				atom1, err  := dep.NewAtom(fmt.Sprintf("%s/%s",x, y), nil, false, nil, nil, "", nil, nil)
				if err != nil {
					//except InvalidAtom:
					continue
				}
				if atom1.value != atom1.cp {
					continue
				}
				d[atom1.cp] = true
			}
		}
	}
	l := []string{}
	for k := range d{
		l = append(l, k)
	}
	if sort {
		l = myutil.Reversed(myutil.sorted(l))
	}
	return l
}

// 1, nil
func (p *portdbapi) cp_list(mycp string, use_cache int, mytree []string) []*versions.PkgStr {
	if p.frozen && mytree != nil && len(p.porttrees) == 1 && len(mytree) == 1 && mytree[0] == p.porttrees[0] {
		mytree = nil
	}

	if p.frozen && mytree == nil {
		cachelist := p.xcache["cp-list"][[2]string{mycp}]
		if cachelist != nil {
			p.xcache["match-all"][[2]string{mycp, mycp}] = cachelist
			return cachelist[:]
		}
	}
	mysplit := strings.Split(mycp, "/")
	invalid_category := !p._categories()[mysplit[0]]
	repos := []*repository.RepoConfig{}
	if mytree != nil {
		for _, location := range mytree {
			repos = append(repos, p.repositories.GetRepoForLocation(location))
		}
	} else if p._better_cache == nil {
		for _, k := range p._porttrees_repos {
			repos = append(repos, k)
		}
	} else {
		rpbc := []*repository.RepoConfig{}
		for _, v := range p._better_cache.__getitem__(mycp) {
			rpbc = append([]*repository.RepoConfig{v}, rpbc...)
		}
		p._better_cache.__getitem__(mycp)
		for _, repo := range rpbc {
			if _, ok := p._porttrees_repos[repo.Name]; ok {
				repos = append(repos, repo)
			}
		}
	}
	mylist := []*versions.PkgStr{}
	for _, repo := range repos {
		oroot := repo.Location
		file_list, err := myutil.ListDir(filepath.Join(oroot, mycp))
		if err != nil {
			//except OSError:
			continue
		}
		for _, x := range file_list {
			pf := ""
			if x[len(x)-7:] == ".ebuild" {
				pf = x[:len(x)-7]
			}

			if pf != "" {
				ps := versions.PkgSplit(pf, 1, "")
				if ps == [3]string{} {
					msg.WriteMsg(fmt.Sprintf("\nInvalid ebuild name: %s\n",
						filepath.Join(oroot, mycp, x)), -1, nil)
					continue
				}
				if ps[0] != mysplit[1] {
					msg.WriteMsg(fmt.Sprintf("\nInvalid ebuild name: %s\n",
						filepath.Join(oroot, mycp, x)), -1, nil)
					continue
				}
				if !versions.verRegexp.MatchString(strings.Join(ps[1:], "-")) {
					msg.WriteMsg(fmt.Sprintf("\nInvalid ebuild version: %s\n",
						filepath.Join(oroot, mycp, x)), -1, nil)
					continue
				}
				mylist = append(mylist, versions.NewPkgStr(mysplit[0]+"/"+pf, nil, nil, "", "", repo.Name, 0, 0, "", 0, p))
			}
		}
	}
	if invalid_category && len(mylist) > 0 {
		msg.WriteMsg(fmt.Sprintf("\n!!! '%s' has a category that is not listed in "+
			"%setc/portage/categories\n",
			mycp, p.settings.ValueDict["PORTAGE_CONFIGROOT"]), -1, nil)
		mylist = []*versions.PkgStr{}
	}
	p._cpv_sort_ascending(mylist)
	if p.frozen && mytree == nil {
		cachelist := mylist[:]
		p.xcache["cp-list"][[2]string{mycp}] = cachelist
		p.xcache["match-all"][[2]string{mycp, mycp}] = cachelist
	}
	return mylist

}

func (p *portdbapi) freeze() {

	for _, x := range []string{"bestmatch-visible", "cp-list", "match-all",
		"match-all-cpv-only", "match-visible", "minimum-all",
		"minimum-all-ignore-profile", "minimum-visible"} {
		p.xcache[x] = map[[2]string][]*versions.PkgStr{}
	}
	p.frozen=true
	p._better_cache = NewBetterCache(p.repositories)
}

func (p *portdbapi) melt() {
	p.xcache = map[string]map[[2]string][]*versions.PkgStr{}
	p._aux_cache = map[string]map[string]string{}
	p._better_cache = nil
	p.frozen = false
}

func (p *portdbapi) xmatch(level string, origdep *dep.Atom) []*versions.PkgStr {
	return p.async_xmatch(level, origdep)
}

// @coroutine
func (p *portdbapi) async_xmatch(level string, origdep *dep.Atom) []*versions.PkgStr {
	mydep := dep_expand(origdep, p, 1, p.settings)
	mykey := mydep.cp

	cache_key := [2]string{}
	if p.frozen {
		cache_key = [2]string{mydep.value, mydep.unevaluatedAtom.value}
		c, ok := p.xcache[level]
		if ok {
			l, ok := c[cache_key]
			if ok {
				return l
			}
		}
		//except KeyError:
		//pass
	}

	var myval, mylist []*versions.PkgStr
	mytree := ""
	if mydep.repo != "" {
		mytree = p.treemap[mydep.repo]
		if mytree == "" {
			if strings.HasPrefix(level, "match-") {
				myval = []*versions.PkgStr{}
			} else {
				myval = []*versions.PkgStr{versions.NewPkgStr("",nil, nil, "", "", "", 0, 0, "", 0, nil)}
			}
		}
	}

	if myval != nil {
		//pass
	} else if level == "match-all-cpv-only" {
		if mydep.value == mykey {
			level = "match-all"
			myval = p.cp_list(mykey, 1, []string{mytree})
		} else {
			myval = dep.matchFromList(mydep,
				p.cp_list(mykey, 1, []string{mytree}))
		}
	} else if myutil.Ins([]string{"bestmatch-visible", "match-all",
		"match-visible", "minimum-all", "minimum-all-ignore-profile",
		"minimum-visible"}, level) {
		if mydep.value == mykey {
			mylist = p.cp_list(mykey, 1, []string{mytree})
		} else {
			mylist = dep.matchFromList(mydep,
				p.cp_list(mykey, 1, []string{mytree}))
		}

		ignore_profile := level == "minimum-all-ignore-profile"
		visibility_filter := !myutil.Ins([]string{"match-all", "minimum-all", "minimum-all-ignore-profile"}, level)
		single_match := !myutil.Ins([]string{"match-all", "match-visible"}, level)
		myval = []*versions.PkgStr{}
		aux_keys := []string{}
		for k := range p._aux_cache_keys {
			aux_keys = append(aux_keys, k)
		}

		iterfunc := func(a []*versions.PkgStr) []*versions.PkgStr { return a }
		if level == "bestmatch-visible" {
			iterfunc = func(a []*versions.PkgStr) []*versions.PkgStr {
				b := []*versions.PkgStr{}
				for _, v := range a {
					b = append([]*versions.PkgStr{v}, b...)
				}
				return b}
		}

		for _, cpv := range iterfunc(mylist) {
			metadata := map[string]string{}
			aag := p.async_aux_get(cpv, aux_keys, "", cpv.repo)
			for i := range aux_keys {
				metadata[aux_keys[i]] = aag[i]
			}
			//except KeyError:
			//continue

			//try:
			pkg_str := versions.NewPkgStr(cpv.string, metadata,
				p.settings, "", "", "", 0, 0, "", 0, p)
			//except InvalidData:
			//continue

			if visibility_filter && !p._visible(pkg_str, metadata) {
				continue
			}

			if mydep.slot != "" && !dep.matchSlot(mydep, pkg_str) {
				continue
			}

			if mydep.unevaluatedAtom.Use != nil && !p._match_use(mydep, pkg_str, metadata, ignore_profile) {
				continue
			}

			myval = append(myval, pkg_str)
			if single_match {
				break
			}
		}

		if single_match {
			if len(myval) > 0 {
				myval = []*versions.PkgStr{myval[0]}
			} else {
				myval = []*versions.PkgStr{versions.NewPkgStr("", nil, nil, "", "", "", 0, 0, "", 0, nil)}
			}
		}
	} else {
		//raise
		//AssertionError(
		//"Invalid level argument: '%s'" % level)
	}

	if p.frozen {
		xcache_this_level := p.xcache[level]
		if xcache_this_level != nil {
			xcache_this_level[cache_key] = myval
			//if not isinstance(myval, _pkg_str) {
			myval = myval[:]
			//}
		}
	}

	return myval
}

// 1
func (p *portdbapi) match(mydep  *dep.Atom, use_cache int)[]*versions.PkgStr {
	return p.xmatch("match-visible", mydep)
}

func (p *portdbapi) _visible(cpv *versions.PkgStr, metadata map[string]string) bool {
	eapi := metadata["EAPI"]
	if !eapi2.EapiIsSupported(eapi) {
		return false
	}
	if eapi2.eapiIsDeprecated(eapi) {
		return false
	}
	if metadata["SLOT"] == "" {
		return false
	}

	settings := p.settings
	if settings._getMaskAtom(cpv, metadata) != nil {
		return false
	}
	if settings._getMissingKeywords(cpv, metadata) != nil {
		return false
	}
	if settings.localConfig {
		metadata["CHOST"] = settings.ValueDict["CHOST"]
		if !settings._accept_chost(metadata) {
			return false
		}
		metadata["USE"] = ""
		if strings.Contains(metadata["LICENSE"], "?") ||
			strings.Contains(metadata["PROPERTIES"], "?") {
			p.doebuild_settings.SetCpv(cpv, metadata)
			metadata["USE"] = p.doebuild_settings.ValueDict["PORTAGE_USE"]
		}
		//try:
		if len(settings._getMissingLicenses(cpv, metadata)) > 0 {
			return false
		}
		if len(settings._getMissingProperties(cpv, metadata)) > 0 {
			return false
		}
		if len(settings._getMissingRestrict(cpv, metadata)) > 0 {
			return false
		}
		//except
		//InvalidDependString:
		return false
	}

	return true
}

// nil
func NewPortDbApi(mysettings *ebuild.Config) *portdbapi {
	p := &portdbapi{}
	p._use_mutable = true
	if mysettings != nil {
		p.settings = mysettings
	} else {
		p.settings = ebuild.NewConfig(portage.Settings(), nil, "", nil, "", "", "", "", true, nil, false, nil)
	}

	p.repositories = p.settings.Repositories
	p.treemap = p.repositories.treeMap

	p.doebuild_settings = ebuild.NewConfig(p.settings, nil, "", nil, "", "", "", "", true, nil, false, nil)
	p.depcachedir, _ = filepath.EvalSymlinks(p.settings.depcachedir)

	if os.Getenv("SANDBOX_ON") == "1" {
		sandbox_write := strings.Split(os.Getenv("SANDBOX_WRITE"), ":")
		if !myutil.Ins(sandbox_write, p.depcachedir) {
			sandbox_write = append(sandbox_write, p.depcachedir)
			os.Setenv("SANDBOX_WRITE", strings.Join(sandbox_write, ":"))
		}
	}

	p.porttrees = p.settings.Repositories.repoLocationList
	st, _ := os.Stat(
		filepath.Join(p.settings.Repositories.mainRepoLocation(), "eclass"))

	p._have_root_eclass_dir = st != nil && st.IsDir()

	p.xcache = map[string]map[[2]string][]*versions.PkgStr{}
	p.frozen = false

	rs := []string{}
	copy(rs, p.repositories.preposOrder)
	myutil.ReverseSlice(rs)
	p._ordered_repo_name_list = rs

	p.auxdbmodule = p.settings.load_best_module("portdbapi.auxdbmodule")
	p.auxdb = map[string]*cache.VolatileDatabase{}
	p._pregen_auxdb = map[string]string{}

	p._ro_auxdb = map[string]string{}
	p._init_cache_dirs()
	depcachedir_st, err := os.Stat(p.depcachedir)
	depcachedir_w_ok := false
	if err == nil {
		st, err = os.Stat(p.depcachedir)
		if err == nil {
			depcachedir_w_ok = st.Mode()&unix.W_OK != 0
		}
	} else {
		//except OSError:
	}

	cache_kwargs := map[string]int{}

	depcachedir_unshared := false
	if *data.secpass < 1 &&
		depcachedir_w_ok &&
		depcachedir_st != nil &&
		os.Getuid() == int(depcachedir_st.Sys().(syscall.Stat_t).Uid) &&
		os.Getgid() == int(depcachedir_st.Sys().(syscall.Stat_t).Gid) {

		depcachedir_unshared = true
	} else {
		cache_kwargs["gid"] = int(*data.Portage_gid)
		cache_kwargs["perms"] = 0o664
	}

	if (*data.secpass < 1 && !depcachedir_unshared) || !depcachedir_w_ok {
		for _, x := range p.porttrees {
			p.auxdb[x] = cache.NewVolatileDatabase(
				p.depcachedir, x, p._known_keys, false)
			p._ro_auxdb[x], err = p.auxdbmodule(p.depcachedir, x,
				p._known_keys, readonly = true, **cache_kwargs)
			if err != nil {
				//except CacheError:
				//pass
			}
		}
	} else {
		for _, x := range p.porttrees {
			if _, ok := p.auxdb[x]; ok {
				continue
			}
		}
	}

	p.auxdb[x] = p.auxdbmodule(
		p.depcachedir, x, p._known_keys, **cache_kwargs)
	if !p.settings.Features.Features["metadata-transfer"] {
		for _, x := range p.porttrees {
			if _, ok := p._pregen_auxdb[x]; ok {
				continue
			}
			cache := p._create_pregen_cache(x)
			if cache != nil {
				p._pregen_auxdb[x] = cache
			}
		}
	}

	p._aux_cache_keys = map[string]bool{
		"BDEPEND": true, "DEPEND": true, "EAPI": true,
		"INHERITED": true, "IUSE": true, "KEYWORDS": true, "LICENSE": true,
		"PDEPEND": true, "PROPERTIES": true, "RDEPEND": true, "repository": true,
		"RESTRICT": true, "SLOT": true, "DEFINED_PHASES": true, "REQUIRED_USE": true}

	p._aux_cache = map[string]map[string]string{}
	p._better_cache = nil
	p._broken_ebuilds = map[string]bool{}

	return p
}

type PortageTree struct {
	settings *ebuild.Config
	dbapi    *portdbapi
}

func (p *PortageTree) dep_bestmatch(mydep  *dep.Atom) *versions.PkgStr {
	mymatch := p.dbapi.xmatch("bestmatch-visible", mydep)
	if mymatch == nil {
		return versions.NewPkgStr("", nil, nil, "", "", "", 0, 0, "", 0, nil)
	}
	return mymatch[0]
}

func (p *PortageTree) dep_match(mydep  *dep.Atom) []*versions.PkgStr {
	mymatch := p.dbapi.xmatch("match-visible", mydep)
	if mymatch == nil {
		return []*versions.PkgStr{}
	}
	return mymatch
}

func (p *PortageTree) exists_specific(cpv string) int {
	return p.dbapi.cpv_exists(cpv, "")
}

func (p *PortageTree) getallnodes() []string {
	return p.dbapi.cp_all(nil, nil, false, true)
}

func (p *PortageTree) getslot(mycatpkg *versions.PkgStr) string {

	myslot := ""
	//try:
	myslot = p.dbapi._pkg_str(mycatpkg, "").slot
	//except KeyError:
	//pass
	return myslot
}

func NewPortageTree(settings *ebuild.Config) *PortageTree {
	p := &PortageTree{}
	if settings == nil {
		settings = portage.Settings()
	}
	p.settings = settings
	p.dbapi = NewPortDbApi(settings)
	return p
}

type FetchlistDict struct {
	pkgdir, cp, mytree string
	settings           *ebuild.Config
	portdb             *portdbapi
}

func (f *FetchlistDict) __getitem__(pkg_key string) {
	return list(f.portdb.getFetchMap(pkg_key, nil, f.mytree))

}

func (f *FetchlistDict) __contains__(cpv *versions.PkgStr) bool {
	for _, i := range f.__iter__() {
		if cpv.string == i.string {
			return true
		}
	}
	return false
}

func (f *FetchlistDict) __iter__() []*versions.PkgStr {
	return f.portdb.cp_list(f.cp, 1, f.mytree)

}

func (f *FetchlistDict) __len__() int {
	return len(f.portdb.cp_list(f.cp, 1, f.mytree))

}

func (f *FetchlistDict) keys() []*versions.PkgStr {
	return f.portdb.cp_list(f.cp, 1, f.mytree)
}

func NewFetchlistDict(pkgdir string, settings *ebuild.Config, mydbapi *portdbapi) *FetchlistDict {
	f := &FetchlistDict{}
	f.pkgdir = pkgdir
	f.cp = filepath.Join(strings.Split(pkgdir, string(os.PathSeparator))[len(strings.Split(pkgdir, string(os.PathSeparator)))-2:]...)
	f.settings = settings
	f.mytree, _ = filepath.EvalSymlinks(filepath.Dir(filepath.Dir(pkgdir)))
	f.portdb = mydbapi

	return f
}

// nil, nil, nil, nil
func _async_manifest_fetchlist(portdb *portdbapi, repo_config *repository.RepoConfig, cp string, cpv_list []*versions.PkgStr,
	max_jobs=nil, max_load=nil, loop=nil) {
	loop = asyncio._wrap_loop(loop)
	result = loop.create_future()

	if cpv_list == nil {
		cpv_list = portdb.cp_list(cp, 1, repo_config.Location)
	}

	gather_done := func(gather_result) {
		e = nil
		if not gather_result.cancelled():
		for future
			in
		gather_result.result():
		if (future.done() &&
			not
			future.cancelled()
		&&
		future.exception()
		is
		not
		nil):
		e = future.exception()
	}

	if result.cancelled():
	return
	else if
	e
		is
nil:
	result.set_result(dict((k, list(versions.v.result()))
	for k, versions.v
		in
	zip(cpv_list, gather_result.result()))) else:
	result.set_exception(e)

	gather_result = iter_gather(
		(portdb.async_fetch_map(versions.cpv, mytree = repo_config.location, loop = loop)
	for versions.cpv
		in
	cpv_list),
	max_jobs = max_jobs,
		max_load=max_load,
		loop = loop,
)

	gather_result.add_done_callback(gather_done)
	result.add_done_callback(lambda
result:
	gather_result.cancel()
	if result.cancelled()
	else
	nil)

	return result

}

// ordered map
// nil
func _parse_uri_map(cpv *versions.PkgStr, metadata map[string]string, use map[string]bool) map[string]map[string]bool {
	myuris := dep.useReduce(metadata["SRC_URI"], use, []string{}, use == nil, []string{}, true, metadata["EAPI"], false, false, nil, nil, false)

	uri_map := map[string]map[string]bool{}

	myutil.ReverseSlice(myuris)
	var distfile string
	for len(myuris) > 0 {
		uri := myuris[len(myuris)-1]
		myuris = myuris[:len(myuris)-1]
		if len(myuris) > 0 && myuris[len(myuris)-1] == "->" {
			myuris = myuris[:len(myuris)-1]
			distfile = myuris[len(myuris)-1]
			myuris = myuris[:len(myuris)-1]
		} else {
			distfile = filepath.Base(uri)
			if distfile == "" {
				//raise portage.exception.InvalidDependString(
				//	("getFetchMap(): '%s' SRC_URI has no file " +
				//"name: '%s'") % (cpv, uri))
			}
		}

		uri_set, ok := uri_map[distfile]
		if !ok {
			uri_set = map[string]bool{}
		}
		uri_map[distfile] = uri_set

		if u, err := url.Parse(uri); err != nil && u.Scheme != "" {
			uri_set[uri] = true
		}
	}

	return uri_map
}
