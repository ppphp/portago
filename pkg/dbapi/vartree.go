package dbapi

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"github.com/pkg/xattr"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/exception"
	"github.com/ppphp/portago/pkg/locks"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"github.com/spf13/pflag"
	"hash"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type vardbapi struct {
	*dbapi
	_excluded_dirs, _aux_cache_keys_re, _aux_multi_line_re *regexp.Regexp
	_aux_cache_version, _owners_cache_version              int
	_lock                                                  string
	_aux_cache_threshold                                   int

	_pkgs_changed, _flush_cache_enabled bool
	matchcache                          map[string]map[[2]*dep.Atom][]*versions.PkgStr
	blockers                            map[string]string
	cpcache                             map[string]struct {
		int64
		p []*versions.PkgStr
	}
	mtdircache                                                                                 map[string]int
	_eroot, _dbroot, _conf_mem_file, _aux_cache_filename, _cache_delta_filename, _counter_path string
	_fs_lock_obj                                                                               *locks.LockFileS
	_slot_locks                                                                                map[*dep.Atom]*struct {
		s *locks.LockFileS
		int
	}
	_aux_cache_obj              *auxCache
	_cached_counter             interface{}
	_lock_count, _fs_lock_count int
	vartree                     *varTree
	_aux_cache_keys             map[string]bool
	_cache_delta                *vdbMetadataDelta
	_plib_registry              *util.preservedLibsRegistry
	_linkmap                    *util.linkageMapELF
	_owners                     *_owners_db
}

func (v *vardbapi) writable() bool {
	st, err := os.Stat(atom.firstExisting(v._dbroot))
	return err != nil && st.Mode()&os.FileMode(os.O_WRONLY) != 0
}

func (v *vardbapi) getpath(myKey, filename string) string { // ""+
	rValue := v._dbroot + _const.VdbPath + string(os.PathSeparator) + myKey
	if filename != "" {
		rValue = filepath.Join(rValue, filename)
	}
	return rValue
}

func (v *vardbapi) lock() {
	if v._lock_count != 0 {
		v._lock_count++
	} else {
		if v._lock != "" {
			//raise AssertionError("already locked")
		}
		util.EnsureDirs(v._dbroot, -1, -1, -1, -1, nil, true)
		//v._lock
	}
}

func (v *vardbapi) unlock() {
	if v._lock_count > 1 {
		v._lock_count -= 1
	} else {
		if v._lock == "" {
			panic("not locked")
		}
		v._lock_count = 0
		atom.unlockdir(v._lock)
		v._lock = ""
	}

}

func (v *vardbapi) _fs_lock() {
	if v._fs_lock_count < 1 {
		if v._fs_lock_obj != nil {
			panic("already locked")
		}
		v._fs_lock_obj, _ = locks.Lockfile(v._conf_mem_file, false, false, "", 0)
		// if err == InvalidLocataion {
		// v.Settings.init_dirs()
		//
		// }
	}
	v._fs_lock_count += 1
}

func (v *vardbapi) _fs_unlock() {
	if v._fs_lock_count < 1 {
		if v._fs_lock_obj == nil {
			panic("not locked")
		}
		locks.Unlockfile(v._fs_lock_obj)
		v._fs_lock_obj = nil
	}
	v._fs_lock_count -= 1
}

func (v *vardbapi) _slot_lock(slotAtom *dep.Atom) {
	lock := v._slot_locks[slotAtom].s
	counter := v._slot_locks[slotAtom].int
	if lock == nil {
		lockPath := v.getpath(fmt.Sprintf("%s:%s", slotAtom.cp, slotAtom.slot), "")
		util.EnsureDirs(filepath.Dir(lockPath), -1, -1, -1, -1, nil, true)
		lock, _ = locks.Lockfile(lockPath, true, false, "", 0)
	}
	v._slot_locks[slotAtom] = &struct {
		s *locks.LockFileS
		int
	}{lock, counter + 1}
}

func (v *vardbapi) _slot_unlock(slotAtom *dep.Atom) {
	lock := v._slot_locks[slotAtom].s
	counter := v._slot_locks[slotAtom].int
	if lock == nil {
		panic("not locked")
	}
	counter -= 1
	if counter == 0 {
		locks.Unlockfile(lock)
		delete(v._slot_locks, slotAtom)
	} else {
		v._slot_locks[slotAtom] = &struct {
			s *locks.LockFileS
			int
		}{s: lock, int: counter}
	}
}

func (v *vardbapi) _bump_mtime(cpv string) {
	base := v._eroot + _const.VdbPath
	cat := versions.catsplit(cpv)[0]
	catDir := base + string(filepath.Separator) + cat
	t := time.Now()

	for _, x := range []string{catDir, base} {
		if err := syscall.Utime(x, &syscall.Utimbuf{Actime: t.Unix(), Modtime: t.Unix()}); err != nil {
			util.EnsureDirs(catDir, -1, -1, -1, -1, nil, true)
		}
	}
}

func (v *vardbapi) cpv_exists(myKey, myRepo string) bool {
	_, err := os.Stat(v.getpath(myKey, ""))
	if err != nil {
		return true
	}
	return false
}

func (v *vardbapi) cpv_counter(myCpv *versions.PkgStr) int {
	s, err := strconv.Atoi(v.AuxGet(myCpv, []string{"COUNTER"}, "")[0])
	if err != nil {
		msg.WriteMsgLevel(fmt.Sprintf("portage: COUNTER for %s was corrupted; resetting to value of 0\n", myCpv.string), 40, -1)
		return 0
	}
	return s
}

func (v *vardbapi) cpv_inject(myCpv *versions.PkgStr) {
	util.EnsureDirs(v.getpath(myCpv.string, ""), -1, -1, -1, -1, nil, true)
	counter := v.counter_tick()
	util.write_atomic(v.getpath(myCpv.string, "COUNTER"), string(counter), 0, true)
}

func (v *vardbapi) isInjected(myCpv string) bool {
	if v.cpv_exists(myCpv, "") {
		if _, err := os.Stat(v.getpath(myCpv, "INJECTED")); err == nil {
			return true
		}
		if _, err := os.Stat(v.getpath(myCpv, "CONTENTS")); err != nil {
			return true
		}
	}
	return false
}

// nil
func (v *vardbapi) move_ent(myList []*dep.Atom, repoMatch func(string) bool) int {
	origCp := myList[1]
	newCp := myList[2]

	for _, atom := range []*dep.Atom{origCp, newCp} {
		if !dep.isJustName(atom.value) {
			//raise InvalidPackageName(str(atom))
		}
	}
	origMatches := v.match(origCp.value, 0)
	moves := 0
	if len(origMatches) == 0 {
		return moves
	}
	for _, mycpv := range origMatches {
		mycpv = v._pkg_str(mycpv, "")
		mycpvCp := versions.cpvGetKey(mycpv.string, "")
		if mycpvCp != origCp.value {
			continue
		}
		if repoMatch != nil && !repoMatch(mycpv.repo) {
			continue
		}

		if !dep.isValidAtom(newCp.value, false, false, false, mycpv.eapi, false) {
			continue
		}

		myNewCpv := strings.Replace(mycpv.string, mycpvCp, newCp.value, 1)
		myNewCat := versions.catsplit(newCp.value)[0]
		origPath := v.getpath(mycpv.string, "")
		if _, err := os.Stat(origPath); err != nil {
			continue
		}
		moves += 1
		if _, err := os.Stat(v.getpath(myNewCat, "")); err != nil {
			util.EnsureDirs(v.getpath(myNewCat, ""), -1, -1, -1, -1, nil, true)
		}
		newPath := v.getpath(myNewCpv, "")
		if _, err := os.Stat(newPath); err == nil {
			continue
		}
		util._movefile(origPath, newPath, 0, nil, v.settings, nil)
		v._clear_pkg_cache(v._dblink(mycpv.string))
		v._clear_pkg_cache(v._dblink(myNewCpv))

		oldPf := versions.catsplit(mycpv.string)[1]
		newPf := versions.catsplit(myNewCpv)[1]
		if newPf != oldPf {
			err := os.Rename(filepath.Join(newPath, oldPf+".ebuild"),
				filepath.Join(newPath, newPf+".ebuild"))
			if err != nil {
				if err != syscall.ENOENT {
					//raise
				}
				//del e
			}
		}
		util.write_atomic(filepath.Join(newPath, "PF"), newPf+"\n", 0, true)
		util.write_atomic(filepath.Join(newPath, "CATEGORY"), myNewCat+"\n", 0, true)
	}
	return moves
}

func (v *vardbapi) cp_list(myCp string, useCache int) []*versions.PkgStr {
	mySplit := versions.catsplit(myCp)
	if mySplit[0] == "*" {
		mySplit[0] = mySplit[0][1:]
	}
	myStatt, err := os.Stat(v.getpath(mySplit[0], ""))

	myStat := int64(0)
	if err == nil {
		myStat = myStatt.ModTime().UnixNano()
	}
	if cpc, ok := v.cpcache[myCp]; useCache != 0 && ok {
		if cpc.int64 == myStat {
			return cpc.p
		}
	}
	catDir := v.getpath(mySplit[0], "")
	dirList, err := ioutil.ReadDir(catDir)
	if err != nil {
		if err == syscall.EPERM {
			//raise PermissionDenied(cat_dir)
		}
		dirList = []os.FileInfo{}
	}

	returnMe := []*versions.PkgStr{}
	for _, x := range dirList {
		if v._excluded_dirs.MatchString(x.Name()) {
			continue
		}
		ps := versions.PkgSplit(x.Name(), 1, "")
		if ps == [3]string{} {
			v.invalidentry(filepath.Join(v.getpath(mySplit[0], ""), x.Name()))
			continue
		}
		if len(mySplit) > 1 {
			if ps[0] == mySplit[1] {
				cpv := fmt.Sprintf("%s/%s", mySplit[0], x)
				metadata := map[string]string{}
				for i := range v._aux_cache_keys {
					metadata[i] = v.aux_get(cpv, v._aux_cache_keys, "")[0]
				}
				returnMe = append(returnMe, versions.NewPkgStr(cpv, metadata,
					v.settings, "", "", "", 0, 0, "", 0, v.dbapi))
			}
		}
	}
	v._cpv_sort_ascending(returnMe)
	if useCache != 0 {
		v.cpcache[myCp] = struct {
			int64
			p []*versions.PkgStr
		}{myStat, returnMe}

	} else if _, ok := v.cpcache[myCp]; ok {
		delete(v.cpcache, myCp)
	}
	return returnMe
}

// 1
func (v *vardbapi) cpv_all(useCache int) []*versions.PkgStr {
	return v._iter_cpv_all(useCache != 0, false)
}

// true, true
func (v *vardbapi) _iter_cpv_all(useCache, sort1 bool) []*versions.PkgStr {
	basePath := filepath.Join(v._eroot, _const.VdbPath) + string(filepath.Separator)
	ListDir := util.ListDir
	if !useCache {
		ListDir = func(myPath string, recursive, filesOnly, ignoreCvs bool, ignoreList []string, followSymlinks, EmptyOnError, dirsOnly bool) []string {
			ss, err := ioutil.ReadDir(myPath)
			if err != nil {
				//except EnvironmentError as e:
				//if err == PermissionDenied.errno:
				//raise PermissionDenied(p)
				//del e
				return []string{}
			}
			ret := []string{}
			for _, x := range ss {
				if x.IsDir() {
					ret = append(ret, x.Name())
				}
			}
			return ret
		}
	}
	catDirs := ListDir(basePath, false, false, true, []string{}, true, true, true)
	if sort1 {
		sort.Strings(catDirs)
	}

	ps := []*versions.PkgStr{}
	for _, x := range catDirs {
		if v._excluded_dirs.MatchString(x) {
			continue
		}
		if !v._category_re.MatchString(x) {
			continue
		}
		pkgDirs := ListDir(basePath+x, false, false, false, []string{}, true, true, true)
		if sort1 {
			sort.Strings(pkgDirs)
		}

		for _, y := range pkgDirs {
			if v._excluded_dirs.MatchString(y) {
				continue
			}
			subPath := x + "/" + y
			subPathP := versions.NewPkgStr(subPath, nil, nil, "", "", "", 0, 0, "", 0, v.dbapi)
			//except InvalidData:
			//v.invalidentry(v.getpath(subPath))
			//continue

			ps = append(ps, subPathP)
		}
	}
	return ps
}

// 1, false
func (v *vardbapi) cp_all(useCache int, sort1 bool) []string {
	myList := v.cpv_all(useCache)
	d := map[string]bool{}
	for _, y := range myList {
		if y.string[0] == '*' {
			y.string = y.string[1:]
		}
		//try:
		mySplit := versions.CatPkgSplit(y.string, 1, "")
		//except InvalidData:
		//v.invalidentry(v.getpath(y))
		//continue
		if mySplit == [4]string{} {
			v.invalidentry(v.getpath(y.string, ""))
			continue
		}
		d[mySplit[0]+"/"+mySplit[1]] = true
	}
	dr := []string{}
	for k := range d {
		dr = append(dr, k)
	}
	if sort1 {
		sort.Strings(dr)
	}
	return dr
}

func (v *vardbapi) checkblockers() {}

func (v *vardbapi) _clear_cache() {
	v.mtdircache = map[string]int{}
	v.matchcache = map[string]map[[2]*dep.Atom][]*versions.PkgStr{}
	v.cpcache = map[string]struct {
		int64
		p []*versions.PkgStr
	}{}
	v._aux_cache_obj = nil
}

func (v *vardbapi) _add(pkgDblink *dblink) {
	v._pkgs_changed = true
	v._clear_pkg_cache(pkgDblink)
}

func (v *vardbapi) _remove(pkgDblink *dblink) {
	v._pkgs_changed = true
	v._clear_pkg_cache(pkgDblink)
}

func (v *vardbapi) _clear_pkg_cache(pkgDblink *dblink) {
	delete(v.mtdircache, pkgDblink.cat)
	delete(v.matchcache, pkgDblink.cat)
	delete(v.cpcache, pkgDblink.mysplit[0])
	// TODO: already deprecated?
	//delete(dircache,pkg_dblink.dbcatdir)
}

// 1
func (v *vardbapi) match(origDep string, useCache int) []*versions.PkgStr {
	myDep := dep_expandS(origDep, v.dbapi, useCache, v.settings)
	cacheKey := [2]*dep.Atom{myDep, myDep.unevaluatedAtom}
	myKey := dep.depGetKey(myDep.value)
	myCat := versions.catsplit(myKey)[0]
	if useCache == 0 {
		if _, ok := v.matchcache[myKey]; ok {
			delete(v.mtdircache, myCat)
			delete(v.matchcache, myCat)
		}
		return v._iter_match(myDep,
			v.cp_list(myDep.cp, useCache))
	}
	st, err := os.Stat(filepath.Join(v._eroot, _const.VdbPath, myCat))
	curMtime := 0
	if err == nil {
		curMtime = st.ModTime().Nanosecond()
	}

	if _, ok := v.matchcache[myCat]; !ok || v.mtdircache[myCat] != curMtime {
		v.mtdircache[myCat] = curMtime
		v.matchcache[myCat] = map[[2]*dep.Atom][]*versions.PkgStr{}
	}
	if _, ok := v.matchcache[myCat][[2]*dep.Atom{myDep, nil}]; !ok {
		myMatch := v._iter_match(myDep,
			v.cp_list(myDep.cp, useCache))
		v.matchcache[myCat][cacheKey] = myMatch
	}
	return v.matchcache[myCat][cacheKey][:]
}

func (v *vardbapi) findname(myCpv string) string {
	return v.getpath(myCpv, versions.catsplit(myCpv)[1]+".ebuild")
}

func (v *vardbapi) flush_cache() {
	if v._flush_cache_enabled && v._aux_cache() != nil && *data.secpass >= 2 && (len(v._aux_cache().modified)) >= v._aux_cache_threshold || !myutil.pathExists(v._cache_delta_filename) {

		util.EnsureDirs(filepath.Dir(v._aux_cache_filename), -1, -1, -1, -1, nil, true)
		v._owners.populate()
		valid_nodes := map[string]bool{}
		for _, v := range v.cpv_all(1) {
			valid_nodes[v.string] = true
		}
		for cpv := range v._aux_cache().packages {
			if !valid_nodes[cpv] {
				delete(v._aux_cache().packages, cpv)
			}
		}
		v._aux_cache().modified = nil
		timestamp := time.Now().Nanosecond()
		v._aux_cache().timestamp = timestamp

		f := util.NewAtomic_ofstream(v._aux_cache_filename, os.O_RDWR|os.O_CREATE, true)

		jm, _ :=json.Marshal(v._aux_cache())
		f.Write(jm)
		f.Close()
		util.apply_secpass_permissions(
			v._aux_cache_filename, -1, -1, 0644, -1, nil, true)

		v._cache_delta.initialize(timestamp)
		util.apply_secpass_permissions(v._cache_delta_filename, -1, -1, 0644, -1, nil, true)

		v._aux_cache().modified = map[string]bool{}
	}
}

func (v *vardbapi) _aux_cache() *auxCache {
	if v._aux_cache_obj == nil {
		v._aux_cache_init()
	}
	return v._aux_cache_obj
}

func (v *vardbapi) _aux_cache_init() {

	//TODO: pickle
	//aux_cache := nil
	//open_kwargs := {}
	//try:
	//	with open(_unicode_encode(v._aux_cache_filename,
	//		encoding=_encodings['fs'], errors='strict'),
	//		mode='rb', **open_kwargs) as f:
	//		mypickle = pickle.Unpickler(f)
	//		try:
	//			mypickle.find_global = nil
	//		except AttributeError:
	//				//			pass
	//		aux_cache = mypickle.load()
	//except (SystemExit, KeyboardInterrupt):
	//	raise
	//except Exception as e:
	//	if isinstance(e, EnvironmentError) &&
	//		getattr(e, 'errno', nil) in (syscall.ENOENT, errno.EACCES):
	//		pass
	//	else:
	//		WriteMsg(_("!!! Error loading '%s': %s\n") %
	//			(v._aux_cache_filename, e), noiselevel=-1)
	//	del e

	auxCache := &auxCache{}

	owners := auxCache.owners
	if owners != nil {
		if owners == nil {
			owners = nil
		} else if owners.version == 0 {
			owners = nil
		} else if owners.version != v._owners_cache_version {
			owners = nil
		} else if len(owners.base_names) == 0 {
			owners = nil
		}
	}

	if owners == nil {
		owners = &struct {
			base_names map[struct {
				s1 string
				int
				s2 string
			}]string
			version int
		}{base_names: map[struct {
			s1 string
			int
			s2 string
		}]string{}, version: v._owners_cache_version}
		auxCache.owners = owners
	}
	auxCache.modified = map[string]bool{}
	v._aux_cache_obj = auxCache
}

// nil
func (v *vardbapi) aux_get(myCpv string, wants map[string]bool, myRepo string) []string {
	cacheTheseWants := map[string]bool{}
	for k := range v._aux_cache_keys {
		if wants[k] {
			cacheTheseWants[k] = true
		}
	}
	for x := range wants {
		if v._aux_cache_keys_re.MatchString(x) {
			cacheTheseWants[x] = true
		}
	}

	if len(cacheTheseWants) == 0 {
		myData := v._aux_get(myCpv, wants, nil)
		ret := []string{}
		for x := range wants {
			ret = append(ret, myData[x])
		}
		return ret
	}

	cacheThese := map[string]bool{}
	for k := range v._aux_cache_keys {
		cacheThese[k] = true
	}
	for k := range cacheTheseWants {
		cacheThese[k] = true
	}

	myDir := v.getpath(myCpv, "")
	myDirStat, err := os.Stat(myDir)
	if err != nil {
		//except OSError as e:
		if err != syscall.ENOENT {
			//raise
		}
		//raise KeyError(myCpv)
	}
	mydirMtime := myDirStat.ModTime().UnixNano()
	pkgData := v._aux_cache().packages[myCpv]
	pullMe := map[string]bool{}
	for k := range cacheThese {
		pullMe[k] = true
	}
	for k := range wants {
		pullMe[k] = true
	}
	myData := map[string]string{"_mtime_": fmt.Sprint(mydirMtime)}
	cacheValid := false
	cacheMtime := int64(0)
	var metadata map[string]string = nil

	if pkgData != nil {
		cacheMtime, metadata = pkgData.cache_mtime, pkgData.metadata
		if cacheMtime == myDirStat.ModTime().UnixNano() {
			cacheValid = true
		} else if cacheMtime == myDirStat.ModTime().UnixNano() {
			cacheValid = true
		} else {
			cacheValid = cacheMtime == myDirStat.ModTime().UnixNano()
		}
	}
	if cacheValid {
		for k, v := range metadata {
			myData[k] = v
		}
		for k := range myData {
			delete(pullMe, k)
		}
	}

	if len(pullMe) > 0 {
		auxKeys := myutil.CopyMapSB(pullMe)
		for k, v := range v._aux_get(myCpv, auxKeys, myDirStat) {
			myData[k] = v
		}
		df := map[string]bool{}
		for k := range cacheThese {
			if _, ok := metadata[k]; !ok {
				df[k] = true
			}
		}
		if !cacheValid || len(df) > 0 {
			cacheData := map[string]string{}
			if cacheValid && len(metadata) > 0 {
				for k, v := range metadata {
					cacheData[k] = v
				}
			}
			for auxKey := range cacheThese {
				cacheData[auxKey] = myData[auxKey]
			}
			v._aux_cache().packages[myCpv] = &struct {
				cache_mtime int64
				metadata    map[string]string
			}{mydirMtime, cacheData}
			v._aux_cache().modified[myCpv] = true
		}
	}

	eapiAttrs := eapi2.getEapiAttrs(myData["EAPI"])
	if !versions.getSlotRe(eapiAttrs).MatchString(myData["SLOT"]) {
		myData["SLOT"] = "0"
	}

	ret := []string{}
	for x := range wants {
		ret = append(ret, myData[x])
	}

	return ret
}

// nil
func (v *vardbapi) _aux_get(myCpv string, wants map[string]bool, st os.FileInfo) map[string]string {
	myDir := v.getpath(myCpv, "")
	if st == nil {
		var err error
		st, err = os.Stat(myDir)
		if err != nil {
			//except OSError as e:
			if err == syscall.ENOENT {
				//raise KeyError(myCpv)
			}
			//else if err == PermissionDenied.errno:
			//raise PermissionDenied(myDir)
			//else:
			//raise
		}
	}
	if !st.IsDir() {
		//raise KeyError(myCpv)
	}
	results := map[string]string{}
	envKeys := []string{}
	for x := range wants {
		if x == "_mtime_" {
			results[x] = fmt.Sprint(st.ModTime().UnixNano())
			continue
		}
		myd, err := ioutil.ReadFile(filepath.Join(myDir, x))
		if err != nil {
			//except IOError:
			if !v._aux_cache_keys[x] && !v._aux_cache_keys_re.MatchString(x) {
				envKeys = append(envKeys, x)
				continue
			}
			myd = []byte("")
		}

		if !v._aux_multi_line_re.MatchString(x) {
			myd = []byte(strings.Join(strings.Fields(string(myd)), " "))
		}

		results[x] = string(myd)
	}

	if len(envKeys) > 0 {
		envResults := v._aux_env_search(myCpv, envKeys)
		for _, k := range envKeys {
			va := envResults[k]
			if va == "" {
				va = ""
			}
			if !v._aux_multi_line_re.MatchString(k) {
				va = strings.Join(strings.Fields(va), " ")
			}
			results[k] = va
		}
	}

	if results["EAPI"] == "" {
		results["EAPI"] = "0"
	}

	return results
}

func (v *vardbapi) _aux_env_search(cpv string, variables []string) map[string]string {

	envFile := v.getpath(cpv, "environment.bz2")
	if st, _ := os.Stat(envFile); st != nil && !st.IsDir() {
		return map[string]string{}
	}
	bunzip2Cmd, _ := shlex.Split(
		strings.NewReader(v.settings.ValueDict["PORTAGE_BUNZIP2_COMMAND"]), false, true)
	if len(bunzip2Cmd) == 0 {
		bunzip2Cmd, _ = shlex.Split(
			strings.NewReader(v.settings.ValueDict["PORTAGE_BZIP2_COMMAND"]), false, true)
		bunzip2Cmd = append(bunzip2Cmd, "-d")
	}
	args := append(bunzip2Cmd, "-c", envFile)
	cmd := exec.Command(args[0], args[1:]...)
	lines := &bytes.Buffer{}
	cmd.Stdout = lines
	if err := cmd.Run(); err != nil {
		//except EnvironmentError as e:
		//if err != syscall.ENOENT:
		//raise
		//raise portage.exception.CommandNotFound(args[0])
	}

	varAssignRe := regexp.MustCompile("(^|^declare\\s+-\\S+\\s+|^declare\\s+|^export\\s+)([^=\\s]+)=(\"|\\')?(.*)$")
	closeQuoteRe := regexp.MustCompile("(\\\\\"|\"|\\')\\s*$")
	haveEndQuote := func(quote, line string) bool {
		closeQuoteMatch := closeQuoteRe.FindStringSubmatch(line)
		return closeQuoteMatch != nil && closeQuoteMatch[1] == quote
	}

	results := map[string]string{}
	for _, line := range strings.Split(lines.String(), "\n") {
		varAssignMatch := varAssignRe.FindStringSubmatch(line)
		var key, value string
		if varAssignMatch != nil {
			key = varAssignMatch[2]
			quote := varAssignMatch[3]
			if quote != "" {
				if haveEndQuote(quote,
					line[varAssignRe.FindAllStringSubmatchIndex(line, -1)[2][1]+2:]) {
					value = varAssignMatch[4]
				} else {
					values := []string{varAssignMatch[4]}
					for _, line := range strings.Split(lines.String(), "\n") {
						values = append(values, line)
						if haveEndQuote(quote, line) {
							break
						}
						value = strings.Join(values, "")
					}
					value = strings.TrimRight(value, " ")
					value = value[:len(value)-1]
				}
			} else {
				value = strings.TrimRight(varAssignMatch[4], " ")
			}

			if myutil.Ins(variables, key) {
				results[key] = value
			}
		}
	}

	return results
}

func (v *vardbapi) aux_update(cpv string, values map[string]string) {
	mylink := v._dblink(cpv)
	if !mylink.exists() {
		//raise KeyError(cpv)
	}
	v._bump_mtime(cpv)
	v._clear_pkg_cache(mylink)
	for k, v1 := range values {
		if v1 != "" {
			mylink.setfile(k, v1)
		} else {
			if err := syscall.Unlink(filepath.Join(v.getpath(cpv, ""), k)); err != nil {
				//except EnvironmentError:
				//pass
			}
		}
	}
	v._bump_mtime(cpv)
}

func (v *vardbapi) unpack_metadata(versions.pkg, dest_dir) {

	loop = asyncio._wrap_loop()
	if not isinstance(versions.pkg, portage.config):
	versions.cpv = versions.pkg
	else:
	versions.cpv = versions.pkg.mycpv
	dbdir = v.getpath(versions.cpv)
	def
	async_copy():
	for parent, dirs, files
		in
	os.walk(dbdir, onerror = util._raise_exc):
	for key
		in
	files:
	shutil.copy(filepath.Join(parent, key),
		filepath.Join(dest_dir, key))
	break
	yield
	loop.run_in_executor(ForkExecutor(loop = loop), async_copy)

}

func (v *vardbapi) unpack_contents(versions.pkg, dest_dir,
	include_config=nil, include_unmodified_config=nil) {
	loop = asyncio._wrap_loop()
	if not isinstance(versions.pkg, portage.config):
	settings = v.settings
	versions.cpv = versions.pkg
	else:
	settings = versions.pkg
	versions.cpv = settings.mycpv

	scheduler := emerge.NewSchedulerInterface(loop, nil)
	pf := pflag.NewFlagSet("", pflag.ContinueOnError)

	pf.StringVar(, "--include-config", "n", "")

	pf.StringVar(, "--include-unmodified-config", "n", "")


	opts_list, _ := shlex.Split(strings.NewReader(settings.ValueDict["QUICKPKG_DEFAULT_OPTS"], false, true)
	if include_config != nil {
		if len(include_config) > 0 {
			opts_list = append(opts_list, fmt.Sprintf("--include-config=%s", "y"))
		} else {
			opts_list = append(opts_list, fmt.Sprintf("--include-config=%s", "n"))
		}
	}
	if include_unmodified_config != nil {
		if len(include_unmodified_config) > 0 {
			opts_list = append(opts_list, fmt.Sprintf("--include-unmodified-config=%s", "y"))
		} else {
			opts_list = append(opts_list, fmt.Sprintf("--include-unmodified-config=%s", "n"))
		}
	}

	opts, args =
		pf.Parse(opts_list)

	tar_cmd := []string{"tar", "-x", "--xattrs", "--xattrs-include=*", "-C", dest_dir}
	p2 := make([]int, 2)
	syscall.Pipe(p2)
	pr, pw := p2[0], p2[1]
	proc = (yield asyncio.create_subprocess_exec(*tar_cmd, stdin = pr))
	syscall.Close(pr)

	with os.fdopen(pw, 'wb', 0) as pw_file:
	excluded_config_files = (yield loop.run_in_executor(ForkExecutor(loop = loop),
	functools.partial(v._dblink(versions.cpv).quickpkg,
		pw_file,
		include_config = opts.include_config == 'y',
		include_unmodified_config = opts.include_unmodified_config == 'y')))
	yield proc.wait()
	if proc.returncode != 0:
	raise exception.PortageException('command failed: {}'.format(tar_cmd))

	if excluded_config_files:
	log_lines = ([_("Config files excluded by QUICKPKG_DEFAULT_OPTS (see quickpkg(1) man page):")] +
	['\t{}'.format(name) for name in excluded_config_files])
out = io.StringIO()
for line in log_lines:
portage.elog.messages.ewarn(line, phase = 'install', key = cpv, out = out)
scheduler.output(out.getvalue(),
background = v.settings.ValueDict["PORTAGE_BACKGROUND") == "1",
log_path= settings.ValueDict["PORTAGE_LOG_FILE"))

}

func (v *vardbapi) counter_tick() int {
	return v.counter_tick_core(1)
}

// ignored, ignored
func (v *vardbapi) get_counter_tick_core() int {
	counter := -1
	c, err := ioutil.ReadFile(v._counter_path)
	if err == nil {
		lines := strings.Split(string(c), "\n")
		var err2 error
		if len(lines) == 0 {
			err2 = fmt.Errorf("no line")
		} else {
			counter, err2 = strconv.Atoi(lines[0])
		}
		if err2 != nil {
			//except (OverflowError, ValueError) as e:
			msg.WriteMsg(fmt.Sprintf("!!! COUNTER file is corrupt: '%s'\n", v._counter_path), -1, nil)
			msg.WriteMsg(fmt.Sprintf("!!! %s\n", err2), -1, nil)
		}
	}
	if err != nil {
		//except EnvironmentError as e:
		if err != syscall.ENOENT {
			msg.WriteMsg(fmt.Sprintf("!!! Unable to read COUNTER file: '%s'\n", v._counter_path), -1, nil)
			msg.WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
		}
	}

	maxCounter := counter
	if v._cached_counter != counter {
		for _, cpv := range v.cpv_all(1) {
			//try:
			pkgCounter, err := strconv.Atoi(v.aux_get(cpv.string, map[string]bool{"COUNTER": true}, "")[0])
			if err != nil {
				//except(KeyError, OverflowError, ValueError):
				continue
			}
			if pkgCounter > maxCounter {
				maxCounter = pkgCounter
			}
		}
	}
	return maxCounter + 1
}

// ignnored, 1, ignored
func (v *vardbapi) counter_tick_core(incrementing int) int {
	v.lock()
	counter := v.get_counter_tick_core() - 1
	if incrementing != 0 {
		counter += 1
		// try:
		util.write_atomic(v._counter_path, fmt.Sprint(counter), 0, true)
		//except InvalidLocation:
		//v.Settings._init_dirs()
		//write_atomic(v._counter_path, str(counter))
	}
	v._cached_counter = counter
	v.flush_cache()
	v.unlock()
	return counter
}

func (v *vardbapi) _dblink(cpv string) *dblink {
	category, pf := versions.catsplit(cpv)[0], versions.catsplit(cpv)[1]
	return NewDblink(category, pf, "", v.settings, "vartree", v.vartree, nil, nil, 0)
}

// true
func (v *vardbapi) removeFromContents(pkg *dblink, paths []string, relativePaths bool) {
	root := v.settings.ValueDict["ROOT"]
	rootLen := len(root) - 1
	newContents := map[string][]string{}
	for k, v := range pkg.getcontents(){
		var v2 []string
		copy(v2, v)
		newContents[k]=v2
	}
	removed := 0

	for _, filename := range paths {
		filename = msg.NormalizePath(filename)
		relativeFilename := ""
		if relativePaths {
			relativeFilename = filename
		} else {
			relativeFilename = filename[rootLen:]
		}
		contentsKey := pkg._match_contents(relativeFilename)
		if len(contentsKey) > 0 {
			delete(newContents, contentsKey)
			removed += 1
		}
	}

	if removed != 0 {
		neededFilename := filepath.Join(pkg.dbdir, util.NewLinkageMapELF(nil)._needed_aux_key)
		var newNeeded []*util.NeededEntry = nil
		neededLines := []string{}
		f, err := os.Open(neededFilename)
		if err == nil {
			ls, _ := ioutil.ReadAll(f)
			neededLines = strings.Split(string(ls), "\n")
		}
		if err != nil {
			//except IOError as e:
			//if err not in(syscall.ENOENT, syscall.ESTALE):
			//raise
		} else {
			newNeeded = []*util.NeededEntry{}
			for _, l := range neededLines {
				l = strings.TrimRight(l, "\n")
				if l == "" {
					continue
				}
				entry, err := util.NewNeededEntry().parse(neededFilename, l)
				if err != nil {
					//except InvalidData as e:
					msg.WriteMsgLevel(fmt.Sprintf("\n%s\n\n", err),
						40, -1)
					continue
				}

				filename := filepath.Join(root, strings.TrimLeft(entry.filename, string(os.PathSeparator)))
				if _, ok := newContents[filename]; ok {
					newNeeded = append(newNeeded, entry)
				}
			}
		}

		v.writeContentsToContentsFile(pkg, newContents, newNeeded)
	}
}

// nil
func (v *vardbapi) writeContentsToContentsFile(pkg *dblink, new_contents map[string][]string, new_needed []*util.NeededEntry) {
	root := v.settings.ValueDict["ROOT"]
	v._bump_mtime(pkg.mycpv.string)
	if new_needed != nil {
		f := util.NewAtomic_ofstream(filepath.Join(pkg.dbdir, util.NewLinkageMapELF(nil)._needed_aux_key), os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
		for _, entry := range new_needed {
			f.Write([]byte(entry.__str__()))
		}
		f.Close()
	}
	f := util.NewAtomic_ofstream(filepath.Join(pkg.dbdir, "CONTENTS"), os.O_RDWR, true)
	write_contents(new_contents, root, f)
	f.Close()
	v._bump_mtime(pkg.mycpv.string)
	pkg._clear_contents_cache()
}

type _owners_cache struct {
	_new_hash              func() hash.Hash
	_hash_bits, _hex_chars int
	_vardb                 *vardbapi
}

func NewOwners_cache(vardb *vardbapi)*_owners_cache {
	o := &_owners_cache{}
	o._new_hash = md5.New
	o._hash_bits = 16
	o._hex_chars = o._hash_bits

	o._vardb = vardb
	return o
}

func (o *_owners_cache) add( cpv string) {
	erootLen := len(o._vardb._eroot)
	pkgHash := o._hash_pkg(cpv)
	db := o._vardb._dblink(cpv)
	if len(db.getcontents()) == 0 {
		o._add_path("", pkgHash)
	}

	for _, x := range db._contents.keys() {
		o._add_path(x[erootLen:], pkgHash)
	}

	o._vardb._aux_cache().modified[cpv]=true
}

func (o *_owners_cache)	_add_path( path string, pkg_hash struct{s1 string; int; s2 string}) {
	name := ""
	if path!= "" {
		name = filepath.Base(strings.TrimRight(path,string(os.PathSeparator)))
		if  name=="" {
			return
		}
	} else {
		name = path
	}
	nameHash := o._hash_str(name)
	baseNames := o._vardb._aux_cache().owners.base_names
	pkgs := baseNames[nameHash]
	if pkgs == nil {
		pkgs = map[struct{s1 string; int; s2 string}]string{}
	}
	baseNames[nameHash] = pkgs
	pkgs[pkg_hash] = ""
}

func (o *_owners_cache)  _hash_str( s string) string {
	h := o._new_hash()
	h.Write([]byte(s))
	h2 := h.Sum(nil)
	h2 = h2[-o._hex_chars:]
	return string(h2)
}

func (o *_owners_cache)  _hash_pkg( cpv string) struct{s1 string; int; s2 string} {
	v := o._vardb.aux_get(
		cpv, map[string]bool{"COUNTER": true, "_mtime_": true}, "")
	counterS, mtime := v[0], v[1]
	counter, err := strconv.Atoi(counterS)
	if err != nil {
		//except ValueError:
		counter = 0
	}
	return struct{s1 string; int; s2 string}{ cpv,counter, mtime}
}

type _owners_db struct {
	_vardb     *vardbapi
}

func New_owners_db(vardb *vardbapi)*_owners_db {
	o := &_owners_db{}

	o._vardb = vardb
	return o
}

func (o *_owners_db)  populate() {
	o._populate()
}

func (o *_owners_db)  _populate() *_owners_cache {
	ownersCache := NewOwners_cache(o._vardb)
	cachedHashes := map[struct{s1 string; int; s2 string}]bool{}
	baseNames := o._vardb._aux_cache().owners.base_names

	for _, hashValues := range baseNames {
		for v := range hashValues {
			cachedHashes[v] = true
		}
	}

	uncachedPkgs := map[string]bool{}
	hashPkg := ownersCache._hash_pkg
	validPkgHashes := map[struct{s1 string; int; s2 string}]bool{}
	for _, cpv := range o._vardb.cpv_all(1) {
		hashValue := hashPkg(cpv.string)
		validPkgHashes[hashValue] = true
		if !cachedHashes[hashValue] {
			uncachedPkgs[cpv.string] = true
		}
	}

	for cpv := range uncachedPkgs {
		ownersCache.add(cpv)
	}

	staleHashes := map[struct{s1 string; int; s2 string}]bool{}
	for k := range cachedHashes {
		if !validPkgHashes[k] {
			staleHashes[k] = true
		}
	}
	if len(staleHashes) > 0 {
		for baseNameHash, bucket := range baseNames {
			for hashValue := range staleHashes {
				delete(bucket, hashValue)
			}
			if len(bucket) == 0 {
				delete(baseNames, baseNameHash)
			}
		}
	}

	return ownersCache
}

func (o *_owners_db)  get_owners( path_iter []string)map[*dblink]map[string]bool {
	owners := map[*dblink]map[string]bool{}
	for _, v  := range o.iter_owners(path_iter) {
		owner, f := v.d, v.string
		ownedFiles := owners[owner]
		if ownedFiles == nil {
			ownedFiles = map[string]bool{}
			owners[owner] = ownedFiles
		}
		ownedFiles[f] = true
	}
	return owners
}

func (o *_owners_db)  getFileOwnerMap( path_iter []string)map[string]map[*dblink]bool {
	owners := o.get_owners(path_iter)
	fileOwners := map[string]map[*dblink]bool{}
	for pkgDblink, files := range owners {
		for f := range files {
			ownerSet := fileOwners[f]
			if ownerSet == nil {
				ownerSet = map[*dblink]bool{}
				fileOwners[f] = ownerSet
			}
			ownerSet[pkgDblink] = true
		}
	}
	return fileOwners
}

func (o *_owners_db)  iter_owners( path_iter []string)[]struct{d *dblink; string} {

	owners_cache := o._populate()
	vardb := o._vardb
	root := vardb._eroot
	hash_pkg := owners_cache._hash_pkg
	hash_str := owners_cache._hash_str
	base_names := o._vardb._aux_cache().owners.base_names
	case_insensitive := vardb.settings.Features.Features["case-insensitive-fs"]

	dblink_cache := map[string]*dblink{}

	dblinker := func(cpv string) (*dblink, error) {
		x := dblink_cache[cpv]
		if x == nil {
			if len(dblink_cache) > 20 {
				return nil, filepath.SkipDir // 随便用用
			}
			x = o._vardb._dblink(cpv)
			dblink_cache[cpv] = x
		}
		return x, nil
	}
	ret := []struct {
		d *dblink;
		string
	}{}

	for len(path_iter) > 0 {
		path := path_iter[len(path_iter)-1]
		path_iter = path_iter[:len(path_iter)-1]
		if case_insensitive {
			path = strings.ToLower(path)
		}
		is_basename := string(os.PathSeparator) != path[:1]
		name := ""
		if is_basename {
			name = path
		} else {
			name = filepath.Base(strings.TrimRight(path, string(os.PathSeparator)))
		}

		if name == "" {
			continue
		}

		name_hash := hash_str(name)
		pkgs := base_names[name_hash]
		owners := [][2]string{}
		if pkgs != nil {
			var err1 error
			for hash_value := range pkgs {
				cpv, _, _ := hash_value.s1, hash_value.int, hash_value.s2

				current_hash := hash_pkg(cpv)
				if current_hash != hash_value {
					continue
				}

				if is_basename {
					dl, err := dblinker(cpv)
					if err != nil {
						err1 = err
						break
					}
					for _, p := range dl._contents.keys() {
						if filepath.Base(p) == name {
							dl, err := dblinker(cpv)
							if err != nil {
								err1 = err
								break
							}
							owners = append(owners, [2]string{cpv, dl._contents.unmap_key(p)[len(root):]})
						}
					}
				} else {
					dl, err := dblinker(cpv)
					if err != nil {
						err1 = err
						break
					}
					key := dl._match_contents(path)
					if key != "" {
						owners = append(owners, [2]string{cpv, key[len(root):]})
					}
				}
			}
			if err1 == filepath.SkipDir {
				//except StopIteration:
				path_iter = append(path_iter, path)
				owners = [][2]string{}
				dblink_cache = map[string]*dblink{}
				for _, x := range o._iter_owners_low_mem(path_iter) {
					ret = append(ret, x)
				}
				return ret
			} else {
				for _, v := range owners {
					cpv, p := v[0], v[1]
					dl, _ := dblinker(cpv)
					ret = append(ret, struct {
						d *dblink
						string
					}{d: dl, string: p})
				}
			}
		}
	}
	return ret
}

func (o *_owners_db)  _iter_owners_low_mem(path_list []string) []struct{d *dblink; string}{
	if len(path_list) == 0 {
		return nil
	}

	case_insensitive :=  o._vardb.settings.Features.Features["case-insensitive-fs"]
	path_info_list := []struct{s1 string; s2 string; bool}{}
	for _, path := range path_list{
		if case_insensitive {
			path = strings.ToLower(path)
		}
		is_basename := string(os.PathSeparator) != path[:1]
		name := ""
		if is_basename {
			name = path
		}else {
			name = filepath.Base(strings.TrimRight(path, string(os.PathSeparator)))
		}
		path_info_list= append(path_info_list, struct{s1 string; s2 string; bool}{path, name, is_basename})
	}

	root := o._vardb._eroot

	search_pkg:= func(cpv string) []struct{d *dblink; string} {
		dblnk := o._vardb._dblink(cpv)
		results := []struct{d *dblink; string}{}
		for _, v := range path_info_list{
			path, name, is_basename := v.s1,v.s2,v.bool
			if is_basename{
				for _,p:= range dblnk._contents.keys(){
					if filepath.Base(p) == name{
						results=append(results, struct{ d *dblink; string }{dblnk,
							dblnk._contents.unmap_key(p)[len(root):]})
					}
				}
			} else {
				key := dblnk._match_contents(path)
				if key != "" {
					results = append(results, struct{ d *dblink; string }{dblnk, key[len(root):]})
				}
			}
		}
		return results
	}

	ret := []struct{d *dblink; string}{}
	for _, cpv := range	o._vardb.cpv_all(1){
		for _, result := range search_pkg(cpv.string) {
			ret = append(ret,  result)
		}
	}
	return ret
}

func NewVarDbApi(settings *ebuild.Config, vartree *varTree) *vardbapi { // nil, nil
	v := &vardbapi{}
	e := []string{}
	for _, v := range []string{"CVS", "lost+found"} {
		e = append(e, regexp.QuoteMeta(v))
	}
	v._excluded_dirs = regexp.MustCompile("^(\\..*|" + _const.MergingIdentifier + ".*|" + strings.Join(e, "|") + ")$")
	v._aux_cache_version = 1
	v._owners_cache_version = 1
	v._aux_cache_threshold = 5
	v._aux_cache_keys_re = regexp.MustCompile("^NEEDED\\..*$")
	v._aux_multi_line_re = regexp.MustCompile("^(CONTENTS|NEEDED\\..*)$")

	v._pkgs_changed = false
	v._flush_cache_enabled = true
	v.mtdircache = map[string]int{}
	v.matchcache = map[string]map[[2]*dep.Atom][]*versions.PkgStr{}
	v.cpcache = map[string]struct {
		int64
		p []*versions.PkgStr
	}{}
	v.blockers = nil
	if settings == nil {
		settings = portage.Settings()
	}
	v.settings = settings
	v._eroot = settings.ValueDict["EROOT"]
	v._dbroot = v._eroot + _const.VdbPath
	v._lock = ""
	v._lock_count = 0

	v._conf_mem_file = v._eroot + _const.ConfigMemoryFile
	v._fs_lock_obj = nil
	v._fs_lock_count = 0
	v._slot_locks = map[*dep.Atom]*struct {
		s *locks.LockFileS
		int
	}{}

	if vartree == nil {
		vartree = portage.Db().valueDict[settings.ValueDict["EROOT"]].VarTree()
	}
	v.vartree = vartree
	v._aux_cache_keys = map[string]bool{
		"BDEPEND": true, "BUILD_TIME": true, "CHOST": true, "COUNTER": true, "DEPEND": true,
		"DESCRIPTION": true, "EAPI": true, "HDEPEND": true, "HOMEPAGE": true,
		"BUILD_ID": true, "IUSE": true, "KEYWORDS": true,
		"LICENSE": true, "PDEPEND": true, "PROPERTIES": true, "RDEPEND": true,
		"repository": true, "RESTRICT": true, "SLOT": true, "USE": true, "DEFINED_PHASES": true,
		"PROVIDES": true, "REQUIRES": true,
	}
	v._aux_cache_obj = nil
	v._aux_cache_filename = filepath.Join(v._eroot, _const.CachePath, "vdb_metadata.pickle")
	v._cache_delta_filename = filepath.Join(v._eroot, _const.CachePath, "vdb_metadata_delta.json")
	v._cache_delta = NewVdbMetadataDelta(v)
	v._counter_path = filepath.Join(v._eroot, _const.CachePath, "counter")

	v._plib_registry = util.NewPreservedLibsRegistry(settings.ValueDict["ROOT"], filepath.Join(v._eroot, _const.PrivatePath, "preserved_libs_registry"))
	v._linkmap = util.NewLinkageMapELF(v)
	v._owners = New_owners_db(v)

	v._cached_counter = nil

	return v
}

type varTree struct {
	settings  *ebuild.Config
	populated int
	dbapi     *vardbapi
}

// ""
func (v *varTree) getpath(myKey, filename string) string {
	return v.dbapi.getpath(myKey, filename)
}

func (v *varTree) zap() {}

func (v *varTree) inject() {}

func (v *varTree) getprovide() []string {
	return []string{}
}

func (v *varTree) get_all_provides() map[string][]*versions.PkgStr {
	return map[string][]*versions.PkgStr{}
}

// 1
func (v *varTree) dep_bestmatch(myDep string, useCache int) string {
	s := []string{}
	for _, p := range v.dbapi.match(dep_expandS(myDep, v.dbapi.dbapi, 1, v.settings), useCache) {
		s = append(s, p.string)
	}
	myMatch := versions.Best(s, "")
	if myMatch == "" {
		return ""
	} else {
		return myMatch
	}
}

// 1
func (v *varTree) dep_match(myDep *dep.Atom, useCache int) []*versions.PkgStr {
	myMatch := v.dbapi.match(myDep, useCache)
	if myMatch == nil {
		return []*versions.PkgStr{}
	} else {
		return myMatch
	}

}

func (v *varTree) exists_specific(cpv string) bool {
	return v.dbapi.cpv_exists(cpv, "")
}

func (v *varTree) getallcpv() []*versions.PkgStr {
	return v.dbapi.cpv_all(1)
}

func (v *varTree) getallnodes() []string {
	return v.dbapi.cp_all(1, false)
}

func (v *varTree) getebuildpath(fullPackage string) string {
	packagee := versions.catsplit(fullPackage)[1]
	return v.getpath(fullPackage, packagee+".ebuild")
}

func (v *varTree) getslot(myCatPkg *versions.PkgStr) string {
	return v.dbapi._pkg_str(myCatPkg, "").slot
}

func (v *varTree) populate() {
	v.populated = 1
}

func NewVarTree(categories map[string]bool, settings *ebuild.Config) *varTree {
	v := &varTree{}
	if settings == nil {
		settings = portage.Settings()
	}
	v.settings = settings
	v.dbapi = NewVarDbApi(settings, v)
	v.populated = 1

	return v
}

type dblink struct {
	_ignored_rmdir_errnos, _ignored_unlink_errnos []error
	_infodir_cleanup                              map[string]bool
	_contents_re, _normalize_needed               *regexp.Regexp

	_eroot, cat, pkg, treetype, dbroot, dbcatdir, dbtmpdir, dbpkgdir, dbdir, myroot string
	mycpv                                                                           *versions.PkgStr
	mysplit                                                                         []string
	vartree                                                                         *varTree
	settings                                                                        *ebuild.Config
	_verbose, _linkmap_broken, _postinst_failure, _preserve_libs                    bool
	_contents                                                                       *ContentsCaseSensitivityManager
	contentscache                                                                   map[string][]string

	_hash_key           []string
	_protect_obj        *util.ConfigProtect
	_slot_locks         []*dep.Atom
	_contents_basenames map[string]bool
	_contents_inodes    map[[2]uint64][]string
	_installed_instance *dblink
	_scheduler          *emerge.SchedulerInterface
	_device_path_map    map[uint64]string
	_pipe               int
	_blockers           []*dblink
	_hardlink_merge_map map[[2]uint64][]string
}

func (d *dblink) __hash__() string{
	//return hash(d._hash_key)
	return strings.Join(d._hash_key,"")
}

func (d *dblink) __eq__(other *dblink) bool {
	return &d._hash_key == &other._hash_key
}

func (d *dblink) _get_protect_obj() *util.ConfigProtect {
	cp, _ := shlex.Split(
		strings.NewReader(d.settings.ValueDict["CONFIG_PROTECT"]), false, true)
	cpm, _ := shlex.Split(
		strings.NewReader(d.settings.ValueDict["CONFIG_PROTECT_MASK"]), false, true)
	if d._protect_obj == nil {
		d._protect_obj = util.NewConfigProtect(d._eroot,
			cp, cpm,
			d.settings.Features.Features["case-insensitive-fs"])
	}

	return d._protect_obj
}

func (d *dblink) isprotected(obj string) bool {
	return d._get_protect_obj().IsProtected(obj)
}

func (d *dblink) updateprotect() {
	d._get_protect_obj().updateprotect()
}

func (d *dblink) lockdb() {
	d.vartree.dbapi.lock()
}

func (d *dblink) unlockdb() {
	d.vartree.dbapi.unlock()
}

func (d *dblink) _slot_locked(f func()) {

	wrapper := func(d *dblink, *args, **kwargs) {
		if d.settings.Features.Features["parallel-install"] {
			d._acquire_slot_locks(
				kwargs.get("mydbapi", d.vartree.dbapi))
		}
		defer d._release_slot_locks()
		return f(d, *args, **kwargs)
	}
	return wrapper
}

func (d *dblink) _acquire_slot_locks() {

	slot_atoms := []*dep.Atom{}

	//try:
	slot := d.mycpv.slot
	//except AttributeError:
	//slot, = db.aux_get(d.mycpv, ["SLOT"])
	//slot = slot.partition("/")[0]

	a, _ := dep.NewAtom(
		fmt.Sprintf("%s:%s", d.mycpv.cp, slot), nil, false, nil, nil, "", nil, nil)

	slot_atoms = append(slot_atoms, a)

	for _, blocker := range d._blockers {
		slot_atoms = append(slot_atoms, blocker.slot_atom)
	}

	sort.Strings(slot_atoms)
	for _, slot_atom := range slot_atoms {
		d.vartree.dbapi._slot_lock(slot_atom)
		d._slot_locks = append(d._slot_locks, slot_atom)
	}

}

func (d *dblink) _release_slot_locks() {
	for len(d._slot_locks) != 0 {
		l := d._slot_locks[len(d._slot_locks)-1]
		d._slot_locks = d._slot_locks[:len(d._slot_locks)-1]
		d.vartree.dbapi._slot_unlock(l)
	}
}

func (d *dblink) getpath() string {
	return d.dbdir
}

func (d *dblink) exists() bool {
	_, err := os.Stat(d.dbdir)
	if err == nil {
		return true
	} else {
		return false
	}
}

func (d *dblink) delete() {
	if _, err := os.Lstat(d.dbdir); err != nil {
		//except OSError as e:
		if err != syscall.ENOENT && err != syscall.ENOTDIR && err != syscall.ESTALE){
			//raise
		}
		return
	}

	if !strings.HasPrefix(d.dbdir, d.dbroot) {
		msg.WriteMsg(fmt.Sprintf("portage.dblink.delete(): invalid dbdir: %s\n", d.dbdir), -1, nil)
		return
	}

	if d.dbdir == d.dbpkgdir {
		counter := d.vartree.dbapi.aux_get(
			d.mycpv.string, map[string]bool{"COUNTER":true}, "")
		d.vartree.dbapi._cache_delta.recordEvent(
			"remove", d.mycpv,
			strings.Split(d.settings.ValueDict["SLOT"], "/")[0], counter)
	}

	os.RemoveAll(d.dbdir)
	os.RemoveAll(filepath.Dir(d.dbdir))
	d.vartree.dbapi._remove(d)

	ls, _ := os.Lstat(d.dbroot)
	d._merged_path(d.dbroot, ls, true)

	d._post_merge_sync()
}

func (d *dblink) clearcontents() {
	d.lockdb()
	if st, _ := os.Stat(d.dbdir + "/CONTENTS"); st != nil {
		syscall.Unlink(d.dbdir + "/CONTENTS")
	}
	d.unlockdb()
}

func (d *dblink) _clear_contents_cache() {
	d.contentscache = nil
	d._contents_inodes = nil
	d._contents_basenames = nil
	d._contents.clear_cache()
}

func (d *dblink) getcontents() map[string][]string{
	if d.contentscache != nil {
		return d.contentscache
	}
	contentsFile := filepath.Join(d.dbdir, "CONTENTS")
	pkgFiles := map[string][]string{}
	f, err:= ioutil.ReadFile(contentsFile)
	if err != nil {
		//except EnvironmentError as e:
		if err != syscall.ENOENT {
			//raise
		}
		//del e
		d.contentscache = pkgFiles
		return pkgFiles
	}

	myLines := strings.Split(string(f), "\n")

	nullByte := []byte{0}
	normalizeNeeded := d._normalize_needed
	contentsRe := d._contents_re
	var objIndex, dirIndex, symIndex, oldsymIndex int
	for i, v := range contentsRe.SubexpNames(){
		switch v {
		case "obj":
			objIndex = i
		case "dir":
			dirIndex = i
		case "sym":
			symIndex =i
		case "oldsym":
			oldsymIndex = i
		}
	}
	myRoot := d.settings.ValueDict["ROOT"]
	if myRoot == string(os.PathSeparator) {
		myRoot = ""
	}
	dirEntry := []string{"dir"}
	erootSplitLen := len(strings.Split(d.settings.ValueDict["EROOT"],string(os.PathSeparator))) - 1
	errors := []struct{int; string}{}
	for pos, line := range myLines {
		if strings.Contains(line, string(nullByte)) {
			errors = append(errors, struct{ int; string }{pos + 1, "Null byte found in CONTENTS entry"})
			continue
		}
		line = strings.TrimRight(line, "\n")
		m := contentsRe.FindAllString(line, -1)
		if m == nil {
			errors= append(errors, struct{ int; string }{pos + 1, "Unrecognized CONTENTS entry"})
			continue
		}

		base:=0
		var data []string
		if m[objIndex] != "" {
			base = objIndex
			data = []string{m[base + 1], m[base + 4], m[base + 3]}
		}else if m[dirIndex]!= ""{
			base = dirIndex
			data = []string{m[base + 1]}
		}else if m[symIndex]!= "" {
			base = symIndex
			mtime := ""
			if m[oldsymIndex] =="" {
				mtime = m[base + 5]
			} else {
				mtime = m[base+8]
			}
			data = []string{m[base + 1], mtime, m[base + 3]}
		}else{
			//raise AssertionError(_("required group not found " +
			//"in CONTENTS entry: '%s'") % line)
		}

		path := m[base + 2]
		if normalizeNeeded.MatchString(path) {
			path = msg.NormalizePath(path)
			if ! strings.HasPrefix(path, string(os.PathSeparator)) {
				path = string(os.PathSeparator) + path
			}
		}

		if myRoot != "" {
			path = filepath.Join(myRoot, strings.TrimLeft(path, string(os.PathSeparator)))
		}

		pathSplit := strings.Split(path, string(os.PathSeparator))
		pathSplit = pathSplit[:len(pathSplit)-1]
		for len(pathSplit) > erootSplitLen {
			parent:= strings.Join(pathSplit, string(os.PathSeparator))
			if _, ok := pkgFiles[parent]; ok {
				break
			}
			pkgFiles[parent] = dirEntry
			pathSplit = pathSplit[:len(pathSplit)-1]

		}

		pkgFiles[path] = data
	}

	if len(errors) > 0 {
		msg.WriteMsg(fmt.Sprintf("!!! Parse error in '%s'\n", contentsFile), -1, nil)
		for _, v := range errors {
			pos, e := v.int, v.string
			msg.WriteMsg(fmt.Sprintf("!!!   line %d: %s\n", pos, e), -1, nil)
		}
	}
	d.contentscache = pkgFiles
	return pkgFiles
}

// false, false
func (d *dblink) quickpkg(output_file, include_config, include_unmodified_config bool) []string {
	settings := d.settings
	xattrs := settings.Features.Features["xattr"]
	contents := d.getcontents()
	excluded_config_files := []string{}
	var protect func( string) bool = nil

	if !include_config {
		ss1 , _ := shlex.Split(strings.NewReader(settings.ValueDict["CONFIG_PROTECT"]), false, true)
		ss2, _ :=shlex.Split(strings.NewReader(settings.ValueDict["CONFIG_PROTECT_MASK"]), false, true)
		confprot := util.NewConfigProtect(settings.ValueDict["EROOT"],
			ss1,ss2, settings.Features.Features["case-insensitive-fs"]))
		protect= func(filename string) bool {
			if ! confprot.IsProtected(filename){
				return false
			}
			if include_unmodified_config {
				file_data := contents[filename]
				if file_data[0] == "obj" {
					orig_md5 := strings.ToLower(file_data[2])
					cur_md5 := checksum.performMd5(filename, true)
					if orig_md5 == string(cur_md5) {
						return false
					}
				}
			}
			excluded_config_files=append(excluded_config_files, filename)
			return true
		}
	}

	//format := tar.FormatGNU
	//if xattrs{
	//	tar.FormatPAX
	//}
	t := tar.NewWriter(output_file)
	tar_contents(contents, settings.ValueDict["ROOT"], t, protect, nil, xattrs)

	return excluded_config_files
}

// false, "", nil
func (d *dblink) _prune_plib_registry(unmerge bool, needed string, preserve_paths map[string]bool) {
	if !(d._linkmap_broken || d.vartree.dbapi._linkmap == nil || d.vartree.dbapi._plib_registry == nil) {
		d.vartree.dbapi._fs_lock()
		plib_registry := d.vartree.dbapi._plib_registry
		plib_registry.lock()
		defer func() {
			plib_registry.unlock()
			d.vartree.dbapi._fs_unlock()
		}()
		plib_registry.load()

		unmerge_with_replacement := unmerge && preserve_paths != nil

		var exclude_pkgs []*versions.PkgStr
		if unmerge_with_replacement {
			exclude_pkgs = []*versions.PkgStr{d.mycpv,}
		}

		d._linkmap_rebuild(exclude_pkgs, needed, preserve_paths)

		if unmerge {
			unmerge_preserve := []string{}
			if !unmerge_with_replacement {
				unmerge_preserve =
					d._find_libs_to_preserve(true)
			}
			counter := d.vartree.dbapi.cpv_counter(d.mycpv)
			//try:
			slot := d.mycpv.slot
			//except  AttributeError:
			//slot = NewPkgStr(d.mycpv, slot = d.Settings.ValueDict["SLOT"]).slot
			plib_registry.unregister(d.mycpv.string, slot, counter)
			if len(unmerge_preserve) > 0 {
				for _, path := range myutil.sortedmsb(unmerge_preserve) {
					contents_key := d._match_contents(path)
					if len(contents_key) > 0 {
						continue
					}
					obj_type := d.getcontents()[contents_key][0]
					d._display_merge(fmt.Sprintf(">>> needed   %s %s\n", obj_type, contents_key), 0, -1)
				}
				plib_registry.register(d.mycpv.string, slot, fmt.Sprint(counter), unmerge_preserve)
				d.vartree.dbapi.removeFromContents(d, unmerge_preserve, true)
			}
		}

		unmerge_no_replacement := unmerge && !unmerge_with_replacement
		cpv_lib_map := d._find_unused_preserved_libs(unmerge_no_replacement)
		if len(cpv_lib_map) > 0 {
			d._remove_preserved_libs(cpv_lib_map)
			d.vartree.dbapi.lock()
			//try:
			for cpv, removed := range cpv_lib_map {
				if !d.vartree.dbapi.cpv_exists(cpv) {
					continue
				}
				d.vartree.dbapi.removeFromContents(d._quickpkg_dblink(cpv), removed)
			}
			//finally:
			d.vartree.dbapi.unlock()
		}

		plib_registry.store()
	}
}

// nil, true, nil, nil, "", nil
// @_slot_locked
func (d *dblink) unmerge(pkgfiles map[string][]string, cleanup bool,
	ldpath_mtimes=nil, others_in_slot []*dblink, needed string,
	preserve_paths map[string]bool) int {

	background := false
	log_path := d.settings.ValueDict["PORTAGE_LOG_FILE"]
	if d._scheduler == nil {
		d._scheduler = emerge.NewSchedulerInterface(asyncio._safe_loop())
	}
	if d.settings.ValueDict["PORTAGE_BACKGROUND"] == "subprocess" {

		if d.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] == "1" {
			d.settings.ValueDict["PORTAGE_BACKGROUND"] = "1"
			d.settings.BackupChanges("PORTAGE_BACKGROUND")
			background = true
		} else if d.settings.ValueDict["PORTAGE_BACKGROUND_UNMERGE"] == "0" {
			d.settings.ValueDict["PORTAGE_BACKGROUND"] = "0"
			d.settings.BackupChanges("PORTAGE_BACKGROUND")
		}
	} else if d.settings.ValueDict["PORTAGE_BACKGROUND"] == "1" {
		background = true
	}

	d.vartree.dbapi._bump_mtime(d.mycpv.string)
	showMessage := d._display_merge
	if d.vartree.dbapi._categories != nil {
		d.vartree.dbapi._categories = nil
	}

	caller_handles_backup := others_in_slot != nil

	if others_in_slot == nil {
		slot := d.vartree.dbapi._pkg_str(d.mycpv, "").slot
		slot_matches := d.vartree.dbapi.match(
			fmt.Sprintf("%s:%s", versions.cpvGetKey(d.mycpv.string, ""), slot), 1)
		others_in_slot = []*dblink{}
		for _, cur_cpv := range slot_matches {
			if cur_cpv.string == d.mycpv.string {
				continue
			}
			others_in_slot = append(others_in_slot, NewDblink(d.cat, versions.catsplit(cur_cpv.string)[1], "",
				d.settings, "vartree", d.vartree,
				nil, nil, d._pipe))
		}
		retval := d._security_check(append([]*dblink{d}, others_in_slot...))
		if retval != 0 {
			return retval
		}
	}

	contents := d.getcontents()
	myebuildpath := filepath.Join(d.dbdir, d.pkg+".ebuild")
	failures := 0
	ebuild_phase := "prerm"
	mystuff, _ := myutil.ListDir(d.dbdir)
	for _, x := range mystuff {
		if strings.HasSuffix(x, ".ebuild") {
			if x[:len(x)-7] != d.pkg {
				os.Rename(filepath.Join(d.dbdir, x), myebuildpath)
				util.write_atomic(filepath.Join(d.dbdir, "PF"), d.pkg+"\n", 0, true)
			}
			break
		}
	}

	if d.mycpv.string != d.settings.mycpv.string || !myutil.Inmss(d.settings.configDict["pkg"], "EAPI") {
		d.settings.SetCpv(d.mycpv, d.vartree.dbapi)
	}
	eapi_unsupported := false
	//try:
	atom.doebuild_environment(myebuildpath, "prerm", nil, d.settings, false, nil, d.vartree.dbapi)
	//except UnsupportedAPIException as e:
	//eapi_unsupported = e

	if d._preserve_libs && myutil.Ins(strings.Fields(d.settings.ValueDict["PORTAGE_RESTRICT"]), "preserve-libs") {
		d._preserve_libs = false
	}

	var builddir_lock *emerge.EbuildBuildDir
	scheduler := d._scheduler
	retval := 0
	//try:
	if !myutil.Inmss(d.settings.ValueDict, "PORTAGE_BUILDDIR_LOCKED") {
		builddir_lock = emerge.NewEbuildBuildDir(scheduler, d.settings)
		scheduler.run_until_complete(builddir_lock.async_lock())
		atom.prepare_build_dirs(d.settings, true)
		log_path = d.settings.ValueDict["PORTAGE_LOG_FILE"]
	}
	if !caller_handles_backup {
		retval = d._pre_unmerge_backup(background)
		if retval != 0 {
			showMessage(fmt.Sprintf("!!! FAILED prerm: quickpkg: %s\n", retval),
				40, -1)
			return retval
		}
	}

	d._prune_plib_registry(true, needed, preserve_paths)

	if eapi_unsupported {
		failures += 1
		showMessage(fmt.Sprintf("!!! FAILED prerm: %s\n", filepath.Join(d.dbdir, "EAPI")), 40, -1)
		showMessage(fmt.Sprintf("%s\n", eapi_unsupported, ), 40, -1)
	} else if myutil.pathIsFile(myebuildpath) {
		phase := emerge.NewEbuildPhase(nil, background, ebuild_phase, scheduler, d.settings, nil)
		phase.start()
		retval = phase.wait()

		if retval != 0 {
			failures += 1
			showMessage(fmt.Sprintf("!!! FAILED prerm: %s\n", retval),
				40, -1)
		}
	}

	d.vartree.dbapi._fs_lock()
	//try:
	d._unmerge_pkgfiles(pkgfiles, others_in_slot)
	//finally:
	d.vartree.dbapi._fs_unlock()
	d._clear_contents_cache()

	if !eapi_unsupported && myutil.pathIsFile(myebuildpath) {
		ebuild_phase := "postrm"
		phase := emerge.NewEbuildPhase(nil, background, ebuild_phase, scheduler, d.settings, nil)
		phase.start()
		retval = phase.wait()

		if retval != 0 {
			failures += 1
		}
		showMessage(fmt.Sprintf("!!! FAILED postrm: %s\n", retval), 40, -1)
	}

	//finally:
	d.vartree.dbapi._bump_mtime(d.mycpv.string)
	//try:
	if !eapi_unsupported && myutil.pathIsFile(myebuildpath) {
		if retval != 0 {
			msg_lines := []string{}
			msg := fmt.Sprintf("The '%s' "+
				"phase of the '%s' package "+
				"has failed with exit value %s.",
				ebuild_phase, d.mycpv, retval)
			msg_lines = append(msg_lines, myutil.SplitSubN(msg, 72)...)
			msg_lines = append(msg_lines, "")

			ebuild_name := filepath.Base(myebuildpath)
			ebuild_dir := filepath.Dir(myebuildpath)
			msg = fmt.Sprintf("The problem occurred while executing "+
				"the ebuild file named '%s' "+
				"located in the '%s' directory. "+
				"If necessary, manually remove "+
				"the environment.bz2 file and/or the "+
				"ebuild file located in that directory.",
				ebuild_name, ebuild_dir)
			msg_lines = append(msg_lines, myutil.SplitSubN(msg, 72)...)
			msg_lines = append(msg_lines, "")

			msg = "Removal " +
				"of the environment.bz2 file is " +
				"preferred since it may allow the " +
				"removal phases to execute successfully. " +
				"The ebuild will be " +
				"sourced and the eclasses " +
				"from the current ebuild repository will be used " +
				"when necessary. Removal of " +
				"the ebuild file will cause the " +
				"pkg_prerm() and pkg_postrm() removal " +
				"phases to be skipped entirely."
			msg_lines = append(msg_lines, myutil.SplitSubN(msg, 72)...)

			d._eerror(ebuild_phase, msg_lines)
		}
	}

	d._elog_process([]string{"prerm", "postrm"})

	if retval == 0 {
		//try:
		atom.doebuild_environment(myebuildpath, "cleanrm", nil, d.settings, false, nil, d.vartree.dbapi)
		//except UnsupportedAPIException:
		//pass
		phase := emerge.NewEbuildPhase(nil, background, "cleanrm", scheduler,
			d.settings, nil)
		phase.start()
		retval = phase.wait()
	}
	//finally:
	if builddir_lock != nil {
		scheduler.run_until_complete(
			builddir_lock.async_unlock())
	}

	if log_path != "" {
		if failures == 0 && !d.settings.Features.Features["unmerge-logs"] {
			if err := syscall.Unlink(log_path); err != nil {
				//except OSError:
				//pass
			}
		}

		st, err := os.Stat(log_path)
		if err != nil {
			//except OSError:
			//pass
		} else {
			if st.Size() == 0 {
				if err := syscall.Unlink(log_path); err != nil {
					//except OSError:
					//pass
				}
			}
		}
	}

	if log_path != "" && myutil.pathExists(log_path) {
		d.settings.ValueDict["PORTAGE_LOG_FILE"] = log_path
	} else {
		delete(d.settings.ValueDict, "PORTAGE_LOG_FILE")
	}

	util.env_update(1, d.settings.ValueDict["ROOT"],
		prev_mtimes = ldpath_mtimes,
		contents, d.settings,
		d._display_merge, d.vartree.dbapi)

	unmerge_with_replacement := preserve_paths != nil
	if !unmerge_with_replacement {
		d._prune_plib_registry(false, "", nil)
	}

	return 0

}

// 0, 0
func (d *dblink) _display_merge(msg string, level, noiselevel int){
	if ! d._verbose && noiselevel >= 0 && level < 30 {
		return
	}
	if d._scheduler == nil {
		msg.WriteMsgLevel(msg, level, noiselevel)
	}else {
		log_path := ""
		if d.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
			log_path = d.settings.ValueDict["PORTAGE_LOG_FILE"]
		}
		background := d.settings.ValueDict["PORTAGE_BACKGROUND"] == "1"

		if background && log_path == "" {
			if level >= 30 {
				msg.WriteMsgLevel(msg, level, noiselevel)
			}
		} else {
			d._scheduler.output(msg,
				log_path = log_path, background = background,
				level = level, noiselevel=noiselevel)
		}
	}
}

func (d *dblink) _show_unmerge(zing, desc, file_type, file_name string) {
	d._display_merge(fmt.Sprintf("%s % -8s %s %s\n",
		zing, desc, file_type, file_name), 0, 0)
}

func (d *dblink) _unmerge_pkgfiles(pkgfiles map[string][]string, others_in_slot []*dblink) {

	os = _os_merge
	perf_md5 := checksum.performMd5
	showMessage := d._display_merge
	show_unmerge := d._show_unmerge
	ignored_unlink_errnos := d._ignored_unlink_errnos

	if len(pkgfiles) == 0 {
		showMessage("No package files given... Grabbing a set.\n", 0, 0)
		pkgfiles = d.getcontents()
	}

	if others_in_slot == nil {
		others_in_slot = []*dblink{}
		slot := d.vartree.dbapi._pkg_str(d.mycpv, "").slot
		slot_matches := d.vartree.dbapi.match(
			fmt.Sprintf("%s:%s", versions.cpvGetKey(d.mycpv.string, ""), slot), 1)
		for _, cur_cpv := range slot_matches {
			if cur_cpv.string == d.mycpv.string {
				continue
			}
			others_in_slot = append(others_in_slot, NewDblink(d.cat, versions.catsplit(cur_cpv)[1], "",
				d.settings, "vartree", d.vartree, nil, nil, d._pipe))
		}
	}

	cfgfiledict := util.grabDict(d.vartree.dbapi._conf_mem_file, false, false, false, true, false)
	stale_confmem := []string{}
	protected_symlinks := map[[2]uint64][]string{}

	unmerge_orphans := d.settings.Features.Features["unmerge-orphans"]
	calc_prelink := d.settings.Features.Features["prelink-checksums"]

	if len(pkgfiles) > 0 {
		d.updateprotect()
		mykeys := []string{}
		for k := range pkgfiles {
			mykeys = append(mykeys, k)
		}
		sort.Strings(mykeys)
		myutil.ReverseSlice(mykeys)

		mydirs := map[struct {
			s string;
			i [2]uint64
		}]bool{}

		uninstall_ignore, _ := shlex.Split(strings.NewReader(
			d.settings.ValueDict["UNINSTALL_IGNORE"]), false, true)

		unlink := func(file_name string, lstatobj os.FileInfo) {
			//if bsd_chflags {
			//	if lstatobj.st_flags != 0 {
			//		bsd_chflags.lchflags(file_name, 0)
			//	}
			//	parent_name = filepath.Dir(file_name)
			//	pflags = os.Stat(parent_name).st_flags
			//	if pflags != 0 {
			//		bsd_chflags.chflags(parent_name, 0)
			//	}
			//}
			var err error
			if syscall.S_IFLNK&lstatobj.Mode() == 0 {
				err = os.Chmod(file_name, 0)
			}
			if err == nil {
				err = syscall.Unlink(file_name)
			}
			if err != nil {
				//except OSError as ose:
				//d._eerror("postrm", []string{fmt.Sprintf("Could not chmod or unlink '%s': %s", file_name, ose)}
			} else {
				d._merged_path(file_name, lstatobj, false)
			}

			//finally:
			//if bsd_chflags && pflags != 0 {
			//	bsd_chflags.chflags(parent_name, pflags)
			//}
		}

		unmerge_desc := map[string]string{}
		unmerge_desc["cfgpro"] = ("cfgpro")
		unmerge_desc["replaced"] = ("replaced")
		unmerge_desc["!dir"] = ("!dir")
		unmerge_desc["!empty"] = ("!empty")
		unmerge_desc["!fif"] = ("!fif")
		unmerge_desc["!found"] = ("!found")
		unmerge_desc["!md5"] = ("!md5")
		unmerge_desc["!mtime"] = ("!mtime")
		unmerge_desc["!obj"] = ("!obj")
		unmerge_desc["!sym"] = ("!sym")
		unmerge_desc["!prefix"] = ("!prefix")

		real_root := d.settings.ValueDict["ROOT"]
		real_root_len := len(real_root) - 1
		eroot := d.settings.ValueDict["EROOT"]

		infodirs := map[string]bool{}
		for _, infodir := range strings.Split(d.settings.ValueDict["INFOPATH"], ":") {
			if infodir != "" {
				infodirs[infodir] = true
			}
		}
		for _, infodir := range strings.Split(d.settings.ValueDict["INFODIR"], ":") {
			if infodir != "" {
				infodirs[infodir] = true
			}
		}
		infodirs_inodes := map[[2]uint64]bool{}
		for infodir := range infodirs {
			infodir = filepath.Join(real_root, strings.TrimLeft(infodir, string(os.PathSeparator)))
			statobj, err := os.Stat(infodir)
			if err != nil {
				//except OSError:
				//pass
			} else {
				infodirs_inodes[[2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}] = true
			}
		}

		for _, objkey := range mykeys {

			obj := msg.NormalizePath(objkey)

			file_data := pkgfiles[objkey]
			file_type := file_data[0]

			if len(obj) <= len(eroot) || !strings.HasPrefix(obj, eroot) {
				show_unmerge("---", unmerge_desc["!prefix"], file_type, obj)
				continue
			}

			statobj, err := os.Stat(obj)
			if err != nil {
				//except OSError:
				//pass
			}
			lstatobj, err := os.Lstat(obj)
			if err != nil {
				//except (OSError, AttributeError):
				//pass
			}
			islink := lstatobj != nil && syscall.S_IFLNK&lstatobj.Mode() != 0
			if lstatobj == nil {
				show_unmerge("---", unmerge_desc["!found"], file_type, obj)
				continue
			}

			f_match := obj[len(eroot)-1:]
			ignore := false
			for _, pattern := range uninstall_ignore {
				if fnmatch.fnmatch(f_match, pattern) {
					ignore = true
					break
				}
			}

			if !ignore {
				if islink && myutil.Ins([]string{"/lib", "/usr/lib", "/usr/local/lib"}, f_match) {
					ignore = true
				}
			}

			if ignore {
				show_unmerge("---", unmerge_desc["cfgpro"], file_type, obj)
				continue
			}

			if strings.HasPrefix(obj, real_root) {
				relative_path := obj[real_root_len:]
				is_owned := false
				for _, dblnk := range others_in_slot {
					if dblnk.isowner(relative_path) {
						is_owned = true
						break
					}
				}

				if is_owned && islink &&
					(file_type == "sym" || file_type == "dir") &&
					statobj != nil && syscall.S_IFDIR&statobj.Mode() != 0 {
					symlink_orphan := false
					for _, dblnk := range others_in_slot {
						parent_contents_key :=
							dblnk._match_contents(relative_path)
						if parent_contents_key == "" {
							continue
						}
						if !strings.HasPrefix(parent_contents_key, real_root) {
							continue
						}
						if dblnk.getcontents()[
							parent_contents_key][0] == "dir" {
							symlink_orphan = true
							break
						}
					}

					if symlink_orphan {
						if _, ok := protected_symlinks[[2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}]; !ok {
							protected_symlinks[[2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}] = []string{}
						}
						protected_symlinks[[2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}] = append(protected_symlinks[[2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}], relative_path)
					}
				}

				if is_owned {
					show_unmerge("---", unmerge_desc["replaced"], file_type, obj)
					continue
				} else if myutil.Inmsss(cfgfiledict, relative_path) {
					stale_confmem = append(stale_confmem, relative_path)
				}
			}

			if unmerge_orphans &&
				lstatobj != nil && syscall.S_IFDIR&lstatobj.Mode() == 0 &&
				!(islink && statobj != nil && syscall.S_IFDIR&statobj.Mode() != 0) &&
				!d.isprotected(obj) {
				//try:
				unlink(obj, lstatobj)
				//except EnvironmentError as e:
				//if err not in ignored_unlink_errnos:
				//raise
				//del e
				show_unmerge("<<<", "", file_type, obj)
				continue
			}

			lmtime := fmt.Sprint(lstatobj.ModTime().Nanosecond())
			if !myutil.Ins([]string{"dir", "fif", "dev"}, pkgfiles[objkey][0]) && lmtime != pkgfiles[objkey][1] {
				show_unmerge("---", unmerge_desc["!mtime"], file_type, obj)
				continue
			}

			if file_type == "dir" && !islink {
				if lstatobj == nil || syscall.S_IFDIR&lstatobj.Mode() == 0 {
					show_unmerge("---", unmerge_desc["!dir"], file_type, obj)
					continue
				}
				mydirs[struct {
					s string;
					i [2]uint64
				}{obj, [2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}}] = true
			} else if file_type == "sym" || (file_type == "dir" && islink) {
				if !islink {
					show_unmerge("---", unmerge_desc["!sym"], file_type, obj)
					continue
				}

				if islink && statobj != nil && syscall.S_IFDIR&statobj.Mode() != 0 && strings.HasPrefix(obj, real_root) {

					relative_path := obj[real_root_len:]
					target_dir_contents, err := myutil.ListDir(obj)
					if err != nil {
						//except OSError:
						//pass
					} else {
						if len(target_dir_contents) > 0 {
							all_owned := true
							for _, child := range target_dir_contents {
								child := filepath.Join(relative_path, child)
								if !d.isowner(child) {
									all_owned = false
									break
								}
								child_lstat, err := os.Lstat(filepath.Join(
									real_root, strings.TrimLeft(child, string(os.PathSeparator))))
								if err != nil {
									//except OSError:
									continue
								}

								if syscall.S_IFREG&child_lstat.Mode() == 0 {
									all_owned = false
									break
								}
							}

							if !all_owned {
								if _, ok := protected_symlinks[[2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}]; !ok {
									protected_symlinks[[2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}] = []string{}
								}
								protected_symlinks[[2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}] = append(protected_symlinks[[2]uint64{statobj.Sys().(*syscall.Stat_t).Dev, statobj.Sys().(*syscall.Stat_t).Ino}], relative_path)
								continue
							}
						}
					}
				}

				//try:
				unlink(obj, lstatobj)
				show_unmerge("<<<", "", file_type, obj)
				//except (OSError, IOError) as e:
				//if err not in ignored_unlink_errnos:
				//raise
				//del e
				//show_unmerge("!!!", "", file_type, obj)
			} else if pkgfiles[objkey][0] == "obj" {
				if statobj == nil || syscall.S_IFREG&statobj.Mode() == 0 {
					show_unmerge("---", unmerge_desc["!obj"], file_type, obj)
					continue
				}
				//try:
				mymd5 := string(perf_md5(obj, calc_prelink))
				//except FileNotFound as e:
				//show_unmerge("---", unmerge_desc["!obj"], file_type, obj)
				//continue

				if mymd5 != strings.ToLower(pkgfiles[objkey][2]) {
					show_unmerge("---", unmerge_desc["!md5"], file_type, obj)
					continue
				}
				//try:
				unlink(obj, lstatobj)
				//except (OSError, IOError) as e:
				//if err not in ignored_unlink_errnos:
				//raise
				//del e
				show_unmerge("<<<", "", file_type, obj)
			} else if pkgfiles[objkey][0] == "fif" {
				if syscall.S_IFIFO&lstatobj.Mode() == 0 {
					show_unmerge("---", unmerge_desc["!fif"], file_type, obj)
					continue
				}
				show_unmerge("---", "", file_type, obj)
			} else if pkgfiles[objkey][0] == "dev" {
				show_unmerge("---", "", file_type, obj)
			}
		}

		d._unmerge_dirs(mydirs, infodirs_inodes,
			protected_symlinks, unmerge_desc, unlink, os)
		mydirs = map[struct {
			s string;
			i [2]uint64
		}]bool{}
	}

	if len(protected_symlinks) > 0 {
		d._unmerge_protected_symlinks(others_in_slot, infodirs_inodes,
			protected_symlinks, unmerge_desc, unlink, os)
	}

	if len(protected_symlinks) > 0 {
		msg := "One or more symlinks to directories have been " +
			"preserved in order to ensure that files installed " +
			"via these symlinks remain accessible. " +
			"This indicates that the mentioned symlink(s) may " +
			"be obsolete remnants of an old install, and it " +
			"may be appropriate to replace a given symlink " +
			"with the directory that it points to."
		lines := myutil.SplitSubN(msg, 72)
		lines = append(lines, "")
		flat_list := map[string]bool{}
		for _, v := range protected_symlinks {
			for _, v2 := range v {
				flat_list[v2] = true
			}
		}
		for _, f := range myutil.sortedmsb(flat_list) {
			lines = append(lines, fmt.Sprintf("\t%s", filepath.Join(real_root,
				strings.TrimLeft(f, string(os.PathSeparator)))))
		}
		lines = append(lines, "")
		d._elog("elog", "postrm", lines)
	}

	if len(stale_confmem) > 0 {
		for _, filename := range stale_confmem {
			delete(cfgfiledict, filename)
		}
		writedict(cfgfiledict, d.vartree.dbapi._conf_mem_file)
	}

	d.vartree.zap(d.mycpv.string)
}

func (d *dblink) _unmerge_protected_symlinks(others_in_slot []*dblink, infodirs_inodes  map[[2]uint64]bool,
	protected_symlinks map[[2]uint64][]string, unmerge_desc map[string]string, unlink func(string, os.FileInfo)) {

	real_root := d.settings.ValueDict["ROOT"]
	show_unmerge := d._show_unmerge
	//ignored_unlink_errnos := d._ignored_unlink_errnos

	flm := map[string]bool{}
	for _, v := range protected_symlinks {
		for _, k := range v {
			flm[k] = true
		}
	}
	flat_list := []string{}
	for k := range flm {
		flat_list = append(flat_list, k)
	}
	sort.Strings(flat_list)

	for _, f := range flat_list {
		for _, dblnk := range others_in_slot {
			if dblnk.isowner(f) {
				return
			}
		}
	}

	msg := []string{}
	msg = append(msg, "")
	msg = append(msg, ("Directory symlink(s) may need protection:"))
	msg = append(msg, "")

	for _, f := range flat_list {
		msg = append(msg, fmt.Sprintf("\t%s",
			filepath.Join(real_root, strings.TrimLeft(f, string(os.PathSeparator)))))
	}

	msg = append(msg, "")
	msg = append(msg, "Use the UNINSTALL_IGNORE variable to exempt specific symlinks")
	msg = append(msg, "from the following search (see the make.conf man page).")
	msg = append(msg, "")
	msg = append(msg, ("Searching all installed" +
		" packages for files installed via above symlink(s)..."))
	msg = append(msg, "")
	d._elog("elog", "postrm", msg)

	d.lockdb()
	//try:
	owners := d.vartree.dbapi._owners.get_owners(flat_list)
	d.vartree.dbapi.flush_cache()
	//finally:
	d.unlockdb()

	for owner := range owners {
		if owner.mycpv.string == d.mycpv.string {
			delete(owners, owner)
		}
	}

	if len(owners) == 0 {
		msg := []string{}
		msg = append(msg, ("The above directory symlink(s) are all " +
			"safe to remove. Removing them now..."))
		msg = append(msg, "")
		d._elog("elog", "postrm", msg)
		dirs := map[struct {
			s string
			i [2]uint64
		}]bool{}
		for _, unmerge_syms := range protected_symlinks {
			for _, relative_path := range unmerge_syms {
				obj := filepath.Join(real_root,
					strings.TrimLeft(relative_path, string(os.PathSeparator)))
				parent := filepath.Dir(obj)
				for len(parent) > len(d._eroot) {
					lstatobj, err := os.Lstat(parent)
					if err != nil {
						//except OSError:
						break
					} else {
						dirs[struct {
							s string
							i [2]uint64
						}{parent, [2]uint64{lstatobj.Sys().(*syscall.Stat_t).Dev, lstatobj.Sys().(*syscall.Stat_t).Ino}}] = true
						parent = filepath.Dir(parent)
					}
				}
				ls, err := os.Lstat(obj)
				if err != nil {
					//except(OSError, IOError) as e:
					//if err not in ignored_unlink_errnos:
					//raise
					//del e
					//show_unmerge("!!!", "", "sym", obj)
				}
				unlink(obj, ls)
				show_unmerge("<<<", "", "sym", obj)
			}
		}

		protected_symlinks = map[[2]uint64][]string{}
		d._unmerge_dirs(dirs, infodirs_inodes,
			protected_symlinks, unmerge_desc, unlink)
		dirs = map[struct {
			s string
			i [2]uint64
		}]bool{}
	}

}

func (d *dblink) _unmerge_dirs(dirs map[struct{s string; i [2]uint64}]bool, infodirs_inodes map[[2]uint64]bool,
	protected_symlinks  map[[2]uint64][]string, unmerge_desc map[string]string,
	unlink func(string, os.FileInfo)) {

	show_unmerge := d._show_unmerge
	infodir_cleanup := d._infodir_cleanup
	ignored_unlink_errnos := d._ignored_unlink_errnos
	ignored_rmdir_errnos := d._ignored_rmdir_errnos
	real_root := d.settings.ValueDict["ROOT"]

	ds := []struct {
		s string;
		i [2]uint64
	}{}
	for d := range dirs {
		ds = append(ds, d)
	}
	sort.Slice(ds, func(i, j int) bool {
		return ds[i].s < ds[j].s
	})

	revisit := map[string][2]uint64{}

	for len(ds) > 0 {
		dss := ds[len(ds)-1]
		ds = ds[:len(ds)-1]
		obj, inode_key := dss.s, dss.i
		if infodirs_inodes[inode_key] || filepath.Base(obj) == "info" {
			remaining, err := myutil.ListDir(obj)
			if err != nil {
				//except OSError:
				//pass
			} else {
				cleanup_info_dir := map[string]bool{}
				if len(remaining) > 0 && len(remaining) <= len(infodir_cleanup) {
					in := true
					for _, k := range remaining {
						if !infodir_cleanup[k] {
							in = false
							break
						}
					}
					if in {
						cleanup_info_dir = map[string]bool{}
						for _, k := range remaining {
							cleanup_info_dir[k] = true
						}
					}
				}

				for child := range cleanup_info_dir {
					child = filepath.Join(obj, child)
					lstatobj, err := os.Lstat(child)
					if syscall.S_IFREG&lstatobj.Mode() != 0 {
						unlink(child, lstatobj)
						show_unmerge("<<<", "", "obj", child)
					}
					if err != nil {
						//except EnvironmentError as e:
						in := false
						for _, e := range ignored_unlink_errnos {
							if e == err {
								in = true
								break
							}
						}
						if !in {
							//raise
						}
						//del e
						show_unmerge("!!!", "", "obj", child)
					}
				}
			}

			parent_name := filepath.Dir(obj)
			parent_stat, err := os.Stat(parent_name)

			//if bsd_chflags {
			//	lstatobj = os.Lstat(obj)
			//	if lstatobj.st_flags != 0 {
			//		bsd_chflags.lchflags(obj, 0)
			//	}
			//
			//	pflags = parent_stat.st_flags
			//	if pflags != 0 {
			//		bsd_chflags.chflags(parent_name, 0)
			//	}
			//}
			//try:
			os.RemoveAll(obj)
			//finally:
			//	if bsd_chflags && pflags != 0 {
			//		bsd_chflags.chflags(parent_name, pflags)
			//	}

			if err == nil {
				fes, err := filepath.EvalSymlinks(parent_name)
				if err == nil {
					d._merged_path(fes, parent_stat, true)
				}
			}

			show_unmerge("<<<", "", "dir", obj)
			if err != nil {
				//except EnvironmentError as e:
				in := false
				for _, e := range ignored_rmdir_errnos {
					if e == err {
						in = true
						break
					}
				}
				if !in {
					//raise
				}
				if err != syscall.ENOENT {
					show_unmerge("---", unmerge_desc["!empty"], "dir", obj)
					revisit[obj] = inode_key
				}
				dir_stat, err := os.Stat(obj)
				if err != nil {
					//except OSError:
					//pass
				} else {
					if _, ok := d._device_path_map[dir_stat.Sys().(*syscall.Stat_t).Dev]; ok{
						fes, _ := filepath.EvalSymlinks(obj)
						d._merged_path(fes, dir_stat, true)
					}
				}
			} else {
				unmerge_syms := protected_symlinks[inode_key]
				delete(protected_symlinks, inode_key)
				if unmerge_syms != nil {
					parents := []string{}
					for _, relative_path := range unmerge_syms {
						obj = filepath.Join(real_root,
							strings.TrimLeft(relative_path, string(os.PathSeparator)))
						lst, err := os.Lstat(obj)
						if err == nil {
							unlink(obj, lst)
							show_unmerge("<<<", "", "sym", obj)
						}
						if err != nil {
							//except(OSError, IOError) as e:
							in := false
							for _, e := range ignored_unlink_errnos {
								if e == err {
									in = true
									break
								}
							}
							if !in {
								//raise
							}
							//del e
							show_unmerge("!!!", "", "sym", obj)
						} else {
							parents = append(parents, filepath.Dir(obj))
						}
					}

					if len(parents) > 0 {
						recursive_parents := []string{}
						pnt := map[string]bool{}
						for _, p := range parents {
							pnt[p] = true
						}
						for parent := range pnt {
							for {
								if _, ok := revisit[parent]; !ok {
									break
								}
								recursive_parents = append(recursive_parents, parent)
								parent = filepath.Dir(parent)
								if parent == "/" {
									break
								}
							}
						}

						rpa := map[string]bool{}
						for _, p := range recursive_parents {
							rpa[p] = true
						}
						for _, parent := range myutil.sortedmsb(rpa) {
							ds = append(ds, struct {
								s string;
								i [2]uint64
							}{parent, revisit[parent]})
							delete(revisit, parent)
						}
					}
				}
			}
		}
	}
}

func (d *dblink) isowner(filename string) bool {
	return d._match_contents(filename) != ""
}

func (d *dblink) _match_contents(filename string) string {
	destroot := d.settings.ValueDict["ROOT"]

	destfile := msg.NormalizePath(
		filepath.Join(destroot,
			strings.TrimLeft(filename, string(os.PathSeparator))))

	if d.settings.Features.Features["case-insensitive-fs"] {
		destfile = strings.ToLower(destfile)
	}

	if d._contents.contains(destfile) {
		return d._contents.unmap_key(destfile)
	}

	if len(d.getcontents())>0 {
		basename := filepath.Base(destfile)
		if d._contents_basenames == nil {
			for _, x:= range d._contents.keys(){
				d._contents_basenames[filepath.Base(x)] =true
			}
		}
		if d._contents_basenames[basename] {
			return ""
		}

		parent_path := filepath.Dir(destfile)
		parent_stat, err := os.Stat(parent_path)
		if err != nil {
			//except EnvironmentError as e:
			if err != syscall.ENOENT{
				//raise
			}
			//del e
			return ""
		}
		if d._contents_inodes == nil {
			d._contents_inodes = map[[2]uint64][]string{}
			parent_paths := map[string]bool{}
			for _, x := range d._contents.keys(){
				p_path := filepath.Dir(x)
				if parent_paths[p_path] {
					continue
				}
				parent_paths[p_path] = true
				s, err := os.Stat(p_path)
				if err != nil {
					//except OSError:
					//pass
				} else{
					inode_key := [2]uint64{s.Sys().(*syscall.Stat_t).Dev, s.Sys().(*syscall.Stat_t).Ino}
					p_path_list := d._contents_inodes[inode_key]
					if p_path_list == nil{
						p_path_list = []string{}
						d._contents_inodes[inode_key] = p_path_list
					}
					if !myutil.Ins(p_path_list,p_path) {
						p_path_list=append(p_path_list,p_path)
					}
				}
			}
		}


		p_path_list := d._contents_inodes[[2]uint64{parent_stat.Sys().(*syscall.Stat_t).Dev, parent_stat.Sys().(*syscall.Stat_t).Ino}]
		if len(p_path_list) > 0 {
			for _, p_path := range p_path_list {
				x := filepath.Join(p_path, basename)
				if d._contents.contains(x) {
					return d._contents.unmap_key(x)
				}
			}
		}
	}

	return ""
}

func (d *dblink) _linkmap_rebuild(exclude_pkgs []*versions.PkgStr,include_file string, preserve_paths map[string]bool) {
	if d._linkmap_broken ||
		d.vartree.dbapi._linkmap == nil ||
		d.vartree.dbapi._plib_registry == nil ||
		( ! d.settings.Features.Features["preserve-libs"] &&
			! d.vartree.dbapi._plib_registry.hasEntries()) {
		return
	}
	//try:
	d.vartree.dbapi._linkmap.rebuild(exclude_pkgs,include_file,preserve_paths)
	//except CommandNotFound as e:
	//d._linkmap_broken = true
	//d._display_merge(_("!!! Disabling preserve-libs "
	//"due to error: Command Not Found: %s\n") % (e,),
	//	level=logging.ERROR, noiselevel=-1)
}

// false
func (d *dblink) _find_libs_to_preserve(unmerge bool) map[string]bool{

	if d._linkmap_broken ||
		d.vartree.dbapi._linkmap == nil ||
		d.vartree.dbapi._plib_registry == nil ||
		(! unmerge && d._installed_instance == nil) ||
		! d._preserve_libs {
		return map[string]bool{}
	}

	//os = _os_merge
	linkmap := d.vartree.dbapi._linkmap
	var installed_instance *dblink
	if unmerge {
		installed_instance = d
	}else {
		installed_instance = d._installed_instance
	}
	old_contents := installed_instance.getcontents()
	root := d.settings.ValueDict["ROOT"]
	root_len := len(root) - 1
	lib_graph := util.NewDigraph()
	path_node_map := map[string]*util._obj_properties_class{}

	path_to_node:= func(path string) {
		node := path_node_map[path]
		if node == nil {
			node = util.New_LibGraphNode(linkmap._obj_key(path))
			alt_path_node := lib_graph.get(node)
			if alt_path_node != nil {
				node = alt_path_node
			}
			node.alt_paths[path] = true
			path_node_map[path] = node
		}
		return node
	}

	consumer_map := {}
	provider_nodes := map[string]bool{}
	for f_abs := range old_contents{

		f := f_abs[root_len:]
	try:
		consumers := linkmap.findConsumers(f, []func(string)bool{installed_instance.isowner},true)
		except KeyError:
		continue
		if not consumers {
			continue
		}
		provider_node = path_to_node(f)
		lib_graph.add(provider_node, nil)
		provider_nodes.add(provider_node)
		consumer_map[provider_node] = consumers
	}

	for provider_node, consumers in consumer_map.items(){
		for c in consumers{
			consumer_node = path_to_node(c)
			if installed_instance.isowner(c) &&
			consumer_node not in provider_nodes{
			continue
		}
			lib_graph.add(provider_node, consumer_node)
		}
	}

	preserve_nodes := map[string]bool{}
	for consumer_node in lib_graph.root_nodes()
	{
		if consumer_node := range provider_nodes{
		continue
	}
		node_stack = lib_graph.child_nodes(consumer_node)
		for len(node_stack) > 0 {
			provider_node = node_stack.pop()
			if provider_node in preserve_nodes{
				continue
			}
			preserve_nodes.add(provider_node)
			node_stack = append(, lib_graph.child_nodes(provider_node))
		}
	}

	preserve_paths := map[string]bool{}
	for preserve_node := range preserve_nodes {
		hardlinks := map[string]bool{}
		soname_symlinks := map[string]bool{}
		soname := linkmap.getSoname(next(iter(preserve_node.alt_paths)))
		have_replacement_soname_link := false
		have_replacement_hardlink := false
		for f in preserve_node.alt_paths{
			f_abs := filepath.Join(root, f.lstrip(string(os.PathSeparator)))
			try:
			if syscall.S_IFREG&os.Lstat(f_abs).Mode()!= 0{
			hardlinks.add(f)
			if not unmerge && d.isowner(f){
			have_replacement_hardlink = true
			if filepath.Base(f) == soname{
			have_replacement_soname_link = true
		}
		}
		} else if filepath.Base(f) == soname{
			soname_symlinks.add(f)
			if not unmerge && d.isowner(f):
			have_replacement_soname_link = true
		}
			except OSError:
			pass
		}

		if have_replacement_hardlink && have_replacement_soname_link {
			continue
		}

		if hardlinks {
			preserve_paths.update(hardlinks)
			preserve_paths.update(soname_symlinks)
		}
	}

	return preserve_paths

}

func (d *dblink) _add_preserve_libs_to_contents(preserve_paths) {

	if not preserve_paths {
		return
	}

	os = _os_merge
	showMessage := d._display_merge
	root := d.settings.ValueDict["ROOT"]

	new_contents := myutil.CopyMapSSS(d.getcontents())
	old_contents := d._installed_instance.getcontents()
	for f
		in
	myutil.sorted(preserve_paths)
	{
		f_abs := filepath.Join(root, strings.TrimLeft(f, string(os.PathSeparator)))
		contents_entry := old_contents[f_abs]
		if contents_entry == nil {
			showMessage(fmt.Sprintf("!!! File '%s' will not be preserved "+
				"due to missing contents entry\n", f_abs, ), 40, -1)
			preserve_paths.remove(f)
			continue
		}
		new_contents[f_abs] = contents_entry
		obj_type := contents_entry[0]
		showMessage(fmt.Sprintf(">>> needed    %s %s\n", obj_type, f_abs),
			-1, 0)
		parent_dir := filepath.Dir(f_abs)
		for len(parent_dir) > len(root) {
			new_contents[parent_dir] = []string{"dir"}
			prev := parent_dir
			parent_dir := filepath.Dir(parent_dir)
			if prev == parent_dir {
				break
			}
		}
	}
	outfile := util.NewAtomic_ofstream(filepath.Join(d.dbtmpdir, "CONTENTS"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	write_contents(new_contents, root, outfile)
	outfile.Close()
	d._clear_contents_cache()

}

func (d *dblink) _find_unused_preserved_libs(unmerge_no_replacement bool) map[string]map[string]bool {

	if d._linkmap_broken || d.vartree.dbapi._linkmap == nil || d.vartree.dbapi._plib_registry == nil || ! d.vartree.dbapi._plib_registry.hasEntries() {
		return map[string]map[string]bool{}
	}

	plib_dict := d.vartree.dbapi._plib_registry.getPreservedLibs()
	linkmap := d.vartree.dbapi._linkmap
	lib_graph := util.NewDigraph()
	preserved_nodes := map[string]bool{}
	preserved_paths := map[string]bool{}
	path_cpv_map := {}
	path_node_map := {}
	root := d.settings.ValueDict["ROOT"]

	path_to_node:= func(path string) {
		node := path_node_map[path]
		if node == nil {
			node = util.New_LibGraphNode(linkmap._obj_key(path))
			alt_path_node := lib_graph.get(node)
			if alt_path_node != nil {
				node = alt_path_node
			}
			node.alt_paths.add(path)
			path_node_map[path] = node
		}
		return node
	}

	for cpv, plibs := range plib_dict{
		for _, f:= range plibs{
			path_cpv_map[f] = cpv
			preserved_node := path_to_node(f)
			if not preserved_node.file_exists() {
				continue
			}
			lib_graph.add(preserved_node, nil)
			preserved_paths.add(f)
			preserved_nodes.add(preserved_node)
			for c in d.vartree.dbapi._linkmap.findConsumers(f){
				consumer_node = path_to_node(c)
				if not consumer_node.file_exists(){
					continue
				}
				lib_graph.add(preserved_node, consumer_node)
			}
		}
	}

	provider_cache := {}
	for preserved_node in preserved_nodes{
		soname = linkmap.getSoname(preserved_node)
		for consumer_node in lib_graph.parent_nodes(preserved_node){

		if consumer_node in preserved_nodes{
		continue
	}
		if unmerge_no_replacement{
		will_be_unmerged = true
		for path in consumer_node.alt_paths{
		if not d.isowner(path){
		will_be_unmerged = false
		break
	}
	}
		if will_be_unmerged{
		lib_graph.remove_edge(preserved_node, consumer_node)
		continue
	}
	}

		providers = provider_cache.get(consumer_node)
		if providers == nil{
		providers = linkmap.findProviders(consumer_node)
		provider_cache[consumer_node] = providers
	}
		providers = providers.get(soname)
		if providers == nil{
		continue
	}
		for provider in providers{
		if provider in preserved_paths{
		continue
	}
		provider_node = path_to_node(provider)
		if not provider_node.file_exists(){
		continue
	}
		if provider_node in preserved_nodes{
		continue
	}
		lib_graph.remove_edge(preserved_node, consumer_node)
		break
	}
	}
	}

	cpv_lib_map := map[string]map[string]bool{}
	for lib_graph{
		root_nodes = preserved_nodes.intersection(lib_graph.root_nodes())
		if not root_nodes {
			break
		}
		lib_graph.difference_update(root_nodes)
		unlink_list = map[string]bool{}
		for node in root_nodes{
			unlink_list.update(node.alt_paths)
		}
		unlink_list = myutil.sorted(unlink_list)
		for obj in unlink_list{
			versions.cpv = path_cpv_map.get(obj)
			if cpv == nil{
			d._display_merge(fmt.Sprintf("!!! symlink to lib is preserved, "+
			"but not the lib itd:\n!!! '%s'\n", obj, ), 40, -1)
			continue
		}
			removed := cpv_lib_map[cpv]
			if removed == nil{
			removed = map[string]bool{}
			cpv_lib_map[cpv] = removed
		}
			removed.add(obj)
		}
	}
	return cpv_lib_map
}

func (d *dblink) _remove_preserved_libs(cpv_lib_map map[string]map[string]bool) {

	files_to_remove := map[string]bool{}
	for _, files := range cpv_lib_map {
		for k := range files {
			files_to_remove[k] = true
		}
	}
	ftr := []string{}
	for f := range files_to_remove {
		ftr = append(ftr, f)
	}
	sort.Strings(ftr)
	showMessage := d._display_merge
	root := d.settings.ValueDict["ROOT"]

	parent_dirs := map[string]bool{}
	for _, obj := range ftr {
		obj = filepath.Join(root, strings.TrimLeft(obj, string(os.PathSeparator)))
		parent_dirs[filepath.Dir(obj)] = true
		obj_type := ""
		if st, _ := os.Stat(obj); st != nil && st.Mode()&os.ModeSymlink != 0 {
			obj_type = "sym"
		} else {
			obj_type = "obj"
		}
		if err := syscall.Unlink(obj); err != nil {
			//except OSError as e:
			if err != syscall.ENOENT {
				//raise
			}
			//del e
		} else {
			showMessage(fmt.Sprintf("<<< !needed  %s %s\n", obj_type, obj), 0, -1)
		}
	}

	for len(parent_dirs) > 0 {
		x := ""
		for k := range parent_dirs {
			x = k
			break
		}
		delete(parent_dirs, x)
		for {
			if err := os.RemoveAll(x); err != nil {
				//except OSError:
				break
			}
			prev := x
			x = filepath.Dir(x)
			if x == prev {
				break
			}
		}
	}
	d.vartree.dbapi._plib_registry.pruneNonExisting()
}

func (d *dblink) _collision_protect(srcroot string, mypkglist []*dblink, file_list, symlink_list []string) ([]string, map[string]map[[2]string], map[string]bool, []string, map[string]) {
	real_relative_paths := map[string][]string{}

	collision_ignore := []string{}
	ss, _ := shlex.Split(strings.NewReader(d.settings.ValueDict["COLLISION_IGNORE"]), false, true)
	for _, x := range ss {
		if myutil.PathIsDir(filepath.Join(d._eroot, strings.TrimLeft(x, string(os.PathSeparator)))) {
			x = msg.NormalizePath(x)
			x += "/*"
		}
		collision_ignore = append(collision_ignore, x)
	}

	plib_cpv_map := map[string]string{}
	plib_paths := map[string]bool{}
	plib_inodes := map[[2]uint64]map[string]bool{}
	if d.vartree.dbapi._plib_registry == nil {
	} else {
		plib_dict := d.vartree.dbapi._plib_registry.getPreservedLibs()
		plib_cpv_map = map[string]string{}
		for cpv, paths := range plib_dict {
			for _,k := range paths{
				plib_paths[k]=true
			}
			for _, f:= range paths {
				plib_cpv_map[f] = cpv
			}
		}
		plib_inodes = d._lstat_inode_map(plib_paths)
	}

	plib_collisions := map[string]{}

	showMessage := d._display_merge
	stopmerge := false
	collisions := []string{}
	dirs := map[string]bool{}
	dirs_ro := map[string]bool{}
	symlink_collisions := []string{}
	destroot := d.settings.ValueDict["ROOT"]
	totfiles := len(file_list) + len(symlink_list)
	previous := time.Now()
	progress_shown := false
	report_interval := 1.7
	falign := len(fmt.Sprintf("%d", totfiles))
	showMessage(fmt.Sprintf(" %s checking %d files for package collisions\n", output.colorize("GOOD", "*"), totfiles), 0, 0)
	ec := [][2]string{}
	for _, f := range file_list {
		ec = append(ec, [2]string{f, "reg"})
	}
	for _, f := range symlink_list {
		ec = append(ec, [2]string{f, "sym"})
	}
	for i, v := range ec {
		f, f_type := v[0], v[1]
		current := time.Now()
		if current.Sub(previous).Seconds() > report_interval {
			showMessage(fmt.Sprintf("%3d%% done,  %*d files remaining ...\n",
				i*100/totfiles, falign, totfiles-i), 0, 0)
			previous = current
			progress_shown = true
		}

		dest_path := msg.NormalizePath(filepath.Join(destroot, strings.TrimLeft(f, string(os.PathSeparator))))
		es, _ := filepath.EvalSymlinks(filepath.Dir(dest_path))
		real_relative_path := filepath.Join(es,
			filepath.Base(dest_path))[len(destroot):]

		if _, ok := real_relative_paths[real_relative_path]; !ok {
			real_relative_paths[real_relative_path] = []string{}
		}
		real_relative_paths[real_relative_path] = append(real_relative_paths[real_relative_path], strings.TrimLeft(string(os.PathSeparator)))

		parent := filepath.Dir(dest_path)
		if !dirs[parent] {
			for _, x := range atom.iterParents(parent) {
				if dirs[x] {
					break
				}
				dirs[x] = true
				if myutil.PathIsDir(x) {
					if st, _ := os.Stat(x); st != nil && st.Mode()&0222 == 0 {
						dirs_ro[x] = true
					}
					break
				}
			}
		}

		dest_lstat, err := os.Lstat(dest_path)
		if err != nil {
			//except EnvironmentError as e:
			if err == syscall.ENOENT {
				//del e
				continue
			} else if err == syscall.ENOTDIR {
				//del e
				dest_lstat = nil
				parent_path := dest_path
				for len(parent_path) > len(destroot) {
					parent_path = filepath.Dir(parent_path)
					dest_lstat, err = os.Lstat(parent_path)
					if err != nil {
						//except EnvironmentError as e:
						if err != syscall.ENOTDIR {
							//raise
						}
						//del e
					}
					break
				}
				if dest_lstat == nil {
					//raise AssertionError(
					//	"unable to find non-directory " +
					//"parent for '%s'" % dest_path)
				}
				dest_path := parent_path
				f = string(os.PathSeparator) + dest_path[len(destroot):]
				if myutil.Ins(collisions, f) {
					continue
				}
			} else {
				//raise
			}
		}
		if !strings.HasPrefix(f, "/") {
			f = "/" + f
		}

		if dest_lstat.IsDir() {
			if f_type == "sym" {
				symlink_collisions = append(symlink_collisions, f)
				collisions = append(collisions, f)
				continue
			}
		}

		plibs := plib_inodes[[2]uint64{dest_lstat.Sys().(*syscall.Stat_t).Dev, dest_lstat.Sys().(*syscall.Stat_t).Ino}]
		if len(plibs) > 0 {
			for path := range plibs {
				cpv := plib_cpv_map[path]
				paths := plib_collisions[cpv]
				if paths == nil {
					paths = map[string]bool{}
					plib_collisions[cpv] = paths
				}
				paths[path] = true
			}
			continue
		}

		isowned := false
		full_path := filepath.Join(destroot, strings.TrimLeft(f, string(os.PathSeparator)))
		for _, ver:= range mypkglist {
			if ver.isowner(f) {
				isowned = true
				break
			}
		}
		if !isowned && d.isprotected(full_path) {
			isowned = true
		}
		if !isowned {
			f_match := full_path[len(d._eroot)-1:]
			stopmerge = true
			for _, pattern := range collision_ignore {
				if fnmatch.fnmatch(f_match, pattern) {
					stopmerge = false
					break
				}
			}
			if stopmerge {
				collisions = append(collisions, f)
			}
		}
	}

	internal_collisions := map[string]map[[2]string]{}
	for real_relative_path, files := range real_relative_paths {
		if len(files) >= 2 {
			sort.Strings(files)
			for i := 0; i < len(files)-1; i++ {
				file1 := msg.NormalizePath(filepath.Join(srcroot, files[i]))
				file2 := msg.NormalizePath(filepath.Join(srcroot, files[i+1]))
				differences := compare_files(file1, file2, skipped_types = ("atime", "mtime", "ctime"))
				if differences {
					if _, ok := internal_collisions[real_relative_path]; !ok {
						internal_collisions[real_relative_path] = map[[2]string]{}
					}
					internal_collisions[real_relative_path][[2]string{files[i], files[i+1]}] = differences
				}
			}
		}
	}

	if progress_shown {
		showMessage("100% done\n", 0, 0)
	}
	return collisions, internal_collisions, dirs_ro, symlink_collisions, plib_collisions
}

func (d *dblink) _lstat_inode_map(path_iter map[string]bool)map[[2]uint64]map[string]bool {
	root := d.settings.ValueDict["ROOT"]
	inode_map := map[[2]uint64]map[string]bool{}
	for f := range path_iter{
		path := filepath.Join(root, strings.TrimLeft(f, string(os.PathSeparator)))
		st, err := os.Lstat(path)
		if err != nil {
			//except OSError as e:
			if err != syscall.ENOENT &&err != syscall.ENOTDIR){
				//raise
			}
			//del e
			continue
		}
		key := [2]uint64{st.Sys().(*syscall.Stat_t).Dev, st.Sys().(*syscall.Stat_t).Ino}
		paths := inode_map[key]
		if paths == nil {
			paths = map[string]bool{}
			inode_map[key] = paths
		}
		paths[f] = true
	}
	return inode_map
}

func (d *dblink) _security_check(installed_instances []*dblink) int {
	if len(installed_instances) == 0 {
		return 0
	}
	showMessage := d._display_merge
	file_paths := map[string]bool{}
	for _, dblnk := range installed_instances {
		for k := range dblnk.getcontents() {
			file_paths[k] = true
		}
	}
	inode_map := map[[2]uint64][]struct {
		s  string
		s2 os.FileInfo
	}{}
	real_paths := map[string]bool{}
	i := 0
	for path := range file_paths {
		i++
		s, err := os.Lstat(path)
		if err != nil {
			//except OSError as e:
			if err != syscall.ENOENT && err != syscall.ENOTDIR {
				//raise
			}
			//del e
			continue
		}
		if s.Mode()&os.ModeIrregular != 0 {
			continue
		}
		path, _ = filepath.EvalSymlinks(path)
		if real_paths[path] {
			continue
		}
		real_paths[path] = true
		if s.Sys().(*syscall.Stat_t).Nlink > 1 &&
			s.Mode()&(unix.S_ISUID|unix.S_ISGID) != 0 {
			k := [2]uint64{s.Sys().(*syscall.Stat_t).Dev, s.Sys().(*syscall.Stat_t).Ino}
			if _, ok := inode_map[k]; !ok {
				inode_map[k] = []struct {
					s  string
					s2 os.FileInfo
				}{}
			}
			inode_map[k] = append(inode_map[k], struct {
				s  string
				s2 os.FileInfo
			}{path, s})
		}
	}

	suspicious_hardlinks := [][]struct {
		s  string;
		s2 os.FileInfo
	}{}
	for _, path_list := range inode_map {
		s := path_list[0].s2
		if len(path_list) == int(s.Sys().(*syscall.Stat_t).Nlink) {
			continue
		}
		suspicious_hardlinks = append(suspicious_hardlinks, path_list)
	}
	if len(suspicious_hardlinks) == 0 {
		return 0
	}

	msg := []string{}
	msg = append(msg, "suid/sgid file(s) with suspicious hardlink(s):")
	msg = append(msg, "")
	for _, path_list := range suspicious_hardlinks {
		for _, v := range path_list {
			path := v.s
			msg = append(msg, fmt.Sprintf("\t%s", path))
		}
	}
	msg = append(msg, "")
	msg = append(msg, "See the Gentoo Security Handbook "+
		"guide for advice on how to proceed.")

	d._eerror("preinst", msg)

	return 1
}

func (d *dblink) _eqawarn(phase string, lines []string) {
	d._elog("eqawarn", phase, lines)
}

func (d *dblink) _eerror(phase string, lines []string) {
	d._elog("eerror", phase, lines)
}

func (d *dblink) _elog(funcname string, phase string, lines []string) {
	var fun func(msg string, phase string, key string, out io.Writer)
	switch funcname {
	case "elog":
		fun = elog.elog
	case "error":
		fun = elog.eerror
	case "eqawarn":
		fun = elog.eqawarn
	}

	if d._scheduler == nil {
		for _, l := range lines {
			fun(l, phase, d.mycpv.string, nil)
		}
	} else {
		background := d.settings.ValueDict["PORTAGE_BACKGROUND"] == "1"
		log_path := ""
		if d.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
			log_path = d.settings.ValueDict["PORTAGE_LOG_FILE"]
		}
		out := &bytes.Buffer{}
		for _, line := range lines {
			fun(line, phase, d.mycpv.string, out)
		}
		msg := out.String()
		d._scheduler.output(msg, log_path, background, 0, -1)
	}
}

// nil
func (d *dblink) _elog_process(phasefilter []string) {
	cpv := d.mycpv
	if d._pipe == 0 {
		elog.elog_process(cpv.string, d.settings, phasefilter)
	}else {
		logdir := filepath.Join(d.settings.ValueDict["T"], "logging")
		ebuild_logentries := elog.collect_ebuild_messages(logdir)
		py_logentries := elog.collect_messages(cpv.string, phasefilter)[cpv.string]
		if py_logentries == nil {
			py_logentries = map[string][]struct{s string; ss []string}{}
		}
		logentries := elog._merge_logentries(py_logentries, ebuild_logentries)
		funcnames := map[string]string{
			"INFO":  "einfo",
			"LOG":   "elog",
			"WARN":  "ewarn",
			"QA":    "eqawarn",
			"ERROR": "eerror",
		}
		str_buffer := []string{}
		for phase, messages := range logentries{
			for _,v := range messages{
				key, lines := v.s ,v.ss
				funcname := funcnames[key]
				for _, line := range lines {
					for _, line:= range strings.Split(line,"\n") {
						fields := []string{funcname, phase, cpv.string, line}
						str_buffer = append(str_buffer, strings.Join(fields, " "))
						str_buffer = append(str_buffer, "\n")
					}
				}
			}
		}
		if len(str_buffer) >0 {
			sb := strings.Join(str_buffer, "")
			for sb!= ""{
				n, _ := syscall.Write(d._pipe, []byte(sb))
				sb = sb[n:]
			}
		}
	}
}

func (d *dblink) _emerge_log(msg string) { atom.emergelog(false, msg, "")}

// 0, nil, nil, 0
func (d *dblink) treewalk(srcroot, inforoot, myebuild string, cleanup bool, mydbapi IDbApi, prev_mtimes=nil, counter int) int {
	destroot := d.settings.ValueDict["ROOT"]

	showMessage := d._display_merge
	srcroot = strings.TrimRight(msg.NormalizePath(srcroot), string(os.PathSeparator)) + string(os.PathSeparator)

	if !myutil.PathIsDir(srcroot) {
		showMessage(fmt.Sprintf("!!! Directory Not Found: D='%s'\n", srcroot), 40, -1)
		return 1
	}

	atom.doebuild_environment(myebuild, "instprep", nil, d.settings, false, nil, mydbapi)
	phase := emerge.NewEbuildPhase(nil, false, "instprep",
		d._scheduler, d.settings, nil)
	phase.start()
	if phase.wait() != 0 {
		showMessage("!!! instprep failed\n",
			40, -1)
		return 1
	}

	is_binpkg := d.settings.ValueDict["EMERGE_FROM"] == "binary"
	slot := ""
	for _, var_name := range []string{"CHOST", "SLOT"} {
		f, err := ioutil.ReadFile(filepath.Join(inforoot, var_name))
		val := ""
		if err != nil {
			//except EnvironmentError as e:
			if err != syscall.ENOENT {
				//raise
			}
			//del e
		} else {
			val = strings.TrimSpace(strings.Split(string(f), "\n")[0])
		}

		if var_name == "SLOT" {
			slot = val

			if strings.TrimSpace(slot) == "" {
				slot = d.settings.ValueDict[var_name]
				if strings.TrimSpace(slot) == "" {
					showMessage("!!! SLOT is undefined\n", 40, -1)
					return 1
				}
				util.write_atomic(filepath.Join(inforoot, var_name), slot+"\n", os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
			}
		}

		if !is_binpkg && val != d.settings.ValueDict[var_name] {
			d._eqawarn("preinst", []string{fmt.Sprintf("QA Notice: Expected %s='%s', got '%s'\n", var_name, d.settings.ValueDict[var_name], val)})
		}
	}

	eerror := func(lines []string) {
		d._eerror("preinst", lines)
	}

	if !myutil.pathExists(d.dbcatdir) {
		util.EnsureDirs(d.dbcatdir, -1, -1, -1, -1, nil, true)
	}

	slot = versions.NewPkgStr(d.mycpv.string, nil, nil, "", "", slot, 0, 0, "", 0, nil).slot
	cp := d.mysplit[0]
	slot_atom := fmt.Sprintf("%s:%s", cp, slot)

	d.lockdb()
	//try:
	slot_matches := []*versions.PkgStr{}
	for _, cpv := range d.vartree.dbapi.match(slot_atom, 1) {
		if versions.cpvGetKey(cpv.string, "") == cp {
			slot_matches = append(slot_matches, cpv)
		}
	}

	in := false
	for _, v := range slot_matches {
		if v.string == d.mycpv.string {
			return true
		}
	}
	if !in && d.vartree.dbapi.cpv_exists(d.mycpv.string, "") {
		slot_matches = append(slot_matches, d.mycpv)
	}

	others_in_slot := []*dblink{}
	for _, cur_cpv := range slot_matches {
		settings_clone := ebuild.NewConfig(d.settings, nil, "", nil, "", "", "", "", true, nil, false, nil)
		delete(settings_clone.ValueDict, "PORTAGE_BUILDDIR_LOCKED")
		settings_clone.SetCpv(cur_cpv, d.vartree.dbapi)
		if d._preserve_libs && myutil.Ins(strings.Fields(settings_clone.ValueDict["PORTAGE_RESTRICT"]), "preserve-libs") {
			d._preserve_libs = false
		}
		others_in_slot = append(others_in_slot, NewDblink(d.cat, versions.catsplit(cur_cpv)[1], "",
			settings_clone, "vartree", d.vartree, nil, d._scheduler, d._pipe))
	}
	d.unlockdb()

	if !d._preserve_libs {
		for _, dblnk := range others_in_slot {
			dblnk._preserve_libs = false
		}
	}

	retval := d._security_check(others_in_slot)
	if retval != 0 {
		return retval
	}

	if len(slot_matches) > 0 {
		var max_dblnk *dblink
		max_counter := -1
		for _, dblnk := range others_in_slot {
			cur_counter := d.vartree.dbapi.cpv_counter(dblnk.mycpv)
			if cur_counter > max_counter {
				max_counter = cur_counter
				max_dblnk = dblnk
			}
		}
		d._installed_instance = max_dblnk
	}

	phase2 := emerge.NewMiscFunctionsProcess(false, []string{"preinst_mask"}, "preinst", "", nil, d._scheduler, d.settings)
	phase2.start()
	phase2.wait()
	f, err := ioutil.ReadFile(filepath.Join(inforoot, "INSTALL_MASK"))
	if err != nil {
		//except EnvironmentError:
		//install_mask = nil
	}
	install_mask := util.NewInstallMask(string(f))

	if install_mask != nil {
		util.install_mask_dir(d.settings.ValueDict["ED"], install_mask, nil)
		if d.settings.Features.Features["nodoc"] || d.settings.Features.Features["noman"] || d.settings.Features.Features["noinfo"] {
			if err := os.RemoveAll(filepath.Join(d.settings.ValueDict["ED"], "usr", "share")); err != nil {
				//except OSError:
				//pass
			}
		}
	}

	unicode_errors := []string{}
	line_ending_re := regexp.MustCompile("[\\n\\r]")
	srcroot_len := len(srcroot)
	ed_len := len(d.settings.ValueDict["ED"])

	filelist := []string{}
	linklist := []string{}
	paths_with_newlines := []string{}
	for {
		unicode_error := false
		eagain_error := false

		filelist = []string{}
		linklist = []string{}
		paths_with_newlines = []string{}
		onerror := func(e error) {
			//raise
		}

		filepath.Walk(srcroot, func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {

				relative_path := path[srcroot_len:]

				if line_ending_re.MatchString(relative_path) {
					paths_with_newlines = append(paths_with_newlines, relative_path)
				}

				file_mode := info.Mode()
				if unix.S_IFREG&file_mode != 0 {
					filelist = append(filelist, relative_path)
				} else if unix.S_IFLNK&file_mode != 0 {
					linklist = append(linklist, relative_path)

					myto, _ := filepath.EvalSymlinks(path)
					if line_ending_re.MatchString(myto) {
						paths_with_newlines = append(paths_with_newlines, relative_path)
					}
				}
			}
			return nil
		})
		if !(unicode_error || eagain_error) {
			break
		}
	}

	if len(unicode_errors) > 0 {
		d._elog("eqawarn", "preinst",
			atom._merge_unicode_error(unicode_errors))
	}

	if len(paths_with_newlines) > 0 {
		msg := []string{}
		msg = append(msg, ("This package installs one or more files containing line ending characters:"))
		msg = append(msg, "")
		sort.Strings(paths_with_newlines)
		for _, f := range paths_with_newlines {
			msg = append(msg, fmt.Sprintf("\t/%s", strings.ReplaceAll(strings.ReplaceAll(f, "\n", "\\n"), "\r", "\\r")))
		}
		msg = append(msg, "")
		msg = append(msg, fmt.Sprintf("package %s NOT merged", d.mycpv))
		msg = append(msg, "")
		eerror(msg)
		return 1
	}

	if d.settings.ValueDict["PORTAGE_PACKAGE_EMPTY_ABORT"] == "1" && len(filelist) == 0 && len(linklist) == 0 && len(others_in_slot) > 0 {
		var installed_files map[string][]string
		for _, other_dblink := range others_in_slot {
			installed_files = other_dblink.getcontents()
			if len(installed_files) == 0 {
				continue
			}
			msg := []string{}
			msg = append(msg, myutil.SplitSubN(fmt.Sprintf("The '%s' package will not install "+
				"any files, but the currently installed '%s'"+
				" package has the following files: ", d.mycpv, other_dblink.mycpv), 72)...)
			msg = append(msg, "")
			ifs := []string{}
			for k := range installed_files {
				ifs = append(ifs, k)
			}
			sort.Strings(ifs)
			msg = append(msg, ifs...)
			msg = append(msg, "")
			msg = append(msg, fmt.Sprintf("package %s NOT merged", d.mycpv))
			msg = append(msg, "")
			msg = append(msg, myutil.SplitSubN(
				fmt.Sprintf("Manually run `emerge --unmerge =%s` if you "+
					"really want to remove the above files. Set "+
					"PORTAGE_PACKAGE_EMPTY_ABORT=\"0\" in "+
					"/etc/portage/make.conf if you do not want to "+
					"abort in cases like this.", other_dblink.mycpv), 72)...)
			eerror(msg)
		}
		if len(installed_files) > 0 {
			return 1
		}
	}

	if myebuild == "" {
		myebuild = filepath.Join(inforoot, d.pkg+".ebuild")
		atom.doebuild_environment(myebuild, "preinst", nil, d.settings, false, nil, mydbapi)
		dsvrv := []string{}
		for _, other := range others_in_slot {
			dsvrv = append(dsvrv, versions.cpvGetVersion(other.mycpv.string, ""))
		}
		d.settings.ValueDict["REPLACING_VERSIONS"] = strings.Join(dsvrv, " ")
		atom.prepare_build_dirs(d.settings, cleanup)
	}

	blockers := []*dblink{}
	for _, blocker := range d._blockers {
		blocker := d.vartree.dbapi._dblink(blocker.cpv)
		if blocker.exists() {
			blockers = append(blockers, blocker)
		}
	}

	collisions, internal_collisions, dirs_ro, symlink_collisions, plib_collisions :=
		d._collision_protect(srcroot, append(append([]*dblink{}, others_in_slot...), blockers...), filelist, linklist)

	ro_checker := util.get_ro_checker()
	rofilesystems := ro_checker(dirs_ro)

	if len(rofilesystems) > 0 {
		msg := myutil.SplitSubN("One or more files installed to this package are "+
			"set to be installed to read-only filesystems. "+
			"Please mount the following filesystems as read-write "+
			"and retry.", 70)
		msg = append(msg, "")
		for f := range rofilesystems {
			msg = append(msg, fmt.Sprintf("\t%s", f))
		}
		msg = append(msg, "")
		d._elog("eerror", "preinst", msg)

		msg2 := fmt.Sprintf("Package '%s' NOT merged due to read-only file systems.",
			d.settings.mycpv)
		msg2 += (" If necessary, refer to your elog " +
			"messages for the whole content of the above message.")
		msgs := myutil.SplitSubN(msg2, 70)
		eerror(msgs)
		return 1
	}

	if len(internal_collisions) > 0 {
		msg := fmt.Sprintf("Package '%s' has internal collisions between non-identical files "+
			"(located in separate directories in the installation image (${D}) "+
			"corresponding to merged directories in the target "+
			"filesystem (${ROOT})):", d.settings.mycpv)
		msgs := myutil.SplitSubN(msg, 70)
		msgs = append(msgs, "")
		for k, versions.v
			in
		myutil.sorted(internal_collisions.items(), key = operator.itemgetter(0)){
			msgs = append(msgs, "\t%s"%filepath.Join(destroot, k.lstrip(string(os.PathSeparator))))
			for (file1, file2), differences
			in
			myutil.sorted(versions.v.items())
			{
				msgs = append(msgs, fmt.Sprintf("\t\t%s", filepath.Join(destroot, strings.TrimLeft(file1, string(os.PathSeparator)))))
				msgs = append(msgs, fmt.Sprintf("\t\t%s", filepath.Join(destroot, strings.TrimLeft(file2, string(os.PathSeparator)))))
				msgs = append(msgs, fmt.Sprintf("\t\t\tDifferences: %s", strings.Join(differences, ", ")))
				msgs = append(msgs, "")
			}
		}
		d._elog("eerror", "preinst", msgs)

		msg = fmt.Sprintf("Package '%s' NOT merged due to internal collisions "+
			"between non-identical files.", d.settings.mycpv)
		msg += (" If necessary, refer to your elog messages for the whole " +
			"content of the above message.")
		eerror(myutil.SplitSubN(msg, 70))
		return 1
	}

	if len(symlink_collisions) > 0 {
		msg := fmt.Sprintf("Package '%s' has one or more collisions "+
			"between symlinks and directories, which is explicitly "+
			"forbidden by PMS section 13.4 (see bug #326685):",
			d.settings.mycpv, )
		msgs := myutil.SplitSubN(msg, 70)
		msgs = append(msgs, "")
		for _, f := range symlink_collisions {
			msgs = append(msgs, fmt.Sprintf("\t%s", filepath.Join(destroot,
				strings.TrimLeft(f, string(os.PathSeparator)))))
		}
		msgs = append(msgs, "")
		d._elog("eerror", "preinst", msgs)
	}

	if len(collisions) > 0 {
		collision_protect := d.settings.Features.Features["collision-protect"]
		protect_owned := d.settings.Features.Features["protect-owned"]
		msg := "This package will overwrite one or more files that" +
			" may belong to other packages (see list below)."
		if !(collision_protect || protect_owned) {
			msg += " Add either \"collision-protect\" or" +
				" \"protect-owned\" to FEATURES in" +
				" make.conf if you would like the merge to abort" +
				" in cases like this. See the make.conf man page for" +
				" more information about these features."
		}
		if d.settings.ValueDict["PORTAGE_QUIET"] != "1" {
			msg += " You can use a command such as" +
				" `portageq owners / <filename>` to identify the" +
				" installed package that owns a file. If portageq" +
				" reports that only one package owns a file then do NOT" +
				" file a bug report. A bug report is only useful if it" +
				" identifies at least two or more packages that are known" +
				" to install the same file(s)." +
				" If a collision occurs and you" +
				" can not explain where the file came from then you" +
				" should simply ignore the collision since there is not" +
				" enough information to determine if a real problem" +
				" exists. Please do NOT file a bug report at" +
				" https://bugs.gentoo.org/ unless you report exactly which" +
				" two packages install the same file(s). See" +
				" https://wiki.gentoo.org/wiki/Knowledge_Base:Blockers" +
				" for tips on how to solve the problem. And once again," +
				" please do NOT file a bug report unless you have" +
				" completely understood the above message."
		}

		d.settings.ValueDict["EBUILD_PHASE"] = "preinst"
		msgs := myutil.SplitSubN(msg, 70)
		if collision_protect {
			msgs = append(msgs, "")
			msgs = append(msgs, fmt.Sprintf("package %s NOT merged", d.settings.mycpv))
			msgs = append(msgs, "")
			msgs = append(msgs, "Detected file collision(s):")
			msgs = append(msgs, "")
		}

		for _, f := range collisions {
			msgs = append(msgs, fmt.Sprintf("\t%s",
				filepath.Join(destroot, strings.TrimLeft(f, string(os.PathSeparator)))))
		}

		eerror(msgs)

		var owners map[*dblink]map[string]bool
		if collision_protect || protect_owned || len(symlink_collisions) > 0 {
			msg := []string{}
			msg = append(msg, "")
			msg = append(msg, "Searching all installed"+
				" packages for file collisions...")
			msg = append(msg, "")
			msg = append(msg, "Press Ctrl-C to Stop")
			msg = append(msg, "")
			eerror(msg)

			if len(collisions) > 20 {
				collisions = collisions[:20]
			}

			pkg_info_strs := map[string]string{}
			d.lockdb()
			//try:
			owners = d.vartree.dbapi._owners.get_owners(collisions)
			d.vartree.dbapi.flush_cache()

			for pkg := range owners {
				pkg := d.vartree.dbapi._pkg_str(pkg.mycpv, "")
				pkg_info_str := fmt.Sprintf("%s%s%s", pkg,
					dep.slotSeparator, pkg.slot)
				if pkg.repo != versions.unknownRepo {
					pkg_info_str += fmt.Sprintf("%s%s", dep.repoSeparator,
						pkg.repo)
				}
				pkg_info_strs[pkg.string] = pkg_info_str
			}

			//finally:
			d.unlockdb()

			for pkg, owned_files := range owners {
				msg := []string{}
				msg = append(msg, pkg_info_strs[pkg.mycpv.string])
				of := []string{}
				for k := range owned_files {
					of = append(of, k)
				}
				sort.Strings(of)
				for _, f := range of {
					msg = append(msg, fmt.Sprintf("\t%s", filepath.Join(destroot,
						strings.TrimLeft(f, string(os.PathSeparator)))))
				}
				msg = append(msg, "")
				eerror(msg)
			}

			if len(owners) == 0 {
				eerror([]string{"nil of the installed" +
					" packages claim the file(s).", ""})
			}
		}

		symlink_abort_msg := "Package '%s' NOT merged since it has " +
			"one or more collisions between symlinks and directories, " +
			"which is explicitly forbidden by PMS section 13.4 " +
			"(see bug  #326685)."
		abort := false
		if len(symlink_collisions) > 0 {
			abort = true
			msg = fmt.Sprintf(symlink_abort_msg, d.settings.mycpv, )
		} else if collision_protect {
			abort = true
			msg = fmt.Sprintf("Package '%s' NOT merged due to file collisions.",
				d.settings.mycpv)
		} else if protect_owned && len(owners) > 0 {
			abort = true
			msg = fmt.Sprintf("Package '%s' NOT merged due to file collisions.",
				d.settings.mycpv)
		} else {
			msg = fmt.Sprintf("Package '%s' merged despite file collisions.",
				d.settings.mycpv)
		}
		msg += " If necessary, refer to your elog " +
			"messages for the whole content of the above message."
		eerror(myutil.SplitSubN(msg, 70))

		if abort {
			return 1
		}
	}

	if err := syscall.Unlink(filepath.Join(
		filepath.Dir(msg.NormalizePath(srcroot)), ".installed")); err != nil {
		//except OSError as e:
		if err != syscall.ENOENT {
			//raise
		}
		//del e
	}
	d.dbdir = d.dbtmpdir
	d.delete()
	util.EnsureDirs(d.dbtmpdir, -1, -1, -1, -1, nil, true)

	downgrade := false
	v, _ := versions.verCmp(d.mycpv.version,
		d._installed_instance.mycpv.version)
	if d._installed_instance != nil && v < 0 {
		downgrade = true
	}

	if d._installed_instance != nil {
		rval := d._pre_merge_backup(d._installed_instance, downgrade)
		if rval != 0 {
			showMessage(fmt.Sprintf("!!! FAILED preinst: "+
				"quickpkg: %s\n", rval), 40, -1)
			return rval
		}
	}

	showMessage(fmt.Sprintf(">>> Merging %s to %s\n", d.mycpv, destroot), 0, 0)
	phase3 := emerge.NewEbuildPhase(nil, false, "preinst",
		d._scheduler, d.settings, nil)
	phase3.start()
	a := phase3.wait()

	if a != 0 {
		showMessage(fmt.Sprintf("!!! FAILED preinst: ")+fmt.Sprintf(a)+"\n",
			40, -1)
		return a
	}

	xs, _ := myutil.ListDir(inforoot)
	for _, x := range xs {
		d.copyfile(inforoot + "/" + x)
	}

	if counter == 0 {
		counter = d.vartree.dbapi.counter_tick()
	}
	ioutil.WriteFile(filepath.Join(d.dbtmpdir, "COUNTER"), []byte(fmt.Sprintf("%s", counter)), 0644)

	d.updateprotect()

	d.vartree.dbapi._fs_lock()
	//try:
	plib_registry := d.vartree.dbapi._plib_registry
	if plib_registry != nil {
		plib_registry.lock()
	}
	//try:
	plib_registry.load()
	plib_registry.store()
	//finally:
	plib_registry.unlock()

	cfgfiledict := util.grabDict(d.vartree.dbapi._conf_mem_file, false, false, false, true, false)
	if myutil.Inmss(d.settings.ValueDict, "NOCONFMEM") || downgrade {
		cfgfiledict["IGNORE"] = 1
	} else {
		cfgfiledict["IGNORE"] = 0
	}

	rval := d._merge_contents(srcroot, destroot, cfgfiledict)
	if rval != 0 {
		return rval
	}
	//finally:
	d.vartree.dbapi._fs_unlock()

	for _, dblnk := range others_in_slot {
		dblnk._clear_contents_cache()
	}
	d._clear_contents_cache()

	linkmap := d.vartree.dbapi._linkmap
	plib_registry = d.vartree.dbapi._plib_registry

	preserve_paths := map[string]bool{}
	needed := ""
	if !(d._linkmap_broken || linkmap == nil || plib_registry == nil) {
		d.vartree.dbapi._fs_lock()
		plib_registry.lock()
		//try:
		plib_registry.load()
		needed = filepath.Join(inforoot, linkmap._needed_aux_key)
		d._linkmap_rebuild(nil, needed, nil)

		preserve_paths := d._find_libs_to_preserve(false)
		//finally:
		plib_registry.unlock()
		d.vartree.dbapi._fs_unlock()

		if len(preserve_paths) != 0 {
			d._add_preserve_libs_to_contents(preserve_paths)
		}
	}

	reinstall_self := false
	ppa, _ := dep.NewAtom(_const.PortagePackageAtom, nil, false, nil, nil, "", nil, nil)
	if d.myroot == "/" && len(dep.matchFromList(ppa, []*versions.PkgStr{d.mycpv})) > 0 {
		reinstall_self = true
	}

	emerge_log := d._emerge_log

	autoclean := d.settings.ValueDict["AUTOCLEAN"] == "yes" || d.settings.ValueDict["AUTOCLEAN"] == "" || len(preserve_paths) > 0

	if autoclean {
		emerge_log(fmt.Sprintf(" >>> AUTOCLEAN: %s", slot_atom, ))
	}

	others_in_slot = append(others_in_slot, d)
	for _, dblnk := range others_in_slot {
		if dblnk == d {
			continue
		}
		if !(autoclean || dblnk.mycpv.string == d.mycpv.string || reinstall_self) {
			continue
		}
		showMessage((">>> Safely unmerging already-installed instance...\n"), 0, 0)
		emerge_log(fmt.Sprintf(" === Unmerging... (%s)", dblnk.mycpv, ))
		ois := []*dblink{}
		for _, o := range others_in_slot {
			if o != dblnk {
				ois = append(ois, o)
			}
		}
		others_in_slot = ois
		dblnk._linkmap_broken = d._linkmap_broken
		dblnk.settings.ValueDict["REPLACED_BY_VERSION"] = versions.cpvGetVersion(d.mycpv.string, "")
		dblnk.settings.BackupChanges("REPLACED_BY_VERSION")
		unmerge_rval := dblnk.unmerge(nil, true, prev_mtimes,
			others_in_slot, needed, preserve_paths)
		delete(dblnk.settings.ValueDict, "REPLACED_BY_VERSION")

		if unmerge_rval == 0 {
			emerge_log(fmt.Sprintf(" >>> unmerge success: %s", dblnk.mycpv, ))
		} else {
			emerge_log(fmt.Sprintf(" !!! unmerge FAILURE: %s", dblnk.mycpv, ))
		}

		d.lockdb()
		//try:
		dblnk.delete()
		//finally:
		d.unlockdb()
		showMessage(">>> Original instance of package unmerged safely.\n", 0, 0)
	}

	if len(others_in_slot) > 1 {
		showMessage(output.colorize("WARN", "WARNING:")+
			" AUTOCLEAN is disabled.  This can cause serious"+
			" problems due to overlapping packages.\n", 30, -1)
	}

	d.dbdir = d.dbpkgdir
	d.lockdb()
	//try:
	d.delete()
	util._movefile(d.dbtmpdir, d.dbpkgdir, 0, nil, d.settings, nil)
	ol, _ := os.Lstat(d.dbpkgdir)
	d._merged_path(d.dbpkgdir, ol, true)
	d.vartree.dbapi._cache_delta.recordEvent("add", d.mycpv, slot, counter)
	//finally:
	d.unlockdb()

	d._clear_contents_cache()
	contents := d.getcontents()
	destroot_len := len(destroot) - 1
	d.lockdb()
	//try:
	for _, blocker := range blockers {
		cs := []string{}
		for _, c := range contents {
			cs = append(cs, c)
		}
		d.vartree.dbapi.removeFromContents(blocker, cs, false)
	}
	//finally:
	d.unlockdb()

	plib_registry = d.vartree.dbapi._plib_registry
	if plib_registry != nil {
		d.vartree.dbapi._fs_lock()
		plib_registry.lock()
		defer func() {
			plib_registry.unlock()
			d.vartree.dbapi._fs_unlock()
		}()
		plib_registry.load()

		if len(preserve_paths) > 0 {
			plib_registry.register(d.mycpv.string, slot, fmt.Sprint(counter),
				myutil.sortedmsb(preserve_paths))
		}

		plib_dict := plib_registry.getPreservedLibs()
		for cpv, paths := range plib_collisions {
			if !myutil.Inmsss(plib_dict, cpv) {
				continue
			}
			has_vdb_entry := false
			if cpv != d.mycpv.string {
				d.vartree.dbapi.lock()
				//try:
				//try:
				slot := d.vartree.dbapi._pkg_str(cpv, "").slot
				counter := d.vartree.dbapi.cpv_counter(cpv)
				//except(KeyError, InvalidData):
				//pass
				//else:
				has_vdb_entry = true
				d.vartree.dbapi.removeFromContents(cpv, paths, true)
				//finally:
				d.vartree.dbapi.unlock()
			}

			if !has_vdb_entry {
				has_registry_entry := false
				for plib_cps, v := range plib_registry._data {
					plib_cpv, plib_counter, plib_paths := v.cpv, v.counter, v.paths
					if plib_cpv != cpv {
						continue
					}
					//try:
					cs := strings.SplitN(plib_cps, ":", 2)
					if len(cs) == 1 {
						//except ValueError:
						continue
					}
					cp, slot = cs[0], cs[1]
					counter = plib_counter
					has_registry_entry = true
					break
				}

				if !has_registry_entry {
					continue
				}
			}

			remaining := []string{}
			for _, f := range plib_dict[cpv] {
				if !myutil.Ins(paths, f) {
					remaining = append(remaining, f)
				}
			}
			plib_registry.register(cpv, slot, counter, remaining)
		}

		plib_registry.store()
	}

	d.vartree.dbapi._add(d)
	contents = d.getcontents()

	d.settings.ValueDict["PORTAGE_UPDATE_ENV"] = filepath.Join(d.dbpkgdir, "environment.bz2")
	d.settings.BackupChanges("PORTAGE_UPDATE_ENV")
	//try:
	phase = emerge.NewEbuildPhase(nil, false, "postinst",
		d._scheduler, d.settings, nil)
	phase.start()
	a = phase.wait()
	if a == 0 {
		showMessage(fmt.Sprintf(">>> %s merged.\n", d.mycpv), 0, 0)
	}
	//finally:
	delete(d.settings.ValueDict, "PORTAGE_UPDATE_ENV")

	if a != 0 {
		d._postinst_failure = true
		d._elog("eerror", "postinst", []string{
			fmt.Sprintf("FAILED postinst: %s", a, ),
		})
	}

	util.env_update(1, d.settings.ValueDict["ROOT"], prev_mtimes, contents, d.settings, d._display_merge, d.vartree.dbapi)

	d._prune_plib_registry(false, "", nil)
	d._post_merge_sync()

	return 0
}

func (d *dblink) _new_backup_path(p string) string {
	x := -1
	backup_p := ""
	for {
		x += 1
		backup_p = fmt.Sprintf("%s.backup.%04d", p, x)
		if _, err := os.Lstat(backup_p); err != nil {
			//except OSError:
			break
		}
	}

	return backup_p
}

func (d *dblink) _merge_contents(srcroot, destroot string, cfgfiledict  map[string][]string) int {

	cfgfiledict_orig := myutil.CopyMapSSS(cfgfiledict)
	outfile := util.NewAtomic_ofstream(filepath.Join(d.dbtmpdir, "CONTENTS"), os.O_CREATE|os.O_TRUNC|os.O_RDWR, true)
	mymtime := int64(0)

	prevmask := syscall.Umask(0)
	secondhand := []string{}

	if d.mergeme(srcroot, destroot, outfile, secondhand, nil, strings.TrimLeft(d.settings.ValueDict["EPREFIX"], string(os.PathSeparator)),cfgfiledict, mymtime) != 0 {
		return 1
	}

	lastlen := 0
	for len(secondhand) > 0 && len(secondhand) != lastlen {

		thirdhand := []string{}
		if d.mergeme(srcroot, destroot, outfile, thirdhand,
			secondhand, "", cfgfiledict, mymtime) != 0 {
			return 1
		}

		lastlen = len(secondhand)

		secondhand = thirdhand
	}

	if len(secondhand) > 0 {
		if d.mergeme(srcroot, destroot, outfile, nil, secondhand, "", cfgfiledict, mymtime) != 0 {
			return 1
		}
	}

	syscall.Umask(prevmask)

	outfile.Close()

	if cfgfiledict != cfgfiledict_orig {
		delete(cfgfiledict,"IGNORE")
	try:
		writedict(cfgfiledict, d.vartree.dbapi._conf_mem_file)
		except
	InvalidLocation:
		d.settings.InitDirs()
		writedict(cfgfiledict, d.vartree.dbapi._conf_mem_file)
	}

	return 0
}

func (d *dblink) mergeme(srcroot, destroot string, outfile io.WriteCloser, secondhand, stufftomerge []string, stufftomerge2 string, cfgfiledict map[string][]string, thismtime int64) int {

	showMessage := d._display_merge
	WriteMsg := d._display_merge

	os = _os_merge
	sep := string(os.PathSeparator)
	join := filepath.Join
	srcroot = strings.TrimRight(msg.NormalizePath(srcroot), sep) + sep
	destroot = strings.TrimRight(msg.NormalizePath(destroot), sep) + sep
	calc_prelink := d.settings.Features.Features["prelink-checksums"]

	protect_if_modified := d.settings.Features.Features["config-protect-if-modified"] && d._installed_instance != nil

	mergelist := []string{}
	if stufftomerge2 != "" {
		cs, _ := myutil.ListDir(join(srcroot, stufftomerge2))
		for _, child := range cs {
			mergelist = append(mergelist, join(stufftomerge2, child))
		}
	} else {
		mergelist = stufftomerge[:]
	}

	for len(mergelist) > 0 {
		relative_path := mergelist[len(mergelist)-1]
		mergelist = mergelist[:len(mergelist)-1]
		mysrc := join(srcroot, relative_path)
		mydest := join(destroot, relative_path)
		myrealdest := join(sep, relative_path)
		mystat, _ := os.Lstat(mysrc)
		mymode := mystat.Mode()
		mymd5 := ""
		myto := ""

		mymtime := int64(mystat.ModTime().Nanosecond())

		if mymode&syscall.S_IFREG != 0 {
			mymd5 = string(checksum.performMd5(mysrc, calc_prelink))
		} else if mymode&syscall.S_IFLNK != 0 {
			myto, _ = filepath.EvalSymlinks(mysrc)
			syscall.Unlink(mysrc)
			os.Symlink(myto, mysrc)
			h := md5.New()
			h.Write([]byte(myto))
			mymd5 = hex.EncodeToString(h.Sum(nil))
		}

		protected := false
		if mymode&syscall.S_IFLNK != 0 || mymode&syscall.S_IFREG != 0 {
			protected = d.isprotected(mydest)

			if mymode&syscall.S_IFREG != 0 &&
				mystat.Size() == 0 &&
				strings.HasPrefix(filepath.Base(mydest), ".keep") {
				protected = false
			}
		}

		destmd5 := ""
		mydest_link := ""
		//try:
		mydstat, _ := os.Lstat(mydest)
		mydmode := mydstat.Mode()
		if protected {
			if mymode&syscall.S_IFLNK != 0 {
				mydest_link, _ = filepath.EvalSymlinks(mydest)
				h := md5.New()
				h.Write([]byte(mydest_link))
				destmd5 = hex.EncodeToString(h.Sum(nil))
			} else if syscall.S_IFREG&mydmode != 0 {
				destmd5 = string(checksum.performMd5(mydest, calc_prelink))
			}
		}
		//except (FileNotFound, OSError) as e:
		//if isinstance(e, OSError) && err != syscall.ENOENT:
		//raise
		//mydstat = nil
		//mydmode = nil
		//mydest_link = nil
		//destmd5 = nil

		moveme := true
		if protected {
			mydest, protected, moveme = d._protect(cfgfiledict,
				protect_if_modified, mymd5, myto, mydest,
				myrealdest, mydmode, destmd5, mydest_link)
		}

		zing := "!!!"
		if !moveme {
			zing = "---"
		}

		if syscall.S_IFLNK&mymode != 0 {
			myabsto := atom.absSymlink(mysrc, myto)

			if strings.HasPrefix(myabsto, srcroot) {
				myabsto = myabsto[len(srcroot):]
			}
			myabsto = strings.TrimLeft(myabsto, sep)
			if d.settings != nil && d.settings.ValueDict["D"] != "" {
				if strings.HasPrefix(myto, d.settings.ValueDict["D"]) {
					myto = myto[len(d.settings.ValueDict["D"])-1:]
				}
			}
			myrealto := msg.NormalizePath(filepath.Join(destroot, myabsto))
			if mydmode != 0 && syscall.S_IFDIR&mydmode != 0 {
				if !protected {
					newdest := d._new_backup_path(mydest)
					msg := []string{}
					msg = append(msg, "")
					msg = append(msg, "Installation of a symlink is blocked by a directory:")
					msg = append(msg, fmt.Sprintf("  '%s'", mydest))
					msg = append(msg, "This symlink will be merged with a different name:")
					msg = append(msg, fmt.Sprintf("  '%s'", newdest))
					msg = append(msg, "")
					d._eerror("preinst", msg)
					mydest = newdest
				}
			}

			if (secondhand != nil) && (!myutil.pathExists(myrealto)) {
				secondhand = append(secondhand, mysrc[len(srcroot):])
				continue
			}
			if moveme {
				zing = ">>>"
				mymtime = util._movefile(mysrc, mydest, thismtime, mystat, d.settings, nil)
			}

			st, err := os.Lstat(mydest)
			if err != nil {
				//except OSError:
				//pass
			} else {
				d._merged_path(mydest, st, true)
			}

			if mymtime != 0 {
				if not(os.path.lexists(myrealto) || os.path.lexists(join(srcroot, myabsto))) {
					d._eqawarn("preinst", []string{fmt.Sprintf("QA Notice: Symbolic link /%s points to /%s which does not exist.", relative_path, myabsto)})
				}
				showMessage(fmt.Sprintf("%s %s -> %s\n", zing, mydest, myto), 0, 0)
				outfile.Write([]byte("sym " + myrealdest + " -> " + myto + " " + fmt.Sprint(mymtime/1000000000) + "\n"))
			} else {
				showMessage("!!! Failed to move file.\n",
					40, -1)
				showMessage(fmt.Sprintf("!!! %s -> %s\n", mydest, myto),
					40, -1)
				return 1
			}
		} else if syscall.S_IFDIR&mymode != 0 {
			if mydmode != 0 {
				//if bsd_chflags {
				//	dflags = mydstat.st_flags
				//	if dflags != 0 {
				//		bsd_chflags.lchflags(mydest, 0)
				//	}
				//}

				if syscall.S_IFLNK&mydmode == 0 && !myutil.osAccess(mydest, unix.W_OK) {
					pkgstuff := versions.pkgSplit(d.pkg, "")
					WriteMsg(fmt.Sprintf("\n!!! Cannot write to '%s'.\n", mydest), 0, -1)
					WriteMsg(("!!! Please check permissions and directories for broken symlinks.\n"), 0, 0)
					WriteMsg(("!!! You may start the merge process again by using ebuild:\n"), 0, 0)
					WriteMsg("!!! ebuild "+d.settings.ValueDict["PORTDIR"]+"/"+d.cat+"/"+pkgstuff[0]+"/"+d.pkg+".ebuild merge\n", 0, 0)
					WriteMsg(("!!! And finish by running this: env-update\n\n"), 0, 0)
					return 1
				}

				if syscall.S_IFDIR&mydmode != 0 || (syscall.S_IFLNK&mydmode != 0) && myutil.PathIsDir(mydest) {
					showMessage(fmt.Sprintf("--- %s/\n", mydest), 0, 0)
					//if bsd_chflags {
					//	bsd_chflags.lchflags(mydest, dflags)
					//}
				} else {
					backup_dest := d._new_backup_path(mydest)
					msg := []string{}
					msg = append(msg, "")
					msg = append(msg, "Installation of a directory is blocked by a file:")
					msg = append(msg, fmt.Sprintf("  '%s'", mydest))
					msg = append(msg, "This file will be renamed to a different name:")
					msg = append(msg, fmt.Sprintf("  '%s'", backup_dest))
					msg = append(msg, "")
					d._eerror("preinst", msg)
					if util._movefile(mydest, backup_dest, 0, nil,
						d.settings, nil) == 0 {
						return 1
					}
					showMessage(fmt.Sprintf("bak %s %s.backup\n", mydest, mydest), 40, -1)
					//try:
					if d.settings.selinux_enabled() {
						_selinux_merge.mkdir(mydest, mysrc)
					} else {
						os.MkdirAll(mydest, 0755)
					}
					//except OSError as e:
					//if err in(errno.EEXIST, ):
					//pass
					//else if PathIsDir(mydest):
					//pass
					//else:
					//raise
					//del e

					//if bsd_chflags {
					//	bsd_chflags.lchflags(mydest, dflags)
					//}
					os.Chmod(mydest, mystat[0])
					os.Chown(mydest, mystat[4], mystat[5])
					showMessage(fmt.Sprintf(">>> %s/\n", mydest), 0, 0)
				}
			} else {
				//try:
				if d.settings.selinux_enabled() {
					_selinux_merge.mkdir(mydest, mysrc)
				} else {
					os.MkdirAll(mydest, 0755)
				}
				//except OSError as e:
				//if err in(errno.EEXIST, ):
				//pass
				//else if PathIsDir(mydest):
				//pass
				//else:
				//raise
				//del e
				os.Chmod(mydest, mystat[0])
				os.Chown(mydest, mystat[4], mystat[5])
				showMessage(fmt.Sprintf(">>> %s/\n", mydest), 0, 0)
			}
			ols, err := os.Lstat(mydest)
			if err == nil {
				d._merged_path(mydest, ols, true)
			} else {
				//except OSError:
				//pass
			}

			outfile.Write([]byte("dir " + myrealdest + "\n"))

			lds, _ := myutil.ListDir(join(srcroot, relative_path))
			for _, child := range lds {
				mergelist = append(mergelist, join(relative_path, child))
			}

		} else if syscall.S_IFREG&mymode != 0 {
			if !protected && mydmode != 0 && syscall.S_IFDIR&mydmode != 0 {
				newdest := d._new_backup_path(mydest)
				msg := []string{}
				msg = append(msg, "")
				msg = append(msg, ("Installation of a regular file is blocked by a directory:"))
				msg = append(msg, fmt.Sprintf("  '%s'", mydest))
				msg = append(msg, ("This file will be merged with a different name:"))
				msg = append(msg, fmt.Sprintf("  '%s'", newdest))
				msg = append(msg, "")
				d._eerror("preinst", msg)
				mydest = newdest
			}

			if moveme {
				hardlink_key := [2]uint64{mystat.Sys().(*syscall.Stat_t).Dev, mystat.Sys().(*syscall.Stat_t).Dev}

				hardlink_candidates := d._hardlink_merge_map[hardlink_key]
				if hardlink_candidates == nil {
					hardlink_candidates = []string{}
					d._hardlink_merge_map[hardlink_key] = hardlink_candidates
				}

				mymtime = util._movefile(mysrc, mydest, thismtime, mystat, d.settings, hardlink_candidates, )
				if mymtime == 0 {
					return 1
				}
				hardlink_candidates = append(hardlink_candidates, mydest)
				zing = ">>>"

				st, err := os.Lstat(mydest)
				if err != nil {
					//except OSError:
					//pass
				} else {
					d._merged_path(mydest, st, true)
				}
			}

			if mymtime != 0 {
				outfile.Write([]byte("obj " + myrealdest + " " + mymd5 + " " + fmt.Sprint(mymtime/1000000000) + "\n"))
			}
			showMessage(fmt.Sprintf("%s %s\n", zing, mydest), 0, 0)
		} else {
			zing = "!!!"
			if mydmode == 0 {
				if util._movefile(mysrc, mydest, thismtime, mystat, d.settings, nil) != nil {
					zing = ">>>"

					ls, err := os.Lstat(mydest)
					if err != nil {
						//except OSError:
						//pass
					}
					d._merged_path(mydest, ls, true)
				} else {
					return 1
				}
			}
			if syscall.S_IFIFO&mymode != 0 {
				outfile.Write([]byte(fmt.Sprintf("fif %s\n", myrealdest)))
			} else {
				outfile.Write([]byte(fmt.Sprintf("dev %s\n", myrealdest)))
			}
			showMessage(zing+" "+mydest+"\n", 0, 0)
		}
	}
}

func (d *dblink) _protect(cfgfiledict map[string][]string, protect_if_modified bool, src_md5,
	src_link, dest, dest_real string, dest_mode os.FileMode, dest_md5, dest_link string) (string, bool,bool) {

	move_me := true
	protected := true
	force := false
	k := ""
	if d._installed_instance != nil {
		k = d._installed_instance._match_contents(dest_real)
	}
	if k != "" {
		if dest_mode == 0 {
			force = true
		} else if protect_if_modified {
			data := d._installed_instance.getcontents()[k]
			if data[0] == "obj" && data[2] == dest_md5 {
				protected = false
			} else if data[0] == "sym" && data[2] == dest_link {
				protected = false
			}
		}
	}

	if protected && dest_mode != 0 {
		if src_md5 == dest_md5 {
			protected = false
		} else if src_md5 == cfgfiledict[dest_real][0] {
			protected = len(cfgfiledict["IGNORE"]) == 0
			move_me = protected
		}

		if protected && (dest_link != "" || src_link != "") && dest_link != src_link {
			force = true
		}

		if move_me {
			cfgfiledict[dest_real] = []string{src_md5}
		} else if dest_md5 == cfgfiledict[dest_real][0] {
			delete(cfgfiledict, dest_real)
		}
	}

	if protected && move_me {
		nm := dest_link
		if nm == "" {
			nm = src_md5
		}
		dest = util.new_protect_filename(dest, nm, force)
	}

	return dest, protected, move_me

}

// true
func (d *dblink) _merged_path(path string, lstatobj os.FileInfo, exists bool) {
	previous_path := d._device_path_map[lstatobj.Sys().(*syscall.Stat_t).Dev]
	if previous_path == "" || (exists && len(path) < len(previous_path)) {
		if exists {
			d._device_path_map[lstatobj.Sys().(*syscall.Stat_t).Dev] = path
		}else {
			d._device_path_map[lstatobj.Sys().(*syscall.Stat_t).Dev] = ""
		}
	}
}

func (d *dblink) _post_merge_sync() {
	if len(d._device_path_map) == 0 || ! d.settings.Features.Features["merge-sync"] {
		return
	}

	returncode = nil
	if runtime.GOOS == "linux"{
		paths := []string{}
		for _, path := range d._device_path_map{
			if path != "" {
				paths = append(paths, path)
			}
		}
		paths = tuple(paths)

		proc = SyncfsProcess(paths=paths,
			scheduler=(d._scheduler || asyncio._safe_loop()))
		proc.start()
		returncode = proc.wait()
	}

	if returncode == nil || returncode != 0{
	try:
		proc = subprocess.Popen(["sync"])
		except EnvironmentError:
		pass
		else:
		proc.wait()
	}
}

// nil, nil, 0,nil, nil, nil
func (d *dblink) merge(mergeroot, inforoot , myebuild string, cleanup bool,
	mydbapi *vardbapi, prev_mtimes *emerge.MergeProcess, counter int) int {

	retval := -1
	parallel_install := d.settings.Features.Features["parallel-install"]
	if ! parallel_install{
		d.lockdb()
	}
	d.vartree.dbapi._bump_mtime(d.mycpv.string)
	if d._scheduler == nil {
		d._scheduler = emerge.NewSchedulerInterface(asyncio._safe_loop(), nil)
	}
	//try:
	retval = d.treewalk(mergeroot, inforoot, myebuild,
		cleanup, mydbapi, prev_mtimes, counter)

	if myutil.PathIsDir(d.settings.ValueDict["PORTAGE_BUILDDIR"]){
		phase := ""
		if retval == 0 {
			phase = "success_hooks"
		}else {
			phase = "die_hooks"
		}

		ebuild_phase := emerge.NewMiscFunctionsProcess(false, []string{phase}, "", "", nil, d._scheduler, d.settings)
		ebuild_phase.start()
		ebuild_phase.wait()
		d._elog_process(nil)

		if  ! d.settings.Features.Features["noclean"] &&
			(retval == 0 || d.settings.Features.Features["fail-clean"]){
			if myebuild == "" {
				myebuild = filepath.Join(inforoot, d.pkg+".ebuild")
			}

			atom.doebuild_environment(myebuild, "clean", nil,
				d.settings, false, nil, mydbapi)
			phase2 := emerge.NewEbuildPhase(nil, false, "clean", d._scheduler, d.settings, nil)
			phase2.start()
			phase2.wait()
		}
	}

	//finally:
	delete(d.settings.ValueDict,"REPLACING_VERSIONS")
	if d.vartree.dbapi._linkmap == nil {
		//pass
	}else {
		d.vartree.dbapi._linkmap._clear_cache()
	}
	d.vartree.dbapi._bump_mtime(d.mycpv.string)
	if ! parallel_install {
		d.unlockdb()
	}

	if retval == 0 && d._postinst_failure {
		retval = _const.ReturncodePostinstFailure
	}

	return retval
}

func (d *dblink) getstring(name string) string {
	if _, err := os.Stat(d.dbdir + "/" + name); err != nil {
		return ""
	}
	f, _ := ioutil.ReadFile(filepath.Join(d.dbdir, name))
	mydata := strings.Fields(string(f))
	return strings.Join(mydata, " ")
}

func (d *dblink) copyfile(fname string) {
	util.copyfile(fname, d.dbdir+"/"+filepath.Base(fname))
}

func (d *dblink) getfile(fname string) string {
	if ! myutil.pathExists(d.dbdir+"/"+fname) {
		return ""
	}
	f, _ := ioutil.ReadFile(filepath.Join(d.dbdir, fname))
	return string(f)
}

func (d *dblink) setfile(fname, data string) {
	util.write_atomic(filepath.Join(d.dbdir, fname), data, os.O_RDWR|os.O_TRUNC|os.O_CREATE, true)
}

func (d *dblink) getelements(ename string) []string {
	if !myutil.pathExists(d.dbdir + "/" + ename) {
		return []string{}
	}
	f, _ := ioutil.ReadFile(filepath.Join(d.dbdir, ename))
	mylines := strings.Split(string(f), "\n")
	myreturn := []string{}
	for _, x := range mylines {
		for _, y := range strings.Fields(x[:len(x)-1]) {
			myreturn = append(myreturn, y)
		}
	}
	return myreturn
}

func (d *dblink) isregular() bool {
	return myutil.pathExists(filepath.Join(d.dbdir, "CATEGORY"))

}

func (d *dblink) _pre_merge_backup(backup_dblink *dblink, downgrade bool) int {
	if d.settings.Features.Features["unmerge-backup"] || (downgrade && d.settings.Features.Features["downgrade-backup"]) {
		return d._quickpkg_dblink(backup_dblink, false, "")
	}
	return 0
}

func (d *dblink) _pre_unmerge_backup(background bool) int {
	if d.settings.Features.Features[ "unmerge-backup"] {
		logfile := ""
		if d.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
			logfile = d.settings.ValueDict["PORTAGE_LOG_FILE"]
		}
		return d._quickpkg_dblink(d, background, logfile)
	}
	return 0
}

func (d *dblink) _quickpkg_dblink(backup_dblink *dblink, background bool, logfile string) int {

	build_timeS := backup_dblink.getfile("BUILD_TIME")
	build_time, _ := strconv.Atoi(strings.TrimSpace(build_timeS))
	//except ValueError:
	//build_time = 0

	trees := ebuild.NewQueryCommand(nil, "").get_db().Values()[d.settings.ValueDict["EROOT"]]
	bintree := trees.BinTree()

	bdm := []*versions.PkgStr{}
	for _, v := range bintree.dbapi.match(fmt.Sprintf("=%v", backup_dblink.mycpv), 1) {
		bdm = append([]*versions.PkgStr{v}, bdm...)
	}
	for _, binpkg := range bdm {
		if binpkg.buildTime == build_time {
			return 0
		}
	}

	d.lockdb()
	defer d.unlockdb()

	if !backup_dblink.exists() {
		return 0
	}

	quickpkg_binary := filepath.Join(d.settings.ValueDict["PORTAGE_BIN_PATH"], "quickpkg")

	if st, _ := os.Stat(quickpkg_binary); st == nil || st.Mode()&0111 == 0 {
		quickpkg_binary := process.FindBinary("quickpkg")
		if quickpkg_binary == "" {
			d._display_merge(fmt.Sprintf("%s: command not found", "quickpkg"),
				40, -1)
			return 127
		}
	}

	env := myutil.CopyMapSS(d.vartree.settings.ValueDict)
	env["__PORTAGE_INHERIT_VARDB_LOCK"] = "1"

	pythonpath := []string{}
	for _, x := range strings.Split(env["PYTHONPATH"], ":") {
		if x != "" {
			pythonpath = append(pythonpath, x)
		}
	}
	if len(pythonpath) == 0 ||
		not os.path.samefile(pythonpath[0], portage._pym_path) {
		pythonpath.insert(0, portage._pym_path)
	}
	env["PYTHONPATH"] = strings.Join(pythonpath, ":")

	quickpkg_proc := emerge.NewSpawnProcess(
		[]string{_python_interpreter, quickpkg_binary,
			fmt.Sprintf("=%s" , backup_dblink.mycpv.string)},
		background, env, nil,
		d._scheduler, logfile)
	quickpkg_proc.start()

	return *quickpkg_proc.wait()
}

// "", nil, "", nil, nil, nil, 0
func NewDblink(cat, pkg, myroot string, settings *ebuild.Config, treetype string,
	vartree *varTree, blockers []*dblink, scheduler *emerge.SchedulerInterface, pipe int) *dblink {
	d := &dblink{}

	d._normalize_needed = regexp.MustCompile("//|^[^/]|./$|(^|/)\\.\\.?(/|$)")

	d._contents_re = regexp.MustCompile("^((?P<dir>(dev|dir|fif) (.+))|(?P<obj>(obj) (.+) (\\S+) (\\d+))|(?P<sym>(sym) (.+) -> (.+) ((\\d+)|(?P<oldsym>(\\(\\d+, \\d+L, \\d+L, \\d+, \\d+, \\d+, \\d+L, \\d+, (\\d+), \\d+\\))))))$")

	d._infodir_cleanup = map[string]bool{"dir": true, "dir.old": true}

	d._ignored_unlink_errnos = []error{
		syscall.EBUSY, syscall.ENOENT,
		syscall.ENOTDIR, syscall.EISDIR}

	d._ignored_rmdir_errnos = []error{
		syscall.EEXIST, syscall.ENOTEMPTY,
		syscall.EBUSY, syscall.ENOENT,
		syscall.ENOTDIR, syscall.EISDIR,
		syscall.EPERM}

	if settings == nil {
		//raise TypeError("Settings argument is required")
	}

	mysettings := settings
	d._eroot = mysettings.ValueDict["EROOT"]
	d.cat = cat
	d.pkg = pkg
	mycpv := d.cat + "/" + d.pkg
	//if d.mycpv == Settings.mycpv &&	isinstance(Settings.mycpv, _pkg_str):
	//d.mycpv = Settings.mycpv
	//else:
	d.mycpv = versions.NewPkgStr(mycpv, nil, nil, "", "", "", 0, 0, "", 0, nil)
	d.mysplit = d.mycpv.cpvSplit[1:]
	d.mysplit[0] = d.mycpv.cp
	d.treetype = treetype
	if vartree == nil {
		vartree = portage.Db().valueDict[d._eroot].VarTree()
	}
	d.vartree = vartree
	d._blockers = blockers
	d._scheduler = scheduler
	d.dbroot = msg.NormalizePath(filepath.Join(d._eroot, _const.VdbPath))
	d.dbcatdir = d.dbroot + "/" + cat
	d.dbpkgdir = d.dbcatdir + "/" + pkg
	d.dbtmpdir = d.dbcatdir + "/" + _const.MergingIdentifier + pkg
	d.dbdir = d.dbpkgdir
	d.settings = mysettings
	d._verbose = d.settings.ValueDict["PORTAGE_VERBOSE"] == "1"

	d.myroot = d.settings.ValueDict["ROOT"]
	d._installed_instance = nil
	d.contentscache = nil
	d._contents_inodes = nil
	d._contents_basenames = nil
	d._linkmap_broken = false
	d._device_path_map = map[uint64]string{}
	d._hardlink_merge_map = map[[2]uint64][]string{}
	d._hash_key = []string{d._eroot, d.mycpv.string}
	d._protect_obj = nil
	d._pipe = pipe
	d._postinst_failure = false

	d._preserve_libs = mysettings.Features.Features["preserve-libs"]
	d._contents = NewContentsCaseSensitivityManager(d)
	d._slot_locks = []*dep.Atom{}

	return d
}

// nil, "", "", nil, nil, nil, nil, nil, nil
func merge(mycat, mypkg, pkgloc, infloc string, settings *ebuild.Config, myebuild, mytree string,
	mydbapi IDbApi, vartree *varTree, prev_mtimes=nil, blockers=nil, scheduler=nil, fd_pipes=nil) int {
	if settings == nil{
		//raise TypeError("Settings argument is required")
	}
	if st, _:= os.Stat(settings.ValueDict["EROOT"]); st!= nil &&st.Mode()&unix.W_OK ==0 {
		msg.WriteMsg(fmt.Sprintf("Permission denied: access('%s', W_OK)\n", settings.ValueDict["EROOT"]), -1, nil)
		return int(unix.EACCES)
	}
	background := settings.ValueDict["PORTAGE_BACKGROUND"] == "1"
	merge_task := emerge.NewMergeProcess(
		mycat, mypkg, settings, mytree, vartree,
		(scheduler || asyncio._safe_loop()),
		background, blockers, pkgloc,
		infloc, myebuild, mydbapi,
		prev_mtimes, settings.ValueDict["PORTAGE_LOG_FILE"],
		fd_pipes)
	merge_task.start()
	retcode := merge_task.wait()
	return retcode
}

// nil, nil, nil, nil, nil
func unmerge(cat, pkg string, settings *ebuild.Config,
	vartree *varTree, ldpath_mtimes=nil, scheduler=nil) int {

	if settings == nil {
		//raise TypeError("Settings argument is required")
	}
	mylink := NewDblink(cat, pkg, settings, "vartree", vartree, nil, scheduler, 0)
	vartree = mylink.vartree
	parallel_install := settings.Features.Features["parallel-install"]
	if ! parallel_install {
		mylink.lockdb()
	}
	defer func() {
		if vartree.dbapi._linkmap == nil {
			//pass
		}else {
			vartree.dbapi._linkmap._clear_cache()
		}
		if ! parallel_install {
			mylink.unlockdb()
		}
	}()
	if mylink.exists() {
		retval := mylink.unmerge(nil, true,ldpath_mtimes, nil, nil, nil)
		if retval == 0 {
			mylink.lockdb()
			//try:
			mylink.delete()
			//finally:
			mylink.unlockdb()
			return retval
		}
	}
	return 0
}

func write_contents(contents map[string][]string, root string, f io.WriteCloser) {
	rootLen := len(root) - 1
	cts := []string{}
	for k := range contents{
		cts =append(cts, k)
	}
	for _, filename := range myutil.sorted(cts){
		entryData := contents[filename]
		entryType := entryData[0]
		relativeFilename := filename[rootLen:]
		line := ""
		if entryType == "obj" {
			entryType, mtime, md5sum := entryData[0], entryData[1], entryData[2]
			line = fmt.Sprintf("%s %s %s %s\n", entryType, relativeFilename, md5sum, mtime)
		}else if entryType == "sym" {
			entryType, mtime, link := entryData[0], entryData[1], entryData[2]
			line = fmt.Sprintf("%s %s -> %s %s\n", entryType, relativeFilename, link, mtime)
		}else {
			line = fmt.Sprintf("%s %s\n" , entryType, relativeFilename)
		}
		f.Write([]byte(line))
	}
}

// nil, nil, false
func tar_contents(contents map[string][]string, root string, tar io.Writer, protect=nil, onProgress func(int, int), xattrs bool) {

	os = _os_merge
	encoding = _encodings['merge']

	tar.encoding = encoding
	root := strings.TrimRight(msg.NormalizePath(root), string(os.PathSeparator)) + string(os.PathSeparator)
	id_strings :=
	{
	}
	maxval := len(contents)
	curval := 0
	if onProgress != nil {
		onProgress(maxval, 0)
	}
	paths := []string{}
	for x := range contents {
		paths = append(paths, x)
	}
	sort.Strings(paths)
	for _, path := range paths {
		curval += 1
		lst, err := os.Lstat(path)
		if err != nil {
			//except OSError as e:
			if err != syscall.ENOENT {
				//raise
			}
			//del e
			if onProgress != nil {
				onProgress(maxval, curval)
			}
			continue
		}
		contents_type := contents[path][0]
		if strings.HasPrefix(path, root) {
			arcname = "./" + path[len(root):]
		} else {
			//raise ValueError("invalid root argument: '%s'" % root)
		}
		live_path := path
		if "dir" == contents_type && syscall.S_IFDIR&lst.Mode() == 0 &&
			myutil.PathIsDir(live_path) {
			live_path, _ = filepath.EvalSymlinks(live_path)
			lst, _ = os.Lstat(live_path)
		}

		tarinfo := tar.tarinfo()
		tarinfo.name = arcname
		tarinfo.mode = lst.Mode()
		tarinfo.uid = lst.st_uid
		tarinfo.gid = lst.st_gid
		tarinfo.size = 0
		tarinfo.mtime = lst.st_mtime
		tarinfo.linkname = ""
		if syscall.S_IFREG&lst.Mode() != 0 {
			inode = (lst.st_ino, lst.st_dev)
			if (lst.st_nlink > 1 &&
				inode in
			tar.inodes &&
				arcname != tar.inodes[inode]):
			tarinfo.
			type = tarfile.LNKTYPE
			tarinfo.linkname = tar.inodes[inode]
			else:
			tar.inodes[inode] = arcname
			tarinfo.
			type = tarfile.REGTYPE
			tarinfo.size = lst.st_size
		} else if syscall.S_IFDIR&lst.Mode() != 0 {
			tarinfo.
			type = tarfile.DIRTYPE
		} else if syscall.S_IFLNK&lst.Mode() != 0 {
			tarinfo.
			type = tarfile.SYMTYPE
			tarinfo.linkname = os.readlink(live_path)
		} else {
			continue
		}
	try:
		tarinfo.uname = pwd.getpwuid(tarinfo.uid)[0]
		except
	KeyError:
		pass
	try:
		tarinfo.gname = grp.getgrgid(tarinfo.gid)[0]
		except
	KeyError:
		pass

		if syscall.S_IFREG&lst.Mode() != 0 {
			if protect && protect(path) {
				f = tempfile.TemporaryFile()
				f.write(_unicode_encode(
					"	when `quickpkg` was used\n"))
				f.flush()
				f.seek(0)
				tarinfo.size = os.fstat(f.fileno()).st_size
				tar.addfile(tarinfo, f)
				f.close()
			} else:
			path_bytes = _unicode_encode(path,
				encoding = encoding,
				errors = 'strict')

			if xattrs:
			for k
				in
			xattr.list(path_bytes):
			tarinfo.pax_headers["SCHILY.xattr."+
				_unicode_decode(k)] = _unicode_decode(
				xattr.get(path_bytes, _unicode_encode(k)))

			with
			open(path_bytes, 'rb')
			as
		f:
			tar.addfile(tarinfo, f)

		} else {
			tar.addfile(tarinfo)
		}
		if onProgress != nil {
			onProgress(maxval, curval)
		}
	}
}
