package atom

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//nil,1,nil
func dep_expand(mydep *Atom, mydb *dbapi, use_cache int, settings *Config) *Atom {
	orig_dep := mydep
	d := mydep.value
	if !strings.HasPrefix(mydep.cp, "virtual/") {
		return mydep
	}
	d = mydep.cp

	expanded := cpv_expand(d, mydb, use_cache, settings)
	r := true
	a, _ := NewAtom(strings.Replace(d, orig_dep.value, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}

func cpv_expand(mycpv string, mydb *dbapi, use_cache int, settings *Config) string { // n1n
	myslash := strings.Split(mycpv, "/")
	mysplit := pkgSplit(myslash[len(myslash)-1], "")
	if settings == nil {
		settings = mydb.settings
	}
	mykey := ""
	if len(myslash) > 2 {
		mysplit = [3]string{}
		mykey = mycpv
	} else if len(myslash) == 2 {
		if mysplit != [3]string{} {
			mykey = myslash[0] + "/" + mysplit[0]
		} else {
			mykey = mycpv
		}
	}
	if strings.HasPrefix(mykey, "virtual/") && len(mydb.cp_list(mykey, use_cache)) == 0 {
		//		if hasattr(mydb, "vartree"):
		//		settings._populate_treeVirtuals_if_needed(mydb.vartree)
		//		virts = settings.getvirtuals().get(mykey)
		//		if virts:
		//		mykey_orig = mykey
		//		for vkey in virts:
		//		if mydb.cp_list(vkey.cp):
		//		mykey = str(vkey)
		//		break
		//		if mykey == mykey_orig:
		//		mykey = str(virts[0])
		//	}
	} else {
		//	if mysplit:
		//	myp=mysplit[0]
		//	else:
		//	myp=mycpv
		//	mykey=None
		//	matches=[]
		//	if mydb and hasattr(mydb, "categories"):
		//	for x in mydb.categories:
		//	if mydb.cp_list(x+"/"+myp,use_cache=use_cache):
		//	matches.append(x+"/"+myp)
		//	if len(matches) > 1:
		//	virtual_name_collision = False
		//	if len(matches) == 2:
		//	for x in matches:
		//	if not x.startswith("virtual/"):
		//	mykey = x
		//	else:
		//	virtual_name_collision = True
		//	if not virtual_name_collision:
		//		raise AmbiguousPackageName(matches)
		//	elif matches:
		//	mykey=matches[0]
		//
		//	if not mykey and not isinstance(mydb, list):
		//	if hasattr(mydb, "vartree"):
		//	settings._populate_treeVirtuals_if_needed(mydb.vartree)
		//	virts_p = settings.get_virts_p().get(myp)
		//	if virts_p:
		//	mykey = virts_p[0]
		//	if not mykey:
		//	mykey="null/"+myp
	}
	if mysplit != [3]string{} {
		if mysplit[2] == "r0" {
			return mykey + "-" + mysplit[1]
		} else {
			return mykey + "-" + mysplit[1] + "-" + mysplit[2]
		}
	} else {
		return mykey
	}
}

type dbapi struct {
	_category_re      *regexp.Regexp
	_use_mutable      bool
	_categories       []string
	_known_keys       map[string]bool
	_pkg_str_aux_keys []string
	settings          *Config
}

func (d *dbapi) categories() []string {
	if d._categories != nil {
		return d._categories
	}
	m := map[string]bool{}
	for _, x := range d.cp_all(false) {
		m[catsplit(x)[0]] = true
	}
	d._categories = []string{}
	for x := range m {
		d._categories = append(d._categories, x)
	}
	sort.Strings(d._categories)

	return d._categories
}

func (d *dbapi) close_caches() {}

func (d *dbapi) cp_list(cp string, useCache int) []*pkgStr { //1
	panic("")
	return nil
}

func (d *dbapi) _cmp_cpv(cpv1, cpv2 *pkgStr) int {
	result, _ := verCmp(cpv1.version, cpv2.version)
	if result == 0 && cpv1.buildTime != 0 && cpv2.buildTime != 0 {
		if (cpv1.buildTime > cpv2.buildTime) && (cpv1.buildTime < cpv2.buildTime) {
			result = 0
		} else if !(cpv1.buildTime > cpv2.buildTime) && (cpv1.buildTime < cpv2.buildTime) {
			result = -2
		} else if (cpv1.buildTime > cpv2.buildTime) && !(cpv1.buildTime < cpv2.buildTime) {
			result = 2
		} else { // (cpv1.buildTime > cpv2.buildTime)&&(cpv1.buildTime < cpv2.buildTime)
			result = 0
		}
	}
	return result
}

func (d *dbapi) _cpv_sort_ascending(cpv_list []*pkgStr) {
	if len(cpv_list) > 1 {
		sort.Slice(cpv_list, func(i, j int) bool {
			return d._cmp_cpv(cpv_list[i], cpv_list[j]) < 0
		})
	}
}

func (d *dbapi) cpv_all() []*pkgStr {
	cpvList := []*pkgStr{}
	for _, cp := range d.cp_all(false) {
		cpvList = append(cpvList, d.cp_list(cp, 1)...)
	}
	return cpvList
}

func (d *dbapi) cp_all(sort bool) []string { // false
	panic("")
	return nil
}

func (d *dbapi) auxGet(myCpv *pkgStr, myList []string, myRepo string) []string {
	panic("NotImplementedError")
	return nil
}

func (d *dbapi) auxUpdate(cpv string, metadataUpdates map[string]string) {
	panic("NotImplementedError")
}

func (d *dbapi) match(origdep *Atom, useCache int) []*pkgStr { // 1
	mydep := dep_expand(origdep, d, 1, d.settings)
	return d._iter_match(mydep, d.cp_list(mydep.cp, useCache))
}

func (d *dbapi) _iter_match(atom *Atom, cpvIter []*pkgStr) []*pkgStr {
	cpvIter = matchFromList(atom, cpvIter)
	if atom.repo != "" {

	}
	cpvIter = d._iter_match_repo(atom, cpvIter)
	if atom.slot != "" {
		cpvIter = d._iter_match_slot(atom, cpvIter)
	}
	if atom.unevaluatedAtom.use != nil {
		cpvIter = d._iter_match_use(atom, cpvIter)
	}
	return cpvIter
}

func (d *dbapi) _pkg_str(cpv *pkgStr, repo string) *pkgStr {
	//try:
	//cpv.slot
	//except AttributeError:
	//pass
	//else:
	return cpv
	//
	//metadata = dict(zip(self._pkg_str_aux_keys,
	//self.aux_get(cpv, self._pkg_str_aux_keys, myrepo=repo)))
	//
	//return _pkg_str(cpv, metadata=metadata, settings=self.settings, db=self)
}

func (d *dbapi) _iter_match_repo(atom *Atom, cpvIter []*pkgStr) []*pkgStr {
	r := []*pkgStr{}
	for _, cpv := range cpvIter {
		pkgStr := d._pkg_str(cpv, atom.repo)
		if pkgStr.repo == atom.repo {
			r = append(r, pkgStr)
		}
	}
	return r
}

func (d *dbapi) _iter_match_slot(atom *Atom, cpvIter []*pkgStr) []*pkgStr {
	r := []*pkgStr{}
	for _, cpv := range cpvIter {
		pkgStr := d._pkg_str(cpv, atom.repo)
		if matchSlot(atom, cpv) {
			r = append(r, pkgStr)
		}
	}
	return r
}

func (d *dbapi) _iter_match_use(atom *Atom, cpvIter []*pkgStr) []*pkgStr {
	aux_keys := []string{"EAPI", "IUSE", "KEYWORDS", "SLOT", "USE", "repository"}

	r := []*pkgStr{}
	for _, cpv := range cpvIter {
		metadata := map[string]string{}
		a := d.auxGet(cpv, aux_keys, atom.repo)
		for i, k := range aux_keys {
			metadata[k] = a[i]
		}
		if !d._match_use(atom, cpv, metadata, false) {
			continue
		}
		r = append(r, cpv)
	}
	return r
}

func (d *dbapi) _repoman_iuse_implicit_cnstr(pkg, metadata map[string]string) func(flag string) bool {
	eapiAttrs := getEapiAttrs(metadata["EAPI"])
	var iuseImplicitMatch func(flag string) bool = nil
	if eapiAttrs.iuseEffective {
		iuseImplicitMatch = func(flag string) bool {
			return d.settings.iuseEffectiveMatch(flag)
		}
	} else {
		iuseImplicitMatch = func(flag string) bool {
			return d.settings.iuseImplicitMatch.call(flag)
		}
	}
	return iuseImplicitMatch
}

func (d *dbapi) _iuse_implicit_cnstr(pkg *pkgStr, metadata map[string]string) func(string) bool {
	eapiAttrs := getEapiAttrs(metadata["EAPI"])
	var iuseImplicitMatch func(string) bool
	if eapiAttrs.iuseEffective {
		iuseImplicitMatch = d.settings.iuseEffectiveMatch
	} else {
		iuseImplicitMatch = d.settings.iuseImplicitMatch.call
	}

	if !d._use_mutable && eapiAttrs.iuseEffective {
		profIuse := iuseImplicitMatch
		enabled := strings.Fields(metadata["USE"])
		iuseImplicitMatch = func(flag string) bool {
			if profIuse(flag) {
				return true
			}
			for _, f := range enabled {
				if f == flag {
					return true
				}
			}
			return false
		}
	}

	return iuseImplicitMatch
}

func (d *dbapi) _match_use(atom *Atom, pkg *pkgStr, metadata map[string]string, ignore_profile bool) bool { // false
	iuseImplicitMatch := d._iuse_implicit_cnstr(pkg, metadata)
	useAliases := d.settings.useManager.getUseAliases(pkg)
	iuse := NewIUse("", strings.Fields(metadata["IUSE"]), iuseImplicitMatch, useAliases, metadata["EAPI"])

	for x := range atom.unevaluatedAtom.use.required {
		if iuse.getRealFlag(x) == "" {
			return false
		}
	}

	if atom.use == nil {
	} else if !d._use_mutable {
		use := map[string]bool{}
		for _, x := range strings.Fields(metadata["USE"]) {
			if iuse.getRealFlag(x) != "" {
				use[x] = true
			}
		}
		missingEnabled := map[string]bool{}
		for x := range atom.use.missingEnabled {
			if iuse.getRealFlag(x) == "" {
				missingEnabled[x] = true
			}
		}
		missingDisabled := map[string]bool{}
		for x := range atom.use.missingDisabled {
			if iuse.getRealFlag(x) == "" {
				missingDisabled[x] = true
			}
		}
		enabled := map[string]bool{}
		for x := range atom.use.enabled {
			if iuse.getRealFlag(x) != "" {
				enabled[iuse.getRealFlag(x)] = true
			} else {
				enabled[x] = true
			}
		}
		disabled := map[string]bool{}
		for x := range atom.use.disabled {
			if iuse.getRealFlag(x) != "" {
				disabled[iuse.getRealFlag(x)] = true
			} else {
				disabled[x] = true
			}
		}
		if len(enabled) > 0 {
			for x := range missingDisabled {
				if enabled[x] {
					return false
				}
			}
			needEnabled := map[string]bool{}
			for x := range enabled {
				if !use[x] {
					needEnabled[x] = true
				}
			}
			if len(needEnabled) > 0 {
				for x := range needEnabled {
					if !missingEnabled[x] {
						return false
					}
				}
			}
		}
		if len(disabled) > 0 {
			for x := range missingEnabled {
				if disabled[x] {
					return false
				}
			}
			needDisabled := map[string]bool{}
			for x := range disabled {
				if !use[x] {
					needDisabled[x] = true
				}
			}
			if len(needDisabled) > 0 {
				for x := range needDisabled {
					if !missingDisabled[x] {
						return false
					}
				}
			}
		}
	} else if !d.settings.localConfig {
		if !ignore_profile {
			useMask := d.settings._getUseMask(pkg, d.settings.parentStable)
			for x := range atom.use.enabled {
				for y := range useMask {
					if x == y.value {
						return false
					}
				}
			}
			useForce := d.settings._getUseForce(pkg, d.settings.parentStable)
			for x := range atom.use.disabled {
				for y := range useForce {
					if x == y.value {
						in := false
						for z := range useMask {
							if x == z.value {
								in = true
								break
							}
						}
						if !in {
							return false
						}
					}
				}
			}
		}

		if len(atom.use.enabled) > 0 {
			for x := range atom.use.missingDisabled {
				if iuse.getRealFlag(x) == "" {
					if atom.use.enabled[x] {
						return false
					}
				}
			}
		}
		if len(atom.use.disabled) > 0 {
			for x := range atom.use.missingEnabled {
				if iuse.getRealFlag(x) == "" {
					if atom.use.disabled[x] {
						return false
					}
				}
			}
		}
	}

	return true
}

func (d *dbapi) invalidentry(mypath string) {
	if strings.Contains(mypath, "/"+MergingIdentifier) {
		if _, err := os.Stat(mypath); err != nil {
			WriteMsg(colorize("BAD", "INCOMPLETE MERGE:"+fmt.Sprintf(" %s\n", mypath)), -1, nil)
		}
	} else {
		WriteMsg(fmt.Sprintf("!!! Invalid db entry: %s\n", mypath), -1, nil)
	}
}

func (d *dbapi) update_ents(updates map[string][][]*Atom, onProgress, onUpdate func(int, int)) {
	cpvAll := d.cpv_all()
	sort.Slice(cpvAll, func(i, j int) bool {
		return cpvAll[i].string < cpvAll[j].string
	})
	maxval := len(cpvAll)
	auxGet := d.auxGet
	auxUpdate := d.auxUpdate
	updateKeys := Package{}.depKeys
	metaKeys := append(updateKeys, d._pkg_str_aux_keys...)
	repoDict := updates // is dict, else nil
	if onUpdate != nil {
		onUpdate(maxval, 0)
	}
	if onProgress != nil {
		onProgress(maxval, 0)
	}
	for i, cpv := range cpvAll {

		metadata := map[string]string{}
		a := auxGet(cpv, metaKeys, "")
		for i, v := range metaKeys {
			metadata[v] = a[i]
		}
		//except KeyError:
		//continue
		pkg := NewPkgStr(cpv.string, metadata, d.settings, "", "", "", 0, "", "", 0, nil)
		//except InvalidData:
		//continue
		m := map[string]string{}
		for _, k := range updateKeys {
			m[k] = metadata[k]
		}
		//if repo_dict ==nil{ // always false
		//	updates_list = updates
		//} else{
		var updatesList [][]*Atom = nil
		var ok bool
		if updatesList, ok = repoDict[pkg.repo]; !ok {
			if updatesList, ok = repoDict["DEFAULT"]; !ok {
				continue
			}
		}

		if len(updatesList) == 0 {
			continue
		}
		metadataUpdates := update_dbentries(updatesList, metadata, "", pkg)
		if len(metadataUpdates) != 0 {
			auxUpdate(cpv.string, metadataUpdates)
		}
		if onUpdate != nil {
			onUpdate(maxval, i+1)
		}
		if onProgress != nil {
			onProgress(maxval, i+1)
		}
	}
}

func (d *dbapi) move_slot_ent(mylist []*Atom, repo_match func(string) bool) int { // nil
	atom := mylist[1]
	origSlot := mylist[2]
	newSlot := mylist[3]
	atom = atom.withSlot(origSlot.value)
	origMatches := d.match(atom, 1)
	moves := 0
	if len(origMatches) == 0 {
		return moves
	}
	for _, mycpv := range origMatches {
		mycpv = d._pkg_str(mycpv, atom.repo)
		if repo_match != nil && !repo_match(mycpv.repo) {
			continue
		}
		moves += 1
		if !strings.Contains(newSlot.value, "/") && mycpv.subSlot != "" && mycpv.subSlot != mycpv.slot && mycpv.subSlot != newSlot.value {
			newSlot.value = fmt.Sprintf("%s/%s", newSlot.value, mycpv.subSlot)
		}
		mydata := map[string]string{"SLOT": newSlot.value + "\n"}
		d.auxUpdate(mycpv.string, mydata)
	}
	return moves
}

func NewDbapi() *dbapi {
	d := &dbapi{_category_re: regexp.MustCompile(`^\w[-.+\w]*$`),
		_categories:  nil,
		_use_mutable: false}
	for x := range auxdbkeys {
		if !strings.HasPrefix(x, "UNUSED_0") {
			d._known_keys[x] = true
		}
	}
	d._pkg_str_aux_keys = []string{"BUILD_TIME", "EAPI", "BUILD_ID", "KEYWORDS", "SLOT", "repository"}
	return d
}

type ContentsCaseSensitivityManager struct {
	getContents        string
	unmapKey           string
	keys               string
	contentInsensitive string
	reverseKeyMap      string
}

func NewContentsCaseSensitivityManager(db string) *ContentsCaseSensitivityManager {
	return nil
}

type vdbMetadataDelta struct {
	vardb *vardbapi
}

func (v *vdbMetadataDelta) initialize() {}

func (v *vdbMetadataDelta) load() {}

func (v *vdbMetadataDelta) loadRace() {}

func (v *vdbMetadataDelta) recordEvent() {}

func (v *vdbMetadataDelta) applyDelta() {}

func NewVdbMetadataDelta(vardb *vardbapi) *vdbMetadataDelta {
	v := &vdbMetadataDelta{}
	v.vardb = vardb
	return v
}

type vardbapi struct {
	*dbapi
	_excluded_dirs, _aux_cache_keys_re, _aux_multi_line_re *regexp.Regexp
	_aux_cache_version, _owners_cache_version, _lock       string
	_aux_cache_threshold                                   int

	_pkgs_changed, _flush_cache_enabled                                                        bool
	 matchcache, cpcache, blockers                                                  map[string]string
	mtdircache map[string]int
	_eroot, _dbroot, _conf_mem_file, _aux_cache_filename, _cache_delta_filename, _counter_path string
	_fs_lock_obj                                                                               *struct {
		string
		int
		bool
		method func(int, int) error
	}
	_slot_locks map[*Atom]*struct {
		s *struct {
			string
			int
			bool
			method func(int, int) error
		}
		int
	}
	_aux_cache_obj, _cached_counter interface{}
	_lock_count, _fs_lock_count     int
	vartree                         *varTree
	_aux_cache_keys                 map[string]bool
	_cache_delta                    *vdbMetadataDelta
	_plib_registry                  *preservedLibsRegistry
	_linkmap                        *linkageMapELF
	_owners                         *_owners_db
}

func (v *vardbapi) writable() bool {
	st, err := os.Stat(firstExisting(v._dbroot))
	return err != nil && st.Mode()&os.FileMode(os.O_WRONLY) != 0
}

func (v *vardbapi) root() string {
	return v.settings.ValueDict["ROOT"]
}

func (v *vardbapi) getpath(mykey, filename string) string { // ""
	rValue := v._dbroot + VdbPath + string(os.PathSeparator) + mykey
	if filename != "" {
		rValue = path.Join(rValue, filename)
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
		ensureDirs(v._dbroot, -1, -1, -1, -1, nil, true)
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
		unlockdir(v._lock)
		v._lock = ""
	}

}

func (v *vardbapi) _fs_lock() {
	if v._fs_lock_count < 1 {
		if v._fs_lock_obj != nil {
			panic("already locked")
		}
		a, b, c, d, _ := lockfile(v._conf_mem_file, false, false, "", 0)
		v._fs_lock_obj = &struct {
			string
			int
			bool
			method func(int, int) error
		}{a, b, c, d}
		// if err == InvalidLocataion {
		// v.settings.init_dirs()
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
		unlockfile(v._fs_lock_obj.string, v._fs_lock_obj.int, v._fs_lock_obj.bool, v._fs_lock_obj.method)
		v._fs_lock_obj = nil
	}
	v._fs_lock_count -= 1
}

func (v *vardbapi) _slot_lock(slot_atom *Atom) {
	lock := v._slot_locks[slot_atom].s
	counter := v._slot_locks[slot_atom].int
	if lock == nil {
		lock_path := v.getpath(fmt.Sprintf("%s:%s", slot_atom.cp, slot_atom.slot), "")
		ensureDirs(path.Dir(lock_path), -1, -1, -1, -1, nil, true)
		a, b, c, d, _ := lockfile(lock_path, true, false, "", 0)
		lock = &struct {
			string
			int
			bool
			method func(int, int) error
		}{a, b, c, d}
	}
	v._slot_locks[slot_atom] = &struct {
		s *struct {
			string
			int
			bool
			method func(int, int) error
		}
		int
	}{lock, counter + 1}
}

func (v *vardbapi) _slot_unlock(slot_atom *Atom) {
	lock := v._slot_locks[slot_atom].s
	counter := v._slot_locks[slot_atom].int
	if lock == nil {
		panic("not locked")
	}
	counter -= 1
	if counter == 0 {
		unlockfile(lock.string, lock.int, lock.bool, lock.method)
		delete(v._slot_locks, slot_atom)
	} else {
		v._slot_locks[slot_atom] = &struct {
			s *struct {
				string
				int
				bool
				method func(int, int) error
			}
			int
		}{s: lock, int: counter}
	}
}

func (v *vardbapi) _bump_mtime(cpv string) {
	base := v._eroot + VdbPath
	cat := catsplit(cpv)[0]
	catdir := base + string(filepath.Separator) + cat
	t := time.Now()

	for _, x := range []string{catdir, base} {
		if err := syscall.Utime(x, &syscall.Utimbuf{Actime: t.Unix(), Modtime: t.Unix()}); err != nil {
			ensureDirs(catdir, -1, -1, -1, -1, nil, true)
		}
	}
}

func (v *vardbapi) cpv_exists(mykey, myrepo string) bool {
	_, err := os.Stat(v.getpath(mykey, ""))
	if err != nil {
		return true
	}
	return false
}

func (v *vardbapi) cpv_counter(mycpv *pkgStr) int {
	s, err := strconv.Atoi(v.auxGet(mycpv, []string{"COUNTER"}, "")[0])
	if err != nil {
		writeMsgLevel(fmt.Sprintf("portage: COUNTER for %s was corrupted; resetting to value of 0\n",mycpv.string), 40, -1)
		return 0
	}
	return s
}

func (v *vardbapi) cpv_inject(mycpv *pkgStr) {
	ensureDirs(v.getpath(mycpv.string, ""),  -1,-1,-1,-1,nil,true)
	counter := v.counter_tick(mycpv)
	write_atomic(v.getpath(mycpv.string, "COUNTER"), string(counter))
}

func (v *vardbapi) isInjected(mycpv string)bool {
	if v.cpv_exists(mycpv, ""){
		if _, err := os.Stat(v.getpath(mycpv, "INJECTED")); err == nil {
			return true
		}
		if _, err := os.Stat(v.getpath(mycpv, "CONTENTS")); err != nil {
			return true
		}
	}
	return false
}

// nil
func (v *vardbapi) move_ent(mylist []*Atom, repo_match func(string)bool) int{
	origcp := mylist[1]
	newcp := mylist[2]

	for _, atom := range []*Atom{origcp, newcp}{
		if ! isJustName(atom.value){
			//raise InvalidPackageName(str(atom))
		}
	}
	origmatches := v.match(origcp, 0)
	moves := 0
	if len(origmatches)==0 {
		return moves
	}
	for _, mycpv := range origmatches{
		mycpv = v._pkg_str(mycpv, "")
		mycpv_cp := cpvGetKey(mycpv, "")
		if mycpv_cp != origcp.value{
			continue
		}
		if repo_match != nil && !repo_match(mycpv.repo) {
			continue
		}

		if ! isValidAtom(newcp.value,false, false, false, mycpv.eapi, false ) {
			continue
		}

		mynewcpv := strings.Replace(mycpv.string, mycpv_cp, newcp.value, 1)
		mynewcat := catsplit(newcp.value)[0]
		origpath := v.getpath(mycpv,"")
		if _, err := os.Stat(origpath); err != nil {
			continue
		}
		moves += 1
		if _, err := os.Stat(v.getpath(mynewcat, "")); err != nil {
			ensureDirs(v.getpath(mynewcat, ""), -1,-1,-1,-1,nil,true)
		}
		newpath := v.getpath(mynewcpv, "")
		if _, err := os.Stat(newpath); err == nil{
			continue
		}
		_movefile(origpath, newpath, nil, nil, v.settings, nil)
		v._clear_pkg_cache(v._dblink(mycpv))
		v._clear_pkg_cache(v._dblink(mynewcpv))

			old_pf = catsplit(mycpv)[1]
		new_pf = catsplit(mynewcpv)[1]
		if new_pf != old_pf:
	try:
		os.rename(os.path.join(newpath, old_pf + ".ebuild"),
			os.path.join(newpath, new_pf + ".ebuild"))
		except EnvironmentError as e:
		if e.errno != errno.ENOENT:
		raise
		del e
		write_atomic(path.Join(newpath, "PF"), new_pf+"\n")
		write_atomic(path.Join(newpath, "CATEGORY"), mynewcat+"\n")
	}
	return moves
}

func (v *vardbapi) cp_list(mycp *pkgStr, use_cache int) []*pkgStr{
	mysplit:=catsplit(mycp.string)
	if mysplit[0] == "*"{
		mysplit[0] = mysplit[0][1:]
	}
	mystatt, err := os.Stat(v.getpath(mysplit[0], ""))

	mystat := int64(0)
	if err == nil {
		mystat = mystatt.ModTime().UnixNano()
	}
	if cpc, ok := v.cpcache[mycp.string]; use_cache!= 0 && ok {
		if cpc[0] == mystat {
			return cpc[1][:]
		}
	}
	cat_dir := v.getpath(mysplit[0], "")
	dir_list, err := ioutil.ReadDir(cat_dir)
	if err != nil {
		if err ==syscall.EPERM {
			//raise PermissionDenied(cat_dir)
		}
		dir_list = []os.FileInfo{}
	}

	returnme := []*pkgStr{}
	for _, x := range dir_list{
		if v._excluded_dirs.MatchString(x.Name()) {
			continue
		}
		ps := PkgSplit(x.Name(), 1, "")
		if ps==[3]string{}{
			v.invalidentry(path.Join(v.getpath(mysplit[0], ""), x.Name()))
			continue
		}
		if len(mysplit) > 1{
			if ps[0] == mysplit[1]{
				cpv := fmt.Sprintf("%s/%s" ,mysplit[0], x)
				metadata := map[string]string{}
				for i := range v._aux_cache_keys {
					metadata[i]= v.aux_get(cpv, v._aux_cache_keys)
				}
				returnme = append(returnme, NewPkgStr(cpv, metadata,
					v.settings, "", "", "", 0, "", "", 0, v.dbapi))
			}
		}
	}
	v._cpv_sort_ascending(returnme)
	if use_cache!= 0 {
		v.cpcache[mycp.string] = []string{mystat, returnme[:]}
}else if _, ok := v.cpcache[mycp.string];ok{
delete(v.cpcache,mycp.string)
}
	return returnme
}

func (v *vardbapi) cpv_all() {}

func (v *vardbapi) _iter_cpv_all() {}

func (v *vardbapi) checkblockers() {}

func (v *vardbapi) _clear_cache() {}

func (v *vardbapi) _add() {}

func (v *vardbapi) _remove() {}

func (v *vardbapi) _clear_pkg_cache() {}

// 1
func (v *vardbapi) match(origdep *Atom, use_cache int) []*pkgStr {
	mydep := dep_expand(origdep, v.dbapi, use_cache, v.settings)
	cache_key := []*Atom{mydep, mydep.unevaluatedAtom}
	mykey := depGetKey(mydep.value)
	mycat := catsplit(mykey)[0]
	if use_cache== 0{
		if _, ok := v.matchcache[mykey]; ok {
			delete( v.mtdircache,mycat)
			delete( v.matchcache,mycat)
		}
		return v._iter_match(mydep,
			v.cp_list(mydep.cp, use_cache))
	}
	st, err := os.Stat(path.Join(v._eroot, VdbPath, mycat))
	curmtime := 0
	if err == nil {
		curmtime = st.ModTime().Nanosecond()
	}

	if  _, ok:= v.matchcache[mycat]; !ok ||v.mtdircache[mycat] != curmtime{
		v.mtdircache[mycat] = curmtime
		v.matchcache[mycat] = map[]
	}
	if _, ok:= v.matchcache[mycat][mydep.value]; !ok {
		mymatch := v._iter_match(mydep,
			v.cp_list(mydep.cp, use_cache))
		v.matchcache[mycat][cache_key] = mymatch
	}
	return v.matchcache[mycat][cache_key][:]
}

func (v *vardbapi) findname(mycpv string) string {
	return v.getpath(mycpv, catsplit(mycpv)[1]+".ebuild")
}

func (v *vardbapi) flush_cache() {}

func (v *vardbapi) _aux_cache() {}

func (v *vardbapi) _aux_cache_init() {}

// nil
func (v *vardbapi) aux_get(mycpv string, wants map[string] bool, myrepo = None) {
	cache_these_wants := map[string]bool{}
	for k := range v._aux_cache_keys {
		if wants[k] {
			cache_these_wants[k]=true
		}
	}
	for x := range wants{
		if v._aux_cache_keys_re.MatchString(x){
		cache_these_wants[x]=true
	}
	}

	if len(cache_these_wants)==0{
		mydata := v._aux_get(mycpv, wants)
		ret := []string{		}
		for x := range wants{
			ret = append(ret, mydata[x])
		}
		return ret
	}

	cache_these := map[string]bool {}
	for k := range v._aux_cache_keys {
		cache_these[k]=true
	}
	for k := range cache_these_wants {
		cache_these[k]=true
	}

	mydir := v.getpath(mycpv, "")
	mydir_stat = None
	try:
	mydir_stat = os.stat(mydir)
	except OSError as e:
	if e.errno != errno.ENOENT:
	raise
	raise KeyError(mycpv)
	# Use float mtime when available.
	mydir_mtime = mydir_stat.st_mtime
	pkg_data = self._aux_cache["packages"].get(mycpv)
	pull_me = cache_these.union(wants)
	mydata = {"_mtime_" : mydir_mtime}
	cache_valid = False
	cache_incomplete = False
	cache_mtime = None
	metadata = None
	if pkg_data is not None:
	if not isinstance(pkg_data, tuple) or len(pkg_data) != 2:
	pkg_data = None
	else:
	cache_mtime, metadata = pkg_data
	if not isinstance(cache_mtime, (float, long, int)) or \
	not isinstance(metadata, dict):
	pkg_data = None

	if pkg_data:
	cache_mtime, metadata = pkg_data
	if isinstance(cache_mtime, float):
	if cache_mtime == mydir_stat.st_mtime:
	cache_valid = True

	# Handle truncated mtime in order to avoid cache
	# invalidation for livecd squashfs (bug 564222).
	elif long(cache_mtime) == mydir_stat.st_mtime:
	cache_valid = True
	else:
	# Cache may contain integer mtime.
	cache_valid = cache_mtime == mydir_stat[stat.ST_MTIME]

	if cache_valid:
	# Migrate old metadata to unicode.
	for k, v in metadata.items():
	metadata[k] = _unicode_decode(v,
	encoding=_encodings['repo.content'], errors='replace')

	mydata.update(metadata)
	pull_me.difference_update(mydata)

	if pull_me:
	# pull any needed data and cache it
	aux_keys = list(pull_me)
	mydata.update(self._aux_get(mycpv, aux_keys, st=mydir_stat))
	if not cache_valid or cache_these.difference(metadata):
	cache_data = {}
	if cache_valid and metadata:
	cache_data.update(metadata)
	for aux_key in cache_these:
	cache_data[aux_key] = mydata[aux_key]
	self._aux_cache["packages"][_unicode(mycpv)] = \
	(mydir_mtime, cache_data)
	self._aux_cache["modified"].add(mycpv)

	eapi_attrs = _get_eapi_attrs(mydata['EAPI'])
	if _get_slot_re(eapi_attrs).match(mydata['SLOT']) is None:
	# Empty or invalid slot triggers InvalidAtom exceptions when
	# generating slot atoms for packages, so translate it to '0' here.
	mydata['SLOT'] = '0'

	return [mydata[x] for x in wants]
}

// nil
func (v *vardbapi) _aux_get(mycpv, wants, st=None) {
	mydir = self.getpath(mycpv)
	if st is None:
try:
	st = os.stat(mydir)
	except OSError as e:
	if e.errno == errno.ENOENT:
	raise KeyError(mycpv)
	elif e.errno == PermissionDenied.errno:
	raise PermissionDenied(mydir)
	else:
	raise
	if not stat.S_ISDIR(st.st_mode):
	raise KeyError(mycpv)
	results = {}
	env_keys = []
	for x in wants:
	if x == "_mtime_":
	results[x] = st[stat.ST_MTIME]
	continue
try:
	with io.open(
		_unicode_encode(os.path.join(mydir, x),
			encoding=_encodings['fs'], errors='strict'),
	mode='r', encoding=_encodings['repo.content'],
		errors='replace') as f:
	myd = f.read()
	except IOError:
	if x not in self._aux_cache_keys and \
	self._aux_cache_keys_re.match(x) is None:
	env_keys.append(x)
	continue
	myd = ''

	# Preserve \n for metadata that is known to
	# contain multiple lines.
	if self._aux_multi_line_re.match(x) is None:
	myd = " ".join(myd.split())

	results[x] = myd

	if env_keys:
	env_results = self._aux_env_search(mycpv, env_keys)
	for k in env_keys:
	v = env_results.get(k)
	if v is None:
	v = ''
	if self._aux_multi_line_re.match(k) is None:
	v = " ".join(v.split())
	results[k] = v

	if results.get("EAPI") == "":
	results["EAPI"] = '0'

	return results
}

func (v *vardbapi) _aux_env_search() {}

func (v *vardbapi) aux_update() {}

func (v *vardbapi) counter_tick() {}

func (v *vardbapi) get_counter_tick_core() {}

func (v *vardbapi) counter_tick_core() {}

func (v *vardbapi) _dblink() {}

func (v *vardbapi) removeFromContents() {}

func (v *vardbapi) writeContentsToContentsFile() {}

func NewVarDbApi(settings *Config, vartree *varTree) *vardbapi { // nil, nil
	v := &vardbapi{}
	e := []string{}
	for _, v := range []string{"CVS", "lost+found"} {
		e = append(e, regexp.QuoteMeta(v))
	}
	v._excluded_dirs = regexp.MustCompile("^(\\..*|" + MergingIdentifier + ".*|" + strings.Join(e, "|") + ")$")
	v._aux_cache_version = "1"
	v._owners_cache_version = "1"
	v._aux_cache_threshold = 5
	v._aux_cache_keys_re = regexp.MustCompile("^NEEDED\\..*$")
	v._aux_multi_line_re = regexp.MustCompile("^(CONTENTS|NEEDED\\..*)$")

	v._pkgs_changed = false
	v._flush_cache_enabled = true
	v.mtdircache = map[string]string{}
	v.matchcache = map[string]string{}
	v.cpcache = map[string]string{}
	v.blockers = nil
	if settings == nil {
		settings = Settings()
	}
	v.settings = settings
	v._eroot = settings.ValueDict["EROOT"]
	v._dbroot = v._eroot + VdbPath
	v._lock = ""
	v._lock_count = 0

	v._conf_mem_file = v._eroot + ConfigMemoryFile
	v._fs_lock_obj = nil
	v._fs_lock_count = 0
	v._slot_locks = map[*Atom]*struct {
		s *struct {
			string
			int
			bool
			method func(int, int) error
		}
		int
	}{}

	if vartree == nil {
		vartree = Db().valueDict[settings.ValueDict["EROOT"]].VarTree()
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
	v._aux_cache_filename = path.Join(v._eroot, CachePath, "vdb_metadata.pickle")
	v._cache_delta_filename = path.Join(v._eroot, CachePath, "vdb_metadata_delta.json")
	v._cache_delta = NewVdbMetadataDelta(v)
	v._counter_path = path.Join(v._eroot, CachePath, "counter")

	v._plib_registry = NewPreservedLibsRegistry(settings.ValueDict["ROOT"], path.Join(v._eroot, PrivatePath, "preserved_libs_registry"))
	v._linkmap = NewLinkageMapELF(v)
	v._owners = NewOwnersDb(v)

	v._cached_counter = nil

	return v
}

type _owners_db struct {
	vardb *vardbapi
}

func NewOwnersDb(vardb *vardbapi) *_owners_db {
	o := &_owners_db{}
	o.vardb = vardb
	return o
}

type varTree struct {
	settings  *Config
	populated int
	dbapi     *vardbapi
}

func (v *varTree) get_all_provides() map[string][]*pkgStr {
	return map[string][]*pkgStr{}
}

func NewVarTree(categories map[string]bool, settings *Config) *varTree {
	v := &varTree{}
	if settings == nil {
		settings = Settings()
	}
	v.settings = settings

	return v
}

type fakedbapi struct {
	*dbapi
	_exclusive_slots bool
	cpvdict          map[string]map[string]string
	cpdict           map[string][]*pkgStr
	_match_cache     map[[2]string][]*pkgStr
	_instance_key    func(cpv *pkgStr, support_string bool) *pkgStr
	_multi_instance  bool
}

func (f *fakedbapi) _set_multi_instance(multi_instance bool) {
	if len(f.cpvdict) != 0 {
		//raise AssertionError("_set_multi_instance called after "
		//"packages have already been added")
	}
	f._multi_instance = multi_instance
	if multi_instance {
		f._instance_key = f._instance_key_multi_instance
	} else {
		f._instance_key = f._instance_key_cpv
	}
}

// false
func (f *fakedbapi) _instance_key_cpv(cpv *pkgStr, support_string bool) *pkgStr {
	return cpv
}

// false
func (f *fakedbapi) _instance_key_multi_instance(cpv *pkgStr, support_string bool) *pkgStr {
	return NewPkgStr(cpv.string, nil, nil, "", "", "", cpv.buildTime, cpv.buildId, cpv.fileSize, cpv.mtime, nil)
	//except AttributeError:
	//if ! support_string{
	//	//raise
	//}
	//
	//	latest := None
	//for _, pkg := range f.cp_list(cpv_getkey(cpv)){
	//
	//	if pkg == cpv and (
	//		latest is None or
	//	latest.build_time < pkg.build_time):
	//	latest = pkg
	//}
	//
	//if latest is not None:
	//return (latest, latest.build_id, latest.file_size,
	//	latest.build_time, latest.mtime)
	//
	//raise KeyError(cpv)
}

func (f *fakedbapi) clear() {
	f._clear_cache()
	f.cpvdict = map[string]map[string]string{}
	f.cpdict = map[string][]*pkgStr{}
}

func (f *fakedbapi) _clear_cache() {
	if f._categories != nil {
		f._categories = nil
	}
	if len(f._match_cache) > 0 {
		f._match_cache = map[[2]string][]*pkgStr{}
	}
}

// 1
func (f *fakedbapi) match(origdep *Atom, use_cache int) []*pkgStr {
	atom := dep_expand(origdep, f.dbapi, 1, f.settings)
	cacheKey := [2]string{atom.value, atom.unevaluatedAtom.value}
	result := f._match_cache[cacheKey]
	if result != nil {
		return result[:]
	}
	result = f._iter_match(atom, f.cp_list(atom.cp, 1))
	f._match_cache[cacheKey] = result
	return result[:]
}

// nil
func (f *fakedbapi) cpv_exists(mycpv *pkgStr, myrepo interface{}) bool {
	_, ok := f.cpvdict[f._instance_key(mycpv,
		true).string]
	return ok
}

// 1
func (f *fakedbapi) cp_list(mycp string, use_cache int) []*pkgStr {
	cacheKey := [2]string{mycp, mycp}
	cacheList := f._match_cache[cacheKey]
	if cacheList != nil {
		return cacheList[:]
	}
	cpvList := f.cpdict[mycp]
	if cpvList == nil {
		cpvList = []*pkgStr{}
	}
	f._cpv_sort_ascending(cpvList)
	f._match_cache[cacheKey] = cpvList
	return cpvList[:]
}

// false
func (f *fakedbapi) cp_all(sortt bool) []string {
	s := []string{}
	for x := range f.cpdict {
		s = append(s, x)
	}
	if sortt {
		sort.Strings(s)
	}
	return s
}

func (f *fakedbapi) cpv_all() []string {
	if f._multi_instance {
		ss := []string{}
		for k := range f.cpvdict {
			ss = append(ss, k) // k[0]
		}
		return ss
	} else {
		ss := []string{}
		for k := range f.cpvdict {
			ss = append(ss, k)
		}
		return ss
	}
}

func (f *fakedbapi) cpv_inject(mycpv *pkgStr, metadata map[string]string) {
	f._clear_cache()

	myCp := mycpv.cp
	mySlot := mycpv.slot
	if myCp == "" || (mySlot == "" && metadata != nil && metadata["SLOT"] != "") {

		if metadata == nil {
			mycpv = NewPkgStr(mycpv.string, nil, nil, "", "", "", 0, "", "", 0, f.dbapi)
		} else {
			mycpv = NewPkgStr(mycpv.string, metadata, f.settings, "", "", "", 0, "", "", 0, f.dbapi)
		}
		myCp = mycpv.cp
		mySlot = mycpv.slot
	}

	instanceKey := f._instance_key(mycpv, false)
	f.cpvdict[instanceKey.string] = metadata
	if !f._exclusive_slots {
		mySlot = ""
	}
	if _, ok := f.cpdict[myCp]; mySlot != "" && ok {
		for _, cpv := range f.cpdict[myCp] {
			if instanceKey != f._instance_key(cpv, false) {
				otherSlot := cpv.slot
				if otherSlot != "" {
					if mySlot == otherSlot {
						f.cpv_remove(cpv)
						break
					}
				}
			}
		}
	}

	cpList := f.cpdict[myCp]
	if cpList == nil {
		cpList = []*pkgStr{}
	}
	tmp := cpList
	cpList = []*pkgStr{}
	for _, x := range tmp {
		if f._instance_key(x, false) != instanceKey {
			cpList = append(cpList, x)
		}
	}
	cpList = append(cpList, mycpv)
	f.cpdict[myCp] = cpList
}

func (f *fakedbapi) cpv_remove(mycpv *pkgStr) {
	f._clear_cache()
	myCp := cpvGetKey(mycpv.string, "")
	instanceKey := f._instance_key(mycpv, false)
	delete(f.cpvdict, instanceKey.string)
	cpList := f.cpdict[myCp]
	if cpList != nil {
		tmp := cpList
		cpList = []*pkgStr{}
		for _, x := range tmp {
			if f._instance_key(x, false) != instanceKey {
				cpList = append(cpList, x)
			}
		}
	}
	if len(cpList) != 0 {
		f.cpdict[myCp] = cpList
	} else {
		delete(f.cpdict, myCp)
	}
}

// nil
func (f *fakedbapi) aux_get(mycpv *pkgStr, wants []string) []string {
	metadata := f.cpvdict[f._instance_key(mycpv, true).string]
	if metadata == nil {
		//raise KeyError(mycpv)
	}
	ret := []string{}
	for _, x := range wants {
		ret = append(ret, metadata[x])
	}
	return ret
}

func (f *fakedbapi) aux_update(cpv *pkgStr, values map[string]string) {
	f._clear_cache()
	metadata := f.cpvdict[f._instance_key(cpv, true).string]
	if metadata == nil {
		//raise KeyError(cpv)
	}
	for k, v := range values {
		metadata[k] = v
	}
}

// nil, true, false
func NewFakeDbApi(settings *Config, exclusive_slots, multi_instance bool) *fakedbapi {
	f := &fakedbapi{dbapi: NewDbapi(), _exclusive_slots: exclusive_slots,
		cpvdict: map[string]map[string]string{},
		cpdict:  map[string][]*pkgStr{}}
	if settings == nil {
		settings = Settings()
	}
	f.settings = settings
	f._match_cache = map[[2]string][]*pkgStr{}
	f._set_multi_instance(multi_instance)
	return f
}

type bindbapi struct {
	*fakedbapi
	bintree  *BinaryTree
	move_ent func()

	_aux_chache  map[string]string
	auxCacheKeys map[string]bool
}

func (b *bindbapi) writable() bool {
	if f, err := os.Stat(firstExisting(b.bintree.pkgdir)); err != nil || f == nil {
		return false
	} else {
		return true
	}
}

func (b *bindbapi) match() {

}

func (b *bindbapi) cpv_exists(cpv, myrepo string) {}

func (b *bindbapi) cpv_inject() {}

func (b *bindbapi) cpv_remove() {}

func (b *bindbapi) aux_get() {}

func (b *bindbapi) aux_update() {}

func (b *bindbapi) cp_list() {}

func (b *bindbapi) cp_all() {}

func (b *bindbapi) cpv_all() {}

func (b *bindbapi) getfetchsizes() {}

// nil, true, false
func NewBinDbApi(mybintree *BinaryTree, settings *Config, exclusive_slots, multi_instance bool) *bindbapi { //
	b := &bindbapi{}
	b.fakedbapi = NewFakeDbApi(settings, false, true)
	b.bintree = mybintree
	b.move_ent = mybintree.move_ent
	b.auxCacheKeys = map[string]bool{}
	//b._aux_cache_slot_dict
	b._aux_chache = map[string]string{}
	return b
}

type BinaryTree struct {
	pkgdir,  _pkgindex_file , _pkgindex_header     string
	PkgIndexFile interface{}
	settings *Config
	populated, _populating, _multi_instance, _remote_has_index, _all_directory  bool
	 _pkgindex_version int
	_pkgindex_hashes , _pkgindex_keys, _pkgindex_aux_keys, _pkgindex_use_evaluated_keys, _pkgindex_inherited_keys []string
	_remotepkgs interface{}
	dbapi *bindbapi
	update_ents func(updates map[string][][]*Atom, onProgress, onUpdate func(int, int))
	move_slot_ent func(mylist []*Atom, repo_match func(string) bool) int
	tree, _additional_pkgs, _pkg_paths map[string]interface{}
	_pkgindex_header_keys, _pkgindex_allowed_pkg_keys map[string]bool
	_pkgindex_default_pkg_data, _pkgindex_default_header_data map[string]string
	_pkgindex_translated_keys [][2]string
	invalids []string
}

func (b *BinaryTree) root() string{
	return b.settings.ValueDict["ROOT"]
}

func (b *BinaryTree) move_ent() {}

func (b *BinaryTree) prevent_collision() {}

func (b *BinaryTree) _ensure_dir() {}

func (b *BinaryTree) _file_permissions() {}

// true, []string{}
func (b *BinaryTree) Populate(getbinpkg_refresh bool, add_repos []string) {
	if b._populating{
		return
	}
	if st, _ :=os.Stat(b.pkgdir) ; st!= nil && !st.IsDir() && !(getbinpkgs || len(add_repos)!=0){
		b.populated = true
		return
	}
	b._remotepkgs = nil

	b._populating = true
	defer func() {b._populating = false}()
	update_pkgindex := b._populate_local(
		reindex='pkgdir-index-trusted' not in self.settings.features)

	if update_pkgindex and self.dbapi.writable:
	pkgindex_lock = None
	try:
	pkgindex_lock = lockfile(self._pkgindex_file,
	wantnewlockfile=True)
	update_pkgindex = self._populate_local()
	if update_pkgindex:
	self._pkgindex_write(update_pkgindex)
	finally:
	if pkgindex_lock:
	unlockfile(pkgindex_lock)

	if add_repos:
	self._populate_additional(add_repos)

	if getbinpkgs:
	if not self.settings.get("PORTAGE_BINHOST"):
	writemsg(_("!!! PORTAGE_BINHOST unset, but use is requested.\n"),
	noiselevel=-1)
	else:
	self._populate_remote(getbinpkg_refresh=getbinpkg_refresh)

	b.populated = true

}

// true
func (b *BinaryTree) _populate_local(reindex bool) {
	b.dbapi.clear()

	_instance_key := b.dbapi._instance_key

	minimum_keys := []string{}
	for _, k := range b._pkgindex_keys {
		in := false
		for _,k2 := range b._pkgindex_hashes{
			if k == k2{
				in = true
				break
			}
		}
		if !in {
			minimum_keys = append(minimum_keys, k)
		}
	}
	pkg_paths := map[string]interface{}{}
	b._pkg_paths = pkg_paths
	dir_files := map[string][]string{}
	if reindex {
		filepath.Walk(b.pkgdir, func(path string, info os.FileInfo, err error) error {
			if info.IsDir(){
				return nil
			}
			dir_files[filepath.Dir(path)] = append(dir_files[filepath.Dir(path)], filepath.Base(path))
			return nil
		})
	}

	pkgindex := b.LoadPkgIndex()
	if not self._pkgindex_version_supported(pkgindex):
	pkgindex = self._new_pkgindex()
	metadata = {}
	basename_index = {}
	for d in pkgindex.packages:
	cpv = _pkg_str(d["CPV"], metadata=d,
		settings=self.settings, db=self.dbapi)
	d["CPV"] = cpv
	metadata[_instance_key(cpv)] = d
	path = d.get("PATH")
	if not path:
	path = cpv + ".tbz2"

	if reindex:
	basename = os.path.basename(path)
	basename_index.setdefault(basename, []).append(d)
	else:
	instance_key = _instance_key(cpv)
	pkg_paths[instance_key] = path
	self.dbapi.cpv_inject(cpv)

	update_pkgindex = False
	for mydir, file_names in dir_files.items():
try:
	mydir = _unicode_decode(mydir,
		encoding=_encodings["fs"], errors="strict")
	except UnicodeDecodeError:
	continue
	for myfile in file_names:
try:
	myfile = _unicode_decode(myfile,
		encoding=_encodings["fs"], errors="strict")
	except UnicodeDecodeError:
	continue
	if not myfile.endswith(SUPPORTED_XPAK_EXTENSIONS):
	continue
	mypath = os.path.join(mydir, myfile)
	full_path = os.path.join(self.pkgdir, mypath)
	s = os.lstat(full_path)

	if not stat.S_ISREG(s.st_mode):
	continue

	# Validate data from the package index and try to avoid
	# reading the xpak if possible.
		possibilities = basename_index.get(myfile)
	if possibilities:
	match = None
	for d in possibilities:
try:
	if long(d["_mtime_"]) != s[stat.ST_MTIME]:
	continue
	except (KeyError, ValueError):
	continue
try:
	if long(d["SIZE"]) != long(s.st_size):
	continue
	except (KeyError, ValueError):
	continue
	if not minimum_keys.difference(d):
	match = d
	break
	if match:
	mycpv = match["CPV"]
	instance_key = _instance_key(mycpv)
	pkg_paths[instance_key] = mypath
	oldpath = d.get("PATH")
	if oldpath and oldpath != mypath:
	update_pkgindex = True
	if mypath != mycpv + ".tbz2":
	d["PATH"] = mypath
	if not oldpath:
	update_pkgindex = True
	else:
	d.pop("PATH", None)
	if oldpath:
	update_pkgindex = True
	self.dbapi.cpv_inject(mycpv)
	continue
	if not os.access(full_path, os.R_OK):
	writemsg(_("!!! Permission denied to read " \
	"binary package: '%s'\n") % full_path,
	noiselevel=-1)
	self.invalids.append(myfile[:-5])
	continue
	pkg_metadata = self._read_metadata(full_path, s,
	keys=chain(self.dbapi._aux_cache_keys,
	("PF", "CATEGORY")))
	mycat = pkg_metadata.get("CATEGORY", "")
	mypf = pkg_metadata.get("PF", "")
	slot = pkg_metadata.get("SLOT", "")
	mypkg = myfile[:-5]
	if not mycat or not mypf or not slot:
	writemsg(_("\n!!! Invalid binary package: '%s'\n") % full_path,
	noiselevel=-1)
	missing_keys = []
	if not mycat:
	missing_keys.append("CATEGORY")
	if not mypf:
	missing_keys.append("PF")
	if not slot:
	missing_keys.append("SLOT")
	msg = []
	if missing_keys:
	missing_keys.sort()
	msg.append(_("Missing metadata key(s): %s.") % \
	", ".join(missing_keys))
	msg.append(_(" This binary package is not " \
	"recoverable and should be deleted."))
	for line in textwrap.wrap("".join(msg), 72):
	writemsg("!!! %s\n" % line, noiselevel=-1)
	self.invalids.append(mypkg)
	continue

	multi_instance = False
	invalid_name = False
	build_id = None
	if myfile.endswith(".xpak"):
	multi_instance = True
	build_id = self._parse_build_id(myfile)
	if build_id < 1:
	invalid_name = True
	elif myfile != "%s-%s.xpak" % (
	mypf, build_id):
	invalid_name = True
	else:
	mypkg = mypkg[:-len(str(build_id))-1]
	elif myfile != mypf + ".tbz2":
	invalid_name = True

	if invalid_name:
	writemsg(_("\n!!! Binary package name is "
	"invalid: '%s'\n") % full_path,
	noiselevel=-1)
	continue

	if pkg_metadata.get("BUILD_ID"):
	try:
	build_id = long(pkg_metadata["BUILD_ID"])
	except ValueError:
	writemsg(_("!!! Binary package has "
	"invalid BUILD_ID: '%s'\n") %
	full_path, noiselevel=-1)
	continue
	else:
	build_id = None

	if multi_instance:
	name_split = catpkgsplit("%s/%s" %
	(mycat, mypf))
	if (name_split is None or
	tuple(catsplit(mydir)) != name_split[:2]):
	continue
	elif mycat != mydir and mydir != "All":
	continue
	if mypkg != mypf.strip():
	continue
	mycpv = mycat + "/" + mypkg
	if not self.dbapi._category_re.match(mycat):
	writemsg(_("!!! Binary package has an " \
	"unrecognized category: '%s'\n") % full_path,
	noiselevel=-1)
	writemsg(_("!!! '%s' has a category that is not" \
	" listed in %setc/portage/categories\n") % \
	(mycpv, self.settings["PORTAGE_CONFIGROOT"]),
	noiselevel=-1)
	continue
	if build_id is not None:
	pkg_metadata["BUILD_ID"] = _unicode(build_id)
	pkg_metadata["SIZE"] = _unicode(s.st_size)
	# Discard items used only for validation above.
	pkg_metadata.pop("CATEGORY")
	pkg_metadata.pop("PF")
	mycpv = _pkg_str(mycpv,
	metadata=self.dbapi._aux_cache_slot_dict(pkg_metadata),
	db=self.dbapi)
	pkg_paths[_instance_key(mycpv)] = mypath
	self.dbapi.cpv_inject(mycpv)
	update_pkgindex = True
	d = metadata.get(_instance_key(mycpv),
	pkgindex._pkg_slot_dict())
	if d:
	try:
	if long(d["_mtime_"]) != s[stat.ST_MTIME]:
	d.clear()
	except (KeyError, ValueError):
	d.clear()
	if d:
	try:
	if long(d["SIZE"]) != long(s.st_size):
	d.clear()
	except (KeyError, ValueError):
	d.clear()

	for k in self._pkgindex_allowed_pkg_keys:
	v = pkg_metadata.get(k)
	if v:
	d[k] = v
	d["CPV"] = mycpv

	try:
	self._eval_use_flags(mycpv, d)
	except portage.exception.InvalidDependString:
	writemsg(_("!!! Invalid binary package: '%s'\n") % \
	self.getname(mycpv), noiselevel=-1)
	self.dbapi.cpv_remove(mycpv)
	del pkg_paths[_instance_key(mycpv)]

	# record location if it's non-default
	if mypath != mycpv + ".tbz2":
	d["PATH"] = mypath
	else:
	d.pop("PATH", None)
	metadata[_instance_key(mycpv)] = d

	if reindex:
	for instance_key in list(metadata):
	if instance_key not in pkg_paths:
	del metadata[instance_key]

	if update_pkgindex:
	del pkgindex.packages[:]
	pkgindex.packages.extend(iter(metadata.values()))
	self._update_pkgindex_header(pkgindex.header)

	self._pkgindex_header = {}
	self._merge_pkgindex_header(pkgindex.header,
	self._pkgindex_header)

	return pkgindex if update_pkgindex else None

}

func (b *BinaryTree) _populate_remote() {}

func (b *BinaryTree) inject() {}

func (b *BinaryTree) _read_metadata() {}

func (b *BinaryTree) _inject_file() {}

func (b *BinaryTree) _pkgindex_write() {}

func (b *BinaryTree) _pkgindex_entry() {}

func (b *BinaryTree) _new_pkgindex() {}

func (b *BinaryTree) _merge_pkgindex_header() {}

func (b *BinaryTree) _propagate_config() {}

func (b *BinaryTree) _update_pkgindex_header() {}

func (b *BinaryTree) _pkgindex_version_supported() {}

func (b *BinaryTree) _eval_use_flags() {}

func (b *BinaryTree) exists_specific() {}

func (b *BinaryTree) dep_bestmatch() {}

// nil
func (b *BinaryTree) getname(cpv, allocate_new string) {

}

func (b *BinaryTree) _is_specific_instance() {}

func (b *BinaryTree) _max_build_id() {}

func (b *BinaryTree) _allocate_filename() {}

func (b *BinaryTree) _allocate_filename_multi() {}

func (b *BinaryTree) _parse_build_id() {}

func (b *BinaryTree) isremote() {}

func (b *BinaryTree) get_pkgindex_uri() {}

func (b *BinaryTree) gettbz2() {}

func (b *BinaryTree) LoadPkgIndex() interface{} { return nil }

func (b *BinaryTree) _get_digests() {}

func (b *BinaryTree) digestCheck() {}

func (b *BinaryTree) getslot() {}

func NewBinaryTree(pkgDir string, settings *Config) *BinaryTree {
	b := &BinaryTree{}
	if pkgDir == "" {
		//raise TypeError("pkgdir parameter is required")
	}
	if settings != nil {
		//raise TypeError("settings parameter is required")
	}

	b.pkgdir = NormalizePath(pkgDir)
	b._multi_instance = settings.Features.Features["binpkg-multi-instance"]
	if b._multi_instance{
		b._allocate_filename = b._allocate_filename_multi
	}
	b.dbapi = NewBinDbApi(b, settings, true, false)
	b.update_ents = b.dbapi.update_ents
	b.move_slot_ent = b.dbapi.move_slot_ent
	b.populated = false
	b.tree = map[string]interface{}{}
	b._remote_has_index = false
	b._remotepkgs = nil
	b._additional_pkgs = map[string]interface{}{}
	b.invalids = []string{}
	b.settings = settings
	b._pkg_paths = map[string]interface{}{}
	b._populating = false
	st, err := os.Stat(path.Join(b.pkgdir, "All"))
	b._all_directory = err != nil && st.IsDir()
	b._pkgindex_version = 0
	b._pkgindex_hashes = []string{"MD5","SHA1"}
	b._pkgindex_file = path.Join(b.pkgdir, "Packages")
	b._pkgindex_keys = b.dbapi._aux_cache_keys.copy()
	b._pkgindex_keys["CPV"] = true
	b._pkgindex_keys["SIZE"] = true
	b._pkgindex_aux_keys = []string{"BASE_URI", "BDEPEND", "BUILD_ID", "BUILD_TIME", "CHOST",
	"DEFINED_PHASES", "DEPEND", "DESCRIPTION", "EAPI",
	"IUSE", "KEYWORDS", "LICENSE", "PDEPEND",
	"PKGINDEX_URI", "PROPERTIES", "PROVIDES",
	"RDEPEND", "repository", "REQUIRES", "RESTRICT",
	"SIZE", "SLOT", "USE"}
	b._pkgindex_aux_keys = list(b._pkgindex_aux_keys)
	b._pkgindex_use_evaluated_keys = []string{"BDEPEND", "DEPEND", "LICENSE", "RDEPEND",
	"PDEPEND", "PROPERTIES", "RESTRICT"}
	b._pkgindex_header = ""

	b._pkgindex_header_keys = map[string]bool{}
	for _, k := range []string{
		"ACCEPT_KEYWORDS", "ACCEPT_LICENSE",
		"ACCEPT_PROPERTIES", "ACCEPT_RESTRICT", "CBUILD",
		"CONFIG_PROTECT", "CONFIG_PROTECT_MASK", "FEATURES",
		"GENTOO_MIRRORS", "INSTALL_MASK", "IUSE_IMPLICIT", "USE",
		"USE_EXPAND", "USE_EXPAND_HIDDEN", "USE_EXPAND_IMPLICIT",
		"USE_EXPAND_UNPREFIXED"}{
		b._pkgindex_header_keys[k] =true
	}

	b._pkgindex_default_pkg_data = map[string]string{
	"BDEPEND" : "",
	"BUILD_ID"           : "",
	"BUILD_TIME"         : "",
	"DEFINED_PHASES"     : "",
	"DEPEND"  : "",
	"EAPI"    : "0",
	"IUSE"    : "",
	"KEYWORDS": "",
	"LICENSE" : "",
	"PATH"    : "",
	"PDEPEND" : "",
	"PROPERTIES" : "",
	"PROVIDES": "",
	"RDEPEND" : "",
	"REQUIRES": "",
	"RESTRICT": "",
	"SLOT"    : "0",
	"USE"     : "",
	}
	b._pkgindex_inherited_keys = []string{"CHOST", "repository"}

	b._pkgindex_default_header_data = map[string]string{
	"CHOST"        : b.settings.ValueDict["CHOST"],
	"repository"   : "",
	}

	b._pkgindex_translated_keys = [][2]string{
		{"DESCRIPTION", "DESC"},
	{"_mtime_", "MTIME"},
		{"repository", "REPO"},
	}

	b._pkgindex_allowed_pkg_keys = map[string]bool{}
	for _, v := range b._pkgindex_keys{
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_keys{
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_aux_keys{
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_hashes{
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for v := range b._pkgindex_default_pkg_data{
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_inherited_keys{
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_translated_keys{
		b._pkgindex_allowed_pkg_keys[v[0]] = true
		b._pkgindex_allowed_pkg_keys[v[1]] = true
	}
	return b
}

type portdbapi struct {
	*dbapi
}

func NewPortDbApi() *portdbapi {
	p := &portdbapi{}
	return p
}

type PortageTree struct {
}

func NewPortageTree(setting *Config) *PortageTree {
	p := &PortageTree{}
	return p
}
