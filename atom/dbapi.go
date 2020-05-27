package atom

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
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
func dep_expandS(mydep string, mydb *dbapi, use_cache int, settings *Config) *Atom {
	orig_dep := mydep
	if mydep == "" {
		return nil
	}
	if mydep[0] == '*' {
		mydep = mydep[1:]
		orig_dep = mydep
	}
	has_cat := strings.Contains(strings.Split(orig_dep, ":")[0], "/")
	if !has_cat {
		re := regexp.MustCompile("\\w")
		alphanum := re.FindStringSubmatchIndex(orig_dep)
		if len(alphanum) > 0 {
			mydep = orig_dep[:alphanum[0]] + "null/" + orig_dep[alphanum[0]:]
		}
	}
	allow_repo := true
	mydepA, err := NewAtom(mydep, nil, false, &allow_repo, nil, "", nil, nil)
	if err != nil {
		//except InvalidAtom:
		if !isValidAtom("="+mydep, false, false, true, "", false) {
			//raise
		}
		mydepA, _ = NewAtom("="+mydep, nil, false, &allow_repo, nil, "", nil, nil)
		orig_dep = "=" + orig_dep
	}

	if !has_cat {
		mydep = catsplit(mydepA.cp)[1]
	}

	if has_cat {

		if strings.HasPrefix(mydepA.cp, "virtual/") {
			return mydepA
		}
		if len(mydb.cp_list(mydepA.cp, 1)) > 0 {
			return mydepA
		}
		mydep = mydepA.cp
	}

	expanded := cpv_expand(mydep, mydb, use_cache, settings)
	r := true
	a, _ := NewAtom(strings.Replace(mydep, orig_dep, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}

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

type DBAPI interface {
	categories() []string
	close_caches()
	cp_list(cp string, useCache int) []*pkgStr
	_cmp_cpv(cpv1, cpv2 *pkgStr) int
	_cpv_sort_ascending(cpv_list []*pkgStr)
	cpv_all() []*pkgStr
	auxGet(myCpv *pkgStr, myList []string, myRepo string) []string
	auxUpdate(cpv string, metadataUpdates map[string]string)
	match(origdep *Atom, useCache int) []*pkgStr
	_iter_match(atom *Atom, cpvIter []*pkgStr) []*pkgStr
	_pkg_str(cpv *pkgStr, repo string) *pkgStr
	_iter_match_repo(atom *Atom, cpvIter []*pkgStr) []*pkgStr
	_iter_match_slot(atom *Atom, cpvIter []*pkgStr) []*pkgStr
	_iter_match_use(atom *Atom, cpvIter []*pkgStr) []*pkgStr
	_repoman_iuse_implicit_cnstr(pkg, metadata map[string]string) func(flag string) bool
	_iuse_implicit_cnstr(pkg *pkgStr, metadata map[string]string) func(string) bool
	_match_use(atom *Atom, pkg *pkgStr, metadata map[string]string, ignore_profile bool) bool
	invalidentry(mypath string)
	update_ents(updates map[string][][]*Atom, onProgress, onUpdate func(int, int))
	move_slot_ent(mylist []*Atom, repo_match func(string) bool) int
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

//1
func (d *dbapi) cp_list(cp string, useCache int) []*pkgStr {
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
	if atom.unevaluatedAtom.Use != nil {
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

// false
func (d *dbapi) _match_use(atom *Atom, pkg *pkgStr, metadata map[string]string, ignore_profile bool) bool {
	iuseImplicitMatch := d._iuse_implicit_cnstr(pkg, metadata)
	useAliases := d.settings.useManager.getUseAliases(pkg)
	iuse := NewIUse("", strings.Fields(metadata["IUSE"]), iuseImplicitMatch, useAliases, metadata["EAPI"])

	for x := range atom.unevaluatedAtom.Use.required {
		if iuse.getRealFlag(x) == "" {
			return false
		}
	}

	if atom.Use == nil {
	} else if !d._use_mutable {
		use := map[string]bool{}
		for _, x := range strings.Fields(metadata["USE"]) {
			if iuse.getRealFlag(x) != "" {
				use[x] = true
			}
		}
		missingEnabled := map[string]bool{}
		for x := range atom.Use.missingEnabled {
			if iuse.getRealFlag(x) == "" {
				missingEnabled[x] = true
			}
		}
		missingDisabled := map[string]bool{}
		for x := range atom.Use.missingDisabled {
			if iuse.getRealFlag(x) == "" {
				missingDisabled[x] = true
			}
		}
		enabled := map[string]bool{}
		for x := range atom.Use.enabled {
			if iuse.getRealFlag(x) != "" {
				enabled[iuse.getRealFlag(x)] = true
			} else {
				enabled[x] = true
			}
		}
		disabled := map[string]bool{}
		for x := range atom.Use.disabled {
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
			for x := range atom.Use.enabled {
				for y := range useMask {
					if x == y.value {
						return false
					}
				}
			}
			useForce := d.settings._getUseForce(pkg, d.settings.parentStable)
			for x := range atom.Use.disabled {
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

		if len(atom.Use.enabled) > 0 {
			for x := range atom.Use.missingDisabled {
				if iuse.getRealFlag(x) == "" {
					if atom.Use.enabled[x] {
						return false
					}
				}
			}
		}
		if len(atom.Use.disabled) > 0 {
			for x := range atom.Use.missingEnabled {
				if iuse.getRealFlag(x) == "" {
					if atom.Use.disabled[x] {
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
		pkg := NewPkgStr(cpv.string, metadata, d.settings, "", "", "", 0, 0, "", 0, nil)
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
	_aux_cache_version, _owners_cache_version              int
	_lock                                                  string
	_aux_cache_threshold                                   int

	_pkgs_changed, _flush_cache_enabled bool
	matchcache                          map[string]map[[2]*Atom][]*pkgStr
	blockers                            map[string]string
	cpcache                             map[string]struct {
		int64
		p []*pkgStr
	}
	mtdircache                                                                                 map[string]int
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
	_aux_cache_obj *struct {
		version  int
		packages map[string]*struct {
			cache_mtime int64
			metadata    map[string]string
		}
		owners *struct {
			base_names map[string]string
			version    int
		}
		modified map[string]bool
	}
	_cached_counter             interface{}
	_lock_count, _fs_lock_count int
	vartree                     *varTree
	_aux_cache_keys             map[string]bool
	_cache_delta                *vdbMetadataDelta
	_plib_registry              *preservedLibsRegistry
	_linkmap                    *linkageMapELF
	_owners                     *_owners_db
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
		a, b, c, d, _ := Lockfile(v._conf_mem_file, false, false, "", 0)
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
		Unlockfile(v._fs_lock_obj.string, v._fs_lock_obj.int, v._fs_lock_obj.bool, v._fs_lock_obj.method)
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
		a, b, c, d, _ := Lockfile(lock_path, true, false, "", 0)
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
		Unlockfile(lock.string, lock.int, lock.bool, lock.method)
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
		WriteMsgLevel(fmt.Sprintf("portage: COUNTER for %s was corrupted; resetting to value of 0\n", mycpv.string), 40, -1)
		return 0
	}
	return s
}

func (v *vardbapi) cpv_inject(mycpv *pkgStr) {
	ensureDirs(v.getpath(mycpv.string, ""), -1, -1, -1, -1, nil, true)
	counter := v.counter_tick()
	write_atomic(v.getpath(mycpv.string, "COUNTER"), string(counter), 0, true)
}

func (v *vardbapi) isInjected(mycpv string) bool {
	if v.cpv_exists(mycpv, "") {
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
func (v *vardbapi) move_ent(mylist []*Atom, repo_match func(string) bool) int {
	origcp := mylist[1]
	newcp := mylist[2]

	for _, atom := range []*Atom{origcp, newcp} {
		if !isJustName(atom.value) {
			//raise InvalidPackageName(str(atom))
		}
	}
	origmatches := v.match(origcp, 0)
	moves := 0
	if len(origmatches) == 0 {
		return moves
	}
	for _, mycpv := range origmatches {
		mycpv = v._pkg_str(mycpv, "")
		mycpv_cp := cpvGetKey(mycpv.string, "")
		if mycpv_cp != origcp.value {
			continue
		}
		if repo_match != nil && !repo_match(mycpv.repo) {
			continue
		}

		if !isValidAtom(newcp.value, false, false, false, mycpv.eapi, false) {
			continue
		}

		mynewcpv := strings.Replace(mycpv.string, mycpv_cp, newcp.value, 1)
		mynewcat := catsplit(newcp.value)[0]
		origpath := v.getpath(mycpv.string, "")
		if _, err := os.Stat(origpath); err != nil {
			continue
		}
		moves += 1
		if _, err := os.Stat(v.getpath(mynewcat, "")); err != nil {
			ensureDirs(v.getpath(mynewcat, ""), -1, -1, -1, -1, nil, true)
		}
		newpath := v.getpath(mynewcpv, "")
		if _, err := os.Stat(newpath); err == nil {
			continue
		}
		_movefile(origpath, newpath, 0, nil, v.settings, nil)
		v._clear_pkg_cache(v._dblink(mycpv.string))
		v._clear_pkg_cache(v._dblink(mynewcpv))

		old_pf := catsplit(mycpv.string)[1]
		new_pf := catsplit(mynewcpv)[1]
		if new_pf != old_pf {
			err := os.Rename(path.Join(newpath, old_pf+".ebuild"),
				path.Join(newpath, new_pf+".ebuild"))
			if err != nil {
				if err != syscall.ENOENT {
					//raise
				}
				//del e
			}
		}
		write_atomic(path.Join(newpath, "PF"), new_pf+"\n", 0, true)
		write_atomic(path.Join(newpath, "CATEGORY"), mynewcat+"\n", 0, true)
	}
	return moves
}

func (v *vardbapi) cp_list(mycp string, use_cache int) []*pkgStr {
	mysplit := catsplit(mycp)
	if mysplit[0] == "*" {
		mysplit[0] = mysplit[0][1:]
	}
	mystatt, err := os.Stat(v.getpath(mysplit[0], ""))

	mystat := int64(0)
	if err == nil {
		mystat = mystatt.ModTime().UnixNano()
	}
	if cpc, ok := v.cpcache[mycp]; use_cache != 0 && ok {
		if cpc.int64 == mystat {
			return cpc.p
		}
	}
	cat_dir := v.getpath(mysplit[0], "")
	dir_list, err := ioutil.ReadDir(cat_dir)
	if err != nil {
		if err == syscall.EPERM {
			//raise PermissionDenied(cat_dir)
		}
		dir_list = []os.FileInfo{}
	}

	returnme := []*pkgStr{}
	for _, x := range dir_list {
		if v._excluded_dirs.MatchString(x.Name()) {
			continue
		}
		ps := PkgSplit(x.Name(), 1, "")
		if ps == [3]string{} {
			v.invalidentry(path.Join(v.getpath(mysplit[0], ""), x.Name()))
			continue
		}
		if len(mysplit) > 1 {
			if ps[0] == mysplit[1] {
				cpv := fmt.Sprintf("%s/%s", mysplit[0], x)
				metadata := map[string]string{}
				for i := range v._aux_cache_keys {
					metadata[i] = v.aux_get(cpv, v._aux_cache_keys, "")[0]
				}
				returnme = append(returnme, NewPkgStr(cpv, metadata,
					v.settings, "", "", "", 0, 0, "", 0, v.dbapi))
			}
		}
	}
	v._cpv_sort_ascending(returnme)
	if use_cache != 0 {
		v.cpcache[mycp] = struct {
			int64
			p []*pkgStr
		}{mystat, returnme}

	} else if _, ok := v.cpcache[mycp]; ok {
		delete(v.cpcache, mycp)
	}
	return returnme
}

// 1
func (v *vardbapi) cpv_all(use_cache int) []*pkgStr {
	return v._iter_cpv_all(use_cache != 0, false)
}

// true, true
func (v *vardbapi) _iter_cpv_all(use_cache, sort1 bool) []*pkgStr {
	basepath := filepath.Join(v._eroot, VdbPath) + string(filepath.Separator)
	listdir := listdir
	if !use_cache {
		listdir = func(mypath string, recursive, filesonly, ignorecvs bool, ignorelist []string, followSymlinks, EmptyOnError, dirsonly bool) []string {
			ss, err := ioutil.ReadDir(mypath)
			if err != nil {
				//except EnvironmentError as e:
				//if e.errno == PermissionDenied.errno:
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
	catdirs := listdir(basepath, false, false, true, []string{}, true, true, true)
	if sort1 {
		sort.Strings(catdirs)
	}

	ps := []*pkgStr{}
	for _, x := range catdirs {
		if v._excluded_dirs.MatchString(x) {
			continue
		}
		if !v._category_re.MatchString(x) {
			continue
		}
		pkgdirs := listdir(basepath+x, false, false, false, []string{}, true, true, true)
		if sort1 {
			sort.Strings(pkgdirs)
		}

		for _, y := range pkgdirs {
			if v._excluded_dirs.MatchString(y) {
				continue
			}
			subpath := x + "/" + y
			subpathP := NewPkgStr(subpath, nil, nil, "", "", "", 0, 0, "", 0, v.dbapi)
			//except InvalidData:
			//v.invalidentry(v.getpath(subpath))
			//continue

			ps = append(ps, subpathP)
		}
	}
	return ps
}

// 1, false
func (v *vardbapi) cp_all(use_cache int, sort1 bool) []string {
	mylist := v.cpv_all(use_cache)
	d := map[string]bool{}
	for _, y := range mylist {
		if y.string[0] == '*' {
			y.string = y.string[1:]
		}
		//try:
		mysplit := catPkgSplit(y.string, 1, "")
		//except InvalidData:
		//v.invalidentry(v.getpath(y))
		//continue
		if mysplit == [4]string{} {
			v.invalidentry(v.getpath(y.string, ""))
			continue
		}
		d[mysplit[0]+"/"+mysplit[1]] = true
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
	v.matchcache = map[string]map[[2]*Atom][]*pkgStr{}
	v.cpcache = map[string]struct {
		int64
		p []*pkgStr
	}{}
	v._aux_cache_obj = nil
}

func (v *vardbapi) _add(pkg_dblink *dblink) {
	v._pkgs_changed = true
	v._clear_pkg_cache(pkg_dblink)
}

func (v *vardbapi) _remove(pkg_dblink *dblink) {
	v._pkgs_changed = true
	v._clear_pkg_cache(pkg_dblink)
}

func (v *vardbapi) _clear_pkg_cache(pkg_dblink *dblink) {
	delete(v.mtdircache, pkg_dblink.cat)
	delete(v.matchcache, pkg_dblink.cat)
	delete(v.cpcache, pkg_dblink.mysplit[0])
	// TODO: already deprecated?
	//delete(dircache,pkg_dblink.dbcatdir)
}

// 1
func (v *vardbapi) match(origdep *Atom, use_cache int) []*pkgStr {
	mydep := dep_expand(origdep, v.dbapi, use_cache, v.settings)
	cache_key := [2]*Atom{mydep, mydep.unevaluatedAtom}
	mykey := depGetKey(mydep.value)
	mycat := catsplit(mykey)[0]
	if use_cache == 0 {
		if _, ok := v.matchcache[mykey]; ok {
			delete(v.mtdircache, mycat)
			delete(v.matchcache, mycat)
		}
		return v._iter_match(mydep,
			v.cp_list(mydep.cp, use_cache))
	}
	st, err := os.Stat(path.Join(v._eroot, VdbPath, mycat))
	curmtime := 0
	if err == nil {
		curmtime = st.ModTime().Nanosecond()
	}

	if _, ok := v.matchcache[mycat]; !ok || v.mtdircache[mycat] != curmtime {
		v.mtdircache[mycat] = curmtime
		v.matchcache[mycat] = map[[2]*Atom][]*pkgStr{}
	}
	if _, ok := v.matchcache[mycat][[2]*Atom{mydep, nil}]; !ok {
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

func (v *vardbapi) _aux_cache() *struct {
	version  int
	packages map[string]*struct {
		cache_mtime int64
		metadata    map[string]string
	}
	owners *struct {
		base_names map[string]string
		version    int
	}
	modified map[string]bool
} {
	if v._aux_cache_obj == nil {
		v._aux_cache_init()
	}
	return v._aux_cache_obj
}

func (v *vardbapi) _aux_cache_init() {

	//TODO: pickle
	//aux_cache := None
	//open_kwargs := {}
	//try:
	//	with open(_unicode_encode(self._aux_cache_filename,
	//		encoding=_encodings['fs'], errors='strict'),
	//		mode='rb', **open_kwargs) as f:
	//		mypickle = pickle.Unpickler(f)
	//		try:
	//			mypickle.find_global = None
	//		except AttributeError:
	//			# TODO: If py3k, override Unpickler.find_class().
	//			pass
	//		aux_cache = mypickle.load()
	//except (SystemExit, KeyboardInterrupt):
	//	raise
	//except Exception as e:
	//	if isinstance(e, EnvironmentError) and \
	//		getattr(e, 'errno', None) in (errno.ENOENT, errno.EACCES):
	//		pass
	//	else:
	//		writemsg(_("!!! Error loading '%s': %s\n") % \
	//			(self._aux_cache_filename, e), noiselevel=-1)
	//	del e

	aux_cache := &struct {
		version  int
		packages map[string]*struct {
			cache_mtime int64
			metadata    map[string]string
		}
		owners *struct {
			base_names map[string]string
			version    int
		}
		modified map[string]bool
	}{version: v._aux_cache_version}
	aux_cache.packages = map[string]*struct {
		cache_mtime int64
		metadata    map[string]string
	}{}

	owners := aux_cache.owners
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
			base_names map[string]string
			version    int
		}{base_names: map[string]string{}, version: v._owners_cache_version}
		aux_cache.owners = owners
	}
	aux_cache.modified = map[string]bool{}
	v._aux_cache_obj = aux_cache
}

// nil
func (v *vardbapi) aux_get(mycpv string, wants map[string]bool, myrepo string) []string {
	cache_these_wants := map[string]bool{}
	for k := range v._aux_cache_keys {
		if wants[k] {
			cache_these_wants[k] = true
		}
	}
	for x := range wants {
		if v._aux_cache_keys_re.MatchString(x) {
			cache_these_wants[x] = true
		}
	}

	if len(cache_these_wants) == 0 {
		mydata := v._aux_get(mycpv, wants, nil)
		ret := []string{}
		for x := range wants {
			ret = append(ret, mydata[x])
		}
		return ret
	}

	cache_these := map[string]bool{}
	for k := range v._aux_cache_keys {
		cache_these[k] = true
	}
	for k := range cache_these_wants {
		cache_these[k] = true
	}

	mydir := v.getpath(mycpv, "")
	mydir_stat, err := os.Stat(mydir)
	if err != nil {
		//except OSError as e:
		if err != syscall.ENOENT {
			//raise
		}
		//raise KeyError(mycpv)
	}
	mydir_mtime := mydir_stat.ModTime().UnixNano()
	pkg_data := v._aux_cache().packages[mycpv]
	pull_me := map[string]bool{}
	for k := range cache_these {
		pull_me[k] = true
	}
	for k := range wants {
		pull_me[k] = true
	}
	mydata := map[string]string{"_mtime_": fmt.Sprint(mydir_mtime)}
	cache_valid := false
	cache_mtime := int64(0)
	var metadata map[string]string = nil

	if pkg_data != nil {
		cache_mtime, metadata = pkg_data.cache_mtime, pkg_data.metadata
		if cache_mtime == mydir_stat.ModTime().UnixNano() {
			cache_valid = true
		} else if cache_mtime == mydir_stat.ModTime().UnixNano() {
			cache_valid = true
		} else {
			cache_valid = cache_mtime == mydir_stat.ModTime().UnixNano()
		}
	}
	if cache_valid {
		for k, v := range metadata {
			mydata[k] = v
		}
		for k := range mydata {
			delete(pull_me, k)
		}
	}

	if len(pull_me) > 0 {
		aux_keys := CopyMapSB(pull_me)
		for k, v := range v._aux_get(mycpv, aux_keys, mydir_stat) {
			mydata[k] = v
		}
		df := map[string]bool{}
		for k := range cache_these {
			if _, ok := metadata[k]; !ok {
				df[k] = true
			}
		}
		if !cache_valid || len(df) > 0 {
			cache_data := map[string]string{}
			if cache_valid && len(metadata) > 0 {
				for k, v := range metadata {
					cache_data[k] = v
				}
			}
			for aux_key := range cache_these {
				cache_data[aux_key] = mydata[aux_key]
			}
			v._aux_cache().packages[mycpv] = &struct {
				cache_mtime int64
				metadata    map[string]string
			}{mydir_mtime, cache_data}
			v._aux_cache().modified[mycpv] = true
		}
	}

	eapi_attrs := getEapiAttrs(mydata["EAPI"])
	if !getSlotRe(eapi_attrs).MatchString(mydata["SLOT"]) {
		mydata["SLOT"] = "0"
	}

	ret := []string{}
	for x := range wants {
		ret = append(ret, mydata[x])
	}

	return ret
}

// nil
func (v *vardbapi) _aux_get(mycpv string, wants map[string]bool, st os.FileInfo) map[string]string {
	mydir := v.getpath(mycpv, "")
	if st == nil {
		var err error
		st, err = os.Stat(mydir)
		if err != nil {
			//except OSError as e:
			if err == syscall.ENOENT {
				//raise KeyError(mycpv)
			}
			//elif e.errno == PermissionDenied.errno:
			//raise PermissionDenied(mydir)
			//else:
			//raise
		}
	}
	if !st.IsDir() {
		//raise KeyError(mycpv)
	}
	results := map[string]string{}
	env_keys := []string{}
	for x := range wants {
		if x == "_mtime_" {
			results[x] = fmt.Sprint(st.ModTime().UnixNano())
			continue
		}
		myd, err := ioutil.ReadFile(path.Join(mydir, x))
		if err != nil {
			//except IOError:
			if !v._aux_cache_keys[x] && !v._aux_cache_keys_re.MatchString(x) {
				env_keys = append(env_keys, x)
				continue
			}
			myd = []byte("")
		}

		if !v._aux_multi_line_re.MatchString(x) {
			myd = []byte(strings.Join(strings.Fields(string(myd)), " "))
		}

		results[x] = string(myd)
	}

	if len(env_keys) > 0 {
		env_results := v._aux_env_search(mycpv, env_keys)
		for _, k := range env_keys {
			va := env_results[k]
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

func (v *vardbapi) _aux_env_search(cpv, variables string) {}

func (v *vardbapi) aux_update() {}

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
			WriteMsg(fmt.Sprintf("!!! COUNTER file is corrupt: '%s'\n", v._counter_path), -1, nil)
			WriteMsg(fmt.Sprintf("!!! %s\n", err2), -1, nil)
		}
	}
	if err != nil {
		//except EnvironmentError as e:
		if err != syscall.ENOENT {
			WriteMsg(fmt.Sprintf("!!! Unable to read COUNTER file: '%s'\n", v._counter_path), -1, nil)
			WriteMsg(fmt.Sprintf("!!! %s\n", err), -1, nil)
		}
	}

	max_counter := counter
	if v._cached_counter != counter {
		for _, cpv := range v.cpv_all(1) {
			//try:
			pkg_counter, err := strconv.Atoi(v.aux_get(cpv.string, map[string]bool{"COUNTER": true}, "")[0])
			if err != nil {
				//except(KeyError, OverflowError, ValueError):
				continue
			}
			if pkg_counter > max_counter {
				max_counter = pkg_counter
			}
		}
	}
	return max_counter + 1
}

// ignnored, 1, ignored
func (v *vardbapi) counter_tick_core(incrementing int) int {
	v.lock()
	counter := v.get_counter_tick_core() - 1
	if incrementing != 0 {
		counter += 1
		// try:
		write_atomic(v._counter_path, fmt.Sprint(counter), 0, true)
		//except InvalidLocation:
		//self.settings._init_dirs()
		//write_atomic(self._counter_path, str(counter))
	}
	v._cached_counter = counter
	v.flush_cache()
	v.unlock()
	return counter
}

func (v *vardbapi) _dblink(cpv string) *dblink {
	category, pf := catsplit(cpv)[0], catsplit(cpv)[1]
	return NewDblink(category, pf, "", v.settings, "vartree", v.vartree, nil, nil, nil)
}

func (v *vardbapi) removeFromContents() {}

func (v *vardbapi) writeContentsToContentsFile() {}

func NewVarDbApi(settings *Config, vartree *varTree) *vardbapi { // nil, nil
	v := &vardbapi{}
	e := []string{}
	for _, v := range []string{"CVS", "lost+found"} {
		e = append(e, regexp.QuoteMeta(v))
	}
	v._excluded_dirs = regexp.MustCompile("^(\\..*|" + MergingIdentifier + ".*|" + strings.Join(e, "|") + ")$")
	v._aux_cache_version = 1
	v._owners_cache_version = 1
	v._aux_cache_threshold = 5
	v._aux_cache_keys_re = regexp.MustCompile("^NEEDED\\..*$")
	v._aux_multi_line_re = regexp.MustCompile("^(CONTENTS|NEEDED\\..*)$")

	v._pkgs_changed = false
	v._flush_cache_enabled = true
	v.mtdircache = map[string]int{}
	v.matchcache = map[string]map[[2]*Atom][]*pkgStr{}
	v.cpcache = map[string]struct {
		int64
		p []*pkgStr
	}{}
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

func (v *varTree) root() string {
	return v.settings.ValueDict["ROOT"]
}

// ""
func (v *varTree) getpath(mykey, filname string) string {
	return v.dbapi.getpath(mykey, filname)
}

func (v *varTree) zap() {}

func (v *varTree) inject() {}

func (v *varTree) getprovide() []string {
	return []string{}
}

func (v *varTree) get_all_provides() map[string][]*pkgStr {
	return map[string][]*pkgStr{}
}

// 1
func (v *varTree) dep_bestmatch(mydep *Atom, use_cache int) string {
	s := []string{}
	for _, p := range v.dbapi.match(dep_expand(mydep, v.dbapi.dbapi, 1, v.settings), use_cache) {
		s = append(s, p.string)
	}
	mymatch := best(s, "")
	if mymatch == "" {
		return ""
	} else {
		return mymatch
	}
}

// 1
func (v *varTree) dep_match(mydep *Atom, use_cache int) []*pkgStr {
	mymatch := v.dbapi.match(mydep, use_cache)
	if mymatch == nil {
		return []*pkgStr{}
	} else {
		return mymatch
	}

}

func (v *varTree) exists_specific(cpv string) bool {
	return v.dbapi.cpv_exists(cpv, "")
}

func (v *varTree) getallcpv() []*pkgStr {
	return v.dbapi.cpv_all(1)
}

func (v *varTree) getallnodes() []string {
	return v.dbapi.cp_all(1, false)
}

func (v *varTree) getebuildpath(fullpackage string) string {
	packagee := catsplit(fullpackage)[1]
	return v.getpath(fullpackage, packagee+".ebuild")
}

func (v *varTree) getslot(mycatpkg *pkgStr) string {
	return v.dbapi._pkg_str(mycatpkg, "").slot
}

func (v *varTree) populate() {
	v.populated = 1
}

func NewVarTree(categories map[string]bool, settings *Config) *varTree {
	v := &varTree{}
	if settings == nil {
		settings = Settings()
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
	mycpv                                                                           *pkgStr
	mysplit                                                                         []string
	vartree                                                                         *varTree
	settings                                                                        *Config
	_verbose, _linkmap_broken, _postinst_failure, _preserve_libs                    bool
	_contents                                                                       *ContentsCaseSensitivityManager

	_hash_key []string
}

func (d *dblink) __hash__() {}

func (d *dblink) __eq__() {}

func (d *dblink) _get_protect_obj() {}

func (d *dblink) isprotected() {}

func (d *dblink) updateprotect() {}

func (d *dblink) lockdb() {}

func (d *dblink) unlockdb() {}

func (d *dblink) _slot_locked() {}

func (d *dblink) _acquire_slot_locks() {}

func (d *dblink) _release_slot_locks() {}

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

func (d *dblink) delete() {}

func (d *dblink) clearcontents() {}

func (d *dblink) _clear_contents_cache() {
	d.contentscache = nil
	d._contents_inodes = nil
	d._contents_basenames = nil
	d._contents.clear_cache()
}

func (d *dblink) getcontents() {}

func (d *dblink) quickpkg() {}

func (d *dblink) _prune_plib_registry() {}

// @_slot_locked

func (d *dblink) unmerge() {}

func (d *dblink) _display_merge() {}

func (d *dblink) _show_unmerge() {}

func (d *dblink) _unmerge_pkgfiles() {}

func (d *dblink) _unmerge_protected_symlinks() {}

func (d *dblink) _unmerge_dirs() {}

func (d *dblink) isowner() {}

func (d *dblink) _match_contents() {}

func (d *dblink) _linkmap_rebuild() {}

func (d *dblink) _find_libs_to_preserve() {}

func (d *dblink) _add_preserve_libs_to_contents() {}

func (d *dblink) _find_unused_preserved_libs() {}

func (d *dblink) _remove_preserved_libs() {}

func (d *dblink) _collision_protect() {}

func (d *dblink) _lstat_inode_map() {}

func (d *dblink) _security_check() {}

func (d *dblink) _eqawarn() {}

func (d *dblink) _eerror() {}

func (d *dblink) _elog() {}

func (d *dblink) _elog_process() {}

func (d *dblink) _emerge_log() {}

func (d *dblink) treewalk() {}

func (d *dblink) _new_backup_path() {}

func (d *dblink) _merge_contents() {}

func (d *dblink) mergeme() {}

func (d *dblink) _protect() {}

func (d *dblink) _merged_path() {}

func (d *dblink) _post_merge_sync() {}

func (d *dblink) merge() {}

func (d *dblink) getstring(name string) string {
	if _, err := os.Stat(d.dbdir + "/" + name); err != nil {
		return ""
	}
	f, _ := ioutil.ReadFile(filepath.Join(d.dbdir, name))
	mydata := strings.Fields(string(f))
	return strings.Join(mydata, " ")
}

func (d *dblink) copyfile(fname string) {
	copyfile(fname, d.dbdir+"/"+path.Base(fname))
}

func (d *dblink) getfile() {}

func (d *dblink) setfile() {}

func (d *dblink) getelements() {}

func (d *dblink) setelements() {}

func (d *dblink) isregular() {}

func (d *dblink) _pre_merge_backup() {}

func (d *dblink) _pre_unmerge_backup() {}

func (d *dblink) _quickpkg_dblink() {}

// "", nil, "", nil, nil, nil, nil
func NewDblink(cat, pkg, myroot string, settings *Config, treetype string,
	vartree *varTree, blockers, scheduler, pipe interface{}) *dblink {
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
		//raise TypeError("settings argument is required")
	}

	mysettings := settings
	d._eroot = mysettings.ValueDict["EROOT"]
	d.cat = cat
	d.pkg = pkg
	mycpv := d.cat + "/" + d.pkg
	//if d.mycpv == settings.mycpv &&	isinstance(settings.mycpv, _pkg_str):
	//d.mycpv = settings.mycpv
	//else:
	d.mycpv = NewPkgStr(mycpv, nil, nil, "", "", "", 0, 0, "", 0, nil)
	d.mysplit = d.mycpv.cpvSplit[1:]
	d.mysplit[0] = d.mycpv.cp
	d.treetype = treetype
	if vartree == nil {
		vartree = Db().valueDict[d._eroot].VarTree()
	}
	d.vartree = vartree
	d._blockers = blockers
	d._scheduler = scheduler
	d.dbroot = NormalizePath(filepath.Join(d._eroot, VdbPath))
	d.dbcatdir = d.dbroot + "/" + cat
	d.dbpkgdir = d.dbcatdir + "/" + pkg
	d.dbtmpdir = d.dbcatdir + "/" + MergingIdentifier + pkg
	d.dbdir = d.dbpkgdir
	d.settings = mysettings
	d._verbose = d.settings.ValueDict["PORTAGE_VERBOSE"] == "1"

	d.myroot = d.settings.ValueDict["ROOT"]
	d._installed_instance = nil
	d.contentscache = nil
	d._contents_inodes = nil
	d._contents_basenames = nil
	d._linkmap_broken = false
	d._device_path_map = map[string]string{}
	d._hardlink_merge_map = map[string]string{}
	d._hash_key = []string{d._eroot, d.mycpv.string}
	d._protect_obj = nil
	d._pipe = pipe
	d._postinst_failure = false

	d._preserve_libs = mysettings.Features.Features["preserve-libs"]
	d._contents = NewContentsCaseSensitivityManager(d)
	d._slot_locks = []string{}

	return d
}

func merge() {}

func unmerge() {}

func write_contents() {}

func tar_contents() {}

type fakedbapi struct {
	*dbapi
	_exclusive_slots bool
	cpvdict          map[string]map[string]string
	cpdict           map[string][]*pkgStr
	_match_cache     map[[2]string][]*pkgStr
	_instance_key    func(*pkgStr, bool) *pkgStr
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

func (f *fakedbapi) cpv_exists(mycpv *pkgStr) bool {
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
			mycpv = NewPkgStr(mycpv.string, nil, nil, "", "", "", 0, 0, "", 0, f.dbapi)
		} else {
			mycpv = NewPkgStr(mycpv.string, metadata, f.settings, "", "", "", 0, 0, "", 0, f.dbapi)
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

// 1
func (b *bindbapi) match(origdep *Atom, use_cache int) []*pkgStr {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.match(origdep, use_cache)
}

func (b *bindbapi) cpv_exists(cpv *pkgStr) bool {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.cpv_exists(cpv)
}

func (b *bindbapi) cpv_inject(cpv *pkgStr) {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	b.fakedbapi.cpv_inject(cpv, cpv.metadata)
}

func (b *bindbapi) cpv_remove(cpv *pkgStr) {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	b.fakedbapi.cpv_remove(cpv)
}

func (b *bindbapi) aux_get(mycpv *pkgStr, wants map[string]string) []string {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	instance_key := b._instance_key(mycpv, true)
	if !b._known_keys.intersection(
		wants).difference(b._aux_cache_keys) {
		aux_cache := b.cpvdict[instance_key.string]
		if aux_cache != nil {
			ret := []string{}
			for x := range wants {
				ret = append(ret, aux_cache[x])
			}
			return ret
		}
	}
	add_pkg := b.bintree._additional_pkgs[instance_key.string]
	getitem := func(string) string { return "" }
	if add_pkg != nil {
		return add_pkg._db.aux_get(add_pkg, wants)
	} else if !b.bintree._remotepkgs || !b.bintree.isremote(mycpv) {
		tbz2_path, ok := b.bintree._pkg_paths[instance_key.string]
		if !ok {
			//except KeyError:
			//raise KeyError(mycpv)
		}
		tbz2_path = filepath.Join(b.bintree.pkgdir, tbz2_path)
		st, err := os.Lstat(tbz2_path)
		if err != nil {
			//except OSError:
			//raise KeyError(mycpv)
		}
		metadata_bytes := NewTbz2(tbz2_path).get_data()
		getitem = func(k string) string {
			if k == "_mtime_" {
				return fmt.Sprint(st.ModTime().UnixNano())
			} else if k == "SIZE" {
				return fmt.Sprint(st.Size())
			}
			v := metadata_bytes[k]
			return v
		}
	} else {
		getitem = func(s string) string {
			return b.cpvdict[instance_key.string][s]
		}
	}
	mydata := map[string]string{}
	mykeys := wants
	for x := range mykeys {
		myval := getitem(x)
		if myval != "" {
			mydata[x] = strings.Join(strings.Fields(myval), " ")
		}
	}

	if mydata["EAPI"] == "" {
		mydata["EAPI"] = "0"
	}

	ret := []string{}
	for x := range wants {
		ret = append(ret, mydata[x])
	}
	return ret
}

func (b *bindbapi) aux_update() {}

// 1
func (b *bindbapi) cp_list(mycp string, use_cache int) []*pkgStr {
	if !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.cp_list(mycp, use_cache)
}

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
	pkgdir, _pkgindex_file                                                                                       string
	PkgIndexFile                                                                                                 interface{}
	settings                                                                                                     *Config
	populated, _populating, _multi_instance, _remote_has_index, _all_directory                                   bool
	_pkgindex_version                                                                                            int
	_pkgindex_hashes, _pkgindex_keys, _pkgindex_aux_keys, _pkgindex_use_evaluated_keys, _pkgindex_inherited_keys []string
	_remotepkgs                                                                                                  interface{}
	dbapi                                                                                                        *bindbapi
	update_ents                                                                                                  func(updates map[string][][]*Atom, onProgress, onUpdate func(int, int))
	move_slot_ent                                                                                                func(mylist []*Atom, repo_match func(string) bool) int
	tree, _additional_pkgs                                                                                       map[string]interface{}
	_pkgindex_header_keys, _pkgindex_allowed_pkg_keys                                                            map[string]bool
	_pkgindex_default_pkg_data, _pkgindex_default_header_data, _pkg_paths, _pkgindex_header                      map[string]string
	_pkgindex_translated_keys                                                                                    [][2]string
	invalids                                                                                                     []string
	_allocate_filename                                                                                           func(cpv *pkgStr) string
}

func (b *BinaryTree) root() string {
	return b.settings.ValueDict["ROOT"]
}

// nil
func (b *BinaryTree) move_ent(mylist []string, repo_match func(string) bool) int {
	if !b.populated {
		b.Populate(false, true, []string{})
	}
	origcp := mylist[1]
	newcp := mylist[2]
	for _, atom := range []string{origcp, newcp} {
		if !isJustName(atom) {
			//raise InvalidPackageName(_unicode(atom))
		}
	}
	mynewcat := catsplit(newcp)[0]
	origmatches := b.dbapi.cp_list(origcp, 1)
	moves := 0
	if len(origmatches) == 0 {
		return moves
	}
	for _, mycpv := range origmatches {
		//try:
		mycpv := b.dbapi._pkg_str(mycpv, "")
		//except (KeyError, InvalidData):
		//continue
		mycpv_cp := cpvGetKey(mycpv.string, "")
		if mycpv_cp != origcp {
			continue
		}
		if repo_match != nil && !repo_match(mycpv.repo) {
			continue
		}

		if !isValidAtom(newcp, false, false, false, mycpv.eapi, false) {
			continue
		}

		mynewcpv := strings.Replace(mycpv.string, mycpv_cp, newcp, 1)
		myoldpkg := catsplit(mycpv.string)[1]
		mynewpkg := catsplit(mynewcpv)[1]

		if _, err := os.Stat(b.getname(mynewcpv, false)); (mynewpkg != myoldpkg) && err == nil {
			WriteMsg(fmt.Sprintf("!!! Cannot update binary: Destination exists.\n"), -1, nil)
			WriteMsg(fmt.Sprintf("!!! "+mycpv.string+" -> "+mynewcpv+"\n"), -1, nil)
			continue
		}

		tbz2path := b.getname(mycpv.string, false)
		if _, err := os.Stat(tbz2path); err == syscall.EPERM {
			WriteMsg(fmt.Sprintf("!!! Cannot update readonly binary: %s\n", mycpv), -1, nil)
			continue
		}

		moves += 1
		mytbz2 := NewTbz2(tbz2path)
		mydata := mytbz2.get_data()
		updated_items := update_dbentries([][]*Atom{mylist}, mydata, "", mycpv)
		for k, v := range updated_items {
			mydata[k] = v
		}
		mydata["PF"] = mynewpkg + "\n"
		mydata["CATEGORY"] = mynewcat + "\n"
		if mynewpkg != myoldpkg {
			ebuild_data := mydata[myoldpkg+".ebuild"]
			delete(mydata, myoldpkg+".ebuild")
			if ebuild_data != "" {
				mydata[mynewpkg+".ebuild"] = ebuild_data
			}
		}

		mytbz2.recompose_mem(string(xpak_mem(mydata)), true)

		b.dbapi.cpv_remove(mycpv)
		delete(b._pkg_paths, b.dbapi._instance_key(mycpv, false).string)
		metadata := b.dbapi._aux_cache_slot_dict()
		for _, k := range b.dbapi._aux_cache_keys {
			if v, ok := mydata[k]; ok {
				metadata[k] = strings.Join(strings.Fields(v), " ")
			}
		}
		mynewcpvP := NewPkgStr(mynewcpv, metadata, nil, "", "", "", 0, 0, "", 0, b.dbapi.dbapi)
		new_path := b.getname(mynewcpv, false)
		b._pkg_paths[b.dbapi._instance_key(mynewcpvP, false).string] = new_path[len(b.pkgdir)+1:]
		if new_path != mytbz2.file {
			b._ensure_dir(filepath.Dir(new_path))
			_movefile(tbz2path, new_path, 0, nil, b.settings, nil)
		}
		b.inject(mynewcpv)
	}
	return moves
}

func (b *BinaryTree) prevent_collision() {}

func (b *BinaryTree) _ensure_dir(path string) {
	pkgdir_st, err := os.Stat(b.pkgdir)
	if err != nil {
		//except OSError:
		ensureDirs(path, -1, -1, -1, -1, nil, true)
		return
	}
	pkgdir_gid := pkgdir_st.Sys().(*syscall.Stat_t).Gid
	pkgdir_grp_mode := 0o2070 & pkgdir_st.Mode()
	ensureDirs(path, -1, pkgdir_gid, pkgdir_grp_mode, 0, nil, true)
	//except PortageException:
	//if not os.path.isdir(path):
	//raise
}

func (b *BinaryTree) _file_permissions(path string) {
	pkgdir_st, err := os.Stat(b.pkgdir)
	if err != nil {
		//except OSError:
		//pass
	} else {
		pkgdir_gid := pkgdir_st.Sys().(*syscall.Stat_t).Gid
		pkgdir_grp_mode := 0o0060 & pkgdir_st.Mode()
		applyPermissions(path, -1, pkgdir_gid,
			pkgdir_grp_mode, 0, nil, true)
		//except PortageException:
		//pass
	}
}

// false, true, []string{}
func (b *BinaryTree) Populate(getbinpkgs, getbinpkg_refresh bool, add_repos []string) {
	if b._populating {
		return
	}
	if st, _ := os.Stat(b.pkgdir); st != nil && !st.IsDir() && !(getbinpkgs || len(add_repos) != 0) {
		b.populated = true
		return
	}
	b._remotepkgs = nil

	b._populating = true
	defer func() { b._populating = false }()
	update_pkgindex := b._populate_local(!b.settings.Features.Features["pkgdir-index-trusted"])

	if update_pkgindex != nil && b.dbapi.writable() {
		a, f, c, d, _ := Lockfile(b._pkgindex_file, true, false, "", 0)
		update_pkgindex = b._populate_local(true)
		if update_pkgindex != nil {
			b._pkgindex_write(update_pkgindex)
		}
		//if pkgindex_lock:
		Unlockfile(a, f, c, d)
	}

	if len(add_repos) > 0 {
		b._populate_additional(add_repos)
	}

	if getbinpkgs {
		if b.settings.ValueDict["PORTAGE_BINHOST"] == "" {
			WriteMsg(fmt.Sprintf("!!! PORTAGE_BINHOST unset, but Use is requested.\n"), -1, nil)
		} else {
			b._populate_remote(getbinpkg_refresh)
		}
	}

	b.populated = true

}

// true
func (b *BinaryTree) _populate_local(reindex bool) *PackageIndex {
	b.dbapi.clear()

	_instance_key := b.dbapi._instance_key

	minimum_keys := []string{}
	for _, k := range b._pkgindex_keys {
		if !ins(b._pkgindex_hashes, k) {
			minimum_keys = append(minimum_keys, k)
		}
	}
	pkg_paths := map[string]string{}
	b._pkg_paths = pkg_paths
	dir_files := map[string][]string{}
	if reindex {
		filepath.Walk(b.pkgdir, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}
			dir_files[filepath.Dir(path)] = append(dir_files[filepath.Dir(path)], filepath.Base(path))
			return nil
		})
	}

	pkgindex := b.LoadPkgIndex()
	if !b._pkgindex_version_supported(pkgindex) {
		pkgindex = b._new_pkgindex()
	}
	metadata := map[string]map[string]string{}
	basename_index := map[string][]map[string]string{}
	for _, d := range pkgindex.packages {
		cpv := NewPkgStr(d["CPV"], d, b.settings, "", "", "", 0, 0, "", 0, b.dbapi.dbapi)
		d["CPV"] = cpv.string
		metadata[_instance_key(cpv, false).string] = d
		path := d["PATH"]
		if path == "" {
			path = cpv.string + ".tbz2"
		}

		if reindex {
			basename := filepath.Base(path)
			if _, ok := basename_index[basename]; !ok {
				basename_index[basename] = []map[string]string{d}
			}
		} else {
			instance_key := _instance_key(cpv, false)
			pkg_paths[instance_key.string] = path
			b.dbapi.cpv_inject(cpv)
		}
	}

	update_pkgindex := false
	for mydir, file_names := range dir_files {
		for _, myfile := range file_names {
			has := false
			for k := range SUPPORTED_XPAK_EXTENSIONS {
				if !strings.HasSuffix(myfile, k) {
					has = true
					break
				}
			}
			if !has {
				continue
			}
			mypath := filepath.Join(mydir, myfile)
			full_path := filepath.Join(b.pkgdir, mypath)
			s, _ := os.Lstat(full_path)

			if s == nil || s.IsDir() {
				continue
			}
			possibilities := basename_index[myfile]
			if len(possibilities) != 0 {
				var match map[string]string = nil
				var d map[string]string
				for _, d = range possibilities {
					mt, err := strconv.Atoi(d["_mtime_"])
					if err != nil {
						continue
					}
					if mt != s.ModTime().Nanosecond() {
						continue
					}
					sz, err := strconv.ParseInt(d["SIZE"], 10, 64)
					if err != nil {
						continue
					}
					if sz != s.Size() {
						continue
					}
					in := true
					for _, k := range minimum_keys {
						if _, ok := d[k]; !ok {
							in = false
							break
						}
					}
					if in {
						match = d
						break
					}
				}
				if len(match) > 0 {
					mycpv := match["CPV"]
					instance_key := _instance_key(mycpv, false)
					pkg_paths[instance_key.string] = mypath
					oldpath := d["PATH"]
					if oldpath != "" && oldpath != mypath {
						update_pkgindex = true
					}
					if mypath != mycpv+".tbz2" {
						d["PATH"] = mypath
						if oldpath == "" {
							update_pkgindex = true
						}
					} else {
						delete(d, "PATH")
						if oldpath != "" {
							update_pkgindex = true
						}
					}
					b.dbapi.cpv_inject(mycpv)
					continue
				}
			}
			if _, err := os.Stat(full_path); err != nil {
				WriteMsg(fmt.Sprintf("!!! Permission denied to read binary package: '%s'\n", full_path), -1, nil)
				b.invalids = append(b.invalids, myfile[:len(myfile)-5])
				continue
			}
			chain := []string{}
			for _, v := range b.dbapi._aux_cache_keys {
				chain = append(chain, v)
			}
			chain = append(chain, "PF", "CATEGORY")
			pkg_metadata := b._read_metadata(full_path, s,
				chain)
			mycat := pkg_metadata["CATEGORY"]
			mypf := pkg_metadata["PF"]
			slot := pkg_metadata["SLOT"]
			mypkg := myfile[:len(myfile)-5]
			if !mycat || mypf == "" || slot == "" {
				WriteMsg(fmt.Sprintf("\n!!! Invalid binary package: '%s'\n", full_path), -1, nil)
				missing_keys := []string{}
				if !mycat {
					missing_keys = append(missing_keys, "CATEGORY")
				}
				if mypf == "" {
					missing_keys = append(missing_keys, "PF")
				}
				if slot == "" {
					missing_keys = append(missing_keys, "SLOT")
				}
				msg := []string{}
				if len(missing_keys) > 0 {
					sort.Strings(missing_keys)
					msg = append(msg, fmt.Sprintf("Missing metadata key(s): %s.",
						strings.Join(missing_keys, ", ")))
				}
				msg = append(msg, fmt.Sprintf(" This binary package is not recoverable and should be deleted."))
				for _, line := range SplitSubN(strings.Join(msg, ""), 72) {
					WriteMsg(fmt.Sprintf("!!! %s\n", line), -1, nil)
				}
				b.invalids = append(b.invalids, mypkg)
				continue
			}

			multi_instance := false
			invalid_name := false
			build_id := 0
			if strings.HasSuffix(myfile, ".xpak") {
				multi_instance = true
				build_id = b._parse_build_id(myfile)
				if build_id < 1 {
					invalid_name = true
				} else if myfile != fmt.Sprintf("%s-%s.xpak", mypf, build_id) {
					invalid_name = true
				} else {
					mypkg = mypkg[:len(mypkg)-len(fmt.Sprint(build_id))-1]
				}
			} else if myfile != mypf+".tbz2" {
				invalid_name = true
			}

			if invalid_name {
				WriteMsg(fmt.Sprintf("\n!!! Binary package name is invalid: '%s'\n", full_path), -1, nil)
				continue
			}

			if pkg_metadata["BUILD_ID"] != "" {
				var err error
				build_id, err = strconv.Atoi(pkg_metadata["BUILD_ID"])
				if err != nil {
					//except ValueError:
					WriteMsg(fmt.Sprintf("!!! Binary package has invalid BUILD_ID: '%s'\n", full_path), -1, nil)
					continue
				}
			} else {
				build_id = 0
			}

			if multi_instance {
				name_split := catPkgSplit(mycat+"/"+mypf, 1, "")
				if name_split == [4]string{} || catsplit(mydir)[0] != name_split[0] || catsplit(mydir)[1] != name_split[1] {
					continue
				}
			} else if mycat != mydir && mydir != "All" {
				continue
			}
			if mypkg != strings.TrimSpace(mypf) {
				continue
			}
			mycpvS := mycat + "/" + mypkg
			if !b.dbapi._category_re.MatchString(mycat) {
				WriteMsg(fmt.Sprintf("!!! Binary package has an unrecognized category: '%s'\n", full_path), -1, nil)
				WriteMsg(fmt.Sprintf("!!! '%s' has a category that is not listed in %setc/portage/categories\n", mycpvS, b.settings.ValueDict["PORTAGE_CONFIGROOT"]), -1, nil)
				continue
			}
			if build_id != 0 {
				pkg_metadata["BUILD_ID"] = fmt.Sprint(build_id)
			}
			pkg_metadata["SIZE"] = fmt.Sprint(s.Size())
			delete(pkg_metadata, "CATEGORY")
			delete(pkg_metadata, "PF")
			mycpv := NewPkgStr(mycpvS, b.dbapi._aux_cache_slot_dict(pkg_metadata), b.dbapi.dbapi, "", "", "", 0, 0, "", 0, nil)
			pkg_paths[_instance_key(mycpv, false).string] = mypath
			b.dbapi.cpv_inject(mycpv)
			update_pkgindex = true
			d, ok := metadata[_instance_key(mycpv, false).string]
			if !ok {
				d = pkgindex._pkg_slot_dict()
			}
			if len(d) > 0 {
				mt, err := strconv.Atoi(d["_mtime_"])
				if err != nil {
					d = map[string]string{}
				}
				if mt != s.ModTime().Nanosecond() {
					d = map[string]string{}
				}
			}
			if len(d) > 0 {
				sz, err := strconv.ParseInt(d["SIZE"], 10, 64)
				if err != nil {
					d = map[string]string{}
				}
				if sz != s.Size() {
					d = map[string]string{}
				}
			}

			for k := range b._pkgindex_allowed_pkg_keys {
				v := pkg_metadata[k]
				if v {
					d[k] = v
				}
				d["CPV"] = mycpv.string
			}

			//try:
			b._eval_use_flags(d)
			//except portage.exception.InvalidDependString:
			//WriteMsg(fmt.Sprintf("!!! Invalid binary package: '%s'\n", b.getname(mycpv)), -1, nil)
			//self.dbapi.cpv_remove(mycpv)
			//del pkg_paths[_instance_key(mycpv)]

			if mypath != mycpv.string+".tbz2" {
				d["PATH"] = mypath
			} else {
				delete(d, "PATH")
			}
			metadata[_instance_key(mycpv, false).string] = d
		}
	}

	if reindex {
		for instance_key := range metadata {
			if _, ok := pkg_paths[instance_key]; !ok {
				delete(metadata, instance_key)
			}
		}
	}

	if update_pkgindex {
		pkgindex.packages = []map[string]string{}
		for _, v := range metadata {
			pkgindex.packages = append(pkgindex.packages, v)
		}
		b._update_pkgindex_header(pkgindex.header)
	}

	b._pkgindex_header = map[string]string{}
	b._merge_pkgindex_header(pkgindex.header, b._pkgindex_header)

	if update_pkgindex {
		return pkgindex
	} else {
		return nil
	}

}

func (b *BinaryTree) _populate_remote() {}

func (b *BinaryTree) _populate_additional() {}

func (b *BinaryTree) inject() {}

func (b *BinaryTree) _read_metadata() {}

func (b *BinaryTree) _inject_file() {}

func (b *BinaryTree) _pkgindex_write(pkgindex *PackageIndex) {
	contents := &bytes.Buffer{}
	pkgindex.write(contents)
	contentsB := contents.Bytes()
	mtime, _ := strconv.Atoi(pkgindex.header["TIMESTAMP"])
	atime := mtime
	output_files := []struct {
		io.WriteCloser
		string
		io.Closer
	}{{NewAtomic_ofstream(b._pkgindex_file, os.O_RDWR, true),
		b._pkgindex_file, nil}}

	if _, ok := b.settings.Features.Features["compress-index"]; ok {
		gz_fname := b._pkgindex_file + ".gz"
		fileobj := NewAtomic_ofstream(gz_fname, os.O_RDWR, true)
		output_files = append(output_files, struct {
			io.WriteCloser
			string
			io.Closer
		}{gzip.NewWriter(fileobj), gz_fname, fileobj})
	}

	for _, v := range output_files {
		f := v.WriteCloser
		fname := v.string
		f_close := v.Closer
		f.Write(contentsB)
		f.Close()
		if f_close != nil {
			f_close.Close()
		}
		b._file_permissions(fname)
		syscall.Utime(fname, &syscall.Utimbuf{int64(atime), int64(mtime)})
	}
}

func (b *BinaryTree) _pkgindex_entry(cpv *pkgStr) map[string]string {

	pkg_path := b.getname(cpv.string, false)

	d := CopyMapSS(cpv.metadata)
	for k, v := range performMultipleChecksums(pkg_path, b._pkgindex_hashes, 0) {
		d[k] = string(v)
	}

	d["CPV"] = cpv.string
	st, _ := os.Lstat(pkg_path)
	d["_mtime_"] = fmt.Sprint(st.ModTime().UnixNano())
	d["SIZE"] = fmt.Sprint(st.Size())

	rel_path := pkg_path[len(b.pkgdir)+1:]
	if rel_path != cpv.string+".tbz2" {
		d["PATH"] = rel_path
	}

	return d
}

func (b *BinaryTree) _new_pkgindex() *PackageIndex {
	return NewPackageIndex(b._pkgindex_allowed_pkg_keys,
		b._pkgindex_default_header_data,
		b._pkgindex_default_pkg_data,
		b._pkgindex_inherited_keys,
		b._pkgindex_translated_keys)
}

func (b *BinaryTree) _merge_pkgindex_header(src, dest map[string]string) {
	for _, i := range iterIuseVars(src) {
		k := i[0]
		v := i[1]
		v_before := dest[k]
		if v_before != "" {
			merged_values := map[string]bool{}
			for _, v := range strings.Fields(v_before) {
				merged_values[v] = true
			}
			for _, v := range strings.Fields(v) {
				merged_values[v] = true
			}
			mv := []string{}
			for k := range merged_values {
				mv = append(mv, k)
			}
			sort.Strings(mv)
			v = strings.Join(mv, " ")
		}
		dest[k] = v
	}
	if dest["ARCH"] == "" && src["ARCH"] != "" {
		dest["ARCH"] = src["ARCH"]
	}
}

func (b *BinaryTree) _propagate_config() {}

func (b *BinaryTree) _update_pkgindex_header(header map[string]string) {

	if _, ok := b.settings.ValueDict["IUSE_IMPLICIT"]; !(b.settings.profilePath != "" && ok) {
		if _, ok := header["VERSION"]; !ok {
			header["VERSION"] = fmt.Sprint(b._pkgindex_version)
		}
		return
	}
	rp, _ := filepath.EvalSymlinks(b.settings.ValueDict["PORTDIR"])
	portdir := NormalizePath(rp)
	profiles_base := filepath.Join(portdir, "profiles") + string(filepath.Separator)
	profile_path := ""
	if b.settings.profilePath != "" {
		rp, _ := filepath.EvalSymlinks(b.settings.ValueDict["PORTDIR"])
		profile_path = NormalizePath(rp)
	}
	if strings.HasPrefix(profile_path, profiles_base) {
		profile_path = profile_path[len(profiles_base):]
	}
	header["PROFILE"] = profile_path
	header["VERSION"] = fmt.Sprint(b._pkgindex_version)
	base_uri := b.settings.ValueDict["PORTAGE_BINHOST_HEADER_URI"]
	if base_uri != "" {
		header["URI"] = base_uri
	} else {
		delete(header, "URI")
	}
	phk := []string{}
	for k := range b._pkgindex_header_keys {
		phk = append(phk, k)
	}
	for _, k := range append(append(append([]string{}, phk...),
		strings.Fields(b.settings.ValueDict["USE_EXPAND_IMPLICIT"])...),
		strings.Fields(b.settings.ValueDict["USE_EXPAND_UNPREFIXED"])...) {
		v := b.settings.ValueDict[k]
		if v != "" {
			header[k] = v
		} else {
			delete(header, k)
		}
	}
}

func (b *BinaryTree) _pkgindex_version_supported(pkgindex *PackageIndex) bool {
	version := pkgindex.header["VERSION"]
	if version != "" {
		v, err := strconv.Atoi(version)
		if err == nil {
			if v < b._pkgindex_version {
				return true
			}
		}
		if err != nil {
			//except ValueError:
			//pass
		}
	}
	return false
}

//
func (b *BinaryTree) _eval_use_flags(metadata map[string]string) {
	use := map[string]bool{}
	for _, v := range strings.Fields(metadata["USE"]) {
		use[v] = true
	}
	for _, k := range b._pkgindex_use_evaluated_keys {
		token_class := func(s string) *Atom { NewAtom(s, nil, false, nil, nil, "", nil, nil) }
		if !strings.HasSuffix(k, "DEPEND") {
			token_class = nil
		}

		deps := metadata[k]
		if deps == "" {
			continue
		}
		//try:
		deps1 := useReduce(deps, use, []string{}, false, []string{}, false, "", false, false, nil, token_class, false)
		deps2 := parenEncloses(deps1, false, false)
		//except portage.exception.InvalidDependString as e:
		//writemsg("%s: %s\n" % (k, e), noiselevel=-1)
		//raise
		metadata[k] = deps2
	}
}

// deprecated ?
func (b *BinaryTree) exists_specific(cpv string) []*pkgStr {
	if !b.populated {
		b.Populate(false, true, []string{})
	}
	return b.dbapi.match(dep_expandS("="+cpv, b.dbapi.dbapi, 1, b.settings), 1)
}

func (b *BinaryTree) dep_bestmatch(mydep *Atom) string {
	if !b.populated {
		b.Populate(false, true, []string{})
	}
	WriteMsg("\n\n", 1, nil)
	WriteMsg(fmt.Sprintf("mydep: %s\n", mydep), 1, nil)
	mydep = dep_expand(mydep, b.dbapi.dbapi, 1, b.settings)
	WriteMsg(fmt.Sprintf("mydep: %s\n", mydep), 1, nil)
	mykey := depGetKey(mydep.value)
	WriteMsg(fmt.Sprintf("mykey: %s\n", mykey), 1, nil)
	ml := []string{}
	for _, p := range matchFromList(mydep, b.dbapi.cp_list(mykey, 1)) {
		ml = append(ml, p.string)
	}
	mymatch := best(ml, "")
	WriteMsg(fmt.Sprintf("mymatch: %s\n", mymatch), 1, nil)
	if mymatch == "" {
		return ""
	}
	return mymatch
}

// false
func (b *BinaryTree) getname(cpvS string, allocate_new bool) string {

	if !b.populated {
		b.Populate(false, true, []string{})
	}

	cpv := NewPkgStr(cpvS, nil, nil, "", "", "", 0, 0, "", 0, nil)

	filename := ""
	if allocate_new {
		filename = b._allocate_filename(cpv)
	} else if b._is_specific_instance(cpv) {
		instance_key := b.dbapi._instance_key(cpv, false)
		path := b._pkg_paths[instance_key.string]
		if path != "" {
			filename = filepath.Join(b.pkgdir, path)
		}
	}

	if filename == "" && !allocate_new {
		//try:
		instance_key := b.dbapi._instance_key(cpv, true)
		//except KeyError:
		//pass
		//else:
		filename = b._pkg_paths[instance_key.string]
		if filename != "" {
			filename = filepath.Join(b.pkgdir, filename)
		} else if _, ok := b._additional_pkgs[instance_key.string]; ok {
			return ""
		}
	}

	if filename == "" {
		if b._multi_instance {
			pf := catsplit(cpv.string)[1]
			filename = fmt.Sprintf("%s-%s.xpak", filepath.Join(b.pkgdir, cpv.cp, pf), "1")
		} else {
			filename = filepath.Join(b.pkgdir, cpv.string+".tbz2")
		}
	}

	return filename
}

func (b *BinaryTree) _is_specific_instance() {}

func (b *BinaryTree) _max_build_id(cpv *pkgStr) int {
	max_build_id := 0
	for _, x := range b.dbapi.cp_list(cpv.cp, 1) {
		if x.string == cpv.string && x.buildId != 0 && x.buildId > max_build_id {
			max_build_id = x.buildId
		}
	}
	return max_build_id
}

func (b *BinaryTree) _allocate_filename_multi(cpv *pkgStr) string {
	max_build_id := b._max_build_id(cpv)

	pf := catsplit(cpv.string)[1]
	build_id := max_build_id + 1

	for {
		filename := fmt.Sprintf("%s-%s.xpak",
			filepath.Join(b.pkgdir, cpv.cp, pf), build_id)
		if _, err := os.Stat(filename); err == nil {
			build_id += 1
		} else {
			return filename
		}
	}
}

func (b *BinaryTree) _parse_build_id(filename string) int {
	build_id := -1
	suffixlen := len(".xpak")
	hyphen := strings.LastIndex(filename[0:len(filename)-(suffixlen+1)], "-")
	if hyphen != -1 {
		build_idS := filename[hyphen+1 : -suffixlen]
		var err error
		build_id, err = strconv.Atoi(build_idS)
		if err != nil {
			//pass
		}
	}
	return build_id
}

func (b *BinaryTree) isremote(pkgname *pkgStr) bool {
	if b._remotepkgs == nil {
		return false
	}
	instance_key := b.dbapi._instance_key(pkgname, false)
	if _, ok := b._remotepkgs[instance_key.string]; !ok {
		return false
	} else if _, ok := b._additional_pkgs[instance_key.string]; ok {
		return false
	}
	return true
}

func (b *BinaryTree) get_pkgindex_uri() {}

func (b *BinaryTree) gettbz2() {}

func (b *BinaryTree) LoadPkgIndex() *PackageIndex {
	pkgindex := b._new_pkgindex()
	f, err := os.Open(b._pkgindex_file)
	if err == nil {
		//try:
		pkgindex.read(f)
		//finally:
		//	f.close()
	}
	return pkgindex
}

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
	if b._multi_instance {
		b._allocate_filename = b._allocate_filename_multi
	} else {
		b._allocate_filename = func(cpv *pkgStr) string {
			return filepath.Join(b.pkgdir, cpv.string+".tbz2")
		}
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
	b._pkg_paths = map[string]string{}
	b._populating = false
	st, err := os.Stat(path.Join(b.pkgdir, "All"))
	b._all_directory = err != nil && st != nil && st.IsDir()
	b._pkgindex_version = 0
	b._pkgindex_hashes = []string{"MD5", "SHA1"}
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
	b._pkgindex_use_evaluated_keys = []string{"BDEPEND", "DEPEND", "LICENSE", "RDEPEND",
		"PDEPEND", "PROPERTIES", "RESTRICT"}
	b._pkgindex_header = nil

	b._pkgindex_header_keys = map[string]bool{}
	for _, k := range []string{
		"ACCEPT_KEYWORDS", "ACCEPT_LICENSE",
		"ACCEPT_PROPERTIES", "ACCEPT_RESTRICT", "CBUILD",
		"CONFIG_PROTECT", "CONFIG_PROTECT_MASK", "FEATURES",
		"GENTOO_MIRRORS", "INSTALL_MASK", "IUSE_IMPLICIT", "USE",
		"USE_EXPAND", "USE_EXPAND_HIDDEN", "USE_EXPAND_IMPLICIT",
		"USE_EXPAND_UNPREFIXED"} {
		b._pkgindex_header_keys[k] = true
	}

	b._pkgindex_default_pkg_data = map[string]string{
		"BDEPEND":        "",
		"BUILD_ID":       "",
		"BUILD_TIME":     "",
		"DEFINED_PHASES": "",
		"DEPEND":         "",
		"EAPI":           "0",
		"IUSE":           "",
		"KEYWORDS":       "",
		"LICENSE":        "",
		"PATH":           "",
		"PDEPEND":        "",
		"PROPERTIES":     "",
		"PROVIDES":       "",
		"RDEPEND":        "",
		"REQUIRES":       "",
		"RESTRICT":       "",
		"SLOT":           "0",
		"USE":            "",
	}
	b._pkgindex_inherited_keys = []string{"CHOST", "repository"}

	b._pkgindex_default_header_data = map[string]string{
		"CHOST":      b.settings.ValueDict["CHOST"],
		"repository": "",
	}

	b._pkgindex_translated_keys = [][2]string{
		{"DESCRIPTION", "DESC"},
		{"_mtime_", "MTIME"},
		{"repository", "REPO"},
	}

	b._pkgindex_allowed_pkg_keys = map[string]bool{}
	for _, v := range b._pkgindex_keys {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_keys {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_aux_keys {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_hashes {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for v := range b._pkgindex_default_pkg_data {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_inherited_keys {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_translated_keys {
		b._pkgindex_allowed_pkg_keys[v[0]] = true
		b._pkgindex_allowed_pkg_keys[v[1]] = true
	}
	return b
}

type portdbapi struct {
	*dbapi
	_use_mutable bool
}

func (p *portdbapi) _categories() {}

func (p *portdbapi) porttree_root() {}

func (p *portdbapi) eclassdb() {}

func (p *portdbapi) _set_porttrees() {}

func (p *portdbapi) _get_porttrees() {}

func (p *portdbapi) _event_loop() {}

func (p *portdbapi) _create_pregen_cache() {}

func (p *portdbapi) _init_cache_dirs() {}

func (p *portdbapi) close_caches() {}

func (p *portdbapi) flush_cache() {}

func (p *portdbapi) findLicensePath() {}

func (p *portdbapi) findname() {}

func (p *portdbapi) getRepositoryPath() {}

func (p *portdbapi) getRepositoryName() {}

func (p *portdbapi) getRepositories() {}

func (p *portdbapi) getMissingRepoNames() {}

func (p *portdbapi) getIgnoredRepos() {}

func (p *portdbapi) findname2() {}

func (p *portdbapi) _write_cache() {}

func (p *portdbapi) _pull_valid_cache() {}

func (p *portdbapi) aux_get() {}

func (p *portdbapi) async_aux_get() {}

func (p *portdbapi) _aux_get_cancel() {}

func (p *portdbapi) _aux_get_return() {}

func (p *portdbapi) getFetchMap() {}

func (p *portdbapi) async_fetch_map() {}

func (p *portdbapi) getfetchsizes() {}

func (p *portdbapi) fetch_check() {}

func (p *portdbapi) cpv_exists() {}

func (p *portdbapi) cp_all() {}

func (p *portdbapi) cp_list() {}

func (p *portdbapi) freeze() {}

func (p *portdbapi) melt() {}

func (p *portdbapi) xmatch() {}

func (p *portdbapi) async_xmatch() {}

func (p *portdbapi) match() {}

func (p *portdbapi) gvisible() {}

func (p *portdbapi) visible() {}

func (p *portdbapi) _iter_visible() {}

func (p *portdbapi) _visible() {}

func NewPortDbApi() *portdbapi {
	p := &portdbapi{}
	p._use_mutable = true
	return p
}

type PortageTree struct {
}

func (p *PortageTree) portroot() {}

func (p *PortageTree) root() {}

func (p *PortageTree) virtual() {}

func (p *PortageTree) dep_bestmatch() {}

func (p *PortageTree) dep_match() {}

func (p *PortageTree) exists_specific() {}

func (p *PortageTree) getallnodes() {}

func (p *PortageTree) getname() {}

func (p *PortageTree) getslot() {}

func NewPortageTree(setting *Config) *PortageTree {
	p := &PortageTree{}
	return p
}

type FetchlistDict struct {
}

func (f *FetchlistDict) __getitem__() {}

func (f *FetchlistDict) __contains__() {}

func (f *FetchlistDict) has_key() {}

func (f *FetchlistDict) __iter__() {}

func (f *FetchlistDict) __len__() {}

func (f *FetchlistDict) keys() {}

func NewFetchlistDict(setting *Config) *FetchlistDict {
	f := &FetchlistDict{}
	return f
}

func _async_manifest_fetchlist() {}

// ordered map
// nil
func _parse_uri_map(cpv, metadata map[string]string, use map[string]bool) map[string]map[string]bool {
	myuris := useReduce(metadata["SRC_URI"], use, []string{}, use == nil, []string{}, true, metadata["EAPI"], false, false, nil, nil, false)

	uri_map := map[string]map[string]bool{}

	ReverseSlice(myuris)
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
				//	("getFetchMap(): '%s' SRC_URI has no file " + \
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
