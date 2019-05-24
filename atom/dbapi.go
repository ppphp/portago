package atom

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

func dep_expand(mydep *Atom, mydb *dbapi, use_cache int, settings *Config) *Atom { //nil,1,nil
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

func (d *dbapi) invalidentry(mypath string) {
	if strings.Contains(mypath, "/"+MergingIdentifier) {
		if _, err := os.Stat(mypath); err != nil {
			WriteMsg(colorize("BAD", "INCOMPLETE MERGE:"+fmt.Sprintf(" %s\n", mypath)), -1, nil)
		}
	} else {
		WriteMsg(fmt.Sprintf("!!! Invalid db entry: %s\n", mypath), -1, nil)
	}
}
func (d *dbapi) cpv_all() []*pkgStr {
	cpvList := []*pkgStr{}
	for _, cp := range d.cp_all(false) {
		cpvList = append(cpvList, d.cp_list(cp, 1)...)
	}
	return cpvList
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
		pkg := NewPkgStr(cpv.string, metadata, d.settings, "", "", "", 0, "", "", 0, "")
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

func (d *dbapi) _cpv_sort_ascending(cpv_list []*pkgStr) {
	if len(cpv_list) > 1 {
		sort.Slice(cpv_list, func(i, j int) bool {
			return d._cmp_cpv(cpv_list[i], cpv_list[j]) < 0
		})
	}
}

func (d *dbapi) auxGet(myCpv *pkgStr, myList []string, myRepo string) []string {
	panic("NotImplementedError")
	return nil
}

func (d *dbapi) auxUpdate(cpv string, metadataUpdates map[string]string) {
	panic("NotImplementedError")
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

func (d *dbapi) cp_all(sort bool) []string { // false
	panic("")
	return nil
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
	_exclude_dirs, _aux_cache_keys_re, _aux_multi_line_re *regexp.Regexp
	_aux_cache_version, _owners_cache_version             string
	_aux_cache_threshold                                  int

	_pkgs_changed, _flush_cache_enabled                                                        bool
	mtdircache, matchcache, cpcache, blockers, _slot_locks                                     map[string]string
	_eroot, _dbroot, _conf_mem_file, _aux_cache_filename, _cache_delta_filename, _counter_path string
	_lock, _fs_lock_obj, _aux_cache_obj, _cached_counter                                       interface{}
	_lock_count, _fs_lock_count                                                                int
	vartree                                                                                    *varTree
	_aux_cache_keys                                                                            map[string]bool
	_cache_delta                                                                               *vdbMetadataDelta
	_plib_registry                                                                             *preservedLibsRegistry
	_linkmap                                                                                   *linkageMapELF
	_owners                                                                                    *_owners_db
}

func (v *vardbapi) writable() bool {
	st, err := os.Stat(firstExisting(v._dbroot))
	return err != nil && st.Mode()&os.FileMode(os.O_WRONLY) != 0
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
		if v._lock != nil {
			//raise AssertionError("already locked")
		}
		ensureDirs(v._dbroot, -1, -1, -1, -1, nil, true)
		//v._lock
	}
}

func (v *vardbapi) unlock() {}

func (v *vardbapi) _fs_lock() {}

func (v *vardbapi) _fs_unlock() {}

func (v *vardbapi) _slot_lock() {}

func (v *vardbapi) _slot_unlock() {}

func (v *vardbapi) _bump_mtime() {}

func (v *vardbapi) cpv_exists() {}

func (v *vardbapi) cpv_counter() {}

func (v *vardbapi) cpv_inject() {}

func (v *vardbapi) isInjected() {}

func (v *vardbapi) move_ent() {}

func (v *vardbapi) cp_list() {}

func (v *vardbapi) cpv_all() {}

func (v *vardbapi) _iter_cpv_all() {}

func (v *vardbapi) checkblockers() {}

func (v *vardbapi) _clear_cache() {}

func (v *vardbapi) _add() {}

func (v *vardbapi) _remove() {}

func (v *vardbapi) _clear_pkg_cache() {}

func (v *vardbapi) match() {}

func (v *vardbapi) findname() {}

func (v *vardbapi) flush_cache() {}

func (v *vardbapi) _aux_cache() {}

func (v *vardbapi) _aux_cache_init() {}

func (v *vardbapi) aux_get() {}

func (v *vardbapi) _aux_get() {}

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
	v._exclude_dirs = regexp.MustCompile("^(\\..*|" + MergingIdentifier + ".*|" + strings.Join(e, "|") + ")$")
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
	v._lock = nil
	v._lock_count = 0

	v._conf_mem_file = v._eroot + ConfigMemoryFile
	v._fs_lock_obj = nil
	v._fs_lock_count = 0
	v._slot_locks = map[string]string{}

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
	_exclusive_slots              bool
	cpvdict, cpdict, _match_cache map[string]string
}

func (f *fakedbapi) _set_multi_instance() {}

func (f *fakedbapi) _instance_key_cpv(cpv *pkgStr, support_string bool) *pkgStr { // false
	return cpv
}

func (f *fakedbapi) _instance_key_multi_instance() {}

func (f *fakedbapi) clear() {
	f._clear_cache()
	f.cpvdict = map[string]string{}
	f.cpdict = map[string]string{}
}

func (f *fakedbapi) _clear_cache() {
	if f._categories != nil {
		f._categories = nil
	}
	if len(f._match_cache) > 0 {
		f._match_cache = map[string]string{}
	}
}

func (f *fakedbapi) match() {}

func (f *fakedbapi) cpv_exists() {}

func (f *fakedbapi) cp_list() {}

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

func (f *fakedbapi) cpv_all() {}

func (f *fakedbapi) cpv_inject() {}

func (f *fakedbapi) cpv_remove() {}

func (f *fakedbapi) aux_get() {}

func (f *fakedbapi) aux_update() {}

func NewFakeDbApi(settings *Config, exclusive_slots, multi_instance bool) *fakedbapi { // nil, true, false
	f := &fakedbapi{dbapi: NewDbapi(), _exclusive_slots: exclusive_slots,
		cpvdict: map[string]string{},
		cpdict:  map[string]string{}}
	f.settings = settings
	f._match_cache = map[string]string{}
	return f
}

type bindbapi struct {
	*fakedbapi
	bintree  *binarytree
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

func (b *bindbapi) match() {}

func (b *bindbapi) cpv_exists(cpv, myrepo string) {}

func (b *bindbapi) cpv_inject() {}

func (b *bindbapi) cpv_remove() {}

func (b *bindbapi) aux_get() {}

func (b *bindbapi) aux_update() {}

func (b *bindbapi) cp_list() {}

func (b *bindbapi) cp_all() {}

func (b *bindbapi) cpv_all() {}

func (b *bindbapi) getfetchsizes() {}

func NewBinDbApi(mybintree *binarytree, settings *Config) *bindbapi { //
	b := &bindbapi{}
	b.fakedbapi = NewFakeDbApi(settings, false, true)
	b.bintree = mybintree
	b.move_ent = mybintree.move_ent
	b.auxCacheKeys = map[string]bool{}
	//b._aux_cache_slot_dict
	b._aux_chache = map[string]string{}
	return b
}

type binarytree struct {
	pkgdir string
}

func (b *binarytree) root() {}

func (b *binarytree) move_ent() {}

func (b *binarytree) prevent_collision() {}

func (b *binarytree) _ensure_dir() {}

func (b *binarytree) _file_permissions() {}

func (b *binarytree) populate() {}

func (b *binarytree) _populate_local() {}

func (b *binarytree) _populate_remote() {}

func (b *binarytree) inject() {}

func (b *binarytree) _read_metadata() {}

func (b *binarytree) _inject_file() {}

func (b *binarytree) _pkgindex_write() {}

func (b *binarytree) _pkgindex_entry() {}

func (b *binarytree) _new_pkgindex() {}

func (b *binarytree) _merge_pkgindex_header() {}

func (b *binarytree) _propagate_config() {}

func (b *binarytree) _update_pkgindex_header() {}

func (b *binarytree) _pkgindex_version_supported() {}

func (b *binarytree) _eval_use_flags() {}

func (b *binarytree) exists_specific() {}

func (b *binarytree) dep_bestmatch() {}

func (b *binarytree) getname() {}

func (b *binarytree) _is_specific_instance() {}

func (b *binarytree) _max_build_id() {}

func (b *binarytree) _allocate_filename() {}

func (b *binarytree) _allocate_filename_multi() {}

func (b *binarytree) _parse_build_id() {}

func (b *binarytree) isremote() {}

func (b *binarytree) get_pkgindex_uri() {}

func (b *binarytree) gettbz2() {}

func (b *binarytree) _load_pkgindex() {}

func (b *binarytree) _get_digests() {}

func (b *binarytree) digestCheck() {}

func (b *binarytree) getslot() {}

func NewBinaryTree(pkgDir string, setting *Config) *binarytree {
	b := &binarytree{}
	return b
}

type portdbapi struct {
	*dbapi
}

func NewPortDbApi() *portdbapi {
	p := &portdbapi{}
	return p
}

type portagetree struct {
}

func NewPortageTree(setting *Config) *portagetree {
	p := &portagetree{}
	return p
}
