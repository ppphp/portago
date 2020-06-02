package atom

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/ppphp/shlex"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
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
func dep_expandS(myDep string, myDb *dbapi, useCache int, settings *Config) *Atom {
	origDep := myDep
	if myDep == "" {
		return nil
	}
	if myDep[0] == '*' {
		myDep = myDep[1:]
		origDep = myDep
	}
	hasCat := strings.Contains(strings.Split(origDep, ":")[0], "/")
	if !hasCat {
		re := regexp.MustCompile("\\w")
		alphanum := re.FindStringSubmatchIndex(origDep)
		if len(alphanum) > 0 {
			myDep = origDep[:alphanum[0]] + "null/" + origDep[alphanum[0]:]
		}
	}
	allowRepo := true
	myDepA, err := NewAtom(myDep, nil, false, &allowRepo, nil, "", nil, nil)
	if err != nil {
		//except InvalidAtom:
		if !isValidAtom("="+myDep, false, false, true, "", false) {
			//raise
		}
		myDepA, _ = NewAtom("="+myDep, nil, false, &allowRepo, nil, "", nil, nil)
		origDep = "=" + origDep
	}

	if !hasCat {
		myDep = catsplit(myDepA.cp)[1]
	}

	if hasCat {
		if strings.HasPrefix(myDepA.cp, "virtual/") {
			return myDepA
		}
		if len(myDb.cp_list(myDepA.cp, 1)) > 0 {
			return myDepA
		}
		myDep = myDepA.cp
	}

	expanded := cpv_expand(myDep, myDb, useCache, settings)
	r := true
	a, _ := NewAtom(strings.Replace(myDep, origDep, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}

//nil,1,nil
func dep_expand(myDep *Atom, myDb *dbapi, useCache int, settings *Config) *Atom {
	origDep := myDep
	d := myDep.value
	if !strings.HasPrefix(myDep.cp, "virtual/") {
		return myDep
	}
	d = myDep.cp

	expanded := cpv_expand(d, myDb, useCache, settings)
	r := true
	a, _ := NewAtom(strings.Replace(d, origDep.value, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}

func cpv_expand(myCpv string, myDb *dbapi, useCache int, settings *Config) string { // n1n
	mySlash := strings.Split(myCpv, "/")
	mySplit := pkgSplit(mySlash[len(mySlash)-1], "")
	if settings == nil {
		settings = myDb.settings
	}
	myKey := ""
	if len(mySlash) > 2 {
		mySplit = [3]string{}
		myKey = myCpv
	} else if len(mySlash) == 2 {
		if mySplit != [3]string{} {
			myKey = mySlash[0] + "/" + mySplit[0]
		} else {
			myKey = myCpv
		}
	}
	if strings.HasPrefix(myKey, "virtual/") && len(myDb.cp_list(myKey, useCache)) == 0 {
		//		if hasattr(myDb, "vartree"):
		//		settings._populate_treeVirtuals_if_needed(myDb.vartree)
		//		virts = settings.getvirtuals().get(myKey)
		//		if virts:
		//		mykey_orig = myKey
		//		for vkey in virts:
		//		if myDb.cp_list(vkey.cp):
		//		myKey = str(vkey)
		//		break
		//		if myKey == mykey_orig:
		//		myKey = str(virts[0])
		//	}
	} else {
		//	if mySplit:
		//	myp=mySplit[0]
		//	else:
		//	myp=myCpv
		//	myKey=nil
		//	matches=[]
		//	if myDb && hasattr(myDb, "categories"):
		//	for x in myDb.categories:
		//	if myDb.cp_list(x+"/"+myp,use_cache=use_cache):
		//	matches.append(x+"/"+myp)
		//	if len(matches) > 1:
		//	virtual_name_collision = false
		//	if len(matches) == 2:
		//	for x in matches:
		//	if not x.startswith("virtual/"):
		//	myKey = x
		//	else:
		//	virtual_name_collision = true
		//	if not virtual_name_collision:
		//		raise AmbiguousPackageName(matches)
		//	elif matches:
		//	myKey=matches[0]
		//
		//	if not myKey && not isinstance(myDb, list):
		//	if hasattr(myDb, "vartree"):
		//	settings._populate_treeVirtuals_if_needed(myDb.vartree)
		//	virts_p = settings.get_virts_p().get(myp)
		//	if virts_p:
		//	myKey = virts_p[0]
		//	if not myKey:
		//	myKey="null/"+myp
	}
	if mySplit != [3]string{} {
		if mySplit[2] == "r0" {
			return myKey + "-" + mySplit[1]
		} else {
			return myKey + "-" + mySplit[1] + "-" + mySplit[2]
		}
	} else {
		return myKey
	}
}

type DBAPI interface {
	categories() []string
	close_caches()
	cp_list(cp string, useCache int) []*PkgStr
	_cmp_cpv(cpv1, cpv2 *PkgStr) int
	_cpv_sort_ascending(cpv_list []*PkgStr)
	cpv_all() []*PkgStr
	AuxGet(myCpv *PkgStr, myList []string, myRepo string) []string
	auxUpdate(cpv string, metadataUpdates map[string]string)
	match(origdep *Atom, useCache int) []*PkgStr
	_iter_match(atom *Atom, cpvIter []*PkgStr) []*PkgStr
	_pkg_str(cpv *PkgStr, repo string) *PkgStr
	_iter_match_repo(atom *Atom, cpvIter []*PkgStr) []*PkgStr
	_iter_match_slot(atom *Atom, cpvIter []*PkgStr) []*PkgStr
	_iter_match_use(atom *Atom, cpvIter []*PkgStr) []*PkgStr
	_repoman_iuse_implicit_cnstr(pkg, metadata map[string]string) func(flag string) bool
	_iuse_implicit_cnstr(pkg *PkgStr, metadata map[string]string) func(string) bool
	_match_use(atom *Atom, pkg *PkgStr, metadata map[string]string, ignore_profile bool) bool
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
func (d *dbapi) cp_list(cp string, useCache int) []*PkgStr {
	panic("")
	return nil
}

func (d *dbapi) _cmp_cpv(cpv1, cpv2 *PkgStr) int {
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

func (d *dbapi) _cpv_sort_ascending(cpvList []*PkgStr) {
	if len(cpvList) > 1 {
		sort.Slice(cpvList, func(i, j int) bool {
			return d._cmp_cpv(cpvList[i], cpvList[j]) < 0
		})
	}
}

func (d *dbapi) cpv_all() []*PkgStr {
	cpvList := []*PkgStr{}
	for _, cp := range d.cp_all(false) {
		cpvList = append(cpvList, d.cp_list(cp, 1)...)
	}
	return cpvList
}

func (d *dbapi) cp_all(sort bool) []string { // false
	panic("")
	return nil
}

func (d *dbapi) AuxGet(myCpv *PkgStr, myList []string, myRepo string) []string {
	panic("NotImplementedError")
	return nil
}

func (d *dbapi) auxUpdate(cpv string, metadataUpdates map[string]string) {
	panic("NotImplementedError")
}

func (d *dbapi) match(origdep *Atom, useCache int) []*PkgStr { // 1
	mydep := dep_expand(origdep, d, 1, d.settings)
	return d._iter_match(mydep, d.cp_list(mydep.cp, useCache))
}

func (d *dbapi) _iter_match(atom *Atom, cpvIter []*PkgStr) []*PkgStr {
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

func (d *dbapi) _pkg_str(cpv *PkgStr, repo string) *PkgStr {
	//try:
	//cpv.slot
	//except AttributeError:
	//pass
	//else:
	return cpv
	//
	//metadata = dict(zip(d._pkg_str_aux_keys,
	//d.aux_get(cpv, d._pkg_str_aux_keys, myrepo=repo)))
	//
	//return _pkg_str(cpv, metadata=metadata, settings=d.settings, db=d)
}

func (d *dbapi) _iter_match_repo(atom *Atom, cpvIter []*PkgStr) []*PkgStr {
	r := []*PkgStr{}
	for _, cpv := range cpvIter {
		pkgStr := d._pkg_str(cpv, atom.repo)
		if pkgStr.repo == atom.repo {
			r = append(r, pkgStr)
		}
	}
	return r
}

func (d *dbapi) _iter_match_slot(atom *Atom, cpvIter []*PkgStr) []*PkgStr {
	r := []*PkgStr{}
	for _, cpv := range cpvIter {
		pkgStr := d._pkg_str(cpv, atom.repo)
		if matchSlot(atom, cpv) {
			r = append(r, pkgStr)
		}
	}
	return r
}

func (d *dbapi) _iter_match_use(atom *Atom, cpvIter []*PkgStr) []*PkgStr {
	aux_keys := []string{"EAPI", "IUSE", "KEYWORDS", "SLOT", "USE", "repository"}

	r := []*PkgStr{}
	for _, cpv := range cpvIter {
		metadata := map[string]string{}
		a := d.AuxGet(cpv, aux_keys, atom.repo)
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
	var iUseImplicitMatch func(flag string) bool = nil
	if eapiAttrs.iuseEffective {
		iUseImplicitMatch = func(flag string) bool {
			return d.settings.iuseEffectiveMatch(flag)
		}
	} else {
		iUseImplicitMatch = func(flag string) bool {
			return d.settings.iuseImplicitMatch.call(flag)
		}
	}
	return iUseImplicitMatch
}

func (d *dbapi) _iuse_implicit_cnstr(pkg *PkgStr, metadata map[string]string) func(string) bool {
	eapiAttrs := getEapiAttrs(metadata["EAPI"])
	var iUseImplicitMatch func(string) bool
	if eapiAttrs.iuseEffective {
		iUseImplicitMatch = d.settings.iuseEffectiveMatch
	} else {
		iUseImplicitMatch = d.settings.iuseImplicitMatch.call
	}

	if !d._use_mutable && eapiAttrs.iuseEffective {
		profIuse := iUseImplicitMatch
		enabled := strings.Fields(metadata["USE"])
		iUseImplicitMatch = func(flag string) bool {
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

	return iUseImplicitMatch
}

// false
func (d *dbapi) _match_use(atom *Atom, pkg *PkgStr, metadata map[string]string, ignoreProfile bool) bool {
	iUseImplicitMatch := d._iuse_implicit_cnstr(pkg, metadata)
	useAliases := d.settings.useManager.getUseAliases(pkg)
	iUse := NewIUse("", strings.Fields(metadata["IUSE"]), iUseImplicitMatch, useAliases, metadata["EAPI"])

	for x := range atom.unevaluatedAtom.Use.required {
		if iUse.getRealFlag(x) == "" {
			return false
		}
	}

	if atom.Use == nil {
	} else if !d._use_mutable {
		use := map[string]bool{}
		for _, x := range strings.Fields(metadata["USE"]) {
			if iUse.getRealFlag(x) != "" {
				use[x] = true
			}
		}
		missingEnabled := map[string]bool{}
		for x := range atom.Use.missingEnabled {
			if iUse.getRealFlag(x) == "" {
				missingEnabled[x] = true
			}
		}
		missingDisabled := map[string]bool{}
		for x := range atom.Use.missingDisabled {
			if iUse.getRealFlag(x) == "" {
				missingDisabled[x] = true
			}
		}
		enabled := map[string]bool{}
		for x := range atom.Use.enabled {
			if iUse.getRealFlag(x) != "" {
				enabled[iUse.getRealFlag(x)] = true
			} else {
				enabled[x] = true
			}
		}
		disabled := map[string]bool{}
		for x := range atom.Use.disabled {
			if iUse.getRealFlag(x) != "" {
				disabled[iUse.getRealFlag(x)] = true
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
		if !ignoreProfile {
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
				if iUse.getRealFlag(x) == "" {
					if atom.Use.enabled[x] {
						return false
					}
				}
			}
		}
		if len(atom.Use.disabled) > 0 {
			for x := range atom.Use.missingEnabled {
				if iUse.getRealFlag(x) == "" {
					if atom.Use.disabled[x] {
						return false
					}
				}
			}
		}
	}

	return true
}

func (d *dbapi) invalidentry(myPath string) {
	if strings.Contains(myPath, "/"+MergingIdentifier) {
		if _, err := os.Stat(myPath); err != nil {
			WriteMsg(colorize("BAD", "INCOMPLETE MERGE:"+fmt.Sprintf(" %s\n", myPath)), -1, nil)
		}
	} else {
		WriteMsg(fmt.Sprintf("!!! Invalid db entry: %s\n", myPath), -1, nil)
	}
}

func (d *dbapi) update_ents(updates map[string][][]*Atom, onProgress, onUpdate func(int, int)) {
	cpvAll := d.cpv_all()
	sort.Slice(cpvAll, func(i, j int) bool {
		return cpvAll[i].string < cpvAll[j].string
	})
	maxval := len(cpvAll)
	auxGet := d.AuxGet
	auxUpdate := d.auxUpdate
	updateKeys := NewPackage(false, nil, false, nil, nil, "").depKeys
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

func (d *dbapi) move_slot_ent(myList []*Atom, repoMatch func(string) bool) int { // nil
	atom := myList[1]
	origSlot := myList[2]
	newSlot := myList[3]
	atom = atom.withSlot(origSlot.value)
	origMatches := d.match(atom, 1)
	moves := 0
	if len(origMatches) == 0 {
		return moves
	}
	for _, mycpv := range origMatches {
		mycpv = d._pkg_str(mycpv, atom.repo)
		if repoMatch != nil && !repoMatch(mycpv.repo) {
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
	getcontents           func() map[string][]string
	unmap_key              func(string) string
	contains              func(string) bool
	keys                  func() []string
	_contents_insensitive map[string][]string
	_reverse_key_map      map[string]string
}

func(c *ContentsCaseSensitivityManager) clear_cache() {
	c._contents_insensitive = nil
	c._reverse_key_map = nil
}



func(c *ContentsCaseSensitivityManager) _case_insensitive_init() {
	c._contents_insensitive = map[string][]string{}
	for k, v:= range c.getcontents(){
		c._contents_insensitive[strings.ToLower(k)] = v
	}
	c._reverse_key_map = map[string]string{}
	for k:= range c.getcontents(){
		c._reverse_key_map[strings.ToLower(k)] = k
	}
}

func(c *ContentsCaseSensitivityManager) _keys_case_insensitive() []string{
	if c._contents_insensitive == nil {
		c._case_insensitive_init()
	}
	ret := []string{}
	for k := range c._contents_insensitive{
		ret = append(ret, k)
	}
	return ret
}

func(c *ContentsCaseSensitivityManager) _contains_case_insensitive(key string) bool{
	if c._contents_insensitive ==nil {
		c._case_insensitive_init()
	}
	_, ok := c._contents_insensitive[strings.ToLower(key)]
	return ok
}

func(c *ContentsCaseSensitivityManager) _unmap_key_case_insensitive(key string) string {
	if c._reverse_key_map  ==nil {
		c._case_insensitive_init()
	}
	return c._reverse_key_map[key]
}

func NewContentsCaseSensitivityManager(db *dblink) *ContentsCaseSensitivityManager {
	c := &ContentsCaseSensitivityManager{}

	c.getcontents = db.getcontents

	c.keys = func() []string {
		ret := []string{}
		for k := range c.getcontents() {
			ret = append(ret, k)
		}
		return ret
	}
	c.contains = func(key string) bool {
		_, ok := c.getcontents()[key]
		return ok
	}
	c.unmap_key = func(key string) string {
		return key
	}
	if db.settings.Features.Features["case-insensitive-fs"] {
		c.unmap_key = c._unmap_key_case_insensitive
		c.contains = c._contains_case_insensitive
		c.keys = c._keys_case_insensitive
	}

	c._contents_insensitive = nil
	c._reverse_key_map = nil
	return c
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
	matchcache                          map[string]map[[2]*Atom][]*PkgStr
	blockers                            map[string]string
	cpcache                             map[string]struct {
		int64
		p []*PkgStr
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

func (v *vardbapi) getpath(myKey, filename string) string { // ""
	rValue := v._dbroot + VdbPath + string(os.PathSeparator) + myKey
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

func (v *vardbapi) _slot_lock(slotAtom *Atom) {
	lock := v._slot_locks[slotAtom].s
	counter := v._slot_locks[slotAtom].int
	if lock == nil {
		lockPath := v.getpath(fmt.Sprintf("%s:%s", slotAtom.cp, slotAtom.slot), "")
		ensureDirs(path.Dir(lockPath), -1, -1, -1, -1, nil, true)
		a, b, c, d, _ := Lockfile(lockPath, true, false, "", 0)
		lock = &struct {
			string
			int
			bool
			method func(int, int) error
		}{a, b, c, d}
	}
	v._slot_locks[slotAtom] = &struct {
		s *struct {
			string
			int
			bool
			method func(int, int) error
		}
		int
	}{lock, counter + 1}
}

func (v *vardbapi) _slot_unlock(slotAtom *Atom) {
	lock := v._slot_locks[slotAtom].s
	counter := v._slot_locks[slotAtom].int
	if lock == nil {
		panic("not locked")
	}
	counter -= 1
	if counter == 0 {
		Unlockfile(lock.string, lock.int, lock.bool, lock.method)
		delete(v._slot_locks, slotAtom)
	} else {
		v._slot_locks[slotAtom] = &struct {
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
	catDir := base + string(filepath.Separator) + cat
	t := time.Now()

	for _, x := range []string{catDir, base} {
		if err := syscall.Utime(x, &syscall.Utimbuf{Actime: t.Unix(), Modtime: t.Unix()}); err != nil {
			ensureDirs(catDir, -1, -1, -1, -1, nil, true)
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

func (v *vardbapi) cpv_counter(myCpv *PkgStr) int {
	s, err := strconv.Atoi(v.AuxGet(myCpv, []string{"COUNTER"}, "")[0])
	if err != nil {
		WriteMsgLevel(fmt.Sprintf("portage: COUNTER for %s was corrupted; resetting to value of 0\n", myCpv.string), 40, -1)
		return 0
	}
	return s
}

func (v *vardbapi) cpv_inject(myCpv *PkgStr) {
	ensureDirs(v.getpath(myCpv.string, ""), -1, -1, -1, -1, nil, true)
	counter := v.counter_tick()
	write_atomic(v.getpath(myCpv.string, "COUNTER"), string(counter), 0, true)
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
func (v *vardbapi) move_ent(myList []*Atom, repoMatch func(string) bool) int {
	origCp := myList[1]
	newCp := myList[2]

	for _, atom := range []*Atom{origCp, newCp} {
		if !isJustName(atom.value) {
			//raise InvalidPackageName(str(atom))
		}
	}
	origMatches := v.match(origCp, 0)
	moves := 0
	if len(origMatches) == 0 {
		return moves
	}
	for _, mycpv := range origMatches {
		mycpv = v._pkg_str(mycpv, "")
		mycpvCp := cpvGetKey(mycpv.string, "")
		if mycpvCp != origCp.value {
			continue
		}
		if repoMatch != nil && !repoMatch(mycpv.repo) {
			continue
		}

		if !isValidAtom(newCp.value, false, false, false, mycpv.eapi, false) {
			continue
		}

		myNewCpv := strings.Replace(mycpv.string, mycpvCp, newCp.value, 1)
		myNewCat := catsplit(newCp.value)[0]
		origPath := v.getpath(mycpv.string, "")
		if _, err := os.Stat(origPath); err != nil {
			continue
		}
		moves += 1
		if _, err := os.Stat(v.getpath(myNewCat, "")); err != nil {
			ensureDirs(v.getpath(myNewCat, ""), -1, -1, -1, -1, nil, true)
		}
		newPath := v.getpath(myNewCpv, "")
		if _, err := os.Stat(newPath); err == nil {
			continue
		}
		_movefile(origPath, newPath, 0, nil, v.settings, nil)
		v._clear_pkg_cache(v._dblink(mycpv.string))
		v._clear_pkg_cache(v._dblink(myNewCpv))

		oldPf := catsplit(mycpv.string)[1]
		newPf := catsplit(myNewCpv)[1]
		if newPf != oldPf {
			err := os.Rename(path.Join(newPath, oldPf+".ebuild"),
				path.Join(newPath, newPf+".ebuild"))
			if err != nil {
				if err != syscall.ENOENT {
					//raise
				}
				//del e
			}
		}
		write_atomic(path.Join(newPath, "PF"), newPf+"\n", 0, true)
		write_atomic(path.Join(newPath, "CATEGORY"), myNewCat+"\n", 0, true)
	}
	return moves
}

func (v *vardbapi) cp_list(myCp string, useCache int) []*PkgStr {
	mySplit := catsplit(myCp)
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

	returnMe := []*PkgStr{}
	for _, x := range dirList {
		if v._excluded_dirs.MatchString(x.Name()) {
			continue
		}
		ps := PkgSplit(x.Name(), 1, "")
		if ps == [3]string{} {
			v.invalidentry(path.Join(v.getpath(mySplit[0], ""), x.Name()))
			continue
		}
		if len(mySplit) > 1 {
			if ps[0] == mySplit[1] {
				cpv := fmt.Sprintf("%s/%s", mySplit[0], x)
				metadata := map[string]string{}
				for i := range v._aux_cache_keys {
					metadata[i] = v.aux_get(cpv, v._aux_cache_keys, "")[0]
				}
				returnMe = append(returnMe, NewPkgStr(cpv, metadata,
					v.settings, "", "", "", 0, 0, "", 0, v.dbapi))
			}
		}
	}
	v._cpv_sort_ascending(returnMe)
	if useCache != 0 {
		v.cpcache[myCp] = struct {
			int64
			p []*PkgStr
		}{myStat, returnMe}

	} else if _, ok := v.cpcache[myCp]; ok {
		delete(v.cpcache, myCp)
	}
	return returnMe
}

// 1
func (v *vardbapi) cpv_all(useCache int) []*PkgStr {
	return v._iter_cpv_all(useCache != 0, false)
}

// true, true
func (v *vardbapi) _iter_cpv_all(useCache, sort1 bool) []*PkgStr {
	basePath := filepath.Join(v._eroot, VdbPath) + string(filepath.Separator)
	listDir := listdir
	if !useCache {
		listDir = func(myPath string, recursive, filesOnly, ignoreCvs bool, ignoreList []string, followSymlinks, EmptyOnError, dirsOnly bool) []string {
			ss, err := ioutil.ReadDir(myPath)
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
	catDirs := listDir(basePath, false, false, true, []string{}, true, true, true)
	if sort1 {
		sort.Strings(catDirs)
	}

	ps := []*PkgStr{}
	for _, x := range catDirs {
		if v._excluded_dirs.MatchString(x) {
			continue
		}
		if !v._category_re.MatchString(x) {
			continue
		}
		pkgDirs := listDir(basePath+x, false, false, false, []string{}, true, true, true)
		if sort1 {
			sort.Strings(pkgDirs)
		}

		for _, y := range pkgDirs {
			if v._excluded_dirs.MatchString(y) {
				continue
			}
			subPath := x + "/" + y
			subPathP := NewPkgStr(subPath, nil, nil, "", "", "", 0, 0, "", 0, v.dbapi)
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
		mySplit := CatPkgSplit(y.string, 1, "")
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
	v.matchcache = map[string]map[[2]*Atom][]*PkgStr{}
	v.cpcache = map[string]struct {
		int64
		p []*PkgStr
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
func (v *vardbapi) match(origDep *Atom, useCache int) []*PkgStr {
	myDep := dep_expand(origDep, v.dbapi, useCache, v.settings)
	cacheKey := [2]*Atom{myDep, myDep.unevaluatedAtom}
	myKey := depGetKey(myDep.value)
	myCat := catsplit(myKey)[0]
	if useCache == 0 {
		if _, ok := v.matchcache[myKey]; ok {
			delete(v.mtdircache, myCat)
			delete(v.matchcache, myCat)
		}
		return v._iter_match(myDep,
			v.cp_list(myDep.cp, useCache))
	}
	st, err := os.Stat(path.Join(v._eroot, VdbPath, myCat))
	curMtime := 0
	if err == nil {
		curMtime = st.ModTime().Nanosecond()
	}

	if _, ok := v.matchcache[myCat]; !ok || v.mtdircache[myCat] != curMtime {
		v.mtdircache[myCat] = curMtime
		v.matchcache[myCat] = map[[2]*Atom][]*PkgStr{}
	}
	if _, ok := v.matchcache[myCat][[2]*Atom{myDep, nil}]; !ok {
		myMatch := v._iter_match(myDep,
			v.cp_list(myDep.cp, useCache))
		v.matchcache[myCat][cacheKey] = myMatch
	}
	return v.matchcache[myCat][cacheKey][:]
}

func (v *vardbapi) findname(myCpv string) string {
	return v.getpath(myCpv, catsplit(myCpv)[1]+".ebuild")
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
	//			# TODO: If py3k, override Unpickler.find_class().
	//			pass
	//		aux_cache = mypickle.load()
	//except (SystemExit, KeyboardInterrupt):
	//	raise
	//except Exception as e:
	//	if isinstance(e, EnvironmentError) && \
	//		getattr(e, 'errno', nil) in (errno.ENOENT, errno.EACCES):
	//		pass
	//	else:
	//		writemsg(_("!!! Error loading '%s': %s\n") % \
	//			(v._aux_cache_filename, e), noiselevel=-1)
	//	del e

	auxCache := &struct {
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
	auxCache.packages = map[string]*struct {
		cache_mtime int64
		metadata    map[string]string
	}{}

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
			base_names map[string]string
			version    int
		}{base_names: map[string]string{}, version: v._owners_cache_version}
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
		auxKeys := CopyMapSB(pullMe)
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

	eapiAttrs := getEapiAttrs(myData["EAPI"])
	if !getSlotRe(eapiAttrs).MatchString(myData["SLOT"]) {
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
			//elif e.errno == PermissionDenied.errno:
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
		myd, err := ioutil.ReadFile(path.Join(myDir, x))
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
		//if e.errno != errno.ENOENT:
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

			if Ins(variables, key) {
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

func (v *vardbapi) unpack_metadata() {}

func (v *vardbapi) unpack_contents() {}

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
		write_atomic(v._counter_path, fmt.Sprint(counter), 0, true)
		//except InvalidLocation:
		//v.settings._init_dirs()
		//write_atomic(v._counter_path, str(counter))
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
		filename = NormalizePath(filename)
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
		neededFilename := filepath.Join(pkg.dbdir, NewLinkageMapELF(nil)._needed_aux_key)
		var newNeeded []*NeededEntry = nil
		neededLines := []string{}
		f, err := os.Open(neededFilename)
		if err == nil {
			ls, _ := ioutil.ReadAll(f)
			neededLines = strings.Split(string(ls), "\n")
		}
		if err != nil {
			//except IOError as e:
			//if e.errno not in(errno.ENOENT, errno.ESTALE):
			//raise
		} else {
			newNeeded = []*NeededEntry{}
			for _, l := range neededLines {
				l = strings.TrimRight(l, "\n")
				if l == "" {
					continue
				}
				entry, err := NewNeededEntry().parse(neededFilename, l)
				if err != nil {
					//except InvalidData as e:
					WriteMsgLevel(fmt.Sprintf("\n%s\n\n", err),
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
func (v *vardbapi) writeContentsToContentsFile(pkg *dblink, new_contents map[string][]string, new_needed []*NeededEntry) {
	root := v.settings.ValueDict["ROOT"]
	v._bump_mtime(pkg.mycpv.string)
	if new_needed != nil {
		f := NewAtomic_ofstream(filepath.Join(pkg.dbdir, NewLinkageMapELF(nil)._needed_aux_key), os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
		for _, entry := range new_needed {
			f.Write([]byte(entry.__str__()))
		}
		f.Close()
	}
	f := NewAtomic_ofstream(filepath.Join(pkg.dbdir, "CONTENTS"), os.O_RDWR, true)
	write_contents(new_contents, root, f)
	f.Close()
	v._bump_mtime(pkg.mycpv.string)
	pkg._clear_contents_cache()
}

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
	v.matchcache = map[string]map[[2]*Atom][]*PkgStr{}
	v.cpcache = map[string]struct {
		int64
		p []*PkgStr
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

func (v *varTree) get_all_provides() map[string][]*PkgStr {
	return map[string][]*PkgStr{}
}

// 1
func (v *varTree) dep_bestmatch(mydep *Atom, use_cache int) string {
	s := []string{}
	for _, p := range v.dbapi.match(dep_expand(mydep, v.dbapi.dbapi, 1, v.settings), use_cache) {
		s = append(s, p.string)
	}
	mymatch := Best(s, "")
	if mymatch == "" {
		return ""
	} else {
		return mymatch
	}
}

// 1
func (v *varTree) dep_match(mydep *Atom, use_cache int) []*PkgStr {
	mymatch := v.dbapi.match(mydep, use_cache)
	if mymatch == nil {
		return []*PkgStr{}
	} else {
		return mymatch
	}

}

func (v *varTree) exists_specific(cpv string) bool {
	return v.dbapi.cpv_exists(cpv, "")
}

func (v *varTree) getallcpv() []*PkgStr {
	return v.dbapi.cpv_all(1)
}

func (v *varTree) getallnodes() []string {
	return v.dbapi.cp_all(1, false)
}

func (v *varTree) getebuildpath(fullpackage string) string {
	packagee := catsplit(fullpackage)[1]
	return v.getpath(fullpackage, packagee+".ebuild")
}

func (v *varTree) getslot(mycatpkg *PkgStr) string {
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
	mycpv                                                                           *PkgStr
	mysplit                                                                         []string
	vartree                                                                         *varTree
	settings                                                                        *Config
	_verbose, _linkmap_broken, _postinst_failure, _preserve_libs                    bool
	_contents                                                                       *ContentsCaseSensitivityManager
	contentscache                                                                   map[string][]string

	_hash_key           []string
	_protect_obj        *ConfigProtect
	_slot_locks         []*Atom
	_contents_basenames map[string]bool
	_contents_inodes    map[[2]uint64][]string
}

func (d *dblink) __hash__() {}

func (d *dblink) __eq__() {}

func (d *dblink) _get_protect_obj() *ConfigProtect {
	cp, _ := shlex.Split(
		strings.NewReader(d.settings.ValueDict["CONFIG_PROTECT"]), false, true)
	cpm, _ := shlex.Split(
		strings.NewReader(d.settings.ValueDict["CONFIG_PROTECT_MASK"]), false, true)
	if d._protect_obj == nil {
		d._protect_obj = NewConfigProtect(d._eroot,
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

	slot_atoms := []*Atom{}

	//try:
	slot := d.mycpv.slot
	//except AttributeError:
	//slot, = db.aux_get(d.mycpv, ["SLOT"])
	//slot = slot.partition("/")[0]

	a, _ := NewAtom(
		fmt.Sprintf("%s:%s", d.mycpv.cp, slot), nil, false, nil, nil, "", nil, nil)

	slot_atoms = append(slot_atoms, a)

	for _, blocker := range d._blockers || []string{} {
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
		WriteMsg(fmt.Sprintf("portage.dblink.delete(): invalid dbdir: %s\n", d.dbdir), -1, nil)
		return
	}

	if d.dbdir == d.dbpkgdir {
		counter := d.vartree.dbapi.aux_get(
			d.mycpv, []string{"COUNTER"}, "")
		d.vartree.dbapi._cache_delta.recordEvent(
			"remove", d.mycpv,
			strings.Split(d.settings["SLOT"], "/")[0], counter)
	}

	os.RemoveAll(d.dbdir)
	os.RemoveAll(filepath.Dir(d.dbdir))
	d.vartree.dbapi._remove(d)

	ls, _ := os.Lstat(d.dbroot)
	d._merged_path(d.dbroot, ls)

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
	contents_file := filepath.Join(d.dbdir, "CONTENTS")
	pkgfiles := map[string][]string{}
	f, err:= ioutil.ReadFile(contents_file)
	if err != nil {
		//except EnvironmentError as e:
		if err != syscall.ENOENT {
			//raise
		}
		//del e
		d.contentscache = pkgfiles
		return pkgfiles
	}
			
	mylines := strings.Split(string(f), "\n") 

	null_byte := []byte{0}
	normalize_needed := d._normalize_needed
	contents_re := d._contents_re
	var obj_index,dir_index,sym_index,oldsym_index int
	for i, v := range contents_re.SubexpNames(){
		switch v {
		case "obj":
			obj_index = i
		case "dir":
			dir_index = i
		case "sym":
			sym_index=i
		case "oldsym":
			oldsym_index = i
		}
	}
	myroot := d.settings.ValueDict["ROOT"]
	if myroot == string(os.PathSeparator) {
		myroot = ""
	}
	dir_entry := []string{"dir"}
	eroot_split_len := len(strings.Split(d.settings.ValueDict["EROOT"],string(os.PathSeparator))) - 1
	errors := []struct{int; string}{}
	for pos, line := range mylines {
		if strings.Contains(line, string(null_byte)) {
			errors = append(errors, struct{ int; string }{pos + 1, "Null byte found in CONTENTS entry"})
			continue
		}
		line = strings.TrimRight(line, "\n")
		m := contents_re.FindAllString(line, -1)
		if m == nil {
			errors= append(errors, struct{ int; string }{pos + 1, "Unrecognized CONTENTS entry"})
			continue
		}

		base:=0
		var data []string
		if m[obj_index] != "" {
			base = obj_index
			data = []string{m[base + 1], m[base + 4], m[base + 3]}
		}else if m[dir_index]!= ""{
				base = dir_index
				data = []string{m[base + 1]}
		}else if m[sym_index]!= "" {
			base = sym_index
			mtime := ""
			if m[oldsym_index] =="" {
				mtime = m[base + 5]
			} else {
				mtime = m[base+8]
			}
			data = []string{m[base + 1], mtime, m[base + 3]}
		}else{
			//raise AssertionError(_("required group not found " + \
			//"in CONTENTS entry: '%s'") % line)
		}

		path := m[base + 2]
		if normalize_needed.MatchString(path) {
			path = NormalizePath(path)
			if ! strings.HasPrefix(path, string(os.PathSeparator)) {
				path = string(os.PathSeparator) + path
			}
		}

		if myroot != "" {
			path = filepath.Join(myroot, strings.TrimLeft(path, string(os.PathSeparator)))
		}

		path_split := strings.Split(path, string(os.PathSeparator))
		path_split = path_split[:len(path_split)-1]
		for len(path_split) > eroot_split_len {
			parent:= strings.Join(path_split, string(os.PathSeparator))
			if _, ok := pkgfiles[parent]; ok {
				break
			}
			pkgfiles[parent] = dir_entry
			path_split = path_split[:len(path_split)-1]

		}

		pkgfiles[path] = data
	}

	if len(errors) > 0 {
		WriteMsg(fmt.Sprintf("!!! Parse error in '%s'\n", contents_file), -1, nil)
		for _, v := range errors {
			pos, e := v.int, v.string
			WriteMsg(fmt.Sprintf("!!!   line %d: %s\n", pos, e), -1, nil)
		}
	}
	d.contentscache = pkgfiles
	return pkgfiles
}

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

func (d *dblink) _match_contents(filename string) string {
	destroot := d.settings.ValueDict["ROOT"]

	destfile := NormalizePath(
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
					if !Ins(p_path_list,p_path) {
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

func (d *dblink) setfile(fname, data string) {
	write_atomic(filepath.Join(d.dbdir, fname), data, os.O_RDWR|os.O_TRUNC|os.O_CREATE, true)
}

func (d *dblink) getelements() {}

func (d *dblink) setelements() {}

func (d *dblink) isregular() {

}

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
	d._slot_locks = []*Atom{}

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
	cpdict           map[string][]*PkgStr
	_match_cache     map[[2]string][]*PkgStr
	_instance_key    func(*PkgStr, bool) *PkgStr
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
func (f *fakedbapi) _instance_key_cpv(cpv *PkgStr, support_string bool) *PkgStr {
	return cpv
}

// false
func (f *fakedbapi) _instance_key_multi_instance(cpv *PkgStr, support_string bool) *PkgStr {
	return NewPkgStr(cpv.string, nil, nil, "", "", "", cpv.buildTime, cpv.buildId, cpv.fileSize, cpv.mtime, nil)
	//except AttributeError:
	//if ! support_string{
	//	//raise
	//}
	//
	//	latest := nil
	//for _, pkg := range f.cp_list(cpv_getkey(cpv)){
	//
	//	if pkg == cpv && (
	//		latest == nil or
	//	latest.build_time < pkg.build_time):
	//	latest = pkg
	//}
	//
	//if latest != nil:
	//return (latest, latest.build_id, latest.file_size,
	//	latest.build_time, latest.mtime)
	//
	//raise KeyError(cpv)
}

func (f *fakedbapi) clear() {
	f._clear_cache()
	f.cpvdict = map[string]map[string]string{}
	f.cpdict = map[string][]*PkgStr{}
}

func (f *fakedbapi) _clear_cache() {
	if f._categories != nil {
		f._categories = nil
	}
	if len(f._match_cache) > 0 {
		f._match_cache = map[[2]string][]*PkgStr{}
	}
}

// 1
func (f *fakedbapi) match(origdep *Atom, use_cache int) []*PkgStr {
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

func (f *fakedbapi) cpv_exists(mycpv *PkgStr) bool {
	_, ok := f.cpvdict[f._instance_key(mycpv,
		true).string]
	return ok
}

// 1
func (f *fakedbapi) cp_list(mycp string, use_cache int) []*PkgStr {
	cacheKey := [2]string{mycp, mycp}
	cacheList := f._match_cache[cacheKey]
	if cacheList != nil {
		return cacheList[:]
	}
	cpvList := f.cpdict[mycp]
	if cpvList == nil {
		cpvList = []*PkgStr{}
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

func (f *fakedbapi) cpv_inject(mycpv *PkgStr, metadata map[string]string) {
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
		cpList = []*PkgStr{}
	}
	tmp := cpList
	cpList = []*PkgStr{}
	for _, x := range tmp {
		if f._instance_key(x, false) != instanceKey {
			cpList = append(cpList, x)
		}
	}
	cpList = append(cpList, mycpv)
	f.cpdict[myCp] = cpList
}

func (f *fakedbapi) cpv_remove(mycpv *PkgStr) {
	f._clear_cache()
	myCp := cpvGetKey(mycpv.string, "")
	instanceKey := f._instance_key(mycpv, false)
	delete(f.cpvdict, instanceKey.string)
	cpList := f.cpdict[myCp]
	if cpList != nil {
		tmp := cpList
		cpList = []*PkgStr{}
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
func (f *fakedbapi) aux_get(mycpv *PkgStr, wants []string) []string {
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

func (f *fakedbapi) aux_update(cpv *PkgStr, values map[string]string) {
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
		cpdict:  map[string][]*PkgStr{}}
	if settings == nil {
		settings = Settings()
	}
	f.settings = settings
	f._match_cache = map[[2]string][]*PkgStr{}
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
func (b *bindbapi) match(origdep *Atom, use_cache int) []*PkgStr {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.match(origdep, use_cache)
}

func (b *bindbapi) cpv_exists(cpv *PkgStr) bool {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.cpv_exists(cpv)
}

func (b *bindbapi) cpv_inject(cpv *PkgStr) {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	b.fakedbapi.cpv_inject(cpv, cpv.metadata)
}

func (b *bindbapi) cpv_remove(cpv *PkgStr) {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	b.fakedbapi.cpv_remove(cpv)
}

func (b *bindbapi) aux_get(mycpv *PkgStr, wants map[string]string) []string {
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
func (b *bindbapi) cp_list(mycp string, use_cache int) []*PkgStr {
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
	_allocate_filename                                                                                           func(cpv *PkgStr) string
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
		if !Ins(b._pkgindex_hashes, k) {
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
				name_split := CatPkgSplit(mycat+"/"+mypf, 1, "")
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
			//b.dbapi.cpv_remove(mycpv)
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

func (b *BinaryTree) _pkgindex_entry(cpv *PkgStr) map[string]string {

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
func (b *BinaryTree) exists_specific(cpv string) []*PkgStr {
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
	mymatch := Best(ml, "")
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

func (b *BinaryTree) _max_build_id(cpv *PkgStr) int {
	max_build_id := 0
	for _, x := range b.dbapi.cp_list(cpv.cp, 1) {
		if x.string == cpv.string && x.buildId != 0 && x.buildId > max_build_id {
			max_build_id = x.buildId
		}
	}
	return max_build_id
}

func (b *BinaryTree) _allocate_filename_multi(cpv *PkgStr) string {
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

func (b *BinaryTree) isremote(pkgname *PkgStr) bool {
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
		b._allocate_filename = func(cpv *PkgStr) string {
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
	_use_mutable            bool
	repositories            *repoConfigLoader
	treemap                 map[string]string
	doebuild_settings       *Config
	depcachedir             string
	porttrees               []string
	_have_root_eclass_dir   bool
	xcache                  map[string]string
	frozen                  int
	auxdb                   map[string]string
	_pregen_auxdb           map[string]string
	_ro_auxdb               map[string]string
	_ordered_repo_name_list []string
	_aux_cache_keys         map[string]bool
	_aux_cache              map[string]string
	_broken_ebuilds         map[string]bool
	_better_cache           interface{}
	_porttrees_repos        map[string]*RepoConfig
}

func (p *portdbapi) _categories() map[string]bool{
	return p.settings.categories
}

func (p *portdbapi) _set_porttrees(porttrees []string) {
	for _, location := range porttrees {
		repo := p.repositories.getRepoForLocation(location)
			p._porttrees_repos[repo.Name] = repo
	}
	p.porttrees = porttrees
}

func (p *portdbapi) _get_porttrees() []string {
	return p.porttrees
}

func (p *portdbapi) _event_loop() {}

func (p *portdbapi) _create_pregen_cache(tree string) {
	conf := p.repositories.getRepoForLocation(tree)
	cache := conf.get_pregenerated_cache(p._known_keys, true,false)
	if cache!= nil {

	}
}

func (p *portdbapi) _init_cache_dirs() {
	ensureDirs(p.depcachedir, -1, *portage_gid,
		0o2070, 0o2, nil, true)
}

func (p *portdbapi) close_caches() {}

func (p *portdbapi) flush_cache() {}

func (p *portdbapi) findLicensePath() {}

func (p *portdbapi) findname(mycpv, mytree = None, myrepo = None) {
	return p.findname2(mycpv, mytree, myrepo)[0]
}

func (p *portdbapi) getRepositoryPath() {}

func (p *portdbapi) getRepositoryName() {}

func (p *portdbapi) getRepositories() {}

func (p *portdbapi) getMissingRepoNames() map[string]bool{
	return p.settings.Repositories.missingRepoNames
}

func (p *portdbapi) getIgnoredRepos() []sss{
	return p.settings.Repositories.ignoredRepos
}

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

// nil
func NewPortDbApi(mysettings *Config) *portdbapi {
	p := &portdbapi{}
	p._use_mutable = true
	if mysettings != nil {
		p.settings = mysettings
	} else {
		p.settings = NewConfig(Settings(), nil, "", nil, "", "", "", "", true, nil, false, nil)
	}

	p.repositories = p.settings.Repositories
	p.treemap = p.repositories.treeMap

	p.doebuild_settings = NewConfig(p.settings, nil, "", nil, "", "", "", "", true, nil, false, nil)
	p.depcachedir, _ = filepath.EvalSymlinks(p.settings.depcachedir)

	if os.Getenv("SANDBOX_ON") == "1" {
		sandbox_write := strings.Split(os.Getenv("SANDBOX_WRITE"), ":")
		if !Ins(sandbox_write, p.depcachedir) {
			sandbox_write = append(sandbox_write, p.depcachedir)
			os.Setenv("SANDBOX_WRITE", strings.Join(sandbox_write, ":"))
		}
	}

	p.porttrees = p.settings.Repositories.repoLocationList
	st, _ := os.Stat(
		filepath.Join(p.settings.Repositories.mainRepoLocation(), "eclass"))

	p._have_root_eclass_dir = st != nil && st.IsDir()

	p.xcache = map[string]string{}
	p.frozen = 0

	rs := []string{}
	copy(rs, p.repositories.preposOrder)
	ReverseSlice(rs)
	p._ordered_repo_name_list = rs

	p.auxdbmodule = p.settings.load_best_module("portdbapi.auxdbmodule")
	p.auxdb = map[string]string{}
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
	if *secpass < 1 &&
		depcachedir_w_ok &&
		depcachedir_st != nil &&
		os.Getuid() == int(depcachedir_st.Sys().(syscall.Stat_t).Uid) &&
		os.Getgid() == int(depcachedir_st.Sys().(syscall.Stat_t).Gid) {

		depcachedir_unshared = true
	} else {
		cache_kwargs["gid"] = int(*portage_gid)
		cache_kwargs["perms"] = 0o664
	}

	if (*secpass < 1 && !depcachedir_unshared) || !depcachedir_w_ok {
		for _, x := range p.porttrees {
			p.auxdb[x] = volatile.database(
				p.depcachedir, x, p._known_keys,
				**cache_kwargs)
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
		}
		cache := p._create_pregen_cache(x)
		if cache != nil {
			p._pregen_auxdb[x] = cache
		}
	}

	p._aux_cache_keys = map[string]bool{
		"BDEPEND": true, "DEPEND": true, "EAPI": true,
		"INHERITED": true, "IUSE": true, "KEYWORDS": true, "LICENSE": true,
		"PDEPEND": true, "PROPERTIES": true, "RDEPEND": true, "repository": true,
		"RESTRICT": true, "SLOT": true, "DEFINED_PHASES": true, "REQUIRED_USE": true}

	p._aux_cache = map[string]string{}
	p._better_cache = nil
	p._broken_ebuilds = map[string]bool{}

	return p
}

type PortageTree struct {
	settings *Config
	dbapi    *portdbapi
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

func NewPortageTree(settings *Config) *PortageTree {
	p := &PortageTree{}
	if settings == nil {
		settings = Settings()
	}
	p.settings = settings
	p.dbapi = NewPortDbApi(settings)
	return p
}

type FetchlistDict struct {
	pkgdir, cp, mytree string
	settings           *Config
	portdb             *portdbapi
}

func (f *FetchlistDict) __getitem__() {}

func (f *FetchlistDict) __contains__() {}

func (f *FetchlistDict) has_key() {}

func (f *FetchlistDict) __iter__() {}

func (f *FetchlistDict) __len__() {}

func (f *FetchlistDict) keys() {}

func NewFetchlistDict(pkgdir string, settings *Config, mydbapi *portdbapi) *FetchlistDict {
	f := &FetchlistDict{}
	f.pkgdir = pkgdir
	f.cp = filepath.Join(strings.Split(pkgdir, string(os.PathSeparator))[len(strings.Split(pkgdir, string(os.PathSeparator)))-2:]...)
	f.settings = settings
	f.mytree, _ = filepath.EvalSymlinks(filepath.Dir(filepath.Dir(pkgdir)))
	f.portdb = mydbapi

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
