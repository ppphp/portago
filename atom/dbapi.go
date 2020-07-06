package atom

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pkg/xattr"
	"github.com/ppphp/shlex"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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
	if myDep[0] == "*" {
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
		//		Settings._populate_treeVirtuals_if_needed(myDb.vartree)
		//		virts = Settings.getvirtuals().get(myKey)
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
		//	matches=append(,x+"/"+myp)
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
		//	else if matches:
		//	myKey=matches[0]
		//
		//	if not myKey && not isinstance(myDb, list):
		//	if hasattr(myDb, "vartree"):
		//	Settings._populate_treeVirtuals_if_needed(myDb.vartree)
		//	virts_p = Settings.get_virts_p().get(myp)
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
	//return _pkg_str(cpv, metadata=metadata, Settings=d.Settings, db=d)
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
	_vardb *vardbapi
}

func (v *vdbMetadataDelta) initialize(timestamp int) {

	f := NewAtomic_ofstream(v._vardb._cache_delta_filename, os.O_RDWR, true)
	ms, _ := json.Marshal(map[string]{
		"version":   v._format_version,
		"timestamp": timestamp,
	})
	f.Write(ms)
	f.Close()
}

func (v *vdbMetadataDelta) load() {

	if ! pathExists(v._vardb._aux_cache_filename) {
		return nil
	}

	f, err := ioutil.ReadFile(v._vardb._cache_delta_filename)
	cache_obj := map[string]interface{}{}
	if err == nil {
		err = json.Unmarshal(f, &cache_obj)
	}
	if err != nil {
	//except EnvironmentError as e:
	if err != syscall.ENOENT && err != syscall.ESTALE{
			//raise
		}
	//except (SystemExit, KeyboardInterrupt):
	//raise
	//except Exception:
	//	pass
	}else {
		//try:
		version, ok := cache_obj["version"]
		//except KeyError:
		//pass
		//else:
		if ok {
			if version == v._format_version {
				//try:
				deltas, ok := cache_obj["deltas"]
				//except
				//KeyError:
				if !ok {
					deltas = []
					cache_obj["deltas"] = deltas
				}

				if _, ok := deltas.([]interface{}) {
					return cache_obj
				}
			}
		}
	}
	return nil
}

func (v *vdbMetadataDelta) loadRace() {
	tries := 2
	for tries > 0 {
		tries -= 1
		cache_delta := v.load()
		if cache_delta != nil &&
			cache_delta.timestamp !=
				v._vardb._aux_cache().timestamp {
			v._vardb._aux_cache_obj = nil
		} else {
			return cache_delta
		}
	}
	return nil
}

func (v *vdbMetadataDelta) recordEvent(event string, cpv *PkgStr, slot, counter string) {

	v._vardb.lock()
try:
	deltas_obj := v.load()

	if deltas_obj == nil {
		return
	}

	delta_node := map[string]string{
		"event":   event,
		"package": cpv.cp,
		"version": cpv.version,
		"slot":    slot,
		"counter": fmt.Sprintf("%s", counter),
	}

	deltas_obj["deltas"] = append(deltas_obj["deltas"], delta_node)

	filtered_list := []map[string]string{}
	slot_keys := map[string]bool{}
	version_keys := map[string]bool{}
	for delta_node
		in
	reversed(deltas_obj["deltas"]) {
		slot_key := (delta_node["package"],
			delta_node["slot"])
		version_key := (delta_node["package"],
			delta_node["version"])
		if !(slot_keys[slot_key] || version_keys[version_key]) {
			filtered_list = append(filtered_list, delta_node)
			slot_keys[slot_key] = true
			version_keys[version_key] = true
		}
	}

	ReverseSlice(filtered_list)
	deltas_obj["deltas"] = filtered_list

	f := NewAtomic_ofstream(v._vardb._cache_delta_filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
	ms, _ := json.Marshal(deltas_obj)
	f.Write(ms)
	f.Close()
	v._vardb.unlock()
}

func (v *vdbMetadataDelta) applyDelta(data map[string][]map[string]string) {
	packages := v._vardb._aux_cache().packages
	deltas := map[string]map[string]string{}
	for _, delta := range data["deltas"] {
		cpv := delta["package"] + "-" + delta["version"]
		deltas[cpv] = delta
		event := delta["event"]
		if event == "add" {
			if _, ok := packages[cpv]; !ok {
				//try:
				v._vardb.aux_get(cpv, map[string]bool{"DESCRIPTION": true}, "")
				//except KeyError:
				//pass
			}
		} else if event == "remove" {
			delete(packages, cpv)
		}
	}

	if len(deltas) > 0 {
		for cached_cpv, v := range packages {
			metadata := v.metadata
			if Inmsmss(deltas, cached_cpv) {
				continue
			}

			removed := false
			cpv1 := ""
			for cpv, delta := range deltas {
				cpv1 = cpv
				if strings.HasPrefix(cached_cpv, delta["package"]) && metadata["SLOT"] == delta["slot"] && cpvGetKey(cached_cpv, "") == delta["package"] {
					removed = true
					break
				}
			}

			if removed {
				delete(packages, cached_cpv)
				delete(deltas, cpv1)
				if len(deltas) == 0 {
					break
				}
			}
		}
	}
}

func NewVdbMetadataDelta(vardb *vardbapi) *vdbMetadataDelta {
	v := &vdbMetadataDelta{}
	v._vardb = vardb
	return v
}

type auxCache struct {
	version  int
	packages map[string]*struct {
		cache_mtime int64
		metadata    map[string]string
	}
	owners *struct {
		base_names map[string]map[struct {
			s1 string;
			int;
			s2 string
		}]string
		version int
	}
	modified map[string]bool
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
	_fs_lock_obj                                                                               *LockFileS
	_slot_locks                                                                                map[*Atom]*struct {
		s *LockFileS
		int
	}
	_aux_cache_obj              *auxCache
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

func (v *vardbapi) getpath(myKey, filename string) string { // ""+
	rValue := v._dbroot + VdbPath + string(os.PathSeparator) + myKey
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
		v._fs_lock_obj, _ = Lockfile(v._conf_mem_file, false, false, "", 0)
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
		Unlockfile(v._fs_lock_obj)
		v._fs_lock_obj = nil
	}
	v._fs_lock_count -= 1
}

func (v *vardbapi) _slot_lock(slotAtom *Atom) {
	lock := v._slot_locks[slotAtom].s
	counter := v._slot_locks[slotAtom].int
	if lock == nil {
		lockPath := v.getpath(fmt.Sprintf("%s:%s", slotAtom.cp, slotAtom.slot), "")
		ensureDirs(filepath.Dir(lockPath), -1, -1, -1, -1, nil, true)
		lock, _ = Lockfile(lockPath, true, false, "", 0)
	}
	v._slot_locks[slotAtom] = &struct {
		s *LockFileS
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
		Unlockfile(lock)
		delete(v._slot_locks, slotAtom)
	} else {
		v._slot_locks[slotAtom] = &struct {
			s *LockFileS
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
	origMatches := v.match(origCp.value, 0)
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
			err := os.Rename(filepath.Join(newPath, oldPf+".ebuild"),
				filepath.Join(newPath, newPf+".ebuild"))
			if err != nil {
				if err != syscall.ENOENT {
					//raise
				}
				//del e
			}
		}
		write_atomic(filepath.Join(newPath, "PF"), newPf+"\n", 0, true)
		write_atomic(filepath.Join(newPath, "CATEGORY"), myNewCat+"\n", 0, true)
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
func (v *vardbapi) match(origDep string, useCache int) []*PkgStr {
	myDep := dep_expandS(origDep, v.dbapi, useCache, v.settings)
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
	st, err := os.Stat(filepath.Join(v._eroot, VdbPath, myCat))
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

func (v *vardbapi) flush_cache() {
	if v._flush_cache_enabled && v._aux_cache() != nil && *secpass >= 2 && (len(v._aux_cache().modified)) >= v._aux_cache_threshold || !pathExists(v._cache_delta_filename) {

		ensureDirs(filepath.Dir(v._aux_cache_filename), -1, -1, -1, -1, nil, true)
		v._owners.populate()
		valid_nodes := map[string]bool{}
		for _, v := range v.cpv_all() {
			valid_nodes[v] = true
		}
		for cpv := range v._aux_cache().packages {
			if !valid_nodes[cpv] {
				delete(v._aux_cache().packages, cpv)
			}
		}
		v._aux_cache().modified = nil
		timestamp := time.Now().Nanosecond()
		v._aux_cache().timestamp = timestamp

		f := NewAtomic_ofstream(v._aux_cache_filename, os.O_RDWR|os.O_CREATE, true)

		jm, _ :=json.Marshal(v._aux_cache())
		f.Write(jm)
		f.Close()
		apply_secpass_permissions(
			v._aux_cache_filename, -1, -1, 0644, -1, nil, true)

		v._cache_delta.initialize(timestamp)
		apply_secpass_permissions(v._cache_delta_filename, -1, -1, 0644, -1, nil, true)

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

func (v *vardbapi) unpack_metadata(pkg, dest_dir) {

	loop = asyncio._wrap_loop()
	if not isinstance(pkg, portage.config):
	cpv = pkg
	else:
	cpv = pkg.mycpv
	dbdir = v.getpath(cpv)
	def
	async_copy():
	for parent, dirs, files
	in
	os.walk(dbdir, onerror = _raise_exc):
	for key
	in
files:
	shutil.copy(filepath.Join(parent, key),
		filepath.Join(dest_dir, key))
	break
	yield
	loop.run_in_executor(ForkExecutor(loop = loop), async_copy)

}

func (v *vardbapi) unpack_contents(pkg, dest_dir,
	include_config=nil, include_unmodified_config=nil) {
	loop = asyncio._wrap_loop()
	if not isinstance(pkg, portage.config):
	settings = v.settings
	cpv = pkg
	else:
	settings = pkg
	cpv = settings.mycpv

	scheduler := NewSchedulerInterface(loop, nil)
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
	functools.partial(v._dblink(cpv).quickpkg,
	pw_file,
	include_config = opts.include_config == 'y',
	include_unmodified_config = opts.include_unmodified_config == 'y')))
	yield proc.wait()
	if proc.returncode != 0:
	raise PortageException('command failed: {}'.format(tar_cmd))

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
		//v.Settings._init_dirs()
		//write_atomic(v._counter_path, str(counter))
	}
	v._cached_counter = counter
	v.flush_cache()
	v.unlock()
	return counter
}

func (v *vardbapi) _dblink(cpv string) *dblink {
	category, pf := catsplit(cpv)[0], catsplit(cpv)[1]
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
			//if err not in(syscall.ENOENT, syscall.ESTALE):
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
		s *LockFileS
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
	v._aux_cache_filename = filepath.Join(v._eroot, CachePath, "vdb_metadata.pickle")
	v._cache_delta_filename = filepath.Join(v._eroot, CachePath, "vdb_metadata_delta.json")
	v._cache_delta = NewVdbMetadataDelta(v)
	v._counter_path = filepath.Join(v._eroot, CachePath, "counter")

	v._plib_registry = NewPreservedLibsRegistry(settings.ValueDict["ROOT"], filepath.Join(v._eroot, PrivatePath, "preserved_libs_registry"))
	v._linkmap = NewLinkageMapELF(v)
	v._owners = New_owners_db(v)

	v._cached_counter = nil

	return v
}

type varTree struct {
	settings  *Config
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

func (v *varTree) get_all_provides() map[string][]*PkgStr {
	return map[string][]*PkgStr{}
}

// 1
func (v *varTree) dep_bestmatch(myDep string, useCache int) string {
	s := []string{}
	for _, p := range v.dbapi.match(dep_expandS(myDep, v.dbapi.dbapi, 1, v.settings), useCache) {
		s = append(s, p.string)
	}
	myMatch := Best(s, "")
	if myMatch == "" {
		return ""
	} else {
		return myMatch
	}
}

// 1
func (v *varTree) dep_match(myDep *Atom, useCache int) []*PkgStr {
	myMatch := v.dbapi.match(myDep, useCache)
	if myMatch == nil {
		return []*PkgStr{}
	} else {
		return myMatch
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

func (v *varTree) getebuildpath(fullPackage string) string {
	packagee := catsplit(fullPackage)[1]
	return v.getpath(fullPackage, packagee+".ebuild")
}

func (v *varTree) getslot(myCatPkg *PkgStr) string {
	return v.dbapi._pkg_str(myCatPkg, "").slot
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
	_installed_instance *dblink
	_scheduler          *SchedulerInterface
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
		WriteMsg(fmt.Sprintf("portage.dblink.delete(): invalid dbdir: %s\n", d.dbdir), -1, nil)
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
			path = NormalizePath(path)
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
		WriteMsg(fmt.Sprintf("!!! Parse error in '%s'\n", contentsFile), -1, nil)
		for _, v := range errors {
			pos, e := v.int, v.string
			WriteMsg(fmt.Sprintf("!!!   line %d: %s\n", pos, e), -1, nil)
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
		confprot := NewConfigProtect(settings.ValueDict["EROOT"],
				ss1,ss2, settings.Features.Features["case-insensitive-fs"]))
		protect= func(filename string) bool {
			if ! confprot.IsProtected(filename){
				return false
			}
			if include_unmodified_config {
				file_data := contents[filename]
				if file_data[0] == "obj" {
					orig_md5 := strings.ToLower(file_data[2])
					cur_md5 := performMd5(filename, true)
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
func (d *dblink) _prune_plib_registry(unmerge bool,
	needed string, preserve_paths=nil) {
	if !(d._linkmap_broken || d.vartree.dbapi._linkmap == nil || d.vartree.dbapi._plib_registry == nil) {
		d.vartree.dbapi._fs_lock()
		plib_registry:= d.vartree.dbapi._plib_registry
		plib_registry.lock()
		defer func() {
			plib_registry.unlock()
			d.vartree.dbapi._fs_unlock()
		}()
		plib_registry.load()

		unmerge_with_replacement := unmerge&&preserve_paths!=nil

		var exclude_pkgs []*PkgStr
		if unmerge_with_replacement {
			exclude_pkgs = []*PkgStr{d.mycpv,}
		}

		d._linkmap_rebuild(exclude_pkgs, needed, preserve_paths)

		if unmerge{
			unmerge_preserve := []string{}
			if ! unmerge_with_replacement {
				unmerge_preserve =
					d._find_libs_to_preserve(true)
			}
			counter := d.vartree.dbapi.cpv_counter(d.mycpv)
		//try:
			slot := d.mycpv.slot
			//except  AttributeError:
			//slot = NewPkgStr(d.mycpv, slot = d.Settings.ValueDict["SLOT"]).slot
			plib_registry.unregister(d.mycpv.string, slot, counter)
			if len(unmerge_preserve) > 0{
				for _, path := range sorted(unmerge_preserve){
					contents_key := d._match_contents(path)
					if len(contents_key) > 0 {
						continue
					}
					obj_type := d.getcontents()[contents_key][0]
					d._display_merge(fmt.Sprintf(">>> needed   %s %s\n", obj_type, contents_key),0, -1)
				}
				plib_registry.register(d.mycpv.string, slot, counter, unmerge_preserve)
				d.vartree.dbapi.removeFromContents(d, unmerge_preserve, true)
			}
		}

		unmerge_no_replacement := unmerge&& !unmerge_with_replacement
		cpv_lib_map := d._find_unused_preserved_libs(unmerge_no_replacement)
		if len(cpv_lib_map) > 0 {
			d._remove_preserved_libs(cpv_lib_map)
			d.vartree.dbapi.lock()
		//try:
			for cpv, removed:= range cpv_lib_map {
				if ! d.vartree.dbapi.cpv_exists(cpv) {
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
	preserve_paths=nil) int {

	background := false
	log_path := d.settings.ValueDict["PORTAGE_LOG_FILE"]
	if d._scheduler == nil {
		d._scheduler = NewSchedulerInterface(asyncio._safe_loop())
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
			fmt.Sprintf("%s:%s", cpvGetKey(d.mycpv.string, ""), slot), 1)
		others_in_slot = []*dblink{}
		for _, cur_cpv := range slot_matches {
			if cur_cpv.string == d.mycpv.string {
				continue
			}
			others_in_slot = append(others_in_slot, NewDblink(d.cat, catsplit(cur_cpv.string)[1], "",
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
	mystuff, _ := listDir(d.dbdir)
	for _, x := range mystuff {
		if strings.HasSuffix(x, ".ebuild") {
			if x[:len(x)-7] != d.pkg {
				os.Rename(filepath.Join(d.dbdir, x), myebuildpath)
				write_atomic(filepath.Join(d.dbdir, "PF"), d.pkg+"\n", 0, true)
			}
			break
		}
	}

	if d.mycpv.string != d.settings.mycpv.string || !Inmss(d.settings.configDict["pkg"], "EAPI") {
		d.settings.SetCpv(d.mycpv, d.vartree.dbapi)
	}
	eapi_unsupported := false
	//try:
	doebuild_environment(myebuildpath, "prerm", nil, d.settings, false, nil, d.vartree.dbapi)
	//except UnsupportedAPIException as e:
	//eapi_unsupported = e

	if d._preserve_libs && Ins(strings.Fields(d.settings.ValueDict["PORTAGE_RESTRICT"]), "preserve-libs") {
		d._preserve_libs = false
	}

	var builddir_lock *EbuildBuildDir
	scheduler := d._scheduler
	retval := 0
	//try:
	if !Inmss(d.settings.ValueDict, "PORTAGE_BUILDDIR_LOCKED") {
		builddir_lock = NewEbuildBuildDir(scheduler, d.settings)
		scheduler.run_until_complete(builddir_lock.async_lock())
		prepare_build_dirs(d.settings, true)
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
	} else if pathIsFile(myebuildpath) {
		phase := NewEbuildPhase(nil, background, ebuild_phase, scheduler, d.settings, nil)
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

	if !eapi_unsupported && pathIsFile(myebuildpath) {
		ebuild_phase := "postrm"
		phase := NewEbuildPhase(nil, background, ebuild_phase, scheduler, d.settings, nil)
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
	if !eapi_unsupported && pathIsFile(myebuildpath) {
		if retval != 0 {
			msg_lines := []string{}
			msg := fmt.Sprintf("The '%s' "+
				"phase of the '%s' package "+
				"has failed with exit value %s.",
				ebuild_phase, d.mycpv, retval)
			msg_lines = append(msg_lines, SplitSubN(msg, 72)...)
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
			msg_lines = append(msg_lines, SplitSubN(msg, 72)...)
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
			msg_lines = append(msg_lines, SplitSubN(msg, 72)...)

			d._eerror(ebuild_phase, msg_lines)
		}
	}

	d._elog_process([]string{"prerm", "postrm"})

	if retval == 0 {
		//try:
		doebuild_environment(myebuildpath, "cleanrm", nil, d.settings, false, nil, d.vartree.dbapi)
		//except UnsupportedAPIException:
		//pass
		phase := NewEbuildPhase(nil, background, "cleanrm", scheduler,
			d.settings, nil)
		phase.start()
		retval = phase.wait()
	}
	//finally:
	if builddir_lock != nil {
		scheduler.run_until_complete(
			builddir_lock.async_unlock())
	}

	if log_path != nil {

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

	if log_path != "" && pathExists(log_path) {
		d.settings.ValueDict["PORTAGE_LOG_FILE"] = log_path
	} else {
		delete(d.settings.ValueDict, "PORTAGE_LOG_FILE")
	}

	env_update(1, d.settings.ValueDict["ROOT"],
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
		WriteMsgLevel(msg, level, noiselevel)
	}else {
		log_path := ""
		if d.settings.ValueDict["PORTAGE_BACKGROUND"] != "subprocess" {
			log_path = d.settings.ValueDict["PORTAGE_LOG_FILE"]
		}
		background := d.settings.ValueDict["PORTAGE_BACKGROUND"] == "1"

		if background && log_path == "" {
			if level >= 30 {
				WriteMsgLevel(msg, level, noiselevel)
			}
		} else {
			d._scheduler.output(msg,
				log_path = log_path, background = background,
				level = level, noiselevel=noiselevel)
		}
	}
}

func (d *dblink) _show_unmerge(zing, desc, file_type, file_name) {
	d._display_merge(fmt.Sprintf("%s %s %s %s\n",
		zing, desc.ljust(8), file_type, file_name), 0, 0)
}

func (d *dblink) _unmerge_pkgfiles(pkgfiles map[string][]string, others_in_slot []*dblink) {

	os = _os_merge
	perf_md5 := performMd5
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
			fmt.Sprintf("%s:%s", cpvGetKey(d.mycpv.string, ""), slot), 1)
		for _, cur_cpv := range slot_matches {
			if cur_cpv.string == d.mycpv.string {
				continue
			}
			others_in_slot = append(others_in_slot, NewDblink(d.cat, catsplit(cur_cpv)[1], "",
				d.settings, "vartree", d.vartree, nil, nil, d._pipe))
		}
	}

	cfgfiledict := grabDict(d.vartree.dbapi._conf_mem_file, false, false, false, true, false)
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
		ReverseSlice(mykeys)

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

			obj := NormalizePath(objkey)

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
				if islink && Ins([]string{"/lib", "/usr/lib", "/usr/local/lib"}, f_match) {
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
				} else if Inmsss(cfgfiledict, relative_path) {
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
			if !Ins([]string{"dir", "fif", "dev"}, pkgfiles[objkey][0]) && lmtime != pkgfiles[objkey][1] {
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
					target_dir_contents, err := listDir(obj)
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
				if !syscall.S_IFIFO&lstatobj.Mode() != 0 {
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
		lines := SplitSubN(msg, 72)
		lines = append(lines, "")
		flat_list := map[string]bool{}
		for _, v := range protected_symlinks {
			for _, v2 := range v {
				flat_list[v2] = true
			}
		}
		for _, f := range sortedmsb(flat_list) {
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
				//try:
				unlink(obj, os.Lstat(obj))
				show_unmerge("<<<", "", "sym", obj)
				//except(OSError, IOError) as e:
				//if err not in ignored_unlink_errnos:
				//raise
				//del e
				//show_unmerge("!!!", "", "sym", obj)
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
			remaining, err := listDir(obj)
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
					if dir_stat.st_dev in
					d._device_path_map{
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
						for _, parent := range sortedmsb(rpa) {
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

func (d *dblink) _linkmap_rebuild(exclude_pkgs []*PkgStr,include_file string, preserve_paths) {
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
func (d *dblink) _find_libs_to_preserve(unmerge bool) {

	if d._linkmap_broken || 
d.vartree.dbapi._linkmap == nil || 
d.vartree.dbapi._plib_registry == nil || 
(! unmerge && d._installed_instance == nil) ||
! d._preserve_libs {
		return map[string]bool{}
	}

	os = _os_merge
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
	lib_graph := NewDigraph()
	path_node_map := map[string]*_obj_properties_class{}

	path_to_node:= func(path string) {
		node := path_node_map[path]
		if node == nil {
			node = New_LibGraphNode(linkmap._obj_key(path))
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

	new_contents := CopyMapSSS(d.getcontents())
	old_contents := d._installed_instance.getcontents()
	for f
	in
	sorted(preserve_paths)
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
	outfile := NewAtomic_ofstream(filepath.Join(d.dbtmpdir, "CONTENTS"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
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
	lib_graph := NewDigraph()
	preserved_nodes := map[string]bool{}
	preserved_paths := map[string]bool{}
	path_cpv_map := {}
	path_node_map := {}
	root := d.settings.ValueDict["ROOT"]

	 path_to_node:= func(path string) {
		 node := path_node_map[path]
		 if node == nil {
			 node = New_LibGraphNode(linkmap._obj_key(path))
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
		unlink_list = sorted(unlink_list)
		for obj in unlink_list{
			cpv = path_cpv_map.get(obj)
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
		if pathIsDir(filepath.Join(d._eroot, strings.TrimLeft(x, string(os.PathSeparator)))) {
			x = NormalizePath(x)
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
	showMessage(fmt.Sprintf(" %s checking %d files for package collisions\n", colorize("GOOD", "*"), totfiles), 0, 0)
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

		dest_path := NormalizePath(filepath.Join(destroot, strings.TrimLeft(f, string(os.PathSeparator))))
		es, _ := filepath.EvalSymlinks(filepath.Dir(dest_path))
		real_relative_path := filepath.Join(es,
			filepath.Base(dest_path))[len(destroot):]

		if _, ok := real_relative_paths[real_relative_path]; !ok {
			real_relative_paths[real_relative_path] = []string{}
		}
		real_relative_paths[real_relative_path] = append(real_relative_paths[real_relative_path], strings.TrimLeft(string(os.PathSeparator)))

		parent := filepath.Dir(dest_path)
		if !dirs[parent] {
			for _, x := range iterParents(parent) {
				if dirs[x] {
					break
				}
				dirs[x] = true
				if pathIsDir(x) {
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
				if Ins(collisions, f) {
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
				file1 := NormalizePath(filepath.Join(srcroot, files[i]))
				file2 := NormalizePath(filepath.Join(srcroot, files[i+1]))
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
		fun = elog
	case "error":
		fun = eerror
	case "eqawarn":
		fun = eqawarn
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
		elog_process(cpv.string, d.settings, phasefilter)
	}else {
		logdir := filepath.Join(d.settings.ValueDict["T"], "logging")
		ebuild_logentries := collect_ebuild_messages(logdir)
		py_logentries := collect_messages(cpv.string, phasefilter)[cpv.string]
		if py_logentries == nil {
			py_logentries = map[string][]struct{s string; ss []string}{}
		}
		logentries := _merge_logentries(py_logentries, ebuild_logentries)
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

func (d *dblink) _emerge_log(msg string) {emergelog(false, msg)}

// 0, nil, nil, 0
func (d *dblink) treewalk(srcroot, inforoot, myebuild string, cleanup int, mydbapi DBAPI, prev_mtimes=nil, counter string) int {

	destroot := d.settings.ValueDict["ROOT"]

	showMessage := d._display_merge
	srcroot = strings.TrimRight(NormalizePath(srcroot), string(os.PathSeparator)) + string(os.PathSeparator)

	if !pathIsDir(srcroot) {
		showMessage(fmt.Sprintf("!!! Directory Not Found: D='%s'\n", srcroot), 40, -1)
		return 1
	}

	doebuild_environment(myebuild, "instprep", nil, d.settings, false, nil, mydbapi)
	phase := NewEbuildPhase(nil, false, "instprep",
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
				write_atomic(filepath.Join(inforoot, var_name), slot+"\n", os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
			}
		}

		if !is_binpkg && val != d.settings.ValueDict[var_name] {
			d._eqawarn("preinst", []string{fmt.Sprintf("QA Notice: Expected %s='%s', got '%s'\n", var_name, d.settings.ValueDict[var_name], val)})
		}
	}

	eerror := func(lines []string) {
		d._eerror("preinst", lines)
	}

	if !pathExists(d.dbcatdir) {
		ensureDirs(d.dbcatdir, -1, -1, -1, -1, nil, true)
	}

	slot = NewPkgStr(d.mycpv.string, nil, nil, "", "", slot, 0, 0, "", 0, nil).slot
	cp := d.mysplit[0]
	slot_atom := fmt.Sprintf("%s:%s", cp, slot)

	d.lockdb()
	//try:
	slot_matches := []*PkgStr{}
	for _, cpv := range d.vartree.dbapi.match(slot_atom, 1) {
		if cpvGetKey(cpv.string, "") == cp {
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
		settings_clone := NewConfig(d.settings, nil, "", nil, "", "", "", "", true, nil, false, nil)
		delete(settings_clone.ValueDict, "PORTAGE_BUILDDIR_LOCKED")
		settings_clone.SetCpv(cur_cpv, d.vartree.dbapi)
		if d._preserve_libs && Ins(strings.Fields(settings_clone.ValueDict["PORTAGE_RESTRICT"]), "preserve-libs") {
			d._preserve_libs = false
		}
		others_in_slot = append(others_in_slot, NewDblink(d.cat, catsplit(cur_cpv)[1], "",
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

	phase2 := NewMiscFunctionsProcess(false, []string{"preinst_mask"}, "preinst", "", nil, d._scheduler, d.settings)
	phase2.start()
	phase2.wait()
	f, err := ioutil.ReadFile(filepath.Join(inforoot, "INSTALL_MASK"))
	if err != nil {
		//except EnvironmentError:
		//install_mask = nil
	}
	install_mask := NewInstallMask(string(f))

	if install_mask != nil {
		install_mask_dir(d.settings.ValueDict["ED"], install_mask, nil)
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
			_merge_unicode_error(unicode_errors))
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
			msg = append(msg, SplitSubN(fmt.Sprintf("The '%s' package will not install "+
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
			msg = append(msg, SplitSubN(
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
		doebuild_environment(myebuild, "preinst", nil, d.settings, false, nil, mydbapi)
		dsvrv := []string{}
		for _, other := range others_in_slot {
			dsvrv = append(dsvrv, cpvGetVersion(other.mycpv.string, ""))
		}
		d.settings.ValueDict["REPLACING_VERSIONS"] = strings.Join(dsvrv, " ")
		prepare_build_dirs(settings = d.settings, cleanup = cleanup)
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

	ro_checker := get_ro_checker()
	rofilesystems := ro_checker(dirs_ro)

	if len(rofilesystems) > 0 {
		msg := SplitSubN("One or more files installed to this package are "+
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
		msgs := SplitSubN(msg2, 70)
		eerror(msgs)
		return 1
	}

	if len(internal_collisions) > 0 {
		msg := fmt.Sprintf("Package '%s' has internal collisions between non-identical files "+
			"(located in separate directories in the installation image (${D}) "+
			"corresponding to merged directories in the target "+
			"filesystem (${ROOT})):", d.settings.mycpv)
		msgs := SplitSubN(msg, 70)
		msgs = append(msgs, "")
		for k, v
			in
		sorted(internal_collisions.items(), key = operator.itemgetter(0)){
			msgs = append(msgs, "\t%s"%filepath.Join(destroot, k.lstrip(string(os.PathSeparator))))
			for (file1, file2), differences
			in
			sorted(v.items())
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
		eerror(SplitSubN(msg, 70))
		return 1
	}

	if len(symlink_collisions) > 0 {
		msg := fmt.Sprintf("Package '%s' has one or more collisions "+
			"between symlinks and directories, which is explicitly "+
			"forbidden by PMS section 13.4 (see bug #326685):",
			d.settings.mycpv, )
		msgs := SplitSubN(msg, 70)
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
		msgs := SplitSubN(msg, 70)
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
					slotSeparator, pkg.slot)
				if pkg.repo != unknownRepo {
					pkg_info_str += fmt.Sprintf("%s%s", repoSeparator,
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
		eerror(SplitSubN(msg, 70))

		if abort {
			return 1
		}
	}

	if err := syscall.Unlink(filepath.Join(
		filepath.Dir(NormalizePath(srcroot)), ".installed")); err != nil {
		//except OSError as e:
		if err != syscall.ENOENT {
			//raise
		}
		//del e
	}
	d.dbdir = d.dbtmpdir
	d.delete()
	ensureDirs(d.dbtmpdir, -1, -1, -1, -1, nil, true)

	downgrade := false
	v, _ := verCmp(d.mycpv.version,
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
	phase3 := NewEbuildPhase(nil, false, "preinst",
		d._scheduler, d.settings, nil)
	phase3.start()
	a := phase3.wait()

	if a != 0 {
		showMessage(fmt.Sprintf("!!! FAILED preinst: ")+fmt.Sprintf(a)+"\n",
			40, -1)
		return a
	}

	xs, _ := listDir(inforoot)
	for _, x := range xs {
		d.copyfile(inforoot + "/" + x)
	}

	if counter == nil {
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

	cfgfiledict := grabDict(d.vartree.dbapi._conf_mem_file, false, false, false, true, false)
	if Inmss(d.settings.ValueDict, "NOCONFMEM") || downgrade {
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

		if preserve_paths {
			d._add_preserve_libs_to_contents(preserve_paths)
		}
	}

	reinstall_self := false
	ppa, _ := NewAtom(PortagePackageAtom, nil, false, nil, nil, "", nil, nil)
	if d.myroot == "/" && len(matchFromList(ppa, []*PkgStr{d.mycpv})) > 0 {
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
		dblnk.settings.ValueDict["REPLACED_BY_VERSION"] = cpvGetVersion(d.mycpv.string, "")
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
		showMessage(colorize("WARN", "WARNING:")+
			" AUTOCLEAN is disabled.  This can cause serious"+
			" problems due to overlapping packages.\n", 30, -1)
	}

	d.dbdir = d.dbpkgdir
	d.lockdb()
	//try:
	d.delete()
	_movefile(d.dbtmpdir, d.dbpkgdir, 0, nil, d.settings, nil)
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

		if preserve_paths {
			plib_registry.register(d.mycpv.string, slot, counter,
				sorted(preserve_paths))
		}

		plib_dict := plib_registry.getPreservedLibs()
		for cpv, paths := range plib_collisions {
			if !Inmsss(plib_dict, cpv) {
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
				if !Ins(paths, f) {
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
	phase = NewEbuildPhase(nil, false, "postinst",
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

	env_update(1, d.settings.ValueDict["ROOT"], prev_mtimes, contents, d.settings, d._display_merge, d.vartree.dbapi)

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

	cfgfiledict_orig := CopyMapSSS(cfgfiledict)

	outfile := NewAtomic_ofstream(filepath.Join(d.dbtmpdir, "CONTENTS"), os.O_CREATE|os.O_TRUNC|os.O_RDWR, true)

	mymtime = nil

	prevmask := syscall.Umask(0)
	secondhand := map[string][]string{}

	if d.mergeme(srcroot, destroot, outfile, secondhand, cfgfiledict, mymtime) != 0 {
		return 1
	}

	lastlen := 0
	for len(secondhand) > 0 && len(secondhand) != lastlen {

		thirdhand = []
		if d.mergeme(srcroot, destroot, outfile, thirdhand,
			secondhand, cfgfiledict, mymtime) != 0 {
			return 1
		}

		lastlen = len(secondhand)

		secondhand = thirdhand
	}

	if len(secondhand) > 0 {
		if d.mergeme(srcroot, destroot, outfile, nil,
			secondhand, cfgfiledict, mymtime) != 0 {
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

func (d *dblink) mergeme(srcroot, destroot string, outfile io.WriteCloser, secondhand, stufftomerge, cfgfiledict map[string][]string, thismtime) int {

	showMessage := d._display_merge
	WriteMsg := d._display_merge

	os = _os_merge
	sep := string(os.PathSeparator)
	join := filepath.Join
	srcroot = strings.TrimRight(NormalizePath(srcroot), sep) + sep
	destroot = strings.TrimRight(NormalizePath(destroot), sep) + sep
	calc_prelink := d.settings.Features.Features["prelink-checksums"]

	protect_if_modified := d.settings.Features.Features["config-protect-if-modified"] && d._installed_instance != nil

	mergelist := []string{}
	if isinstance(stufftomerge, basestring) {
		for child
			in
		os.listdir(join(srcroot, stufftomerge))
		{
			mergelist = append(mergelist, join(stufftomerge, child))
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

		mymtime := mystat.ModTime().Nanosecond()

		if mymode&syscall.S_IFREG != 0 {
			mymd5 = string(performMd5(mysrc, calc_prelink))
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
				destmd5 = string(performMd5(mydest, calc_prelink))
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
			myabsto := abssymlink(mysrc, target = myto)

			if strings.HasPrefix(myabsto, srcroot) {
				myabsto = myabsto[len(srcroot):]
			}
			myabsto = strings.TrimLeft(myabsto, sep)
			if d.settings != nil && d.settings.ValueDict["D"] != "" {
				if strings.HasPrefix(myto, d.settings.ValueDict["D"]) {
					myto = myto[len(d.settings.ValueDict["D"])-1:]
				}
			}
			myrealto := NormalizePath(filepath.Join(destroot, myabsto))
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

			if (secondhand != nil) && (!pathExists(myrealto)) {
				secondhand = append(secondhand, mysrc[len(srcroot):])
				continue
			}
			if moveme {
				zing = ">>>"
				mymtime = movefile(mysrc, mydest, newmtime = thismtime,
					sstat = mystat, mysettings=d.settings,
					encoding = _encodings["merge"])
			}

			st, err := os.Lstat(mydest)
			if err != nil {
				//except OSError:
				//pass
			} else {
				d._merged_path(mydest, st, true)
			}

			if mymtime != nil {
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

				if syscall.S_IFLNK&mydmode == 0 && !osAccess(mydest, unix.W_OK) {
					pkgstuff := pkgSplit(d.pkg, "")
					WriteMsg(fmt.Sprintf("\n!!! Cannot write to '%s'.\n", mydest), 0, -1)
					WriteMsg(("!!! Please check permissions and directories for broken symlinks.\n"), 0, 0)
					WriteMsg(("!!! You may start the merge process again by using ebuild:\n"), 0, 0)
					WriteMsg("!!! ebuild "+d.settings.ValueDict["PORTDIR"]+"/"+d.cat+"/"+pkgstuff[0]+"/"+d.pkg+".ebuild merge\n", 0, 0)
					WriteMsg(("!!! And finish by running this: env-update\n\n"), 0, 0)
					return 1
				}

				if syscall.S_IFDIR&mydmode != 0 || (syscall.S_IFLNK&mydmode != 0) && pathIsDir(mydest) {
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
					if _movefile(mydest, backup_dest, 0, nil,
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
					//else if pathIsDir(mydest):
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
				//else if pathIsDir(mydest):
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

			lds, _ := listDir(join(srcroot, relative_path))
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

				mymtime = movefile(mysrc, mydest, newmtime = thismtime,
					sstat = mystat, mysettings=d.settings,
					hardlink_candidates = hardlink_candidates,
					encoding=_encodings['merge'])
				if mymtime == nil {
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
				if movefile(mysrc, mydest, newmtime = thismtime,
					sstat = mystat, mysettings = d.settings,
					encoding=_encodings['merge']) != nil{
					zing = ">>>"

					try:
					d._merged_path(mydest, os.Lstat(mydest))
					except
					OSError:
					pass
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
		dest = new_protect_filename(dest, nm, force)
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
func (d *dblink) merge(mergeroot, inforoot , myebuild string, cleanup int,
	mydbapi *vardbapi, prev_mtimes *MergeProcess, counter string) int {

	retval := -1
	parallel_install := d.settings.Features.Features["parallel-install"]
	if ! parallel_install{
		d.lockdb()
	}
	d.vartree.dbapi._bump_mtime(d.mycpv.string)
	if d._scheduler == nil {
		d._scheduler = NewSchedulerInterface(asyncio._safe_loop(), nil)
	}
//try:
	retval = d.treewalk(mergeroot, inforoot, myebuild,
		cleanup, mydbapi, prev_mtimes, counter)

	if pathIsDir(d.settings.ValueDict["PORTAGE_BUILDDIR"]){
		phase := ""
		if retval == 0 {
			phase = "success_hooks"
		}else {
			phase = "die_hooks"
		}

		ebuild_phase := NewMiscFunctionsProcess(false, []string{phase}, "", "", nil, d._scheduler, d.settings)
		ebuild_phase.start()
		ebuild_phase.wait()
		d._elog_process(nil)

		if  ! d.settings.Features.Features["noclean"] &&
			(retval == 0 || d.settings.Features.Features["fail-clean"]){
			if myebuild == "" {
				myebuild = filepath.Join(inforoot, d.pkg+".ebuild")
			}

			doebuild_environment(myebuild, "clean", nil,
				d.settings, false, nil, mydbapi)
			phase2 := NewEbuildPhase(nil, false, "clean", d._scheduler, d.settings, nil)
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
		retval = ReturncodePostinstFailure
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
	copyfile(fname, d.dbdir+"/"+filepath.Base(fname))
}

func (d *dblink) getfile(fname string) string {
	if ! pathExists(d.dbdir+"/"+fname) {
		return ""
	}
	f, _ := ioutil.ReadFile(filepath.Join(d.dbdir, fname))
	return string(f)
}

func (d *dblink) setfile(fname, data string) {
	write_atomic(filepath.Join(d.dbdir, fname), data, os.O_RDWR|os.O_TRUNC|os.O_CREATE, true)
}

func (d *dblink) getelements(ename string) []string {
	if !pathExists(d.dbdir + "/" + ename) {
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
	return pathExists(filepath.Join(d.dbdir, "CATEGORY"))

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

	trees := NewQueryCommand(nil, "").get_db().Values()[d.settings.ValueDict["EROOT"]]
	bintree := trees.BinTree()

	bdm := []*PkgStr{}
	for _, v := range bintree.dbapi.match(fmt.Sprintf("=%v", backup_dblink.mycpv), 1) {
		bdm = append([]*PkgStr{v}, bdm...)
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
		quickpkg_binary := FindBinary("quickpkg")
		if quickpkg_binary == "" {
			d._display_merge(fmt.Sprintf("%s: command not found", "quickpkg"),
				40, -1)
			return 127
		}
	}

	env := CopyMapSS(d.vartree.settings.ValueDict)
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

	quickpkg_proc := NewSpawnProcess(
		[]string{_python_interpreter, quickpkg_binary,
		fmt.Sprintf("=%s" , backup_dblink.mycpv.string)},
		background, env, nil,
		d._scheduler, logfile)
	quickpkg_proc.start()

	return *quickpkg_proc.wait()
}

// "", nil, "", nil, nil, nil, 0
func NewDblink(cat, pkg, myroot string, settings *Config, treetype string,
	vartree *varTree, blockers []*dblink, scheduler *SchedulerInterface, pipe int) *dblink {
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
	d._device_path_map = map[uint64]string{}
	d._hardlink_merge_map = map[[2]uint64][]string{}
	d._hash_key = []string{d._eroot, d.mycpv.string}
	d._protect_obj = nil
	d._pipe = pipe
	d._postinst_failure = false

	d._preserve_libs = mysettings.Features.Features["preserve-libs"]
	d._contents = NewContentsCaseSensitivityManager(d)
	d._slot_locks = []*Atom{}

	return d
}

// nil, "", "", nil, nil, nil, nil, nil, nil
func merge(mycat, mypkg, pkgloc, infloc string, settings *Config, myebuild, mytree string,
	mydbapi DBAPI, vartree *varTree, prev_mtimes=nil, blockers=nil, scheduler=nil, fd_pipes=nil) int {
	if settings == nil{
		//raise TypeError("Settings argument is required")
	}
	if st, _:= os.Stat(settings.ValueDict["EROOT"]); st!= nil &&st.Mode()&unix.W_OK ==0 {
		WriteMsg(fmt.Sprintf("Permission denied: access('%s', W_OK)\n", settings.ValueDict["EROOT"]), -1, nil)
		return int(unix.EACCES)
	}
	background := settings.ValueDict["PORTAGE_BACKGROUND"] == "1"
	merge_task := NewMergeProcess(
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
func unmerge(cat, pkg string, settings *Config,
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
	for _, filename := range sorted(cts){
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
	root := strings.TrimRight(NormalizePath(root), string(os.PathSeparator)) + string(os.PathSeparator)
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
			pathIsDir(live_path) {
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
func (f *fakedbapi) match(origdep string, use_cache int) []*PkgStr {
	atom := dep_expandS(origdep, f.dbapi, 1, f.settings)
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
	move_ent func([]string, func(string) bool) int

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
func (b *bindbapi) match(origdep string, use_cache int) []*PkgStr {
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
	kiwda := CopyMapSB(b._known_keys)
	for k := range kiwda {
		if !Inmss(wants, k){
			delete(kiwda, k)
		}
	}
	for k := range b._aux_cache_keys {
		delete(kiwda, k)
	}
	if len(kiwda)==0 {
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
	} else if len(b.bintree._remotepkgs)==0 || !b.bintree.isremote(mycpv) {
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

func (b *bindbapi) aux_update(cpv, values) {

	if ! b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	build_id = nil
try:
	build_id = cpv.build_id
	except AttributeError:
	if b.bintree._multi_instance {
		//raise
	}else {
		cpv = b._instance_key(cpv, true)[0]
		build_id = cpv.build_id
	}

	tbz2path := b.bintree.getname(cpv, false)
	if ! pathExists(tbz2path) {
		//raise KeyError(cpv)
	}
	mytbz2 := NewTbz2(tbz2path)
	mydata := mytbz2.get_data()

	for k, v in values.items(){
		mydata[k] = v
	}

	for k, v := range mydata{
		if  v== "" {
			delete(mydata, k)
		}
	}
	mytbz2.recompose_mem(string(xpak_mem(mydata)), true)
	b.bintree.inject(cpv, filename=tbz2path)
}

func (b *bindbapi) unpack_metadata(pkg, dest_dir){

	loop = asyncio._wrap_loop()
	if isinstance(pkg, _pkg_str) {
		cpv = pkg
	}else {
		cpv = pkg.mycpv
	}
	key := b._instance_key(cpv, false)
	add_pkg := b.bintree._additional_pkgs[key.string]
	if add_pkg != nil {
		yield
		add_pkg._db.unpack_metadata(pkg, dest_dir)
	}else {
		tbz2_file := b.bintree.getname(cpv, false)
		yield
		loop.run_in_executor(ForkExecutor(loop = loop),
		NewTbz2(tbz2_file).unpackinfo, dest_dir)
	}
}

func (b *bindbapi) unpack_contents(pkg *PkgStr, dest_dir){

	loop = asyncio._wrap_loop()
	//if isinstance(pkg, _pkg_str) {
		settings := b.settings
		cpv = pkg
	//}else {
	//	settings = pkg
	//	cpv = settings.mycpv
	//}

	pkg_path := b.bintree.getname(cpv.string, false)
	if pkg_path != "" {

		extractor := NewBinpkgExtractorAsync(
			settings.ValueDict["PORTAGE_BACKGROUND"] == "1",
			settings.environ(), settings.Features.Features, dest_dir,
			 cpv,  pkg_path, settings.ValueDict["PORTAGE_LOG_FILE"],
			NewSchedulerInterface(loop))

		extractor.start()
		yield
		extractor.async_wait()
		if extractor.returncode == nil || *extractor.returncode != 0 {
			raise
			PortageException("Error Extracting '{}'".format(pkg_path))
		}

	}else {
		instance_key := b._instance_key(cpv, false)
		add_pkg := b.bintree._additional_pkgs[instance_key.string]
		if add_pkg == nil {
			raise
			portage.exception.PackageNotFound(cpv)
		}
		yield
		add_pkg._db.unpack_contents(pkg, dest_dir)
	}
}

// 1
func (b *bindbapi) cp_list(mycp string, use_cache int) []*PkgStr {
	if !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.cp_list(mycp, use_cache)
}

// false
func (b *bindbapi) cp_all(sort bool) []string {

	if ! b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.cp_all(sort)
}

func (b *bindbapi) cpv_all() []string {

	if ! b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.cpv_all()
}

func (b *bindbapi) getfetchsizes(pkg) map[string]int {

	if ! b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}

	pkg = getattr(pkg, "cpv", pkg)

	filesdict := map[string]int{}
	if ! b.bintree.isremote(pkg) {
		//pass
	}else {
		metadata = b.bintree._remotepkgs[b._instance_key(pkg)]
		sizeS, ok := metadata["SIZE"]
		if !ok {
			//except KeyError:
			//raise portage.exception.MissingSignature("SIZE")
		}
		size ,err := strconv.Atoi(sizeS)
		if err != nil {
			//except ValueError:
			//raise portage.exception.InvalidSignature(
			//	"SIZE: %s" % metadata["SIZE"])
		}else {
			filesdict[filepath.Base(b.bintree.getname(pkg))] = size
		}
	}

	return filesdict

}

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
	_pkgindex_hashes, _pkgindex_aux_keys, _pkgindex_use_evaluated_keys, _pkgindex_inherited_keys []string
	_remotepkgs map[string]map[string]string
	dbapi                                                                                                        *bindbapi
	update_ents                                                                                                  func(updates map[string][][]*Atom, onProgress, onUpdate func(int, int))
	move_slot_ent                                                                                                func(mylist []*Atom, repo_match func(string) bool) int
	tree, _additional_pkgs                                                                                       map[string]interface{}
	_pkgindex_header_keys, _pkgindex_allowed_pkg_keys,_pkgindex_keys                                                            map[string]bool
	_pkgindex_default_pkg_data, _pkgindex_default_header_data, _pkg_paths, _pkgindex_header                      map[string]string
	_pkgindex_translated_keys                                                                                    [][2]string
	invalids                                                                                                     []string
	_allocate_filename                                                                                           func(cpv *PkgStr) string
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
		updated_items := update_dbentries([][]string{mylist}, mydata, "", mycpv)
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
	//if not pathIsDir(path):
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
		l, _ := Lockfile(b._pkgindex_file, true, false, "", 0)
		update_pkgindex = b._populate_local(true)
		if update_pkgindex != nil {
			b._pkgindex_write(update_pkgindex)
		}
		//if pkgindex_lock:
		Unlockfile(l)
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
	for k := range b._pkgindex_keys {
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
			for v := range b.dbapi.auxCacheKeys {
				chain = append(chain, v)
			}
			chain = append(chain, "PF", "CATEGORY")
			pkg_metadata := b._read_metadata(full_path, s,
				chain)
			mycat := pkg_metadata["CATEGORY"]
			mypf := pkg_metadata["PF"]
			slot := pkg_metadata["SLOT"]
			mypkg := myfile[:len(myfile)-5]
			if mycat =="" || mypf == "" || slot == "" {
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

// true
func (b *BinaryTree) _populate_remote(getbinpkg_refresh bool) {

	b._remote_has_index = false
	b._remotepkgs = map[string]map[string]string{}
	for _, base_url := range strings.Fields(b.settings.ValueDict["PORTAGE_BINHOST"]) {
		parsed_url, _ := url.Parse(base_url)
		host := parsed_url.Hostname()
		port := parsed_url.Port()
		user_passwd := parsed_url.User.String()
		user := parsed_url.User.Username()
		passwd, _ := parsed_url.User.Password()

		pkgindex_file := filepath.Join(b.settings.ValueDict["EROOT"], CachePath, "binhost",
			host, strings.TrimLeft(parsed_url.Path, "/"), "Packages")
		pkgindex := b._new_pkgindex()

		f, err := os.Open(pkgindex_file)
		if err != nil {
			//except EnvironmentError as e:
			if err != syscall.ENOENT {
				//raise
			}
		} else {
			//try:
			pkgindex.read(f)
			//finally:
			f.Close()
		}

		local_timestamp := pkgindex.header["TIMESTAMP"]
		download_timestamp, err := strconv.ParseFloat(pkgindex.header["DOWNLOAD_TIMESTAMP"], 64)
		remote_timestamp := ""
		rmt_idx := b._new_pkgindex()
		var proc *exec.Cmd
		tmp_filename := ""
		//try:
		url := strings.TrimRight(base_url, "/") + "/Packages"
		f = nil

		if !getbinpkg_refresh && local_timestamp {
			//raise UseCachedCopyOfRemoteIndex()
		}

		ttl, err := strconv.ParseFloat(pkgindex.header["TTL"], 64)
		if err == nil {
			if download_timestamp != 0 && ttl != 0 &&
				download_timestamp+ttl > time.Now().Nanosecond() {
				//raise UseCachedCopyOfRemoteIndex()
			}
		}

		r, err := http.NewRequest(http.MethodGet, url, nil)
		var resp *http.Response
		if err == nil {
			r.Header.Set("If-Modified-Since", local_timestamp)
			resp, err = http.DefaultClient.Do(r)
		}
		if err != nil {
			//except IOError as err:
			if parsed_url.Scheme == "ftp" || parsed_url.Scheme == "http" || parsed_url.Scheme == "https" {
				if v, ok := b.settings.ValueDict["PORTAGE_DEBUG"]; ok && v != "0" {
					//traceback.print_exc()
				}
			}
			//except ValueError:
			//raise ParseError("Invalid Portage BINHOST value '%s'"
			//% url.lstrip())
		} else if resp.StatusCode == 304 {
			//raise UseCachedCopyOfRemoteIndex()
		}
		var f_dec io.Reader
		if resp == nil {
			path := strings.TrimRight(parsed_url.Path, "/") + "/Packages"
			if parsed_url.Scheme == "ssh" {
				ssh_args := []string{"ssh"}
				if port != "" {
					ssh_args = append(ssh_args, fmt.Sprintf("-p%s", port, ))
				}
				ss, _ := shlex.Split(strings.NewReader(b.settings.ValueDict["PORTAGE_SSH_OPTS"]), false, true)

				ssh_args = append(ssh_args, ss...)
				ssh_args = append(ssh_args, user_passwd+host)
				ssh_args = append(ssh_args, "--")
				ssh_args = append(ssh_args, "cat")
				ssh_args = append(ssh_args, path)

				f_dec = &bytes.Buffer{}
				proc := exec.Command(ssh_args[0], ssh_args[1:]...)
				proc.Stdout = f_dec
				proc.Run()
			} else {
				setting := "FETCHCOMMAND_" + strings.ToUpper(parsed_url.Scheme)
				fcmd := b.settings.ValueDict[setting]
				if fcmd == "" {
					fcmd = b.settings.ValueDict["FETCHCOMMAND"]
					if fcmd == "" {
						//raise EnvironmentError("FETCHCOMMAND is unset")
					}
				}
				fd, _ := ioutil.TempFile(os.TempDir(), "")
				tmp_dirname, tmp_basename := os.TempDir(), fd.Name()
				fd.Close()

				fcmd_vars := map[string]string{
					"DISTDIR": tmp_dirname,
					"FILE":    tmp_basename,
					"URI":     url,
				}

				for _, k := range []string{"PORTAGE_SSH_OPTS"} {
					v := b.settings.ValueDict[k]
					if v != "" {
						fcmd_vars[k] = v
					}
				}

				success = portage.getbinpkg.file_get(
					fcmd = fcmd, fcmd_vars = fcmd_vars)
				if not success {
					//raise EnvironmentError("%s failed" % (setting, ))
				}
				tmp_filename = filepath.Join(tmp_dirname, tmp_basename)
				f_dec, _ = os.Open(tmp_filename)
			}
		} else {
			f_dec = resp.Body
		}

		//try:
		rmt_idx.readHeader(f_dec)
		if remote_timestamp == "" {
			remote_timestamp = rmt_idx.header["TIMESTAMP"]
		}
		if remote_timestamp == "" {
			pkgindex = nil
			WriteMsg("\n\n!!! Binhost package index  has no TIMESTAMP field.\n", -1, nil)
		} else {
			if !b._pkgindex_version_supported(rmt_idx) {
				WriteMsg(fmt.Sprintf("\n\n!!! Binhost package index version"+
					" is not supported: '%s'\n", rmt_idx.header["VERSION"]), -1, nil)
				pkgindex = nil
			} else if local_timestamp != remote_timestamp {
				rmt_idx.readBody(f_dec)
				pkgindex = rmt_idx
			}
		}
		//	finally:
		//			try:
		//	try:
		//	AlarmSignal.register(5)
		//	f.close()
		//	finally:
		//	AlarmSignal.unregister()
		//	except AlarmSignal:
		//	WriteMsg("\n\n!!! %s\n" %
		//_("Timed out while closing connection to binhost"),
		//	noiselevel=-1)
		//	except UseCachedCopyOfRemoteIndex:
		//	WriteMsg_stdout("\n")
		//	WriteMsg_stdout(
		//	colorize("GOOD", _("Local copy of remote index is up-to-date and will be used.")) +
		//"\n")
		//	rmt_idx = pkgindex
		//	except EnvironmentError as e:
		//			WriteMsg(_("\n\n!!! Error fetching binhost package"
		//" info from '%s'\n") % _hide_url_passwd(base_url))
		//				try:
		//	error_msg = _unicode(e)
		//	except UnicodeDecodeError as uerror:
		//	error_msg = _unicode(uerror.object,
		//	encoding='utf_8', errors='replace')
		//	WriteMsg("!!! %s\n\n" % error_msg)
		//	del e
		//	pkgindex = nil
		if proc != nil {
			if proc.poll() == nil {
				proc.kill()
				proc.wait()
			}
			proc = nil
		}
		if tmp_filename != "" {
			if err := syscall.Unlink(tmp_filename); err != nil {
				//except OSError:
				//pass
			}
		}
		if pkgindex == rmt_idx {
			pkgindex.modified = false
			pkgindex.header["DOWNLOAD_TIMESTAMP"] = fmt.Sprintf("%d", time.Now().Nanosecond())
			//try:
			ensureDirs(filepath.Dir(pkgindex_file), -1, -1, -1, -1, nil, true)
			f = NewAtomic_ofstream(pkgindex_file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
			pkgindex.write(f)
			f.close()
			//except(IOError, PortageException):
			//if os.access(filepath.Dir(pkgindex_file), os.W_OK):
			//raise
		}
		if pkgindex != nil {
			remote_base_uri := pkgindex.header["URI"]
			if remote_base_uri == "" {
				remote_base_uri = base_url
			}
			for _, d := range pkgindex.packages {
				cpv := NewPkgStr(d["CPV"], d,
					b.settings, "", "", "", 0, 0, "", 0, b.dbapi)
				if b.dbapi.cpv_exists(cpv) {
					continue
				}
				d["CPV"] = cpv
				d["BASE_URI"] = remote_base_uri
				d["PKGINDEX_URI"] = url
				b._remotepkgs[b.dbapi._instance_key(cpv.string, false).string] = d
				b.dbapi.cpv_inject(cpv)
			}

			b._remote_has_index = true
			b._merge_pkgindex_header(pkgindex.header, b._pkgindex_header)
		}
	}
}

func (b *BinaryTree) _populate_additional(repos []string) *PkgStr {

	for _, repo := range repos {
		aux_keys = list(set(chain(repo._aux_cache_keys, repo._pkg_str_aux_keys)))
		for cpv
		in
		repo.cpv_all() {
			metadata = dict(zip(aux_keys, repo.aux_get(cpv, aux_keys)))
			pkg = _pkg_str(cpv, metadata = metadata, settings = repo.settings, db=repo)
			instance_key = b.dbapi._instance_key(pkg)
			b._additional_pkgs[instance_key] = pkg
			b.dbapi.cpv_inject(pkg)
		}
	}
}

// ""
func (b *BinaryTree) inject(cpv *PkgStr, filename string) *PkgStr {
	if !b.populated {
		b.Populate(false, true, []string{})
	}
	full_path := filename
	if filename == "" {
		full_path = b.getname(cpv.string, false)
	}
	s, err := os.Stat(full_path)
	if err != nil {
		//except OSError as e:
		if err != syscall.ENOENT {
			//raise
		}
		//del e
		WriteMsg(fmt.Sprintf("!!! Binary package does not exist: '%s'\n",full_path), -1, nil)
		return
	}
	metadata := b._read_metadata(full_path, s, nil)
	invalid_depend := false
//try:
	b._eval_use_flags(metadata)
	//except portage.exception.InvalidDependString:
	//invalid_depend = true
	if invalid_depend || metadata["SLOT"]=="" {
		WriteMsg(fmt.Sprintf("!!! Invalid binary package: '%s'\n",full_path), -1, nil)
		return nil
	}

	fetched := map[string]string{}
//try:
	build_id := cpv.buildId
	//except AttributeError:
	//build_id := 0
	//else:
	instance_key := b.dbapi._instance_key(cpv, false)
	if _, ok := b.dbapi.cpvdict[instance_key.string]; ok{
		b.dbapi.cpv_remove(cpv)
		delete(b._pkg_paths, instance_key.string)
		if b._remotepkgs != nil {
			fetched = b._remotepkgs[instance_key.string]
			delete(b._remotepkgs, instance_key.string)
		}
	}

	cpv = NewPkgStr(cpv.string, metadata, b.settings,"", "", "", 0, 0, "", 0, b.dbapi)

	pkgindex_lock, err := Lockfile(b._pkgindex_file,true, false, "", 0)
	defer func() {
		if pkgindex_lock!= nil {
			Unlockfile(pkgindex_lock)
		}
	}()
	if filename != "" {
		new_filename := b.getname(cpv.string, true)
	try:
		samefile = os.path.samefile(filename, new_filename)
		except
	OSError:
		samefile = false
		if not samefile {
			b._ensure_dir(filepath.Dir(new_filename))
			_movefile(filename, new_filename, 0, nil, b.settings, nil)
		}
		full_path = new_filename
	}

	basename := filepath.Base(full_path)
	if build_id == 0 && len(fetched) == 0 &&
		strings.HasSuffix(basename, ".xpak") {
		build_id = b._parse_build_id(basename)
		metadata["BUILD_ID"] = fmt.Sprint(build_id)
		cpv = NewPkgStr(cpv.string,  metadata, b.settings, "", "", "", 0, 0, "", 0,b.dbapi)
		binpkg := NewTbz2(full_path)
		binary_data := binpkg.get_data()
		binary_data["BUILD_ID"] = metadata["BUILD_ID"]
		binpkg.recompose_mem(string(xpak_mem(binary_data)), true)
	}

	b._file_permissions(full_path)
	pkgindex := b.LoadPkgIndex()
	if ! b._pkgindex_version_supported(pkgindex) {
		pkgindex = b._new_pkgindex()
	}

	d := b._inject_file(pkgindex, cpv, full_path)
	b._update_pkgindex_header(pkgindex.header)
	b._pkgindex_write(pkgindex)

	cpv.metadata["MD5"] = d["MD5"]

	return cpv
}

// nil
func (b *BinaryTree) _read_metadata(filename string, st os.FileInfo, keys []string) map[string]string {
	metadata :=map[string]string{}
	if keys == nil {
		keys = b.dbapi._aux_cache_keys
		metadata = b.dbapi._aux_cache_slot_dict()
	}
	binary_metadata := NewTbz2(filename).get_data()
	for _, k := range keys {
		if k == "_mtime_" {
			metadata[k] = fmt.Sprint(st.ModTime().Nanosecond())
		} else if k == "SIZE" {
			metadata[k] = fmt.Sprint(st.Size())
		} else {
			v := binary_metadata[k]
			if v == "" {
				if k == "EAPI" {
					metadata[k] = "0"
				} else {
					metadata[k] = ""
				}
			} else {
				metadata[k] = strings.Join(strings.Fields(v), " ")
			}
		}
	}
	return metadata
}

func (b *BinaryTree) _inject_file(pkgindex *PackageIndex, cpv *PkgStr, filename string) map[string]string {

	instance_key := b.dbapi._instance_key(cpv, false)
	if b._remotepkgs != nil {
		delete(b._remotepkgs, instance_key.string)
	}

	b.dbapi.cpv_inject(cpv)
	b._pkg_paths[instance_key.string] = filename[len(b.pkgdir)+1:]
	d := b._pkgindex_entry(cpv)

	path := d["PATH"]
	for i := len(pkgindex.packages) - 1; i > -1; i-- {
		d2 := pkgindex.packages[i]
		if path != "" && path == d2["PATH"] {
			pp := []map[string]string{}
			for i2, p := range pkgindex.packages {
				if i != i2 {
					pp = append(pp, p)
				}
			}
			pkgindex.packages = pp
		} else if cpv.string == d2["CPV"] {
			if path == d2["PATH"] {
				pp := []map[string]string{}
				for i2, p := range pkgindex.packages {
					if i != i2 {
						pp = append(pp, p)
					}
				}
				pkgindex.packages = pp
			}
		}
	}

	pkgindex.packages = append(pkgindex.packages, d)
	return d
}

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
	for k, v := range performMultipleChecksums(pkg_path, b._pkgindex_hashes, false) {
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

func (b *BinaryTree) _propagate_config(config *Config) bool {

	if b._pkgindex_header == nil {
		return false
	}

	b._merge_pkgindex_header(b._pkgindex_header,
		config.configDict["defaults"])
	config.regenerate(0)
	config.initIuse()
	return true
}

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
		//WriteMsg("%s: %s\n" % (k, e), noiselevel=-1)
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

func (b *BinaryTree) _is_specific_instance(cpv *PkgStr) bool {

	specific := true
//try:
	build_time := cpv.buildTime
	build_id := cpv.buildId
	//except AttributeError:
	//specific = false
	//else:
	if build_time == 0 || build_id == 0 {
		specific = false
	}
	return specific
}

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

func (b *BinaryTree) get_pkgindex_uri(cpv *PkgStr) string {
	uri := ""
	if b._remotepkgs != nil {
		metadata := b._remotepkgs[b.dbapi._instance_key(cpv, false).string]
		if metadata != nil {
			uri = metadata["PKGINDEX_URI"]
		}
	}
	return uri

}

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

func (b *BinaryTree) _get_digests(pkg) {

try:
	cpv = pkg.cpv
	except AttributeError:
	cpv = pkg

	_instance_key := b.dbapi._instance_key
	instance_key := _instance_key(cpv, false)
	digests := {}
	metadata = (nil if b._remotepkgs == nil else
	b._remotepkgs.get(instance_key))
	if metadata == nil:
	for d in b._load_pkgindex().packages:
	if (d["CPV"] == cpv &&
	instance_key == _instance_key(_pkg_str(d["CPV"],
		metadata=d, settings=b.settings))):
	metadata = d
	break

	if metadata == nil:
	return digests

	for k in get_valid_checksum_keys():
	v = metadata.get(k)
	if not v:
	continue
	digests[k] = v

	if "SIZE" in metadata:
try:
	digests["size"] = int(metadata["SIZE"])
	except ValueError:
	WriteMsg(_("!!! Malformed SIZE attribute in remote " 
"metadata for '%s'\n") % cpv)

	return digests

}

func (b *BinaryTree) getslot(mycatpkg *PkgStr) string {

	myslot := ""
//try:
	myslot = b.dbapi._pkg_str(mycatpkg, "").slot
	//except KeyError:
	//pass
	return myslot
}

func NewBinaryTree(pkgDir string, settings *Config) *BinaryTree {
	b := &BinaryTree{}
	if pkgDir == "" {
		//raise TypeError("pkgdir parameter is required")
	}
	if settings != nil {
		//raise TypeError("Settings parameter is required")
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
	st, err := os.Stat(filepath.Join(b.pkgdir, "All"))
	b._all_directory = err != nil && st != nil && st.IsDir()
	b._pkgindex_version = 0
	b._pkgindex_hashes = []string{"MD5", "SHA1"}
	b._pkgindex_file = filepath.Join(b.pkgdir, "Packages")
	b._pkgindex_keys = CopyMapSB(b.dbapi.auxCacheKeys)
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
	for v := range b._pkgindex_keys {
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

type _better_cache struct {
	_scanned_cats map[string]bool
	_repo_list    []*RepoConfig
	_items        map[string][]*RepoConfig
}

func (b *_better_cache) __getitem__(catpkg string) []*RepoConfig {
	result := b._items[catpkg]
	if result != nil {
		return result
	}

	cat := catsplit(catpkg)[0]
	if _, ok := b._scanned_cats[cat]; !ok {
		b._scan_cat(cat)
	}
	return b._items[catpkg]
}

func (b *_better_cache) _scan_cat( cat string) {
	for _, repo := range b._repo_list {
		cat_dir := repo.Location + "/" + cat
		pkg_list, err := listDir(cat_dir)
		if err != nil {
			//except OSError as e:
			if err != syscall.ENOTDIR && err != syscall.ENOENT && err != syscall.ESTALE {
				//raise
			}
			continue
		}
		for _, p := range pkg_list {
			if pathIsDir(cat_dir + "/" + p) {
				b._items[cat+"/"+p] = append(b._items[cat+"/"+p], repo)
			}
		}
	}
	b._scanned_cats[cat] = true
}

func NewBetterCache( repositories []*RepoConfig)*_better_cache {
	b := &_better_cache{}
	b._items = map[string][]*RepoConfig{}
	b._scanned_cats = map[string]bool{}

	b._repo_list = []*RepoConfig{}

	r := []*RepoConfig{}
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
	repositories             *repoConfigLoader
	treemap                  map[string]string
	doebuild_settings        *Config
	depcachedir              string
	porttrees                []string
	_have_root_eclass_dir    bool
	xcache                   map[string]map[[2]string][]*PkgStr
	frozen                   bool
	auxdb                    map[string]*VolatileDatabase
	_pregen_auxdb, _ro_auxdb map[string]map[string]string
	_ordered_repo_name_list  []string
	_aux_cache_keys          map[string]bool
	_aux_cache               map[string]string
	_broken_ebuilds          map[string]bool
	_better_cache            *_better_cache
	_porttrees_repos         map[string]*RepoConfig
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

func (p *portdbapi) _event_loop() {
	return asyncio._safe_loop()
}

func (p *portdbapi) _create_pregen_cache(tree string) {
	conf := p.repositories.getRepoForLocation(tree)
	cache := conf.get_pregenerated_cache(p._known_keys, true,false)
	if cache!= nil {
	//try:
		cache.ec = p.repositories.getRepoForLocation(tree).eclassDb
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
	ensureDirs(p.depcachedir, -1, *portage_gid,
		0o2070, 0o2, nil, true)
}

func (p *portdbapi) close_caches() {
	if p.auxdb == nil {
		return
	}
	for x := range p.auxdb{
		p.auxdb[x].sync(0)
	}
	p.auxdb = map[string]*VolatileDatabase{}
}

func (p *portdbapi) flush_cache() {
	for _, x := range p.auxdb {
		x.sync(0)
	}
}

func (p *portdbapi) findLicensePath(license_name string) string {
	for _, x := range reversed(p.porttrees) {
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

func (p *portdbapi) getIgnoredRepos() []sss{
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
	psplit := pkgSplit(mysplit[1], "")
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
			mytrees = reversed(p.porttrees)
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
		if osAccess(filename, unix.R_OK) {
			return filename, x
		}
	}
	return "", 0
}

func (p *portdbapi) _write_cache(cpv, repo_path, metadata, ebuild_hash) {
try:
	cache := p.auxdb[repo_path]
	chf := cache.validation_chf
	metadata[fmt.Sprintf("_%s_", chf)] = getattr(ebuild_hash, chf)
	except CacheError:
		traceback.print_exc()
	cache = nil

	if cache != nil:
try:
	cache[cpv] = metadata
	except CacheError:
		traceback.print_exc()
}

func (p *portdbapi) _pull_valid_cache(cpv, ebuild_path, repo_path string) {

try:
	ebuild_hash = eclass_cache.hashed_path(ebuild_path)
	ebuild_hash.mtime
	except FileNotFound:
	WriteMsg(fmt.Sprintf("!!! aux_get(): ebuild for "
"'%s' does not exist at:\n", cpv,),-1, nil)
	WriteMsg(fmt.Sprintf("!!!            %s\n" , ebuild_path),-1, nil)
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
	eclass_db := p.repositories.getRepoForLocation(repo_path).eclassDb

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
		WriteMsg(fmt.Sprintf("!!! aux_get(): %s\n",
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

	proc := NewEbuildMetadataPhase(mycpv, ebuild_hash, p, mylocation, loop, p.doebuild_settings)

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

func (p *portdbapi) _aux_get_return(future Future, mycpv, mylist, myebuild, ebuild_hash,
	mydata, mylocation string, cache_me, proc) {
	if future.cancelled() {
		return
	}
	if proc is
	not
nil:
	if proc.returncode != 0:
	p._broken_ebuilds.add(myebuild)
	future.set_exception(PortageKeyError(mycpv))
	return
	mydata = proc.metadata
	mydata["repository"] = p.repositories.getNameForLocation(mylocation)
	mydata["_mtime_"] = ebuild_hash.mtime
	eapi = mydata.get("EAPI")
	if not eapi:
	eapi = "0"
	mydata["EAPI"] = eapi
	if eapi_is_supported(eapi):
	mydata["INHERITED"] = " ".join(mydata.get("_eclasses_", []))

	for x
		in
	mylist {
		returnme = append(returnme, mydata.get(x, ""))
	}

	if cache_me && p.frozen:
	aux_cache =
	{
	}
	for x
	in
	p._aux_cache_keys:
	aux_cache[x] = mydata.get(x, "")
	p._aux_cache[mycpv] = aux_cache

	future.set_result(returnme)

}

// nil, nil
func (p *portdbapi) getFetchMap(mypkg string, useflags []string, mytree string) {
	loop = p._event_loop
	return loop.run_until_complete(
		p.async_fetch_map(mypkg, useflags = useflags,
		mytree = mytree, loop=loop))
}

// coroutine
func (p *portdbapi) async_fetch_map(mypkg, useflags=nil, mytree=nil, loop=nil) {

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

		if !eapiIsSupported(eapi) {
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
func (p *portdbapi) getfetchsizes(mypkg string, useflags []string, debug int, myrepo string) {
	myebuild, mytree := p.findname2(mypkg, "", myrepo)
	if myebuild == "" {
		//raise AssertionError(_("ebuild not found for '%s'") % mypkg)
	}
	pkgdir := filepath.Dir(myebuild)
	mf := p.repositories.getRepoForLocation(
		filepath.Dir(filepath.Dir(pkgdir))).load_manifest(
		pkgdir, p.settings.ValueDict["DISTDIR"], nil, false)
	checksums := mf.getDigests()
	if len(checksums) == 0 {
		if debug != 0 {
			WriteMsg(fmt.Sprintf("[empty/missing/bad digest]: %s\n", mypkg, ), -1, nil)
		}
		return {}
	}
	filesdict :={}
	myfiles := p.getFetchMap(mypkg, useflags, mytree)
	for myfile
	in
myfiles:
	fetch_size, err := strconv.Atoi(checksums[myfile]["size"])
	if err != nil {
		//except(KeyError, ValueError):
		if debug {
			WriteMsg(fmt.Sprintf("[bad digest]: missing %s for %s\n", myfile, mypkg), 0, nil)
		}
		continue
	}
	file_path := filepath.Join(p.settings.ValueDict["DISTDIR"], myfile)
	mystat, err := os.Stat(file_path)
	if err != nil {
		//except OSError:
		//pass
	}else {
		if mystat.Size() != fetch_size {
			mystat = nil
		}
	}

	if mystat == nil {
		var err error
		mystat, err = os.Stat(file_path + _download_suffix)
		if err != nil {
			//except OSError:
			//pass
		}
	}

	if mystat == nil {
	existing_size = 0
	ro_distdirs = p.settings.ValueDict["PORTAGE_RO_DISTDIRS"]
	if ro_distdirs is
	not
nil:
	for x
	in
	shlex_split(ro_distdirs):
try:
	mystat = os.Stat(filepath.Join(x, myfile))
	except
OSError:
	pass
	else{
			if mystat.st_size == fetch_size {
				existing_size = fetch_size
				break
			}
		}
	}else{
		existing_size = mystat.Size()
	}
	remaining_size = fetch_size - existing_size
	if remaining_size > 0 {
		filesdict[myfile] = remaining_size
	}else if remaining_size < 0 {
		filesdict[myfile], _ = strconv.Atoi(checksums[myfile]["size"])
	}
	return filesdict

}

// nil, nil, false, ""
func (p *portdbapi) fetch_check(mypkg string, useflags []string, mysettings *Config, all bool, myrepo string) {

	if all {
		useflags = nil
	}else if useflags == nil {
		if mysettings != nil {
			useflags = strings.Fields(mysettings.ValueDict["USE"])
		}
	}
	mytree :=""
	if myrepo != "" {
		mytree := p.treemap[myrepo]
		if mytree == "" {
			return false
		}
	}

	myfiles := p.getFetchMap(mypkg, useflags, mytree)
	myebuild := p.findname(mypkg, "", myrepo)
	if myebuild is
nil:
	raise
	AssertionError(_("ebuild not found for '%s'") % mypkg)
	pkgdir = filepath.Dir(myebuild)
	mf = p.repositories.get_repo_for_location(
		filepath.Dir(filepath.Dir(pkgdir)))
	mf = mf.load_manifest(pkgdir, p.settings.ValueDict["DISTDIR"])
	mysums = mf.getDigests()

	failures =
	{
	}
	for x
	in
myfiles:
	if not mysums
||	x
	not
	in
mysums:
	ok = false
	reason = _("digest missing")
	else:
try:
	ok, reason = portage.checksum.verify_all(
		filepath.Join(p.settings.ValueDict["DISTDIR"], x), mysums[x])
	except
	FileNotFound
	as
e:
	ok = false
	reason = _("File Not Found: '%s'") % (e,)
	if not ok:
	failures[x] = reason
	if failures:
	return false
	return true
}

// ""
func (p *portdbapi) cpv_exists(mykey, myrepo string) int {
	cps2:= strings.Split(mykey, "/")
	cps := CatPkgSplit(mykey, 0, "")
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
			for _, y := range listdir(oroot+"/"+x, false, false, true, []string{}, true, true, true) {
				atom1, err  := NewAtom(fmt.Sprintf("%s/%s",x, y), nil, false, nil, nil, "", nil, nil)
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
		l = reversed(sorted(l))
	}
	return l
}

// 1, nil
func (p *portdbapi) cp_list(mycp string, use_cache int, mytree []string) []*PkgStr {
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
	repos := []*RepoConfig{}
	if mytree != nil {
		for _, location := range mytree {
			repos = append(repos, p.repositories.getRepoForLocation(location))
		}
	} else if p._better_cache == nil {
		for _, k := range p._porttrees_repos {
			repos = append(repos, k)
		}
	} else {
		rpbc := []*RepoConfig{}
		for _, v := range p._better_cache.__getitem__(mycp) {
			rpbc = append([]*RepoConfig{v}, rpbc...)
		}
		p._better_cache.__getitem__(mycp)
		for _, repo := range rpbc {
			if _, ok := p._porttrees_repos[repo.Name]; ok {
				repos = append(repos, repo)
			}
		}
	}
	mylist := []*PkgStr{}
	for _, repo := range repos {
		oroot := repo.Location
		file_list, err := listDir(filepath.Join(oroot, mycp))
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
				ps := PkgSplit(pf, 1, "")
				if ps == [3]string{} {
					WriteMsg(fmt.Sprintf("\nInvalid ebuild name: %s\n",
						filepath.Join(oroot, mycp, x)), -1, nil)
					continue
				}
				if ps[0] != mysplit[1] {
					WriteMsg(fmt.Sprintf("\nInvalid ebuild name: %s\n",
						filepath.Join(oroot, mycp, x)), -1, nil)
					continue
				}
				if !verRegexp.MatchString(strings.Join(ps[1:], "-")) {
					WriteMsg(fmt.Sprintf("\nInvalid ebuild version: %s\n",
						filepath.Join(oroot, mycp, x)), -1, nil)
					continue
				}
				mylist = append(mylist, NewPkgStr(mysplit[0]+"/"+pf, nil, nil, "", "", repo.Name, 0, 0, "", 0, p))
			}
		}
	}
	if invalid_category && len(mylist) > 0 {
		WriteMsg(fmt.Sprintf("\n!!! '%s' has a category that is not listed in "+
			"%setc/portage/categories\n",
			mycp, p.settings.ValueDict["PORTAGE_CONFIGROOT"]), -1, nil)
		mylist = []*PkgStr{}
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
		p.xcache[x] = map[[2]string][]*PkgStr{}
	}
	p.frozen=true
	p._better_cache = NewBetterCache(p.repositories)
}

func (p *portdbapi) melt() {
	p.xcache = map[string]map[[2]string][]*PkgStr{}
	p._aux_cache = map[string]string{}
	p._better_cache = nil
	p.frozen = false
}

func (p *portdbapi) xmatch(level string, origdep *Atom) []*PkgStr {

	loop = p._event_loop
	return loop.run_until_complete(
		p.async_xmatch(level, origdep, loop=loop))
}

// @coroutine
func (p *portdbapi) async_xmatch(level string, origdep *Atom, loop=nil) []*PkgStr {
	mydep := dep_expand(origdep, p, 1, p.settings)
	mykey := mydep.cp

	cache_key := [2]string{}
	if p.frozen {
		cache_key = [2]string{mydep.value, mydep.unevaluatedAtom.value}
		c, ok := p.xcache[level]
		if ok {
			l, ok := c[cache_key]
			if ok {
				coroutine_return(l)
			}
		}
		//except KeyError:
		//pass
	}

	loop = asyncio._wrap_loop(loop)
	var myval, mylist []*PkgStr
	mytree := ""
	if mydep.repo != "" {
		mytree = p.treemap[mydep.repo]
		if mytree == "" {
			if strings.HasPrefix(level, "match-") {
				myval = []*PkgStr{}
			} else {
				myval = []*PkgStr{""}
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
			myval = matchFromList(mydep,
				p.cp_list(mykey, 1, []string{mytree}))
		}
	} else if Ins([]string{"bestmatch-visible", "match-all",
		"match-visible", "minimum-all", "minimum-all-ignore-profile",
		"minimum-visible"}, level) {
		if mydep.value == mykey {
			mylist = p.cp_list(mykey, 1, []string{mytree})
		} else {
			mylist = matchFromList(mydep,
				p.cp_list(mykey, 1, []string{mytree}))
		}

		ignore_profile := level == "minimum-all-ignore-profile"
		visibility_filter := !Ins([]string{"match-all", "minimum-all", "minimum-all-ignore-profile"}, level)
		single_match := !Ins([]string{"match-all", "match-visible"}, level)
		myval = []
		aux_keys = list(p._aux_cache_keys)
		if level == "bestmatch-visible" {
			iterfunc = reversed
		} else {
			iterfunc = iter
		}

		for _, cpv := range iterfunc(mylist) {
		try:
			metadata = dict(zip(aux_keys, (yield
			p.async_aux_get(cpv,
				aux_keys, myrepo = cpv.repo, loop = loop))))
			except
		KeyError:
			continue

			//try:
			pkg_str := NewPkgStr(cpv.string, metadata,
				p.settings, "", "", "", 0, 0, "", 0, p)
			//except InvalidData:
			//continue

			if visibility_filter && !p._visible(pkg_str, metadata) {
				continue
			}

			if mydep.slot != "" && !matchSlot(mydep, pkg_str) {
				continue
			}

			if mydep.unevaluated_atom.use != nil && !p._match_use(mydep, pkg_str, metadata, ignore_profile) {
				continue
			}

			myval = append(myval, pkg_str)
			if single_match {
				break
			}
		}

		if single_match {
			if myval {
				myval = myval[0]
			} else {
				myval = ""
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
			if not isinstance(myval, _pkg_str) {
				myval = myval[:]
			}
		}
	}

	coroutine_return(myval)
}

// 1
func (p *portdbapi) match(mydep  *Atom, use_cache int)[]*PkgStr {
	return p.xmatch("match-visible", mydep)
}

func (p *portdbapi) _visible(cpv *PkgStr, metadata map[string]string) bool {
	eapi := metadata["EAPI"]
	if !eapiIsSupported(eapi) {
		return false
	}
	if eapiIsDeprecated(eapi) {
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
		if !settings._accept_chost(cpv, metadata) {
			return false
		}
		metadata["USE"] = ""
		if strings.Contains(metadata["LICENSE"], "?") ||
			strings.Contains(metadata["PROPERTIES"], "?") {
			p.doebuild_settings.SetCpv(cpv, metadata)
			metadata["USE"] = p.doebuild_settings.ValueDict["PORTAGE_USE"]
		}
		//try:
		if settings._getMissingLicenses(cpv, metadata) {
			return false
		}
		if settings._getMissingProperties(cpv, metadata) {
			return false
		}
		if settings._getMissingRestrict(cpv, metadata) {
			return false
		}
		//except
		//InvalidDependString:
		return false
	}

	return true
}

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

	p.xcache = map[string]map[[2]string][]*PkgStr{}
	p.frozen = false

	rs := []string{}
	copy(rs, p.repositories.preposOrder)
	ReverseSlice(rs)
	p._ordered_repo_name_list = rs

	p.auxdbmodule = p.settings.load_best_module("portdbapi.auxdbmodule")
	p.auxdb = map[string]*VolatileDatabase{}
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
			p.auxdb[x] = NewVolatileDatabase(
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

	p._aux_cache = map[string]string{}
	p._better_cache = nil
	p._broken_ebuilds = map[string]bool{}

	return p
}

type PortageTree struct {
	settings *Config
	dbapi    *portdbapi
}

func (p *PortageTree) dep_bestmatch(mydep  *Atom) string {
	mymatch := p.dbapi.xmatch("bestmatch-visible", mydep)
	if mymatch == nil {
		return ""
	}
	return mymatch
}

func (p *PortageTree) dep_match(mydep  *Atom) {
	mymatch := p.dbapi.xmatch("match-visible", mydep)
	if mymatch == nil {
		return []
	}
	return mymatch
}

func (p *PortageTree) exists_specific(cpv) int {

	return p.dbapi.cpv_exists(cpv)
}

func (p *PortageTree) getallnodes() []string {
	return p.dbapi.cp_all()

}

func (p *PortageTree) getslot(mycatpkg *PkgStr) string {

	myslot := ""
	//try:
	myslot = p.dbapi._pkg_str(mycatpkg, "").slot
	//except KeyError:
	//pass
	return myslot
}

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

func (f *FetchlistDict) __getitem__(pkg_key string) {
	return list(f.portdb.getFetchMap(pkg_key, nil, f.mytree))

}

func (f *FetchlistDict) __contains__(cpv *PkgStr) bool {
	for _, i := range f.__iter__() {
		if cpv.string == i.string {
			return true
		}
	}
	return false
}

func (f *FetchlistDict) __iter__() []*PkgStr {
	return f.portdb.cp_list(f.cp, 1, f.mytree)

}

func (f *FetchlistDict) __len__() int {
	return len(f.portdb.cp_list(f.cp, 1, f.mytree))

}

func (f *FetchlistDict) keys() []*PkgStr {
	return f.portdb.cp_list(f.cp, 1, f.mytree)
}

func NewFetchlistDict(pkgdir string, settings *Config, mydbapi *portdbapi) *FetchlistDict {
	f := &FetchlistDict{}
	f.pkgdir = pkgdir
	f.cp = filepath.Join(strings.Split(pkgdir, string(os.PathSeparator))[len(strings.Split(pkgdir, string(os.PathSeparator)))-2:]...)
	f.settings = settings
	f.mytree, _ = filepath.EvalSymlinks(filepath.Dir(filepath.Dir(pkgdir)))
	f.portdb = mydbapi

	return f
}

// nil, nil, nil, nil
func _async_manifest_fetchlist(portdb, repo_config, cp, cpv_list=nil,
	max_jobs=nil, max_load=nil, loop=nil) {
	loop = asyncio._wrap_loop(loop)
	result = loop.create_future()
	cpv_list = (portdb.cp_list(cp, mytree = repo_config.location)
	if cpv_list is
	nil else cpv_list)

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
	result.set_result(dict((k, list(v.result()))
	for k, v
	in
	zip(cpv_list, gather_result.result()))) else:
	result.set_exception(e)

	gather_result = iter_gather(
		(portdb.async_fetch_map(cpv, mytree = repo_config.location, loop = loop)
	for cpv
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
func _parse_uri_map(cpv *PkgStr, metadata map[string]string, use map[string]bool) map[string]map[string]bool {
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
