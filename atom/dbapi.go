package atom

import (
	"fmt"
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
		iuseImplicitMatch = d.settings._iuse_effective_match
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

func (d *dbapi) auxGet(myCpv *pkgStr, myList []string, myRepo string) string {
	panic("NotImplementedError")
	return ""
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

//func (d *dbapi) _cpv_sort_ascending(cpv_list []) {
//
//}

func (d *dbapi) cp_all(sort bool) []string { // f
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
		for _, k := range aux_keys {
			metadata[k] = d.auxGet(cpv, aux_keys, atom.repo)
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

type vardbapi struct {
	*dbapi
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

	return v
}

type fakedbapi struct {
	*dbapi
}

type bindbapi struct {
	*fakedbapi
}

type binarytree struct {

}

func NewBinaryTree(pkgDir string, setting *Config)*binarytree{
	b := &binarytree{}
	return b
}

type portdbapi struct {
	*dbapi
}

type portagetree struct {

}

func NewPortageTree(setting *Config)*portagetree{
	p := &portagetree{}
	return p
}
