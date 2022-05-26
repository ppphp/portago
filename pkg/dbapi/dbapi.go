package dbapi

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/dep"
	eapi2 "github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"os"
	"regexp"
	"sort"
	"strings"
)

//nil,1,nil
func dep_expandS(myDep string, myDb *dbapi, useCache int, settings *ebuild.Config) *dep.Atom {
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
	myDepA, err := dep.NewAtom(myDep, nil, false, &allowRepo, nil, "", nil, nil)
	if err != nil {
		//except InvalidAtom:
		if !dep.isValidAtom("="+myDep, false, false, true, "", false) {
			//raise
		}
		myDepA, _ = dep.NewAtom("="+myDep, nil, false, &allowRepo, nil, "", nil, nil)
		origDep = "=" + origDep
	}

	if !hasCat {
		myDep = versions.catsplit(myDepA.cp)[1]
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
	a, _ := dep.NewAtom(strings.Replace(myDep, origDep, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}

//nil,1,nil
func dep_expand(myDep *dep.Atom, myDb *dbapi, useCache int, settings *ebuild.Config) *dep.Atom {
	origDep := myDep
	d := myDep.value
	if !strings.HasPrefix(myDep.cp, "virtual/") {
		return myDep
	}
	d = myDep.cp

	expanded := cpv_expand(d, myDb, useCache, settings)
	r := true
	a, _ := dep.NewAtom(strings.Replace(d, origDep.value, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}

func cpv_expand(myCpv string, myDb *dbapi, useCache int, settings *ebuild.Config) string { // n1n
	mySlash := strings.Split(myCpv, "/")
	mySplit := versions.pkgSplit(mySlash[len(mySlash)-1], "")
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

type IDbApi interface {
	categories() []string
	close_caches()
	cp_list(cp string, useCache int) []*versions.PkgStr
	_cmp_cpv(cpv1, cpv2 *versions.PkgStr) int
	_cpv_sort_ascending(cpv_list []*versions.PkgStr)
	cpv_all() []*versions.PkgStr
	AuxGet(myCpv *versions.PkgStr, myList []string, myRepo string) []string
	auxUpdate(cpv string, metadataUpdates map[string]string)
	match(origdep *dep.Atom, useCache int) []*versions.PkgStr
	_iter_match(atom *dep.Atom, cpvIter []*versions.PkgStr) []*versions.PkgStr
	_pkg_str(cpv *versions.PkgStr, repo string) *versions.PkgStr
	_iter_match_repo(atom *dep.Atom, cpvIter []*versions.PkgStr) []*versions.PkgStr
	_iter_match_slot(atom *dep.Atom, cpvIter []*versions.PkgStr) []*versions.PkgStr
	_iter_match_use(atom *dep.Atom, cpvIter []*versions.PkgStr) []*versions.PkgStr
	_repoman_iuse_implicit_cnstr(pkg, metadata map[string]string) func(flag string) bool
	_iuse_implicit_cnstr(pkg *versions.PkgStr, metadata map[string]string) func(string) bool
	_match_use(atom *dep.Atom, pkg *versions.PkgStr, metadata map[string]string, ignore_profile bool) bool
	invalidentry(mypath string)
	update_ents(updates map[string][][]*dep.Atom, onProgress, onUpdate func(int, int))
	move_slot_ent(mylist []*dep.Atom, repo_match func(string) bool) int
}

type dbapi struct {
	_category_re      *regexp.Regexp
	_use_mutable      bool
	_categories       []string
	_known_keys       map[string]bool
	_pkg_str_aux_keys []string
	settings          *ebuild.Config
}

func (d *dbapi) categories() []string {
	if d._categories != nil {
		return d._categories
	}
	m := map[string]bool{}
	for _, x := range d.cp_all(false) {
		m[versions.catsplit(x)[0]] = true
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
func (d *dbapi) cp_list(cp string, useCache int) []*versions.PkgStr {
	panic("")
	return nil
}

func (d *dbapi) _cmp_cpv(cpv1, cpv2 *versions.PkgStr) int {
	result, _ := versions.verCmp(cpv1.version, cpv2.version)
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

func (d *dbapi) _cpv_sort_ascending(cpvList []*versions.PkgStr) {
	if len(cpvList) > 1 {
		sort.Slice(cpvList, func(i, j int) bool {
			return d._cmp_cpv(cpvList[i], cpvList[j]) < 0
		})
	}
}

func (d *dbapi) cpv_all() []*versions.PkgStr {
	cpvList := []*versions.PkgStr{}
	for _, cp := range d.cp_all(false) {
		cpvList = append(cpvList, d.cp_list(cp, 1)...)
	}
	return cpvList
}

func (d *dbapi) cp_all(sort bool) []string { // false
	panic("")
	return nil
}

func (d *dbapi) AuxGet(myCpv *versions.PkgStr, myList []string, myRepo string) []string {
	panic("NotImplementedError")
	return nil
}

func (d *dbapi) auxUpdate(cpv string, metadataUpdates map[string]string) {
	panic("NotImplementedError")
}

func (d *dbapi) match(origdep *dep.Atom, useCache int) []*versions.PkgStr { // 1
	mydep := dep_expand(origdep, d, 1, d.settings)
	return d._iter_match(mydep, d.cp_list(mydep.cp, useCache))
}

func (d *dbapi) _iter_match(atom *dep.Atom, cpvIter []*versions.PkgStr) []*versions.PkgStr {
	cpvIter = dep.matchFromList(atom, cpvIter)
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

func (d *dbapi) _pkg_str(cpv *versions.PkgStr, repo string) *versions.PkgStr {
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

func (d *dbapi) _iter_match_repo(atom *dep.Atom, cpvIter []*versions.PkgStr) []*versions.PkgStr {
	r := []*versions.PkgStr{}
	for _, cpv := range cpvIter {
		pkgStr := d._pkg_str(cpv, atom.repo)
		if pkgStr.repo == atom.repo {
			r = append(r, pkgStr)
		}
	}
	return r
}

func (d *dbapi) _iter_match_slot(atom *dep.Atom, cpvIter []*versions.PkgStr) []*versions.PkgStr {
	r := []*versions.PkgStr{}
	for _, cpv := range cpvIter {
		pkgStr := d._pkg_str(cpv, atom.repo)
		if dep.matchSlot(atom, cpv) {
			r = append(r, pkgStr)
		}
	}
	return r
}

func (d *dbapi) _iter_match_use(atom *dep.Atom, cpvIter []*versions.PkgStr) []*versions.PkgStr {
	aux_keys := []string{"EAPI", "IUSE", "KEYWORDS", "SLOT", "USE", "repository"}

	r := []*versions.PkgStr{}
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
	eapiAttrs := eapi2.getEapiAttrs(metadata["EAPI"])
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

func (d *dbapi) _iuse_implicit_cnstr(pkg *versions.PkgStr, metadata map[string]string) func(string) bool {
	eapiAttrs := eapi2.getEapiAttrs(metadata["EAPI"])
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
func (d *dbapi) _match_use(atom *dep.Atom, pkg *versions.PkgStr, metadata map[string]string, ignoreProfile bool) bool {
	iUseImplicitMatch := d._iuse_implicit_cnstr(pkg, metadata)
	useAliases := d.settings.useManager.getUseAliases(pkg)
	iUse := emerge.NewIUse("", strings.Fields(metadata["IUSE"]), iUseImplicitMatch, useAliases, metadata["EAPI"])

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
	if strings.Contains(myPath, "/"+_const.MergingIdentifier) {
		if _, err := os.Stat(myPath); err != nil {
			msg.WriteMsg(output.Colorize("BAD", "INCOMPLETE MERGE:"+fmt.Sprintf(" %s\n", myPath)), -1, nil)
		}
	} else {
		msg.WriteMsg(fmt.Sprintf("!!! Invalid db entry: %s\n", myPath), -1, nil)
	}
}

func (d *dbapi) update_ents(updates map[string][][]*dep.Atom, onProgress, onUpdate func(int, int)) {
	cpvAll := d.cpv_all()
	sort.Slice(cpvAll, func(i, j int) bool {
		return cpvAll[i].string < cpvAll[j].string
	})
	maxval := len(cpvAll)
	auxGet := d.AuxGet
	auxUpdate := d.auxUpdate
	updateKeys := emerge.NewPackage(false, nil, false, nil, nil, "").depKeys
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
		pkg := versions.NewPkgStr(cpv.string, metadata, d.settings, "", "", "", 0, 0, "", 0, nil)
		//except InvalidData:
		//continue
		m := map[string]string{}
		for _, k := range updateKeys {
			m[k] = metadata[k]
		}
		//if repo_dict ==nil{ // always false
		//	updates_list = updates
		//} else{
		var updatesList [][]*dep.Atom = nil
		var ok bool
		if updatesList, ok = repoDict[pkg.repo]; !ok {
			if updatesList, ok = repoDict["DEFAULT"]; !ok {
				continue
			}
		}

		if len(updatesList) == 0 {
			continue
		}
		metadataUpdates := atom.update_dbentries(updatesList, metadata, "", pkg)
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

func (d *dbapi) move_slot_ent(myList []*dep.Atom, repoMatch func(string) bool) int { // nil
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
	for x := range atom.auxdbkeys {
		if !strings.HasPrefix(x, "UNUSED_0") {
			d._known_keys[x] = true
		}
	}
	d._pkg_str_aux_keys = []string{"BUILD_TIME", "EAPI", "BUILD_ID", "KEYWORDS", "SLOT", "repository"}
	return d
}
