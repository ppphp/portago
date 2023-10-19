package dbapi

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/dep"
	eapi2 "github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/emerge/structs"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"os"
	"regexp"
	"sort"
	"strings"
)

type dbapi[T interfaces.ISettings] struct {
	interfaces.IDbApi
	_category_re      *regexp.Regexp
	_use_mutable      bool
	_categories       []string
	_known_keys       map[string]bool
	_pkg_str_aux_keys []string
	settings          T
}

func NewDbapi[T interfaces.ISettings]() *dbapi[T] {
	d := &dbapi[T]{_category_re: regexp.MustCompile(`^\w[-.+\w]*$`),
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

func (d *dbapi[T]) Categories() []string {
	if d._categories != nil {
		return d._categories
	}
	m := map[string]bool{}
	for _, x := range d.cp_all(false) {
		m[versions.CatSplit(x)[0]] = true
	}
	d._categories = []string{}
	for x := range m {
		d._categories = append(d._categories, x)
	}
	sort.Strings(d._categories)

	return d._categories
}

func (d *dbapi[T]) Close_caches() {}

//1
func (d *dbapi[T]) Cp_list(cp string, useCache int) []interfaces.IPkgStr {
	panic("")
	return nil
}

func (d *dbapi[T]) _cmp_cpv(cpv1, cpv2 *versions.PkgStr[T]) int {
	result, _ := versions.VerCmp(cpv1.Version(), cpv2.Version())
	if result == 0 && cpv1.BuildTime() != 0 && cpv2.BuildTime() != 0 {
		if (cpv1.BuildTime() > cpv2.BuildTime()) && (cpv1.BuildTime() < cpv2.BuildTime()) {
			result = 0
		} else if !(cpv1.BuildTime() > cpv2.BuildTime()) && (cpv1.BuildTime() < cpv2.BuildTime()) {
			result = -2
		} else if (cpv1.BuildTime() > cpv2.BuildTime()) && !(cpv1.BuildTime() < cpv2.BuildTime()) {
			result = 2
		} else { // (cpv1.BuildTime > cpv2.BuildTime)&&(cpv1.BuildTime < cpv2.BuildTime)
			result = 0
		}
	}
	return result
}

func (d *dbapi[T]) _cpv_sort_ascending(cpvList []*versions.PkgStr[T]) {
	if len(cpvList) > 1 {
		sort.Slice(cpvList, func(i, j int) bool {
			return d._cmp_cpv(cpvList[i], cpvList[j]) < 0
		})
	}
}

func (d *dbapi[T]) cpv_all() []*versions.PkgStr[T] {
	cpvList := []*versions.PkgStr[T]{}
	for _, cp := range d.cp_all(false) {
		cpvList = append(cpvList, d.Cp_list(cp, 1)...)
	}
	return cpvList
}

func (d *dbapi[T]) cp_all(sort bool) []string { // false
	panic("")
	return nil
}

func (d *dbapi[T]) AuxGet(myCpv *versions.PkgStr[T], myList []string, myRepo string) []string {
	panic("NotImplementedError")
	return nil
}

func (d *dbapi[T]) auxUpdate(cpv string, metadataUpdates map[string]string) {
	panic("NotImplementedError")
}

func (d *dbapi[T]) match(origdep *dep.Atom[T], useCache int) []interfaces.IPkgStr { // 1
	mydep := Dep_expand(origdep, d, 1, d.settings)
	return d.Iter_match(mydep, d.Cp_list(mydep.Cp, useCache))
}

func (d *dbapi[T]) Iter_match(atom *dep.Atom[T], cpvIter []interfaces.IPkgStr) []interfaces.IPkgStr {
	cpvIter = dep.MatchFromList(atom, cpvIter)
	if atom.Repo != "" {

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

func (d *dbapi[T]) _pkg_str(cpv *versions.PkgStr[T], repo string) *versions.PkgStr[T] {
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

func (d *dbapi[T]) _iter_match_repo(atom *dep.Atom[T], cpvIter []*versions.PkgStr[T]) []*versions.PkgStr[T] {
	r := []*versions.PkgStr[T]{}
	for _, cpv := range cpvIter {
		pkgStr := d._pkg_str(cpv, atom.Repo)
		if pkgStr.Repo == atom.Repo {
			r = append(r, pkgStr)
		}
	}
	return r
}

func (d *dbapi[T]) _iter_match_slot(atom *dep.Atom, cpvIter []*versions.PkgStr[T]) []*versions.PkgStr[T] {
	r := []*versions.PkgStr[T]{}
	for _, cpv := range cpvIter {
		pkgStr := d._pkg_str(cpv, atom.Repo)
		if dep.MatchSlot(atom, cpv) {
			r = append(r, pkgStr)
		}
	}
	return r
}

func (d *dbapi[T]) _iter_match_use(atom *dep.Atom[T], cpvIter []*versions.PkgStr[T]) []*versions.PkgStr[T] {
	aux_keys := []string{"EAPI", "IUSE", "KEYWORDS", "SLOT", "USE", "repository"}

	r := []*versions.PkgStr[T]{}
	for _, cpv := range cpvIter {
		metadata := map[string]string{}
		a := d.AuxGet(cpv, aux_keys, atom.Repo)
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

func (d *dbapi[T]) _repoman_iuse_implicit_cnstr(pkg, metadata map[string]string) func(flag string) bool {
	eapiAttrs := eapi2.GetEapiAttrs(metadata["EAPI"])
	var iUseImplicitMatch func(flag string) bool = nil
	if eapiAttrs.IuseEffective {
		iUseImplicitMatch = func(flag string) bool {
			return d.settings.IuseEffectiveMatch(flag)
		}
	} else {
		iUseImplicitMatch = func(flag string) bool {
			return d.settings.iuseImplicitMatch.call(flag)
		}
	}
	return iUseImplicitMatch
}

func (d *dbapi[T]) _iuse_implicit_cnstr(pkg *versions.PkgStr[T], metadata map[string]string) func(string) bool {
	eapiAttrs := eapi2.GetEapiAttrs(metadata["EAPI"])
	var iUseImplicitMatch func(string) bool
	if eapiAttrs.IuseEffective {
		iUseImplicitMatch = d.settings.IuseEffectiveMatch
	} else {
		iUseImplicitMatch = d.settings.iuseImplicitMatch.call
	}

	if !d._use_mutable && eapiAttrs.IuseEffective {
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
func (d *dbapi[T]) _match_use(atom *dep.Atom[T], pkg *versions.PkgStr[T], metadata map[string]string, ignoreProfile bool) bool {
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

func (d *dbapi[T]) invalidentry(myPath string) {
	if strings.Contains(myPath, "/"+_const.MergingIdentifier) {
		if _, err := os.Stat(myPath); err != nil {
			msg.WriteMsg(output.Colorize("BAD", "INCOMPLETE MERGE:"+fmt.Sprintf(" %s\n", myPath)), -1, nil)
		}
	} else {
		msg.WriteMsg(fmt.Sprintf("!!! Invalid db entry: %s\n", myPath), -1, nil)
	}
}

func (d *dbapi[T]) update_ents(updates map[string][][]*dep.Atom[T], onProgress, onUpdate func(int, int)) {
	cpvAll := d.cpv_all()
	sort.Slice(cpvAll, func(i, j int) bool {
		return cpvAll[i].String < cpvAll[j].String
	})
	maxval := len(cpvAll)
	auxGet := d.AuxGet
	auxUpdate := d.auxUpdate
	updateKeys := structs.NewPackage(false, nil, false, nil, nil, "").depKeys
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
		pkg := versions.NewPkgStr(cpv.String, metadata, d.settings, "", "", "", 0, 0, "", 0, nil)
		//except InvalidData:
		//continue
		m := map[string]string{}
		for _, k := range updateKeys {
			m[k] = metadata[k]
		}
		//if repo_dict ==nil{ // always false
		//	updates_list = updates
		//} else{
		var updatesList [][]*dep.Atom[T] = nil
		var ok bool
		if updatesList, ok = repoDict[pkg.Repo]; !ok {
			if updatesList, ok = repoDict["DEFAULT"]; !ok {
				continue
			}
		}

		if len(updatesList) == 0 {
			continue
		}
		metadataUpdates :=  portage.update_dbentries(updatesList, metadata, "", pkg)
		if len(metadataUpdates) != 0 {
			auxUpdate(cpv.String, metadataUpdates)
		}
		if onUpdate != nil {
			onUpdate(maxval, i+1)
		}
		if onProgress != nil {
			onProgress(maxval, i+1)
		}
	}
}

func (d *dbapi[T]) move_slot_ent(myList []*dep.Atom[T], repoMatch func(string) bool) int { // nil
	atom := myList[1]
	origSlot := myList[2]
	newSlot := myList[3]
	atom = atom.withSlot(origSlot.Value)
	origMatches := d.match(atom, 1)
	moves := 0
	if len(origMatches) == 0 {
		return moves
	}
	for _, mycpv := range origMatches {
		mycpv = d._pkg_str(mycpv, atom.Repo)
		if repoMatch != nil && !repoMatch(mycpv.Repo) {
			continue
		}
		moves += 1
		if !strings.Contains(newSlot.Value, "/") && mycpv.SubSlot != "" && mycpv.SubSlot != mycpv.Slot && mycpv.SubSlot != newSlot.Value {
			newSlot.Value = fmt.Sprintf("%s/%s", newSlot.Value, mycpv.SubSlot)
		}
		mydata := map[string]string{"SLOT": newSlot.Value + "\n"}
		d.auxUpdate(mycpv.String, mydata)
	}
	return moves
}
