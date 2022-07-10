package dbapi

import (
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/versions"
	"sort"
)

type fakedbapi struct {
	*dbapi
	_exclusive_slots bool
	cpvdict          map[string]map[string]string
	cpdict           map[string][]*versions.PkgStr
	_match_cache     map[[2]string][]*versions.PkgStr
	_instance_key    func(*versions.PkgStr, bool) *versions.PkgStr
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
func (f *fakedbapi) _instance_key_cpv(cpv *versions.PkgStr, support_string bool) *versions.PkgStr {
	return cpv
}

// false
func (f *fakedbapi) _instance_key_multi_instance(cpv *versions.PkgStr, support_string bool) *versions.PkgStr {
	return versions.NewPkgStr(cpv.string, nil, nil, "", "", "", cpv.buildTime, cpv.buildId, cpv.fileSize, cpv.mtime, nil)
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
	f.cpdict = map[string][]*versions.PkgStr{}
}

func (f *fakedbapi) _clear_cache() {
	if f._categories != nil {
		f._categories = nil
	}
	if len(f._match_cache) > 0 {
		f._match_cache = map[[2]string][]*versions.PkgStr{}
	}
}

// 1
func (f *fakedbapi) match(origdep string, use_cache int) []*versions.PkgStr {
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

func (f *fakedbapi) cpv_exists(mycpv *versions.PkgStr) bool {
	_, ok := f.cpvdict[f._instance_key(mycpv,
		true).string]
	return ok
}

// 1
func (f *fakedbapi) cp_list(mycp string, use_cache int) []*versions.PkgStr {
	cacheKey := [2]string{mycp, mycp}
	cacheList := f._match_cache[cacheKey]
	if cacheList != nil {
		return cacheList[:]
	}
	cpvList := f.cpdict[mycp]
	if cpvList == nil {
		cpvList = []*versions.PkgStr{}
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

func (f *fakedbapi) cpv_inject(mycpv *versions.PkgStr, metadata map[string]string) {
	f._clear_cache()

	myCp := mycpv.cp
	mySlot := mycpv.slot
	if myCp == "" || (mySlot == "" && metadata != nil && metadata["SLOT"] != "") {

		if metadata == nil {
			mycpv = versions.NewPkgStr(mycpv.string, nil, nil, "", "", "", 0, 0, "", 0, f.dbapi)
		} else {
			mycpv = versions.NewPkgStr(mycpv.string, metadata, f.settings, "", "", "", 0, 0, "", 0, f.dbapi)
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
		cpList = []*versions.PkgStr{}
	}
	tmp := cpList
	cpList = []*versions.PkgStr{}
	for _, x := range tmp {
		if f._instance_key(x, false) != instanceKey {
			cpList = append(cpList, x)
		}
	}
	cpList = append(cpList, mycpv)
	f.cpdict[myCp] = cpList
}

func (f *fakedbapi) cpv_remove(mycpv *versions.PkgStr) {
	f._clear_cache()
	myCp := versions.cpvGetKey(mycpv.string, "")
	instanceKey := f._instance_key(mycpv, false)
	delete(f.cpvdict, instanceKey.string)
	cpList := f.cpdict[myCp]
	if cpList != nil {
		tmp := cpList
		cpList = []*versions.PkgStr{}
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
func (f *fakedbapi) aux_get(mycpv *versions.PkgStr, wants []string) []string {
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

func (f *fakedbapi) aux_update(cpv *versions.PkgStr, values map[string]string) {
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
func NewFakeDbApi(settings *config.Config, exclusive_slots, multi_instance bool) *fakedbapi {
	f := &fakedbapi{dbapi: NewDbapi(), _exclusive_slots: exclusive_slots,
		cpvdict: map[string]map[string]string{},
		cpdict:  map[string][]*versions.PkgStr{}}
	if settings == nil {
		settings = portage.Settings()
	}
	f.settings = settings
	f._match_cache = map[[2]string][]*versions.PkgStr{}
	f._set_multi_instance(multi_instance)
	return f
}
