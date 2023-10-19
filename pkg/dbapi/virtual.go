package dbapi

import (
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/versions"
	"sort"
)

type fakedbapi[T interfaces.ISettings] struct {
	*dbapi[T]
	_exclusive_slots bool
	cpvdict          map[string]map[string]string
	cpdict           map[string][]interfaces.IPkgStr
	_match_cache     map[[2]string][]interfaces.IPkgStr
	_instance_key    func(interfaces.IPkgStr, bool) interfaces.IPkgStr
	_multi_instance  bool
}

// nil, true, false
func NewFakeDbApi[T interfaces.ISettings](settings T, exclusive_slots, multi_instance bool) *fakedbapi[T] {
	f := &fakedbapi[T]{dbapi: NewDbapi[T](), _exclusive_slots: exclusive_slots,
		cpvdict: map[string]map[string]string{},
		cpdict:  map[string][]interfaces.IPkgStr{}}
	if settings == nil {
		settings = portage.Settings()
	}
	f.settings = settings
	f._match_cache = map[[2]string][]interfaces.IPkgStr{}
	f._set_multi_instance(multi_instance)
	return f
}

func (f *fakedbapi[T]) _set_multi_instance(multi_instance bool) {
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
func (f *fakedbapi[T]) _instance_key_cpv(cpv interfaces.IPkgStr, support_string bool) interfaces.IPkgStr {
	return cpv
}

// false
func (f *fakedbapi[T]) _instance_key_multi_instance(cpv interfaces.IPkgStr, support_string bool) interfaces.IPkgStr {
	return versions.NewPkgStr[T](cpv.String, nil, nil, "", "", "", cpv.BuildTime, cpv.BuildId, cpv.FileSize, cpv.Mtime, nil)
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

func (f *fakedbapi[T]) clear() {
	f._clear_cache()
	f.cpvdict = map[string]map[string]string{}
	f.cpdict = map[string][]interfaces.IPkgStr{}
}

func (f *fakedbapi[T]) _clear_cache() {
	if f._categories != nil {
		f._categories = nil
	}
	if len(f._match_cache) > 0 {
		f._match_cache = map[[2]string][]interfaces.IPkgStr{}
	}
}

// 1
func (f *fakedbapi[T]) Match(origdep string, use_cache int) []interfaces.IPkgStr {
	atom := dep_expandS(origdep, f.dbapi, 1, f.settings)
	cacheKey := [2]string{atom.Value, atom.UnevaluatedAtom().Value}
	result := f._match_cache[cacheKey]
	if result != nil {
		return result[:]
	}
	result = f.Iter_match(atom, f.cp_list(atom.Cp, 1))
	f._match_cache[cacheKey] = result
	return result[:]
}

func (f *fakedbapi[T]) cpv_exists(mycpv interfaces.IPkgStr) bool {
	_, ok := f.cpvdict[f._instance_key(mycpv, true).String]
	return ok
}

// 1
func (f *fakedbapi[T]) cp_list(mycp string, use_cache int) []interfaces.IPkgStr {
	cacheKey := [2]string{mycp, mycp}
	cacheList := f._match_cache[cacheKey]
	if cacheList != nil {
		return cacheList[:]
	}
	cpvList := f.cpdict[mycp]
	if cpvList == nil {
		cpvList = []interfaces.IPkgStr{}
	}
	f._cpv_sort_ascending(cpvList)
	f._match_cache[cacheKey] = cpvList
	return cpvList[:]
}

// false
func (f *fakedbapi[T]) cp_all(sortt bool) []string {
	s := []string{}
	for x := range f.cpdict {
		s = append(s, x)
	}
	if sortt {
		sort.Strings(s)
	}
	return s
}

func (f *fakedbapi[T]) cpv_all() []string {
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

func (f *fakedbapi[T]) cpv_inject(mycpv interfaces.IPkgStr, metadata map[string]string) {
	f._clear_cache()

	myCp := mycpv.Cp
	mySlot := mycpv.Slot
	if myCp == "" || (mySlot == "" && metadata != nil && metadata["SLOT"] != "") {

		if metadata == nil {
			mycpv = versions.NewPkgStr[T](mycpv.String, nil, nil, "", "", "", 0, 0, "", 0, f.dbapi)
		} else {
			mycpv = versions.NewPkgStr[T](mycpv.String, metadata, f.settings, "", "", "", 0, 0, "", 0, f.dbapi)
		}
		myCp = mycpv.Cp
		mySlot = mycpv.Slot
	}

	instanceKey := f._instance_key(mycpv, false)
	f.cpvdict[instanceKey.String] = metadata
	if !f._exclusive_slots {
		mySlot = ""
	}
	if _, ok := f.cpdict[myCp]; mySlot != "" && ok {
		for _, cpv := range f.cpdict[myCp] {
			if instanceKey != f._instance_key(cpv, false) {
				otherSlot := cpv.Slot
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
		cpList = []interfaces.IPkgStr{}
	}
	tmp := cpList
	cpList = []interfaces.IPkgStr{}
	for _, x := range tmp {
		if f._instance_key(x, false) != instanceKey {
			cpList = append(cpList, x)
		}
	}
	cpList = append(cpList, mycpv)
	f.cpdict[myCp] = cpList
}

func (f *fakedbapi[T]) cpv_remove(mycpv interfaces.IPkgStr) {
	f._clear_cache()
	myCp := versions.CpvGetKey(mycpv.String, "")
	instanceKey := f._instance_key(mycpv, false)
	delete(f.cpvdict, instanceKey.String)
	cpList := f.cpdict[myCp]
	if cpList != nil {
		tmp := cpList
		cpList = []interfaces.IPkgStr{}
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
func (f *fakedbapi[T]) aux_get(mycpv interfaces.IPkgStr, wants []string) []string {
	metadata := f.cpvdict[f._instance_key(mycpv, true).String]
	if metadata == nil {
		//raise KeyError(mycpv)
	}
	ret := []string{}
	for _, x := range wants {
		ret = append(ret, metadata[x])
	}
	return ret
}

func (f *fakedbapi[T]) aux_update(cpv interfaces.IPkgStr, values map[string]string) {
	f._clear_cache()
	metadata := f.cpvdict[f._instance_key(cpv, true).String]
	if metadata == nil {
		//raise KeyError(cpv)
	}
	for k, v := range values {
		metadata[k] = v
	}
}
