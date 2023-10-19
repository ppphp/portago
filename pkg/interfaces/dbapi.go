package interfaces

type IDbApi interface {
	Categories() []string
	Close_caches()
	Cp_list(cp string, useCache int, mytree string) []IPkgStr
	_cmp_cpv(cpv1, cpv2 IPkgStr) int
	_cpv_sort_ascending(cpv_list []IPkgStr)
	Cpv_all() []IPkgStr
	AuxGet(myCpv IPkgStr, myList []string, myRepo string) []string
	AuxUpdate(cpv string, metadataUpdates map[string]string)
	Match(origdep IAtom, useCache int) []IPkgStr
	Iter_match(atom IAtom, cpvIter []IPkgStr) []IPkgStr
	Pkg_str(cpv IPkgStr, repo string) IPkgStr
	Iter_match_repo(atom IAtom, cpvIter []IPkgStr) []IPkgStr
	Iter_match_slot(atom IAtom, cpvIter []IPkgStr) []IPkgStr
	Iter_match_use(atom IAtom, cpvIter []IPkgStr) []IPkgStr
	Repoman_iuse_implicit_cnstr(pkg, metadata map[string]string) func(flag string) bool
	Iuse_implicit_cnstr(pkg IPkgStr, metadata map[string]string) func(string) bool
	Match_use(atom IAtom, pkg IPkgStr, metadata map[string]string, ignore_profile bool) bool
	Invalidentry(mypath string)
	Update_ents(updates map[string][][]IAtom, onProgress, onUpdate func(int, int))
	Move_slot_ent(mylist []IAtom, repo_match func(string) bool) int
}

type IVarDbApi interface {
	IDbApi
}

type IPortDbApi interface {
	IDbApi
	GetFetchMap(mypkg string, useflags []string, mytree string) []string
}

type IVarTree interface {
	Get_all_provides() map[string][]IPkgStr
}

type IPortTree interface {
}
