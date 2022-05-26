package interfaces

type IDbApi interface {
	categories() []string
	close_caches()
	cp_list(cp string, useCache int) []IPkgStr
	_cmp_cpv(cpv1, cpv2 IPkgStr) int
	_cpv_sort_ascending(cpv_list []IPkgStr)
	cpv_all() []IPkgStr
	AuxGet(myCpv IPkgStr, myList []string, myRepo string) []string
	auxUpdate(cpv string, metadataUpdates map[string]string)
	match(origdep IAtom, useCache int) []IPkgStr
	_iter_match(atom IAtom, cpvIter []IPkgStr) []IPkgStr
	_pkg_str(cpv IPkgStr, repo string) IPkgStr
	_iter_match_repo(atom IAtom, cpvIter []IPkgStr) []IPkgStr
	_iter_match_slot(atom IAtom, cpvIter []IPkgStr) []IPkgStr
	_iter_match_use(atom IAtom, cpvIter []IPkgStr) []IPkgStr
	_repoman_iuse_implicit_cnstr(pkg, metadata map[string]string) func(flag string) bool
	_iuse_implicit_cnstr(pkg IPkgStr, metadata map[string]string) func(string) bool
	_match_use(atom IAtom, pkg IPkgStr, metadata map[string]string, ignore_profile bool) bool
	invalidentry(mypath string)
	update_ents(updates map[string][][]IAtom, onProgress, onUpdate func(int, int))
	move_slot_ent(mylist []IAtom, repo_match func(string) bool) int
}
