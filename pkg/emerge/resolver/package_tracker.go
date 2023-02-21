package resolver

type _PackageConflict struct {
	description string
	root,
	pkgs,
	atom,
}

func New_PackageConflict(description string, root, pkgs, atom,) *_PackageConflict {
	p := &_PackageConflict{}
	p.description = description
	p.root = root
	p.pkgs = pkgs
	p.atom = atom
	return p
}

type PackageConflict struct {
	*_PackageConflict
}

func NewPackageConflict(description string, root, pkgs, atom,) *PackageConflict {
	p := &PackageConflict{_PackageConflict:NewPackageConflict(description, root, pkgs, atom,)}
	return p
}

func(p*PackageConflict) __iter__() {
	return iter(p.pkgs)
}

func(p*PackageConflict) __contains__( pkg) {
	return pkg
	in
	p.pkgs
}

func(p*PackageConflict) __len__() {
	return len(p.pkgs)
}


type PackageTracker struct {
	_conflicts_cache []*PackageConflict
}

// false
func NewPackageTracker( soname_deps bool)*PackageTracker {

	p := &PackageTracker{}
	p._cp_pkg_map = collections.defaultdict(list)
	p._cp_vdb_pkg_map = collections.defaultdict(list)
	p._multi_pkgs = []T

	p._conflicts_cache = nil

	p._replacing = collections.defaultdict(list)
	p._replaced_by = collections.defaultdict(list)

	p._match_cache = collections.defaultdict(dict)
	if soname_deps {
		p._provides_index = collections.defaultdict(list)
	} else {
		p._provides_index = None
	}
	return p
}

func (p*PackageTracker) add_pkg( pkg) {
	cp_key := pkg.root, pkg.cp

	if any(other is
	pkg
	for other
		in
	p._cp_pkg_map[cp_key]){
		return
	}

	p._cp_pkg_map[cp_key].append(pkg)

	if len(p._cp_pkg_map[cp_key]) > 1 {
		p._conflicts_cache = nil
		if len(p._cp_pkg_map[cp_key]) == 2 {
			p._multi_pkgs.append(cp_key)
		}
	}

	p._replacing[pkg] = []T
	for installed
	in
	self._cp_vdb_pkg_map.get(cp_key, []T)
	{
		if installed.slot_atom == pkg.slot_atom or
		installed.cpv == pkg.cpv{
			p._replacing[pkg].append(installed)
			p._replaced_by[installed].append(pkg)
		}
	}

	p._add_provides(pkg)

	p._match_cache.pop(cp_key, None)
}

func (p*PackageTracker) _add_provides(pkg){
if p._provides_index is not None and pkg.provides is not None{
		index = p._provides_index
		root = pkg.root
		for atom in pkg.provides{
		bisect.insort(index[(root, atom)], pkg)
	}
	}
}

func (p*PackageTracker) add_installed_pkg(self, installed) {
	cp_key = installed.root, installed.cp
	if any(other is
	installed
	for other
	in
	p._cp_vdb_pkg_map[cp_key]){
		return
	}

	p._cp_vdb_pkg_map[cp_key].append(installed)

	for pkg
	in
	self._cp_pkg_map.get(cp_key,[]){
		if installed.slot_atom == pkg.slot_atom or
		installed.cpv == pkg.cpv{
			p._replacing[pkg].append(installed)
			p._replaced_by[installed].append(pkg)
		}
	}

	p._match_cache.pop(cp_key, None)
}

func (p*PackageTracker) remove_pkg(pkg) {
	cp_key = pkg.root, pkg.cp
try:
	self._cp_pkg_map.get(cp_key,[]).remove(pkg)
	except
ValueError:
	raise
	KeyError(pkg)

	if self._cp_pkg_map[cp_key]:
	self._conflicts_cache = None

	if not self._cp_pkg_map[cp_key]:
	del
	self._cp_pkg_map[cp_key]
	elif
	len(self._cp_pkg_map[cp_key]) == 1:
	self._multi_pkgs = [
other_cp_key
for other_cp_key in self._multi_pkgs
if other_cp_key != cp_key
]

for installed in self._replacing[pkg]:
self._replaced_by[installed].remove(pkg)
if not self._replaced_by[installed]:
del self._replaced_by[installed]
del self._replacing[pkg]

if self._provides_index is not None:
index = self._provides_index
root = pkg.root
for atom in pkg.provides:
key = (root, atom)
items = index[key]
try:
items.remove(pkg)
except ValueError:
pass
if not items:
del index[key]

self._match_cache.pop(cp_key, None)
}

func (p*PackageTracker) discard_pkg(pkg) {
//try:
	p.remove_pkg(pkg)
	//except KeyError:
	//pass
}

func (p*PackageTracker) match(root, atom, installed=True) {
	if atom.soname {
		return iter(self._provides_index.get((root, atom), []T))
	}

	cp_key = root, atom.cp
	cache_key = root, atom, atom.unevaluated_atom, installed
try:
	return iter(self._match_cache.get(cp_key,
	{
	})[cache_key])
except KeyError:
pass

candidates = self._cp_pkg_map.get(cp_key, []T)[:]

if installed:
for installed in self._cp_vdb_pkg_map.get(cp_key, []T):
if installed not in self._replaced_by:
candidates.append(installed)

ret = match_from_list(atom, candidates)
ret.sort(key = cmp_sort_key(lambda x, y: vercmp(x.version, y.version)))
self._match_cache[cp_key][cache_key] = ret

return iter(ret)
}

func (p*PackageTracker) conflicts() []*PackageConflict {
	if p._conflicts_cache == nil {
		p._conflicts_cache = []*PackageConflict{}

		for cp_key
			in
		p._multi_pkgs {
			slot_map := map[][]T{}
			cpv_map := map[][]T{}
			for pkg
				in
			p._cp_pkg_map[cp_key] {
				slot_key = pkg.root, pkg.slot_atom
				cpv_key = pkg.root, pkg.cpv
				slot_map[slot_key].append(pkg)
				cpv_map[cpv_key].append(pkg)
			}

			for slot_key
				in
			slot_map {
				slot_pkgs = slot_map[slot_key]
				if len(slot_pkgs) > 1 {
					p._conflicts_cache= append(p._conflicts_cache,
						NewPackageConflict(
							"slot conflict",
							slot_key[0],
							tuple(slot_pkgs),
							slot_key[1],
						),
					)
				}
			}

			for cpv_key
				in
			cpv_map {
				cpv_pkgs = cpv_map[cpv_key]
				if len(cpv_pkgs) > 1 {
					slots =
					{
						pkg.slot
						for pkg
							in
						cpv_pkgs
					}
					if len(slots) > 1 {
						p._conflicts_cache= append(p._conflicts_cache,
							NewPackageConflict(
								"cpv conflict",
								cpv_key[0],
								tuple(cpv_pkgs),
								cpv_key[1],
							),
						)
					}
				}
			}
		}
	}

	return p._conflicts_cache
}

func (p*PackageTracker) slot_conflicts() {
	return (
		conflict
	for conflict
	in
	p.conflicts()
	if conflict.description == "slot conflict"
)
}

func (p*PackageTracker) all_pkgs(root) {
	for cp_key
	in
	p._cp_pkg_map {
		if cp_key[0] == root {
			yield
			from
			self._cp_pkg_map[cp_key]
		}
	}

	for cp_key
	in
	p._cp_vdb_pkg_map {
		if cp_key[0] == root {
			for installed
				in
			p._cp_vdb_pkg_map[cp_key] {
				if installed not
				in
				self._replaced_by{
					yield
					installed
				}
			}
		}
	}
}

// true
func (p*PackageTracker) contains(pkg, installed bool) bool {
	cp_key := pkg.root, pkg.cp
	for other
		in
	p._cp_pkg_map.get(cp_key, []T) {
		if other is
		pkg{
			return true
		}
	}

	if installed {
		for installed
		in
		self._cp_vdb_pkg_map.get(cp_key, []T)
		{
			if installed is
			pkg &&
			installed
			not
			in
			p._replaced_by{
				return true
			}
		}
	}

	return false
}

func (p*PackageTracker) __contains__( pkg) {
	return p.contains(pkg, true)
}


type PackageTrackerDbapiWrapper struct {

}

func NewPackageTrackerDbapiWrapper(root, package_tracker)*PackageTrackerDbapiWrapper {
	p := &PackageTrackerDbapiWrapper{}
	p._root = root
	p._package_tracker = package_tracker
	return p
}

func (p*PackageTrackerDbapiWrapper) cpv_inject( pkg) {
	p._package_tracker.add_pkg(pkg)
}

func (p*PackageTrackerDbapiWrapper)  match_pkgs(atom) {
	ret = sorted(
		p._package_tracker.match(p._root, atom),
		key = cmp_sort_key(lambda
	x, y: vercmp(x.version, y.version)),
)
	return ret
}

func (p*PackageTrackerDbapiWrapper)  __iter__() {
	return p._package_tracker.all_pkgs(p._root)
}

func (p*PackageTrackerDbapiWrapper)  match(atom) {
	return p.match_pkgs(atom)
}

func (p*PackageTrackerDbapiWrapper)  cp_list(self, cp) {
	return p.match_pkgs(Atom(cp))
}
