package sets

import (
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/versions"
	"strings"
)

var OPERATIONS = []string{"merge", "unmerge"}

type PackageSet struct {
	_operations []string
	description string

	_loaded, _loading, world_candidate, _allow_wildcard, _allow_repo bool

	_atoms
	_atommap
	errors
	_nonatoms
}

// false, false
func NewPackageSet(allow_wildcard, allow_repo bool) *PackageSet {
	p := &PackageSet{}
	p._operations = []string{"merge"}
	p.description = "generic package set"

	p._atoms = set()
	p._atommap = ExtendedAtomDict(set)
	p._loaded = false
	p._loading = false
	p.errors = []T{}
p._nonatoms = set()
p.world_candidate = false
p._allow_wildcard = allow_wildcard
p._allow_repo = allow_repo
return p
}

func (p*PackageSet) __contains__(atom) bool {
	p._load()

	_, ok := p._atoms[atom]
	if ok {
		return  true
	}

	_, ok = p._nonatoms[atom]
	return ok
}

func (p*PackageSet) __iter__() {
	p._load()
	for x
		in
	p._atoms:
	yield
	x
	for x
		in
	p._nonatoms:
	yield
	x
}

func (p*PackageSet) __bool__() bool {
	p._load()
	return len(p._atoms) > 0 || len(p._nonatoms) > 0

}

func (p*PackageSet) supportsOperation(op string) bool {
	if ! myutil.Ins(OPERATIONS, op) {
		//raise ValueError(dep.op)
	}
	return myutil.Ins(p._operations, op)

}

func (p*PackageSet) _load() {
	if !(p._loaded || p._loading) {
		p._loading = true
		p.load()
		p._loaded = true
		p._loading = false
	}
}

func (p*PackageSet) getAtoms() {
	p._load()
	return p._atoms.copy()
}

func (p*PackageSet) getNonAtoms() {
	p._load()
	return p._nonatoms.copy()
}

func (p*PackageSet) _setAtoms( atoms) {
	p._atoms.clear()
	p._nonatoms.clear()
	for a
		in
	atoms:
	if not isinstance(a, dep.Atom):
	if isinstance(a, basestring):
	a = a.strip()
	if not a:
	continue
try:
	a = dep.Atom(a, allow_wildcard = true, allow_repo = true)
	except
InvalidAtom:
	p._nonatoms.add(a)
	continue
	if ! p._allow_wildcard && a.extended_syntax {
		//raise InvalidAtom("extended atom syntax not allowed here")
	}
	if ! p._allow_repo && a.repo {
		//raise InvalidAtom("repository specification not allowed here")
	}
	p._atoms.add(a)

	p._updateAtomMap(nil)
}

func (p*PackageSet) load() {
	//raise NotImplementedError()
}

func (p*PackageSet) containsCPV(versions.cpv) {
	p._load()
	for a
		in
	p._atoms:
	if match_from_list(a, [versions.cpv]):
	return true
	return false
}

func (p*PackageSet) getMetadata(key) {
	if hasattr(p, key.lower()):
	return getattr(p, key.lower())
	else:
	return ""
}

// nil
func (p*PackageSet) _updateAtomMap(atoms=None) {
	if not atoms:
	p._atommap.clear()
	atoms = p._atoms
	for a
		in
	atoms:
	p._atommap.setdefault(a.cp, set()).add(a)
}

// nil
func (p*PackageSet) FindAtomForPackage(pkg, modified_use []string) {
	if modified_use != nil && modified_use!= versions.pkg.use.enabled {
		pkg = pkg.copy()
	}
	pkg._metadata["USE"] = strings.Join(modified_use, " ")

	rev_transform :=
	{
	}
	for atom
		in
	p.iterAtomsForPackage(pkg):
	if atom.cp == pkg.cp:
	rev_transform[atom] = atom
	else:
	rev_transform
[Atom(atom.replace(atom.cp, pkg.cp, 1), allow_wildcard = true, allow_repo = true)] = atom
best_match = best_match_to_list(pkg, iter(rev_transform))
if best_match:
return rev_transform[best_match]
return nil
}

func (p*PackageSet) iterAtomsForPackage(pkg) {
	cpv_slot_list := []T{pkg}
cp := versions.CpvGetKey(pkg.cpv, "")
p._load()

atoms := p._atommap.get(cp)
if atoms {
	for atom
		in
	atoms {
		if match_from_list(atom, cpv_slot_list):
		yield
		atom
	}
}
}

type EditablePackageSet struct {
	*PackageSet
}

// false, false
func NewEditablePackageSet(allow_wildcard, allow_repo bool)*EditablePackageSet {
	p :=&EditablePackageSet{}
	p.PackageSet = NewPackageSet(allow_wildcard, allow_repo)
	return p
}

func(p*EditablePackageSet) update( atoms []*dep.Atom) {
	p._load()
	modified := false
	normal_atoms := []T{}
for _, a:= range atoms:
if not isinstance(a, Atom):
try:
a = Atom(a, allow_wildcard = true, allow_repo = true)
except
InvalidAtom:
modified = true
p._nonatoms.add(a)
continue
if not p._allow_wildcard
and
a.extended_syntax:
raise
InvalidAtom("extended atom syntax not allowed here")
if not p._allow_repo
and
a.repo:
raise
InvalidAtom("repository specification not allowed here")
normal_atoms.append(a)

if normal_atoms:
modified = true
p._atoms.update(normal_atoms)
p._updateAtomMap(atoms = normal_atoms)
if modified:
p.write()
}

func(p*EditablePackageSet) add( atom) {
	p.update([atom])
}

func(p*EditablePackageSet) replace(p, atoms) {
	p._setAtoms(atoms)
	p.write()
}

func(p*EditablePackageSet) remove(atom) {
	p._load()
	p._atoms.discard(atom)
	p._nonatoms.discard(atom)
	p._updateAtomMap()
	p.write()
}

func(p*EditablePackageSet) removePackageAtoms(versions.cp) {
	p._load()
	for a
		in
	list(p._atoms):
	if a.cp == versions.cp:
	p.remove(a)
	p.write()
}

func(p*EditablePackageSet) write() {
	//raise NotImplementedError()
}

type InternalPackageSet struct {
	*EditablePackageSet
}

// nil, false, true
func NewInternalPackageSet(initial_atoms []*dep.Atom, allow_wildcard, allow_repo bool)*InternalPackageSet {
	p := &InternalPackageSet{}
	p.EditablePackageSet = NewEditablePackageSet(allow_wildcard, allow_repo)
	if initial_atoms != nil {
		p.update(initial_atoms)
	}
}

func(p*InternalPackageSet) clear() {
	p._atoms.clear()
	p._updateAtomMap(nil)
}

func(p*InternalPackageSet) load() {
	//pass
}

func(p*InternalPackageSet) write() {
	//pass
}
