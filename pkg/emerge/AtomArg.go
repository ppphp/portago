package emerge

import (
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/sets"
)

type AtomArg struct {
	*DependencyArg

	// slot
	atom *dep.Atom
	pset *sets.InternalPackageSet
}

// nil, "", false, false, true, nil
func NewAtomArg(atom *dep.Atom, arg string, force_reinstall bool, internal bool, reset_depth bool, root_config *RootConfig) *AtomArg {
	a := &AtomArg{}
	a.DependencyArg = NewDependencyArg(arg, force_reinstall, internal, reset_depth, root_config)
	a.atom = atom
	a.pset = sets.NewInternalPackageSet([]*dep.Atom{a.atom}, false, true)
	return a
}
