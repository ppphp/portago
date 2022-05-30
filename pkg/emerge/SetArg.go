package emerge

import "github.com/ppphp/portago/pkg/sets"

type SetArg struct {
	*DependencyArg

	// slot
	name string
	pset *sets.PackageSet
}

// nil, "", false, false, true, nil
func NewSetArg(pset *sets.PackageSet, arg string, force_reinstall, internal, reset_depth bool, root_config *RootConfig) *SetArg {
	s := &SetArg{}
	s.DependencyArg = NewDependencyArg(arg, force_reinstall, internal, reset_depth, root_config)
	s.pset = pset
	s.name = s.arg[len(sets.SETPREFIX):]
	return s
}
