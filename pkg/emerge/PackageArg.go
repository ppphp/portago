package emerge

import (
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/emerge/structs"
	"github.com/ppphp/portago/pkg/sets"
)

type PackageArg struct {
	*DependencyArg

	atom *dep.Atom
	pset *sets.InternalPackageSet
}

// nil
func NewPackageArg(packagee=None, arg string, root_config *RootConfig, **kwargs)*PackaeArg {
	p := &PackageArg{}
	p.DependencyArg = NewDependencyArg(arg, false, false, true, root_config,**kwargs)
	p.packagee = packagee
	atom := "=" + packagee.cpv
	if packagee.repo != structs.Package.UNKNOWN_REPO {
		atom += _repo_separator + packagee.repo
	}
	allow_repo := true
	p.atom, _ = dep.NewAtom(atom, nil, false, &allow_repo, nil, "", nil, nil)
	p.pset = sets.NewInternalPackageSet([]*dep.Atom{p.atom,}, true, true)
	return p
}
