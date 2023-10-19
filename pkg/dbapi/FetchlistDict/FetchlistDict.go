package FetchlistDict

import (
	"github.com/ppphp/portago/pkg/interfaces"
	"os"
	"path/filepath"
	"strings"
)

type FetchlistDict[T interfaces.ISettings] struct {
	pkgdir, cp, mytree string
	settings           T
	portdb             interfaces.IPortDbApi
}

func (f *FetchlistDict[T]) GetItem(pkg_key string) []string {
	return f.portdb.GetFetchMap(pkg_key, nil, f.mytree)

}

func (f *FetchlistDict[T]) __contains__(cpv interfaces.IPkgStr) bool {
	for _, i := range f.__iter__() {
		if cpv.String() == i.String() {
			return true
		}
	}
	return false
}

func (f *FetchlistDict[T]) __iter__() []interfaces.IPkgStr {
	return f.portdb.Cp_list(f.cp, 1, f.mytree)

}

func (f *FetchlistDict[T]) __len__() int {
	return len(f.portdb.Cp_list(f.cp, 1, f.mytree))

}

func (f *FetchlistDict[T]) keys() []interfaces.IPkgStr {
	return f.portdb.Cp_list(f.cp, 1, f.mytree)
}

func NewFetchlistDict[T interfaces.ISettings](pkgdir string, settings T, mydbapi interfaces.IPortDbApi) *FetchlistDict[T] {
	f := &FetchlistDict[T]{}
	f.pkgdir = pkgdir
	f.cp = filepath.Join(strings.Split(pkgdir, string(os.PathSeparator))[len(strings.Split(pkgdir, string(os.PathSeparator)))-2:]...)
	f.settings = settings
	f.mytree, _ = filepath.EvalSymlinks(filepath.Dir(filepath.Dir(pkgdir)))
	f.portdb = mydbapi

	return f
}
