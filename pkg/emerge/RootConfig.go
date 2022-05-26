package emerge

import (
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/sets"
	"github.com/ppphp/portago/pkg/util"
)

type RootConfig struct {
	// slot
	Mtimedb   *util.MtimeDB
	root      string
	Settings  *ebuild.Config
	trees     *portage.Tree
	setconfig *sets.SetConfig
	sets      map[string]string

	pkg_tree_map, tree_pkg_map map[string]string
}

func NewRootConfig(settings *ebuild.Config, trees *portage.Tree, setconfig *sets.SetConfig) *RootConfig {
	r := &RootConfig{}
	r.pkg_tree_map = map[string]string{
		"ebuild":    "porttree",
		"binary":    "bintree",
		"installed": "vartree",
	}
	r.tree_pkg_map = map[string]string{
		"porttree": "ebuild",
		"bintree":  "binary",
		"vartree":  "installed",
	}
	r.trees = trees
	r.Settings = settings
	r.root = r.Settings.ValueDict["EROOT"]
	r.setconfig = setconfig
	if setconfig == nil {
		r.sets = map[string]string{}
	} else {
		r.sets = r.setconfig.getSets()
	}
	return r
}

func (r *RootConfig) Update(other *RootConfig) {
	r.Mtimedb = other.Mtimedb
	r.root = other.root
	r.Settings = other.Settings
	r.trees = other.trees
	r.setconfig = other.setconfig
	r.sets = other.sets
}
