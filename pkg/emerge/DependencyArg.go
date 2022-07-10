package emerge

import (
	"fmt"
)

type DependencyArg struct {
	// slot
	arg                                    string
	root_config                            *RootConfig
	force_reinstall, internal, reset_depth bool
}

// "", false, false, true, nil
func NewDependencyArg(arg string, force_reinstall, internal,
	reset_depth bool, root_config *RootConfig) *DependencyArg {
	d := &DependencyArg{}
	d.arg = arg
	d.force_reinstall = force_reinstall
	d.internal = internal
	d.reset_depth = reset_depth
	d.root_config = root_config
	return d
}

func (d *DependencyArg) __eq__(other *DependencyArg) bool {
	return d.arg == other.arg && d.root_config.root == other.root_config.root
}

func (d *DependencyArg) __hash__() {
	//return hash((d.arg, d.root_config.root))
}

func (d *DependencyArg) __str__() string {
	return fmt.Sprintf("%s", d.arg)
}
