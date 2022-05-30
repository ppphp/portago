package emerge

// slot object
type Dependency struct {
	// slot
	depth int
	collapsed_priority, priority *DepPriority
	atom,blocker,child,
	parent,onlydeps,root,want_update,
	collapsed_parent
}

func NewDependency()*Dependency {
	d := &Dependency{}
	SlotObject.__init__(d, **kwargs)
	if d.priority ==nil {
		d.priority = NewDepPriority(false)
	}
	if d.depth == 0 {
		d.depth = 0
	}
	if d.collapsed_parent == nil {
		d.collapsed_parent = d.parent
	}
	if d.collapsed_priority == nil {
		d.collapsed_priority = d.priority
	}
	return d
}
