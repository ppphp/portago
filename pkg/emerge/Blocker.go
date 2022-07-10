package emerge

import "github.com/ppphp/portago/pkg/emerge/structs"

type Blocker struct {
	*structs.Task

	//slot
	root,atom,cp,eapi,priority,satisfied string
}

__hash__ = Task.__hash__

func NewBlocker( **kwargs) *Blocker {
	b := &Blocker{}
	b.Task = structs.NewTask(**kwargs)
	b.cp = b.atom.cp
	b._hash_key = ("blocks", b.root, b.atom, b.eapi)
	b._hash_value = hash(b._hash_key)
	return b
}
