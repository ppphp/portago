package dbapi

// DummyTree is useful in cases where alternative dbapi implementations (or wrappers that
// modify or extend behavior of existing dbapi implementations) are needed, since it allows
// these implementations to be exposed through an interface which is minimally compatible
// with the *tree classes.
type DummyTree struct {
	dbapi interface{}
}

// NewDummyTree creates a new instance of DummyTree with the given dbapi implementation.
func NewDummyTree(dbapi interface{}) *DummyTree {
	return &DummyTree{dbapi: dbapi}
}
