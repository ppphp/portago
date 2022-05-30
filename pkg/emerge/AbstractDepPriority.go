package emerge

type AbstractDepPriority struct {
	// slot
	buildtime                                                 bool
	buildtime_slot_op, runtime, runtime_post, runtime_slot_op string
}

func (a *AbstractDepPriority) __int__() int {
	return 0
}

func (a *AbstractDepPriority) __lt__(other DepPriorityInterface) bool {
	return a.__int__() < other.__int__()
}

func (a *AbstractDepPriority) __le__(other DepPriorityInterface) bool {
	return a.__int__() <= other.__int__()
}

func (a *AbstractDepPriority) __eq__(other DepPriorityInterface) bool {
	return a.__int__() == other.__int__()
}

func (a *AbstractDepPriority) __ne__(other DepPriorityInterface) bool {
	return a.__int__() != other.__int__()
}

func (a *AbstractDepPriority) __gt__(other DepPriorityInterface) bool {
	return a.__int__() > other.__int__()
}

func (a *AbstractDepPriority) __ge__(other DepPriorityInterface) bool {
	return a.__int__() >= other.__int__()
}

func (a *AbstractDepPriority) copy() DepPriorityInterface {
	b := *a
	return &b
}

func NewAbstractDepPriority() *AbstractDepPriority {
	a := &AbstractDepPriority{}
	return a
}
