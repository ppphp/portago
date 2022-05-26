package emerge

type Task struct {
	hashKey   string
	hashValue string
}

func (t *Task) eq(task *Task) bool {
	return t.hashKey == task.hashKey
}

func (t *Task) ne(task *Task) bool {
	return t.hashKey != task.hashKey
}

func (t *Task) hash() string {
	return t.hashValue
}

func (t *Task) len() int {
	return len(t.hashKey)
}

func (t *Task) iter(key string) int {
	return len(t.hashKey)
}

func (t *Task) contains() int {
	return len(t.hashKey)
}

func (t *Task) str() int {
	return len(t.hashKey)
}

func (t *Task) repr() int {
	return len(t.hashKey)
}

func NewTask() *Task {
	t := &Task{}

	return t
}
