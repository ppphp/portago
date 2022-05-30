package util

type Digraph struct {
	nodes interface{}
	order []
}

func NewDigraph() *Digraph {
	d := &Digraph{}

	d.nodes =
	{
	}
	d.order = []
return d
}

// 0
func(d*Digraph) add(node, parent, priority=0) {
	if node not
	in
	d.nodes:
	d.nodes[node] = (
	{
	}, {
	}, node)
	d.order.append(node)

	if not parent:
	return

	if parent not
	in
	d.nodes:
	d.nodes[parent] = (
	{
	}, {
	}, parent)
	d.order.append(parent)

	priorities = d.nodes[node][1].get(parent)
	if priorities is
None:
	priorities = []
d.nodes[node][1][parent] = priorities
d.nodes[parent][0][node] = priorities

if not priorities
or
priorities[-1]
is
not
priority:
bisect.insort(priorities, priority)
}

func(d*Digraph) discard( node) {
try:
	d.remove(node)
	except
KeyError:
	pass
}

func(d*Digraph) remove( node) {

	if node not
	in
	d.nodes:
	raise
	KeyError(node)

	for parent
		in
	d.nodes[node][1]:
	del
	d.nodes[parent][0][node]
	for child
		in
	d.nodes[node][0]:
	del
	d.nodes[child][1][node]

	del
	d.nodes[node]
	d.order.remove(node)
}

func(d*Digraph) update( other) {
	for node
		in
	other.order:
	children, parents, node = other.nodes[node]
	if parents:
	for parent, priorities
		in
	parents.items():
	for priority
		in
	priorities:
	d.add(node, parent, priority = priority) else:
	d.add(node, None)
}

func(d*Digraph) clear() {
	d.nodes.clear()
	del
	d.order[:]
}

func(d*Digraph) difference_update( t) {
	if isinstance(t, (list, tuple)) or \
	not
	hasattr(t, "__contains__"):
	t = frozenset(t)
	order = []
for node
in
d.order:
if node not
in
t:
order.append(node)
continue
for parent
in
d.nodes[node][1]:
del
d.nodes[parent][0][node]
for child
in
d.nodes[node][0]:
del
d.nodes[child][1][node]
del
d.nodes[node]
d.order = order
}

func(d*Digraph) has_edge(child, parent) bool {
try:
	return child
	in
	d.nodes[parent][0]
	except
KeyError:
	return false
}

func(d*Digraph) remove_edge(child, parent) {

	for k
		in
	parent, child:
	if k not
	in
	d.nodes:
	raise
	KeyError(k)

	if child not
	in
	d.nodes[parent][0]:
	raise
	KeyError(child)
	if parent not
	in
	d.nodes[child][1]:
	raise
	KeyError(parent)

	del
	d.nodes[child][1][parent]
	del
	d.nodes[parent][0][child]
}

func(d*Digraph) __iter__() {
	return iter(d.order)
}

func(d*Digraph) contains(node) {
	return node
	in
	d.nodes
}

func(d*Digraph) get( key, default=None) {
	node_data = d.nodes.get(key, d)
	if node_data is
d:
	return default
return node_data[2]
}

func(d*Digraph) all_nodes() {
	return d.order[:]
}

func(d*Digraph) child_nodes(node, ignore_priority=None) {
	if ignore_priority is
None:
	return list(d.nodes[node][0])
	children = []
if hasattr(ignore_priority, '__call__'):
for child, priorities
in
d.nodes[node][0].items():
for priority
in
reversed(priorities):
if not ignore_priority(priority):
children.append(child)
break
else:
for child, priorities
in
d.nodes[node][0].items():
if ignore_priority < priorities[-1]:
children.append(child)
return children
}

func(d*Digraph) parent_nodes(node, ignore_priority=None) {
	if ignore_priority is
None:
	return list(d.nodes[node][1])
	parents = []
if hasattr(ignore_priority, '__call__'):
for parent, priorities
in
d.nodes[node][1].items():
for priority
in
reversed(priorities):
if not ignore_priority(priority):
parents.append(parent)
break
else:
for parent, priorities
in
d.nodes[node][1].items():
if ignore_priority < priorities[-1]:
parents.append(parent)
return parents
}

func(d*Digraph) leaf_nodes(ignore_priority=None) {

	leaf_nodes = []
if ignore_priority is
None:
for node
in
d.order:
if not d.nodes[node][0]:
leaf_nodes.append(node)
elif
hasattr(ignore_priority, '__call__'):
for node
in
d.order:
is_leaf_node = true
for child, priorities
in
d.nodes[node][0].items():
for priority
in
reversed(priorities):
if not ignore_priority(priority):
is_leaf_node = false
break
if not is_leaf_node:
break
if is_leaf_node:
leaf_nodes.append(node)
else:
for node
in
d.order:
is_leaf_node = true
for child, priorities
in
d.nodes[node][0].items():
if ignore_priority < priorities[-1]:
is_leaf_node = false
break
if is_leaf_node:
leaf_nodes.append(node)
return leaf_nodes
}

// nil
func(d*Digraph) root_nodes(ignore_priority=None) {

	root_nodes = []
if ignore_priority is
None:
for node
in
d.order:
if not d.nodes[node][1]:
root_nodes.append(node)
elif
hasattr(ignore_priority, '__call__'):
for node
in
d.order:
is_root_node = true
for parent, priorities
in
d.nodes[node][1].items():
for priority
in
reversed(priorities):
if not ignore_priority(priority):
is_root_node = false
break
if not is_root_node:
break
if is_root_node:
root_nodes.append(node)
else:
for node
in
d.order:
is_root_node = true
for parent, priorities
in
d.nodes[node][1].items():
if ignore_priority < priorities[-1]:
is_root_node = false
break
if is_root_node:
root_nodes.append(node)
return root_nodes
}

func(d*Digraph) __bool__() {
	return bool(d.nodes)
}

func(d*Digraph) is_empty() {
	return len(d.nodes) == 0
}

func(d*Digraph) clone() {
	clone := NewDigraph()
	clone.nodes =
	{
	}
	memo =
	{
	}
	for children, parents, node
		in
	d.nodes.values():
	children_clone =
	{
	}
	for child, priorities
		in
	children.items():
	priorities_clone = memo.get(id(priorities))
	if priorities_clone is
None:
	priorities_clone = priorities[:]
	memo[id(priorities)] = priorities_clone
	children_clone[child] = priorities_clone
	parents_clone =
	{
	}
	for parent, priorities
		in
	parents.items():
	priorities_clone = memo.get(id(priorities))
	if priorities_clone is
None:
	priorities_clone = priorities[:]
	memo[id(priorities)] = priorities_clone
	parents_clone[parent] = priorities_clone
	clone.nodes[node] = (children_clone, parents_clone, node)
	clone.order = d.order[:]
	return clone
}

func(d*Digraph) delnode( node) {
try:
	d.remove(node)
	except
KeyError:
	pass
}

func(d*Digraph) firstzero() {
	leaf_nodes = d.leaf_nodes()
	if leaf_nodes:
	return leaf_nodes[0]
	return None
}

func(d*Digraph) hasallzeros( ignore_priority=None) {
	return len(d.leaf_nodes(ignore_priority = ignore_priority)) == \
	len(d.order)

	func(d *Digraph) debug_print():
	def
	output(s):
	writemsg(s, noiselevel = -1)
	for node
		in
	d.nodes:
	output("%s " % (node, ))
	if d.nodes[node][0]:
	output("depends on\n")
	else:
	output("(no children)\n")
	for child, priorities
		in
	d.nodes[node][0].items():
	output("  %s (%s)\n"%(child, priorities[-1], ))
}

func(d*Digraph) bfs( start, ignore_priority=None) {
	if start not
	in
d:
	raise
	KeyError(start)

	queue, enqueued = deque([(None, start)]), set([start])
while queue:
parent, n = queue.popleft()
yield parent, n
new = set(d.child_nodes(n, ignore_priority)) - enqueued
enqueued |= new
queue.extend([(n, child) for child in new])
}

func(d*Digraph) shortest_path( start, end, ignore_priority=None) {
	if start not
	in
d:
	raise
	KeyError(start)
	elif
	end
	not
	in
d:
	raise
	KeyError(end)

	paths =
	{
	None:
[]
}
for parent, child
in
d.bfs(start, ignore_priority):
paths[child] = paths[parent] + [child]
if child == end:
return paths[child]
return None
}

func(d*Digraph) get_cycles( ignore_priority=None, max_length=None) {
	all_cycles = []
for node
in
d.nodes:
shortest_path = None
candidates = []
for child
in
d.child_nodes(node, ignore_priority):
path = d.shortest_path(child, node, ignore_priority)
if path is
None:
continue
if not shortest_path
or
len(shortest_path) >= len(path):
shortest_path = path
candidates.append(path)
if shortest_path and \
(not
max_length
or
len(shortest_path) <= max_length):
for path
in
candidates:
if len(path) == len(shortest_path):
all_cycles.append(path)
return all_cycles
}
