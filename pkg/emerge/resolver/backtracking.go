package resolver

type BacktrackParameter struct {
	circular_dependency,
	needed_unstable_keywords,
	runtime_pkg_mask,
	needed_use_config_changes,
	needed_license_changes,
	prune_rebuilds,
	rebuild_list,
	reinstall_list,
	needed_p_mask_changes,
	slot_operator_mask_built,
	slot_operator_replace_installed,
}

func NewBacktrackParameter() *BacktrackParameter {
	b := &BacktrackParameter{}
	b.circular_dependency =
	{
	}
	b.needed_unstable_keywords = set()
	b.needed_p_mask_changes = set()
	b.runtime_pkg_mask =
	{
	}
	b.needed_use_config_changes =
	{
	}
	b.needed_license_changes =
	{
	}
	b.rebuild_list = set()
	b.reinstall_list = set()
	b.slot_operator_replace_installed = set()
	b.slot_operator_mask_built = set()
	b.prune_rebuilds = false
	return b
}

func (b*BacktrackParameter) __deepcopy__(memo=None) {
	if memo is
	None{
		memo =
	{}
	}
	result = BacktrackParameter()
	memo[id(b)] = result

	result.circular_dependency = copy.copy(b.circular_dependency)
	result.needed_unstable_keywords = copy.copy(b.needed_unstable_keywords)
	result.needed_p_mask_changes = copy.copy(b.needed_p_mask_changes)
	result.needed_use_config_changes = copy.copy(b.needed_use_config_changes)
	result.needed_license_changes = copy.copy(b.needed_license_changes)
	result.rebuild_list = copy.copy(b.rebuild_list)
	result.reinstall_list = copy.copy(b.reinstall_list)
	result.slot_operator_replace_installed = copy.copy(
		b.slot_operator_replace_installed
	)
	result.slot_operator_mask_built = b.slot_operator_mask_built.copy()
	result.prune_rebuilds = b.prune_rebuilds

	result.runtime_pkg_mask =
	{
	}
	for k, v
	in
	b.runtime_pkg_mask.items() {
		result.runtime_pkg_mask[k] = copy.copy(v)
	}

	return result
}

func  (b*BacktrackParameter) __eq__( other*BacktrackParameter) bool {
	return 	b.circular_dependency == other.circular_dependency&&
	b.needed_unstable_keywords == other.needed_unstable_keywords&&
	b.needed_p_mask_changes == other.needed_p_mask_changes&&
	b.runtime_pkg_mask == other.runtime_pkg_mask&&
	b.needed_use_config_changes == other.needed_use_config_changes&&
	b.needed_license_changes == other.needed_license_changes&&
	b.rebuild_list == other.rebuild_list&&
	b.reinstall_list == other.reinstall_list&&
	b.slot_operator_replace_installed== other.slot_operator_replace_installed&&
	b.slot_operator_mask_built == other.slot_operator_mask_built&&
	b.prune_rebuilds == other.prune_rebuilds

}


type _BacktrackNode struct {
	parameter,
	depth,
	mask_steps,
	terminal,
}

// BacktrackParameter(), 0, 0, true
func New_BacktrackNode(parameter *BacktrackParameter, depth int, mask_steps int, terminal bool){
	b :=&_BacktrackNode{}
b.parameter = parameter
b.depth = depth
b.mask_steps = mask_steps
b.terminal = terminal
}

func (b*_BacktrackNode) __eq__(other *_BacktrackNode) bool{
	return b.parameter == other.parameter
}


type Backtracker struct {
	_max_depth,
	_unexplored_nodes,
	_current_node,
	_nodes,
	_root,
}

func NewBacktracker(max_depth) *Backtracker {
	b :=&Backtracker{}
	b._max_depth = max_depth
	b._unexplored_nodes = []x
b._current_node = None
b._nodes = []x

b._root = _BacktrackNode()
b._add(b._root)
return b
}

// true
func (b*Backtracker) _add(node, explore bool) {
	if not b._check_runtime_pkg_mask(node.parameter.runtime_pkg_mask) {
		return
	}

	if node.mask_steps <= b._max_depth && node not
	in
	b._nodes{
		if explore{
		b._unexplored_nodes.append(node)
	}
		b._nodes.append(node)
	}
}

func (b*Backtracker) get() {
	if b._unexplored_nodes {
		node = b._unexplored_nodes.pop()
		b._current_node = node
		return copy.deepcopy(node.parameter)
	}
	return None
}

func (b*Backtracker) __len__() {
	return len(b._unexplored_nodes)
}

func (b*Backtracker) _check_runtime_pkg_mask(runtime_pkg_mask)bool{

for pkg, mask_info in runtime_pkg_mask.items()
	{
		if ("missing dependency" in
		mask_info ||
			"slot_operator_mask_built"
		in
		mask_info
		){
		continue
	}

		entry_is_valid = False
		any_conflict_parents = False

		for ppkg, patom
			in
		runtime_pkg_mask[pkg].get("slot conflict", set()) {
			any_conflict_parents = True
			if ppkg not
			in
		runtime_pkg_mask{
			entry_is_valid = True
			break
		}
		}else {
		if not any_conflict_parents {
			entry_is_valid = True
		}
	}

		if not entry_is_valid {
			return False
		}
	}

		return True
	}

func (b*Backtracker) _feedback_slot_conflicts(conflicts_data) {
	b._feedback_slot_conflict(conflicts_data[0])
}

func (b*Backtracker) _feedback_slot_conflict( conflict_data) {
	for similar_pkgs
	in
conflict_data {
		new_node = copy.deepcopy(b._current_node)
		new_node.depth += 1
		new_node.mask_steps += 1
		new_node.terminal = False
		for pkg, parent_atoms
			in
		similar_pkgs {
			new_node.parameter.runtime_pkg_mask.setdefault(pkg,
			{
			})[]string{
				"slot conflict"
			} = parent_atoms
		}
		b._add(new_node)
	}
}

func (b*Backtracker) _feedback_missing_dep( dep){
new_node = copy.deepcopy(b._current_node)
new_node.depth += 1
new_node.mask_steps += 1
new_node.terminal = False

new_node.parameter.runtime_pkg_mask.setdefault(dep.parent, {})[
"missing dependency"
] = {(dep.parent, dep.root, dep.atom)}

b._add(new_node)
}

// true
func (b*Backtracker) _feedback_config( changes T, explore bool) {
	new_node = copy.deepcopy(b._current_node)
	new_node.depth += 1
	para = new_node.parameter

	for change, data
	in
	changes.items()
	{
		if change == "circular_dependency" {
			for pkg, circular_children
				in
			data.items() {
				para.circular_dependency.setdefault(pkg, set()).update(
					circular_children
				)
			}
		}else if
		change == "needed_unstable_keywords" {
			para.needed_unstable_keywords.update(data)
		}else if
		change == "needed_p_mask_changes" {
			para.needed_p_mask_changes.update(data)
		}else if
		change == "needed_license_changes" {
			for pkg, missing_licenses
				in
			data {
				para.needed_license_changes.setdefault(pkg, set()).update(
					missing_licenses
				)
			}
		}else if
		change == "needed_use_config_changes" {
			for pkg, (new_use, new_changes) in
			data{
				para.needed_use_config_changes[pkg] = (new_use, new_changes)
			}
		}else if
		change == "slot_conflict_abi" {
			new_node.terminal = False
		}else if
		change == "slot_operator_mask_built" {
			para.slot_operator_mask_built.update(data)
			for pkg, mask_reasons
				in
			data.items() {
				para.runtime_pkg_mask.setdefault(pkg,
				{
				}).update(mask_reasons)
			}
		}else if
		change == "slot_operator_replace_installed" {
			para.slot_operator_replace_installed.update(data)
		}else if
		change == "rebuild_list" {
			para.rebuild_list.update(data)
		}else if
		change == "reinstall_list" {
			para.reinstall_list.update(data)
		}else if
		change == "prune_rebuilds" {
			para.prune_rebuilds = true
			para.slot_operator_replace_installed.clear()
			for pkg
				in
			para.slot_operator_mask_built {
				runtime_masks = para.runtime_pkg_mask.get(pkg)
				if runtime_masks is
				None{
					continue
				}
				runtime_masks.pop("slot_operator_mask_built", None)
				if not runtime_masks {
					para.runtime_pkg_mask.pop(pkg)
				}
			}
			para.slot_operator_mask_built.clear()
		}
	}
	b._add(new_node, explore)
	b._current_node = new_node
}

func (b*Backtracker) feedback( infos) {
	assert(
		b._current_node
	is
	not
	None
	), "call feedback() only after get() was called"

	if "config" in
	infos{
		b._feedback_config(infos["config"], explore = (len(infos) == 1))
	}

	if "slot conflict" in
	infos{
		b._feedback_slot_conflicts(infos["slot conflict"])
	} else if "missing dependency" in
	infos{
		b._feedback_missing_dep(infos["missing dependency"])
	}
}

func (b*Backtracker) backtracked() bool{
	return len(b._nodes) > 1
}

func (b*Backtracker) get_best_run() {
	best_node = b._root
	for node
	in
	b._nodes {
		if node.terminal && node.depth > best_node.depth {
			best_node = node
		}
	}

	return copy.deepcopy(best_node.parameter)
}
