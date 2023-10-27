package resolver

import dep2 "github.com/ppphp/portage/pkg/dep"

type  circular_dependency_handler struct {
	MAX_AFFECTING_USE int
}

func NewCircular_dependency_handler ( depgraph, graph) *circular_dependency_handler{
	c := &circular_dependency_handler{}
	c.MAX_AFFECTING_USE = 10
	c.depgraph = depgraph
	c.graph = graph
	c.all_parent_atoms = depgraph._dynamic_config._parent_atoms

	if "--debug" in
	depgraph._frozen_config.myopts
	{
		writemsg_level(
			"\n\ncircular dependency graph:\n\n", level = logging.DEBUG, noiselevel = -1
		)
		c.debug_print()
	}

	c.cycles, c.shortest_cycle = c._find_cycles()
	c.large_cycle_count = len(c.cycles) > 3
	c.merge_list = c._prepare_reduced_merge_list()
	c.circular_dep_message = c._prepare_circular_dep_message()
	c.solutions, c.suggestions = c._find_suggestions()
	return c
}

func(c*circular_dependency_handler) _find_cycles() {
	shortest_cycle = None
	cycles = c.graph.get_cycles(
		ignore_priority = DepPrioritySatisfiedRange.ignore_medium_soft
	)
	for cycle
	in
cycles {
		if not shortest_cycle || len(cycle) < len(shortest_cycle)
		{
			shortest_cycle = cycle
		}
	}
	return cycles, shortest_cycle
}

func(c*circular_dependency_handler) _prepare_reduced_merge_list() {
	display_order = []T
	tempgraph = self.graph.copy()
	while
tempgraph{
	nodes = tempgraph.leaf_nodes()
	if not nodes{
	node = tempgraph.order[0]
}else{
	node = nodes[0]
}
	display_order.append(node)
	tempgraph.remove(node)
}
	return tuple(display_order)
}

func(c*circular_dependency_handler) _prepare_circular_dep_message() {
	if not c.shortest_cycle {
		return None
	}

	msg = []T
	indent = ""
	for pos, pkg
	in
	enumerate(c.shortest_cycle) {
		parent = c.shortest_cycle[pos-1]
		priorities = c.graph.nodes[parent][0][pkg]
		if pos > 0 {
			msg.append(indent + f
			"{pkg} ({priorities[-1]})")
		}else {
			msg.append(indent + f
			"{pkg} depends on")
		}
		indent += " "
	}

	pkg = c.shortest_cycle[0]
	parent = c.shortest_cycle[-1]
	priorities = c.graph.nodes[parent][0][pkg]
	msg.append(indent + f
	"{pkg} ({priorities[-1]})")

	return "\n".join(msg)
}

func(c*circular_dependency_handler) _get_use_mask_and_force(pkg) {
	return pkg.use.mask, pkg.use.force
}

func(c*circular_dependency_handler) _get_autounmask_changes(pkg) {
	needed_use_config_change = (
		c.depgraph._dynamic_config._needed_use_config_changes.get(pkg)
	)
	if needed_use_config_change is
	None{
		return frozenset()
	}

	use, changes = needed_use_config_change
	return frozenset(changes.keys())
}

func(c*circular_dependency_handler) _find_suggestions() {
	if !c.shortest_cycle {
		return None, None
	}

	suggestions = []T
	final_solutions =
	{
	}

	for pos, pkg
		in
	enumerate(c.shortest_cycle) {
		parent = c.shortest_cycle[pos-1]
		priorities = c.graph.nodes[parent][0][pkg]
		parent_atoms = c.all_parent_atoms.get(pkg)

		if priorities[-1].buildtime {
			dep = " ".join(parent._metadata[k]
			for k
				in
			Package._buildtime_keys)
		} else if
		priorities[-1].runtime {
			dep = parent._metadata["RDEPEND"]
		}

		for ppkg, atom
			in
		parent_atoms {
			if ppkg == parent {
				changed_parent = ppkg
				parent_atom = atom.unevaluated_atom
				break
			}
		}

		//try:
		affecting_use = extract_affecting_use(
			dep, parent_atom, eapi = parent.eapi
		)
		//except InvalidDependString:
		//if not parent.installed:
		//raise
		//affecting_use = set()

		usemask, useforce = c._get_use_mask_and_force(parent)
		autounmask_changes = c._get_autounmask_changes(parent)
		untouchable_flags = frozenset(chain(usemask, useforce, autounmask_changes))

		affecting_use.difference_update(untouchable_flags)

		required_use_flags = get_required_use_flags(
			parent._metadata.get("REQUIRED_USE", ""), eapi = parent.eapi
		)

		if affecting_use.intersection(required_use_flags) {
			total_flags = set()
			total_flags.update(affecting_use, required_use_flags)
			total_flags.difference_update(untouchable_flags)
			if len(total_flags) <= c.MAX_AFFECTING_USE {
				affecting_use = total_flags
			}
		}

		affecting_use = tuple(affecting_use)

		if not affecting_use {
			continue
		}

		if len(affecting_use) > c.MAX_AFFECTING_USE {
			current_use = self.depgraph._pkg_use_enabled(parent)
			affecting_use = tuple(
				flag
			for flag
				in
			affecting_use
			if flag in
			current_use
			)

			if len(affecting_use) > self.MAX_AFFECTING_USE {
				continue
			}
		}

		solutions = set()
		for use_state
			in
		product(
			("disabled", "enabled"), repeat = len(affecting_use)
		){
			current_use = set(self.depgraph._pkg_use_enabled(parent))
			for flag, state
				in
			zip(affecting_use, use_state) {
				if state == "enabled" {
					current_use.add(flag)
				} else {
					current_use.discard(flag)
				}
			}
			//try:
			reduced_dep = dep2.UseReduce(dep, uselist = current_use, flat = True)
			//except InvalidDependString:
			//if not parent.installed:
			//raise
			//reduced_dep = None

			if reduced_dep is
			not
			None && parent_atom
			not
			in
			reduced_dep{
				required_use = parent._metadata.get("REQUIRED_USE", "")

				if check_required_use(
				required_use,
				current_use,
				parent.iuse.is_valid_flag,
				eapi = parent.eapi,
			){
				use = self.depgraph._pkg_use_enabled(parent)
				solution = set()
				for flag, state
				in
				zip(affecting_use, use_state){
				if state == "enabled" and
				flag
				not
				in
				use{
				solution.add((flag, True))
			} else if
				state == "disabled"
				and
				flag
				in
				use{
				solution.add((flag, False))
			}
				solutions.add(frozenset(solution))
			}
			}
			}

			for solution
				in
			solutions {
				ignore_solution = False
				for other_solution
					in
				solutions {
					if solution is
					other_solution{
						continue
					}
					if solution.issuperset(other_solution) {
						ignore_solution = True
					}
				}
				if ignore_solution {
					continue
				}

				followup_change = False
				parent_parent_atoms = self.depgraph._dynamic_config._parent_atoms.get(
					changed_parent
				)
				for ppkg, atom
					in
				parent_parent_atoms {
					atom = atom.unevaluated_atom
					if not atom.use {
						continue
					}

					for flag, state
						in
					solution {
						if flag in
						atom.use.enabled
						or
						flag
						in
						atom.use.disabled
						{
							ignore_solution = True
							break
						}
					} else if atom.use.conditional {
						for flags
							in
						atom.use.conditional.values() {
							if flag in
							flags{
								followup_change = True
								break
							}
						}
					}

					if ignore_solution {
						break
					}
				}

				if ignore_solution {
					continue
				}

				changes = []T
				for flag, state
					in
				solution {
					if state {
						changes.append(colorize("red", "+"+flag))
					} else {
						changes.append(colorize("blue", "-"+flag))
					}
				}
				msg = f
				"- {parent.cpv} (Change USE: {' '.join(changes)})\n"
				if followup_change {
					msg +=
						" (This change might require USE changes on parent packages.)"

				}
				suggestions.append(msg)
				final_solutions.setdefault(pkg, set()).add(solution)
			}
		}
	}

	return final_solutions, suggestions
}

func(c*circular_dependency_handler) debug_print()
	{
		graph := c.graph.copy()
		for {
			root_nodes := graph.root_nodes(
				ignore_priority = DepPrioritySatisfiedRange.ignore_medium_soft
			)
			if len(root_nodes) == 0 {
				break
			}
			graph.difference_update(root_nodes)
		}

		graph.debug_print()
	}
