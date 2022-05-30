package emerge

import (
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/sets"
	"github.com/ppphp/portago/pkg/util"
	"golang.org/x/net/html/atom"
)

var bad = output.NewCreateColorFunc("BAD")

type _dep_check_graph_interface struct {
	will_replace_child
	removal_action bool
	want_update_pkg
}

type _scheduler_graph_config struct{
	trees
	pkg_cache
	graph
	mergelist
}

func New_scheduler_graph_config(trees, pkg_cache, graph, mergelist) *_scheduler_graph_config{
	s := &_scheduler_graph_config{}
	s.trees = trees
	s.pkg_cache = pkg_cache
	s.graph = graph
	s.mergelist = mergelist
	return s
}

func _wildcard_set(atoms) {
	pkgs := sets.NewInternalPackageSet(nil, true, true)
	for x
	in
atoms {
	try:
		x = dep.NewAtom(x, allow_wildcard = true, allow_repo = false)
		except
		portage.exception.InvalidAtom:
		x = dep.NewAtom("*/"+x, allow_wildcard = true, allow_repo = false)
		pkgs.add(x)
	}
	return pkgs
}


type _frozen_depgraph_config struct{
	rebuild_if_new_rev,
	rebuild_if_new_ver,
	rebuild_if_unbuilt bool
	settings
	target_root
	myopts
	edebug
	spinner
	requested_depth
	_running_root
	pkgsettings
	trees
	_trees_orig
	roots
	_pkg_cache
	_highest_license_masked
	soname_deps_enabled
	_required_set_names
	excluded_pkgs
	reinstall_atoms
	usepkg_exclude
	useoldpkg_atoms
	rebuild_exclude
	rebuild_ignore
}

func New_frozen_depgraph_config(settings, trees, myopts, params, spinner)*_frozen_depgraph_config{
	f := &_frozen_depgraph_config{}

	f.settings = settings
	f.target_root = settings["EROOT"]
	f.myopts = myopts
	f.edebug = 0
	if settings.get("PORTAGE_DEBUG", "") == "1":
	f.edebug = 1
	f.spinner = spinner
	f.requested_depth = params.get("deep", 0)
	f._running_root = trees[trees._running_eroot]["root_config"]
	f.pkgsettings = {}
	f.trees = {}
	f._trees_orig = trees
	f.roots = {}
	f._pkg_cache = {}
	f._highest_license_masked = {}
		f.soname_deps_enabled = (
		"--usepkgonly" in myopts or "remove" in params
	) and params.get("ignore_soname_deps") != "y"
	dynamic_deps := "dynamic_deps" in params
	ignore_built_slot_operator_deps := (
		myopts.get("--ignore-built-slot-operator-deps", "n") == "y"
	)
	for myroot in trees:
	f.trees[myroot] = {}
		f.roots[myroot] = RootConfig(
		trees[myroot]["vartree"].settings,
		f.trees[myroot],
		trees[myroot]["root_config"].setconfig,
	)
	for tree in ("porttree", "bintree"):
	f.trees[myroot][tree] = trees[myroot][tree]
	f.trees[myroot]["vartree"] = FakeVartree(
		trees[myroot]["root_config"],
		pkg_cache=f._pkg_cache,
		pkg_root_config=f.roots[myroot],
		dynamic_deps=dynamic_deps,
		ignore_built_slot_operator_deps=ignore_built_slot_operator_deps,
		soname_deps=f.soname_deps_enabled,
)
	f.pkgsettings[myroot] = portage.config(
		clone=f.trees[myroot]["vartree"].settings
	)
	if f.soname_deps_enabled and "remove" not in params:
	f.trees[myroot]["bintree"] = DummyTree(
		DbapiProvidesIndex(trees[myroot]["bintree"].dbapi)
	)

	if params.get("ignore_world", false):
	f._required_set_names = set()
	else:
	f._required_set_names = {"world"}

	atoms = " ".join(myopts.get("--exclude", [])).split()
	f.excluded_pkgs = _wildcard_set(atoms)
	atoms = " ".join(myopts.get("--reinstall-atoms", [])).split()
	f.reinstall_atoms = _wildcard_set(atoms)
	atoms = " ".join(myopts.get("--usepkg-exclude", [])).split()
	f.usepkg_exclude = _wildcard_set(atoms)
	atoms = " ".join(myopts.get("--useoldpkg-atoms", [])).split()
	f.useoldpkg_atoms = _wildcard_set(atoms)
	atoms = " ".join(myopts.get("--rebuild-exclude", [])).split()
	f.rebuild_exclude = _wildcard_set(atoms)
	atoms = " ".join(myopts.get("--rebuild-ignore", [])).split()
	f.rebuild_ignore = _wildcard_set(atoms)

	f.rebuild_if_new_rev = "--rebuild-if-new-rev" in myopts
	f.rebuild_if_new_ver = "--rebuild-if-new-ver" in myopts
	f.rebuild_if_unbuilt = "--rebuild-if-unbuilt" in myopts
	return f
}



type _depgraph_sets struct {
	sets map[string]*sets.InternalPackageSet
	atoms *sets.InternalPackageSet
	atom_arg_map
}

func New_depgraph_sets() *_depgraph_sets{
d := &_depgraph_sets{}
	d.sets = map[string]*sets.InternalPackageSet{}
	d.sets["__non_set_args__"] = sets.NewInternalPackageSet(nil, false,true)
	d.atoms = sets.NewInternalPackageSet(nil, false,true)
	d.atom_arg_map = {}
	return d
}


type _rebuild_config struct {
	_graph *util.Digraph
	_frozen_config
	rebuild_list
	orig_rebuild_list
	reinstall_list
	rebuild_if_new_rev
	rebuild_if_new_ver
	rebuild_if_unbuilt
	rebuild bool
}
func New_rebuild_config(frozen_config, backtrack_parameters)*_rebuild_config {
	r := &_rebuild_config{}
	r._graph = util.NewDigraph()
	r._frozen_config = frozen_config
	r.rebuild_list = backtrack_parameters.rebuild_list.copy()
	r.orig_rebuild_list = r.rebuild_list.copy()
	r.reinstall_list = backtrack_parameters.reinstall_list.copy()
	r.rebuild_if_new_rev = frozen_config.rebuild_if_new_rev
	r.rebuild_if_new_ver = frozen_config.rebuild_if_new_ver
	r.rebuild_if_unbuilt = frozen_config.rebuild_if_unbuilt
	r.rebuild = r.rebuild_if_new_rev || r.rebuild_if_new_ver || r.rebuild_if_unbuilt
	return r
}

func (r*_rebuild_config) add( dep_pkg, dep) {
	parent := dep.collapsed_parent
	priority := dep.collapsed_priority
	rebuild_exclude := r._frozen_config.rebuild_exclude
	rebuild_ignore = r._frozen_config.rebuild_ignore
	if (
		r.rebuild
		and
	isinstance(parent, Package)
	and
	parent.built
	and
	priority.buildtime
	and
	isinstance(dep_pkg, Package)
	and
	not
	rebuild_exclude.findAtomForPackage(parent)
	and
	not
	rebuild_ignore.findAtomForPackage(dep_pkg)
	):
	r._graph.add(dep_pkg, parent, priority)
}

func (r*_rebuild_config) _needs_rebuild( dep_pkg) {
	dep_root_slot = (dep_pkg.root, dep_pkg.slot_atom)
	if dep_pkg.built or
	dep_root_slot
	in
	r.orig_rebuild_list:
	return false

	if r.rebuild_if_unbuilt:
	return true

	trees = r._frozen_config.trees
	vardb = trees[dep_pkg.root]["vartree"].dbapi
	if r.rebuild_if_new_rev:
	return dep_pkg.cpv
	not
	in
	vardb.match(dep_pkg.slot_atom)

	assert
	r.rebuild_if_new_ver
	cpv_norev = catpkgsplit(dep_pkg.cpv)[:-1]
	for inst_cpv
	in
	vardb.match(dep_pkg.slot_atom):
	inst_cpv_norev = catpkgsplit(inst_cpv)[:-1]
	if inst_cpv_norev == cpv_norev:
	return false

	return true
}

func (r*_rebuild_config) _trigger_rebuild( parent, build_deps) {
	root_slot := (parent.root, parent.slot_atom)
	if root_slot in
	r.rebuild_list:
	return false
	trees = r._frozen_config.trees
	reinstall = false
	for slot_atom, dep_pkg
	in
	build_deps.items():
	dep_root_slot = (dep_pkg.root, slot_atom)
	if r._needs_rebuild(dep_pkg):
	r.rebuild_list.add(root_slot)
	return true
	if "--usepkg" in
	r._frozen_config.myopts
	and(
		dep_root_slot
	in
	r.reinstall_list
	or
	dep_root_slot
	in
	r.rebuild_list
	or
	not
	dep_pkg.installed
	):

	bintree = trees[parent.root]["bintree"]
	uri = bintree.get_pkgindex_uri(parent.cpv)
	dep_uri = bintree.get_pkgindex_uri(dep_pkg.cpv)
	bindb = bintree.dbapi
	if r.rebuild_if_new_ver and
	uri
	and
	uri != dep_uri:
	cpv_norev = catpkgsplit(dep_pkg.cpv)[:-1]
	for cpv
	in
	bindb.match(dep_pkg.slot_atom):
	if cpv_norev == catpkgsplit(cpv)[:-1]:
	dep_uri = bintree.get_pkgindex_uri(cpv)
	if uri == dep_uri:
	break
	if uri and
	uri != dep_uri:
	r.rebuild_list.add(root_slot)
	return true
	if parent.installed and
	root_slot
	not
	in
	r.reinstall_list:
try:
	(bin_build_time,) = bindb.aux_get(parent.cpv,["BUILD_TIME"])
	except
KeyError:
	continue
	if bin_build_time != str(parent.build_time):
	reinstall = true
	if reinstall:
	r.reinstall_list.add(root_slot)
	return reinstall
}

func (r*_rebuild_config) trigger_rebuilds() {
	need_restart := false
	graph := r._graph
	build_deps :=
	{
	}

	leaf_nodes := deque(graph.leaf_nodes())

	while
graph:
	if not leaf_nodes:
	leaf_nodes.append(graph.order[-1])

	node = leaf_nodes.popleft()
	if node not
	in
graph:
	continue
	slot_atom = node.slot_atom

	parents = graph.parent_nodes(node)
	graph.remove(node)
	node_build_deps = build_deps.get(node,
	{
	})
	for parent
	in
parents:
	if parent == node:
	continue
	parent_bdeps = build_deps.setdefault(parent,
	{
	})
	parent_bdeps[slot_atom] = node
	if not graph.child_nodes(parent):
	leaf_nodes.append(parent)

	if r._trigger_rebuild(node, node_build_deps):
	need_restart = true

	return need_restart
}


type _use_changes struct{}
(tuple):
def __new__(cls, new_use, new_changes, required_use_satisfied=true):
obj = tuple.__new__(cls, [new_use, new_changes])
obj.required_use_satisfied = required_use_satisfied
return obj


type _dynamic_depgraph_config struct{
	_need_restart,
	_need_config_reload,
	_skip_restart,
	_buildpkgonly_deps_unsatisfied,
	_quickpkg_direct_deps_unsatisfied,
	_displayed_autounmask,
	_success_without_autounmask,
	_autounmask_backtrack_disabled,
	_required_use_unsatisfied,
	_traverse_ignored_deps,
	_complete_mode,
	_vdb_loaded bool
	_blocker_uninstalls,
	_blocker_parents,
	_irrelevant_blockers,
	_unsolvable_blockers,
	digraph *util.Digraph
	myparams
	_allow_backtracking
	_reinstall_nodes
	sets
	_set_nodes
	_blocked_pkgs
	_blocked_world_pkgs
	_traversed_pkg_deps
	_parent_atoms
	_slot_conflict_handler
	_circular_dependency_handler
	_serialized_tasks_cache
	_scheduler_graph
	_displayed_list
	_pprovided_args
	_missing_args
	_masked_installed
	_masked_license_updates
	_unsatisfied_deps_for_display
	_unsatisfied_blockers_for_display
	_circular_deps_for_display
	_dep_stack
	_dep_disjunctive_stack
	_unsatisfied_deps
	_initially_unsatisfied_deps
	_ignored_deps
	_highest_pkg_cache
	_highest_pkg_cache_cp_map
	_flatten_atoms_cache
	_changed_deps_pkgs
	ignored_binaries
	_circular_dependency
	_needed_unstable_keywords
	_needed_p_mask_changes
	_needed_license_changes
	_needed_use_config_changes
	_runtime_pkg_mask
	_slot_operator_replace_installed
	_prune_rebuilds
	_backtrack_infos
	_autounmask
	_slot_operator_deps
	_installed_sonames
	_package_tracker
	_conflict_missed_update
}

func New_dynamic_depgraph_config(depgraph, myparams, allow_backtracking, backtrack_parameters) *_dynamic_depgraph_config {
	d := &_dynamic_depgraph_config{}
	d.myparams = myparams.copy()
	d._vdb_loaded = false
	d._allow_backtracking = allow_backtracking
	d._reinstall_nodes =
	{
	}
	d._filtered_trees =
	{
	}
	d._graph_trees =
	{
	}
	d._visible_pkgs =
	{
	}
	d._initial_arg_list = []T{}
	d.digraph = util.NewDigraph()
	d.sets =
	{
	}
	d._set_nodes = set()
	d._blocker_uninstalls = util.NewDigraph()
	d._blocker_parents = util.NewDigraph()
	d._irrelevant_blockers = util.NewDigraph()
	d._unsolvable_blockers = util.NewDigraph()
	d._blocked_pkgs = nil
	d._blocked_world_pkgs =
	{
	}
	d._traversed_pkg_deps = set()
	d._parent_atoms =
	{
	}
	d._slot_conflict_handler = nil
	d._circular_dependency_handler = nil
	d._serialized_tasks_cache = nil
	d._scheduler_graph = nil
	d._displayed_list = nil
	d._pprovided_args = []T{}
	d._missing_args = []T{}
	d._masked_installed = set()
	d._masked_license_updates = set()
	d._unsatisfied_deps_for_display = []T{}
	d._unsatisfied_blockers_for_display = nil
	d._circular_deps_for_display = nil
	d._dep_stack = []T{}
	d._dep_disjunctive_stack = []T{}
	d._unsatisfied_deps = []T{}
	d._initially_unsatisfied_deps = []T{}
	d._ignored_deps = []T{}
	d._highest_pkg_cache =
	{
	}
	d._highest_pkg_cache_cp_map =
	{
	}
	d._flatten_atoms_cache =
	{
	}
	d._changed_deps_pkgs =
	{
	}

	d.ignored_binaries =
	{
	}

	d._circular_dependency = backtrack_parameters.circular_dependency
	d._needed_unstable_keywords = backtrack_parameters.needed_unstable_keywords
	d._needed_p_mask_changes = backtrack_parameters.needed_p_mask_changes
	d._needed_license_changes = backtrack_parameters.needed_license_changes
	d._needed_use_config_changes = backtrack_parameters.needed_use_config_changes
	d._runtime_pkg_mask = backtrack_parameters.runtime_pkg_mask
	d._slot_operator_replace_installed = (
		backtrack_parameters.slot_operator_replace_installed
	)
	d._prune_rebuilds = backtrack_parameters.prune_rebuilds
	d._need_restart = false
	d._need_config_reload = false
	d._skip_restart = false
	d._backtrack_infos =
	{
	}

	d._buildpkgonly_deps_unsatisfied = false
	d._quickpkg_direct_deps_unsatisfied = false
	d._autounmask = d.myparams["autounmask"]
	d._displayed_autounmask = false
	d._success_without_autounmask = false
	d._autounmask_backtrack_disabled = false
	d._required_use_unsatisfied = false
	d._traverse_ignored_deps = false
	d._complete_mode = false
	d._slot_operator_deps =
	{
	}
	d._installed_sonames = collections.defaultdict(list)
	d._package_tracker = PackageTracker(
		soname_deps = depgraph._frozen_config.soname_deps_enabled
	)
	d._conflict_missed_update = collections.defaultdict(dict)
	dep_check_iface := _dep_check_graph_interface{
		will_replace_child: depgraph._will_replace_child,
		removal_action:     "remove" in myparams,
		want_update_pkg: depgraph._want_update_pkg,
	}

	for myroot
	in
	depgraph._frozen_config.trees:
	d.sets[myroot] = _depgraph_sets()
	vardb = depgraph._frozen_config.trees[myroot]["vartree"].dbapi
	fakedb = PackageTrackerDbapiWrapper(myroot, d._package_tracker)

	graph_tree := func() {
		//pass
	}

	graph_tree.dbapi = fakedb
	d._graph_trees[myroot] =
	{
	}
	d._filtered_trees[myroot] =
	{
	}
	d._graph_trees[myroot]["porttree"] = graph_tree
	d._graph_trees[myroot]["vartree"] = graph_tree
	d._graph_trees[myroot]["graph_db"] = graph_tree.dbapi
	d._graph_trees[myroot]["graph"] = d.digraph
	d._graph_trees[myroot]["graph_interface"] = dep_check_iface
	d._graph_trees[myroot]["downgrade_probe"] = depgraph._downgrade_probe

	filtered_tree := func() {
		//pass
	}

	filtered_tree.dbapi = _dep_check_composite_db(depgraph, myroot)
	d._filtered_trees[myroot]["porttree"] = filtered_tree
	d._visible_pkgs[myroot] = NewPackageVirtualDbapi(vardb.settings)

	d._filtered_trees[myroot]["graph_db"] = graph_tree.dbapi
	d._filtered_trees[myroot]["graph"] = d.digraph
	d._filtered_trees[myroot]["vartree"] = depgraph._frozen_config.trees[
		myroot
	]["vartree"]
	d._filtered_trees[myroot]["graph_interface"] = dep_check_iface
	d._filtered_trees[myroot]["downgrade_probe"] = depgraph._downgrade_probe

	dbs = []T{}
	if "remove" in
	d.myparams:
	d._graph_trees[myroot]["porttree"] = filtered_tree else:
	if "--usepkgonly" not
	in
	depgraph._frozen_config.myopts:
	portdb = depgraph._frozen_config.trees[myroot]["porttree"].dbapi
	db_keys = list(portdb._aux_cache_keys)
	dbs.append((portdb, "ebuild", false, false, db_keys))

	if "--usepkg" in
	depgraph._frozen_config.myopts:
	bindb = depgraph._frozen_config.trees[myroot]["bintree"].dbapi
	db_keys = list(bindb._aux_cache_keys)
	dbs.append((bindb, "binary", true, false, db_keys))

	vardb = depgraph._frozen_config.trees[myroot]["vartree"].dbapi
	db_keys = list(
		depgraph._frozen_config._trees_orig[myroot][
			"vartree"
		].dbapi._aux_cache_keys
	)
	dbs.append((vardb, "installed", true, true, db_keys))
	d._filtered_trees[myroot]["dbs"] = dbs
	return d
}


type depgraph struct{}

_UNREACHABLE_DEPTH = object()

pkg_tree_map = RootConfig.pkg_tree_map

// nil, BacktrackParameter(), false
func NewDepgraph(settings, trees, myopts, myparams, spinner, frozen_config=nil,
	backtrack_parameters=BacktrackParameter(),allow_backtracking bool, ) *depgraph {
	d := &depgraph{}
if frozen_config is nil:
frozen_config = _frozen_depgraph_config(
settings, trees, myopts, myparams, spinner
)
d._frozen_config = frozen_config
d._dynamic_config = _dynamic_depgraph_config(
d, myparams, allow_backtracking, backtrack_parameters
)
d._rebuild = _rebuild_config(frozen_config, backtrack_parameters)

d._select_atoms = d._select_atoms_highest_available
d._select_package = d._select_pkg_highest_available

d._event_loop = asyncio._safe_loop()

d._select_atoms_parent = nil

d.query = UserQuery(myopts).query
	return d
}


func (d*depgraph) _index_binpkgs() {
	for root
	in
	d._frozen_config.trees:
	bindb = d._frozen_config.trees[root]["bintree"].dbapi
	if bindb._provides_index:
	continue
	root_config = d._frozen_config.roots[root]
	for cpv
	in
	d._frozen_config._trees_orig[root]["bintree"].dbapi.cpv_all():
	bindb._provides_inject(d._pkg(cpv, "binary", root_config))
}

func (d*depgraph) _load_vdb() {

	if d._dynamic_config._vdb_loaded:
	return

	for myroot
	in
	d._frozen_config.trees:

	dynamic_deps = "dynamic_deps"
	in
	d._dynamic_config.myparams
	preload_installed_pkgs = "--nodeps"
	not
	in
	d._frozen_config.myopts

	fake_vartree = d._frozen_config.trees[myroot]["vartree"]
	if not fake_vartree.dbapi:
	fake_vartree.sync()

	d._frozen_config.pkgsettings[myroot] = portage.config(
		clone = fake_vartree.settings
	)

	if preload_installed_pkgs:
	vardb = fake_vartree.dbapi

	if not dynamic_deps:
	for pkg
	in
vardb:
	d._dynamic_config._package_tracker.add_installed_pkg(pkg)
	d._add_installed_sonames(pkg)
	else:
	max_jobs = d._frozen_config.myopts.get("--jobs")
	max_load = d._frozen_config.myopts.get("--load-average")
	scheduler = TaskScheduler(
		d._dynamic_deps_preload(fake_vartree),
		max_jobs = max_jobs,
		max_load = max_load,
		event_loop=fake_vartree._portdb._event_loop,
)
	scheduler.start()
	scheduler.wait()

	d._dynamic_config._vdb_loaded = true
}

func (d*depgraph) _dynamic_deps_preload( fake_vartree) {
	portdb = fake_vartree._portdb
	for pkg
	in
	fake_vartree.dbapi:
	d._spinner_update()
	d._dynamic_config._package_tracker.add_installed_pkg(pkg)
	d._add_installed_sonames(pkg)
	ebuild_path, repo_path = portdb.findname2(pkg.cpv, myrepo = pkg.repo)
	if ebuild_path is
nil:
	fake_vartree.dynamic_deps_preload(pkg, nil)
	continue
	metadata, ebuild_hash = portdb._pull_valid_cache(
		pkg.cpv, ebuild_path, repo_path
	)
	if metadata is
	not
nil:
	fake_vartree.dynamic_deps_preload(pkg, metadata)
	else:
	proc = EbuildMetadataPhase(
		cpv = pkg.cpv,
		ebuild_hash = ebuild_hash,
		portdb=portdb,
		repo_path = repo_path,
		settings=portdb.doebuild_settings,
)
	proc.addExitListener(d._dynamic_deps_proc_exit(pkg, fake_vartree))
	yield
	proc
}

type _dynamic_deps_proc_exit struct{
	// slot
	_pkg
	_fake_vartree
}

func New_dynamic_deps_proc_exit(pkg, fake_vartree) *_dynamic_deps_proc_exit {
	d := &_dynamic_deps_proc_exit{}
	d._pkg = pkg
	d._fake_vartree = fake_vartree
	return d
}

func (d*_dynamic_deps_proc_exit) __call__(proc) {
	metadata = nil
	if proc.returncode == os.EX_OK {
		metadata = proc.metadata
	}
	d._fake_vartree.dynamic_deps_preload(d._pkg, metadata)
}

func (d*depgraph) _spinner_update() {
	if d._frozen_config.spinner {
		d._frozen_config.spinner.update()
	}
}

func (d*depgraph) _compute_abi_rebuild_info() {

	debug = "--debug"
	in
	d._frozen_config.myopts
	installed_sonames = d._dynamic_config._installed_sonames
	package_tracker = d._dynamic_config._package_tracker

	atoms =
	{
	}
	for s
	in
	d._dynamic_config._initial_arg_list:
	if s.force_reinstall:
	root = s.root_config.root
	atoms.setdefault(root, set()).update(s.pset)

	if debug:
	writemsg_level(
		"forced reinstall atoms:\n", level = logging.DEBUG, noiselevel = -1
	)

	for root
	in
atoms:
	writemsg_level(
		"   root: %s\n"%root, level = logging.DEBUG, noiselevel = -1
	)
	for atom
	in
	atoms[root]:
	writemsg_level(
		"      atom: %s\n"%atom, level = logging.DEBUG, noiselevel = -1
	)
	writemsg_level("\n\n", level = logging.DEBUG, noiselevel = -1)

	forced_rebuilds =
	{
	}

	for root, rebuild_atoms
	in
	atoms.items():

	for slot_atom
	in
rebuild_atoms:

	inst_pkg, reinst_pkg = d._select_pkg_from_installed(root, slot_atom)

	if inst_pkg is
	reinst_pkg
	or
	reinst_pkg
	is
nil:
	continue

	if inst_pkg is
	not
	nil
	and
	inst_pkg.requires
	is
	not
nil:
	for atom
	in
	inst_pkg.requires:
	initial_providers = installed_sonames.get((root, atom))
	if initial_providers is
nil:
	continue
	final_provider = next(package_tracker.match(root, atom), nil)
	if final_provider:
	continue
	for provider
	in
initial_providers:
	child = next(
		(
			pkg
	for pkg
	in
	package_tracker.match(
		root, provider.slot_atom
	)
	if not pkg.installed
	),
	nil,
)

	if child is
nil:
	continue

	forced_rebuilds.setdefault(root,
	{
	}).setdefault(
		child, set()
	).add(inst_pkg)

	built_slot_op_atoms = []
if inst_pkg is not nil:
selected_atoms = d._select_atoms_probe(inst_pkg.root, inst_pkg)
for atom in selected_atoms:
if atom.slot_operator_built:
built_slot_op_atoms.append(atom)

if not built_slot_op_atoms:
continue

deps = d._dynamic_config._slot_operator_deps.get(
(root, slot_atom), []
)[:]

if built_slot_op_atoms and reinst_pkg is not nil:
for child in d._dynamic_config.digraph.child_nodes(reinst_pkg):

if child.installed:
continue

for atom in built_slot_op_atoms:
if atom.cp != child.cp:
continue
if atom.slot and atom.slot != child.slot:
continue
deps.append(
Dependency(
atom = atom,
child =child,
root = child.root,
parent =reinst_pkg,
)
)

for dep in deps:
if dep.child.installed:
child = next(
(
pkg
for pkg in d._dynamic_config._package_tracker.match(
dep.root, dep.child.slot_atom
)
if not pkg.installed
),
nil,
)

if child is nil:
continue

inst_child = dep.child else:
child = dep.child
inst_child = d._select_pkg_from_installed(
child.root, child.slot_atom
)[0]

if (
inst_child
and inst_child.slot == child.slot
and inst_child.sub_slot == child.sub_slot
):
continue

if dep.parent.installed:
parent = next(
(
pkg
for pkg in d._dynamic_config._package_tracker.match(
dep.parent.root, dep.parent.slot_atom
)
if not pkg.installed
),
nil,
)

if parent is nil:
continue else:
parent = dep.parent

forced_rebuilds.setdefault(root, {}).setdefault(child, set()).add(
parent
)

if debug:
writemsg_level(
"slot operator dependencies:\n", level = logging.DEBUG, noiselevel = -1
)

for (
root,
slot_atom,
), deps in d._dynamic_config._slot_operator_deps.items():
writemsg_level(
"   (%s, %s)\n" % (root, slot_atom),
level = logging.DEBUG,
noiselevel = -1,
)
for dep in deps:
writemsg_level(
"      parent: %s\n" % dep.parent,
level = logging.DEBUG,
noiselevel= -1,
)
writemsg_level(
"        child: %s (%s)\n" % (dep.child, dep.priority),
level = logging.DEBUG,
noiselevel = -1,
)

writemsg_level("\n\n", level = logging.DEBUG, noiselevel = -1)

writemsg_level("forced rebuilds:\n", level = logging.DEBUG, noiselevel= -1)

for root in forced_rebuilds:
writemsg_level(
"   root: %s\n" % root, level = logging.DEBUG, noiselevel = -1
)
for child in forced_rebuilds[root]:
writemsg_level(
"      child: %s\n" % child, level = logging.DEBUG, noiselevel= -1
)
for parent in forced_rebuilds[root][child]:
writemsg_level(
"         parent: %s\n" % parent,
level = logging.DEBUG,
noiselevel= -1,
)
writemsg_level("\n\n", level = logging.DEBUG, noiselevel = -1)

d._forced_rebuilds = forced_rebuilds
}

func (d*depgraph) _show_abi_rebuild_info() {

	if not d._forced_rebuilds:
	return

	writemsg_stdout(
		"\nThe following packages are causing rebuilds:\n\n", noiselevel = -1
	)

	for root
	in
	d._forced_rebuilds:
	for child
	in
	d._forced_rebuilds[root]:
	writemsg_stdout("  %s causes rebuilds for:\n" % (child, ), noiselevel = -1)
	for parent
	in
	d._forced_rebuilds[root][child]:
	writemsg_stdout("    %s\n" % (parent, ), noiselevel = -1)
}

func (d*depgraph) _eliminate_ignored_binaries() {
	for pkg
	in
	list(d._dynamic_config.ignored_binaries):

	for selected_pkg
	in
	d._dynamic_config._package_tracker.match(
		pkg.root, pkg.slot_atom
	):

	if selected_pkg > pkg:
	d._dynamic_config.ignored_binaries.pop(pkg)
	break

	if selected_pkg.type_name == "binary" and
	selected_pkg >= pkg:
	d._dynamic_config.ignored_binaries.pop(pkg)
	break

	if (
		selected_pkg.installed
		and
	selected_pkg.cpv == pkg.cpv
	and
	selected_pkg.build_time == pkg.build_time
	):
	d._dynamic_config.ignored_binaries.pop(pkg)
	break
}

func (d*depgraph) _ignored_binaries_autounmask_backtrack() {
	if not all(
	[
		d._dynamic_config._allow_backtracking,
	d._dynamic_config._needed_use_config_changes,
		d._dynamic_config.ignored_binaries,
]
):
return false

d._eliminate_ignored_binaries()

if not d._dynamic_config.ignored_binaries:
return false

use_changes = collections.defaultdict(
functools.partial(collections.defaultdict, dict)
)
for pkg, (
new_use,
changes,
) in d._dynamic_config._needed_use_config_changes.items():
if pkg in d._dynamic_config.digraph:
use_changes[pkg.root][pkg.slot_atom] = (pkg, new_use)

for pkg in d._dynamic_config.ignored_binaries:
selected_pkg, new_use = use_changes[pkg.root].get(
pkg.slot_atom, (nil, nil)
)
if new_use is nil:
continue

if new_use != pkg.use.enabled:
continue

if selected_pkg > pkg:
continue

return true

return false
}

func (d*depgraph) _changed_deps_report() {
	if (
		d._dynamic_config.myparams.get("changed_deps", "n") == "y"
		or
	"dynamic_deps"
	in
	d._dynamic_config.myparams
	):
	return

	report_pkgs = []
for pkg, ebuild in d._dynamic_config._changed_deps_pkgs.items():
if pkg.repo != ebuild.repo:
continue
report_pkgs.append((pkg, ebuild))

if not report_pkgs:
return

graph = d._dynamic_config.digraph
in_graph = false
for pkg, ebuild in report_pkgs:
if pkg in graph:
in_graph = true
break

if not in_graph:
return

writemsg(
"\n%s\n\n"
% colorize(
"WARN",
"!!! Detected ebuild dependency change(s) without revision bump:",
),
noiselevel = -1,
)

for pkg, ebuild in report_pkgs:
writemsg("    %s::%s" % (pkg.cpv, pkg.repo), noiselevel = -1)
if pkg.root_config.settings["ROOT"] != "/":
writemsg(" for %s" % (pkg.root, ), noiselevel = -1)
writemsg("\n", noiselevel = -1)

msg = []
if "--quiet" not in d._frozen_config.myopts:
msg.extend(
[
"",
"NOTE: Refer to the following page for more information about dependency",
"      change(s) without revision bump:",
"",
"          https://wiki.gentoo.org/wiki/Project:Portage/Changed_Deps",
"",
"      In order to suppress reports about dependency changes, add",
"      --changed-deps-report=n to the EMERGE_DEFAULT_OPTS variable in",
"      '/etc/portage/make.conf'.",
]
)

msg.extend(
[
"",
"HINT: In order to avoid problems involving changed dependencies, use the",
"      --changed-deps option to automatically trigger rebuilds when changed",
"      dependencies are detected. Refer to the emerge man page for more",
"      information about this option.",
]
)

for line in msg:
if line:
line = colorize("INFORM", line)
writemsg(line + "\n", noiselevel = -1)
}

func (d*depgraph) _show_ignored_binaries() {
	if (
		not d._dynamic_config.ignored_binaries
	or
	"--quiet"
	in
	d._frozen_config.myopts
	):
	return

	d._eliminate_ignored_binaries()

	ignored_binaries =
	{
	}

	for pkg
		in
	d._dynamic_config.ignored_binaries:
	for reason, info
		in
	d._dynamic_config.ignored_binaries[pkg].items():
	ignored_binaries.setdefault(reason,
	{
	})[pkg] = info

if d._dynamic_config.myparams.get("binpkg_respect_use") in ("y", "n"):
ignored_binaries.pop("respect_use", nil)

if d._dynamic_config.myparams.get("binpkg_changed_deps") in ("y", "n"):
ignored_binaries.pop("changed_deps", nil)

if not ignored_binaries:
return

d._show_merge_list()

if "respect_use" in ignored_binaries:
d._show_ignored_binaries_respect_use(ignored_binaries["respect_use"])

if "changed_deps" in ignored_binaries:
d._show_ignored_binaries_changed_deps(ignored_binaries["changed_deps"])
}

func (d*depgraph) _show_ignored_binaries_respect_use(respect_use){

writemsg(
"\n!!! The following binary packages have been ignored "
+ "due to non matching USE:\n\n",
noiselevel = -1,
)

for pkg, flags in respect_use.items():
flag_display = []
for flag in sorted(flags):
if flag not in pkg.use.enabled:
flag = "-" + flag
flag_display.append(flag)
flag_display = " ".join(flag_display)
writemsg("    =%s %s" % (pkg.cpv, flag_display), noiselevel = -1)
if pkg.root_config.settings["ROOT"] != "/":
writemsg(" # for %s" % (pkg.root, ), noiselevel = -1)
writemsg("\n", noiselevel = -1)

msg = [
"",
"NOTE: The --binpkg-respect-use=n option will prevent emerge",
"      from ignoring these binary packages if possible.",
"      Using --binpkg-respect-use=y will silence this warning.",
]

for line in msg:
if line:
line = colorize("INFORM", line)
writemsg(line + "\n", noiselevel = -1)
}

func (d*depgraph) _show_ignored_binaries_changed_deps( changed_deps) {

	writemsg(
		"\n!!! The following binary packages have been "
	"ignored due to changed dependencies:\n\n",
		noiselevel = -1,
)

	for pkg
		in
	changed_deps:
	msg = "     %s%s%s" % (pkg.cpv, _repo_separator, pkg.repo)
	if pkg.root_config.settings["ROOT"] != "/":
	msg += " for %s" % pkg.root
	writemsg("%s\n"%msg, noiselevel = -1)

	msg = [
"",
"NOTE: The --binpkg-changed-deps=n option will prevent emerge",
"      from ignoring these binary packages if possible.",
"      Using --binpkg-changed-deps=y will silence this warning.",
]

for line in msg:
if line:
line = colorize("INFORM", line)
writemsg(line + "\n", noiselevel = -1)
}

func (d*depgraph) _get_missed_updates(){

missed_updates = {}
for pkg, mask_reasons in chain(
d._dynamic_config._runtime_pkg_mask.items(),
d._dynamic_config._conflict_missed_update.items(),
):
if pkg.installed:
continue
missed_update = true
any_selected = false
for chosen_pkg in d._dynamic_config._package_tracker.match(
pkg.root, pkg.slot_atom
):
any_selected = true
if chosen_pkg > pkg or (
not chosen_pkg.installed and chosen_pkg.version == pkg.version
):
missed_update = false
break
if any_selected and missed_update:
k = (pkg.root, pkg.slot_atom)
if k in missed_updates:
other_pkg, mask_type, parent_atoms = missed_updates[k]
if other_pkg > pkg:
continue
for mask_type, parent_atoms in mask_reasons.items():
if not parent_atoms:
continue
missed_updates[k] = (pkg, mask_type, parent_atoms)
break

return missed_updates

}

func (d*depgraph) _show_missed_update() {

	missed_updates = d._get_missed_updates()

	if not missed_updates:
	return

	missed_update_types =
	{
	}
	for pkg, mask_type, parent_atoms
	in
	missed_updates.values():
	missed_update_types.setdefault(mask_type,[]).append((pkg, parent_atoms))

	if (
		"--quiet" in
	d._frozen_config.myopts
	and
	"--debug"
	not
	in
	d._frozen_config.myopts
	):
	missed_update_types.pop("slot conflict", nil)
	missed_update_types.pop("missing dependency", nil)

	d._show_missed_update_slot_conflicts(
		missed_update_types.get("slot conflict")
	)

	d._show_missed_update_unsatisfied_dep(
		missed_update_types.get("missing dependency")
	)
}

func (d*depgraph) _show_missed_update_unsatisfied_dep( missed_updates) {

	if not missed_updates:
	return

	d._show_merge_list()
	backtrack_masked = []

for pkg, parent_atoms in missed_updates:

try:
for parent, root, atom in parent_atoms:
d._show_unsatisfied_dep(
root, atom, myparent =parent, check_backtrack = true
)
except d._backtrack_mask:
backtrack_masked.append((pkg, parent_atoms))
continue

writemsg(
"\n!!! The following update has been skipped "
+ "due to unsatisfied dependencies:\n\n",
noiselevel = -1,
)

writemsg(str(pkg.slot_atom), noiselevel= -1)
if pkg.root_config.settings["ROOT"] != "/":
writemsg(" for %s" % (pkg.root, ), noiselevel =-1)
writemsg("\n\n", noiselevel =-1)

selected_pkg = next(
d._dynamic_config._package_tracker.match(pkg.root, pkg.slot_atom),
nil,
)

writemsg("  selected: %s\n" % (selected_pkg, ), noiselevel =-1)
writemsg(
"  skipped: %s (see unsatisfied dependency below)\n" % (pkg, ),
noiselevel = -1,
)

for parent, root, atom in parent_atoms:
d._show_unsatisfied_dep(root, atom, myparent = parent)
writemsg("\n", noiselevel = -1)

if backtrack_masked:
writemsg(
"\n!!! The following update(s) have been skipped "
+ "due to unsatisfied dependencies\n"
+ "!!! triggered by backtracking:\n\n",
noiselevel = -1,
)
for pkg, parent_atoms in backtrack_masked:
writemsg(str(pkg.slot_atom), noiselevel =-1)
if pkg.root_config.settings["ROOT"] != "/":
writemsg(" for %s" % (pkg.root, ), noiselevel = -1)
writemsg("\n", noiselevel = -1)
}

func (d*depgraph) _show_missed_update_slot_conflicts( missed_updates) {

	if not missed_updates:
	return

	d._show_merge_list()
	msg = [
"\nWARNING: One or more updates/rebuilds have been "
"skipped due to a dependency conflict:\n\n"
]

indent = "  "
for pkg, parent_atoms in missed_updates:
msg.append(str(pkg.slot_atom))
if pkg.root_config.settings["ROOT"] != "/":
msg.append(" for %s" % (pkg.root, ))
msg.append("\n\n")

msg.append(indent)
msg.append(
"%s %s"
% (
pkg,
pkg_use_display(
pkg,
d._frozen_config.myopts,
modified_use= d._pkg_use_enabled(pkg),
),
)
)
msg.append(" conflicts with\n")

for parent, atom in parent_atoms:
if isinstance(parent, (PackageArg, AtomArg)):
msg.append(2 * indent)
msg.append(str(parent))
msg.append("\n") else:
atom, marker = format_unmatched_atom(
pkg, atom, d._pkg_use_enabled
)

if isinstance(parent, Package):
use_display = pkg_use_display(
parent,
d._frozen_config.myopts,
modified_use = d._pkg_use_enabled(parent),
) else:
use_display = ""

msg.append(2 * indent)
msg.append("%s required by %s %s\n" % (atom, parent, use_display))
msg.append(2 * indent)
msg.append(marker)
msg.append("\n")
msg.append("\n")

writemsg("".join(msg), noiselevel = -1)
}

func (d*depgraph) _show_slot_collision_notice() {

	if not any(d._dynamic_config._package_tracker.slot_conflicts()):
	return

	d._show_merge_list()

	if d._dynamic_config._slot_conflict_handler is
nil:
	d._dynamic_config._slot_conflict_handler = slot_conflict_handler(self)
	handler = d._dynamic_config._slot_conflict_handler

	conflict = handler.get_conflict()
	writemsg(conflict, noiselevel = -1)

	explanation = handler.get_explanation()
	if explanation:
	writemsg(explanation, noiselevel = -1)
	return

	if "--quiet" in
	d._frozen_config.myopts:
	return

	msg = [
"It may be possible to solve this problem "
"by using package.mask to prevent one of "
"those packages from being selected. "
"However, it is also possible that conflicting "
"dependencies exist such that they are impossible to "
"satisfy simultaneously.  If such a conflict exists in "
"the dependencies of two different packages, then those "
"packages can not be installed simultaneously."
]
backtrack_opt = d._frozen_config.myopts.get("--backtrack")
if not d._dynamic_config._allow_backtracking and (
backtrack_opt is nil or (backtrack_opt > 0 and backtrack_opt < 30)
):
msg.append(
" You may want to try a larger value of the "
"--backtrack option, such as --backtrack=30, "
"in order to see if that will solve this conflict "
"automatically."
)

for line in textwrap.wrap("".join(msg), 70):
writemsg(line + "\n", noiselevel = -1)
writemsg("\n", noiselevel = -1)

msg = (
"For more information, see MASKED PACKAGES "
"section in the emerge man page or refer "
"to the Gentoo Handbook."
)
for line in textwrap.wrap(msg, 70):
writemsg(line + "\n", noiselevel =-1)
writemsg("\n", noiselevel =-1)
}

func (d*depgraph) _solve_non_slot_operator_slot_conflicts() {
	debug = "--debug"
	in
	d._frozen_config.myopts

	conflicts = []
for conflict in d._dynamic_config._package_tracker.slot_conflicts():
slot_key = conflict.root, conflict.atom
if slot_key not in d._dynamic_config._slot_operator_replace_installed:
conflicts.append(conflict)

if not conflicts:
return

if debug:
writemsg_level(
"\n!!! Slot conflict handler started.\n",
level = logging.DEBUG,
noiselevel = -1,
)

conflict_pkgs = set()
for conflict in conflicts:
conflict_pkgs.update(conflict)

indirect_conflict_candidates = set()
for pkg in conflict_pkgs:
indirect_conflict_candidates.update(
d._dynamic_config.digraph.child_nodes(pkg)
)
indirect_conflict_candidates -= conflict_pkgs

indirect_conflict_pkgs = set()
while indirect_conflict_candidates:
pkg = indirect_conflict_candidates.pop()

only_conflict_parents = true
for parent, atom in d._dynamic_config._parent_atoms.get(pkg, []):
if parent not in conflict_pkgs and parent not in indirect_conflict_pkgs:
only_conflict_parents = false
break
if not only_conflict_parents:
continue

indirect_conflict_pkgs.add(pkg)
for child in d._dynamic_config.digraph.child_nodes(pkg):
if child in conflict_pkgs or child in indirect_conflict_pkgs:
continue
indirect_conflict_candidates.add(child)

conflict_graph = digraph()

non_conflict_node = "(non-conflict package)"
conflict_graph.add(non_conflict_node, nil)

for pkg in chain(conflict_pkgs, indirect_conflict_pkgs):
conflict_graph.add(pkg, nil)

class or_tuple(tuple):

def __str__(self):
return "(%s)" % ",".join(str(pkg) for pkg in self)

non_matching_forced = set()
for conflict in conflicts:
if debug:
writemsg_level("   conflict:\n", level = logging.DEBUG, noiselevel = -1)
writemsg_level(
"      root: %s\n" % conflict.root,
level = logging.DEBUG,
noiselevel = -1,
)
writemsg_level(
"      atom: %s\n" % conflict.atom,
level = logging.DEBUG,
noiselevel = -1,
)
for pkg in conflict:
writemsg_level(
"      pkg: %s\n" % pkg, level = logging.DEBUG, noiselevel = -1
)

all_parent_atoms = set()
highest_pkg = nil
inst_pkg = nil
for pkg in conflict:
if pkg.installed:
inst_pkg = pkg
if highest_pkg is nil or highest_pkg < pkg:
highest_pkg = pkg
all_parent_atoms.update(d._dynamic_config._parent_atoms.get(pkg, []))

for parent, atom in all_parent_atoms:
is_arg_parent = inst_pkg is not nil and not d._want_installed_pkg(
inst_pkg
)
is_non_conflict_parent = (
parent not in conflict_pkgs and parent not in indirect_conflict_pkgs
)

if debug:
writemsg_level(
"      parent: %s\n" % parent,
level = logging.DEBUG,
noiselevel = -1,
)
writemsg_level(
"      arg, non-conflict: %s, %s\n"
% (is_arg_parent, is_non_conflict_parent),
level = logging.DEBUG,
noiselevel = -1,
)
writemsg_level(
"         atom: %s\n" % atom, level = logging.DEBUG, noiselevel= -1
)

if is_non_conflict_parent:
parent = non_conflict_node

matched = []
for pkg in conflict:
if atom.match(pkg.with_use(d._pkg_use_enabled(pkg))) and not (
is_arg_parent and pkg.installed
):
matched.append(pkg)

if debug:
for match in matched:
writemsg_level(
"         match: %s\n" % match,
level = logging.DEBUG,
noiselevel =-1,
)

if len(matched) > 1:
conflict_graph.add(or_tuple(matched), parent)
elif len(matched) == 1:
conflict_graph.add(matched[0], parent) else:
non_matching_forced.update(conflict)
if debug:
for pkg in conflict:
writemsg_level(
"         non-match: %s\n" % pkg,
level =logging.DEBUG,
noiselevel = -1,
)

for pkg in indirect_conflict_pkgs:
for parent, atom in d._dynamic_config._parent_atoms.get(pkg, []):
if parent not in conflict_pkgs and parent not in indirect_conflict_pkgs:
parent = non_conflict_node
conflict_graph.add(pkg, parent)

if debug:
writemsg_level(
"\n!!! Slot conflict graph:\n", level = logging.DEBUG, noiselevel = -1
)
conflict_graph.debug_print()

forced = {non_conflict_node}
forced |= non_matching_forced
unexplored = {non_conflict_node}
unexplored_tuples = set()
explored_nodes = set()

while unexplored:
while true:
try:
node = unexplored.pop()
except KeyError:
break
for child in conflict_graph.child_nodes(node):
if child in explored_nodes:
continue
explored_nodes.add(child)
forced.add(child)
if isinstance(child, Package):
unexplored.add(child)
else:
unexplored_tuples.add(child)

while unexplored_tuples:
nodes = unexplored_tuples.pop()
if any(node in forced for node in nodes):
continue

forced.add(nodes[0])
unexplored.add(nodes[0])
break

forced = {pkg for pkg in forced if isinstance(pkg, Package)}

stack = list(forced)
traversed = set()
while stack:
pkg = stack.pop()
traversed.add(pkg)
for child in conflict_graph.child_nodes(pkg):
if isinstance(child, Package) and child not in traversed:
forced.add(child)
stack.append(child)

non_forced = {pkg for pkg in conflict_pkgs if pkg not in forced}

if debug:
writemsg_level(
"\n!!! Slot conflict solution:\n", level =logging.DEBUG, noiselevel = -1
)
for conflict in conflicts:
writemsg_level(
"   Conflict: (%s, %s)\n" % (conflict.root, conflict.atom),
level = logging.DEBUG,
noiselevel = -1,
)
for pkg in conflict:
if pkg in forced:
writemsg_level(
"      keep:   %s\n" % pkg,
level= logging.DEBUG,
noiselevel = -1,
) else:
writemsg_level(
"      remove: %s\n" % pkg,
level = logging.DEBUG,
noiselevel = -1,
)

broken_packages = set()
for pkg in non_forced:
for parent, atom in d._dynamic_config._parent_atoms.get(pkg, []):
if isinstance(parent, Package) and parent not in non_forced:
broken_packages.add(parent)
d._remove_pkg(pkg)

broken_packages |= forced
broken_packages = [
pkg
for pkg in broken_packages
if pkg in broken_packages
and d._dynamic_config._package_tracker.contains(pkg, installed = false)
]

d._dynamic_config._dep_stack.extend(broken_packages)

if broken_packages:
d._create_graph()

for conflict in conflicts:
for pkg in conflict:
if pkg not in non_forced:
continue

for other in conflict:
if other is pkg:
continue

for parent, atom in d._dynamic_config._parent_atoms.get(
other, []
):
if not atom.match(pkg.with_use(d._pkg_use_enabled(pkg))):
d._dynamic_config._conflict_missed_update[
pkg
].setdefault("slot conflict", set())
d._dynamic_config._conflict_missed_update[pkg][
"slot conflict"
].add((parent, atom))
}

func (d*depgraph) _process_slot_conflicts() {

	d._solve_non_slot_operator_slot_conflicts()

	if not d._validate_blockers():
	raise
	d._unknown_internal_error()

	for conflict
	in
	d._dynamic_config._package_tracker.slot_conflicts():
	d._process_slot_conflict(conflict)

	if d._dynamic_config._allow_backtracking:
	d._slot_operator_trigger_reinstalls()
}

func (d*depgraph) _process_slot_conflict( conflict) {
	root = conflict.root
	slot_atom = conflict.atom
	slot_nodes = conflict.pkgs

	debug = "--debug"
	in
	d._frozen_config.myopts

	slot_parent_atoms = set()
	for pkg
	in
slot_nodes:
	parent_atoms = d._dynamic_config._parent_atoms.get(pkg)
	if not parent_atoms:
	continue
	slot_parent_atoms.update(parent_atoms)

	conflict_pkgs = []
conflict_atoms = {}
for pkg in slot_nodes:

if (
d._dynamic_config._allow_backtracking
and pkg in d._dynamic_config._runtime_pkg_mask
):
if debug:
writemsg_level(
"!!! backtracking loop detected: %s %s\n"
% (pkg, d._dynamic_config._runtime_pkg_mask[pkg]),
level = logging.DEBUG,
noiselevel = -1,
)

parent_atoms = d._dynamic_config._parent_atoms.get(pkg)
if parent_atoms is nil:
parent_atoms = set()
d._dynamic_config._parent_atoms[pkg] = parent_atoms

all_match = true
for parent_atom in slot_parent_atoms:
if parent_atom in parent_atoms:
continue
parent, atom = parent_atom
if atom.match(pkg.with_use(d._pkg_use_enabled(pkg))):
parent_atoms.add(parent_atom)
else:
all_match = false
conflict_atoms.setdefault(parent_atom, set()).add(pkg)

if not all_match:
conflict_pkgs.append(pkg)

if (
conflict_pkgs
and d._dynamic_config._allow_backtracking
and not d._accept_blocker_conflicts()
):
remaining = []
for pkg in conflict_pkgs:
if d._slot_conflict_backtrack_abi(pkg, slot_nodes, conflict_atoms):
backtrack_infos = d._dynamic_config._backtrack_infos
config = backtrack_infos.setdefault("config", {})
config.setdefault("slot_conflict_abi", set()).add(pkg) else:
remaining.append(pkg)
if remaining:
d._slot_confict_backtrack(
root, slot_atom, slot_parent_atoms, remaining
)
}

func (d*depgraph) _slot_confict_backtrack(root, slot_atom, all_parents, conflict_pkgs) {

	debug = "--debug"
	in
	d._frozen_config.myopts
	existing_node = next(
		d._dynamic_config._package_tracker.match(
			root, slot_atom, installed = false
	)
)
	if existing_node not
	in
conflict_pkgs:
	conflict_pkgs.append(existing_node)
	conflict_pkgs.sort(reverse = true)
	backtrack_data = []
for to_be_masked in conflict_pkgs:
parent_atoms = d._dynamic_config._parent_atoms.get(to_be_masked, set())
conflict_atoms = set(
parent_atom
for parent_atom in all_parents
if parent_atom not in parent_atoms
)

similar_pkgs = []
if conflict_atoms:
for similar_pkg in d._iter_similar_available(
to_be_masked, slot_atom
):
if similar_pkg in conflict_pkgs:
continue
similar_conflict_atoms = []
for parent_atom in conflict_atoms:
parent, atom = parent_atom
if not atom.match(similar_pkg):
similar_conflict_atoms.append(parent_atom)
if similar_conflict_atoms:
similar_pkgs.append((similar_pkg, set(similar_conflict_atoms)))
similar_pkgs.append((to_be_masked, conflict_atoms))
backtrack_data.append(tuple(similar_pkgs))

backtrack_data.sort(key = lambda similar_pkgs: len(similar_pkgs[-1][1]))
to_be_masked = [item[0] for item in backtrack_data[-1]]

d._dynamic_config._backtrack_infos.setdefault("slot conflict", []).append(
backtrack_data
)
d._dynamic_config._need_restart = true
if debug:
msg = [
"",
"",
"backtracking due to slot conflict:",
"   first package:  %s" % existing_node,
"  package(s) to mask: %s" % str(to_be_masked),
"      slot: %s" % slot_atom,
"   parents: %s"
% ", ".join("(%s, '%s')" % (ppkg, atom) for ppkg, atom in all_parents),
"",
]
writemsg_level(
"".join("%s\n" % l for l in msg), noiselevel = -1, level = logging.DEBUG
)
}

func (d*depgraph) _slot_conflict_backtrack_abi( pkg, slot_nodes, conflict_atoms) {

	found_update = false
	for parent_atom, conflict_pkgs
	in
	conflict_atoms.items():
	parent, atom = parent_atom

	if not isinstance(parent, Package):
	continue

	if not parent.built:
	continue

	if not atom.soname
	and
	not(atom.package
	and
	atom.slot_operator_built):
	continue

	for other_pkg
	in
slot_nodes:
	if other_pkg in
conflict_pkgs:
	continue

	dep = Dependency(
		atom = atom, child = other_pkg, parent=parent, root = pkg.root
	)

	new_dep = d._slot_operator_update_probe_slot_conflict(dep)
	if new_dep is
	not
nil:
	d._slot_operator_update_backtrack(dep, new_dep = new_dep)
	found_update = true

	return found_update
}

func (d*depgraph) _slot_change_probe( dep) {
	if not(
		isinstance(dep.parent, Package) and
	not
	dep.parent.built
	and
	dep.child.built
	):
	return nil

	root_config = d._frozen_config.roots[dep.root]
	matches = []
try:
matches.append(
d._pkg(dep.child.cpv, "ebuild", root_config, myrepo = dep.child.repo)
)
except PackageNotFound:
pass

for unbuilt_child in chain(
matches,
d._iter_match_pkgs(
root_config, "ebuild", Atom("=%s" % (dep.child.cpv, ))
),
):
if unbuilt_child in d._dynamic_config._runtime_pkg_mask:
continue
if d._frozen_config.excluded_pkgs.findAtomForPackage(
unbuilt_child, modified_use = d._pkg_use_enabled(unbuilt_child)
):
continue
if not d._pkg_visibility_check(unbuilt_child):
continue
break else:
return nil

if (
unbuilt_child.slot == dep.child.slot
and unbuilt_child.sub_slot == dep.child.sub_slot
):
return nil

return unbuilt_child
}

func (d*depgraph) _slot_change_backtrack( dep, new_child_slot){
child = dep.child
if "--debug" in d._frozen_config.myopts:
msg = [
"",
"",
"backtracking due to slot/sub-slot change:",
"   child package:  %s" % child,
"      child slot:  %s/%s" % (child.slot, child.sub_slot),
"       new child:  %s" % new_child_slot,
"  new child slot:  %s/%s"
% (new_child_slot.slot, new_child_slot.sub_slot),
"   parent package: %s" % dep.parent,
"   atom: %s" % dep.atom,
"",
]
writemsg_level("\n".join(msg), noiselevel = -1, level = logging.DEBUG)
backtrack_infos = d._dynamic_config._backtrack_infos
config = backtrack_infos.setdefault("config", {})

masks = {}
if not child.installed:
masks.setdefault(dep.child, {})["slot_operator_mask_built"] = nil
if masks:
config.setdefault("slot_operator_mask_built", {}).update(masks)

reinstalls = set()
if child.installed:
replacement_atom = d._replace_installed_atom(child)
if replacement_atom is not nil:
reinstalls.add((child.root, replacement_atom))
if reinstalls:
config.setdefault("slot_operator_replace_installed", set()).update(
reinstalls
)

d._dynamic_config._need_restart = true
}

func (d*depgraph) _slot_operator_update_backtrack(dep, new_child_slot=nil, new_dep=nil) {
	if new_child_slot is
nil:
	child = dep.child
	else:
	child = new_child_slot
	if "--debug" in
	d._frozen_config.myopts:
	msg = [
"",
"",
"backtracking due to missed slot abi update:",
"   child package:  %s" % child,
]
if new_child_slot is not nil:
msg.append("   new child slot package:  %s" % new_child_slot)
msg.append("   parent package: %s" % dep.parent)
if new_dep is not nil:
msg.append("   new parent pkg: %s" % new_dep.parent)
msg.append("   atom: %s" % dep.atom)
msg.append("")
writemsg_level("\n".join(msg), noiselevel = -1, level = logging.DEBUG)
backtrack_infos = d._dynamic_config._backtrack_infos
config = backtrack_infos.setdefault("config", {})

abi_masks = {}
if new_child_slot is nil:
if not child.installed:
abi_masks.setdefault(child, {})["slot_operator_mask_built"] = nil
if not dep.parent.installed:
abi_masks.setdefault(dep.parent, {})["slot_operator_mask_built"] = nil
if abi_masks:
config.setdefault("slot_operator_mask_built", {}).update(abi_masks)

abi_reinstalls = set()
if dep.parent.installed:
if new_dep is not nil:
replacement_atom = new_dep.parent.slot_atom else:
replacement_atom = d._replace_installed_atom(dep.parent)
if replacement_atom is not nil:
abi_reinstalls.add((dep.parent.root, replacement_atom))
if new_child_slot is nil and child.installed:
replacement_atom = d._replace_installed_atom(child)
if replacement_atom is not nil:
abi_reinstalls.add((child.root, replacement_atom))
if abi_reinstalls:
config.setdefault("slot_operator_replace_installed", set()).update(
abi_reinstalls
)

d._dynamic_config._need_restart = true
}

func (d*depgraph) _slot_operator_update_probe_slot_conflict(dep) {
	new_dep = d._slot_operator_update_probe(dep, slot_conflict = true)

	if new_dep is
	not
nil:
	return new_dep

	if d._dynamic_config._autounmask is
true:

	for autounmask_level
	in
	d._autounmask_levels():

	new_dep = d._slot_operator_update_probe(
		dep, slot_conflict = true, autounmask_level = autounmask_level
	)

	if new_dep is
	not
nil:
	return new_dep

	return nil
}

func (d*depgraph) _slot_operator_update_probe(
dep, new_child_slot=false, slot_conflict=false, autounmask_level=nil
) {

	if (
		dep.child.installed
		and
	d._frozen_config.excluded_pkgs.findAtomForPackage(
		dep.child, modified_use = d._pkg_use_enabled(dep.child)
	)
):
	return nil

	if (
		dep.parent.installed
		and
	d._frozen_config.excluded_pkgs.findAtomForPackage(
		dep.parent, modified_use = d._pkg_use_enabled(dep.parent)
	)
):
	return nil

	debug = "--debug"
	in
	d._frozen_config.myopts
	selective = "selective"
	in
	d._dynamic_config.myparams
	want_downgrade = nil
	want_downgrade_parent = nil

	def
	check_reverse_dependencies(
		existing_pkg, candidate_pkg, replacement_parent = nil
	):
	built_slot_operator_parents = set()
	for parent, atom
		in
	d._dynamic_config._parent_atoms.get(
		existing_pkg,[]
	):
	if atom.soname or
	atom.slot_operator_built:
	built_slot_operator_parents.add(parent)

	for parent, atom
		in
	d._dynamic_config._parent_atoms.get(
		existing_pkg,[]
	):
	if isinstance(parent, Package):
	if parent in
built_slot_operator_parents:
	if hasattr(atom, "_orig_atom"):
	atom = atom._orig_atom
	if atom.soname:
	continue
	elif
	atom.package
	and
	atom.slot_operator_built:
	atom = atom.with_slot("=")

	if replacement_parent is
	not
	nil
	and(
		replacement_parent.slot_atom == parent.slot_atom
	or
	replacement_parent.cpv == parent.cpv
	):
	continue

	if any(
		pkg is
	not
	parent
	and(pkg.slot_atom == parent.slot_atom
	or
	pkg.cpv == parent.cpv)
	for pkg
		in
	d._dynamic_config._package_tracker.match(
		parent.root, Atom(parent.cp)
	)
	):
	continue

	if not d._too_deep(
		parent.depth
	)
	and
	not
	d._frozen_config.excluded_pkgs.findAtomForPackage(
		parent, modified_use = d._pkg_use_enabled(parent)
	):
	if d._upgrade_available(parent):
	continue
	if parent.installed and
	d._in_blocker_conflict(parent):
	continue
	if d._dynamic_config.digraph.has_edge(parent, existing_pkg):
	continue

	atom_set = InternalPackageSet(initial_atoms = (atom,), allow_repo = true)
	if not atom_set.findAtomForPackage(
		candidate_pkg, modified_use = d._pkg_use_enabled(candidate_pkg)
	):
	if debug:
	parent_atoms = []
for (
other_parent,
other_atom,
) in d._dynamic_config._parent_atoms.get(existing_pkg, []):
if other_parent is parent:
parent_atoms.append(other_atom)
msg = (
"",
"",
"check_reverse_dependencies:",
"   candidate package does not match atom '%s': %s"
% (atom, candidate_pkg),
"   parent: %s" % parent,
"   parent atoms: %s" % " ".join(parent_atoms),
"",
)
writemsg_level(
"\n".join(msg), noiselevel = -1, level = logging.DEBUG
)
return false
return true

for replacement_parent in d._iter_similar_available(
dep.parent, dep.parent.slot_atom, autounmask_level = autounmask_level
):

if replacement_parent is dep.parent:
continue

if replacement_parent < dep.parent:
if want_downgrade_parent is nil:
want_downgrade_parent = d._downgrade_probe(dep.parent)
if not want_downgrade_parent:
continue

if not check_reverse_dependencies(dep.parent, replacement_parent):
continue

selected_atoms = nil

try:
atoms = d._flatten_atoms(
replacement_parent, d._pkg_use_enabled(replacement_parent)
)
except InvalidDependString:
continue

if replacement_parent.requires is not nil:
atoms = list(atoms)
atoms.extend(replacement_parent.requires)

replacement_candidates = []
all_candidate_pkgs = nil

for atom in atoms:
atom_not_selected = nil

if not atom.package:
unevaluated_atom = nil
if atom.match(dep.child):
continue else:

if atom.blocker or atom.cp != dep.child.cp:
continue

unevaluated_atom = atom.unevaluated_atom
atom = atom.without_use

if replacement_parent.built and portage.dep._match_slot(
atom, dep.child
):
continue

candidate_pkg_atoms = []
candidate_pkgs = []
for pkg in d._iter_similar_available(dep.child, atom):
if (
dep.atom.package
and pkg.slot == dep.child.slot
and pkg.sub_slot == dep.child.sub_slot
):
continue
if new_child_slot:
if pkg.slot == dep.child.slot:
continue
if pkg < dep.child:
continue else:
if pkg.slot != dep.child.slot:
continue
if pkg < dep.child:
if want_downgrade is nil:
want_downgrade = d._downgrade_probe(dep.child)
if not want_downgrade:
continue
if pkg.version == dep.child.version and not dep.child.built:
continue

insignificant = false
if (
not slot_conflict
and selective
and dep.parent.installed
and dep.child.installed
and dep.parent >= replacement_parent
and dep.child.cpv == pkg.cpv
):
insignificant = true

if not insignificant and unevaluated_atom is not nil:
if selected_atoms is nil:
selected_atoms = d._select_atoms_probe(
dep.child.root, replacement_parent
)
atom_not_selected = unevaluated_atom not in selected_atoms
if atom_not_selected:
break

if not insignificant and check_reverse_dependencies(
dep.child, pkg, replacement_parent = replacement_parent
):

candidate_pkg_atoms.append((pkg, unevaluated_atom or atom))
candidate_pkgs.append(pkg)

if atom_not_selected is nil and unevaluated_atom is not nil:
if selected_atoms is nil:
selected_atoms = d._select_atoms_probe(
dep.child.root, replacement_parent
)
atom_not_selected = unevaluated_atom not in selected_atoms

if atom_not_selected:
continue
replacement_candidates.append(candidate_pkg_atoms)
if all_candidate_pkgs is nil:
all_candidate_pkgs = set(candidate_pkgs) else:
all_candidate_pkgs.intersection_update(candidate_pkgs)

if not all_candidate_pkgs:
continue

selected = nil
for candidate_pkg_atoms in replacement_candidates:
for i, (pkg, atom) in enumerate(candidate_pkg_atoms):
if pkg not in all_candidate_pkgs:
continue
if (
selected is nil
or selected[0] < pkg
or (selected[0] is pkg and i < selected[2])
):
selected = (pkg, atom, i)

if debug:
msg = (
"",
"",
"slot_operator_update_probe:",
"   existing child package:  %s" % dep.child,
"   existing parent package: %s" % dep.parent,
"   new child package:  %s" % selected[0],
"   new parent package: %s" % replacement_parent,
"",
)
writemsg_level("\n".join(msg), noiselevel= -1, level = logging.DEBUG)

return Dependency(
parent = replacement_parent, child =selected[0], atom = selected[1]
)

if debug:
msg = (
"",
"",
"slot_operator_update_probe:",
"   existing child package:  %s" % dep.child,
"   existing parent package: %s" % dep.parent,
"   new child package:  %s" % nil,
"   new parent package: %s" % nil,
"",
)
writemsg_level("\n".join(msg), noiselevel= -1, level = logging.DEBUG)

return nil
}

func (d*depgraph) _slot_operator_unsatisfied_probe(dep) {

	if (
		dep.parent.installed
		and
	d._frozen_config.excluded_pkgs.findAtomForPackage(
		dep.parent, modified_use = d._pkg_use_enabled(dep.parent)
	)
):
	return false

	debug = "--debug"
	in
	d._frozen_config.myopts

	for replacement_parent
	in
	d._iter_similar_available(
		dep.parent, dep.parent.slot_atom
	):

	for atom
	in
	replacement_parent.validated_atoms:
	if (
		not atom.slot_operator == "="
	or
	atom.blocker
	or
	atom.cp != dep.atom.cp
	):
	continue

	atom = atom.without_use

	pkg, existing_node = d._select_package(
		dep.root, atom, onlydeps = dep.onlydeps
	)

	if pkg is
	not
nil:

	if debug:
	msg = (
		"",
		"",
		"slot_operator_unsatisfied_probe:",
		"   existing parent package: %s" % dep.parent,
		"   existing parent atom: %s" % dep.atom,
		"   new parent package: %s" % replacement_parent,
		"   new child package:  %s" % pkg,
		"",
)
	writemsg_level(
		"\n".join(msg), noiselevel = -1, level = logging.DEBUG
	)

	return true

	if debug:
	msg = (
		"",
		"",
		"slot_operator_unsatisfied_probe:",
		"   existing parent package: %s" % dep.parent,
		"   existing parent atom: %s" % dep.atom,
		"   new parent package: %s" % nil,
		"   new child package:  %s" % nil,
		"",
)
	writemsg_level("\n".join(msg), noiselevel = -1, level = logging.DEBUG)

	return false
}

func (d*depgraph) _slot_operator_unsatisfied_backtrack(dep) {

	parent = dep.parent

	if "--debug" in
	d._frozen_config.myopts:
	msg = (
		"",
		"",
		"backtracking due to unsatisfied built slot-operator dep:",
		"   parent package: %s" % parent,
		"   atom: %s" % dep.atom,
		"",
)
	writemsg_level("\n".join(msg), noiselevel = -1, level = logging.DEBUG)

	backtrack_infos = d._dynamic_config._backtrack_infos
	config = backtrack_infos.setdefault("config",
	{
	})

	masks =
	{
	}
	if not parent.installed:
	masks.setdefault(parent,
	{
	})["slot_operator_mask_built"] = nil
if masks:
config.setdefault("slot_operator_mask_built", {}).update(masks)

reinstalls = set()
if parent.installed:
replacement_atom = d._replace_installed_atom(parent)
if replacement_atom is not nil:
reinstalls.add((parent.root, replacement_atom))
if reinstalls:
config.setdefault("slot_operator_replace_installed", set()).update(
reinstalls
)

d._dynamic_config._need_restart = true
}

func (d*depgraph) _in_blocker_conflict( pkg)bool {

	if d._dynamic_config._blocked_pkgs is
	nil
	and
	not
	d._validate_blockers():
	raise
	d._unknown_internal_error()

	if pkg in
	d._dynamic_config._blocked_pkgs:
	return true

	if pkg in
	d._dynamic_config._blocker_parents:
	return true

	return false
}

func (d*depgraph) _upgrade_available( pkg) bool{
	for available_pkg
	in
	d._iter_similar_available(pkg, pkg.slot_atom):
	if available_pkg > pkg {
		return true
	}

	return false
}

func (d*depgraph) _downgrade_probe( pkg) bool {
	available_pkg = nil
	for available_pkg
	in
	d._iter_similar_available(pkg, pkg.slot_atom):
	if available_pkg >= pkg:
	return false

	return available_pkg!= nil
}

func (d*depgraph) _select_atoms_probe( root, pkg) {
	selected_atoms = []
use = d._pkg_use_enabled(pkg)
for k in pkg._dep_keys:
v = pkg._metadata.get(k)
if not v:
continue
selected_atoms.extend(
d._select_atoms(root, v, myuse = use, parent = pkg)[pkg]
)
return frozenset(x.unevaluated_atom for x in selected_atoms)
}

func (d*depgraph) _flatten_atoms( pkg, use) {

	cache_key = (pkg, use)

try:
	return d._dynamic_config._flatten_atoms_cache[cache_key]
	except
KeyError:
	pass

	atoms = []

for dep_key in pkg._dep_keys:
dep_string = pkg._metadata[dep_key]
if not dep_string:
continue

dep_string = portage.dep.use_reduce(
dep_string,
uselist = use,
is_valid_flag =pkg.iuse.is_valid_flag,
flat = true,
token_class = Atom,
eapi = pkg.eapi,
)

atoms.extend(token for token in dep_string if isinstance(token, Atom))

atoms = frozenset(atoms)

d._dynamic_config._flatten_atoms_cache[cache_key] = atoms
return atoms
}

func (d*depgraph) _iter_similar_available(graph_pkg, atom, autounmask_level=nil) {

	usepkgonly = "--usepkgonly"
	in
	d._frozen_config.myopts
	useoldpkg_atoms = d._frozen_config.useoldpkg_atoms
	use_ebuild_visibility = (
		d._frozen_config.myopts.get("--use-ebuild-visibility", "n") != "n"
	)

	for pkg
	in
	d._iter_match_pkgs_any(graph_pkg.root_config, atom):
	if pkg.cp != graph_pkg.cp:
	# discard
	old - style
	virtual
	match
	continue
	if pkg.installed:
	continue
	if pkg in
	d._dynamic_config._runtime_pkg_mask:
	continue
	if d._frozen_config.excluded_pkgs.findAtomForPackage(
		pkg, modified_use = d._pkg_use_enabled(pkg)
):
	continue
	if pkg.built:
	if d._equiv_binary_installed(pkg):
	continue
	if not(
		not use_ebuild_visibility
	and(
		usepkgonly
	or
	useoldpkg_atoms.findAtomForPackage(
		pkg, modified_use = d._pkg_use_enabled(pkg)
	)
)
) and
	not
	d._equiv_ebuild_visible(
		pkg, autounmask_level = autounmask_level
	):
	continue
	if not d._pkg_visibility_check(pkg, autounmask_level = autounmask_level):
	continue
	yield
	pkg
}

func (d*depgraph) _replace_installed_atom(inst_pkg) {
	built_pkgs = []
for pkg in d._iter_similar_available(inst_pkg, Atom("=%s" % inst_pkg.cpv)):
if not pkg.built:
return pkg.slot_atom
if not pkg.installed:
built_pkgs.append(pkg)

for pkg in d._iter_similar_available(inst_pkg, inst_pkg.slot_atom):
if not pkg.built:
return pkg.slot_atom
if not pkg.installed:
built_pkgs.append(pkg)

if built_pkgs:
best_version = nil
for pkg in built_pkgs:
if best_version is nil or pkg > best_version:
best_version = pkg
return best_version.slot_atom

return nil
}

func (d*depgraph) _slot_operator_trigger_reinstalls() {

	rebuild_if_new_slot = (
		d._dynamic_config.myparams.get("rebuild_if_new_slot", "y") == "y"
	)

	for slot_key, slot_info
	in
	d._dynamic_config._slot_operator_deps.items():

	for dep
	in
slot_info:

	atom = dep.atom

	if not(atom.soname or
	atom.slot_operator_built):
	new_child_slot = d._slot_change_probe(dep)
	if new_child_slot is
	not
nil:
	d._slot_change_backtrack(dep, new_child_slot)
	continue

	if not(
		dep.parent and
	isinstance(dep.parent, Package)
	and
	dep.parent.built
	):
	continue

	want_update_probe = dep.want_update
	or
	not
	dep.parent.installed

	if rebuild_if_new_slot and
want_update_probe:
	new_dep = d._slot_operator_update_probe(dep, new_child_slot = true)
	if new_dep is
	not
nil:
	d._slot_operator_update_backtrack(
		dep, new_child_slot = new_dep.child
	)

	if want_update_probe:
	if d._slot_operator_update_probe(dep):
	d._slot_operator_update_backtrack(dep)
}

func (d*depgraph) _reinstall_for_flags(pkg, forced_flags, orig_use, orig_iuse, cur_use, cur_iuse) {
	binpkg_respect_use = pkg.built
	and
	d._dynamic_config.myparams.get(
		"binpkg_respect_use"
	)
	in("y", "auto")
	newuse = "--newuse"
	in
	d._frozen_config.myopts
	changed_use = "changed-use" == d._frozen_config.myopts.get("--reinstall")
	feature_flags = _get_feature_flags(_get_eapi_attrs(pkg.eapi))

	if newuse or(binpkg_respect_use
	and
	not
	changed_use):
	flags = set(orig_iuse)
	flags ^= cur_iuse
	flags -= forced_flags
	flags |= orig_iuse.intersection(orig_use) ^ cur_iuse.intersection(cur_use)
	flags -= feature_flags
	if flags:
	return flags
	elif
	changed_use
	or
binpkg_respect_use:
	flags = set(orig_iuse)
	flags.intersection_update(orig_use)
	flags ^= cur_iuse.intersection(cur_use)
	flags -= feature_flags
	if flags:
	return flags
	return nil
}

func (d*depgraph) _changed_deps( pkg) {

	ebuild = nil
try:
	ebuild = d._pkg(pkg.cpv, "ebuild", pkg.root_config, myrepo = pkg.repo)
	except
PackageNotFound:
	for ebuild
	in
	d._iter_match_pkgs(
		pkg.root_config, "ebuild", Atom("="+pkg.cpv)
	):
	break

	if ebuild is
nil:
	changed = false
	else:
	if d._dynamic_config.myparams.get("bdeps") in("y", "auto"):
	depvars = Package._dep_keys
	else:
	depvars = Package._runtime_keys

try:
	built_deps = []
for k in depvars:
dep_struct = portage.dep.use_reduce(
pkg._raw_metadata[k],
uselist = pkg.use.enabled,
eapi = pkg.eapi,
token_class = Atom,
)
strip_slots(dep_struct)
built_deps.append(dep_struct)
except InvalidDependString:
changed = true
else:
unbuilt_deps = []
for k in depvars:
dep_struct = portage.dep.use_reduce(
ebuild._raw_metadata[k],
uselist =pkg.use.enabled,
eapi = ebuild.eapi,
token_class = Atom,
)
strip_slots(dep_struct)
unbuilt_deps.append(dep_struct)

changed = built_deps != unbuilt_deps

if (
changed
and pkg.installed
and d._dynamic_config.myparams.get("changed_deps_report")
):
d._dynamic_config._changed_deps_pkgs[pkg] = ebuild

return changed
}

func (d*depgraph) _changed_slot( pkg) {
	ebuild := d._equiv_ebuild(pkg)
	return ebuild!= nil&& (ebuild.slot, ebuild.sub_slot) != (
		pkg.slot, pkg.sub_slot,)
}

// false
func (d*depgraph) _create_graph(allow_unsatisfied bool) {
	dep_stack = d._dynamic_config._dep_stack
	dep_disjunctive_stack = d._dynamic_config._dep_disjunctive_stack
	while
	dep_stack
	or
dep_disjunctive_stack:
	d._spinner_update()
	while
dep_stack:
	dep = dep_stack.pop()
	if isinstance(dep, Package):
	if not d._add_pkg_deps(dep, allow_unsatisfied = allow_unsatisfied):
	return 0
	continue
	if not d._add_dep(dep, allow_unsatisfied = allow_unsatisfied):
	return 0
	if dep_disjunctive_stack:
	if not d._pop_disjunction(allow_unsatisfied):
	return 0
	return 1
}

// false
func (d*depgraph) _expand_set_args(input_args, add_to_digraph=false) {

	traversed_set_args = set()

	for arg
	in
input_args:
	if not isinstance(arg, SetArg):
	yield
	arg
	continue

	root_config = arg.root_config
	depgraph_sets = d._dynamic_config.sets[root_config.root]
	arg_stack = [arg]
while arg_stack:
arg = arg_stack.pop()
if arg in traversed_set_args:
continue

arg = d._dynamic_config.digraph.get(arg, arg)
traversed_set_args.add(arg)

if add_to_digraph:
d._dynamic_config.digraph.add(
arg, nil, priority =BlockerDepPriority.instance
)

yield arg

for token in sorted(arg.pset.getNonAtoms()):
if not token.startswith(SETPREFIX):
continue
s = token[len(SETPREFIX):]
nested_set = depgraph_sets.sets.get(s)
if nested_set is nil:
nested_set = root_config.sets.get(s)
if nested_set is not nil:
nested_arg = SetArg(
arg = token,
pset = nested_set,
reset_depth = arg.reset_depth,
root_config = root_config,
)

nested_arg = d._dynamic_config.digraph.get(
nested_arg, nested_arg
)
arg_stack.append(nested_arg)
if add_to_digraph:
d._dynamic_config.digraph.add(
nested_arg, arg, priority = BlockerDepPriority.instance
)
depgraph_sets.sets[nested_arg.name] = nested_arg.pset
}

// false
func (d*depgraph) _add_dep(dep, allow_unsatisfied=false) {
	debug = "--debug"
	in
	d._frozen_config.myopts
	nodeps = "--nodeps"
	in
	d._frozen_config.myopts
	if dep.blocker:

	is_slot_conflict_parent = any(
		dep.parent
	in
	conflict.pkgs[1:]
	for conflict
	in
	d._dynamic_config._package_tracker.slot_conflicts()
	)
	if (
		not nodeps
	and
	not
	dep.collapsed_priority.ignored
	and
	not
	dep.collapsed_priority.optional
	and
	not
	is_slot_conflict_parent
	):
	if dep.parent.onlydeps:
	return 1
	blocker = Blocker(
		atom = dep.atom,
		eapi = dep.parent.eapi,
		priority=dep.priority,
		root = dep.parent.root,
)
	d._dynamic_config._blocker_parents.add(blocker, dep.parent)
	return 1

	if dep.child is
nil:
	dep_pkg, existing_node = d._select_package(
		dep.root, dep.atom, onlydeps = dep.onlydeps
	) else:
	dep_pkg = dep.child
	existing_node = next(
		d._dynamic_config._package_tracker.match(
			dep.root, dep_pkg.slot_atom, installed = false
	),
	nil,
)

	if not dep_pkg:
	if dep.collapsed_priority.optional or
	dep.collapsed_priority.ignored:
	return 1

	if allow_unsatisfied:
	d._dynamic_config._unsatisfied_deps.append(dep)
	return 1

	if (
		d._dynamic_config._complete_mode
		and
	isinstance(dep.parent, Package)
	and
	dep.parent.installed
	and(
		dep.parent.depth
	is
	d._UNREACHABLE_DEPTH
	or(
		d._frozen_config.requested_depth
	is
	not
	true
	and
	dep.parent.depth >= d._frozen_config.requested_depth
	)
)
):
	inst_pkg, in_graph = d._select_pkg_from_installed(dep.root, dep.atom)
	if inst_pkg is
nil:
	d._dynamic_config._initially_unsatisfied_deps.append(dep)
	return 1

	d._dynamic_config._unsatisfied_deps_for_display.append(
		((dep.root, dep.atom),
	{
		"myparent": dep.parent
	})
)

	if d._dynamic_config._allow_backtracking:
	if (
		dep.parent not
	in
	d._dynamic_config._runtime_pkg_mask
	and
	dep.atom.package
	and
	dep.atom.slot_operator_built
	and
	d._slot_operator_unsatisfied_probe(dep)
	):
	d._slot_operator_unsatisfied_backtrack(dep)
	return 1

	if (
		dep.parent.installed
		and
	dep.parent
	in
	d._dynamic_config._runtime_pkg_mask
	and
	not
	any(
		d._iter_match_pkgs_any(dep.parent.root_config, dep.atom)
	)
	):
	d._dynamic_config._initially_unsatisfied_deps.append(dep)
	return 1

	dep_pkg, existing_node = d._select_package(
		dep.root,
		dep.atom.without_use
	if dep.atom.package
	else
	dep.atom,
		onlydeps = dep.onlydeps,
)
	if dep_pkg is
nil:

	for (
		dep_pkg,
	reasons,
) in
	d._dynamic_config._runtime_pkg_mask.items():
	if (
		dep.atom.match(dep_pkg)
		and
	len(reasons) == 1
	and
	not
	reasons.get("slot conflict", true)
	):
	d._dynamic_config._skip_restart = true
	return 0

	d._dynamic_config._backtrack_infos["missing dependency"] = dep
	d._dynamic_config._need_restart = true
	if debug:
	msg = []
msg.append("")
msg.append("")
msg.append("backtracking due to unsatisfied dep:")
msg.append("    parent: %s" % dep.parent)
msg.append("  priority: %s" % dep.priority)
msg.append("      root: %s" % dep.root)
msg.append("      atom: %s" % dep.atom)
msg.append("")
writemsg_level(
"".join("%s\n" % l for l in msg),
noiselevel= -1,
level = logging.DEBUG,
)

return 0

d._rebuild.add(dep_pkg, dep)

ignore = (
dep.collapsed_priority.ignored
and not d._dynamic_config._traverse_ignored_deps
)
if not ignore and not d._add_pkg(dep_pkg, dep):
return 0
return 1
}

func (d*depgraph) _check_slot_conflict( pkg, atom) {
	existing_node = next(
		d._dynamic_config._package_tracker.match(
			pkg.root, pkg.slot_atom, installed = false
	),
	nil,
)

	matches = nil
	if existing_node:
	matches = pkg.cpv == existing_node.cpv
	if pkg != existing_node and
	atom
	is
	not
nil:
	matches = atom.match(
		existing_node.with_use(d._pkg_use_enabled(existing_node))
	)

	return (existing_node, matches)
}

func (d*depgraph) _add_pkg( pkg, dep) {
	debug = "--debug"
	in
	d._frozen_config.myopts
	myparent = nil
	priority = nil
	depth = 0
	if dep is
nil:
	dep = Dependency()
	else:
	myparent = dep.parent
	priority = dep.priority
	depth = dep.depth
	if priority is
nil:
	priority = DepPriority()

	if debug:
	writemsg_level(
		"\n%s%s %s\n"
	% (
		"Child:".ljust(15),
		pkg,
		pkg_use_display(
			pkg,
			d._frozen_config.myopts,
			modified_use = d._pkg_use_enabled(pkg),
),
),
	level = logging.DEBUG,
		noiselevel=-1,
)
	if isinstance(myparent, (PackageArg, AtomArg)):
	writemsg_level(
		"%s%s\n"%("Parent Dep:".ljust(15), myparent),
		level = logging.DEBUG,
		noiselevel = -1,
) else:
	uneval = ""
	if (
		dep.atom
		and
	dep.atom.package
	and
	dep.atom
	is
	not
	dep.atom.unevaluated_atom
	):
	uneval = " (%s)" % (dep.atom.unevaluated_atom,)
	writemsg_level(
		"%s%s%s required by %s\n"
	% ("Parent Dep:".ljust(15), dep.atom, uneval, myparent),
	level = logging.DEBUG,
		noiselevel=-1,
)

	previously_added = pkg
	in
	d._dynamic_config.digraph

	pkgsettings = d._frozen_config.pkgsettings[pkg.root]

	arg_atoms = nil
	if true:
try:
	arg_atoms = list(d._iter_atoms_for_pkg(pkg))
	except
	portage.exception.InvalidDependString
	as
e:
	if not pkg.installed:
	raise
	del
	e

	if (
		not pkg.built
	and
	pkg._metadata.get("REQUIRED_USE")
	and
	eapi_has_required_use(pkg.eapi)
	):
	required_use_is_sat = check_required_use(
		pkg._metadata["REQUIRED_USE"],
		d._pkg_use_enabled(pkg),
		pkg.iuse.is_valid_flag,
		eapi = pkg.eapi,
)
	if not required_use_is_sat:
	if dep.atom is
	not
	nil
	and
	dep.parent
	is
	not
nil:
	d._add_parent_atom(pkg, (dep.parent, dep.atom))

	if arg_atoms:
	for parent_atom
	in
arg_atoms:
	parent, atom = parent_atom
	d._add_parent_atom(pkg, parent_atom)

	atom = dep.atom
	if atom is
nil:
	atom = Atom("=" + pkg.cpv)
	d._dynamic_config._unsatisfied_deps_for_display.append(
		((pkg.root, atom),
	{
		"myparent": dep.parent, "show_req_use": pkg
	})
)
	d._dynamic_config._required_use_unsatisfied = true
	d._dynamic_config._skip_restart = true
	d._dynamic_config.digraph.add(pkg, dep.parent, priority = priority)
	return 0

	if not pkg.onlydeps:

	existing_node, existing_node_matches = d._check_slot_conflict(
		pkg, dep.atom
	)
	if existing_node:
	if existing_node_matches:
	if pkg != existing_node:
	pkg = existing_node
	previously_added = true
try:
	arg_atoms = list(d._iter_atoms_for_pkg(pkg))
	except
	InvalidDependString
	as
e:
	if not pkg.installed:
	raise

	if debug:
	writemsg_level(
		"%s%s %s\n"
	% (
		"Re-used Child:".ljust(15),
		pkg,
		pkg_use_display(
			pkg,
			d._frozen_config.myopts,
			modified_use = d._pkg_use_enabled(pkg),
),
),
	level = logging.DEBUG,
		noiselevel=-1,
)
	elif(
		pkg.installed
	and
	isinstance(myparent, Package)
	and
	pkg.root == myparent.root
	and
	pkg.slot_atom == myparent.slot_atom
	):
	if debug:
	writemsg_level(
		"%s%s %s\n"
	% (
		"Replace Child:".ljust(15),
		pkg,
		pkg_use_display(
			pkg,
			d._frozen_config.myopts,
			modified_use = d._pkg_use_enabled(pkg),
),
),
	level = logging.DEBUG,
		noiselevel=-1,
)
	return 1

	else:
	if debug:
	writemsg_level(
		"%s%s %s\n"
	% (
		"Slot Conflict:".ljust(15),
		existing_node,
		pkg_use_display(
			existing_node,
			d._frozen_config.myopts,
			modified_use = d._pkg_use_enabled(existing_node),
),
),
	level = logging.DEBUG,
		noiselevel=-1,
)

	if not previously_added:
	d._dynamic_config._package_tracker.add_pkg(pkg)
	d._dynamic_config._filtered_trees[pkg.root][
		"porttree"
	].dbapi._clear_cache()
	d._check_masks(pkg)
	d._prune_highest_pkg_cache(pkg)

	if not pkg.installed:
try:
	pkgsettings.setinst(pkg.cpv, pkg._metadata)
	settings = d._frozen_config.roots[pkg.root].settings
	settings.unlock()
	settings.setinst(pkg.cpv, pkg._metadata)
	settings.lock()
	except
	portage.exception.InvalidDependString:
	if not pkg.installed:
	raise

	if arg_atoms:
	d._dynamic_config._set_nodes.add(pkg)

	if pkg != dep.parent or(priority.buildtime
	and
	not
	priority.satisfied):
	d._dynamic_config.digraph.add(pkg, dep.parent, priority = priority)
	if dep.atom is
	not
	nil
	and
	dep.parent
	is
	not
nil:
	d._add_parent_atom(pkg, (dep.parent, dep.atom))

	if arg_atoms:
	for parent_atom
	in
arg_atoms:
	parent, atom = parent_atom
	d._dynamic_config.digraph.add(pkg, parent, priority = priority)
	d._add_parent_atom(pkg, parent_atom)

	if arg_atoms and
	depth != 0:
	for parent, atom
	in
arg_atoms:
	if parent.reset_depth:
	depth = 0
	break

	if previously_added and
	depth != 0
	and
	isinstance(pkg.depth, int):
	if isinstance(depth, int):
	depth = min(pkg.depth, depth)
	else:
	depth = pkg.depth

	pkg.depth = depth
	deep = d._dynamic_config.myparams.get("deep", 0)
	update = "--update"
	in
	d._frozen_config.myopts

	dep.want_update = (
		not
	d._dynamic_config._complete_mode
	and(arg_atoms
	or
	update)
	and
	not
	d._too_deep(depth)
	)

	dep.child = pkg
	if (
		not pkg.onlydeps
	and
	dep.atom
	and(dep.atom.soname
	or
	dep.atom.slot_operator == "=")
):
	d._add_slot_operator_dep(dep)

	recurse = deep
	is
	true
	or
	not
	d._too_deep(d._depth_increment(depth, n = 1))
	dep_stack = d._dynamic_config._dep_stack
	if "recurse" not
	in
	d._dynamic_config.myparams:
	return 1
	if pkg.installed and
	not
recurse:
	dep_stack = d._dynamic_config._ignored_deps

	d._spinner_update()

	if not previously_added:
	dep_stack.append(pkg)
	return 1
}

func (d*depgraph) _add_installed_sonames(pkg) {
	if d._frozen_config.soname_deps_enabled and
	pkg.provides
	is
	not
nil:
	for atom
	in
	pkg.provides:
	d._dynamic_config._installed_sonames[(pkg.root,
	atom)].append(pkg)
}

// false
func (d*depgraph) _add_pkg_soname_deps(pkg, allow_unsatisfied=false) {
	if d._frozen_config.soname_deps_enabled and
	pkg.requires
	is
	not
nil:
	if isinstance(pkg.depth, int):
	depth = pkg.depth + 1
	else:
	depth = pkg.depth
	soname_provided = d._frozen_config.roots[
		pkg.root
	].settings.soname_provided
	for atom
	in
	pkg.requires:
	if atom in
soname_provided:
	continue
	dep = Dependency(
		atom = atom,
		blocker = false,
		depth=depth,
		parent = pkg,
		priority=d._priority(runtime = true),
	root = pkg.root,
)
	if not d._add_dep(dep, allow_unsatisfied = allow_unsatisfied):
	return false
	return true
}

func (d*depgraph) _remove_pkg(pkg) {
	debug = "--debug"
	in
	d._frozen_config.myopts
	if debug:
	writemsg_level(
		"Removing package: %s\n"%pkg, level = logging.DEBUG, noiselevel = -1
	)

try:
	children = [
child
for child in d._dynamic_config.digraph.child_nodes(pkg)
if child is not pkg
]
d._dynamic_config.digraph.remove(pkg)
except KeyError:
children = []

d._dynamic_config._package_tracker.discard_pkg(pkg)

d._dynamic_config._parent_atoms.pop(pkg, nil)
d._dynamic_config._set_nodes.discard(pkg)

for child in children:
try:
d._dynamic_config._parent_atoms[child] = set(
(parent, atom)
for (parent, atom) in d._dynamic_config._parent_atoms[child]
if parent is not pkg
)
except KeyError:
pass

slot_key = (pkg.root, pkg.slot_atom)
if slot_key in d._dynamic_config._slot_operator_deps:
d._dynamic_config._slot_operator_deps[slot_key] = [
dep
for dep in d._dynamic_config._slot_operator_deps[slot_key]
if dep.child is not pkg
]
if not d._dynamic_config._slot_operator_deps[slot_key]:
del d._dynamic_config._slot_operator_deps[slot_key]

d._dynamic_config._blocker_parents.discard(pkg)
d._dynamic_config._irrelevant_blockers.discard(pkg)
d._dynamic_config._unsolvable_blockers.discard(pkg)
if d._dynamic_config._blocked_pkgs is not nil:
d._dynamic_config._blocked_pkgs.discard(pkg)
d._dynamic_config._blocked_world_pkgs.pop(pkg, nil)

for child in children:
if (
child in d._dynamic_config.digraph
and not d._dynamic_config.digraph.parent_nodes(child)
):
d._remove_pkg(child)

d._dynamic_config._filtered_trees[pkg.root]["porttree"].dbapi._clear_cache()
d._dynamic_config._highest_pkg_cache.clear()
d._dynamic_config._highest_pkg_cache_cp_map.clear()
}

func (d*depgraph) _check_masks(pkg) {

	slot_key = (pkg.root, pkg.slot_atom)

	other_pkg = d._frozen_config._highest_license_masked.get(slot_key)
	if other_pkg is
	not
	nil
	and
	pkg < other_pkg:
	d._dynamic_config._masked_license_updates.add(other_pkg)
}

func (d*depgraph) _add_parent_atom( pkg, parent_atom){
	parent_atoms = d._dynamic_config._parent_atoms.get(pkg)
	if parent_atoms is
nil:
	parent_atoms = set()
	d._dynamic_config._parent_atoms[pkg] = parent_atoms
	parent_atoms.add(parent_atom)
}

func (d*depgraph) _add_slot_operator_dep(dep) {
	slot_key = (dep.root, dep.child.slot_atom)
	slot_info = d._dynamic_config._slot_operator_deps.get(slot_key)
	if slot_info is
nil:
	slot_info = []
d._dynamic_config._slot_operator_deps[slot_key] = slot_info
slot_info.append(dep)
}

// false
func (d*depgraph) _add_pkg_deps( pkg, allow_unsatisfied=false) {

	if not d._add_pkg_soname_deps(pkg, allow_unsatisfied = allow_unsatisfied):
	return false

	myroot = pkg.root
	metadata = pkg._metadata
	removal_action = "remove"
	in
	d._dynamic_config.myparams
	eapi_attrs = _get_eapi_attrs(pkg.eapi)

	edepend =
	{
	}
	for k
	in
	Package._dep_keys:
	edepend[k] = metadata[k]

	use_enabled = d._pkg_use_enabled(pkg)

	with_test_deps = (
		not
	removal_action
	and
	"with_test_deps"
	in
	d._dynamic_config.myparams
	and
	pkg.depth == 0
	and
	"test"
	not
	in
	use_enabled
	and
	pkg.iuse.is_valid_flag("test")
	and
	d._is_argument(pkg)
	)

	if (
		not pkg.built
	and
	"--buildpkgonly"
	in
	d._frozen_config.myopts
	and
	"deep"
	not
	in
	d._dynamic_config.myparams
	):
	edepend["RDEPEND"] = ""
	edepend["PDEPEND"] = ""
	edepend["IDEPEND"] = ""

	if (
		pkg.onlydeps
		and
	d._frozen_config.myopts.get("--onlydeps-with-rdeps") == "n"
	):
	edepend["RDEPEND"] = ""
	edepend["PDEPEND"] = ""
	edepend["IDEPEND"] = ""

	ignore_build_time_deps = false
	if pkg.built and
	not
removal_action:
	if d._dynamic_config.myparams.get("bdeps") in("y", "auto"):
	pass
	else:
	ignore_build_time_deps = true

	if removal_action and
	d._dynamic_config.myparams.get("bdeps", "y") == "n":
	edepend["DEPEND"] = ""
	edepend["BDEPEND"] = ""
	ignore_build_time_deps = true

	ignore_depend_deps = ignore_build_time_deps
	ignore_bdepend_deps = ignore_build_time_deps

	if removal_action:
	depend_root = myroot
	else:
	if eapi_attrs.bdepend:
	depend_root = pkg.root_config.settings["ESYSROOT"]
	else:
	depend_root = d._frozen_config._running_root.root
	root_deps = d._frozen_config.myopts.get("--root-deps")
	if root_deps is
	not
nil:
	if root_deps is
true:
	depend_root = myroot
	elif
	root_deps == "rdeps":
	ignore_depend_deps = true

	if not d._rebuild.rebuild:
	if ignore_depend_deps:
	edepend["DEPEND"] = ""
	if ignore_bdepend_deps:
	edepend["BDEPEND"] = ""

	deps = (
		(myroot, edepend["RDEPEND"], d._priority(runtime = true)),
	(
		d._frozen_config._running_root.root,
		edepend["IDEPEND"],
		d._priority(runtime = true),
),
	(myroot, edepend["PDEPEND"], d._priority(runtime_post = true)),
	(
		depend_root,
		edepend["DEPEND"],
		d._priority(
			buildtime = true,
		optional = (pkg.built
	or
	ignore_depend_deps),
	ignored = ignore_depend_deps,
),
),
	(
		d._frozen_config._running_root.root,
		edepend["BDEPEND"],
		d._priority(
			buildtime = true,
		optional = (pkg.built
	or
	ignore_bdepend_deps),
	ignored = ignore_bdepend_deps,
),
),
)

	debug = "--debug"
	in
	d._frozen_config.myopts

	for dep_root, dep_string, dep_priority
	in
deps:
	if not dep_string:
	continue
	if debug:
	writemsg_level(
		"\nParent:    %s\n"%(pkg, ), noiselevel = -1, level = logging.DEBUG
	)
	writemsg_level(
		"Depstring: %s\n"%(dep_string, ),
		noiselevel = -1,
		level = logging.DEBUG,
)
	writemsg_level(
		"Priority:  %s\n"%(dep_priority, ),
		noiselevel = -1,
		level = logging.DEBUG,
)

try:
	if (
		with_test_deps
		and
	"test"
	not
	in
	use_enabled
	and
	pkg.iuse.is_valid_flag("test")
	):
	test_deps = portage.dep.use_reduce(
		dep_string,
		uselist = use_enabled |
	{
		"test"
	},
	is_valid_flag = pkg.iuse.is_valid_flag,
		opconvert=true,
		token_class = Atom,
		eapi=pkg.eapi,
		subset =
	{
		"test"
	},
)

	if test_deps:
	test_deps = list(
		d._queue_disjunctive_deps(
			pkg,
			dep_root,
			d._priority(runtime_post = true),
	test_deps,
)
)

	if test_deps and
	not
	d._add_pkg_dep_string(
		pkg,
		dep_root,
		d._priority(runtime_post = true),
	test_deps,
		allow_unsatisfied,
):
	return 0

	dep_string = portage.dep.use_reduce(
		dep_string,
		uselist = use_enabled,
		is_valid_flag = pkg.iuse.is_valid_flag,
		opconvert=true,
		token_class = Atom,
		eapi=pkg.eapi,
)
	except
	portage.exception.InvalidDependString
	as
e:
	if not pkg.installed:
	raise
	del
	e

try:
	dep_string = portage.dep.use_reduce(
		dep_string,
		uselist = use_enabled,
		opconvert = true,
		token_class=Atom,
		eapi = pkg.eapi,
)
	except
	portage.exception.InvalidDependString
	as
e:
	d._dynamic_config._masked_installed.add(pkg)
	del
	e
	continue

try:
	dep_string = list(
		d._queue_disjunctive_deps(
			pkg, dep_root, dep_priority, dep_string
		)
	)
	except
	portage.exception.InvalidDependString
	as
e:
	if pkg.installed:
	d._dynamic_config._masked_installed.add(pkg)
	del
	e
	continue

	raise

	if not dep_string:
	continue

	if not d._add_pkg_dep_string(
		pkg, dep_root, dep_priority, dep_string, allow_unsatisfied
	):
	return 0

	d._dynamic_config._traversed_pkg_deps.add(pkg)
	return 1
}

func (d*depgraph) _add_pkg_dep_string(pkg, dep_root, dep_priority, dep_string, allow_unsatisfied) {
	_autounmask_backup = d._dynamic_config._autounmask
	if dep_priority.optional or
	dep_priority.ignored:
	d._dynamic_config._autounmask = false
try:
	return d._wrapped_add_pkg_dep_string(
		pkg, dep_root, dep_priority, dep_string, allow_unsatisfied
	)
finally:
	d._dynamic_config._autounmask = _autounmask_backup
}

func (d*depgraph) _ignore_dependency( atom, pkg, child, dep, mypriority, recurse_satisfied) {
	if not mypriority.satisfied:
	return false
	slot_operator_rebuild = false
	if (
		atom.slot_operator == "="
		and(pkg.root, pkg.slot_atom)
	in
	d._dynamic_config._slot_operator_replace_installed
	and
	mypriority.satisfied
	is
	not
	child
	and
	mypriority.satisfied.installed
	and
	child
	and
	not
	child.installed
	and(
		child.slot != mypriority.satisfied.slot
	or
	child.sub_slot != mypriority.satisfied.sub_slot
	)
):
	slot_operator_rebuild = true

	return (
		not
	atom.blocker
	and
	not
	recurse_satisfied
	and
	mypriority.satisfied.visible
	and
	dep.child
	is
	not
	nil
	and
	not
	dep.child.installed
	and
	not
	any(
		d._dynamic_config._package_tracker.match(
			dep.child.root, dep.child.slot_atom, installed = false
	)
)
	and
	not
	slot_operator_rebuild
	)
}

func (d*depgraph) _wrapped_add_pkg_dep_string(pkg, dep_root, dep_priority, dep_string, allow_unsatisfied) {
	if isinstance(pkg.depth, int):
	depth = pkg.depth + 1
	else:
	depth = pkg.depth

	deep = d._dynamic_config.myparams.get("deep", 0)
	recurse_satisfied = deep
	is
	true
	or
	depth <= deep
	debug = "--debug"
	in
	d._frozen_config.myopts
	strict = pkg.type_name != "installed"

	if debug:
	writemsg_level(
		"\nParent:    %s\n"%(pkg, ), noiselevel = -1, level = logging.DEBUG
	)
	dep_repr = portage.dep.paren_enclose(
		dep_string, unevaluated_atom = true, opconvert = true
	)
	writemsg_level(
		"Depstring: %s\n"%(dep_repr, ), noiselevel = -1, level = logging.DEBUG
	)
	writemsg_level(
		"Priority:  %s\n"%(dep_priority, ), noiselevel = -1, level = logging.DEBUG
	)

try:
	selected_atoms = d._select_atoms(
		dep_root,
		dep_string,
		myuse = d._pkg_use_enabled(pkg),
		parent = pkg,
		strict=strict,
		priority = dep_priority,
)
	except
	portage.exception.InvalidDependString:
	if pkg.installed:
	d._dynamic_config._masked_installed.add(pkg)
	return 1

	raise

	if debug:
	writemsg_level(
		"Candidates: %s\n" % ([str(x)
	for x
	in
	selected_atoms[pkg]], ),
noiselevel = -1,
level =logging.DEBUG,
)

root_config = d._frozen_config.roots[dep_root]
vardb = root_config.trees["vartree"].dbapi
traversed_virt_pkgs = set()

reinstall_atoms = d._frozen_config.reinstall_atoms
for atom, child in d._minimize_children(
pkg, dep_priority, root_config, selected_atoms[pkg]
):

is_virt = hasattr(atom, "_orig_atom")
atom = getattr(atom, "_orig_atom", atom)

if atom.blocker and (dep_priority.optional or dep_priority.ignored):
continue

mypriority = dep_priority.copy()
if not atom.blocker:

if atom.slot_operator == "=":
if mypriority.buildtime:
mypriority.buildtime_slot_op = true
if mypriority.runtime:
mypriority.runtime_slot_op = true

inst_pkgs = [
inst_pkg
for inst_pkg in reversed(vardb.match_pkgs(atom))
if not reinstall_atoms.findAtomForPackage(
inst_pkg, modified_use = d._pkg_use_enabled(inst_pkg)
)
]
if inst_pkgs:
for inst_pkg in inst_pkgs:
if d._pkg_visibility_check(inst_pkg):
mypriority.satisfied = inst_pkg
break
if not mypriority.satisfied:
mypriority.satisfied = inst_pkgs[0]

dep = Dependency(
atom = atom,
blocker = atom.blocker,
child = child,
depth = depth,
parent = pkg,
priority =mypriority,
root = dep_root,
)

ignored = false
if d._ignore_dependency(
atom, pkg, child, dep, mypriority, recurse_satisfied
):
myarg = nil
try:
myarg = next(d._iter_atoms_for_pkg(dep.child), nil)
except InvalidDependString:
if not dep.child.installed:
raise

if myarg is nil:
ignored = true
dep.child = nil
d._dynamic_config._ignored_deps.append(dep)

if not ignored:
if (
dep_priority.ignored
and not d._dynamic_config._traverse_ignored_deps
):
if is_virt and dep.child is not nil:
traversed_virt_pkgs.add(dep.child)
dep.child = nil
d._dynamic_config._ignored_deps.append(dep) else:
if not d._add_dep(dep, allow_unsatisfied =allow_unsatisfied):
return 0
if is_virt and dep.child is not nil:
traversed_virt_pkgs.add(dep.child)

selected_atoms.pop(pkg)

for virt_dep, atoms in selected_atoms.items():

virt_pkg = virt_dep.child
if virt_pkg not in traversed_virt_pkgs:
continue

if debug:
writemsg_level(
"\nCandidates: %s: %s\n" % (virt_pkg.cpv, [str(x) for x in atoms]),
noiselevel = -1,
level = logging.DEBUG,
)

if not dep_priority.ignored or d._dynamic_config._traverse_ignored_deps:

inst_pkgs = [
inst_pkg
for inst_pkg in reversed(vardb.match_pkgs(virt_dep.atom))
if not reinstall_atoms.findAtomForPackage(
inst_pkg, modified_use = d._pkg_use_enabled(inst_pkg)
)
]
if inst_pkgs:
for inst_pkg in inst_pkgs:
if d._pkg_visibility_check(inst_pkg):
virt_dep.priority.satisfied = inst_pkg
break
if not virt_dep.priority.satisfied:
virt_dep.priority.satisfied = inst_pkgs[0]

if not d._add_pkg(virt_pkg, virt_dep):
return 0

for atom, child in d._minimize_children(
pkg, d._priority(runtime = true), root_config, atoms
):

is_virt = hasattr(atom, "_orig_atom")
atom = getattr(atom, "_orig_atom", atom)

mypriority = d._priority(runtime =true)
if not atom.blocker:
inst_pkgs = [
inst_pkg
for inst_pkg in reversed(vardb.match_pkgs(atom))
if not reinstall_atoms.findAtomForPackage(
inst_pkg, modified_use = d._pkg_use_enabled(inst_pkg)
)
]
if inst_pkgs:
for inst_pkg in inst_pkgs:
if d._pkg_visibility_check(inst_pkg):
mypriority.satisfied = inst_pkg
break
if not mypriority.satisfied:
mypriority.satisfied = inst_pkgs[0]

dep = Dependency(
atom = atom,
blocker = atom.blocker,
child = child,
depth = virt_dep.depth,
parent = virt_pkg,
priority = mypriority,
root= dep_root,
collapsed_parent = pkg,
collapsed_priority = dep_priority,
)

ignored = false
if d._ignore_dependency(
atom, pkg, child, dep, mypriority, recurse_satisfied
):
myarg = nil
try:
myarg = next(d._iter_atoms_for_pkg(dep.child), nil)
except InvalidDependString:
if not dep.child.installed:
raise

if myarg is nil:
ignored = true
dep.child = nil
d._dynamic_config._ignored_deps.append(dep)

if not ignored:
if (
dep_priority.ignored
and not d._dynamic_config._traverse_ignored_deps
):
if is_virt and dep.child is not nil:
traversed_virt_pkgs.add(dep.child)
dep.child = nil
d._dynamic_config._ignored_deps.append(dep) else:
if not d._add_dep(dep, allow_unsatisfied = allow_unsatisfied):
return 0
if is_virt and dep.child is not nil:
traversed_virt_pkgs.add(dep.child)

if debug:
writemsg_level(
"\nExiting... %s\n" % (pkg,), noiselevel = -1, level = logging.DEBUG
)

return 1
}

func (d*depgraph) _minimize_children( parent, priority, root_config, atoms) {

	atom_pkg_map =
	{
	}

	for atom
	in
atoms:
	if atom.blocker:
	yield(atom, nil)
	continue
	dep_pkg, existing_node = d._select_package(
		root_config.root, atom, parent = parent
	)
	if dep_pkg is
nil:
	yield(atom, nil)
	continue
	atom_pkg_map[atom] = dep_pkg

	if len(atom_pkg_map) < 2:
	for item
	in
	atom_pkg_map.items():
	yield
	item
	return

	cp_pkg_map =
	{
	}
	pkg_atom_map =
	{
	}
	for atom, pkg
	in
	atom_pkg_map.items():
	pkg_atom_map.setdefault(pkg, set()).add(atom)
	cp_pkg_map.setdefault(pkg.cp, set()).add(pkg)

	for pkgs
	in
	cp_pkg_map.values():
	if len(pkgs) < 2:
	for pkg
	in
pkgs:
	for atom
	in
	pkg_atom_map[pkg]:
	yield(atom, pkg)
	continue

	atom_pkg_graph = digraph()
	cp_atoms = set()
	for pkg1
	in
pkgs:
	for atom
	in
	pkg_atom_map[pkg1]:
	cp_atoms.add(atom)
	atom_pkg_graph.add(pkg1, atom)
	atom_set = InternalPackageSet(
		initial_atoms = (atom,), allow_repo = true
	)
	for pkg2
	in
pkgs:
	if pkg2 is
pkg1:
	continue
	if atom_set.findAtomForPackage(
		pkg2, modified_use = d._pkg_use_enabled(pkg2)
):
	atom_pkg_graph.add(pkg2, atom)

	pkgs = sorted(pkg
	for pkg
	in
	pkgs
	if pkg.installed) +sorted(
		pkg
	for pkg
	in
	pkgs
	if not pkg.installed
	)

	for pkg
	in
pkgs:
	eliminate_pkg = true
	for atom
	in
	atom_pkg_graph.parent_nodes(pkg):
	if len(atom_pkg_graph.child_nodes(atom)) < 2:
	eliminate_pkg = false
	break
	if eliminate_pkg:
	atom_pkg_graph.remove(pkg)

	conflict_atoms = []
normal_atoms = []
abi_atoms = []
for atom in cp_atoms:
if atom.slot_operator_built:
abi_atoms.append(atom)
continue
conflict = false
for child_pkg in atom_pkg_graph.child_nodes(atom):
existing_node, matches = d._check_slot_conflict(child_pkg, atom)
if existing_node and not matches:
conflict = true
break
if conflict:
conflict_atoms.append(atom)
else:
normal_atoms.append(atom)

for atom in chain(abi_atoms, conflict_atoms, normal_atoms):
child_pkgs = atom_pkg_graph.child_nodes(atom)
if len(child_pkgs) > 1:
child_pkgs.sort()
yield (atom, child_pkgs[-1])
}

func (d*depgraph) _queue_disjunctive_deps(pkg, dep_root, dep_priority, dep_struct, _disjunctions_recursive=nil) {
	disjunctions = (
	[]
	if _disjunctions_recursive is
	nil else _disjunctions_recursive
	)
	for x
		in
	dep_struct:
	if isinstance(x, list):
	if x and
	x[0] == "||":
	disjunctions.append(x)
	else:
	for y
		in
	d._queue_disjunctive_deps(
		pkg,
		dep_root,
		dep_priority,
		x,
		_disjunctions_recursive = disjunctions,
):
	yield
	y
	else:
	if x.cp.startswith("virtual/"):
	disjunctions.append(x)
	else:
	yield
	x

	if _disjunctions_recursive is
	nil
	and
disjunctions:
	d._queue_disjunction(pkg, dep_root, dep_priority, disjunctions)
}

func (d*depgraph)_queue_disjunction(pkg, dep_root, dep_priority, dep_struct){
	d._dynamic_config._dep_disjunctive_stack.append(
		(pkg, dep_root, dep_priority, dep_struct)
	)
}

func (d*depgraph) _pop_disjunction(allow_unsatisfied) {
	(
		pkg,
		dep_root,
		dep_priority,
		dep_struct,
) = d._dynamic_config._dep_disjunctive_stack.pop()
	if not d._add_pkg_dep_string(
		pkg, dep_root, dep_priority, dep_struct, allow_unsatisfied
	):
	return 0
	return 1
}

func (d*depgraph) _priority( **kwargs) {
	if "remove" in
	d._dynamic_config.myparams:
	priority_constructor = UnmergeDepPriority
	else:
	priority_constructor = DepPriority
	return priority_constructor(**kwargs)
}

func (d*depgraph) _dep_expand( root_config, atom_without_category) {
	null_cp = portage.dep_getkey(
		insert_category_into_atom(atom_without_category, "null")
	)
	cat, atom_pn = portage.catsplit(null_cp)

	dbs = d._dynamic_config._filtered_trees[root_config.root]["dbs"]
	categories = set()
	for db, pkg_type, built, installed, db_keys
	in
dbs:
	for cat
	in
	db.categories:
	if db.cp_list("%s/%s"%(cat, atom_pn)):
	categories.add(cat)

	deps = []
for cat in categories:
deps.append(
Atom(
insert_category_into_atom(atom_without_category, cat),
allow_repo = true,
)
)
return deps
}

func (d*depgraph) _have_new_virt(root, atom_cp) {
	ret = false
	for (
		db,
	pkg_type,
		built,
		installed,
		db_keys,
) in
	d._dynamic_config._filtered_trees[root]["dbs"]:
	if db.cp_list(atom_cp):
	ret = true
	break
	return ret
}

func (d*depgraph) _iter_atoms_for_pkg(pkg) {
	depgraph_sets = d._dynamic_config.sets[pkg.root]
	atom_arg_map = depgraph_sets.atom_arg_map
	for atom
	in
	depgraph_sets.atoms.iterAtomsForPackage(pkg):
	if atom.cp != pkg.cp and
	d._have_new_virt(pkg.root, atom.cp):
	continue
	visible_pkgs = d._dynamic_config._visible_pkgs[pkg.root].match_pkgs(atom)
	visible_pkgs.reverse()  # descending
	order
	higher_slot = nil
	for visible_pkg
	in
visible_pkgs:
	if visible_pkg.cp != atom.cp:
	continue
	if pkg >= visible_pkg:
	break
	if pkg.slot_atom != visible_pkg.slot_atom:
	higher_slot = visible_pkg
	break
	if higher_slot is
	not
nil:
	continue
	for arg
	in
	atom_arg_map[(atom,
	pkg.root)]:
if isinstance(arg, PackageArg) and arg.package != pkg:
continue
yield arg, atom
}

func (d*depgraph) select_files( args) {
	def
	spinner_cb():
	d._frozen_config.spinner.update()
	spinner_cb.handle = d._event_loop.call_soon(spinner_cb)

	spinner_cb.handle = nil
try:
	spinner = d._frozen_config.spinner
	if spinner is
	not
	nil
	and
	spinner.update
	is
	not
	spinner.update_quiet:
	spinner_cb.handle = d._event_loop.call_soon(spinner_cb)
	return d._select_files(args)
finally:
	if spinner_cb.handle is
	not
nil:
	spinner_cb.handle.cancel()
}

func (d*depgraph) _select_files(myfiles) {
	d._load_vdb()
	if (
		d._frozen_config.soname_deps_enabled
		and
	"remove"
	not
	in
	d._dynamic_config.myparams
	):
	d._index_binpkgs()
	debug = "--debug"
	in
	d._frozen_config.myopts
	root_config = d._frozen_config.roots[d._frozen_config.target_root]
	sets = root_config.sets
	depgraph_sets = d._dynamic_config.sets[root_config.root]
	myfavorites = []
eroot = root_config.root
root = root_config.settings["ROOT"]
vardb = d._frozen_config.trees[eroot]["vartree"].dbapi
real_vardb = d._frozen_config._trees_orig[eroot]["vartree"].dbapi
portdb = d._frozen_config.trees[eroot]["porttree"].dbapi
bindb = d._frozen_config.trees[eroot]["bintree"].dbapi
pkgsettings = d._frozen_config.pkgsettings[eroot]
args = []
onlydeps = "--onlydeps" in d._frozen_config.myopts
lookup_owners = []
for x in myfiles:
if x.endswith(".tbz2") or x.endswith(SUPPORTED_GPKG_EXTENSIONS):
if not os.path.exists(x):
if os.path.exists(os.path.join(pkgsettings["PKGDIR"], "All", x)):
x = os.path.join(pkgsettings["PKGDIR"], "All", x)
elif os.path.exists(os.path.join(pkgsettings["PKGDIR"], x)):
x = os.path.join(pkgsettings["PKGDIR"], x) else:
writemsg(
"\n\n!!! Binary package '" + str(x) + "' does not exist.\n",
noiselevel = -1,
)
writemsg(
"!!! Please ensure the binpkg exists as specified.\n\n",
noiselevel = -1,
)
return 0, myfavorites
binpkg_format = get_binpkg_format(x)
if binpkg_format == "xpak":
mytbz2 = portage.xpak.tbz2(x)
mykey = nil
cat = mytbz2.getfile("CATEGORY")
elif binpkg_format == "gpkg":
mygpkg = portage.gpkg.gpkg(d.frozen_config, nil, x)
mykey = nil
cat = mygpkg.get_metadata("CATEGORY")
else:
raise InvalidBinaryPackageFormat(x)

if cat is not nil:
cat = _unicode_decode(
cat.strip(), encoding = _encodings["repo.content"]
)
mykey = cat + "/" + os.path.basename(x)[:-5]

if mykey is nil:
writemsg(
colorize(
"BAD",
"\n*** Package is missing CATEGORY metadata: %s.\n\n" % x,
),
noiselevel = -1,
)
d._dynamic_config._skip_restart = true
return 0, myfavorites

x = os.path.realpath(x)
for pkg in d._iter_match_pkgs(
root_config, "binary", Atom("=%s" % mykey)
):
if x == os.path.realpath(bindb.bintree.getname(pkg.cpv)):
break else:
writemsg(
"\n%s\n\n"
% colorize(
"BAD",
"*** "
+ _(
"You need to adjust PKGDIR to emerge "
"this package: %s"
)
% x,
),
noiselevel = -1,
)
d._dynamic_config._skip_restart = true
return 0, myfavorites

args.append(PackageArg(arg = x, package = pkg, root_config = root_config))
elif x.endswith(".ebuild"):
ebuild_path = portage.util.normalize_path(os.path.abspath(x))
pkgdir = os.path.dirname(ebuild_path)
tree_root = os.path.dirname(os.path.dirname(pkgdir))
cp = pkgdir[len(tree_root) + 1:]
error_msg = (
"\n\n!!! '%s' is not in a valid ebuild repository "
"hierarchy or does not exist\n"
) % x
if not portage.isvalidatom(cp):
writemsg(error_msg, noiselevel = -1)
return 0, myfavorites
cat = portage.catsplit(cp)[0]
mykey = cat + "/" + os.path.basename(ebuild_path[:-7])
if not portage.isvalidatom("=" + mykey):
writemsg(error_msg, noiselevel = -1)
return 0, myfavorites
ebuild_path = portdb.findname(mykey)
if ebuild_path:
if ebuild_path != os.path.join(
os.path.realpath(tree_root), cp, os.path.basename(ebuild_path)
):
writemsg(
colorize(
"BAD",
"\n*** You need to adjust repos.conf to emerge this package.\n\n",
),
noiselevel = -1,
)
d._dynamic_config._skip_restart = true
return 0, myfavorites
if mykey not in portdb.xmatch(
"match-visible", portage.cpv_getkey(mykey)
):
writemsg(
colorize(
"BAD",
"\n*** You are emerging a masked package. It is MUCH better to use\n",
),
noiselevel = -1,
)
writemsg(
colorize(
"BAD",
"*** /etc/portage/package.* to accomplish this. See portage(5) man\n",
),
noiselevel = -1,
)
writemsg(
colorize("BAD", "*** page for details.\n"), noiselevel = -1
)
countdown(
int(d._frozen_config.settings["EMERGE_WARNING_DELAY"]),
"Continuing...",
) else:
writemsg(error_msg, noiselevel =-1)
return 0, myfavorites
pkg = d._pkg(
mykey,
"ebuild",
root_config,
onlydeps = onlydeps,
myrepo = portdb.getRepositoryName(
os.path.dirname(os.path.dirname(os.path.dirname(ebuild_path)))
),
)
args.append(PackageArg(arg = x, package =pkg, root_config = root_config))
elif x.startswith(os.path.sep):
if not x.startswith(eroot):
portage.writemsg(
("\n\n!!! '%s' does not start with" + " $EROOT.\n") % x,
noiselevel = -1,
)
d._dynamic_config._skip_restart = true
return 0, []
lookup_owners.append(x)
elif x.startswith("." + os.sep) or x.startswith(".." + os.sep):
f = os.path.abspath(x)
if not f.startswith(eroot):
portage.writemsg(
(
"\n\n!!! '%s' (resolved from '%s') does not start with"
+ " $EROOT.\n"
)
% (f, x),
noiselevel = -1,
)
d._dynamic_config._skip_restart = true
return 0, []
lookup_owners.append(f) else:
if x in ("system", "world"):
x = SETPREFIX + x
if x.startswith(SETPREFIX):
s = x[len(SETPREFIX):]
if s not in sets:
raise portage.exception.PackageSetNotFound(s)
if s in depgraph_sets.sets:
continue

try:
set_atoms = root_config.setconfig.getSetAtoms(s)
except portage.exception.PackageSetNotFound as e:
writemsg_level("\n\n", level = logging.ERROR, noiselevel = -1)
for pset in list(depgraph_sets.sets.values()) + [sets[s]]:
for error_msg in pset.errors:
writemsg_level(
"%s\n" % (error_msg, ),
level = logging.ERROR,
noiselevel = -1,
)

writemsg_level(
(
"emerge: the given set '%s' "
"contains a non-existent set named '%s'.\n"
)
% (s, e),
level = logging.ERROR,
noiselevel = -1,
)
if (
s in ("world", "selected")
and SETPREFIX + e.value in sets["selected"]
):
writemsg_level(
(
"Use `emerge --deselect %s%s` to "
"remove this set from world_sets.\n"
)
% (
SETPREFIX,
e,
),
level =logging.ERROR,
noiselevel = -1,
)
writemsg_level("\n", level = logging.ERROR, noiselevel = -1)
return false, myfavorites

pset = sets[s]
depgraph_sets.sets[s] = pset
args.append(SetArg(arg = x, pset =pset, root_config = root_config))
continue
if not is_valid_package_atom(x, allow_repo = true):
portage.writemsg(
"\n\n!!! '%s' is not a valid package atom.\n" % x, noiselevel= -1
)
portage.writemsg("!!! Please check ebuild(5) for full details.\n")
portage.writemsg(
"!!! (Did you specify a version but forget to prefix with '='?)\n"
)
d._dynamic_config._skip_restart = true
return (0, [])
if "/" in x.split(":")[0]:
args.append(
AtomArg(
arg = x,
atom = Atom(x, allow_repo = true),
root_config = root_config,
)
)
continue
expanded_atoms = d._dep_expand(root_config, x)
installed_cp_set = set()
for atom in expanded_atoms:
if vardb.cp_list(atom.cp):
installed_cp_set.add(atom.cp)

if len(installed_cp_set) > 1:
non_virtual_cps = set()
for atom_cp in installed_cp_set:
if not atom_cp.startswith("virtual/"):
non_virtual_cps.add(atom_cp)
if len(non_virtual_cps) == 1:
installed_cp_set = non_virtual_cps

if len(expanded_atoms) > 1:
number_of_virtuals = 0
for expanded_atom in expanded_atoms:
if expanded_atom.cp.startswith(
("acct-group/", "acct-user/", "virtual/")
):
number_of_virtuals += 1 else:
candidate = expanded_atom
if len(expanded_atoms) - number_of_virtuals == 1:
expanded_atoms = [candidate]

if len(expanded_atoms) > 1:
writemsg("\n\n", noiselevel = -1)
ambiguous_package_name(
x,
expanded_atoms,
root_config,
d._frozen_config.spinner,
d._frozen_config.myopts,
)
d._dynamic_config._skip_restart = true
return false, myfavorites
if expanded_atoms:
atom = expanded_atoms[0] else:
null_atom = Atom(
insert_category_into_atom(x, "null"), allow_repo = true
)
cat, atom_pn = portage.catsplit(null_atom.cp)
virts_p = root_config.settings.get_virts_p().get(atom_pn)
if virts_p:
atom = Atom(
null_atom.replace("null/", "virtual/", 1), allow_repo = true
) else:
atom = null_atom

if atom.use and atom.use.conditional:
writemsg(
(
"\n\n!!! '%s' contains a conditional "
+ "which is not allowed.\n"
)
% (x, ),
noiselevel = -1,
)
writemsg("!!! Please check ebuild(5) for full details.\n")
d._dynamic_config._skip_restart = true
return (0, [])

args.append(AtomArg(arg = x, atom = atom, root_config =root_config))

if lookup_owners:
relative_paths = []
search_for_multiple = false
if len(lookup_owners) > 1:
search_for_multiple = true

for x in lookup_owners:
if not search_for_multiple and os.path.isdir(x):
search_for_multiple = true
relative_paths.append(x[len(root) - 1:])

owners = set()
for pkg, relative_path in real_vardb._owners.iter_owners(relative_paths):
owners.add(pkg.mycpv)
if not search_for_multiple:
break

if not owners:
portage.writemsg(
("\n\n!!! '%s' is not claimed " + "by any package.\n")
% lookup_owners[0],
noiselevel = -1,
)
d._dynamic_config._skip_restart = true
return 0, []

for cpv in owners:
pkg = vardb._pkg_str(cpv, nil)
atom = Atom("%s:%s" % (pkg.cp, pkg.slot))
args.append(AtomArg(arg = atom, atom = atom, root_config= root_config))

if "--update" in d._frozen_config.myopts:

d._set_args(args)
greedy_args = []
for arg in args:
greedy_args.append(arg)
if not isinstance(arg, AtomArg):
continue
for atom in d._greedy_slots(arg.root_config, arg.atom):
greedy_args.append(
AtomArg(arg = arg.arg, atom = atom, root_config = arg.root_config)
)

d._set_args(greedy_args)
del greedy_args

revised_greedy_args = []
for arg in args:
revised_greedy_args.append(arg)
if not isinstance(arg, AtomArg):
continue
for atom in d._greedy_slots(
arg.root_config, arg.atom, blocker_lookahead = true
):
revised_greedy_args.append(
AtomArg(arg = arg.arg, atom = atom, root_config = arg.root_config)
)
args = revised_greedy_args
del revised_greedy_args

args.extend(d._gen_reinstall_sets())
d._set_args(args)

myfavorites = set(myfavorites)
for arg in args:
if isinstance(arg, (AtomArg, PackageArg)):
myfavorites.add(arg.atom)
elif isinstance(arg, SetArg):
if not arg.internal:
myfavorites.add(arg.arg)
myfavorites = list(myfavorites)

if debug:
portage.writemsg("\n", noiselevel = -1)
d._dynamic_config._initial_arg_list = args[:]

return d._resolve(myfavorites)
}

func (d*depgraph) _gen_reinstall_sets() {

	atom_list = []
for root, atom in d._rebuild.rebuild_list:
atom_list.append((root, "__auto_rebuild__", atom))
for root, atom in d._rebuild.reinstall_list:
atom_list.append((root, "__auto_reinstall__", atom))
for root, atom in d._dynamic_config._slot_operator_replace_installed:
atom_list.append((root, "__auto_slot_operator_replace_installed__", atom))

set_dict = {}
for root, set_name, atom in atom_list:
set_dict.setdefault((root, set_name), []).append(atom)

for (root, set_name), atoms in set_dict.items():
yield SetArg(
arg = (SETPREFIX + set_name),
pset = InternalPackageSet(initial_atoms= atoms),
force_reinstall = true,
internal =true,
reset_depth = false,
root_config = d._frozen_config.roots[root],
)
}

func (d*depgraph) _resolve( myfavorites) {
	debug = "--debug"
	in
	d._frozen_config.myopts
	onlydeps = "--onlydeps"
	in
	d._frozen_config.myopts
	myroot = d._frozen_config.target_root
	pkgsettings = d._frozen_config.pkgsettings[myroot]
	pprovideddict = pkgsettings.pprovideddict
	virtuals = pkgsettings.getvirtuals()
	args = d._dynamic_config._initial_arg_list[:]

	for arg
	in
	d._expand_set_args(args, add_to_digraph = true):
	for atom
	in
	sorted(arg.pset.getAtoms()):
	d._spinner_update()
	dep = Dependency(atom = atom, onlydeps = onlydeps, root=myroot, parent = arg)
try:
	pprovided = pprovideddict.get(atom.cp)
	if pprovided and
	portage.match_from_list(atom, pprovided):
	d._dynamic_config._pprovided_args.append((arg, atom))
	continue
	if isinstance(arg, PackageArg):
	if (
		not d._add_pkg(arg.package, dep)
	or
	not
	d._create_graph()
	):
	if not d.need_restart():
	writemsg(
		(
			"\n\n!!! Problem "
	+"resolving dependencies for %s\n"
	)
	% arg.arg,
		noiselevel = -1,
)
	return 0, myfavorites
	continue
	if debug:
	writemsg_level(
		"\n      Arg: %s\n     Atom: %s\n"%(arg, atom),
		noiselevel = -1,
		level = logging.DEBUG,
)
	pkg, existing_node = d._select_package(
		myroot, atom, onlydeps = onlydeps
	)
	if not pkg:
	pprovided_match = false
	for virt_choice
	in
	virtuals.get(atom.cp,[]):
	expanded_atom = portage.dep.Atom(
		atom.replace(atom.cp, virt_choice.cp, 1)
	)
	pprovided = pprovideddict.get(expanded_atom.cp)
	if pprovided and
	portage.match_from_list(
		expanded_atom, pprovided
	):
	d._dynamic_config._pprovided_args.append((arg, atom))
	pprovided_match = true
	break
	if pprovided_match:
	continue

	excluded = false
	for any_match
	in
	d._iter_match_pkgs_any(
		d._frozen_config.roots[myroot], atom
	):
	if d._frozen_config.excluded_pkgs.findAtomForPackage(
		any_match, modified_use = d._pkg_use_enabled(any_match)
):
	excluded = true
	break
	if excluded:
	continue

	if not(
		isinstance(arg, SetArg)
		and
	arg.name
	in("selected", "world")
	):
	d._dynamic_config._unsatisfied_deps_for_display.append(
		((myroot, atom),
	{
		"myparent": arg
	})
)
	return 0, myfavorites

	d._dynamic_config._missing_args.append((arg, atom))
	continue
	if atom.cp != pkg.cp:
	expanded_atom = atom.replace(atom.cp, pkg.cp)
	pprovided = pprovideddict.get(pkg.cp)
	if pprovided and
	portage.match_from_list(
		expanded_atom, pprovided
	):
	d._dynamic_config._pprovided_args.append((arg, atom))
	continue
	if (
		pkg.installed
		and
	"selective"
	not
	in
	d._dynamic_config.myparams
	and
	not
	d._frozen_config.excluded_pkgs.findAtomForPackage(
		pkg, modified_use = d._pkg_use_enabled(pkg)
	)
):
	d._dynamic_config._unsatisfied_deps_for_display.append(
		((myroot, atom),
	{
		"myparent": arg
	})
)
	if not(
		isinstance(arg, SetArg)
		and
	arg.name
	in("selected", "system", "world")
	):
	return 0, myfavorites

	if not d._add_pkg(pkg, dep):
	if d.need_restart():
	pass
	elif
	isinstance(arg, SetArg):
	writemsg(
		(
			"\n\n!!! Problem resolving "
	+"dependencies for %s from %s\n"
	)
	% (atom, arg.arg),
	noiselevel = -1,
) else:
	writemsg(
		("\n\n!!! Problem resolving " + "dependencies for %s\n")
	% (atom,),
	noiselevel = -1,
)
	return 0, myfavorites

	except
	SystemExit
	as
e:
	raise  # Needed else can
	't exit
	except
	Exception
	as
e:
	writemsg(
		"\n\n!!! Problem in '%s' dependencies.\n"%atom, noiselevel = -1
	)
	writemsg(
		"!!! %s %s\n"%(str(e), str(getattr(e, "__module__", nil)))
	)
	raise

	if not d._create_graph():
	d._apply_parent_use_changes()
	return 0, myfavorites

try:
	d.altlist()
	except
	d._unknown_internal_error:
	return false, myfavorites

	have_slot_conflict = any(d._dynamic_config._package_tracker.slot_conflicts())
	if (have_slot_conflict and
	not
	d._accept_blocker_conflicts()) or(
		d._dynamic_config._allow_backtracking
	and
	"slot conflict"
	in
	d._dynamic_config._backtrack_infos
	):
	return false, myfavorites

	if d._rebuild.trigger_rebuilds():
	backtrack_infos = d._dynamic_config._backtrack_infos
	config = backtrack_infos.setdefault("config",
	{
	})
	config["rebuild_list"] = d._rebuild.rebuild_list
	config["reinstall_list"] = d._rebuild.reinstall_list
	d._dynamic_config._need_restart = true
	return false, myfavorites

	if (
		"config" in
	d._dynamic_config._backtrack_infos
	and(
		"slot_operator_mask_built"
	in
	d._dynamic_config._backtrack_infos["config"]
	or
	"slot_operator_replace_installed"
	in
	d._dynamic_config._backtrack_infos["config"]
	)
	and
	d.need_restart()
	):
	return false, myfavorites

	if (
		not d._dynamic_config._prune_rebuilds
	and
	d._dynamic_config._slot_operator_replace_installed
	and
	d._get_missed_updates()
	):
	backtrack_infos = d._dynamic_config._backtrack_infos
	config = backtrack_infos.setdefault("config",
	{
	})
	config["prune_rebuilds"] = true
	d._dynamic_config._need_restart = true
	return false, myfavorites

	if d.need_restart():
	return false, myfavorites

	if (
		"--fetchonly" not
	in
	d._frozen_config.myopts
	and
	"--buildpkgonly"
	in
	d._frozen_config.myopts
	):
	graph_copy = d._dynamic_config.digraph.copy()
	removed_nodes = set()
	for node
	in
graph_copy:
	if not isinstance(node, Package)
	or
	node.operation == "nomerge":
	removed_nodes.add(node)
	graph_copy.difference_update(removed_nodes)
	if not graph_copy.hasallzeros(
		ignore_priority = DepPrioritySatisfiedRange.ignore_medium
	):
	d._dynamic_config._buildpkgonly_deps_unsatisfied = true
	d._dynamic_config._skip_restart = true
	return false, myfavorites

	quickpkg_root = (
		normalize_path(
			os.path.abspath(
				d._frozen_config.myopts.get(
					"--quickpkg-direct-root",
					d._frozen_config._running_root.settings["ROOT"],
				)
			)
		).rstrip(os.path.sep)
	+os.path.sep
	)
	if (
		d._frozen_config.myopts.get("--quickpkg-direct", "n") == "y"
		and
	d._frozen_config.settings["ROOT"] != quickpkg_root
	and
	d._frozen_config._running_root.settings["ROOT"] == quickpkg_root
	):
	running_root = d._frozen_config._running_root.root
	for node
	in
	d._dynamic_config.digraph:
	if (
		isinstance(node, Package)
		and
	node.operation
	in("merge", "uninstall")
	and
	node.root == running_root
	):
	d._dynamic_config._quickpkg_direct_deps_unsatisfied = true
	d._dynamic_config._skip_restart = true
	return false, myfavorites

	if (
		not d._dynamic_config._prune_rebuilds
	and
	d._ignored_binaries_autounmask_backtrack()
	):
	config = d._dynamic_config._backtrack_infos.setdefault("config",
	{
	})
	config["prune_rebuilds"] = true
	d._dynamic_config._need_restart = true
	return false, myfavorites

	if d._have_autounmask_changes():
	d._dynamic_config._success_without_autounmask = true
	if (
		d._frozen_config.myopts.get("--autounmask-continue") is
	true
	and
	"--pretend"
	not
	in
	d._frozen_config.myopts
	):
	if d._display_autounmask(autounmask_continue = true):
	d._apply_autounmask_continue_state()
	d._dynamic_config._need_config_reload = true
	return true, myfavorites
	return false, myfavorites

	return (true, myfavorites)
}

func (d*depgraph) _apply_autounmask_continue_state() {
	for node
	in
	d._dynamic_config._serialized_tasks_cache:
	if isinstance(node, Package):
	effective_use = d._pkg_use_enabled(node)
	if effective_use != node.use.enabled:
	node._metadata["USE"] = " ".join(effective_use)
}

func (d*depgraph) _apply_parent_use_changes() {
	if (
		d._dynamic_config._unsatisfied_deps_for_display
		and
	d._dynamic_config._autounmask
	):
	remaining_items = []
for item in d._dynamic_config._unsatisfied_deps_for_display:
pargs, kwargs = item
kwargs = kwargs.copy()
kwargs["collect_use_changes"] = true
if not d._show_unsatisfied_dep(*pargs, **kwargs):
remaining_items.append(item)
if len(remaining_items) != len(
d._dynamic_config._unsatisfied_deps_for_display
):
d._dynamic_config._unsatisfied_deps_for_display = remaining_items
}

func (d*depgraph) _set_args( args) {

	set_atoms =
	{
	}
	non_set_atoms =
	{
	}
	for root
	in
	d._dynamic_config.sets:
	depgraph_sets = d._dynamic_config.sets[root]
	depgraph_sets.sets.setdefault(
		"__non_set_args__", InternalPackageSet(allow_repo = true)
).clear()
	depgraph_sets.atoms.clear()
	depgraph_sets.atom_arg_map.clear()
	set_atoms[root] = []
non_set_atoms[root] = []

for arg in d._expand_set_args(args, add_to_digraph= false):
atom_arg_map = d._dynamic_config.sets[arg.root_config.root].atom_arg_map
if isinstance(arg, SetArg):
atom_group = set_atoms[arg.root_config.root]
else:
atom_group = non_set_atoms[arg.root_config.root]

for atom in arg.pset.getAtoms():
atom_group.append(atom)
atom_key = (atom, arg.root_config.root)
refs = atom_arg_map.get(atom_key)
if refs is nil:
refs = []
atom_arg_map[atom_key] = refs
if arg not in refs:
refs.append(arg)

for root in d._dynamic_config.sets:
depgraph_sets = d._dynamic_config.sets[root]
depgraph_sets.atoms.update(
chain(set_atoms.get(root, []), non_set_atoms.get(root, []))
)
depgraph_sets.sets["__non_set_args__"].update(non_set_atoms.get(root, []))

d._dynamic_config._highest_pkg_cache.clear()
d._dynamic_config._highest_pkg_cache_cp_map.clear()
for trees in d._dynamic_config._filtered_trees.values():
trees["porttree"].dbapi._clear_cache()
}

// false
func (d*depgraph) _greedy_slots( root_config, atom, blocker_lookahead=false) {
	highest_pkg, in_graph = d._select_package(root_config.root, atom)
	if highest_pkg is
nil:
	return []
vardb = root_config.trees["vartree"].dbapi
slots = set()
for cpv in vardb.match(atom):
pkg = vardb._pkg_str(cpv, nil)
if pkg.cp == highest_pkg.cp:
slots.add(pkg.slot)

slots.add(highest_pkg.slot)
if len(slots) == 1:
return []
greedy_pkgs = []
slots.remove(highest_pkg.slot)
while slots:
slot = slots.pop()
slot_atom = portage.dep.Atom("%s:%s" % (highest_pkg.cp, slot))
pkg, in_graph = d._select_package(root_config.root, slot_atom)
if pkg is not nil and pkg.cp == highest_pkg.cp and pkg < highest_pkg:
greedy_pkgs.append(pkg)
if not greedy_pkgs:
return []
if not blocker_lookahead:
return [pkg.slot_atom for pkg in greedy_pkgs]

blockers = {}
blocker_dep_keys = Package._dep_keys
for pkg in greedy_pkgs + [highest_pkg]:
dep_str = " ".join(pkg._metadata[k] for k in blocker_dep_keys)
try:
selected_atoms = d._select_atoms(
pkg.root,
dep_str,
d._pkg_use_enabled(pkg),
parent = pkg,
strict= true,
)
except portage.exception.InvalidDependString:
continue
blocker_atoms = []
for atoms in selected_atoms.values():
blocker_atoms.extend(x for x in atoms if x.blocker)
blockers[pkg] = InternalPackageSet(initial_atoms = blocker_atoms)

if highest_pkg not in blockers:
return []

greedy_pkgs = [pkg for pkg in greedy_pkgs if pkg in blockers]

greedy_pkgs = [
pkg
for pkg in greedy_pkgs
if not (
blockers[highest_pkg].findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
)
or blockers[pkg].findAtomForPackage(
highest_pkg, modified_use = d._pkg_use_enabled(highest_pkg)
)
)
]

if not greedy_pkgs:
return []

discard_pkgs = set()
greedy_pkgs.sort(reverse = true)
for i in range (len(greedy_pkgs) - 1):
pkg1 = greedy_pkgs[i]
if pkg1 in discard_pkgs:
continue
for j in range (i + 1, len(greedy_pkgs)):
pkg2 = greedy_pkgs[j]
if pkg2 in discard_pkgs:
continue
if blockers[pkg1].findAtomForPackage(
pkg2, modified_use = d._pkg_use_enabled(pkg2)
) or blockers[pkg2].findAtomForPackage(
pkg1, modified_use = d._pkg_use_enabled(pkg1)
):
discard_pkgs.add(pkg2)

return [pkg.slot_atom for pkg in greedy_pkgs if pkg not in discard_pkgs]
}

func (d*depgraph) _select_atoms_from_graph( *pargs, **kwargs) {
	kwargs["trees"] = d._dynamic_config._graph_trees
	return d._select_atoms_highest_available(*pargs, **kwargs)
}

func (d*depgraph) _select_atoms_highest_available(
root,
depstring,
myuse=nil,
parent=nil,
strict=true,
trees=nil,
priority=nil,
) {

	if not isinstance(depstring, list):
	eapi = nil
	is_valid_flag = nil
	if parent is
	not
nil:
	eapi = parent.eapi
	if not parent.installed:
	is_valid_flag = parent.iuse.is_valid_flag
	depstring = portage.dep.use_reduce(
		depstring,
		uselist = myuse,
		opconvert = true,
		token_class=Atom,
		is_valid_flag = is_valid_flag,
		eapi=eapi,
)

	if (
		d._dynamic_config.myparams.get("ignore_built_slot_operator_deps", "n")
	== "y"
	and
	parent
	and
	parent.built
	):
	ignore_built_slot_operator_deps(depstring)

	pkgsettings = d._frozen_config.pkgsettings[root]
	if trees is
nil:
	trees = d._dynamic_config._filtered_trees
	mytrees = trees[root]
	atom_graph = digraph()
	if true:
	_autounmask_backup = d._dynamic_config._autounmask
	d._dynamic_config._autounmask = false
	backup_parent = d._select_atoms_parent
	backup_state = mytrees.copy()
try:
	d._select_atoms_parent = nil
	mytrees.pop("pkg_use_enabled", nil)
	mytrees.pop("parent", nil)
	mytrees.pop("atom_graph", nil)
	mytrees.pop("circular_dependency", nil)
	mytrees.pop("priority", nil)

	mytrees["pkg_use_enabled"] = d._pkg_use_enabled
	if parent is
	not
nil:
	d._select_atoms_parent = parent
	mytrees["parent"] = parent
	mytrees["atom_graph"] = atom_graph
	mytrees[
		"circular_dependency"
	] = d._dynamic_config._circular_dependency
	if priority is
	not
nil:
	mytrees["priority"] = priority

	mycheck = portage.dep_check(
		depstring, nil, pkgsettings, myuse = myuse, myroot = root, trees=trees
	)
finally:
	d._dynamic_config._autounmask = _autounmask_backup
	d._select_atoms_parent = backup_parent
	mytrees.pop("pkg_use_enabled", nil)
	mytrees.pop("parent", nil)
	mytrees.pop("atom_graph", nil)
	mytrees.pop("circular_dependency", nil)
	mytrees.pop("priority", nil)
	mytrees.update(backup_state)
	if not mycheck[0]:
	raise
	portage.exception.InvalidDependString(mycheck[1])
	if parent is
nil:
	selected_atoms = mycheck[1]
	elif
	parent
	not
	in
atom_graph:
	selected_atoms =
	{
	parent:
		mycheck[1]
	}
	else:
	if isinstance(parent.depth, int):
	virt_depth = parent.depth + 1
	else:
	virt_depth = parent.depth

	chosen_atom_ids = frozenset(
		chain(
			(id(atom)
	for atom
	in
	mycheck[1]),
	(
		id(atom._orig_atom)
	for atom
	in
	mycheck[1]
	if hasattr(atom, "_orig_atom")
),
)
)
	selected_atoms = OrderedDict()
	node_stack = [(parent, nil, nil)]
traversed_nodes = set()
while node_stack:
node, node_parent, parent_atom = node_stack.pop()
traversed_nodes.add(node)
if node is parent:
k = parent else:
if node_parent is parent:
if priority is nil:
node_priority = nil else:
node_priority = priority.copy() else:
node_priority = d._priority(runtime = true)

k = Dependency(
atom= parent_atom,
blocker = parent_atom.blocker,
child= node,
depth = virt_depth,
parent = node_parent,
priority = node_priority,
root = node.root,
)

child_atoms = []
selected_atoms[k] = child_atoms
for atom_node in atom_graph.child_nodes(node):
child_atom = atom_node[0]
if id(child_atom) not in chosen_atom_ids:
continue
child_atoms.append(child_atom)
for child_node in atom_graph.child_nodes(atom_node):
if child_node in traversed_nodes:
continue
if not portage.match_from_list(child_atom, [child_node]):
continue
node_stack.append((child_node, node, child_atom))

return selected_atoms
}

func (d*depgraph) _expand_virt_from_graph( root, atom) {
	if not isinstance(atom, Atom):
	atom = Atom(atom)

	if not atom.cp.startswith("virtual/"):
	yield
	atom
	return

	any_match = false
	for pkg
	in
	d._dynamic_config._package_tracker.match(root, atom):
try:
	rdepend = d._select_atoms_from_graph(
		pkg.root,
		pkg._metadata.get("RDEPEND", ""),
		myuse = d._pkg_use_enabled(pkg),
		parent = pkg,
		strict=false,
)
	except
	InvalidDependString
	as
e:
	writemsg_level(
		"!!! Invalid RDEPEND in "
	+"'%svar/db/pkg/%s/RDEPEND': %s\n" % (pkg.root, pkg.cpv, e),
	noiselevel = -1,
		level=logging.ERROR,
)
	continue

	for atoms
	in
	rdepend.values():
	for atom
	in
atoms:
	if hasattr(atom, "_orig_atom"):
	continue
	yield
	atom

	any_match = true

	if not any_match:
	yield
	atom
}

// false
func (d*depgraph) _virt_deps_visible( pkg, ignore_use=false) bool {
try:
	rdepend = d._select_atoms(
		pkg.root,
		pkg._metadata.get("RDEPEND", ""),
		myuse = d._pkg_use_enabled(pkg),
		parent = pkg,
		priority=d._priority(runtime = true),
)
	except
	InvalidDependString
	as
e:
	if not pkg.installed:
	raise
	writemsg_level(
		"!!! Invalid RDEPEND in "
	+"'%svar/db/pkg/%s/RDEPEND': %s\n" % (pkg.root, pkg.cpv, e),
	noiselevel = -1,
		level=logging.ERROR,
)
	return false

	for atoms
	in
	rdepend.values():
	for atom
	in
atoms:
	if ignore_use:
	atom = atom.without_use
	pkg, existing = d._select_package(pkg.root, atom)
	if pkg is
	nil
	or
	not
	d._pkg_visibility_check(pkg):
	return false

	return true
}

// false
func (d*depgraph) _get_dep_chain(start_node, target_atom=nil, unsatisfied_dependency=false) {
	traversed_nodes = set()
	dep_chain = []
node = start_node
child = nil
all_parents = d._dynamic_config._parent_atoms
graph = d._dynamic_config.digraph

def format_pkg(pkg):
pkg_name = "%s%s%s" % (pkg.cpv, _repo_separator, pkg.repo)
return pkg_name

if target_atom is not nil and isinstance(node, Package):
affecting_use = set()
for dep_str in Package._dep_keys:
try:
affecting_use.update(
extract_affecting_use(
node._metadata[dep_str], target_atom, eapi = node.eapi
)
)
except InvalidDependString:
if not node.installed:
raise
affecting_use.difference_update(node.use.mask, node.use.force)
pkg_name = format_pkg(node)

if affecting_use:
usedep = []
for flag in affecting_use:
if flag in d._pkg_use_enabled(node):
usedep.append(flag) else:
usedep.append("-" + flag)
pkg_name += "[%s]" % ",".join(usedep)

dep_chain.append((pkg_name, node.type_name))


traversed_nodes.add(start_node)

start_node_parent_atoms = {}
for ppkg, patom in all_parents.get(node, []):
if not unsatisfied_dependency or not patom.match(start_node):
start_node_parent_atoms.setdefault(patom, []).append(ppkg)

if start_node_parent_atoms:
if any(not x.package for x in start_node_parent_atoms) and any(
x.package for x in start_node_parent_atoms
):
for x in list(start_node_parent_atoms):
if not x.package:
del start_node_parent_atoms[x]
if next(iter(start_node_parent_atoms)).package:
best_match = best_match_to_list(node.cpv, start_node_parent_atoms) else:
best_match = next(iter(start_node_parent_atoms))

child = node
for ppkg in start_node_parent_atoms[best_match]:
node = ppkg
if ppkg in d._dynamic_config._initial_arg_list:
break

while node is not nil:
traversed_nodes.add(node)

if node not in graph:
break

elif isinstance(node, DependencyArg):
if graph.parent_nodes(node):
node_type = "set" else:
node_type = "argument"
dep_chain.append(("%s" % (node, ), node_type))

elif node is not start_node:
for ppkg, patom in all_parents[child]:
if ppkg == node:
if (
child is start_node
and unsatisfied_dependency
and patom.match(child)
):
continue
atom = patom.unevaluated_atom if patom.package else patom
break

dep_strings = set()
priorities = graph.nodes[node][0].get(child)
if priorities is nil:
for k in Package._dep_keys:
dep_strings.add(node._metadata[k]) else:
for priority in priorities:
if priority.buildtime:
for k in Package._buildtime_keys:
dep_strings.add(node._metadata[k])
if priority.runtime:
dep_strings.add(node._metadata["RDEPEND"])
dep_strings.add(node._metadata["IDEPEND"])
if priority.runtime_post:
dep_strings.add(node._metadata["PDEPEND"])

affecting_use = set()
for dep_str in dep_strings:
try:
affecting_use.update(
extract_affecting_use(dep_str, atom, eapi =node.eapi)
)
except InvalidDependString:
if not node.installed:
raise

affecting_use.difference_update(node.use.mask, node.use.force)

pkg_name = format_pkg(node)
if affecting_use:
usedep = []
for flag in affecting_use:
if flag in d._pkg_use_enabled(node):
usedep.append(flag) else:
usedep.append("-" + flag)
pkg_name += "[%s]" % ",".join(usedep)

dep_chain.append((pkg_name, node.type_name))

child = node
selected_parent = nil
parent_arg = nil
parent_merge = nil
parent_unsatisfied = nil

for parent in d._dynamic_config.digraph.parent_nodes(node):
if parent in traversed_nodes:
continue
if isinstance(parent, DependencyArg):
parent_arg = parent
else:
if isinstance(parent, Package) and parent.operation == "merge":
parent_merge = parent
if unsatisfied_dependency and node is start_node:
for ppkg, atom in all_parents[start_node]:
if parent is ppkg:
if not atom.match(start_node):
parent_unsatisfied = parent
break else:
selected_parent = parent

if parent_unsatisfied is not nil:
selected_parent = parent_unsatisfied
elif parent_merge is not nil:
selected_parent = parent_merge
elif parent_arg is not nil:
if d._dynamic_config.digraph.parent_nodes(parent_arg):
selected_parent = parent_arg else:
dep_chain.append(("%s" % (parent_arg, ), "argument"))
selected_parent = nil

node = selected_parent
return dep_chain
}

// false
func (d*depgraph) _get_dep_chain_as_comment( pkg, unsatisfied_dependency=false) {
	dep_chain := d._get_dep_chain(
		pkg, unsatisfied_dependency = unsatisfied_dependency
	)
	display_list = []
for node, node_type in dep_chain:
if node_type == "argument":
display_list.append("required by %s (argument)" % node) else:
display_list.append("required by %s" % node)

msg = "# " + "\n# ".join(display_list) + "\n"
return msg
}

// nil, nil, false, false, nil, false
func (d*depgraph) _show_unsatisfied_dep(
root,
atom,
myparent=nil,
arg=nil,
check_backtrack,
check_autounmask_breakage bool,
show_req_use=nil,
collect_use_changes bool,
) {
	backtrack_mask = false
	autounmask_broke_use_dep = false
	if atom.package:
	xinfo = '"%s"' % atom.unevaluated_atom
	atom_without_use = atom.without_use
	else:
	xinfo = '"%s"' % atom
	atom_without_use = nil

	if arg:
	xinfo = '"%s"' % arg
	if isinstance(myparent, AtomArg):
	xinfo = '"%s"' % (myparent,)
	xinfo = xinfo.replace("null/", "")
	if root != d._frozen_config._running_root.root:
	xinfo = "%s for %s" % (xinfo, root)
	masked_packages = []
missing_use = []
missing_use_adjustable = set()
required_use_unsatisfied = []
masked_pkg_instances = set()
have_eapi_mask = false
pkgsettings = d._frozen_config.pkgsettings[root]
root_config = d._frozen_config.roots[root]
portdb = d._frozen_config.roots[root].trees["porttree"].dbapi
vardb = d._frozen_config.roots[root].trees["vartree"].dbapi
bindb = d._frozen_config.roots[root].trees["bintree"].dbapi
dbs = d._dynamic_config._filtered_trees[root]["dbs"]
use_ebuild_visibility = (
d._frozen_config.myopts.get("--use-ebuild-visibility", "n") != "n"
)

for db, pkg_type, built, installed, db_keys in dbs:
if installed:
continue
if atom.soname:
if not isinstance(db, DbapiProvidesIndex):
continue
cpv_list = db.match(atom)
elif hasattr(db, "xmatch"):
cpv_list = db.xmatch("match-all-cpv-only", atom.without_use) else:
cpv_list = db.match(atom.without_use)

if atom.soname:
repo_list = [nil]
elif atom.repo is nil and hasattr(db, "getRepositories"):
repo_list = db.getRepositories(catpkg = atom.cp) else:
repo_list = [atom.repo]

cpv_list.reverse()
for cpv in cpv_list:
for repo in repo_list:
if not db.cpv_exists(cpv, myrepo = repo):
continue

metadata, mreasons = get_mask_info(
root_config,
cpv,
pkgsettings,
db,
pkg_type,
built,
installed,
db_keys,
myrepo = repo,
_pkg_use_enabled = d._pkg_use_enabled,
)
if metadata is not nil and portage.eapi_is_supported(
metadata["EAPI"]
):
if not repo:
repo = metadata.get("repository")
pkg = d._pkg(
cpv, pkg_type, root_config, installed = installed, myrepo = repo
)
metadata = pkg._metadata
if pkg.invalid:
masked_packages.append(
(
root_config,
pkgsettings,
cpv,
repo,
metadata,
mreasons,
)
)
continue
if atom.soname and not atom.match(pkg):
continue
if atom_without_use is not nil and not atom_without_use.match(
pkg
):
continue
if pkg in d._dynamic_config._runtime_pkg_mask:
backtrack_reasons = d._dynamic_config._runtime_pkg_mask[
pkg
]
mreasons.append(
"backtracking: %s"
% ", ".join(sorted(backtrack_reasons))
)
backtrack_mask = true
if (
not mreasons
and d._frozen_config.excluded_pkgs.findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
)
):
mreasons = ["exclude option"]
if mreasons:
masked_pkg_instances.add(pkg)
if atom.package and atom.unevaluated_atom.use:
try:
if (
not pkg.iuse.is_valid_flag(
atom.unevaluated_atom.use.required
)
or atom.violated_conditionals(
d._pkg_use_enabled(pkg),
pkg.iuse.is_valid_flag,
).use
):
missing_use.append(pkg)
if atom.match(pkg):
autounmask_broke_use_dep = true
if not mreasons:
continue
except InvalidAtom:
writemsg(
"violated_conditionals raised "
+ "InvalidAtom: '%s' parent: %s" % (atom, myparent),
noiselevel = -1,
)
raise
if (
not mreasons
and not pkg.built
and pkg._metadata.get("REQUIRED_USE")
and eapi_has_required_use(pkg.eapi)
):
if not check_required_use(
pkg._metadata["REQUIRED_USE"],
d._pkg_use_enabled(pkg),
pkg.iuse.is_valid_flag,
eapi = pkg.eapi,
):
required_use_unsatisfied.append(pkg)
continue

root_slot = (pkg.root, pkg.slot_atom)
if pkg.built and root_slot in d._rebuild.rebuild_list:
mreasons = ["need to rebuild from source"]
elif (
pkg.installed and root_slot in d._rebuild.reinstall_list
):
mreasons = ["need to rebuild from source"]
elif (
pkg.built
and not mreasons
and d._dynamic_config.ignored_binaries.get(pkg, {}).get(
"respect_use"
)
):
mreasons = ["use flag configuration mismatch"]
elif (
pkg.built
and not mreasons
and d._dynamic_config.ignored_binaries.get(pkg, {}).get(
"changed_deps"
)
):
mreasons = ["changed deps"]
elif (
pkg.built
and use_ebuild_visibility
and not d._equiv_ebuild_visible(pkg)
):
equiv_ebuild = d._equiv_ebuild(pkg)
if equiv_ebuild is nil:
if portdb.cpv_exists(pkg.cpv):
mreasons = ["ebuild corrupt"] else:
mreasons = ["ebuild not available"]
elif not mreasons:
mreasons = get_masking_status(
equiv_ebuild,
pkgsettings,
root_config,
use =d._pkg_use_enabled(equiv_ebuild),
)
if mreasons:
metadata = equiv_ebuild._metadata

masked_packages.append(
(root_config, pkgsettings, cpv, repo, metadata, mreasons)
)

if check_backtrack:
if backtrack_mask:
raise d._backtrack_mask()
else:
return

if check_autounmask_breakage:
if autounmask_broke_use_dep:
raise d._autounmask_breakage() else:
return

missing_use_reasons = []
missing_iuse_reasons = []
for pkg in missing_use:
use = d._pkg_use_enabled(pkg)
missing_iuse = []
required_flags = atom.unevaluated_atom.use.required
missing_iuse = pkg.iuse.get_missing_iuse(required_flags)

mreasons = []
if missing_iuse:
mreasons.append("Missing IUSE: %s" % " ".join(missing_iuse))
missing_iuse_reasons.append((pkg, mreasons)) else:
need_enable = sorted((atom.use.enabled - use) & pkg.iuse.all)
need_disable = sorted((atom.use.disabled & use) & pkg.iuse.all)

untouchable_flags = frozenset(chain(pkg.use.mask, pkg.use.force))
if any(
x in untouchable_flags for x in chain(need_enable, need_disable)
):
continue

missing_use_adjustable.add(pkg)
required_use = pkg._metadata.get("REQUIRED_USE")
required_use_warning = ""
if required_use:
old_use = d._pkg_use_enabled(pkg)
new_use = set(d._pkg_use_enabled(pkg))
for flag in need_enable:
new_use.add(flag)
for flag in need_disable:
new_use.discard(flag)
if check_required_use(
required_use, old_use, pkg.iuse.is_valid_flag, eapi = pkg.eapi
) and not check_required_use(
required_use, new_use, pkg.iuse.is_valid_flag, eapi = pkg.eapi
):
required_use_warning = (
", this change violates use flag constraints "
+ "defined by %s: '%s'"
% (pkg.cpv, human_readable_required_use(required_use))
)

if need_enable or need_disable:
changes = []
changes.extend(colorize("red", "+" + x) for x in need_enable)
changes.extend(colorize("blue", "-" + x) for x in need_disable)
mreasons.append(
"Change USE: %s" % " ".join(changes) + required_use_warning
)
missing_use_reasons.append((pkg, mreasons))

if not missing_iuse and myparent and atom.unevaluated_atom.use.conditional:
if pkg in masked_pkg_instances:
continue

mreasons = []
violated_atom = atom.unevaluated_atom.violated_conditionals(
d._pkg_use_enabled(pkg),
pkg.iuse.is_valid_flag,
d._pkg_use_enabled(myparent),
)
if not (violated_atom.use.enabled or violated_atom.use.disabled):
changes = []
conditional = violated_atom.use.conditional
involved_flags = set(
chain(
conditional.equal,
conditional.not_equal,
conditional.enabled,
conditional.disabled,
)
)

untouchable_flags = frozenset(
chain(myparent.use.mask, myparent.use.force)
)
if any(x in untouchable_flags for x in involved_flags):
continue

required_use = myparent._metadata.get("REQUIRED_USE")
required_use_warning = ""
if required_use:
old_use = d._pkg_use_enabled(myparent)
new_use = set(d._pkg_use_enabled(myparent))
for flag in involved_flags:
if flag in old_use:
new_use.discard(flag) else:
new_use.add(flag)
if check_required_use(
required_use,
old_use,
myparent.iuse.is_valid_flag,
eapi = myparent.eapi,
) and not check_required_use(
required_use,
new_use,
myparent.iuse.is_valid_flag,
eapi = myparent.eapi,
):
required_use_warning = (
", this change violates use flag constraints "
+ "defined by %s: '%s'"
% (
myparent.cpv,
human_readable_required_use(required_use),
)
)

target_use = {}
for flag in involved_flags:
if flag in d._pkg_use_enabled(myparent):
target_use[flag] = false
changes.append(colorize("blue", "-" + flag)) else:
target_use[flag] = true
changes.append(colorize("red", "+" + flag))

if collect_use_changes and not required_use_warning:
previous_changes = (
d._dynamic_config._needed_use_config_changes.get(
myparent
)
)
d._pkg_use_enabled(myparent, target_use= target_use)
if (
previous_changes
is not d._dynamic_config._needed_use_config_changes.get(
myparent
)
):
return true

mreasons.append(
"Change USE: %s" % " ".join(changes) + required_use_warning
)
if (myparent, mreasons) not in missing_use_reasons:
missing_use_reasons.append((myparent, mreasons))

if collect_use_changes:
return false

unmasked_use_reasons = [
(pkg, mreasons)
for (pkg, mreasons) in missing_use_reasons
if pkg not in masked_pkg_instances
]

unmasked_iuse_reasons = [
(pkg, mreasons)
for (pkg, mreasons) in missing_iuse_reasons
if pkg not in masked_pkg_instances
]

show_missing_use = false
if unmasked_use_reasons:
show_missing_use = []
pkg_reason = nil
parent_reason = nil
for pkg, mreasons in unmasked_use_reasons:
if pkg is myparent:
if parent_reason is nil:
parent_reason = (pkg, mreasons)
elif pkg_reason is nil:
pkg_reason = (pkg, mreasons)
if pkg_reason:
show_missing_use.append(pkg_reason)
if parent_reason:
show_missing_use.append(parent_reason)

elif unmasked_iuse_reasons:
masked_with_iuse = false
for pkg in masked_pkg_instances:
if not pkg.iuse.get_missing_iuse(atom.unevaluated_atom.use.required):
masked_with_iuse = true
break
if not masked_with_iuse:
show_missing_use = unmasked_iuse_reasons

if required_use_unsatisfied:
for pkg in missing_use_adjustable:
if (
pkg not in masked_pkg_instances
and pkg > required_use_unsatisfied[0]
):
required_use_unsatisfied = false
break

mask_docs = false

if show_req_use is nil and required_use_unsatisfied:
show_req_use = required_use_unsatisfied[0]

if show_req_use is not nil:

pkg = show_req_use
output_cpv = pkg.cpv + _repo_separator + pkg.repo
writemsg(
"\n!!! "
+ colorize("BAD", "The ebuild selected to satisfy ")
+ colorize("INFORM", xinfo)
+ colorize("BAD", " has unmet requirements.")
+ "\n",
noiselevel = -1,
)
use_display = pkg_use_display(pkg, d._frozen_config.myopts)
writemsg("- %s %s\n" % (output_cpv, use_display), noiselevel = -1)
writemsg(
"\n  The following REQUIRED_USE flag constraints "
+ "are unsatisfied:\n",
noiselevel= -1,
)
reduced_noise = check_required_use(
pkg._metadata["REQUIRED_USE"],
d._pkg_use_enabled(pkg),
pkg.iuse.is_valid_flag,
eapi = pkg.eapi,
).tounicode()
writemsg(
"    %s\n" % human_readable_required_use(reduced_noise), noiselevel = -1
)
normalized_required_use = " ".join(pkg._metadata["REQUIRED_USE"].split())
if reduced_noise != normalized_required_use:
writemsg(
"\n  The above constraints "
+ "are a subset of the following complete expression:\n",
noiselevel =-1,
)
writemsg(
"    %s\n" % human_readable_required_use(normalized_required_use),
noiselevel = -1,
)
writemsg("\n", noiselevel = -1)

elif show_missing_use:
writemsg(
"\nemerge: there are no ebuilds built with USE flags to satisfy "
+ green(xinfo)
+ ".\n",
noiselevel = -1,
)
writemsg(
"!!! One of the following packages is required to complete your request:\n",
noiselevel =-1,
)
for pkg, mreasons in show_missing_use:
writemsg(
"- "
+ pkg.cpv
+ _repo_separator
+ pkg.repo
+ " ("
+ ", ".join(mreasons)
+ ")\n",
noiselevel = -1,
)

elif masked_packages:
writemsg(
"\n!!! "
+ colorize("BAD", "All ebuilds that could satisfy ")
+ colorize("INFORM", xinfo)
+ colorize("BAD", " have been masked.")
+ "\n",
noiselevel = -1,
)
writemsg(
"!!! One of the following masked packages is required to complete your request:\n",
noiselevel = -1,
)
have_eapi_mask = show_masked_packages(masked_packages)
if have_eapi_mask:
writemsg("\n", noiselevel = -1)
msg = (
"The current version of portage supports "
+ "EAPI '%s'. You must upgrade to a newer version"
+ " of portage before EAPI masked packages can"
+ " be installed."
) % portage.const.EAPI
writemsg("\n".join(textwrap.wrap(msg, 75)), noiselevel =-1)
writemsg("\n", noiselevel =-1)
mask_docs = true else:
cp_exists = false
if atom.package and not atom.cp.startswith("null/"):
for pkg in d._iter_match_pkgs_any(root_config, Atom(atom.cp)):
cp_exists = true
break

writemsg(
"\nemerge: there are no %s to satisfy "
% (
"binary packages"
if d._frozen_config.myopts.get("--usepkgonly", "y") == true else "ebuilds"
)
+ green(xinfo)
+ ".\n",
noiselevel = -1,
)
if (
isinstance(myparent, AtomArg)
and not cp_exists
and d._frozen_config.myopts.get("--misspell-suggestions", "y") != "n"
):

writemsg("\nemerge: searching for similar names...", noiselevel = -1)

search_index = (
d._frozen_config.myopts.get("--search-index", "y") != "n"
)
dbs = [vardb]
if "--usepkgonly" not in d._frozen_config.myopts:
dbs.append(IndexedPortdb(portdb) if search_index else portdb)
if "--usepkg" in d._frozen_config.myopts:
dbs.append(bindb)

matches = similar_name_search(dbs, atom)

if len(matches) == 1:
writemsg(
"\nemerge: Maybe you meant " + matches[0] + "?\n", noiselevel = -1
)
elif len(matches) > 1:
writemsg(
"\nemerge: Maybe you meant any of these: %s?\n"
% (", ".join(matches),),
noiselevel = -1,
) else:
writemsg(" nothing similar found.\n", noiselevel = -1)
msg = []
if not isinstance(myparent, AtomArg):
dep_chain = d._get_dep_chain(myparent, atom)
for node, node_type in dep_chain:
msg.append(
'(dependency required by "%s" [%s])'
% (colorize("INFORM", "%s" % (node)), node_type)
)

if msg:
writemsg("\n".join(msg), noiselevel= -1)
writemsg("\n", noiselevel= -1)

if mask_docs:
show_mask_docs()
writemsg("\n", noiselevel = -1)
}

// false
func (d*depgraph) _iter_match_pkgs_any(root_config, atom, onlydeps=false) {
	for (
		db,
	pkg_type,
		built,
		installed,
		db_keys,
) in
	d._dynamic_config._filtered_trees[root_config.root]["dbs"]:
	for pkg
	in
	d._iter_match_pkgs(
		root_config, pkg_type, atom, onlydeps = onlydeps
	):
	yield
	pkg
}

// false
func (d*depgraph) _iter_match_pkgs(root_config, pkg_type, atom, onlydeps=false) {
	if atom.package:
	return d._iter_match_pkgs_atom(
		root_config, pkg_type, atom, onlydeps = onlydeps
	)
	return d._iter_match_pkgs_soname(
		root_config, pkg_type, atom, onlydeps = onlydeps
	)
}

// false
func (d*depgraph) _iter_match_pkgs_soname(root_config, pkg_type, atom, onlydeps=false) {
	db = root_config.trees[d.pkg_tree_map[pkg_type]].dbapi
	installed = pkg_type == "installed"

	if isinstance(db, DbapiProvidesIndex):
	for cpv
	in
	reversed(db.match(atom)):
	yield
	d._pkg(
		cpv, pkg_type, root_config, installed = installed, onlydeps = onlydeps
	)
}

// false
func (d*depgraph) _iter_match_pkgs_atom(root_config, pkg_type, atom, onlydeps=false) {

	db = root_config.trees[d.pkg_tree_map[pkg_type]].dbapi
	atom_exp = dep_expand(atom, mydb = db, settings = root_config.settings)
	cp_list = db.cp_list(atom_exp.cp)
	matched_something = false
	installed = pkg_type == "installed"

	if cp_list:
	atom_set = InternalPackageSet(initial_atoms = (atom,), allow_repo = true)

	cp_list.reverse()
	for cpv
	in
cp_list:
	if match_from_list(atom_exp,[cpv]):
try:
	pkg = d._pkg(
		cpv,
		pkg_type,
		root_config,
		installed = installed,
		onlydeps = onlydeps,
		myrepo=getattr(cpv, "repo", nil),
)
	except
	portage.exception.PackageNotFound:
	pass
	else:

	if not atom_set.findAtomForPackage(
		pkg, modified_use = d._pkg_use_enabled(pkg)
	):
	continue
	matched_something = true
	yield
	pkg

	if (
		not matched_something
	and
	installed
	and
	atom.slot
	is
	not
	nil
	and
	not
	atom.slot_operator_built
	):

	if "remove" in
	d._dynamic_config.myparams:
	portdb = d._frozen_config.trees[root_config.root]["porttree"].dbapi
	db_keys = list(portdb._aux_cache_keys)
	dbs = [(portdb, "ebuild", false, false, db_keys)] else:
dbs = d._dynamic_config._filtered_trees[root_config.root]["dbs"]

cp_list = db.cp_list(atom_exp.cp)
if cp_list:
atom_set = InternalPackageSet(
initial_atoms= (atom.without_slot, ), allow_repo =true
)
atom_exp_without_slot = atom_exp.without_slot
cp_list.reverse()
for cpv in cp_list:
if not match_from_list(atom_exp_without_slot, [cpv]):
continue
slot_available = false
for (
other_db,
other_type,
other_built,
other_installed,
other_keys,
) in dbs:
try:
if portage.dep._match_slot(
atom, other_db._pkg_str(str(cpv), nil)
):
slot_available = true
break
except (KeyError, InvalidData):
pass
if not slot_available:
continue
inst_pkg = d._pkg(
cpv,
"installed",
root_config,
installed = installed,
myrepo = atom.repo,
)
if atom_set.findAtomForPackage(inst_pkg):
yield inst_pkg
return
}

// false. nil
func (d*depgraph) _select_pkg_highest_available(root, atom, onlydeps=false, parent=nil) {
	if atom.package:
	cache_key = (
		root,
		atom,
		atom.unevaluated_atom,
		onlydeps,
		d._dynamic_config._autounmask,
)
	d._dynamic_config._highest_pkg_cache_cp_map.setdefault(
		(root, atom.cp), []
).append(cache_key) else:
cache_key = (root, atom, onlydeps, d._dynamic_config._autounmask)
d._dynamic_config._highest_pkg_cache_cp_map.setdefault(
(root, atom), []
).append(cache_key)
ret = d._dynamic_config._highest_pkg_cache.get(cache_key)
if ret is not nil:
return ret
ret = d._select_pkg_highest_available_imp(
root, atom, onlydeps = onlydeps, parent = parent
)
d._dynamic_config._highest_pkg_cache[cache_key] = ret
pkg, existing = ret
if pkg is not nil:
if d._pkg_visibility_check(pkg) and not (pkg.installed and pkg.masks):
d._dynamic_config._visible_pkgs[pkg.root].cpv_inject(pkg)
return ret
}

func (d*depgraph) _is_argument(pkg) bool{
	for arg, atom
	in
	d._iter_atoms_for_pkg(pkg):
	if isinstance(arg, (AtomArg, PackageArg)):
	return true
	return false
}

func (d*depgraph) _prune_highest_pkg_cache( pkg) {
	cache = d._dynamic_config._highest_pkg_cache
	key_map = d._dynamic_config._highest_pkg_cache_cp_map
	for cp
	in
	pkg.provided_cps:
	for cache_key
	in
	key_map.pop((pkg.root, cp), []):
cache.pop(cache_key, nil)
if pkg.provides is not nil:
for atom in pkg.provides:
for cache_key in key_map.pop((pkg.root, atom), []):
cache.pop(cache_key, nil)
}

func (d*depgraph) _want_installed_pkg(pkg) bool {
	if d._frozen_config.excluded_pkgs.findAtomForPackage(
		pkg, modified_use = d._pkg_use_enabled(pkg)
){
		return true
	}
		
	arg = false
try:
	for arg, atom
	in
	d._iter_atoms_for_pkg(pkg):
	if arg.force_reinstall:
	return false
	except
InvalidDependString:
	pass

	if "selective" in
	d._dynamic_config.myparams:
	return true

	return not
	arg
}

func (d*depgraph) _want_update_pkg(parent, pkg) {

	if d._frozen_config.excluded_pkgs.findAtomForPackage(
		pkg, modified_use = d._pkg_use_enabled(pkg)
):
	return false

	arg_atoms = nil
try:
	arg_atoms = list(d._iter_atoms_for_pkg(pkg))
	except
InvalidDependString:
	if not pkg.installed:
	raise

	depth = parent.depth
	or
	0
	if isinstance(depth, int):
	depth += 1

	if arg_atoms:
	for arg, atom
	in
arg_atoms:
	if arg.reset_depth:
	depth = 0
	break

	update = "--update"
	in
	d._frozen_config.myopts

	return (
		not
	d._dynamic_config._complete_mode
	and(arg_atoms
	or
	update)
	and
	not
	d._too_deep(depth)
	)
}

func (d*depgraph) _will_replace_child(parent, root, atom) {
	if parent.root != root or
	parent.cp != atom.cp:
	return nil
	for child
	in
	d._iter_match_pkgs(
		d._frozen_config.roots[root], "installed", atom
	):
	if parent.slot_atom == child.slot_atom:
	return child
	return nil
}

func (d*depgraph) _too_deep(depth) bool {
	deep := d._dynamic_config.myparams.get("deep", 0)
	if depth is
	d._UNREACHABLE_DEPTH:
	return true
	if deep is
true:
	return false
	return depth > deep
}

// 1
func (d*depgraph) _depth_increment(depth, n int) int {
	return depth + n
	if isinstance(depth, int)
	else
	depth
}

func (d*depgraph) _equiv_ebuild(pkg) {
try:
	return d._pkg(pkg.cpv, "ebuild", pkg.root_config, myrepo = pkg.repo)
	except
	portage.exception.PackageNotFound:
	return next(
			d._iter_match_pkgs(
				pkg.root_config, "ebuild", Atom("=%s"%(pkg.cpv, ))
		),
		nil,
)
}

// nil
func (d*depgraph) _equiv_ebuild_visible(pkg, autounmask_level=nil) bool {
try:
	pkg_eb = d._pkg(pkg.cpv, "ebuild", pkg.root_config, myrepo = pkg.repo)
	except
	portage.exception.PackageNotFound:
	pkg_eb_visible = false
	for pkg_eb
	in
	d._iter_match_pkgs(
		pkg.root_config, "ebuild", Atom("=%s"%(pkg.cpv, ))
	):
	if d._pkg_visibility_check(pkg_eb, autounmask_level):
	pkg_eb_visible = true
	break
	if not pkg_eb_visible:
	return false
	else:
	if not d._pkg_visibility_check(pkg_eb, autounmask_level):
	return false

	return true
}

func (d*depgraph) _equiv_binary_installed(pkg) bool {
	build_time = pkg.build_time
	if not build_time:
	return false

try:
	inst_pkg = d._pkg(pkg.cpv, "installed", pkg.root_config, installed = true)
	except
PackageNotFound:
	return false

	return build_time == inst_pkg.build_time
}

type _AutounmaskLevel struct {
	// slot
	allow_use_changes,
	allow_unstable_keywords,
	allow_license_changes,
	allow_missing_keywords,
	allow_unmasks bool
}

func New_AutounmaskLevel() *_AutounmaskLevel{
	a := &_AutounmaskLevel{}
	a.allow_use_changes = false
	a.allow_license_changes = false
	a.allow_unstable_keywords = false
	a.allow_missing_keywords = false
	a.allow_unmasks = false
	return a
}

func (d*depgraph) _autounmask_levels() {

	if d._dynamic_config._autounmask is
	not
true:
	return

	autounmask_keep_keywords = d._dynamic_config.myparams[
		"autounmask_keep_keywords"
	]
	autounmask_keep_license = d._dynamic_config.myparams[
		"autounmask_keep_license"
	]
	autounmask_keep_masks = d._dynamic_config.myparams["autounmask_keep_masks"]
	autounmask_keep_use = d._dynamic_config.myparams["autounmask_keep_use"]
	autounmask_level = d._AutounmaskLevel()

	if not autounmask_keep_use:
	autounmask_level.allow_use_changes = true
	yield
	autounmask_level

	if not autounmask_keep_license:
	autounmask_level.allow_license_changes = true
	yield
	autounmask_level

	if not autounmask_keep_keywords:
	autounmask_level.allow_unstable_keywords = true
	yield
	autounmask_level

	if not(autounmask_keep_keywords or
	autounmask_keep_masks):
	autounmask_level.allow_unstable_keywords = true
	autounmask_level.allow_missing_keywords = true
	yield
	autounmask_level

	if not autounmask_keep_masks:
	autounmask_level.allow_unstable_keywords = false
	autounmask_level.allow_missing_keywords = false
	autounmask_level.allow_unmasks = true
	yield
	autounmask_level

	if not(autounmask_keep_keywords or
	autounmask_keep_masks):
	autounmask_level.allow_unstable_keywords = true

	for missing_keyword, unmask
	in((false, true), (true, true)):

	autounmask_level.allow_missing_keywords = missing_keyword
	autounmask_level.allow_unmasks = unmask

	yield
	autounmask_level
}

func (d*depgraph)_select_pkg_highest_available_imp(root, atom, onlydeps = false, parent = nil){
	pkg, existing = d._wrapped_select_pkg_highest_available_imp(
		root, atom, onlydeps = onlydeps, parent = parent
	)

	default_selection = (pkg, existing)

	if d._dynamic_config._autounmask is
true:
	if pkg is
	not
	nil
	and
	pkg.installed
	and
	not
	d._want_installed_pkg(pkg):
	pkg = nil

	earlier_need_restart = d._dynamic_config._need_restart
	d._dynamic_config._need_restart = false
try:
	for autounmask_level
	in
	d._autounmask_levels():
	if pkg is
	not
nil:
	break

	pkg, existing = d._wrapped_select_pkg_highest_available_imp(
		root,
		atom,
		onlydeps = onlydeps,
		autounmask_level = autounmask_level,
		parent=parent,
)

	if (
		pkg is
	not
	nil
	and
	pkg.installed
	and
	not
	d._want_installed_pkg(pkg)
	):
	pkg = nil

	if d._dynamic_config._need_restart:
	return nil, nil
finally:
	if earlier_need_restart:
	d._dynamic_config._need_restart = true

	if pkg is
nil:
	return default_selection

	return pkg, existing
}

// nil
func (d*depgraph) _pkg_visibility_check( pkg, autounmask_level=nil, trust_graph=true) bool {

	if pkg.visible {
		return true
	}

	if trust_graph and
	pkg
	in
	d._dynamic_config.digraph
	{
		return true
	}

	if not d._dynamic_config._autounmask || autounmask_level == nil {
		return false
	}

	pkgsettings = d._frozen_config.pkgsettings[pkg.root]
	root_config = d._frozen_config.roots[pkg.root]
	mreasons = _get_masking_status(
		pkg, pkgsettings, root_config, use = d._pkg_use_enabled(pkg)
	)

	masked_by_unstable_keywords = false
	masked_by_missing_keywords = false
	missing_licenses = nil
	masked_by_something_else = false
	masked_by_p_mask = false

	for reason
	in
mreasons:
	hint = reason.unmask_hint

	if hint is
nil:
	masked_by_something_else = true
	elif
	hint.key == "unstable keyword":
	masked_by_unstable_keywords = true
	if hint.value == "**":
	masked_by_missing_keywords = true
	elif
	hint.key == "p_mask":
	masked_by_p_mask = true
	elif
	hint.key == "license":
	missing_licenses = hint.value
	else:
	masked_by_something_else = true

	if masked_by_something_else:
	return false

	if pkg in
	d._dynamic_config._needed_unstable_keywords:
	masked_by_unstable_keywords = false
	masked_by_missing_keywords = false

	if pkg in
	d._dynamic_config._needed_p_mask_changes:
	masked_by_p_mask = false

	if missing_licenses:
	missing_licenses.difference_update(
		d._dynamic_config._needed_license_changes.get(pkg, set())
	)

	if not(masked_by_unstable_keywords or
	masked_by_p_mask
	or
	missing_licenses):
	return true

	if (
		(
			masked_by_unstable_keywords
		and
	not
	autounmask_level.allow_unstable_keywords
	)
	or(
		masked_by_missing_keywords
	and
	not
	autounmask_level.allow_missing_keywords
	)
	or(masked_by_p_mask
	and
	not
	autounmask_level.allow_unmasks)
	or(missing_licenses
	and
	not
	autounmask_level.allow_license_changes)
):
	return false

	if masked_by_unstable_keywords:
	d._dynamic_config._needed_unstable_keywords.add(pkg)
	backtrack_infos = d._dynamic_config._backtrack_infos
	backtrack_infos.setdefault("config",
	{
	})
	backtrack_infos["config"].setdefault("needed_unstable_keywords", set())
	backtrack_infos["config"]["needed_unstable_keywords"].add(pkg)

	if masked_by_p_mask:
	d._dynamic_config._needed_p_mask_changes.add(pkg)
	backtrack_infos = d._dynamic_config._backtrack_infos
	backtrack_infos.setdefault("config",
	{
	})
	backtrack_infos["config"].setdefault("needed_p_mask_changes", set())
	backtrack_infos["config"]["needed_p_mask_changes"].add(pkg)

	if missing_licenses:
	d._dynamic_config._needed_license_changes.setdefault(pkg, set()).update(
		missing_licenses
	)
	backtrack_infos = d._dynamic_config._backtrack_infos
	backtrack_infos.setdefault("config",
	{
	})
	backtrack_infos["config"].setdefault("needed_license_changes", set())
	backtrack_infos["config"]["needed_license_changes"].add(
		(pkg, frozenset(missing_licenses))
	)

	return true
}

func (d*depgraph) _pkg_use_enabled( pkg, target_use=nil) {
	if pkg.built:
	return pkg.use.enabled
	needed_use_config_change = d._dynamic_config._needed_use_config_changes.get(
		pkg
	)

	if target_use is
nil:
	if needed_use_config_change is
nil:
	return pkg.use.enabled
	return needed_use_config_change[0]

	if needed_use_config_change is
	not
nil:
	old_use = needed_use_config_change[0]
	new_use = set()
	old_changes = needed_use_config_change[1]
	new_changes = old_changes.copy()
	else:
	old_use = pkg.use.enabled
	new_use = set()
	old_changes =
	{
	}
	new_changes =
	{
	}

	for flag, state
	in
	target_use.items():
	flag = pkg.iuse.get_flag(flag)
	if flag is
nil:
	continue
	if state:
	if flag not
	in
old_use:
	if new_changes.get(flag) == false:
	return old_use
	new_changes[flag] = true
	new_use.add(flag)
	else:
	if flag in
old_use:
	if new_changes.get(flag) == true:
	return old_use
	new_changes[flag] = false
	new_use |= old_use.difference(target_use)

	def
	want_restart_for_use_change(pkg, new_use):
	if pkg not
	in
	d._dynamic_config.digraph.nodes:
	return false

	for key
	in
	Package._dep_keys + ("LICENSE",):
	dep = pkg._metadata[key]
	old_val = set(
		portage.dep.use_reduce(
			dep,
			pkg.use.enabled,
			is_valid_flag = pkg.iuse.is_valid_flag,
		flat = true,
)
)
	new_val = set(
		portage.dep.use_reduce(
			dep, new_use, is_valid_flag = pkg.iuse.is_valid_flag, flat = true
	)
)

	if old_val != new_val:
	return true

	parent_atoms = d._dynamic_config._parent_atoms.get(pkg)
	if not parent_atoms:
	return false

	new_use, changes = d._dynamic_config._needed_use_config_changes.get(pkg)
	for ppkg, atom
	in
parent_atoms:
	if not atom.use:
	continue

	enabled = atom.use.enabled
	disabled = atom.use.disabled
	for k, v
	in
	changes.items():
	want_enabled = k
	in
	enabled
	if (want_enabled or
	k
	in
	disabled) and
	want_enabled != v:
	return true

	return false

	new_use = frozenset(new_use)

	if new_changes != old_changes:
	required_use_satisfied = true
	required_use = pkg._metadata.get("REQUIRED_USE")
	if (
		required_use
		and
	check_required_use(
		required_use, old_use, pkg.iuse.is_valid_flag, eapi = pkg.eapi
	)
	and
	not
	check_required_use(
		required_use, new_use, pkg.iuse.is_valid_flag, eapi = pkg.eapi
	)
):
	required_use_satisfied = false

	if any(x in
	pkg.use.mask
	for x
	in
	new_changes) or
	any(
		x
	in
	pkg.use.force
	for x
	in
	new_changes
	):
	return old_use

	changes = _use_changes(
		new_use, new_changes, required_use_satisfied = required_use_satisfied
	)
	d._dynamic_config._needed_use_config_changes[pkg] = changes
	backtrack_infos = d._dynamic_config._backtrack_infos
	backtrack_infos.setdefault("config",
	{
	})
	backtrack_infos["config"].setdefault("needed_use_config_changes",[])
	backtrack_infos["config"]["needed_use_config_changes"].append(
		(pkg, changes)
	)
	if want_restart_for_use_change(pkg, new_use):
	d._dynamic_config._need_restart = true
	return new_use
}

// false, nil, nil
func (d*depgraph) _wrapped_select_pkg_highest_available_imp(
root, atom, onlydeps=false, autounmask_level=nil, parent=nil
) {
	root_config = d._frozen_config.roots[root]
	pkgsettings = d._frozen_config.pkgsettings[root]
	dbs = d._dynamic_config._filtered_trees[root]["dbs"]
	vardb = d._frozen_config.roots[root].trees["vartree"].dbapi
	matched_packages = []
highest_version = nil
atom_cp = nil
have_new_virt = nil
if atom.package:
atom_cp = atom.cp
have_new_virt = atom_cp.startswith("virtual/") and d._have_new_virt(
root, atom_cp
)

existing_node = nil
myeb = nil
rebuilt_binaries = "rebuilt_binaries" in d._dynamic_config.myparams
usepkg = "--usepkg" in d._frozen_config.myopts
usepkgonly = "--usepkgonly" in d._frozen_config.myopts
usepkg_exclude_live = "--usepkg-exclude-live" in d._frozen_config.myopts
empty = "empty" in d._dynamic_config.myparams
selective = "selective" in d._dynamic_config.myparams
reinstall = false
avoid_update = "--update" not in d._frozen_config.myopts
dont_miss_updates = "--update" in d._frozen_config.myopts
use_ebuild_visibility = (
d._frozen_config.myopts.get("--use-ebuild-visibility", "n") != "n"
)
reinstall_atoms = d._frozen_config.reinstall_atoms
usepkg_exclude = d._frozen_config.usepkg_exclude
useoldpkg_atoms = d._frozen_config.useoldpkg_atoms
matched_oldpkg = []
found_available_arg = false
packages_with_invalid_use_config = []
for find_existing_node in true, false:
if existing_node:
break
for db, pkg_type, built, installed, db_keys in dbs:
if existing_node:
break
if installed and not find_existing_node:
want_reinstall = (
reinstall or empty or (found_available_arg and not selective)
)
if want_reinstall and matched_packages:
continue

for pkg in d._iter_match_pkgs(
root_config,
pkg_type,
atom.without_use if (atom.package and not built) else atom,
onlydeps = onlydeps,
):
if have_new_virt is true and pkg.cp != atom_cp:
continue
if pkg in d._dynamic_config._runtime_pkg_mask:
continue
root_slot = (pkg.root, pkg.slot_atom)
if pkg.built and root_slot in d._rebuild.rebuild_list:
continue
if pkg.installed and root_slot in d._rebuild.reinstall_list:
continue

if (
not pkg.installed
and d._frozen_config.excluded_pkgs.findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
)
):
continue

if (
built
and not installed
and usepkg_exclude.findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
)
):
break

if (
usepkg_exclude_live
and built
and not installed
and "live" in pkg._metadata.get("PROPERTIES", "").split()
):
continue

useoldpkg = useoldpkg_atoms.findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
)

if (
packages_with_invalid_use_config
and (not built or not useoldpkg)
and (not pkg.installed or dont_miss_updates)
):
higher_version_rejected = false
repo_priority = pkg.repo_priority
for rejected in packages_with_invalid_use_config:
if rejected.cp != pkg.cp:
continue
if rejected > pkg:
higher_version_rejected = true
break
if portage.dep.cpvequal(rejected.cpv, pkg.cpv):
rej_repo_priority = rejected.repo_priority
if rej_repo_priority is not nil and (
repo_priority is nil
or rej_repo_priority > repo_priority
):
higher_version_rejected = true
break
if higher_version_rejected:
continue

cpv = pkg.cpv
reinstall_for_flags = nil

if (
pkg.installed
and parent is not nil
and not d._want_update_pkg(parent, pkg)
):
pass
elif not pkg.installed or (matched_packages and not avoid_update):

if not d._pkg_visibility_check(pkg, autounmask_level):
continue


identical_binary = false
if pkg.type_name != "ebuild" and matched_packages:
if usepkg and pkg.installed:
for selected_pkg in matched_packages:
if (
selected_pkg.type_name == "binary"
and selected_pkg.cpv == pkg.cpv
and selected_pkg.build_time == pkg.build_time
):
identical_binary = true
break

if (
not identical_binary
and pkg.built
and (use_ebuild_visibility or matched_packages)
):
if not use_ebuild_visibility and (usepkgonly or useoldpkg):
if pkg.installed and pkg.masks:
continue
elif not d._equiv_ebuild_visible(
pkg, autounmask_level = autounmask_level
):
continue

effective_parent = parent or d._select_atoms_parent
if not (
effective_parent
and d._will_replace_child(effective_parent, root, atom)
):
myarg = nil
try:
for myarg, myarg_atom in d._iter_atoms_for_pkg(pkg):
if myarg.force_reinstall:
reinstall = true
break
except InvalidDependString:
if not installed:
continue
if not installed and myarg:
found_available_arg = true

if atom.package and atom.unevaluated_atom.use:
if pkg.iuse.get_missing_iuse(
atom.unevaluated_atom.use.required
):
continue

if atom.package and atom.use is not nil:

if (
autounmask_level
and autounmask_level.allow_use_changes
and not pkg.built
):
target_use = {}
for flag in atom.use.enabled:
target_use[flag] = true
for flag in atom.use.disabled:
target_use[flag] = false
use = d._pkg_use_enabled(pkg, target_use) else:
use = d._pkg_use_enabled(pkg)

use_match = true
can_adjust_use = not pkg.built
is_valid_flag = pkg.iuse.is_valid_flag
missing_enabled = frozenset(
x for x in atom.use.missing_enabled if not is_valid_flag(x)
)
missing_disabled = frozenset(
x for x in atom.use.missing_disabled if not is_valid_flag(x)
)

if atom.use.enabled:
if any(x in atom.use.enabled for x in missing_disabled):
use_match = false
can_adjust_use = false
need_enabled = atom.use.enabled - use
if need_enabled:
need_enabled -= missing_enabled
if need_enabled:
use_match = false
if can_adjust_use:
if any(x in pkg.use.mask for x in need_enabled):
can_adjust_use = false

if atom.use.disabled:
if any(x in atom.use.disabled for x in missing_enabled):
use_match = false
can_adjust_use = false
need_disabled = atom.use.disabled & use
if need_disabled:
need_disabled -= missing_disabled
if need_disabled:
use_match = false
if can_adjust_use:
if any(
x in pkg.use.force and x not in pkg.use.mask
for x in need_disabled
):
can_adjust_use = false

if not use_match:
if can_adjust_use:
packages_with_invalid_use_config.append(pkg)
continue

if atom_cp is nil or pkg.cp == atom_cp:
if highest_version is nil:
highest_version = pkg
elif pkg > highest_version:
highest_version = pkg
if find_existing_node:
e_pkg = next(
reversed(
list(
d._dynamic_config._package_tracker.match(
root, pkg.slot_atom, installed = false
)
)
),
nil,
)

if not e_pkg:
break

if atom.match(e_pkg.with_use(d._pkg_use_enabled(e_pkg))):
if (
highest_version
and (atom_cp is nil or e_pkg.cp == atom_cp)
and e_pkg < highest_version
and e_pkg.slot_atom != highest_version.slot_atom
):
pass else:
matched_packages.append(e_pkg)
existing_node = e_pkg
break
reinstall_use = (
"--newuse" in d._frozen_config.myopts
or "--reinstall" in d._frozen_config.myopts
)
changed_deps = (
d._dynamic_config.myparams.get("changed_deps", "n") != "n"
)
changed_deps_report = d._dynamic_config.myparams.get(
"changed_deps_report"
)
binpkg_changed_deps = (
d._dynamic_config.myparams.get("binpkg_changed_deps", "n")
!= "n"
)
respect_use = d._dynamic_config.myparams.get(
"binpkg_respect_use"
) in ("y", "auto")
if (
built
and not useoldpkg
and (not installed or matched_packages)
and not (
installed
and d._frozen_config.excluded_pkgs.findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
)
)
):
if (
myeb
and "--newrepo" in d._frozen_config.myopts
and myeb.repo != pkg.repo
):
break
elif d._dynamic_config.myparams.get(
"changed_slot"
) and d._changed_slot(pkg):
if installed:
break else:
continue
elif reinstall_use or (not installed and respect_use):
iuses = pkg.iuse.all
old_use = d._pkg_use_enabled(pkg)
if myeb:
now_use = d._pkg_use_enabled(myeb)
forced_flags = set(chain(myeb.use.force, myeb.use.mask))
else:
pkgsettings.setcpv(pkg)
now_use = pkgsettings["PORTAGE_USE"].split()
forced_flags = set(
chain(pkgsettings.useforce, pkgsettings.usemask)
)
cur_iuse = iuses
if myeb and not usepkgonly and not useoldpkg:
cur_iuse = myeb.iuse.all
reinstall_for_flags = d._reinstall_for_flags(
pkg, forced_flags, old_use, iuses, now_use, cur_iuse
)
if reinstall_for_flags:
if not pkg.installed:
d._dynamic_config.ignored_binaries.setdefault(
pkg, {}
).setdefault("respect_use", set()).update(
reinstall_for_flags
)
continue
break

installed_changed_deps = false
if installed and (changed_deps or changed_deps_report):
installed_changed_deps = d._changed_deps(pkg)

if (installed_changed_deps and changed_deps) or (
not installed
and binpkg_changed_deps
and d._changed_deps(pkg)
):
if not installed:
d._dynamic_config.ignored_binaries.setdefault(
pkg, {}
)["changed_deps"] = true
continue
break

if not installed and not useoldpkg and cpv in vardb.match(atom):
inst_pkg = vardb.match_pkgs(Atom("=" + pkg.cpv))[0]
if (
"--newrepo" in d._frozen_config.myopts
and pkg.repo != inst_pkg.repo
):
reinstall = true
elif reinstall_use:
forced_flags = set()
forced_flags.update(pkg.use.force)
forced_flags.update(pkg.use.mask)
old_use = inst_pkg.use.enabled
old_iuse = inst_pkg.iuse.all
cur_use = d._pkg_use_enabled(pkg)
cur_iuse = pkg.iuse.all
reinstall_for_flags = d._reinstall_for_flags(
pkg, forced_flags, old_use, old_iuse, cur_use, cur_iuse
)
if reinstall_for_flags:
reinstall = true
if reinstall_atoms.findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
):
reinstall = true
if not built:
myeb = pkg
elif useoldpkg:
matched_oldpkg.append(pkg)
matched_packages.append(pkg)
if reinstall_for_flags:
d._dynamic_config._reinstall_nodes[pkg] = reinstall_for_flags
break

if not matched_packages:
return nil, nil

if "--debug" in d._frozen_config.myopts:
for pkg in matched_packages:
portage.writemsg(
"%s %s%s%s\n"
% (
(pkg.type_name + ":").rjust(10),
pkg.cpv,
_repo_separator,
pkg.repo,
),
noiselevel = -1,
)

cp = atom_cp
if (
len(matched_packages) > 1
and cp is not nil
and "virtual" == portage.catsplit(cp)[0]
):
for pkg in matched_packages:
if pkg.cp != cp:
continue
matched_packages = [pkg for pkg in matched_packages if pkg.cp == cp]
break

if existing_node is not nil and existing_node in matched_packages:
return existing_node, existing_node

if len(matched_packages) > 1:
if (
parent is not nil
and (parent.root, parent.slot_atom)
in d._dynamic_config._slot_operator_replace_installed
):
if atom.slot_operator == "=" and atom.sub_slot is nil:
highest_installed = nil
for pkg in matched_packages:
if pkg.installed:
if (
highest_installed is nil
or pkg.version > highest_installed.version
):
highest_installed = pkg

if highest_installed and d._want_update_pkg(
parent, highest_installed
):
non_installed = [
pkg
for pkg in matched_packages
if not pkg.installed
and pkg.version > highest_installed.version
]

if non_installed:
matched_packages = non_installed

if rebuilt_binaries:
inst_pkg = nil
built_pkg = nil
unbuilt_pkg = nil
for pkg in matched_packages:
if pkg.installed:
inst_pkg = pkg
elif pkg.built:
built_pkg = pkg else:
if unbuilt_pkg is nil or pkg > unbuilt_pkg:
unbuilt_pkg = pkg
if built_pkg is not nil and inst_pkg is not nil:
built_timestamp = built_pkg.build_time
installed_timestamp = inst_pkg.build_time

if unbuilt_pkg is not nil and unbuilt_pkg > built_pkg:
pass
elif "--rebuilt-binaries-timestamp" in d._frozen_config.myopts:
minimal_timestamp = d._frozen_config.myopts[
"--rebuilt-binaries-timestamp"
]
if (
built_timestamp
and built_timestamp > installed_timestamp
and built_timestamp >= minimal_timestamp
):
return built_pkg, existing_node
else:
if built_timestamp and built_timestamp != installed_timestamp:
return built_pkg, existing_node

inst_pkg = nil
for pkg in matched_packages:
if pkg.installed:
inst_pkg = pkg
if pkg.installed and pkg.invalid:
matched_packages = [x for x in matched_packages if x is not pkg]

if (
inst_pkg is not nil
and parent is not nil
and not d._want_update_pkg(parent, inst_pkg)
):
return inst_pkg, existing_node

if avoid_update:
for pkg in matched_packages:
if pkg.installed and d._pkg_visibility_check(
pkg, autounmask_level
):
return pkg, existing_node

visible_matches = []
if matched_oldpkg:
visible_matches = [
pkg.cpv
for pkg in matched_oldpkg
if d._pkg_visibility_check(pkg, autounmask_level)
]
if not visible_matches:
visible_matches = [
pkg.cpv
for pkg in matched_packages
if d._pkg_visibility_check(pkg, autounmask_level)
]
if visible_matches:
bestmatch = portage.best(visible_matches) else:
bestmatch = portage.best([pkg.cpv for pkg in matched_packages])
matched_packages = [
pkg
for pkg in matched_packages
if portage.dep.cpvequal(pkg.cpv, bestmatch)
]

return matched_packages[-1], existing_node
}

// false, nil
func (d*depgraph) _select_pkg_from_graph(root, atom, onlydeps=false, parent=nil) {
	graph_db = d._dynamic_config._graph_trees[root]["porttree"].dbapi
	matches = graph_db.match_pkgs(atom)
	if not matches:
	return nil, nil

	for pkg
	in
	reversed(matches):
	if pkg in
	d._dynamic_config.digraph:
	return pkg, pkg

	return d._select_pkg_from_installed(
		root, atom, onlydeps = onlydeps, parent = parent
	)
}

// false, nil
func (d*depgraph) _select_pkg_from_installed(root, atom, onlydeps=false, parent=nil) {
	matches = list(
		d._iter_match_pkgs(d._frozen_config.roots[root], "installed", atom)
	)
	if not matches:
	return nil, nil
	if len(matches) > 1:
	matches.reverse()  # ascending
	order
	unmasked = [pkg for pkg in matches if d._pkg_visibility_check(pkg)]
if unmasked:
if len(unmasked) == 1:
matches = unmasked else:
unmasked = [pkg for pkg in matches if not pkg.masks]
if unmasked:
matches = unmasked
if len(matches) > 1:
unmasked = [
pkg
for pkg in matches
if d._equiv_ebuild_visible(pkg)
]
if unmasked:
matches = unmasked

pkg = matches[-1]  # highest match
in_graph = next(
d._dynamic_config._package_tracker.match(
root, pkg.slot_atom, installed = false
),
nil,
)

return pkg, in_graph
}

// nil
func (d*depgraph) _complete_graph(required_sets) {
	if "recurse" not
	in
	d._dynamic_config.myparams
	{
		return 1
	}

	complete_if_new_use = (
		d._dynamic_config.myparams.get("complete_if_new_use", "y") == "y"
	)
	complete_if_new_ver = (
		d._dynamic_config.myparams.get("complete_if_new_ver", "y") == "y"
	)
	rebuild_if_new_slot = (
		d._dynamic_config.myparams.get("rebuild_if_new_slot", "y") == "y"
	)
	complete_if_new_slot = rebuild_if_new_slot

	if "complete" not
	in
	d._dynamic_config.myparams
	and(
		complete_if_new_use
	or
	complete_if_new_ver
	or
	complete_if_new_slot
	):
	use_change = false
	version_change = false
	for node
	in
	d._dynamic_config.digraph:
	if not isinstance(node, Package)
	or
	node.operation != "merge":
	continue
	vardb = d._frozen_config.roots[node.root].trees["vartree"].dbapi

	if complete_if_new_use or
complete_if_new_ver:
	inst_pkg = vardb.match_pkgs(node.slot_atom)
	if inst_pkg and
	inst_pkg[0].cp == node.cp:
	inst_pkg = inst_pkg[0]
	if complete_if_new_ver:
	if inst_pkg < node or
	node < inst_pkg:
	version_change = true
	break
	elif
	not(
		inst_pkg.slot == node.slot
	and
	inst_pkg.sub_slot == node.sub_slot
	):
	version_change = true
	break

	if complete_if_new_use and(
		node.iuse.all != inst_pkg.iuse.all
	or(d._pkg_use_enabled(node) & node.iuse.all)
	!= d._pkg_use_enabled(inst_pkg).intersection(
		inst_pkg.iuse.all
	)
	):
	use_change = true
	break

	if complete_if_new_slot:
	cp_list = vardb.match_pkgs(Atom(node.cp))
	if (
		cp_list
		and
	cp_list[0].cp == node.cp
	and
	not
	any(
		node.slot == pkg.slot
	and
	node.sub_slot == pkg.sub_slot
	for pkg
	in
	cp_list
	)
):
	version_change = true
	break

	if use_change or
version_change:
	d._dynamic_config.myparams["complete"] = true

	if "complete" not
	in
	d._dynamic_config.myparams:
	return 1

	d._load_vdb()

	d._dynamic_config._complete_mode = true
	d._select_atoms = d._select_atoms_from_graph
	if "remove" in
	d._dynamic_config.myparams:
	d._select_package = d._select_pkg_from_installed
	else:
	d._select_package = d._select_pkg_from_graph
	d._dynamic_config._traverse_ignored_deps = true
	already_deep = d._dynamic_config.myparams.get("deep")
	is
	true
	if not already_deep:
	d._dynamic_config.myparams["deep"] = true

	for trees
	in
	d._dynamic_config._filtered_trees.values():
	trees["porttree"].dbapi._clear_cache()

	args = d._dynamic_config._initial_arg_list[:]
	for root
	in
	d._frozen_config.roots:
	if root != d._frozen_config.target_root and(
		"remove"
	in
	d._dynamic_config.myparams
	or
	d._frozen_config.myopts.get("--root-deps")
	is
	not
	nil
	):
	continue
	depgraph_sets = d._dynamic_config.sets[root]
	required_set_names = d._frozen_config._required_set_names.copy()
	remaining_args = required_set_names.copy()
	if required_sets is
	nil
	or
	root
	not
	in
required_sets:
	pass
	else:
	depgraph_sets.sets.clear()
	depgraph_sets.sets.update(required_sets[root])
	if "world" in
	depgraph_sets.sets:
	world_atoms = list(depgraph_sets.sets["world"])
	world_atoms.extend(
		SETPREFIX + s
	for s
	in
	required_sets[root]
	if s != "world"
)
	depgraph_sets.sets["world"] = InternalPackageSet(
		initial_atoms = world_atoms
	)
	required_set_names =
	{
		"world"
	}
	else:
	required_set_names = set(required_sets[root])
	if (
		"remove" not
	in
	d._dynamic_config.myparams
	and
	root == d._frozen_config.target_root
	and
	already_deep
	):
	remaining_args.difference_update(depgraph_sets.sets)
	if (
		not remaining_args
	and
	not
	d._dynamic_config._ignored_deps
	and
	not
	d._dynamic_config._dep_stack
	):
	continue
	root_config = d._frozen_config.roots[root]
	for s
	in
	sorted(required_set_names):
	pset = depgraph_sets.sets.get(s)
	if pset is
nil:
	pset = root_config.sets[s]
	atom = SETPREFIX + s
	args.append(
		SetArg(
			arg = atom, pset = pset, reset_depth = false, root_config=root_config
	)
)

	d._set_args(args)
	for arg
	in
	d._expand_set_args(args, add_to_digraph = true):
	for atom
	in
	sorted(arg.pset.getAtoms()):
	if not d._add_dep(
		Dependency(
			atom = atom,
		root = arg.root_config.root,
		parent=arg,
		depth = d._UNREACHABLE_DEPTH,
),
	allow_unsatisfied = true,
):
	return 0

	if true:
	if d._dynamic_config._ignored_deps:
	d._dynamic_config._dep_stack.extend(
		d._dynamic_config._ignored_deps
	)
	d._dynamic_config._ignored_deps = []
if not d._create_graph(allow_unsatisfied =true):
return 0
while d._dynamic_config._unsatisfied_deps:
dep = d._dynamic_config._unsatisfied_deps.pop()
vardb = d._frozen_config.roots[dep.root].trees["vartree"].dbapi
matches = vardb.match_pkgs(dep.atom)
if not matches:
d._dynamic_config._initially_unsatisfied_deps.append(dep)
continue
pkg = matches[-1]  # highest match

if (
d._dynamic_config._allow_backtracking
and not d._want_installed_pkg(pkg)
and (
dep.atom.soname
or (dep.atom.package and dep.atom.slot_operator_built)
)
):
dep.child = pkg
new_dep = d._slot_operator_update_probe(dep)
if new_dep is not nil:
d._slot_operator_update_backtrack(dep, new_dep = new_dep)
continue

if not d._add_pkg(pkg, dep):
return 0
if not d._create_graph(allow_unsatisfied = true):
return 0
return 1
}

// false, false, nil
func (d*depgraph) _pkg(cpv, type_name, root_config, installed=false, onlydeps=false, myrepo=nil) {

	root_config = d._frozen_config.roots[root_config.root]
	pkg = d._frozen_config._pkg_cache.get(
		Package._gen_hash_key(
			cpv = cpv,
		type_name = type_name,
		repo_name=myrepo,
		root_config = root_config,
		installed=installed,
		onlydeps = onlydeps,
)
)
	if pkg is
	nil
	and
	onlydeps
	and
	not
installed:
	for candidate
	in
	d._dynamic_config._package_tracker.match(
		root_config.root, Atom("="+cpv)
	):
	if (
		candidate.type_name == type_name
		and
	candidate.repo_name == myrepo
	and
	candidate.root_config
	is
	root_config
	and
	candidate.installed == installed
	and
	not
	candidate.onlydeps
	):
	pkg = candidate

	if pkg is
nil:
	tree_type = d.pkg_tree_map[type_name]
	db = root_config.trees[tree_type].dbapi
	db_keys = list(
		d._frozen_config._trees_orig[root_config.root][
			tree_type
		].dbapi._aux_cache_keys
	)

try:
	metadata = zip(db_keys, db.aux_get(cpv, db_keys, myrepo = myrepo))
	except
KeyError:
	raise
	portage.exception.PackageNotFound(cpv)

	db = getattr(db, "_db", db)
	if getattr(cpv, "_db", nil) is
	not
db:
	cpv = _pkg_str(cpv, db = db)

	pkg = Package(
		built = (type_name != "ebuild"),
		cpv = cpv,
		installed=installed,
		metadata = metadata,
		onlydeps=onlydeps,
		root_config = root_config,
		type_name=type_name,
)

	d._frozen_config._pkg_cache[pkg] = pkg

	if (
		not d._pkg_visibility_check(pkg)
	and
	"LICENSE"
	in
	pkg.masks
	and
	len(pkg.masks) == 1
	):
	slot_key = (pkg.root, pkg.slot_atom)
	other_pkg = d._frozen_config._highest_license_masked.get(slot_key)
	if other_pkg is
	nil
	or
	pkg > other_pkg:
	d._frozen_config._highest_license_masked[slot_key] = pkg

	return pkg
}

func (d*depgraph) _validate_blockers() {
	d._dynamic_config._blocked_pkgs = digraph()

	if "--nodeps" in
	d._frozen_config.myopts:
	return true

	if true:
	dep_keys = Package._runtime_keys
	for myroot
	in
	d._frozen_config.trees:

	if (
		d._frozen_config.myopts.get("--root-deps") is
	not
	nil
	and
	myroot != d._frozen_config.target_root
	):
	continue

	vardb = d._frozen_config.trees[myroot]["vartree"].dbapi
	pkgsettings = d._frozen_config.pkgsettings[myroot]
	root_config = d._frozen_config.roots[myroot]
	final_db = PackageTrackerDbapiWrapper(
		myroot, d._dynamic_config._package_tracker
	)

	blocker_cache = BlockerCache(myroot, vardb)
	stale_cache = set(blocker_cache)
	for pkg
	in
vardb:
	cpv = pkg.cpv
	stale_cache.discard(cpv)
	pkg_in_graph = d._dynamic_config.digraph.contains(pkg)
	pkg_deps_added = pkg
	in
	d._dynamic_config._traversed_pkg_deps

	if pkg in
	d._dynamic_config._package_tracker:
	if not d._pkg_visibility_check(pkg, trust_graph = false) and(
		pkg_in_graph
	or
	"LICENSE"
	in
	pkg.masks
	):
	d._dynamic_config._masked_installed.add(pkg)
	else:
	d._check_masks(pkg)

	blocker_atoms = nil
	blockers = nil
	if pkg_deps_added:
	blockers = []
try:
blockers.extend(
d._dynamic_config._blocker_parents.child_nodes(pkg)
)
except KeyError:
pass
try:
blockers.extend(
d._dynamic_config._irrelevant_blockers.child_nodes(
pkg
)
)
except KeyError:
pass
if blockers:
blockers = [
blocker
for blocker in blockers
if blocker.priority.runtime
or blocker.priority.runtime_post
]
if blockers is not nil:
blockers = set(blocker.atom for blocker in blockers)

d._spinner_update()
blocker_data = blocker_cache.get(cpv)
if blocker_data is not nil and blocker_data.counter != pkg.counter:
blocker_data = nil

if blocker_data is not nil and blockers is not nil:
if not blockers.symmetric_difference(blocker_data.atoms):
continue
blocker_data = nil

if blocker_data is nil and blockers is not nil:
blocker_atoms = sorted(blockers)
blocker_data = blocker_cache.BlockerData(
pkg.counter, blocker_atoms
)
blocker_cache[pkg.cpv] = blocker_data
continue

if blocker_data:
blocker_atoms = [Atom(atom) for atom in blocker_data.atoms]
else:
depstr = " ".join(vardb.aux_get(pkg.cpv, dep_keys))
try:
success, atoms = portage.dep_check(
depstr,
final_db,
pkgsettings,
myuse = d._pkg_use_enabled(pkg),
trees = d._dynamic_config._graph_trees,
myroot = myroot,
)
except SystemExit:
raise
except Exception as e:
show_invalid_depstring_notice(pkg, "%s" % (e, ))
del e
raise
if not success:
replacement_pkgs = (
d._dynamic_config._package_tracker.match(
myroot, pkg.slot_atom
)
)
if any(
replacement_pkg.operation == "merge"
for replacement_pkg in replacement_pkgs
):
continue
show_invalid_depstring_notice(pkg, atoms)
return false
blocker_atoms = [myatom for myatom in atoms if myatom.blocker]
blocker_atoms.sort()
blocker_cache[cpv] = blocker_cache.BlockerData(
pkg.counter, blocker_atoms
)
if blocker_atoms:
try:
for atom in blocker_atoms:
blocker = Blocker(
atom = atom,
eapi = pkg.eapi,
priority = d._priority(runtime = true),
root = myroot,
)
d._dynamic_config._blocker_parents.add(blocker, pkg)
except portage.exception.InvalidAtom as e:
depstr = " ".join(vardb.aux_get(pkg.cpv, dep_keys))
show_invalid_depstring_notice(
pkg, "Invalid Atom: %s" % (e, )
)
return false
for cpv in stale_cache:
del blocker_cache[cpv]
blocker_cache.flush()
del blocker_cache

previous_uninstall_tasks = d._dynamic_config._blocker_uninstalls.leaf_nodes()
if previous_uninstall_tasks:
d._dynamic_config._blocker_uninstalls = digraph()
d._dynamic_config.digraph.difference_update(previous_uninstall_tasks)

d._dynamic_config._blocker_parents.update(
d._dynamic_config._irrelevant_blockers
)
d._dynamic_config._irrelevant_blockers.clear()
d._dynamic_config._unsolvable_blockers.clear()

for blocker in d._dynamic_config._blocker_parents.leaf_nodes():
d._spinner_update()
root_config = d._frozen_config.roots[blocker.root]
virtuals = root_config.settings.getvirtuals()
myroot = blocker.root
initial_db = d._frozen_config.trees[myroot]["vartree"].dbapi

provider_virtual = false
if blocker.cp in virtuals and not d._have_new_virt(
blocker.root, blocker.cp
):
provider_virtual = true

atom_set = InternalPackageSet(initial_atoms = [blocker.atom])

if provider_virtual:
atoms = []
for provider_entry in virtuals[blocker.cp]:
atoms.append(
Atom(blocker.atom.replace(blocker.cp, provider_entry.cp, 1))
) else:
atoms = [blocker.atom]

blocked_initial = set()
for atom in atoms:
for pkg in initial_db.match_pkgs(atom):
if atom_set.findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
):
blocked_initial.add(pkg)

blocked_final = set()
for atom in atoms:
for pkg in d._dynamic_config._package_tracker.match(myroot, atom):
if atom_set.findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
):
blocked_final.add(pkg)

if not blocked_initial and not blocked_final:
parent_pkgs = d._dynamic_config._blocker_parents.parent_nodes(
blocker
)
d._dynamic_config._blocker_parents.remove(blocker)
for pkg in parent_pkgs:
d._dynamic_config._irrelevant_blockers.add(blocker, pkg)
if not d._dynamic_config._blocker_parents.child_nodes(pkg):
d._dynamic_config._blocker_parents.remove(pkg)
continue
for parent in d._dynamic_config._blocker_parents.parent_nodes(blocker):
unresolved_blocks = false
depends_on_order = set()
for pkg in blocked_initial:
if (
pkg.slot_atom == parent.slot_atom
and not blocker.atom.blocker.overlap.forbid
):
continue
if parent.installed:
continue

d._dynamic_config._blocked_pkgs.add(pkg, blocker)

if parent.operation == "merge":
depends_on_order.add((pkg, parent))
continue
unresolved_blocks = true
for pkg in blocked_final:
if (
pkg.slot_atom == parent.slot_atom
and not blocker.atom.blocker.overlap.forbid
):
continue
if parent.operation == "nomerge" and pkg.operation == "nomerge":
continue

d._dynamic_config._blocked_pkgs.add(pkg, blocker)

if parent.operation == "merge" and pkg.installed:
depends_on_order.add((pkg, parent))
continue
elif parent.operation == "nomerge":
depends_on_order.add((parent, pkg))
continue
unresolved_blocks = true

if "--buildpkgonly" in d._frozen_config.myopts and not (
blocker.priority.buildtime and blocker.atom.blocker.overlap.forbid
):
depends_on_order.clear()

if not unresolved_blocks and depends_on_order:
for inst_pkg, inst_task in depends_on_order:
if d._dynamic_config.digraph.contains(
inst_pkg
) and d._dynamic_config.digraph.parent_nodes(inst_pkg):
unresolved_blocks = true
break

if not unresolved_blocks and depends_on_order:
for inst_pkg, inst_task in depends_on_order:
uninst_task = Package(
built = inst_pkg.built,
cpv = inst_pkg.cpv,
installed = inst_pkg.installed,
metadata= inst_pkg._metadata,
operation = "uninstall",
root_config= inst_pkg.root_config,
type_name = inst_pkg.type_name,
)
d._dynamic_config.digraph.addnode(
uninst_task, inst_task, priority = BlockerDepPriority.instance
)
d._dynamic_config._blocker_uninstalls.addnode(
uninst_task, blocker
)
if not unresolved_blocks and not depends_on_order:
d._dynamic_config._irrelevant_blockers.add(blocker, parent)
d._dynamic_config._blocker_parents.remove_edge(blocker, parent)
if not d._dynamic_config._blocker_parents.parent_nodes(blocker):
d._dynamic_config._blocker_parents.remove(blocker)
if not d._dynamic_config._blocker_parents.child_nodes(parent):
d._dynamic_config._blocker_parents.remove(parent)
if unresolved_blocks:
d._dynamic_config._unsolvable_blockers.add(blocker, parent)

return true
}

func (d*depgraph) _accept_blocker_conflicts() {
	acceptable = false
	for x
	in("--buildpkgonly", "--fetchonly", "--fetch-all-uri", "--nodeps"):
	if x in
	d._frozen_config.myopts:
	acceptable = true
	break
	return acceptable
}

func (d*depgraph) _merge_order_bias( mygraph) {
	if not d._dynamic_config.myparams["implicit_system_deps"] {
		return
	}

	node_info =
	{
	}
	for node
	in
	mygraph.order:
	node_info[node] = len(mygraph.parent_nodes(node))
	deep_system_deps = _find_deep_system_runtime_deps(mygraph)

	def
	cmp_merge_preference(node1, node2):

	if node1.operation == "uninstall":
	if node2.operation == "uninstall":
	return 0
	return 1

	if node2.operation == "uninstall":
	if node1.operation == "uninstall":
	return 0
	return -1

	node1_sys = node1
	in
	deep_system_deps
	node2_sys = node2
	in
	deep_system_deps
	if node1_sys != node2_sys:
	if node1_sys:
	return -1
	return 1

	return node_info[node2] - node_info[node1]

	mygraph.order.sort(key = cmp_sort_key(cmp_merge_preference))
}

func (d*depgraph) altlist() {

	while
	d._dynamic_config._serialized_tasks_cache
	is
nil:
	d._resolve_conflicts()
try:
	(
		d._dynamic_config._serialized_tasks_cache,
		d._dynamic_config._scheduler_graph,
) = d._serialize_tasks()
	except
	d._serialize_tasks_retry:
	pass

	retlist = d._dynamic_config._serialized_tasks_cache
	if reversed is
	not
	DeprecationWarning
	and
reversed:
	retlist = list(retlist)
	retlist.reverse()
	retlist = tuple(retlist)

	return retlist
}

func (d*depgraph) _implicit_libc_deps(mergelist, graph) {
	libc_pkgs =
	{
	}
	implicit_libc_roots = (d._frozen_config._running_root.root,)
	for root
	in
implicit_libc_roots:
	vardb = d._frozen_config.trees[root]["vartree"].dbapi
	for atom
	in
	d._expand_virt_from_graph(
		root, portage.
	const.LIBC_PACKAGE_ATOM
	):
	if atom.blocker:
	continue
	for pkg
	in
	d._dynamic_config._package_tracker.match(root, atom):
	if pkg.operation == "merge" and
	not
	vardb.cpv_exists(pkg.cpv):
	libc_pkgs.setdefault(pkg.root, set()).add(pkg)

	if not libc_pkgs:
	return

	earlier_libc_pkgs = set()

	for pkg
	in
mergelist:
	if not isinstance(pkg, Package):
	continue
	root_libc_pkgs = libc_pkgs.get(pkg.root)
	if root_libc_pkgs is
	not
	nil
	and
	pkg.operation == "merge":
	if pkg in
root_libc_pkgs:
	earlier_libc_pkgs.add(pkg)
	else:
	for libc_pkg
	in
root_libc_pkgs:
	if libc_pkg in
earlier_libc_pkgs:
	graph.add(
		libc_pkg, pkg, priority = DepPriority(buildtime = true)
)
}

func (d*depgraph) schedulerGraph() {
	mergelist = d.altlist()
	d._implicit_libc_deps(mergelist, d._dynamic_config._scheduler_graph)

	for (
		parents,
	children,
		node,
) in
	d._dynamic_config._scheduler_graph.nodes.values():
	for priorities
	in
	chain(parents.values(), children.values()):
	for priority
	in
priorities:
	if priority.satisfied:
	priority.satisfied = true

	pkg_cache = d._frozen_config._pkg_cache
	graph = d._dynamic_config._scheduler_graph
	trees = d._frozen_config.trees
	pruned_pkg_cache =
	{
	}
	for key, pkg
	in
	pkg_cache.items():
	if pkg in
	graph
	or(
		pkg.installed
	and
	pkg
	in
	trees[pkg.root]["vartree"].dbapi
	):
	pruned_pkg_cache[key] = pkg

	for root
	in
trees:
	trees[root]["vartree"]._pkg_cache = pruned_pkg_cache

	d.break_refs()
	sched_config = _scheduler_graph_config(
		trees, pruned_pkg_cache, graph, mergelist
	)

	return sched_config
}

func (d*depgraph) break_refs() {
	for root_config
	in
	d._frozen_config.roots.values():
	root_config.update(
		d._frozen_config._trees_orig[root_config.root]["root_config"]
	)
	d._frozen_config._trees_orig[root_config.root][
		"root_config"
	] = root_config
}

func (d*depgraph) _resolve_conflicts() {

	if (
		"complete" not
	in
	d._dynamic_config.myparams
	and
	d._dynamic_config._allow_backtracking
	and
	any(d._dynamic_config._package_tracker.slot_conflicts())
	and
	not
	d._accept_blocker_conflicts()
	):
	d._dynamic_config.myparams["complete"] = true

	if not d._complete_graph():
	raise
	d._unknown_internal_error()

	d._process_slot_conflicts()
}

func (d*depgraph) _serialize_tasks() {

	debug = "--debug"
	in
	d._frozen_config.myopts

	if debug:
	writemsg("\ndigraph:\n\n", noiselevel = -1)
	d._dynamic_config.digraph.debug_print()
	writemsg("\n", noiselevel = -1)

	scheduler_graph = d._dynamic_config.digraph.copy()

	if "--nodeps" in
	d._frozen_config.myopts:
	return (
	[
		node
	for node
	in
	scheduler_graph
	if isinstance(node, Package) and
	node.operation == "merge"
],
scheduler_graph,
)

mygraph = d._dynamic_config.digraph.copy()

removed_nodes = set()

for node in mygraph:
if isinstance(node, DependencyArg):
removed_nodes.add(node)
if removed_nodes:
mygraph.difference_update(removed_nodes)
removed_nodes.clear()


while true:
for node in mygraph.root_nodes():
if not isinstance(node, Package) or node.installed or node.onlydeps:
removed_nodes.add(node)
if removed_nodes:
d._spinner_update()
mygraph.difference_update(removed_nodes)
if not removed_nodes:
break
removed_nodes.clear()
d._merge_order_bias(mygraph)
myblocker_uninstalls = d._dynamic_config._blocker_uninstalls.copy()
retlist = []
scheduled_uninstalls = set()
ignored_uninstall_tasks = set()
have_uninstall_task = false
complete = "complete" in d._dynamic_config.myparams
ignore_world = d._dynamic_config.myparams.get("ignore_world", false)
asap_nodes = []

def get_nodes(**kwargs):
return [
node
for node in mygraph.leaf_nodes(**kwargs)
if isinstance(node, Package)
and (node.operation != "uninstall" or node in scheduled_uninstalls)
]

running_root = d._frozen_config._running_root.root
runtime_deps = InternalPackageSet(initial_atoms = [PORTAGE_PACKAGE_ATOM])
running_portage = d._frozen_config.trees[running_root][
"vartree"
].dbapi.match_pkgs(Atom(PORTAGE_PACKAGE_ATOM))
replacement_portage = list(
d._dynamic_config._package_tracker.match(
running_root, Atom(PORTAGE_PACKAGE_ATOM)
)
)

if running_portage:
running_portage = running_portage[0] else:
running_portage = nil

if replacement_portage:
replacement_portage = replacement_portage[0] else:
replacement_portage = nil

if replacement_portage == running_portage:
replacement_portage = nil

if running_portage is not nil:
try:
portage_rdepend = d._select_atoms_highest_available(
running_root,
running_portage._metadata["RDEPEND"],
myuse = d._pkg_use_enabled(running_portage),
parent = running_portage,
strict = false,
)
except portage.exception.InvalidDependString as e:
portage.writemsg(
"!!! Invalid RDEPEND in "
+ "'%svar/db/pkg/%s/RDEPEND': %s\n"
% (running_root, running_portage.cpv, e),
noiselevel = -1,
)
del e
portage_rdepend = {running_portage: []}
for atoms in portage_rdepend.values():
runtime_deps.update(atom for atom in atoms if not atom.blocker)

implicit_libc_roots = (running_root, )
for root in implicit_libc_roots:
libc_pkgs = set()
vardb = d._frozen_config.trees[root]["vartree"].dbapi
for atom in d._expand_virt_from_graph(
root, portage.const.LIBC_PACKAGE_ATOM
):
if atom.blocker:
continue

for pkg in d._dynamic_config._package_tracker.match(root, atom):
if pkg.operation == "merge" and not vardb.cpv_exists(pkg.cpv):
libc_pkgs.add(pkg)

if libc_pkgs:
for atom in d._expand_virt_from_graph(
root, portage.const.OS_HEADERS_PACKAGE_ATOM
):
if atom.blocker:
continue

for pkg in d._dynamic_config._package_tracker.match(root, atom):
if pkg.operation == "merge" and not vardb.cpv_exists(pkg.cpv):
asap_nodes.append(pkg)

asap_nodes.extend(libc_pkgs)

def gather_deps(ignore_priority, mergeable_nodes, selected_nodes, node):
if node in selected_nodes:
return true
if node not in mergeable_nodes:
return false
if node == replacement_portage and any(
getattr(rdep, "operation", nil) != "uninstall"
for rdep in mygraph.child_nodes(
node, ignore_priority = priority_range.ignore_medium_soft
)
):
return false
selected_nodes.add(node)
for child in mygraph.child_nodes(node, ignore_priority = ignore_priority):
if not gather_deps(
ignore_priority, mergeable_nodes, selected_nodes, child
):
return false
return true

def ignore_uninst_or_med(priority):
if priority is BlockerDepPriority.instance:
return true
return priority_range.ignore_medium(priority)

def ignore_uninst_or_med_soft(priority):
if priority is BlockerDepPriority.instance:
return true
return priority_range.ignore_medium_soft(priority)

tree_mode = "--tree" in d._frozen_config.myopts
prefer_asap = true

drop_satisfied = false


while mygraph:
d._spinner_update()
selected_nodes = nil
ignore_priority = nil
cycle_digraph = nil
if prefer_asap and asap_nodes:
priority_range = DepPrioritySatisfiedRange else:
priority_range = DepPriorityNormalRange
if prefer_asap and asap_nodes:
asap_nodes = [node for node in asap_nodes if mygraph.contains(node)]
for i in range (priority_range.SOFT, priority_range.MEDIUM_SOFT + 1):
ignore_priority = priority_range.ignore_priority[i]
for node in asap_nodes:
if not mygraph.child_nodes(
node, ignore_priority = ignore_priority
):
selected_nodes = [node]
asap_nodes.remove(node)
break
if selected_nodes:
break

if not selected_nodes and not (prefer_asap and asap_nodes):
for i in range (priority_range.nil, priority_range.MEDIUM_SOFT + 1):
ignore_priority = priority_range.ignore_priority[i]
nodes = get_nodes(ignore_priority = ignore_priority)
if nodes:
good_uninstalls = nil
if len(nodes) > 1:
good_uninstalls = [
node for node in nodes if node.operation == "uninstall"
]

if good_uninstalls:
nodes = good_uninstalls
else:
nodes = nodes

if (
good_uninstalls
or len(nodes) == 1
or (
ignore_priority is nil
and not asap_nodes
and not tree_mode
)
):
selected_nodes = nodes
else:
if asap_nodes:
prefer_asap_parents = (true, false) else:
prefer_asap_parents = (false,)
for check_asap_parent in prefer_asap_parents:
if check_asap_parent:
for node in nodes:
parents = mygraph.parent_nodes(
node,
ignore_priority = DepPrioritySatisfiedRange.ignore_medium_soft,
)
if any(x in asap_nodes for x in parents):
selected_nodes = [node]
break
else:
for node in nodes:
if mygraph.parent_nodes(node):
selected_nodes = [node]
break
if selected_nodes:
break
if selected_nodes:
break

if not selected_nodes:

def find_smallest_cycle(mergeable_nodes, local_priority_range):
if prefer_asap and asap_nodes:
nodes = asap_nodes else:
nodes = mergeable_nodes
smallest_cycle = nil
ignore_priority = nil

nodes = sorted(nodes)
for priority in (
local_priority_range.ignore_priority[i]
for i in range (
local_priority_range.MEDIUM_POST,
local_priority_range.MEDIUM_SOFT + 1,
)
):
for node in nodes:
if not mygraph.parent_nodes(node):
continue
selected_nodes = set()
if gather_deps(
priority, mergeable_nodes, selected_nodes, node
):
if smallest_cycle is nil or len(selected_nodes) < len(
smallest_cycle
):
smallest_cycle = selected_nodes
ignore_priority = priority

if smallest_cycle is not nil:
break

return smallest_cycle, ignore_priority

priority_ranges = []
if priority_range is not DepPriorityNormalRange:
priority_ranges.append(DepPriorityNormalRange)
priority_ranges.append(priority_range)
if drop_satisfied and priority_range is not DepPrioritySatisfiedRange:
priority_ranges.append(DepPrioritySatisfiedRange)

for local_priority_range in priority_ranges:
mergeable_nodes = set(
get_nodes(ignore_priority= local_priority_range.ignore_medium)
)
if mergeable_nodes:
selected_nodes, ignore_priority = find_smallest_cycle(
mergeable_nodes, local_priority_range
)
if selected_nodes:
break

if not selected_nodes:
if prefer_asap and asap_nodes:
prefer_asap = false
continue else:
cycle_digraph = mygraph.copy()
cycle_digraph.difference_update(
[x for x in cycle_digraph if x not in selected_nodes]
)

leaves = cycle_digraph.leaf_nodes()
if leaves:
selected_nodes = [leaves[0]]

if debug:
writemsg(
"\nruntime cycle digraph (%s nodes):\n\n"
% (len(selected_nodes), ),
noiselevel =-1,
)
cycle_digraph.debug_print()
writemsg("\n", noiselevel = -1)

if leaves:
writemsg(
"runtime cycle leaf: %s\n\n" % (selected_nodes[0], ),
noiselevel = -1,
)

if selected_nodes and ignore_priority is not nil:
for node in selected_nodes:
children = set(mygraph.child_nodes(node))
medium_post_satisifed = children.difference(
mygraph.child_nodes(
node,
ignore_priority = DepPrioritySatisfiedRange.ignore_medium_post_satisifed,
)
)
medium_post = children.difference(
mygraph.child_nodes(
node,
ignore_priority = DepPrioritySatisfiedRange.ignore_medium_post,
)
)
medium_post -= medium_post_satisifed
for child in medium_post:
if child in selected_nodes:
continue
if child in asap_nodes:
continue
asap_nodes.append(child)

if selected_nodes and len(selected_nodes) > 1 and cycle_digraph is not nil:
ignore_priorities = list(
filter(
nil,
chain(
DepPriorityNormalRange.ignore_priority,
DepPrioritySatisfiedRange.ignore_priority,
),
)
)
selected_nodes = []
while cycle_digraph:
for ignore_priority in ignore_priorities:
leaves = cycle_digraph.leaf_nodes(
ignore_priority = ignore_priority
)
if leaves:
cycle_digraph.difference_update(leaves)
selected_nodes.extend(leaves)
break else:
selected_nodes.extend(cycle_digraph)
break

if not selected_nodes and myblocker_uninstalls:

if drop_satisfied:
priority_range = DepPrioritySatisfiedRange else:
priority_range = DepPriorityNormalRange

mergeable_nodes = get_nodes(ignore_priority= ignore_uninst_or_med)

min_parent_deps = nil
uninst_task = nil

for task in myblocker_uninstalls.leaf_nodes():

if task in ignored_uninstall_tasks:
continue

if task in scheduled_uninstalls:
continue

root_config = d._frozen_config.roots[task.root]
inst_pkg = d._pkg(
task.cpv, "installed", root_config, installed = true
)

if d._dynamic_config.digraph.contains(inst_pkg):
continue

forbid_overlap = false
heuristic_overlap = false
for blocker in myblocker_uninstalls.parent_nodes(task):
if not eapi_has_strong_blocks(blocker.eapi):
heuristic_overlap = true
elif blocker.atom.blocker.overlap.forbid:
forbid_overlap = true
break
if forbid_overlap and running_root == task.root:
continue

if heuristic_overlap and running_root == task.root:
try:
runtime_dep_atoms = list(
runtime_deps.iterAtomsForPackage(task)
)
except portage.exception.InvalidDependString as e:
portage.writemsg(
"!!! Invalid PROVIDE in "
+ "'%svar/db/pkg/%s/PROVIDE': %s\n"
% (task.root, task.cpv, e),
noiselevel = -1,
)
del e
continue

skip = false
vardb = root_config.trees["vartree"].dbapi
for atom in runtime_dep_atoms:
other_version = nil
for pkg in vardb.match_pkgs(atom):
if pkg.cpv == task.cpv and pkg.counter == task.counter:
continue
other_version = pkg
break
if other_version is nil:
skip = true
break
if skip:
continue

skip = false
try:
if d._dynamic_config.myparams[
"implicit_system_deps"
] and any(
root_config.sets["system"].iterAtomsForPackage(task)
):
skip = true
except portage.exception.InvalidDependString as e:
portage.writemsg(
"!!! Invalid PROVIDE in "
+ "'%svar/db/pkg/%s/PROVIDE': %s\n"
% (task.root, task.cpv, e),
noiselevel = -1,
)
del e
skip = true
if skip:
continue

if not (complete or ignore_world):
skip = false
try:
for atom in root_config.sets[
"selected"
].iterAtomsForPackage(task):
satisfied = false
for pkg in d._dynamic_config._package_tracker.match(
task.root, atom
):
if pkg == inst_pkg:
continue
satisfied = true
break
if not satisfied:
skip = true
d._dynamic_config._blocked_world_pkgs[
inst_pkg
] = atom
break
except portage.exception.InvalidDependString as e:
portage.writemsg(
"!!! Invalid PROVIDE in "
+ "'%svar/db/pkg/%s/PROVIDE': %s\n"
% (task.root, task.cpv, e),
noiselevel= -1,
)
del e
skip = true
if skip:
continue

d._spinner_update()
mergeable_parent = false
parent_deps = {task}
for parent in mygraph.parent_nodes(task):
parent_deps.update(
mygraph.child_nodes(
parent,
ignore_priority = priority_range.ignore_medium_soft,
)
)
if (
min_parent_deps is not nil
and len(parent_deps) >= min_parent_deps
):
mergeable_parent = nil
break
if parent in mergeable_nodes and gather_deps(
ignore_uninst_or_med_soft, mergeable_nodes, set(), parent
):
mergeable_parent = true

if not mergeable_parent:
continue

if min_parent_deps is nil or len(parent_deps) < min_parent_deps:
min_parent_deps = len(parent_deps)
uninst_task = task

if uninst_task is not nil and min_parent_deps == 1:
break

if uninst_task is not nil:
scheduled_uninstalls.add(uninst_task)
parent_nodes = mygraph.parent_nodes(uninst_task)

mygraph.remove(uninst_task)
for blocked_pkg in parent_nodes:
mygraph.add(
blocked_pkg,
uninst_task,
priority = BlockerDepPriority.instance,
)
scheduler_graph.remove_edge(uninst_task, blocked_pkg)
scheduler_graph.add(
blocked_pkg,
uninst_task,
priority = BlockerDepPriority.instance,
)

for slot_node in d._dynamic_config._package_tracker.match(
uninst_task.root, uninst_task.slot_atom
):
if slot_node.operation == "merge":
mygraph.add(
slot_node,
uninst_task,
priority= BlockerDepPriority.instance,
)

prefer_asap = true
drop_satisfied = false
continue

if not selected_nodes:
selected_nodes = get_nodes()

if not selected_nodes and not drop_satisfied:
drop_satisfied = true
continue

if not selected_nodes and myblocker_uninstalls:
uninst_task = nil
for node in myblocker_uninstalls.leaf_nodes():
try:
mygraph.remove(node)
except KeyError:
pass else:
uninst_task = node
ignored_uninstall_tasks.add(node)
break

if uninst_task is not nil:
prefer_asap = true
drop_satisfied = false
continue

if not selected_nodes:
d._dynamic_config._circular_deps_for_display = mygraph

unsolved_cycle = false
if d._dynamic_config._allow_backtracking:

backtrack_infos = d._dynamic_config._backtrack_infos
backtrack_infos.setdefault("config", {})
circular_dependency = backtrack_infos["config"].setdefault(
"circular_dependency", {}
)

cycles = mygraph.get_cycles(
ignore_priority= DepPrioritySatisfiedRange.ignore_medium_soft
)
for cycle in cycles:
for index, node in enumerate(cycle):
if node in d._dynamic_config._circular_dependency:
unsolved_cycle = true
if index == 0:
circular_child = cycle[-1] else:
circular_child = cycle[index - 1]
circular_dependency.setdefault(node, set()).add(
circular_child
)

if unsolved_cycle or not d._dynamic_config._allow_backtracking:
d._dynamic_config._skip_restart = true else:
d._dynamic_config._need_restart = true

raise d._unknown_internal_error()

prefer_asap = true
drop_satisfied = false

mygraph.difference_update(selected_nodes)

for node in selected_nodes:
if isinstance(node, Package) and node.operation == "nomerge":
continue

solved_blockers = set()
uninst_task = nil
if isinstance(node, Package) and "uninstall" == node.operation:
have_uninstall_task = true
uninst_task = node else:
vardb = d._frozen_config.trees[node.root]["vartree"].dbapi
inst_pkg = vardb.match_pkgs(node.slot_atom)
if inst_pkg:
inst_pkg = inst_pkg[0]
uninst_task = Package(
built = inst_pkg.built,
cpv = inst_pkg.cpv,
installed = inst_pkg.installed,
metadata = inst_pkg._metadata,
operation ="uninstall",
root_config = inst_pkg.root_config,
type_name =inst_pkg.type_name,
)
try:
mygraph.remove(uninst_task)
except KeyError:
pass

if (
uninst_task is not nil
and uninst_task not in ignored_uninstall_tasks
and myblocker_uninstalls.contains(uninst_task)
):
blocker_nodes = myblocker_uninstalls.parent_nodes(uninst_task)
myblocker_uninstalls.remove(uninst_task)
for blocker in blocker_nodes:
if not myblocker_uninstalls.child_nodes(blocker):
myblocker_uninstalls.remove(blocker)
if blocker not in d._dynamic_config._unsolvable_blockers:
solved_blockers.add(blocker)

retlist.append(node)

if (isinstance(node, Package) and "uninstall" == node.operation) or (
uninst_task is not nil and uninst_task in scheduled_uninstalls
):
retlist.extend(solved_blockers)

unsolvable_blockers = set(
d._dynamic_config._unsolvable_blockers.leaf_nodes()
)
unsolvable_blockers.update(myblocker_uninstalls.root_nodes())

if have_uninstall_task and not complete and not unsolvable_blockers:
d._dynamic_config.myparams["complete"] = true
if "--debug" in d._frozen_config.myopts:
msg = [
"enabling 'complete' depgraph mode " "due to uninstall task(s):",
"",
]
for node in retlist:
if isinstance(node, Package) and node.operation == "uninstall":
msg.append("\t%s" % (node, ))
writemsg_level(
"\n%s\n" % "".join("%s\n" % line for line in msg),
level = logging.DEBUG,
noiselevel= -1,
)
raise d._serialize_tasks_retry("")

for node in retlist:
if isinstance(node, Blocker):
node.satisfied = true

retlist.extend(unsolvable_blockers)
retlist = tuple(retlist)

buildtime_blockers = []
if unsolvable_blockers and "--buildpkgonly" in d._frozen_config.myopts:
for blocker in unsolvable_blockers:
if blocker.priority.buildtime and blocker.atom.blocker.overlap.forbid:
buildtime_blockers.append(blocker)

if unsolvable_blockers and (
buildtime_blockers or not d._accept_blocker_conflicts()
):
d._dynamic_config._unsatisfied_blockers_for_display = (
tuple(buildtime_blockers) if buildtime_blockers else unsolvable_blockers
)
d._dynamic_config._serialized_tasks_cache = retlist
d._dynamic_config._scheduler_graph = scheduler_graph
raise d._unknown_internal_error()

have_slot_conflict = any(d._dynamic_config._package_tracker.slot_conflicts())
if have_slot_conflict and not d._accept_blocker_conflicts():
d._dynamic_config._serialized_tasks_cache = retlist
d._dynamic_config._scheduler_graph = scheduler_graph
raise d._unknown_internal_error()

return retlist, scheduler_graph
}

func (d*depgraph) _show_circular_deps(mygraph) {
	d._dynamic_config._circular_dependency_handler = circular_dependency_handler(
		self, mygraph
	)
	handler = d._dynamic_config._circular_dependency_handler

	d._frozen_config.myopts.pop("--quiet", nil)
	d._frozen_config.myopts["--verbose"] = true
	d._frozen_config.myopts["--tree"] = true
	portage.writemsg("\n\n", noiselevel = -1)
	d.display(handler.merge_list)
	prefix = colorize("BAD", " * ")
	portage.writemsg("\n", noiselevel = -1)
	portage.writemsg(prefix+"Error: circular dependencies:\n", noiselevel = -1)
	portage.writemsg("\n", noiselevel = -1)

	if handler.circular_dep_message is
nil:
	handler.debug_print()
	portage.writemsg("\n", noiselevel = -1)

	if handler.circular_dep_message is
	not
nil:
	portage.writemsg(handler.circular_dep_message, noiselevel = -1)

	suggestions = handler.suggestions
	if suggestions:
	writemsg("\n\nIt might be possible to break this cycle\n", noiselevel = -1)
	if len(suggestions) == 1:
	writemsg("by applying the following change:\n", noiselevel = -1) else:
	writemsg(
		"by applying "
	+colorize("bold", "any of")
	+" the following changes:\n",
		noiselevel = -1,
)
	writemsg("".join(suggestions), noiselevel = -1)
	writemsg(
		"\nNote that this change can be reverted, once the package has"
	+" been installed.\n",
		noiselevel = -1,
)
	if handler.large_cycle_count:
	writemsg(
		"\nNote that the dependency graph contains a lot of cycles.\n"
	+"Several changes might be required to resolve all cycles.\n"
	+"Temporarily changing some use flag for all packages might be the better option.\n",
		noiselevel = -1,
) else:
	writemsg("\n\n", noiselevel = -1)
	writemsg(
		prefix
	+"Note that circular dependencies "
	+"can often be avoided by temporarily\n",
		noiselevel = -1,
)
	writemsg(
		prefix
	+"disabling USE flags that trigger "
	+"optional dependencies.\n",
		noiselevel = -1,
)
}

func (d*depgraph) _show_merge_list() {
	if d._dynamic_config._serialized_tasks_cache is
	not
	nil
	and
	not(
		d._dynamic_config._displayed_list
	is
	not
	nil
	and
	d._dynamic_config._displayed_list
	is
	d._dynamic_config._serialized_tasks_cache
	):
	d.display(d._dynamic_config._serialized_tasks_cache)
}

func (d*depgraph) _show_unsatisfied_blockers(blockers) {
	d._show_merge_list()
	msg = (
		"Error: The above package list contains "
	+"packages which cannot be installed "
	+"at the same time on the same system."
	)
	prefix = colorize("BAD", " * ")
	portage.writemsg("\n", noiselevel = -1)
	for line
	in
	textwrap.wrap(msg, 70):
	portage.writemsg(prefix+line+"\n", noiselevel = -1)


	conflict_pkgs =
	{
	}
	for blocker
	in
blockers:
	for pkg
	in
	chain(
		d._dynamic_config._blocked_pkgs.child_nodes(blocker),
		d._dynamic_config._blocker_parents.parent_nodes(blocker),
	):

	is_slot_conflict_pkg = false
	for conflict
	in
	d._dynamic_config._package_tracker.slot_conflicts():
	if conflict.root == pkg.root and
	conflict.atom == pkg.slot_atom:
	is_slot_conflict_pkg = true
	break
	if is_slot_conflict_pkg:
	continue
	parent_atoms = d._dynamic_config._parent_atoms.get(pkg)
	if not parent_atoms:
	atom = d._dynamic_config._blocked_world_pkgs.get(pkg)
	if atom is
	not
nil:
	parent_atoms =
	{
		("@selected", atom)
	}
	if parent_atoms:
	conflict_pkgs[pkg] = parent_atoms

	if conflict_pkgs:
	pruned_pkgs = set()
	for pkg, parent_atoms
	in
	conflict_pkgs.items():
	relevant_parent = false
	for parent, atom
	in
parent_atoms:
	if parent not
	in
conflict_pkgs:
	relevant_parent = true
	break
	if not relevant_parent:
	pruned_pkgs.add(pkg)
	for pkg
	in
pruned_pkgs:
	del
	conflict_pkgs[pkg]

	if conflict_pkgs:
	msg = ["\n"]
indent = "  "
for pkg, parent_atoms in conflict_pkgs.items():

preferred_parents = set()
for parent_atom in parent_atoms:
parent, atom = parent_atom
if parent not in conflict_pkgs:
preferred_parents.add(parent_atom)

ordered_list = list(preferred_parents)
if len(parent_atoms) > len(ordered_list):
for parent_atom in parent_atoms:
if parent_atom not in preferred_parents:
ordered_list.append(parent_atom)

msg.append(indent + "%s pulled in by\n" % pkg)

for parent_atom in ordered_list:
parent, atom = parent_atom
msg.append(2 * indent)
if isinstance(parent, (PackageArg, AtomArg)):
msg.append(str(parent)) else:
if isinstance(parent, Package):
use_display = pkg_use_display(
parent,
d._frozen_config.myopts,
modified_use= d._pkg_use_enabled(parent),
)
else:
use_display = ""
if atom.package and atom != atom.unevaluated_atom:
msg.append(
"%s (%s) required by %s %s"
% (atom.unevaluated_atom, atom, parent, use_display)
) else:
msg.append(
"%s required by %s %s" % (atom, parent, use_display)
)
msg.append("\n")

msg.append("\n")

writemsg("".join(msg), noiselevel= -1)

if "--quiet" not in d._frozen_config.myopts:
show_blocker_docs_link()
}

func (d*depgraph) display(mylist, favorites=[], verbosity=nil) {
	d._dynamic_config._displayed_list = mylist

	if "--tree" in
	d._frozen_config.myopts:
	mylist = tuple(reversed(mylist))

	display = Display()

	return display(self, mylist, favorites, verbosity)
}

// false
func (d*depgraph) _display_autounmask( autounmask_continue bool) {

	if d._dynamic_config._displayed_autounmask:
	return

	d._dynamic_config._displayed_autounmask = true

	ask = "--ask"
	in
	d._frozen_config.myopts
	autounmask_write = (
		autounmask_continue
	or
	d._frozen_config.myopts.get("--autounmask-write", ask)
	is
	true
	)
	autounmask_unrestricted_atoms = (
		d._frozen_config.myopts.get("--autounmask-unrestricted-atoms", "n")
	== true
	)
	quiet = "--quiet"
	in
	d._frozen_config.myopts
	pretend = "--pretend"
	in
	d._frozen_config.myopts
	enter_invalid = "--ask-enter-invalid"
	in
	d._frozen_config.myopts

	def
	check_if_latest(pkg, check_visibility = false):
	is_latest = true
	is_latest_in_slot = true
	dbs = d._dynamic_config._filtered_trees[pkg.root]["dbs"]
	root_config = d._frozen_config.roots[pkg.root]

	for db, pkg_type, built, installed, db_keys
	in
dbs:
	for other_pkg
	in
	d._iter_match_pkgs(
		root_config, pkg_type, Atom(pkg.cp)
	):
	if check_visibility and
	not
	d._pkg_visibility_check(other_pkg):
	continue
	if other_pkg.cp != pkg.cp:
	break
	if other_pkg > pkg:
	is_latest = false
	if other_pkg.slot_atom == pkg.slot_atom:
	is_latest_in_slot = false
	break
	else:
	break

	if not is_latest_in_slot:
	break

	return is_latest, is_latest_in_slot

	roots = set()

	masked_by_missing_keywords = false
	unstable_keyword_msg =
	{
	}
	for pkg
	in
	d._dynamic_config._needed_unstable_keywords:
	d._show_merge_list()
	if pkg in
	d._dynamic_config.digraph:
	root = pkg.root
	roots.add(root)
	unstable_keyword_msg.setdefault(root,[])
	is_latest, is_latest_in_slot = check_if_latest(pkg)
	pkgsettings = d._frozen_config.pkgsettings[pkg.root]
	mreasons = _get_masking_status(
		pkg, pkgsettings, pkg.root_config, use = d._pkg_use_enabled(pkg)
	)
	for reason
	in
mreasons:
	if (
		reason.unmask_hint
		and
	reason.unmask_hint.key == "unstable keyword"
	):
	keyword = reason.unmask_hint.value
	if keyword == "**":
	masked_by_missing_keywords = true

	unstable_keyword_msg[root].append(
		d._get_dep_chain_as_comment(pkg)
	)
	if autounmask_unrestricted_atoms:
	if is_latest:
	unstable_keyword_msg[root].append(
		">=%s %s\n"%(pkg.cpv, keyword)
	)
	elif
is_latest_in_slot:
	unstable_keyword_msg[root].append(
		">=%s:%s %s\n"%(pkg.cpv, pkg.slot, keyword)
	) else:
	unstable_keyword_msg[root].append(
		"=%s %s\n"%(pkg.cpv, keyword)
	) else:
	unstable_keyword_msg[root].append(
		"=%s %s\n"%(pkg.cpv, keyword)
	)

	p_mask_change_msg =
	{
	}
	for pkg
	in
	d._dynamic_config._needed_p_mask_changes:
	d._show_merge_list()
	if pkg in
	d._dynamic_config.digraph:
	root = pkg.root
	roots.add(root)
	p_mask_change_msg.setdefault(root,[])
	is_latest, is_latest_in_slot = check_if_latest(pkg)
	pkgsettings = d._frozen_config.pkgsettings[pkg.root]
	mreasons = _get_masking_status(
		pkg, pkgsettings, pkg.root_config, use = d._pkg_use_enabled(pkg)
	)
	for reason
	in
mreasons:
	if reason.unmask_hint and
	reason.unmask_hint.key == "p_mask":
	keyword = reason.unmask_hint.value

	comment, filename = portage.getmaskingreason(
		pkg.cpv,
		metadata = pkg._metadata,
		settings = pkgsettings,
		portdb=pkg.root_config.trees["porttree"].dbapi,
		return_location = true,
)

	p_mask_change_msg[root].append(
		d._get_dep_chain_as_comment(pkg)
	)
	if filename:
	p_mask_change_msg[root].append("# %s:\n" % filename)
	if comment:
	comment = [line for line in comment.splitlines() if line]
for line in comment:
p_mask_change_msg[root].append("%s\n" % line)
if autounmask_unrestricted_atoms:
if is_latest:
p_mask_change_msg[root].append(">=%s\n" % pkg.cpv)
elif is_latest_in_slot:
p_mask_change_msg[root].append(
">=%s:%s\n" % (pkg.cpv, pkg.slot)
) else:
p_mask_change_msg[root].append("=%s\n" % pkg.cpv)
else:
p_mask_change_msg[root].append("=%s\n" % pkg.cpv)

use_changes_msg = {}
for (
pkg,
needed_use_config_change,
) in d._dynamic_config._needed_use_config_changes.items():
d._show_merge_list()
if pkg in d._dynamic_config.digraph:
root = pkg.root
roots.add(root)
use_changes_msg.setdefault(root, [])
is_latest, is_latest_in_slot = check_if_latest(
pkg, check_visibility = true
)
changes = needed_use_config_change[1]
adjustments = []
for flag, state in changes.items():
if state:
adjustments.append(flag) else:
adjustments.append("-" + flag)
use_changes_msg[root].append(
d._get_dep_chain_as_comment(pkg, unsatisfied_dependency =true)
)
if is_latest:
use_changes_msg[root].append(
">=%s %s\n" % (pkg.cpv, " ".join(adjustments))
)
elif is_latest_in_slot:
use_changes_msg[root].append(
">=%s:%s %s\n" % (pkg.cpv, pkg.slot, " ".join(adjustments))
) else:
use_changes_msg[root].append(
"=%s %s\n" % (pkg.cpv, " ".join(adjustments))
)

license_msg = {}
for (
pkg,
missing_licenses,
) in d._dynamic_config._needed_license_changes.items():
d._show_merge_list()
if pkg in d._dynamic_config.digraph:
root = pkg.root
roots.add(root)
license_msg.setdefault(root, [])
is_latest, is_latest_in_slot = check_if_latest(pkg)

license_msg[root].append(d._get_dep_chain_as_comment(pkg))
if is_latest:
license_msg[root].append(
">=%s %s\n" % (pkg.cpv, " ".join(sorted(missing_licenses)))
)
elif is_latest_in_slot:
license_msg[root].append(
">=%s:%s %s\n"
% (pkg.cpv, pkg.slot, " ".join(sorted(missing_licenses)))
) else:
license_msg[root].append(
"=%s %s\n" % (pkg.cpv, " ".join(sorted(missing_licenses)))
)

def find_config_file(abs_user_config, file_name):
file_path = os.path.join(abs_user_config, file_name)

try:
os.lstat(file_path)
except OSError as e:
if e.errno == errno.ENOENT:
return file_path

return nil

last_file_path = nil
stack = [file_path]
while stack:
p = stack.pop()
try:
st = os.stat(p)
except OSError:
pass else:
if stat.S_ISREG(st.st_mode):
last_file_path = p
elif stat.S_ISDIR(st.st_mode):
if os.path.basename(p) in VCS_DIRS:
continue
try:
contents = os.listdir(p)
except OSError:
pass else:
contents.sort(reverse = true)
for child in contents:
if child.startswith(".") or child.endswith("~"):
continue
stack.append(os.path.join(p, child))
if last_file_path is nil:
last_file_path = os.path.join(file_path, file_path, "zz-autounmask")
with open(last_file_path, "a+") as default:
default.write("# " + file_name)

return last_file_path

write_to_file = autounmask_write and not pretend
file_to_write_to = {}
problems = []
if write_to_file:
for root in roots:
settings = d._frozen_config.roots[root].settings
abs_user_config = os.path.join(
settings["PORTAGE_CONFIGROOT"], USER_CONFIG_PATH
)

if root in unstable_keyword_msg:
if not os.path.exists(
os.path.join(abs_user_config, "package.keywords")
):
filename = "package.accept_keywords" else:
filename = "package.keywords"
file_to_write_to[
(abs_user_config, "package.keywords")
] = find_config_file(abs_user_config, filename)

if root in p_mask_change_msg:
file_to_write_to[
(abs_user_config, "package.unmask")
] = find_config_file(abs_user_config, "package.unmask")

if root in use_changes_msg:
file_to_write_to[
(abs_user_config, "package.use")
] = find_config_file(abs_user_config, "package.use")

if root in license_msg:
file_to_write_to[
(abs_user_config, "package.license")
] = find_config_file(abs_user_config, "package.license")

for (abs_user_config, f), path in file_to_write_to.items():
if path is nil:
problems.append(
"!!! No file to write for '%s'\n"
% os.path.join(abs_user_config, f)
)

write_to_file = not problems

def format_msg(lines):
lines = lines[:]
for i, line in enumerate(lines):
if line.startswith("#"):
continue
lines[i] = colorize("INFORM", line.rstrip()) + "\n"
return "".join(lines)

for root in roots:
settings = d._frozen_config.roots[root].settings
abs_user_config = os.path.join(
settings["PORTAGE_CONFIGROOT"], USER_CONFIG_PATH
)

if len(roots) > 1:
writemsg("\nFor %s:\n" % abs_user_config, noiselevel = -1)

def _writemsg(reason, file):
writemsg(
(
"\nThe following %s are necessary to proceed:\n"
' (see "%s" in the portage(5) man page for more details)\n'
)
% (colorize("BAD", reason), file),
noiselevel = -1,
)

if root in unstable_keyword_msg:
_writemsg("keyword changes", "package.accept_keywords")
writemsg(format_msg(unstable_keyword_msg[root]), noiselevel = -1)

if root in p_mask_change_msg:
_writemsg("mask changes", "package.unmask")
writemsg(format_msg(p_mask_change_msg[root]), noiselevel =-1)

if root in use_changes_msg:
_writemsg("USE changes", "package.use")
writemsg(format_msg(use_changes_msg[root]), noiselevel = -1)

if root in license_msg:
_writemsg("license changes", "package.license")
writemsg(format_msg(license_msg[root]), noiselevel = -1)

protect_obj = {}
if write_to_file and not autounmask_continue:
for root in roots:
settings = d._frozen_config.roots[root].settings
protect_obj[root] = ConfigProtect(
settings["PORTAGE_CONFIGROOT"],
shlex_split(settings.get("CONFIG_PROTECT", "")),
shlex_split(settings.get("CONFIG_PROTECT_MASK", "")),
case_insensitive = ("case-insensitive-fs" in settings.features),
)

def write_changes(root, changes, file_to_write_to):
file_contents = nil
try:
with io.open(
_unicode_encode(
file_to_write_to, encoding =_encodings["fs"], errors = "strict"
),
mode = "r",
encoding = _encodings["content"],
errors = "replace",
) as f:
file_contents = f.readlines()
except IOError as e:
if e.errno == errno.ENOENT:
file_contents = [] else:
problems.append(
"!!! Failed to read '%s': %s\n" % (file_to_write_to, e)
)
if file_contents is not nil:
file_contents.extend(changes)
if not autounmask_continue and protect_obj[root].isprotected(
file_to_write_to
):
file_to_write_to = new_protect_filename(
file_to_write_to, force = true
)
try:
write_atomic(file_to_write_to, "".join(file_contents))
except PortageException:
problems.append("!!! Failed to write '%s'\n" % file_to_write_to)

if not quiet and (p_mask_change_msg or masked_by_missing_keywords):
msg = [
"",
"NOTE: The --autounmask-keep-masks option will prevent emerge",
"      from creating package.unmask or ** keyword changes.",
]
for line in msg:
if line:
line = colorize("INFORM", line)
writemsg(line + "\n", noiselevel = -1)

if ask and write_to_file and file_to_write_to:
prompt = "\nWould you like to add these " + "changes to your config files?"
if d.query(prompt, enter_invalid) == "No":
write_to_file = false

if write_to_file and file_to_write_to:
for root in roots:
settings = d._frozen_config.roots[root].settings
abs_user_config = os.path.join(
settings["PORTAGE_CONFIGROOT"], USER_CONFIG_PATH
)
ensure_dirs(abs_user_config)

if root in unstable_keyword_msg:
write_changes(
root,
unstable_keyword_msg[root],
file_to_write_to.get((abs_user_config, "package.keywords")),
)

if root in p_mask_change_msg:
write_changes(
root,
p_mask_change_msg[root],
file_to_write_to.get((abs_user_config, "package.unmask")),
)

if root in use_changes_msg:
write_changes(
root,
use_changes_msg[root],
file_to_write_to.get((abs_user_config, "package.use")),
)

if root in license_msg:
write_changes(
root,
license_msg[root],
file_to_write_to.get((abs_user_config, "package.license")),
)

if problems:
writemsg(
"\nThe following problems occurred while writing autounmask changes:\n",
noiselevel =-1,
)
writemsg("".join(problems), noiselevel = -1)
elif write_to_file and roots:
writemsg("\nAutounmask changes successfully written.\n", noiselevel= -1)
if autounmask_continue:
return true
for root in roots:
chk_updated_cfg_files(root, [os.path.join(os.sep, USER_CONFIG_PATH)])
elif not pretend and not autounmask_write and roots:
writemsg(
"\nUse --autounmask-write to write changes to config files (honoring\n"
"CONFIG_PROTECT). Carefully examine the list of proposed changes,\n"
"paying special attention to mask or keyword changes that may expose\n"
"experimental or unstable packages.\n",
noiselevel = -1,
)

if d._dynamic_config._autounmask_backtrack_disabled:
msg = [
"In order to avoid wasting time, backtracking has terminated early",
"due to the above autounmask change(s). The --autounmask-backtrack=y",
"option can be used to force further backtracking, but there is no",
"guarantee that it will produce a solution.",
]
writemsg("\n", noiselevel = -1)
for line in msg:
writemsg(" %s %s\n" % (colorize("WARN", "*"), line), noiselevel = -1)
}

func (d*depgraph) display_problems() {

	if d._dynamic_config._circular_deps_for_display is
	not
nil:
	d._show_circular_deps(d._dynamic_config._circular_deps_for_display)

	unresolved_conflicts = false
	have_slot_conflict = any(d._dynamic_config._package_tracker.slot_conflicts())
	if have_slot_conflict:
	unresolved_conflicts = true
	d._show_slot_collision_notice()
	if d._dynamic_config._unsatisfied_blockers_for_display is
	not
nil:
	unresolved_conflicts = true
	d._show_unsatisfied_blockers(
		d._dynamic_config._unsatisfied_blockers_for_display
	)

	if not unresolved_conflicts:
	d._show_missed_update()

	if d._frozen_config.myopts.get("--verbose-slot-rebuilds", "y") != "n":
	d._compute_abi_rebuild_info()
	d._show_abi_rebuild_info()

	d._show_ignored_binaries()

	d._changed_deps_report()

	d._display_autounmask()

	for depgraph_sets
	in
	d._dynamic_config.sets.values():
	for pset
	in
	depgraph_sets.sets.values():
	for error_msg
	in
	pset.errors:
	writemsg_level(
		"%s\n"%(error_msg, ), level = logging.ERROR, noiselevel = -1
	)


	if d._dynamic_config._missing_args:
	world_problems = false
	if (
		"world"
		in
	d._dynamic_config.sets[d._frozen_config.target_root].sets
	):
	world_set = d._frozen_config.roots[
		d._frozen_config.target_root
	].sets["selected"]
	for arg, atom
	in
	d._dynamic_config._missing_args:
	if arg.name in("selected", "world")
	and
	atom
	in
world_set:
	world_problems = true
	break

	if world_problems:
	writemsg(
		"\n!!! Problems have been "+"detected with your world file\n",
		noiselevel = -1,
)
	writemsg(
		"!!! Please run "+green("emaint --check world")+"\n\n",
		noiselevel = -1,
)

	if d._dynamic_config._missing_args:
	writemsg(
		"\n"
	+colorize("BAD", "!!!")
	+" Ebuilds for the following packages are either all\n",
		noiselevel = -1,
)
	writemsg(
		colorize("BAD", "!!!")+" masked or don't exist:\n", noiselevel = -1
	)
	writemsg(
		" ".join(str(atom)
	for arg, atom
	in
	d._dynamic_config._missing_args)
	+"\n",
		noiselevel = -1,
)

	if d._dynamic_config._pprovided_args:
	arg_refs =
	{
	}
	for arg, atom
	in
	d._dynamic_config._pprovided_args:
	if isinstance(arg, SetArg):
	parent = arg.name
	arg_atom = (atom, atom) else:
	parent = "args"
	arg_atom = (arg.arg, atom)
	refs = arg_refs.setdefault(arg_atom,[])
	if parent not
	in
refs:
	refs.append(parent)
	msg = [bad("\nWARNING: ")]
if len(d._dynamic_config._pprovided_args) > 1:
msg.append(
"Requested packages will not be "
+ "merged because they are listed in\n"
) else:
msg.append(
"A requested package will not be "
+ "merged because it is listed in\n"
)
msg.append("package.provided:\n\n")
problems_sets = set()
for (arg, atom), refs in arg_refs.items():
ref_string = ""
if refs:
problems_sets.update(refs)
refs.sort()
ref_string = ", ".join(["'%s'" % name for name in refs])
ref_string = " pulled in by " + ref_string
msg.append("  %s%s\n" % (colorize("INFORM", str(arg)), ref_string))
msg.append("\n")
if "selected" in problems_sets or "world" in problems_sets:
msg.append(
"This problem can be solved in one of the following ways:\n\n"
"  A) Use emaint to clean offending packages from world (if not installed).\n"
"  B) Uninstall offending packages (cleans them from world).\n"
"  C) Remove offending entries from package.provided.\n\n"
"The best course of action depends on the reason that an offending\n"
"package.provided entry exists.\n\n"
)
writemsg("".join(msg), noiselevel = -1)

masked_packages = []
for pkg in d._dynamic_config._masked_license_updates:
root_config = pkg.root_config
pkgsettings = d._frozen_config.pkgsettings[pkg.root]
mreasons = get_masking_status(
pkg, pkgsettings, root_config, use = d._pkg_use_enabled(pkg)
)
masked_packages.append(
(root_config, pkgsettings, pkg.cpv, pkg.repo, pkg._metadata, mreasons)
)
if masked_packages:
writemsg(
"\n"
+ colorize("BAD", "!!!")
+ " The following updates are masked by LICENSE changes:\n",
noiselevel = -1,
)
show_masked_packages(masked_packages)
show_mask_docs()
writemsg("\n", noiselevel = -1)

masked_packages = []
for pkg in d._dynamic_config._masked_installed:
root_config = pkg.root_config
pkgsettings = d._frozen_config.pkgsettings[pkg.root]
mreasons = get_masking_status(
pkg, pkgsettings, root_config, use = d._pkg_use_enabled
)
masked_packages.append(
(root_config, pkgsettings, pkg.cpv, pkg.repo, pkg._metadata, mreasons)
)
if masked_packages:
writemsg(
"\n"
+ colorize("BAD", "!!!")
+ " The following installed packages are masked:\n",
noiselevel = -1,
)
show_masked_packages(masked_packages)
show_mask_docs()
writemsg("\n", noiselevel = -1)

for pargs, kwargs in d._dynamic_config._unsatisfied_deps_for_display:
d._show_unsatisfied_dep(*pargs, **kwargs)

if d._dynamic_config._buildpkgonly_deps_unsatisfied:
d._show_merge_list()
writemsg(
"\n!!! --buildpkgonly requires all " "dependencies to be merged.\n",
noiselevel= -1,
)
writemsg(
"!!! Cannot merge requested packages. " "Merge deps and try again.\n\n",
noiselevel = -1,
)

if d._dynamic_config._quickpkg_direct_deps_unsatisfied:
d._show_merge_list()
writemsg(
"\n!!! --quickpkg-direct requires all "
"dependencies to be merged for root '{}'.\n".format(
d._frozen_config._running_root.root
),
noiselevel= -1,
)
writemsg(
"!!! Cannot merge requested packages. " "Merge deps and try again.\n\n",
noiselevel = -1,
)
}

func (d*depgraph) saveNomergeFavorites() {
	for x
	in(
		"--buildpkgonly",
		"--fetchonly",
		"--fetch-all-uri",
		"--oneshot",
		"--onlydeps",
		"--pretend",
	):
	if x in
	d._frozen_config.myopts:
	return
	root_config = d._frozen_config.roots[d._frozen_config.target_root]
	world_set = root_config.sets["selected"]

	world_locked = false
	if hasattr(world_set, "lock"):
	world_set.lock()
	world_locked = true

	if hasattr(world_set, "load"):
	world_set.load()  # maybe
	it
	's changed on disk

	args_set = d._dynamic_config.sets[d._frozen_config.target_root].sets[
		"__non_set_args__"
	]
	added_favorites = set()
	for x
	in
	d._dynamic_config._set_nodes:
	if x.operation != "nomerge":
	continue

	if x.root != root_config.root:
	continue

try:
	myfavkey = create_world_atom(x, args_set, root_config)
	if myfavkey:
	if myfavkey in
added_favorites:
	continue
	added_favorites.add(myfavkey)
	except
	portage.exception.InvalidDependString
	as
e:
	writemsg(
		"\n\n!!! '%s' has invalid PROVIDE: %s\n"%(x.cpv, e), noiselevel = -1
	)
	writemsg(
		"!!! see '%s'\n\n"
	% os.path.join(x.root, portage.VDB_PATH, x.cpv, "PROVIDE"),
		noiselevel = -1,
)
	del
	e
	all_added = []
for arg in d._dynamic_config._initial_arg_list:
if not isinstance(arg, SetArg):
continue
if arg.root_config.root != root_config.root:
continue
if arg.internal:
continue
k = arg.name
if k in ("selected", "world") or not root_config.sets[k].world_candidate:
continue
s = SETPREFIX + k
if s in world_set:
continue
all_added.append(s)
all_added.extend(added_favorites)
if all_added:
all_added.sort()
skip = false
if "--ask" in d._frozen_config.myopts:
writemsg_stdout("\n", noiselevel = -1)
for a in all_added:
writemsg_stdout(
" %s %s\n" % (colorize("GOOD", "*"), a), noiselevel =-1
)
writemsg_stdout("\n", noiselevel= -1)
prompt = (
"Would you like to add these packages to your world " "favorites?"
)
enter_invalid = "--ask-enter-invalid" in d._frozen_config.myopts
if d.query(prompt, enter_invalid) == "No":
skip = true

if not skip:
for a in all_added:
if a.startswith(SETPREFIX):
filename = "world_sets"
else:
filename = "world"
writemsg_stdout(
'>>> Recording %s in "%s" favorites file...\n'
% (colorize("INFORM", str(a)), filename),
noiselevel = -1,
)
world_set.update(all_added)

if world_locked:
world_set.unlock()
}

// true, true
func (d*depgraph) _loadResumeCommand(resume_data, skip_masked=true, skip_missing=true) {

	d._load_vdb()

	if not isinstance(resume_data, dict):
	return false

	mergelist = resume_data.get("mergelist")
	if not isinstance(mergelist, list):
	mergelist = []

favorites = resume_data.get("favorites")
if isinstance(favorites, list):
args = d._load_favorites(favorites) else:
args = []

serialized_tasks = []
masked_tasks = []
for x in mergelist:
if not (isinstance(x, list) and len(x) == 4):
continue
pkg_type, myroot, pkg_key, action = x
if pkg_type not in d.pkg_tree_map:
continue
if action != "merge":
continue
root_config = d._frozen_config.roots[myroot]

depgraph_sets = d._dynamic_config.sets[root_config.root]
repo = nil
for atom in depgraph_sets.atoms.getAtoms():
if atom.repo and portage.dep.match_from_list(atom, [pkg_key]):
repo = atom.repo
break

atom = "=" + pkg_key
if repo:
atom = atom + _repo_separator + repo

try:
atom = Atom(atom, allow_repo = true)
except InvalidAtom:
continue

pkg = nil
for pkg in d._iter_match_pkgs(root_config, pkg_type, atom):
if not d._pkg_visibility_check(
pkg
) or d._frozen_config.excluded_pkgs.findAtomForPackage(
pkg, modified_use = d._pkg_use_enabled(pkg)
):
continue
break

if pkg is nil:
if skip_missing:
continue
raise portage.exception.PackageNotFound(pkg_key)

if (
"merge" == pkg.operation
and d._frozen_config.excluded_pkgs.findAtomForPackage(
pkg, modified_use= d._pkg_use_enabled(pkg)
)
):
continue

if "merge" == pkg.operation and not d._pkg_visibility_check(pkg):
if skip_masked:
masked_tasks.append(Dependency(root =pkg.root, parent = pkg))
else:
d._dynamic_config._unsatisfied_deps_for_display.append(
((pkg.root, "=" + pkg.cpv), {"myparent": nil})
)

d._dynamic_config._package_tracker.add_pkg(pkg)
serialized_tasks.append(pkg)
d._spinner_update()

if d._dynamic_config._unsatisfied_deps_for_display:
return false

if not serialized_tasks or "--nodeps" in d._frozen_config.myopts:
d._dynamic_config._serialized_tasks_cache = serialized_tasks
d._dynamic_config._scheduler_graph = d._dynamic_config.digraph
else:
d._select_package = d._select_pkg_from_graph
d._dynamic_config.myparams["selective"] = true
d._dynamic_config.myparams["deep"] = true

for task in serialized_tasks:
if isinstance(task, Package) and task.operation == "merge":
if not d._add_pkg(task, nil):
return false

for arg in d._expand_set_args(args, add_to_digraph = true):
for atom in sorted(arg.pset.getAtoms()):
pkg, existing_node = d._select_package(
arg.root_config.root, atom
)
if existing_node is nil and pkg is not nil:
if not d._add_pkg(
pkg, Dependency(atom = atom, root = pkg.root, parent = arg)
):
return false

if not d._create_graph(allow_unsatisfied = true):
return false

unsatisfied_deps = []
for dep in d._dynamic_config._unsatisfied_deps:
if not isinstance(dep.parent, Package):
continue
if dep.parent.operation == "merge":
unsatisfied_deps.append(dep)
continue

unsatisfied_install = false
traversed = set()
dep_stack = d._dynamic_config.digraph.parent_nodes(dep.parent)
while dep_stack:
node = dep_stack.pop()
if not isinstance(node, Package):
continue
if node.operation == "merge":
unsatisfied_install = true
break
if node in traversed:
continue
traversed.add(node)
dep_stack.extend(d._dynamic_config.digraph.parent_nodes(node))

if unsatisfied_install:
unsatisfied_deps.append(dep)

if masked_tasks or unsatisfied_deps:
raise d.UnsatisfiedResumeDep(self, masked_tasks + unsatisfied_deps)
d._dynamic_config._serialized_tasks_cache = nil
try:
d.altlist()
except d._unknown_internal_error:
return false

return true
}

func (d*depgraph) _load_favorites( favorites) {
	root_config = d._frozen_config.roots[d._frozen_config.target_root]
	sets = root_config.sets
	depgraph_sets = d._dynamic_config.sets[root_config.root]
	args = []
for x in favorites:
if not isinstance(x, str):
continue
if x in ("system", "world"):
x = SETPREFIX + x
if x.startswith(SETPREFIX):
s = x[len(SETPREFIX):]
if s not in sets:
continue
if s in depgraph_sets.sets:
continue
pset = sets[s]
depgraph_sets.sets[s] = pset
args.append(SetArg(arg = x, pset = pset, root_config= root_config)) else:
try:
x = Atom(x, allow_repo = true)
except portage.exception.InvalidAtom:
continue
args.append(AtomArg(arg = x, atom= x, root_config = root_config))

d._set_args(args)
return args
}

type UnsatisfiedResumeDep struct { //(portage.exception.PortageException):
	depgraph
}

func NewUnsatisfiedResumeDep(depgraph, value) *UnsatisfiedResumeDep{
	u := &UnsatisfiedResumeDep{}
	portage.exception.PortageException.__init__(self, value)
	u.depgraph = depgraph
	return u
}

type _internal_exception struct { //(portage.exception.PortageException):
	
}

func New_internal_exception()*_internal_exception{
	i := &_internal_exception{}
	portage.exception.PortageException.__init__(self, value)
	return i
}

type _unknown_internal_error _internal_exception

type _serialize_tasks_retry _internal_exception

type _backtrack_mask _internal_exception

type _autounmask_breakage _internal_exception

func(d*depgraph) need_restart() {
	return (
		d._dynamic_config._need_restart
	and
	not
	d._dynamic_config._skip_restart
	)
}

func(d*depgraph) need_display_problems() bool {
	if d.need_config_change():
	return true
	if d._dynamic_config._circular_deps_for_display:
	return true
	return false
}

func(d*depgraph) need_config_change()bool {
	if (
		d._dynamic_config._success_without_autounmask
		or
	d._dynamic_config._required_use_unsatisfied
	):
	return true

	if (
		d._dynamic_config._slot_conflict_handler is
	nil
	and
	not
	d._accept_blocker_conflicts()
	and
	any(d._dynamic_config._package_tracker.slot_conflicts())
	):
	d._dynamic_config._slot_conflict_handler = slot_conflict_handler(self)
	if d._dynamic_config._slot_conflict_handler.changes:
	return true

	if (
		d._dynamic_config._allow_backtracking
		and
	d._frozen_config.myopts.get("--autounmask-backtrack") != "y"
	and
	d._have_autounmask_changes()
	):

	if (
		d._frozen_config.myopts.get("--autounmask-continue") is
	true
	and
	d._frozen_config.myopts.get("--autounmask-backtrack") != "n"
	):
	return false

	d._dynamic_config._autounmask_backtrack_disabled = true
	return true

	return false
}

func(d*depgraph) _have_autounmask_changes() {
	digraph_nodes = d._dynamic_config.digraph.nodes
	return (
		any(
			x
	in
	digraph_nodes
	for x
	in
	d._dynamic_config._needed_unstable_keywords
	)
	or
	any(
		x
	in
	digraph_nodes
	for x
	in
	d._dynamic_config._needed_p_mask_changes
	)
	or
	any(
		x
	in
	digraph_nodes
	for x
	in
	d._dynamic_config._needed_use_config_changes
	)
	or
	any(
		x
	in
	digraph_nodes
	for x
	in
	d._dynamic_config._needed_license_changes
	)
)
}

func(d*depgraph) need_config_reload() {
	return d._dynamic_config._need_config_reload
}

func(d*depgraph) autounmask_breakage_detected() {
try:
	for pargs, kwargs
	in
	d._dynamic_config._unsatisfied_deps_for_display:
	d._show_unsatisfied_dep(
		*pargs, check_autounmask_breakage = true, **kwargs
	)
	except
	d._autounmask_breakage:
	return true
	return false
}

func(d*depgraph) get_backtrack_infos() {
	return d._dynamic_config._backtrack_infos
}

type _dep_check_composite_db struct { //(dbapi):
}

func New_dep_check_composite_db( depgraph, root) *_dep_check_composite_db{
	d := &_dep_check_composite_db{}
	dbapi.__init__(self)
	d._depgraph = depgraph
	d._root = root
	d._match_cache =
	{
	}
	d._cpv_pkg_map =
	{
	}
	return d
}

func(d *_dep_check_composite_db) _clear_cache() {
	d._match_cache.clear()
	d._cpv_pkg_map.clear()
}

func(d *_dep_check_composite_db) cp_list( cp) {
	if isinstance(cp, Atom):
	atom = cp
	else:
	atom = Atom(cp)
	ret = []
for pkg in d._depgraph._iter_match_pkgs_any(
d._depgraph._frozen_config.roots[d._root], atom
):
if pkg.cp == cp:
ret.append(pkg.cpv)
break

return ret
}

func(d *_dep_check_composite_db) match_pkgs( atom) {
	cache_key = (atom, atom.unevaluated_atom)
	ret = d._match_cache.get(cache_key)
	if ret is
	not
nil:
	for pkg
	in
ret:
	d._cpv_pkg_map[pkg.cpv] = pkg
	return ret[:]

	atom_set = InternalPackageSet(initial_atoms = (atom,))
	ret = []
pkg, existing = d._depgraph._select_package(d._root, atom)

if pkg is not nil and d._visible(pkg, atom_set):
ret.append(pkg)

if (
pkg is not nil
and atom.sub_slot is nil
and pkg.cp.startswith("virtual/")
and (
(
"remove" not in d._depgraph._dynamic_config.myparams
and "--update" not in d._depgraph._frozen_config.myopts
)
or not ret
)
):
sub_slots = set()
resolved_sub_slots = set()
for virt_pkg in d._depgraph._iter_match_pkgs_any(
d._depgraph._frozen_config.roots[d._root], atom
):
if virt_pkg.cp != pkg.cp:
continue
sub_slots.add((virt_pkg.slot, virt_pkg.sub_slot))

sub_slot_key = (pkg.slot, pkg.sub_slot)
if ret:
sub_slots.discard(sub_slot_key)
resolved_sub_slots.add(sub_slot_key) else:
sub_slots.add(sub_slot_key)

while sub_slots:
slot, sub_slot = sub_slots.pop()
slot_atom = atom.with_slot("%s/%s" % (slot, sub_slot))
pkg, existing = d._depgraph._select_package(d._root, slot_atom)
if not pkg:
continue
if not d._visible(pkg, atom_set, avoid_slot_conflict = false):
selected = pkg
for candidate in d._iter_virt_update(pkg, atom_set):

if candidate.slot != slot:
continue

if (candidate.slot, candidate.sub_slot) in resolved_sub_slots:
continue

if selected is nil or selected < candidate:
selected = candidate

if selected is pkg:
continue
pkg = selected

resolved_sub_slots.add((pkg.slot, pkg.sub_slot))
ret.append(pkg)

if len(ret) > 1:
ret = sorted(set(ret))

d._match_cache[cache_key] = ret
for pkg in ret:
d._cpv_pkg_map[pkg.cpv] = pkg
return ret[:]
}

// true, true
func(d *_dep_check_composite_db) _visible(pkg, atom_set, avoid_slot_conflict=true, probe_virt_update=true)bool {
	if pkg.installed and
	not
	d._depgraph._want_installed_pkg(pkg):
	return false
	if pkg.installed and(
		pkg.masks
	or
	not
	d._depgraph._pkg_visibility_check(pkg)
	):
	myopts = d._depgraph._frozen_config.myopts
	use_ebuild_visibility = myopts.get("--use-ebuild-visibility", "n") != "n"
	avoid_update = (
		"--update"
	not
	in
	myopts
	and
	"remove"
	not
	in
	d._depgraph._dynamic_config.myparams
	)
	usepkgonly = "--usepkgonly"
	in
	myopts
	if not avoid_update:
	if not use_ebuild_visibility
	and
usepkgonly:
	return false
	if not d._depgraph._equiv_ebuild_visible(pkg):
	return false

	if pkg.cp.startswith("virtual/"):

	if not d._depgraph._virt_deps_visible(pkg, ignore_use = true):
	return false

	if probe_virt_update and
	d._have_virt_update(pkg, atom_set):
	return false

	if not avoid_slot_conflict:
	return true

	in_graph = next(
		reversed(
			list(
				d._depgraph._dynamic_config._package_tracker.match(
					d._root, pkg.slot_atom, installed = false
	)
)
),
	nil,
)

	if in_graph is
nil:
	highest_visible, in_graph = d._depgraph._select_package(
		d._root, pkg.slot_atom
	)
	if (
		highest_visible is
	not
	nil
	and
	pkg < highest_visible
	and
	atom_set.findAtomForPackage(
		highest_visible,
		modified_use = d._depgraph._pkg_use_enabled(highest_visible),
)
):
	return false
	elif
	in_graph != pkg:
	if not atom_set.findAtomForPackage(
		in_graph, modified_use = d._depgraph._pkg_use_enabled(in_graph)
	):
	return true
	return false
	return true
}

func(d *_dep_check_composite_db) _iter_virt_update(pkg, atom_set) {

	if (
		d._depgraph._select_atoms_parent is
	not
	nil
	and
	d._depgraph._want_update_pkg(
		d._depgraph._select_atoms_parent, pkg
	)
	):

	for new_child
	in
	d._depgraph._iter_similar_available(
		pkg, next(iter(atom_set))
	):

	if not d._depgraph._virt_deps_visible(new_child, ignore_use = true):
	continue

	if not d._visible(
		new_child,
		atom_set,
		avoid_slot_conflict = false,
		probe_virt_update = false,
):
	continue

	yield
	new_child
}

func(d *_dep_check_composite_db) _have_virt_update( pkg, atom_set) bool {

	for new_child
	in
	d._iter_virt_update(pkg, atom_set):
	if pkg < new_child:
	return true

	return false
}

func(d *_dep_check_composite_db) aux_get(cpv, wants) {
	metadata = d._cpv_pkg_map[cpv]._metadata
	return [metadata.get(x, "") for x in wants]
}

func(d *_dep_check_composite_db) match(atom) {
	return [pkg.cpv for pkg in d.match_pkgs(atom)]
}


func ambiguous_package_name(arg, atoms, root_config, spinner, myopts) {

	if "--quiet" in
myopts:
	writemsg(
		'!!! The short ebuild name "%s" is ambiguous. Please specify\n'%arg,
		noiselevel = -1,
)
	writemsg(
		"!!! one of the following fully-qualified ebuild names instead:\n\n",
		noiselevel = -1,
)
	for cp
	in
	sorted(set(portage.dep_getkey(atom)
	for atom
	in
	atoms)):
	writemsg("    "+colorize("INFORM", cp)+"\n", noiselevel = -1)
	return

	s = search(
		root_config,
		spinner,
		"--searchdesc"
	in
	myopts,
		"--quiet"
	not
	in
	myopts,
		"--usepkg"
	in
	myopts,
		"--usepkgonly"
	in
	myopts,
		search_index = false,
)
	null_cp = portage.dep_getkey(insert_category_into_atom(arg, "null"))
	cat, atom_pn = portage.catsplit(null_cp)
	s.searchkey = atom_pn
	for cp
	in
	sorted(set(portage.dep_getkey(atom)
	for atom
	in
	atoms)):
	s.addCP(cp)
	s.output()
	writemsg(
		'!!! The short ebuild name "%s" is ambiguous. Please specify\n'%arg,
		noiselevel = -1,
)
	writemsg(
		"!!! one of the above fully-qualified ebuild names instead.\n\n", noiselevel = -1
	)
}

func _spinner_start(spinner, myopts) {
	if spinner is
nil:
	return
	if "--quiet" not
	in
	myopts
	and(
		"--pretend"
	in
	myopts
	or
	"--ask"
	in
	myopts
	or
	"--tree"
	in
	myopts
	or
	"--verbose"
	in
	myopts
	):
	action = ""
	if "--fetchonly" in
	myopts
	or
	"--fetch-all-uri"
	in
myopts:
	action = "fetched"
	elif
	"--buildpkgonly"
	in
myopts:
	action = "built"
	else:
	action = "merged"
	if (
		"--tree" in
	myopts
	and
	action != "fetched"
	):  # Tree
	doesn
	't work with fetching
	if "--unordered-display" in
myopts:
	portage.writemsg_stdout(
		"\n"
	+darkgreen(
		"These are the packages that " + "would be %s:"%action
	)
	+"\n\n"
	) else:
	portage.writemsg_stdout(
		"\n"
	+darkgreen(
		"These are the packages that "
	+"would be %s, in reverse order:" % action
	)
	+"\n\n"
	) else:
	portage.writemsg_stdout(
		"\n"
	+darkgreen(
		"These are the packages that " + "would be %s, in order:"%action
	)
	+"\n\n"
	)

	show_spinner = "--quiet"
	not
	in
	myopts
	and
	"--nodeps"
	not
	in
	myopts
	if not show_spinner:
	spinner.update = spinner.update_quiet

	if show_spinner:
	portage.writemsg_stdout("Calculating dependencies  ")
}


func _spinner_stop(spinner) {
	if spinner is
	nil
	or
	spinner.update == spinner.update_quiet:
	return

	if spinner.update != spinner.update_basic:
	portage.writemsg_stdout("\b\b")

	portage.writemsg_stdout("... done!\n")
}


func backtrack_depgraph(settings, trees, myopts, myparams, myaction, myfiles, spinner) {
	_spinner_start(spinner, myopts)
try:
	return _backtrack_depgraph(
		settings, trees, myopts, myparams, myaction, myfiles, spinner
	)
finally:
	_spinner_stop(spinner)
}

func _backtrack_depgraph(settings, trees, myopts, myparams, myaction, myfiles, spinner){

debug = "--debug" in myopts
mydepgraph = nil
max_retries = myopts.get("--backtrack", 10)
max_depth = max(1, (max_retries + 1) // 2)
allow_backtracking = max_retries > 0
backtracker = Backtracker(max_depth)
backtracked = 0

frozen_config = _frozen_depgraph_config(settings, trees, myopts, myparams, spinner)

while backtracker:

if debug and mydepgraph is not nil:
writemsg_level(
"\n\nbacktracking try %s \n\n" % backtracked,
noiselevel=-1,
level=logging.DEBUG,
)
mydepgraph.display_problems()

backtrack_parameters = backtracker.get()
if debug and backtrack_parameters.runtime_pkg_mask:
writemsg_level(
"\n\nruntime_pkg_mask: %s \n\n" % backtrack_parameters.runtime_pkg_mask,
noiselevel=-1,
level=logging.DEBUG,
)

mydepgraph = depgraph(
settings,
trees,
myopts,
myparams,
spinner,
frozen_config=frozen_config,
allow_backtracking=allow_backtracking,
backtrack_parameters=backtrack_parameters,
)
success, favorites = mydepgraph.select_files(myfiles)

if success or mydepgraph.need_config_change():
break
elif not allow_backtracking:
break
elif backtracked >= max_retries:
break
elif mydepgraph.need_restart():
backtracked += 1
backtracker.feedback(mydepgraph.get_backtrack_infos())
elif backtracker:
backtracked += 1

if backtracked and not success and not mydepgraph.need_display_problems():

if debug:
writemsg_level(
"\n\nbacktracking aborted after %s tries\n\n" % backtracked,
noiselevel=-1,
level=logging.DEBUG,
)
mydepgraph.display_problems()

mydepgraph = depgraph(
settings,
trees,
myopts,
myparams,
spinner,
frozen_config=frozen_config,
allow_backtracking=false,
backtrack_parameters=backtracker.get_best_run(),
)
success, favorites = mydepgraph.select_files(myfiles)

if not success and mydepgraph.autounmask_breakage_detected():
if debug:
writemsg_level(
"\n\nautounmask breakage detected\n\n",
noiselevel=-1,
level=logging.DEBUG,
)
mydepgraph.display_problems()
myparams["autounmask"] = false
mydepgraph = depgraph(
settings,
trees,
myopts,
myparams,
spinner,
frozen_config=frozen_config,
allow_backtracking=false,
)
success, favorites = mydepgraph.select_files(myfiles)

return (success, mydepgraph, favorites)
}


func resume_depgraph(settings, trees, mtimedb, myopts, myparams, spinner) {
	_spinner_start(spinner, myopts)
try:
	return _resume_depgraph(settings, trees, mtimedb, myopts, myparams, spinner)
finally:
	_spinner_stop(spinner)
}

func _resume_depgraph(settings, trees, mtimedb, myopts, myparams, spinner) {
	skip_masked = true
	skip_unsatisfied = true
	mergelist = mtimedb["resume"]["mergelist"]
	dropped_tasks =
	{
	}
	frozen_config = _frozen_depgraph_config(settings, trees, myopts, myparams, spinner)
	while
true:
	mydepgraph = depgraph(
		settings, trees, myopts, myparams, spinner, frozen_config = frozen_config
	)
try:
	success = mydepgraph._loadResumeCommand(
		mtimedb["resume"], skip_masked = skip_masked
	)
	except
	depgraph.UnsatisfiedResumeDep
	as
e:
	if not skip_unsatisfied:
	raise

	graph = mydepgraph._dynamic_config.digraph
	unsatisfied_parents =
	{
	}
	traversed_nodes = set()
	unsatisfied_stack = [(dep.parent, dep.atom) for dep in e.value]
while unsatisfied_stack:
pkg, atom = unsatisfied_stack.pop()
if (
atom is not nil
and mydepgraph._select_pkg_from_installed(pkg.root, atom)[0]
is not nil
):
continue
atoms = unsatisfied_parents.get(pkg)
if atoms is nil:
atoms = []
unsatisfied_parents[pkg] = atoms
if atom is not nil:
atoms.append(atom)
if pkg in traversed_nodes:
continue
traversed_nodes.add(pkg)

for parent_node, atom in mydepgraph._dynamic_config._parent_atoms.get(
pkg, []
):
if not isinstance(
parent_node, Package
) or parent_node.operation not in ("merge", "nomerge"):
continue
unsatisfied_stack.append((parent_node, atom))

unsatisfied_tuples = frozenset(
tuple(parent_node)
for parent_node in unsatisfied_parents
if isinstance(parent_node, Package)
)
pruned_mergelist = []
for x in mergelist:
if isinstance(x, list) and tuple(x) not in unsatisfied_tuples:
pruned_mergelist.append(x)

if len(pruned_mergelist) == len(mergelist):
raise
mergelist[:] = pruned_mergelist

dropped_tasks.update(
(pkg, atoms)
for pkg, atoms in unsatisfied_parents.items()
if pkg.operation != "nomerge"
)

del e, graph, traversed_nodes, unsatisfied_parents, unsatisfied_stack
continue else:
break
return (success, mydepgraph, dropped_tasks)
}

// nil, nil
func get_mask_info(
root_config,
cpv,
pkgsettings,
db,
pkg_type,
built,
installed,
db_keys,
myrepo=nil,
_pkg_use_enabled=nil,
) {
try:
	metadata = dict(zip(db_keys, db.aux_get(cpv, db_keys, myrepo = myrepo)))
	except
KeyError:
	metadata = nil

	if metadata is
nil:
	mreasons = ["corruption"] else:
eapi = metadata["EAPI"]
if not portage.eapi_is_supported(eapi):
mreasons = ["EAPI %s" % eapi] else:
pkg = Package(
type_name = pkg_type,
root_config= root_config,
cpv = cpv,
built = built,
installed = installed,
metadata = metadata,
)

modified_use = nil
if _pkg_use_enabled is not nil:
modified_use = _pkg_use_enabled(pkg)

mreasons = get_masking_status(
pkg, pkgsettings, root_config, myrepo =myrepo, use = modified_use
)

return metadata, mreasons
}

func show_masked_packages(masked_packages) {
	shown_licenses = set()
	shown_comments = set()
	shown_cpvs = set()
	have_eapi_mask = false
	for (root_config, pkgsettings, cpv, repo, metadata, mreasons) in
masked_packages:
	output_cpv = cpv
	if repo:
	output_cpv += _repo_separator + repo
	if output_cpv in
shown_cpvs:
	continue
	shown_cpvs.add(output_cpv)
	eapi_masked = metadata
	is
	not
	nil
	and
	not
	portage.eapi_is_supported(
		metadata["EAPI"]
	)
	if eapi_masked:
	have_eapi_mask = true
	metadata = nil
	comment, filename = nil, nil
	if not eapi_masked
	and
	"package.mask"
	in
mreasons:
	comment, filename = portage.getmaskingreason(
		cpv,
		metadata = metadata,
		settings = pkgsettings,
		portdb=root_config.trees["porttree"].dbapi,
		return_location = true,
)
	missing_licenses = []
if not eapi_masked and metadata is not nil:
try:
missing_licenses = pkgsettings._getMissingLicenses(cpv, metadata)
except portage.exception.InvalidDependString:
pass

writemsg(
"- " + output_cpv + " (masked by: " + ", ".join(mreasons) + ")\n",
noiselevel = -1,
)

if comment and comment not in shown_comments:
writemsg(filename + ":\n" + comment + "\n", noiselevel = -1)
shown_comments.add(comment)
portdb = root_config.trees["porttree"].dbapi
for l in missing_licenses:
if l in shown_licenses:
continue
l_path = portdb.findLicensePath(l)
if l_path is nil:
continue
msg = ("A copy of the '%s' license" + " is located at '%s'.\n\n") % (
l,
l_path,
)
writemsg(msg, noiselevel = -1)
shown_licenses.add(l)
return have_eapi_mask
}

func show_mask_docs() {
	writemsg(
		"For more information, see the MASKED PACKAGES "
	"section in the emerge\n",
		noiselevel = -1,
)
	writemsg("man page or refer to the Gentoo Handbook.\n", noiselevel = -1)
}

func show_blocker_docs_link() {
	writemsg(
		"\nFor more information about "
	+bad("Blocked Packages")
	+", please refer to the following\n",
		noiselevel = -1,
)
	writemsg(
		"section of the Gentoo Linux x86 Handbook (architecture is irrelevant):\n\n",
		noiselevel = -1,
)
	writemsg(
		"https://wiki.gentoo.org/wiki/Handbook:X86/Working/Portage#Blocked_packages\n\n",
		noiselevel = -1,
)
}

func get_masking_status(pkg, pkgsettings, root_config, myrepo=nil, use=nil) {
	return [
mreason.message
for mreason in _get_masking_status(
pkg, pkgsettings, root_config, myrepo = myrepo, use= use
)
]
}

func _get_masking_status(pkg, pkgsettings, root_config, myrepo=nil, use=nil) {
	mreasons = _getmaskingstatus(
		pkg,
		settings = pkgsettings,
		portdb = root_config.trees["porttree"].dbapi,
		myrepo=myrepo,
)

	if not pkg.installed:
	if not pkgsettings._accept_chost(pkg.cpv, pkg._metadata):
	mreasons.append(_MaskReason("CHOST", "CHOST: %s"%pkg._metadata["CHOST"]))

	if pkg.invalid:
	for msgs
	in
	pkg.invalid.values():
	for msg
	in
msgs:
	mreasons.append(_MaskReason("invalid", "invalid: %s"%(msg, )))

	if not pkg._metadata["SLOT"]:
	mreasons.append(_MaskReason("invalid", "SLOT: undefined"))

	return mreasons
}
