package emerge

import (
	"fmt"
	"github.com/ppphp/portago/pkg/output"
	"regexp"
	"strings"
)

func localized_size(num_bytes int) string{
	return fmt.Sprintf("%d KiB", num_bytes / 1024 + 1)
}

var bad = output.NewCreateColorFunc("BAD")

type _RepoDisplay struct {
	_shown_repos map[]{}
	_unknown_repo bool
	_repo_paths
	_repo_paths_real []T
}

func NewRepoDisplay(roots) *_RepoDisplay{
	r := &_RepoDisplay{}
	r._shown_repos = map[]{}
	r._unknown_repo = false
	repo_paths := map[]bool{}
	for root_config in roots.values()
	{
		for repo
		in
		root_config.settings.repositories {
			repo_paths.add(repo.location)
		}
	}
	repo_paths = list(repo_paths)
	r._repo_paths = repo_paths
	r._repo_paths_real = []string{}
	for _ ,repo_path := range repo_paths{
		r._repo_paths_real = append(r._repo_paths_real, os.path.realpath(repo_path))
	}

	return r
}

func(r*_RepoDisplay) repoStr( repo_path_real) {
	real_index = -1
	if repo_path_real:
	real_index = r._repo_paths_real.index(repo_path_real)
	if real_index == -1:
	s = "?"
	r._unknown_repo = true
	else:
	shown_repos = r._shown_repos
	repo_paths = r._repo_paths
	repo_path = repo_paths[real_index]
	index = shown_repos.get(repo_path)
	if index is
None:
	index = len(shown_repos)
	shown_repos[repo_path] = index
	s = str(index)
	return s
}

func(r*_RepoDisplay) __str__() {
	output := []string
shown_repos = r._shown_repos
unknown_repo = r._unknown_repo
if shown_repos or r._unknown_repo:
output.append("Repositories:\n")
show_repo_paths = list(shown_repos)
for repo_path, repo_index in shown_repos.items():
show_repo_paths[repo_index] = repo_path
if show_repo_paths:
for index, repo_path in enumerate(show_repo_paths):
output.append(" " + teal("[" + str(index) + "]") + " %s\n" % repo_path)
if unknown_repo:
output.append(
" "
+ teal("[?]")
+ " indicates that the source repository could not be determined\n"
)
return "".join(output)
}


type _PackageCounters struct {
	upgrades,
	downgrades,
	new,
	newslot,
	reinst,
	uninst,
	blocks,
	blocks_satisfied,
	totalsize,
	restrict_fetch,
	restrict_fetch_satisfied,
	interactive,
	binary int
}

func NewPackageCounters()*_PackageCounters{
	p := &_PackageCounters{}
	p.upgrades = 0
	p.downgrades = 0
	p.new = 0
	p.newslot = 0
	p.reinst = 0
	p.uninst = 0
	p.blocks = 0
	p.blocks_satisfied = 0
	p.totalsize = 0
	p.restrict_fetch = 0
	p.restrict_fetch_satisfied = 0
	p.interactive = 0
	p.binary = 0
	return p
}

func (p*_PackageCounters) __str__() string {
	total_installs :=
		p.upgrades + p.downgrades + p.newslot + p.new + p.reinst

	myoutput := []string{}
	details := []string{}
	myoutput = append(myoutput, fmt.Sprintf("Total: %s package", total_installs))
	if total_installs != 1 {
		myoutput = append(myoutput, "s")
	}
	if total_installs != 0 {
		myoutput = append(myoutput, " (")
	}
	if p.upgrades > 0 {
		details = append(details, fmt.Sprintf("%s upgrade", p.upgrades))
		if p.upgrades > 1 {
			details[len(details)-1] += "s"
		}
	}
	if p.downgrades > 0 {
		details = append(details, fmt.Sprintf("%s downgrade", p.downgrades))
		if p.downgrades > 1 {
			details[len(details)-1] += "s"
		}
	}
	if p.new > 0 {
		details=append(details, fmt.Sprintf("%s new" , p.new))
	}
	if p.newslot > 0 {
		details = append(details, fmt.Sprintf("%s in new slot", p.newslot))
		if p.newslot > 1 {
			details[len(details)-1] += "s"
		}
	}
	if p.reinst > 0 {
		details= append(details,fmt.Sprintf("%s reinstall" , p.reinst))
		if p.reinst > 1 {
			details[len(details)-1] += "s"
		}
	}
	if p.binary > 0 {
		details = append(details, fmt.Sprintf("%s binary", p.binary))
		if p.binary > 1 {
			details[len(details)-1] = details[len(details)-1][:len(details)-1] + "ies"
		}
	}
	if p.uninst > 0 {
		details = append(details, fmt.Sprintf("%s uninstall", p.uninst))
		if p.uninst > 1 {
			details[len(details)-1] += "s"
		}
	}
	if p.interactive > 0 {
		details = append(details,
			fmt.Sprintf("%s %s",p.interactive, output.Colorize("WARN", "interactive")))
	}
	myoutput= append(myoutput, strings.Join(details, ", "))
	if total_installs != 0 {
		myoutput = append(myoutput, ")")
	}
	myoutput= append(myoutput,fmt.Sprintf(", Size of downloads: %s" , localized_size(p.totalsize)))
	if p.restrict_fetch != 0 {
		myoutput = append(myoutput,fmt.Sprintf( "\nFetch Restriction: %s package",p.restrict_fetch))
		if p.restrict_fetch > 1 {
			myoutput = append(myoutput, "s")
		}
	}
	if p.restrict_fetch_satisfied < p.restrict_fetch {
		myoutput = append(myoutput, fmt.Sprintf(bad(" (%s unsatisfied)"), p.restrict_fetch - p.restrict_fetch_satisfied))
	}
	if p.blocks > 0 {
		myoutput = append(myoutput, fmt.Sprintf("\nConflict: %s block", p.blocks))
		if p.blocks > 1 {
			myoutput = append(myoutput, "s")
		}
		if p.blocks_satisfied < p.blocks {
			myoutput = append(myoutput,fmt.Sprintf(bad(" (%s unsatisfied)"),p.blocks-p.blocks_satisfied))
		}else{
			myoutput = append(myoutput, " (all satisfied)")
		}
	}
	return strings.Join(myoutput, "")
}

type _DisplayConfig struct {

}

func NewDisplayConfig(depgraph, mylist, favorites, verbosity) *_DisplayConfig{
	d := &_DisplayConfig{}
	frozen_config := depgraph._frozen_config
	dynamic_config := depgraph._dynamic_config

	d.mylist = mylist
	d.favorites = InternalPackageSet(favorites, allow_repo=true)
	d.verbosity = verbosity

	if d.verbosity is None:
	d.verbosity = (
		"--quiet" in frozen_config.myopts
	and 1
	or "--verbose" in frozen_config.myopts
	and 3
	or 2
	)

	d.oneshot = (
		"--oneshot" in frozen_config.myopts or "--onlydeps" in frozen_config.myopts
	)
	d.columns = "--columns" in frozen_config.myopts
	d.tree_display = "--tree" in frozen_config.myopts
	d.alphabetical = "--alphabetical" in frozen_config.myopts
	d.quiet = "--quiet" in frozen_config.myopts
	d.all_flags = d.verbosity == 3 or d.quiet
	d.print_use_string = (
		d.verbosity != 1 or "--verbose" in frozen_config.myopts
	)
	d.edebug = frozen_config.edebug
	d.unordered_display = "--unordered-display" in frozen_config.myopts

	mywidth = 130
	if "COLUMNWIDTH" in frozen_config.settings:
try:
	mywidth = int(frozen_config.settings["COLUMNWIDTH"])
	except ValueError as e:
	writemsg("!!! %s\n" % str(e), noiselevel=-1)
	writemsg(
		"!!! Unable to parse COLUMNWIDTH='%s'\n"
	% frozen_config.settings["COLUMNWIDTH"],
		noiselevel=-1,
)
	del e
	d.columnwidth = mywidth

	if "--quiet-repo-display" in frozen_config.myopts:
	d.repo_display = NewRepoDisplay(frozen_config.roots)
	d.trees = frozen_config.trees
	d.pkgsettings = frozen_config.pkgsettings
	d.target_root = frozen_config.target_root
	d.running_root = frozen_config._running_root
	d.roots = frozen_config.roots

	# Create a set of selected packages for each root
	d.selected_sets = {}
	for root_name, root in d.roots.items():
try:
	d.selected_sets[root_name] = InternalPackageSet(
		initial_atoms=root.setconfig.getSetAtoms("selected")
	)
	except PackageSetNotFound:
	# A nested set could not be resolved, so ignore nested sets.
		d.selected_sets[root_name] = root.sets["selected"]

	d.blocker_parents = dynamic_config._blocker_parents
	d.reinstall_nodes = dynamic_config._reinstall_nodes
	d.digraph = dynamic_config.digraph
	d.blocker_uninstalls = dynamic_config._blocker_uninstalls
	d.package_tracker = dynamic_config._package_tracker
	d.set_nodes = dynamic_config._set_nodes

	d.pkg_use_enabled = depgraph._pkg_use_enabled
	d.pkg = depgraph._pkg
	return d
}

var _alnum_sort_re = regexp.MustCompile("(\\d+)")

func _alnum_sort_key(x) {
	def
	_convert_even_to_int(it):
	it = iter(it)
try:
	while
true:
	yield
	next(it)
	yield
	int(next(it))
	except
StopIteration:
	pass

	return tuple(_convert_even_to_int(_alnum_sort_re.split(x)))
}


func _create_use_string(
conf,
name,
cur_iuse,
iuse_forced,
cur_use,
old_iuse,
old_use,
is_new,
feature_flags,
reinst_flags,
) {

	if not conf.print_use_string:
	return ""

	enabled = []
if conf.alphabetical:
disabled = enabled
removed = enabled else:
disabled = []
removed = []
cur_iuse = set(cur_iuse)
enabled_flags = cur_iuse.intersection(cur_use)
removed_iuse = set(old_iuse).difference(cur_iuse)
any_iuse = cur_iuse.union(old_iuse)
any_iuse = list(any_iuse)
any_iuse.sort(key = _alnum_sort_key)

for flag in any_iuse:
flag_str = None
isEnabled = false
reinst_flag = reinst_flags and flag in reinst_flags
if flag in enabled_flags:
isEnabled = true
if is_new or flag in old_use and (conf.all_flags or reinst_flag):
flag_str = red(flag)
elif flag not in old_iuse:
flag_str = yellow(flag) + "%*"
elif flag not in old_use:
flag_str = green(flag) + "*"
elif flag in removed_iuse:
if conf.all_flags or reinst_flag:
flag_str = yellow("-" + flag) + "%"
if flag in old_use:
flag_str += "*"
flag_str = "(" + flag_str + ")"
removed.append(flag_str)
continue
else:
if (
is_new
or flag in old_iuse
and flag not in old_use
and (conf.all_flags or reinst_flag)
):
flag_str = blue("-" + flag)
elif flag not in old_iuse:
flag_str = yellow("-" + flag)
if flag not in iuse_forced:
flag_str += "%"
elif flag in old_use:
flag_str = green("-" + flag) + "*"
if flag_str:
if flag in feature_flags:
flag_str = "{" + flag_str + "}"
elif flag in iuse_forced:
flag_str = "(" + flag_str + ")"
if isEnabled:
enabled.append(flag_str) else:
disabled.append(flag_str)

if conf.alphabetical:
ret = " ".join(enabled)
else:
ret = " ".join(enabled + disabled + removed)
if ret:
ret = '%s="%s" ' % (name, ret)
return ret
}


func _tree_display(conf, mylist) {

	# If
	there
	are
	any
	Uninstall
	instances, add
	the
	# corresponding
	blockers
	to
	the
	digraph.
		mygraph = conf.digraph.copy()

	executed_uninstalls = set(
		node
	for node
	in
	mylist
	if isinstance(node, Package) and
	node.operation == "unmerge"
	)

	for uninstall
	in
	conf.blocker_uninstalls.leaf_nodes():
	uninstall_parents = conf.blocker_uninstalls.parent_nodes(uninstall)
	if not uninstall_parents:
	continue

	# Remove
	the
	corresponding
	"nomerge"
	node
	and
	substitute
	# the
	Uninstall
	node.
		inst_pkg = conf.pkg(
		uninstall.cpv, "installed", uninstall.root_config, installed = true
	)

try:
	mygraph.remove(inst_pkg)
	except
KeyError:
	pass

try:
	inst_pkg_blockers = conf.blocker_parents.child_nodes(inst_pkg)
	except
KeyError:
	inst_pkg_blockers = []

# Break the Package -> Uninstall edges.
mygraph.remove(uninstall)

# Resolution of a package 's blockers
# depend on it's own uninstallation.
for blocker in inst_pkg_blockers:
mygraph.add(uninstall, blocker)

# Expand Package -> Uninstall edges into
# Package -> Blocker -> Uninstall edges.
for blocker in uninstall_parents:
mygraph.add(uninstall, blocker)
for parent in conf.blocker_parents.parent_nodes(blocker):
if parent != inst_pkg:
mygraph.add(blocker, parent)

# If the uninstall task did not need to be executed because
# of an upgrade, display Blocker -> Upgrade edges since the
# corresponding Blocker -> Uninstall edges will not be shown.
upgrade_node = next(
conf.package_tracker.match(uninstall.root, uninstall.slot_atom), None
)

if upgrade_node is not None and uninstall not in executed_uninstalls:
for blocker in uninstall_parents:
mygraph.add(upgrade_node, blocker)

if conf.unordered_display:
display_list = _unordered_tree_display(mygraph, mylist) else:
display_list = _ordered_tree_display(conf, mygraph, mylist)

_prune_tree_display(display_list)

return display_list
}


func _unordered_tree_display(mygraph, mylist) {
	display_list = []
seen_nodes = set()

def print_node(node, depth):

if node in seen_nodes:
pass else:
seen_nodes.add(node)

if isinstance(node, (Blocker, Package)):
display_list.append((node, depth, true)) else:
depth = -1

for child_node in mygraph.child_nodes(node):
print_node(child_node, depth + 1)

for root_node in mygraph.root_nodes():
print_node(root_node, 0)

return display_list
}

func _ordered_tree_display(conf, mygraph, mylist) {
	depth = 0
	shown_edges = set()
	tree_nodes = []
display_list = []

for x in mylist:
depth = len(tree_nodes)
while depth and x not in mygraph.child_nodes(tree_nodes[depth - 1]):
depth -= 1
if depth:
tree_nodes = tree_nodes[:depth]
tree_nodes.append(x)
display_list.append((x, depth, true))
shown_edges.add((x, tree_nodes[depth - 1])) else:
traversed_nodes = set()  # prevent endless circles
traversed_nodes.add(x)

def add_parents(current_node, ordered):
parent_nodes = None
# Do not traverse to parents if this node is an
# an argument or a direct member of a set that has
# been specified as an argument (system or world).
if current_node not in conf.set_nodes:
parent_nodes = mygraph.parent_nodes(current_node)
if parent_nodes:
child_nodes = set(mygraph.child_nodes(current_node))
selected_parent = None
# First, try to avoid a direct cycle.
for node in parent_nodes:
if not isinstance(node, (Blocker, Package)):
continue
if node not in traversed_nodes and node not in child_nodes:
edge = (current_node, node)
if edge in shown_edges:
continue
selected_parent = node
break
if not selected_parent:
# A direct cycle is unavoidable.
for node in parent_nodes:
if not isinstance(node, (Blocker, Package)):
continue
if node not in traversed_nodes:
edge = (current_node, node)
if edge in shown_edges:
continue
selected_parent = node
break
if selected_parent:
shown_edges.add((current_node, selected_parent))
traversed_nodes.add(selected_parent)
add_parents(selected_parent, false)
display_list.append((current_node, len(tree_nodes), ordered))
tree_nodes.append(current_node)

tree_nodes = []
add_parents(x, true)

return display_list
}

func _prune_tree_display(display_list) {
	last_merge_depth = 0
	for i
	in range
	(len(display_list) - 1, -1, -1):
	node, depth, ordered = display_list[i]
	if (
		not ordered
	and
	depth == 0
	and
	i > 0
	and
	node == display_list[i-1][0]
	and
	display_list[i-1][1] == 0
	):
	# An
	ordered
	node
	got
	a
	consecutive
	duplicate
	# when
	the
	tree
	was
	being
	filled
	in.
		del
	display_list[i]
	continue
	if (
		ordered
		and
	isinstance(node, Package)
	and
	node.operation
	in("merge", "uninstall")
	):
	last_merge_depth = depth
	continue
	if (
		depth >= last_merge_depth
		or
	i < len(display_list)-1
	and
	depth >= display_list[i+1][1]
	):
	del
	display_list[i]
}

func _strip_header_comments(lines) {
	# strip
	leading
	and
	trailing
	blank
	or
	header / comment
	lines
	i = 0
	while
	i < len(lines)
	and(not
	lines[i]
	or
	lines[i][:1] == "#"):
	i += 1
	if i:
	lines = lines[i:]
	while
	lines
	and(not
	lines[-1]
	or
	lines[-1][:1] == "#"):
	lines.pop()
	return lines
}

type PkgInfo struct {
	// slots
	attr_display,
	built,
	cp,
	ebuild_path,
	fetch_symbol,
	merge,
	oldbest,
	oldbest_list,
	operation,
	ordered,
	previous_pkg,
	repo_name,
	repo_path_real,
	slot,
	sub_slot,
	system,
	use,
	ver,
	world,
}

func NewPkgInfo() *PkgInfo {
	p := &PkgInfo{}
	p.built = false
	p.cp = ""
	p.ebuild_path = ""
	p.fetch_symbol = ""
	p.merge = ""
	p.oldbest = ""
	p.oldbest_list = []
	p.operation = ""
	p.ordered = false
	p.previous_pkg = None
	p.repo_path_real = ""
	p.repo_name = ""
	p.slot = ""
	p.sub_slot = ""
	p.system = false
	p.use = ""
	p.ver = ""
	p.world = false
	p.attr_display = PkgAttrDisplay()
	return p
}


type PkgAttrDisplay struct {
	// slot
	downgrade,
	fetch_restrict,
	fetch_restrict_satisfied,
	force_reinstall,
	interactive,
	mask,
	new,
	new_slot,
	new_version,
	replace,
}

func (p*PkgAttrDisplay) __str__() {

	output = []

if p.interactive:
output.append(colorize("WARN", "I")) else:
output.append(" ")

if p.new or p.force_reinstall:
if p.force_reinstall:
output.append(red("r")) else:
output.append(green("N")) else:
output.append(" ")

if p.new_slot or p.replace:
if p.replace:
output.append(yellow("R")) else:
output.append(green("S")) else:
output.append(" ")

if p.fetch_restrict or p.fetch_restrict_satisfied:
if p.fetch_restrict_satisfied:
output.append(green("f")) else:
output.append(red("F")) else:
output.append(" ")

if p.new_version:
output.append(turquoise("U")) else:
output.append(" ")

if p.downgrade:
output.append(blue("D")) else:
output.append(" ")

if p.mask is not None:
output.append(p.mask)

return "".join(output)
}
