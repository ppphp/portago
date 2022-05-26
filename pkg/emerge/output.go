package emerge

import "github.com/ppphp/portago/pkg/output"

// var bad = output.NewCreateColorFunc("BAD")

type Display struct {
	print_msg []T
	blockers []T
	counters _PackageCounters
	resolver,
	resolved,
	vardb,
	portdb T
	verboseadd string
	oldlp,
	myfetchlist T
	indent string
	use_expand,
	use_expand_hidden,
	pkgsettings,
	forced_flags,
	newlp,
	conf,
	blocker_style,
}

func NewDisplay() {

}

func (d*Display) _blockers( blocker) {
	if blocker.satisfied:
	d.blocker_style = "PKG_BLOCKER_SATISFIED"
	addl = "%s     " % (output.Colorize(d.blocker_style, "b"),) else:
	d.blocker_style = "PKG_BLOCKER"
	addl = "%s     " % (output.Colorize(d.blocker_style, "B"),)
	addl += d.empty_space_in_brackets()
	d.resolved = dep_expand(
		str(blocker.atom).lstrip("!"), mydb = d.vardb, settings = d.pkgsettings
	)
	if d.conf.columns and
	d.conf.quiet:
	addl += " " + output.Colorize(d.blocker_style, str(d.resolved))
	else:
	addl = "[%s %s] %s%s" % (
		output.Colorize(d.blocker_style, "blocks"),
		addl,
		d.indent,
		output.Colorize(d.blocker_style, str(d.resolved)),
)
	block_parents = d.conf.blocker_parents.parent_nodes(blocker)
	block_parents = set(str(pnode.cpv)
	for pnode
	in
	block_parents)
	block_parents = ", ".join(block_parents)
	if blocker.atom.blocker.overlap.forbid:
	blocking_desc = "hard blocking"
	else:
	blocking_desc = "soft blocking"
	if d.resolved != blocker.atom:
	addl += output.Colorize(
		d.blocker_style,
		' ("%s" is %s %s)'
	% (str(blocker.atom).lstrip("!"), blocking_desc, block_parents),
) else:
	addl += output.Colorize(
		d.blocker_style, " (is %s %s)"%(blocking_desc, block_parents)
	)
	if blocker.satisfied:
	if not d.conf.columns:
	d.print_msg.append(addl)
	else:
	d.blockers.append(addl)
}

func (d*Display) include_mask_str() {
	return d.conf.verbosity > 1
}

func (d*Display) gen_mask_str( pkg) {
	hardmasked = pkg.isHardMasked()
	mask_str = " "

	if hardmasked:
	mask_str = output.Colorize("BAD", "#")
	else:
	keyword_mask = pkg.get_keyword_mask()

	if keyword_mask is
None:
	pass
	elif
	keyword_mask == "missing":
	mask_str = output.Colorize("BAD", "*")
	else:
	mask_str = output.Colorize("WARN", "~")

	return mask_str
}

func (d*Display) empty_space_in_brackets() {
	space = ""
	if d.include_mask_str():
	# add
	column
	for mask
	status
	space += " "
	return space
}

func (d*Display) map_to_use_expand( myvals, forced_flags=False, remove_hidden=True) {
	ret =
	{
	}
	forced =
	{
	}
	for exp
	in
	d.use_expand:
	ret[exp] = []
forced[exp] = set()
for val in myvals[:]:
if val.startswith(exp.lower() + "_"):
if val in d.forced_flags:
forced[exp].add(val[len(exp) + 1:])
ret[exp].append(val[len(exp) + 1:])
myvals.remove(val)
ret["USE"] = myvals
forced["USE"] = [val for val in myvals if val in d.forced_flags]
if remove_hidden:
for exp in d.use_expand_hidden:
ret.pop(exp, None)
if forced_flags:
return ret, forced
return ret
}

func (d*Display) _display_use( pkg, pkg_info) {

	d.forced_flags = set()
	d.forced_flags.update(pkg.use.force)
	d.forced_flags.update(pkg.use.mask)

	cur_use = [
flag for flag in d.conf.pkg_use_enabled(pkg) if flag in pkg.iuse.all
]
cur_iuse = sorted(pkg.iuse.all)

if pkg_info.previous_pkg is not None:
previous_pkg = pkg_info.previous_pkg
old_iuse = sorted(previous_pkg.iuse.all)
old_use = previous_pkg.use.enabled
is_new = False
else:
old_iuse = []
old_use = []
is_new = True

old_use = [flag for flag in old_use if flag in old_iuse]

d.use_expand = pkg.use.expand
d.use_expand_hidden = pkg.use.expand_hidden

# Prevent USE_EXPAND_HIDDEN flags from being hidden if they
# are the only thing that triggered reinstallation.
reinst_flags_map = {}
reinstall_for_flags = d.conf.reinstall_nodes.get(pkg)
reinst_expand_map = None
if reinstall_for_flags:
reinst_flags_map = d.map_to_use_expand(
list(reinstall_for_flags), remove_hidden = False
)
for k in list(reinst_flags_map):
if not reinst_flags_map[k]:
del reinst_flags_map[k]
if not reinst_flags_map.get("USE"):
reinst_expand_map = reinst_flags_map.copy()
reinst_expand_map.pop("USE", None)
if reinst_expand_map and not set(reinst_expand_map).difference(
d.use_expand_hidden
):
d.use_expand_hidden = set(d.use_expand_hidden).difference(
reinst_expand_map
)

cur_iuse_map, iuse_forced = d.map_to_use_expand(cur_iuse, forced_flags= True)
cur_use_map = d.map_to_use_expand(cur_use)
old_iuse_map = d.map_to_use_expand(old_iuse)
old_use_map = d.map_to_use_expand(old_use)

use_expand = sorted(d.use_expand)
use_expand.insert(0, "USE")
feature_flags = _get_feature_flags(_get_eapi_attrs(pkg.eapi))

for key in use_expand:
if key in d.use_expand_hidden:
continue
d.verboseadd += _create_use_string(
d.conf,
key.upper(),
cur_iuse_map[key],
iuse_forced[key],
cur_use_map[key],
old_iuse_map[key],
old_use_map[key],
is_new,
feature_flags,
reinst_flags_map.get(key),
)
}

func (d Display) pkgprint(pkg_str, pkg_info) {
	if pkg_info.merge:
	if pkg_info.built:
	if pkg_info.system:
	return output.Colorize("PKG_BINARY_MERGE_SYSTEM", pkg_str)
	if pkg_info.world:
	return output.Colorize("PKG_BINARY_MERGE_WORLD", pkg_str)
	return output.Colorize("PKG_BINARY_MERGE", pkg_str)

	if pkg_info.system:
	return output.Colorize("PKG_MERGE_SYSTEM", pkg_str)
	if pkg_info.world:
	return output.Colorize("PKG_MERGE_WORLD", pkg_str)
	return output.Colorize("PKG_MERGE", pkg_str)

	if pkg_info.operation == "uninstall":
	return output.Colorize("PKG_UNINSTALL", pkg_str)

	if pkg_info.system:
	return output.Colorize("PKG_NOMERGE_SYSTEM", pkg_str)
	if pkg_info.world:
	return output.Colorize("PKG_NOMERGE_WORLD", pkg_str)
	return output.Colorize("PKG_NOMERGE", pkg_str)
}

func (d*Display) verbose_size( pkg, repoadd_set, pkg_info) {
	mysize = 0
	if pkg.type_name in("binary", "ebuild")
	and
	pkg_info.merge:
	db = pkg.root_config.trees[
		pkg.root_config.pkg_tree_map[pkg.type_name]
	].dbapi
	kwargs =
	{
	}
	if pkg.type_name == "ebuild":
	kwargs["useflags"] = pkg_info.use
	kwargs["myrepo"] = pkg.repo
	myfilesdict = None
try:
	myfilesdict = db.getfetchsizes(pkg.cpv, **kwargs)
	except
	InvalidDependString
	as
e:
	# FIXME:
	validate
	SRC_URI
	earlier
	(depstr,) = db.aux_get(pkg.cpv,["SRC_URI"], myrepo = pkg.repo)
	show_invalid_depstring_notice(pkg, str(e))
	raise
	except
SignatureException:
	# missing / invalid
	binary package
	SIZE
	signature
	pass
	if myfilesdict is
None:
	myfilesdict = "[empty/missing/bad digest]"
	else:
	for myfetchfile
	in
myfilesdict:
	if myfetchfile not
	in
	d.myfetchlist:
	mysize += myfilesdict[myfetchfile]
	d.myfetchlist.add(myfetchfile)
	if pkg_info.ordered:
	d.counters.totalsize += mysize
	d.verboseadd += localized_size(mysize)

	if d.quiet_repo_display:
	# overlay
	verbose
	# assign
	index
	for a
	previous
	version
	in
	the
	same
	slot
	if pkg_info.previous_pkg is
	not
None:
	repo_name_prev = pkg_info.previous_pkg.repo
	else:
	repo_name_prev = None

	# now
	use
	the
	data
	to
	generate
	output
	if pkg.installed or
	pkg_info.previous_pkg
	is
None:
	d.repoadd = d.conf.repo_display.repoStr(pkg_info.repo_path_real)
	else:
	repo_path_prev = None
	if repo_name_prev:
	repo_path_prev = d.portdb.getRepositoryPath(repo_name_prev)
	if repo_path_prev == pkg_info.repo_path_real:
	d.repoadd = d.conf.repo_display.repoStr(
		pkg_info.repo_path_real
	)
	else:
	d.repoadd = "%s=>%s" % (
		d.conf.repo_display.repoStr(repo_path_prev),
		d.conf.repo_display.repoStr(pkg_info.repo_path_real),
)
	if d.repoadd:
	repoadd_set.add(d.repoadd)
}

func (d*Display) convert_myoldbest( pkg, pkg_info) {
	myoldbest = pkg_info.oldbest_list
	# Convert
	myoldbest
	from
	a
	list
	to
	a
	string.
		myoldbest_str = ""
	if myoldbest:
	versions = []
for pos, old_pkg in enumerate(myoldbest):
key = old_pkg.version
if key[-3:] == "-r0":
key = key[:-3]
if d.conf.verbosity == 3:
if pkg_info.attr_display.new_slot:
key += _slot_separator + old_pkg.slot
if old_pkg.slot != old_pkg.sub_slot:
key += "/" + old_pkg.sub_slot
elif any(
x.slot + "/" + x.sub_slot != "0/0" for x in myoldbest + [pkg]
):
key += _slot_separator + old_pkg.slot
if (
old_pkg.slot != old_pkg.sub_slot
or old_pkg.slot == pkg.slot
and old_pkg.sub_slot != pkg.sub_slot
):
key += "/" + old_pkg.sub_slot
if not d.quiet_repo_display:
key += _repo_separator + old_pkg.repo
versions.append(key)
myoldbest_str = blue("[" + ", ".join(versions) + "]")
return myoldbest_str
}

func (d*Display) _append_slot( pkg_str, pkg, pkg_info) {
	if pkg_info.attr_display.new_slot:
	pkg_str += _slot_separator + pkg_info.slot
	if pkg_info.slot != pkg_info.sub_slot:
	pkg_str += "/" + pkg_info.sub_slot
	elif
	any(
		x.slot+"/"+x.sub_slot != "0/0"
	for x
	in
	pkg_info.oldbest_list +[pkg]
	):
	pkg_str += _slot_separator + pkg_info.slot
	if pkg_info.slot != pkg_info.sub_slot or
	any(
		x.slot == pkg_info.slot
	and
	x.sub_slot != pkg_info.sub_slot
	for x
	in
	pkg_info.oldbest_list
	):
	pkg_str += "/" + pkg_info.sub_slot
	return pkg_str
}

func (d*Display) _append_repository( pkg_str, pkg, pkg_info) {
	if not d.quiet_repo_display:
	pkg_str += _repo_separator + pkg.repo
	return pkg_str
}

func (d*Display) _append_build_id( pkg_str, pkg, pkg_info) {
	if pkg.type_name == "binary" and
	pkg.cpv.build_id
	is
	not
None:
	pkg_str += "-%s" % pkg.cpv.build_id
	return pkg_str
}

func (d*Display) _set_non_root_columns( pkg, pkg_info) {
	ver_str = d._append_build_id(pkg_info.ver, pkg, pkg_info)
	if d.conf.verbosity == 3:
	ver_str = d._append_slot(ver_str, pkg, pkg_info)
	ver_str = d._append_repository(ver_str, pkg, pkg_info)
	if d.conf.quiet:
	myprint = (
		str(pkg_info.attr_display)
	+" "
	+d.indent
	+d.pkgprint(pkg_info.cp, pkg_info)
	)
	myprint = myprint + darkblue(" "+ver_str) + " "
	myprint = myprint + pkg_info.oldbest
	myprint = myprint + darkgreen("to "+pkg.root)
	d.verboseadd = None
	else:
	if not pkg_info.merge:
	myprint = "[%s] %s%s" % (
		d.pkgprint(pkg_info.operation.ljust(13), pkg_info),
		d.indent,
		d.pkgprint(pkg.cp, pkg_info),
) else:
	myprint = "[%s %s] %s%s" % (
		d.pkgprint(pkg.type_name, pkg_info),
		pkg_info.attr_display,
		d.indent,
		d.pkgprint(pkg.cp, pkg_info),
)
	if (d.newlp - nc_len(myprint)) > 0:
	myprint = myprint + (" " * (d.newlp - nc_len(myprint)))
	myprint = myprint + " " + darkblue("["+ver_str+"]") + " "
	if (d.oldlp - nc_len(myprint)) > 0:
	myprint = myprint + " "*(d.oldlp-nc_len(myprint))
	myprint = myprint + pkg_info.oldbest
	myprint += darkgreen("to " + pkg.root)
	return myprint
}

func (d*Display) _set_root_columns( pkg, pkg_info) {
	ver_str = d._append_build_id(pkg_info.ver, pkg, pkg_info)
	if d.conf.verbosity == 3:
	ver_str = d._append_slot(ver_str, pkg, pkg_info)
	ver_str = d._append_repository(ver_str, pkg, pkg_info)
	if d.conf.quiet:
	myprint = (
		str(pkg_info.attr_display)
	+" "
	+d.indent
	+d.pkgprint(pkg_info.cp, pkg_info)
	)
	myprint = myprint + " " + green(ver_str) + " "
	myprint = myprint + pkg_info.oldbest
	d.verboseadd = None
	else:
	if not pkg_info.merge:
	addl = d.empty_space_in_brackets()
	myprint = "[%s%s] %s%s" % (
		d.pkgprint(pkg_info.operation.ljust(13), pkg_info),
		addl,
		d.indent,
		d.pkgprint(pkg.cp, pkg_info),
) else:
	myprint = "[%s %s] %s%s" % (
		d.pkgprint(pkg.type_name, pkg_info),
		pkg_info.attr_display,
		d.indent,
		d.pkgprint(pkg.cp, pkg_info),
)
	if (d.newlp - nc_len(myprint)) > 0:
	myprint = myprint + (" " * (d.newlp - nc_len(myprint)))
	myprint = myprint + " " + green("["+ver_str+"]") + " "
	if (d.oldlp - nc_len(myprint)) > 0:
	myprint = myprint + (" " * (d.oldlp - nc_len(myprint)))
	myprint += pkg_info.oldbest
	return myprint
}

func (d*Display) _set_no_columns( pkg, pkg_info) {
	pkg_str = d._append_build_id(pkg.cpv, pkg, pkg_info)
	if d.conf.verbosity == 3:
	pkg_str = d._append_slot(pkg_str, pkg, pkg_info)
	pkg_str = d._append_repository(pkg_str, pkg, pkg_info)
	if not pkg_info.merge:
	addl = d.empty_space_in_brackets()
	myprint = "[%s%s] %s%s %s" % (
		d.pkgprint(pkg_info.operation.ljust(13), pkg_info),
		addl,
		d.indent,
		d.pkgprint(pkg_str, pkg_info),
		pkg_info.oldbest,
) else:
	myprint = "[%s %s] %s%s %s" % (
		d.pkgprint(pkg.type_name, pkg_info),
		pkg_info.attr_display,
		d.indent,
		d.pkgprint(pkg_str, pkg_info),
		pkg_info.oldbest,
)
	return myprint
}

func (d*Display) print_messages( show_repos) {
	for msg
	in
	d.print_msg:
	if isinstance(msg, str):
	writemsg_stdout("%s\n" % (msg, ), noiselevel = -1)
	continue
	myprint, d.verboseadd, repoadd = msg
	if d.verboseadd:
	myprint += " " + d.verboseadd
	if show_repos and
repoadd:
	myprint += " " + teal("[%s]"%repoadd)
	writemsg_stdout("%s\n" % (myprint, ), noiselevel = -1)
}

func (d*Display) print_blockers() {
	for pkg
	in
	d.blockers:
	writemsg_stdout("%s\n" % (pkg, ), noiselevel = -1)
}

func (d*Display) print_verbose( show_repos) {
	writemsg_stdout("\n%s\n" % (d.counters, ), noiselevel = -1)
	if show_repos:
	writemsg_stdout("%s" % (d.conf.repo_display, ), noiselevel = -1)
}

func (d*Display) get_display_list( mylist) {
	unsatisfied_blockers = []
ordered_nodes = []
for pkg in mylist:
if isinstance(pkg, Blocker):
d.counters.blocks += 1
if pkg.satisfied:
ordered_nodes.append(pkg)
d.counters.blocks_satisfied += 1 else:
unsatisfied_blockers.append(pkg) else:
ordered_nodes.append(pkg)
if d.conf.tree_display:
display_list = _tree_display(d.conf, ordered_nodes) else:
display_list = [(pkg, 0, True) for pkg in ordered_nodes]
for pkg in unsatisfied_blockers:
display_list.append((pkg, 0, True))
return display_list
}

func (d*Display) set_pkg_info( pkg, ordered) {
	pkg_info = PkgInfo()
	pkg_info.cp = pkg.cp
	pkg_info.ver = d.get_ver_str(pkg)
	pkg_info.slot = pkg.slot
	pkg_info.sub_slot = pkg.sub_slot
	pkg_info.repo_name = pkg.repo
	pkg_info.ordered = ordered
	pkg_info.operation = pkg.operation
	pkg_info.merge = ordered
	and
	pkg_info.operation == "merge"
	if not pkg_info.merge
	and
	pkg_info.operation == "merge":
	pkg_info.operation = "nomerge"
	pkg_info.built = pkg.type_name != "ebuild"
	pkg_info.ebuild_path = None
	if ordered:
	if pkg_info.merge:
	if pkg.type_name == "binary":
	d.counters.binary += 1
	elif
	pkg_info.operation == "uninstall":
	d.counters.uninst += 1
	if pkg.type_name == "ebuild":
	pkg_info.ebuild_path = d.portdb.findname(
		pkg.cpv, myrepo = pkg_info.repo_name
	)
	if pkg_info.ebuild_path is
None:
	raise
	AssertionError("ebuild not found for '%s'" % pkg.cpv)
	pkg_info.repo_path_real = os.path.dirname(
		os.path.dirname(os.path.dirname(pkg_info.ebuild_path))
	)
	else:
	pkg_info.repo_path_real = d.portdb.getRepositoryPath(pkg.repo)
	pkg_info.use = list(d.conf.pkg_use_enabled(pkg))
	if not pkg.built
	and
	pkg.operation == "merge"
	and
	"fetch"
	in
	pkg.restrict:
	if pkg_info.ordered:
	d.counters.restrict_fetch += 1
	pkg_info.attr_display.fetch_restrict = True
	if not d.portdb.getfetchsizes(
		pkg.cpv, useflags = pkg_info.use, myrepo = pkg.repo
	):
	pkg_info.attr_display.fetch_restrict_satisfied = True
	if pkg_info.ordered:
	d.counters.restrict_fetch_satisfied += 1
	else:
	if pkg_info.ebuild_path is
	not
None:
	d.restrict_fetch_list[pkg] = pkg_info

	if d.vardb.cpv_exists(pkg.cpv):
	# Do
	a
	cpv
	match
	first, in case the SLOT has changed.
pkg_info.previous_pkg = d.vardb.match_pkgs(Atom("=" + pkg.cpv))[0] else:
cp_slot_matches = d.vardb.match_pkgs(pkg.slot_atom)
if cp_slot_matches:
pkg_info.previous_pkg = cp_slot_matches[0] else:
cp_matches = d.vardb.match_pkgs(Atom(pkg.cp))
if cp_matches:
# Use highest installed other-slot package instance.
pkg_info.previous_pkg = cp_matches[-1]

return pkg_info
}

func (d*Display) check_system_world( pkg) {
	root_config = d.conf.roots[pkg.root]
	system_set = root_config.sets["system"]
	world_set = d.conf.selected_sets[pkg.root]
	system = False
	world = False
try:
	system = system_set.findAtomForPackage(
		pkg, modified_use = d.conf.pkg_use_enabled(pkg)
	)
	world = world_set.findAtomForPackage(
		pkg, modified_use = d.conf.pkg_use_enabled(pkg)
	)
	if (
		not(d.conf.oneshot or
	world)
	and
	pkg.root == d.conf.target_root
	and
	d.conf.favorites.findAtomForPackage(
		pkg, modified_use = d.conf.pkg_use_enabled(pkg)
	)
):
	# Maybe
	it
	will
	be
	added
	to
	world
	now.
	if create_world_atom(pkg, d.conf.favorites, root_config):
	world = True
	except
InvalidDependString:
	# This
	is
	reported
	elsewhere
	if relevant.
		pass
	return system, world
}

func (d Display) get_ver_str(pkg) {
	ver_str = pkg.cpv.version
	if ver_str.endswith("-r0"):
	ver_str = ver_str[:-3]
	return ver_str
}

func (d*Display) _get_installed_best( pkg, pkg_info) {
	myoldbest = []
myinslotlist = None
installed_versions = d.vardb.match_pkgs(Atom(pkg.cp))
if d.vardb.cpv_exists(pkg.cpv):
pkg_info.attr_display.replace = True
installed_version = pkg_info.previous_pkg
if (
installed_version.slot != pkg.slot
or installed_version.sub_slot != pkg.sub_slot
or not d.quiet_repo_display
and installed_version.repo != pkg.repo
):
myoldbest = [installed_version]
if pkg_info.ordered:
if pkg_info.merge:
d.counters.reinst += 1
# filter out old-style virtual matches
elif installed_versions and installed_versions[0].cp == pkg.cp:
myinslotlist = d.vardb.match_pkgs(pkg.slot_atom)
# If this is the first install of a new-style virtual, we
# need to filter out old-style virtual matches.
if myinslotlist and myinslotlist[0].cp != pkg.cp:
myinslotlist = None
if myinslotlist:
myoldbest = myinslotlist[:]
if not cpvequal(
pkg.cpv, best([pkg.cpv] + [x.cpv for x in myinslotlist])
):
# Downgrade in slot
pkg_info.attr_display.new_version = True
pkg_info.attr_display.downgrade = True
if pkg_info.ordered:
d.counters.downgrades += 1 else:
# Update in slot
pkg_info.attr_display.new_version = True
if pkg_info.ordered:
d.counters.upgrades += 1
else:
myoldbest = installed_versions
pkg_info.attr_display.new = True
pkg_info.attr_display.new_slot = True
if pkg_info.ordered:
d.counters.newslot += 1 else:
pkg_info.attr_display.new = True
if pkg_info.ordered:
d.counters.new += 1
return myoldbest, myinslotlist
}

func (d*Display) __call__( depgraph, mylist, favorites=None, verbosity=None) {
	if favorites is
None:
	favorites = []
d.conf = _DisplayConfig(depgraph, mylist, favorites, verbosity)
mylist = d.get_display_list(d.conf.mylist)
# files to fetch list - avoids counting a same file twice
# in size display (verbose mode)
d.myfetchlist = set()

d.quiet_repo_display = (
"--quiet-repo-display" in depgraph._frozen_config.myopts
)
if d.quiet_repo_display:
# Use this set to detect when all the "repoadd" strings are "[0]"
# and disable the entire repo display in this case.
repoadd_set = set()

d.restrict_fetch_list = {}

for mylist_index in range (len(mylist)):
pkg, depth, ordered = mylist[mylist_index]
d.portdb = d.conf.trees[pkg.root]["porttree"].dbapi
d.vardb = d.conf.trees[pkg.root]["vartree"].dbapi
d.pkgsettings = d.conf.pkgsettings[pkg.root]
d.indent = " " * depth

if isinstance(pkg, Blocker):
d._blockers(pkg)
else:
pkg_info = d.set_pkg_info(pkg, ordered)
pkg_info.oldbest_list, myinslotlist = d._get_installed_best(
pkg, pkg_info
)
if ordered and pkg_info.merge and not pkg_info.attr_display.new:
for arg, atom in depgraph._iter_atoms_for_pkg(pkg):
if arg.force_reinstall:
pkg_info.attr_display.force_reinstall = True
break

d.verboseadd = ""
if d.quiet_repo_display:
d.repoadd = None
d._display_use(pkg, pkg_info)
if d.conf.verbosity == 3:
if d.quiet_repo_display:
d.verbose_size(pkg, repoadd_set, pkg_info) else:
d.verbose_size(pkg, None, pkg_info)

d.oldlp = d.conf.columnwidth - 30
d.newlp = d.oldlp - 30
pkg_info.oldbest = d.convert_myoldbest(pkg, pkg_info)
pkg_info.system, pkg_info.world = d.check_system_world(pkg)
if "interactive" in pkg.properties and pkg.operation == "merge":
pkg_info.attr_display.interactive = True
if ordered:
d.counters.interactive += 1

if d.include_mask_str():
pkg_info.attr_display.mask = d.gen_mask_str(pkg)

if pkg.root_config.settings["ROOT"] != "/":
if pkg_info.oldbest:
pkg_info.oldbest += " "
if d.conf.columns:
myprint = d._set_non_root_columns(pkg, pkg_info) else:
pkg_str = d._append_build_id(pkg.cpv, pkg, pkg_info)
if d.conf.verbosity == 3:
pkg_str = d._append_slot(pkg_str, pkg, pkg_info)
pkg_str = d._append_repository(pkg_str, pkg, pkg_info)
if not pkg_info.merge:
addl = d.empty_space_in_brackets()
myprint = "[%s%s] " % (
d.pkgprint(pkg_info.operation.ljust(13), pkg_info),
addl,
) else:
myprint = "[%s %s] " % (
d.pkgprint(pkg.type_name, pkg_info),
pkg_info.attr_display,
)
myprint += (
d.indent
+ d.pkgprint(pkg_str, pkg_info)
+ " "
+ pkg_info.oldbest
+ darkgreen("to " + pkg.root)
)
else:
if d.conf.columns:
myprint = d._set_root_columns(pkg, pkg_info)
else:
myprint = d._set_no_columns(pkg, pkg_info)

if d.conf.columns and pkg.operation == "uninstall":
continue
if d.quiet_repo_display:
d.print_msg.append((myprint, d.verboseadd, d.repoadd)) else:
d.print_msg.append((myprint, d.verboseadd, None))

show_repos = (
d.quiet_repo_display and repoadd_set and repoadd_set != set(["0"])
)

# now finally print out the messages
d.print_messages(show_repos)
d.print_blockers()
if d.conf.verbosity == 3:
d.print_verbose(show_repos)
for pkg, pkg_info in d.restrict_fetch_list.items():
writemsg_stdout(
"\nFetch instructions for %s:\n" % (pkg.cpv,), noiselevel = -1
)
spawn_nofetch(
d.conf.trees[pkg.root]["porttree"].dbapi, pkg_info.ebuild_path
)

return os.EX_OK
}


func Format_unmatched_atom(pkg, atom, pkg_use_enabled) {

	if atom.soname:
	return "%s" % (atom,), ""

	highlight = set()

	def
	perform_coloring():
	atom_str = ""
	marker_str = ""
	for ii, x
	in
	enumerate(atom):
	if ii in
highlight:
	atom_str += output.Colorize("BAD", x)
	marker_str += "^"
	else:
	atom_str += x
	marker_str += " "
	return atom_str, marker_str

	if atom.cp != pkg.cp:
	# Highlight
	the
	cp
	part
	only.
		ii = atom.find(atom.cp)
	highlight.update(range
	(ii, ii + len(atom.cp)))
	return perform_coloring()

	version_atom = atom.without_repo.without_slot.without_use
	version_atom_set = InternalPackageSet(initial_atoms = (version_atom,))
	highlight_version = not
	bool(
		version_atom_set.findAtomForPackage(pkg, modified_use = pkg_use_enabled(pkg))
)

	highlight_slot = False
	if (atom.slot and
	atom.slot != pkg.slot) or(
		atom.sub_slot
	and
	atom.sub_slot != pkg.sub_slot
	):
	highlight_slot = True

	if highlight_version:
	op = atom.operator
	ver = None
	if atom.cp != atom.cpv:
	ver = cpv_getversion(atom.cpv)

	if op == "=*":
	op = "="
	ver += "*"

	if op is
	not
None:
	highlight.update(range
	(len(op)))

	if ver is
	not
None:
	start = atom.rfind(ver)
	end = start + len(ver)
	highlight.update(range
	(start, end))

	if highlight_slot:
	slot_str = ":" + atom.slot
	if atom.sub_slot:
	slot_str += "/" + atom.sub_slot
	if atom.slot_operator:
	slot_str += atom.slot_operator
	start = atom.find(slot_str)
	end = start + len(slot_str)
	highlight.update(range
	(start, end))

	highlight_use = set()
	if atom.use:
	use_atom = "%s[%s]" % (atom.cp, str(atom.use))
	use_atom_set = InternalPackageSet(initial_atoms = (use_atom,))
	if not use_atom_set.findAtomForPackage(pkg, modified_use = pkg_use_enabled(pkg)):
	missing_iuse = pkg.iuse.get_missing_iuse(atom.unevaluated_atom.use.required)
	if missing_iuse:
	highlight_use = set(missing_iuse)
	else:
	# Use
	conditionals
	not
	met.
		violated_atom = atom.violated_conditionals(
		pkg_use_enabled(pkg), pkg.iuse.is_valid_flag
	)
	if violated_atom.use is
	not
None:
	highlight_use = set(
		violated_atom.use.enabled.union(violated_atom.use.disabled)
	)

	if highlight_use:
	ii = atom.find("[") + 1
	for token
	in
	atom.use.tokens:
	if token.lstrip("-!").rstrip("=?") in
highlight_use:
	highlight.update(range
	(ii, ii + len(token)))
	ii += len(token) + 1

	return perform_coloring()
}
