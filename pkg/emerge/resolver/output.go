package resolver

import (
	"fmt"
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/sets"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"path/filepath"
	"strings"
)

// var bad = output.NewCreateColorFunc("BAD")

type Display struct {
	counters *emerge._PackageCounters
	verboseadd ,
	indent,
	repoadd,
	blocker_style string
	print_msg ,
	blockers []string
	conf *_DisplayConfig
	quiet_repo_display bool
	resolver,
	resolved,
	vardb,
	portdb,
	oldlp,
	myfetchlist,
	use_expand,
	use_expand_hidden,
	pkgsettings,
	forced_flags,
	newlp,
	restrict_fetch_list,
	myfetchlist,
}

func NewDisplay() *Display {
	d := &Display{}
	d.print_msg = []string{}
	d.blockers = []string{}
	d.counters = NewPackageCounters()
	d.resolver = None
	d.resolved = None
	d.vardb = None
	d.portdb = None
	d.verboseadd = ""
	d.oldlp = None
	d.myfetchlist = None
	d.indent = ""
	d.use_expand = None
	d.use_expand_hidden = None
	d.pkgsettings = None
	d.forced_flags = None
	d.newlp = None
	d.conf = nil
	d.blocker_style = ""
	return d
}

func (d*Display) _blockers( blocker) {
	addl := ""
	if blocker.satisfied {
		d.blocker_style = "PKG_BLOCKER_SATISFIED"
		addl = fmt.Sprintf("%s     " ,output.Colorize(d.blocker_style, "b"))
	}else {
		d.blocker_style = "PKG_BLOCKER"
		addl = fmt.Sprintf("%s     " ,output.Colorize(d.blocker_style, "B"))
	}
	addl += d.empty_space_in_brackets()
	d.resolved = dbapi.Dep_expand(
		str(blocker.atom).lstrip("!"), mydb = d.vardb, settings = d.pkgsettings
	)
	if d.conf.columns && d.conf.quiet {
		addl += " " + output.Colorize(d.blocker_style, str(d.resolved))
	}else {
		addl = fmt.Sprintf("[%s %s] %s%s",
			output.Colorize(d.blocker_style, "blocks"),
			addl,
			d.indent,
			output.Colorize(d.blocker_style, str(d.resolved)),
		)
	}
	block_parents := d.conf.blocker_parents.parent_nodes(blocker)
	block_parents = set(str(pnode.cpv)
	for pnode
	in
	block_parents)
	block_parents1 := strings.Join(block_parents,  ", ")
	if blocker.atom.blocker.overlap.forbid {
		blocking_desc = "hard blocking"
	}else {
		blocking_desc = "soft blocking"
	}
	if d.resolved != blocker.atom {
		addl += output.Colorize(
			d.blocker_style,
			fmt.Sprintf(" (\"%s\" is %s %s)"
		, str(blocker.atom).lstrip("!"), blocking_desc, block_parents1),
	)
	}else {
		addl += output.Colorize(
			d.blocker_style, fmt.Sprintf(" (is %s %s)", blocking_desc, block_parents1)
		)
	}
	if blocker.satisfied {
		if ! d.conf.columns {
			d.print_msg=append(d.print_msg, addl)
		}
	}else {
		d.blockers=append(d.blockers, addl)
	}
}

func (d*Display) include_mask_str() bool {
	return d.conf.verbosity > 1
}

func (d*Display) gen_mask_str( pkg) string {
	hardmasked := pkg.isHardMasked()
	mask_str := " "

	if hardmasked {
		mask_str = output.Colorize("BAD", "#")
	}else {
		keyword_mask := pkg.get_keyword_mask()
		if keyword_mask == ""{
			// pass
		}else if keyword_mask == "missing"{
		mask_str = output.Colorize("BAD", "*")
	}else{
			mask_str = output.Colorize("WARN", "~")
		}
	}

	return mask_str
}

func (d*Display) empty_space_in_brackets() string {
	space := ""
	if d.include_mask_str() {
		space += " "
	}
	return space
}

// false, true
func (d*Display) map_to_use_expand( myvals T, forced_flags, remove_hidden bool) {
	ret :=
	{
	}
	forced :=
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

	cur_use := []T{
flag for flag in d.conf.pkg_use_enabled(pkg) if flag in pkg.iuse.all
}

cur_iuse = sorted(pkg.iuse.all)

	old_iuse := []T{}
	old_use := []T{}
	is_new := true
if pkg_info.previous_pkg is not None{
previous_pkg = pkg_info.previous_pkg
old_iuse = sorted(previous_pkg.iuse.all)
old_use = previous_pkg.use.enabled
is_new = false
}

old_use = []T{flag for flag in old_use if flag in old_iuse}

d.use_expand = pkg.use.expand
d.use_expand_hidden = pkg.use.expand_hidden

reinst_flags_map = {}
reinstall_for_flags := d.conf.reinstall_nodes.get(pkg)
reinst_expand_map = None
if reinstall_for_flags {
	reinst_flags_map = d.map_to_use_expand(
		list(reinstall_for_flags), remove_hidden = false
	)
	for k
	in
	list(reinst_flags_map) {
		if not reinst_flags_map[k] {
			del
			reinst_flags_map[k]
		}
	}
	if not reinst_flags_map.get("USE") {
		reinst_expand_map = reinst_flags_map.copy()
		reinst_expand_map.pop("USE", None)
	}
}
if reinst_expand_map and not set(reinst_expand_map).difference(
d.use_expand_hidden
)
	{
		d.use_expand_hidden = set(d.use_expand_hidden).difference(
			reinst_expand_map
		)
	}

cur_iuse_map, iuse_forced = d.map_to_use_expand(cur_iuse, forced_flags= true)
cur_use_map = d.map_to_use_expand(cur_use)
old_iuse_map = d.map_to_use_expand(old_iuse)
old_use_map = d.map_to_use_expand(old_use)

use_expand = sorted(d.use_expand)
use_expand.insert(0, "USE")
feature_flags = _get_feature_flags(_get_eapi_attrs(pkg.eapi))

for key in use_expand{
		if key in d.use_expand_hidden{
		continue
	}
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
}

func (d Display) pkgprint(pkg_str string, pkg_info) string {
	if pkg_info.merge {
		if pkg_info.built {
			if pkg_info.system {
				return output.Colorize("PKG_BINARY_MERGE_SYSTEM", pkg_str)
			}
			if pkg_info.world {
				return output.Colorize("PKG_BINARY_MERGE_WORLD", pkg_str)
			}
			return output.Colorize("PKG_BINARY_MERGE", pkg_str)
		}

		if pkg_info.system {
			return output.Colorize("PKG_MERGE_SYSTEM", pkg_str)
		}
		if pkg_info.world {
			return output.Colorize("PKG_MERGE_WORLD", pkg_str)
		}
		return output.Colorize("PKG_MERGE", pkg_str)
	}

	if pkg_info.operation == "uninstall" {
		return output.Colorize("PKG_UNINSTALL", pkg_str)
	}

	if pkg_info.system {
		return output.Colorize("PKG_NOMERGE_SYSTEM", pkg_str)
	}
	if pkg_info.world {
		return output.Colorize("PKG_NOMERGE_WORLD", pkg_str)
	}
	return output.Colorize("PKG_NOMERGE", pkg_str)
}

func (d*Display) verbose_size( pkg, repoadd_set, pkg_info) {
	mysize := 0
	if pkg.type_name in("binary", "ebuild")&& pkg_info.merge {
		db = pkg.root_config.trees[
			pkg.root_config.pkg_tree_map[pkg.type_name]
		].dbapi
		kwargs =
		{
		}
		if pkg.type_name == "ebuild" {
			kwargs["useflags"] = pkg_info.use
			kwargs["myrepo"] = pkg.repo
		}
		myfilesdict = None
	//try:
		myfilesdict = db.getfetchsizes(pkg.cpv, **kwargs)
		//except InvalidDependString as e:
		//(depstr,) = db.aux_get(pkg.cpv,["SRC_URI"], myrepo = pkg.repo)
		//show_invalid_depstring_notice(pkg, str(e))
		//raise
		//except SignatureException:
		//pass
		if myfilesdict == nil{
		myfilesdict = "[empty/missing/bad digest]"
	}else {
			for myfetchfile
				in
			myfilesdict {
				if myfetchfile not
				in
				d.myfetchlist{
					mysize += myfilesdict[myfetchfile]
					d.myfetchlist.add(myfetchfile)
				}
			}
			if pkg_info.ordered {
				d.counters.totalsize += mysize
			}
		}
		d.verboseadd += Localized_size(mysize)
	}

	if d.quiet_repo_display {
		if pkg_info.previous_pkg != nil {
			repo_name_prev = pkg_info.previous_pkg.repo
		}else {
			repo_name_prev = None
		}

		if pkg.installed || pkg_info.previous_pkg
		is
	None{
		d.repoadd = d.conf.repo_display.repoStr(pkg_info.repo_path_real)
	}else {
			repo_path_prev = None
			if repo_name_prev {
				repo_path_prev = d.portdb.getRepositoryPath(repo_name_prev)
			}
			if repo_path_prev == pkg_info.repo_path_real {
				d.repoadd = d.conf.repo_display.repoStr(
					pkg_info.repo_path_real
				)
			}else {
				d.repoadd = fmt.Sprintf("%s=>%s",
					d.conf.repo_display.repoStr(repo_path_prev),
					d.conf.repo_display.repoStr(pkg_info.repo_path_real),
				)
			}
		}
		if d.repoadd != "" {
			repoadd_set.add(d.repoadd)
		}
	}
}

func (d*Display) convert_myoldbest( pkg, pkg_info) string {
	myoldbest := pkg_info.oldbest_list
	myoldbest_str := ""
	if myoldbest {
		versions := []string{}
		for pos, old_pkg := range myoldbest {
			key := old_pkg.version
			if strings.HasSuffix(key, "-r0") {
				key = key[:len(key)-3]
			}
			if d.conf.verbosity == 3 {
				if pkg_info.attr_display.new_slot {
					key += _slot_separator + old_pkg.slot
					if old_pkg.slot != old_pkg.sub_slot {
						key += "/" + old_pkg.sub_slot
					}
				}else if
				any(
					x.slot+"/"+x.sub_slot != "0/0"
				for x
					in
				myoldbest +[pkg]
				){
					key += _slot_separator + old_pkg.slot
					if (
						old_pkg.slot != old_pkg.sub_slot
						or
					old_pkg.slot == pkg.slot
					and
					old_pkg.sub_slot != pkg.sub_slot
					){
						key += "/" + old_pkg.sub_slot
					}
				}
				if ! d.quiet_repo_display {
					key += _repo_separator + old_pkg.repo
				}
			}
			versions = append(versions, key)
		}
		myoldbest_str = output.Blue("[" + strings.Join(versions, ", ") + "]")
	}
	return myoldbest_str
}

func (d*Display) _append_slot( pkg_str string, pkg, pkg_info) string {
	if pkg_info.attr_display.new_slot {
		pkg_str += _slot_separator + pkg_info.slot
		if pkg_info.slot != pkg_info.sub_slot {
			pkg_str += "/" + pkg_info.sub_slot
		}
	}else if
	any(
		x.slot+"/"+x.sub_slot != "0/0"
	for x
	in
	pkg_info.oldbest_list +[pkg]
	){
		pkg_str += _slot_separator + pkg_info.slot
		if pkg_info.slot != pkg_info.sub_slot or
		any(
			x.slot == pkg_info.slot
		and
		x.sub_slot != pkg_info.sub_slot
		for x
			in
		pkg_info.oldbest_list
		){
			pkg_str += "/" + pkg_info.sub_slot
		}
	}
	return pkg_str
}

func (d*Display) _append_repository( pkg_str string, pkg, pkg_info) string {
	if ! d.quiet_repo_display {
		pkg_str += _repo_separator + pkg.repo
	}
	return pkg_str
}

func (d*Display) _append_build_id( pkg_str string, pkg, pkg_info) string {
	if pkg.type_name == "binary" && pkg.cpv.build_id!= nil {
		pkg_str += fmt.Sprintf("-%s" , pkg.cpv.build_id)
	}
	return pkg_str
}

func (d*Display) _set_non_root_columns( pkg, pkg_info) {
	ver_str := d._append_build_id(pkg_info.ver, pkg, pkg_info)
	if d.conf.verbosity == 3 {
		ver_str = d._append_slot(ver_str, pkg, pkg_info)
		ver_str = d._append_repository(ver_str, pkg, pkg_info)
	}
	if d.conf.quiet {
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
	}else {
		if not pkg_info.merge {
			myprint = "[%s] %s%s" % (
				d.pkgprint(pkg_info.operation.ljust(13), pkg_info),
				d.indent,
				d.pkgprint(pkg.cp, pkg_info),
		)
		}else {
			myprint = "[%s %s] %s%s" % (
				d.pkgprint(pkg.type_name, pkg_info),
				pkg_info.attr_display,
				d.indent,
				d.pkgprint(pkg.cp, pkg_info),
		)
		}
		if (d.newlp - output.NcLen(myprint)) > 0 {
			myprint = myprint + (" " * (d.newlp - output.NcLen(myprint)))
		}
		myprint = myprint + " " + darkblue("["+ver_str+"]") + " "
		if (d.oldlp - output.NcLen(myprint)) > 0 {
			myprint = myprint + " "*(d.oldlp-output.NcLen(myprint))
		}
		myprint = myprint + pkg_info.oldbest
		myprint += darkgreen("to " + pkg.root)
	}
	return myprint
}

func (d*Display) _set_root_columns( pkg, pkg_info) string {
	ver_str := d._append_build_id(pkg_info.ver, pkg, pkg_info)
	if d.conf.verbosity == 3 {
		ver_str = d._append_slot(ver_str, pkg, pkg_info)
		ver_str = d._append_repository(ver_str, pkg, pkg_info)
	}
	myprint := ""
	if d.conf.quiet {
		myprint = str(pkg_info.attr_display)+" "+d.indent+d.pkgprint(pkg_info.cp, pkg_info)
		
		myprint = myprint + " " + output.Green(ver_str) + " "
		myprint = myprint + pkg_info.oldbest
		d.verboseadd = ""
	}else {
		if ! pkg_info.merge {
			addl := d.empty_space_in_brackets()
			myprint = fmt.Sprintf("[%s%s] %s%s", 
				d.pkgprint(pkg_info.operation.ljust(13), pkg_info),
				addl, d.indent, d.pkgprint(pkg.cp, pkg_info),)
		}else {
			myprint = fmt.Sprintf("[%s %s] %s%s" , 
				d.pkgprint(pkg.type_name, pkg_info),
				pkg_info.attr_display, d.indent, d.pkgprint(pkg.cp, pkg_info), )
		}
		if (d.newlp - output.NcLen(myprint)) > 0 {
			myprint = myprint + (" " * (d.newlp - output.NcLen(myprint)))
		}
		myprint = myprint + " " + output.Green("["+ver_str+"]") + " "
		if (d.oldlp - output.NcLen(myprint)) > 0 {
			myprint = myprint + (" " * (d.oldlp - output.NcLen(myprint)))
		}
		myprint += pkg_info.oldbest
	}
	return myprint
}

func (d*Display) _set_no_columns( pkg, pkg_info) string {
	pkg_str := d._append_build_id(pkg.cpv, pkg, pkg_info)
	if d.conf.verbosity == 3 {
		pkg_str = d._append_slot(pkg_str, pkg, pkg_info)
		pkg_str = d._append_repository(pkg_str, pkg, pkg_info)
	}
	myprint := ""
	if !pkg_info.merge {
		addl := d.empty_space_in_brackets()
		myprint = fmt.Sprintf("[%s%s] %s%s %s",
			d.pkgprint(pkg_info.operation.ljust(13), pkg_info), addl,
			d.indent, d.pkgprint(pkg_str, pkg_info), pkg_info.oldbest, )
	} else {
		myprint = fmt.Sprintf("[%s %s] %s%s %s", 
			d.pkgprint(pkg.type_name, pkg_info), pkg_info.attr_display,
			d.indent, d.pkgprint(pkg_str, pkg_info), pkg_info.oldbest, )
	}
	return myprint
}

func (d*Display) print_messages( show_repos) {
	for _,  msg1:= range d.print_msg {
		//if isinstance(msg, str):
		msg.WriteMsgStdout(fmt.Sprintf("%s\n", msg1, ), -1)
		continue
		//myprint, d.verboseadd, repoadd = msg
		//if d.verboseadd:
		//myprint += " " + d.verboseadd
		//if show_repos and
	//repoadd:
	//	myprint += " " + teal("[%s]"%repoadd)
	//	msg.WriteMsgStdout("%s\n" % (myprint, ), noiselevel = -1)
	}
}

func (d*Display) print_blockers() {
	for pkg := range d.blockers {
		msg.WriteMsgStdout(fmt.Sprintf("%s\n", pkg, ), -1)
	}
}

func (d*Display) print_verbose( show_repos) {
	msg.WriteMsgStdout(fmt.Sprintf("\n%s\n" ,d.counters, ),  -1)
	if show_repos {
		msg.WriteMsgStdout(fmt.Sprintf("%s",d.conf.repo_display, ),  -1)
	}
}

func (d*Display) get_display_list( mylist) {
	unsatisfied_blockers := []T{}
	ordered_nodes := []T{}
	for pkg
	in
mylist {
		if isinstance(pkg, emerge.Blocker) {
			d.counters.blocks += 1
			if pkg.satisfied {
				ordered_nodes = append(ordered_nodes, pkg)
				d.counters.blocks_satisfied += 1
			}else {
				unsatisfied_blockers = append(unsatisfied_blockers, pkg)
			}
		}else {
			ordered_nodes = append(ordered_nodes, pkg)
		}
	}
	if d.conf.tree_display {
		display_list = emerge._tree_display(d.conf, ordered_nodes)
	} else {
		display_list = [(pkg, 0, true) for pkg in ordered_nodes]
}
for pkg in unsatisfied_blockers{
display_list = append(display_list, (pkg, 0, true))
}
return display_list
}

func (d*Display) set_pkg_info( pkg, ordered) {
	pkg_info := NewPkgInfo()
	pkg_info.cp = pkg.cp
	pkg_info.ver = d.get_ver_str(pkg)
	pkg_info.slot = pkg.slot
	pkg_info.sub_slot = pkg.sub_slot
	pkg_info.repo_name = pkg.repo
	pkg_info.ordered = ordered
	pkg_info.operation = pkg.operation
	pkg_info.merge = ordered && pkg_info.operation == "merge"
	if !pkg_info.merge && pkg_info.operation == "merge" {
		pkg_info.operation = "nomerge"
	}
	pkg_info.built = pkg.type_name != "ebuild"
	pkg_info.ebuild_path = None
	if ordered {
		if pkg_info.merge {
			if pkg.type_name == "binary" {
				d.counters.binary += 1
			}
		} else if pkg_info.operation == "uninstall" {
			d.counters.uninst += 1
		}
	}
	if pkg.type_name == "ebuild" {
		pkg_info.ebuild_path = d.portdb.findname(
			pkg.cpv, myrepo = pkg_info.repo_name
		)
		if pkg_info.ebuild_path is
	None:
		raise
		AssertionError("ebuild not found for '%s'" % pkg.cpv)
		pkg_info.repo_path_real = filepath.Dir(filepath.Dir(filepath.Dir(pkg_info.ebuild_path)))
	} else {
		pkg_info.repo_path_real = d.portdb.getRepositoryPath(pkg.repo)
	}
	pkg_info.use = list(d.conf.pkg_use_enabled(pkg))
	if !pkg.built && pkg.operation == "merge" && "fetch" in
	pkg.restrict{
		if pkg_info.ordered{
		d.counters.restrict_fetch += 1
	}
		pkg_info.attr_display.fetch_restrict = true
		if not d.portdb.getfetchsizes(
		pkg.cpv, useflags = pkg_info.use, myrepo = pkg.repo
	){
		pkg_info.attr_display.fetch_restrict_satisfied = true
		if pkg_info.ordered{
		d.counters.restrict_fetch_satisfied += 1
	}
	} else{
		if pkg_info.ebuild_path is
		not
		None{
		d.restrict_fetch_list[pkg] = pkg_info
	}
	}
	}

	if d.vardb.cpv_exists(pkg.cpv) {
		pkg_info.previous_pkg = d.vardb.match_pkgs(Atom("=" + pkg.cpv))[0]
	} else {
		cp_slot_matches = d.vardb.match_pkgs(pkg.slot_atom)
		if cp_slot_matches {
			pkg_info.previous_pkg = cp_slot_matches[0]
		} else {
			cp_matches = d.vardb.match_pkgs(Atom(pkg.cp))
			if cp_matches {
				pkg_info.previous_pkg = cp_matches[-1]
			}
		}
	}

	return pkg_info
}

func (d*Display) check_system_world( pkg) {
	root_config := d.conf.roots[pkg.root]
	system_set := root_config.sets["system"]
	world_set := d.conf.selected_sets[pkg.root]
	system := false
	world := false
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
	d.conf.favorites.FindAtomForPackage(
		pkg, modified_use = d.conf.pkg_use_enabled(pkg)
	)
):
	if create_world_atom(pkg, d.conf.favorites, root_config):
	world = true
	except
InvalidDependString:
		pass
	return system, world
}

func (d Display) get_ver_str(pkg) string {
	ver_str := pkg.cpv.version
	if strings.HasSuffix(ver_str,"-r0") {
		ver_str = ver_str[len(ver_str):-3]
	}
	return ver_str
}

func (d*Display) _get_installed_best( pkg, pkg_info) {
	myoldbest := []T{}
myinslotlist := None
installed_versions := d.vardb.match_pkgs(Atom(pkg.cp))
if d.vardb.cpv_exists(pkg.cpv) {
	pkg_info.attr_display.replace = true
	installed_version = pkg_info.previous_pkg
	if (
		installed_version.slot != pkg.slot
		or
	installed_version.sub_slot != pkg.sub_slot
	or
	not
	d.quiet_repo_display
	and
	installed_version.repo != pkg.repo
	){
		myoldbest = []T{installed_version}
	}
	if pkg_info.ordered {
		if pkg_info.merge {
			d.counters.reinst += 1
		}
	}
}else if installed_versions and installed_versions[0].cp == pkg.cp{
		myinslotlist = d.vardb.match_pkgs(pkg.slot_atom)
		if myinslotlist and myinslotlist[0].cp != pkg.cp{
		myinslotlist = None
	}
		if myinslotlist{
		myoldbest = myinslotlist[:]
		if not cpvequal(
		pkg.cpv, best([pkg.cpv] + [x.cpv for x in myinslotlist])
	){
		pkg_info.attr_display.new_version = true
		pkg_info.attr_display.downgrade = true
		if pkg_info.ordered{
		d.counters.downgrades += 1
	}
	}else{
		pkg_info.attr_display.new_version = true
		if pkg_info.ordered{
		d.counters.upgrades += 1
	}
	}
	}else{
		myoldbest = installed_versions
		pkg_info.attr_display.new = true
		pkg_info.attr_display.new_slot = true
		if pkg_info.ordered{
		d.counters.newslot += 1
	}
	}
	}else {
		pkg_info.attr_display.new = true
		if pkg_info.ordered {
			d.counters.new += 1
		}
	}
return myoldbest, myinslotlist
}

// nil, nil
func (d*Display) __call__( depgraph *emerge.Depgraph, mylist, favorites  []*dep.Atom, verbosity int) int {
	if favorites == nil {
		favorites = []T{}
	}
	d.conf = NewDisplayConfig(depgraph, mylist, favorites, verbosity)
	mylist := d.get_display_list(d.conf.mylist)
	d.myfetchlist = set()

	d.quiet_repo_display = "--quiet-repo-display"
	in
	depgraph._frozen_config.myopts

	if d.quiet_repo_display {
		repoadd_set = set()
	}

	d.restrict_fetch_list =
	{
	}

	for mylist_index
	in range
	(len(mylist))
	{
		pkg, depth, ordered = mylist[mylist_index]
		d.portdb = d.conf.trees[pkg.root]["porttree"].dbapi
		d.vardb = d.conf.trees[pkg.root]["vartree"].dbapi
		d.pkgsettings = d.conf.pkgsettings[pkg.root]
		d.indent = " " * depth

		if isinstance(pkg, emerge.Blocker):
		d._blockers(pkg)
		else:
		pkg_info = d.set_pkg_info(pkg, ordered)
		pkg_info.oldbest_list, myinslotlist = d._get_installed_best(
			pkg, pkg_info
		)
		if ordered and
		pkg_info.merge
		and
		not
		pkg_info.attr_display.new:
		for arg, atom
			in
		depgraph._iter_atoms_for_pkg(pkg):
		if arg.force_reinstall:
		pkg_info.attr_display.force_reinstall = true
		break

		d.verboseadd = ""
		if d.quiet_repo_display:
		d.repoadd = ""
		d._display_use(pkg, pkg_info)
		if d.conf.verbosity == 3:
		if d.quiet_repo_display:
		d.verbose_size(pkg, repoadd_set, pkg_info) else:
		d.verbose_size(pkg, None, pkg_info)

		d.oldlp = d.conf.columnwidth - 30
		d.newlp = d.oldlp - 30
		pkg_info.oldbest = d.convert_myoldbest(pkg, pkg_info)
		pkg_info.system, pkg_info.world = d.check_system_world(pkg)
		if "interactive" in
		pkg.properties
		and
		pkg.operation == "merge":
		pkg_info.attr_display.interactive = true
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
		+d.pkgprint(pkg_str, pkg_info)
		+" "
		+pkg_info.oldbest
		+darkgreen("to " + pkg.root)
		) else:
		if d.conf.columns:
		myprint = d._set_root_columns(pkg, pkg_info)
		else:
		myprint = d._set_no_columns(pkg, pkg_info)

		if d.conf.columns and
		pkg.operation == "uninstall":
		continue
		if d.quiet_repo_display:
		d.print_msg.append((myprint, d.verboseadd, d.repoadd)) else:
		d.print_msg.append((myprint, d.verboseadd, None))
	}

	show_repos := d.quiet_repo_display && repoadd_set && repoadd_set != set(["0"])


	d.print_messages(show_repos)
	d.print_blockers()
	if d.conf.verbosity == 3 {
		d.print_verbose(show_repos)
	}
	for pkg, pkg_info
	in
	d.restrict_fetch_list.items()
	{
		msg.WriteMsgStdout(
			"\nFetch instructions for %s:\n" % (pkg.cpv, ), noiselevel = -1
		)
		spawn_nofetch(
			d.conf.trees[pkg.root]["porttree"].dbapi, pkg_info.ebuild_path
		)
	}

	return 0
}


func Format_unmatched_atom(pkg, atom *dep.Atom, pkg_use_enabled) (string, string) {

	if atom.soname {
		return fmt.Sprintf("%s" ,atom,), ""
	}

	highlight := set()

	 perform_coloring := func() (string, string) {
		 atom_str := ""
		 marker_str := ""
		 for ii, x := range atom {
			 if ii in
			 highlight{
				 atom_str += output.Colorize("BAD", x)
				 marker_str += "^"
			 } else {
				 atom_str += x
				 marker_str += " "
			 }
		 }
		 return atom_str, marker_str
	 }

	if atom.cp != pkg.cp {
		ii = atom.find(atom.cp)
		highlight.update(range
		(ii, ii + len(atom.cp)))
		return perform_coloring()
	}

	version_atom := atom.without_repo.without_slot.without_use
	version_atom_set := sets.NewInternalPackageSet([]*dep.Atom{version_atom}, false, true)
	highlight_version := !bool(version_atom_set.FindAtomForPackage(pkg, pkg_use_enabled(pkg)))

	highlight_slot := false
	if (atom.slot && atom.slot != pkg.slot) ||(atom.sub_slot && atom.sub_slot != pkg.sub_slot) {
		highlight_slot = true
	}

	if highlight_version {
		op := atom.operator
		ver = None
		if atom.cp != atom.cpv:
		ver = versions.CpvGetVersion(atom.cpv)

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
	}

	if highlight_slot {
		slot_str = ":" + atom.slot
		if atom.sub_slot:
		slot_str += "/" + atom.sub_slot
		if atom.slot_operator:
		slot_str += atom.slot_operator
		start = atom.find(slot_str)
		end = start + len(slot_str)
		highlight.update(range
		(start, end))
	}

	highlight_use := set()
	if atom.use:
	use_atom = "%s[%s]" % (atom.cp, str(atom.use))
	use_atom_set := sets.NewInternalPackageSet([]*dep.Atom{use_atom,}, false, true)
	if not use_atom_set.findAtomForPackage(pkg, modified_use = pkg_use_enabled(pkg)):
	missing_iuse = pkg.iuse.get_missing_iuse(atom.unevaluated_atom.use.required)
	if missing_iuse:
	highlight_use = set(missing_iuse)
	else:
		violated_atom = atom.violated_conditionals(
		pkg_use_enabled(pkg), pkg.iuse.is_valid_flag
	)
	if violated_atom.use is
	not
None:
	highlight_use = set(
		violated_atom.use.enabled.union(violated_atom.use.disabled)
	)

	if highlight_use {
		ii = atom.find("[") + 1
		for token
			in
		atom.use.tokens {
			if token.lstrip("-!").rstrip("=?") in
			highlight_use{
				highlight.update(range
			(ii, ii + len(token)))
			}
			ii += len(token) + 1
		}
	}

	return perform_coloring()
}
