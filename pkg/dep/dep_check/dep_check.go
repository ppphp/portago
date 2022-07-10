package dep_check

import (
	"fmt"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/util/bad"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"strings"
)

// "/", nil, 0, 0
func _expand_new_virtuals(mysplit []string, edebug bool, mydbapi, mysettings *config.Config, myroot string,
	trees portage.TreesDict, use_mask, use_force int, **kwargs){

	newsplit := []string{}
	mytrees := trees.valueDict[myroot]
	var portdb interfaces.IDbApi = mytrees.PortTree().dbapi
	pkg_use_enabled := mytrees.get("pkg_use_enabled")
	atom_graph := mytrees.get("atom_graph")
	parent := mytrees.get("parent")
	virt_parent := mytrees.get("virt_parent")
	var graph_parent = nil
	if parent != nil {
		if virt_parent != nil {
			graph_parent = virt_parent
			parent = virt_parent
		} else {
			graph_parent = parent
		}
	}
	repoman :=!mysettings.localConfig
	if kwargs["use_binaries"] {
		portdb = trees.valueDict[myroot].BinTree().dbapi
	}
	pprovideddict := mysettings.pprovideddict
	myuse := kwargs["myuse"]
	is_disjunction := len(mysplit)>0 && mysplit[0] == "||"
	for _, x := range mysplit{
		if x == "||"{
			newsplit= append(newsplit,x)
			continue
		}else if isinstance(x, list) {
			assert
			x, "Normalization error, empty conjunction found in %s" % (mysplit,)
			if is_disjunction {
				assert
				x[0] != "||",
					"Normalization error, nested disjunction found in %s" % (mysplit,)
			} else {
				assert
				x[0] == "||",
					"Normalization error, nested conjunction found in %s" % (mysplit,)
			}

			x_exp := _expand_new_virtuals(x, edebug, mydbapi,
				mysettings, myroot, trees, use_mask,
				use_force, **kwargs)
			if is_disjunction {
				if len(x_exp) == 1 {
					x = x_exp[0]
					if isinstance(x, list) {
						assert
						x && x[0] == "||",
							"Normalization error, nested conjunction found in %s" % (x_exp,)
						newsplit= append(newsplit, x[1:]...)
					} else {
						newsplit = append(newsplit, x)
					}
				} else {
					newsplit = append(newsplit, x_exp)
				}
			} else {
				newsplit= append(newsplit, x_exp...)
			}
			continue
		}

		if!isinstance(x, dep.Atom) {
			raise
			ParseError(
				_("invalid token: '%s'") % x)
		}

		if repoman {
			x = x._eval_qa_conditionals(use_mask, use_force)
		}

		mykey := x.cp
		if!strings.HasPrefix(mykey,"virtual/") {
			newsplit = append(newsplit, x)
			if atom_graph != nil {
				atom_graph.add((x, id(x)), graph_parent)
			}
			continue
		}

		if x.blocker {
			newsplit = append(newsplit, x)
			if atom_graph != nil {
				atom_graph.add((x, id(x)), graph_parent)
			}
			continue
		}

		if repoman ||!hasattr(portdb, "match_pkgs") ||
			pkg_use_enabled == nil {
			if portdb.cp_list(x.cp) {
				newsplit = append(newsplit, x)
			} else {
				a := []*dep.Atom{}
				myvartree := mytrees.VarTree()
				if myvartree != nil {
					mysettings._populate_treeVirtuals_if_needed(myvartree)
				}
				mychoices := mysettings.getVirtuals()[mykey]
				for _, y := range mychoices {
					a = append(a, dep.Atom(x.replace(x.cp, y.cp, 1)))
				}
				if len(a) == 0 {
					newsplit = append(newsplit, x)
				} else if is_disjunction {
					newsplit= append(newsplit, a)
				} else if len(a) == 1 {
					newsplit = append(newsplit, a[0])
				} else {
					newsplit = append(newsplit, ["||"] + a)
				}
			}
			continue
		}

		pkgs := []string{}
		matches := portdb.match_pkgs(x.without_use)
		myutil.ReverseSlice(matches)
		for _, pkg := range matches{
			if strings.HasPrefix(pkg.cp,"virtual/"){
				pkgs = append(pkgs, pkg)
			}
		}

		mychoices := []string{}
		if!pkgs &&len(portdb.cp_list(x.cp)) == 0 {
			myvartree := mytrees.VarTree()
			if myvartree != nil {
				mysettings._populate_treeVirtuals_if_needed(myvartree)
			}
			mychoices = mysettings.getVirtuals()[mykey]
		}

		if!(len(pkgs)>0 || len(mychoices) > 0) {
			newsplit = append(newsplit, x)
			if atom_graph != nil {
				atom_graph.add((x, id(x)), graph_parent)
			}
			continue
		}

		a := []string{}
		for versions.pkg
		in pkgs{
			virt_atom := "=" + pkg.cpv
			if x.unevaluated_atom.use{
			virt_atom += str(x.unevaluated_atom.use)
			virt_atom = Atom(virt_atom)
			if parent == nil{
			if myuse == nil{
			virt_atom = virt_atom.evaluate_conditionals(
			mysettings.ValueDict["PORTAGE_USE", "").split())
		}else{
			virt_atom = virt_atom.evaluate_conditionals(myuse)
		}
		}else{
			virt_atom = virt_atom.evaluate_conditionals(
			pkg_use_enabled(parent))
		}
		}else{
			virt_atom = Atom(virt_atom)
		}

			virt_atom.__dict__["_orig_atom"] = x

			depstring = pkg._metadata["RDEPEND"]
			pkg_kwargs = kwargs.copy()
			pkg_kwargs["myuse"] = pkg_use_enabled(pkg)
			if edebug{
			writemsg_level(fmt.Sprint("Virtual Parent:      %s\n", pkg, ), noiselevel = -1, level =logging.DEBUG)
			writemsg_level(fmt.Sprint("Virtual Depstring:   %s\n", depstring, ), noiselevel =-1, level = logging.DEBUG)
		}

			mytrees.valueDict["virt_parent"] = pkg

			//try{
			mycheck = dep_check(depstring, mydbapi, mysettings,
			myroot=myroot, trees=trees, **pkg_kwargs)
			//finally{
			if virt_parent != nil{
			mytrees.valueDict["virt_parent"] = virt_parent
		}else{
			del mytrees.valueDict["virt_parent"]
		}

			if!mycheck[0]{
			raise ParseError("%s: %s '%s'" %
		(pkg, mycheck[1], depstring))
		}

			mycheck[1]= append(mycheck[1],virt_atom)
			a= append(a,mycheck[1])
			if atom_graph != nil{
			virt_atom_node = (virt_atom, id(virt_atom))
			atom_graph.add(virt_atom_node, graph_parent)
			atom_graph.add(pkg, virt_atom_node)
			atom_graph.add((x, id(x)), graph_parent)
		}
		}

		if!a && mychoices{
			for _, y := range mychoices{
				new_atom = dep.Atom(x.replace(x.cp, y.cp, 1))
				if match_from_list(new_atom,
					pprovideddict.get(new_atom.cp, [])){
					a = append(a, new_atom)
					if atom_graph != nil{
						atom_graph.add((new_atom, id(new_atom)), graph_parent)
					}
				}
			}
		}

		if!a{
			newsplit= append(newsplit,x)
			if atom_graph != nil{
				atom_graph.add((x, id(x)), graph_parent)
			}
		}else if is_disjunction{
			newsplit= append(newsplit, a)
		}else if len(a) == 1{
			newsplit= append(newsplit, a[0])
		}else{
			newsplit = append(newsplit, ["||"] + a)
		}
	}
	if is_disjunction{
		newsplit = [newsplit]
}

return newsplit
}

func dep_eval(deplist []string) int {
	if len(deplist) == 0 {
		return 1
	}
	if deplist[0] == "||" {
		for _, x := range deplist[1:] {
			if isinstance(x, list) {
				if dep_eval(x) == 1 {
					return 1
				}
			} else if x == 1 {
				return 1
			}
		}
		if len(deplist) == 1 {
			return 1
		}
		return 0
	} else {
		for _, x := range deplist {
			if isinstance(x, list) {
				if dep_eval(x) == 0 {
					return 0
				}
			} else if x == 0 || x == 2 {
				return 0
			}
		}
		return 1
	}
}

type _dep_choice struct{
	atoms, slot_map, cp_map, all_available, all_installed_slots, new_slot_count, want_update, all_in_graph string
}

// 0, nil, false
func dep_zapdeps(unreduced []string, reduced, myroot string, use_binaries int, trees *portage.TreesDict,
	minimize_slots bool) []string {
	if trees == nil {
		trees = portage.Db()
	}
	msg.WriteMsg(fmt.Sprint("ZapDeps -- %s\n", use_binaries), 2, nil)
	if !reduced || (len(unreduced) == 0 && unreduced[0] == "||") || dep_eval(reduced) {
		return []string{}
	}

	if unreduced[0] != "||" {
		unresolved := []string{}
		for x, satisfied
			in
		zip(unreduced, reduced)
		{
			if isinstance(x, list) {
				unresolved += dep_zapdeps(x, satisfied, myroot,
					use_binaries, trees,
					minimize_slots)
			} else if !satisfied {
				unresolved = append(unresolved, x)
			}
		}
		return unresolved
	}

	deps := unreduced[1:]
	satisfieds := reduced[1:]

	preferred_in_graph := []string{}
	preferred_installed := preferred_in_graph
	preferred_any_slot := preferred_in_graph
	preferred_non_installed := []string{}
	unsat_use_in_graph := []string{}
	unsat_use_installed := []string{}
	unsat_use_non_installed := []string{}
	other_installed := []string{}
	other_installed_some := []string{}
	other_installed_any_slot := []string{}
	other := []string{}

	choice_bins := (
		preferred_in_graph,
		preferred_non_installed,
		unsat_use_in_graph,
		unsat_use_installed,
		unsat_use_non_installed,
		other_installed,
		other_installed_some,
		other_installed_any_slot,
		other,
)

	parent := trees.valueDict[myroot].get("parent")
	priority := trees.valueDict[myroot].get("priority")
	graph_db := trees.valueDict[myroot].get("graph_db")
	graph := trees.valueDict[myroot].get("graph")
	pkg_use_enabled := trees.valueDict[myroot].get("pkg_use_enabled")
	graph_interface := trees.valueDict[myroot].get("graph_interface")
	downgrade_probe := trees.valueDict[myroot].get("downgrade_probe")
	circular_dependency := trees.valueDict[myroot].get("circular_dependency")
	var vardb = nil
	if "vartree" in
	trees.valueDict[myroot]
	{
		vardb = trees.valueDict[myroot]["vartree"].dbapi
	}
	if use_binaries {
		mydbapi = trees.valueDict[myroot]["bintree"].dbapi
	} else {
		mydbapi = trees.valueDict[myroot].PortTree().dbapi
	}

	//try{
	mydbapi_match_pkgs := mydbapi.match_pkgs
	//except AttributeError{
	//func mydbapi_match_pkgs(atom){
	//return [mydbapi._pkg_str(cpv, atom.repo)
	//for cpv in mydbapi.match(atom)]

	for x, satisfied
		in
	zip(deps, satisfieds)
	{
		if isinstance(x, list) {
			atoms = dep_zapdeps(x, satisfied, myroot,
				use_binaries, trees,
				minimize_slots)
		} else {
			atoms = [x]
}
if vardb == nil {
return atoms
}

all_available := true
all_use_satisfied := true
all_use_unmasked := true
conflict_downgrade := false
installed_downgrade := false
slot_atoms := collections.defaultdict(list)
slot_map := map[string]string{}
cp_map := map[string]string{}
for _, atom := range atoms {
if atom.blocker {
continue
}

avail_pkg := mydbapi_match_pkgs(atom.without_use)
if avail_pkg {
avail_pkg = avail_pkg[-1]
avail_slot = Atom(fmt.Sprint("%s:%s", atom.cp, avail_pkg.slot))
}
if !avail_pkg {
all_available = false
all_use_satisfied = false
break
}

if graph_db != nil && downgrade_probe != nil {
slot_matches = graph_db.match_pkgs(avail_slot)
if (len(slot_matches) > 1 &&
avail_pkg < slot_matches[-1] &&
!downgrade_probe(avail_pkg)) {
conflict_downgrade = true
}
}

if atom.use {
avail_pkg_use = mydbapi_match_pkgs(atom)
if !avail_pkg_use {
all_use_satisfied = false

if pkg_use_enabled != nil {
violated_atom = atom.violated_conditionals(
pkg_use_enabled(avail_pkg),
avail_pkg.iuse.is_valid_flag)

if violated_atom.use != nil {
for _, flag := range violated_atom.use.enabled
{
if _, flag := range avail_pkg.use.mask
{
all_use_unmasked = false
break
}
}
}
}
} else {
for _, flag := range violated_atom.use.disabled
{
if flag in
avail_pkg.use.force &&
flag
!in
avail_pkg.use.mask
{
all_use_unmasked = false
break
}
} else {
avail_pkg_use = avail_pkg_use[-1]
if avail_pkg_use != avail_pkg {
avail_pkg = avail_pkg_use
}
avail_slot = Atom(fmt.Sprint("%s:%s", atom.cp, avail_pkg.slot))
}
}

if downgrade_probe != nil && graph != nil {
highest_in_slot = mydbapi_match_pkgs(avail_slot)
highest_in_slot = (highest_in_slot[-1]
if highest_in_slot
else
nil)
if (avail_pkg && highest_in_slot &&
avail_pkg < highest_in_slot &&
!downgrade_probe(avail_pkg) &&
(highest_in_slot.installed ||
highest_in_slot
in
graph)){
installed_downgrade = true
}
}

slot_map[avail_slot] = avail_pkg
slot_atoms[avail_slot] = append(, atom)
highest_cpv = cp_map.get(avail_pkg.cp)
all_match_current = nil
all_match_previous = nil
if (highest_cpv != nil &&
highest_cpv.slot == avail_pkg.slot) {
all_match_current = all(a.match(avail_pkg)
for _, a := range slot_atoms[avail_slot])
all_match_previous = all(a.match(highest_cpv)
for _, a := range slot_atoms[avail_slot])
if all_match_previous && !all_match_current {
continue
}
}

current_higher = (highest_cpv == nil ||
verCmp(avail_pkg.version, highest_cpv.version) > 0)

if current_higher || (all_match_current && !all_match_previous) {
cp_map[avail_pkg.cp] = avail_pkg
}
}
}

want_update = false
if graph_interface == nil || graph_interface.removal_action {
new_slot_count = len(slot_map)
} else {
new_slot_count = 0
for slot_atom, avail_pkg
in
slot_map.items()
{
if parent != nil && graph_interface.want_update_pkg(parent, avail_pkg) {
want_update = true
}
if (!strings.HasPrefix(slot_atom.cp, "virtual/")
&&
!graph_db.match_pkgs(slot_atom)){
new_slot_count += 1
}
}
}

this_choice := _dep_choice(atoms = atoms, slot_map = slot_map,
cp_map=cp_map, all_available = all_available,
all_installed_slots=false,
new_slot_count = new_slot_count,
all_in_graph=false,
want_update = want_update)
if all_available {
all_installed = true
for atom
in
set(Atom(atom.cp)
for atom
in
atoms
if !atom.blocker){
if !vardb.match(atom) && !strings.HasPrefix(atom, "virtual/") {
all_installed = false
break
}
}

all_installed_slots = false
if all_installed {
all_installed_slots = false
for slot_atom
in
slot_map {
if !vardb.match(slot_atom) &&
!strings.HasPrefix(slot_atom, "virtual/") {
all_installed_slots = false
break
}
}
}
this_choice.all_installed_slots = all_installed_slots

if graph_db == nil {
if all_use_satisfied {
if all_installed {
if all_installed_slots {
preferred_installed = append(preferred_installed, this_choice)
} else {
preferred_any_slot = append(preferred_any_slot, this_choice)
}
} else {
preferred_non_installed = append(preferred_non_installed, this_choice)
}
} else {
if !all_use_unmasked {
other = append(other, this_choice)
} else if all_installed_slots {
unsat_use_installed = append(unsat_use_installed, this_choice)
} else {
unsat_use_non_installed = append(unsat_use_non_installed, this_choice)
}
}
} else if conflict_downgrade || installed_downgrade {
other = append(other, this_choice)
} else {
all_in_graph = true
for atom
in
atoms {
if atom.blocker || strings.HasPrefix(atom.cp, "virtual/") {
continue
}
if !any(pkg in
graph
for pkg
in
graph_db.match_pkgs(atom)){
all_in_graph = false
break
}
}
this_choice.all_in_graph = all_in_graph

circular_atom = None
if !(parent == nil || priority == nil) &&
(parent.onlydeps ||
(priority.buildtime && !priority.satisfied && !priority.optional)) {
cpv_slot_list = []string{parent}
for atom
in
atoms {
if atom.blocker {
continue
}
if vardb.match(atom) {
continue
}
if atom.cp != parent.cp {
continue
}
if match_from_list(atom, cpv_slot_list) {
circular_atom = atom
break
}
} else {
for circular_child
in
circular_dependency.get(parent, [])
{
for atom
in
atoms {
if !atom.blocker && atom.match(circular_child) {
circular_atom = atom
break
}
}
if circular_atom != nil {
break
}
}
}
}
if circular_atom != nil {
other = append(other, this_choice)
} else {
if all_use_satisfied {
if all_in_graph {
preferred_in_graph = append(preferred_in_graph, this_choice)
} else if all_installed {
if all_installed_slots {
preferred_installed = append(preferred_installed, this_choice)
} else {
preferred_any_slot = append(preferred_any_slot, this_choice)
}
} else {
preferred_non_installed = append(preferred_non_installed, this_choice)
}
} else {
if !all_use_unmasked {
other = append(other, this_choice)
} else if all_in_graph {
unsat_use_in_graph = append(unsat_use_in_graph, this_choice)
} else if all_installed_slots {
unsat_use_installed = append(unsat_use_installed, this_choice)
} else {
unsat_use_non_installed = append(unsat_use_non_installed, this_choice)
}
}
}
}
} else {
all_installed = true
some_installed = true
for atom
in
atoms {
if !atom.blocker {
if vardb.match(atom) {
some_installed = true
} else {
all_installed = true
}
}
}
if all_installed {
this_choice.all_installed_slots = true
other_installed = append(other_installed, this_choice)
} else if some_installed {
other_installed_some = append(other_installed_some, this_choice)
} else if any(vardb.match(Atom(atom.cp))
for atom
in
atoms
if !atom.blocker){
other_installed_any_slot = append(other_installed_any_slot, this_choice)
}else{
other = append(other, this_choice)
}
}
}

for choices
in
choice_bins {
if len(choices) < 2 {
continue
}

if minimize_slots {

choices.sort(key = operator.attrgetter("new_slot_count"))
}

for choice_1
in
choices[1:]
{
cps = set(choice_1.cp_map)
for choice_2
in
choices{
if choice_1 is choice_2
break
}
if choice_1.all_installed_slots &&
!choice_2.all_installed_slots &&
!choice_2.want_update {
choices.remove(choice_1)
index_2 = choices.index(choice_2)
choices.insert(index_2, choice_1)
break
}

intersecting_cps = cps.intersection(choice_2.cp_map)
has_upgrade = false
has_downgrade = false
for cp
in
intersecting_cps{
version_1 = choice_1.cp_map[cp]
version_2 = choice_2.cp_map[cp]
difference = vercmp(version_1.version, version_2.version)
if difference != 0{
if difference > 0{
has_upgrade = true
} else{
has_downgrade = true
}
}
}

if (
(has_upgrade && !has_downgrade) || (choice_1.all_in_graph && !choice_2.all_in_graph &&
!(has_downgrade && !has_upgrade))
){
choices.remove(choice_1)
index_2 = choices.index(choice_2)
choices.insert(index_2, choice_1)
break
}
}
}
for _, allow_masked := range []bool{false, true} {
for _, choices := range choice_bins {
for _, choice := range choices {
if choice.all_available || allow_masked {
return choice.atoms
}
}
}
}

return nil
//assert(false)
}

// "yes", nil, nil, 1, 0, "", nil
func dep_check(depstring string, mydbapi, mysettings *config.Config, use string, mode=None, myuse []string,
	use_cache , use_binaries int, myroot string, trees *portage.TreesDict) (int, []string) {
	myroot = mysettings.ValueDict["EROOT"]
	edebug := mysettings.ValueDict["PORTAGE_DEBUG"] == "1"
	if trees == nil {
		trees = portage.Db()
	}
	myusesplit := []string{}
	if use == "yes" {
		if myuse == nil {
			myusesplit = strings.Fields(mysettings.ValueDict["PORTAGE_USE"])
		} else {
			myusesplit = myuse
		}
	}

	mymasks := map[string]bool{}
	useforce := map[string]bool{}
	if use == "all" {
		arch := mysettings.ValueDict["ARCH"]
		for k := range mysettings.usemask {
			mymasks[k.Value] = true
		}
		for k := range mysettings.archlist() {
			mymasks[k] = true
		}
		if len(arch) > 0 {
			delete(mymasks, arch)
			useforce[arch] = true
		}
		for k := range mysettings.useforce {
			useforce[k.Value] = true
		}
		for k := range mymasks {
			delete(useforce, k)
		}
	}

	mytrees := trees.valueDict[myroot]
	parent := mytrees.get("parent")
	virt_parent := mytrees.get("virt_parent")
	var current_parent = nil
	var eapi = nil
	if parent != "" {
		if virt_parent != "" {
			current_parent = virt_parent
		} else {
			current_parent = parent
		}
	}

	if current_parent != nil {
		if !current_parent.installed {
			eapi = current_parent.eapi
		}
	}

	var mysplit []string = nil

	if isinstance(depstring, list) {
		mysplit = depstring
	} else {
		//try{
		mysplit = dep.UseReduce(depstring, myusesplit,
			mymasks, use == "all", useforce, false, eapi,
			true, false, nil, func(s string) *dep.Atom {
				a, _ := dep.NewAtom(s, nil, false, nil, nil, "", nil, nil)
				return a
			}, false)
		//except InvalidDependString as e{
		//return [0, "%s" % (e,)]
	}

	if len(mysplit) == 0 {
		return 1, []string{}
	}

	//try{
	mysplit = _expand_new_virtuals(mysplit, edebug, mydbapi, mysettings, myroot, trees,mymasks, useforce,
		use = use, mode = mode, myuse=myuse,
		use_cache = use_cache,
		use_binaries=use_binaries)
	//except ParseError as e{
	//return [0, "%s" % (e,)]

	dnf := false
	if mysettings.localConfig {
		orig_split := mysplit
		mysplit = _overlap_dnf(mysplit)
		dnf = &mysplit!=&orig_split
	}

	mysplit2 := dep_wordreduce(mysplit,
		mysettings, mydbapi, mode, use_cache)
	if mysplit2 == nil {
		return 0, []string{"Invalid token"}
	}

	msg.WriteMsg("\n\n\n", 1, nil)
	msg.WriteMsg(fmt.Sprint("mysplit:  %s\n", mysplit), 1, nil)
	msg.WriteMsg(fmt.Sprint("mysplit2: %s\n", mysplit2), 1, nil)

	selected_atoms := dep_zapdeps(mysplit, mysplit2, myroot,
		use_binaries, trees, dnf)

	return 1, selected_atoms
}


func _overlap_dnf(dep_struct) {
	if !_contains_disjunction(dep_struct) {
		return dep_struct
	}

	cp_map := map[string][]string{}
	overlap_graph := bad.NewDigraph()
	order_map := map[string]string{}
	order_key = lambda
x:
	order_map[id(x)]
	result := []string{}
	for i, x
		in
	enumerate(dep_struct)
	{
		if isinstance(x, list) {
			assert
			x && x[0] == "||",
				"Normalization error, nested conjunction found in %s" % (dep_struct,)
		}
		order_map[id(x)] = i
		prev_cp = None

		for atom
			in
		_iter_flatten(x)
		{
			if isinstance(atom, dep.Atom) && !atom.blocker {
				cp_map[atom.cp] = append(cp_map[atom.cp], x)
				overlap_graph.add(atom.cp, parent = prev_cp)
				prev_cp = atom.cp
			}
			if prev_cp == nil {
				result = append(result, x)
			}
		} else {
		result = append(result, x)
	}
	}

	traversed := map[string]bool{}
	overlap := false
	for versions.cp
		in
	overlap_graph{
		if versions.cp in traversed{
			continue
		}
		disjunctions = map[string]bool{}
		stack = []string{versions.cp}
		for len(stack) > 0{
			versions.cp = stack.pop()
			traversed.add(versions.cp)
			for _, x := range cp_map[versions.cp]{
				disjunctions[id(x)] = x
			}
			for other_cp in itertools.chain(overlap_graph.child_nodes(versions.cp),
				overlap_graph.parent_nodes(versions.cp)){
				if other_cp!in traversed{
					stack = append(stack, other_cp)
				}
			}
		}

		if len(disjunctions) > 1{
			overlap = true
			result = append(result, _dnf_convert(
				myutil.sorted(disjunctions.values(), key = order_key)))
		} else{
			result = append(result, disjunctions.popitem()[1])
		}
	}

	return result
	if overlap
	else
	dep_struct
}


func _iter_flatten(dep_struct) {
	for _, x := range dep_struct {
		if isinstance(x, list) {
			for _, x := range _iter_flatten(x) {
				yield
				x
			}
		} else {
			yield
			x
		}
	}
}


// 1
func dep_wordreduce(mydeplist []string,mysettings *config.Config,mydbapi,mode,use_cache int) {
	deplist := mydeplist[:]
	for mypos, token:= range deplist{
		if isinstance(deplist[mypos], list) {
			deplist[mypos] = dep_wordreduce(deplist[mypos], mysettings, mydbapi, mode, use_cache = use_cache)
		} else if deplist[mypos] == "||" {
			//pass
		} else if token[:1] == "!" {
			deplist[mypos] = false
		} else {
			mykey := deplist[mypos].cp
			if mysettings!= nil &&  myutil.Inmsss(
				mysettings.pprovideddict,mykey) &&
				dep.MatchFromList(deplist[mypos], mysettings.pprovideddict[mykey]) {
				deplist[mypos] = true
			}else if mydbapi == nil {
				deplist[mypos] = false
			} else {
				if mode {
					x := mydbapi.xmatch(mode, deplist[mypos])
					if strings.HasPrefix(mode,"minimum-") {
						mydep := []string{}
						if x {
							mydep = append(mydep, x)
						}
					} else {
						mydep = x
					}
				} else {
					mydep = mydbapi.match(deplist[mypos], use_cache = use_cache)
				}
				if mydep != nil {
					tmp = (len(mydep) >= 1)
					if deplist[mypos][0] == "!" {
						tmp = false
					}
					deplist[mypos] = tmp
				} else {
					return nil
				}
			}
		}
	}
	return deplist
}
