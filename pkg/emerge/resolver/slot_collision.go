package resolver

import (
	"fmt"
	"github.com/ppphp/portago/pkg/util/msg"
	"strings"
)

type slot_conflict_handler struct {
	_check_configuration_max int

	conflict_msg []string
	conflict_is_unspecific,is_a_version_conflict bool
}

func Newslot_conflict_handler(depgraph) *slot_conflict_handler {
	s := &slot_conflict_handler{}
	s._check_configuration_max= 1024

	s.depgraph = depgraph
	s.myopts = depgraph._frozen_config.myopts
	s.debug = "--debug"
	in
	s.myopts
	if s.debug {
		writemsg("Starting slot conflict handler\n", noiselevel = -1)
	}

	s.all_conflicts = []T
	for conflict
	in
	depgraph._dynamic_config._package_tracker.slot_conflicts()
	{
		s.all_conflicts.append((conflict.root, conflict.atom, conflict.pkgs))
	}

	s.all_parents = depgraph._dynamic_config._parent_atoms

	conflict_nodes = set()

	conflict_pkgs = []T

	all_conflict_atoms_by_slotatom = []T

	for root, atom, pkgs
	in
	self.all_conflicts{
		conflict_pkgs.append(list(pkgs))
		all_conflict_atoms_by_slotatom.append(set())

		for pkg in pkgs{
		conflict_nodes.add(pkg)
		for ppkg, atom in s.all_parents.get(pkg){
		all_conflict_atoms_by_slotatom[-1].add((ppkg, atom))
	}
	}
	}

	s.conflict_msg = []string{}
	s.conflict_is_unspecific = false

	s.is_a_version_conflict = false

	s._prepare_conflict_msg_and_check_for_specificity()

	s.solutions = []T

	s.changes = []T

	config_gen = _configuration_generator(conflict_pkgs)
	first_config = true

	for {
		config = config_gen.get_configuration()
		if not config {
			break
		}

		if s.debug {
			writemsg("\nNew configuration:\n", noiselevel = -1)
			for pkg
				in
			config {
				writemsg(f
				"   {pkg}\n", noiselevel = -1)
			}
			writemsg("\n", noiselevel = -1)
		}

		new_solutions = s._check_configuration(
			config, all_conflict_atoms_by_slotatom, conflict_nodes
		)

		if new_solutions {
			s.solutions.extend(new_solutions)

			if first_config {
				if s.debug {
					msg.WriteMsg("All-ebuild configuration has a solution. Aborting search.\n", -1,nil)
				}
				break
			}
		}
		first_config = false

		if len(conflict_pkgs) > 4 {
			if s.debug {
				msg.WriteMsg("\nAborting search due to excessive number of configurations.\n", -1, nil)
			}
			break
		}
	}

	for solution
	in
	s.solutions{
		s._add_change(s._get_change(solution))
	}
}

func (s *slot_conflict_handler) get_conflict() string {
	return strings.Join(s.conflict_msg, "")
}

func (s *slot_conflict_handler) _is_subset(change1, change2):
for pkg in change1:
if pkg not in change2:
return False

for flag in change1[pkg]:
if flag not in change2[pkg]:
return False
if change1[pkg][flag] != change2[pkg][flag]:
return False
return True

func (s *slot_conflict_handler) _add_change(new_change):
changes = self.changes
ignore = False
to_be_removed = []
for change in changes:
if self._is_subset(change, new_change):
ignore = True
break
elif self._is_subset(new_change, change):
to_be_removed.append(change)

if not ignore:
for obsolete_change in to_be_removed:
changes.remove(obsolete_change)
changes.append(new_change)

func (s *slot_conflict_handler) _get_change(solution):
_pkg_use_enabled = self.depgraph._pkg_use_enabled
new_change = {}
for pkg in solution:
for flag, state in solution[pkg].items():
flag = pkg.iuse.get_flag(flag)
if flag is None:
continue
if state == "enabled" and flag not in _pkg_use_enabled(pkg):
new_change.setdefault(pkg, {})[flag] = True
elif state == "disabled" and flag in _pkg_use_enabled(pkg):
new_change.setdefault(pkg, {})[flag] = False
return new_change

func (s *slot_conflict_handler) _prepare_conflict_msg_and_check_for_specificity() {
	_pkg_use_enabled = s.depgraph._pkg_use_enabled
	usepkgonly = "--usepkgonly"
	in
	s.myopts
	need_rebuild =
	{
	}
	verboseconflicts = "--verbose-conflicts"
	in
	s.myopts
	any_omitted_parents = False
	msg = s.conflict_msg
	indent = "  "
	msg.append(
		"\n!!! Multiple package instances within a single "
	+"package slot have been pulled\n"
	)
	msg.append(
		"!!! into the dependency graph, resulting" + " in a slot conflict:\n\n"
	)

	for root, slot_atom, pkgs
	in
	s.all_conflicts:
	msg.append(f
	"{slot_atom}")
	if root != s.depgraph._frozen_config._running_root.root:
	msg.append(f
	" for {root}")
	msg.append("\n\n")

	for pkg
	in
pkgs:
	msg.append(indent)
	msg.append(
		"%s %s"
	% (
		pkg,
		pkg_use_display(
			pkg,
			s.depgraph._frozen_config.myopts,
			modified_use = s.depgraph._pkg_use_enabled(pkg),
),
)
)
	parent_atoms = s.all_parents.get(pkg)
	if parent_atoms:
	collision_reasons =
	{
	}
	num_all_specific_atoms = 0

	for ppkg, atom
	in
parent_atoms:
	if not atom.soname:
	atom_set = InternalPackageSet(initial_atoms = (atom,))
	atom_without_use_set = InternalPackageSet(
		initial_atoms = (atom.without_use,)
)
	atom_without_use_and_slot_set = InternalPackageSet(
		initial_atoms = (atom.without_use.without_slot,)
)

	for other_pkg
	in
pkgs:
	if other_pkg == pkg:
	continue

	if atom.soname:
	# The
	soname
	does
	not
	match.
		key = ("soname", atom)
	atoms = collision_reasons.get(key, set())
	atoms.add((ppkg, atom, other_pkg))
	num_all_specific_atoms += 1
	collision_reasons[key] = atoms
	elif
	not
	atom_without_use_and_slot_set.findAtomForPackage(
		other_pkg, modified_use = _pkg_use_enabled(other_pkg)
	):
	if atom.operator is
	not
None:
	sub_type = None
	if atom.operator in(">=", ">"):
	sub_type = "ge"
	elif
	atom.operator
	in("=", "~"):
	sub_type = "eq"
	elif
	atom.operator
	in("<=", "<"):
	sub_type = "le"

	key = ("version", sub_type)
	atoms = collision_reasons.get(key, set())
	atoms.add((ppkg, atom, other_pkg))
	num_all_specific_atoms += 1
	collision_reasons[key] = atoms

	elif
	not
	atom_without_use_set.findAtomForPackage(
		other_pkg, modified_use = _pkg_use_enabled(other_pkg)
	):
	key = (
		"slot",
		(atom.slot, atom.sub_slot, atom.slot_operator),
)
	atoms = collision_reasons.get(key, set())
	atoms.add((ppkg, atom, other_pkg))
	num_all_specific_atoms += 1
	collision_reasons[key] = atoms

	elif
	not
	atom_set.findAtomForPackage(
		other_pkg, modified_use = _pkg_use_enabled(other_pkg)
	):
	missing_iuse = other_pkg.iuse.get_missing_iuse(
		atom.unevaluated_atom.use.required
	)
	if missing_iuse:
	for flag
	in
missing_iuse:
	atoms = collision_reasons.get(
		("use", flag), set()
	)
	atoms.add((ppkg, atom, other_pkg))
	collision_reasons[("use",
	flag)] = atoms
num_all_specific_atoms += 1 else:
violated_atom = atom.violated_conditionals(
_pkg_use_enabled(other_pkg),
other_pkg.iuse.is_valid_flag,
)
if violated_atom.use is None:
msg = (
"\n\n!!! BUG: Detected "
"USE dep match inconsistency:\n"
"\tppkg: %s\n"
"\tviolated_atom: %s\n"
"\tatom: %s unevaluated: %s\n"
"\tother_pkg: %s IUSE: %s USE: %s\n"
% (
ppkg,
violated_atom,
atom,
atom.unevaluated_atom,
other_pkg,
sorted(other_pkg.iuse.all),
sorted(_pkg_use_enabled(other_pkg)),
)
)
writemsg(msg, noiselevel= -2)
raise AssertionError(
"BUG: USE dep match inconsistency"
)
for flag in violated_atom.use.enabled.union(
violated_atom.use.disabled
):
atoms = collision_reasons.get(
("use", flag), set()
)
atoms.add((ppkg, atom, other_pkg))
collision_reasons[("use", flag)] = atoms
num_all_specific_atoms += 1
elif isinstance(ppkg, AtomArg) and other_pkg.installed:
parent_atoms = collision_reasons.get(
("AtomArg", None), set()
)
parent_atoms.add((ppkg, atom))
collision_reasons[("AtomArg", None)] = parent_atoms
num_all_specific_atoms += 1

msg.append(" pulled in by\n")

selected_for_display = set()
unconditional_use_deps = set()

for (ctype, sub_type), parents in collision_reasons.items():

if ctype == "version":
best_matches = {}
for ppkg, atom, other_pkg in parents:
if atom.cp in best_matches:
cmp = vercmp(
cpv_getversion(atom.cpv),
cpv_getversion(best_matches[atom.cp][1].cpv),
)

if (
(sub_type == "ge" and cmp > 0)
or (sub_type == "le" and cmp < 0)
or (sub_type == "eq" and cmp > 0)
):
best_matches[atom.cp] = (ppkg, atom) else:
best_matches[atom.cp] = (ppkg, atom)
if verboseconflicts:
selected_for_display.add((ppkg, atom))
if not verboseconflicts:
selected_for_display.update(best_matches.values())
elif ctype in ("soname", "slot"):
for ppkg, atom, other_pkg in parents:
if not (isinstance(ppkg, Package) and ppkg.installed):
continue
if not (atom.soname or atom.slot_operator_built):
continue
if s.depgraph._frozen_config.excluded_pkgs.findAtomForPackage(
ppkg,
modified_use = s.depgraph._pkg_use_enabled(ppkg),
):
selected_for_display.add((ppkg, atom))
need_rebuild[ppkg] = "matched by --exclude argument"
elif s.depgraph._frozen_config.useoldpkg_atoms.findAtomForPackage(
ppkg,
modified_use = s.depgraph._pkg_use_enabled(ppkg),
):
selected_for_display.add((ppkg, atom))
need_rebuild[
ppkg
] = "matched by --useoldpkg-atoms argument"
elif usepkgonly:
pass
elif not s.depgraph._equiv_ebuild_visible(ppkg):
selected_for_display.add((ppkg, atom))
need_rebuild[
ppkg
] = "ebuild is masked or unavailable"

for ppkg, atom, other_pkg in parents:
selected_for_display.add((ppkg, atom))
if not verboseconflicts:
break
elif ctype == "use":
use = sub_type
for ppkg, atom, other_pkg in parents:
missing_iuse = other_pkg.iuse.get_missing_iuse(
atom.unevaluated_atom.use.required
)
if missing_iuse:
unconditional_use_deps.add((ppkg, atom)) else:
parent_use = None
if isinstance(ppkg, Package):
parent_use = _pkg_use_enabled(ppkg)
violated_atom = (
atom.unevaluated_atom.violated_conditionals(
_pkg_use_enabled(other_pkg),
other_pkg.iuse.is_valid_flag,
parent_use =parent_use,
)
)
if violated_atom.use is None:
continue
if (
use in violated_atom.use.enabled
or use in violated_atom.use.disabled
):
unconditional_use_deps.add((ppkg, atom))
selected_for_display.add((ppkg, atom))
elif ctype == "AtomArg":
for ppkg, atom in parents:
selected_for_display.add((ppkg, atom))

def highlight_violations(atom, version, use, slot_violated):
atom_str = f"{atom}"
colored_idx = set()
if version:
op = atom.operator
ver = None
if atom.cp != atom.cpv:
ver = cpv_getversion(atom.cpv)
slot = atom.slot
sub_slot = atom.sub_slot
slot_operator = atom.slot_operator

if op == "=*":
op = "="
ver += "*"

slot_str = ""
if slot:
slot_str = ":" + slot
if sub_slot:
slot_str += "/" + sub_slot
if slot_operator:
slot_str += slot_operator

if op is not None:
colored_idx.update(range (len(op)))

if ver is not None:
start = atom_str.rfind(ver)
end = start + len(ver)
colored_idx.update(range (start, end))

if slot_str:
ii = atom_str.find(slot_str)
colored_idx.update(range (ii, ii + len(slot_str)))

if op is not None:
atom_str = atom_str.replace(op, colorize("BAD", op), 1)

if ver is not None:
start = atom_str.rfind(ver)
end = start + len(ver)
atom_str = (
atom_str[:start]
+ colorize("BAD", ver)
+ atom_str[end:]
)

if slot_str:
atom_str = atom_str.replace(
slot_str, colorize("BAD", slot_str), 1
)

elif slot_violated:
slot = atom.slot
sub_slot = atom.sub_slot
slot_operator = atom.slot_operator

slot_str = ""
if slot:
slot_str = ":" + slot
if sub_slot:
slot_str += "/" + sub_slot
if slot_operator:
slot_str += slot_operator

if slot_str:
ii = atom_str.find(slot_str)
colored_idx.update(range (ii, ii + len(slot_str)))
atom_str = atom_str.replace(
slot_str, colorize("BAD", slot_str), 1
)

if use and atom.use.tokens:
use_part_start = atom_str.find("[")
use_part_end = atom_str.find("]")

new_tokens = []
ii = str(atom).find("[") + 1
for token in atom.use.tokens:
if token.lstrip("-!").rstrip("=?") in use:
new_tokens.append(colorize("BAD", token))
colored_idx.update(range(ii, ii + len(token))) else:
new_tokens.append(token)
ii += 1 + len(token)

atom_str = (
atom_str[:use_part_start]
+ f"[{','.join(new_tokens)}]"
+ atom_str[use_part_end + 1:]
)

return atom_str, colored_idx

ordered_list = list(unconditional_use_deps)
if len(selected_for_display) > len(unconditional_use_deps):
for parent_atom in selected_for_display:
if parent_atom not in unconditional_use_deps:
ordered_list.append(parent_atom)
for parent_atom in ordered_list:
parent, atom = parent_atom
if isinstance(parent, Package):
use_display = pkg_use_display(
parent,
s.depgraph._frozen_config.myopts,
modified_use =s.depgraph._pkg_use_enabled(parent),
)
else:
use_display = ""
if atom.soname:
msg.append(f"{atom} required by {parent} {use_display}\n")
elif isinstance(parent, PackageArg):
msg.append(f"{parent}\n")
elif isinstance(parent, AtomArg):
msg.append(2 * indent)
msg.append(f"{atom} (Argument)\n")
else:
version_violated = False
slot_violated = False
use = []
for (ctype, sub_type), parents in collision_reasons.items():
for x in parents:
if parent == x[0] and atom == x[1]:
if ctype == "version":
version_violated = True
elif ctype == "slot":
slot_violated = True
elif ctype == "use":
use.append(sub_type)
break

atom_str, colored_idx = highlight_violations(
atom.unevaluated_atom,
version_violated,
use,
slot_violated,
)

if version_violated or slot_violated:
s.is_a_version_conflict = True

cur_line = "{} required by {} {}\n".format(
atom_str,
parent,
use_display,
)
marker_line = ""
for ii in range (len(cur_line)):
if ii in colored_idx:
marker_line += "^"
else:
marker_line += " "
marker_line += "\n"
msg.append(2 * indent)
msg.append(cur_line)
msg.append(2 * indent)
msg.append(marker_line)

if not selected_for_display:
msg.append(2 * indent)
msg.append(
"(no parents that aren't satisfied by other packages in this slot)\n"
)
s.conflict_is_unspecific = True

omitted_parents = num_all_specific_atoms - len(selected_for_display)
if omitted_parents:
any_omitted_parents = True
msg.append(2 * indent)
if len(selected_for_display) > 1:
msg.append(
"(and %d more with the same problems)\n"
% omitted_parents
) else:
msg.append(
"(and %d more with the same problem)\n"
% omitted_parents
) else:
msg.append(" (no parents)\n")
msg.append("\n")

if any_omitted_parents:
msg.append(
colorize(
"INFORM",
"NOTE: Use the '--verbose-conflicts'"
" option to display parents omitted above",
)
)
msg.append("\n")

if need_rebuild:
msg.append(
"\n!!! The slot conflict(s) shown above involve package(s) which may need to\n"
)
msg.append(
"!!! be rebuilt in order to solve the conflict(s). However, the following\n"
)
msg.append("!!! package(s) cannot be rebuilt for the reason(s) shown:\n\n")
for ppkg, reason in need_rebuild.items():
msg.append(f"{indent}{ppkg}: {reason}\n")
msg.append("\n")

msg.append("\n")
}

func (s *slot_conflict_handler) get_explanation() {
	msg = ""

	if s.is_a_version_conflict:
	return None

	if s.conflict_is_unspecific and
	not(
		"--newuse"
	in
	s.myopts
	and
	"--update"
	in
	s.myopts
	):
	msg += "!!! Enabling --newuse and --update might solve this conflict.\n"
	msg += "!!! If not, it might help emerge to give a more specific suggestion.\n\n"
	return msg

	solutions = s.solutions
	if not solutions:
	return None

	if len(solutions) == 1:
	if len(s.all_conflicts) == 1:
	msg += "It might be possible to solve this slot collision\n"
	else:
	msg += "It might be possible to solve these slot collisions\n"
	msg += "by applying all of the following changes:\n"
	else:
	if len(s.all_conflicts) == 1:
	msg += "It might be possible to solve this slot collision\n"
	else:
	msg += "It might be possible to solve these slot collisions\n"
	msg += "by applying one of the following solutions:\n"
}

// ""
func (s *slot_conflict_handler) print_change(indent string) {
	mymsg = ""
	for pkg
	in
change:
	changes = []T
for flag, state in change[pkg].items():
if state:
changes.append(colorize("red", "+" + flag)) else:
changes.append(colorize("blue", "-" + flag))
mymsg += (
indent
+ "- "
+ pkg.cpv
+ f" (Change USE: {' '.join(changes)}"
+ ")\n"
)
mymsg += "\n"
return mymsg

if len(s.changes) == 1:
msg += print_change(s.changes[0], "   ") else:
for change in s.changes:
msg += "  Solution: Apply all of:\n"
msg += print_change(change, "     ")

return msg
}

func (s *slot_conflict_handler) _check_configuration(config, all_conflict_atoms_by_slotatom, conflict_nodes) {
	_pkg_use_enabled = s.depgraph._pkg_use_enabled
	for pkg
	in
config:
	if not pkg.installed:
	continue

	for root, atom, pkgs
	in
	s.all_conflicts:
	if pkg not
	in
pkgs:
	continue
	for other_pkg
	in
pkgs:
	if other_pkg == pkg:
	continue
	if pkg.iuse.all.symmetric_difference(
		other_pkg.iuse.all
	) or
	_pkg_use_enabled(pkg).symmetric_difference(
		_pkg_use_enabled(other_pkg)
	):
	if s.debug:
	writemsg(
		(
			"%s has pending USE changes. "
	"Rejecting configuration.\n"
	)
	% (pkg,),
	noiselevel = -1,
)
	return False

	all_involved_flags = []T

for idx, pkg in enumerate(config):
involved_flags = {}
for ppkg, atom in all_conflict_atoms_by_slotatom[idx]:
if not atom.package:
continue

if ppkg in conflict_nodes and not ppkg in config:
continue

i = InternalPackageSet(initial_atoms = (atom,))
if i.findAtomForPackage(pkg, modified_use = _pkg_use_enabled(pkg)):
continue

i = InternalPackageSet(initial_atoms = (atom.without_use, ))
if not i.findAtomForPackage(pkg, modified_use = _pkg_use_enabled(pkg)):
if s.debug:
writemsg(
(
"%s does not satify all version "
"requirements. Rejecting configuration.\n"
)
% (pkg, ),
noiselevel = -1,
)
return False

if not pkg.iuse.is_valid_flag(atom.unevaluated_atom.use.required):
if s.debug:
writemsg(
(
"%s misses needed flags from IUSE."
" Rejecting configuration.\n"
)
% (pkg, ),
noiselevel = -1,
)
return False

if not isinstance(ppkg, Package) or ppkg.installed:
violated_atom = atom.violated_conditionals(
_pkg_use_enabled(pkg), pkg.iuse.is_valid_flag
) else:
violated_atom = atom.unevaluated_atom.violated_conditionals(
_pkg_use_enabled(pkg),
pkg.iuse.is_valid_flag,
parent_use = _pkg_use_enabled(ppkg),
)
if violated_atom.use is None:
continue

if pkg.installed and (
violated_atom.use.enabled or violated_atom.use.disabled
):
if s.debug:
writemsg(
(
"%s: installed package would need USE"
" changes. Rejecting configuration.\n"
)
% (pkg, ),
noiselevel =-1,
)
return False

for flag in violated_atom.use.required:
state = involved_flags.get(flag, "")

if flag in violated_atom.use.enabled:
if state in ("", "cond", "enabled"):
state = "enabled" else:
state = "contradiction"
elif flag in violated_atom.use.disabled:
if state in ("", "cond", "disabled"):
state = "disabled" else:
state = "contradiction" else:
if state == "":
state = "cond"

involved_flags[flag] = state

if pkg.installed:
for flag in involved_flags:
if involved_flags[flag] == "enabled":
if not flag in _pkg_use_enabled(pkg):
involved_flags[flag] = "contradiction"
elif involved_flags[flag] == "disabled":
if flag in _pkg_use_enabled(pkg):
involved_flags[flag] = "contradiction"
elif involved_flags[flag] == "cond":
if flag in _pkg_use_enabled(pkg):
involved_flags[flag] = "enabled" else:
involved_flags[flag] = "disabled"

for flag, state in involved_flags.items():
if state == "contradiction":
if s.debug:
writemsg(
"Contradicting requirements found for flag "
+ flag
+ ". Rejecting configuration.\n",
noiselevel = -1,
)
return False

all_involved_flags.append(involved_flags)

if s.debug:
writemsg("All involved flags:\n", noiselevel = -1)
for idx, involved_flags in enumerate(all_involved_flags):
writemsg(f"   {config[idx]}\n", noiselevel = -1)
for flag, state in involved_flags.items():
writemsg("     " + flag + ": " + state + "\n", noiselevel = -1)

solutions = []T
sol_gen = _solution_candidate_generator(all_involved_flags)
checked = 0
while True:
candidate = sol_gen.get_candidate()
if not candidate:
break
solution = s._check_solution(
config, candidate, all_conflict_atoms_by_slotatom
)
checked += 1
if solution:
solutions.append(solution)

if checked >= s._check_configuration_max:
if s.debug:
writemsg(
"\nAborting _check_configuration due to "
"excessive number of candidates.\n",
noiselevel = -1,
)
break

if s.debug:
if not solutions:
writemsg(
"No viable solutions. Rejecting configuration.\n", noiselevel= -1
)
return solutions
}

func (s *slot_conflict_handler) _force_flag_for_package(required_changes, pkg, flag, state) {
	_pkg_use_enabled = s.depgraph._pkg_use_enabled

	if state == "disabled":
	changes = required_changes.get(pkg,
	{
	})
	flag_change = changes.get(flag, "")
	if flag_change == "enabled":
	flag_change = "contradiction"
	elif
	flag
	in
	_pkg_use_enabled(pkg):
	flag_change = "disabled"

	changes[flag] = flag_change
	required_changes[pkg] = changes
	elif
	state == "enabled":
	changes = required_changes.get(pkg,
	{
	})
	flag_change = changes.get(flag, "")
	if flag_change == "disabled":
	flag_change = "contradiction"
	else:
	flag_change = "enabled"

	changes[flag] = flag_change
	required_changes[pkg] = changes
}

func (s *slot_conflict_handler) _check_solution(config, all_involved_flags, all_conflict_atoms_by_slotatom) {
	_pkg_use_enabled = s.depgraph._pkg_use_enabled

	if s.debug:
	msg = "Solution candidate: "
	msg += "["
	first = True
	for involved_flags
	in
all_involved_flags:
	if first:
	first = False
	else:
	msg += ", "
	msg += "{"
	inner_first = True
	for flag, state
	in
	involved_flags.items():
	if inner_first:
	inner_first = False
	else:
	msg += ", "
	msg += flag + f
	": {state}"
	msg += "}"
	msg += "]\n"
	writemsg(msg, noiselevel = -1)

	required_changes =
	{
	}
	for idx, pkg
	in
	enumerate(config):
	if not pkg.installed:
	for flag
	in
	all_involved_flags[idx]:
	if not pkg.iuse.is_valid_flag(flag):
	continue
	state = all_involved_flags[idx][flag]
	s._force_flag_for_package(required_changes, pkg, flag, state)

	for ppkg, atom
	in
	all_conflict_atoms_by_slotatom[idx]:
	if not atom.package:
	continue
	use = atom.unevaluated_atom.use
	if not use:
	continue
	for flag
	in
	all_involved_flags[idx]:
	state = all_involved_flags[idx][flag]

	if flag not
	in
	use.required
	or
	not
	use.conditional:
	continue
	if flag in
	use.conditional.enabled:
	if state == "enabled":
	pass
	elif
	state == "disabled":
	s._force_flag_for_package(
		required_changes, ppkg, flag, "disabled"
	)
	elif
	flag
	in
	use.conditional.disabled:
	if state == "enabled":
	s._force_flag_for_package(
		required_changes, ppkg, flag, "disabled"
	)
	elif
	state == "disabled":
	pass
	elif
	flag
	in
	use.conditional.equal:
	if state == "enabled":
	s._force_flag_for_package(
		required_changes, ppkg, flag, "enabled"
	)
	elif
	state == "disabled":
	s._force_flag_for_package(
		required_changes, ppkg, flag, "disabled"
	)
	elif
	flag
	in
	use.conditional.not_equal:
	if state == "enabled":
	s._force_flag_for_package(
		required_changes, ppkg, flag, "disabled"
	)
	elif
	state == "disabled":
	s._force_flag_for_package(
		required_changes, ppkg, flag, "enabled"
	)

	is_valid_solution = True
	for pkg
	in
required_changes:
	for state
	in
	required_changes[pkg].values():
	if not state
	in("enabled", "disabled"):
	is_valid_solution = False

	if not is_valid_solution:
	return None

	for idx, pkg
	in
	enumerate(config):
	new_use = _pkg_use_enabled(pkg)
	if pkg in
required_changes:
	old_use = pkg.use.enabled
	new_use = set(new_use)
	for flag, state
	in
	required_changes[pkg].items():
	if state == "enabled":
	new_use.add(flag)
	elif
	state == "disabled":
	new_use.discard(flag)
	if not new_use.symmetric_difference(old_use):\
	new_use = old_use

	for ppkg, atom
	in
	all_conflict_atoms_by_slotatom[idx]:
	if not atom.package:
	continue
	if not hasattr(ppkg, "use"):
	continue
	ppkg_new_use = set(_pkg_use_enabled(ppkg))
	if ppkg in
required_changes:
	for flag, state
	in
	required_changes[ppkg].items():
	if state == "enabled":
	ppkg_new_use.add(flag)
	elif
	state == "disabled":
	ppkg_new_use.discard(flag)

	new_atom = atom.unevaluated_atom.evaluate_conditionals(ppkg_new_use)
	i = InternalPackageSet(initial_atoms = (new_atom,))
	if not i.findAtomForPackage(pkg, new_use):
	is_valid_solution = False
	if s.debug:
	writemsg(
		(
			"new conflict introduced: %s"
	" does not match %s from %s\n"
	)
	% (pkg, new_atom, ppkg),
	noiselevel = -1,
)
	break

	if not is_valid_solution:
	break

	for pkg
	in
required_changes:
	required_use = pkg._metadata.get("REQUIRED_USE")
	if not required_use:
	continue

	use = set(_pkg_use_enabled(pkg))
	for flag, state
	in
	required_changes[pkg].items():
	if state == "enabled":
	use.add(flag)
	else:
	use.discard(flag)

	if not check_required_use(required_use, use, pkg.iuse.is_valid_flag):
	is_valid_solution = False
	break

	if is_valid_solution and
required_changes:
	return required_changes
	return None

	type _configuration_generator struct {
		_is_first_solution bool
		solution_ids       []int
	}
}

func New_configuration_generator( conflict_pkgs)*_configuration_generator {
	c := &_configuration_generator{}
	c.conflict_pkgs = []T
	for pkgs
	in
	conflict_pkgs{
		new_pkgs = []T
		for pkg in pkgs{
		if not pkg.installed{
		new_pkgs=append(new_pkgs, pkg)
	}
	}
		for pkg in pkgs{
		if pkg.installed{
		new_pkgs=append(new_pkgs, pkg)
	}
	}
		c.conflict_pkgs=append(c.conflict_pkgs, new_pkgs)
	}

	c.solution_ids = []int{}
	for pkgs
	in
	c.conflict_pkgs{
		c.solution_ids=append(c.solution_ids,0)
	}
	c._is_first_solution = true
	return c
}

func (c*_configuration_generator) get_configuration() {
	if c._is_first_solution {
		c._is_first_solution = false
	} else {
		if ! c._next() {
			return None
		}
	}

	solution := []T
	for idx, pkgs := range c.conflict_pkgs{
		solution = append(solution, pkgs[c.solution_ids[idx]])
	}
	return solution
}

func (c*_configuration_generator) _next(id=None)bool {
	solution_ids := c.solution_ids
	conflict_pkgs := c.conflict_pkgs

	if id is
	None{
		id = len(solution_ids) - 1
	}

	if solution_ids[id] == len(conflict_pkgs[id])-1 {
		if id > 0 {
			return c._next(id = id - 1)
		}
		return false
	}

	solution_ids[id] += 1
	for other_id
	in range
	(id + 1, len(solution_ids)){
		solution_ids[other_id] = 0
	}
	return true
}


type _solution_candidate_generator struct {
	_is_first_solution bool
}

type _value_helper struct {

}
func New_value_helper( value=None)*_value_helper {
	v := &_value_helper{}
	v.value = value
	return v
}

func (v *_value_helper) __eq__( other) bool {
	if isinstance(other, str) {
		return v.value == other
	}
	return v.value == other.value
}

func (v *_value_helper) __str__() string {
	return fmt.Sprint(v.value)
}

func New_solution_candidate_generator(all_involved_flags)*_solution_candidate_generator {
	s := &_solution_candidate_generator{}
	s.all_involved_flags = []T

	s.conditional_values = []T

	for involved_flags
	in
	all_involved_flags{
		new_involved_flags ={}
		for flag, state in involved_flags.items(){
		if state in ("enabled", "disabled"){
		new_involved_flags[flag] = state
	} else{
		v = s._value_helper("disabled")
		new_involved_flags[flag] = v
		s.conditional_values.append(v)
	}
	}
		s.all_involved_flags.append(new_involved_flags)
	}

	s._is_first_solution = true
	return s
}

func (s*_solution_candidate_generator) get_candidate() {
	if s._is_first_solution {
		s._is_first_solution = false
	}else {
		if not s._next() {
			return None
		}
	}

	return s.all_involved_flags
}

func (s*_solution_candidate_generator) _next( id=None) bool {
values := s.conditional_values

if not values{
return false
}

if id is None{
id = len(values) - 1
}

if values[id].value == "enabled"{
if id > 0{
return s._next(id = id - 1)
}
return false
}

values[id].value = "enabled"
for other_id in range(id + 1, len(values)){
values[other_id].value = "disabled"
}
return true
}
