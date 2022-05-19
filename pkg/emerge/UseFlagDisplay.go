package emerge

import (
	"fmt"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
)

type UseFlagDisplay struct {
	// slots
	name,forced string
	enabled bool

	sort_combined func()
	sort_separated func()
}

func NewUseFlagDisplay( name string, enabled bool, forced string)*UseFlagDisplay {
	u := &UseFlagDisplay{}

	u.sort_combined = func (a, b){
		return (a.name > b.name) - (a.name < b.name)
	}

	u.sort_separated = func (a, b) {
		enabled_diff := b.enabled - a.enabled
		if enabled_diff {
			return enabled_diff
		}
		return (a.name > b.name) - (a.name < b.name)
	}

	u.name = name
	u.enabled = enabled
	u.forced = forced
	return u
}

func(u*UseFlagDisplay) __str__() string {
	s := u.name
	if u.enabled {
		s = output.Red(s)
	} else {
		s = "-" + s
		s = output.Blue(s)
	}
	if u.forced != "" {
		s = fmt.Sprintf("(%s)", s)
	}
	return s
}

type _flag_info struct{flag, display string}

// nil
func pkg_use_display(pkg, opts map[string]string, modified_use=None) {
	settings := pkg.root_config.settings
	use_expand := pkg.use.expand
	use_expand_hidden := pkg.use.expand_hidden
	_, alphabetical_use :=opts["--alphabetical"]
	forced_flags = set(chain(pkg.use.force,
		pkg.use.mask))
	if modified_use == nil {
		dep.use = set(pkg.use.enabled)
	}else {
		dep.use = set(modified_use)
	}
	dep.use.discard(settings.get('ARCH'))
	use_expand_flags := set()
	use_enabled :=
	{
	}
	use_disabled :=
	{
	}
	for varname
		in
	use_expand:
	flag_prefix = varname.lower() + "_"
	for f
		in
	dep.use {
		if f.startswith(flag_prefix):
		use_expand_flags.add(f)
		use_enabled.setdefault(
			varname.upper(),[]).append(
			&_flag_info{f, f[len(flag_prefix):]})

		for f
			in
		pkg.iuse.all:
		if f.startswith(flag_prefix):
		use_expand_flags.add(f)
		if f not
		in
	use:
		use_disabled.setdefault(
			varname.upper(),[]).append(
			&_flag_info{f, f[len(flag_prefix):]})
	}

	var_order = set(use_enabled)
	var_order.update(use_disabled)
	var_order = myutil.sorted(var_order)
	var_order.insert(0, 'USE')
	dep.use.difference_update(use_expand_flags)
	use_enabled['USE'] = list(&_flag_info{f, f}
	for f
		in
	dep.use)
	use_disabled['USE'] = []

for f
in
pkg.iuse.all{
if f not
in
use
&&
f
not
in
use_expand_flags{
use_disabled['USE'].append(&_flag_info{f, f})
}
}

flag_displays = []
for varname
in
var_order{
if varname.lower() in
use_expand_hidden{
continue
}
flags = []
for f
in
use_enabled.get(varname, []){
flags.append(NewUseFlagDisplay(f.display, true, f.flag
in
forced_flags))
}
for f
in
use_disabled.get(varname, []){
flags.append(UseFlagDisplay(f.display, false, f.flag
in
forced_flags))
}
if alphabetical_use{
flags.sort(key = UseFlagDisplay.sort_combined)
}else{
flags.sort(key = UseFlagDisplay.sort_separated)
}
flag_displays.append('%s="%s"'%(varname,
' '.join("%s"%(f, )
for f
in
flags)))
}

return strings.Join(flag_displays, " ")
}
