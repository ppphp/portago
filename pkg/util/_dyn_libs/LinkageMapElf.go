package _dyn_libs

import (
	"bytes"
	"fmt"
	"github.com/ppphp/portago/atom"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/versions"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type linkageMapELF struct {
	_needed_aux_key   string
	_soname_map_class struct {
		consumers, providers []string
	}
	_dbapi                                                            *atom.vardbapi
	_root                                                             string
	_libs map[string][] string
	_obj_properties map[string]*_obj_properties_class
	_defpath map[string]bool
	_obj_key_cache, _path_key_cache map[string]*_ObjectKey
}

type _obj_properties_class struct{
	//slot
	arch,soname,owner string
	needed,runpaths []string
	alt_paths map[string]bool
}

func New_obj_properties_class(arch string, needed, runpaths []string, soname string, alt_paths map[string]bool, owner string)*_obj_properties_class {
	o := &_obj_properties_class{}
	o.arch = arch
	o.needed = needed
	o.runpaths = runpaths
	o.soname = soname
	o.alt_paths = alt_paths
	o.owner = owner
	return o
}

func (o*linkageMapELF) _clear_cache() {
	o._libs= map[string]string{}
	o._obj_properties= map[string]*_obj_properties_class{}
	o._obj_key_cache= map[string]*_ObjectKey{}
	o._defpath= map[string]bool{}
	o._path_key_cache= map[string]*_ObjectKey{}
}

func (o*linkageMapELF) _path_key( path string)  *_ObjectKey {
	key := o._path_key_cache[path]
	if key == nil {
		key = New_ObjectKey(path, o._root)
	}
	o._path_key_cache[path] = key
	return key
}

func (o*linkageMapELF) _obj_key(path string) *_ObjectKey {
	key := o._obj_key_cache[path]
	if key == nil {
		key = New_ObjectKey(path, o._root)
	}
	o._obj_key_cache[path] = key
	return key
}


type _ObjectKey struct{
	_key interface{}
}

func(o*_ObjectKey) __hash__() {
	return hash(o._key)
}

func(o*_ObjectKey) __eq__( other *_ObjectKey) bool {
	return o._key == other._key
}

func(o*_ObjectKey) _generate_object_key(obj, root string) interface{} {

	abs_path := filepath.Join(root, strings.TrimLeft(obj, string(os.PathSeparator)))
	object_stat, err := os.Stat(abs_path)
	if err != nil {
		//except OSError:
		rp, _ := filepath.EvalSymlinks(abs_path)
		return rp
	}
	return [2]uint64{object_stat.Sys().(*syscall.Stat_t).Dev, object_stat.Sys().(*syscall.Stat_t).Ino}
}

func(o*_ObjectKey) file_exists() bool{
	_, ok := o._key.([2]uint64)
	return ok
}

func New_ObjectKey(obj, root string)*_ObjectKey {
	o := &_ObjectKey{}
	o._key = o._generate_object_key(obj, root)
	return o
}

type _LibGraphNode struct{
	*_ObjectKey
	// slot
	alt_paths map[string]bool
}

func( l*_LibGraphNode) __str__() string {
	return str(atom.sortedmsb(l.alt_paths))
}

func New_LibGraphNode( key *_ObjectKey) *_LibGraphNode {
	l := &_LibGraphNode{}
	l._key = key._key
	l.alt_paths = map[string]bool{}
	return l
}

// nil, "", nil
func (o*linkageMapELF) rebuild(exclude_pkgs []*versions.PkgStr, include_file string, preserve_paths map[string]bool) {

	root := o._root
	root_len := len(root) - 1
	o._clear_cache()
	for _, k := range getLibPaths(o._dbapi.settings.ValueDict["EROOT"],
		o._dbapi.settings.ValueDict) {
		o._defpath[k] = true
	}
	libs := o._libs
	obj_properties := o._obj_properties

	lines := []*struct {
		p      *versions.PkgStr;
		s1, s2 string
	}{}

	if include_file != "" {
		for _, line := range grabFile(include_file, 0, false, false) {
			lines = append(lines, &struct {
				p      *versions.PkgStr;
				s1, s2 string
			}{nil, include_file, line[0]})
		}
	}

	aux_keys := map[string]bool{o._needed_aux_key: true}
	can_lock := atom.osAccess(filepath.Dir(o._dbapi._dbroot), unix.W_OK)
	if can_lock {
		o._dbapi.lock()
	}
	//try:
	for _, cpv := range o._dbapi.cpv_all(1) {
		in := false
		for _, k := range exclude_pkgs {
			if k.string == cpv.string {
				in = true
				break
			}
		}
		if exclude_pkgs != nil && in {
			continue
		}
		needed_file := o._dbapi.getpath(cpv.string, o._needed_aux_key)
		for _, line := range strings.Split(o._dbapi.aux_get(cpv.string, aux_keys, "")[0], "\n") {
			lines = append(lines, &struct {
				p      *versions.PkgStr;
				s1, s2 string
			}{cpv, needed_file, line})
		}
	}
	//finally:
	if can_lock {
		o._dbapi.unlock()
	}

	plibs := map[string]*versions.PkgStr{}
	if preserve_paths != nil{
		for x := range preserve_paths {
			plibs[x] = nil
		}
	}
	if o._dbapi._plib_registry!= nil && o._dbapi._plib_registry.hasEntries() {
		for cpv, items := range o._dbapi._plib_registry.getPreservedLibs() {
			in := false
			for _, k := range exclude_pkgs {
				if k.string == cpv {
					in = true
					break
				}
			}
			if exclude_pkgs != nil && in {
				continue
			}

			for _, x := range items {
				plibs[x]= cpv
			}
		}
	}
	if len(plibs) > 0 {
		ep := _const.EPREFIX
		if ep == "" {
			ep = "/"
		}
		args := []string{filepath.Join(ep, "usr/bin/scanelf"), "-qF", "%a;%F;%S;%r;%n"}
		for x := range plibs {
			args = append(args, filepath.Join(root, strings.TrimLeft(x, "."+string(os.PathSeparator))))
		}

		cmd := exec.Command(args[0], args[1:]...)
		b := &bytes.Buffer{}
		cmd.Stdout = b
		if err := cmd.Run(); err != nil {
			//except EnvironmentError as e:
			if err != syscall.ENOENT {
				//raise
			}
			//raise CommandNotFound(args[0])
		} else {
			for _, l := range strings.Split(b.String(), "\n") {
				//try:
				//	l = _unicode_decode(l,
				//		encoding = _encodings['content'], errors = 'strict')
				//	except
				//UnicodeDecodeError:
				//	l = _unicode_decode(l,
				//		encoding = _encodings['content'], errors = 'replace')
				//	WriteMsgLevel(_("\nError decoding characters " \
				//	"returned from scanelf: %s\n\n") % (l, ),
				//	level = logging.ERROR, noiselevel = -1)
				l = strings.TrimRight(l[3:], "\n")
				if l == "" {
					continue
				}
				entry, err := NewNeededEntry().parse("scanelf", l)
				if err != nil {
					//except InvalidData as e:
					WriteMsgLevel(fmt.Sprintf("\n%s\n\n", err, ),
						40, -1)
					continue
				}
				f, err := os.Open(entry.filename)
				if err != nil {
					//except EnvironmentError as e:
					if err != syscall.ENOENT {
						//raise
					}
					continue
				}
				elf_header := atom.ReadELFHeader(f)

				if entry.soname == "" {
					cmd := exec.Command("file", entry.filename)
					var out, err bytes.Buffer
					cmd.Stdout=&out
					cmd.Stderr=&err
					if err := cmd.Run(); err != nil {
						//except EnvironmentError:
					} else {
						if strings.Contains(out.String(), "SB shared object"){
							entry.soname = filepath.Base(entry.filename)
						}
					}
				}

				entry.multilib_category = atom.compute_multilib_category(elf_header)
				entry.filename = entry.filename[root_len:]
				owner := plibs[entry.filename]
				delete(plibs, entry.filename)
				lines=append(lines, &struct {p *versions.PkgStr;s1, s2 string}{owner, "scanelf", entry.__str__()})
			}
		}
	}

	if len(plibs) > 0 {
		for x, cpv := range plibs {
			lines=append(lines, &struct {p *versions.PkgStr;s1, s2 string}{cpv, "plibs", strings.Join([]string{"", x, "", "", ""},";")})
		}
	}

	frozensets =
	{
	}
	owner_entries := map[string][]*NeededEntry{}

	for {
		if len(lines) == 0 {
			//except IndexError:
			break
		}
		line := lines[len(lines)-1]
		lines = lines[:len(lines)-1]
		owner, location, l := line.p, line.s1, line.s2
		l = strings.TrimRight(l, "\n")
		if l == "" {
			continue
		}
		if strings.Contains(l, string([]byte{0})) {
			WriteMsgLevel(fmt.Sprintf("\nLine contains null byte(s) "+
				"in %s: %s\n\n", location, l), 40, -1)
			continue
		}
		entry ,err := NewNeededEntry().parse(location, l)
		if err != nil {
			//except InvalidData as e:
			WriteMsgLevel(fmt.Sprintf("\n%s\n\n", err), 40, -1)
			continue
		}

		if entry.multilib_category == "" {
			entry.multilib_category = _approx_multilib_categories.get(
				entry.arch, entry.arch)
		}

		entry.filename = NormalizePath(entry.filename)
		expand := map[string]string{
			"ORIGIN": filepath.Dir(entry.filename),
		}
		runpaths:=map[string]bool{}
		for _, x := range entry.runpaths{
			runpaths[NormalizePath(varExpand(x, expand, func() string {return fmt.Sprintf("%s: " , location)})] = true
		}
		entry.runpaths = []string{}
		for   k := range runpaths{
			entry.runpaths = append(entry.runpaths, k)
		}
		owner_entries[owner.string] = append(owner_entries[owner.string], entry)
	}

	for owner, entries:= range owner_entries {
		if owner == "" {
			continue
		}

		providers :=
		{
		}
		for _, entry := range entries {
			if entry.soname != "" {
				providers[atom.NewSonameAtom(entry.multilib_category, entry.soname)] = entry
			}
		}

		for _, entry := range entries {
			implicit_runpaths = []
for soname
in
entry.needed:
soname_atom := NewSonameAtom(entry.multilib_category, soname)
provider = providers.get(soname_atom)
if provider is
None:
continue
provider_dir = filepath.Dir(provider.filename)
if provider_dir not
in
entry.runpaths:
implicit_runpaths.append(provider_dir)

if implicit_runpaths:
entry.runpaths = frozenset(
itertools.chain(entry.runpaths, implicit_runpaths))
entry.runpaths = frozensets.setdefault(
entry.runpaths, entry.runpaths)
}
}

for owner, entries := range owner_entries {
for _, entry := range entries{
arch := entry.multilib_category
obj := entry.filename
soname := entry.soname
path := entry.runpaths
neededmsb := map[string]bool{}
for _, k := range entry.needed{
neededmsb[k]=true
}
needed := []string{}
for k := range neededmsb {
needed =append(needed, k)
}
obj_key := o._obj_key(obj)
indexed := true
myprops := obj_properties[obj_key]
if myprops == nil {
indexed = false
myprops = New_obj_properties_class(
arch, needed, path, soname, [], owner)
obj_properties[obj_key] = myprops
}
myprops.alt_paths=append(myprops.alt_paths,obj)

if indexed{
continue
}

arch_map := libs[arch]
if arch_map == nil {
arch_map =
{
}
libs[arch] = arch_map
}
if soname {
soname_map := arch_map[soname]
if soname_map == nil {
soname_map = o._soname_map_class(
providers = [], consumers = [])
arch_map[soname] = soname_map
}
soname_map.providers=append(soname_map.providers,obj_key)
}
for _, needed_soname:= range needed {
soname_map = arch_map.get(needed_soname)
if soname_map == nil {
soname_map = o._soname_map_class(
providers = [], consumers = [])
}
arch_map[needed_soname] = soname_map
soname_map.consumers=append(soname_map.consumers,obj_key)
}
}
}

for arch, sonames:= range libs {
for _, soname_node := range sonames {
soname_node.providers = tuple(set(soname_node.providers))
soname_node.consumers = tuple(set(soname_node.consumers))
}
}
}

type _LibraryCache struct {
	o *linkageMapELF
	cache map[]
}

func NewLibraryCache(o *linkageMapELF) *_LibraryCache {
	l := &_LibraryCache{}
	l.o = o
	l.cache =
	{
	}
	return l
}

func (l *_LibraryCache)get(obj) {

	if obj in
	l.cache{
		return l.cache[obj]
	} else {
		obj_key := l.o._obj_key(obj)
		if obj_key.file_exists() {
			obj_props := l.o._obj_properties[obj_key]
			if obj_props == nil {
				arch = None
				soname = None
			} else {
				arch = obj_props.arch
				soname = obj_props.soname
				return l.cache.setdefault(obj, \
				(arch, soname, obj_key, true))
			}
		} else {
			return l.cache.setdefault(obj, \
			(None, None, obj_key, false))
		}
	}
}

// false
func (o*linkageMapELF) listBrokenBinaries( debug bool) {

	rValue :=
	{
	}
	cache := NewLibraryCache(o)
	providers := o.listProviders()

	for obj_key, sonames
		in
	providers.items() {
		obj_props := o._obj_properties[obj_key]
		arch := obj_props.arch
		path := obj_props.runpaths
		objs := obj_props.alt_paths
		path := path.union(o._defpath)
		for soname, libraries
			in
		sonames.items() {
			validLibraries = set()
			for directory
				in
			path:
			cachedArch, cachedSoname, cachedKey, cachedExists = \
			cache.get(filepath.Join(directory, soname))
			if cachedSoname == soname && cachedArch == arch{
				validLibraries.add(cachedKey)
				if debug &&
					cachedKey
					not
				in \
				set(map(o._obj_key_cache.get,
				libraries)){
				WriteMsgLevel(
				_("Found provider outside of findProviders:") + \
				(" %s -> %s %s\n" % (filepath.Join(directory, soname),
				o._obj_properties[cachedKey].alt_paths, libraries)),
				level = logging.DEBUG,
				noiselevel = -1)
				}
				break
			}
			if debug && cachedArch == arch &&
				cachedKey
				in
			o._obj_properties{
				WriteMsgLevel(fmt.Sprintf("Broken symlink or missing/bad soname: "+
					"%s -> %s with soname %s but expecting %s",
					filepath.Join(directory, soname), o._obj_properties[cachedKey],
					cachedSoname, soname)+"\n", 20, -1)
			}
			if not validLibraries:
			for obj
				in
			objs {
				rValue.setdefault(obj, set()).add(soname)
			}
			for lib
				in
			libraries {
				rValue.setdefault(lib, set()).add(soname)
				if debug {
					if not atom.pathIsFile(lib) {
						WriteMsgLevel(fmt.Sprintf("Missing library:"+" %s\n", lib, ), 20, -1)
					}else {
						WriteMsgLevel(fmt.Sprintf("Possibly missing symlink:"+
							"%s\n", filepath.Join(filepath.Dir(lib), soname)), 20, -1)
					}
				}
			}
		}
	}
	return rValue
}

func (o*linkageMapELF) listProviders() {
	rValue :=
	{
	}
	if len( o._libs)==0 {
		o.rebuild(nil, "", nil)
	}
	for obj_key:= range o._obj_properties {
		rValue.setdefault(obj_key, o.findProviders(obj_key))
	}
	return rValue
}

func (o*linkageMapELF) isMasterLink( obj string) {
	os = _os_merge
	obj_key := o._obj_key(obj)
	if obj_key not
	in
	o._obj_properties{
		raise
		KeyError("%s (%s) not in object list"%(obj_key, obj))
	}
	basename := filepath.Base(obj)
	soname := o._obj_properties[obj_key].soname
	return len(basename) < len(soname)&& strings.HasSuffix(basename, ".so")&& strings.HasPrefix(soname, basename[:len(basename)-3])
}

func (o*linkageMapELF) listLibraryObjects() {
	rValue := []
if len(o._libs) == 0 {
o.rebuild()
}
for arch_map
in
o._libs.values() {
for soname_map
in
arch_map.values() {
for obj_key
in
soname_map.providers {
rValue=append(rValue, o._obj_properties[obj_key].alt_paths...)
}
}
}
return rValue
}

func (o*linkageMapELF) getOwners( obj) {
	if not o._libs:
	o.rebuild()
	if isinstance(obj, o._ObjectKey):
	obj_key = obj
	else:
	obj_key = o._obj_key_cache.get(obj)
	if obj_key is
None:
	raise
	KeyError("%s not in object list" % obj)
	obj_props = o._obj_properties.get(obj_key)
	if obj_props is
None:
	raise
	KeyError("%s not in object list" % obj_key)
	if obj_props.owner is
None:
	return ()
	return (obj_props.owner,)
}

func (o*linkageMapELF) getSoname( obj) {
	if not o._libs:
	o.rebuild()
	if isinstance(obj, o._ObjectKey):
	obj_key = obj
	if obj_key not
	in
	o._obj_properties:
	raise
	KeyError("%s not in object list" % obj_key)
	return o._obj_properties[obj_key].soname
	if obj not
	in
	o._obj_key_cache:
	raise
	KeyError("%s not in object list" % obj)
	return o._obj_properties[o._obj_key_cache[obj]].soname
}

func (o*linkageMapELF) findProviders( obj) {

	os = _os_merge

	rValue =
	{
	}

	if len(o._libs) == 0 {
		o.rebuild(nil, "", nil)
	}

	if isinstance(obj, o._ObjectKey):
	obj_key = obj
	if obj_key not
	in
	o._obj_properties:
	raise
	KeyError("%s not in object list" % obj_key)
	else:
	obj_key = o._obj_key(obj)
	if obj_key not
	in
	o._obj_properties:
	raise
	KeyError("%s (%s) not in object list"%(obj_key, obj))

	obj_props = o._obj_properties[obj_key]
	arch = obj_props.arch
	needed = obj_props.needed
	path = obj_props.runpaths
	path_keys = set(o._path_key(x)
	for x
		in
	path.union(o._defpath))
	for soname
		in
	needed:
	rValue[soname] = set()
	if arch not
	in
	o._libs
	or
	soname
	not
	in
	o._libs[arch]:
	continue
	for provider_key
		in
	o._libs[arch][soname].providers:
	providers = o._obj_properties[provider_key].alt_paths
	for provider
		in
	providers:
	if o._path_key(filepath.Dir(provider)) in
path_keys:
	rValue[soname].add(provider)
	return rValue
}

// nil, true
func (o*linkageMapELF) findConsumers( obj string, exclude_providers []func(string)bool, greedy bool) {

	os = _os_merge

	if len(o._libs)==0 {
		o.rebuild(nil, "", nil)
	}

	if isinstance(obj, o._ObjectKey) {
		obj_key = obj
		if obj_key not
		in
		o._obj_properties:
		raise
		KeyError("%s not in object list" % obj_key)
		objs = o._obj_properties[obj_key].alt_paths
	}else {
		objs = set([obj])
		obj_key = o._obj_key(obj)
		if obj_key not
		in
		o._obj_properties:
		raise
		KeyError("%s (%s) not in object list"%(obj_key, obj))
	}

	if not isinstance(obj, o._ObjectKey) {
		soname = o._obj_properties[obj_key].soname
		soname_link = filepath.Join(o._root,
			filepath.Dir(obj).lstrip(os.path.sep), soname)
		obj_path = filepath.Join(o._root, obj.lstrip(string(os.PathSeparator)))
	try:
		soname_st = os.stat(soname_link)
		obj_st = os.stat(obj_path)
		except
	OSError:
		pass
		else:
		if (obj_st.st_dev, obj_st.st_ino) != \
		(soname_st.st_dev, soname_st.st_ino):
		return set()
	}

	obj_props = o._obj_properties[obj_key]
	arch = obj_props.arch
	soname = obj_props.soname

	soname_node = None
	arch_map = o._libs.get(arch)
	if arch_map is
	not
	None{
		soname_node = arch_map.get(soname)
	}

	defpath_keys = set(o._path_key(x)
	for x
		in
	o._defpath)
	satisfied_consumer_keys = set()
	if soname_node is
	not
	None{
		if exclude_providers is
		not
		None
		or
		not
		greedy:
		relevant_dir_keys = set()
		for provider_key
		in
		soname_node.providers:
		if not greedy
		and
		provider_key == obj_key:
		continue
		provider_objs = o._obj_properties[provider_key].alt_paths
		for p
		in
		provider_objs:
		provider_excluded = false
		if exclude_providers is
		not
		None:
		for excluded_provider_isowner
		in
		exclude_providers:
		if excluded_provider_isowner(p):
		provider_excluded = true
		break
		if not provider_excluded:
		relevant_dir_keys.add(
		o._path_key(filepath.Dir(p)))

		if relevant_dir_keys:
		for consumer_key
		in
		soname_node.consumers:
		path = o._obj_properties[consumer_key].runpaths
		path_keys = defpath_keys.copy()
		path_keys.update(o._path_key(x)
		for x
		in
		path)
		if relevant_dir_keys.intersection(path_keys):
		satisfied_consumer_keys.add(consumer_key)
	}

	rValue = set()
	if soname_node != nil {
		objs_dir_keys = set(o._path_key(filepath.Dir(x))
		for x
			in
		objs)
		for consumer_key
			in
		soname_node.consumers {
			if consumer_key in
			satisfied_consumer_keys{
				continue
			}
			consumer_props = o._obj_properties[consumer_key]
			path = consumer_props.runpaths
			consumer_objs = consumer_props.alt_paths
			path_keys = defpath_keys.union(o._path_key(x)
			for x
				in
			path)
			if objs_dir_keys.intersection(path_keys) {
				rValue.update(consumer_objs)
			}
		}
	}
	return rValue
}

func NewLinkageMapELF(vardbapi *atom.vardbapi) *linkageMapELF {
	l := &linkageMapELF{}
	l._dbapi = vardbapi
	l._root = l._dbapi.settings.ValueDict["ROOT"]
	l._libs = map[string]string{}
	l._obj_properties = map[string]string{}
	l._obj_key_cache = map[string]*_ObjectKey{}
	l._defpath = map[string]bool{}
	l._path_key_cache = map[string]*_ObjectKey{}
	return l
}
