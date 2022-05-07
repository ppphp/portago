package atom

import (
	"fmt"
	"github.com/ppphp/portago/pkg/myutil"
	"strings"
)

type templateDatabase struct {
	complete_eclass_entries, autocommits, cleanse_keys, serialize_eclasses, store_eclass_paths bool
	validation_chf                                                                             string

	readonly           bool
	sync_rate, updates int
	_known_keys        map[string]bool
	location, label    string
}

// false
func NewTemplateDatabase( location, label string, auxdbkeys map[string]bool, readonly bool) *database {
	d := &templateDatabase{}

	d.complete_eclass_entries = true
	d.autocommits = false
	d.cleanse_keys = false
	d.serialize_eclasses = true
	d.validation_chf = "mtime"
	d.store_eclass_paths = true

	d._known_keys = auxdbkeys
	d.location = location
	d.label = label
	d.readonly = readonly
	d.sync_rate = 0
	d.updates = 0
	return d
}

func (d *templateDatabase) __getitem__(cpv) {
	if d.updates > d.sync_rate {
		d.commit()
		d.updates = 0
	}
	d1 := d._getitem(cpv)

try:
	chf_types := d.chf_types
	except AttributeError:
	chf_types = (d.validation_chf, )

	if d.serialize_eclasses && "_eclasses_" in d:
	for chf_type in chf_types:
	if '_%s_' % chf_type not in d:
	continue
try:
	d["_eclasses_"] = reconstruct_eclasses(cpv, d["_eclasses_"],
		chf_type, paths = d.store_eclass_paths)
	except cache_errors.CacheCorruption:
	if chf_type is chf_types[-1]:
	raise else:
	break else:
	raise cache_errors.CacheCorruption(cpv,
		'entry does not contain a recognized chf_type')

	elif "_eclasses_" not in d:
	d["_eclasses_"] ={}
	d.pop("INHERITED", None)

	mtime_required = not any(d.get('_%s_' % x)
	for x in chf_types if x != 'mtime')

	mtime = d.get('_mtime_')
	if not mtime:
	if mtime_required:
	raise cache_errors.CacheCorruption(cpv,
		'_mtime_ field is missing')
	d.pop('_mtime_', None) else:
try:
	mtime = long(mtime)
	except ValueError:
	raise cache_errors.CacheCorruption(cpv,
		'_mtime_ conversion to long failed: %s'%(mtime, ))
	d['_mtime_'] = mtime
	return d
}

func (d *templateDatabase) _getitem(cpv) {
	panic("")
	//raise NotImplementedError
}

@staticmethod
func (d *templateDatabase) _internal_eclasses(extern_ec_dict, chf_type, paths) {
	if not extern_ec_dict {
		return extern_ec_dict
	}
	chf_getter := operator.attrgetter(chf_type)
	if paths {
		intern_ec_dict = dict((k, (v.eclass_dir, chf_getter(v)))
		for k, v
			in
		extern_ec_dict.items())
	} else {
		intern_ec_dict = dict((k, chf_getter(v))
		for k, v
			in
		extern_ec_dict.items())
	}
	return intern_ec_dict
}

func (d *templateDatabase) __setitem__(cpv, values) {
	if d.readonly {
		//raise cache_errors.ReadOnlyRestriction()
	}
	d1 = None
	if d.cleanse_keys {
		d1 = ProtectedDict(values)
		for k, v
			in
		list(item
		for item
			in
		d1.items()
		if item[0] != "_eclasses_"):
		if not v:
		del
		d1[k]
	}
	if "_eclasses_" in
values:
	if d1 is
None:
	d1 = ProtectedDict(values)
	if d.serialize_eclasses:
	d1["_eclasses_"] = serialize_eclasses(d1["_eclasses_"],
		d.validation_chf, paths = d.store_eclass_paths) else:
	d1["_eclasses_"] = d._internal_eclasses(d1["_eclasses_"],
		d.validation_chf, d.store_eclass_paths)
	elif
	d1
	is
None:
	d1 = values
	d._setitem(cpv, d1)
	if not d.autocommits:
	d.updates += 1
	if d.updates > d.sync_rate:
	d.commit()
	d.updates = 0
}

func (d *templateDatabase) _setitem( name, values) {
	panic("")
	//raise NotImplementedError
}

func (d *templateDatabase) __delitem__(cpv) {
	if d.readonly {
		//raise cache_errors.ReadOnlyRestriction()
	}
	if ! d.autocommits {
		d.updates += 1
	}
	d._delitem(cpv)
	if d.updates > d.sync_rate {
		d.commit()
		d.updates = 0
	}
}

func (d *templateDatabase) _delitem(cpv) {
	panic("")
	//raise NotImplementedError
}

func (d *templateDatabase) has_key(cpv) {
	return cpv
	in
	d
}

func (d *templateDatabase) iterkeys() {
	return iter(d)
}

func (d *templateDatabase) iteritems() {
	for x
	in
d:
	yield(x, d[x])
}

// 0
func (d *templateDatabase) sync(rate int) {
	d.sync_rate = rate
	if rate == 0 {
		d.commit()
	}
}

func (d *templateDatabase) commit() {
	if ! d.autocommits {
		panic("")
		//raise NotImplementedError(d)
	}
}

func (d *templateDatabase) __del__() {
	d.sync()
}

func (d *templateDatabase) __contains__(cpv) {
	if d.has_key is
	database.has_key{
		panic(""),
		//raise NotImplementedError
	}
	//warnings.warn("portage.cache.template.database.has_key() is "
	//"deprecated, override __contains__ instead",
	//	DeprecationWarning)
	return d.has_key(cpv)
}

func (d *templateDatabase) __iter__() {
	if d.iterkeys is
	database.iterkeys:
	raise
	NotImplementedError(d)
	return iter(d.keys())
}

func (d *templateDatabase) get(k, x=None) {
try:
	return d[k]
	except
KeyError:
	return x
}

func (d *templateDatabase) validate_entry( entry, ebuild_hash, eclass_db) {
try:
	chf_types := d.chf_types
	except
AttributeError:
	chf_types = (d.validation_chf,)

	for chf_type
	in
chf_types:
	if d._validate_entry(chf_type, entry, ebuild_hash, eclass_db):
	return true

	return false
}

func (d *templateDatabase) _validate_entry(chf_type string, entry, ebuild_hash, eclass_db) bool {
	hash_key := fmt.Sprintf("_%s_", chf_type)
	entry_hash, ok := entry[hash_key]
	if !ok {
		return false
	} else {
		if entry_hash != getattr(ebuild_hash, chf_type) {
			return false
		}
	}
	update := eclass_db.validate_and_rewrite_cache(entry['_eclasses_'], chf_type,
		d.store_eclass_paths)
	if update == nil {
		return false
	}
	if update {
		entry['_eclasses_'] = update
	}
	return true
}

func (d *templateDatabase) get_matches( match_dict) {

	import re
	restricts := {}
	for key, match
	in
	match_dict.items():
try:
	if isinstance(match, basestring):
	restricts[key] = re.compile(match).match
	else:
	restricts[key] = re.compile(match[0], match[1]).match
	except
	re.error
	as
e:
	raise
	InvalidRestriction(key, match, e)
	if key not
	in
	d.__known_keys:
	raise
	InvalidRestriction(key, match, "Key isn't valid")

	for cpv
	in
d:
	cont = true
	vals = d[cpv]
	for key, match
	in
	restricts.items():
	if not match(vals[key]):
	cont = false
	break
	if cont:
	yield
	cpv

	if sys.hexversion >= 0x3000000:
	keys = __iter__
	items = iteritems

}
	_keysorter = operator.itemgetter(0)

// "mtime", true
func serialize_eclasses(eclass_dict, chf_type string, paths bool) string {
	if not eclass_dict {
		return ""
	}
	getter = operator.attrgetter(chf_type)
	if paths {
		return "\t".join("%s\t%s\t%s"%(k, v.eclass_dir, getter(v))
		for k, v
			in
		myutil.sorted(eclass_dict.items(), key = _keysorter))
	}
	return "\t".join("%s\t%s"%(k, getter(v))
	for k, v
	in
	myutil.sorted(eclass_dict.items(), key = _keysorter))
}

func _md5_deserializer(md5 string) string {
	if len(md5) != 32 {
		//raise ValueError('expected 32 hex digits')
	}
	return md5
}

var _chf_deserializers = map[string]func(string)string{
	"md5":   _md5_deserializer,
	"mtime": long,
}

// "mtime", true
func reconstruct_eclasses(cpv, eclass_string string, chf_type string, paths bool) {
	eclasses := strings.Split(strings.TrimSpace(eclass_string), "\t")
	if len(eclasses) == 1 && eclasses[0] == "" {
		return
		{
		}
	}

	converter, ok := _chf_deserializers[chf_type]
	if !ok {
		converter = func(s string) string {
			return s
		}
	}

	if paths {
		if len(eclasses)%3 != 0 {
			//raise cache_errors.CacheCorruption(cpv, "_eclasses_ was of invalid len %i"%len(eclasses))
		}
	}else if len(eclasses)%2 != 0 {
		//raise cache_errors.CacheCorruption(cpv, "_eclasses_ was of invalid len %i"%len(eclasses))
	}
	d :=
	{
	}
try:
	i = iter(eclasses)
	if paths {
		for name, path, val
			in
		zip(i, i, i) {
			d[name] = (path, converter(val))
		}
	}else {
		for name, val
			in
		zip(i, i) {
			d[name] = converter(val)
		}
	}
	except
IndexError:
	raise
	cache_errors.CacheCorruption(cpv,
		"_eclasses_ was of invalid len %i"%len(eclasses))
	except
ValueError:
	raise
	cache_errors.CacheCorruption(cpv,
		"_eclasses_ not valid for chf_type {}".format(chf_type))
	del
	eclasses
	return d
}

type VolatileDatabase struct{
	*database
	autocommits,serialize_eclasses,store_eclass_paths bool
}

// false
func NewVolatileDatabase(location, label string, auxdbkeys map[string]bool, readonly bool) *VolatileDatabase{
	v := &VolatileDatabase{}

	v.autocommits = true
	v.serialize_eclasses = false
	v.store_eclass_paths = false

	v.database = NewDatabase(location, label, auxdbkeys, readonly)
	v._data =
	{
	}
	v._delitem = v._data.__delitem__
	return v
}

func(v*VolatileDatabase) _setitem(name string, values) {
	v._data[name] = copy.deepcopy(values)
}

func(v*VolatileDatabase) __getitem__( cpv) {
	return copy.deepcopy(v._data[cpv])
}

func(v*VolatileDatabase) __iter__() {
	return iter(v._data)
}

func(v*VolatileDatabase) __contains__( key) {
	return key
	in
	v._data
}



type md5Database struct {
	*database
}

func NewMd5Database (location, label string, auxdbkeys map[string]bool, readonly bool) *md5Database {
	m := &md5Database{NewDatabase(location, label, auxdbkeys, readonly)}
	m.validation_chf = "md5"
	m.store_eclass_paths = false
	return m
}
