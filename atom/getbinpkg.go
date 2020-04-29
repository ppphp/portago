package atom

import (
	"fmt"
	"os"
	"sort"
	"time"
)

type PackageIndex struct {
	modified bool
	header, _default_header_data map[string]string
}

// true
func (p* PackageIndex) _readpkgindex( pkgfile *os.File, pkg_entry bool) {

	allowed_keys = None
	if p._pkg_slot_dict is
	None
	or
	not
pkg_entry:
	d =
	{
	}
	else:
	d = p._pkg_slot_dict()
	allowed_keys = d.allowed_keys

	for line
	in
pkgfile:
	line = line.rstrip("\n")
	if not line:
	break
	line = line.split(":", 1)
	if not len(line) == 2:
	continue
	k, v = line
	if v:
	v = v[1:]
	k = p._read_translation_map.get(k, k)
	if allowed_keys is
	not
	None
	and \
	k
	not
	in
allowed_keys:
	continue
	d[k] = v
	return d
}

	func (p* PackageIndex) _writepkgindex( pkgfile *os.File, items[]string ) {
		for k, v :=range	items{
			pkgfile.write("%s: %s\n" % \
			(p._write_translation_map.get(k, k), v))
		}
		pkgfile.write("\n")
	}

func (p* PackageIndex) read( pkgfile *os.File) {
	p.readHeader(pkgfile)
	p.readBody(pkgfile)
}

func (p* PackageIndex) readHeader( pkgfile *os.File) {
	p.header.update(p._readpkgindex(pkgfile, pkg_entry = False))
}

func (p* PackageIndex) readBody( pkgfile *os.File) {
	while
True:
	d = p._readpkgindex(pkgfile)
	if not d:
	break
	mycpv = d.get("CPV")
	if not mycpv:
	continue
	if p._default_pkg_data:
	for k, v
	in
	p._default_pkg_data.items():
	d.setdefault(k, v)
	if p._inherited_keys:
	for k
	in
	p._inherited_keys:
	v = p.header.get(k)
	if v is
	not
None:
	d.setdefault(k, v)
	p.packages.append(d)
}

func (p* PackageIndex) write( pkgfile *os.File) {
	if p.modified {
		p.header["TIMESTAMP"] = fmt.Sprint(time.Now().Unix())
		p.header["PACKAGES"] = str(len(p.packages))
	}
	keys:= []string{}
	for k := range p.header{
		keys = append(keys, k)
	}
	sort.Strings(keys)
	p._writepkgindex(pkgfile, [(k, p.header[k]) \
	for k
	in
	keys
	if p.header[k]])
for metadata in sorted(p.packages,
key = portage.util.cmp_sort_key(_cmp_cpv)):
metadata = metadata.copy()
if p._inherited_keys:
for k in p._inherited_keys:
v = p.header.get(k)
if v is not None and v == metadata.get(k):
del metadata[k]
if p._default_pkg_data:
for k, v in p._default_pkg_data.items():
if metadata.get(k) == v:
metadata.pop(k, None)
keys = list(metadata)
keys.sort()
p._writepkgindex(pkgfile,
[(k, metadata[k]) for k in keys if metadata[k]])
}

// nil, nil, nil, nil, nil
func NewPackageIndex(
	allowed_pkg_keys=None,
	default_header_data map[string]string,
	default_pkg_data=None,
	inherited_keys=None,
	translated_keys=None) *PackageIndex{
	p:=&PackageIndex{}

	p._pkg_slot_dict = None
	if allowed_pkg_keys != None {
		p._pkg_slot_dict = slot_dict_class(allowed_pkg_keys)
	}

	p._default_header_data = default_header_data
	p._default_pkg_data = default_pkg_data
	p._inherited_keys = inherited_keys
	p._write_translation_map = {}
	p._read_translation_map = {}
	if translated_keys {
		p._write_translation_map.update(translated_keys)
		p._read_translation_map.update(((y, x)
		for (x, y) in
		translated_keys))
	}
	p.header = map[string]string{}
	if len(p._default_header_data) != 0 {
		for k, v := range p._default_header_data{
			p.header[k] = v
		}
	}
	p.packages = []
	p.modified = true
}

