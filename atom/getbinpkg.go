package atom

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"
)

func _cmp_cpv(d1,d2 map[string]int ) int{
	cpv1 := d1["CPV"]
	cpv2 := d2["CPV"]
	if cpv1 > cpv2 {
		return 1
	}else if cpv1 == cpv2 {
		return 0
	}else{
			return -1
		}
}

type PackageIndex struct {
	modified bool
	header, _default_header_data, _write_translation_map map[string]string
	_pkg_slot_dict func()map[string]string
}

// true
func (p* PackageIndex) _readpkgindex( pkgfile *os.File, pkg_entry bool) map[string]string {
	var allowed_keys map[string]string = nil
	d := map[string]string{}
	if p._pkg_slot_dict == nil || !pkg_entry{
	} else{
		d = p._pkg_slot_dict()
		allowed_keys = d.allowed_keys
	}

	b, _ := ioutil.ReadAll(pkgfile)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\n")
		if line=="" {
			break
		}
		lines := strings.SplitN(line, ":", 2)
		if len(lines) != 2{
			continue
		}
		k, v := lines[0], lines[1]
		if v!= "" {
			v = v[1:]
		}
		k = p._read_translation_map.get(k, k)
		if _, ok := allowed_keys[k]; allowed_keys != nil && !ok {
			continue
		}
		d[k] = v
	}
	return d
}

	func (p* PackageIndex) _writepkgindex( pkgfile *os.File, items[]string ) {
		for k, v :=range	items{
			a, ok :=p._write_translation_map[k]
			if !ok{
				a = k
			}
			pkgfile.write("%s: %s\n" , a, v)
		}
		pkgfile.write("\n")
	}

func (p* PackageIndex) read( pkgfile *os.File) {
	p.readHeader(pkgfile)
	p.readBody(pkgfile)
}

func (p* PackageIndex) readHeader( pkgfile *os.File) {
	for k, v := range p._readpkgindex(pkgfile, false) {
		p.header[k] = v
	}
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
		p.header["PACKAGES"] = fmt.Sprint(len(p.packages))
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

