package getbinpkg

import (
	"fmt"
	"github.com/ppphp/portago/pkg/myutil"
	"io"
	"io/ioutil"
	"sort"
	"strings"
	"time"
)

func _cmp_cpv(d1, d2 map[string]string) int {
	cpv1 := d1["CPV"]
	cpv2 := d2["CPV"]
	if cpv1 > cpv2 {
		return 1
	} else if cpv1 == cpv2 {
		return 0
	} else {
		return -1
	}
}

type PackageIndex struct {
	modified                                                                                       bool
	header, _default_header_data, _write_translation_map, _read_translation_map, _default_pkg_data map[string]string
	packages                                                                                       []map[string]string
	_pkg_slot_dict                                                                                 func() map[string]string
	_inherited_keys                                                                                []string
}

// nil, nil, nil, nil, nil
func NewPackageIndex(allowedPkgKeys map[string]bool, defaultHeaderData map[string]string,
	defaultPkgData map[string]string, inheritedKeys []string, translatedKeys [][2]string) *PackageIndex {
	p := &PackageIndex{}

	p._pkg_slot_dict = nil
	if len(allowedPkgKeys) > 0 {
		p._pkg_slot_dict = func() map[string]string {
			return map[string]string{}
		} //slot_dict_class(allowed_pkg_keys)
	}

	p._default_header_data = defaultHeaderData
	p._default_pkg_data = defaultPkgData
	p._inherited_keys = inheritedKeys
	p._write_translation_map = map[string]string{}
	p._read_translation_map = map[string]string{}
	if len(translatedKeys) > 0 {
		for _, x := range translatedKeys {
			k, v := x[0], x[1]
			p._write_translation_map[k] = v
		}
		for _, x := range translatedKeys {
			k, v := x[0], x[1]
			p._read_translation_map[v] = k
		}
	}
	p.header = map[string]string{}
	if len(p._default_header_data) != 0 {
		for k, v := range p._default_header_data {
			p.header[k] = v
		}
	}
	p.packages = []map[string]string{}
	p.modified = true

	return p
}

// true
func (p *PackageIndex) _readpkgindex(pkgfile io.Reader, pkg_entry bool) map[string]string {
	d := map[string]string{}
	var allowed_keys []string = nil
	if p._pkg_slot_dict == nil && pkg_entry {
		d = p._pkg_slot_dict()
		allowed_keys = []string{}
	}

	b, _ := ioutil.ReadAll(pkgfile)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\n")
		if line == "" {
			break
		}
		lines := strings.SplitN(line, ":", 2)
		if len(lines) != 2 {
			continue
		}
		k, v := lines[0], lines[1]
		if v != "" {
			v = v[1:]
		}
		if v, ok := p._read_translation_map[k]; ok {
			k = v
		}
		if allowed_keys != nil && !myutil.Ins(allowed_keys, k) {
			continue
		}
		d[k] = v
	}
	return d
}

func (p *PackageIndex) _writepkgindex(pkgfile io.Writer, items [][2]string) {
	for _, x := range items {
		k, v := x[0], x[1]
		a, ok := p._write_translation_map[k]
		if !ok {
			a = k
		}
		pkgfile.Write([]byte(fmt.Sprintf("%s: %s\n", a, v)))
	}
	pkgfile.Write([]byte("\n"))
}

func (p *PackageIndex) read(pkgfile io.Reader) {
	p.readHeader(pkgfile)
	p.readBody(pkgfile)
}

func (p *PackageIndex) readHeader(pkgfile io.Reader) {
	for k, v := range p._readpkgindex(pkgfile, false) {
		p.header[k] = v
	}
}

func (p *PackageIndex) readBody(pkgfile io.Reader) {
	for {
		d := p._readpkgindex(pkgfile, true)
		if len(d) == 0 {
			break
		}
		mycpv := d["CPV"]
		if len(mycpv) == 0 {
			continue
		}
		if len(p._default_pkg_data) != 0 {
			for k, v := range p._default_pkg_data {
				if _, ok := d[k]; !ok {
					d[k] = v
				}
			}
		}
		if len(p._inherited_keys) != 0 {
			for _, k := range p._inherited_keys {
				v := p.header[k]
				if v != "" {
					if _, ok := d[k]; !ok {
						d[k] = v
					}
				}
			}
		}
		p.packages = append(p.packages, d)
	}
}

func (p *PackageIndex) write(pkgfile io.Writer) {
	if p.modified {
		p.header["TIMESTAMP"] = fmt.Sprint(time.Now().Unix())
		p.header["PACKAGES"] = fmt.Sprint(len(p.packages))
	}
	keys := myutil.SortedMS[string](p.header)
	s := [][2]string{}
	for _, k := range keys {
		if len(p.header[k]) != 0 {
			s = append(s, [2]string{k, p.header[k]})
		}
	}

	p._writepkgindex(pkgfile, s)
	sort.Slice(p.packages, func(i, j int) bool {
		return _cmp_cpv(p.packages[i], p.packages[j]) < 0
	})
	for _, metadata := range p.packages {
		metadata = myutil.CopyMapSS(metadata)
		if len(p._inherited_keys) != 0 {
			for _, k := range p._inherited_keys {
				v := p.header[k]
				if v != "" && v == metadata[k] {
					delete(metadata, k)
				}
			}
		}
		if len(p._default_pkg_data) != 0 {
			for k, v := range p._default_pkg_data {
				if metadata[k] == v {
					delete(metadata, k)
				}
			}
		}
		keys := myutil.SortedMS[string](metadata)

		s := [][2]string{}
		for _, k := range keys {
			if metadata[k] != "" {
				s = append(s, [2]string{k, metadata[k]})
			}
		}
		p._writepkgindex(pkgfile, s)
	}
}
