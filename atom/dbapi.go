package atom

import (
	"regexp"
	"sort"
	"strings"
)

type dbapi struct {
	_category_re      *regexp.Regexp
	_use_mutable      bool
	_categories       []string
	_known_keys       map[string]bool
	_pkg_str_aux_keys []string
}

func (d *dbapi) categories() []string {
	if d._categories != nil {
		return d._categories
	}
	m := map[string]bool{}
	for _, x := range d.cp_all(false) {
		m[catsplit(x)[0]] = true
	}
	d._categories = []string{}
	for x := range m {
		d._categories = append(d._categories, x)
	}
	sort.Strings(d._categories)

	return d._categories
}

func (d *dbapi) close_caches() {}

func (d *dbapi) cp_list(cp, use_cache int) { //1
	panic("")
}

func (d *dbapi) _cmp_cpv(cpv1, cpv2 *pkgStr) int {
	result, _ := verCmp(cpv1.version, cpv2.version)
	if (result == 0 && cpv1.buildTime != 0 && cpv2.buildTime != 0) {
		if (cpv1.buildTime > cpv2.buildTime) && (cpv1.buildTime < cpv2.buildTime) {
			result = 0
		} else if !(cpv1.buildTime > cpv2.buildTime) && (cpv1.buildTime < cpv2.buildTime) {
			result = -2
		} else if (cpv1.buildTime > cpv2.buildTime) && !(cpv1.buildTime < cpv2.buildTime) {
			result = 2
		} else { // (cpv1.buildTime > cpv2.buildTime)&&(cpv1.buildTime < cpv2.buildTime)
			result = 0
		}
	}
	return result
}

func (d *dbapi) _cpv_sort_ascending(cpv_list []) {

}

func (d *dbapi) cp_all(sort bool) []string { // f
	panic("")
	return nil
}

func NewDbapi() *dbapi {
	d := &dbapi{}
	d._category_re = regexp.MustCompile(`^\w[-.+\w]*$`)
	d._categories = nil
	d._use_mutable = false
	for x := range auxdbkeys {
		if ! strings.HasPrefix(x, "UNUSED_0") {
			d._known_keys[x] = true
		}
	}
	d._pkg_str_aux_keys = []string{"BUILD_TIME", "EAPI", "BUILD_ID", "KEYWORDS", "SLOT", "repository"}
	return d
}

type ContentsCaseSensitivityManager struct {
	getContents        string
	unmapKey           string
	keys               string
	contentInsensitive string
	reverseKeyMap      string
}

func NewContentsCaseSensitivityManager(db string) *ContentsCaseSensitivityManager {
	return nil
}
