package atom

import (
	"strconv"
	"strings"
)

type Task struct {
	hashKey   string
	hashValue string
}

func (t *Task) eq(task *Task) bool {
	return t.hashKey == task.hashKey
}

func (t *Task) ne(task *Task) bool {
	return t.hashKey != task.hashKey
}

func (t *Task) hash() string {
	return t.hashValue
}

func (t *Task) len() int {
	return len(t.hashKey)
}

func (t *Task) iter(key string) int {
	return len(t.hashKey)
}

func (t *Task) contains() int {
	return len(t.hashKey)
}

func (t *Task) str() int {
	return len(t.hashKey)
}

func (t *Task) repr() int {
	return len(t.hashKey)
}

type iUse struct {
	__weakref__, _pkg                  string
	tokens                             []string
	iuseImplicitMatch                  func(string) bool
	aliasMapping                       map[string][]string
	all, allAliases, enabled, disabled map[string]bool
}

func (i *iUse) isValidFlag(flags []string) bool {
	for _, flag := range flags {
		if !i.all[flag] && !i.allAliases[flag] && !i.iuseImplicitMatch(flag) {
			return false
		}
	}
	return true
}

func (i *iUse) getMissingIuse(flags []string) []string {
	missingIUse := []string{}
	for _, flag := range flags {
		if !i.all[flag] && !i.allAliases[flag] && !i.iuseImplicitMatch(flag) {
			missingIUse = append(missingIUse, flag)
		}
	}
	return missingIUse
}

func (i *iUse) getRealFlag(flag string) string {
	if i.all[flag] {
		return flag
	} else if i.allAliases[flag] {
		for k, v := range i.aliasMapping {
			for _, x := range v {
				if flag == x {
					return k
				}
			}
		}
	}
	if i.iuseImplicitMatch(flag) {
		return flag
	}
	return ""
}

func NewIUse(pkg string, tokens []string, iuseImplicitMatch func(string) bool, aliases map[string][]string, eapi string) *iUse {
	i := &iUse{}
	i._pkg = pkg
	i.tokens = tokens
	i.iuseImplicitMatch = iuseImplicitMatch
	enabled := []string{}
	disabled := []string{}
	other := []string{}
	enabledAliases := []string{}
	disabledAliases := []string{}
	otherAliases := []string{}
	aliasesSupported := eapiHasUseAliases(eapi)
	i.aliasMapping = map[string][]string{}
	for _, x := range tokens {
		prefix := x[:1]
		if prefix == "+" {
			enabled = append(enabled, x[1:])
			if aliasesSupported {
				if a, ok := aliases[x[1:]]; ok {
					i.aliasMapping[x[1:]] = a
				} else {
					i.aliasMapping[x[1:]] = []string{}
				}
				enabledAliases = append(enabledAliases, i.aliasMapping[x[1:]]...)
			}
		} else if prefix == "-" {
			disabled = append(disabled, x[1:])
			if aliasesSupported {
				if a, ok := aliases[x[1:]]; ok {
					i.aliasMapping[x[1:]] = a
				} else {
					i.aliasMapping[x[1:]] = []string{}
				}
				disabledAliases = append(disabledAliases, i.aliasMapping[x[1:]]...)
			}
		} else {
			other = append(other, x[1:])
			if aliasesSupported {
				if a, ok := aliases[x[1:]]; ok {
					i.aliasMapping[x[1:]] = a
				} else {
					i.aliasMapping[x[1:]] = []string{}
				}
				otherAliases = append(otherAliases, i.aliasMapping[x[1:]]...)
			}
		}
	}
	i.enabled = map[string]bool{}
	for _, x := range append(enabled, enabledAliases...) {
		i.enabled[x] = true
	}
	i.disabled = map[string]bool{}
	for _, x := range append(disabled, disabledAliases...) {
		i.disabled[x] = true
	}
	i.all = map[string]bool{}
	for _, x := range append(append(enabled, disabled...), other...) {
		i.enabled[x] = true
	}
	i.allAliases = map[string]bool{}
	for _, x := range append(append(enabledAliases, disabledAliases...), otherAliases...) {
		i.allAliases[x] = true
	}

	return i
}

type Package struct {
	*Task
	metadataKeys, buildtimeKeys, runtimeKeys, useConditionalMiscKeys                                                                                                                                            map[string]bool
	depKeys                                                                                                                                                                                                     []string
	UnknownRepo                                                                                                                                                                                                 string
	built, installed                                                                                                                                                                                            bool
	cpv                                                                                                                                                                                                         *PkgStr
	counter, mtime                                                                                                                                                                                              int
	metadata                                                                                                                                                                                                    *packageMetadataWrapper
	_raw_metadata                                                                                                                                                                                               map[string]string
	inherited                                                                                                                                                                                                   map[string]bool
	depth, onlydeps, operation, type_name, category, cp, cpv_split, iuse, pf, root, slot, sub_slot, slot_atom, version, _invalid, _masks, _provided_cps, _provides, _requires, _use, _validated_atoms, _visible string
	root_config                                                                                                                                                                                                 *RootConfig
}

func (p *Package) eapi() string {
	return p.metadata.valueDict["EAPI"]
}

func (p *Package) buildId() int {
	return p.cpv.buildId
}

func (p *Package) buildTime() int {
	return p.cpv.buildTime
}

//func (p *Package)definedPhases()string{
//	return p.metadata
//}

func (p *Package) masks() {
	if p._masks == "" {

	}
}

func NewPackage(built bool, cpv *PkgStr, installed bool, metadata map[string]string, root_config *RootConfig, type_name string) *Package {
	p := &Package{metadataKeys: map[string]bool{
		"BDEPEND": true, "BUILD_ID": true, "BUILD_TIME": true, "CHOST": true, "COUNTER": true, "DEFINED_PHASES": true,
		"DEPEND": true, "EAPI": true, "HDEPEND": true, "INHERITED": true, "IUSE": true, "KEYWORDS": true,
		"LICENSE": true, "MD5": true, "PDEPEND": true, "PROVIDES": true, "RDEPEND": true, "repository": true, "REQUIRED_USE": true,
		"PROPERTIES": true, "REQUIRES": true, "RESTRICT": true, "SIZE": true, "SLOT": true, "USE": true, "_mtime_": true,
	}, depKeys: []string{"BDEPEND", "DEPEND", "HDEPEND", "PDEPEND", "RDEPEND"},
		buildtimeKeys:          map[string]bool{"BDEPEND": true, "DEPEND": true, "HDEPEND": true},
		runtimeKeys:            map[string]bool{"PDEPEND": true, "RDEPEND": true},
		useConditionalMiscKeys: map[string]bool{"LICENSE": true, "PROPERTIES": true, "RESTRICT": true},
		UnknownRepo:            unknownRepo}
	p.built = built
	p.cpv = cpv
	p.installed = installed
	p.root_config = root_config
	p.type_name = type_name

	//p.root = p.root_config.root
	p._raw_metadata = metadata

	p.metadata = NewPackageMetadataWrapper(p, metadata)

	return p
}

var allMetadataKeys = map[string]bool{
	"DEPEND": true, "RDEPEND": true, "SLOT": true, "SRC_URI": true,
	"RESTRICT": true, "HOMEPAGE": true, "LICENSE": true, "DESCRIPTION": true,
	"KEYWORDS": true, "INHERITED": true, "IUSE": true, "REQUIRED_USE": true,
	"PDEPEND": true, "BDEPEND": true, "EAPI": true, "PROPERTIES": true,
	"DEFINED_PHASES": true, "HDEPEND": true, "BUILD_ID": true, "BUILD_TIME": true,
	"CHOST": true, "COUNTER": true, "MD5": true, "PROVIDES": true,
	"repository": true, "REQUIRES": true, "SIZE": true, "USE": true, "_mtime_": true,
}

var wrappedKeys = map[string]bool{
	"COUNTER": true, "INHERITED": true, "USE": true, "_mtime_": true,
}

var useConditionalKeys = map[string]bool{
	"LICENSE": true, "PROPERTIES": true, "RESTRICT": true,
}

type packageMetadataWrapper struct {
	valueDict                                        map[string]string
	pkg                                              *Package
	allMetadataKeys, wrappedKeys, useConditionalKeys map[string]bool
}

func (p *packageMetadataWrapper) setItem(k, v string) {
	if p.allMetadataKeys[k] {
		p.valueDict[k] = v
	}
	switch k {
	case "COUNTER":
		p.setCounter(k, v)
	case "INHERITED":
		p.setInherited(k, v)
	case "USE":
		p.setUse(k, v)
	case "_mtime_":
		p.setMtime(k, v)
	}
}

func (p *packageMetadataWrapper) setInherited(k, v string) {
	p.pkg.inherited = map[string]bool{}
	for _, f := range strings.Fields(v) {
		p.pkg.inherited[f] = true
	}
}

func (p *packageMetadataWrapper) setCounter(k, v string) {
	n, _ := strconv.Atoi(v)
	p.pkg.counter = n
}

func (p *packageMetadataWrapper) setUse(k, v string) {
	p.pkg._use = ""
	rawMetadata := p.pkg._raw_metadata
	for x := range p.useConditionalKeys {
		if v, ok := rawMetadata[x]; ok {
			p.valueDict[x] = v
		}
	}
}

func (p *packageMetadataWrapper) setMtime(k, v string) {
	n, _ := strconv.Atoi(v)
	p.pkg.mtime = n
}

func (p *packageMetadataWrapper) properties() []string {
	return strings.Fields(p.valueDict["PROPERTIES"])
}

func (p *packageMetadataWrapper) restrict() []string {
	return strings.Fields(p.valueDict["RESTRICT"])
}

func (p *packageMetadataWrapper) definedPhases() map[string]bool {
	if s, ok := p.valueDict["DEFINED_PHASES"]; ok {
		phases := map[string]bool{}
		for _, v := range strings.Fields(s) {
			phases[v] = true
		}
		return phases
	}
	return EBUILD_PHASES
}

func NewPackageMetadataWrapper(pkg *Package, metadata map[string]string) *packageMetadataWrapper {
	p := &packageMetadataWrapper{pkg: pkg, valueDict: make(map[string]string), useConditionalKeys: useConditionalKeys, wrappedKeys: wrappedKeys, allMetadataKeys: CopyMapSB(allMetadataKeys)}
	if !pkg.built {
		p.valueDict["USE"] = ""
	}
	for k, v := range metadata {
		p.valueDict[k] = v
	}
	return p
}
