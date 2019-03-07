package atom

import (
	"strconv"
	"strings"
)

var (
	depKeys                = map[string]bool{"BDEPEND": true, "DEPEND": true, "HDEPEND": true, "PDEPEND": true, "RDEPEND": true}
	buildtimeKeys          = map[string]bool{"BDEPEND": true, "DEPEND": true, "HDEPEND": true}
	runtimeKeys            = map[string]bool{"PDEPEND": true, "RDEPEND": true}
	useConditionalMiscKeys = map[string]bool{"LICENSE": true, "PROPERTIES": true, "RESTRICT": true}

	metadata_keys = map[string]bool{
		"BDEPEND": true, "BUILD_ID": true, "BUILD_TIME": true, "CHOST": true, "COUNTER": true, "DEFINED_PHASES": true,
		"DEPEND": true, "EAPI": true, "HDEPEND": true, "INHERITED": true, "IUSE": true, "KEYWORDS": true,
		"LICENSE": true, "MD5": true, "PDEPEND": true, "PROVIDES": true, "RDEPEND": true, "repository": true, "REQUIRED_USE": true,
		"PROPERTIES": true, "REQUIRES": true, "RESTRICT": true, "SIZE": true, "SLOT": true, "USE": true, "_mtime_": true,
	}
)

type Task struct {
	hashKey   string
	hashValue string
}

func (t *Task) eq(task Task) bool {
	return t.hashKey == task.hashKey
}

func (t *Task) ne(task Task) bool {
	return t.hashKey != task.hashKey
}

func (t *Task) hash() string {
	return t.hashValue
}

func (t *Task) len() int {
	return len(t.hashKey)
}

type Package struct {
	built                                                                                                                                                                                                                              bool
	cpv                                                                                                                                                                                                                                *pkgStr
	counter, mtime                                                                                                                                                                                                                     int
	metadata, _raw_metadata                                                                                                                                                                                                            map[string]string
	inherited                                                                                                                                                                                                                          map[string]bool
	depth, installed, onlydeps, peration, root_config, type_name, category, cp, cpv_split, iuse, pf, root, slot, sub_slot, slot_atom, version, _invalid, _masks, _provided_cps, _provides, _requires, _use, _validated_atoms, _visible string
}

func (p *Package) eapi() string {
	return p.metadata["EAPI"]
}

func (p *Package) buildId() string {
	return p.cpv.build_id
}

func (p *Package) buildTime() string {
	return p.cpv.build_time
}

//func (p *Package)definedPhases()string{
//	return p.metadata
//}

func (p *Package) masks() {
	if p._masks == "" {

	}
}

//func NewPackage()

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
	valueDict                                 map[string]string
	pkg                                       *Package
	allMetadataKeys, wrappedKeys, useConditionalKeys map[string]bool
}

func (p *packageMetadataWrapper) setItem(k, v string) {
	if p.allMetadataKeys[k] {
		p.valueDict[k]=v
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
