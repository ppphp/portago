package emerge

import (
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/versions"
	"strconv"
	"strings"
)

const _unknown_repo = "__unknown__"

type Package struct {
	*Task
	metadataKeys, buildtimeKeys, runtimeKeys, useConditionalMiscKeys                                                                                                                                 map[string]bool
	depKeys                                                                                                                                                                                          []string
	UnknownRepo                                                                                                                                                                                      string
	built, installed                                                                                                                                                                                 bool
	cpv                                                                                                                                                                                              *versions.PkgStr
	counter, mtime                                                                                                                                                                                   int
	metadata                                                                                                                                                                                         *packageMetadataWrapper
	_raw_metadata                                                                                                                                                                                    map[string]string
	inherited                                                                                                                                                                                        map[string]bool
	depth, onlydeps, operation, type_name, category, cp, cpv_split, iuse, pf, root, slot, sub_slot, slot_atom, version, _invalid, _masks, _provided_cps, _requires, _use, _validated_atoms, _visible string
	Provides                                                                                                                                                                                         map[[2]string]*dep.SonameAtom
	root_config                                                                                                                                                                                      *RootConfig
}

func (p *Package) eapi() string {
	return p.metadata.valueDict["EAPI"]
}

func (p *Package) buildId() int {
	return p.cpv.BuildId
}

func (p *Package) buildTime() int {
	return p.cpv.BuildTime
}

//func (p *Package)definedPhases()string{
//	return p.metadata
//}

func (p *Package) masks() {
	if p._masks == "" {

	}
}

func NewPackage(built bool, cpv *versions.PkgStr, installed bool, metadata map[string]string, root_config *RootConfig, type_name string) *Package {
	p := &Package{metadataKeys: map[string]bool{
		"BDEPEND": true, "BUILD_ID": true, "BUILD_TIME": true, "CHOST": true, "COUNTER": true, "DEFINED_PHASES": true,
		"DEPEND": true, "EAPI": true, "HDEPEND": true, "INHERITED": true, "IUSE": true, "KEYWORDS": true,
		"LICENSE": true, "MD5": true, "PDEPEND": true, "PROVIDES": true, "RDEPEND": true, "repository": true, "REQUIRED_USE": true,
		"PROPERTIES": true, "REQUIRES": true, "RESTRICT": true, "SIZE": true, "SLOT": true, "USE": true, "_mtime_": true,
	}, depKeys: []string{"BDEPEND", "DEPEND", "HDEPEND", "PDEPEND", "RDEPEND"},
		buildtimeKeys:          map[string]bool{"BDEPEND": true, "DEPEND": true, "HDEPEND": true},
		runtimeKeys:            map[string]bool{"PDEPEND": true, "RDEPEND": true},
		useConditionalMiscKeys: map[string]bool{"LICENSE": true, "PROPERTIES": true, "RESTRICT": true},
		UnknownRepo:            _unknown_repo}
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
	return _const.EBUILD_PHASES
}

func NewPackageMetadataWrapper(pkg *Package, metadata map[string]string) *packageMetadataWrapper {
	p := &packageMetadataWrapper{pkg: pkg, valueDict: make(map[string]string), useConditionalKeys: useConditionalKeys, wrappedKeys: wrappedKeys, allMetadataKeys: myutil.CopyMapSB(allMetadataKeys)}
	if !pkg.built {
		p.valueDict["USE"] = ""
	}
	for k, v := range metadata {
		p.valueDict[k] = v
	}
	return p
}
