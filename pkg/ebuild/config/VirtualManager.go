package config

import (
	"fmt"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/util/grab"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"path"
	"strings"
)

type VirtualManager struct {
	_dirVirtuals, _virtuals, _treeVirtuals, _depgraphVirtuals, _virts_p map[string][]string
}

func (v *VirtualManager) read_dirVirtuals(profiles []string) {
	virtualsList := []map[string][]string{}
	for _, x := range profiles {
		virtualsFile := path.Join(x, "virtuals")
		virtualsDict := grab.GrabDict(virtualsFile, false, false, false, false, false)
		atomsDict := map[string][]string{}
		for k, v := range virtualsDict {
			virtAtom, err := dep.NewAtom(k, nil, false, nil, nil, "", nil, nil)
			if err != nil {
				virtAtom = nil
			} else {
				if virtAtom.Blocker != nil || virtAtom.Value != virtAtom.Cp {
					virtAtom = nil
				}
			}
			if virtAtom == nil {
				msg.WriteMsg(fmt.Sprintf("--- Invalid virtuals Atom in %s: %s\n", virtualsFile, k), -1, nil)
				continue
			}
			providers := []string{}
			for _, atom := range v {
				atomOrig := atom
				if atom[:1] == "-" {
					atom = atom[1:]
				}
				atomA, err := dep.NewAtom(atom, nil, false, nil, nil, "", nil, nil)
				if err != nil {
					atomA = nil
				} else {
					if atomA.Blocker != nil {
						atomA = nil
					}
				}
				if atomA == nil {
					msg.WriteMsg(fmt.Sprintf("--- Invalid Atom in %s: %s\n", virtualsFile, atomOrig), -1, nil)
				} else {
					if atomOrig == atomA.Value {
						providers = append(providers, atom)
					} else {
						providers = append(providers, atomOrig)
					}
				}
			}
			if len(providers) > 0 {
				atomsDict[virtAtom.Value] = providers
			}
		}
		if len(atomsDict) > 0 {
			virtualsList = append(virtualsList, atomsDict)
		}
	}

	v._dirVirtuals = grab.StackDictList(virtualsList, 1, nil, 0)

	for virt := range v._dirVirtuals {
		myutil.ReverseSlice(v._dirVirtuals[virt])
	}
}

func (v *VirtualManager) _compile_virtuals() {
	ptVirtuals := map[string][]string{}

	for virt, installedList := range v._treeVirtuals {
		profileList := v._dirVirtuals[virt]
		if len(profileList) == 0 {
			continue
		}
		for _, cp := range installedList {
			if myutil.Ins(profileList, cp) {
				if _, ok := ptVirtuals[virt]; !ok {
					ptVirtuals[virt] = []string{cp}
				} else {
					ptVirtuals[virt] = append(ptVirtuals[virt], cp)
				}
			}
		}
	}

	virtuals := grab.StackDictList([]map[string][]string{ptVirtuals, v._treeVirtuals, v._dirVirtuals, v._depgraphVirtuals}, 0, nil, 0)
	v._virtuals = virtuals
	v._virts_p = nil
}

func (v *VirtualManager) getvirtuals() map[string][]string {
	if v._treeVirtuals != nil {
		panic("_populate_treeVirtuals() must be called before any query about virtuals")
	}
	if v._virtuals == nil {
		v._compile_virtuals()
	}
	return v._virtuals
}

func (v *VirtualManager) deepcopy() *VirtualManager {
	return v
}

func (v *VirtualManager) getVirtsP() map[string][]string {
	if v._virts_p != nil {
		return v._virts_p
	}
	virts := v.getvirtuals()
	virtsP := map[string][]string{}
	for x := range virts {
		vkeysplit := strings.Split(x, "/")
		if _, ok := virtsP[vkeysplit[1]]; !ok {
			virtsP[vkeysplit[1]] = virts[x]
		}
	}
	v._virts_p = virtsP
	return virtsP
}

func (v *VirtualManager) _populate_treeVirtuals(vartree interfaces.IVarTree) {
	if v._treeVirtuals != nil {
		panic("treeVirtuals must not be reinitialized")
	}
	v._treeVirtuals = map[string][]string{}

	for provide, cpvList := range vartree.Get_all_provides() {
		provideA, err := dep.NewAtom(provide, nil, false, nil, nil, "", nil, nil)
		if err != nil {
			continue
		}
		v._treeVirtuals[provideA.Cp] = []string{}
		for _, cpv := range cpvList {
			v._treeVirtuals[provideA.Cp] = append(v._treeVirtuals[provideA.Cp], cpv.GetCp())
		}
	}
}

func (v *VirtualManager) populate_treeVirtuals_if_needed(vartree interfaces.IVarTree) {
	if v._treeVirtuals != nil {
		return
	}
	v._populate_treeVirtuals(vartree)
}

func (v *VirtualManager) add_depgraph_virtuals(mycpv string, virts []string) {
	if v._virtuals == nil {
		v.getvirtuals()
	}

	modified := false
	cp, _ := dep.NewAtom(versions.CpvGetKey(mycpv, ""), nil, false, nil, nil, "", nil, nil)
	for _, virt := range virts {
		a, err := dep.NewAtom(virt, nil, false, nil, nil, "", nil, nil)
		if err != nil {
			continue
		}
		virt = a.Cp
		providers := v._depgraphVirtuals[virt]
		if providers == nil {
			providers = []string{}
			v._depgraphVirtuals[virt] = providers
		}
		if !myutil.Ins(providers, cp.Value) {
			providers = append(providers, cp.Value)
			modified = true
		}
	}
	if modified {
		v._compile_virtuals()
	}
}

func NewVirtualManager(profiles []string) *VirtualManager {
	v := &VirtualManager{}
	v._virtuals = nil
	v._dirVirtuals = nil
	v._virts_p = nil
	v._treeVirtuals = nil
	v._depgraphVirtuals = map[string][]string{}
	v.read_dirVirtuals(profiles)
	return v
}
