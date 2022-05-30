package ebuild

import (
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/util"
	"path"
	"strings"
)

type KeywordsManager struct {
	pkeywordsList, pAcceptKeywords []map[string]map[*dep.Atom][]string
	pkeywordsDict                  map[string]map[*dep.Atom][]string
}

func NewKeywordsManager(profiles []*profileNode, absUserConfig string, userConfig bool, globalAcceptKeywords string) *KeywordsManager { // t""
	k := &KeywordsManager{}
	k.pkeywordsList = []map[string]map[*dep.Atom][]string{}
	rawPkeywords := []map[*dep.Atom][]string{}
	for _, x := range profiles {
		rawPkeywords = append(rawPkeywords, util.GrabDictPackage(path.Join(x.location, "package.keywords"), false, x.portage1Directories, false, false, false, x.allowBuildId, false, true, x.eapi, ""))
	}
	for _, pkeyworddict := range rawPkeywords {
		if len(pkeyworddict) == 0 {
			continue
		}
		cpdict := map[string]map[*dep.Atom][]string{}
		for k, v := range pkeyworddict {
			if _, ok := cpdict[k.Cp]; !ok {
				cpdict[k.Cp] = map[*dep.Atom][]string{k: v}
			} else {
				cpdict[k.Cp][k] = v
			}
		}
		k.pkeywordsList = append(k.pkeywordsList, cpdict)
	}
	k.pAcceptKeywords = []map[string]map[*dep.Atom][]string{}
	rawPAcceptKeywords := []map[*dep.Atom][]string{}
	for _, x := range profiles {
		rawPAcceptKeywords = append(rawPAcceptKeywords, util.GrabDictPackage(path.Join(x.location, "package.accept_keywords"), false, x.portage1Directories, false, false, false, false, false, true, x.eapi, ""))
	}
	for _, d := range rawPAcceptKeywords {
		if len(d) == 0 {
			continue
		}
		cpdict := map[string]map[*dep.Atom][]string{}
		for k, v := range d {
			if _, ok := cpdict[k.Cp]; !ok {
				cpdict[k.Cp] = map[*dep.Atom][]string{k: v}
			} else {
				cpdict[k.Cp][k] = v
			}
		}
		k.pAcceptKeywords = append(k.pAcceptKeywords, cpdict)
	}

	k.pkeywordsDict = map[string]map[*dep.Atom][]string{}
	if userConfig {
		pkgDict := util.GrabDictPackage(path.Join(absUserConfig, "package.keywords"), false, true, false, true, true, true, false, true, "", "")
		for k, v := range util.GrabDictPackage(path.Join(absUserConfig, "package.accept_keywords"), false, true, false, true, true, true, false, true, "", "") {
			if _, ok := pkgDict[k]; !ok {
				pkgDict[k] = v
			} else {
				pkgDict[k] = append(pkgDict[k], v...)
			}
		}
		acceptKeywordDefaults := []string{}
		a := strings.Fields(globalAcceptKeywords)
		for _, v := range a {
			if v[:1] != "~" && v[:1] != "-" {
				acceptKeywordDefaults = append(acceptKeywordDefaults, "~"+v)
			}
		}
		for k1, v := range pkgDict {
			if len(v) == 0 {
				v = acceptKeywordDefaults
			}
			if _, ok := k.pkeywordsDict[k1.Cp]; !ok {
				k.pkeywordsDict[k1.Cp] = map[*dep.Atom][]string{k1: v}
			} else {
				k.pkeywordsDict[k1.Cp][k1] = v
			}
		}
	}
	return k
}

func (k *KeywordsManager) getKeywords(cpv *PkgStr, slot, keywords, repo string) map[*dep.Atom]string {
	pkg := cpv
	cp := pkg.cp
	kw := [][][2]string{{}}
	for _, x := range strings.Fields(keywords) {
		if x != "-*" {
			kw[0] = append(kw[0], [2]string{x, ""})
		}
	}
	for _, pkeywordsDict := range k.pkeywordsList {
		cpdict := pkeywordsDict[cp]
		if len(cpdict) > 0 {
			pkgKeywords := orderedByAtomSpecificity(cpdict, pkg, "")
			if len(pkgKeywords) > 0 {
				for _, v := range pkgKeywords {
					x := [][2]string{}
					for _, y := range v {
						x = append(x, [2]string{y})
					}
					kw = append(kw, x)
				}
			}
		}
	}
	return util.StackLists(kw, 1, false, false, false, false)
}

func (k *KeywordsManager) isStable(pkg *PkgStr, globalAcceptKeywords, backupedAcceptKeywords string) bool {
	myGroups := k.getKeywords(pkg, "", pkg.metadata["KEYWORDS"], "")
	pGroups := strings.Fields(globalAcceptKeywords)
	unmaskGroups := k.getPKeywords(pkg, "", "", globalAcceptKeywords)
	pGroups = append(pGroups, unmaskGroups...)
	eGroups := strings.Fields(backupedAcceptKeywords)
	pgroups := map[string]bool{}
	if len(unmaskGroups) > 0 || len(eGroups) > 0 {
		pgroups = k.getEgroups(eGroups, pGroups)
	} else {
		for _, v := range pGroups {
			pgroups[v] = true
		}
	}
	if len(k._getMissingKeywords(pkg, pgroups, myGroups)) > 0 {
		return false
	}
	unstable := map[*dep.Atom]string{}
	for _, kw := range myGroups {
		if kw[:1] != "~" {
			kw = "~" + kw
		}
		unstable[&dep.Atom{Value: kw}] = ""
	}
	return len(k._getMissingKeywords(pkg, pgroups, unstable)) > 0
}

func (k *KeywordsManager) GetMissingKeywords(cpv *PkgStr, slot, keywords, repo, globalAcceptKeywords, backupedAcceptKeywords string) map[*dep.Atom]string {
	mygroups := k.getKeywords(cpv, slot, keywords, repo)
	pGroups := strings.Fields(globalAcceptKeywords)
	unmaskGroups := k.getPKeywords(cpv, slot, repo, globalAcceptKeywords)
	pGroups = append(pGroups, unmaskGroups...)
	eGroups := strings.Fields(backupedAcceptKeywords)
	pgroups := map[string]bool{}
	if len(unmaskGroups) > 0 || len(eGroups) > 0 {
		pgroups = k.getEgroups(eGroups, pGroups)
	} else {
		for _, v := range pGroups {
			pgroups[v] = true
		}
	}
	return k._getMissingKeywords(cpv, pgroups, mygroups)
}

func (k *KeywordsManager) getRawMissingKeywords(cpv *PkgStr, slot, keywords, repo, globalAcceptKeywords string) map[*dep.Atom]string {
	mygroups := k.getKeywords(cpv, slot, keywords, repo)
	pGroups := strings.Fields(globalAcceptKeywords)
	pgroups := map[string]bool{}
	for _, v := range pGroups {
		pgroups[v] = true
	}
	return k._getMissingKeywords(cpv, pgroups, mygroups)
}

func (k *KeywordsManager) getEgroups(egroups, mygroups []string) map[string]bool {
	mygroups = append(mygroups[:0:0], mygroups...)
	mygroups = append(mygroups, egroups...)
	incPGroups := map[string]bool{}
	for _, x := range mygroups {
		if x[:1] == "-" {
			if x == "-*" {
				incPGroups = map[string]bool{}
			} else {
				delete(incPGroups, x[1:])
			}
		} else {
			incPGroups[x] = true
		}
	}
	return incPGroups
}

func (k *KeywordsManager) _getMissingKeywords(cpv *PkgStr, pgroups map[string]bool, mygroups map[*dep.Atom]string) map[*dep.Atom]string {
	match := false
	hasstable := false
	hastesting := false
	for gp := range mygroups {
		if gp.Value == "*" {
			match = true
			break
		} else if gp.Value == "~*" {
			hastesting = true
			for x := range pgroups {
				if x[:1] == "~" {
					match = true
					break
				}
			}
			if match {
				break
			}
		} else if pgroups[gp.Value] {
			match = true
			break
		} else if strings.HasPrefix(gp.Value, "~") {
			hastesting = true
		} else if !strings.HasPrefix(gp.Value, "-") {
			hasstable = true
		}
	}
	if !match && ((hastesting && pgroups["~*"]) || (hasstable && pgroups["*"]) || pgroups["**"]) {
		match = true
	}
	if match {
		return map[*dep.Atom]string{}
	} else {
		if len(mygroups) == 0 {
			mygroups = map[*dep.Atom]string{{Value: "**"}: ""}
		}
		return mygroups
	}
}

func (k *KeywordsManager) getPKeywords(cpv *PkgStr, slot, repo, globalAcceptKeywords string) []string {
	pgroups := strings.Fields(globalAcceptKeywords)
	cp := cpv.cp
	unmaskGroups := []string{}
	if len(k.pAcceptKeywords) > 0 {
		acceptKeyWordsDefaults := []string{}
		for _, keyword := range pgroups {
			if keyword[:1] != "~" && keyword[:1] != "-" {
				acceptKeyWordsDefaults = append(acceptKeyWordsDefaults, "~"+keyword)
			}
			for _, d := range k.pAcceptKeywords {
				cpDict := d[cp]
				if len(cpDict) > 0 {
					pkgAcceptKeywords := orderedByAtomSpecificity(cpDict, cpv, "")
					if len(pkgAcceptKeywords) > 0 {
						for _, x := range pkgAcceptKeywords {
							unmaskGroups = append(unmaskGroups, x...)
						}
					}
				}
			}
		}
	}
	pkgDict := k.pkeywordsDict[cp]
	if len(pkgDict) > 0 {
		pkgAcceptKeywords := orderedByAtomSpecificity(pkgDict, cpv, "")
		if len(pkgAcceptKeywords) > 0 {
			for _, x := range pkgAcceptKeywords {
				unmaskGroups = append(unmaskGroups, x...)
			}
		}
	}
	return unmaskGroups
}
