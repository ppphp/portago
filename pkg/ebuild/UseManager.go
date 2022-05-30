package ebuild

import (
	"fmt"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/repository"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/grab"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"path"
	"strings"
)

type UseManager struct {
	userConfig                                                                                         bool
	isStable                                                                                           func(str interfaces.IPkgStr) bool
	repoUsemaskDict, repoUsestablemaskDict, repoUseforceDict, repoUsestableforceDict                   map[string][]string
	repoPusemaskDict, repoPusestablemaskDict, repoPuseforceDict, repoPusestableforceDict, repoPuseDict map[string]map[string]map[*dep.Atom][]string
	usemaskList, usestablemaskList, useforceList, usestableforceList                                   [][]string
	pusemaskList, pusestablemaskList, pkgprofileuse, puseforceList, pusestableforceList                []map[string]map[*dep.Atom][]string
	pUseDict                                                                                           map[string]map[*dep.Atom][]string // extatom
	repoUsealiasesDict                                                                                 map[string]map[string][]string
	repoPusealiasesDict                                                                                map[string]map[string]map[*dep.Atom]map[string][]string
	repositories                                                                                       *repository.RepoConfigLoader
}

// true
func NewUseManager(repositories *repository.RepoConfigLoader, profiles []*profileNode, absUserConfig string, isStable func(str interfaces.IPkgStr) bool, userConfig bool) *UseManager {
	u := &UseManager{}
	u.userConfig = userConfig
	u.isStable = isStable
	u.repoUsemaskDict = u.parseRepositoryFilesToDictOfTuples("use.mask", repositories, nil)
	u.repoUsestablemaskDict = u.parseRepositoryFilesToDictOfTuples("use.stable.mask", repositories, eapi.EapiSupportsStableUseForcingAndMasking)
	u.repoUseforceDict = u.parseRepositoryFilesToDictOfTuples("use.force", repositories, nil)
	u.repoUsestableforceDict = u.parseRepositoryFilesToDictOfTuples("use.stable.force", repositories, eapi.EapiSupportsStableUseForcingAndMasking)
	u.repoPusemaskDict = u.parseRepositoryFilesToDictOfDicts("package.use.mask", repositories, nil)
	u.repoPusestablemaskDict = u.parseRepositoryFilesToDictOfDicts("package.use.stable.mask", repositories, eapi.EapiSupportsStableUseForcingAndMasking)
	u.repoPuseforceDict = u.parseRepositoryFilesToDictOfDicts("package.use.force", repositories, nil)
	u.repoPusestableforceDict = u.parseRepositoryFilesToDictOfDicts("package.use.stable.force", repositories, eapi.EapiSupportsStableUseForcingAndMasking)
	u.repoPuseDict = u.parseRepositoryFilesToDictOfDicts("package.use", repositories, nil)

	u.usemaskList = u.parseProfileFilesToTupleOfTuples("use.mask", profiles, nil)
	u.usestablemaskList = u.parseProfileFilesToTupleOfTuples("use.stable.mask", profiles, eapi.EapiSupportsStableUseForcingAndMasking)
	u.useforceList = u.parseProfileFilesToTupleOfTuples("use.force", profiles, nil)
	u.usestableforceList = u.parseProfileFilesToTupleOfTuples("use.stable.force", profiles, eapi.EapiSupportsStableUseForcingAndMasking)
	u.pusemaskList = u.parseProfileFilesToTupleOfDicts("package.use.mask", profiles, false, nil)
	u.pusestablemaskList = u.parseProfileFilesToTupleOfDicts("package.use.stable.mask", profiles, false, eapi.EapiSupportsStableUseForcingAndMasking)
	u.pkgprofileuse = u.parseProfileFilesToTupleOfDicts("package.use", profiles, true, nil)
	u.puseforceList = u.parseProfileFilesToTupleOfDicts("package.use.force", profiles, false, nil)
	u.pusestableforceList = u.parseProfileFilesToTupleOfDicts("package.use.stable.force", profiles, false, eapi.EapiSupportsStableUseForcingAndMasking)

	u.pUseDict = u.parseUserFilesToExtatomdict("package.use", absUserConfig, userConfig)

	u.repoUsealiasesDict = u.parseRepositoryUsealiases(repositories)
	u.repoPusealiasesDict = u.parseRepositoryPackageusealiases(repositories)

	u.repositories = repositories
	return u
}

func (u *UseManager) parseFileToTuple(fileName string, recursive bool, eapiFilter func(string) bool, eapi, eapiDefault string) []string { // tnn"0"
	ret := []string{}
	lines := grab.GrabFile(fileName, 0, true, false)
	if eapi == "" {
		eapi = util.ReadCorrespondingEapiFile(fileName, eapiDefault)
	}
	if eapiFilter != nil && !eapiFilter(eapi) {
		if len(lines) > 0 {
			msg.WriteMsg(fmt.Sprintf("--- EAPI '%s' does not support '%s': '%s'\n", eapi, path.Base(fileName), fileName), -1, nil)
		}
		return ret
	}
	useFlagRe := dep.GetUseflagRe(eapi)
	for _, v := range lines {
		prefixedUseflag := v[0]
		useflag := ""
		if prefixedUseflag[:1] == "-" {
			useflag = prefixedUseflag[1:]
		} else {
			useflag = prefixedUseflag
		}
		if !useFlagRe.MatchString(useflag) {
			msg.WriteMsg(fmt.Sprintf("--- Invalid USE flag in '%s': '%s'\n", fileName, prefixedUseflag), -1, nil)
		} else {
			ret = append(ret, prefixedUseflag)
		}
	}

	return ret
}

func (u *UseManager) parseFileToDict(fileName string, justStrings, recursive bool, eapiFilter func(string) bool, userConfig bool, eapi, eapiDefault string, allowBuildId bool) map[string]map[*dep.Atom][]string { //ftnfn"0"f
	ret := map[string]map[*dep.Atom][]string{}
	locationDict := map[*dep.Atom][]string{}
	if eapi == "" {
		eapi = util.ReadCorrespondingEapiFile(fileName, eapiDefault)
	}
	extendedSyntax := eapi == "" && userConfig
	if extendedSyntax {
		ret = map[string]map[*dep.Atom][]string{}
	} else {
		ret = map[string]map[*dep.Atom][]string{}
	}
	fileDict := util.GrabDictPackage(fileName, false, recursive, false, extendedSyntax, extendedSyntax, !extendedSyntax, allowBuildId, false, eapi, eapiDefault)
	if eapi != "" && eapiFilter != nil && !eapiFilter(eapi) {
		if len(fileDict) > 0 {
			msg.WriteMsg(fmt.Sprintf("--- EAPI '%s' does not support '%s': '%s'\n", eapi, path.Base(fileName), fileName), -1, nil)
		}
		return ret
	}
	useFlagRe := dep.GetUseflagRe(eapi)
	for k, v := range fileDict {
		useFlags := []string{}
		useExpandPrefix := ""
		for _, prefixedUseFlag := range v {
			if extendedSyntax && prefixedUseFlag == "\n" {
				useExpandPrefix = ""
				continue
			}
			if extendedSyntax && prefixedUseFlag[len(prefixedUseFlag)-1:] == ":" {
				useExpandPrefix = strings.ToLower(prefixedUseFlag[:len(prefixedUseFlag)-1]) + "_"
				continue
			}
			useFlag := ""
			if prefixedUseFlag[:1] == "-" {
				useFlag = useExpandPrefix + prefixedUseFlag[1:]
				prefixedUseFlag = "-" + useFlag
			} else {
				useFlag = useExpandPrefix + prefixedUseFlag
				prefixedUseFlag = "-" + useFlag
			}
			if !useFlagRe.MatchString(useFlag) {
				msg.WriteMsg(fmt.Sprintf("--- Invalid USE flag for '%v' in '%s': '%s'\n", k, fileName, prefixedUseFlag), -1, nil)
			} else {
				useFlags = append(useFlags, prefixedUseFlag)
			}
		}
		if _, ok := locationDict[k]; ok {
			locationDict[k] = append(locationDict[k], useFlags...)
		} else {
			locationDict[k] = useFlags
		}
	}
	for k, v := range locationDict {
		s := []string{}
		if justStrings {
			s = []string{strings.Join(v, " ")}
		}
		if _, ok := ret[k.cp]; !ok {
			ret[k.cp] = map[*dep.Atom][]string{k: s}
		} else {
			ret[k.cp][k] = v
		}
	}
	return ret
}

func (u *UseManager) parseUserFilesToExtatomdict(fileName, location string, userConfig bool) map[string]map[*dep.Atom][]string {
	ret := map[string]map[*dep.Atom][]string{}
	if userConfig {
		puseDict := util.GrabDictPackage(path.Join(location, fileName), false, true, true, true, true, true, false, false, "", "")
		for k, v := range puseDict {
			l := []string{}
			useExpandPrefix := ""
			for _, flag := range v {
				if flag == "\n" {
					useExpandPrefix = ""
					continue
				}
				if flag[len(flag)-1] == ':' {
					useExpandPrefix = strings.ToLower(flag[:len(flag)-1]) + "_"
					continue
				}
				nv := ""
				if flag[0] == '-' {
					nv = "-" + useExpandPrefix + flag[1:]
				} else {
					nv = useExpandPrefix + flag
				}
				l = append(l, nv)
			}
			if ret[k.cp] == nil {
				ret[k.cp] = map[*dep.Atom][]string{k: l}
			} else {
				ret[k.cp][k] = l
			}
		}
	}
	return ret
}

func (u *UseManager) parseRepositoryFilesToDictOfTuples(fileName string, repositories *repository.RepoConfigLoader, eapiFilter func(string) bool) map[string][]string { // n
	ret := map[string][]string{}
	for _, repo := range repositories.ReposWithProfiles() {
		ret[repo.Name] = u.parseFileToTuple(path.Join(repo.Location, "profiles", fileName), true, eapiFilter, "", repo.eapi)
	}
	return ret
}

func (u *UseManager) parseRepositoryFilesToDictOfDicts(fileName string, repositories *repository.RepoConfigLoader, eapiFilter func(string) bool) map[string]map[string]map[*dep.Atom][]string {
	ret := map[string]map[string]map[*dep.Atom][]string{}
	for _, repo := range repositories.ReposWithProfiles() {
		ret[repo.Name] = u.parseFileToDict(path.Join(repo.Location, "profiles", fileName), false, true, eapiFilter, false, "0", repo.eapi, myutil.Ins(repo.profileFormats, "build-id"))
	}
	return ret
}

func (u *UseManager) parseProfileFilesToTupleOfTuples(fileName string, locations []*profileNode, eapiFilter func(string) bool) [][]string {
	ret := [][]string{}
	for _, profile := range locations {
		ret = append(ret, u.parseFileToTuple(path.Join(profile.location, fileName), profile.portage1Directories, eapiFilter, profile.eapi, ""))
	}
	return ret
}

func (u *UseManager) parseProfileFilesToTupleOfDicts(fileName string, locations []*profileNode, justStrings bool, eapiFilter func(string) bool) []map[string]map[*dep.Atom][]string { // fn
	ret := []map[string]map[*dep.Atom][]string{}
	for _, profile := range locations {
		ret = append(ret, u.parseFileToDict(path.Join(profile.location, fileName), justStrings, profile.portage1Directories, eapiFilter, profile.userConfig, profile.eapi, "", profile.allowBuildId))
	}
	return ret
}

func (u *UseManager) parseRepositoryUsealiases(repositorires *repository.RepoConfigLoader) map[string]map[string][]string {
	ret := map[string]map[string][]string{}
	for _, repo := range repositorires.ReposWithProfiles() {
		fileName := path.Join(repo.Location, "profiles", "use.aliases")
		eapi := util.ReadCorrespondingEapiFile(fileName, repo.eapi)
		useFlagRe := dep.GetUseflagRe(eapi)
		rawFileDict := grab.GrabDict(fileName, false, false, true, false, false)
		fileDict := map[string][]string{}
		for realFlag, aliases := range rawFileDict {
			if !useFlagRe.MatchString(realFlag) {
				msg.WriteMsg(fmt.Sprintf("--- Invalid real USE flag in '%s': '%s'\n", fileName, realFlag), -1, nil)
			} else {
				for _, alias := range aliases {
					if !useFlagRe.MatchString(alias) {
						msg.WriteMsg(fmt.Sprintf("--- Invalid USE flag alias for '%s' real USE flag in '%s': '%s'\n", realFlag, fileName, alias), -1, nil)
					} else {
						in := false
						for k, v := range fileDict {
							if k != realFlag {
								for _, x := range v {
									if x == alias {
										in = true
									}
								}
							}
						}
						if in {
							msg.WriteMsg(fmt.Sprintf("--- Duplicated USE flag alias in '%s': '%s'\n", fileName, alias), -1, nil)
						} else {
							if _, ok := fileDict[realFlag]; ok {
								fileDict[realFlag] = append(fileDict[realFlag], alias)
							} else {
								fileDict[realFlag] = []string{alias}
							}
						}
					}
				}
			}
		}
		ret[repo.Name] = fileDict
	}

	return ret
}

func (u *UseManager) parseRepositoryPackageusealiases(repositorires *repository.RepoConfigLoader) map[string]map[string]map[*dep.Atom]map[string][]string {
	ret := map[string]map[string]map[*dep.Atom]map[string][]string{}
	for _, repo := range repositorires.ReposWithProfiles() {
		fileName := path.Join(repo.Location, "profiles", "package.use.aliases")
		eapi := util.ReadCorrespondingEapiFile(fileName, repo.eapi)
		useFlagRe := dep.GetUseflagRe(eapi)
		lines := grab.GrabFile(fileName, 0, true, false)
		fileDict := map[string]map[*dep.Atom]map[string][]string{}
		for _, line := range lines {
			elements := strings.Fields(line[0])
			atom1, err := dep.NewAtom(elements[0], nil, false, nil, nil, eapi, nil, nil)
			if err != nil {
				msg.WriteMsg(fmt.Sprintf("--- Invalid atom1 in '%s': '%v'\n", fileName, atom1), 0, nil)
				continue
			}
			if len(elements) == 1 {
				msg.WriteMsg(fmt.Sprintf("--- Missing real USE flag for '%s' in '%v'\n", fileName, atom1), -1, nil)
				continue
			}
			realFlag := elements[1]
			if !useFlagRe.MatchString(realFlag) {
				msg.WriteMsg(fmt.Sprintf("--- Invalid real USE flag in '%s': '%v'\n", fileName, realFlag), -1, nil)
			} else {
				for _, alias := range elements[2:] {
					if !useFlagRe.MatchString(alias) {
						msg.WriteMsg(fmt.Sprintf("--- Invalid USE flag alias for '%s' real USE flag in '%s': '%s'\n", realFlag, fileName, alias), -1, nil)
					} else {
						in := false
						if _, ok := fileDict[atom1.cp]; ok {
							if _, ok := fileDict[atom1.cp][atom1]; ok {
								for k, v := range fileDict[atom1.cp][atom1] {
									if k != realFlag {
										for _, x := range v {
											if x == alias {
												in = true
											}
										}
									}
								}
							}
						}
						if in {
							msg.WriteMsg(fmt.Sprintf("--- Duplicated USE flag alias in '%s': '%s'\n", fileName, alias), -1, nil)
						} else {
							if _, ok := fileDict[atom1.cp]; !ok {
								fileDict[atom1.cp] = map[*dep.Atom]map[string][]string{atom1: {realFlag: {alias}}}
							} else if _, ok := fileDict[atom1.cp][atom1]; !ok {
								fileDict[atom1.cp][atom1] = map[string][]string{realFlag: {alias}}
							} else if _, ok := fileDict[atom1.cp][atom1][realFlag]; !ok {
								fileDict[atom1.cp][atom1][realFlag] = []string{alias}
							} else {
								fileDict[atom1.cp][atom1][realFlag] = append(fileDict[atom1.cp][atom1][realFlag], alias)
							}
						}
					}
				}
			}
		}
		ret[repo.Name] = fileDict
	}
	return ret
}

func (u *UseManager) _isStable(pkg *versions.PkgStr) bool {
	if u.userConfig {
		return pkg.stable()
	}
	if pkg.metadata == nil {
		return false
	}
	return u.isStable(pkg)
}

func (u *UseManager) getUseMask(pkg *versions.PkgStr, stable *bool) map[*dep.Atom]string { //nn
	if pkg == nil {
		p := [][][2]string{}
		for _, v := range u.usemaskList {
			q := [][2]string{}
			for _, w := range v {
				q = append(q, [2]string{w, ""})
			}
			p = append(p, q)
		}
		return util.StackLists(p, 1, false, false, false, false)
	}
	cp := pkg.cp
	if stable == nil {
		stable = new(bool)
		*stable = u.isStable(pkg)
	}
	useMask := [][]string{}
	if pkg.repo != "" && pkg.repo != versions.unknownRepo {
		repos := []string{}
		for range u.repositories.Getitem(pkg.repo).masters {
		}
		repos = append(repos, pkg.repo)
		for _, repo := range repos {
			useMask = append(useMask, u.repoUsemaskDict[repo])
			if *stable {
				useMask = append(useMask, u.repoUsestablemaskDict[repo])
			}
			cpdict := u.repoPusemaskDict[repo][cp]
			if len(cpdict) > 0 {
				pkgUsemask := orderedByAtomSpecificity(cpdict, pkg, "")
				if len(pkgUsemask) > 0 {
					useMask = append(useMask, pkgUsemask...)
				}
			}
			if *stable {
				cpdict = u.repoPusestablemaskDict[repo][cp]
				if len(cpdict) > 0 {
					pkgUsemask := orderedByAtomSpecificity(cpdict, pkg, "")
					if len(pkgUsemask) > 0 {
						useMask = append(useMask, pkgUsemask...)
					}
				}
			}
		}
	}
	for i, puseMaskDict := range u.pusemaskList {
		if len(u.usemaskList[i]) > 0 {
			useMask = append(useMask, u.usemaskList[i])
		}
		if *stable && len(u.usestablemaskList[i]) > 0 {
			useMask = append(useMask, u.usestablemaskList[i])
		}
		cpdict := puseMaskDict[cp]
		if len(cpdict) > 0 {
			pkgUsemask := orderedByAtomSpecificity(cpdict, pkg, "")
			if len(pkgUsemask) > 0 {
				useMask = append(useMask, pkgUsemask...)
			}
		}
		if *stable {
			cpdict := u.pusestablemaskList[i][cp]
			if len(cpdict) > 0 {
				pkgUsemask := orderedByAtomSpecificity(cpdict, pkg, "")
				if len(pkgUsemask) > 0 {
					useMask = append(useMask, pkgUsemask...)
				}
			}
		}
	}
	p := [][][2]string{}
	for _, v := range useMask {
		q := [][2]string{}
		for _, w := range v {
			q = append(q, [2]string{w})
		}
		p = append(p, q)
	}
	return util.StackLists(p, 1, false, false, false, false)
}

func (u *UseManager) getUseForce(pkg *versions.PkgStr, stable *bool) map[*dep.Atom]string { //n

	if pkg == nil {
		p := [][][2]string{}
		for _, v := range u.useforceList {
			q := [][2]string{}
			for _, w := range v {
				q = append(q, [2]string{w, ""})
			}
			p = append(p, q)
		}
		return util.StackLists(p, 1, false, false, false, false)
	}
	cp := pkg.cp
	if stable == nil {
		stable = new(bool)
		*stable = u.isStable(pkg)
	}
	useForce := [][]string{}
	if pkg.repo != "" && pkg.repo != versions.unknownRepo {
		repos := []string{}
		for range u.repositories.Getitem(pkg.repo).masters {
		}
		repos = append(repos, pkg.repo)
		for _, repo := range repos {
			useForce = append(useForce, u.repoUseforceDict[repo])
			if *stable {
				useForce = append(useForce, u.repoUsestableforceDict[repo])
			}
			cpdict := u.repoPuseforceDict[repo][cp]
			if len(cpdict) > 0 {
				pkgUseforce := orderedByAtomSpecificity(cpdict, pkg, "")
				if len(pkgUseforce) > 0 {
					useForce = append(useForce, pkgUseforce...)
				}
			}
			if *stable {
				cpdict = u.repoPusestableforceDict[repo][cp]
				if len(cpdict) > 0 {
					pkgUseforce := orderedByAtomSpecificity(cpdict, pkg, "")
					if len(pkgUseforce) > 0 {
						useForce = append(useForce, pkgUseforce...)
					}
				}
			}
		}
	}
	for i, puseForceDict := range u.puseforceList {
		if len(u.useforceList[i]) > 0 {
			useForce = append(useForce, u.useforceList[i])
		}
		if *stable && len(u.usestableforceList[i]) > 0 {
			useForce = append(useForce, u.usestableforceList[i])
		}
		cpdict := puseForceDict[cp]
		if len(cpdict) > 0 {
			pkgUseforce := orderedByAtomSpecificity(cpdict, pkg, "")
			if len(pkgUseforce) > 0 {
				useForce = append(useForce, pkgUseforce...)
			}
		}
		if *stable {
			cpdict := u.pusestablemaskList[i][cp]
			if len(cpdict) > 0 {
				pkgUseforce := orderedByAtomSpecificity(cpdict, pkg, "")
				if len(pkgUseforce) > 0 {
					useForce = append(useForce, pkgUseforce...)
				}
			}
		}
	}
	p := [][][2]string{}
	for _, v := range useForce {
		q := [][2]string{}
		for _, w := range v {
			q = append(q, [2]string{w})
		}
		p = append(p, q)
	}
	return util.StackLists(p, 1, false, false, false, false)
}

func (u *UseManager) getUseAliases(pkg *versions.PkgStr) map[string][]string {
	if pkg.eapi != "" && !eapi.eapiHasUseAliases(pkg.eapi) {
		return map[string][]string{}
	}
	cp := pkg.cp
	if cp == "" {
		slot := dep.DepGetslot(pkg.string)
		repo := dep.DepGetrepo(pkg.string)
		pkg := versions.NewPkgStr(dep.RemoveSlot(pkg.string), nil, nil, "", repo, slot, 0, 0, "", 0, nil)
		cp = pkg.cp
	}
	useAliases := map[string][]string{}
	if pkg.repo != "" && pkg.repo != versions.unknownRepo {
		repos := []string{}
		for _, repo := range u.repositories.Prepos[pkg.repo].masters {
			repos = append(repos, repo)
		}
		for _, repo := range repos {
			usealiasesDict := u.repoUsealiasesDict[repo]
			if usealiasesDict == nil {
				usealiasesDict = map[string][]string{}
			}
			for realFlag, aliases := range usealiasesDict {
				for _, alias := range aliases {
					in := false
					for k, v := range useAliases {
						if k != realFlag {
							for _, a := range v {
								if alias == a {
									in = true
									break
								}
							}
							if in {
								break
							}
						}
					}
					if in {
						msg.WriteMsg(fmt.Sprintf("--- Duplicated USE flag alias for '%v%s%s': '%s'\n", pkg.cpv, dep.repoSeparator, pkg.repo, alias), -1, nil)
					} else {
						if _, ok := useAliases[realFlag]; ok {
							useAliases[realFlag] = append(useAliases[realFlag], alias)
						} else {
							useAliases[realFlag] = []string{alias}
						}
					}
				}
			}

			var cpUsealiasesDict map[*dep.Atom]map[string][]string = nil
			if _, ok := u.repoPusealiasesDict[repo]; ok {
				cpUsealiasesDict = u.repoPusealiasesDict[repo][cp]
			}
			if len(cpUsealiasesDict) > 0 {
				usealiasesDictList := orderedByAtomSpecificity2(cpUsealiasesDict, pkg, "")
				for _, usealiasesDict := range usealiasesDictList {
					for realFlag, aliases := range usealiasesDict {
						for _, alias := range aliases {
							in := false
							for k, v := range useAliases {
								if k != realFlag {
									for _, a := range v {
										if alias == a {
											in = true
											break
										}
									}
									if in {
										break
									}
								}
							}
							if in {
								msg.WriteMsg(fmt.Sprintf("--- Duplicated USE flag alias for '%v%s%s': '%s'\n", pkg.cpv, dep.repoSeparator, pkg.repo, alias), -1, nil)
							} else {
								if _, ok := useAliases[realFlag]; ok {
									useAliases[realFlag] = append(useAliases[realFlag], alias)
								} else {
									useAliases[realFlag] = []string{alias}
								}
							}
						}
					}
				}
			}
		}
	}
	return useAliases
}

func (u *UseManager) getPUSE(pkg *versions.PkgStr) string {
	cp := pkg.cp
	if cp == "" {
		slot := dep.DepGetslot(pkg.string)
		repo := dep.DepGetrepo(pkg.string)
		pkg := versions.NewPkgStr(dep.RemoveSlot(pkg.string), nil, nil, "", repo, slot, 0, 0, "", 0, nil)
		cp = pkg.cp
	}
	ret := ""
	cpDict := u.pUseDict[cp]
	if len(cpDict) > 0 {
		puseMatches := orderedByAtomSpecificity(cpDict, pkg, "")
		if len(puseMatches) > 0 {
			puseList := []string{}
			for _, x := range puseMatches {
				puseList = append(puseList, x...)
			}
			ret = strings.Join(puseList, " ")
		}
	}

	return ret
}

func (u *UseManager) extract_global_USE_changes(old string) string { //""
	ret := old
	cpdict := u.pUseDict["*/*"]
	if cpdict != nil {
		var v []string = nil
		for a := range cpdict {
			if a.value == "*/*" {
				v = cpdict[a]
				delete(cpdict, a)
				break
			}
		}
		if v != nil {
			ret = strings.Join(v, " ")
			if old != "" {
				ret = old + " " + ret
				if len(cpdict) == 0 {
					delete(u.pUseDict, "*/*")
				}
			}
		}
	}
	return ret
}
