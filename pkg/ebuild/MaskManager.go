package ebuild

import (
	"fmt"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/repository"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"path"
	"strings"
)

type maskManager struct {
	_punmaskdict, _pmaskdict, _pmaskdict_raw map[string][]*dep.Atom
}

func (m *maskManager) _getMaskAtom(cpv *versions.PkgStr, slot, repo string, unmask_atoms []*dep.Atom) *dep.Atom { // nil
	var pkg *versions.PkgStr = nil
	if cpv.slot == "" {
		pkg = versions.NewPkgStr[*Config](cpv.string, nil, nil, "", repo, slot, 0, 0, "", 0, nil)
	} else {
		pkg = cpv
	}
	maskAtoms := m._punmaskdict[pkg.cp]
	if len(maskAtoms) > 0 {
		pkgList := []*versions.PkgStr{pkg}
		for _, x := range maskAtoms {
			if len(dep.matchFromList(x, pkgList)) == 0 {
				continue
			}
			if len(unmask_atoms) > 0 {
				for _, y := range unmask_atoms {
					if len(dep.matchFromList(y, pkgList)) > 0 {
						return nil
					}
				}
			}
			return x
		}
	}
	return nil
}

func (m *maskManager) getMaskAtom(cpv *versions.PkgStr, slot, repo string) *dep.Atom {
	var pkg *versions.PkgStr = nil
	if cpv.slot == "" {
		pkg = versions.NewPkgStr(cpv.string, nil, nil, "", repo, slot, 0, 0, "", 0, nil)
	} else {
		pkg = cpv
	}
	return m._getMaskAtom(pkg, slot, repo, m._punmaskdict[pkg.cp])
}

func (m *maskManager) getRawMaskAtom(cpv *versions.PkgStr, slot, repo string) *dep.Atom {
	return m._getMaskAtom(cpv, slot, repo, nil)
}

func NewMaskManager(repositories *repository.RepoConfigLoader, profiles []*profileNode, abs_user_config string, user_config, strict_umatched_removal bool) *maskManager { // true, false
	m := &maskManager{}
	m._punmaskdict, m._pmaskdict, m._pmaskdict_raw = map[string][]*dep.Atom{}, map[string][]*dep.Atom{}, map[string][]*dep.Atom{}
	pmaskCache := map[string][][2]string{}
	grabPMask := func(loc string, repoConfig *repository.RepoConfig) [][2]string {
		if _, ok := pmaskCache[loc]; !ok {
			path := path.Join(loc, "profiles", "package.mask")
			pmaskCache[loc] = util.GrabFilePackage(path, 0, repoConfig.portage1Profiles, false, false, myutil.Ins(repoConfig.profileFormats, "build-id"), true, true, "", repoConfig.eapi)
			//if repo_config.portage1_profiles_compat and os.path.isdir(path):
			//warnings.warn(_("Repository '%(repo_name)s' is implicitly using "
			//"'portage-1' profile format in its profiles/package.mask, but "
			//"the repository profiles are not marked as that format.  This will break "
			//"in the future.  Please either convert the following paths "
			//"to files, or add\nprofile-formats = portage-1\nto the "
			//"repository's layout.conf.\n")
			//% dict(repo_name=repo_config.name))
		}
		return pmaskCache[loc]
	}
	repoPkgMaskLines := []util.AS{}
	for _, repo := range repositories.reposWithProfiles() {
		lines := []map[*dep.Atom]string{}
		repoLines := grabPMask(repo.Location, repo)
		removals := map[string]bool{}
		for _, line := range repoLines {
			if line[0][:1] == "-" {
				removals[line[0][1:]] = true
			}
		}
		matchedRemovals := map[string]bool{}
		for _, master := range repo.mastersRepo {
			masterLines := grabPMask(master.Location, master)
			for _, line := range masterLines {
				if removals[line[0]] {
					matchedRemovals[line[0]] = true
				}
			}
			lines = append(lines, util.StackLists([][][2]string{masterLines, repoLines}, 1, true, false, false, false))
		}
		if len(repo.mastersRepo) > 0 {
			unmatchedRemovals := map[string]bool{}
			for r := range removals {
				if !matchedRemovals[r] {
					unmatchedRemovals[r] = true
				}
			}
			if len(unmatchedRemovals) > 0 && !user_config {
				sourceFile := path.Join(repo.Location, "profiles", "package.mask")
				ur := []string{}
				for r := range unmatchedRemovals {
					if len(ur) <= 3 {
						r = "-" + r
					}
					ur = append(ur, r)
				}
				if len(ur) > 3 {
					msg.WriteMsg(fmt.Sprintf("--- Unmatched removal atoms in %s: %s and %v more\n", sourceFile, strings.Join(ur[:3], ","), len(ur)-3), -1, nil)
				} else {
					msg.WriteMsg(fmt.Sprintf("--- Unmatched removal atom(s) in %s: %s\n", sourceFile, strings.Join(ur[:3], ",")), -1, nil)
				}
			}
		} else {
			lines = append(lines, util.StackLists([][][2]string{repoLines}, 1, true, !user_config, strict_umatched_removal, false))
		}
		ls := [][2]string{}
		for _, l := range lines {
			for a, s := range l {
				ls = append(ls, [2]string{a.value, s})
			}
		}
		repoPkgMaskLines = append(repoPkgMaskLines, util.AppendRepo(util.StackLists([][][2]string{ls}, 1, false, false, false, false), repo.Name, true)...)
	}
	repoPkgUnmaskLines := []util.AS{}
	for _, repo := range repositories.reposWithProfiles() {
		if !repo.portage1Profiles {
			continue
		}
		repoLines := util.GrabFilePackage(path.Join(repo.Location, "profiles", "package.unmask"), 0, true, false, false, myutil.Ins(repo.profileFormats, "build-id"), true, true, "", repo.eapi)
		lines := util.StackLists([][][2]string{repoLines}, 1, true, true, strict_umatched_removal, false)
		repoPkgUnmaskLines = append(repoPkgUnmaskLines, util.AppendRepo(lines, repo.Name, true)...)
	}
	profilePkgMaskLiness := [][][2]string{}
	profilePkgUnmaskLiness := [][][2]string{}
	for _, x := range profiles {
		profilePkgMaskLiness = append(profilePkgMaskLiness, util.GrabFilePackage(path.Join(x.location, "package.mask"), 0, x.portage1Directories, false, false, true, true, true, x.eapi, ""))
		if x.portage1Directories {
			profilePkgUnmaskLiness = append(profilePkgUnmaskLiness, util.GrabFilePackage(path.Join(x.location, "package.unmask"), 0, x.portage1Directories, false, false, true, true, true, x.eapi, ""))
		}
	}
	profilePkgmasklines := util.StackLists(profilePkgMaskLiness, 1, true, true, strict_umatched_removal, false)
	profilePkgunmasklines := util.StackLists(profilePkgUnmaskLiness, 1, true, true, strict_umatched_removal, false)

	userPkgMaskLines := [][2]string{}
	userPkgUnmaskLines := [][2]string{}
	if user_config {
		userPkgMaskLines = util.GrabFilePackage(path.Join(abs_user_config, "package.mask"), 0, true, true, true, true, true, true, "", "")
		userPkgUnmaskLines = util.GrabFilePackage(path.Join(abs_user_config, "package.mask"), 0, true, true, true, true, true, true, "", "")
	}

	var r1, r2, p1, p2 [][2]string
	for _, r := range repoPkgMaskLines {
		r1 = append(r1, [2]string{r.A.value, r.S})
	}
	for _, r := range repoPkgUnmaskLines {
		r2 = append(r2, [2]string{r.A.value, r.S})
	}
	for a, s := range profilePkgmasklines {
		p1 = append(p1, [2]string{a.value, s})
	}
	for a, s := range profilePkgunmasklines {
		p2 = append(p2, [2]string{a.value, s})
	}

	rawPkgMaskLines := util.StackLists([][][2]string{r1, p1}, 1, true, false, false, false)
	pkgMaskLines := util.StackLists([][][2]string{r1, p1, userPkgMaskLines}, 1, true, false, false, false)
	pkgUnmaskLines := util.StackLists([][][2]string{r2, p2, userPkgUnmaskLines}, 1, true, false, false, false)

	for x := range rawPkgMaskLines {
		if _, ok := m._pmaskdict_raw[x.cp]; !ok {
			m._pmaskdict_raw[x.cp] = []*dep.Atom{x}
		}
	}
	for x := range pkgMaskLines {
		if _, ok := m._pmaskdict[x.cp]; !ok {
			m._pmaskdict[x.cp] = []*dep.Atom{x}
		}
	}
	for x := range pkgUnmaskLines {
		if _, ok := m._punmaskdict[x.cp]; !ok {
			m._punmaskdict[x.cp] = []*dep.Atom{x}
		}
	}

	return m
}
