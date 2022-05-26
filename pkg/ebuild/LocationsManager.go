package ebuild

import (
	"bufio"
	"errors"
	"fmt"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/repository"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

var (
	portage1Directories = map[string]bool{
		"package.mask": true, "package.provided": true,
		"package.use": true, "package.use.mask": true, "package.use.force": true,
		"use.mask": true, "use.force": true}

	allowParentColon = map[string]bool{"portage-2": true}
)

type profileNode struct {
	location, eapi                                string
	profileFormats                                []string
	allowBuildId, portage1Directories, userConfig bool
}

type LocationsManager struct {
	userProfileDir, localRepoConfPath, eprefix, configRoot, targetRoot, sysroot, absUserConfig, profilePath, configProfilePath, esysroot, broot, portdir, portdirOverlay, eroot, globalConfigPath string
	userConfig                                                                                                                                                                                    bool
	overlayProfiles, profileLocations, profileAndUserLocations, profiles                                                                                                                          []string
	profilesComplex                                                                                                                                                                               []*profileNode
}

type SMSSS struct {
	S    string
	MSSS map[string][]string
}

func (l *LocationsManager) loadProfiles(repositories *repository.RepoConfigLoader, knownRepositoryPaths []string) {
	k := map[string]bool{}
	for _, v := range knownRepositoryPaths {
		x, _ := filepath.EvalSymlinks(v)
		k[x] = true
	}
	knownRepos := []SMSSS{}
	for x := range k {
		repo := repositories.GetRepoForLocation(x)
		layoutData := map[string][]string{}
		if repo == nil {
			layoutData, _ = repository.ParseLayoutConf(x, "")
		} else {
			layoutData = map[string][]string{"profile-formats": repo.profileFormats, "profile-eapi_when_unspecified": {repo.eapi}}
		}
		knownRepos = append(knownRepos, SMSSS{S: x + "/", MSSS: layoutData})
	}
	if l.configProfilePath == "" {
		deprecatedProfilePath := path.Join(l.configRoot, "etc", "make.profile")
		l.configProfilePath = path.Join(l.configRoot, _const.ProfilePath)
		if util.IsdirRaiseEaccess(l.configProfilePath) {
			l.profilePath = l.configProfilePath
			if util.IsdirRaiseEaccess(deprecatedProfilePath) && path.Clean(l.profilePath) != deprecatedProfilePath {
				msg.WriteMsg(fmt.Sprintf("!!! Found 2 make.profile dirs: using '%s', ignoring '%s'\n", l.profilePath, deprecatedProfilePath), -1, nil)
			}
		} else {
			l.configProfilePath = deprecatedProfilePath
			if util.IsdirRaiseEaccess(l.configProfilePath) {
				l.profilePath = l.configProfilePath
			} else {
				l.profilePath = ""
			}
		}
	} else {
		l.profilePath = l.configProfilePath
	}
	l.profiles = []string{}
	l.profilesComplex = []*profileNode{}
	if len(l.profilePath) > 0 {
		rp, _ := filepath.EvalSymlinks(l.profilePath)
		l.addProfile(rp, repositories, knownRepos)
	}
	if l.userConfig && len(l.profiles) != 0 {
		customProf := path.Join(l.configRoot, _const.CustomProfilePath)
		if _, err := os.Stat(customProf); !os.IsNotExist(err) {
			l.userProfileDir = customProf
			l.profiles = append(l.profiles, customProf)
			l.profilesComplex = append(l.profilesComplex, &profileNode{location: customProf, portage1Directories: true, userConfig: true, profileFormats: []string{"profile-bashrcs", "profile-set"}, eapi: util.ReadCorrespondingEapiFile(customProf+string(os.PathSeparator), ""), allowBuildId: true})
		}
	}
}

func (l *LocationsManager) checkVarDirectory(varname, varr string) error {
	if !util.IsdirRaiseEaccess(varr) {
		msg.WriteMsg(fmt.Sprintf("!!! Error: %s='%s' is not a directory. "+
			"Please correct this.\n", varname, varr), -1, nil)
		return errors.New("DirectoryNotFound") // DirectoryNotFound(var)
	}
	return nil
}

func (l *LocationsManager) addProfile(currentPath string, repositories *repository.RepoConfigLoader, known_repos []SMSSS) {
	currentAbsPath, _ := filepath.Abs(currentPath)
	allowDirectories := true
	allowParentColon := true
	repoLoc := ""
	compatMode := false
	currentFormats := []string{}
	eapi1 := ""
	intersectingRepos := []SMSSS{}
	for _, x := range known_repos {
		if strings.HasPrefix(currentAbsPath, x.S) {
			intersectingRepos = append(intersectingRepos, x)
		}
	}
	var layoutData map[string][]string = nil
	if len(intersectingRepos) > 0 {
		for _, x := range intersectingRepos {
			if len(x.S) > len(repoLoc) {
				repoLoc = x.S
				layoutData = x.MSSS
			}
		}
		if len(layoutData["profile_eapi_when_unspecified"]) > 0 {
			eapi1 = layoutData["profile_eapi_when_unspecified"][0]
		}
	}
	eapiFile := path.Join(currentPath, "eapi")
	if eapi1 == "" {
		eapi1 = "0"
	}
	if f, err := os.Open(eapiFile); err == nil {
		bd := bufio.NewReader(f)
		l, _, err := bd.ReadLine()
		if err == nil {
			eapi1 = strings.TrimSpace(string(l))
			if !eapi.EapiIsSupported(eapi1) {
				//raise ParseError(_(
				//	"Profile contains unsupported "
				//"EAPI '%s': '%s'") % \
				//(eapi, os.path.realpath(eapi_file),))
			}
		}
		f.Close()
	}
	if len(intersectingRepos) > 0 {
		for _, x := range layoutData["profile-formats"] {
			if repository.Portage1ProfilesAllowDirectories[x] {
				allowDirectories = true
				break
			}
		}
		if !allowDirectories {
			allowDirectories = eapi.EapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi)
		}
		compatMode = !eapi.EapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi) && len(layoutData["profile-formats"]) == 1 && layoutData["profile-formats"][0] == "portage-1-compat"
		for _, x := range layoutData["profile-formats"] {
			if "portage-2" == x {
				allowParentColon = true
				break
			}
		}
		currentFormats = layoutData["profile-formats"]
	}
	if compatMode {
		offenders := myutil.CopyMapSB(repository.Portage1ProfilesAllowDirectories)
		fs, _ := filepath.Glob(currentPath + "/*")
		for _, x := range fs {
			offenders[x] = true
		}
		o := []string{}
		for x := range offenders {
			s, _ := os.Stat(path.Join(currentPath, x))
			if s != nil && s.IsDir() {
				o = append(o, x)
			}
		}
		sort.Strings(o)
		if len(o) > 0 {
			//warnings.warn(_(
			//	"\nThe selected profile is implicitly using the 'portage-1' format:\n"
			//"\tprofile = %(profile_path)s\n"
			//"But this repository is not using that format:\n"
			//"\trepo = %(repo_name)s\n"
			//"This will break in the future.  Please convert these dirs to files:\n"
			//"\t%(files)s\n"
			//"Or, add this line to the repository's layout.conf:\n"
			//"\tprofile-formats = portage-1")
			//% dict(profile_path=currentPath, repo_name=repo_loc,
			//	files='\n\t'.join(offenders)))
		}
	}
	parentsFile := path.Join(currentPath, "parent")
	if util.ExistsRaiseEaccess(parentsFile) {
		parents := util.GrabFile(parentsFile, 0, false, false)
		if len(parents) == 0 {
			//raise ParseError(
			//	_("Empty parent file: '%s'") % parentsFile)
		}
		for _, p := range parents {
			parentPath := p[0]
			absParent := parentPath[:1] == string(os.PathSeparator)
			if !absParent && allowParentColon {
				parentPath = l.expandParentColon(parentsFile, parentPath, repoLoc, repositories)
			}
			parentPath = msg.NormalizePath(path.Join(currentPath, parentPath))
			if absParent || repoLoc == "" || strings.HasPrefix(parentPath, repoLoc) {
				parentPath, _ = filepath.EvalSymlinks(parentPath)
			}
			if util.ExistsRaiseEaccess(parentPath) {
				l.addProfile(parentPath, repositories, known_repos)
			} else {
				//raise ParseError(
				//	_("Parent '%s' not found: '%s'") %  \
				//(parentPath, parentsFile))
			}
		}
	}
	l.profiles = append(l.profiles, currentPath)
	l.profilesComplex = append(l.profilesComplex, &profileNode{location: currentPath, portage1Directories: allowDirectories, userConfig: false, profileFormats: currentFormats, eapi: eapi, allowBuildId: myutil.Ins(currentFormats, "build-id")})
}

func (l *LocationsManager) expandParentColon(parentsFile, parentPath, repoLoc string, repositories *repository.RepoConfigLoader) string {
	colon := strings.Index(parentPath, ":")
	if colon == -1 {
		return parentPath
	}
	if colon == 0 {
		if repoLoc == "" {
			//raise ParseError(
			//	_("Parent '%s' not found: '%s'") %  \
			//(parentPath, parentsFile))
		} else {
			parentPath = msg.NormalizePath(path.Join(repoLoc, "profiles", parentPath[colon+1:]))
		}
	} else {
		pRepoName := parentPath[:colon]
		pRepoLoc := repositories.GetLocationForName(pRepoName)
		parentPath = msg.NormalizePath(path.Join(pRepoLoc, "profiles", parentPath[colon+1:]))
	}
	return parentPath
}

func (l *LocationsManager) setRootOverride(rootOverwrite string) error {
	if l.targetRoot != "" && rootOverwrite != "" {
		l.targetRoot = rootOverwrite
		if len(strings.TrimSpace(l.targetRoot)) == 0 {
			l.targetRoot = ""
		}
	}
	if l.targetRoot == "" {
		l.targetRoot = string(os.PathSeparator)
	}
	fap, _ := filepath.Abs(l.targetRoot)
	l.targetRoot = strings.TrimSuffix(msg.NormalizePath(fap), string(os.PathSeparator)) + string(os.PathSeparator)
	if l.sysroot != "/" && l.sysroot != l.targetRoot {
		msg.WriteMsg(fmt.Sprintf("!!! Error: SYSROOT (currently %s) must "+
			"equal / or ROOT (currently %s).\n", l.sysroot, l.targetRoot), 1, nil)
		return errors.New("InvalidLocation") // raise InvalidLocation(self.sysroot)
	}
	util.EnsureDirs(l.targetRoot, -1, -1, -1, -1, nil, false)
	l.checkVarDirectory("ROOT", l.targetRoot)
	l.eroot = strings.TrimSuffix(l.targetRoot, string(os.PathSeparator)) + l.eprefix + string(os.PathSeparator)
	l.globalConfigPath = _const.GlobalConfigPath
	if _const.EPREFIX != "" {
		l.globalConfigPath = path.Join(_const.EPREFIX, strings.TrimPrefix(_const.GlobalConfigPath, string(os.PathSeparator)))
	}
	return nil
}

func (l *LocationsManager) setPortDirs(portdir, portdirOverlay string) {
	l.portdir = portdir
	l.portdirOverlay = portdirOverlay
	l.overlayProfiles = []string{}
	ovs, _ := shlex.Split(l.portdirOverlay)
	for _, ov := range ovs {
		ov = msg.NormalizePath(ov)
		profilesDir := path.Join(ov, "profiles")
		if util.IsdirRaiseEaccess(profilesDir) {
			l.overlayProfiles = append(l.overlayProfiles, profilesDir)
		}
	}
	l.profileLocations = append([]string{path.Join(portdir, "profiles")}, l.overlayProfiles...)
	l.profileAndUserLocations = append(l.profileLocations[:0:0], l.profileLocations...)
	if l.userConfig {
		l.profileAndUserLocations = append(l.profileAndUserLocations, l.absUserConfig)
	}
}

func NewLocationsManager(configRoot, eprefix, configProfilePath string, localConfig bool, targetRoot, sysroot string) *LocationsManager { // "", "", "", true, "", ""
	l := &LocationsManager{userProfileDir: "", localRepoConfPath: "", eprefix: eprefix, configRoot: configRoot, targetRoot: targetRoot, sysroot: sysroot, userConfig: localConfig}
	if l.eprefix == "" {
		l.eprefix = _const.EPREFIX
	} else {
		l.eprefix = msg.NormalizePath(l.eprefix)
		if l.eprefix == string(os.PathSeparator) {
			l.eprefix = ""
		}
	}

	if l.configRoot == "" {
		l.configRoot = _const.EPREFIX + string(os.PathSeparator)
	}
	fap := ""
	if l.configRoot != "" {
		s, err := filepath.Abs(l.configRoot)
		if err != nil {
			println(s, err.Error())
		}
		fap = s
	} else {
		s, err := filepath.Abs(string(os.PathSeparator))
		if err != nil {
			println(s, err.Error())
		}
		fap = s
	}
	l.configRoot = strings.TrimRight(msg.NormalizePath(fap), string(os.PathSeparator)) + string(os.PathSeparator)
	l.checkVarDirectory("PORTAGE_CONFIGROOT", l.configRoot)
	l.absUserConfig = path.Join(l.configRoot, _const.UserConfigPath)
	l.configProfilePath = configProfilePath
	if l.sysroot == "" {
		l.sysroot = "/"
	} else {
		fap, _ := filepath.Abs(l.sysroot)
		l.sysroot = strings.TrimSuffix(msg.NormalizePath(fap), string(os.PathSeparator)) + string(os.PathSeparator)
	}
	l.esysroot = strings.TrimSuffix(l.sysroot, string(os.PathSeparator)) + l.eprefix + string(os.PathSeparator)
	l.broot = _const.EPREFIX
	return l
}
