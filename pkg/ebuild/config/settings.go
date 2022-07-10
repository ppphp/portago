package config

import (
	"errors"
	"fmt"
	"github.com/ppphp/portago/pkg/_selinux"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/data"
	data_init "github.com/ppphp/portago/pkg/data/_init"
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/dep/soname"
	"github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/emerge/structs"
	"github.com/ppphp/portago/pkg/env"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/portage/vars"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/repository"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/grab"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/shlex"
)

var (
	categoryRe       = regexp.MustCompile("^\\w[-.+\\w]*$")

	_feature_flags_cache = map[bool]map[string]bool{}
)

func GetFeatureFlags(eapi_attrs eapi.EapiAttrs) map[string]bool {
    cache_key := eapi_attrs.FeatureFlagTest
	flags, ok := _feature_flags_cache[cache_key]
	if ok {
		return flags
	}
	flags = map[string]bool{}
	if eapi_attrs.FeatureFlagTest {
		flags["test"] = true
	}
	_feature_flags_cache[cache_key] = flags
	return flags
}

// 1, 1
func BestFromDict(key string, topDict map[string]map[string]string, keyOrders []string, EmptyOnError, FullCopy int) string {
	for _, x := range keyOrders {
		if _, ok1 := topDict[x]; ok1 {
			if _, ok2 := topDict[x][key]; ok2 {
				if FullCopy != 0 {
					return topDict[x][key] // TODO copy
				} else {
					return topDict[x][key]
				}
			}
		}
	}
	if EmptyOnError != 0 {
		return ""
	}
	return ""
}

func lazyIuseRegex(iuse_implicit []string) string {
	r := []string{}
	for _, v := range iuse_implicit {
		r = append(r, regexp.QuoteMeta(v))
	}
	sort.Strings(r)
	str := fmt.Sprintf("^(%s)$", strings.Join(r, "|"))
	str = strings.Replace(str, "\\.\\*", ".*", -1)
	return str
}

type IuseImplicitMatchCache func(string) bool

func NewIuseImplicitMatchCache(settings *Config) IuseImplicitMatchCache {
	g := []string{}
	for x := range settings.getImplicitIuse() {
		g = append(g, x)
	}
	iuseImplicitRe := regexp.MustCompile(fmt.Sprintf("^(%s)$", strings.Join(g, "|")))
	cache := map[string]bool{}
	return func(flag string)bool {
		if v, ok := cache[flag]; ok {
			return v
		}
		m := iuseImplicitRe.MatchString(flag)
		cache[flag] = m
		return m
	}
}

type Config struct {
	// self
	ValueDict map[string]string

	// class variable
	constantKeys    map[string]bool
	deprecatedKeys  map[string]string
	setcpvAuxKeys   map[string]bool
	_module_aliases map[string]string

	// special_env_vars
	caseInsensitiveVars map[string]bool
	defaultGlobals      map[string]string
	envBlacklist        map[string]bool
	environFilter       map[string]bool
	environWhitelist    map[string]bool
	environWhitelistRe  *regexp.Regexp
	globalOnlyVars      map[string]bool

	// variable
	tolerent, unmatchedRemoval, LocalConfig, setCpvActive bool
	locked                                                int
	acceptChostRe                                         *regexp.Regexp
	penv, modifiedkeys                                    []string
	mycpv                                                 *versions.PkgStr[*Config]
	setcpvArgsHash                                        *struct {
		cpv  *versions.PkgStr[*Config]
		mydb interfaces.IVarDbApi
	}
	sonameProvided                                                                                                                       map[*soname.SonameAtom]bool
	parentStable, _selinux_enabled                                                       *bool
	puse, depcachedir, profilePath, defaultFeaturesUse, userProfileDir, GlobalConfigPath                                                 string
	useManager                                                                                                                           *UseManager
	keywordsManagerObj                                                                                                                   *KeywordsManager
	maskManagerObj                                                                                                                       *maskManager
	virtualsManagerObj                                                                                                                   *VirtualManager
	licenseManager                                                                                                                       *LicenseManager
	iuseImplicitMatch                                                                                                                    IuseImplicitMatchCache
	unpackDependencies                                                                                                                   map[string]map[string]map[string]string
	packages, usemask, useforce                                                                                                          map[*dep.Atom[*Config]]string
	ppropertiesdict, pacceptRestrict, penvdict                                                                                           dep.ExtendedAtomDict[*Config]
	makeDefaultsUse, featuresOverrides, acceptRestrict, profiles                                                                         []string
	profileBashrc                                                                                                                        []bool
	lookupList, configList, makeDefaults, uvlist                                                                                         []map[string]string
	repoMakeDefaults, configDict                                                                                                         map[string]map[string]string
	backupenv, useExpandDict, acceptProperties, expandMap                                                                                map[string]string
	pprovideddict                                                                                                                        map[string][]string
	pbashrcdict                                                                                                                          map[*profileNode]map[string]map[*dep.Atom[*Config]][]string
	prevmaskdict                                                                                                                         map[string][]*dep.Atom[*Config]
	modulePriority, incrementals, validateCommands, unknownFeatures, nonUserVariables, envDBlacklist, pbashrc, categories, IuseEffective map[string]bool
	Features                                                                                                                             *featuresSet
	Repositories                                                                                                                         *repository.RepoConfigLoader
	modules                                                                                                                              map[string]map[string][]string
	locationsManager                                                                                                                     *LocationsManager
	_tolerant                                                                                                                            bool
	_thirdpartymirrors                                                                                                                   map[string][]string
}

// nil, nil, "", nil, "","","","",true, nil, false, nil
func NewConfig(clone *Config, mycpv *versions.PkgStr[*Config], configProfilePath string, configIncrementals []string, configRoot, targetRoot, sysroot, eprefix string, localConfig bool, env1 map[string]string, unmatchedRemoval bool, repositories *repository.RepoConfigLoader) *Config {
	eapiCache = make(map[string]bool)
	tolerant := vars.InitializingGlobals == nil
	c := &Config{
		constantKeys:   map[string]bool{"PORTAGE_BIN_PATH": true, "PORTAGE_GID": true, "PORTAGE_PYM_PATH": true, "PORTAGE_PYTHONPATH": true},
		deprecatedKeys: map[string]string{"PORTAGE_LOGDIR": "PORT_LOGDIR", "PORTAGE_LOGDIR_CLEAN": "PORT_LOGDIR_CLEAN"},
		setcpvAuxKeys: map[string]bool{"BDEPEND": true, "DEFINED_PHASES": true, "DEPEND": true, "EAPI": true, "HDEPEND": true,
			"INHERITED": true, "IUSE": true, "REQUIRED_USE": true, "KEYWORDS": true, "LICENSE": true, "PDEPEND": true,
			"PROPERTIES": true, "SLOT": true, "repository": true, "RESTRICT": true},
		_module_aliases: map[string]string{
			"cache.metadata_overlay.database":         "portage.cache.flat_hash.mtime_md5_database",
			"portage.cache.metadata_overlay.database": "portage.cache.flat_hash.mtime_md5_database",},
		caseInsensitiveVars: caseInsensitiveVars,
		defaultGlobals:      defaultGlobals,
		envBlacklist:        envBlacklist,
		environFilter:       environFilter,
		environWhitelist:    environWhitelist,
		globalOnlyVars:      globalOnlyVars,
		environWhitelistRe:  environWhitelistRe,

		tolerent:          tolerant,
		unmatchedRemoval:  unmatchedRemoval,
		locked:            0,
		mycpv:             nil,
		setcpvArgsHash:    nil,
		puse:              "",
		penv:              []string{},
		modifiedkeys:      []string{},
		uvlist:            []map[string]string{},
		acceptChostRe:     nil,
		acceptProperties:  nil,
		acceptRestrict:    nil,
		featuresOverrides: []string{},
		makeDefaults:      nil,
		parentStable:      nil,
		sonameProvided:    nil,
		unknownFeatures:   map[string]bool{},
		LocalConfig:       localConfig,
	}

	if clone != nil {
		c.tolerent = clone.tolerent
		c.unmatchedRemoval = clone.unmatchedRemoval
		c.categories = clone.categories
		c.depcachedir = clone.depcachedir
		c.incrementals = clone.incrementals
		c.modulePriority = clone.modulePriority
		c.profilePath = clone.profilePath
		c.profiles = clone.profiles
		c.packages = clone.packages
		c.Repositories = clone.Repositories
		c.defaultFeaturesUse = clone.defaultFeaturesUse
		c.IuseEffective = clone.IuseEffective
		c.iuseImplicitMatch = clone.iuseImplicitMatch
		c.nonUserVariables = clone.nonUserVariables
		c.envDBlacklist = clone.envDBlacklist
		c.pbashrc = clone.pbashrc
		c.repoMakeDefaults = clone.repoMakeDefaults
		c.usemask = clone.usemask
		c.useforce = clone.useforce
		c.puse = clone.puse
		c.userProfileDir = clone.userProfileDir
		c.LocalConfig = clone.LocalConfig
		c.makeDefaultsUse = c.makeDefaultsUse
		c.mycpv = clone.mycpv
		c.setcpvArgsHash = clone.setcpvArgsHash
		c.sonameProvided = clone.sonameProvided
		c.profileBashrc = clone.profileBashrc

		c.locationsManager = clone.locationsManager
		c.useManager = clone.useManager
		c.keywordsManagerObj = clone.keywordsManagerObj
		c.maskManagerObj = clone.maskManagerObj

		c.unknownFeatures = clone.unknownFeatures

		c.modules = myutil.CopyMapT(clone.modules)
		copy(c.penv, clone.penv)
		c.configDict = myutil.CopyMapT(clone.configDict)
		c.configList = []map[string]string{
			c.configDict["env.d"],
			c.configDict["repo"],
			c.configDict["features"],
			c.configDict["pkginternal"],
			c.configDict["globals"],
			c.configDict["defaults"],
			c.configDict["conf"],
			c.configDict["pkg"],
			c.configDict["env"],
		}

		c.lookupList = append(c.configList[:0:0], c.configList...)
		myutil.ReverseSlice(c.lookupList)
		c.useExpandDict = myutil.CopyMapT(clone.useExpandDict)
		c.backupenv = c.configDict["backupenv"]
		c.prevmaskdict = myutil.CopyMapT(clone.prevmaskdict)
		c.pprovideddict = myutil.CopyMapT(clone.pprovideddict)
		c.Features = NewFeaturesSet(c)
		c.Features.Features = myutil.CopyMapT(clone.Features.Features)
		c.featuresOverrides = append(clone.featuresOverrides[:0:0], clone.featuresOverrides...)

		c.licenseManager = clone.licenseManager

		c.virtualsManagerObj = clone.virtualsManager().deepcopy()
		c.acceptProperties = myutil.CopyMapT(clone.acceptProperties)
		c.ppropertiesdict = myutil.CopyMapT(clone.ppropertiesdict)
		c.acceptRestrict = append(clone.acceptRestrict[:0:0], clone.acceptRestrict...)
		c.pacceptRestrict = myutil.CopyMapT(clone.pacceptRestrict)
		c.penvdict = myutil.CopyMapT(clone.penvdict)
		c.pbashrcdict = clone.pbashrcdict //CopyMapSS(clone.pbashrcdict)
		c.expandMap = myutil.CopyMapT(clone.expandMap)
	} else {
		c.keywordsManagerObj = nil
		c.maskManagerObj = nil
		c.virtualsManagerObj = nil

		locationsManager := NewLocationsManager(configRoot, eprefix, configProfilePath, localConfig, targetRoot, sysroot)
		c.locationsManager = locationsManager

		eprefix = locationsManager.eprefix
		configRoot = locationsManager.configRoot
		sysroot = locationsManager.sysroot
		esysroot := locationsManager.esysroot
		broot := locationsManager.broot
		absUserConfig := locationsManager.absUserConfig
		makeConfPaths := []string{
			path.Join(configRoot, "etc", "make.conf"),
			path.Join(configRoot, _const.MakeConfFile)}
		p0, _ := filepath.EvalSymlinks(makeConfPaths[0])
		p1, _ := filepath.EvalSymlinks(makeConfPaths[1])
		if p0 == p1 {
			makeConfPaths = makeConfPaths[:len(makeConfPaths)-1]
		}

		makeConfCount := 0
		makeConf := map[string]string{}
		for _, x := range makeConfPaths {
			mygcfg := util.GetConfig(x, tolerant, true, true, true, makeConf)

			if mygcfg != nil {
				for k, v := range mygcfg {
					makeConf[k] = v
				}
				makeConfCount += 1
			}
		}

		if makeConfCount == 2 {
			msg.WriteMsg(fmt.Sprintf("!!! Found 2 make.conf files, using both '%s' and '%s'\n", makeConfPaths[0], makeConfPaths[1]), -1, nil)
		}

		for k := range makeConf {
			if strings.HasPrefix(k, "__") {
				delete(makeConf, k)
			}
		}

		locationsManager.setRootOverride(makeConf["ROOT"])
		targetRoot = locationsManager.targetRoot
		eroot := locationsManager.eroot
		c.GlobalConfigPath = locationsManager.globalConfigPath

		envD := util.GetConfig(path.Join(eroot, "etc", "profile.env"), tolerant, false, false, false, nil)
		expandMap := myutil.CopyMapT(envD)
		c.expandMap = expandMap

		expandMap["BROOT"] = broot
		expandMap["EPREFIX"] = eprefix
		expandMap["EROOT"] = eroot
		expandMap["ESYSROOT"] = esysroot
		expandMap["PORTAGE_CONFIGROOT"] = configRoot
		expandMap["ROOT"] = targetRoot
		expandMap["SYSROOT"] = sysroot

		makeGlobalsPath := ""
		if vars.NotInstalled {
			makeGlobalsPath = path.Join(_const.PORTAGE_BASE_PATH, "cnf", "make.globals")
		} else {
			makeGlobalsPath = path.Join(c.GlobalConfigPath, "make.globals")
		}
		oldMakeGlobals := path.Join(configRoot, "etc", "make.globals")
		f1, _ := filepath.EvalSymlinks(makeGlobalsPath)
		f2, _ := filepath.EvalSymlinks(oldMakeGlobals)
		if s, err := os.Stat(oldMakeGlobals); err == nil && (!s.IsDir() && f1 != f2) {
			msg.WriteMsg(fmt.Sprintf("!!!Found obsolete make.globals file: '%s', (using '%s' instead)\n", oldMakeGlobals, makeGlobalsPath), -1, nil)
		}

		makeGlobals := util.GetConfig(makeGlobalsPath, tolerant, false, true, false, expandMap)
		if makeGlobals == nil {
			makeGlobals = map[string]string{}
		}

		for k, v := range c.defaultGlobals {
			if _, ok := makeGlobals[k]; !ok {
				makeGlobals[k] = v
			}
		}

		if configIncrementals == nil {
			c.incrementals = _const.INCREMENTALS
		} else {
			c.incrementals = map[string]bool{}
			for _, v := range configIncrementals {
				c.incrementals[v] = true
			}
		}

		c.modulePriority = map[string]bool{"user": true, "default": true}
		c.modules = map[string]map[string][]string{}
		modulesFile := path.Join(configRoot, _const.ModulesFilePath)
		modulesLoader := env.NewKeyValuePairFileLoader(modulesFile, nil, nil)
		modulesDict, _ := modulesLoader.Load()
		c.modules["user"] = modulesDict
		if len(c.modules["user"]) == 0 {
			c.modules["user"] = map[string][]string{}
		}
		user_auxdbmodule, ok := c.modules["user"]["portdbapi.auxdbmodule"]
		if ok && myutil.InmsT(c._module_aliases, user_auxdbmodule[0]) {
			//warnings.warn(
			//	"'%s' is deprecated: %s"%(user_auxdbmodule, modules_file)
			//)
		}

		c.modules["default"] = map[string][]string{"portdbapi.auxdbmodule": {"portage.cache.flat_hash.mtime_md5_database"}}

		c.configList = []map[string]string{}

		c.configDict = map[string]map[string]string{}
		c.useExpandDict = map[string]string{}
		c.configList = append(c.configList, map[string]string{})
		c.configDict["env.d"] = c.configList[len(c.configList)-1]

		c.configList = append(c.configList, map[string]string{})
		c.configDict["repo"] = c.configList[len(c.configList)-1]

		c.configList = append(c.configList, map[string]string{})
		c.configDict["features"] = c.configList[len(c.configList)-1]

		c.configList = append(c.configList, map[string]string{})
		c.configDict["pkginternal"] = c.configList[len(c.configList)-1]

		if len(envD) > 0 {
			for k, v := range envD {
				c.configDict["env.d"][k] = v
			}
		}

		if env1 == nil {
			env1 = map[string]string{}
			for _, v := range os.Environ() {
				s := strings.SplitN(v, "=", 2)
				env1[s[0]] = s[1]
			}
		}

		c.backupenv = myutil.CopyMapT(env1)

		if len(envD) > 0 {
			for k, v := range envD {
				if c.backupenv[k] == v {
					delete(c.backupenv, k)
				}
			}
		}

		c.configDict["env"] = c.backupenv

		c.configList = append(c.configList, makeGlobals)
		c.configDict["globals"] = c.configList[len(c.configList)-1]

		c.makeDefaultsUse = []string{}

		c.ValueDict = map[string]string{}
		c.ValueDict["PORTAGE_CONFIGROOT"] = configRoot
		c.ValueDict["ROOT"] = targetRoot
		c.ValueDict["SYSROOT"] = sysroot
		c.ValueDict["EPREFIX"] = eprefix
		c.ValueDict["EROOT"] = eroot
		c.ValueDict["ESYSROOT"] = esysroot
		c.ValueDict["BROOT"] = broot
		knownRepos := []string{}
		portDir := ""
		portDirOverlay := ""
		portDirSync := ""
		for _, confs := range []map[string]string{makeGlobals, makeConf, c.configDict["env"]} {
			if v, ok := confs["PORTDIR"]; ok {
				portDir = v
				knownRepos = append(knownRepos, v)
			}
			if v, ok := confs["PORTDIR_OVERLAY"]; ok {
				portDirOverlay = v
				ss, _ := shlex.Split(v)
				knownRepos = append(knownRepos, ss...)
			}
			if v, ok := confs["SYNC"]; ok {
				portDirSync = v
			}
			if _, ok := confs["PORTAGE_RSYNC_EXTRA_OPTS"]; ok {
				c.ValueDict["PORTAGE_RSYNC_EXTRA_OPTS"] = confs["PORTAGE_RSYNC_EXTRA_OPTS"]
			}
		}

		c.ValueDict["PORTDIR"] = portDir
		c.ValueDict["PORTDIR_OVERLAY"] = portDirOverlay
		if portDirSync != "" {
			c.ValueDict["SYNC"] = portDirSync
		}
		c.lookupList = []map[string]string{c.configDict["env"]}
		if repositories == nil {
			c.Repositories = repository.LoadRepositoryConfig(c, "")
		} else {
			c.Repositories = repositories
		}

		for _, v := range c.Repositories.Prepos {
			knownRepos = append(knownRepos, v.Location)
		}
		kr := map[string]bool{}
		for _, v := range knownRepos {
			kr[v] = true
		}

		c.ValueDict["PORTAGE_REPOSITORIES"] = c.Repositories.ConfigString()
		c.BackupChanges("PORTAGE_REPOSITORIES")

		mainRepo := c.Repositories.MainRepo()
		if mainRepo != nil {
			c.ValueDict["PORTDIR"] = mainRepo.Location
			c.BackupChanges("PORTDIR")
			expandMap["PORTDIR"] = c.ValueDict["PORTDIR"]
		}

		portDirOverlay1 := c.Repositories.RepoLocationList
		if len(portDirOverlay1) > 0 && portDirOverlay1[0] == c.ValueDict["PORTDIR"] {
			portDirOverlay1 = portDirOverlay1[1:]
		}

		newOv := []string{}
		if len(portDirOverlay1) > 0 {
			for _, ov := range portDirOverlay1 {
				ov = msg.NormalizePath(ov)
				if util.IsdirRaiseEaccess(ov) || vars.SyncMode {
					newOv = append(newOv, vars.ShellQuote(ov))
				} else {
					msg.WriteMsg(fmt.Sprintf("!!! Invalid PORTDIR_OVERLAY(not a dir): '%s'\n", ov), -1, nil)
				}
			}
		}

		c.ValueDict["PORTDIR_OVERLAY"] = strings.Join(newOv, " ")
		c.BackupChanges("PORTDIR_OVERLAY")
		expandMap["PORTDIR_OVERLAY"] = c.ValueDict["PORTDIR_OVERLAY"]

		locationsManager.setPortDirs(c.ValueDict["PORTDIR"], c.ValueDict["PORTDIR_OVERLAY"])
		locationsManager.loadProfiles(c.Repositories, knownRepos)

		profilesComplex := locationsManager.profilesComplex
		c.profiles = locationsManager.profiles
		c.profilePath = locationsManager.profilePath
		c.userProfileDir = locationsManager.userProfileDir

		packageList := [][][2]string{}
		for _, x := range profilesComplex {
			packageList = append(packageList, util.GrabFilePackage(path.Join(x.location, "packages"), 0, false, false, false, x.allowBuildId, false, true, x.eapi, ""))
		}

		c.packages = util.StackLists[*Config](packageList, 1, false, false, false, false)

		c.prevmaskdict = map[string][]*dep.Atom[*Config]{}
		for x := range c.packages {
			if c.prevmaskdict[x.Cp] == nil {
				c.prevmaskdict[x.Cp] = []*dep.Atom[*Config]{x}
			} else {
				c.prevmaskdict[x.Cp] = append(c.prevmaskdict[x.Cp], x)
			}
		}

		//c.unpackDependencies = loadUnpackDependenciesConfiguration(c.Repositories)
		myGCfg := map[string]string{}
		if len(profilesComplex) != 0 {
			myGCfgDLists := []map[string]string{}
			for _, x := range profilesComplex {
				delete(expandMap, "USE")
				myGCfgDLists = append(myGCfgDLists, util.GetConfig(path.Join(x.location, "make.defaults"), tolerant, false, true, x.portage1Directories, expandMap))
			}
			c.makeDefaults = myGCfgDLists
			myGCfg = grab.StackDicts(myGCfgDLists, 0, c.incrementals, 0)
			if len(myGCfg) == 0 {
				myGCfg = map[string]string{}
			}
		}
		c.configList = append(c.configList, myGCfg)
		c.configDict["defaults"] = c.configList[len(c.configList)-1]

		myGCfg = map[string]string{}
		for _, x := range makeConfPaths {
			for k, v := range util.GetConfig(x, tolerant, true, true, true, expandMap) {
				myGCfg[k] = v
			}
		}

		for k := range myGCfg {
			if strings.HasPrefix(k ,"__") {
				delete(myGCfg, k)
			}
		}

		p := [][2]string{}
		for _, v := range strings.Fields(c.configDict["defaults"]["PROFILE_ONLY_VARIABLES"]) {
			p = append(p, [2]string{v, ""})
		}
		profileOnlyVariables := util.StackLists([][][2]string{p}, 0, false, false, false, false)
		nonUserVariables := map[string]bool{}
		for k := range profileOnlyVariables {
			nonUserVariables[k.Value] = true
		}
		for k := range c.envBlacklist {
			nonUserVariables[k] = true
		}
		for k := range c.globalOnlyVars {
			nonUserVariables[k] = true
		}
		c.nonUserVariables = nonUserVariables

		c.envDBlacklist = map[string]bool{}
		for k := range profileOnlyVariables {
			c.envDBlacklist[k.Value] = true
		}
		for k := range c.envBlacklist {
			c.envDBlacklist[k] = true
		}
		envD = c.configDict["env.d"]
		for k := range c.envDBlacklist {
			delete(envD, k)
		}

		for k := range profileOnlyVariables {
			delete(myGCfg, k.Value)
		}

		c.configList = append(c.configList, myGCfg)
		c.configDict["conf"] = c.configList[len(c.configList)-1]

		c.configList = append(c.configList, map[string]string{}) //LazyItemsDict
		c.configDict["pkg"] = c.configList[len(c.configList)-1]

		c.configDict["backupenv"] = c.backupenv

		for k := range profileOnlyVariables {
			delete(c.backupenv, k.Value)
		}

		c.configList = append(c.configList, c.configDict["env"])

		c.lookupList = myutil.ReversedT(c.configList)

		for blackListed := range c.envBlacklist {
			for _, cfg := range c.lookupList {
				delete(cfg, blackListed)
			}
			delete(c.backupenv, blackListed)
		}

		c.ValueDict["PORTAGE_CONFIGROOT"] = configRoot
		c.BackupChanges("PORTAGE_CONFIGROOT")
		c.ValueDict["ROOT"] = targetRoot
		c.BackupChanges("ROOT")
		c.ValueDict["SYSROOT"] = sysroot
		c.BackupChanges("SYSROOT")
		c.ValueDict["EPREFIX"] = eprefix
		c.BackupChanges("EPREFIX")
		c.ValueDict["EROOT"] = eroot
		c.BackupChanges("EROOT")
		c.ValueDict["ESYSROOT"] = esysroot
		c.BackupChanges("ESYSROOT")
		c.ValueDict["BROOT"] = broot
		c.BackupChanges("BROOT")

		c.ValueDict["PORTAGE_OVERRIDE_EPREFIX"] = _const.EPREFIX
		c.BackupChanges("PORTAGE_OVERRIDE_EPREFIX")

		c.ppropertiesdict = dep.ExtendedAtomDict[*Config]{}
		c.pacceptRestrict = dep.ExtendedAtomDict[*Config]{}
		c.penvdict = dep.ExtendedAtomDict[*Config]{}
		c.pbashrcdict = map[*profileNode]map[string]map[*dep.Atom[*Config]][]string{}
		c.pbashrc = map[string]bool{}

		c.repoMakeDefaults = map[string]map[string]string{}
		for _, repo := range c.Repositories.ReposWithProfiles() {
			d := util.GetConfig(path.Join(repo.Location, "profiles", "make.defaults"), tolerant, false, true, repo.Portage1Profiles, myutil.CopyMapSS(c.configDict["globals"]))
			if len(d) > 0 {
				for k := range c.envBlacklist {
					delete(d, k)
				}
				for k := range profileOnlyVariables {
					delete(d, k.Value)
				}
				for k := range c.globalOnlyVars {
					delete(d, k)
				}
			}
			c.repoMakeDefaults[repo.Name] = d
		}

		c.useManager = NewUseManager(c.Repositories, profilesComplex, absUserConfig, c.IsStable, localConfig)
		c.usemask = c.useManager.getUseMask(nil, nil)
		c.useforce = c.useManager.getUseForce(nil, nil)
		c.configDict["conf"]["USE"] = c.useManager.extract_global_USE_changes(c.configDict["conf"]["USE"])

		c.licenseManager = NewLicenseManager(locationsManager.profileLocations, absUserConfig, localConfig)
		c.configDict["conf"]["ACCEPT_LICENSE"] = c.licenseManager.extractGlobalChanges(c.configDict["conf"]["ACCEPT_LICENSE"])

		for _, profile := range profilesComplex {
			s, err := os.Stat(path.Join(profile.location, "profile.bashrc"))
			c.profileBashrc = append(c.profileBashrc, err == nil && !s.IsDir())
		}

		if localConfig {
			propDict := util.GrabDictPackage[*Config](path.Join(absUserConfig, "package.properties"), false, true, false, true, true, true, false, false, "", "0")
			var v []string = nil
			for a, x := range propDict {
				if a.Value == "*/*" {
					v = x
				}
				delete(propDict, a)
			}
			if v != nil {
				if _, ok := c.configDict["conf"]["ACCEPT_PROPERTIES"]; ok {
					c.configDict["conf"]["ACCEPT_PROPERTIES"] += " " + strings.Join(v, " ")
				} else {
					c.configDict["conf"]["ACCEPT_PROPERTIES"] = strings.Join(v, " ")
				}
			}
			for k, v := range propDict {
				if _, ok := c.ppropertiesdict[k.Cp]; !ok {
					c.ppropertiesdict[k.Cp] = map[*dep.Atom[*Config]][]string{k: v}
				} else {
					c.ppropertiesdict[k.Cp][k] = v
				}
			}
			d := util.GrabDictPackage[*Config](path.Join(absUserConfig, "package.accept_restrict"), false, true, false, true, true, true, false, false, "", "0")
			v = nil
			for a, x := range d {
				if a.Value == "*/*" {
					v = x
				}
				delete(d, a)
			}
			if v != nil {
				if myutil.InmsT(c.configDict["conf"],"ACCEPT_RESTRICT") {
					c.configDict["conf"]["ACCEPT_RESTRICT"] += " " + strings.Join(v, " ")
				} else {
					c.configDict["conf"]["ACCEPT_RESTRICT"] = strings.Join(v, " ")
				}
			}
			for k, v := range d {
				if _, ok := c.pacceptRestrict[k.Cp]; !ok {
					c.pacceptRestrict[k.Cp] = map[*dep.Atom[*Config]][]string{k: v}
				} else {
					c.pacceptRestrict[k.Cp][k] = v
				}
			}

			pEnvDict := util.GrabDictPackage[*Config](path.Join(absUserConfig, "package.env"), false, true, false, true, true, true, false, false, "", "0")
			v = nil
			for a, x := range pEnvDict {
				if a.Value == "*/*" {
					v = x
				}
				delete(pEnvDict, a)
			}
			if v != nil {
				globalWildcardConf := map[string]string{}
				c.grabPkgEnv(v, globalWildcardConf, nil)
				incrementals := c.incrementals
				confConfigDict := c.configDict["conf"]
				for k, v := range globalWildcardConf {
					if incrementals[k] {
						if myutil.InmsT(confConfigDict, k) {
							confConfigDict[k] = confConfigDict[k] + v
						} else {
							confConfigDict[k] = v
						}
					} else {
						confConfigDict[k] = v
					}
					expandMap[k] = v
				}
			}

			for k, v := range pEnvDict {
				if !myutil.InmsT(c.penvdict, k.Cp) {
					c.penvdict[k.Cp] = map[*dep.Atom[*Config]][]string{k: v}
				} else {
					c.penvdict[k.Cp][k] = v
				}
			}

			for _, profile := range profilesComplex {
				if !myutil.Ins(profile.profileFormats, "profile-bashrcs") {
					continue
				}
				c.pbashrcdict[profile] = dep.ExtendedAtomDict[*Config]{}
				bashrc := util.GrabDictPackage[*Config](path.Join(profile.location, "package.bashrc"), false, true, false, true, true, profile.allowBuildId, false, true, profile.eapi, "")
				if len(bashrc) == 0 {
					continue
				}
				for k, v := range bashrc {
					envFiles := []string{}
					for _, envname := range v {
						envFiles = append(envFiles, path.Join(profile.location, "bashrc", envname))
					}
					if _, ok := c.pbashrcdict[profile][k.Cp]; !ok {
						c.pbashrcdict[profile][k.Cp] = map[*dep.Atom[*Config]][]string{k: v}
					} else if _, ok := c.pbashrcdict[profile][k.Cp][k]; !ok {
						c.pbashrcdict[profile][k.Cp][k] = v
					} else {
						c.pbashrcdict[profile][k.Cp][k] = append(c.pbashrcdict[profile][k.Cp][k], v...)
					}
				}
			}
		}

		categories := [][][2]string{}
		for _, x := range locationsManager.profileAndUserLocations {
			categories = append(categories, grab.GrabFile(path.Join(x, "categories"), 0, false, false))
		}
		c.categories = map[string]bool{}
		for x := range util.StackLists(categories, 1, false, false, false, false) {
			if categoryRe.MatchString(x.Value) {
				c.categories[x.Value] = true
			}
		}

		al := [][][2]string{}
		for _, x := range locationsManager.profileAndUserLocations {
			al = append(al, grab.GrabFile(path.Join(x, "arch.list"), 0, false, false))
		}
		archList := util.StackLists(al, 1, false, false, false, false)
		als := []string{}
		for a := range archList {
			als = append(als, a.Value)
		}
		sort.Strings(als)
		c.configDict["conf"]["PORTAGE_ARCHLIST"] = strings.Join(als, " ")

		ppl := [][][2]string{}
		for _, x := range profilesComplex {
			provPath := path.Join(x.location, "package.provided")
			if myutil.PathExists(provPath) {
				if eapi.GetEapiAttrs(x.eapi).AllowsPackageProvided {
					ppl = append(ppl, grab.GrabFile(provPath, 1, x.portage1Directories, false))
				} else {
					msg.WriteMsg(fmt.Sprintf("!!! package.provided not allowed in EAPI %s: ", x.eapi)+ x.location+ "\n", -1, nil)
				}
			}
		}

		ppls := util.StackLists(ppl, 1, false, false, false, false)
		pkgProvidedLines := []string{}
		for a := range ppls {
			pkgProvidedLines = append(pkgProvidedLines, a.Value)
		}
		hasInvalidData := false
		for x := len(pkgProvidedLines) - 1; x > -1; x-- {
			myline := pkgProvidedLines[x]
			if !dep.IsValidAtom("="+myline, false, false, false, "", false) {
				msg.WriteMsg(fmt.Sprintf("Invalid package name in package.provided: %s\n", myline), -1, nil)
				hasInvalidData = true
				p := []string{}
				for k, v := range pkgProvidedLines {
					if x != k {
						p = append(p, v)
					}
				}
				pkgProvidedLines = p
				continue
			}
			cpvr := versions.CatPkgSplit(pkgProvidedLines[x], 1, "")
			if cpvr == [4]string{} || cpvr[0] == "null" {
				msg.WriteMsg("Invalid package name in package.provided: "+pkgProvidedLines[x]+"\n", -1, nil)
				hasInvalidData = true
				p := []string{}
				for k, v := range pkgProvidedLines {
					if x != k {
						p = append(p, v)
					}
				}
				pkgProvidedLines = p
				continue
			}
		}
		if hasInvalidData {
			msg.WriteMsg("See portage(5) for correct package.provided usage.\n", -1, nil)
		}
		c.pprovideddict = map[string][]string{}
		for _, x := range pkgProvidedLines {
			x_split := versions.CatPkgSplit(x, 1, "")
			if x_split == [4]string{} {
				continue
			}
			mycatpkg := versions.CpvGetKey(x, "")
			if myutil.InmsT(c.pprovideddict, mycatpkg) {
				c.pprovideddict[mycatpkg] = append(c.pprovideddict[mycatpkg], x)
			} else {
				c.pprovideddict[mycatpkg] = []string{x}
			}
		}

		if !myutil.InmsT(c.ValueDict, "USE_ORDER") {
			c.ValueDict["USE_ORDER"] = "env:pkg:conf:defaults:pkginternal:features:repo:env.d"
			c.BackupChanges("USE_ORDER")
		}

		if !myutil.InmsT(c.ValueDict,"CBUILD") && myutil.InmsT(c.ValueDict,"CHOST") {
			c.ValueDict["CBUILD"] = c.ValueDict["CHOST"]
			c.BackupChanges("CBUILD")
		}

		if _, ok := c.ValueDict["USERLAND"]; !ok {
			system := runtime.GOOS
			if system != "" && (strings.HasSuffix(system, "BSD") || system == "DragonFly") {
				c.ValueDict["USERLAND"] = "BSD"
			} else {
				c.ValueDict["USERLAND"] = "GNU"
			}
			c.BackupChanges("USERLAND")
		}

		defaultInstIds := map[string]string{
			"PORTAGE_INST_GID": "0",
			"PORTAGE_INST_UID": "0"}

		erootOrParent := util.FirstExisting(eroot)
		unprivileged := false
		if erootSt, err := os.Stat(erootOrParent); err == nil {
			if vars.UnprivilegedMode(erootOrParent, erootSt) {
				unprivileged = true

				defaultInstIds["PORTAGE_INST_GID"] = fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Gid)
				defaultInstIds["PORTAGE_INST_UID"] = fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Uid)

				if !myutil.InmsT(c.ValueDict, "PORTAGE_USERNAME") {
					if pwdStruct, err := user.LookupId(fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Uid)); err != nil {
					} else {
						c.ValueDict["PORTAGE_USERNAME"] = pwdStruct.Name
						c.BackupChanges("PORTAGE_USERNAME")
					}
				}

				if !myutil.InmsT(c.ValueDict, "PORTAGE_GRPNAME") {
					if grpStruct, err := user.LookupGroupId(fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Gid)); err != nil {
					} else {
						c.ValueDict["PORTAGE_GRPNAME"] = grpStruct.Name
						c.BackupChanges("PORTAGE_GRPNAME")
					}
				}
			}
		}

		for varr, defaultVal := range defaultInstIds {
			v, ok := c.ValueDict[varr]
			if !ok {
				v = defaultVal
			}
			if _, err := strconv.Atoi(v); err != nil {
				msg.WriteMsg(fmt.Sprintf("!!! %s='%s' is not a valid integer. Falling back to %s.\n", varr, c.ValueDict[varr], defaultVal), -1, nil)
				c.ValueDict[varr] = defaultVal
			}
			c.BackupChanges(varr)
		}

		c.depcachedir, ok = c.ValueDict["PORTAGE_DEPCACHEDIR"]
		if !ok {
			c.depcachedir = filepath.Join(string(os.PathSeparator), _const.EPREFIX, strings.TrimPrefix(_const.DepcachePath, string(os.PathSeparator)))
			if unprivileged && targetRoot != string(os.PathSeparator) {
				if !myutil.OsAccess(util.FirstExisting(c.depcachedir), 0222) {
					c.depcachedir = filepath.Join(eroot, strings.TrimPrefix(_const.DepcachePath, string(os.PathSeparator)))
				}
			}
		}

		c.ValueDict["PORTAGE_DEPCACHEDIR"] = c.depcachedir
		c.BackupChanges("PORTAGE_DEPCACHEDIR")

		if vars.InternalCaller {
			c.ValueDict["PORTAGE_INTERNAL_CALLER"] = "1"
			c.BackupChanges("PORTAGE_INTERNAL_CALLER")
		}

		c.regenerate(0)
		featureUse := []string{}
		if c.Features.Features["test"] {
			featureUse = append(featureUse, "test")
		}
		c.defaultFeaturesUse = strings.Join(featureUse, " ")
		c.configDict["features"]["USE"] = c.defaultFeaturesUse
		if len(featureUse) > 0 {
			c.regenerate(0)
		}

		if unprivileged {
			c.Features.Features["unprivileged"] = true
		}

		if runtime.GOOS == "FreeBSD" {
			c.Features.Features["chflags"] = true
		}

		c.initIuse()

		c._validateCommands()

		for k := range c.caseInsensitiveVars {
			if _, ok := c.ValueDict[k]; ok {
				c.ValueDict[k] = strings.ToLower(c.ValueDict[k])
				c.BackupChanges(k)
			}
		}
		output.Output_init(c.ValueDict["PORTAGE_CONFIGROOT"])
		data_init.Data_init(c)
	}
	if mycpv != nil {
		c.SetCpv(mycpv, nil)
	}

	return c
}

func (c *Config) initIuse() {
	c.IuseEffective = c.calcIuseEffective()
	c.iuseImplicitMatch = NewIuseImplicitMatchCache(c)
}

func (c *Config) _validateCommands() {
	for k := range validateCommands {
		v, ok := c.ValueDict[k]
		if ok {
			valid, vSplit := validateCmdVar(v)
			if !valid {
				if len(vSplit) > 0 {
					msg.WriteMsgLevel(fmt.Sprintf("%s setting is invalid: '%s'\n", k, v), 40, -1)
				}

				v, ok = c.configDict["globals"][k]
				if ok {
					defaultValid, vSplit := validateCmdVar(v)
					if !defaultValid {
						if len(vSplit) > 0 {
							msg.WriteMsgLevel(fmt.Sprintf("%s setting from make.globals is invalid: '%s'\n", k, v), 40, -1)
						}
						v = c.defaultGlobals[k]
					}
				}

				delete(c.ValueDict, k)
				delete(c.backupenv, k)
				if v != "" {
					c.configDict["globals"][k] = v
				}
			}
		}
	}
}

func (c *Config) InitDirs() {
	if !myutil.OsAccess(c.ValueDict["EROOT"], 0222){
		return
	}
	var m1 uint32
	m1--
	dirModeMap := map[string]struct {
		gid           uint32
		mode          os.FileMode
		mask          os.FileMode
		preservePerms bool
	}{
		"tmp":              {m1, 01777, 0, true},
		"var/tmp":          {m1, 01777, 0, true},
		_const.PrivatePath: {*data.Portage_gid, 02750, 02, false},
		_const.CachePath:   {*data.Portage_gid, 0755, 02, false},
	}

	for myPath, s := range dirModeMap {
		gid, mode, modemask, preservePerms := s.gid, s.mode, s.mask, s.preservePerms
		myDir := filepath.Join(c.ValueDict["EROOT"], myPath)
		if preservePerms && myutil.PathIsDir(myDir) {
			continue
		}
		if !util.EnsureDirs(myDir, 0, gid, mode, modemask, nil, false) {
			msg.WriteMsg(fmt.Sprintf("!!! Directory initialization failed: '%s'\n", myDir), -1, nil)
			msg.WriteMsg(fmt.Sprintf("!!! %v\n", false), -1, nil) // error
		}
	}
}

func (c *Config) keywordsManager() *KeywordsManager {
	if c.keywordsManagerObj == nil {
		c.keywordsManagerObj = NewKeywordsManager(c.locationsManager.profilesComplex, c.locationsManager.absUserConfig, c.LocalConfig, c.configDict["defaults"]["ACCEPT_KEYWORDS"])
	}
	return c.keywordsManagerObj
}

func (c *Config) maskManager() *maskManager {
	if c.maskManagerObj == nil {
		c.maskManagerObj = NewMaskManager(c.Repositories, c.locationsManager.profilesComplex, c.locationsManager.absUserConfig, c.LocalConfig, c.unmatchedRemoval)
	}
	return c.maskManagerObj
}

func (c *Config) virtualsManager() *VirtualManager {
	if c.virtualsManagerObj == nil {
		c.virtualsManagerObj = NewVirtualManager(c.profiles)
	}
	return c.virtualsManagerObj
}

func (c *Config) pkeywordsdict() map[string]map[*dep.Atom[*Config]][]string {
	return myutil.CopyMapT(c.keywordsManager().pkeywordsDict)
}

func (c *Config) pmaskdict() map[string][]*dep.Atom[*Config] {
	return myutil.CopyMapT(c.maskManager()._pmaskdict)
}

func (c *Config) _punmaskdict() map[string][]*dep.Atom[*Config] {
	return myutil.CopyMapT(c.maskManager()._punmaskdict)
}

func (c *Config) soname_provided() map[*soname.SonameAtom]bool {
	if c.sonameProvided == nil {
		e := []map[string][]string{}
		for _, x := range c.profiles {
			e = append(e, grab.GrabDict(path.Join(x, "soname.provided"), false, false, true, true, false))
		}
		c.sonameProvided = map[*soname.SonameAtom]bool{}
		d := grab.StackDictList(e, 1, []string{}, 0)
		for cat, sonames := range d {
			for _, soname1 := range sonames {
				c.sonameProvided[soname.NewSonameAtom(cat, soname1)] = true
			}
		}
	}
	return c.sonameProvided
}

func (c *Config) expandLicenseTokens(tokens []string) []string {
	return c.licenseManager.expandLicenseTokens(tokens)
}

func (c *Config) Validate() {
	groups := strings.Fields(c.ValueDict["ACCEPT_KEYWORDS"])
	archlist := c.archlist()
	if len(archlist) == 0 {
		msg.WriteMsg(fmt.Sprintf("--- 'profiles/arch.list' is empty or not available. Empty ebuild repository?\n"), 1, nil)
	} else {
		for _, group := range groups {
			if !archlist[group] && !strings.HasPrefix(group, "-") && archlist[group[1:]] && group != "*" && group != "~*" && group != "**" {
				msg.WriteMsg(fmt.Sprintf("!!! INVALID ACCEPT_KEYWORDS: %v\n", group), -1, nil)
			}
		}
	}

	profileBroken := false

	arch := c.ValueDict["ARCH"]
	if len(c.profilePath) == 0 || len(arch) == 0 {
		profileBroken = true
	} else {
		in := true
		for _, x := range []string{"make.defaults", "parent",
			"packages", "use.force", "use.mask"} {
			if util.ExistsRaiseEaccess(path.Join(c.profilePath, x)) {
				in = false
				break
			}
		}
		if in {
			profileBroken = true
		}
	}

	if profileBroken && !vars.SyncMode {
		absProfilePath := ""
		for _, x := range []string{_const.ProfilePath, "etc/make.profile"} {
			x = filepath.Join(c.ValueDict["PORTAGE_CONFIGROOT"], x)
			if _, err := os.Lstat(x); err != nil {
			} else {
				absProfilePath = x
				break
			}
		}
		if absProfilePath == "" {
			absProfilePath = filepath.Join(c.ValueDict["PORTAGE_CONFIGROOT"], _const.ProfilePath)
		}

		msg.WriteMsg(fmt.Sprintf("\n\n!!! %s is not a symlink and will probably prevent most merges.\n", absProfilePath), -1, nil)
		msg.WriteMsg(fmt.Sprintf("!!! It should point into a profile within %s/profiles/\n", c.ValueDict["PORTDIR"]), 0, nil)
		msg.WriteMsg(fmt.Sprintf("!!! (You can safely ignore this message when syncing. It's harmless.)\n\n\n"), 0, nil)
	}
	
	absUserVirtuals := filepath.Join(c.ValueDict["PORTAGE_CONFIGROOT"], _const.UserVirtualsFile)
	if myutil.PathExists(absUserVirtuals) {
		msg.WriteMsg("\n!!! /etc/portage/virtuals is deprecated in favor of\n",0, nil)
		msg.WriteMsg("!!! /etc/portage/profile/virtuals. Please move it to\n",0, nil)
		msg.WriteMsg("!!! this new location.\n\n",0, nil)
	}
	
	if !process.Sandbox_capable && (c.Features.Features["sandbox"] || c.Features.Features["usersandbox"]) {
		cp, _ := filepath.EvalSymlinks(c.profilePath)
		pp, _ := filepath.EvalSymlinks(path.Join(c.ValueDict["PORTAGE_CONFIGROOT"], _const.ProfilePath))
		if c.profilePath != "" && cp == pp {
			msg.WriteMsg(output.Colorize("BAD", fmt.Sprintf("!!! Problem with sandbox binary. Disabling...\n\n")), -1, nil)
		}
	}
	if c.Features.Features["fakeroot"] && !process.Fakeroot_capable {
		msg.WriteMsg(fmt.Sprintf("!!! FEATURES=fakeroot is enabled, but the fakeroot binary is not installed.\n"), -1, nil)
	}

	binpkgFormat, ok := c.ValueDict["BINPKG_FORMAT"]
	if ok {
		if !_const.SUPPORTED_GENTOO_BINPKG_FORMATS [binpkgFormat]{
			msg.WriteMsg(fmt.Sprintf("!!! BINPKG_FORMAT contains invalid or unsupported format: %s" , binpkgFormat), -1,nil)
		}
	}

	if binpkgCompression, ok := c.ValueDict["BINPKG_COMPRESS"]; ok {
		if compression, ok := util.Compressors[binpkgCompression]; !ok {
			msg.WriteMsg(fmt.Sprintf("!!! BINPKG_COMPRESS contains invalid or unsupported compression method: %s", binpkgCompression), -1, nil)
		} else {
			if cs, err := shlex.Split(util.VarExpand(compression["compress"], c.ValueDict, nil)); err != nil {

			} else if len(cs) == 0 {
				msg.WriteMsg(fmt.Sprintf("!!! BINPKG_COMPRESS contains invalid or unsupported compression method: %s", compression["compress"]), -1, nil)
			} else {
				compressionBinary := cs[0]
				if process.FindBinary(compressionBinary) == "" {
					missingPackage := compression["package"]
					msg.WriteMsg(fmt.Sprintf("!!! BINPKG_COMPRESS unsupported %s. Missing package: %s", binpkgCompression, missingPackage), -1, nil)
				}
			}
		}
	}
}

func (c *Config) Lock() {
	c.locked = 1
}

func (c *Config) Unlock() {
	c.locked = 0
}

func (c *Config) modifying() error {
	if c.locked != 0 {
		return errors.New("Configuration is locked.")
	}
	return nil
}

func (c *Config) BackupChanges(key string) {
	c.modifying()
	if key != "" && myutil.InmsT(c.configDict["env"],key) {
		c.backupenv[key] = c.configDict["env"][key]
	} else {
		//raise KeyError(_("No such key defined in environment: %s") % key)
	}
}

// 0
func (c *Config) reset(keeping_pkg int) {
	c.modifying()
	c.configDict["env"] = map[string]string{}
	for k, v := range c.backupenv {
		c.configDict["env"][k] = v
	}

	c.modifiedkeys = []string{}
	if keeping_pkg == 0 {
		c.mycpv = nil
		c.setcpvArgsHash = &struct {
			cpv  *versions.PkgStr[*Config]
			mydb interfaces.IVarDbApi
		}{}
		c.puse = ""
		c.penv = []string{}
		c.configDict["pkg"] = map[string]string{}
		c.configDict["pkginternal"] = map[string]string{}
		c.configDict["features"]["USE"] = c.defaultFeaturesUse
		c.configDict["repo"] = map[string]string{}
		c.configDict["defaults"]["USE"] = strings.Join(c.makeDefaultsUse, " ")
		c.usemask = c.useManager.getUseMask(nil, nil)
		c.useforce = c.useManager.getUseForce(nil, nil)
	}
	c.regenerate(0)
}

// nil
func (c *Config) SetCpv(mycpv *versions.PkgStr[*Config], mydb interfaces.IVarDbApi) {
	if c.setCpvActive {
		//AssertionError('setcpv recursion detected')
	}
	c.setCpvActive = true
	defer func() { c.setCpvActive = false }()
	c.modifying()

	var pkg *versions.PkgStr[*Config] = nil
	var explicitIUse map[string]bool = nil
	var builtUse []string = nil
	if mycpv == c.setcpvArgsHash.cpv && mydb == c.setcpvArgsHash.mydb {
		return
	}
	c.setcpvArgsHash.cpv = mycpv
	c.setcpvArgsHash.mydb = mydb

	hasChanged := false
	c.mycpv = mycpv
	s := versions.CatSplit(mycpv.String)
	cat := s[0]
	pf := s[1]
	cp := versions.CpvGetKey(mycpv.String, "")
	cpvSlot := c.mycpv
	pkgInternalUse := ""
	pkgInternalUseList := []string{}
	featureUse := []string{}
	iUse := ""
	pkgConfigDict := c.configDict["pkg"]
	previousIUse := pkgConfigDict["IUSE"]
	previousIuseEffective := pkgConfigDict["IUSE_EFFECTIVE"]
	previousFeatures := pkgConfigDict["FEATURES"]
	previousPEnv := c.penv

	auxKeys := c.setcpvAuxKeys

	pkgConfigDict = map[string]string{}

	pkgConfigDict["CATEGORY"] = cat
	pkgConfigDict["PF"] = pf

	repository := ""
	eapi1 := ""
	if mydb != nil {
		ak := map[string]bool{}
		for v := range auxKeys {
			if mydb._aux_cache_keys[v] {
				ak[v] = true
			}
		}
		auxKeys["USE"] = true
		aks := []string{}
		for v := range ak {
			aks = append(aks, v)
		}
		ag := mydb.AuxGet(c.mycpv, aks, "")

		for i := range aks {
			k := aks[i]
			v := ag[i]
			pkgConfigDict[k] = v
		}
		use := strings.Fields(pkgConfigDict["USE"])
		delete(pkgConfigDict, "USE")
		builtUse := map[string]bool{}
		for _, u := range use {
			builtUse[u] = true
		}
		if len(builtUse) == 0 {
			builtUse = nil
		}
		eapi1 = pkgConfigDict["EAPI"]

		repository = pkgConfigDict["repository"]
		delete(pkgConfigDict, "repository")
		if repository != "" {
			pkgConfigDict["PORTAGE_REPO_NAME"] = repository
		}
		iUse = pkgConfigDict["IUSE"]
		if pkg == nil {
			c.mycpv = versions.NewPkgStr[*Config](c.mycpv.String, pkgConfigDict, c, "", "", "", 0, 0, "", 0, nil)
			cpvSlot = c.mycpv
		} else {
			cpvSlot = pkg
		}
		for _, x := range strings.Fields(iUse) {
			if strings.HasPrefix(x, "+") {
				pkgInternalUseList = append(pkgInternalUseList, x[1:])
			} else if strings.HasPrefix(x, "-") {
				pkgInternalUseList = append(pkgInternalUseList, x)
			}
		}
		pkgInternalUse = strings.Join(pkgInternalUseList, " ")
	}

	EapiAttrs := eapi.GetEapiAttrs(eapi1)
	if pkgInternalUse != c.configDict["pkginternal"]["USE"] {
		c.configDict["pkginternal"]["USE"] = pkgInternalUse
		hasChanged = true
	}

	var repoEnv []map[string]string = nil
	if repository != "" && repository != structs.NewPackage[*Config](false, nil, false, nil, nil, "").UnknownRepo {
		repos := []string{}
		for _, repo := range c.Repositories.Getitem(repository).MastersRepo {
			repos = append(repos, repo.Name)
		}
		repos = append(repos, repository)
		for _, repo := range repos {
			d := c.repoMakeDefaults[repo]
			if d == nil {
				d = map[string]string{}
			} else {
				e := map[string]string{}
				for k, v := range d {
					e[k] = v
				}
				d = e
			}
			var cpDict map[*dep.Atom[*Config]][]string = nil
			if _, ok := c.useManager.repoPuseDict[repo]; !ok {
				cpDict = map[*dep.Atom[*Config]][]string{}
			} else {
				cpDict = c.useManager.repoPuseDict[repo][cp]
			}
			var repoPUse [][]string = nil
			if len(cpDict) > 0 {
				repoPUse = orderedByAtomSpecificity(cpDict, cpvSlot, "")
				if len(repoPUse) > 0 {
					for _, x := range repoPUse {
						d["USE"] = d["USE"] + " " + strings.Join(x, " ")
					}
				}
			}
			if len(d) > 0 {
				repoEnv = append(repoEnv, d)
			}
		}
	}

	if len(repoEnv) != 0 || len(c.configDict["repo"]) != 0 {
		c.configDict["repo"] = map[string]string{}
		incremental := 0
		if len(c.incrementals) > 0 {
			incremental = 1
		}
		r := [][][2]string{}
		for _, v := range repoEnv {
			re := [][2]string{}
			for _, w := range v {
				re = append(re, [2]string{w, ""})
			}
			r = append(r, re)
		}
		s := util.StackLists(r, incremental, false, false, false, false)
		for k, v := range s {
			c.configDict["repo"][k.Value] = v
		}
		hasChanged = true
	}

	defaultsV := []string{}
	for i, pkgProfileUseDict := range c.useManager.pkgprofileuse {
		if len(c.makeDefaultsUse[i]) > 0 {
			defaultsV = append(defaultsV, c.makeDefaultsUse[i])
		}
		cpDict := pkgProfileUseDict[cp]
		if len(cpDict) > 0 {
			pkgDefaults := orderedByAtomSpecificity(cpDict, cpvSlot, "")
			if len(pkgDefaults) > 0 {
				for _, v := range pkgDefaults {
					defaultsV = append(defaultsV, v...)
				}
			}
		}
	}
	defaults := strings.Join(defaultsV, " ")
	if defaults != c.configDict["defaults"]["USE"] {
		c.configDict["defaults"]["USE"] = defaults
		hasChanged = true
	}

	useForce := c.useManager.getUseForce(cpvSlot, nil)
	if len(useForce) != len(c.useforce) {
		c.useforce = useForce
		hasChanged = true
	}

	useMask := c.useManager.getUseMask(cpvSlot, nil)
	if len(useMask) != len(c.usemask) {
		c.usemask = useMask
		hasChanged = true
	}

	oldpuse := c.puse
	c.puse = c.useManager.getPUSE(cpvSlot)
	if oldpuse != c.puse {
		hasChanged = true
	}
	c.configDict["pkg"]["PKGUSE"] = c.puse
	c.configDict["pkg"]["USE"] = c.puse

	if len(previousFeatures) != 0 {
		hasChanged = true
		c.configDict["features"]["USE"] = c.defaultFeaturesUse
	}

	c.penv = []string{}
	cpDict := c.penvdict[cp]
	if len(cpDict) > 0 {
		pEnvMatches := orderedByAtomSpecificity(cpDict, cpvSlot, "")
		if len(pEnvMatches) > 0 {
			for _, x := range pEnvMatches {
				c.penv = append(c.penv, x...)
			}
		}
	}

	bashrcFiles := []string{}
	for i := range c.locationsManager.profilesComplex {
		profile, profileBashrc := c.locationsManager.profilesComplex[i], c.profileBashrc[i]
		if profileBashrc {
			bashrcFiles = append(bashrcFiles, path.Join(profile.location, "profile.bashrc"))
		}
		if _, ok := c.pbashrcdict[profile]; ok {
			cpDict = c.pbashrcdict[profile][cp]
			if len(cpDict) > 0 {
				bashrcMatches := orderedByAtomSpecificity(cpDict, cpvSlot, "")
				for _, x := range bashrcMatches {
					bashrcFiles = append(bashrcFiles, x...)
				}
			}
		}
	}
	c.pbashrc = map[string]bool{}
	for _, v := range bashrcFiles {
		c.pbashrc[v] = true
	}

	protectedPkgKeys := map[string]bool{}
	for k := range pkgConfigDict {
		protectedPkgKeys[k] = true
	}
	delete(protectedPkgKeys, "USE")

	if len(c.penv) > 0 {

		hasChanged = true
		delete(pkgConfigDict, "USE")
		c.grabPkgEnv(c.penv, pkgConfigDict, protectedPkgKeys)

		if len(c.puse) > 0 {
			if myutil.InmsT(pkgConfigDict, "USE") {
				pkgConfigDict["USE"] = pkgConfigDict["USE"] + " " + c.puse
			} else {
				pkgConfigDict["USE"] = c.puse
			}
		}
	} else if len(previousPEnv) > 0 {
		hasChanged = true
	}
	if !(previousIUse == iUse && ((previousIuseEffective != "") == EapiAttrs.IuseEffective)) {
		hasChanged = true
	}

	if hasChanged {
		c.reset(1)
	}

	if c.Features.Features["test"] {
		featureUse = append(featureUse, "test")
	}

	fu := strings.Join(featureUse, " ")
	if fu != c.configDict["features"]["USE"] {
		c.configDict["features"]["USE"] = fu
		c.reset(1)
		hasChanged = true
	}

	if explicitIUse == nil {
		explicitIUse = map[string]bool{}
		for _, x := range strings.Fields(iUse) {
			explicitIUse[strings.TrimLeft(x, "+-")] = true
		}
	}
	var iUseImplicitMatch func(string) bool
	if EapiAttrs.IuseEffective {
		iUseImplicitMatch = c.IuseEffectiveMatch
	} else {
		iUseImplicitMatch = c.iuseImplicitMatch
	}

	rawRestrict := ""
	if pkg == nil {
		rawRestrict = pkgConfigDict["RESTRICT"]
	} else {
		rawRestrict = pkg.Metadata["RESTRICT"]
	}

	restrictTest := false
	if rawRestrict != "" {
		var restrict []string = nil
		if builtUse != nil {
			useList := map[string]bool{}
			for _, x := range builtUse {
				useList[x] = true
			}
			restrict = dep.UseReduce[*Config](rawRestrict, useList, []string{}, false, []string{}, false, "", false, true, nil, nil, false)
		} else {
			useList := map[string]bool{}
			for _, x := range strings.Fields(c.ValueDict["USE"]) {
				if explicitIUse[x] || iUseImplicitMatch(x) {
					useList[x] = true
				}
			}
			restrict = dep.UseReduce[*Config](rawRestrict, useList, []string{}, false, []string{}, false, "", false, true, nil, nil, false, nil)
		}
		restrictTest = false
		for _, v := range restrict {
			if v == "test" {
				restrictTest = true
				break
			}
		}
	}

	if restrictTest && c.Features.Features["test"] {
		pkgInternalUseList = append(pkgInternalUseList, "-test")
		pkgInternalUse = strings.Join(pkgInternalUseList, " ")
		c.configDict["pkginternal"]["USE"] = pkgInternalUse
		c.reset(1)
		hasChanged = true
	}

	envConfigDict := c.configDict["env"]

	for k := range protectedPkgKeys {
		delete(envConfigDict, k)
	}

	b := map[string]bool{}
	for _, x := range builtUse {
		b[x] = true
	}
	envConfigDict["ACCEPT_LICENSE"] = c.licenseManager.getPrunnedAcceptLicense(c.mycpv, b, c.ValueDict["LICENSE"], c.ValueDict["SLOT"], c.ValueDict["PORTAGE_REPO_NAME"])
	restrict := dep.UseReduce[*Config](c.ValueDict["RESTRICT"], map[string]bool{}, []string{}, false, []string{}, false, "", false, false, nil, nil, false, nil)
	rm := map[string]bool{}
	for _, r := range restrict {
		rm[r] = true
	}
	restrict = []string{}
	for r := range rm {
		restrict = append(restrict, r)
	}
	sort.Strings(restrict)
	envConfigDict["PORTAGE_RESTRICT"] = strings.Join(restrict, " ")

	if builtUse != nil {
		pkgConfigDict["PORTAGE_BUILT_USE"] = strings.Join(builtUse, " ")
	}

	if !hasChanged {
		return
	}

	use := map[string]bool{}
	for _, x := range strings.Fields(c.ValueDict["USE"]) {
		use[x] = true
	}

	var portageIuse map[string]bool = nil
	if EapiAttrs.IuseEffective {

		portageIuse = myutil.CopyMapSB(c.IuseEffective)
		for x := range explicitIUse {
			portageIuse[x] = true
		}
		if builtUse != nil {
			for _, x := range builtUse {
				portageIuse[x] = true
			}
		}
		pi := []string{}
		for x := range portageIuse {
			pi = append(pi, x)
		}
		sort.Strings(pi)
		c.configDict["pkg"]["IUSE_EFFECTIVE"] = strings.Join(pi, " ")

		pis := []string{}
		for _, x := range pi {
			pis = append(pis, fmt.Sprintf("[\"%s\"]=1", x))
		}

		c.configDict["env"]["BASH_FUNC____in_portage_iuse%%"] = fmt.Sprintf("() { if [[ ${#___PORTAGE_IUSE_HASH[@]} -lt 1 ]]; then   declare -gA ___PORTAGE_IUSE_HASH=(%s); fi; [[ -n ${___PORTAGE_IUSE_HASH[$1]} ]]; }", strings.Join(pis, " "))
	} else {
		portageIuse = c.getImplicitIuse()
		for x := range explicitIUse {
			portageIuse[x] = true
		}

		pis := []string{}
		for k := range portageIuse {
			pis = append(pis, k)
		}
		c.configDict["env"]["PORTAGE_IUSE"] = lazyIuseRegex(pis)
		c.configDict["env"]["BASH_FUNC____in_portage_iuse%%"] = "() { [[ $1 =~ ${PORTAGE_IUSE} ]]; }"
	}

	ebuildForceTest := !restrictTest && c.ValueDict["EBUILD_FORCE_TEST"] == "1"

	if explicitIUse["test"] || iUseImplicitMatch("test") {
		if c.Features.Features["test"] {
			in := false
			var at *dep.Atom[*Config]
			for a := range c.usemask {
				if a.Value == "test" {
					in = true
					at = a
					break
				}
			}
			if ebuildForceTest && in {
				delete(c.usemask, at)
			}
		}
		in := false
		for a := range c.usemask {
			if a.Value == "test" {
				in = true
				break
			}
		}
		if restrictTest || (in && !ebuildForceTest) {
			fs := []string{}
			for x := range c.Features.Features {
				if x != "test" {
					fs = append(fs, x)
				}
			}
			c.ValueDict["FEATURES"] = strings.Join(fs, " ")
		}
	}

	if EapiAttrs.featureFlagTargetroot && (explicitIUse["targetroot"] || iUseImplicitMatch("targetroot")) {
		if c.ValueDict["ROOT"] != "/" {
			use["targetroot"] = true
		} else {
			delete(use, "targetroot")
		}
	}
	for x := range use {
		if (!explicitIUse[x] && !iUseImplicitMatch(x)) && x[len(x)-2:] != "_*" {
			delete(use, x)
		}
	}

	useExpandSplit := map[string]bool{}
	for _, x := range strings.Fields(c.ValueDict["USE_EXPAND"]) {
		useExpandSplit[strings.ToLower(x)] = true
	}

	useExpandIuses := map[string]map[string]bool{}
	for k := range useExpandSplit {
		useExpandIuses[k] = map[string]bool{}
	}
	for x := range portageIuse {
		xSplit := strings.Split(x, "_")
		if len(xSplit) == 1 {
			continue
		}
		for i := 0; i < (len(xSplit) - 1); i++ {
			k := strings.Join(xSplit[:i+1], "_")
			if useExpandSplit[k] {
				useExpandIuses[k][x] = true
				break
			}
		}
	}

	for k, useExpandIuse := range useExpandIuses {
		if use[k+"_*"] {
			for x := range useExpandIuse {
				for u := range useMask {
					if u.Value == x {
						use[x] = true
					}
				}
			}
		}
		k = strings.ToUpper(k)
		prefix := strings.ToLower(k) + "_"
		prefixLen := len(prefix)
		expandFlags := map[string]bool{}
		for x := range use {
			if x[:prefixLen] == prefix {
				expandFlags[x[prefixLen:]] = true
			}
		}
		varSplit := []string{}
		for _, x := range strings.Fields(c.useExpandDict[k]) {
			if expandFlags[x] {
				varSplit = append(varSplit, x)
			}
		}
		vs := []string{}
		for x := range expandFlags {
			if myutil.Ins(varSplit, x) {
				vs = append(vs, x)
			}
		}
		varSplit = append(varSplit, vs...)
		hasWildcard := expandFlags["*"]
		if hasWildcard {
			v := []string{}
			for _, x := range varSplit {
				if x != "*" {
					v = append(v, x)
				}
			}
			varSplit = v
		}
		hasIUse := map[string]bool{}
		for x := range portageIuse {

			if x[:prefixLen] == prefix {

				hasIUse[x[prefixLen:]] = true
			}
		}
		if hasWildcard {
			if len(hasIUse) > 0 {
				for suffix := range hasIUse {
					x := prefix + suffix
					in := false
					for u := range useMask {
						if u.Value == x {
							in = true
							break
						}
					}
					if !in {
						if expandFlags[suffix] {
							varSplit = append(varSplit, suffix)
						}
					}
				}
			} else {
				varSplit = []string{}
			}
		}
		filteredVarSplit := []string{}
		remaining := map[string]bool{}
		for x := range hasIUse {
			if myutil.Ins(varSplit, x) {
				remaining[x] = true
			}
		}
		for _, x := range varSplit {
			if remaining[x] {
				delete(remaining, x)
				filteredVarSplit = append(filteredVarSplit, x)
			}
		}
		varSplit = filteredVarSplit

		c.configDict["env"][k] = strings.Join(varSplit, " ")
	}

	for _, k := range strings.Fields(c.ValueDict["USE_EXPAND_UNPREFIXED"]) {
		varSplit := strings.Fields(c.ValueDict[k])
		vs := []string{}
		for _, x := range varSplit {
			if use[x] {
				vs = append(vs, x)
			}
		}
		varSplit = vs
		if len(varSplit) > 0 {
			c.configList[len(c.configList)-1][k] = strings.Join(varSplit, " ")
		} else if _, ok := c.ValueDict[k]; ok {
			c.configList[len(c.configList)-1][k] = ""
		}
	}

	u := []string{}
	for x := range use {
		if x[len(x)-2:] != "_*" {
			u = append(u, x)
		}
	}
	sort.Strings(u)

	c.configDict["env"]["PORTAGE_USE"] = strings.Join(u, " ")

	eapiCache = map[string]bool{}
}

func (c *Config) grabPkgEnv(penv []string, container map[string]string, protected_keys map[string]bool) { // n
	if protected_keys == nil {
		protected_keys = map[string]bool{}
	}
	absUserConfig := path.Join(c.ValueDict["PORTAGE_CONFIGROOT"], _const.UserConfigPath)
	nonUserVariables := c.nonUserVariables
	expandMap := myutil.CopyMapSS(c.expandMap)
	incrementals := c.incrementals
	for _, envname := range penv {
		penvfile := path.Join(absUserConfig, "env", envname)
		penvconfig := util.GetConfig(penvfile, c.tolerent, true, true, false, expandMap)
		if penvconfig == nil {
			msg.WriteMsg(fmt.Sprintf("!!! %s references non-existent file: %s\n", path.Join(absUserConfig, "package.env"), penvfile), -1, nil)
		} else {
			for k, v := range penvconfig {
				if protected_keys[k] || nonUserVariables[k] {
					msg.WriteMsg(fmt.Sprintf("!!! Illegal variable '%s' assigned in '%s'\n", k, penvfile), -1, nil)
				} else if incrementals[k] {
					if _, ok := container[k]; ok {
						container[k] = container[k] + " " + v
					} else {
						container[k] = v
					}
				} else {
					container[k] = v
				}
			}
		}
	}
}

func (c *Config) IuseEffectiveMatch(flag string) bool {
	return c.IuseEffective[flag]
}

func (c *Config) calcIuseEffective() map[string]bool {
	IuseEffective := map[string]bool{}
	for _, x := range strings.Fields(c.ValueDict["IUSE_IMPLICIT"]) {
		IuseEffective[x] = true
	}
	useExpandImplicit := map[string]bool{}
	for _, x := range strings.Fields(c.ValueDict["USE_EXPAND_IMPLICIT"]) {
		useExpandImplicit[x] = true
	}
	for _, v := range strings.Fields(c.ValueDict["USE_EXPAND_UNPREFIXED"]) {
		if !useExpandImplicit[v] {
			continue
		}
		for _, x := range strings.Fields(c.ValueDict["USE_EXPAND_IMPLICIT"]) {
			useExpandImplicit[x] = true
		}
		for _, x := range strings.Fields(c.ValueDict["USE_EXPAND_VALUES_"+v]) {
			IuseEffective[x] = true
		}
	}
	useExpand := map[string]bool{}
	for _, x := range strings.Fields(c.ValueDict["USE_EXPAND"]) {
		useExpand[x] = true
	}
	for v := range useExpandImplicit {
		if !useExpand[v] {
			continue
		}
		lowerV := strings.ToLower(v)
		for _, x := range strings.Fields(c.ValueDict["USE_EXPAND_VALUES_"+v]) {
			IuseEffective[lowerV+"_"+x] = true
		}
	}
	return IuseEffective
}

func (c *Config) getImplicitIuse() map[string]bool {

	iuseImplicit := map[string]bool{}
	arch := c.configDict["defaults"]["ARCH"]
	if arch != "" {
		iuseImplicit[arch] = true
	}
	for _, x := range strings.Fields(c.ValueDict["PORTAGE_ARCHLIST"]) {
		iuseImplicit[x] = true
	}
	useExpandHidden := strings.Fields(c.ValueDict["USE_EXPAND_HIDDEN"])
	for _, x := range useExpandHidden {
		iuseImplicit[strings.ToLower(x)+"_.*"] = true
	}
	for x := range c.usemask {
		iuseImplicit[x.Value] = true
	}
	for x := range c.useforce {
		iuseImplicit[x.Value] = true
	}
	iuseImplicit["build"] = true
	iuseImplicit["bootstrap"] = true

	return iuseImplicit
}

func (c *Config) _getUseMask(pkg *versions.PkgStr[*Config], stable *bool) map[*dep.Atom[*Config]]string {
	return c.useManager.getUseMask(pkg, stable)
}

func (c *Config) _getUseForce(pkg *versions.PkgStr[*Config], stable *bool) map[*dep.Atom[*Config]]string {
	return c.useManager.getUseForce(pkg, stable)
}

func (c *Config) _getMaskAtom(cpv *versions.PkgStr[*Config], metadata map[string]string) *dep.Atom[*Config] {
	return c.maskManager().getMaskAtom(cpv, metadata["SLOT"], metadata["repository"])
}

func (c *Config) _getRawMaskAtom(cpv *versions.PkgStr[*Config], metadata map[string]string) *dep.Atom[*Config] {
	return c.maskManager().getRawMaskAtom(cpv, metadata["SLOT"], metadata["repository"])
}

func (c *Config) IsStable(pkg interfaces.IPkgStr) bool {
	pkg1 := pkg.(*versions.PkgStr[*Config])
	return c.keywordsManager().isStable(pkg1, c.ValueDict["ACCEPT_KEYWORDS"], c.configDict["backupenv"]["ACCEPT_KEYWORDS"])
}

func (c *Config) _getKeywords(cpv *versions.PkgStr[*Config], metadata map[string]string) map[*dep.Atom[*Config]]string {
	return c.keywordsManager().getKeywords(cpv, metadata["SLOT"], metadata["KEYWORDS"], metadata["repository"])
}

func (c *Config) _getMissingKeywords(cpv *versions.PkgStr[*Config], metadata map[string]string) map[*dep.Atom[*Config]]string {
	backupedAcceptKeywords := c.configDict["backupenv"]["ACCEPT_KEYWORDS"]
	globalAcceptKeywords := c.ValueDict["ACCEPT_KEYWORDS"]
	return c.keywordsManager().GetMissingKeywords(cpv, metadata["SLOT"], metadata["KEYWORDS"], metadata["repository"], globalAcceptKeywords, backupedAcceptKeywords)
}

func (c *Config) _getRawMissingKeywords(cpv *versions.PkgStr[*Config], metadata map[string]string) map[*dep.Atom[*Config]]string {
	return c.keywordsManager().getRawMissingKeywords(cpv, metadata["SLOT"], metadata["KEYWORDS"], metadata["repository"], c.ValueDict["ACCEPT_KEYWORDS"])
}

func (c *Config) _getPKeywords(cpv *versions.PkgStr[*Config], metadata map[string]string) []string {
	globalAcceptKeywords := c.ValueDict["ACCEPT_KEYWORDS"]
	return c.keywordsManager().getPKeywords(cpv, metadata["SLOT"], metadata["repository"], globalAcceptKeywords)
}

func (c *Config) _getMissingLicenses(cpv *versions.PkgStr[*Config], metadata map[string]string) []string {
	return c.licenseManager.getMissingLicenses(cpv, metadata["USE"], metadata["LICENSE"], metadata["SLOT"], metadata["repository"])
}

func (c *Config) _getMissingProperties(cpv *versions.PkgStr[*Config], metadata map[string]string) []string {

	accept_properties := []string{}
	for k := range c.acceptProperties{
		accept_properties = append(accept_properties, k)
	}
	//try:
	//	cpv.slot
	//	except AttributeError:
	//	cpv = _pkg_str(cpv, metadata=metadata, settings=c)
	cp := versions.CpvGetKey(cpv.String, "")
	cpdict := c.ppropertiesdict[cp]
	if len(cpdict) > 0 {
		pproperties_list := orderedByAtomSpecificity(cpdict, cpv, "")
		if len(pproperties_list) > 0 {
			accept_properties = []string{}
			for k := range c.acceptProperties{
				accept_properties = append(accept_properties, k)
			}
			for _, x := range pproperties_list {
				accept_properties = append(accept_properties, x...)
			}
		}
	}

	properties_str := metadata["PROPERTIES"]
	properties := map[string]bool{}
	for _, v := range dep.UseReduce[*Config](properties_str, map[string]bool{}, []string{}, true, []string{}, false, "", false, true, nil, nil, false) {
		properties[v] = true
	}

	acceptable_properties := map[string]bool{}
	for _, x := range accept_properties {
		if x == "*" {
			for k := range properties {
				acceptable_properties[k] = true
			}
		} else if x == "-*" {
			acceptable_properties = map[string]bool{}
		} else if x[:1] == "-" {
			delete(acceptable_properties, x[1:])
		} else {
			acceptable_properties[x] = true
		}
	}

	use := []string{}
	if strings.Contains(properties_str, "?") {
		use = strings.Fields(metadata["USE"])
	}

	ret := []string{}
	usemsb := map[string]bool{}
	for _, v := range use {
		usemsb[v] = true
	}
	for _, x := range dep.UseReduce[*Config](properties_str, usemsb, []string{}, false, []string{}, false, "", false, true, nil, nil, false) {
		if !acceptable_properties[x] {
			ret = append(ret, x)
		}
	}
	return ret
}

func (c *Config) _getMissingRestrict(cpv *versions.PkgStr[*Config], metadata map[string]string) []string {

	accept_restrict := []string{}
	for _, k := range c.acceptRestrict{
		accept_restrict = append(accept_restrict, k)
	}
	//try:
	//	cpv.slot
	//	except AttributeError:
	//	cpv = _pkg_str(cpv, metadata=metadata, settings=c)
	cp := versions.CpvGetKey(cpv.String, "")
	cpdict := c.pacceptRestrict[cp]
	if len(cpdict) > 0 {
		paccept_restrict_list := orderedByAtomSpecificity(cpdict, cpv, "")
		if len(paccept_restrict_list) > 0 {
			accept_restrict = []string{}
			for _, k := range c.acceptRestrict{
				accept_restrict = append(accept_restrict, k)
			}
			for _, x := range paccept_restrict_list {
				accept_restrict = append(accept_restrict, x...)
			}
		}
	}

	restrict_str := metadata["RESTRICT"]
	all_restricts := map[string]bool{}
	for _, v := range dep.UseReduce[*Config](restrict_str, map[string]bool{}, []string{}, true, []string{}, false, "", false, true, nil, nil, false, nil) {
		all_restricts[v] = true
	}

	acceptable_restricts := map[string]bool{}
	for _, x := range accept_restrict {
		if x == "*" {
			for k := range all_restricts {
				acceptable_restricts[k] = true
			}
		} else if x == "-*" {
			acceptable_restricts = map[string]bool{}
		} else if x[:1] == "-" {
			delete(acceptable_restricts, x[1:])
		} else {
			acceptable_restricts[x] = true
		}
	}

	use := []string{}
	if strings.Contains(restrict_str, "?") {
		use = strings.Fields(metadata["USE"])
	}

	ret := []string{}
	usemsb := map[string]bool{}
	for _, v := range use {
		usemsb[v] = true
	}
	for _, x := range dep.UseReduce[*Config](restrict_str, usemsb, []string{}, false, []string{}, false, "", false, true, nil, nil, false, nil) {
		if !acceptable_restricts[x] {
			ret = append(ret, x)
		}
	}
	return ret
}

func (c *Config)_accept_chost(metadata map[string]string)bool{

	if c.acceptChostRe == nil {
		accept_chost := strings.Fields(c.ValueDict["ACCEPT_CHOSTS"])
		if len(accept_chost)== 0 {
			chost := c.ValueDict["CHOST"]
			if chost== "" {
				accept_chost=append(accept_chost,chost)
			}
		}
		if len(accept_chost) == 0 {
			c.acceptChostRe = regexp.MustCompile(".*")
		}else if len(accept_chost) == 1 {
			var err error
			c.acceptChostRe, err = regexp.Compile(fmt.Sprintf("^%s$", accept_chost[0]))
			if err != nil {
				//except re.error as e:
				msg.WriteMsg(fmt.Sprintf("!!! Invalid ACCEPT_CHOSTS value: '%s': %s\n",
				accept_chost[0], err), -1, nil)
				c.acceptChostRe = regexp.MustCompile("^$")
			}
		}else {
			var err error
			c.acceptChostRe, err = regexp.Compile(fmt.Sprintf("^(%s)$", strings.Join(accept_chost, "|")))
			if err != nil {
				//except re.error as e:
				msg.WriteMsg(fmt.Sprintf("!!! Invalid ACCEPT_CHOSTS value: '%s': %s\n",
					strings.Join(accept_chost, " "), err), -1, nil)
				c.acceptChostRe = regexp.MustCompile("^$")
			}
		}
	}

	pkg_chost := metadata["CHOST"]
	return pkg_chost == "" || c.acceptChostRe.MatchString(pkg_chost)
}

func (c *Config)setinst(){
}

func (c *Config) reload() {
	envDFilename := filepath.Join(c.ValueDict["EROOT"], "etc", "profile.env")
	c.configDict["env.d"] = map[string]string{}
	envD := util.GetConfig(envDFilename, c._tolerant, false, false, false, nil)
	if len(envD) > 0 {
		for k := range c.envDBlacklist {
			delete(envD, k)
		}
		for k, v := range envD {
			c.configDict["env.d"][k] = v
		}
	}
}

// 0
func (c *Config) regenerate(useonly int) {
	c.modifying()
	myincrementals := map[string]bool{}
	if useonly != 0 {
		myincrementals["USE"] = true
	} else {
		myincrementals = c.incrementals
	}
	delete(myincrementals, "USE")
	mydbs := append(c.configList[:0:0], c.configList...)
	mydbs = append(mydbs, c.backupenv)
	if c.LocalConfig {
		mySplit := []string{}
		for _, curdb := range mydbs {
			mySplit = append(mySplit, strings.Fields(curdb["ACCEPT_LICENSE"])...)
		}
		mySplit = pruneIncremental(mySplit)
		acceptLicenseStr := strings.Join(mySplit, " ")
		if acceptLicenseStr == "" {
			acceptLicenseStr = "* -@EULA"
		}
		if c.configList[len(c.configList)-1] == nil {
			c.configList[len(c.configList)-1] = map[string]string{}
		}
		c.configList[len(c.configList)-1]["ACCEPT_LICENSE"] = acceptLicenseStr
		c.licenseManager.setAcceptLicenseStr(acceptLicenseStr)
	} else {
		c.licenseManager.setAcceptLicenseStr("*")
	}
	if c.LocalConfig {
		mySplit := []string{}
		for _, curdb := range mydbs {
			mySplit = append(mySplit, strings.Fields(curdb["ACCEPT_RESTRICT"])...)
		}
		mySplit = pruneIncremental(mySplit)
		acceptLicenseStr := strings.Join(mySplit, " ")
		c.configList[len(c.configList)-1]["ACCEPT_RESTRICT"] = acceptLicenseStr
		c.acceptRestrict = mySplit
	} else {
		c.acceptRestrict = []string{"*"}
	}
	incrementLists := map[string][][]string{}
	for k := range myincrementals {
		incrementList := [][]string{}
		incrementLists[k] = incrementList
		for _, curdb := range mydbs {
			v, ok := curdb[k]
			if ok {
				incrementList = append(incrementList, strings.Fields(v))
			}
		}
	}
	if _, ok := incrementLists["FEATURES"]; ok {
		incrementLists["FEATURES"] = append(incrementLists["FEATURES"], c.featuresOverrides)
	}
	myFlags := map[string]bool{}
	for myKey, incrementList := range incrementLists {
		myFlags = map[string]bool{}
		for _, mySplit := range incrementList {
			for _, x := range mySplit {
				if x == "-*" {
					myFlags = map[string]bool{}
					continue
				}
				if x[0] == '+' {
					msg.WriteMsg(output.Colorize("BAD", fmt.Sprintf("%s values should not start with a '+': %s", myKey, x))+"\n", -1, nil)
					x = x[1:]
					if x == "" {
						continue
					}
				}
				if x[0] == '-' {
					delete(myFlags, x[1:])
					continue
				}
				myFlags[x] = true
			}
		}
		if _, ok := c.ValueDict[myKey]; len(myFlags) > 0 || ok {
			m := []string{}
			for k := range myFlags {
				m = append(m, k)
			}
			sort.Strings(m)
			c.configList[len(c.configList)-1][myKey] = strings.Join(m, " ")
		}
	}
	useExpand := strings.Fields(c.ValueDict["USE_EXPAND"])
	useExpandDict := c.useExpandDict
	useExpandDict = map[string]string{}
	for _, k := range useExpand {
		if v, ok := c.ValueDict[k]; ok {
			useExpandDict[k] = v
		}
	}
	useExpandUnprefixed := strings.Fields(c.ValueDict["USE_EXPAND_UNPREFIXED"])
	configDictDefaults := c.configDict["defaults"]
	if c.makeDefaults != nil {
		for _, cfg := range c.makeDefaults {
			if len(cfg) == 0 {
				c.makeDefaultsUse = append(c.makeDefaultsUse, "")
				continue
			}
			use := cfg["USE"]
			expandUse := []string{}
			for _, k := range useExpandUnprefixed {
				if v, ok := cfg[k]; ok {
					expandUse = append(expandUse, strings.Fields(v)...)
				}
			}
			for k := range useExpandDict {
				v, ok := cfg[k]
				if !ok {
					continue
				}
				prefix := strings.ToLower(k) + "_"
				for _, x := range strings.Fields(v) {
					if x[:1] == "-" {
						expandUse = append(expandUse, "-"+prefix+x[:1])
					} else {
						expandUse = append(expandUse, prefix+x)
					}
				}
			}
			if len(expandUse) > 0 {
				expandUse = append(expandUse, use)
				use = strings.Join(expandUse, " ")
			}
			c.makeDefaultsUse = append(c.makeDefaultsUse, use)
		}
		configDictDefaults["USE"] = strings.Join(c.makeDefaultsUse, " ")
		c.makeDefaults = nil
	}
	if len(c.uvlist) == 0 {
		for _, x := range strings.Split(c.ValueDict["USER_ORDER"], ":") {
			if _, ok := c.configDict[x]; ok {
				c.uvlist = append(c.uvlist, c.configDict[x])
			}
		}
		myutil.ReverseSlice(c.uvlist)
	}
	iu := c.configDict["pkg"]["IUSE"]
	iuse := []string{}
	if iu != "" {
		for _, x := range strings.Fields(iu) {
			iuse = append(iuse, strings.TrimPrefix(x, "+-"))
		}
	}
	myFlags = map[string]bool{}
	for _, curdb := range c.uvlist {
		for _, k := range useExpandUnprefixed {
			v := curdb[k]
			if v == "" {
				continue
			}
			for _, x := range strings.Fields(v) {
				if x[:1] == "-" {
					delete(myFlags, x[1:])
				} else {
					myFlags[x] = true
				}
			}
		}
		curUseExpand := []string{}
		for _, x := range useExpand {
			if _, ok := curdb[x]; ok {
				curUseExpand = append(curUseExpand, x)
			}
		}
		mySplit := strings.Fields(curdb["USE"])
		if len(mySplit) == 0 && len(curUseExpand) == 0 {
			continue
		}
		for _, x := range mySplit {
			if x == "-*" {
				myFlags = map[string]bool{}
				continue
			}
			if x[0] == '+' {
				msg.WriteMsg(output.Colorize("BAD", fmt.Sprintf("USE flags should not start with a '+': %s\n", x)), -1, nil)
				x = x[1:]
				if x == "" {
					continue
				}
			}
			if x[0] == '-' {
				if x[len(x)-2:] == "_*" {
					prefix := x[1 : len(x)-1]
					prefixLen := len(prefix)
					for y := range myFlags {
						if y[:prefixLen] == prefix {
							delete(myFlags, y)
						}
					}
				}
				delete(myFlags, x[1:])
				continue
			}
			if iuse != nil && x[len(x)-2:] == "_*" {
				prefix := x[:len(x)-1]
				prefixLen := len(prefix)
				hasIuse := false
				for _, y := range iuse {
					if y[:prefixLen] == prefix {
						hasIuse = true
						myFlags[y] = true
					}
				}
				if !hasIuse {
					myFlags[x] = true
				}
			} else {
				myFlags[x] = true
			}
		}
		if reflect.ValueOf(curdb).Pointer() == reflect.ValueOf(configDictDefaults).Pointer() {
			continue
		}
		for _, varr := range curUseExpand {
			varLower := strings.ToLower(varr)
			isNotIncremental := !myincrementals[varr]
			if isNotIncremental {
				prefix := varLower + "_"
				prefixLen := len(prefix)
				for x := range myFlags {
					if x[:prefixLen] == prefix {
						delete(myFlags, x)
					}
				}
			}
			for _, x := range strings.Fields(curdb[varr]) {
				if x[0] == '+' {
					if isNotIncremental {
						msg.WriteMsg(output.Colorize("BAD", fmt.Sprintf("Invalid '+' operator in non-incremental variable '%s': '%s'\n", varr, x)), -1, nil)
						continue
					} else {
						msg.WriteMsg(output.Colorize("BAD", fmt.Sprintf("Invalid '+' operator in non-incremental variable '%s': '%s'\n", varr, x)), -1, nil)
					}
					x = x[1:]
				}
				if x[0] == '-' {
					if isNotIncremental {
						msg.WriteMsg(output.Colorize("BAD", fmt.Sprintf("Invalid '+' operator in non-incremental variable '%s': '%s'\n", varr, x)), -1, nil)
						continue
					}
					delete(myFlags, varLower+"_"+x)
					continue
				}
				myFlags[varLower+"_"+x] = true
			}
		}
	}
	if c.Features != nil {
		c.Features.Features = map[string]bool{}
	} else {
		c.Features = NewFeaturesSet(c)
	}
	for _, x := range strings.Fields(c.ValueDict["FEATURES"]) {
		c.Features.Features[x] = true
	}
	c.Features.syncEnvVar()
	c.Features.validate()
	for x := range c.useforce {
		myFlags[x.Value] = true
	}
	for x := range c.usemask {
		delete(myFlags, x.Value)
	}
	m := []string{}
	for x := range myFlags {
		m = append(m, x)
	}
	sort.Strings(m)
	c.configList[len(c.configList)-1]["USE"] = strings.Join(m, " ")
	if c.mycpv == nil {
		for _, k := range useExpand {
			prefix := strings.ToLower(k) + "_"
			prefixLen := len(prefix)
			expandFlags := map[string]bool{}
			for x := range myFlags {
				if x[:prefixLen] == prefix {
					expandFlags[x[prefixLen:]] = true
				}
			}
			varSplit := strings.Fields(useExpandDict[k])
			v := []string{}
			for _, x := range varSplit {
				if expandFlags[x] {
					v = append(v, x)
				}
			}
			varSplit = v
			for _, v := range varSplit {
				delete(expandFlags, v)
			}
			e := []string{}
			for x := range expandFlags {
				e = append(e, x)
			}
			sort.Strings(e)
			varSplit = append(varSplit, e...)
			if len(varSplit) > 0 {
				c.configList[len(c.configList)-1][k] = strings.Join(varSplit, " ")
			} else if _, ok := c.ValueDict[k]; ok {
				c.configList[len(c.configList)-1][k] = ""
			}
		}
		for _, k := range useExpandUnprefixed {
			varSplit := strings.Fields(c.ValueDict[k])
			v := []string{}
			for _, x := range varSplit {
				if myFlags[x] {
					v = append(v, x)
				}
			}
			if len(varSplit) > 0 {
				c.configList[len(c.configList)-1][k] = strings.Join(varSplit, " ")
			} else if _, ok := c.ValueDict[k]; ok {
				c.configList[len(c.configList)-1][k] = ""
			}
		}

	}
}

func (c *Config) get_virts_p() map[string][]string {
	c.getVirtuals()
	return c.virtualsManager().getVirtsP()
}

func (c *Config) getVirtuals() map[string][]string {
	if c.virtualsManager()._treeVirtuals == nil {
		if c.LocalConfig {
			tempVartree := dbapi.NewVarTree(nil, c)
			c.virtualsManager()._populate_treeVirtuals(tempVartree)
		} else {
			c.virtualsManager()._treeVirtuals = map[string][]string{}
		}
	}

	return c.virtualsManager().getvirtuals()
}

func (c *Config) _populate_treeVirtuals_if_needed(vartree *dbapi.VarTree) {
	if c.virtualsManager()._treeVirtuals == nil {
		if c.LocalConfig {
			c.virtualsManager()._populate_treeVirtuals(vartree)
		} else {
			c.virtualsManager()._treeVirtuals = map[string][]string{}
		}
	}
}

func (c *Config) environ() map[string]string {
	mydict := map[string]string{}
	environ_filter := c.environFilter

	eapi1 := c.ValueDict["EAPI"]
	eapi_attrs := eapi.GetEapiAttrs(eapi1)
	phase := c.ValueDict["EBUILD_PHASE"]
	emerge_from := c.ValueDict["EMERGE_FROM"]
	filter_calling_env := false
	if c.mycpv != nil &&
		!(emerge_from == "ebuild" && phase == "setup") &&
		!myutil.Ins([]string{"clean", "cleanrm", "depend", "fetch"}, phase) {
		temp_dir := c.ValueDict["T"]
		if temp_dir != "" && myutil.PathExists(filepath.Join(temp_dir, "environment")) {
			filter_calling_env = true
		}
	}

	environ_whitelist := c.environWhitelist
	for x, myvalue := range c.ValueDict {
		if environ_filter[x] {
			continue
		}
		if filter_calling_env &&
			!environ_whitelist[x] &&
			!c.environWhitelistRe.MatchString(x) {
			continue
		}
		mydict[x] = myvalue
	}
	if !myutil.Inmss(mydict, "HOME") && myutil.Inmss(mydict, "BUILD_PREFIX") {
		msg.WriteMsg("*** HOME not set. Setting to "+mydict["BUILD_PREFIX"]+"\n", 0, nil)
		mydict["HOME"] = mydict["BUILD_PREFIX"][:]
	}

	if filter_calling_env {
		if phase != "" {
			whitelist := []string{}
			if "rpm" == phase {
				whitelist = append(whitelist, "RPMDIR")
			}
			for _, k := range whitelist {
				v := c.ValueDict[k]
				if v != "" {
					mydict[k] = v
				}
			}
		}
	}

	mydict["PORTAGE_FEATURES"] = c.ValueDict["FEATURES"]

	mydict["USE"] = c.ValueDict["PORTAGE_USE"]

	if !eapi.EapiExportsAa(eapi1) {
		delete(mydict, "AA")
	}

	if !eapi.EapiExportsMergeType(eapi1) {
		delete(mydict, "MERGE_TYPE")
	}

	src_like_phase := phase == "setup" || strings.HasPrefix(ebuild._phase_func_map[phase], "src_")

	if !(src_like_phase && eapi_attrs.Sysroot) {
		delete(mydict, "ESYSROOT")
	}

	if !(src_like_phase && eapi_attrs.Broot) {
		delete(mydict, "BROOT")
	}

	if phase == "depend" || (!c.Features.Features["force-prefix"] && eapi1 != "" && !eapi.eapiSupportsPrefix(eapi)) {
		delete(mydict, "ED")
		delete(mydict, "EPREFIX")
		delete(mydict, "EROOT")
		delete(mydict, "ESYSROOT")
	}

	if !myutil.Ins([]string{"pretend", "setup", "preinst", "postinst"}, phase) || !eapi.eapiExportsReplaceVars(eapi) {
		delete(mydict, "REPLACING_VERSIONS")
	}

	if !myutil.Ins([]string{"prerm", "postrm"}, phase) || !eapi.EapiExportsReplaceVars(eapi) {
		delete(mydict, "REPLACED_BY_VERSION")
	}

	if phase != "" && eapi_attrs.ExportsEbuildPhaseFunc {
		phase_func := ebuild._phase_func_map[phase]
		if phase_func != "" {
			mydict["EBUILD_PHASE_FUNC"] = phase_func
		}
	}

	if eapi_attrs.PosixishLocale {
		split_LC_ALL(mydict)
		mydict["LC_COLLATE"] = "C"
		if check_locale(silent = True, env = mydict) is
	False:
		for _, l := range []string{"C.UTF-8", "en_US.UTF-8", "en_GB.UTF-8", "C"} {
			mydict["LC_CTYPE"] = l
			if check_locale(silent = True, env = mydict){
				break
			}
		}
		else:
		raise
		AssertionError("C locale did not pass the test!")
	}

	if !eapi_attrs.ExportsPortdir {
		delete(mydict, "PORTDIR")
	}
	if !eapi_attrs.ExportsEclassdir {
		delete(mydict, "ECLASSDIR")
	}

	if !eapi_attrs.PathVariablesEndWithTrailingSlash {
		for _, v := range []string{"D", "ED", "ROOT", "EROOT", "ESYSROOT", "BROOT"} {
			if myutil.Inmss(mydict, v) {
				mydict[v] = strings.TrimRight(mydict[v], string(os.PathSeparator))
			}
		}
	}

	if myutil.Inmss(mydict, "SYSROOT") {
		mydict["SYSROOT"] = strings.TrimRight(mydict["SYSROOT"], string(os.PathSeparator))
	}

	builddir := mydict["PORTAGE_BUILDDIR"]
	distdir := mydict["DISTDIR"]
	mydict["PORTAGE_ACTUAL_DISTDIR"] = distdir
	mydict["DISTDIR"] = filepath.Join(builddir, "distdir")

	return mydict
}

func (c *Config) thirdpartymirrors()  map[string][]string {
	if c._thirdpartymirrors == nil {
		thirdparty_lists := []map[string][]string{}
		for _, repo_name := range myutil.Reversed(c.Repositories.PreposOrder) {
			thirdparty_lists = append(thirdparty_lists, grab.GrabDict(filepath.Join(
				c.Repositories.Prepos[repo_name].Location,
				"profiles", "thirdpartymirrors"), false, false, false, true, false))
		}
		c._thirdpartymirrors = grab.StackDictList(thirdparty_lists, 1, []string{}, 0)
	}
	return c._thirdpartymirrors
}

func (c *Config) archlist() map[string]bool {
	archlist := map[string]bool{}
	for _, myarch := range strings.Fields(c.ValueDict["PORTAGE_ARCHLIST"]) {
		archlist[myarch] = true
		archlist["~"+myarch] = true
	}
	return archlist
}

func (c *Config) Selinux_enabled() *bool {
	if c._selinux_enabled == nil {
		f := false
		c._selinux_enabled = &f
		if myutil.Ins(strings.Fields(c.ValueDict["USE"]), "selinux") {
			//if selinux {
			if _selinux.Is_selinux_enabled() {
				f = true
				c._selinux_enabled = &f
			}
			//} else {
			//	msg.WriteMsg("!!! SELinux module not found. Please verify that it was installed.\n", -1, nil)
			//}
		}
	}

	return c._selinux_enabled
}

// interface
func (c *Config) GetValueDict() map[string]string{
	return c.ValueDict
}
func (c *Config) GetLocalConfig() bool{
	return c.LocalConfig
}
func (c *Config) GetGlobalConfigPath() string{
	return c.GlobalConfigPath
}

/*
func loadUnpackDependenciesConfiguration(repositories *repository.RepoConfigLoader) map[string]map[string]map[string]string {
	repoDict := map[string]map[string]map[string]string{}
	for _, repo := range repositories.ReposWithProfiles() {
		for eapi1 := range eapi.SupportedEapis {
			if eapi.EapiHasAutomaticUnpackDependencies(eapi1) {
				fileName := path.Join(repo.Location, "profiles", "unpack_dependencies", eapi1)
				lines := grab.GrabFile(fileName, 0, true, false)
				for _, line := range lines {
					elements := strings.Fields(line[0])
					suffix := strings.ToLower(elements[0])
					if len(elements) == 1 {
						msg.WriteMsg(fmt.Sprintf("--- Missing unpack dependencies for '%s' suffix in '%s'\n", suffix, fileName), 0, nil)
					}
					depend := strings.Join(elements[1:], " ")
					dep.UseReduce[*Config](depend, map[string]bool{}, []string{}, false, []string{}, false, eapi, false, false, nil, nil, false)
					if repoDict[repo.Name] == nil {
						repoDict[repo.Name] = map[string]map[string]string{eapi1: {suffix: depend}}
					} else if repoDict[repo.Name][eapi1] == nil {
						repoDict[repo.Name][eapi1] = map[string]string{suffix: depend}
					} else {
						repoDict[repo.Name][eapi1][suffix] = depend
					}
				}
			}
		}
	}
	ret := map[string]map[string]map[string]string{}
	for _, repo := range repositories.ReposWithProfiles() {
		names := []string{}
		for _, v := range repo.MastersRepo {
			names = append(names, v.Name)
		}
		names = append(names, repo.Name)
		for _, repoName := range names {
			for eapi := range repoDict[repoName] {
				if repoDict[repoName] != nil {
					for suffix, depend := range repoDict[repoName][eapi] {
						if ret[repo.Name] == nil {
							ret[repo.Name] = map[string]map[string]string{eapi: {suffix: depend}}
						} else if repoDict[repo.Name][eapi] == nil {
							ret[repo.Name][eapi] = map[string]string{suffix: depend}
						} else {
							ret[repo.Name][eapi][suffix] = depend
						}
					}
				}
			}
		}
	}
	return ret
}
 */
