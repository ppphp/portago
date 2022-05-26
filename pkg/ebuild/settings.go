package ebuild

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/data"
	data_init "github.com/ppphp/portago/pkg/data/_init"
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/process"
	"github.com/ppphp/portago/pkg/repository"
	"github.com/ppphp/portago/pkg/util"
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
	validateCommands = map[string]bool{"PORTAGE_BZIP2_COMMAND": true, "PORTAGE_BUNZIP2_COMMAND": true}
	categoryRe       = regexp.MustCompile("^\\w[-.+\\w]*$")
)

func lazyIuseRegex(s []string) string {
	r := []string{}
	for _, v := range s {
		r = append(r, regexp.QuoteMeta(v))
	}
	sort.Strings(r)
	str := fmt.Sprintf("^(%s)$", strings.Join(r, "|"))
	str = strings.Replace(str, "\\.\\*", ".*", -1)
	return str
}

func getFeatureFlags(attrs eapi.EapiAttrs) map[string]bool {
	flags := map[string]bool{}
	if attrs.FeatureFlagTest {
		flags["test"] = true
	}
	if attrs.featureFlagTargetroot {
		flags["targetroot"] = true
	}
	return flags
}

func bestFromDict(key string, topDict map[string]map[string]string, keyOrders []string, EmptyOnError, FullCopy, AllowEmpty int) string {
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

type iuseImplicitMatchCache struct {
	iuseImplicitRe *regexp.Regexp
	cache          map[string]bool
}

func (i *iuseImplicitMatchCache) call(flag string) bool {
	if v, ok := i.cache[flag]; ok {
		return v
	}
	m := i.iuseImplicitRe.MatchString(flag)
	i.cache[flag] = m
	return m
}

func NewIuseImplicitMatchCache(settings *Config) *iuseImplicitMatchCache {
	i := &iuseImplicitMatchCache{}
	g := []string{}
	for x := range settings.getImplicitIuse() {
		g = append(g, x)
	}
	i.iuseImplicitRe = regexp.MustCompile(fmt.Sprintf("^(%s)$", strings.Join(g, "|")))
	i.cache = map[string]bool{}
	return i
}

type Config struct {
	ValueDict                                                                                                       map[string]string
	constantKeys, setcpvAuxKeys, envBlacklist, environFilter, environWhitelist, globalOnlyVars, caseInsensitiveVars map[string]bool
	tolerent, unmatchedRemoval, localConfig, setCpvActive                                                           bool
	locked                                                                                                          int
	acceptChostRe                                                                                                   *regexp.Regexp
	penv, modifiedkeys                                                                                              []string
	mycpv                                                                                                           *versions.PkgStr
	setcpvArgsHash                                                                                                  struct {
		cpv  *versions.PkgStr
		mydb *dbapi.vardbapi
	}
	sonameProvided                                                                                                                       map[*dep.SonameAtom]bool
	parentStable, _selinux_enabled                                                                                                       *bool
	puse, depcachedir, profilePath, defaultFeaturesUse, userProfileDir, globalConfigPath                                                 string
	useManager                                                                                                                           *UseManager
	keywordsManagerObj                                                                                                                   *KeywordsManager
	maskManagerObj                                                                                                                       *maskManager
	virtualsManagerObj                                                                                                                   *VirtualManager
	licenseManager                                                                                                                       *LicenseManager
	iuseImplicitMatch                                                                                                                    *iuseImplicitMatchCache
	unpackDependencies                                                                                                                   map[string]map[string]map[string]string
	packages, usemask, useforce                                                                                                          map[*dep.Atom]string
	ppropertiesdict, pacceptRestrict, penvdict                                                                                           map[string]map[*dep.Atom][]string
	makeDefaultsUse, featuresOverrides, acceptRestrict, profiles                                                                         []string
	profileBashrc                                                                                                                        []bool
	lookupList, configList, makeDefaults, uvlist                                                                                         []map[string]string
	repoMakeDefaults, configDict                                                                                                         map[string]map[string]string
	backupenv, defaultGlobals, deprecatedKeys, useExpandDict, acceptProperties, expandMap                                                map[string]string
	pprovideddict                                                                                                                        map[string][]string
	pbashrcdict                                                                                                                          map[*profileNode]map[string]map[*dep.Atom][]string
	prevmaskdict                                                                                                                         map[string][]*dep.Atom
	modulePriority, incrementals, validateCommands, unknownFeatures, nonUserVariables, envDBlacklist, pbashrc, categories, iuseEffective map[string]bool
	Features                                                                                                                             *featuresSet
	Repositories                                                                                                                         *repository.RepoConfigLoader
	modules                                                                                                                              map[string]map[string][]string
	locationsManager                                                                                                                     *LocationsManager
	environWhitelistRe                                                                                                                   *regexp.Regexp
	_tolerant                                                                                                                            bool
	_thirdpartymirrors                                                                                                                   map[string][]string
}

func (c *Config) initIuse() {
	c.iuseEffective = c.calcIuseEffective()
	c.iuseImplicitMatch = NewIuseImplicitMatchCache(c)
}

func (c *Config) _validateCommands() {
	for k := range validateCommands {
		v := c.ValueDict[k]
		if v != "" {
			valid, vSplit := validateCmdVar(v)
			if !valid {
				if len(vSplit) > 0 {
					msg.WriteMsgLevel(fmt.Sprintf("%s setting is invalid: '%s'\n", k, v), 40, -1)
				}

				v = c.configDict["globals"][k]
				if v != "" {
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
	st, _ := os.Stat(c.ValueDict["EROOT"])
	if st.Mode()|os.FileMode(os.O_WRONLY) == 0 {
		return
	}
	dirModeMap := map[string]struct {
		gid           uint32
		mode          os.FileMode
		mask          os.FileMode
		preservePerms bool
	}{
		"tmp":              {-1, 01777, 0, true},
		"var/tmp":          {-1, 01777, 0, true},
		_const.PrivatePath: {*data.portage_gid, 02750, 02, false},
		_const.CachePath:   {*data.portage_gid, 0755, 02, false},
	}

	for myPath, s := range dirModeMap {
		gid, mode, modemask, preservePerms := s.gid, s.mode, s.mask, s.preservePerms
		myDir := path.Join(c.ValueDict["EROOT"], myPath)
		st, _ := os.Stat(myDir)
		if preservePerms && st.IsDir() {
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
		c.keywordsManagerObj = NewKeywordsManager(c.locationsManager.profilesComplex, c.locationsManager.absUserConfig, c.localConfig, c.configDict["defaults"]["ACCEPT_KEYWORDS"])
	}
	return c.keywordsManagerObj
}

func (c *Config) maskManager() *maskManager {
	if c.maskManagerObj == nil {
		c.maskManagerObj = NewMaskManager(c.Repositories, c.locationsManager.profilesComplex, c.locationsManager.absUserConfig, c.localConfig, c.unmatchedRemoval)
	}
	return c.maskManagerObj
}

func (c *Config) virtualsManager() *VirtualManager {
	if c.virtualsManagerObj == nil {
		c.virtualsManagerObj = NewVirtualManager(c.profiles)
	}
	return c.virtualsManagerObj
}

func (c *Config) pkeywordsdict() map[string]map[*dep.Atom][]string {
	return c.keywordsManager().pkeywordsDict
}

func (c *Config) pmaskdict() map[string][]*dep.Atom {
	return c.maskManager()._pmaskdict
}

func (c *Config) _punmaskdict() map[string][]*dep.Atom {
	return c.maskManager()._punmaskdict
}

func (c *Config) soname_provided() map[*dep.SonameAtom]bool {
	if c.sonameProvided == nil {
		e := []map[string][]string{}
		for _, x := range c.profiles {
			e = append(e, util.GrabDict(path.Join(x, "soname.provided"), false, false, true, true, false))
		}
		c.sonameProvided = map[*dep.SonameAtom]bool{}
		d := util.stackDictList(e, 1, []string{}, 0)
		for cat, sonames := range d {
			for _, soname := range sonames {
				c.sonameProvided[NewSonameAtom(cat, soname)] = true
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
			"packages", "Use.force", "Use.mask"} {
			if util.ExistsRaiseEaccess(path.Join(c.profilePath, x)) {
				in = false
				break
			}
		}
		if in {
			profileBroken = true
		}
	}

	if profileBroken && !portage.SyncMode {
		absProfilePath := ""
		for _, x := range []string{_const.ProfilePath, "etc/make.profile"} {
			x = path.Join(c.ValueDict["PORTAGE_CONFIGROOT"], x)
			if _, err := os.Lstat(x); err != nil {
			} else {
				absProfilePath = x
				break
			}
		}
		if absProfilePath == "" {
			absProfilePath = path.Join(c.ValueDict["PORTAGE_CONFIGROOT"], _const.ProfilePath)
		}

		msg.WriteMsg(fmt.Sprintf("\n\n!!! %s is not a symlink and will probably prevent most merges.\n", absProfilePath), -1, nil)
		msg.WriteMsg(fmt.Sprintf("!!! It should point into a profile within %s/profiles/\n", c.ValueDict["PORTDIR"]), 0, nil)
		msg.WriteMsg(fmt.Sprintf("!!! (You can safely ignore this message when syncing. It's harmless.)\n\n\n"), 0, nil)
	}
	if !process.sandbox_capable && (c.Features.Features["sandbox"] || c.Features.Features["usersandbox"]) {
		cp, _ := filepath.EvalSymlinks(c.profilePath)
		pp, _ := filepath.EvalSymlinks(path.Join(c.ValueDict["PORTAGE_CONFIGROOT"], _const.ProfilePath))
		if c.profilePath != "" && cp == pp {
			msg.WriteMsg(output.Colorize("BAD", fmt.Sprintf("!!! Problem with sandbox binary. Disabling...\n\n")), -1, nil)
		}
	}
	if c.Features.Features["fakeroot"] && !process.fakeroot_capable {
		msg.WriteMsg(fmt.Sprintf("!!! FEATURES=fakeroot is enabled, but the fakeroot binary is not installed.\n"), -1, nil)
	}

	if binpkgCompression, ok := c.ValueDict["BINPKG_COMPRESS"]; ok {
		if compression, ok := util._compressors[binpkgCompression]; !ok {
			msg.WriteMsg(fmt.Sprintf("!!! BINPKG_COMPRESS contains invalid or unsupported compression method: %s", binpkgCompression), -1, nil)
		} else {
			if cs, err := shlex.Split(util.varExpand(compression["compress"], c.ValueDict, nil)); err != nil {

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
		return errors.New("")
	}
	return nil
}

func (c *Config) BackupChanges(key string) {
	c.modifying()
	if _, ok := c.configDict["env"][key]; key != "" && ok {
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
		c.setcpvArgsHash = struct {
			cpv  *versions.PkgStr
			mydb *dbapi.vardbapi
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
func (c *Config) SetCpv(mycpv *versions.PkgStr, mydb *dbapi.vardbapi) {
	if c.setCpvActive {
		//AssertionError('setcpv recursion detected')
	}
	c.setCpvActive = true
	defer func() { c.setCpvActive = false }()
	c.modifying()

	var pkg *versions.PkgStr = nil
	var explicitIUse map[string]bool = nil
	var builtUse []string = nil
	if mycpv == c.setcpvArgsHash.cpv && mydb == c.setcpvArgsHash.mydb {
		return
	}
	c.setcpvArgsHash.cpv = mycpv
	c.setcpvArgsHash.mydb = mydb

	hasChanged := false
	c.mycpv = mycpv
	s := versions.catsplit(mycpv.string)
	cat := s[0]
	pf := s[1]
	cp := versions.cpvGetKey(mycpv.string, "")
	cpvSlot := c.mycpv
	pkgInternalUse := ""
	pkgInternalUseList := []string{}
	featureUse := []string{}
	iUse := ""
	pkgConfigDict := c.configDict["pkg"]
	previousIUse := pkgConfigDict["IUSE"]
	previousIUseEffective := pkgConfigDict["IUSE_EFFECTIVE"]
	previousFeatures := pkgConfigDict["FEATURES"]
	previousPEnv := c.penv
	auxKeys := c.setcpvAuxKeys

	pkgConfigDict = map[string]string{}

	pkgConfigDict["CATEGORY"] = cat
	pkgConfigDict["PF"] = pf

	repository := ""
	eapi := ""
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
		eapi = pkgConfigDict["EAPI"]

		repository = pkgConfigDict["repository"]
		delete(pkgConfigDict, "repository")
		if repository != "" {
			pkgConfigDict["PORTAGE_REPO_NAME"] = repository
		}
		iUse = pkgConfigDict["IUSE"]
		if pkg == nil {
			c.mycpv = versions.NewPkgStr(c.mycpv.string, pkgConfigDict, c, "", "", "", 0, 0, "", 0, nil)
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

	EapiAttrs := eapi.getEapiAttrs(eapi)
	if pkgInternalUse != c.configDict["pkginternal"]["USE"] {
		c.configDict["pkginternal"]["USE"] = pkgInternalUse
		hasChanged = true
	}

	var repoEnv []map[string]string = nil
	if repository != "" && repository != (&emerge.Package{}).UnknownRepo {
		repos := []string{}
		for _, repo := range c.Repositories.getitem(repository).mastersRepo {
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
			var cpDict map[*dep.Atom][]string = nil
			if _, ok := c.useManager.repoPuseDict[repo]; !ok {
				cpDict = map[*dep.Atom][]string{}
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
			c.configDict["repo"][k.value] = v
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
	c.configDict["pkg"]["PKGUSE"] = c.puse[:]
	c.configDict["pkg"]["USE"] = c.puse[:]

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
			if _, ok := pkgConfigDict["USE"]; ok {
				pkgConfigDict["USE"] = pkgConfigDict["USE"] + " " + c.puse
			} else {
				pkgConfigDict["USE"] = c.puse
			}
		}
	} else if len(previousPEnv) > 0 {
		hasChanged = true
	}
	if !(previousIUse == iUse &&
		((previousIUseEffective != "") == EapiAttrs.iuseEffective)) {
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
	if EapiAttrs.iuseEffective {
		iUseImplicitMatch = c.iuseEffectiveMatch
	} else {
		iUseImplicitMatch = c.iuseImplicitMatch.call
	}

	rawRestrict := ""
	if pkg == nil {
		rawRestrict = pkgConfigDict["RESTRICT"]
	} else {
		rawRestrict = pkg.metadata["RESTRICT"]
	}

	restrictTest := false
	if rawRestrict != "" {
		var restrict []string = nil
		if builtUse != nil {
			useList := map[string]bool{}
			for _, x := range builtUse {
				useList[x] = true
			}
			restrict = dep.useReduce(rawRestrict, useList, []string{}, false, []string{}, false, "", false, true, nil, nil, false)
		} else {
			useList := map[string]bool{}
			for _, x := range strings.Fields(c.ValueDict["USE"]) {
				if explicitIUse[x] || iUseImplicitMatch(x) {
					useList[x] = true
				}
			}
			restrict = dep.useReduce(rawRestrict, useList, []string{}, false, []string{}, false, "", false, true, nil, nil, false)
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
	restrict := dep.useReduce(c.ValueDict["RESTRICT"], map[string]bool{}, []string{}, false, []string{}, false, "", false, false, nil, nil, false)
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
	if EapiAttrs.iuseEffective {

		portageIuse = myutil.CopyMapSB(c.iuseEffective)
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
			var at *dep.Atom
			for a := range c.usemask {
				if a.value == "test" {
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
			if a.value == "test" {
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
					if u.value == x {
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
						if u.value == x {
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

func (c *Config) iuseEffectiveMatch(flag string) bool {
	return c.iuseEffective[flag]
}

func (c *Config) calcIuseEffective() map[string]bool {
	iuseEffective := map[string]bool{}
	for _, x := range strings.Fields(c.ValueDict["IUSE_IMPLICIT"]) {
		iuseEffective[x] = true
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
			iuseEffective[x] = true
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
			iuseEffective[lowerV+"_"+x] = true
		}
	}
	return iuseEffective
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
		iuseImplicit[x.value] = true
	}
	for x := range c.useforce {
		iuseImplicit[x.value] = true
	}
	iuseImplicit["build"] = true
	iuseImplicit["bootstrap"] = true

	return iuseImplicit
}

func (c *Config) _getUseMask(pkg *versions.PkgStr, stable *bool) map[*dep.Atom]string {
	return c.useManager.getUseMask(pkg, stable)
}

func (c *Config) _getUseForce(pkg *versions.PkgStr, stable *bool) map[*dep.Atom]string {
	return c.useManager.getUseForce(pkg, stable)
}

func (c *Config) _getMaskAtom(cpv *versions.PkgStr, metadata map[string]string) *dep.Atom {
	return c.maskManager().getMaskAtom(cpv, metadata["SLOT"], metadata["repository"])
}

func (c *Config) _getRawMaskAtom(cpv *versions.PkgStr, metadata map[string]string) *dep.Atom {
	return c.maskManager().getRawMaskAtom(cpv, metadata["SLOT"], metadata["repository"])
}

func (c *Config) IsStable(pkg *versions.PkgStr) bool {
	return c.keywordsManager().isStable(pkg, c.ValueDict["ACCEPT_KEYWORDS"], c.configDict["backupenv"]["ACCEPT_KEYWORDS"])
}

func (c *Config) _getKeywords(cpv *versions.PkgStr, metadata map[string]string) map[*dep.Atom]string {
	return c.keywordsManager().getKeywords(cpv, metadata["SLOT"], metadata["KEYWORDS"], metadata["repository"])
}

func (c *Config) _getMissingKeywords(cpv *versions.PkgStr, metadata map[string]string) map[*dep.Atom]string {
	backupedAcceptKeywords := c.configDict["backupenv"]["ACCEPT_KEYWORDS"]
	globalAcceptKeywords := c.ValueDict["ACCEPT_KEYWORDS"]
	return c.keywordsManager().GetMissingKeywords(cpv, metadata["SLOT"], metadata["KEYWORDS"], metadata["repository"], globalAcceptKeywords, backupedAcceptKeywords)
}

func (c *Config) _getRawMissingKeywords(cpv *versions.PkgStr, metadata map[string]string) map[*dep.Atom]string {
	return c.keywordsManager().getRawMissingKeywords(cpv, metadata["SLOT"], metadata["KEYWORDS"], metadata["repository"], c.ValueDict["ACCEPT_KEYWORDS"])
}

func (c *Config) _getPKeywords(cpv *versions.PkgStr, metadata map[string]string) []string {
	globalAcceptKeywords := c.ValueDict["ACCEPT_KEYWORDS"]
	return c.keywordsManager().getPKeywords(cpv, metadata["SLOT"], metadata["repository"], globalAcceptKeywords)
}

func (c *Config) _getMissingLicenses(cpv *versions.PkgStr, metadata map[string]string) []string {
	return c.licenseManager.getMissingLicenses(cpv, metadata["USE"], metadata["LICENSE"], metadata["SLOT"], metadata["repository"])
}

func (c *Config) _getMissingProperties(cpv *versions.PkgStr, metadata map[string]string) []string {

	accept_properties := []string{}
	for k := range c.acceptProperties{
		accept_properties = append(accept_properties, k)
	}
	//try:
	//	cpv.slot
	//	except AttributeError:
	//	cpv = _pkg_str(cpv, metadata=metadata, settings=c)
	cp := versions.cpvGetKey(cpv.string, "")
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
	for _, v := range dep.useReduce(properties_str, map[string]bool{}, []string{}, true, []string{}, false, "", false, true, nil, nil, false) {
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
	for _, x := range dep.useReduce(properties_str, usemsb, []string{}, false, []string{}, false, "", false, true, nil, nil, false) {
		if !acceptable_properties[x] {
			ret = append(ret, x)
		}
	}
	return ret
}

func (c *Config) _getMissingRestrict(cpv *versions.PkgStr, metadata map[string]string) []string {

	accept_restrict := []string{}
	for _, k := range c.acceptRestrict{
		accept_restrict = append(accept_restrict, k)
	}
	//try:
	//	cpv.slot
	//	except AttributeError:
	//	cpv = _pkg_str(cpv, metadata=metadata, settings=c)
	cp := versions.cpvGetKey(cpv.string, "")
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
	for _, v := range dep.useReduce(restrict_str, map[string]bool{}, []string{}, true, []string{}, false, "", false, true, nil, nil, false) {
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
	for _, x := range dep.useReduce(restrict_str, usemsb, []string{}, false, []string{}, false, "", false, true, nil, nil, false) {
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
	if c.localConfig {
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
	if c.localConfig {
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
		myFlags[x.value] = true
	}
	for x := range c.usemask {
		delete(myFlags, x.value)
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
		if c.localConfig {
			tempVartree := dbapi.NewVarTree(nil, c)
			c.virtualsManager()._populate_treeVirtuals(tempVartree)
		} else {
			c.virtualsManager()._treeVirtuals = map[string][]string{}
		}
	}

	return c.virtualsManager().getvirtuals()
}

func (c *Config) _populate_treeVirtuals_if_needed(vartree *dbapi.varTree) {
	if c.virtualsManager()._treeVirtuals == nil {
		if c.localConfig {
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

	src_like_phase := phase == "setup" || strings.HasPrefix(atom._phase_func_map[phase], "src_")

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
		phase_func := _phase_func_map[phase]
		if phase_func != "" {
			mydict["EBUILD_PHASE_FUNC"] = phase_func
		}
	}

	if eapi_attrs.posixishLocale {
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

	if !eapi_attrs.exportsPortdir {
		delete(mydict, "PORTDIR")
	}
	if !eapi_attrs.exportsEclassdir {
		delete(mydict, "ECLASSDIR")
	}

	if !eapi_attrs.pathVariablesEndWithTrailingSlash {
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
		for _, repo_name := range myutil.Reversed(c.Repositories.preposOrder) {
			thirdparty_lists = append(thirdparty_lists, util.GrabDict(filepath.Join(
				c.Repositories.Prepos[repo_name].Location,
				"profiles", "thirdpartymirrors"), false, false, false, true, false))
		}
		c._thirdpartymirrors = util.StackDictList(thirdparty_lists, 1, []string{}, 0)
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

func (c *Config) selinux_enabled() bool {
	if c._selinux_enabled == nil {
		f := false
		c._selinux_enabled = &f
		if myutil.Ins(strings.Fields(c.ValueDict["USE"]), "selinux") {
			if selinux {
				if selinux.is_selinux_enabled() == 1 {
					f = true
					c._selinux_enabled = &f
				}
			} else {
				msg.WriteMsg("!!! SELinux module not found. Please verify that it was installed.\n", -1, nil)
			}
		}
	}

	return c._selinux_enabled
}

var eapiCache = map[string]bool{}

// nil, nil, "", nil, "","","","",true, nil, false, nil
func NewConfig(clone *Config, mycpv *versions.PkgStr, configProfilePath string, configIncrementals []string, configRoot, targetRoot, sysroot, eprefix string, localConfig bool, env map[string]string, unmatchedRemoval bool, repositories *repository.RepoConfigLoader) *Config {
	eapiCache = make(map[string]bool)
	tolerant := portage.InitializingGlobals == nil
	c := &Config{
		constantKeys:   map[string]bool{"PORTAGE_BIN_PATH": true, "PORTAGE_GID": true, "PORTAGE_PYM_PATH": true, "PORTAGE_PYTHONPATH": true},
		deprecatedKeys: map[string]string{"PORTAGE_LOGDIR": "PORT_LOGDIR", "PORTAGE_LOGDIR_CLEAN": "PORT_LOGDIR_CLEAN"},
		setcpvAuxKeys: map[string]bool{"BDEPEND": true, "DEFINED_PHASES": true, "DEPEND": true, "EAPI": true, "HDEPEND": true,
			"INHERITED": true, "IUSE": true, "REQUIRED_USE": true, "KEYWORDS": true, "LICENSE": true, "PDEPEND": true,
			"PROPERTIES": true, "SLOT": true, "repository": true, "RESTRICT": true},
		caseInsensitiveVars: map[string]bool{"AUTOCLEAN": true, "NOCOLOR": true},
		defaultGlobals:      map[string]string{"ACCEPT_PROPERTIES": "*", "PORTAGE_BZIP2_COMMAND": "bzip2"},
		envBlacklist: map[string]bool{
			"A": true, "AA": true, "BDEPEND": true, "BROOT": true, "CATEGORY": true, "DEPEND": true, "DESCRIPTION": true,
			"DOCS": true, "EAPI": true,
			"EBUILD_FORCE_TEST": true, "EBUILD_PHASE": true,
			"EBUILD_PHASE_FUNC": true, "EBUILD_SKIP_MANIFEST": true,
			"ED": true, "EMERGE_FROM": true, "EPREFIX": true, "EROOT": true,
			"GREP_OPTIONS": true, "HDEPEND": true, "HOMEPAGE": true,
			"INHERITED": true, "IUSE": true, "IUSE_EFFECTIVE": true,
			"KEYWORDS": true, "LICENSE": true, "MERGE_TYPE": true,
			"PDEPEND": true, "PF": true, "PKGUSE": true, "PORTAGE_BACKGROUND": true,
			"PORTAGE_BACKGROUND_UNMERGE": true, "PORTAGE_BUILDDIR_LOCKED": true,
			"PORTAGE_BUILT_USE": true, "PORTAGE_CONFIGROOT": true,
			"PORTAGE_INTERNAL_CALLER": true, "PORTAGE_IUSE": true,
			"PORTAGE_NONFATAL": true, "PORTAGE_PIPE_FD": true, "PORTAGE_REPO_NAME": true,
			"PORTAGE_USE": true, "PROPERTIES": true, "RDEPEND": true, "REPOSITORY": true,
			"REQUIRED_USE": true, "RESTRICT": true, "ROOT": true, "SLOT": true, "SRC_URI": true, "_": true},
		environFilter: map[string]bool{
			"DEPEND": true, "RDEPEND": true, "PDEPEND": true, "SRC_URI": true,
			"INFOPATH": true, "MANPATH": true, "USER": true,
			"HISTFILE": true, "POSIXLY_CORRECT": true,
			"ACCEPT_CHOSTS": true, "ACCEPT_KEYWORDS": true, "ACCEPT_PROPERTIES": true,
			"ACCEPT_RESTRICT": true, "AUTOCLEAN": true,
			"BINPKG_COMPRESS": true, "BINPKG_COMPRESS_FLAGS": true,
			"CLEAN_DELAY": true, "COLLISION_IGNORE": true,
			"CONFIG_PROTECT": true, "CONFIG_PROTECT_MASK": true,
			"DCO_SIGNED_OFF_BY":      true,
			"EGENCACHE_DEFAULT_OPTS": true, "EMERGE_DEFAULT_OPTS": true,
			"EMERGE_LOG_DIR":       true,
			"EMERGE_WARNING_DELAY": true,
			"FETCHCOMMAND":         true, "FETCHCOMMAND_FTP": true,
			"FETCHCOMMAND_HTTP": true, "FETCHCOMMAND_HTTPS": true,
			"FETCHCOMMAND_RSYNC": true, "FETCHCOMMAND_SFTP": true,
			"GENTOO_MIRRORS": true, "NOCONFMEM": true, "O": true,
			"PORTAGE_BACKGROUND": true, "PORTAGE_BACKGROUND_UNMERGE": true,
			"PORTAGE_BINHOST": true, "PORTAGE_BINPKG_FORMAT": true,
			"PORTAGE_BUILDDIR_LOCKED": true,
			"PORTAGE_CHECKSUM_FILTER": true,
			"PORTAGE_ELOG_CLASSES":    true,
			"PORTAGE_ELOG_MAILFROM":   true, "PORTAGE_ELOG_MAILSUBJECT": true,
			"PORTAGE_ELOG_MAILURI": true, "PORTAGE_ELOG_SYSTEM": true,
			"PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS": true, "PORTAGE_FETCH_RESUME_MIN_SIZE": true,
			"PORTAGE_GPG_DIR": true,
			"PORTAGE_GPG_KEY": true, "PORTAGE_GPG_SIGNING_COMMAND": true,
			"PORTAGE_IONICE_COMMAND":      true,
			"PORTAGE_PACKAGE_EMPTY_ABORT": true,
			"PORTAGE_REPO_DUPLICATE_WARN": true,
			"PORTAGE_RO_DISTDIRS":         true,
			"PORTAGE_RSYNC_EXTRA_OPTS":    true, "PORTAGE_RSYNC_OPTS": true,
			"PORTAGE_RSYNC_RETRIES": true, "PORTAGE_SSH_OPTS": true, "PORTAGE_SYNC_STALE": true,
			"PORTAGE_USE":    true,
			"PORTAGE_LOGDIR": true, "PORTAGE_LOGDIR_CLEAN": true,
			"QUICKPKG_DEFAULT_OPTS": true, "REPOMAN_DEFAULT_OPTS": true,
			"RESUMECOMMAND": true, "RESUMECOMMAND_FTP": true,
			"RESUMECOMMAND_HTTP": true, "RESUMECOMMAND_HTTPS": true,
			"RESUMECOMMAND_RSYNC": true, "RESUMECOMMAND_SFTP": true,
			"UNINSTALL_IGNORE": true, "USE_EXPAND_HIDDEN": true, "USE_ORDER": true,
			"__PORTAGE_HELPER": true,
			"SYNC":             true},
		environWhitelist: map[string]bool{"ACCEPT_LICENSE": true, "BASH_ENV": true, "BROOT": true, "BUILD_PREFIX": true, "COLUMNS": true, "D": true,
			"DISTDIR": true, "DOC_SYMLINKS_DIR": true, "EAPI": true, "EBUILD": true,
			"EBUILD_FORCE_TEST": true,
			"EBUILD_PHASE":      true, "EBUILD_PHASE_FUNC": true, "ECLASSDIR": true, "ECLASS_DEPTH": true, "ED": true,
			"EMERGE_FROM": true, "EPREFIX": true, "EROOT": true, "ESYSROOT": true,
			"FEATURES": true, "FILESDIR": true, "HOME": true, "MERGE_TYPE": true, "NOCOLOR": true, "PATH": true,
			"PKGDIR": true,
			"PKGUSE": true, "PKG_LOGDIR": true, "PKG_TMPDIR": true,
			"PORTAGE_ACTUAL_DISTDIR": true, "PORTAGE_ARCHLIST": true, "PORTAGE_BASHRC_FILES": true,
			"PORTAGE_BASHRC": true, "PM_EBUILD_HOOK_DIR": true,
			"PORTAGE_BINPKG_FILE": true, "PORTAGE_BINPKG_TAR_OPTS": true,
			"PORTAGE_BINPKG_TMPFILE": true,
			"PORTAGE_BIN_PATH":       true,
			"PORTAGE_BUILDDIR":       true, "PORTAGE_BUILD_GROUP": true, "PORTAGE_BUILD_USER": true,
			"PORTAGE_BUNZIP2_COMMAND": true, "PORTAGE_BZIP2_COMMAND": true,
			"PORTAGE_COLORMAP": true, "PORTAGE_COMPRESS": true, "PORTAGE_COMPRESSION_COMMAND": true,
			"PORTAGE_COMPRESS_EXCLUDE_SUFFIXES": true,
			"PORTAGE_CONFIGROOT":                true, "PORTAGE_DEBUG": true, "PORTAGE_DEPCACHEDIR": true,
			"PORTAGE_DOHTML_UNWARNED_SKIPPED_EXTENSIONS": true,
			"PORTAGE_DOHTML_UNWARNED_SKIPPED_FILES":      true,
			"PORTAGE_DOHTML_WARN_ON_SKIPPED_FILES":       true,
			"PORTAGE_EBUILD_EXIT_FILE":                   true, "PORTAGE_FEATURES": true,
			"PORTAGE_GID": true, "PORTAGE_GRPNAME": true,
			"PORTAGE_INTERNAL_CALLER": true,
			"PORTAGE_INST_GID":        true, "PORTAGE_INST_UID": true,
			"PORTAGE_IPC_DAEMON": true, "PORTAGE_IUSE": true, "PORTAGE_ECLASS_LOCATIONS": true,
			"PORTAGE_LOG_FILE": true, "PORTAGE_OVERRIDE_EPREFIX": true, "PORTAGE_PIPE_FD": true,
			"PORTAGE_PYM_PATH": true, "PORTAGE_PYTHON": true,
			"PORTAGE_PYTHONPATH": true, "PORTAGE_QUIET": true,
			"PORTAGE_REPO_NAME": true, "PORTAGE_REPOSITORIES": true, "PORTAGE_RESTRICT": true,
			"PORTAGE_SIGPIPE_STATUS": true, "PORTAGE_SOCKS5_PROXY": true,
			"PORTAGE_TMPDIR": true, "PORTAGE_UPDATE_ENV": true, "PORTAGE_USERNAME": true,
			"PORTAGE_VERBOSE": true, "PORTAGE_WORKDIR_MODE": true, "PORTAGE_XATTR_EXCLUDE": true,
			"PORTDIR": true, "PORTDIR_OVERLAY": true, "PREROOTPATH": true, "PYTHONDONTWRITEBYTECODE": true,
			"REPLACING_VERSIONS": true, "REPLACED_BY_VERSION": true,
			"ROOT": true, "ROOTPATH": true, "SYSROOT": true, "T": true,
			"USE_EXPAND": true, "USE_ORDER": true, "WORKDIR": true,
			"XARGS": true, "__PORTAGE_TEST_HARDLINK_LOCKS": true,
			"INSTALL_MASK": true, "PKG_INSTALL_MASK": true,
			"A": true, "AA": true, "CATEGORY": true, "P": true, "PF": true, "PN": true, "PR": true, "PV": true, "PVR": true,
			"COLORTERM": true, "DISPLAY": true, "EDITOR": true, "LESS": true,
			"LESSOPEN": true, "LOGNAME": true, "LS_COLORS": true, "PAGER": true,
			"TERM": true, "TERMCAP": true, "USER": true,
			"ftp_proxy": true, "http_proxy": true, "no_proxy": true,
			"TMPDIR": true, "TEMP": true, "TMP": true,
			"LANG": true, "LC_COLLATE": true, "LC_CTYPE": true, "LC_MESSAGES": true,
			"LC_MONETARY": true, "LC_NUMERIC": true, "LC_TIME": true, "LC_PAPER": true,
			"LC_ALL":  true,
			"CVS_RSH": true, "ECHANGELOG_USER": true,
			"GPG_AGENT_INFO": true,
			"SSH_AGENT_PID":  true, "SSH_AUTH_SOCK": true,
			"STY": true, "WINDOW": true, "XAUTHORITY": true},
		globalOnlyVars:     map[string]bool{"CONFIG_PROTECT": true},
		environWhitelistRe: regexp.MustCompile(`^(CCACHE_|DISTCC_).*`),
		tolerent:           tolerant, unmatchedRemoval: unmatchedRemoval, localConfig: localConfig}

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
		c.unpackDependencies = clone.unpackDependencies
		c.defaultFeaturesUse = clone.defaultFeaturesUse
		c.iuseEffective = clone.iuseEffective
		c.iuseImplicitMatch = clone.iuseImplicitMatch
		c.nonUserVariables = clone.nonUserVariables
		c.envDBlacklist = clone.envDBlacklist
		c.pbashrc = clone.pbashrc
		c.repoMakeDefaults = clone.repoMakeDefaults
		c.usemask = clone.usemask
		c.useforce = clone.useforce
		c.puse = clone.puse
		c.userProfileDir = clone.userProfileDir
		c.localConfig = clone.localConfig
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
		c.modules = clone.modules       // TODO deepcopy
		c.penv = clone.penv             // TODO deepcopy
		c.configDict = clone.configDict // TODO deepcopy
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
		c.useExpandDict = myutil.CopyMapSS(clone.useExpandDict)
		c.backupenv = c.configDict["backupenv"]
		c.prevmaskdict = clone.prevmaskdict   // CopyMapSS(clone.prevmaskdict)
		c.pprovideddict = clone.pprovideddict //CopyMapSS()
		c.Features = NewFeaturesSet(c)
		c.Features.Features = myutil.CopyMapSB(clone.Features.Features)
		c.featuresOverrides = append(clone.featuresOverrides[:0:0], clone.featuresOverrides...)
		c.licenseManager = clone.licenseManager

		c.virtualsManagerObj = clone.virtualsManager()
		c.acceptProperties = myutil.CopyMapSS(clone.acceptProperties)
		c.ppropertiesdict = myutil.CopyMSMASS(clone.ppropertiesdict)
		c.acceptRestrict = append(clone.acceptRestrict[:0:0], clone.acceptRestrict...)
		c.pacceptRestrict = myutil.CopyMSMASS(clone.pacceptRestrict)
		c.penvdict = myutil.CopyMSMASS(clone.penvdict)
		c.pbashrcdict = clone.pbashrcdict //CopyMapSS(clone.pbashrcdict)
		c.expandMap = myutil.CopyMapSS(clone.expandMap)
	} else {
		c.keywordsManagerObj = nil
		c.maskManagerObj = nil
		c.virtualsManagerObj = nil
		locationsManager := NewLocationsManager(configRoot, eprefix, configProfilePath, localConfig, targetRoot, sysroot)
		c.locationsManager = locationsManager
		eprefix := locationsManager.eprefix
		configRoot = locationsManager.configRoot
		sysroot = locationsManager.sysroot
		esysroot := locationsManager.esysroot
		broot := locationsManager.broot
		absUserConfig := locationsManager.absUserConfig
		makeConfPaths := []string{path.Join(configRoot, "etc", "make.conf"), path.Join(configRoot, _const.MakeConfFile)}
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
		locationsManager.setRootOverride(makeConf["ROOT"])
		targetRoot = locationsManager.targetRoot
		eroot := locationsManager.eroot
		c.globalConfigPath = locationsManager.globalConfigPath
		envD := util.GetConfig(path.Join(eroot, "etc", "profile.env"), tolerant, false, false, false, nil)
		expandMap := myutil.CopyMapSS(envD)
		c.expandMap = expandMap
		expandMap["EPREFIX"] = eprefix
		expandMap["PORTAGE_CONFIGROOT"] = configRoot
		makeGlobalsPath := ""
		if atom.notInstalled {
			makeGlobalsPath = path.Join(_const.PORTAGE_BASE_PATH, "cnf", "make.globals")
		} else {
			makeGlobalsPath = path.Join(c.globalConfigPath, "make.globals")
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
		modulesLoader := NewKeyValuePairFileLoader(modulesFile, nil, nil)
		modulesDict, _ := modulesLoader.load()
		c.modules["user"] = modulesDict
		if len(c.modules["user"]) == 0 {
			c.modules["user"] = map[string][]string{}
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
		if env == nil {
			env = map[string]string{}
			for _, v := range os.Environ() {
				s := strings.SplitN(v, "=", 2)
				env[s[0]] = s[1]
			}
		}
		c.backupenv = myutil.CopyMapSS(env)
		if len(envD) > 0 {
			for k, v := range envD {
				if c.backupenv[k] == v {
					delete(c.backupenv, k)
				}
			}
		}
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
			c.Repositories = repository.loadRepositoryConfig(c, "")
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
		c.ValueDict["PORTAGE_REPOSITORIES"] = c.Repositories.configString()
		c.BackupChanges("PORTAGE_REPOSITORIES")
		mainRepo := c.Repositories.mainRepo()
		if mainRepo != nil {
			c.ValueDict["PORTDIR"] = mainRepo.Location
			c.BackupChanges("PORTDIR")
			expandMap["PORTDIR"] = c.ValueDict["PORTDIR"]
		}
		portDirOverlay1 := c.Repositories.repoLocationList
		if len(portDirOverlay1) > 0 && portDirOverlay1[0] == c.ValueDict["PORTDIR"] {
			portDirOverlay1 = portDirOverlay1[1:]
		}
		newOv := []string{}
		if len(portDirOverlay1) > 0 {
			for _, ov := range portDirOverlay1 {
				ov = msg.NormalizePath(ov)
				if util.IsdirRaiseEaccess(ov) || portage.SyncMode {
					newOv = append(newOv, portage.ShellQuote(ov))
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
		c.packages = util.StackLists(packageList, 1, false, false, false, false)
		c.prevmaskdict = map[string][]*dep.Atom{}
		for x := range c.packages {
			if c.prevmaskdict[x.cp] == nil {
				c.prevmaskdict[x.cp] = []*dep.Atom{x}
			} else {
				c.prevmaskdict[x.cp] = append(c.prevmaskdict[x.cp], x)
			}
		}
		c.unpackDependencies = loadUnpackDependenciesConfiguration(c.Repositories)
		myGCfg := map[string]string{}
		if len(profilesComplex) != 0 {
			myGCfgDLists := []map[string]string{}
			for _, x := range profilesComplex {
				myGCfgDLists = append(myGCfgDLists, util.GetConfig(path.Join(x.location, "make.defaults"), tolerant, false, true, x.portage1Directories, expandMap))
			}
			c.makeDefaults = myGCfgDLists
			myGCfg = util.stackDicts(myGCfgDLists, 0, c.incrementals, 0)
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
		p := [][2]string{}
		for _, v := range strings.Fields(c.configDict["defaults"]["PROFILE_ONLY_VARIABLES"]) {
			p = append(p, [2]string{v, ""})
		}
		profileOnlyVariables := util.StackLists([][][2]string{p}, 0, false, false, false, false)
		nonUserVariables := map[string]bool{}
		for k := range profileOnlyVariables {
			nonUserVariables[k.value] = true
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
			c.envDBlacklist[k.value] = true
		}
		for k := range c.envBlacklist {
			c.envDBlacklist[k] = true
		}
		envD = c.configDict["env.d"]
		for k := range c.envDBlacklist {
			delete(envD, k)
		}
		for k := range profileOnlyVariables {
			delete(myGCfg, k.value)
		}
		c.configList = append(c.configList, myGCfg)
		c.configDict["conf"] = c.configList[len(c.configList)-1]
		c.configList = append(c.configList, map[string]string{}) //LazyItemsDict
		c.configDict["pkg"] = c.configList[len(c.configList)-1]
		c.configDict["backupenv"] = c.backupenv
		for k := range profileOnlyVariables {
			delete(c.backupenv, k.value)
		}
		c.configList = append(c.configList, c.configDict["env"])
		c.lookupList = []map[string]string{}
		for i := 0; i < len(c.configList); i++ {
			c.lookupList = append(c.lookupList, c.configList[len(c.configList)-1-i])
		}
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

		c.ppropertiesdict = map[string]map[*dep.Atom][]string{}
		c.pacceptRestrict = map[string]map[*dep.Atom][]string{}
		c.penvdict = map[string]map[*dep.Atom][]string{}
		c.pbashrcdict = map[*profileNode]map[string]map[*dep.Atom][]string{}
		c.pbashrc = map[string]bool{}
		c.repoMakeDefaults = map[string]map[string]string{}

		for _, repo := range c.Repositories.reposWithProfiles() {
			d := util.GetConfig(path.Join(repo.Location, "profiles", "make.defaults"), tolerant, false, true, repo.portage1Profiles, myutil.CopyMapSS(c.configDict["globals"]))
			if len(d) > 0 {
				for k := range c.envBlacklist {
					delete(d, k)
				}
				for k := range profileOnlyVariables {
					delete(d, k.value)
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
			propDict := util.GrabDictPackage(path.Join(absUserConfig, "package.properties"), false, true, false, true, true, true, false, false, "", "0")
			var v []string = nil
			for a, x := range propDict {
				if a.value == "*/*" {
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
				if _, ok := c.ppropertiesdict[k.cp]; !ok {
					c.ppropertiesdict[k.cp] = map[*dep.Atom][]string{k: v}
				} else {
					c.ppropertiesdict[k.cp][k] = v
				}
			}
			d := util.GrabDictPackage(path.Join(absUserConfig, "package.accept_restrict"), false, true, false, true, true, true, false, false, "", "0")
			v = nil
			for a, x := range d {
				if a.value == "*/*" {
					v = x
				}
				delete(d, a)
			}
			if v != nil {
				if _, ok := c.configDict["conf"]["ACCEPT_RESTRICT"]; ok {
					c.configDict["conf"]["ACCEPT_RESTRICT"] += " " + strings.Join(v, " ")
				} else {
					c.configDict["conf"]["ACCEPT_RESTRICT"] = strings.Join(v, " ")
				}
			}
			for k, v := range d {
				if _, ok := c.pacceptRestrict[k.cp]; !ok {
					c.pacceptRestrict[k.cp] = map[*dep.Atom][]string{k: v}
				} else {
					c.pacceptRestrict[k.cp][k] = v
				}
			}
			pEnvDict := util.GrabDictPackage(path.Join(absUserConfig, "package.env"), false, true, false, true, true, true, false, false, "", "0")
			v = nil
			for a, x := range pEnvDict {
				if a.value == "*/*" {
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
						if _, ok := confConfigDict[k]; ok {
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
				if _, ok := c.penvdict[k.cp]; !ok {
					c.penvdict[k.cp] = map[*dep.Atom][]string{k: v}
				} else {
					c.penvdict[k.cp][k] = v
				}
			}
			for _, profile := range profilesComplex {
				if !myutil.Ins(profile.profileFormats, "profile-bashrcs") {
					continue
				}
				c.pbashrcdict[profile] = map[string]map[*dep.Atom][]string{}

				bashrc := util.GrabDictPackage(path.Join(profile.location, "package.bashrc"), false, true, false, true, true, profile.allowBuildId, false, true, profile.eapi, "")
				if len(bashrc) == 0 {
					continue
				}
				for k, v := range bashrc {
					envFiles := []string{}
					for _, envname := range v {
						envFiles = append(envFiles, path.Join(profile.location, "bashrc", envname))
					}
					if _, ok := c.pbashrcdict[profile][k.cp]; !ok {
						c.pbashrcdict[profile][k.cp] = map[*dep.Atom][]string{k: v}
					} else if _, ok := c.pbashrcdict[profile][k.cp][k]; !ok {
						c.pbashrcdict[profile][k.cp][k] = v
					} else {
						c.pbashrcdict[profile][k.cp][k] = append(c.pbashrcdict[profile][k.cp][k], v...)
					}
				}
			}
		}
		categories := [][][2]string{}
		for _, x := range locationsManager.profileAndUserLocations {
			categories = append(categories, util.GrabFile(path.Join(x, "categories"), 0, false, false))
		}
		c.categories = map[string]bool{}
		for x := range util.StackLists(categories, 1, false, false, false, false) {
			if categoryRe.MatchString(x.value) {
				c.categories[x.value] = true
			}
		}
		al := [][][2]string{}
		for _, x := range locationsManager.profileAndUserLocations {
			al = append(al, util.GrabFile(path.Join(x, "arch.list"), 0, false, false))
		}
		archList := util.StackLists(al, 1, false, false, false, false)
		als := []string{}
		for a := range archList {
			als = append(als, a.value)
		}
		sort.Strings(als)
		c.configDict["conf"]["PORTAGE_ARCHLIST"] = strings.Join(als, " ")

		ppl := [][][2]string{}
		for _, x := range profilesComplex {
			provPath := path.Join(x.location, "package.provided")
			if _, err := os.Stat(provPath); err == nil {
				if eapi.GetEapiAttrs(x.eapi).AllowsPackageProvided {
					ppl = append(ppl, util.GrabFile(provPath, 1, x.portage1Directories, false))
				}
			}
		}
		ppls := util.StackLists(ppl, 1, false, false, false, false)
		pkgProvidedLines := []string{}
		for a := range ppls {
			pkgProvidedLines = append(pkgProvidedLines, a.value)
		}
		hasInvalidData := false
		for x := len(pkgProvidedLines) - 1; x > -1; x-- {
			myline := pkgProvidedLines[x]
			if !dep.isValidAtom("="+myline, false, false, false, "", false) {
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
			mycatpkg := versions.cpvGetKey(x, "")
			if _, ok := c.pprovideddict[mycatpkg]; ok {
				c.pprovideddict[mycatpkg] = append(c.pprovideddict[mycatpkg], x)
			} else {
				c.pprovideddict[mycatpkg] = []string{x}
			}
		}

		if _, ok := c.ValueDict["USE_ORDER"]; !ok {
			c.ValueDict["USE_ORDER"] = "env:pkg:conf:defaults:pkginternal:features:repo:env.d"
			c.BackupChanges("USE_ORDER")
		}
		_, ok1 := c.ValueDict["CBUILD"]
		_, ok2 := c.ValueDict["CHOST"]
		if !ok1 && ok2 {
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

		defaultInstIds := map[string]string{"PORTAGE_INST_GID": "0", "PORTAGE_INST_UID": "0"}

		erootOrParent := atom.firstExisting(eroot)
		unprivileged := false

		if erootSt, err := os.Stat(erootOrParent); err == nil {
			if atom.unprivilegedMode(erootOrParent, erootSt) {
				unprivileged = true
			}

			defaultInstIds["PORTAGE_INST_GID"] = fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Gid)
			defaultInstIds["PORTAGE_INST_UID"] = fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Uid)

			if _, ok := c.ValueDict["PORTAGE_USERNAME"]; !ok {
				if pwdStruct, err := user.LookupId(fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Uid)); err != nil {
				} else {
					c.ValueDict["PORTAGE_USERNAME"] = pwdStruct.Name
					c.BackupChanges("PORTAGE_USERNAME")
				}
			}

			if _, ok := c.ValueDict["PORTAGE_GRPNAME"]; !ok {
				if grpStruct, err := user.LookupGroupId(fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Gid)); err != nil {
				} else {
					c.ValueDict["PORTAGE_GRPNAME"] = grpStruct.Name
					c.BackupChanges("PORTAGE_GRPNAME")
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
			} else {
				c.ValueDict[varr] = v
			}
			c.BackupChanges(varr)
		}

		c.depcachedir = c.ValueDict["PORTAGE_DEPCACHEDIR"]
		if c.depcachedir == "" {
			c.depcachedir = path.Join(string(os.PathSeparator), _const.EPREFIX, strings.TrimPrefix(_const.DepcachePath, string(os.PathSeparator)))
			if unprivileged && targetRoot != string(os.PathSeparator) {
				if s, err := os.Stat(firstExisting(c.depcachedir)); err != nil && s.Mode()&2 != 0 {
					c.depcachedir = path.Join(eroot, strings.TrimPrefix(_const.DepcachePath, string(os.PathSeparator)))
				}
			}
		}

		c.ValueDict["PORTAGE_DEPCACHEDIR"] = c.depcachedir
		c.BackupChanges("PORTAGE_DEPCACHEDIR")

		if portage.InternalCaller {
			c.ValueDict["PORTAGE_INTERNAL_CALLER"] = "1"
			c.BackupChanges("PORTAGE_INTERNAL_CALLER")
		}

		c.regenerate(0)
		featureUse := []string{}
		if !c.Features.Features["test"] {
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
		output.output_init(c.ValueDict["PORTAGE_CONFIGROOT"])
		data_init.Data_init(c)
	}
	if mycpv != nil {
		c.SetCpv(mycpv, nil)
	}

	return c
}

type featuresSet struct {
	settings *Config
	Features map[string]bool
}

func (f *featuresSet) contains(k string) bool {
	return f.Features[k]
}

func (f *featuresSet) iter() []string {
	r := []string{}
	for k := range f.Features {
		r = append(r, k)
	}
	return r
}

func (f *featuresSet) syncEnvVar() {
	p := f.iter()
	sort.Strings(p)
	f.settings.ValueDict["FEATURES"] = strings.Join(p, " ")
}

func (f *featuresSet) add(k string) {
	f.settings.modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, k)
	if !f.Features[k] {
		f.Features[k] = true
		f.syncEnvVar()
	}
}

func (f *featuresSet) update(values []string) {
	f.settings.modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, values...)
	needSync := false
	for _, k := range values {
		if f.Features[k] {
			continue
		}
		f.Features[k] = true
		needSync = true
	}
	if needSync {
		f.syncEnvVar()
	}
}

func (f *featuresSet) differenceUpdate(values []string) {
	f.settings.modifying()
	removeUs := []string{}
	for _, v := range values {
		f.settings.featuresOverrides = append(f.settings.featuresOverrides, "-"+v)
		if f.Features[v] {
			removeUs = append(removeUs, v)
		}
	}
	if len(removeUs) > 0 {
		for _, k := range removeUs {
			delete(f.Features, k)
		}
		f.syncEnvVar()
	}
}

func (f *featuresSet) remove(k string) {
	f.Discard(k)
}

func (f *featuresSet) Discard(k string) {
	f.settings.modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, "-"+versions.v)
	if f.Features[versions.v] {
		delete(f.Features, k)
	}
	f.syncEnvVar()
}

func (f *featuresSet) validate() {
	if f.Features["unknown-features-warn"] {
		var unknownFeatures []string
		for k := range f.Features {
			if !_const.SUPPORTED_FEATURES[k] {
				unknownFeatures = append(unknownFeatures, k)
			}
		}
		if len(unknownFeatures) > 0 {
			var unknownFeatures2 []string
			for _, u := range unknownFeatures {
				if !f.settings.unknownFeatures[u] {
					unknownFeatures2 = append(unknownFeatures2, u)
				}
			}
			if len(unknownFeatures2) > 0 {
				for _, u := range unknownFeatures2 {
					f.settings.unknownFeatures[u] = true
				}
				msg.WriteMsgLevel(output.Colorize("BAD", fmt.Sprintf("FEATURES variable contains unknown value(s): %s", strings.Join(unknownFeatures2, ", "))+"\n"), 30, -1)
			}
		}
	}
	if f.Features["unknown-features-filter"] {
		var unknownFeatures []string
		for k := range f.Features {
			if !_const.SUPPORTED_FEATURES[k] {
				unknownFeatures = append(unknownFeatures, k)
			}
		}
		if len(unknownFeatures) > 0 {
			f.differenceUpdate(unknownFeatures)
			f.pruneOverrides()
		}
	}
}

func (f *featuresSet) pruneOverrides() {
	overridesSet := map[string]bool{}

	positive := map[string]bool{}
	negative := map[string]bool{}
	for _, u := range f.settings.featuresOverrides {
		overridesSet[u] = true
	}
	for _, x := range f.settings.featuresOverrides {
		if x[:1] == "-" {
			delete(positive, x[1:])
			negative[x[1:]] = true
		} else {
			delete(negative, x)
			positive[x] = true
		}
	}
	f.settings.featuresOverrides = []string{}
	for p := range positive {
		f.settings.featuresOverrides = append(f.settings.featuresOverrides, p)
	}
	for n := range negative {
		f.settings.featuresOverrides = append(f.settings.featuresOverrides, "-"+n)
	}
}

func NewFeaturesSet(settings *Config) *featuresSet {
	return &featuresSet{settings: settings, Features: map[string]bool{}}
}

func loadUnpackDependenciesConfiguration(repositories *repository.RepoConfigLoader) map[string]map[string]map[string]string {
	repoDict := map[string]map[string]map[string]string{}
	for _, repo := range repositories.reposWithProfiles() {
		for eapi1 := range eapi.supportedEapis {
			if eapi.eapiHasAutomaticUnpackDependencies(eapi1) {
				fileName := path.Join(repo.Location, "profiles", "unpack_dependencies", eapi)
				lines := util.GrabFile(fileName, 0, true, false)
				for _, line := range lines {
					elements := strings.Fields(line[0])
					suffix := strings.ToLower(elements[0])
					if len(elements) == 1 {
						msg.WriteMsg(fmt.Sprintf("--- Missing unpack dependencies for '%s' suffix in '%s'\n", suffix, fileName), 0, nil)
					}
					depend := strings.Join(elements[1:], " ")
					dep.useReduce(depend, map[string]bool{}, []string{}, false, []string{}, false, eapi, false, false, nil, nil, false)
					if repoDict[repo.Name] == nil {
						repoDict[repo.Name] = map[string]map[string]string{eapi: {suffix: depend}}
					} else if repoDict[repo.Name][eapi] == nil {
						repoDict[repo.Name][eapi] = map[string]string{suffix: depend}
					} else {
						repoDict[repo.Name][eapi][suffix] = depend
					}
				}
			}
		}
	}
	ret := map[string]map[string]map[string]string{}
	for _, repo := range repositories.reposWithProfiles() {
		names := []string{}
		for _, v := range repo.mastersRepo {
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

func validateCmdVar(v string) (bool, []string) {
	invalid := false
	vSplit, _ := shlex.Split(v)
	if len(vSplit) == 0 {
		invalid = true
	} else if path.IsAbs(vSplit[0]) {
		s, _ := os.Stat(vSplit[0])
		invalid = s.Mode()&0111 == 0
	} else if process.FindBinary(vSplit[0]) == "" {
		invalid = true
	}
	return !invalid, vSplit
}

func orderedByAtomSpecificity(cpdict map[*dep.Atom][]string, pkg *versions.PkgStr, repo string) [][]string {
	if pkg.repo == "" && repo != "" && repo != versions.unknownRepo {
		//pkg = pkg +repoSeparator+repo
	}
	results := [][]string{}
	keys := []*dep.Atom{}
	for k := range cpdict {
		keys = append(keys, k)
	}
	for len(keys) > 0 {
		bestMatch := dep.bestMatchToList(pkg, keys)
		if bestMatch != nil {
			keys2 := []*dep.Atom{}
			for k := range cpdict {
				if k != bestMatch {
					keys2 = append(keys2, k)
				}
			}
			keys = keys2
			results = append(results, cpdict[bestMatch])
		} else {
			break
		}
	}
	if len(results) != 0 {
		r := [][]string{}
		for i := 0; i < len(results); i++ {
			r = append(r, results[len(results)-1-i])
		}
		return r
	}
	return results
}

func orderedByAtomSpecificity2(cpdict map[*dep.Atom]map[string][]string, pkg *versions.PkgStr, repo string) []map[string][]string {
	if pkg.repo == "" && repo != "" && repo != versions.unknownRepo {
		//pkg = pkg +repoSeparator+repo
	}
	results := []map[string][]string{}
	keys := []*dep.Atom{}
	for k := range cpdict {
		keys = append(keys, k)
	}
	for len(keys) > 0 {
		bestMatch := dep.bestMatchToList(pkg, keys)
		if bestMatch != nil {
			keys2 := []*dep.Atom{}
			for k := range cpdict {
				if k != bestMatch {
					keys2 = append(keys2, k)
				}
			}
			keys = keys2
			results = append(results, cpdict[bestMatch])
		} else {
			break
		}
	}
	if len(results) != 0 {
		r := []map[string][]string{}
		for i := 0; i < len(results); i++ {
			r = append(r, results[len(results)-1-i])
		}
		return r
	}
	return results
}

func pruneIncremental(split []string) []string {
	myutil.ReverseSlice(split)
	for i, x := range split {
		if x == "*" {
			split = split[len(split)-i-1:]
			break
		} else if x == "-*" {
			if i == 0 {
				split = []string{}
			} else {
				split = split[len(split)-i:]
			}
			break
		}
	}
	return split
}
