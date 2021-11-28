package atom

import (
	"bufio"
	"errors"
	"fmt"
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

func getFeatureFlags(attrs eapiAttrs) map[string]bool {
	flags := map[string]bool{}
	if attrs.featureFlagTest {
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
	mycpv                                                                                                           *PkgStr
	setcpvArgsHash                                                                                                  struct {
		cpv  *PkgStr
		mydb *vardbapi
	}
	sonameProvided                                                                                                                       map[*sonameAtom]bool
	parentStable, _selinux_enabled                                                                                                       *bool
	puse, depcachedir, profilePath, defaultFeaturesUse, userProfileDir, globalConfigPath                                                 string
	useManager                                                                                                                           *useManager
	keywordsManagerObj                                                                                                                   *keywordsManager
	maskManagerObj                                                                                                                       *maskManager
	virtualsManagerObj                                                                                                                   *virtualManager
	licenseManager                                                                                                                       *licenseManager
	iuseImplicitMatch                                                                                                                    *iuseImplicitMatchCache
	unpackDependencies                                                                                                                   map[string]map[string]map[string]string
	packages, usemask, useforce                                                                                                          map[*Atom]string
	ppropertiesdict, pacceptRestrict, penvdict                                                                                           map[string]map[*Atom][]string
	makeDefaultsUse, featuresOverrides, acceptRestrict, profiles                                                                         []string
	profileBashrc                                                                                                                        []bool
	lookupList, configList, makeDefaults, uvlist                                                                                         []map[string]string
	repoMakeDefaults, configDict                                                                                                         map[string]map[string]string
	backupenv, defaultGlobals, deprecatedKeys, useExpandDict, acceptProperties, expandMap                                                map[string]string
	pprovideddict                                                                                                                        map[string][]string
	pbashrcdict                                                                                                                          map[*profileNode]map[string]map[*Atom][]string
	prevmaskdict                                                                                                                         map[string][]*Atom
	modulePriority, incrementals, validateCommands, unknownFeatures, nonUserVariables, envDBlacklist, pbashrc, categories, iuseEffective map[string]bool
	Features                                                                                                                             *featuresSet
	Repositories                                                                                                                         *repoConfigLoader
	modules                                                                                                                              map[string]map[string][]string
	locationsManager                                                                                                                     *locationsManager
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
					WriteMsgLevel(fmt.Sprintf("%s setting is invalid: '%s'\n", k, v), 40, -1)
				}

				v = c.configDict["globals"][k]
				if v != "" {
					defaultValid, vSplit := validateCmdVar(v)
					if !defaultValid {
						if len(vSplit) > 0 {
							WriteMsgLevel(fmt.Sprintf("%s setting from make.globals is invalid: '%s'\n", k, v), 40, -1)
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
		"tmp":       {-1, 01777, 0, true},
		"var/tmp":   {-1, 01777, 0, true},
		PrivatePath: {*portage_gid, 02750, 02, false},
		CachePath:   {*portage_gid, 0755, 02, false},
	}

	for myPath, s := range dirModeMap {
		gid, mode, modemask, preservePerms := s.gid, s.mode, s.mask, s.preservePerms
		myDir := path.Join(c.ValueDict["EROOT"], myPath)
		st, _ := os.Stat(myDir)
		if preservePerms && st.IsDir() {
			continue
		}
		if !ensureDirs(myDir, 0, gid, mode, modemask, nil, false) {
			WriteMsg(fmt.Sprintf("!!! Directory initialization failed: '%s'\n", myDir), -1, nil)
			WriteMsg(fmt.Sprintf("!!! %v\n", false), -1, nil) // error
		}
	}
}

func (c *Config) keywordsManager() *keywordsManager {
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

func (c *Config) virtualsManager() *virtualManager {
	if c.virtualsManagerObj == nil {
		c.virtualsManagerObj = NewVirtualManager(c.profiles)
	}
	return c.virtualsManagerObj
}

func (c *Config) pkeywordsdict() map[string]map[*Atom][]string {
	return c.keywordsManager().pkeywordsDict
}

func (c *Config) pmaskdict() map[string][]*Atom {
	return c.maskManager()._pmaskdict
}

func (c *Config) _punmaskdict() map[string][]*Atom {
	return c.maskManager()._punmaskdict
}

func (c *Config) soname_provided() map[*sonameAtom]bool {
	if c.sonameProvided == nil {
		e := []map[string][]string{}
		for _, x := range c.profiles {
			e = append(e, grabDict(path.Join(x, "soname.provided"), false, false, true, true, false))
		}
		c.sonameProvided = map[*sonameAtom]bool{}
		d := stackDictList(e, 1, []string{}, 0)
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
		WriteMsg(fmt.Sprintf("--- 'profiles/arch.list' is empty or not available. Empty ebuild repository?\n"), 1, nil)
	} else {
		for _, group := range groups {
			if !archlist[group] && !strings.HasPrefix(group, "-") && archlist[group[1:]] && group != "*" && group != "~*" && group != "**" {
				WriteMsg(fmt.Sprintf("!!! INVALID ACCEPT_KEYWORDS: %v\n", group), -1, nil)
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
			if existsRaiseEaccess(path.Join(c.profilePath, x)) {
				in = false
				break
			}
		}
		if in {
			profileBroken = true
		}
	}

	if profileBroken && !SyncMode {
		absProfilePath := ""
		for _, x := range []string{ProfilePath, "etc/make.profile"} {
			x = path.Join(c.ValueDict["PORTAGE_CONFIGROOT"], x)
			if _, err := os.Lstat(x); err != nil {
			} else {
				absProfilePath = x
				break
			}
		}
		if absProfilePath == "" {
			absProfilePath = path.Join(c.ValueDict["PORTAGE_CONFIGROOT"], ProfilePath)
		}

		WriteMsg(fmt.Sprintf("\n\n!!! %s is not a symlink and will probably prevent most merges.\n", absProfilePath), -1, nil)
		WriteMsg(fmt.Sprintf("!!! It should point into a profile within %s/profiles/\n", c.ValueDict["PORTDIR"]), 0, nil)
		WriteMsg(fmt.Sprintf("!!! (You can safely ignore this message when syncing. It's harmless.)\n\n\n"), 0, nil)
	}
	if !sandbox_capable && (c.Features.Features["sandbox"] || c.Features.Features["usersandbox"]) {
		cp, _ := filepath.EvalSymlinks(c.profilePath)
		pp, _ := filepath.EvalSymlinks(path.Join(c.ValueDict["PORTAGE_CONFIGROOT"], ProfilePath))
		if c.profilePath != "" && cp == pp {
			WriteMsg(colorize("BAD", fmt.Sprintf("!!! Problem with sandbox binary. Disabling...\n\n")), -1, nil)
		}
	}
	if c.Features.Features["fakeroot"] && !fakeroot_capable {
		WriteMsg(fmt.Sprintf("!!! FEATURES=fakeroot is enabled, but the fakeroot binary is not installed.\n"), -1, nil)
	}

	if binpkgCompression, ok := c.ValueDict["BINPKG_COMPRESS"]; ok {
		if compression, ok := _compressors[binpkgCompression]; !ok {
			WriteMsg(fmt.Sprintf("!!! BINPKG_COMPRESS contains invalid or unsupported compression method: %s", binpkgCompression), -1, nil)
		} else {
			if cs, err := shlex.Split(varExpand(compression["compress"], c.ValueDict, nil)); err != nil {

			} else if len(cs) == 0 {
				WriteMsg(fmt.Sprintf("!!! BINPKG_COMPRESS contains invalid or unsupported compression method: %s", compression["compress"]), -1, nil)
			} else {
				compressionBinary := cs[0]
				if FindBinary(compressionBinary) == "" {
					missingPackage := compression["package"]
					WriteMsg(fmt.Sprintf("!!! BINPKG_COMPRESS unsupported %s. Missing package: %s", binpkgCompression, missingPackage), -1, nil)
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
			cpv  *PkgStr
			mydb *vardbapi
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
func (c *Config) SetCpv(mycpv *PkgStr, mydb *vardbapi) {
	if c.setCpvActive {
		//AssertionError('setcpv recursion detected')
	}
	c.setCpvActive = true
	defer func() { c.setCpvActive = false }()
	c.modifying()

	var pkg *PkgStr = nil
	var explicitIUse map[string]bool = nil
	var builtUse []string = nil
	if mycpv == c.setcpvArgsHash.cpv && mydb == c.setcpvArgsHash.mydb {
		return
	}
	c.setcpvArgsHash.cpv = mycpv
	c.setcpvArgsHash.mydb = mydb

	hasChanged := false
	c.mycpv = mycpv
	s := catsplit(mycpv.string)
	cat := s[0]
	pf := s[1]
	cp := cpvGetKey(mycpv.string, "")
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
			c.mycpv = NewPkgStr(c.mycpv.string, pkgConfigDict, c, "", "", "", 0, 0, "", 0, nil)
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

	eapiAttrs := getEapiAttrs(eapi)
	if pkgInternalUse != c.configDict["pkginternal"]["USE"] {
		c.configDict["pkginternal"]["USE"] = pkgInternalUse
		hasChanged = true
	}

	var repoEnv []map[string]string = nil
	if repository != "" && repository != (&Package{}).UnknownRepo {
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
			var cpDict map[*Atom][]string = nil
			if _, ok := c.useManager.repoPuseDict[repo]; !ok {
				cpDict = map[*Atom][]string{}
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
		s := stackLists(r, incremental, false, false, false, false)
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
		((previousIUseEffective != "") == eapiAttrs.iuseEffective)) {
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
	if eapiAttrs.iuseEffective {
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
			restrict = useReduce(rawRestrict, useList, []string{}, false, []string{}, false, "", false, true, nil, nil, false)
		} else {
			useList := map[string]bool{}
			for _, x := range strings.Fields(c.ValueDict["USE"]) {
				if explicitIUse[x] || iUseImplicitMatch(x) {
					useList[x] = true
				}
			}
			restrict = useReduce(rawRestrict, useList, []string{}, false, []string{}, false, "", false, true, nil, nil, false)
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
	restrict := useReduce(c.ValueDict["RESTRICT"], map[string]bool{}, []string{}, false, []string{}, false, "", false, false, nil, nil, false)
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
	if eapiAttrs.iuseEffective {

		portageIuse = CopyMapSB(c.iuseEffective)
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
			var at *Atom
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

	if eapiAttrs.featureFlagTargetroot && (explicitIUse["targetroot"] || iUseImplicitMatch("targetroot")) {
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
			if Ins(varSplit, x) {
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
			if Ins(varSplit, x) {
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
	absUserConfig := path.Join(c.ValueDict["PORTAGE_CONFIGROOT"], UserConfigPath)
	nonUserVariables := c.nonUserVariables
	expandMap := CopyMapSS(c.expandMap)
	incrementals := c.incrementals
	for _, envname := range penv {
		penvfile := path.Join(absUserConfig, "env", envname)
		penvconfig := getConfig(penvfile, c.tolerent, true, true, false, expandMap)
		if penvconfig == nil {
			WriteMsg(fmt.Sprintf("!!! %s references non-existent file: %s\n", path.Join(absUserConfig, "package.env"), penvfile), -1, nil)
		} else {
			for k, v := range penvconfig {
				if protected_keys[k] || nonUserVariables[k] {
					WriteMsg(fmt.Sprintf("!!! Illegal variable '%s' assigned in '%s'\n", k, penvfile), -1, nil)
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

func (c *Config) _getUseMask(pkg *PkgStr, stable *bool) map[*Atom]string {
	return c.useManager.getUseMask(pkg, stable)
}

func (c *Config) _getUseForce(pkg *PkgStr, stable *bool) map[*Atom]string {
	return c.useManager.getUseForce(pkg, stable)
}

func (c *Config) _getMaskAtom(cpv *PkgStr, metadata map[string]string) *Atom {
	return c.maskManager().getMaskAtom(cpv, metadata["SLOT"], metadata["repository"])
}

func (c *Config) _getRawMaskAtom(cpv *PkgStr, metadata map[string]string) *Atom {
	return c.maskManager().getRawMaskAtom(cpv, metadata["SLOT"], metadata["repository"])
}

func (c *Config) isStable(pkg *PkgStr) bool {
	return c.keywordsManager().isStable(pkg, c.ValueDict["ACCEPT_KEYWORDS"], c.configDict["backupenv"]["ACCEPT_KEYWORDS"])
}

func (c *Config) _getKeywords(cpv *PkgStr, metadata map[string]string) map[*Atom]string {
	return c.keywordsManager().getKeywords(cpv, metadata["SLOT"], metadata["KEYWORDS"], metadata["repository"])
}

func (c *Config) _getMissingKeywords(cpv *PkgStr, metadata map[string]string) map[*Atom]string {
	backupedAcceptKeywords := c.configDict["backupenv"]["ACCEPT_KEYWORDS"]
	globalAcceptKeywords := c.ValueDict["ACCEPT_KEYWORDS"]
	return c.keywordsManager().GetMissingKeywords(cpv, metadata["SLOT"], metadata["KEYWORDS"], metadata["repository"], globalAcceptKeywords, backupedAcceptKeywords)
}

func (c *Config) _getRawMissingKeywords(cpv *PkgStr, metadata map[string]string) map[*Atom]string {
	return c.keywordsManager().getRawMissingKeywords(cpv, metadata["SLOT"], metadata["KEYWORDS"], metadata["repository"], c.ValueDict["ACCEPT_KEYWORDS"])
}

func (c *Config) _getPKeywords(cpv *PkgStr, metadata map[string]string) []string {
	globalAcceptKeywords := c.ValueDict["ACCEPT_KEYWORDS"]
	return c.keywordsManager().getPKeywords(cpv, metadata["SLOT"], metadata["repository"], globalAcceptKeywords)
}

func (c *Config) _getMissingLicenses(cpv *PkgStr, metadata map[string]string) []string {
	return c.licenseManager.getMissingLicenses(cpv, metadata["USE"], metadata["LICENSE"], metadata["SLOT"], metadata["repository"])
}

func (c *Config) _getMissingProperties(cpv *PkgStr, metadata map[string]string) []string {

	accept_properties := []string{}
	for k := range c.acceptProperties{
		accept_properties = append(accept_properties, k)
	}
	//try:
	//	cpv.slot
	//	except AttributeError:
	//	cpv = _pkg_str(cpv, metadata=metadata, settings=c)
	cp := cpvGetKey(cpv.string, "")
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
	for _, v := range useReduce(properties_str, map[string]bool{}, []string{}, true, []string{}, false, "", false, true, nil, nil, false) {
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
	for _, x := range useReduce(properties_str, usemsb, []string{}, false, []string{}, false, "", false, true, nil, nil, false) {
		if !acceptable_properties[x] {
			ret = append(ret, x)
		}
	}
	return ret
}

func (c *Config) _getMissingRestrict(cpv *PkgStr, metadata map[string]string) []string {

	accept_restrict := []string{}
	for _, k := range c.acceptRestrict{
		accept_restrict = append(accept_restrict, k)
	}
	//try:
	//	cpv.slot
	//	except AttributeError:
	//	cpv = _pkg_str(cpv, metadata=metadata, settings=c)
	cp := cpvGetKey(cpv.string, "")
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
	for _, v := range useReduce(restrict_str, map[string]bool{}, []string{}, true, []string{}, false, "", false, true, nil, nil, false) {
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
	for _, x := range useReduce(restrict_str, usemsb, []string{}, false, []string{}, false, "", false, true, nil, nil, false) {
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
				WriteMsg(fmt.Sprintf("!!! Invalid ACCEPT_CHOSTS value: '%s': %s\n",
				accept_chost[0], err), -1, nil)
				c.acceptChostRe = regexp.MustCompile("^$")
			}
		}else {
			var err error
			c.acceptChostRe, err = regexp.Compile(fmt.Sprintf("^(%s)$", strings.Join(accept_chost, "|")))
			if err != nil {
				//except re.error as e:
				WriteMsg(fmt.Sprintf("!!! Invalid ACCEPT_CHOSTS value: '%s': %s\n",
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
	envD := getConfig(envDFilename, c._tolerant, false, false, false, nil)
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
					WriteMsg(colorize("BAD", fmt.Sprintf("%s values should not start with a '+': %s", myKey, x))+"\n", -1, nil)
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
		ReverseSlice(c.uvlist)
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
				WriteMsg(colorize("BAD", fmt.Sprintf("USE flags should not start with a '+': %s\n", x)), -1, nil)
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
						WriteMsg(colorize("BAD", fmt.Sprintf("Invalid '+' operator in non-incremental variable '%s': '%s'\n", varr, x)), -1, nil)
						continue
					} else {
						WriteMsg(colorize("BAD", fmt.Sprintf("Invalid '+' operator in non-incremental variable '%s': '%s'\n", varr, x)), -1, nil)
					}
					x = x[1:]
				}
				if x[0] == '-' {
					if isNotIncremental {
						WriteMsg(colorize("BAD", fmt.Sprintf("Invalid '+' operator in non-incremental variable '%s': '%s'\n", varr, x)), -1, nil)
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
			tempVartree := NewVarTree(nil, c)
			c.virtualsManager()._populate_treeVirtuals(tempVartree)
		} else {
			c.virtualsManager()._treeVirtuals = map[string][]string{}
		}
	}

	return c.virtualsManager().getvirtuals()
}

func (c *Config) _populate_treeVirtuals_if_needed(vartree *varTree) {
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

	eapi := c.ValueDict["EAPI"]
	eapi_attrs := getEapiAttrs(eapi)
	phase := c.ValueDict["EBUILD_PHASE"]
	emerge_from := c.ValueDict["EMERGE_FROM"]
	filter_calling_env := false
	if c.mycpv != nil &&
		!(emerge_from == "ebuild" && phase == "setup") &&
		!Ins([]string{"clean", "cleanrm", "depend", "fetch"}, phase) {
		temp_dir := c.ValueDict["T"]
		if temp_dir != "" && pathExists(filepath.Join(temp_dir, "environment")) {
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
	if !Inmss(mydict, "HOME") && Inmss(mydict, "BUILD_PREFIX") {
		WriteMsg("*** HOME not set. Setting to "+mydict["BUILD_PREFIX"]+"\n", 0, nil)
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

	if !eapiExportsAa(eapi) {
		delete(mydict, "AA")
	}

	if !eapiExportsMergeType(eapi) {
		delete(mydict, "MERGE_TYPE")
	}

	src_like_phase := phase == "setup" || strings.HasPrefix(_phase_func_map[phase], "src_")

	if !(src_like_phase && eapi_attrs.sysroot) {
		delete(mydict, "ESYSROOT")
	}

	if !(src_like_phase && eapi_attrs.broot) {
		delete(mydict, "BROOT")
	}

	if phase == "depend" || (!c.Features.Features["force-prefix"] && eapi != "" && !eapiSupportsPrefix(eapi)) {
		delete(mydict, "ED")
		delete(mydict, "EPREFIX")
		delete(mydict, "EROOT")
		delete(mydict, "ESYSROOT")
	}

	if !Ins([]string{"pretend", "setup", "preinst", "postinst"}, phase) || !eapiExportsReplaceVars(eapi) {
		delete(mydict, "REPLACING_VERSIONS")
	}

	if !Ins([]string{"prerm", "postrm"}, phase) || !eapiExportsReplaceVars(eapi) {
		delete(mydict, "REPLACED_BY_VERSION")
	}

	if phase != "" && eapi_attrs.exportsEbuildPhaseFunc {
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
			if Inmss(mydict, v) {
				mydict[v] = strings.TrimRight(mydict[v], string(os.PathSeparator))
			}
		}
	}

	if Inmss(mydict, "SYSROOT") {
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
		for _, repo_name := range reversed(c.Repositories.preposOrder) {
			thirdparty_lists = append(thirdparty_lists, grabDict(filepath.Join(
				c.Repositories.Prepos[repo_name].Location,
				"profiles", "thirdpartymirrors"), false, false, false, true, false))
		}
		c._thirdpartymirrors = stackDictList(thirdparty_lists, 1, []string{}, 0)
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
		if Ins(strings.Fields(c.ValueDict["USE"]), "selinux") {
			if selinux {
				if selinux.is_selinux_enabled() == 1 {
					f = true
					c._selinux_enabled = &f
				}
			} else {
				WriteMsg("!!! SELinux module not found. Please verify that it was installed.\n", -1, nil)
			}
		}
	}

	return c._selinux_enabled
}

var eapiCache = map[string]bool{}

// nil, nil, "", nil, "","","","",true, nil, false, nil
func NewConfig(clone *Config, mycpv *PkgStr, configProfilePath string, configIncrementals []string, configRoot, targetRoot, sysroot, eprefix string, localConfig bool, env map[string]string, unmatchedRemoval bool, repositories *repoConfigLoader) *Config {
	eapiCache = make(map[string]bool)
	tolerant := initializingGlobals == nil
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
		ReverseSlice(c.lookupList)
		c.useExpandDict = CopyMapSS(clone.useExpandDict)
		c.backupenv = c.configDict["backupenv"]
		c.prevmaskdict = clone.prevmaskdict   // CopyMapSS(clone.prevmaskdict)
		c.pprovideddict = clone.pprovideddict //CopyMapSS()
		c.Features = NewFeaturesSet(c)
		c.Features.Features = CopyMapSB(clone.Features.Features)
		c.featuresOverrides = append(clone.featuresOverrides[:0:0], clone.featuresOverrides...)
		c.licenseManager = clone.licenseManager

		c.virtualsManagerObj = clone.virtualsManager()
		c.acceptProperties = CopyMapSS(clone.acceptProperties)
		c.ppropertiesdict = CopyMSMASS(clone.ppropertiesdict)
		c.acceptRestrict = append(clone.acceptRestrict[:0:0], clone.acceptRestrict...)
		c.pacceptRestrict = CopyMSMASS(clone.pacceptRestrict)
		c.penvdict = CopyMSMASS(clone.penvdict)
		c.pbashrcdict = clone.pbashrcdict //CopyMapSS(clone.pbashrcdict)
		c.expandMap = CopyMapSS(clone.expandMap)
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
		makeConfPaths := []string{path.Join(configRoot, "etc", "make.conf"), path.Join(configRoot, MakeConfFile)}
		p0, _ := filepath.EvalSymlinks(makeConfPaths[0])
		p1, _ := filepath.EvalSymlinks(makeConfPaths[1])
		if p0 == p1 {
			makeConfPaths = makeConfPaths[:len(makeConfPaths)-1]
		}
		makeConfCount := 0
		makeConf := map[string]string{}
		for _, x := range makeConfPaths {
			mygcfg := getConfig(x, tolerant, true, true, true, makeConf)

			if mygcfg != nil {
				for k, v := range mygcfg {
					makeConf[k] = v
				}
				makeConfCount += 1
			}
		}

		if makeConfCount == 2 {
			WriteMsg(fmt.Sprintf("!!! Found 2 make.conf files, using both '%s' and '%s'\n", makeConfPaths[0], makeConfPaths[1]), -1, nil)
		}
		locationsManager.setRootOverride(makeConf["ROOT"])
		targetRoot = locationsManager.targetRoot
		eroot := locationsManager.eroot
		c.globalConfigPath = locationsManager.globalConfigPath
		envD := getConfig(path.Join(eroot, "etc", "profile.env"), tolerant, false, false, false, nil)
		expandMap := CopyMapSS(envD)
		c.expandMap = expandMap
		expandMap["EPREFIX"] = eprefix
		expandMap["PORTAGE_CONFIGROOT"] = configRoot
		makeGlobalsPath := ""
		if notInstalled {
			makeGlobalsPath = path.Join(PORTAGE_BASE_PATH, "cnf", "make.globals")
		} else {
			makeGlobalsPath = path.Join(c.globalConfigPath, "make.globals")
		}
		oldMakeGlobals := path.Join(configRoot, "etc", "make.globals")
		f1, _ := filepath.EvalSymlinks(makeGlobalsPath)
		f2, _ := filepath.EvalSymlinks(oldMakeGlobals)
		if s, err := os.Stat(oldMakeGlobals); err == nil && (!s.IsDir() && f1 != f2) {
			WriteMsg(fmt.Sprintf("!!!Found obsolete make.globals file: '%s', (using '%s' instead)\n", oldMakeGlobals, makeGlobalsPath), -1, nil)
		}
		makeGlobals := getConfig(makeGlobalsPath, tolerant, false, true, false, expandMap)
		if makeGlobals == nil {
			makeGlobals = map[string]string{}
		}
		for k, v := range c.defaultGlobals {
			if _, ok := makeGlobals[k]; !ok {
				makeGlobals[k] = v
			}
		}
		if configIncrementals == nil {
			c.incrementals = INCREMENTALS
		} else {
			c.incrementals = map[string]bool{}
			for _, v := range configIncrementals {
				c.incrementals[v] = true
			}
		}
		c.modulePriority = map[string]bool{"user": true, "default": true}
		c.modules = map[string]map[string][]string{}
		modulesFile := path.Join(configRoot, ModulesFilePath)
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
		c.backupenv = CopyMapSS(env)
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
			c.Repositories = loadRepositoryConfig(c, "")
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
				ov = NormalizePath(ov)
				if isdirRaiseEaccess(ov) || SyncMode {
					newOv = append(newOv, ShellQuote(ov))
				} else {
					WriteMsg(fmt.Sprintf("!!! Invalid PORTDIR_OVERLAY(not a dir): '%s'\n", ov), -1, nil)
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
			packageList = append(packageList, grabFilePackage(path.Join(x.location, "packages"), 0, false, false, false, x.allowBuildId, false, true, x.eapi, ""))
		}
		c.packages = stackLists(packageList, 1, false, false, false, false)
		c.prevmaskdict = map[string][]*Atom{}
		for x := range c.packages {
			if c.prevmaskdict[x.cp] == nil {
				c.prevmaskdict[x.cp] = []*Atom{x}
			} else {
				c.prevmaskdict[x.cp] = append(c.prevmaskdict[x.cp], x)
			}
		}
		c.unpackDependencies = loadUnpackDependenciesConfiguration(c.Repositories)
		myGCfg := map[string]string{}
		if len(profilesComplex) != 0 {
			myGCfgDLists := []map[string]string{}
			for _, x := range profilesComplex {
				myGCfgDLists = append(myGCfgDLists, getConfig(path.Join(x.location, "make.defaults"), tolerant, false, true, x.portage1Directories, expandMap))
			}
			c.makeDefaults = myGCfgDLists
			myGCfg = stackDicts(myGCfgDLists, 0, c.incrementals, 0)
			if len(myGCfg) == 0 {
				myGCfg = map[string]string{}
			}
		}
		c.configList = append(c.configList, myGCfg)
		c.configDict["defaults"] = c.configList[len(c.configList)-1]
		myGCfg = map[string]string{}
		for _, x := range makeConfPaths {
			for k, v := range getConfig(x, tolerant, true, true, true, expandMap) {
				myGCfg[k] = v
			}
		}
		p := [][2]string{}
		for _, v := range strings.Fields(c.configDict["defaults"]["PROFILE_ONLY_VARIABLES"]) {
			p = append(p, [2]string{v, ""})
		}
		profileOnlyVariables := stackLists([][][2]string{p}, 0, false, false, false, false)
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
		c.ValueDict["PORTAGE_OVERRIDE_EPREFIX"] = EPREFIX
		c.BackupChanges("PORTAGE_OVERRIDE_EPREFIX")

		c.ppropertiesdict = map[string]map[*Atom][]string{}
		c.pacceptRestrict = map[string]map[*Atom][]string{}
		c.penvdict = map[string]map[*Atom][]string{}
		c.pbashrcdict = map[*profileNode]map[string]map[*Atom][]string{}
		c.pbashrc = map[string]bool{}
		c.repoMakeDefaults = map[string]map[string]string{}

		for _, repo := range c.Repositories.reposWithProfiles() {
			d := getConfig(path.Join(repo.Location, "profiles", "make.defaults"), tolerant, false, true, repo.portage1Profiles, CopyMapSS(c.configDict["globals"]))
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
		c.useManager = NewUseManager(c.Repositories, profilesComplex, absUserConfig, c.isStable, localConfig)
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
			propDict := grabDictPackage(path.Join(absUserConfig, "package.properties"), false, true, false, true, true, true, false, false, "", "0")
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
					c.ppropertiesdict[k.cp] = map[*Atom][]string{k: v}
				} else {
					c.ppropertiesdict[k.cp][k] = v
				}
			}
			d := grabDictPackage(path.Join(absUserConfig, "package.accept_restrict"), false, true, false, true, true, true, false, false, "", "0")
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
					c.pacceptRestrict[k.cp] = map[*Atom][]string{k: v}
				} else {
					c.pacceptRestrict[k.cp][k] = v
				}
			}
			pEnvDict := grabDictPackage(path.Join(absUserConfig, "package.env"), false, true, false, true, true, true, false, false, "", "0")
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
					c.penvdict[k.cp] = map[*Atom][]string{k: v}
				} else {
					c.penvdict[k.cp][k] = v
				}
			}
			for _, profile := range profilesComplex {
				if !Ins(profile.profileFormats, "profile-bashrcs") {
					continue
				}
				c.pbashrcdict[profile] = map[string]map[*Atom][]string{}

				bashrc := grabDictPackage(path.Join(profile.location, "package.bashrc"), false, true, false, true, true, profile.allowBuildId, false, true, profile.eapi, "")
				if len(bashrc) == 0 {
					continue
				}
				for k, v := range bashrc {
					envFiles := []string{}
					for _, envname := range v {
						envFiles = append(envFiles, path.Join(profile.location, "bashrc", envname))
					}
					if _, ok := c.pbashrcdict[profile][k.cp]; !ok {
						c.pbashrcdict[profile][k.cp] = map[*Atom][]string{k: v}
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
			categories = append(categories, grabFile(path.Join(x, "categories"), 0, false, false))
		}
		c.categories = map[string]bool{}
		for x := range stackLists(categories, 1, false, false, false, false) {
			if categoryRe.MatchString(x.value) {
				c.categories[x.value] = true
			}
		}
		al := [][][2]string{}
		for _, x := range locationsManager.profileAndUserLocations {
			al = append(al, grabFile(path.Join(x, "arch.list"), 0, false, false))
		}
		archList := stackLists(al, 1, false, false, false, false)
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
				if getEapiAttrs(x.eapi).allowsPackageProvided {
					ppl = append(ppl, grabFile(provPath, 1, x.portage1Directories, false))
				}
			}
		}
		ppls := stackLists(ppl, 1, false, false, false, false)
		pkgProvidedLines := []string{}
		for a := range ppls {
			pkgProvidedLines = append(pkgProvidedLines, a.value)
		}
		hasInvalidData := false
		for x := len(pkgProvidedLines) - 1; x > -1; x-- {
			myline := pkgProvidedLines[x]
			if !isValidAtom("="+myline, false, false, false, "", false) {
				WriteMsg(fmt.Sprintf("Invalid package name in package.provided: %s\n", myline), -1, nil)
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
			cpvr := CatPkgSplit(pkgProvidedLines[x], 1, "")
			if cpvr == [4]string{} || cpvr[0] == "null" {
				WriteMsg("Invalid package name in package.provided: "+pkgProvidedLines[x]+"\n", -1, nil)
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
			WriteMsg("See portage(5) for correct package.provided usage.\n", -1, nil)
		}
		c.pprovideddict = map[string][]string{}
		for _, x := range pkgProvidedLines {
			x_split := CatPkgSplit(x, 1, "")
			if x_split == [4]string{} {
				continue
			}
			mycatpkg := cpvGetKey(x, "")
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

		erootOrParent := firstExisting(eroot)
		unprivileged := false

		if erootSt, err := os.Stat(erootOrParent); err == nil {
			if unprivilegedMode(erootOrParent, erootSt) {
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
				WriteMsg(fmt.Sprintf("!!! %s='%s' is not a valid integer. Falling back to %s.\n", varr, c.ValueDict[varr], defaultVal), -1, nil)
			} else {
				c.ValueDict[varr] = v
			}
			c.BackupChanges(varr)
		}

		c.depcachedir = c.ValueDict["PORTAGE_DEPCACHEDIR"]
		if c.depcachedir == "" {
			c.depcachedir = path.Join(string(os.PathSeparator), EPREFIX, strings.TrimPrefix(DepcachePath, string(os.PathSeparator)))
			if unprivileged && targetRoot != string(os.PathSeparator) {
				if s, err := os.Stat(firstExisting(c.depcachedir)); err != nil && s.Mode()&2 != 0 {
					c.depcachedir = path.Join(eroot, strings.TrimPrefix(DepcachePath, string(os.PathSeparator)))
				}
			}
		}

		c.ValueDict["PORTAGE_DEPCACHEDIR"] = c.depcachedir
		c.BackupChanges("PORTAGE_DEPCACHEDIR")

		if InternalCaller {
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
		output_init(c.ValueDict["PORTAGE_CONFIGROOT"])
		data_init(c)
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
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, "-"+v)
	if f.Features[v] {
		delete(f.Features, k)
	}
	f.syncEnvVar()
}

func (f *featuresSet) validate() {
	if f.Features["unknown-features-warn"] {
		var unknownFeatures []string
		for k := range f.Features {
			if !SUPPORTED_FEATURES[k] {
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
				WriteMsgLevel(colorize("BAD", fmt.Sprintf("FEATURES variable contains unknown value(s): %s", strings.Join(unknownFeatures2, ", "))+"\n"), 30, -1)
			}
		}
	}
	if f.Features["unknown-features-filter"] {
		var unknownFeatures []string
		for k := range f.Features {
			if !SUPPORTED_FEATURES[k] {
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

type locationsManager struct {
	userProfileDir, localRepoConfPath, eprefix, configRoot, targetRoot, sysroot, absUserConfig, profilePath, configProfilePath, esysroot, broot, portdir, portdirOverlay, eroot, globalConfigPath string
	userConfig                                                                                                                                                                                    bool
	overlayProfiles, profileLocations, profileAndUserLocations, profiles                                                                                                                          []string
	profilesComplex                                                                                                                                                                               []*profileNode
}

type SMSSS struct {
	S    string
	MSSS map[string][]string
}

func (l *locationsManager) loadProfiles(repositories *repoConfigLoader, knownRepositoryPaths []string) {
	k := map[string]bool{}
	for _, v := range knownRepositoryPaths {
		x, _ := filepath.EvalSymlinks(v)
		k[x] = true
	}
	knownRepos := []SMSSS{}
	for x := range k {
		repo := repositories.getRepoForLocation(x)
		layoutData := map[string][]string{}
		if repo == nil {
			layoutData, _ = parseLayoutConf(x, "")
		} else {
			layoutData = map[string][]string{"profile-formats": repo.profileFormats, "profile-eapi_when_unspecified": {repo.eapi}}
		}
		knownRepos = append(knownRepos, SMSSS{S: x + "/", MSSS: layoutData})
	}
	if l.configProfilePath == "" {
		deprecatedProfilePath := path.Join(l.configRoot, "etc", "make.profile")
		l.configProfilePath = path.Join(l.configRoot, ProfilePath)
		if isdirRaiseEaccess(l.configProfilePath) {
			l.profilePath = l.configProfilePath
			if isdirRaiseEaccess(deprecatedProfilePath) && path.Clean(l.profilePath) != deprecatedProfilePath {
				WriteMsg(fmt.Sprintf("!!! Found 2 make.profile dirs: using '%s', ignoring '%s'\n", l.profilePath, deprecatedProfilePath), -1, nil)
			}
		} else {
			l.configProfilePath = deprecatedProfilePath
			if isdirRaiseEaccess(l.configProfilePath) {
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
		customProf := path.Join(l.configRoot, CustomProfilePath)
		if _, err := os.Stat(customProf); !os.IsNotExist(err) {
			l.userProfileDir = customProf
			l.profiles = append(l.profiles, customProf)
			l.profilesComplex = append(l.profilesComplex, &profileNode{location: customProf, portage1Directories: true, userConfig: true, profileFormats: []string{"profile-bashrcs", "profile-set"}, eapi: readCorrespondingEapiFile(customProf+string(os.PathSeparator), ""), allowBuildId: true})
		}
	}
}

func (l *locationsManager) checkVarDirectory(varname, varr string) error {
	if !isdirRaiseEaccess(varr) {
		WriteMsg(fmt.Sprintf("!!! Error: %s='%s' is not a directory. "+
			"Please correct this.\n", varname, varr), -1, nil)
		return errors.New("DirectoryNotFound") // DirectoryNotFound(var)
	}
	return nil
}

func (l *locationsManager) addProfile(currentPath string, repositories *repoConfigLoader, known_repos []SMSSS) {
	currentAbsPath, _ := filepath.Abs(currentPath)
	allowDirectories := true
	allowParentColon := true
	repoLoc := ""
	compatMode := false
	currentFormats := []string{}
	eapi := ""
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
			eapi = layoutData["profile_eapi_when_unspecified"][0]
		}
	}
	eapiFile := path.Join(currentPath, "eapi")
	if eapi == "" {
		eapi = "0"
	}
	if f, err := os.Open(eapiFile); err == nil {
		bd := bufio.NewReader(f)
		l, _, err := bd.ReadLine()
		if err == nil {
			eapi = strings.TrimSpace(string(l))
			if !eapiIsSupported(eapi) {
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
			if portage1ProfilesAllowDirectories[x] {
				allowDirectories = true
				break
			}
		}
		if !allowDirectories {
			allowDirectories = eapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi)
		}
		compatMode = !eapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi) && len(layoutData["profile-formats"]) == 1 && layoutData["profile-formats"][0] == "portage-1-compat"
		for _, x := range layoutData["profile-formats"] {
			if "portage-2" == x {
				allowParentColon = true
				break
			}
		}
		currentFormats = layoutData["profile-formats"]
	}
	if compatMode {
		offenders := CopyMapSB(portage1ProfilesAllowDirectories)
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
	if existsRaiseEaccess(parentsFile) {
		parents := grabFile(parentsFile, 0, false, false)
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
			parentPath = NormalizePath(path.Join(currentPath, parentPath))
			if absParent || repoLoc == "" || strings.HasPrefix(parentPath, repoLoc) {
				parentPath, _ = filepath.EvalSymlinks(parentPath)
			}
			if existsRaiseEaccess(parentPath) {
				l.addProfile(parentPath, repositories, known_repos)
			} else {
				//raise ParseError(
				//	_("Parent '%s' not found: '%s'") %  \
				//(parentPath, parentsFile))
			}
		}
	}
	l.profiles = append(l.profiles, currentPath)
	l.profilesComplex = append(l.profilesComplex, &profileNode{location: currentPath, portage1Directories: allowDirectories, userConfig: false, profileFormats: currentFormats, eapi: eapi, allowBuildId: Ins(currentFormats, "build-id")})
}

func (l *locationsManager) expandParentColon(parentsFile, parentPath, repoLoc string, repositories *repoConfigLoader) string {
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
			parentPath = NormalizePath(path.Join(repoLoc, "profiles", parentPath[colon+1:]))
		}
	} else {
		pRepoName := parentPath[:colon]
		pRepoLoc := repositories.getLocationForName(pRepoName)
		parentPath = NormalizePath(path.Join(pRepoLoc, "profiles", parentPath[colon+1:]))
	}
	return parentPath
}

func (l *locationsManager) setRootOverride(rootOverwrite string) error {
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
	l.targetRoot = strings.TrimSuffix(NormalizePath(fap), string(os.PathSeparator)) + string(os.PathSeparator)
	if l.sysroot != "/" && l.sysroot != l.targetRoot {
		WriteMsg(fmt.Sprintf("!!! Error: SYSROOT (currently %s) must "+
			"equal / or ROOT (currently %s).\n", l.sysroot, l.targetRoot), 1, nil)
		return errors.New("InvalidLocation") // raise InvalidLocation(self.sysroot)
	}
	ensureDirs(l.targetRoot, -1, -1, -1, -1, nil, false)
	l.checkVarDirectory("ROOT", l.targetRoot)
	l.eroot = strings.TrimSuffix(l.targetRoot, string(os.PathSeparator)) + l.eprefix + string(os.PathSeparator)
	l.globalConfigPath = GlobalConfigPath
	if EPREFIX != "" {
		l.globalConfigPath = path.Join(EPREFIX, strings.TrimPrefix(GlobalConfigPath, string(os.PathSeparator)))
	}
	return nil
}

func (l *locationsManager) setPortDirs(portdir, portdirOverlay string) {
	l.portdir = portdir
	l.portdirOverlay = portdirOverlay
	l.overlayProfiles = []string{}
	ovs, _ := shlex.Split(l.portdirOverlay)
	for _, ov := range ovs {
		ov = NormalizePath(ov)
		profilesDir := path.Join(ov, "profiles")
		if isdirRaiseEaccess(profilesDir) {
			l.overlayProfiles = append(l.overlayProfiles, profilesDir)
		}
	}
	l.profileLocations = append([]string{path.Join(portdir, "profiles")}, l.overlayProfiles...)
	l.profileAndUserLocations = append(l.profileLocations[:0:0], l.profileLocations...)
	if l.userConfig {
		l.profileAndUserLocations = append(l.profileAndUserLocations, l.absUserConfig)
	}
}

func NewLocationsManager(configRoot, eprefix, configProfilePath string, localConfig bool, targetRoot, sysroot string) *locationsManager { // "", "", "", true, "", ""
	l := &locationsManager{userProfileDir: "", localRepoConfPath: "", eprefix: eprefix, configRoot: configRoot, targetRoot: targetRoot, sysroot: sysroot, userConfig: localConfig}
	if l.eprefix == "" {
		l.eprefix = EPREFIX
	} else {
		l.eprefix = NormalizePath(l.eprefix)
		if l.eprefix == string(os.PathSeparator) {
			l.eprefix = ""
		}
	}

	if l.configRoot == "" {
		l.configRoot = EPREFIX + string(os.PathSeparator)
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
	l.configRoot = strings.TrimRight(NormalizePath(fap), string(os.PathSeparator)) + string(os.PathSeparator)
	l.checkVarDirectory("PORTAGE_CONFIGROOT", l.configRoot)
	l.absUserConfig = path.Join(l.configRoot, UserConfigPath)
	l.configProfilePath = configProfilePath
	if l.sysroot == "" {
		l.sysroot = "/"
	} else {
		fap, _ := filepath.Abs(l.sysroot)
		l.sysroot = strings.TrimSuffix(NormalizePath(fap), string(os.PathSeparator)) + string(os.PathSeparator)
	}
	l.esysroot = strings.TrimSuffix(l.sysroot, string(os.PathSeparator)) + l.eprefix + string(os.PathSeparator)
	l.broot = EPREFIX
	return l
}

type useManager struct {
	userConfig                                                                                         bool
	isStable                                                                                           func(*PkgStr) bool
	repoUsemaskDict, repoUsestablemaskDict, repoUseforceDict, repoUsestableforceDict                   map[string][]string
	repoPusemaskDict, repoPusestablemaskDict, repoPuseforceDict, repoPusestableforceDict, repoPuseDict map[string]map[string]map[*Atom][]string
	usemaskList, usestablemaskList, useforceList, usestableforceList                                   [][]string
	pusemaskList, pusestablemaskList, pkgprofileuse, puseforceList, pusestableforceList                []map[string]map[*Atom][]string
	pUseDict                                                                                           map[string]map[*Atom][]string // extatom
	repoUsealiasesDict                                                                                 map[string]map[string][]string
	repoPusealiasesDict                                                                                map[string]map[string]map[*Atom]map[string][]string
	repositories                                                                                       *repoConfigLoader
}

func (u *useManager) parseFileToTuple(fileName string, recursive bool, eapiFilter func(string) bool, eapi, eapiDefault string) []string { // tnn"0"
	ret := []string{}
	lines := grabFile(fileName, 0, true, false)
	if eapi == "" {
		eapi = readCorrespondingEapiFile(fileName, eapiDefault)
	}
	if eapiFilter != nil && !eapiFilter(eapi) {
		if len(lines) > 0 {
			WriteMsg(fmt.Sprintf("--- EAPI '%s' does not support '%s': '%s'\n", eapi, path.Base(fileName), fileName), -1, nil)
		}
		return ret
	}
	useFlagRe := getUseflagRe(eapi)
	for _, v := range lines {
		prefixedUseflag := v[0]
		useflag := ""
		if prefixedUseflag[:1] == "-" {
			useflag = prefixedUseflag[1:]
		} else {
			useflag = prefixedUseflag
		}
		if !useFlagRe.MatchString(useflag) {
			WriteMsg(fmt.Sprintf("--- Invalid USE flag in '%s': '%s'\n", fileName, prefixedUseflag), -1, nil)
		} else {
			ret = append(ret, prefixedUseflag)
		}
	}

	return ret
}

func (u *useManager) parseFileToDict(fileName string, justStrings, recursive bool, eapiFilter func(string) bool, userConfig bool, eapi, eapiDefault string, allowBuildId bool) map[string]map[*Atom][]string { //ftnfn"0"f
	ret := map[string]map[*Atom][]string{}
	locationDict := map[*Atom][]string{}
	if eapi == "" {
		eapi = readCorrespondingEapiFile(fileName, eapiDefault)
	}
	extendedSyntax := eapi == "" && userConfig
	if extendedSyntax {
		ret = map[string]map[*Atom][]string{}
	} else {
		ret = map[string]map[*Atom][]string{}
	}
	fileDict := grabDictPackage(fileName, false, recursive, false, extendedSyntax, extendedSyntax, !extendedSyntax, allowBuildId, false, eapi, eapiDefault)
	if eapi != "" && eapiFilter != nil && !eapiFilter(eapi) {
		if len(fileDict) > 0 {
			WriteMsg(fmt.Sprintf("--- EAPI '%s' does not support '%s': '%s'\n", eapi, path.Base(fileName), fileName), -1, nil)
		}
		return ret
	}
	useFlagRe := getUseflagRe(eapi)
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
				WriteMsg(fmt.Sprintf("--- Invalid USE flag for '%v' in '%s': '%s'\n", k, fileName, prefixedUseFlag), -1, nil)
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
			ret[k.cp] = map[*Atom][]string{k: s}
		} else {
			ret[k.cp][k] = v
		}
	}
	return ret
}

func (u *useManager) parseUserFilesToExtatomdict(fileName, location string, userConfig bool) map[string]map[*Atom][]string {
	ret := map[string]map[*Atom][]string{}
	if userConfig {
		puseDict := grabDictPackage(path.Join(location, fileName), false, true, true, true, true, true, false, false, "", "")
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
				ret[k.cp] = map[*Atom][]string{k: l}
			} else {
				ret[k.cp][k] = l
			}
		}
	}
	return ret
}

func (u *useManager) parseRepositoryFilesToDictOfTuples(fileName string, repositories *repoConfigLoader, eapiFilter func(string) bool) map[string][]string { // n
	ret := map[string][]string{}
	for _, repo := range repositories.reposWithProfiles() {
		ret[repo.Name] = u.parseFileToTuple(path.Join(repo.Location, "profiles", fileName), true, eapiFilter, "", repo.eapi)
	}
	return ret
}

func (u *useManager) parseRepositoryFilesToDictOfDicts(fileName string, repositories *repoConfigLoader, eapiFilter func(string) bool) map[string]map[string]map[*Atom][]string {
	ret := map[string]map[string]map[*Atom][]string{}
	for _, repo := range repositories.reposWithProfiles() {
		ret[repo.Name] = u.parseFileToDict(path.Join(repo.Location, "profiles", fileName), false, true, eapiFilter, false, "0", repo.eapi, Ins(repo.profileFormats, "build-id"))
	}
	return ret
}

func (u *useManager) parseProfileFilesToTupleOfTuples(fileName string, locations []*profileNode, eapiFilter func(string) bool) [][]string {
	ret := [][]string{}
	for _, profile := range locations {
		ret = append(ret, u.parseFileToTuple(path.Join(profile.location, fileName), profile.portage1Directories, eapiFilter, profile.eapi, ""))
	}
	return ret
}

func (u *useManager) parseProfileFilesToTupleOfDicts(fileName string, locations []*profileNode, justStrings bool, eapiFilter func(string) bool) []map[string]map[*Atom][]string { // fn
	ret := []map[string]map[*Atom][]string{}
	for _, profile := range locations {
		ret = append(ret, u.parseFileToDict(path.Join(profile.location, fileName), justStrings, profile.portage1Directories, eapiFilter, profile.userConfig, profile.eapi, "", profile.allowBuildId))
	}
	return ret
}

func (u *useManager) parseRepositoryUsealiases(repositorires *repoConfigLoader) map[string]map[string][]string {
	ret := map[string]map[string][]string{}
	for _, repo := range repositorires.reposWithProfiles() {
		fileName := path.Join(repo.Location, "profiles", "use.aliases")
		eapi := readCorrespondingEapiFile(fileName, repo.eapi)
		useFlagRe := getUseflagRe(eapi)
		rawFileDict := grabDict(fileName, false, false, true, false, false)
		fileDict := map[string][]string{}
		for realFlag, aliases := range rawFileDict {
			if !useFlagRe.MatchString(realFlag) {
				WriteMsg(fmt.Sprintf("--- Invalid real USE flag in '%s': '%s'\n", fileName, realFlag), -1, nil)
			} else {
				for _, alias := range aliases {
					if !useFlagRe.MatchString(alias) {
						WriteMsg(fmt.Sprintf("--- Invalid USE flag alias for '%s' real USE flag in '%s': '%s'\n", realFlag, fileName, alias), -1, nil)
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
							WriteMsg(fmt.Sprintf("--- Duplicated USE flag alias in '%s': '%s'\n", fileName, alias), -1, nil)
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

func (u *useManager) parseRepositoryPackageusealiases(repositorires *repoConfigLoader) map[string]map[string]map[*Atom]map[string][]string {
	ret := map[string]map[string]map[*Atom]map[string][]string{}
	for _, repo := range repositorires.reposWithProfiles() {
		fileName := path.Join(repo.Location, "profiles", "package.use.aliases")
		eapi := readCorrespondingEapiFile(fileName, repo.eapi)
		useFlagRe := getUseflagRe(eapi)
		lines := grabFile(fileName, 0, true, false)
		fileDict := map[string]map[*Atom]map[string][]string{}
		for _, line := range lines {
			elements := strings.Fields(line[0])
			atom1, err := NewAtom(elements[0], nil, false, nil, nil, eapi, nil, nil)
			if err != nil {
				WriteMsg(fmt.Sprintf("--- Invalid atom1 in '%s': '%v'\n", fileName, atom1), 0, nil)
				continue
			}
			if len(elements) == 1 {
				WriteMsg(fmt.Sprintf("--- Missing real USE flag for '%s' in '%v'\n", fileName, atom1), -1, nil)
				continue
			}
			realFlag := elements[1]
			if !useFlagRe.MatchString(realFlag) {
				WriteMsg(fmt.Sprintf("--- Invalid real USE flag in '%s': '%v'\n", fileName, realFlag), -1, nil)
			} else {
				for _, alias := range elements[2:] {
					if !useFlagRe.MatchString(alias) {
						WriteMsg(fmt.Sprintf("--- Invalid USE flag alias for '%s' real USE flag in '%s': '%s'\n", realFlag, fileName, alias), -1, nil)
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
							WriteMsg(fmt.Sprintf("--- Duplicated USE flag alias in '%s': '%s'\n", fileName, alias), -1, nil)
						} else {
							if _, ok := fileDict[atom1.cp]; !ok {
								fileDict[atom1.cp] = map[*Atom]map[string][]string{atom1: {realFlag: {alias}}}
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

func (u *useManager) _isStable(pkg *PkgStr) bool {
	if u.userConfig {
		return pkg.stable()
	}
	if pkg.metadata == nil {
		return false
	}
	return u.isStable(pkg)
}

func (u *useManager) getUseMask(pkg *PkgStr, stable *bool) map[*Atom]string { //nn
	if pkg == nil {
		p := [][][2]string{}
		for _, v := range u.usemaskList {
			q := [][2]string{}
			for _, w := range v {
				q = append(q, [2]string{w, ""})
			}
			p = append(p, q)
		}
		return stackLists(p, 1, false, false, false, false)
	}
	cp := pkg.cp
	if stable == nil {
		stable = new(bool)
		*stable = u.isStable(pkg)
	}
	useMask := [][]string{}
	if pkg.repo != "" && pkg.repo != unknownRepo {
		repos := []string{}
		for range u.repositories.getitem(pkg.repo).masters {
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
	return stackLists(p, 1, false, false, false, false)
}

func (u *useManager) getUseForce(pkg *PkgStr, stable *bool) map[*Atom]string { //n

	if pkg == nil {
		p := [][][2]string{}
		for _, v := range u.useforceList {
			q := [][2]string{}
			for _, w := range v {
				q = append(q, [2]string{w, ""})
			}
			p = append(p, q)
		}
		return stackLists(p, 1, false, false, false, false)
	}
	cp := pkg.cp
	if stable == nil {
		stable = new(bool)
		*stable = u.isStable(pkg)
	}
	useForce := [][]string{}
	if pkg.repo != "" && pkg.repo != unknownRepo {
		repos := []string{}
		for range u.repositories.getitem(pkg.repo).masters {
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
	return stackLists(p, 1, false, false, false, false)
}

func (u *useManager) getUseAliases(pkg *PkgStr) map[string][]string {
	if pkg.eapi != "" && !eapiHasUseAliases(pkg.eapi) {
		return map[string][]string{}
	}
	cp := pkg.cp
	if cp == "" {
		slot := depGetslot(pkg.string)
		repo := DepGetrepo(pkg.string)
		pkg := NewPkgStr(RemoveSlot(pkg.string), nil, nil, "", repo, slot, 0, 0, "", 0, nil)
		cp = pkg.cp
	}
	useAliases := map[string][]string{}
	if pkg.repo != "" && pkg.repo != unknownRepo {
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
						WriteMsg(fmt.Sprintf("--- Duplicated USE flag alias for '%v%s%s': '%s'\n", pkg.cpv, repoSeparator, pkg.repo, alias), -1, nil)
					} else {
						if _, ok := useAliases[realFlag]; ok {
							useAliases[realFlag] = append(useAliases[realFlag], alias)
						} else {
							useAliases[realFlag] = []string{alias}
						}
					}
				}
			}

			var cpUsealiasesDict map[*Atom]map[string][]string = nil
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
								WriteMsg(fmt.Sprintf("--- Duplicated USE flag alias for '%v%s%s': '%s'\n", pkg.cpv, repoSeparator, pkg.repo, alias), -1, nil)
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

func (u *useManager) getPUSE(pkg *PkgStr) string {
	cp := pkg.cp
	if cp == "" {
		slot := depGetslot(pkg.string)
		repo := DepGetrepo(pkg.string)
		pkg := NewPkgStr(RemoveSlot(pkg.string), nil, nil, "", repo, slot, 0, 0, "", 0, nil)
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

func (u *useManager) extract_global_USE_changes(old string) string { //""
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

func NewUseManager(repositories *repoConfigLoader, profiles []*profileNode, absUserConfig string, isStable func(*PkgStr) bool, userConfig bool) *useManager { // t
	u := &useManager{}
	u.userConfig = userConfig
	u.isStable = isStable
	u.repoUsemaskDict = u.parseRepositoryFilesToDictOfTuples("use.mask", repositories, nil)
	u.repoUsestablemaskDict = u.parseRepositoryFilesToDictOfTuples("use.stable.mask", repositories, eapiSupportsStableUseForcingAndMasking)
	u.repoUseforceDict = u.parseRepositoryFilesToDictOfTuples("use.force", repositories, nil)
	u.repoUsestableforceDict = u.parseRepositoryFilesToDictOfTuples("use.stable.force", repositories, eapiSupportsStableUseForcingAndMasking)
	u.repoPusemaskDict = u.parseRepositoryFilesToDictOfDicts("package.use.mask", repositories, nil)
	u.repoPusestablemaskDict = u.parseRepositoryFilesToDictOfDicts("package.use.stable.mask", repositories, eapiSupportsStableUseForcingAndMasking)
	u.repoPuseforceDict = u.parseRepositoryFilesToDictOfDicts("package.use.force", repositories, nil)
	u.repoPusestableforceDict = u.parseRepositoryFilesToDictOfDicts("package.use.stable.force", repositories, eapiSupportsStableUseForcingAndMasking)
	u.repoPuseDict = u.parseRepositoryFilesToDictOfDicts("package.use", repositories, nil)

	u.usemaskList = u.parseProfileFilesToTupleOfTuples("use.mask", profiles, nil)
	u.usestablemaskList = u.parseProfileFilesToTupleOfTuples("use.stable.mask", profiles, eapiSupportsStableUseForcingAndMasking)
	u.useforceList = u.parseProfileFilesToTupleOfTuples("use.force", profiles, nil)
	u.usestableforceList = u.parseProfileFilesToTupleOfTuples("use.stable.force", profiles, eapiSupportsStableUseForcingAndMasking)
	u.pusemaskList = u.parseProfileFilesToTupleOfDicts("package.use.mask", profiles, false, nil)
	u.pusestablemaskList = u.parseProfileFilesToTupleOfDicts("package.use.stable.mask", profiles, false, eapiSupportsStableUseForcingAndMasking)
	u.pkgprofileuse = u.parseProfileFilesToTupleOfDicts("package.use", profiles, true, nil)
	u.puseforceList = u.parseProfileFilesToTupleOfDicts("package.use.force", profiles, false, nil)
	u.pusestableforceList = u.parseProfileFilesToTupleOfDicts("package.use.stable.force", profiles, false, eapiSupportsStableUseForcingAndMasking)

	u.pUseDict = u.parseUserFilesToExtatomdict("package.use", absUserConfig, userConfig)

	u.repoUsealiasesDict = u.parseRepositoryUsealiases(repositories)
	u.repoPusealiasesDict = u.parseRepositoryPackageusealiases(repositories)

	u.repositories = repositories
	return u
}

type maskManager struct {
	_punmaskdict, _pmaskdict, _pmaskdict_raw map[string][]*Atom
}

func (m *maskManager) _getMaskAtom(cpv *PkgStr, slot, repo string, unmask_atoms []*Atom) *Atom { // nil
	var pkg *PkgStr = nil
	if cpv.slot == "" {
		pkg = NewPkgStr(cpv.string, nil, nil, "", repo, slot, 0, 0, "", 0, nil)
	} else {
		pkg = cpv
	}
	maskAtoms := m._punmaskdict[pkg.cp]
	if len(maskAtoms) > 0 {
		pkgList := []*PkgStr{pkg}
		for _, x := range maskAtoms {
			if len(matchFromList(x, pkgList)) == 0 {
				continue
			}
			if len(unmask_atoms) > 0 {
				for _, y := range unmask_atoms {
					if len(matchFromList(y, pkgList)) > 0 {
						return nil
					}
				}
			}
			return x
		}
	}
	return nil
}

func (m *maskManager) getMaskAtom(cpv *PkgStr, slot, repo string) *Atom {
	var pkg *PkgStr = nil
	if cpv.slot == "" {
		pkg = NewPkgStr(cpv.string, nil, nil, "", repo, slot, 0, 0, "", 0, nil)
	} else {
		pkg = cpv
	}
	return m._getMaskAtom(pkg, slot, repo, m._punmaskdict[pkg.cp])
}

func (m *maskManager) getRawMaskAtom(cpv *PkgStr, slot, repo string) *Atom {
	return m._getMaskAtom(cpv, slot, repo, nil)
}

func NewMaskManager(repositories *repoConfigLoader, profiles []*profileNode, abs_user_config string, user_config, strict_umatched_removal bool) *maskManager { // true, false
	m := &maskManager{}
	m._punmaskdict, m._pmaskdict, m._pmaskdict_raw = map[string][]*Atom{}, map[string][]*Atom{}, map[string][]*Atom{}
	pmaskCache := map[string][][2]string{}
	grabPMask := func(loc string, repoConfig *RepoConfig) [][2]string {
		if _, ok := pmaskCache[loc]; !ok {
			path := path.Join(loc, "profiles", "package.mask")
			pmaskCache[loc] = grabFilePackage(path, 0, repoConfig.portage1Profiles, false, false, Ins(repoConfig.profileFormats, "build-id"), true, true, "", repoConfig.eapi)
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
	repoPkgMaskLines := []AS{}
	for _, repo := range repositories.reposWithProfiles() {
		lines := []map[*Atom]string{}
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
			lines = append(lines, stackLists([][][2]string{masterLines, repoLines}, 1, true, false, false, false))
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
					WriteMsg(fmt.Sprintf("--- Unmatched removal atoms in %s: %s and %v more\n", sourceFile, strings.Join(ur[:3], ","), len(ur)-3), -1, nil)
				} else {
					WriteMsg(fmt.Sprintf("--- Unmatched removal atom(s) in %s: %s\n", sourceFile, strings.Join(ur[:3], ",")), -1, nil)
				}
			}
		} else {
			lines = append(lines, stackLists([][][2]string{repoLines}, 1, true, !user_config, strict_umatched_removal, false))
		}
		ls := [][2]string{}
		for _, l := range lines {
			for a, s := range l {
				ls = append(ls, [2]string{a.value, s})
			}
		}
		repoPkgMaskLines = append(repoPkgMaskLines, appendRepo(stackLists([][][2]string{ls}, 1, false, false, false, false), repo.Name, true)...)
	}
	repoPkgUnmaskLines := []AS{}
	for _, repo := range repositories.reposWithProfiles() {
		if !repo.portage1Profiles {
			continue
		}
		repoLines := grabFilePackage(path.Join(repo.Location, "profiles", "package.unmask"), 0, true, false, false, Ins(repo.profileFormats, "build-id"), true, true, "", repo.eapi)
		lines := stackLists([][][2]string{repoLines}, 1, true, true, strict_umatched_removal, false)
		repoPkgUnmaskLines = append(repoPkgUnmaskLines, appendRepo(lines, repo.Name, true)...)
	}
	profilePkgMaskLiness := [][][2]string{}
	profilePkgUnmaskLiness := [][][2]string{}
	for _, x := range profiles {
		profilePkgMaskLiness = append(profilePkgMaskLiness, grabFilePackage(path.Join(x.location, "package.mask"), 0, x.portage1Directories, false, false, true, true, true, x.eapi, ""))
		if x.portage1Directories {
			profilePkgUnmaskLiness = append(profilePkgUnmaskLiness, grabFilePackage(path.Join(x.location, "package.unmask"), 0, x.portage1Directories, false, false, true, true, true, x.eapi, ""))
		}
	}
	profilePkgmasklines := stackLists(profilePkgMaskLiness, 1, true, true, strict_umatched_removal, false)
	profilePkgunmasklines := stackLists(profilePkgUnmaskLiness, 1, true, true, strict_umatched_removal, false)

	userPkgMaskLines := [][2]string{}
	userPkgUnmaskLines := [][2]string{}
	if user_config {
		userPkgMaskLines = grabFilePackage(path.Join(abs_user_config, "package.mask"), 0, true, true, true, true, true, true, "", "")
		userPkgUnmaskLines = grabFilePackage(path.Join(abs_user_config, "package.mask"), 0, true, true, true, true, true, true, "", "")
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

	rawPkgMaskLines := stackLists([][][2]string{r1, p1}, 1, true, false, false, false)
	pkgMaskLines := stackLists([][][2]string{r1, p1, userPkgMaskLines}, 1, true, false, false, false)
	pkgUnmaskLines := stackLists([][][2]string{r2, p2, userPkgUnmaskLines}, 1, true, false, false, false)

	for x := range rawPkgMaskLines {
		if _, ok := m._pmaskdict_raw[x.cp]; !ok {
			m._pmaskdict_raw[x.cp] = []*Atom{x}
		}
	}
	for x := range pkgMaskLines {
		if _, ok := m._pmaskdict[x.cp]; !ok {
			m._pmaskdict[x.cp] = []*Atom{x}
		}
	}
	for x := range pkgUnmaskLines {
		if _, ok := m._punmaskdict[x.cp]; !ok {
			m._punmaskdict[x.cp] = []*Atom{x}
		}
	}

	return m
}

type keywordsManager struct {
	pkeywordsList, pAcceptKeywords []map[string]map[*Atom][]string
	pkeywordsDict                  map[string]map[*Atom][]string
}

func (k *keywordsManager) getKeywords(cpv *PkgStr, slot, keywords, repo string) map[*Atom]string {
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
	return stackLists(kw, 1, false, false, false, false)
}

func (k *keywordsManager) isStable(pkg *PkgStr, globalAcceptKeywords, backupedAcceptKeywords string) bool {
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
	unstable := map[*Atom]string{}
	for _, kw := range myGroups {
		if kw[:1] != "~" {
			kw = "~" + kw
		}
		unstable[&Atom{value: kw}] = ""
	}
	return len(k._getMissingKeywords(pkg, pgroups, unstable)) > 0
}

func (k *keywordsManager) GetMissingKeywords(cpv *PkgStr, slot, keywords, repo, globalAcceptKeywords, backupedAcceptKeywords string) map[*Atom]string {
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

func (k *keywordsManager) getRawMissingKeywords(cpv *PkgStr, slot, keywords, repo, globalAcceptKeywords string) map[*Atom]string {
	mygroups := k.getKeywords(cpv, slot, keywords, repo)
	pGroups := strings.Fields(globalAcceptKeywords)
	pgroups := map[string]bool{}
	for _, v := range pGroups {
		pgroups[v] = true
	}
	return k._getMissingKeywords(cpv, pgroups, mygroups)
}

func (k *keywordsManager) getEgroups(egroups, mygroups []string) map[string]bool {
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

func (k *keywordsManager) _getMissingKeywords(cpv *PkgStr, pgroups map[string]bool, mygroups map[*Atom]string) map[*Atom]string {
	match := false
	hasstable := false
	hastesting := false
	for gp := range mygroups {
		if gp.value == "*" {
			match = true
			break
		} else if gp.value == "~*" {
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
		} else if pgroups[gp.value] {
			match = true
			break
		} else if strings.HasPrefix(gp.value, "~") {
			hastesting = true
		} else if !strings.HasPrefix(gp.value, "-") {
			hasstable = true
		}
	}
	if !match && ((hastesting && pgroups["~*"]) || (hasstable && pgroups["*"]) || pgroups["**"]) {
		match = true
	}
	if match {
		return map[*Atom]string{}
	} else {
		if len(mygroups) == 0 {
			mygroups = map[*Atom]string{{value: "**"}: ""}
		}
		return mygroups
	}
}

func (k *keywordsManager) getPKeywords(cpv *PkgStr, slot, repo, globalAcceptKeywords string) []string {
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

func NewKeywordsManager(profiles []*profileNode, absUserConfig string, userConfig bool, globalAcceptKeywords string) *keywordsManager { // t""
	k := &keywordsManager{}
	k.pkeywordsList = []map[string]map[*Atom][]string{}
	rawPkeywords := []map[*Atom][]string{}
	for _, x := range profiles {
		rawPkeywords = append(rawPkeywords, grabDictPackage(path.Join(x.location, "package.keywords"), false, x.portage1Directories, false, false, false, x.allowBuildId, false, true, x.eapi, ""))
	}
	for _, pkeyworddict := range rawPkeywords {
		if len(pkeyworddict) == 0 {
			continue
		}
		cpdict := map[string]map[*Atom][]string{}
		for k, v := range pkeyworddict {
			if _, ok := cpdict[k.cp]; !ok {
				cpdict[k.cp] = map[*Atom][]string{k: v}
			} else {
				cpdict[k.cp][k] = v
			}
		}
		k.pkeywordsList = append(k.pkeywordsList, cpdict)
	}
	k.pAcceptKeywords = []map[string]map[*Atom][]string{}
	rawPAcceptKeywords := []map[*Atom][]string{}
	for _, x := range profiles {
		rawPAcceptKeywords = append(rawPAcceptKeywords, grabDictPackage(path.Join(x.location, "package.accept_keywords"), false, x.portage1Directories, false, false, false, false, false, true, x.eapi, ""))
	}
	for _, d := range rawPAcceptKeywords {
		if len(d) == 0 {
			continue
		}
		cpdict := map[string]map[*Atom][]string{}
		for k, v := range d {
			if _, ok := cpdict[k.cp]; !ok {
				cpdict[k.cp] = map[*Atom][]string{k: v}
			} else {
				cpdict[k.cp][k] = v
			}
		}
		k.pAcceptKeywords = append(k.pAcceptKeywords, cpdict)
	}

	k.pkeywordsDict = map[string]map[*Atom][]string{}
	if userConfig {
		pkgDict := grabDictPackage(path.Join(absUserConfig, "package.keywords"), false, true, false, true, true, true, false, true, "", "")
		for k, v := range grabDictPackage(path.Join(absUserConfig, "package.accept_keywords"), false, true, false, true, true, true, false, true, "", "") {
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
			if _, ok := k.pkeywordsDict[k1.cp]; !ok {
				k.pkeywordsDict[k1.cp] = map[*Atom][]string{k1: v}
			} else {
				k.pkeywordsDict[k1.cp][k1] = v
			}
		}
	}
	return k
}

type licenseManager struct {
	acceptLicenseStr string
	acceptLicense    []string
	_plicensedict    map[string]map[*Atom][]string
	undefLicGroups   map[string]bool
	licenseGroups    map[string]map[string]bool
}

func (l *licenseManager) readUserConfig(absUserConfig string) {
	licDictt := grabDictPackage(path.Join(absUserConfig, "package.license"), false, true, false, true, true, false, false, false, "", "")
	for k, v := range licDictt {
		if _, ok := l._plicensedict[k.cp]; !ok {
			l._plicensedict[k.cp] = map[*Atom][]string{k: v}
		} else {
			l._plicensedict[k.cp][k] = v
		}
	}
}

func (l *licenseManager) readLicenseGroups(locations []string) {
	for _, loc := range locations {
		for k, v := range grabDict(path.Join(loc, "license_groups"), false, false, false, true, false) {
			if _, ok := l.licenseGroups[k]; !ok {
				l.licenseGroups[k] = map[string]bool{}
			}
			for _, w := range v {
				l.licenseGroups[k][w] = true
			}
		}
	}
}

func (l *licenseManager) extractGlobalChanges(old string) string { // ""
	ret := old
	atomLicenseMap := l._plicensedict["*/*"]
	if len(atomLicenseMap) > 0 {
		var v []string = nil
		for a, m := range atomLicenseMap {
			if a.value == "*/*" {
				v = m
				delete(atomLicenseMap, a)
				break
			}
		}
		if v != nil {
			ret = strings.Join(v, " ")
			if old != "" {
				ret = old + " " + ret
			}
			if len(atomLicenseMap) == 0 {
				delete(l._plicensedict, "*/*")
			}
		}
	}
	return ret
}

func (l *licenseManager) expandLicenseTokens(tokens []string) []string {
	expandedTokens := []string{}
	for _, x := range tokens {
		expandedTokens = append(expandedTokens, l._expandLicenseToken(x, nil)...)
	}
	return expandedTokens
}

func (l *licenseManager) _expandLicenseToken(token string, traversedGroups map[string]bool) []string {
	negate := false
	rValue := []string{}
	licenseName := ""
	if strings.HasPrefix(token, "-") {
		negate = true
		licenseName = token[1:]
	} else {
		licenseName = token
	}
	if !strings.HasPrefix(licenseName, "@") {
		rValue = append(rValue, token)
		return rValue
	}

	groupName := licenseName[1:]
	if traversedGroups == nil {
		traversedGroups = map[string]bool{}
	}
	licenseGroup := l.licenseGroups[groupName]
	if traversedGroups[groupName] {
		WriteMsg(fmt.Sprintf("Circular license group reference detected in '%s'\n", groupName), -1, nil)
		rValue = append(rValue, "@"+groupName)
	} else if len(licenseGroup) > 0 {
		traversedGroups[groupName] = true
		for li := range licenseGroup {
			if strings.HasPrefix(li, "-") {
				WriteMsg(fmt.Sprintf("Skipping invalid element %s in license group '%s'\n", li, groupName), -1, nil)
			} else {
				rValue = append(rValue, l._expandLicenseToken(li, traversedGroups)...)
			}
		}
	} else {
		if len(l.licenseGroups) > 0 && !l.undefLicGroups[groupName] {
			l.undefLicGroups[groupName] = true
			WriteMsg(fmt.Sprintf("Undefined license group '%s'\n", groupName), -1, nil)
			rValue = append(rValue, "@"+groupName)
		}
	}
	if negate {
		for k := range rValue {
			rValue[k] = "-" + rValue[k]
		}
	}
	return rValue
}

func (l *licenseManager) _getPkgAcceptLicense(cpv *PkgStr, slot, repo string) []string {
	acceptLicense := l.acceptLicense
	cp := cpvGetKey(cpv.string, "")
	cpdict := l._plicensedict[cp]
	if len(cpdict) > 0 {
		if cpv.slot == "" {
			cpv = NewPkgStr(cpv.string, nil, nil, "", repo, slot, 0, 0, "", 0, nil)
		}
		plicenceList := orderedByAtomSpecificity(cpdict, cpv, "")
		if len(plicenceList) > 0 {
			acceptLicense = append(l.acceptLicense[:0:0], l.acceptLicense...)
		}
		for _, x := range plicenceList {
			acceptLicense = append(acceptLicense, x...)
		}
	}
	return acceptLicense
}

func (l *licenseManager) getPrunnedAcceptLicense(cpv *PkgStr, use map[string]bool, lic, slot, repo string) string {
	licenses := map[string]bool{}
	for _, u := range useReduce(lic, use, nil, false, nil, false, "", false, true, nil, nil, false) {
		licenses[u] = true
	}
	acceptLicense := l._getPkgAcceptLicense(cpv, slot, repo)
	if len(acceptLicense) > 0 {
		acceptableLicenses := map[string]bool{}
		for _, x := range acceptLicense {
			if x == "*" {
				for k := range licenses {
					acceptableLicenses[k] = true
				}
			} else if x == "-*" {
				acceptableLicenses = map[string]bool{}
			} else if x[:1] == "-" {
				delete(acceptableLicenses, x[1:])
			} else if licenses[x] {
				acceptableLicenses[x] = true
			}
		}
		licenses = acceptableLicenses
	}
	licensesS := []string{}
	for k := range licenses {
		licensesS = append(licensesS, k)
	}
	sort.Strings(licensesS)
	return strings.Join(licensesS, " ")
}

func (l *licenseManager) getMissingLicenses(cpv *PkgStr, use, lic, slot, repo string) []string {
	licenses := map[string]bool{}
	for _, u := range useReduce(lic, nil, nil, true, nil, false, "", false, true, nil, nil, false) {
		licenses[u] = true
	}
	delete(licenses, "||")

	acceptableLicenses := map[string]bool{}
	for _, x := range l._getPkgAcceptLicense(cpv, slot, repo) {
		if x == "*" {
			for k := range licenses {
				acceptableLicenses[k] = true
			}
		} else if x == "-*" {
			acceptableLicenses = map[string]bool{}
		} else if x[:1] == "-" {
			delete(acceptableLicenses, x[1:])
		} else {
			acceptableLicenses[x] = true
		}
	}
	licenseStr := lic
	useM := map[string]bool{}
	if strings.Contains(licenseStr, "?") {
		for _, u := range strings.Fields(use) {
			useM[u] = true
		}
	}
	licenseStruct := useReduce(licenseStr, useM, []string{}, false, []string{}, false, "", false, false, nil, nil, false)

	return l._getMaskedLicenses(licenseStruct, acceptableLicenses)
}

func (l *licenseManager) _getMaskedLicenses(licenseStruct []string, acceptableLicenses map[string]bool) []string {
	if len(licenseStruct) == 0 {
		return []string{}
	}
	if licenseStruct[0] == "||" {
		ret := []string{}
		for _, element := range licenseStruct[1:] {
			if acceptableLicenses[element] {
				return []string{}
			}
			ret = append(ret, element)
		}
		return ret
	}
	ret := []string{}
	for _, element := range licenseStruct {
		if !acceptableLicenses[element] {
			ret = append(ret, element)
		}
	}
	return ret
}

func (l *licenseManager) setAcceptLicenseStr(acceptLicenseStr string) {
	if acceptLicenseStr != l.acceptLicenseStr {
		l.acceptLicenseStr = acceptLicenseStr
		l.acceptLicense = l.expandLicenseTokens(strings.Fields(acceptLicenseStr))
	}
}

func NewLicenseManager(licenseGroupLocations []string, absUserConfig string, userConfig bool) *licenseManager { // t
	l := &licenseManager{}
	l.acceptLicenseStr = ""
	l.acceptLicense = nil
	l.licenseGroups = map[string]map[string]bool{}
	l._plicensedict = map[string]map[*Atom][]string{}
	l.undefLicGroups = map[string]bool{}
	if userConfig {
		licenseGroupLocations = append(licenseGroupLocations, absUserConfig)
	}
	l.readLicenseGroups(licenseGroupLocations)
	if userConfig {
		l.readUserConfig(absUserConfig)
	}
	return l
}

type virtualManager struct {
	_dirVirtuals, _virtuals, _treeVirtuals, _depgraphVirtuals, _virts_p map[string][]string
}

func (v *virtualManager) read_dirVirtuals(profiles []string) {
	virtualsList := []map[string][]string{}
	for _, x := range profiles {
		virtualsFile := path.Join(x, "virtuals")
		virtualsDict := grabDict(virtualsFile, false, false, false, false, false)
		atomsDict := map[string][]string{}
		for k, v := range virtualsDict {
			virtAtom, err := NewAtom(k, nil, false, nil, nil, "", nil, nil)
			if err != nil {
				virtAtom = nil
			} else {
				if virtAtom.Blocker != nil || virtAtom.value != virtAtom.cp {
					virtAtom = nil
				}
			}
			if virtAtom == nil {
				WriteMsg(fmt.Sprintf("--- Invalid virtuals Atom in %s: %s\n", virtualsFile, k), -1, nil)
				continue
			}
			providers := []string{}
			for _, atom := range v {
				atomOrig := atom
				if atom[:1] == "-" {
					atom = atom[1:]
				}
				atomA, err := NewAtom(atom, nil, false, nil, nil, "", nil, nil)
				if err != nil {
					atomA = nil
				} else {
					if atomA.Blocker != nil {
						atomA = nil
					}
				}
				if atomA == nil {
					WriteMsg(fmt.Sprintf("--- Invalid Atom in %s: %s\n", virtualsFile, atomOrig), -1, nil)
				} else {
					if atomOrig == atomA.value {
						providers = append(providers, atom)
					} else {
						providers = append(providers, atomOrig)
					}
				}
			}
			if len(providers) > 0 {
				atomsDict[virtAtom.value] = providers
			}
		}
		if len(atomsDict) > 0 {
			virtualsList = append(virtualsList, atomsDict)
		}
	}

	v._dirVirtuals = stackDictList(virtualsList, 1, nil, 0)

	for virt := range v._dirVirtuals {
		ReverseSlice(v._dirVirtuals[virt])
	}
}

func (v *virtualManager) _compile_virtuals() {
	ptVirtuals := map[string][]string{}

	for virt, installedList := range v._treeVirtuals {
		profileList := v._dirVirtuals[virt]
		if len(profileList) == 0 {
			continue
		}
		for _, cp := range installedList {
			if Ins(profileList, cp) {
				if _, ok := ptVirtuals[virt]; !ok {
					ptVirtuals[virt] = []string{cp}
				} else {
					ptVirtuals[virt] = append(ptVirtuals[virt], cp)
				}
			}
		}
	}

	virtuals := stackDictList([]map[string][]string{ptVirtuals, v._treeVirtuals, v._dirVirtuals, v._depgraphVirtuals}, 0, nil, 0)
	v._virtuals = virtuals
	v._virts_p = nil
}

func (v *virtualManager) getvirtuals() map[string][]string {
	if v._treeVirtuals != nil {
		panic("_populate_treeVirtuals() must be called before any query about virtuals")
	}
	if v._virtuals == nil {
		v._compile_virtuals()
	}
	return v._virtuals
}

func (v *virtualManager) deepcopy() *virtualManager {
	return v
}

func (v *virtualManager) getVirtsP() map[string][]string {
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

func (v *virtualManager) _populate_treeVirtuals(vartree *varTree) {
	if v._treeVirtuals != nil {
		panic("treeVirtuals must not be reinitialized")
	}
	v._treeVirtuals = map[string][]string{}

	for provide, cpvList := range vartree.get_all_provides() {
		provideA, err := NewAtom(provide, nil, false, nil, nil, "", nil, nil)
		if err != nil {
			continue
		}
		v._treeVirtuals[provideA.cp] = []string{}
		for _, cpv := range cpvList {
			v._treeVirtuals[provideA.cp] = append(v._treeVirtuals[provideA.cp], cpv.cp)
		}
	}
}

func (v *virtualManager) populate_treeVirtuals_if_needed(vartree *varTree) {
	if v._treeVirtuals != nil {
		return
	}
	v._populate_treeVirtuals(vartree)
}

func (v *virtualManager) add_depgraph_virtuals(mycpv string, virts []string) {
	if v._virtuals == nil {
		v.getvirtuals()
	}

	modified := false
	cp, _ := NewAtom(cpvGetKey(mycpv, ""), nil, false, nil, nil, "", nil, nil)
	for _, virt := range virts {
		a, err := NewAtom(virt, nil, false, nil, nil, "", nil, nil)
		if err != nil {
			continue
		}
		virt = a.cp
		providers := v._depgraphVirtuals[virt]
		if providers == nil {
			providers = []string{}
			v._depgraphVirtuals[virt] = providers
		}
		if !Ins(providers, cp.value) {
			providers = append(providers, cp.value)
			modified = true
		}
	}
	if modified {
		v._compile_virtuals()
	}
}

func NewVirtualManager(profiles []string) *virtualManager {
	v := &virtualManager{}
	v._virtuals = nil
	v._dirVirtuals = nil
	v._virts_p = nil
	v._treeVirtuals = nil
	v._depgraphVirtuals = map[string][]string{}
	v.read_dirVirtuals(profiles)
	return v
}

func loadUnpackDependenciesConfiguration(repositories *repoConfigLoader) map[string]map[string]map[string]string {
	repoDict := map[string]map[string]map[string]string{}
	for _, repo := range repositories.reposWithProfiles() {
		for eapi := range supportedEapis {
			if eapiHasAutomaticUnpackDependencies(eapi) {
				fileName := path.Join(repo.Location, "profiles", "unpack_dependencies", eapi)
				lines := grabFile(fileName, 0, true, false)
				for _, line := range lines {
					elements := strings.Fields(line[0])
					suffix := strings.ToLower(elements[0])
					if len(elements) == 1 {
						WriteMsg(fmt.Sprintf("--- Missing unpack dependencies for '%s' suffix in '%s'\n", suffix, fileName), 0, nil)
					}
					depend := strings.Join(elements[1:], " ")
					useReduce(depend, map[string]bool{}, []string{}, false, []string{}, false, eapi, false, false, nil, nil, false)
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
	} else if FindBinary(vSplit[0]) == "" {
		invalid = true
	}
	return !invalid, vSplit
}

func orderedByAtomSpecificity(cpdict map[*Atom][]string, pkg *PkgStr, repo string) [][]string {
	if pkg.repo == "" && repo != "" && repo != unknownRepo {
		//pkg = pkg +repoSeparator+repo
	}
	results := [][]string{}
	keys := []*Atom{}
	for k := range cpdict {
		keys = append(keys, k)
	}
	for len(keys) > 0 {
		bestMatch := bestMatchToList(pkg, keys)
		if bestMatch != nil {
			keys2 := []*Atom{}
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

func orderedByAtomSpecificity2(cpdict map[*Atom]map[string][]string, pkg *PkgStr, repo string) []map[string][]string {
	if pkg.repo == "" && repo != "" && repo != unknownRepo {
		//pkg = pkg +repoSeparator+repo
	}
	results := []map[string][]string{}
	keys := []*Atom{}
	for k := range cpdict {
		keys = append(keys, k)
	}
	for len(keys) > 0 {
		bestMatch := bestMatchToList(pkg, keys)
		if bestMatch != nil {
			keys2 := []*Atom{}
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
	ReverseSlice(split)
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
