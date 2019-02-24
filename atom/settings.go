package atom

import (
	"errors"
	"fmt"
	"github.com/google/shlex"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

var (
	constantKeys   = map[string]bool{"PORTAGE_BIN_PATH": true, "PORTAGE_GID": true, "PORTAGE_PYM_PATH": true, "PORTAGE_PYTHONPATH": true}
	deprecatedKeys = map[string]string{"PORTAGE_LOGDIR": "PORT_LOGDIR", "PORTAGE_LOGDIR_CLEAN": "PORT_LOGDIR_CLEAN"}
	setcpvAuxKeys  = map[string]bool{"BDEPEND": true, "DEFINED_PHASES": true, "DEPEND": true, "EAPI": true, "HDEPEND": true,
		"INHERITED": true, "IUSE": true, "REQUIRED_USE": true, "KEYWORDS": true, "LICENSE": true, "PDEPEND": true,
		"PROPERTIES": true, "SLOT": true, "repository": true, "RESTRICT": true}
	caseInsensitiveVars = map[string]bool{"AUTOCLEAN": true, "NOCOLOR": true}
	defaultGlobals      = map[string]string{"ACCEPT_PROPERTIES": "*", "PORTAGE_BZIP2_COMMAND": "bzip2"}
	envBlacklist        = map[string]bool{
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
		"REQUIRED_USE": true, "RESTRICT": true, "ROOT": true, "SLOT": true, "SRC_URI": true, "_": true}
	environFilter = map[string]bool{
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
		"SYNC":             true}
	environWhitelist = map[string]bool{"ACCEPT_LICENSE": true, "BASH_ENV": true, "BROOT": true, "BUILD_PREFIX": true, "COLUMNS": true, "D": true,
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
		"STY": true, "WINDOW": true, "XAUTHORITY": true}
	validateCommands   = map[string]bool{"PORTAGE_BZIP2_COMMAND": true, "PORTAGE_BUNZIP2_COMMAND": true}
	globalOnlyVars     = map[string]bool{"CONFIG_PROTECT": true}
	environWhitelistRe = regexp.MustCompile(`^(CCACHE_|DISTCC_).*`)
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
}

func NewIuseImplicitMatchCache(setting map[string]string) {

}

type Config struct {
	valueDict                                                                                                                                                                                                                                                                                                                                                                             map[string]string
	tolerent, unmatchedRemoval, localConfig                                                                                                                                                                                                                                                                                                                                               bool
	locked                                                                                                                                                                                                                                                                                                                                                                                int
	mycpv, setcpvArgsHash, penv, modifiedkeys, uvlist, acceptChostRe, makeDefaults, parentStable, sonameProvided                                                                                                                                                                                                                                                                          *int
	puse, categories, depcachedir, incrementals, modulePriority, profilePath, profiles, packages, repositories, unpackDependencies, defaultFeaturesUse, iuseEffective, iuseImplicitMatch, nonUserVariables, envDBlacklist, pbashrc, repoMakeDefaults, usemask, useforce, userProfileDir, makeDefaultsUse, profileBashrc, locationsManager, useManager, modules, backupenv, licenseManager string
	configList, lookupList, featuresOverrides                                                                                                                                                                                                                                                                                                                                             []string
	configDict, useExpandDict, prevmaskdict, pprovideddict, virtualsManagerObj, virtualsManager, acceptProperties, ppropertiesdict, acceptRestrict, pacceptRestrict, penvdict, pbashrcdict, expandMap, keywordsManagerObj, maskManagerObj                                                                                                                                                 map[string]string
	unknownFeatures                                                                                                                                                                                                                                                                                                                                                                       map[string]bool
	features                                                                                                                                                                                                                                                                                                                                                                              *featuresSet
}

func (c *Config) Lock() {
	c.locked = 1
}
func (c *Config) Unlock() {
	c.locked = 0
}
func (c *Config) Modifying() error {
	if c.locked != 0 {
		return errors.New("")
	}
	return nil
}
func (c *Config) SetCpv(cpv string, useCache map[string]string, myDb string) {
	if useCache != nil {
		// warn here
	}
	c.Modifying()
}

var eapiCache = map[string]bool{}

func NewConfig(clone *Config, mycpv, configProfilePath string, configIncrementals []int, config_root, target_root, sysroot, eprefix string, local_config bool, env map[string]string, unmatchedRemoval bool, repositories string) *Config {
	eapiCache = make(map[string]bool)
	tolerant := initializingGlobals == nil
	c := &Config{tolerent: tolerant, unmatchedRemoval: unmatchedRemoval, localConfig: local_config}
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
		c.repositories = clone.repositories
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
		c.configList = []string{
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

		c.lookupList = c.configList[:]
		ReverseSlice(c.lookupList)
		c.useExpandDict = CopyMapSS(clone.useExpandDict)
		c.backupenv = c.configDict["backupenv"]
		c.prevmaskdict = CopyMapSS(clone.prevmaskdict)
		c.pprovideddict = CopyMapSS(clone.pprovideddict)
		c.features = NewFeaturesSet(c)
		c.features.features = CopyMapSB(clone.features.features)
		c.featuresOverrides = CopySliceS(clone.featuresOverrides)
		c.licenseManager = clone.licenseManager

		c.virtualsManagerObj = CopyMapSS(clone.virtualsManager)
		c.acceptProperties = CopyMapSS(clone.acceptProperties)
		c.ppropertiesdict = CopyMapSS(clone.ppropertiesdict)
		c.acceptRestrict = CopyMapSS(clone.acceptRestrict)
		c.pacceptRestrict = CopyMapSS(clone.pacceptRestrict)
		c.penvdict = CopyMapSS(clone.penvdict)
		c.pbashrcdict = CopyMapSS(clone.pbashrcdict)
		c.expandMap = CopyMapSS(clone.expandMap)
	} else {
		c.keywordsManagerObj = nil
		c.maskManagerObj = nil
		c.virtualsManagerObj = nil
		//locationsManager :=
	}
	if mycpv != "" {
		c.SetCpv(mycpv, nil, "")
	}

	return c
}

func ReverseSlice(s interface{}) {
	size := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)
	for i, j := 0, size-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}
func CopyMapSS(m map[string]string) map[string]string {
	r := map[string]string{}
	for k, v := range m {
		r[k] = v
	}
	return r
}
func CopyMapSB(m map[string]bool) map[string]bool {
	r := map[string]bool{}
	for k, v := range m {
		r[k] = v
	}
	return r
}
func CopySliceS(m []string) []string {
	r := []string{}
	for _, v := range m {
		r = append(r, v)
	}
	return r
}

type featuresSet struct {
	settings *Config
	features map[string]bool
}

func (f *featuresSet) contains(k string) bool {
	return f.features[k]
}

func (f *featuresSet) iter() []string {
	r := []string{}
	for k := range f.features {
		r = append(r, k)
	}
	return r
}

func (f *featuresSet) syncEnvVar() {
	p := f.iter()
	sort.Strings(p)
	f.settings.valueDict["FEATURES"] = strings.Join(p, " ")
}

func (f *featuresSet) add(k string) {
	f.settings.Modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, k)
	if !f.features[k] {
		f.features[k] = true
		f.syncEnvVar()
	}
}

func (f *featuresSet) update(values []string) {
	f.settings.Modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, values...)
	needSync := false
	for _, k := range values {
		if f.features[k] {
			continue
		}
		f.features[k] = true
		needSync = true
	}
	if needSync {
		f.syncEnvVar()
	}
}

func (f *featuresSet) differenceUpdate(values []string) {
	f.settings.Modifying()
	removeUs := []string{}
	for _, v := range values {
		f.settings.featuresOverrides = append(f.settings.featuresOverrides, "-"+v)
		if f.features[v] {
			removeUs = append(removeUs, v)
		}
	}
	if len(removeUs) > 0 {
		for _, k := range removeUs {
			delete(f.features, k)
		}
		f.syncEnvVar()
	}
}

func (f *featuresSet) remove(k string) {
	f.discard(k)
}

func (f *featuresSet) discard(k string) {
	f.settings.Modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, "-"+v)
	if f.features[v] {
		delete(f.features, k)
	}
	f.syncEnvVar()
}

func (f *featuresSet) validate() {
	if f.features["unknown-features-warn"] {
		unknownFeatures := []string{}
		for k := range f.features {
			if !SUPPORTED_FEATURES[k] {
				unknownFeatures = append(unknownFeatures, k)
			}
		}
		if len(unknownFeatures) > 0 {
			unknownFeatures2 := []string{}
			for _, u := range unknownFeatures {
				if !f.settings.unknownFeatures[u] {
					unknownFeatures2 = append(unknownFeatures2, u)
				}
			}
			if len(unknownFeatures2) > 0 {
				for _, u := range unknownFeatures2 {
					f.settings.unknownFeatures[u] = true
				}
				//writemsg_level(colorize("BAD",
				//	_("FEATURES variable contains unknown value(s): %s") % \
				//", ".join(sorted(unknown_features))) \
				//+ "\n", level=logging.WARNING, noiselevel=-1)
			}
		}
	}
	if f.features["unknown-features-filter"] {
		unknownFeatures := []string{}
		for k := range f.features {
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
	return &featuresSet{settings: settings, features: map[string]bool{}}
}

type locationsManager struct {
	userProfileDir, localRepoConfPath, eprefix, configRoot, targetRoot, sysroot, absUserConfig, configProfilePath, esysroot, broot, portdir, portdirOverlay string
	userConfig                                                                                                                                              bool
	overlayProfiles, profileLocations, profileAndUserLocations                                                                                                                                         []string
}

func (l *locationsManager) checkVarDirectory(varname, varr string) error {
	if !isdirRaiseEaccess(varr) {
		writeMsg(fmt.Sprintf("!!! Error: %s='%s' is not a directory. "+
			"Please correct this.\n", varname, varr), -1, nil)
		return errors.New("DirectoryNotFound") // DirectoryNotFound(var)
	}
	return nil
}
func (l *locationsManager) setRootOverride(rootOverwrite string) error {
	if l.targetRoot != "" && rootOverwrite != ""{
		l.targetRoot = rootOverwrite
		if len(strings.TrimSpace(l.targetRoot)) == 0 {
			l.targetRoot = ""
		}
	}
	if l.targetRoot == "" {
		l.targetRoot = string(os.PathSeparator)
	}
	fap, _ := filepath.Abs(l.targetRoot)
	l.targetRoot = NormalizePath(strings.TrimSuffix(fap, string(os.PathSeparator))) + string(os.PathSeparator)
	if l.sysroot != "/" && l.sysroot != l.targetRoot {
		writeMsg(fmt.Sprintf("!!! Error: SYSROOT (currently %s) must "+
		"equal / or ROOT (currently %s).\n", l.sysroot, l.targetRoot), 1, nil)
		return errors.New("InvalidLocation")// raise InvalidLocation(self.sysroot)
	}
	//ensure
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
	l.profileAndUserLocations = append(l.profileLocations[:0:0],l.profileLocations...)
	if l.userConfig {
		l.profileAndUserLocations = append(l.profileAndUserLocations, l.absUserConfig)
	}
}

func NewLocaitonsManager(configRoot, eprefix, configProfilePath string, localConfig bool, targetRoot, sysroot string) *locationsManager {
	l := &locationsManager{userProfileDir: "", localRepoConfPath: "", eprefix: eprefix, configRoot: configRoot, targetRoot: targetRoot, sysroot: sysroot, userConfig: localConfig}
	if l.eprefix != "" {
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
	fap, _ := filepath.Abs(l.configRoot)
	if fap == "" {
		l.configRoot = string(os.PathSeparator)
	} else {
		l.configRoot = NormalizePath(strings.TrimSuffix(l.configRoot, string(os.PathSeparator))) + string(os.PathSeparator)
	}
	l.checkVarDirectory("PORTAGE_CONFIGROOT", configRoot)
	l.absUserConfig = path.Join(l.configRoot, UserConfigPath)
	l.configProfilePath = configProfilePath
	if l.sysroot == "" {
		l.sysroot = "/"
	} else {
		fap, _ := filepath.Abs(l.sysroot)
		l.sysroot = NormalizePath(fap)
	}
	l.esysroot = strings.TrimSuffix(l.sysroot, string(os.PathSeparator)) + l.eprefix + string(os.PathSeparator)
	l.broot = EPREFIX
	return l
}
