package atom

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/google/shlex"
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
	valueDict                                                                                                                                                                                                                              map[string]string
	tolerent, unmatchedRemoval, localConfig                                                                                                                                                                                                bool
	locked                                                                                                                                                                                                                                 int
	mycpv, setcpvArgsHash, penv, modifiedkeys, acceptChostRe, parentStable, sonameProvided                                                                                                                                         *int
	puse, depcachedir, profilePath, defaultFeaturesUse, iuseEffective, iuseImplicitMatch, userProfileDir, globalConfigPath                                                                                                                 string
	useManager                                                                                                                                                                                                                             *useManager
	keywordsManagerObj                                                                                                                                                                                                                     *keywordsManager
	maskManagerObj                                                                                                                                                                                                                         *maskManager
	virtualManagerObj                                                                                                                                                                                                                      *virtualManager
	licenseManager                                                                                                                                                                                                                         *licenseManager
	unpackDependencies                                                                                                                                                                                                                     map[string]map[string]map[string]string
	packages, usemask, useforce                                                                                                                                                                                                            map[*atom]string
	ppropertiesdict,  pacceptRestrict, penvdict                                                                                                                                                                             map[string]map[*atom][]string
	makeDefaultsUse, featuresOverrides, acceptRestrict,profiles                                                                                                                                                                                           []string
	profileBashrc                                                                                                                                                                                                                          []bool
	lookupList, configList, makeDefaults,uvlist                                                                                                                                                                                                   []map[string]string
	repoMakeDefaults, configDict                                                                                                                                                                                                           map[string]map[string]string
	backupenv, defaultGlobals, deprecatedKeys, useExpandDict, virtualsManagerObj, virtualsManager, acceptProperties, expandMap                                                                                              map[string]string
	pprovideddict map[string][]string
	pbashrcdict                                                                                                                                                                                                                            map[*profileNode]map[string]map[*atom][]string
	prevmaskdict                                                                                                                                                                                                                           map[string][]*atom
	modulePriority, incrementals, envBlacklist, environFilter, environWhitelist, validateCommands, globalOnlyVars, caseInsensitiveVars, setcpvAuxKeys, constantKeys, unknownFeatures, nonUserVariables, envDBlacklist, pbashrc, categories map[string]bool
	features                                                                                                                                                                                                                               *featuresSet
	repositories                                                                                                                                                                                                                           *repoConfigLoader
	modules                                                                                                                                                                                                                                map[string]map[string][]string
	locationsManager                                                                                                                                                                                                                       *locationsManager
	environWhitelistRe                                                                                                                                                                                                                     *regexp.Regexp
}

func (c *Config) backupChanges(key string) {
	c.modifying()
	if _, ok := c.configDict["env"][key]; key != "" && ok {
		c.backupenv[key] = c.configDict["env"][key]
	} else {
		//raise KeyError(_("No such key defined in environment: %s") % key)
	}
}

func (c *Config) regenerate(useonly int) { // 0 n
	c.modifying()
	myincrementals := map[string]bool{}
	if useonly!=0{
		myincrementals["USE"]= true
	} else {
		myincrementals = c.incrementals
	}
	delete(myincrementals, "USE")
	mydbs := append(c.configList[:0:0], c.configList...)
	mydbs = append(mydbs, c.backupenv)
	if c.localConfig{
		mySplit := []string{}
		for _, curdb :=range mydbs{
			mySplit = append(mySplit, strings.Fields(curdb["ACCEPT_LICENSE"])...)
		}
		mySplit = pruneIncremental(mySplit)
		acceptLicenseStr := strings.Join(mySplit, " ")
		if acceptLicenseStr ==""{
			acceptLicenseStr = "* -@EULA"
		}
		c.configList[len(c.configList)-1]["ACCEPT_LICENSE"] = acceptLicenseStr
		c.licenseManager.setAcceptLicenseStr(acceptLicenseStr)
	} else {
		c.licenseManager.setAcceptLicenseStr("*")
	}
	if c.localConfig{
		mySplit := []string{}
		for _, curdb :=range mydbs{
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
		incrementLists[k]=incrementList
		for _,curdb := range mydbs{
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
		for _, mySplit := range incrementList{
			for _,x := range mySplit{
				if x=="-*"{
					myFlags = map[string]bool{}
					continue
				}
				if x[0]=='+'{
					writeMsg(colorize("BAD", fmt.Sprintf("%s values should not start with a '+': %s",myKey,x)) +"\n", -1, nil)
					x=x[1:]
					if x==""{
						continue
					}
				}
				if x[0] == '-'{
					delete(myFlags, x[1:])
					continue
				}
				myFlags[x]=true
			}
		}
		if _, ok := c.valueDict[myKey];len(myFlags)>0 ||ok{
			m := []string{}
			for k := range myFlags {
				m = append(m ,k)
			}
			sort.Strings(m)
			c.configList[len(c.configList)-1][myKey] = strings.Join(m , " ")
		}
	}
	useExpand := strings.Fields(c.valueDict["USE_EXPAND"])
	useExpandDict :=  c.useExpandDict
	useExpandDict = map[string]string{}
	for _,k := range useExpand{
		if v,ok := c.valueDict[k]; ok{
			useExpandDict[k]=v
		}
	}
	useExpandUnprefixed := strings.Fields(c.valueDict["USE_EXPAND_UNPREFIXED"])
	configDictDefaults := c.configDict["defaults"]
	if c.makeDefaults != nil {
		for i, cfg := range c.makeDefaults{
			if len(cfg) ==0{
				c.makeDefaultsUse = append(c.makeDefaultsUse, "")
				continue
			}
			use := cfg["USE"]
			expandUse := []string{}
			for _, k := range useExpandUnprefixed{
				if v, ok:= cfg[k];ok {
					expandUse = append(expandUse, strings.Fields(v)...)
				}
			}
			for k := range useExpandDict{
				v, ok:= cfg[k]
				if !ok {
					continue
				}
				prefix := strings.ToLower(k)+"_"
				for _,x := range strings.Fields(v){
					if x[:1]=="-"{
						expandUse = append(expandUse,"-"+prefix+x[:1])
					} else {
						expandUse = append(expandUse, prefix+x)
					}
				}
			}
			if len(expandUse)>0 {
				expandUse = append(expandUse, use)
				use = strings.Join(expandUse, " ")
			}
			c.makeDefaultsUse = append(c.makeDefaultsUse, use)
		}
		configDictDefaults["USE"] = strings.Join(c.makeDefaultsUse, " ")
		c.makeDefaults = nil
	}
	if len(c.uvlist) == 0 {
		for _, x := range strings.Split(c.valueDict["USER_ORDER"], ":"){
			if _, ok := c.configDict[x]; ok {
				c.uvlist = append(c.uvlist, c.configDict[x])
			}
		}
		ReverseSlice(c.uvlist)
	}
	iu := c.configDict["pkg"]["IUSE"]
	iuse := []string{}
	if iu != "" {
		for _, x := range strings.Fields(iu){
			iuse = append(iuse, strings.TrimPrefix(x, "+-"))
		}
	}
	myFlags = map[string]bool{}
	for _,curdb:= range c.uvlist{
		for _, k:= range useExpandUnprefixed{
			v := curdb[k]
			if v == "" {
				continue
			}
			for _, x:=range strings.Fields(v){
				if x[:1]=="-"{
					delete(myFlags,x[1:])
				} else {
					myFlags[x]=true
				}
			}
		}
		curUseExpand := []string{}
		for _,x := range useExpand{
			if _,ok:=curdb[x];ok{
				curUseExpand = append(curUseExpand, x)
			}
		}
		mySplit := strings.Fields(curdb["USE"])
		if len(mySplit) == 0 && len(curUseExpand)==0{
			continue
		}
		for _,x :=range mySplit{
			if x=="-*"{
				myFlags = map[string]bool{}
				continue
			}
			if x[0]=='+'{
				writeMsg(colorize("BAD", fmt.Sprintf("USE flags should not start with a '+': %s\n",x)), -1, nil)
				x=x[1:]
				if x==""{
					continue
				}
			}
			if x[0]=='-'{
				if x[len(x)-2:]=="_*"{
					prefix := x[1:len(x)-1]
					prefixLen := len(prefix)
					for y := range myFlags {
						if y[:prefixLen]== prefix{
							delete(myFlags, y)
						}
					}
				}
				delete(myFlags,x[1:])
				continue
			}
			if iuse != nil && x[len(x)-2:] == "_*"{
				prefix := x[:len(x)-1]
				prefixLen := len(prefix)
				hasIuse := false
				for _,y := range iuse {
					if y[:prefixLen]==prefix{
						hasIuse=true
						myFlags[y]=true
					}
				}
				if !hasIuse{
					myFlags[x]=true
				}
			} else {
				myFlags[x]=true
			}
		}
		if reflect.ValueOf(curdb).Pointer() == reflect.ValueOf(configDictDefaults).Pointer(){
			continue
		}
		for _,varr := range curUseExpand{
			varLower:= strings.ToLower(varr)
			isNotIncremental := !myincrementals[varr]
			if isNotIncremental{
				prefix := varLower + "_"
				prefixLen := len(prefix)
				for x := range myFlags{
					if x[:prefixLen]==prefix{
						delete(myFlags,x)
					}
				}
			}
			for _, x:=range strings.Fields(curdb[varr]){
				if x[0]=='+'{
					if isNotIncremental{
						writeMsg(colorize("BAD", fmt.Sprintf("Invalid '+' operator in non-incremental variable '%s': '%s'\n",varr, x)), -1, nil)
						continue
					} else {
						writeMsg(colorize("BAD", fmt.Sprintf("Invalid '+' operator in non-incremental variable '%s': '%s'\n",varr, x)), -1, nil)
					}
					x = x[1:]
				}
				if x[0]=='-'{
					if isNotIncremental{
						writeMsg(colorize("BAD", fmt.Sprintf("Invalid '+' operator in non-incremental variable '%s': '%s'\n",varr, x)), -1, nil)
						continue
					}
					delete(myFlags, varLower + "_" + x)
					continue
				}
				myFlags[varLower + "_" + x]=true
			}
		}
	}
	if c.features!= nil {
		c.features.features = map[string]bool{}
	}else {
		c.features = NewFeaturesSet(c)
	}
	for _,x:=range strings.Fields(c.valueDict["FEATURES"]){
		c.features.features[x]=true
	}
	c.features.syncEnvVar()
	c.features.validate()
	for x := range c.useforce{
		myFlags[x.value]=true
	}
	for x:=range c.usemask{
		delete(myFlags,x.value)
	}
	m := []string{}
	for x :=range myFlags {
		m = append(m ,x)
	}
	sort.Strings(m)
	c.configList[len(c.configList)-1]["USE"] = strings.Join(m, " ")
	if c.mycpv == nil {
		for _, k := range useExpand {
			prefix := strings.ToLower(k) + "_"
			prefixLen := len(prefix)
			expandFlags := map[string]bool{}
			for x :=range myFlags{
				if x[:prefixLen]==prefix{
					expandFlags[x[prefixLen:]] = true
				}
			}
			varSplit := strings.Fields(useExpandDict[k])
			v:=[]string{}
			for _,x:=range varSplit {
				if expandFlags[x]{
					v=append(v,x)
				}
			}
			varSplit=v
			for _,v:=range varSplit{
				delete(expandFlags,v)
			}
			e:=[]string{}
			for x:= range expandFlags{
				e =append(e,x)
			}
			sort.Strings(e)
			varSplit = append(varSplit, e...)
			if len(varSplit)>0{
				c.configList[len(c.configList)-1][k]=strings.Join(varSplit, " ")
			} else if _, ok := c.valueDict[k];ok {
				c.configList[len(c.configList)-1][k]=""
			}
		}
		for _, k := range useExpandUnprefixed{
			varSplit := strings.Fields(c.valueDict[k])
			v := []string{}
			for _,x:=range varSplit{
				if myFlags[x]{
					v = append(v,x)
				}
			}
			if len(varSplit)>0{
				c.configList[len(c.configList)-1][k]=strings.Join(varSplit, " ")
			} else if _, ok := c.valueDict[k];ok {
				c.configList[len(c.configList)-1][k]=""
			}
		}

	}
}

func (c *Config) lock() {
	c.locked = 1
}

func (c *Config) unlock() {
	c.locked = 0
}

func (c *Config) modifying() error {
	if c.locked != 0 {
		return errors.New("")
	}
	return nil
}

func (c *Config) SetCpv(cpv string, myDb string) {
	c.modifying()
}

func (c *Config) isStable(pkg *pkgStr) bool {
	return c.keywordsManager().isStable(pkg, c.valueDict["ACCEPT_KEYWORDS"], c.configDict["backupenv"]["ACCEPT_KEYWORDS"])
}

func (c *Config) keywordsManager() *keywordsManager {
	if c.keywordsManagerObj == nil {
		c.keywordsManagerObj = NewKeywordsManager(c.locationsManager.profilesComplex, c.locationsManager.absUserConfig, c.localConfig, c.configDict["defaults"]["ACCEPT_KEYWORDS"])
	}
	return c.keywordsManagerObj
}

func (c *Config) grabPkgEnv(penv []string, container map[string]string, protected_keys map[string]bool) { // n
	if protected_keys == nil {
		protected_keys = map[string]bool{}
	}
	absUserConfig := path.Join(c.valueDict["PORTAGE_CONFIGROOT"], UserConfigPath)
	nonUserVariables := c.nonUserVariables
	expandMap := CopyMapSS(c.expandMap)
	incrementals := c.incrementals
	for _, envname := range penv {
		penvfile := path.Join(absUserConfig, "env", envname)
		penvconfig := getConfig(penvfile, c.tolerent, true, true, false, expandMap)
		if penvconfig == nil {
			writeMsg(fmt.Sprintf("!!! %s references non-existent file: %s\n", path.Join(absUserConfig, "package.env"), penvfile), -1, nil)
		} else {
			for k, v := range penvconfig {
				if protected_keys[k] || nonUserVariables[k] {
					writeMsg(fmt.Sprintf("!!! Illegal variable '%s' assigned in '%s'\n", k, penvfile), -1, nil)
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

var eapiCache = map[string]bool{}

func NewConfig(clone *Config, mycpv, configProfilePath string, configIncrementals []string, configRoot, targetRoot, sysroot, eprefix string, localConfig bool, env map[string]string, unmatchedRemoval bool, repositories *repoConfigLoader) *Config {
	eapiCache = make(map[string]bool)
	tolerant := initializingGlobals == nil
	c := &Config{tolerent: tolerant, unmatchedRemoval: unmatchedRemoval, localConfig: localConfig}
	c.constantKeys = constantKeys
	c.deprecatedKeys = deprecatedKeys
	c.setcpvAuxKeys = setcpvAuxKeys
	c.caseInsensitiveVars = caseInsensitiveVars
	c.defaultGlobals = defaultGlobals
	c.envBlacklist = envBlacklist
	c.environFilter = environFilter
	c.environWhitelist = environWhitelist
	c.globalOnlyVars = globalOnlyVars
	c.environWhitelistRe = environWhitelistRe

	//c.validateCommands=validateCommands

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
		c.prevmaskdict = clone.prevmaskdict // CopyMapSS(clone.prevmaskdict)
		c.pprovideddict = clone.pprovideddict//CopyMapSS()
		c.features = NewFeaturesSet(c)
		c.features.features = CopyMapSB(clone.features.features)
		c.featuresOverrides = append(clone.featuresOverrides[:0:0], clone.featuresOverrides...)
		c.licenseManager = clone.licenseManager

		c.virtualsManagerObj = CopyMapSS(clone.virtualsManager)
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
		locationsManager := NewLocaitonsManager(configRoot, eprefix, configProfilePath, localConfig, targetRoot, sysroot)
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
			if len(mygcfg) > 0 {
				for k, v := range mygcfg {
					makeConf[k] = v
					makeConfCount += 1
				}
			}
		}
		if makeConfCount == 2 {
			writeMsg(fmt.Sprintf("!!! %s\nFound 2 make.conf files, using both '%s' and '%s'", makeConfPaths), -1, nil)
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
		if s, _ := os.Stat(oldMakeGlobals); !s.IsDir() && f1 != f2 {
			writeMsg(fmt.Sprintf("!!!Found obsolete make.globals file: '%s', (using '%s' instead)\n", oldMakeGlobals, makeGlobalsPath), -1, nil)
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
		c.valueDict["PORTAGE_CONFIGROOT"] = configRoot
		c.valueDict["ROOT"] = targetRoot
		c.valueDict["SYSROOT"] = sysroot
		c.valueDict["EPREFIX"] = eprefix
		c.valueDict["EROOT"] = eroot
		c.valueDict["ESYSROOT"] = esysroot
		c.valueDict["BROOT"] = broot
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
				c.valueDict["PORTAGE_RSYNC_EXTRA_OPTS"] = confs["PORTAGE_RSYNC_EXTRA_OPTS"]
			}
		}
		c.valueDict["PORTDIR"] = portDir
		c.valueDict["PORTDIR_OVERLAY"] = portDirOverlay
		if portDirSync != "" {
			c.valueDict["SYNC"] = portDirSync
		}
		c.lookupList = []map[string]string{c.configDict["env"]}
		if repositories == nil {
			c.repositories = loadRepositoryConfig(c, "")
		}
		for _, v := range c.repositories.prepos {
			knownRepos = append(knownRepos, v.location)
		}
		kr := map[string]bool{}
		for _, v := range knownRepos {
			kr[v] = true
		}
		c.valueDict["PORTAGE_REPOSITORIES"] = c.repositories.configString()
		c.backupChanges("PORTAGE_REPOSITORIES")
		mainRepo := c.repositories.mainRepo()
		if mainRepo != nil {
			c.valueDict["PORTDIR"] = mainRepo.location
			c.backupChanges("PORTDIR")
			expandMap["PORTDIR"] = c.valueDict["PORTDIR"]
		}
		portDirOverlay1 := c.repositories.repoLocationList
		if len(portDirOverlay1) > 0 && portDirOverlay1[0] == c.valueDict["PORTDIR"] {
			portDirOverlay1 = portDirOverlay1[1:]
		}
		newOv := []string{}
		if len(portDirOverlay1) > 0 {
			for _, ov := range portDirOverlay1 {
				ov = NormalizePath(ov)
				if isdirRaiseEaccess(ov) || syncMode {
					newOv = append(newOv, ShellQuote(ov))
				} else {
					writeMsg(fmt.Sprintf("!!! Invalid PORTDIR_OVERLAY(not a dir): '%s'\n", ov), -1, nil)
				}
			}
		}
		c.valueDict["PORTDIR_OVERLAY"] = strings.Join(newOv, " ")
		c.backupChanges("PORTDIR_OVERLAY")
		expandMap["PORTDIR_OVERLAY"] = c.valueDict["PORTDIR_OVERLAY"]
		locationsManager.setPortDirs(c.valueDict["PORTDIR"], c.valueDict["PORTDIR_OVERLAY"])
		locationsManager.loadProfiles(c.repositories, knownRepos)
		profilesComplex := locationsManager.profilesComplex
		c.profiles = locationsManager.profiles
		c.profilePath = locationsManager.profilePath
		c.userProfileDir = locationsManager.userProfileDir
		packageList := [][][2]string{}
		for _, x := range profilesComplex {
			packageList = append(packageList, grabFilePackage(path.Join(x.location, "packages"), 0, 0, false, false, x.allowBuildId, false, true, x.eapi, ""))
		}
		c.packages = stackLists(packageList, 1, false, false, false, false)
		c.prevmaskdict = map[string][]*atom{}
		for x := range c.packages {
			if c.prevmaskdict[x.cp] == nil {
				c.prevmaskdict[x.cp] = []*atom{x}
			} else {
				c.prevmaskdict[x.cp] = append(c.prevmaskdict[x.cp], x)
			}
		}
		c.unpackDependencies = loadUnpackDependenciesConfiguration(c.repositories)
		mygcfg := map[string]string{}
		if len(profilesComplex) != 0 {
			mygcfgDlists := []map[string]string{}
			for _, x := range profilesComplex {
				mygcfgDlists = append(mygcfgDlists, getConfig(path.Join(x.location, "make.defaults"), tolerant, false, true, x.portage1Directories, expandMap))
			}
			c.makeDefaults = mygcfgDlists
			mygcfg = stackDicts(mygcfgDlists, 0, c.incrementals, 0)
			if len(mygcfg) == 0 {
				mygcfg = map[string]string{}
			}
		}
		c.configList = append(c.configList, mygcfg)
		c.configDict["defaults"] = c.configList[len(c.configList)-1]
		mygcfg = map[string]string{}
		for _, x := range makeConfPaths {
			for k, v := range getConfig(x, tolerant, true, true, true, expandMap) {
				mygcfg[k] = v
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
			delete(mygcfg, k.value)
		}
		c.configList = append(c.configList, mygcfg)
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
		c.valueDict["PORTAGE_CONFIGROOT"] = configRoot
		c.backupChanges("PORTAGE_CONFIGROOT")
		c.valueDict["ROOT"] = targetRoot
		c.backupChanges("ROOT")
		c.valueDict["SYSROOT"] = sysroot
		c.backupChanges("SYSROOT")
		c.valueDict["EPREFIX"] = eprefix
		c.backupChanges("EPREFIX")
		c.valueDict["EROOT"] = eroot
		c.backupChanges("EROOT")
		c.valueDict["ESYSROOT"] = esysroot
		c.backupChanges("ESYSROOT")
		c.valueDict["BROOT"] = broot
		c.backupChanges("BROOT")
		c.valueDict["PORTAGE_OVERRIDE_EPREFIX"] = EPREFIX
		c.backupChanges("PORTAGE_OVERRIDE_EPREFIX")

		c.ppropertiesdict = map[string]map[*atom][]string{}
		c.pacceptRestrict = map[string]map[*atom][]string{}
		c.penvdict = map[string]map[*atom][]string{}
		c.pbashrcdict = map[*profileNode]map[string]map[*atom][]string{}
		c.pbashrc = map[string]bool{}
		c.repoMakeDefaults = map[string]map[string]string{}

		for _, repo := range c.repositories.reposWithProfiles() {
			d := getConfig(path.Join(repo.location, "profiles", "make.defaults"), tolerant, false, true, repo.portage1Profiles, CopyMapSS(c.configDict["globals"]))
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
			c.repoMakeDefaults[repo.name] = d
		}
		c.useManager = NewUserManager(c.repositories, profilesComplex, absUserConfig, c.isStable, localConfig)
		c.usemask = c.useManager.getUseMask(nil, nil)
		c.useforce = c.useManager.getUseForce(nil, nil)
		c.configDict["conf"]["USE"] = c.useManager.extract_global_USE_changes(c.configDict["conf"]["USE"])
		c.licenseManager = NewLicenseManager(locationsManager.profileLocations, absUserConfig, localConfig)
		c.configDict["conf"]["ACCEPT_LICENSE"] = c.licenseManager.extractGlobalChanges(c.configDict["conf"]["ACCEPT_LICENSE"])

		for _, profile := range profilesComplex {
			s, err := os.Stat(path.Join(profile.location, "profile.bashrc"))
			c.profileBashrc = append(c.profileBashrc, err != nil && !s.IsDir())
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
					c.ppropertiesdict[k.cp] = map[*atom][]string{k: v}
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
					c.pacceptRestrict[k.cp] = map[*atom][]string{k: v}
				} else {
					c.pacceptRestrict[k.cp][k] = v
				}
			}
			penvdict := grabDictPackage(path.Join(absUserConfig, "package.env"), false, true, false, true, true, true, false, false, "", "0")
			v = nil
			for a, x := range penvdict {
				if a.value == "*/*" {
					v = x
				}
				delete(penvdict, a)
			}
			if v != nil {
				globalWildcardConf := map[string]string{}
				c.grabPkgEnv(v, globalWildcardConf, nil)
				incrementals := c.incrementals
				confConfigdict := c.configDict["conf"]
				for k, v := range globalWildcardConf {
					if incrementals[k] {
						if _, ok := confConfigdict[k]; ok {
							confConfigdict[k] = confConfigdict[k] + v
						} else {
							confConfigdict[k] = v
						}
					} else {
						confConfigdict[k] = v
					}
					expandMap[k] = v
				}
			}
			for k, v := range penvdict {
				if _, ok := c.penvdict[k.cp]; !ok {
					c.penvdict[k.cp] = map[*atom][]string{k: v}
				} else {
					c.penvdict[k.cp][k] = v
				}
			}
			for _, profile := range profilesComplex {
				in := false
				for _, v := range profile.profileFormats {
					if v == "profile-bashrcs" {
						in = true
						break
					}
				}
				if !in {
					continue
				}
				c.pbashrcdict[profile] = map[string]map[*atom][]string{}

				bashrc := grabDictPackage(path.Join(profile.location, "package.bashrc"), false, true, false, true, true, profile.allowBuildId, false, true, profile.eapi, "")
				if len(bashrc) == 0 {
					continue
				}
				for k, v := range bashrc {
					envfiles := []string{}
					for _, envname := range v {
						envfiles = append(envfiles, path.Join(profile.location, "bashrc", envname))
					}
					if _, ok := c.pbashrcdict[profile][k.cp]; !ok {
						c.pbashrcdict[profile][k.cp] = map[*atom][]string{k: v}
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
		for _,x :=range locationsManager.profileAndUserLocations {
			al = append(al, grabFile(path.Join(x, "arch.list"), 0, false, false))
		}
		archList := stackLists(al, 1, false, false, false, false)
		als := []string{}
		for a :=range  archList{
			als = append(als, a.value)
		}
		sort.Strings(als)
		c.configDict["conf"]["PORTAGE_ARCHLIST"]=strings.Join(als, " ")

		ppl := [][][2]string{}
		for _, x := range profilesComplex{
			provPath := path.Join(x.location, "package.provided")
			if _,err:=os.Stat(provPath);err==nil{
				if getEapiAttrs(x.eapi).allowsPackageProvided{
					ppl = append(ppl, grabFile(provPath, 1, x.portage1Directories, false))
				}
			}
		}
		ppls :=stackLists(ppl, 1,false, false, false, false)
		pkgProvidedLines := []string{}
		for a := range ppls{
			pkgProvidedLines = append(pkgProvidedLines, a.value)
		}
		hasInvalidData :=false
		for x :=len(pkgProvidedLines)-1;x> -1;x--{
			myline := pkgProvidedLines[x]
			if !isValidAtom("=" + myline, false, false, false, "", false){
				writeMsg(fmt.Sprintf("Invalid package name in package.provided: %s\n",myline), -1, nil)
				hasInvalidData = true
				p := []string{}
				for k,v := range pkgProvidedLines{
					if x!= k {
						p = append(p, v)
					}
				}
				pkgProvidedLines = p
				continue
			}
			cpvr := catPkgSplit(pkgProvidedLines[x], 1, "")
			if cpvr==[4]string{} || cpvr[0] == "null"{
				writeMsg("Invalid package name in package.provided: "+pkgProvidedLines[x]+"\n",-1,nil)
				hasInvalidData = true
				p := []string{}
				for k,v := range pkgProvidedLines{
					if x!= k {
						p = append(p, v)
					}
				}
				pkgProvidedLines = p
				continue
			}
		}
		if hasInvalidData{
			writeMsg("See portage(5) for correct package.provided usage.\n", -1,nil)
		}
		c.pprovideddict = map[string][]string{}
		for _, x:=range pkgProvidedLines{
			x_split := catPkgSplit(x, 1, "")
			if x_split ==[4]string{}{
				continue
			}
			mycatpkg := cpvGetKey(x, "")
			if _, ok := c.pprovideddict[mycatpkg]; ok {
				c.pprovideddict[mycatpkg]=append(c.pprovideddict[mycatpkg],x)
			} else{
				c.pprovideddict[mycatpkg]=[]string{x}
			}
		}

		if _, ok := c.valueDict["USE_ORDER"]; !ok{
			c.valueDict["USE_ORDER"] = "env:pkg:conf:defaults:pkginternal:features:repo:env.d"
			c.backupChanges("USE_ORDER")
		}
		_, ok1 := c.valueDict["CBUILD"]
		_, ok2 := c.valueDict["CHOST"]
		if !ok1 && ok2{
			c.valueDict["CBUILD"] = c.valueDict["CHOST"]
			c.backupChanges("CBUILD")
		}

		if _, ok := c.valueDict["USERLAND"]; !ok{
			system := runtime.GOOS
			if system != "" &&(strings.HasSuffix(system, "BSD")||system=="DragonFly"){
				c.valueDict["USERLAND"] = "BSD"
			} else{
				c.valueDict["USERLAND"] = "GNU"
			}
			c.backupChanges("USERLAND")
		}

		defaultInstIds := map[string]string{"PORTAGE_INST_GID": "0", "PORTAGE_INST_UID": "0",}

		erootOrParent := firstExisting(eroot)
		unprivileged := false

		if erootSt, err := os.Stat(erootOrParent);err == nil{
			if unprivilegedMode(erootOrParent, erootSt){
				unprivileged = true
			}

			defaultInstIds["PORTAGE_INST_GID"] = fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Gid)
			defaultInstIds["PORTAGE_INST_UID"] = fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Uid)

			if _, ok := c.valueDict["PORTAGE_USERNAME"];!ok {
				if pwdStruct, err := user.LookupId(fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Uid)); err != nil{
				} else {
					c.valueDict["PORTAGE_USERNAME"] = pwdStruct.Name
					c.backupChanges("PORTAGE_USERNAME")
				}
			}

			if _, ok := c.valueDict["PORTAGE_GRPNAME"];!ok {
				if grpStruct, err := user.LookupGroupId(fmt.Sprintf("%v", erootSt.Sys().(*syscall.Stat_t).Gid)); err != nil{
				} else {
					c.valueDict["PORTAGE_GRPNAME"] = grpStruct.Name
					c.backupChanges("PORTAGE_GRPNAME")
				}
			}
		}

		for varr, defaultVal := range defaultInstIds {
			v, ok := c.valueDict[varr]
			if !ok {
				v = defaultVal
			}
			if _, err := strconv.Atoi(v); err != nil{
				writeMsg(fmt.Sprintf("!!! %s='%s' is not a valid integer. Falling back to %s.\n",varr, c.valueDict[varr], defaultVal), -1, nil)
			} else {
				c.valueDict[varr] = v
			}
			c.backupChanges(varr)
		}

		c.depcachedir = c.valueDict["PORTAGE_DEPCACHEDIR"]
		if c.depcachedir ==""{
			c.depcachedir = path.Join(string(os.PathSeparator), EPREFIX, strings.TrimPrefix(DepcachePath,string(os.PathSeparator)))
			if unprivileged && targetRoot != string(os.PathSeparator){
				if s, err := os.Stat(firstExisting(c.depcachedir)); err!= nil &&s.Mode()&2!=0{
					c.depcachedir = path.Join(eroot, strings.TrimPrefix(DepcachePath,string(os.PathSeparator)))
				}
			}
		}

		c.valueDict["PORTAGE_DEPCACHEDIR"] = c.depcachedir
		c.backupChanges("PORTAGE_DEPCACHEDIR")

		if internalCaller{
			c.valueDict["PORTAGE_INTERNAL_CALLER"] = "1"
			c.backupChanges("PORTAGE_INTERNAL_CALLER")
		}

		c.regenerate(0)
		featureUse := []string{}
		if !c.features.features["test"]{
			featureUse = append(featureUse, "test")
		}
		c.defaultFeaturesUse = strings.Join(featureUse," ")
		c.configDict["features"]["USE"] = c.defaultFeaturesUse
		if len(featureUse)>0{
			c.regenerate(0)
		}
		if unprivileged{
			c.features.features["unprivileged"]=true
		}

		if runtime.GOOS=="FreeBSD"{
			c.features.features["chflags"]=true
		}
		c._init_iuse()

		c._validate_commands()

		for k :=range c.caseInsensitiveVars{
			if _, ok := c.valueDict[k];ok{
				c.valueDict[k] = strings.ToLower(c.valueDict[k])
				c.backupChanges(k)
			}
		}
		portage.output._init(config_root=self['PORTAGE_CONFIGROOT'])
		portage.data._init(self)
	}
	if mycpv != "" {
		c.SetCpv(mycpv, "")
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

func CopyMSMASS(m map[string]map[*atom][]string) map[string]map[*atom][]string {
	r := map[string]map[*atom][]string{}
	for k, v := range m {
		r[k] = v
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
	f.settings.modifying()
	f.settings.featuresOverrides = append(f.settings.featuresOverrides, k)
	if !f.features[k] {
		f.features[k] = true
		f.syncEnvVar()
	}
}

func (f *featuresSet) update(values []string) {
	f.settings.modifying()
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
	f.settings.modifying()
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
	f.settings.modifying()
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
				writeMsg(fmt.Sprintf("!!! %s\nFound 2 make.profile dirs: using '%s', ignoring '%s'", l.profilePath, deprecatedProfilePath), -1, nil)
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
		writeMsg(fmt.Sprintf("!!! Error: %s='%s' is not a directory. "+
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
			if s.IsDir() {
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
	in := false
	for _, x := range currentFormats {
		if x == "build-id" {
			in = true
			break
		}
	}
	l.profilesComplex = append(l.profilesComplex, &profileNode{location: currentPath, portage1Directories: allowDirectories, userConfig: false, profileFormats: currentFormats, eapi: eapi, allowBuildId: in})
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
	l.targetRoot = NormalizePath(strings.TrimSuffix(fap, string(os.PathSeparator))) + string(os.PathSeparator)
	if l.sysroot != "/" && l.sysroot != l.targetRoot {
		writeMsg(fmt.Sprintf("!!! Error: SYSROOT (currently %s) must "+
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

type useManager struct {
	userConfig                                                                                         bool
	isStable                                                                                           func(*pkgStr) bool
	repoUsemaskDict, repoUsestablemaskDict, repoUseforceDict, repoUsestableforceDict                   map[string][]string
	repoPusemaskDict, repoPusestablemaskDict, repoPuseforceDict, repoPusestableforceDict, repoPuseDict map[string]map[string]map[*atom][]string
	usemaskList, usestablemaskList, useforceList, usestableforceList                                   [][]string
	pusemaskList, pusestablemaskList, pkgprofileuse, puseforceList, pusestableforceList                []map[string]map[*atom][]string
	pUseDict                                                                                           map[string]map[*atom][]string // extatom
	repoUsealiasesDict                                                                                 map[string]map[string][]string
	repoPusealiasesDict                                                                                map[string]map[string]map[*atom]map[string][]string
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
			writeMsg(fmt.Sprintf("--- EAPI '%s' does not support '%s': '%s'\n", eapi, path.Base(fileName), fileName), -1, nil)
		}
		return ret
	}
	useFlagRe := getUseflagRe(eapi)
	for _, v := range lines {
		prefixedUseflag := v[0]
		useflag := ""
		if prefixedUseflag[:1] == "-" {
			useflag = prefixedUseflag[:1]
		} else {
			useflag = prefixedUseflag
		}
		if !useFlagRe.MatchString(useflag) {
			writeMsg(fmt.Sprintf("--- Invalid USE flag in '%s': '%s'\n", fileName, prefixedUseflag), -1, nil)
		} else {
			ret = append(ret, prefixedUseflag)
		}
	}

	return ret
}

func (u *useManager) parseFileToDict(fileName string, justStrings, recursive bool, eapiFilter func(string) bool, userConfig bool, eapi, eapiDefault string, allowBuildId bool) map[string]map[*atom][]string { //ftnfn"0"f
	ret := map[string]map[*atom][]string{}
	locationDict := map[*atom][]string{}
	if eapi == "" {
		eapi = readCorrespondingEapiFile(fileName, eapiDefault)
	}
	extendedSyntax := eapi == "" && userConfig
	if extendedSyntax {
		ret = map[string]map[*atom][]string{}
	} else {
		ret = map[string]map[*atom][]string{}
	}
	fileDict := grabDictPackage(fileName, false, recursive, false, extendedSyntax, extendedSyntax, !extendedSyntax, allowBuildId, false, eapi, eapiDefault)
	if eapi != "" && eapiFilter != nil && !eapiFilter(eapi) {
		if len(fileDict) > 0 {
			writeMsg(fmt.Sprintf("--- EAPI '%s' does not support '%s': '%s'\n", eapi, path.Base(fileName), fileName), -1, nil)
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
				writeMsg(fmt.Sprintf("--- Invalid USE flag for '%v' in '%s': '%s'\n", k, fileName, prefixedUseFlag), -1, nil)
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
			ret[k.cp] = map[*atom][]string{k: s}
		} else {
			ret[k.cp][k] = v
		}
	}
	return ret
}

func (u *useManager) parseUserFilesToExtatomdict(fileName, location string, userConfig bool) map[string]map[*atom][]string {
	ret := map[string]map[*atom][]string{}
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
				ret[k.cp] = map[*atom][]string{k: l}
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
		ret[repo.name] = u.parseFileToTuple(path.Join(repo.location, "profiles", fileName), true, eapiFilter, "", repo.eapi)
	}
	return ret
}

func (u *useManager) parseRepositoryFilesToDictOfDicts(fileName string, repositories *repoConfigLoader, eapiFilter func(string) bool) map[string]map[string]map[*atom][]string {
	ret := map[string]map[string]map[*atom][]string{}
	for _, repo := range repositories.reposWithProfiles() {
		in := false
		for _, v := range repo.profileFormats {
			if v == "build-id" {
				in = true
				break
			}
		}
		ret[repo.name] = u.parseFileToDict(path.Join(repo.location, "profiles", fileName), false, true, eapiFilter, false, "0", repo.eapi, in)
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

func (u *useManager) parseProfileFilesToTupleOfDicts(fileName string, locations []*profileNode, justStrings bool, eapiFilter func(string) bool) []map[string]map[*atom][]string { // fn
	ret := []map[string]map[*atom][]string{}
	for _, profile := range locations {
		ret = append(ret, u.parseFileToDict(path.Join(profile.location, fileName), justStrings, profile.portage1Directories, eapiFilter, profile.userConfig, profile.eapi, "", profile.allowBuildId))
	}
	return ret
}

func (u *useManager) parseRepositoryUsealiases(repositorires *repoConfigLoader) map[string]map[string][]string {
	ret := map[string]map[string][]string{}
	for _, repo := range repositorires.reposWithProfiles() {
		fileName := path.Join(repo.location, "profiles", "use.aliases")
		eapi := readCorrespondingEapiFile(fileName, repo.eapi)
		useFlagRe := getUseflagRe(eapi)
		rawFileDict := grabDict(fileName, false, false, true, false, false)
		fileDict := map[string][]string{}
		for realFlag, aliases := range rawFileDict {
			if !useFlagRe.MatchString(realFlag) {
				writeMsg(fmt.Sprintf("--- Invalid real USE flag in '%s': '%s'\n", fileName, realFlag), -1, nil)
			} else {
				for _, alias := range aliases {
					if !useFlagRe.MatchString(alias) {
						writeMsg(fmt.Sprintf("--- Invalid USE flag alias for '%s' real USE flag in '%s': '%s'\n", realFlag, fileName, alias), -1, nil)
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
							writeMsg(fmt.Sprintf("--- Duplicated USE flag alias in '%s': '%s'\n", fileName, alias), -1, nil)
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
		ret[repo.name] = fileDict
	}

	return ret
}

func (u *useManager) parseRepositoryPackageusealiases(repositorires *repoConfigLoader) map[string]map[string]map[*atom]map[string][]string {
	ret := map[string]map[string]map[*atom]map[string][]string{}
	for _, repo := range repositorires.reposWithProfiles() {
		fileName := path.Join(repo.location, "profiles", "package.use.aliases")
		eapi := readCorrespondingEapiFile(fileName, repo.eapi)
		useFlagRe := getUseflagRe(eapi)
		lines := grabFile(fileName, 0, true, false)
		fileDict := map[string]map[*atom]map[string][]string{}
		for _, line := range lines {
			elements := strings.Fields(line[0])
			atom1, err := NewAtom(elements[0], nil, false, nil, nil, eapi, nil, nil)
			if err != nil {
				writeMsg(fmt.Sprintf("--- Invalid atom1 in '%s': '%s'\n", fileName, atom1), 0, nil)
				continue
			}
			if len(elements) == 1 {
				writeMsg(fmt.Sprintf("--- Missing real USE flag for '%s' in '%s'\n", fileName, atom1), -1, nil)
				continue
			}
			realFlag := elements[1]
			if !useFlagRe.MatchString(realFlag) {
				writeMsg(fmt.Sprintf("--- Invalid real USE flag in '%s': '%s'\n", fileName, realFlag), -1, nil)
			} else {
				for _, alias := range elements[2:] {
					if !useFlagRe.MatchString(alias) {
						writeMsg(fmt.Sprintf("--- Invalid USE flag alias for '%s' real USE flag in '%s': '%s'\n", realFlag, fileName, alias), -1, nil)
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
							writeMsg(fmt.Sprintf("--- Duplicated USE flag alias in '%s': '%s'\n", fileName, alias), -1, nil)
						} else {
							if _, ok := fileDict[atom1.cp]; !ok {
								fileDict[atom1.cp] = map[*atom]map[string][]string{atom1: {realFlag: {alias}}}
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
		ret[repo.name] = fileDict
	}
	return ret
}

func (u *useManager) _isStable(pkg *pkgStr) bool {
	if u.userConfig {
		return pkg.stable()
	}
	if pkg.metadata == nil {
		return false
	}
	return u.isStable(pkg)
}

func (u *useManager) getUseMask(pkg *pkgStr, stable *bool) map[*atom]string { //nn
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

func (u *useManager) getUseForce(pkg *pkgStr, stable *bool) map[*atom]string { //n

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

func (u *useManager) getUseAliases(pkg *pkgStr) {}

func (u *useManager) getPUSE(pkg *pkgStr) {}

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

func NewUserManager(repositories *repoConfigLoader, profiles []*profileNode, absUserConfig string, isStable func(*pkgStr) bool, userConfig bool) *useManager { // t
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
}

func NewMaskManager() *maskManager {
	m := &maskManager{}
	return m
}

type keywordsManager struct {
	pkeywordsList, pAcceptKeywords []map[string]map[*atom][]string
	pkeywordsDict                  map[string]map[*atom][]string
}

func (k *keywordsManager) getKeywords(cpv *pkgStr, slot, keywords, repo string) map[*atom]string {
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

func (k *keywordsManager) isStable(pkg *pkgStr, globalAcceptKeywords, backupedAcceptKeywords string) bool {
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
	unstable := map[*atom]string{}
	for _, kw := range myGroups {
		if kw[:1] != "~" {
			kw = "~" + kw
		}
		unstable[&atom{value: kw}] = ""
	}
	return len(k._getMissingKeywords(pkg, pgroups, unstable)) > 0
}

func (k *keywordsManager) GetMissingKeywords(cpv *pkgStr, slot, keywords, repo, globalAcceptKeywords, backupedAcceptKeywords string) map[*atom]string {
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

func (k *keywordsManager) getRawMissingKeywords(cpv *pkgStr, slot, keywords, repo, globalAcceptKeywords string) map[*atom]string {
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

func (k *keywordsManager) _getMissingKeywords(cpv *pkgStr, pgroups map[string]bool, mygroups map[*atom]string) map[*atom]string {
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
		return map[*atom]string{}
	} else {
		if len(mygroups) == 0 {
			mygroups = map[*atom]string{{value: "**"}: ""}
		}
		return mygroups
	}
}

func (k *keywordsManager) getPKeywords(cpv *pkgStr, slot, repo, globalAcceptKeywords string) []string {
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
	k.pkeywordsList = []map[string]map[*atom][]string{}
	rawPkeywords := []map[*atom][]string{}
	for _, x := range profiles {
		rawPkeywords = append(rawPkeywords, grabDictPackage(path.Join(x.location, "package.keywords"), false, x.portage1Directories, false, false, false, x.allowBuildId, false, true, x.eapi, ""))
	}
	for _, pkeyworddict := range rawPkeywords {
		if len(pkeyworddict) == 0 {
			continue
		}
		cpdict := map[string]map[*atom][]string{}
		for k, v := range pkeyworddict {
			if _, ok := cpdict[k.cp]; !ok {
				cpdict[k.cp] = map[*atom][]string{k: v}
			} else {
				cpdict[k.cp][k] = v
			}
		}
		k.pkeywordsList = append(k.pkeywordsList, cpdict)
	}
	k.pAcceptKeywords = []map[string]map[*atom][]string{}
	rawPAcceptKeywords := []map[*atom][]string{}
	for _, x := range profiles {
		rawPAcceptKeywords = append(rawPAcceptKeywords, grabDictPackage(path.Join(x.location, "package.accept_keywords"), false, x.portage1Directories, false, false, false, false, false, true, x.eapi, ""))
	}
	for _, d := range rawPAcceptKeywords {
		if len(d) == 0 {
			continue
		}
		cpdict := map[string]map[*atom][]string{}
		for k, v := range d {
			if _, ok := cpdict[k.cp]; !ok {
				cpdict[k.cp] = map[*atom][]string{k: v}
			} else {
				cpdict[k.cp][k] = v
			}
		}
		k.pAcceptKeywords = append(k.pAcceptKeywords, cpdict)
	}

	k.pkeywordsDict = map[string]map[*atom][]string{}
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
				k.pkeywordsDict[k1.cp] = map[*atom][]string{k1: v}
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
	_plicensedict    map[string]map[*atom][]string
	undefLicGroups   map[string]bool
	licenseGroups    map[string]map[string]bool
}

func (l *licenseManager) readUserConfig(absUserConfig string) {
	licDictt := grabDictPackage(path.Join(absUserConfig, "package.license"), false, true, false, true, true, false, false, false, "", "")
	for k, v := range licDictt {
		if _, ok := l._plicensedict[k.cp]; !ok {
			l._plicensedict[k.cp] = map[*atom][]string{k: v}
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
		writeMsg(fmt.Sprintf("Circular license group reference detected in '%s'\n", groupName), -1, nil)
		rValue = append(rValue, "@"+groupName)
	} else if len(licenseGroup) > 0 {
		traversedGroups[groupName] = true
		for li := range licenseGroup {
			if strings.HasPrefix(li, "-") {
				writeMsg(fmt.Sprintf("Skipping invalid element %s in license group '%s'\n", li, groupName), -1, nil)
			} else {
				rValue = append(rValue, l._expandLicenseToken(li, traversedGroups)...)
			}
		}
	} else {
		if len(l.licenseGroups) > 0 && !l.undefLicGroups[groupName] {
			l.undefLicGroups[groupName] = true
			writeMsg(fmt.Sprintf("Undefined license group '%s'\n", groupName), -1, nil)
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

func (l *licenseManager) _getPkgAcceptLicense(cpv *pkgStr, slot, repo string) []string {
	acceptLicense := l.acceptLicense
	cp := cpvGetKey(cpv.string, "")
	cpdict := l._plicensedict[cp]
	if len(cpdict) > 0 {
		if cpv.slot == "" {
			cpv = NewPkgStr(cpv.string, nil, nil, "", repo, slot, "", "", "", 0, "")
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

func (l *licenseManager) getPrunnedAcceptLicense(cpv *pkgStr, use map[string]bool, lic, slot, repo string) string {
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

func (l *licenseManager) getMissingLicenses(cpv *pkgStr, use, lic, slot, repo string) []string {
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
	l._plicensedict = map[string]map[*atom][]string{}
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
	_dirVirtuals, _virtuals, _treeVirtuals, _depgraphVirtuals map[string][]string
}

func (v *virtualManager) read_dirVirtuals( profiles []string){
	virtualsList := []map[string][]string{}
	for _, x :=range profiles{
		virtualsFile := path.Join(x, "virtuals")
		virtualsDict := grabDict(virtualsFile,false, false, false,false, false)
		atomsDict := map[string][]string{}
		for k, v := range virtualsDict {
			virtAtom, err := NewAtom(k, nil, false, nil, nil, "", nil, nil)
			if err!=nil{
				virtAtom = nil
			} else{
				if virtAtom.blocker!=nil || virtAtom.value != virtAtom.cp{
					virtAtom = nil
				}
			}
			if virtAtom ==nil{
				writeMsg(fmt.Sprintf("--- Invalid virtuals atom in %s: %s\n", virtualsFile, k), -1, nil)
				continue
			}
			providers := []string{}
			for _, atom := range v{
				atomOrig := atom
				if atom[:1] == "-"{
					atom = atom[1:]
				}
				atomA, err := NewAtom(atom, nil, false, nil, nil, "", nil, nil)
				if err!=nil{
					atomA=nil
				} else{
					if atomA.blocker!=nil{
						atomA=nil
					}
				}
				if atomA==nil{
					writeMsg(fmt.Sprintf("--- Invalid atom in %s: %s\n", virtualsFile, atomOrig),-1,nil)
				} else{
					if atomOrig == atomA.value{
						providers=append(providers, atom)
					} else{
						providers=append(providers, atomOrig)
					}
				}
			}
			if len(providers)>0{
				atomsDict[virtAtom.value] = providers
			}
		}
		if len(atomsDict)>0{
			virtualsList =append(virtualsList, atomsDict)
		}
	}

	v._dirVirtuals = stackDictlist(virtualsList, 1, nil, 0)

	for virt :=range v._dirVirtuals{
		ReverseSlice(v._dirVirtuals[virt])
	}
}

func (v *virtualManager) _compile_virtuals(){
		ptVirtuals   := map[string][]string{}

	for virt, installedList := range v._treeVirtuals{
		profileList := v._dirVirtuals[virt]
		if len(profileList)==0{
			continue
		}
		for _,cp :=range installedList {
			in :=false
			for _, x:=range profileList {
				if x==cp {
					in=true
					break
				}
			}
			if in{
				if _, ok:= ptVirtuals[virt];!ok{
					ptVirtuals[virt] = []string{cp}
				} else{
					ptVirtuals[virt] = append(ptVirtuals[virt], cp)
				}
			}
		}
	}

	virtuals := stackDictlist([]map[string][]string{ptVirtuals, v._treeVirtuals, v._dirVirtuals, v._depgraphVirtuals}, 0, nil, 0)
	v._virtuals = virtuals
	v._virts_p = None
}

func (v *virtualManager)getvirtuals()map[string][]string{
	if v._treeVirtuals!=nil{
		panic("_populate_treeVirtuals() must be called before any query about virtuals")
	}
	if v._virtuals==nil{
		v._compile_virtuals()
	}
	return v._virtuals
}

func NewVirtualManager() *virtualManager {
	v := &virtualManager{}
	return v
}

func loadUnpackDependenciesConfiguration(repositories *repoConfigLoader) map[string]map[string]map[string]string {
	repoDict := map[string]map[string]map[string]string{}
	for _, repo := range repositories.reposWithProfiles() {
		for eapi := range supportedEapis {
			if eapiHasAutomaticUnpackDependencies(eapi) {
				fileName := path.Join(repo.location, "profiles", "unpack_dependencies", eapi)
				lines := grabFile(fileName, 0, true, false)
				for _, line := range lines {
					elements := strings.Fields(line[0])
					suffix := strings.ToLower(elements[0])
					if len(elements) == 1 {
						writeMsg(fmt.Sprintf("--- Missing unpack dependencies for '%s' suffix in '%s'\n", suffix, fileName), 0, nil)
					}
					depend := strings.Join(elements[1:], " ")
					useReduce(depend, map[string]bool{}, []string{}, false, []string{}, false, eapi, false, false, nil, nil, false)
					if repoDict[repo.name] == nil {
						repoDict[repo.name] = map[string]map[string]string{eapi: {suffix: depend}}
					} else if repoDict[repo.name][eapi] == nil {
						repoDict[repo.name][eapi] = map[string]string{suffix: depend}
					} else {
						repoDict[repo.name][eapi][suffix] = depend
					}
				}
			}
		}
	}
	ret := map[string]map[string]map[string]string{}
	for _, repo := range repositories.reposWithProfiles() {
		names := []string{}
		for _, v := range repo.mastersRepo {
			names = append(names, v.name)
		}
		names = append(names, repo.name)
		for _, repoName := range names {
			for eapi := range repoDict[repoName] {
				if repoDict[repoName] != nil {
					for suffix, depend := range repoDict[repoName][eapi] {
						if ret[repo.name] == nil {
							ret[repo.name] = map[string]map[string]string{eapi: {suffix: depend}}
						} else if repoDict[repo.name][eapi] == nil {
							ret[repo.name][eapi] = map[string]string{suffix: depend}
						} else {
							ret[repo.name][eapi][suffix] = depend
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

func orderedByAtomSpecificity(cpdict map[*atom][]string, pkg *pkgStr, repo string) [][]string {
	if pkg.repo == "" && repo != "" && repo != unknownRepo {
		//pkg = pkg +repoSeparator+repo
	}
	results := [][]string{}
	keys := map[*atom][]string{}
	for k, v := range cpdict {
		keys[k] = v
	}
	for len(keys) > 0 {
		bestMatch := bestMatchToList(pkg, keys)
		if bestMatch != nil {
			delete(keys, bestMatch)
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

func pruneIncremental(split []string)[]string{
	ReverseSlice(split)
	for i ,x := range split {
		if x == "*"{
			split = split[-i-1:]
			break
		} else if x == "-*"{
			if i==0{
				split = []string{}
			} else {
				split = split[-i:]
			}
			break
		}
	}
	return split
}
