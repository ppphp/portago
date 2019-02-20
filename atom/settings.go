package atom

import (
	"errors"
	"fmt"
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

type Config struct {
	tolerent                                                                                                                                                                                 bool
	locked                                                                                                                                                                                   int
	unmatchedRemoval, localConfig                                                                                                                                                            bool
	mycpv, setcpvArgsHash, puse, penv, modifiedkeys, uvlist, acceptChostRe, acceptProperties, acceptRestrict, featuresOverrides, makeDefaults, parentStable, sonameProvided, unknownFeatures *int
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
	if clone != nil {

	} else {

	}


	return &Config{tolerent: tolerant, unmatchedRemoval: unmatchedRemoval, localConfig: local_config}
}
