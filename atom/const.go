package atom

import (
	"os"
	"path"
	"strings"
)

// portage/lib/portage/const

const (
	// The variables in this file are grouped by config_root, target_root.

	// variables used with config_root (these need to be relative)
	UserConfigPath        = "etc/portage"
	MakeConfFile          = UserConfigPath + "/make.conf"
	ModulesFilePath       = UserConfigPath + "/modules"
	CustomProfilePath     = UserConfigPath + "/profile"
	UserVirtualsFile      = UserConfigPath + "/virtuals"
	EbuildShEnvFile       = UserConfigPath + "/bashrc"
	EbuildShEnvDir        = UserConfigPath + "/env"
	CustomMirrorsFile     = UserConfigPath + "/mirrors"
	ColorMapFile          = UserConfigPath + "/color.map"
	ProfilePath           = UserConfigPath + "/make.profile"
	MakeDefaultsFile      = ProfilePath + "/make.defaults" // FIXME: not used
	DeprecatedProfileFile = ProfilePath + "/deprecated"

	// variables used with targetroot (these need to be absolute, but not
	// have a leading '/' since they are used directly with os.path.join on EROOT)
	VdbPath          = "var/db/pkg"
	CachePath        = "var/cache/edb"
	PrivatePath      = "var/lib/portage"
	WorldFile        = PrivatePath + "/world"
	WorldSetsFile    = PrivatePath + "/world_sets"
	ConfigMemoryFile = PrivatePath + "/config"
	NewsLibPath      = "var/lib/gentoo"

	// these variables get EPREFIX prepended automagically when they are
	// translated into their lowercase variants
	DepcachePath     = "/var/cache/edb/dep"
	GlobalConfigPath = "/usr/share/portage/config"

	// these variables are not used with target_root or config_root
	// NOTE: Use realpath(__file__) so that python module symlinks in site-packages
	// are followed back to the real location of the whole portage installation.
	// NOTE: Please keep PORTAGE_BASE_PATH in one line to help substitutions.
	SandboxBinary  = "/usr/bin/sandbox"
	FakerootBinary = "/usr/bin/fakeroot"
	BashBinary     = "/bin/bash"
	MoveBinary     = "/bin/mv"
	PrelinkBinary  = "/usr/sbin/prelink"

	InvalidEnvFile    = "/etc/spork/is/not/valid/profile.env"
	MergingIdentifier = "-MERGING-"
	RepoNameFile      = "repo_name"
	RepoNameLoc       = "profiles" + "/" + RepoNameFile

	PortagePackageAtom   = "sys-apps/portage"
	LibcPackageAtom      = "virtual/libc"
	OsHeadersPackageAtom = "virtual/os-headers"
	CvsPackageAtom       = "dev-vcs/cvs"
	GitPackageAtom       = "dev-vcs/git"
	RsyncPackageAtom     = "net-misc/rsync"

	EAPI = 7

	HashingBlocksize = 32768

	//MANIFEST2_HASH_DEFAULTS = frozenset(["BLAKE2B", "SHA512"])
	Manifest2HashDefault = "BLAKE2B"

	// The EPREFIX for the current install is hardcoded here, but access to this
	// constant should be minimal, in favor of access via the EPREFIX setting of
	// a config instance (since it's possible to contruct a config instance with
	// a different EPREFIX). Therefore, the EPREFIX constant should *NOT* be used
	// in the definition of any other constants within this file.

	// Time formats used in various places like metadata.chk.
	TimestampFormat = "%a, %d %b %Y %H:%M:%S +0000" // to be used with time.gmtime()

	ReturncodePostinstFailure = 5

	// ===========================================================================
	// END OF CONSTANTS -- END OF CONSTANTS -- END OF CONSTANTS -- END OF CONSTANT
	// ===========================================================================

	// Private constants for use in conditional code in order to minimize the diff
	// between branches.
	depcleanLibCheckDefault = true
	enableSetConfig         = true

	EbuildDir = "./tmp"
)

var (
	tmpPORTAGE_BASE_PATH = strings.Split(path.Clean(strings.TrimSuffix(os.Args[0], "co")), string(os.PathSeparator))
	PORTAGE_BASE_PATH    = path.Join(string(os.PathSeparator), strings.Join(tmpPORTAGE_BASE_PATH[:len(tmpPORTAGE_BASE_PATH)-2], string(os.PathSeparator)))
	PORTAGE_BIN_PATH     = PORTAGE_BASE_PATH + "/bin"
	PORTAGE_PYM_PATH     = path.Clean(path.Join(os.Args[0], "../.."))
	LOCALE_DATA_PATH     = PORTAGE_BASE_PATH + "/locale"
	EBUILD_SH_BINARY     = PORTAGE_BIN_PATH + "/ebuild.sh"
	MISC_SH_BINARY       = PORTAGE_BIN_PATH + "/misc-functions.sh"

	EPREFIX = ""

	VcsDirs = map[string]bool{"CVS": true, "RCS": true, "SCCS": true, ".bzr": true, ".git": true, ".hg": true, ".svn": true}

	LIVE_ECLASSES = map[string]bool{
		"bzr": true, "cvs": true, "darcs": true, "git": true,
		"git-2": true, "git-r3": true, "golang-vcs": true, "mercurial": true,
		"subversion": true, "tla": true,
	}

	INCREMENTALS = map[string]bool{
		"ACCEPT_KEYWORDS": true, "CONFIG_PROTECT": true,
		"CONFIG_PROTECT_MASK": true, "ENV_UNSET": true, "FEATURES": true,
		"IUSE_IMPLICIT": true, "PRELINK_PATH": true, "PRELINK_PATH_MASK": true,
		"PROFILE_ONLY_VARIABLES": true, "USE": true, "USE_EXPAND": true,
		"USE_EXPAND_HIDDEN": true, "USE_EXPAND_IMPLICIT": true,
		"USE_EXPAND_UNPREFIXED": true,
	}
	EBUILD_PHASES = map[string]bool{
		"pretend": true, "setup": true, "unpack": true, "prepare": true,
		"configure": true, "compile": true, "test": true, "install": true,
		"package": true, "instprep": true, "preinst": true, "postinst": true,
		"prerm": true, "postrm": true, "nofetch": true, "config": true,
		"info": true, "other": true,
	}
	SUPPORTED_FEATURES = map[string]bool{
		"assume-digests": true, "binpkg-docompress": true,
		"binpkg-dostrip": true, "binpkg-logs": true,
		"binpkg-multi-instance": true, "buildpkg": true,
		"buildsyspkg": true, "candy": true, "case-insensitive-fs": true,
		"ccache": true, "cgroup": true, "chflags": true, "clean-logs": true,
		"collision-protect": true, "compress-build-logs": true,
		"compressdebug": true, "compress-index": true,
		"config-protect-if-modified": true, "digest": true, "distcc": true,
		"distcc-pump": true, "distlocks": true, "downgrade-backup": true,
		"ebuild-locks": true, "fail-clean": true, "fakeroot": true,
		"fixlafiles": true, "force-mirror": true, "force-prefix": true,
		"getbinpkg": true, "icecream": true, "installsources": true,
		"ipc-sandbox": true, "keeptemp": true, "keepwork": true,
		"lmirror": true, "merge-sync": true, "metadata-transfer": true,
		"mirror": true, "mount-sandbox": true, "multilib-strict": true,
		"network-sandbox": true, "network-sandbox-proxy": true, "news": true,
		"noauto": true, "noclean": true, "nodoc": true, "noinfo": true,
		"noman": true, "nostrip": true, "notitles": true,
		"parallel-fetch": true, "parallel-install": true, "pid-sandbox": true,
		"prelink-checksums": true, "preserve-libs": true,
		"protect-owned": true, "python-trace": true, "sandbox": true,
		"selinux": true, "sesandbox": true, "sfperms": true, "sign": true,
		"skiprocheck": true, "splitdebug": true, "split-elog": true,
		"split-log": true, "strict": true, "strict-keepdir": true,
		"stricter": true, "suidctl": true, "test": true,
		"test-fail-continue": true, "unknown-features-filter": true,
		"unknown-features-warn": true, "unmerge-backup": true,
		"unmerge-logs": true, "unmerge-orphans": true, "unprivileged": true,
		"userfetch": true, "userpriv": true, "usersandbox": true,
		"usersync": true, "webrsync-gpg": true, "xattr": true,
	}

	MANIFEST2_HASH_DEFAULTS = map[string]bool{"BLAKE2B": true, "SHA512": true}

	MANIFEST2_IDENTIFIERS = map[string]bool{"AUX": true, "MISC": true, "DIST": true, "EBUILD": true}

	SUPPORTED_BINPKG_FORMATS  = map[string]bool{"tar": true, "rpm": true}
	SUPPORTED_XPAK_EXTENSIONS = map[string]bool{".tbz2": true, ".xpak": true}
	PORTAGE_PYM_PACKAGES      = map[string]bool{"_emerge": true, "portage": true}
)

func init() {
	e := os.Getenv("PORTAGE_OVERRIDE_EPREFIX")
	if e != "" {
		EPREFIX = e
		EPREFIX = path.Clean(EPREFIX)
		if EPREFIX == string(os.PathSeparator) {
			EPREFIX = ""
		}
	}
}
