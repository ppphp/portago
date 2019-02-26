package atom

import (
	"bufio"
	"golang.org/x/sys/unix"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	repoNameSubRe = regexp.MustCompile(`[^\w-]`)
)

func genValidRepo(name string) string {
	name = repoNameSubRe.ReplaceAllString(strings.TrimSpace(name), " ")
	name = strings.Join(strings.Fields(name), "-")
	name = strings.TrimPrefix(name, "-")
	return name
}

var (
	invalidPathCharRe   = regexp.MustCompile("[^a-zA-Z0-9._\\-+/]")
	validProfileFormats = map[string]bool{
		"pms": true, "portage-1": true, "portage-2": true, "profile-bashrcs": true, "profile-set": true,
		"profile-default-eapi": true, "build-id": true,
	}

	portage1ProfilesAllowDirectories = map[string]bool{"portage-1-compat": true, "portage-1": true, "portage-2": true}
)

func findInvalidPathChar(path string, pos int, endpos int) int {
	if endpos == 0 {
		endpos = len(path)
	}
	if m := invalidPathCharRe.FindStringIndex(path[pos:endpos]); len(m) > 0 {
		return m[0]
	}
	return -1
}

type repoConfig struct {
	allowMissingManifest, autoSync, cacheFormats, cloneDepth, eapi, eclassDb, eclassLocations, format, location, mainRepo, manifestHashes, manifestRequiredHashes, name, profile_formats, sync_depth, syncOpenpgpKeyPath, syncOpenpgpKeyRefreshRetryCount, syncOpenpgpKeyRefreshRetryDelayExpBase, syncOpenpgpKeyRefreshRetryDelayMax, syncOpenpgpKeyRefreshRetryDelayMult, syncOpenpgpKeyRefreshRetryOverallTimeout, syncRcuStoreDir, sync_type, sync_umask, sync_uri, sync_user, user_location, _eapis_banned, _eapis_deprecated, mastersOrig string
	force, aliases, eclassOverrides, masters                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    map[string]bool
	moduleSpecificOptions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         map[string]string
	localConfig, syncHooksOnlyOnChange, strictMiscDigests, syncAllowHardlinks, syncRcu, missingRepoName, signCommit, signManifest, thinManifest, allowProvideVirtual, createManifest, disableManifest, updateChangelog, portage1Profiles, portage1ProfilesCompat                                                                                                                                                                                                                                                                                  bool
	priority, syncRcuSpareSnapshots, syncRcuTtlDays                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               int
	findInvalidPathChar                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           func(string, int, int) int
}

func (r *repoConfig) writable() bool {
	s, _ := os.Stat(firstExisting(r.location))
	return s.Mode()&unix.W_OK != 0
}

func (r *repoConfig) readValidRepoName(repoPath string) (string, bool) {
	name, missing := r.readRepoName(repoPath)
	name = genValidRepo(name)
	if len(name) == 0 {
		name = "x-" + path.Base(repoPath)
		name = genValidRepo(name)
	}
	return name, missing
}
func (r *repoConfig) readRepoName(repoPath string) (string, bool) {
	repoNamePath := path.Join(repoPath, RepoNameLoc)
	f, _ := os.Open(repoNamePath)
	defer f.Close()
	b := bufio.NewReader(f)
	line, _, _ := b.ReadLine()
	return string(line), false
}

func NewRepoConfig(name string, repoOpts map[string]string, localConfig bool) *repoConfig {
	r := &repoConfig{}
	force, ok := repoOpts["get"]
	f := map[string]bool{}
	if ok {
		for _, x := range strings.Fields(force) {
			f[x] = true
		}

	}
	r.force = f
	r.localConfig = localConfig
	a := map[string]bool{}
	if localConfig || f["aliases"] {
		aliases, ok := repoOpts["aliases"]
		if ok {
			for _, x := range strings.Fields(aliases) {
				a[x] = true
			}
		}
	}
	r.aliases = a

	e := map[string]bool{}
	if localConfig || f["eclass-overrides"] {
		eclassOverrides, ok := repoOpts["eclass-overrides"]
		if ok {
			for _, x := range strings.Fields(eclassOverrides) {
				e[x] = true
			}
		}
	}
	r.eclassOverrides = e
	r.eclassDb = ""
	r.eclassLocations = ""

	m := map[string]bool{}
	if localConfig || f["masters"] {
		masters, ok := repoOpts["masters"]
		if ok {
			for _, x := range strings.Fields(masters) {
				m[x] = true
			}
		}
	}
	r.masters = m
	r.mainRepo = repoOpts["main-repo"]
	priority, ok := repoOpts["priority"]
	if ok {
		p, _ := strconv.Atoi(priority)
		r.priority = p
	}
	syncType, ok := repoOpts["sync-type"]
	if ok {
		r.sync_type = strings.TrimSpace(syncType)
	}
	syncUmask, ok := repoOpts["sync-umask"]
	if ok {
		r.sync_umask = strings.TrimSpace(syncUmask)
	}
	syncUri, ok := repoOpts["sync-uri"]
	if ok {
		r.sync_uri = strings.TrimSpace(syncUri)
	}
	syncUser, ok := repoOpts["sync-user"]
	if ok {
		r.sync_user = strings.TrimSpace(syncUser)
	}
	autoSync, ok := repoOpts["auto-sync"]
	if ok {
		r.autoSync = strings.ToLower(strings.TrimSpace(autoSync))
	} else {
		r.autoSync = "yes"
	}
	r.cloneDepth = repoOpts["clone-depth"]
	r.sync_depth = repoOpts["sync-depth"]

	if s, ok := repoOpts["sync-hooks-only-on-change"]; ok {
		r.syncHooksOnlyOnChange = strings.ToLower(s) == "true"
	} else {
		r.syncHooksOnlyOnChange = strings.ToLower("false") == "true"
	}

	if s, ok := repoOpts["sync-allow-hardlinks"]; ok {
		r.strictMiscDigests = strings.ToLower(s) == "true"
	} else {
		r.strictMiscDigests = strings.ToLower("true") == "true"
	}

	if s, ok := repoOpts["sync-openpgp-key-path"]; ok {
		r.syncAllowHardlinks = strings.ToLower(s) == "true"
	} else {
		r.syncAllowHardlinks = strings.ToLower("true") == "true"
	}
	r.syncOpenpgpKeyRefreshRetryCount = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_count", "_", "-", -1)]
	r.syncOpenpgpKeyRefreshRetryDelayExpBase = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_delay_exp_base", "_", "-", -1)]
	r.syncOpenpgpKeyRefreshRetryDelayMax = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_delay_max", "_", "-", -1)]
	r.syncOpenpgpKeyRefreshRetryDelayMult = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_delay_mult", "_", "-", -1)]
	r.syncOpenpgpKeyRefreshRetryOverallTimeout = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_overall_timeout", "_", "-", -1)]

	if s, ok := repoOpts["sync-rcu"]; ok {
		r.syncRcu = strings.ToLower(s) == "true" || strings.ToLower(s) == "yes"
	} else {
		r.syncRcu = strings.ToLower("false") == "true"
	}

	r.syncRcuStoreDir = repoOpts["sync-rcu-store-dir"]
	r.syncRcuSpareSnapshots, _ = strconv.Atoi(strings.TrimSpace(repoOpts["sync-rcu-spare-snapshots"]))
	r.syncRcuTtlDays, _ = strconv.Atoi(strings.TrimSpace(repoOpts["sync-rcu-ttl-days"]))

	r.moduleSpecificOptions = map[string]string{}
	r.format = strings.TrimSpace(repoOpts["format"])

	if s, _ := os.Stat(repoOpts["location"]); s.IsDir() || syncMode {
		r.user_location = repoOpts["location"]
		r.location, _ = filepath.EvalSymlinks(repoOpts["location"])
	}
	missing := true
	r.name = name
	if len(r.location) > 0 {
		r.name, missing = r.readValidRepoName(r.location)
		if missing {
			if len(name) > 0 {
				r.name = name
			}
			if syncMode {
				missing = false
			}
		}
	} else if name == "DEFAULT" {
		missing = false
	}
	r.eapi = ""
	r.missingRepoName = missing
	r.signCommit = false
	r.signManifest = true
	r.thinManifest = false
	r.allowMissingManifest = ""
	r.allowProvideVirtual = false
	r.createManifest = true
	r.disableManifest = false
	r.manifestHashes = ""
	r.manifestRequiredHashes = ""
	r.updateChangelog = false
	r.cacheFormats = ""
	r.portage1Profiles = true
	r.portage1ProfilesCompat = false
	r.findInvalidPathChar = findInvalidPathChar
	r.mastersOrig = ""

	if len(r.location) >0{
		layoutData:=
		r.mastersOrig = layoutData["masters"]
	}

	return r
}

func loadRepositoryConfig(settings *Config, extraFiles string){
	repoconfigpaths := []string{}
	if pr , ok:= settings.valueDict["PORTAGE_REPOSITORIES"]; ok {
		repoconfigpaths = append(repoconfigpaths, pr)
	}	else{
		if notInstalled{
			repoconfigpaths = append(repoconfigpaths, path.Join(PORTAGE_BASE_PATH, "cnf", "repos.conf"))
		} else{
			repoconfigpaths = append(repoconfigpaths,path.Join(settings.globalConfigPath, "repos.conf"))
		}
	}
	repoconfigpaths.append(os.path.join(settings["PORTAGE_CONFIGROOT"], USER_CONFIG_PATH, "repos.conf"))
	if extra_files:
	repoconfigpaths.extend(extra_files)
	return RepoConfigLoader(repoconfigpaths, settings)

	def _get_repo_name(repo_location, cached=None):
	if cached is not None:
	return cached
	name, missing = RepoConfig._read_repo_name(repo_location)
	if missing:
	return None
	return name
}

def parse_layout_conf(repo_location, repo_name=None):
eapi = read_corresponding_eapi_file(os.path.join(repo_location, REPO_NAME_LOC))

layout_filename = os.path.join(repo_location, "metadata", "layout.conf")
layout_file = KeyValuePairFileLoader(layout_filename, None, None)
layout_data, layout_errors = layout_file.load()

data = {}

# None indicates abscence of a masters setting, which later code uses
# to trigger a backward compatibility fallback that sets an implicit
# master. In order to avoid this fallback behavior, layout.conf can
# explicitly set masters to an empty value, which will result in an
# empty tuple here instead of None.
masters = layout_data.get('masters')
if masters is not None:
masters = tuple(masters.split())
data['masters'] = masters
data['aliases'] = tuple(layout_data.get('aliases', '').split())

data['eapis-banned'] = tuple(layout_data.get('eapis-banned', '').split())
data['eapis-deprecated'] = tuple(layout_data.get('eapis-deprecated', '').split())

data['sign-commit'] = layout_data.get('sign-commits', 'false').lower() \
== 'true'

data['sign-manifest'] = layout_data.get('sign-manifests', 'true').lower() \
== 'true'

data['thin-manifest'] = layout_data.get('thin-manifests', 'false').lower() \
== 'true'

data['repo-name'] = _gen_valid_repo(layout_data.get('repo-name', ''))

manifest_policy = layout_data.get('use-manifests', 'strict').lower()
data['allow-missing-manifest'] = manifest_policy != 'strict'
	data['create-manifest'] = manifest_policy != 'false'
	data['disable-manifest'] = manifest_policy == 'false'

# for compatibility w/ PMS, fallback to pms; but also check if the
# cache exists or not.
cache_formats = layout_data.get('cache-formats', '').lower().split()
if not cache_formats:
# Auto-detect cache formats, and prefer md5-cache if available.
# This behavior was deployed in portage-2.1.11.14, so that the
# default egencache format could eventually be changed to md5-dict
# in portage-2.1.11.32. WARNING: Versions prior to portage-2.1.11.14
# will NOT recognize md5-dict format unless it is explicitly
# listed in layout.conf.
cache_formats = []
if os.path.isdir(os.path.join(repo_location, 'metadata', 'md5-cache')):
cache_formats.append('md5-dict')
if os.path.isdir(os.path.join(repo_location, 'metadata', 'cache')):
cache_formats.append('pms')
data['cache-formats'] = tuple(cache_formats)

manifest_hashes = layout_data.get('manifest-hashes')
manifest_required_hashes = layout_data.get('manifest-required-hashes')

if manifest_required_hashes is not None and manifest_hashes is None:
repo_name = _get_repo_name(repo_location, cached=repo_name)
warnings.warn((_("Repository named '%(repo_name)s' specifies "
"'manifest-required-hashes' setting without corresponding "
"'manifest-hashes'. Portage will default it to match "
"the required set but please add the missing entry "
"to: %(layout_filename)s") %
{"repo_name": repo_name or 'unspecified',
"layout_filename":layout_filename}),
SyntaxWarning)
manifest_hashes = manifest_required_hashes

if manifest_hashes is not None:
# require all the hashes unless specified otherwise
if manifest_required_hashes is None:
manifest_required_hashes = manifest_hashes

manifest_required_hashes = frozenset(manifest_required_hashes.upper().split())
manifest_hashes = frozenset(manifest_hashes.upper().split())
missing_required_hashes = manifest_required_hashes.difference(
manifest_hashes)
if missing_required_hashes:
repo_name = _get_repo_name(repo_location, cached=repo_name)
warnings.warn((_("Repository named '%(repo_name)s' has a "
"'manifest-hashes' setting that does not contain "
"the '%(hash)s' hashes which are listed in "
"'manifest-required-hashes'. Please fix that file "
"if you want to generate valid manifests for this "
"repository: %(layout_filename)s") %
{"repo_name": repo_name or 'unspecified',
"hash": ' '.join(missing_required_hashes),
"layout_filename":layout_filename}),
SyntaxWarning)
unsupported_hashes = manifest_hashes.difference(
get_valid_checksum_keys())
if unsupported_hashes:
repo_name = _get_repo_name(repo_location, cached=repo_name)
warnings.warn((_("Repository named '%(repo_name)s' has a "
"'manifest-hashes' setting that contains one "
"or more hash types '%(hashes)s' which are not supported by "
"this portage version. You will have to upgrade "
"portage if you want to generate valid manifests for "
"this repository: %(layout_filename)s") %
{"repo_name": repo_name or 'unspecified',
"hashes":" ".join(sorted(unsupported_hashes)),
"layout_filename":layout_filename}),
DeprecationWarning)

data['manifest-hashes'] = manifest_hashes
data['manifest-required-hashes'] = manifest_required_hashes

data['update-changelog'] = layout_data.get('update-changelog', 'false').lower() \
== 'true'

raw_formats = layout_data.get('profile-formats')
if raw_formats is None:
if eapi_allows_directories_on_profile_level_and_repository_level(eapi):
raw_formats = ('portage-1',)
else:
raw_formats = ('portage-1-compat',)
else:
raw_formats = set(raw_formats.split())
unknown = raw_formats.difference(_valid_profile_formats)
if unknown:
repo_name = _get_repo_name(repo_location, cached=repo_name)
warnings.warn((_("Repository named '%(repo_name)s' has unsupported "
"profiles in use ('profile-formats = %(unknown_fmts)s' setting in "
"'%(layout_filename)s; please upgrade portage.") %
dict(repo_name=repo_name or 'unspecified',
layout_filename=layout_filename,
unknown_fmts=" ".join(unknown))),
DeprecationWarning)
raw_formats = tuple(raw_formats.intersection(_valid_profile_formats))
data['profile-formats'] = raw_formats

try:
eapi = layout_data['profile_eapi_when_unspecified']
except KeyError:
pass
else:
if 'profile-default-eapi' not in raw_formats:
warnings.warn((_("Repository named '%(repo_name)s' has "
"profile_eapi_when_unspecified setting in "
"'%(layout_filename)s', but 'profile-default-eapi' is "
"not listed in the profile-formats field. Please "
"report this issue to the repository maintainer.") %
dict(repo_name=repo_name or 'unspecified',
layout_filename=layout_filename)),
SyntaxWarning)
elif not portage.eapi_is_supported(eapi):
warnings.warn((_("Repository named '%(repo_name)s' has "
"unsupported EAPI '%(eapi)s' setting in "
"'%(layout_filename)s'; please upgrade portage.") %
dict(repo_name=repo_name or 'unspecified',
eapi=eapi, layout_filename=layout_filename)),
SyntaxWarning)
else:
data['profile_eapi_when_unspecified'] = eapi

return data, layout_errors
