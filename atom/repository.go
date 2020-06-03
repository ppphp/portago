package atom

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/shlex"
	"github.com/ppphp/configparser"
	"golang.org/x/sys/unix"
)

var repoNameSubRe = regexp.MustCompile(`[^\w-]`)

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

// 0, 0
func findInvalidPathChar(path string, pos int, endpos int) int {
	if endpos == 0 {
		endpos = len(path)
	}
	if m := invalidPathCharRe.FindStringIndex(path[pos:endpos]); len(m) > 0 {
		return m[0]
	}
	return -1
}

type RepoConfig struct {
	AutoSync, cloneDepth, eapi, format, location, mainRepo, Name, syncDepth, syncOpenpgpKeyPath, syncOpenpgpKeyRefreshRetryCount, syncOpenpgpKeyRefreshRetryDelayExpBase, syncOpenpgpKeyRefreshRetryDelayMax, syncOpenpgpKeyRefreshRetryDelayMult, syncOpenpgpKeyRefreshRetryOverallTimeout, syncRcuStoreDir, SyncType, syncUmask, SyncUri, syncUser, userLocation string
	eclassDb                                                                                                                                                                                                                                                                                                                                                       *cache
	eapisBanned, eapisDeprecated, force, Aliases, eclassOverrides, manifestHashes, manifestRequiredHashes                                                                                                                                                                                                                                                          map[string]bool
	cacheFormats, profileFormats, masters, eclassLocations, mastersOrig                                                                                                                                                                                                                                                                                            []string
	mastersRepo                                                                                                                                                                                                                                                                                                                                                    []*RepoConfig
	moduleSpecificOptions                                                                                                                                                                                                                                                                                                                                          map[string]string
	localConfig, syncHooksOnlyOnChange, strictMiscDigests, syncAllowHardlinks, syncRcu, missingRepoName, signCommit, signManifest, thinManifest, allowProvideVirtual, createManifest, disableManifest, updateChangelog, portage1Profiles, portage1ProfilesCompat, allowMissingManifest                                                                             bool
	priority, syncRcuSpareSnapshots, syncRcuTtlDays                                                                                                                                                                                                                                                                                                                int
	findInvalidPathChar                                                                                                                                                                                                                                                                                                                                            func(string, int, int) int
}

func (r *RepoConfig) setModuleSpecificOpt(opt, val string) {
	r.moduleSpecificOptions[opt] = val
}

func (r *RepoConfig) eapiIsBanned(eapi string) bool {
	return r.eapisBanned[eapi]
}

func (r *RepoConfig) eapiIsDeprecated(eapi string) bool {
	return r.eapisDeprecated[eapi]
}

// true, false
func (r *RepoConfig) iterPregeneratedCaches(auxdbkeys []string, readonly, force bool) {
	formats := r.cacheFormats
	if len(formats) == 0 {
		if !force {
			return
		}
		formats = []string{"md5-dict"}
	}
	for _, fmt := range formats {
		name := ""
		if fmt == "pms" {
			name = "metadata/cache"
		}else if fmt == "md5-dict" {
			name = "metadata/md5-cache"
		}
		if name != "" {
			yield database(r.location, name,
				auxdbkeys, readonly=readonly)
		}
	}
}

// true, false
func (r *RepoConfig) get_pregenerated_cache(auxdbkeys []string, readonly, force bool){
return r.iterPregeneratedCaches(
auxdbkeys, readonly, force)
}

// nil, false
func (r *RepoConfig) load_manifest( pkgdir, distdir string, fetchlist_dict *FetchlistDict, from_scratch bool) *Manifest{
	if r.disableManifest {
		from_scratch = true
	}
	return NewManifest(pkgdir, distdir, fetchlist_dict, from_scratch,
		r.thinManifest, r.allowMissingManifest, r.createManifest,
		r.manifestHashes,r.manifestRequiredHashes,
		func(s string) int {return r.findInvalidPathChar(s, 0, 0)},
		r.strictMiscDigests)
}

func (r *RepoConfig) update( new_repo *RepoConfig) {

	r.Aliases = new_repo.Aliases
	r.allowMissingManifest = new_repo.allowMissingManifest
	r.allowProvideVirtual = new_repo.allowProvideVirtual
	r.AutoSync = new_repo.AutoSync
	r.cacheFormats = new_repo.cacheFormats
	r.cloneDepth = new_repo.cloneDepth
	r.createManifest = new_repo.createManifest
	r.disableManifest = new_repo.disableManifest
	r.eapi = new_repo.eapi
	r.eclassDb = new_repo.eclassDb
	r.eclassLocations = new_repo.eclassLocations
	r.eclassOverrides = new_repo.eclassOverrides
	r.findInvalidPathChar = new_repo.findInvalidPathChar
	r.force = new_repo.force
	r.format = new_repo.format
	r.localConfig = new_repo.localConfig
	r.location = new_repo.location
	r.mainRepo = new_repo.mainRepo
	r.manifestHashes = new_repo.manifestHashes
	r.manifestRequiredHashes = new_repo.manifestRequiredHashes
	r.masters = new_repo.masters
	r.moduleSpecificOptions = new_repo.moduleSpecificOptions
	r.Name = new_repo.Name
	r.portage1Profiles = new_repo.portage1Profiles
	r.portage1ProfilesCompat = new_repo.portage1ProfilesCompat
	r.priority = new_repo.priority
	r.profileFormats = new_repo.profileFormats
	r.properties_allowed = new_repo.properties_allowed
	r.restrict_allowed = new_repo.restrict_allowed
	r.signCommit = new_repo.signCommit
	r.signManifest = new_repo.signManifest
	r.strictMiscDigests = new_repo.strictMiscDigests
	r.syncAllowHardlinks = new_repo.syncAllowHardlinks
	r.syncDepth = new_repo.syncDepth
	r.syncHooksOnlyOnChange = new_repo.syncHooksOnlyOnChange
	r.sync_openpgp_keyserver = new_repo.sync_openpgp_keyserver
	r.syncOpenpgpKeyPath = new_repo.syncOpenpgpKeyPath
	r.syncOpenpgpKeyRefreshRetryCount = new_repo.syncOpenpgpKeyRefreshRetryCount
	r.syncOpenpgpKeyRefreshRetryDelayExpBase = new_repo.syncOpenpgpKeyRefreshRetryDelayExpBase
	r.syncOpenpgpKeyRefreshRetryDelayMax = new_repo.syncOpenpgpKeyRefreshRetryDelayMax
	r.syncOpenpgpKeyRefreshRetryDelayMult = new_repo.syncOpenpgpKeyRefreshRetryDelayMult
	r.syncOpenpgpKeyRefreshRetryOverallTimeout = new_repo.syncOpenpgpKeyRefreshRetryOverallTimeout
	r.syncRcu = new_repo.syncRcu
	r.syncRcuSpareSnapshots = new_repo.syncRcuSpareSnapshots
	r.syncRcuStoreDir = new_repo.syncRcuStoreDir
	r.syncRcuTtlDays = new_repo.syncRcuTtlDays
	r.SyncType = new_repo.SyncType
	r.syncUmask = new_repo.syncUmask
	r.SyncUri = new_repo.SyncUri
	r.syncUser = new_repo.syncUser
	r.thinManifest = new_repo.thinManifest
	r.updateChangelog = new_repo.updateChangelog
	r.userLocation = new_repo.userLocation
	r.eapisBanned = new_repo.eapisBanned
	r.eapisDeprecated = new_repo.eapisDeprecated
	r.mastersOrig = new_repo.mastersOrig

	if new_repo.Name != ""{
	r.missingRepoName = new_repo.missingRepoName
}
}

func (r *RepoConfig) writable() bool {
	s, _ := os.Stat(firstExisting(r.location))
	return s.Mode()&unix.W_OK != 0
}

func (r *RepoConfig) readValidRepoName(repoPath string) (string, bool) {
	name, missing := r.readRepoName(repoPath)
	name = genValidRepo(name)
	if len(name) == 0 {
		name = "x-" + path.Base(repoPath)
		name = genValidRepo(name)
	}
	return name, missing
}

func (r *RepoConfig) readRepoName(repoPath string) (string, bool) {
	repoNamePath := path.Join(repoPath, RepoNameLoc)
	f, _ := os.Open(repoNamePath)
	defer f.Close()
	b := bufio.NewReader(f)
	line, _, _ := b.ReadLine()
	return string(line), false
}

func (r *RepoConfig) info_string() string {
	indent := "    "
	repo_msg := []string{}
	repo_msg=append(repo_msg,r.Name)
	if len(r.format)!=0 {
		repo_msg = append(repo_msg, indent+"format: "+r.format)
	}
	if len(r.location) != 0 {
		repo_msg = append(repo_msg, indent+"location: "+r.location)
	}
	if !r.strictMiscDigests {
		repo_msg = append(repo_msg, indent+"strict-misc-digests: false")
	}
	if len(r.SyncType) > 0 {
		repo_msg = append(repo_msg, indent+"sync-type: "+r.SyncType)
	}
	if len(r.syncUmask) > 0 {
		repo_msg = append(repo_msg, indent+"sync-umask: "+r.syncUmask)
	}
	if len(r.SyncUri) > 0 {
		repo_msg = append(repo_msg, indent+"sync-uri: "+r.SyncUri)
	}
	if len(r.syncUser) > 0 {
		repo_msg = append(repo_msg, indent+"sync-user: "+r.syncUser)
	}
	if len(r.masters) > 0 {
		rm := []string{}
		for _, master := range r.masters {
			rm = append(rm, master)
		}
		repo_msg = append(repo_msg, indent+"masters: "+strings.Join(rm, " "))
	}
	if r.priority != 0 {
		repo_msg = append(repo_msg, indent+"priority: "+fmt.Sprint(r.priority))
	}
	if len(r.Aliases) > 0 {
		ra := []string{}
		for k := range r.Aliases {
			ra = append(ra, k)
		}
		repo_msg = append(repo_msg, indent+"aliases: "+strings.Join(ra, " "))
	}
	if len(r.eclassOverrides) > 0 {
		re := []string{}
		for k := range r.eclassOverrides {
			re = append(re, k)
		}
		repo_msg = append(repo_msg, indent+"eclass-overrides: "+
			strings.Join(re, " "))
	}
	for o, v := range r.moduleSpecificOptions{
		if v != "" {
			repo_msg = append(repo_msg, indent+o+": "+v)
		}
	}
	repo_msg=append(repo_msg,"")
	return strings.Join(repo_msg, "\n")
}

func NewRepoConfig(name string, repoOpts map[string]string, localConfig bool) *RepoConfig {
	r := &RepoConfig{}
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
	r.Aliases = a

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
	r.eclassDb = nil
	r.eclassLocations = []string{}

	m := []string{}
	if localConfig || f["masters"] {
		masters, ok := repoOpts["masters"]
		if ok {
			for _, x := range strings.Fields(masters) {
				m = append(m, x)
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
		r.SyncType = strings.TrimSpace(syncType)
	}
	syncUmask, ok := repoOpts["sync-umask"]
	if ok {
		r.syncUmask = strings.TrimSpace(syncUmask)
	}
	syncUri, ok := repoOpts["sync-uri"]
	if ok {
		r.SyncUri = strings.TrimSpace(syncUri)
	}
	syncUser, ok := repoOpts["sync-user"]
	if ok {
		r.syncUser = strings.TrimSpace(syncUser)
	}
	autoSync, ok := repoOpts["auto-sync"]
	if ok {
		r.AutoSync = strings.ToLower(strings.TrimSpace(autoSync))
	} else {
		r.AutoSync = "yes"
	}
	r.cloneDepth = repoOpts["clone-depth"]
	r.syncDepth = repoOpts["sync-depth"]

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

	location := repoOpts["location"]
	if s, err := os.Stat(location); err == nil && (s.IsDir() || SyncMode) {
		r.userLocation = location
		location, _ = filepath.EvalSymlinks(location)
	} else {
		location = ""
	}
	r.location = location
	missing := true
	r.Name = name
	if len(r.location) > 0 {
		r.Name, missing = r.readValidRepoName(r.location)
		if missing {
			if len(name) > 0 {
				r.Name = name
			}
			if SyncMode {
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
	r.allowMissingManifest = false
	r.allowProvideVirtual = false
	r.createManifest = true
	r.disableManifest = false
	r.manifestHashes = nil
	r.manifestRequiredHashes = nil
	r.updateChangelog = false
	r.cacheFormats = nil
	r.portage1Profiles = true
	r.portage1ProfilesCompat = false
	r.findInvalidPathChar = findInvalidPathChar
	r.mastersOrig = []string{}

	if len(r.location) > 0 {
		layoutData, _ := parseLayoutConf(r.location, r.Name)
		r.mastersOrig = layoutData["masters"]
		if r.masters == nil {
			r.masters = layoutData["masters"]
		}
		if (localConfig || f["aliases"]) && len(layoutData["aliases"]) != 0 {
			aliases := r.Aliases
			if len(aliases) == 0 {
				aliases = map[string]bool{}
			}
			r.Aliases = map[string]bool{}
			for _, s := range layoutData["aliases"] {
				r.Aliases[s] = true
			}
			for k := range aliases {
				r.Aliases[k] = true
			}
		}
		if len(layoutData["allow-missing-manifest"]) > 0 {
			r.allowMissingManifest = layoutData["allow-missing-manifest"][0]
		}
		if len(layoutData["repo-name"]) > 0 && len(layoutData["repo-name"][0]) > 0 {
			r.Name = layoutData["repo-name"][0]
			r.missingRepoName = false
		}
		r.cacheFormats = layoutData["cache-formats"]
		if len(layoutData["create-manifest"]) > 0 {
			r.createManifest = layoutData["create-manifest"][0] == "true"
		}
		if len(layoutData["disable-manifest"]) > 0 {
			r.disableManifest = layoutData["disable-manifest"][0] == "true"
		}
		if len(layoutData["manifest-hashes"]) > 0 {
			r.manifestHashes = layoutData["manifest-hashes"][0]
		}
		if len(layoutData["manifest-required-hashes"]) > 0 {
			r.manifestRequiredHashes = layoutData["manifest-required-hashes"][0]
		}
		if len(layoutData["profile-formats"]) > 0 {
			r.profileFormats = layoutData["profile-formats"]
		}
		if len(layoutData["sign-commit"]) > 0 {
			r.signCommit = layoutData["sign-commit"][0] == "true"
		}
		if len(layoutData["sign-manifest"]) > 0 {
			r.signCommit = layoutData["sign-manifest"][0] == "true"
		}
		if len(layoutData["thin-manifest"]) > 0 {
			r.thinManifest = layoutData["thin-manifest"][0] == "true"
		}
		if len(layoutData["update-changelog"]) > 0 {
			r.updateChangelog = layoutData["update-changelog"][0] == "true"
		}
		if len(layoutData["profile_eapi_when_unspecified"]) > 0 {
			r.eapi = layoutData["profile_eapi_when_unspecified"][0]
		} else {
			r.eapi = "0"
		}

		eapi := readCorrespondingEapiFile(path.Join(r.location, RepoNameLoc), r.eapi)
		r.portage1Profiles = eapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi)
		for _, v := range layoutData["profile-formats"] {
			if portage1ProfilesAllowDirectories[v] {
				r.portage1Profiles = true
				break
			}
		}
		r.portage1ProfilesCompat = !eapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi) && len(layoutData["profile-formats"]) == 1 && layoutData["profile-formats"][0] == "portage-1-compat"
		r.eapisBanned = map[string]bool{}
		for _, v := range layoutData["eapis-banned"] {
			r.eapisBanned[v] = true
		}
		r.eapisDeprecated = map[string]bool{}
		for _, v := range layoutData["eapis-deprecated"] {
			r.eapisDeprecated[v] = true
		}
	}

	return r
}

type repoConfigLoader struct {
	locationMap, treeMap map[string]string
	Prepos               map[string]*RepoConfig
	preposOrder          []string
	missingRepoNames     map[string]bool
	preposChanged        bool
	repoLocationList     []string
	ignoredRepos         []sss
}

func (r *repoConfigLoader) addRepositories(portDir, portdirOverlay string, prepos map[string]*RepoConfig, ignoredMap map[string][]string, localConfig bool, defaultPortdir string) string {
	overlays := []string{}
	portDirOrig := ""
	if portDir != "" {
		portDir = NormalizePath(portDir)
		portDirOrig = portDir
		overlays = append(overlays, portDir)
	}
	portOv := []string{}
	sl, err := shlex.Split(portdirOverlay)
	if err != nil {
		WriteMsg(fmt.Sprintf("!!! Invalid PORTDIR_OVERLAY:%s: %s\n", err, portdirOverlay), -1, nil)
	} else {
		for _, i := range sl {
			portOv = append(portOv, NormalizePath(i))
		}
	}
	overlays = append(overlays, portOv...)
	defaultRepoOpt := map[string]string{}
	if prepos["DEFAULT"].Aliases != nil {
		s := []string{}
		for k := range prepos["DEFAULT"].Aliases {
			s = append(s, k)
		}
		defaultRepoOpt["aliases"] = strings.Join(s, "k")
	}
	if prepos["DEFAULT"].eclassOverrides != nil {
		s := []string{}
		for k := range prepos["DEFAULT"].eclassOverrides {
			s = append(s, k)
		}
		defaultRepoOpt["eclass-overrides"] = strings.Join(s, "k")
	}
	if prepos["DEFAULT"].masters != nil {
		defaultRepoOpt["aliases"] = strings.Join(prepos["DEFAULT"].masters, "k")
	}
	if len(overlays) != 0 {
		reposConf := map[string]*RepoConfig{}
		for k, v := range prepos {
			reposConf[k] = v
		}
		basePriority := 0
		for _, ov := range overlays {
			if isdirRaiseEaccess(ov) || (basePriority == 0 && ov == portDir) {
				repoOpts := map[string]string{}
				for k, v := range defaultRepoOpt {
					repoOpts[k] = v
				}
				repoOpts["location"] = ov
				name := ""
				if ov == portDir {
					name = prepos["DEFAULT"].mainRepo
				}
				repo := NewRepoConfig(name, repoOpts, localConfig)
				reposConfOpts := reposConf[repo.Name]
				if reposConfOpts != nil {
					if reposConfOpts.Aliases != nil {
						repo.Aliases = reposConfOpts.Aliases
					}
					if reposConfOpts.AutoSync != "" {
						repo.AutoSync = reposConfOpts.AutoSync
					}
					if reposConfOpts.cloneDepth != "" {
						repo.cloneDepth = reposConfOpts.cloneDepth
					}
					if reposConfOpts.force != nil {
						repo.force = reposConfOpts.force
					}
					if reposConfOpts.masters != nil {
						repo.masters = reposConfOpts.masters
					}
					if reposConfOpts.moduleSpecificOptions != nil {
						repo.moduleSpecificOptions = reposConfOpts.moduleSpecificOptions
					}
					if reposConfOpts.priority != 0 {
						repo.priority = reposConfOpts.priority
					}
					if reposConfOpts.strictMiscDigests != false {
						repo.strictMiscDigests = reposConfOpts.strictMiscDigests
					}
					if reposConfOpts.syncAllowHardlinks != false {
						repo.syncAllowHardlinks = reposConfOpts.syncAllowHardlinks
					}
					if reposConfOpts.syncDepth != "" {
						repo.syncDepth = reposConfOpts.syncDepth
					}
					if reposConfOpts.syncHooksOnlyOnChange != false {
						repo.syncHooksOnlyOnChange = reposConfOpts.syncHooksOnlyOnChange
					}
					if reposConfOpts.syncOpenpgpKeyPath != "" {
						repo.syncOpenpgpKeyPath = reposConfOpts.syncOpenpgpKeyPath
					}
					if reposConfOpts.syncOpenpgpKeyRefreshRetryCount != "" {
						repo.syncOpenpgpKeyRefreshRetryCount = reposConfOpts.syncOpenpgpKeyRefreshRetryCount
					}
					if reposConfOpts.syncOpenpgpKeyRefreshRetryDelayExpBase != "" {
						repo.syncOpenpgpKeyRefreshRetryDelayExpBase = reposConfOpts.syncOpenpgpKeyRefreshRetryDelayExpBase
					}
					if reposConfOpts.syncOpenpgpKeyRefreshRetryDelayMax != "" {
						repo.syncOpenpgpKeyRefreshRetryDelayMax = reposConfOpts.syncOpenpgpKeyRefreshRetryDelayMax
					}
					if reposConfOpts.syncOpenpgpKeyRefreshRetryDelayMult != "" {
						repo.syncOpenpgpKeyRefreshRetryDelayMult = reposConfOpts.syncOpenpgpKeyRefreshRetryDelayMult
					}
					if reposConfOpts.syncOpenpgpKeyRefreshRetryOverallTimeout != "" {
						repo.syncOpenpgpKeyRefreshRetryOverallTimeout = reposConfOpts.syncOpenpgpKeyRefreshRetryOverallTimeout
					}
					if reposConfOpts.syncRcu != false {
						repo.syncRcu = reposConfOpts.syncRcu
					}
					if reposConfOpts.syncRcuSpareSnapshots != 0 {
						repo.syncRcuSpareSnapshots = reposConfOpts.syncRcuSpareSnapshots
					}
					if reposConfOpts.syncRcuStoreDir != "" {
						repo.syncRcuStoreDir = reposConfOpts.syncRcuStoreDir
					}
					if reposConfOpts.syncRcuTtlDays != 0 {
						repo.syncRcuTtlDays = reposConfOpts.syncRcuTtlDays
					}
					if reposConfOpts.SyncType != "" {
						repo.SyncType = reposConfOpts.SyncType
					}
					if reposConfOpts.syncUmask != "" {
						repo.syncUmask = reposConfOpts.syncUmask
					}
					if reposConfOpts.SyncUri != "" {
						repo.SyncUri = reposConfOpts.SyncUri
					}
					if reposConfOpts.syncUser != "" {
						repo.syncUser = reposConfOpts.syncUser
					}
				}
				if _, ok := prepos[repo.Name]; ok {
					oldLocation := prepos[repo.Name].location
					if oldLocation != "" && oldLocation != repo.location && !(basePriority == 0 && oldLocation == defaultPortdir) {
						if ignoredMap[repo.Name] == nil {
							ignoredMap[repo.Name] = []string{}
						}
						ignoredMap[repo.Name] = append(ignoredMap[repo.Name], oldLocation)
						if oldLocation == portDir {
							portDir = repo.location
						}
					}
				}
				if repo.priority == 0 {
					if basePriority == 0 && ov == portDirOrig {
					} else {
						repo.priority = basePriority
						basePriority += 1
					}
				}
			} else {
				if !SyncMode {
					WriteMsg(fmt.Sprintf("!!! Invalid PORTDIR_OVERLAY (not a dir): '%s'\n", ov), -1, nil)
				}
			}
		}
	}
	return portDir
}

func (r *repoConfigLoader) parse(paths []string, prepos map[string]*RepoConfig, localConfig bool, defaultOpts map[string]string) error {
	args := configparser.DefaultArgument
	args.Defaults = defaultOpts
	parser := configparser.NewConfigParser(args)
	var recursivePaths []string
	for _, p := range paths {
		recursivePaths = append(recursivePaths, recursiveFileList(p)...)
	}

	if err := readConfigs(parser, recursivePaths); err != nil {
		return err
	}

	prepos["DEFAULT"] = NewRepoConfig("DEFAULT", parser.Defaults(), localConfig)
	for _, sname := range parser.Sections() {
		optdict := map[string]string{}
		onames, _ := parser.Options(sname)
		for _, oname := range onames {
			optdict[oname], _ = parser.Gett(sname, oname)
		}
		repo := NewRepoConfig(sname, optdict, localConfig)
		for o := range moduleSpecificOptions(repo) {
			if parser.HasOption(sname, o) {
				v, _ := parser.Get(sname, o, false, nil, "")
				repo.setModuleSpecificOpt(o, v)
			}
		}
		//validateConfig(repo, logging)
		prepos[sname] = repo
	}
	return nil
}

func (r *repoConfigLoader) mainRepoLocation() string {
	mainRepo := r.Prepos["DEFAULT"].mainRepo
	if _, ok := r.Prepos[mainRepo]; mainRepo == "" || !ok {
		return ""
	}
	return r.Prepos[mainRepo].location
}

func (r *repoConfigLoader) mainRepo() *RepoConfig {
	mainRepo := r.Prepos["DEFAULT"].mainRepo
	if mainRepo == "" {
		return nil
	}
	return r.Prepos[mainRepo]
}

func (r *repoConfigLoader) RepoLocationList() []string {
	if r.preposChanged {
		repoLocationList := []string{}
		for _, repo := range r.preposOrder {
			if r.Prepos[repo].location != "" {
				repoLocationList = append(repoLocationList, r.Prepos[repo].location)
			}
		}
		r.repoLocationList = repoLocationList
		r.preposChanged = false
	}
	return r.repoLocationList
}

func (r *repoConfigLoader) checkLocations() {
	for name, re := range r.Prepos {
		if name != "DEFAULT" {
			if re.location == "" {
				WriteMsg(fmt.Sprintf("!!! Location not set for repository %s\n", name), -1, nil)
			} else {
				if !isdirRaiseEaccess(re.location) && !SyncMode {
					n := []string{}
					for _, v := range r.preposOrder {
						if v != name {
							n = append(n, v)
						}
					}
					r.preposOrder = n
					WriteMsg(fmt.Sprintf("!!! Invalid Repository Location (not a dir): '%s'\n", re.location), -1, nil)
				}
			}
		}
	}
}

func (r *repoConfigLoader) reposWithProfiles() []*RepoConfig {
	rp := []*RepoConfig{}
	for _, repoName := range r.preposOrder {
		repo := r.Prepos[repoName]
		if repo.format != "unavailable" {
			rp = append(rp, repo)
		}
	}
	return rp
}

func (r *repoConfigLoader) getNameForLocation(location string) string {
	return r.locationMap[location]
}

func (r *repoConfigLoader) getLocationForName(repoName string) string {
	if repoName == "" {
		return ""
	}
	return r.treeMap[repoName]
}

func (r *repoConfigLoader) getRepoForLocation(location string) *RepoConfig {
	return r.Prepos[r.getNameForLocation(location)]
}

func (r *repoConfigLoader) getitem(repoName string) *RepoConfig {
	return r.Prepos[repoName]
}

func (r *repoConfigLoader) delitem(repoName string) {
	if repoName == r.Prepos["DEFAULT"].mainRepo {
		r.Prepos["DEFAULT"].mainRepo = ""
	}
	location := r.Prepos[repoName].location
	delete(r.Prepos, repoName)
	n := []string{}
	for _, v := range r.preposOrder {
		if v != repoName {
			n = append(n, v)
		}
	}
	r.preposOrder = n
	for k, v := range CopyMapSS(r.locationMap) {
		if v == repoName {
			delete(r.locationMap, k)
		}
	}
	if _, ok := r.treeMap[repoName]; ok {
		delete(r.treeMap, repoName)
	}
	rll := []string{}
	for _, x := range r.repoLocationList {
		if x != location {
			rll = append(rll, x)
		}
	}
	r.repoLocationList = rll
}

func (r *repoConfigLoader) contains(repoName string) bool {
	_, ok := r.Prepos[repoName]
	return ok
}

func (r *repoConfigLoader) iter() []string {
	rp := []string{}
	for _, repo := range r.preposOrder {
		rp = append(rp, repo)
	}
	return rp
}

func (r *repoConfigLoader) configString() string {
	configString := ""
	repoName := []string{}
	for r := range r.Prepos {
		if r != "DEFAULT" {
			repoName = append(repoName, r)
		}
	}
	sort.Strings(repoName)
	repoName = append(repoName, "DEFAULT")
	for _, v := range repoName {
		configString += fmt.Sprintf("\n[%s]\n", v)
		repo := r.Prepos[v]
		configString += fmt.Sprintf("%s = %v\n", strings.Replace("strict_misc_digests", "_", "-", -1), repo.strictMiscDigests)
		configString += fmt.Sprintf("%s = %v\n", strings.Replace("sync_allow_hardlinks", "_", "-", -1), repo.syncAllowHardlinks)
		configString += fmt.Sprintf("%s = %v\n", strings.Replace("sync_rcu", "_", "-", -1), repo.syncRcu)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("auto_sync", "_", "-", -1), repo.AutoSync)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("clone_depth", "_", "-", -1), repo.cloneDepth)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("format", "_", "-", -1), repo.format)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("location", "_", "-", -1), repo.location)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("main_repo", "_", "-", -1), repo.mainRepo)
		configString += fmt.Sprintf("%s = %v\n", strings.Replace("priority", "_", "-", -1), repo.priority)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_depth", "_", "-", -1), repo.syncDepth)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_path", "_", "-", -1), repo.syncOpenpgpKeyPath)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_count", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryCount)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_delay_exp_base", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryDelayExpBase)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_delay_max", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryDelayMax)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_delay_mult", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryDelayMult)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_overall_timeout", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryOverallTimeout)
		configString += fmt.Sprintf("%s = %v\n", strings.Replace("sync_rcu_spare_snapshots", "_", "-", -1), repo.syncRcuSpareSnapshots)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_rcu_store_dir", "_", "-", -1), repo.syncRcuStoreDir)
		configString += fmt.Sprintf("%s = %v\n", strings.Replace("sync_rcu_ttl_days", "_", "-", -1), repo.syncRcuTtlDays)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_type", "_", "-", -1), repo.SyncType)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_umask", "_", "-", -1), repo.syncUmask)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_uri", "_", "-", -1), repo.SyncUri)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("sync_user", "_", "-", -1), repo.syncUser)
		aliases := []string{}
		for k := range repo.Aliases {
			aliases = append(aliases, k)
		}
		sort.Strings(aliases)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("aliases", "_", "-", -1), strings.Join(aliases, " "))
		eclassOverrides := []string{}
		for k := range repo.eclassOverrides {
			eclassOverrides = append(eclassOverrides, k)
		}
		sort.Strings(eclassOverrides)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("eclass_overrides", "_", "-", -1), strings.Join(eclassOverrides, " "))
		force := []string{}
		for k := range repo.force {
			force = append(force, k)
		}
		sort.Strings(force)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("force", "_", "-", -1), strings.Join(force, " "))
		masters := []string{}
		for _, k := range repo.mastersRepo {
			masters = append(masters, k.Name)
		}
		sort.Strings(masters)
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("masters", "_", "-", -1), strings.Join(masters, " "))
		if v == "DEFAULT" {
			configString += ""
		}

		keys := []string{}
		for o := range repo.moduleSpecificOptions {
			keys = append(keys, o)
		}
		sort.Strings(keys)
		for _, v := range keys {
			configString += fmt.Sprintf("%s = %s\n", v, repo.moduleSpecificOptions[v])
		}
	}
	return strings.TrimPrefix(configString, "\n")
}

func NewRepoConfigLoader(paths []string, settings *Config) *repoConfigLoader {
	r := &repoConfigLoader{}
	prepos, locationMap, treeMap, ignoredMap, defaultOpts := map[string]*RepoConfig{}, map[string]string{}, map[string]string{}, map[string][]string{}, map[string]string{"EPREFIX": settings.ValueDict["EPREFIX"], "EROOT": settings.ValueDict["EROOT"], "PORTAGE_CONFIGROOT": settings.ValueDict["PORTAGE_CONFIGROOT"], "ROOT": settings.ValueDict["ROOT"]}
	var portDir, portDirOverlay string

	if _, ok := settings.ValueDict["PORTAGE_REPOSITORIES"]; !ok {
		portDir = settings.ValueDict["PORTDIR"]
		portDirOverlay = settings.ValueDict["PORTDIR_OVERLAY"]
	}
	defaultOpts["sync-rsync-extra-opts"] = settings.ValueDict["PORTAGE_RSYNC_EXTRA_OPTS"]
	if err := r.parse(paths, prepos, settings.localConfig, defaultOpts); err != nil {
		WriteMsg(fmt.Sprintf("!!! Error while reading repo config file: %s\n", err), -1, nil)
		prepos = map[string]*RepoConfig{}
		prepos["DEFAULT"] = NewRepoConfig("DEFAULT", nil, settings.localConfig)
		locationMap = map[string]string{}
		treeMap = map[string]string{}
	}
	repoLocations := map[string]bool{}
	for repo := range prepos {
		repoLocations[repo] = true
	}
	var defaultPortDir string
	for _, repoLocation := range []string{"var/db/repos/gentoo", "usr/portage"} {
		defaultPortDir = path.Join(string(os.PathSeparator), strings.TrimPrefix(settings.ValueDict["EPREFIX"], string(os.PathSeparator)), repoLocation)
		if repoLocations[defaultPortDir] {
			break
		}
	}
	portDir = r.addRepositories(portDir, portDirOverlay, prepos, ignoredMap, settings.localConfig, defaultPortDir)
	if portDir != "" && strings.TrimSpace(portDir) == "" {
		portDir, _ = filepath.EvalSymlinks(portDir)
	}
	var ignoredRepos []sss
	for k, v := range ignoredMap {
		ignoredRepos = append(ignoredRepos, sss{k, v})
	}
	r.missingRepoNames = map[string]bool{}
	for _, repo := range prepos {
		if repo.location != "" && repo.missingRepoName {
			r.missingRepoNames[repo.location] = true
		}
	}
	for repoName, repo := range prepos {
		if repo.location == "" {
			if repoName != "DEFAULT" {
				if settings.localConfig && len(paths) > 0 {
					WriteMsgLevel(fmt.Sprintf("!!! %s\n", fmt.Sprintf("Section '%s' in repos.conf is missing location attribute", repo.Name)), 40, -1)
				}
				delete(prepos, repoName)
				continue
			}
		} else {
			if !SyncMode {
				if !isdirRaiseEaccess(repo.location) {
					WriteMsgLevel(fmt.Sprintf("!!! %s\n", fmt.Sprintf("Section '%s' in repos.conf has location attribute set to nonexistent directory: '%s'", repoName, repo.location)), 40, -1)
					if repo.Name != "gentoo" {
						delete(prepos, repoName)
						continue
					}
				}
				if repo.missingRepoName && repo.Name != repoName {
					WriteMsgLevel(fmt.Sprintf("!!! Section '%s' in repos.conf refers to repository without repository name set in '%s'\n", repoName, path.Join(repo.location, RepoNameLoc)), 40, -1)
					delete(prepos, repoName)
					continue
				}
				if repo.Name != repoName {
					WriteMsgLevel(fmt.Sprintf("!!! Section '%s' in repos.conf has name different from repository name '%s' set inside repository\n", repoName, repo.Name), 40, -1)
					delete(prepos, repoName)
					continue
				}
			}
			locationMap[repo.location] = repoName
			treeMap[repoName] = repo.location
		}
	}
	for repoName, repo := range prepos {
		names := map[string]bool{}
		names[repoName] = true
		if len(repo.Aliases) > 0 {
			var a [][2]string
			for v := range repo.Aliases {
				a = append(a, [2]string{v})
			}
			aliases := stackLists([][][2]string{a}, 1, false, false, false, false)
			for k := range aliases {
				names[k.value] = true
			}
		}
		for name := range names {
			if _, ok := prepos[name]; ok && prepos[name].location != "" {
				if name == repoName {
					continue
				}
				WriteMsgLevel(fmt.Sprintf("!!! Repository name or alias '%s', defined for repository '%s', overrides existing alias or repository.\n", name, repoName), 40, -1)
				continue
			}
			prepos[name] = repo
			if repo.location != "" {
				if _, ok := locationMap[repo.location]; !ok {
					locationMap[repo.location] = name
				}
				treeMap[name] = repo.location
			}
		}
	}
	mainRepo := prepos["DEFAULT"].mainRepo
	if _, ok := prepos[mainRepo]; mainRepo != "" || !ok {
		mainRepo = locationMap[portDir]
		if mainRepo != "" {
			prepos["DEFAULT"].mainRepo = mainRepo
		} else {
			prepos["DEFAULT"].mainRepo = ""
			if portDir != "" && !SyncMode {
				WriteMsg(fmt.Sprintf("!!! main-repo not set in DEFAULT and PORTDIR is empty.\n"), -1, nil)
			}
		}
	}
	if mainRepo != "" && prepos[mainRepo].priority == 0 {
		prepos[mainRepo].priority = -1000
	}
	var p []*RepoConfig
	for key, repo := range prepos {
		if repo.Name == key && key != "DEFAULT" && repo.location != "" {
			p = append(p, repo)
		}
	}
	sort.SliceStable(p, func(i, j int) bool {
		if p[i].priority != p[j].priority {
			return p[i].priority < p[j].priority
		}
		for k := 0; k < len(p[i].Name) && k < len(p[j].Name); k++ {
			if p[i].Name[k] != p[j].Name[k] {
				return p[i].Name[k] < p[j].Name[k]
			}
		}
		return len(p[i].Name) < len(p[j].Name)
	})
	preposOrder := []string{}
	for _, v := range p {
		preposOrder = append(preposOrder, v.Name)
	}
	r.Prepos = prepos
	r.preposOrder = preposOrder
	r.ignoredRepos = ignoredRepos
	r.locationMap = locationMap
	r.treeMap = treeMap
	r.preposChanged = true
	r.repoLocationList = []string{}

	for repoName, repo := range prepos {
		if repoName == "DEFAULT" {
			continue
		}
		if repo.masters == nil {
			if r.mainRepo() != nil && repoName != r.mainRepo().Name {
				repo.mastersRepo = []*RepoConfig{r.mainRepo()}
			} else {
				repo.mastersRepo = []*RepoConfig{}
			}
		} else {
			if len(repo.masters) > 0 {
				continue
			}
			masterRepos := []*RepoConfig{}
			for _, masterName := range repo.mastersRepo {
				if _, ok := prepos[masterName.Name]; !ok {
					layoutFilename := path.Join(repo.location, "metadata", "layout.conf")
					WriteMsgLevel(fmt.Sprintf("Unavailable repository '%s' referenced by masters entry in '%s'\n", masterName.Name, layoutFilename), 40, -1)
				} else {
					masterRepos = append(masterRepos, prepos[masterName.Name])
				}
			}
			repo.mastersRepo = masterRepos
		}
	}
	for repoName, repo := range prepos {
		if repoName == "DEFAULT" {
			continue
		}
		eclassLocations := []string{}
		for _, masterRepo := range repo.mastersRepo {
			eclassLocations = append(eclassLocations, masterRepo.location)
		}
		if !Ins(eclassLocations, repo.location) {
			eclassLocations = append(eclassLocations, repo.location)
		}
		if len(repo.eclassOverrides) != 0 {
			for otherRepoName := range r.treeMap {
				if _, ok := r.treeMap[otherRepoName]; ok {
					eclassLocations = append(eclassLocations, r.getLocationForName(otherRepoName))
				} else {
					WriteMsgLevel(fmt.Sprintf("Unavailable repository '%s' referenced by eclass-overrides entry for '%s'\n", otherRepoName, repoName), 40, -1)
				}
			}
		}
		repo.eclassLocations = eclassLocations
	}

	eclassDBs := map[string]*cache{}
	for repoName, repo := range prepos {
		if repoName == "DEFAULT" {
			continue
		}
		var eclassDB *cache = nil
		for _, eclassLocation := range repo.eclassLocations {
			treeDb := eclassDBs[eclassLocation]
			if treeDb == nil {
				treeDb = NewCache(eclassLocation, "")
				eclassDBs[eclassLocation] = treeDb
			}
			if eclassDB == nil {
				eclassDB = treeDb.copy()
			} else {
				eclassDB.append(treeDb)
			}
		}
		repo.eclassDb = eclassDB
	}
	for repoName, repo := range prepos {
		if repoName == "DEFAULT" {
			continue
		}
		if repo.mastersOrig == nil && r.mainRepo() != nil && repo.Name != r.mainRepo().Name && !SyncMode {
			WriteMsgLevel(fmt.Sprintf("!!! Repository '%s' is missing masters attribute in '%s'\n", repo.Name, path.Join(repo.location, "metadata", "layout.conf"))+fmt.Sprintf("!!! Set 'masters = %s' in this file for future compatibility\n", r.mainRepo().Name), 30, -1)
		}
	}
	r.preposChanged = true
	r.repoLocationList = []string{}
	r.checkLocations()
	return r
}

func loadRepositoryConfig(settings *Config, extraFiles string) *repoConfigLoader {
	repoConfigPaths := []string{}
	if pr, ok := settings.ValueDict["PORTAGE_REPOSITORIES"]; ok {
		repoConfigPaths = append(repoConfigPaths, pr)
	} else {
		if notInstalled {
			repoConfigPaths = append(repoConfigPaths, path.Join(PORTAGE_BASE_PATH, "cnf", "repos.conf"))
		} else {
			repoConfigPaths = append(repoConfigPaths, path.Join(settings.globalConfigPath, "repos.conf"))
		}
	}
	repoConfigPaths = append(repoConfigPaths, path.Join(settings.ValueDict["PORTAGE_CONFIGROOT"], UserConfigPath, "repos.conf"))
	if len(extraFiles) > 0 {
		repoConfigPaths = append(repoConfigPaths, extraFiles)
	}
	return NewRepoConfigLoader(repoConfigPaths, settings)
}

func getRepoName(repoLocation, cached string) string {
	if cached != "" {
		return cached
	}
	name, missing := (&RepoConfig{}).readRepoName(repoLocation)
	if missing {
		return ""
	}
	return name
}

func parseLayoutConf(repoLocation, repoName string) (map[string][]string, map[string][]string) {
	eapi := readCorrespondingEapiFile(path.Join(repoLocation, RepoNameLoc), "0")

	layoutFilename := path.Join(repoLocation, "metadata", "layout.conf")
	layoutFile := NewKeyValuePairFileLoader(layoutFilename, nil, nil)
	layoutData, layoutErrors := layoutFile.load()

	data := map[string][]string{}

	if v, ok := layoutData["masters"]; ok {
		data["masters"] = strings.Fields(v[0])
	}
	if v, ok := layoutData["aliases"]; ok {
		data["aliases"] = strings.Fields(v[0])
	}
	if v, ok := layoutData["eapis-banned"]; ok {
		data["eapis-banned"] = strings.Fields(v[0])
	}
	if v, ok := layoutData["eapis-deprecated"]; ok {
		data["eapis-deprecated"] = strings.Fields(v[0])
	}
	if v, ok := layoutData["sign-commit"]; ok && v[0] == "true" {
		data["sign-commit"] = []string{layoutData["sign-commit"][0]}
	} else {
		data["sign-commit"] = nil
	}
	if v, ok := layoutData["sign-manifest"]; !ok || (ok && v[0] == "true") {
		data["sign-manifest"] = []string{"true"}
	} else {
		data["sign-manifest"] = nil
	}
	if v, ok := layoutData["thin-manifest"]; ok && v[0] == "true" {
		data["thin-manifest"] = []string{"true"}
	} else {
		data["thin-manifest"] = nil
	}
	if v, ok := layoutData["repo-name"]; ok {
		data["repo-name"] = []string{genValidRepo(v[0])}
	} else {
		data["repo-name"] = []string{genValidRepo("")}
	}

	if v, ok := layoutData["Use-manifests"]; ok && strings.ToLower(v[0]) != "strict" {
		mp := strings.ToLower(v[0])
		if mp == "false" {
			data["allow-missing-manifest"] = []string{"true"}
			data["create-manifest"] = nil
			data["disable-manifest"] = []string{"true"}
		} else {
			data["allow-missing-manifest"] = []string{"true"}
			data["create-manifest"] = []string{"true"}
			data["disable-manifest"] = nil
		}
	} else {
		data["allow-missing-manifest"] = nil
		data["create-manifest"] = []string{"true"}
		data["disable-manifest"] = nil
	}

	cacheFormats := []string{}
	if v, ok := layoutData["cache-formats"]; ok {
		cacheFormats = strings.Fields(strings.ToLower(v[0]))
	} else {
		cacheFormats = []string{}
	}
	if len(cacheFormats) == 0 {
		if s, err := os.Stat(path.Join(repoLocation, "metadata", "md5-cache")); err == nil && s.IsDir() {
			cacheFormats = append(cacheFormats, "md5-dict")
		}
		if s, err := os.Stat(path.Join(repoLocation, "metadata", "ache")); err == nil && s.IsDir() {
			cacheFormats = append(cacheFormats, "pms")
		}
	}
	data["cache-formats"] = cacheFormats

	manifestHashes := layoutData["manifest-hashes"]
	manifestRequiredHashes := layoutData["manifest-required-hashes"]

	if len(manifestRequiredHashes) != 0 && len(manifestHashes) == 0 {
		repoName = getRepoName(repoLocation, repoName)
		//warnings.warn((_("Repository named '%(repo_name)s' specifies "
		//"'manifest-required-hashes' setting without corresponding "
		//"'manifest-hashes'. Portage will default it to match "
		//"the required set but please add the missing entry "
		//"to: %(layout_filename)s") %
		//{"repo_name": repo_name or 'unspecified',
		//"layout_filename":layout_filename}),
		//SyntaxWarning)
		manifestHashes = manifestRequiredHashes
	}

	if len(manifestHashes) != 0 {
		if len(manifestRequiredHashes) == 0 {
			manifestRequiredHashes = manifestHashes
		}
		manifestRequiredHashes = strings.Fields(strings.ToUpper(manifestRequiredHashes[0]))
		manifestHashes = strings.Fields(strings.ToUpper(manifestHashes[0]))
		missingRequiredHashes := []string{}
		for _, v := range manifestRequiredHashes {
			if !Ins(manifestHashes, v) {
				missingRequiredHashes = append(missingRequiredHashes, v)
			}
		}
		if len(missingRequiredHashes) > 0 {
			repoName = getRepoName(repoLocation, repoName)
			//warnings.warn((_("Repository named '%(repo_name)s' has a "
			//"'manifest-hashes' setting that does not contain "
			//"the '%(hash)s' hashes which are listed in "
			//"'manifest-required-hashes'. Please fix that file "
			//"if you want to generate valid manifests for this "
			//"repository: %(layout_filename)s") %
			//{"repo_name": repo_name or 'unspecified',
			//"hash": ' '.join(missing_required_hashes),
			//"layout_filename":layout_filename}),
			//SyntaxWarning)
		}
		unsupported_hashes := []string{}
		for _, v := range manifestHashes {
			if !getValidChecksumKeys()[v] {
				unsupported_hashes = append(unsupported_hashes, v)
			}
		}
		if len(unsupported_hashes) > 0 {

			repoName = getRepoName(repoLocation, repoName)
			//warnings.warn((_("Repository named '%(repo_name)s' has a "
			//"'manifest-hashes' setting that contains one "
			//"or more hash types '%(hashes)s' which are not supported by "
			//"this portage version. You will have to upgrade "
			//"portage if you want to generate valid manifests for "
			//"this repository: %(layout_filename)s") %
			//{"repo_name": repo_name or 'unspecified',
			//"hashes":" ".join(sorted(unsupported_hashes)),
			//"layout_filename":layout_filename}),
			//DeprecationWarning)
		}
	}

	data["manifest-hashes"] = manifestHashes
	data["manifest-required-hashes"] = manifestRequiredHashes

	if v, ok := layoutData["update-changelog"]; ok && strings.ToLower(v[0]) == "true" {
		data["update-changelog"] = v
	}

	rawFormats := layoutData["profile-formats"]
	if rawFormats == nil {
		if eapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi) {
			rawFormats = []string{"portage-1"}
		} else {

			rawFormats = []string{"portage-1-compat"}
		}
	} else {
		rawFormats = strings.Fields(rawFormats[0])

		unknown := []string{}
		for _, v := range rawFormats {
			_, ok := validProfileFormats[v]
			if !ok {
				unknown = append(unknown, v)
			}
		}
		if len(unknown) > 0 {
			repoName = getRepoName(repoLocation, repoName)
			//warnings.warn((_("Repository named '%(repo_name)s' has unsupported "
			//"profiles in use ('profile-formats = %(unknown_fmts)s' setting in "
			//"'%(layout_filename)s; please upgrade portage.") %
			//dict(repo_name=repo_name or 'unspecified',
			//layout_filename=layout_filename,
			//	unknown_fmts=" ".join(unknown))),
			//DeprecationWarning)
		}
		rf := []string{}
		for _, v := range rawFormats {
			if validProfileFormats[v] {
				rf = append(rf, v)
			}
		}
		rawFormats = rf
	}
	data["profile-formats"] = rawFormats

	e, ok := layoutData["profile_eapi_when_unspecified"]
	if ok {
		eapi = e[0]
		if Ins(rawFormats, "profile-default-eapi") {
			//warnings.warn((_("Repository named '%(repo_name)s' has "
			//"profile_eapi_when_unspecified setting in "
			//"'%(layout_filename)s', but 'profile-default-eapi' is "
			//"not listed in the profile-formats field. Please "
			//"report this issue to the repository maintainer.") %
			//dict(repo_name=repo_name or 'unspecified',
			//layout_filename=layout_filename)),
			//SyntaxWarning)
		} else if !eapiIsSupported(eapi) {
			//warnings.warn((_("Repository named '%(repo_name)s' has "
			//"unsupported EAPI '%(eapi)s' setting in "
			//"'%(layout_filename)s'; please upgrade portage.") %
			//dict(repo_name=repo_name or 'unspecified',
			//eapi=eapi, layout_filename=layout_filename)),
			//SyntaxWarning)
		} else {
			data["profile_eapi_when_unspecified"] = []string{eapi}
		}
	}

	return data, layoutErrors
}
