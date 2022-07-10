package repository

import (
	"bufio"
	"fmt"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/dbapi/FetchlistDict"
	eapi2 "github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/manifest"
	"github.com/ppphp/portago/pkg/portage/pcache"
	"github.com/ppphp/portago/pkg/portage/vars"
	"github.com/ppphp/portago/pkg/repository/FindInvalidPathChar"
	"github.com/ppphp/portago/pkg/repository/validrepo"
	"github.com/ppphp/portago/pkg/util"
	"golang.org/x/sys/unix"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

type RepoConfig[T interfaces.ISettings] struct {
	AutoSync, cloneDepth, Eapi, format, Location, mainRepo, Name, syncDepth, syncOpenpgpKeyPath, syncOpenpgpKeyRefreshRetryCount, syncOpenpgpKeyRefreshRetryDelayExpBase, syncOpenpgpKeyRefreshRetryDelayMax, syncOpenpgpKeyRefreshRetryDelayMult, syncOpenpgpKeyRefreshRetryOverallTimeout, syncRcuStoreDir, SyncType, syncUmask, SyncUri, syncUser, userLocation string
	eclassDb                                                                                                                                                                                                                                                                                                                                                       *pcache.Cache
	eapisBanned, eapisDeprecated, force, Aliases, eclassOverrides, manifestHashes, manifestRequiredHashes                                                                                                                                                                                                                                                          map[string]bool
	cacheFormats, ProfileFormats, Masters, eclassLocations, mastersOrig                                                                                                                                                                                                                                                                                            []string
	MastersRepo                                                                                                                                                                                                                                                                                                                                                    []*RepoConfig[T]
	moduleSpecificOptions                                                                                                                                                                                                                                                                                                                                          map[string]string
	localConfig, syncHooksOnlyOnChange, strictMiscDigests, syncAllowHardlinks, syncRcu, missingRepoName, signCommit, signManifest, thinManifest, allowProvideVirtual, createManifest, disableManifest, updateChangelog, Portage1Profiles, portage1ProfilesCompat, allowMissingManifest                                                                             bool
	priority, syncRcuSpareSnapshots, syncRcuTtlDays                                                                                                                                                                                                                                                                                                                int
	findInvalidPathChar                                                                                                                                                                                                                                                                                                                                            func(string, int, int) int
}

func NewRepoConfig[T interfaces.ISettings](name string, repoOpts map[string]string, localConfig bool) *RepoConfig[T] {
	r := &RepoConfig[T]{}
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
	r.Masters = m
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
	if s, err := os.Stat(location); err == nil && (s.IsDir() || vars.SyncMode) {
		r.userLocation = location
		location, _ = filepath.EvalSymlinks(location)
	} else {
		location = ""
	}
	r.Location = location
	missing := true
	r.Name = name
	if len(r.Location) > 0 {
		r.Name, missing = r.readValidRepoName(r.Location)
		if missing {
			if len(name) > 0 {
				r.Name = name
			}
			if vars.SyncMode {
				missing = false
			}
		}
	} else if name == "DEFAULT" {
		missing = false
	}
	r.Eapi = ""
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
	r.Portage1Profiles = true
	r.portage1ProfilesCompat = false
	r.findInvalidPathChar = FindInvalidPathChar.FindInvalidPathChar
	r.mastersOrig = []string{}

	if len(r.Location) > 0 {
		layoutData, _ := ParseLayoutConf[T](r.Location, r.Name)
		r.mastersOrig = layoutData["masters"]
		if r.Masters == nil {
			r.Masters = layoutData["masters"]
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
			r.allowMissingManifest = layoutData["allow-missing-manifest"][0] == "y"
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
			for _, k := range layoutData["manifest-hashes"] {
				r.manifestHashes[k] = true
			}
		}
		if len(layoutData["manifest-required-hashes"]) > 0 {
			for _, k := range layoutData["manifest-required-hashes"] {
				r.manifestRequiredHashes[k] = true
			}
		}
		if len(layoutData["profile-formats"]) > 0 {
			r.ProfileFormats = layoutData["profile-formats"]
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
			r.Eapi = layoutData["profile_eapi_when_unspecified"][0]
		} else {
			r.Eapi = "0"
		}

		eapi := util.ReadCorrespondingEapiFile(path.Join(r.Location, _const.RepoNameLoc), r.Eapi)
		r.Portage1Profiles = eapi2.EapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi)
		for _, v := range layoutData["profile-formats"] {
			if Portage1ProfilesAllowDirectories[v] {
				r.Portage1Profiles = true
				break
			}
		}
		r.portage1ProfilesCompat = !eapi2.EapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi) && len(layoutData["profile-formats"]) == 1 && layoutData["profile-formats"][0] == "portage-1-compat"
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

func (r *RepoConfig[T]) setModuleSpecificOpt(opt, val string) {
	r.moduleSpecificOptions[opt] = val
}

func (r *RepoConfig[T]) eapiIsBanned(eapi string) bool {
	return r.eapisBanned[eapi]
}

func (r *RepoConfig[T]) eapiIsDeprecated(eapi string) bool {
	return r.eapisDeprecated[eapi]
}

/*
// true, false
func (r *RepoConfig) iterPregeneratedCaches(auxdbkeys []string, readonly, force bool) {
	formats := r.cacheFormats
	if len(formats) == 0 {
		if !force {
			return
		}
		formats = []string{"md5-dict"}
	}
	ret := []*database{}
	for _, fmt := range formats {
		name := ""
		var database func(string, string, map[string]bool, bool) *database
		if fmt == "pms" {
			name = "metadata/cache"
			database = NewDatabase
		} else if fmt == "md5-dict" {
			name = "metadata/md5-cache"
			database = md5_database
		}
		if name != "" {
			ret = append(ret, database(r.Location, name, auxdbkeys, readonly = readonly))
		}
	}
	return ret
}


// true, false
func (r *RepoConfig) get_pregenerated_cache(auxdbkeys []string, readonly, force bool) {
	r.iterPregeneratedCaches(auxdbkeys, readonly, force)
}
*/

// nil, false
func (r *RepoConfig[T]) load_manifest(pkgdir, distdir string, fetchlist_dict *FetchlistDict.FetchlistDict[T], from_scratch bool) *manifest.Manifest[T] {
	if r.disableManifest {
		from_scratch = true
	}
	return manifest.NewManifest[T](pkgdir, distdir, fetchlist_dict, from_scratch,
		r.thinManifest, r.allowMissingManifest, r.createManifest,
		r.manifestHashes, r.manifestRequiredHashes,
		func(s string) int { return r.findInvalidPathChar(s, 0, 0) },
		r.strictMiscDigests)
}

func (r *RepoConfig[T]) update(new_repo *RepoConfig[T]) {

	r.Aliases = new_repo.Aliases
	r.allowMissingManifest = new_repo.allowMissingManifest
	r.allowProvideVirtual = new_repo.allowProvideVirtual
	r.AutoSync = new_repo.AutoSync
	r.cacheFormats = new_repo.cacheFormats
	r.cloneDepth = new_repo.cloneDepth
	r.createManifest = new_repo.createManifest
	r.disableManifest = new_repo.disableManifest
	r.Eapi = new_repo.Eapi
	r.eclassDb = new_repo.eclassDb
	r.eclassLocations = new_repo.eclassLocations
	r.eclassOverrides = new_repo.eclassOverrides
	r.findInvalidPathChar = new_repo.findInvalidPathChar
	r.force = new_repo.force
	r.format = new_repo.format
	r.localConfig = new_repo.localConfig
	r.Location = new_repo.Location
	r.mainRepo = new_repo.mainRepo
	r.manifestHashes = new_repo.manifestHashes
	r.manifestRequiredHashes = new_repo.manifestRequiredHashes
	r.Masters = new_repo.Masters
	r.moduleSpecificOptions = new_repo.moduleSpecificOptions
	r.Name = new_repo.Name
	r.Portage1Profiles = new_repo.Portage1Profiles
	r.portage1ProfilesCompat = new_repo.portage1ProfilesCompat
	r.priority = new_repo.priority
	r.ProfileFormats = new_repo.ProfileFormats
	r.signCommit = new_repo.signCommit
	r.signManifest = new_repo.signManifest
	r.strictMiscDigests = new_repo.strictMiscDigests
	r.syncAllowHardlinks = new_repo.syncAllowHardlinks
	r.syncDepth = new_repo.syncDepth
	r.syncHooksOnlyOnChange = new_repo.syncHooksOnlyOnChange
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

	if new_repo.Name != "" {
		r.missingRepoName = new_repo.missingRepoName
	}
}

func (r *RepoConfig[T]) writable() bool {
	s, _ := os.Stat(util.FirstExisting(r.Location))
	return s.Mode()&unix.W_OK != 0
}

func (r *RepoConfig[T]) readValidRepoName(repoPath string) (string, bool) {
	name, missing := r.readRepoName(repoPath)
	name = validrepo.GenValidRepo(name)
	if len(name) == 0 {
		name = "x-" + path.Base(repoPath)
		name = validrepo.GenValidRepo(name)
	}
	return name, missing
}

func (r *RepoConfig[T]) readRepoName(repoPath string) (string, bool) {
	repoNamePath := path.Join(repoPath, _const.RepoNameLoc)
	f, _ := os.Open(repoNamePath)
	if f != nil {
		defer f.Close()
	}
	b := bufio.NewReader(f)
	line, _, _ := b.ReadLine()
	return string(line), false
}

func (r *RepoConfig[T]) info_string() string {
	indent := "    "
	repo_msg := []string{}
	repo_msg = append(repo_msg, r.Name)
	if len(r.format) != 0 {
		repo_msg = append(repo_msg, indent+"format: "+r.format)
	}
	if len(r.Location) != 0 {
		repo_msg = append(repo_msg, indent+"location: "+r.Location)
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
	if len(r.Masters) > 0 {
		rm := []string{}
		for _, master := range r.Masters {
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
	for o, v := range r.moduleSpecificOptions {
		if v != "" {
			repo_msg = append(repo_msg, indent+o+": "+v)
		}
	}
	repo_msg = append(repo_msg, "")
	return strings.Join(repo_msg, "\n")
}
