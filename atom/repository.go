package atom

import (
	"os"
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
	allowMissingManifest, allowProvideVirtual, autoSync, cacheFormats, cloneDepth, createManifest, disableManifest, eapi, eclassDb, eclassLocations, findInvalidPathChar, format, location, mainRepo, manifest_hashes, manifest_required_hashes, missing_repo_name, name, portage1_profiles, portage1_profiles_compat, profile_formats, sign_commit, sign_manifest, sync_depth, sync_openpgp_key_path, sync_openpgp_key_refresh_retry_count, sync_openpgp_key_refresh_retry_delay_exp_base, sync_openpgp_key_refresh_retry_delay_max, sync_openpgp_key_refresh_retry_delay_mult, sync_openpgp_key_refresh_retry_overall_timeout, syncRcuStoreDir, sync_type, sync_umask, sync_uri, sync_user, thin_manifest, update_changelog, user_location, _eapis_banned, _eapis_deprecated, _masters_orig string
	force, aliases, eclassOverrides, masters                                           map[string]bool
	moduleSpecificOptions                                                              map[string]string
	localConfig, syncHooksOnlyOnChange, strictMiscDigests, syncAllowHardlinks, syncRcu bool
	priority, syncRcuSpareSnapshots, syncRcuTtlDays                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    int
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
	r.sync_openpgp_key_refresh_retry_count = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_count", "_", "-", -1)]
	r.sync_openpgp_key_refresh_retry_delay_exp_base = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_delay_exp_base", "_", "-", -1)]
	r.sync_openpgp_key_refresh_retry_delay_max = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_delay_max", "_", "-", -1)]
	r.sync_openpgp_key_refresh_retry_delay_mult = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_delay_mult", "_", "-", -1)]
	r.sync_openpgp_key_refresh_retry_overall_timeout = repoOpts[strings.Replace("sync_openpgp_key_refresh_retry_overall_timeout", "_", "-", -1)]

	if s, ok := repoOpts["sync-rcu"]; ok {
		r.syncRcu = strings.ToLower(s) == "true" || strings.ToLower(s) == "yes"
	} else {
		r.syncRcu = strings.ToLower("false") == "true"
	}

	r.syncRcuStoreDir = repoOpts["sync-rcu-store-dir"]
	r.syncRcuSpareSnapshots, _ = strconv.Atoi(strings.TrimSpace(repoOpts["sync-rcu-spare-snapshots"]))
	r.syncRcuTtlDays, _ = strconv.Atoi(strings.TrimSpace(repoOpts["sync-rcu-ttl-days"]))

	r.moduleSpecificOptions =map[string]string {}
	r.format = strings.TrimSpace(repoOpts["format"])

	if s, _:=os.Stat(repoOpts["location"]); s.IsDir() ||syncMode {
		r.user_location= repoOpts["location"]
		r.location, _  = filepath.EvalSymlinks(repoOpts["location"])
	}
	missing := true
	r.name = name
	if len(r.location) > 0 {

	}

	return r
}
