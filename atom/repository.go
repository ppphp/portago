package atom

import (
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
	allowMissingManifest, allowProvideVirtual, autoSync, cacheFormats, cloneDepth, createManifest, disableManifest, eapi, eclassDb, eclassLocations, findInvalidPathChar, format, location, mainRepo, manifest_hashes, manifest_required_hashes, missing_repo_name, module_specific_options, name, portage1_profiles, portage1_profiles_compat, profile_formats, sign_commit, sign_manifest, strict_misc_digests, sync_allow_hardlinks, sync_depth, sync_hooks_only_on_change, sync_openpgp_key_path, sync_openpgp_key_refresh_retry_count, sync_openpgp_key_refresh_retry_delay_exp_base, sync_openpgp_key_refresh_retry_delay_max, sync_openpgp_key_refresh_retry_delay_mult, sync_openpgp_key_refresh_retry_overall_timeout, sync_rcu, sync_rcu_spare_snapshots, sync_rcu_store_dir, sync_rcu_ttl_days, sync_type, sync_umask, sync_uri, sync_user, thin_manifest, update_changelog, user_location, _eapis_banned, _eapis_deprecated, _masters_orig string
	force, aliases, eclassOverrides, masters                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     map[string]bool
	localConfig                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  bool
	priority int
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
	if ok{
		r.autoSync = strings.ToLower(strings.TrimSpace(autoSync))
	} else{
		r.autoSync = "yes"
	}
	r.cloneDepth = repoOpts["clone-depth"]
	r.sync_depth = repoOpts["sync-depth"]


	return r
}
