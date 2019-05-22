package atom

import (
	"bufio"
	"fmt"
	"github.com/google/shlex"
	"github.com/ppphp/configparser"
	"golang.org/x/sys/unix"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	allowMissingManifest, autoSync, cloneDepth, eapi, format, location, mainRepo, manifestHashes, manifestRequiredHashes, name, syncDepth, syncOpenpgpKeyPath, syncOpenpgpKeyRefreshRetryCount, syncOpenpgpKeyRefreshRetryDelayExpBase, syncOpenpgpKeyRefreshRetryDelayMax, syncOpenpgpKeyRefreshRetryDelayMult, syncOpenpgpKeyRefreshRetryOverallTimeout, syncRcuStoreDir, syncType, syncUmask, syncUri, syncUser, userLocation, mastersOrig string
	eclassDb                                                                                                                                                                                                                                                                                                                                                                                                                                  *cache
	eapisBanned, eapisDeprecated, force, aliases, eclassOverrides                                                                                                                                                                                                                                                                                                                                                                             map[string]bool
	cacheFormats, profileFormats, masters, eclassLocations                                                                                                                                                                                                                                                                                                                                                                                    []string
	mastersRepo                                                                                                                                                                                                                                                                                                                                                                                                                               []*repoConfig
	moduleSpecificOptions                                                                                                                                                                                                                                                                                                                                                                                                                     map[string]string
	localConfig, syncHooksOnlyOnChange, strictMiscDigests, syncAllowHardlinks, syncRcu, missingRepoName, signCommit, signManifest, thinManifest, allowProvideVirtual, createManifest, disableManifest, updateChangelog, portage1Profiles, portage1ProfilesCompat                                                                                                                                                                              bool
	priority, syncRcuSpareSnapshots, syncRcuTtlDays                                                                                                                                                                                                                                                                                                                                                                                           int
	findInvalidPathChar                                                                                                                                                                                                                                                                                                                                                                                                                       func(string, int, int) int
}

func (r *repoConfig) setModuleSpecificOpt(opt, val string) {
	r.moduleSpecificOptions[opt] = val
}

func (r *repoConfig) eapiIsBanned(eapi string) bool {
	return r.eapisBanned[eapi]
}

func (r *repoConfig) eapiIsDeprecated(eapi string) bool {
	return r.eapisDeprecated[eapi]
}

func (r *repoConfig) iterPregeneratedCaches(auxdbkeys string, readonly, force bool) { // truefalse
	formats := r.cacheFormats
	if len(formats) == 0 {
		if !force {
			return
		}
		formats = []string{"md5-dict"}
	}
	//for _, fmt := range formats{
	//	name
	//}
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
		r.syncType = strings.TrimSpace(syncType)
	}
	syncUmask, ok := repoOpts["sync-umask"]
	if ok {
		r.syncUmask = strings.TrimSpace(syncUmask)
	}
	syncUri, ok := repoOpts["sync-uri"]
	if ok {
		r.syncUri = strings.TrimSpace(syncUri)
	}
	syncUser, ok := repoOpts["sync-user"]
	if ok {
		r.syncUser = strings.TrimSpace(syncUser)
	}
	autoSync, ok := repoOpts["auto-sync"]
	if ok {
		r.autoSync = strings.ToLower(strings.TrimSpace(autoSync))
	} else {
		r.autoSync = "yes"
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

	if s, err := os.Stat(repoOpts["location"]); err == nil && (s.IsDir() || SyncMode) {
		r.userLocation = repoOpts["location"]
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
	r.allowMissingManifest = ""
	r.allowProvideVirtual = false
	r.createManifest = true
	r.disableManifest = false
	r.manifestHashes = ""
	r.manifestRequiredHashes = ""
	r.updateChangelog = false
	r.cacheFormats = nil
	r.portage1Profiles = true
	r.portage1ProfilesCompat = false
	r.findInvalidPathChar = findInvalidPathChar
	r.mastersOrig = ""

	if len(r.location) > 0 {
		layoutData, _ := parseLayoutConf(r.location, r.name)
		r.mastersOrig = layoutData["masters"][0]
		if r.masters == nil {
			r.masters = layoutData["masters"]
		}
		if (localConfig || f["aliases"]) && len(layoutData["aliases"]) != 0 {
			aliases := r.aliases
			if len(aliases) == 0 {
				aliases = map[string]bool{}
			}
			r.aliases = map[string]bool{}
			for _, s := range layoutData["aliases"] {
				r.aliases[s] = true
			}
			for k := range aliases {
				r.aliases[k] = true
			}
		}
		if len(layoutData["allow-missing-manifest"]) > 0 {
			r.allowMissingManifest = layoutData["allow-missing-manifest"][0]
		}
		if len(layoutData["repo-name"]) > 0 {
			r.name = layoutData["repo-name"][0]
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
	prepos               map[string]*repoConfig
	preposOrder          []string
	missingRepoNames     map[string]bool
	preposChanged        bool
	repoLocationList     []string
	ignoredRepos         []sss
}

func (r *repoConfigLoader) addRepositories(portDir, portdirOverlay string, prepos map[string]*repoConfig, ignoredMap map[string][]string, localConfig bool, defaultPortdir string) string {
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
	if prepos["DEFAULT"].aliases != nil {
		s := []string{}
		for k := range prepos["DEFAULT"].aliases {
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
		reposConf := map[string]*repoConfig{}
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
				reposConfOpts := reposConf[repo.name]
				if reposConfOpts != nil {
					if reposConfOpts.aliases != nil {
						repo.aliases = reposConfOpts.aliases
					}
					if reposConfOpts.autoSync != "" {
						repo.autoSync = reposConfOpts.autoSync
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
					if reposConfOpts.syncType != "" {
						repo.syncType = reposConfOpts.syncType
					}
					if reposConfOpts.syncUmask != "" {
						repo.syncUmask = reposConfOpts.syncUmask
					}
					if reposConfOpts.syncUri != "" {
						repo.syncUri = reposConfOpts.syncUri
					}
					if reposConfOpts.syncUser != "" {
						repo.syncUser = reposConfOpts.syncUser
					}
				}
				if _, ok := prepos[repo.name]; ok {
					oldLocation := prepos[repo.name].location
					if oldLocation != "" && oldLocation != repo.location && !(basePriority == 0 && oldLocation == defaultPortdir) {
						if ignoredMap[repo.name] == nil {
							ignoredMap[repo.name] = []string{}
						}
						ignoredMap[repo.name] = append(ignoredMap[repo.name], oldLocation)
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

func (r *repoConfigLoader) parse(paths []string, prepos map[string]*repoConfig, localConfig bool, defaultOpts map[string]string) error {
	parser := configparser.NewConfiguration()
	//parser.Default(defaultopts)
	recursivePaths := []string{}
	for _, p := range paths {
		recursivePaths = append(recursivePaths, recursiveFileList(p)...)
	}

	readConfigs(parser, recursivePaths)

	prepos["DEFAULT"] = NewRepoConfig("DEFAULT", parser.Default(), localConfig)
	secs, err := parser.Sections("")
	if err != nil {
		return err
	}
	for _, sname := range secs {
		optdict := map[string]string{}
		repo := NewRepoConfig(sname.Name(), optdict, localConfig)
		for o := range moduleSpecificOptions(repo) {
			if v := sname.ValueOf(o); v != "" {
				repo.setModuleSpecificOpt(o, v)
			}
			prepos[sname.Name()] = repo
		}
	}
	return nil
}

func (r *repoConfigLoader) mainRepoLocation() string {
	mainRepo := r.prepos["DEFAULT"].mainRepo
	if _, ok := r.prepos[mainRepo]; mainRepo == "" || !ok {
		return ""
	}
	return r.prepos[mainRepo].location
}

func (r *repoConfigLoader) mainRepo() *repoConfig {
	mainRepo := r.prepos["DEFAULT"].mainRepo
	if mainRepo == "" {
		return nil
	}
	return r.prepos[mainRepo]
}

func (r *repoConfigLoader) RepoLocationList() []string {
	if r.preposChanged {
		repoLocationList := []string{}
		for _, repo := range r.preposOrder {
			if r.prepos[repo].location != "" {
				repoLocationList = append(repoLocationList, r.prepos[repo].location)
			}
		}
		r.repoLocationList = repoLocationList
		r.preposChanged = false
	}
	return r.repoLocationList
}

func (r *repoConfigLoader) checkLocations() {
	for name, re := range r.prepos {
		if name != "DEFAULT" {
			if re.location != "" {
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

func (r *repoConfigLoader) reposWithProfiles() []*repoConfig {
	rp := []*repoConfig{}
	for _, repoName := range r.preposOrder {
		repo := r.prepos[repoName]
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

func (r *repoConfigLoader) getRepoForLocation(location string) *repoConfig {
	return r.prepos[r.getNameForLocation(location)]
}

func (r *repoConfigLoader) getitem(repoName string) *repoConfig {
	return r.prepos[repoName]
}

func (r *repoConfigLoader) delitem(repoName string) {
	if repoName == r.prepos["DEFAULT"].mainRepo {
		r.prepos["DEFAULT"].mainRepo = ""
	}
	location := r.prepos[repoName].location
	delete(r.prepos, repoName)
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
	_, ok := r.prepos[repoName]
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
	config_string := ""
	repoName := []string{}
	for r := range r.prepos {
		if r != "DEFAULT" {
			repoName = append(repoName, r)
		}
	}
	sort.Strings(repoName)
	repoName = append(repoName, "DEFAULT")
	for _, v := range repoName {
		config_string += fmt.Sprintf("\n[%s]\n", v)
		repo := r.prepos[v]
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("strict_misc_digests", "_", "-", -1), repo.strictMiscDigests)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_allow_hardlinks", "_", "-", -1), repo.syncAllowHardlinks)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_rcu", "_", "-", -1), repo.syncRcu)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("auto_sync", "_", "-", -1), repo.autoSync)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("clone_depth", "_", "-", -1), repo.cloneDepth)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("format", "_", "-", -1), repo.format)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("location", "_", "-", -1), repo.location)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("main_repo", "_", "-", -1), repo.mainRepo)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("priority", "_", "-", -1), repo.priority)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_depth", "_", "-", -1), repo.syncDepth)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_path", "_", "-", -1), repo.syncOpenpgpKeyPath)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_count", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryCount)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_delay_exp_base", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryDelayExpBase)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_delay_max", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryDelayMax)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_delay_mult", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryDelayMult)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_openpgp_key_refresh_retry_overall_timeout", "_", "-", -1), repo.syncOpenpgpKeyRefreshRetryOverallTimeout)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_rcu_spare_snapshots", "_", "-", -1), repo.syncRcuSpareSnapshots)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_rcu_store_dir", "_", "-", -1), repo.syncRcuStoreDir)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_rcu_ttl_days", "_", "-", -1), repo.syncRcuTtlDays)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_type", "_", "-", -1), repo.syncType)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_umask", "_", "-", -1), repo.syncUmask)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_uri", "_", "-", -1), repo.syncUri)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("sync_user", "_", "-", -1), repo.syncUser)
		aliases := []string{}
		for k := range repo.aliases {
			aliases = append(aliases, k)
		}
		sort.Strings(aliases)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("aliases", "_", "-", -1), strings.Join(aliases, " "))
		eclassOverrides := []string{}
		for k := range repo.eclassOverrides {
			eclassOverrides = append(eclassOverrides, k)
		}
		sort.Strings(eclassOverrides)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("eclass_overrides", "_", "-", -1), strings.Join(eclassOverrides, " "))
		force := []string{}
		for k := range repo.force {
			force = append(force, k)
		}
		sort.Strings(force)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("force", "_", "-", -1), strings.Join(force, " "))
		masters := []string{}
		for _, k := range repo.mastersRepo {
			masters = append(masters, k.name)
		}
		sort.Strings(masters)
		config_string += fmt.Sprintf("%s = %s\n", strings.Replace("masters", "_", "-", -1), strings.Join(masters, " "))
		if v == "DEFAULT" {
			config_string += ""
		}

		keys := []string{}
		for o := range repo.moduleSpecificOptions {
			keys = append(keys, o)
		}
		sort.Strings(keys)
		for _, v := range keys {
			config_string += fmt.Sprintf("%s = %s\n", v, repo.moduleSpecificOptions[v])
		}
	}
	return strings.TrimPrefix(config_string, "\n")
}

func NewRepoConfigLoader(paths []string, settings *Config) *repoConfigLoader {
	r := &repoConfigLoader{}
	prepos, locationMap, treeMap, ignoredMap, defaultOpts := map[string]*repoConfig{}, map[string]string{}, map[string]string{}, map[string][]string{}, map[string]string{"EPREFIX": settings.ValueDict["EPREFIX"], "EROOT": settings.ValueDict["EROOT"], "PORTAGE_CONFIGROOT": settings.ValueDict["PORTAGE_CONFIGROOT"], "ROOT": settings.ValueDict["ROOT"]}
	portDir, portDirOverlay := "", ""

	if _, ok := settings.ValueDict["PORTAGE_REPOSITORIES"]; !ok {
		portDir = settings.ValueDict["PORTDIR"]
		portDirOverlay = settings.ValueDict["PORTDIR_OVERLAY"]
	}
	defaultOpts["sync-rsync-extra-opts"] = settings.ValueDict["PORTAGE_RSYNC_EXTRA_OPTS"]
	if err := r.parse(paths, prepos, settings.localConfig, defaultOpts); err != nil {
		WriteMsg(fmt.Sprintf("!!! Error while reading repo config file: %s\n", err), -1, nil)
		prepos = map[string]*repoConfig{}
		prepos["DEFAULT"] = NewRepoConfig("DEFAULT", nil, settings.localConfig)
		locationMap = map[string]string{}
		treeMap = map[string]string{}
	}
	defaultPortDir := path.Join(string(os.PathSeparator), strings.TrimPrefix(settings.ValueDict["EPREFIX"], string(os.PathSeparator)), "usr", "portage")
	portDir = r.addRepositories(portDir, portDirOverlay, prepos, ignoredMap, settings.localConfig, defaultPortDir)
	if portDir != "" && strings.TrimSpace(portDir) == "" {
		portDir, _ = filepath.EvalSymlinks(portDir)
	}
	ignoredRepos := []sss{}
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
					writeMsgLevel(fmt.Sprintf("!!! %s\nSection '%s' in repos.conf is missing location attribute", repo.name), 40, -1)
				}
				delete(prepos, repoName)
				continue
			}
		} else {
			if !SyncMode {
				if !isdirRaiseEaccess(repo.location) {
					writeMsgLevel(fmt.Sprintf("!!! %s\nSection '%s' in repos.conf has location attribute set to nonexistent directory: '%s'", repoName, repo.location), 40, -1)
					if repo.name != "gentoo" {
						delete(prepos, repoName)
						continue
					}
				}
				if repo.missingRepoName && repo.name != repoName {
					writeMsgLevel(fmt.Sprintf("!!! %s\nSection '%s' in repos.conf refers to repository without repository name set in '%s'", repoName, path.Join(repo.location, RepoNameLoc)), 40, -1)
					delete(prepos, repoName)
					continue
				}
				if repo.name != repoName {
					writeMsgLevel(fmt.Sprintf("!!! %s\nSection '%s' in repos.conf has name different from repository name '%s' set inside repository", repoName, repo.name), 40, -1)
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
		if len(repo.aliases) > 0 {
			a := [][2]string{}
			for v := range repo.aliases {
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
				writeMsgLevel(fmt.Sprintf("!!! Repository name or alias '%s', defined for repository '%s', overrides existing alias or repository.\n", name, repoName), 40, -1)
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
	p := []*repoConfig{}
	for key, repo := range prepos {
		if repo.name == key && key != "DEFAULT" && repo.location != "" {
			p = append(p, repo)
		}
	}
	sort.SliceStable(p, func(i, j int) bool {
		if p[i].priority != p[j].priority {
			return p[i].priority < p[j].priority
		}
		for k := 0; k < len(p[i].name) && k < len(p[j].name); k++ {
			if p[i].name[k] != p[j].name[k] {
				return p[i].name[k] < p[j].name[k]
			}
		}
		return len(p[i].name) < len(p[j].name)
	})
	preposOrder := []string{}
	for _, v := range p {
		preposOrder = append(preposOrder, v.name)
	}
	r.prepos = prepos
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
			if r.mainRepo() != nil && repoName != r.mainRepo().name {
				repo.mastersRepo = []*repoConfig{r.mainRepo()}
			} else {
				repo.mastersRepo = []*repoConfig{}
			}
		} else {
			if len(repo.masters) > 0 {
				continue
			}
			masterRepos := []*repoConfig{}
			for _, masterName := range repo.mastersRepo {
				if _, ok := prepos[masterName.name]; !ok {
					layoutFilename := path.Join(repo.location, "metadata", "layout.conf")
					writeMsgLevel(fmt.Sprintf("Unavailable repository '%s' referenced by masters entry in '%s'\n", masterName.name, layoutFilename), 40, -1)
				} else {
					masterRepos = append(masterRepos, prepos[masterName.name])
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
		in := false
		for _, v := range eclassLocations {
			if repo.location == v {
				in = true
				break
			}
		}
		if !in {
			eclassLocations = append(eclassLocations, repo.location)
		}
		if len(repo.eclassOverrides) != 0 {
			for otherRepoName := range r.treeMap {
				if _, ok := r.treeMap[otherRepoName]; ok {
					eclassLocations = append(eclassLocations, r.getLocationForName(otherRepoName))
				} else {
					writeMsgLevel(fmt.Sprintf("Unavailable repository '%s' referenced by eclass-overrides entry for '%s'\n", otherRepoName, repoName), 40, -1)
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
		if repo.mastersOrig == "" && r.mainRepo() != nil && repo.name != r.mainRepo().name && !SyncMode {
			writeMsgLevel(fmt.Sprintf("!!! %s\nRepository '%s' is missing masters attribute in '%s'", repo.name, path.Join(repo.location, "metadata", "layout.conf"))+fmt.Sprintf("!!! %s\nSet 'masters = %s' in this file for future compatibility", r.mainRepo().name), 30, -1)
		}
	}
	r.preposChanged = true
	r.repoLocationList = []string{}
	r.checkLocations()
	return r
}

func loadRepositoryConfig(settings *Config, extraFiles string) *repoConfigLoader {
	repoconfigpaths := []string{}
	if pr, ok := settings.ValueDict["PORTAGE_REPOSITORIES"]; ok {
		repoconfigpaths = append(repoconfigpaths, pr)
	} else {
		if notInstalled {
			repoconfigpaths = append(repoconfigpaths, path.Join(PORTAGE_BASE_PATH, "cnf", "repos.conf"))
		} else {
			repoconfigpaths = append(repoconfigpaths, path.Join(settings.globalConfigPath, "repos.conf"))
		}
	}
	repoconfigpaths = append(repoconfigpaths, path.Join(settings.ValueDict["PORTAGE_CONFIGROOT"], UserConfigPath, "repos.conf"))
	if extraFiles != "" {
		repoconfigpaths = append(repoconfigpaths, extraFiles)
	}
	return NewRepoConfigLoader(repoconfigpaths, settings)
}

func getRepoName(repoLocation, cached string) string {
	if cached != "" {
		return cached
	}
	name, missing := (&repoConfig{}).readRepoName(repoLocation)
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

	if v, ok := layoutData["use-manifests"]; ok && strings.ToLower(v[0]) != "strict" {
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
			in := false
			for _, w := range manifestHashes {
				if v == w {
					in = true
					break
				}
			}
			if !in {
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
			in := false
			for w := range getValidChecksumKeys() {
				if v == w {
					in = true
					break
				}
			}
			if !in {
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
		in := false
		for _, v := range rawFormats {
			if v == "profile-default-eapi" {
				in = true
				break
			}
		}
		if in {
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
