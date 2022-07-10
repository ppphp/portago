package repository

import (
	"fmt"
	"github.com/ppphp/configparser"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/portage/pcache"
	"github.com/ppphp/portago/pkg/portage/vars"
	"github.com/ppphp/portago/pkg/sync"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/configs"
	"github.com/ppphp/portago/pkg/util/grab"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/shlex"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type RepoConfigLoader struct {
	locationMap, treeMap map[string]string
	Prepos               map[string]*RepoConfig
	PreposOrder          []string
	missingRepoNames     map[string]bool
	preposChanged        bool
	RepoLocationList     []string
	ignoredRepos         []util.Sss
}

func NewRepoConfigLoader(paths []string, settings *config.Config) *RepoConfigLoader {
	r := &RepoConfigLoader{}
	prepos, locationMap, treeMap, ignoredMap, defaultOpts := map[string]*RepoConfig{}, map[string]string{}, map[string]string{}, map[string][]string{}, map[string]string{"EPREFIX": settings.ValueDict["EPREFIX"], "EROOT": settings.ValueDict["EROOT"], "PORTAGE_CONFIGROOT": settings.ValueDict["PORTAGE_CONFIGROOT"], "ROOT": settings.ValueDict["ROOT"]}
	var portDir, portDirOverlay string

	if _, ok := settings.ValueDict["PORTAGE_REPOSITORIES"]; !ok {
		portDir = settings.ValueDict["PORTDIR"]
		portDirOverlay = settings.ValueDict["PORTDIR_OVERLAY"]
	}
	defaultOpts["sync-rsync-extra-opts"] = settings.ValueDict["PORTAGE_RSYNC_EXTRA_OPTS"]
	if err := r.parse(paths, prepos, settings.LocalConfig, defaultOpts); err != nil {
		msg.WriteMsg(fmt.Sprintf("!!! Error while reading repo config file: %s\n", err), -1, nil)
		prepos = map[string]*RepoConfig{}
		prepos["DEFAULT"] = NewRepoConfig("DEFAULT", nil, settings.LocalConfig)
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
	portDir = r.addRepositories(portDir, portDirOverlay, prepos, ignoredMap, settings.LocalConfig, defaultPortDir)
	if portDir != "" && strings.TrimSpace(portDir) == "" {
		portDir, _ = filepath.EvalSymlinks(portDir)
	}
	var ignoredRepos []util.Sss
	for k, v := range ignoredMap {
		ignoredRepos = append(ignoredRepos, util.Sss{k, v})
	}
	r.missingRepoNames = map[string]bool{}
	for _, repo := range prepos {
		if repo.Location != "" && repo.missingRepoName {
			r.missingRepoNames[repo.Location] = true
		}
	}
	for repoName, repo := range prepos {
		if repo.Location == "" {
			if repoName != "DEFAULT" {
				if settings.LocalConfig && len(paths) > 0 {
					msg.WriteMsgLevel(fmt.Sprintf("!!! %s\n", fmt.Sprintf("Section '%s' in repos.conf is missing location attribute", repo.Name)), 40, -1)
				}
				delete(prepos, repoName)
				continue
			}
		} else {
			if !vars.SyncMode {
				if !util.IsdirRaiseEaccess(repo.Location) {
					msg.WriteMsgLevel(fmt.Sprintf("!!! %s\n", fmt.Sprintf("Section '%s' in repos.conf has location attribute set to nonexistent directory: '%s'", repoName, repo.Location)), 40, -1)
					if repo.Name != "gentoo" {
						delete(prepos, repoName)
						continue
					}
				}
				if repo.missingRepoName && repo.Name != repoName {
					msg.WriteMsgLevel(fmt.Sprintf("!!! Section '%s' in repos.conf refers to repository without repository name set in '%s'\n", repoName, path.Join(repo.Location, _const.RepoNameLoc)), 40, -1)
					delete(prepos, repoName)
					continue
				}
				if repo.Name != repoName {
					msg.WriteMsgLevel(fmt.Sprintf("!!! Section '%s' in repos.conf has name different from repository name '%s' set inside repository\n", repoName, repo.Name), 40, -1)
					delete(prepos, repoName)
					continue
				}
			}
			locationMap[repo.Location] = repoName
			treeMap[repoName] = repo.Location
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
			aliases := util.StackLists([][][2]string{a}, 1, false, false, false, false)
			for k := range aliases {
				names[k.Value] = true
			}
		}
		for name := range names {
			if _, ok := prepos[name]; ok && prepos[name].Location != "" {
				if name == repoName {
					continue
				}
				msg.WriteMsgLevel(fmt.Sprintf("!!! Repository name or alias '%s', defined for repository '%s', overrides existing alias or repository.\n", name, repoName), 40, -1)
				continue
			}
			prepos[name] = repo
			if repo.Location != "" {
				if _, ok := locationMap[repo.Location]; !ok {
					locationMap[repo.Location] = name
				}
				treeMap[name] = repo.Location
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
			if portDir != "" && !vars.SyncMode {
				msg.WriteMsg(fmt.Sprintf("!!! main-repo not set in DEFAULT and PORTDIR is empty.\n"), -1, nil)
			}
		}
	}
	if mainRepo != "" && prepos[mainRepo].priority == 0 {
		prepos[mainRepo].priority = -1000
	}
	var p []*RepoConfig
	for key, repo := range prepos {
		if repo.Name == key && key != "DEFAULT" && repo.Location != "" {
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
	r.PreposOrder = preposOrder
	r.ignoredRepos = ignoredRepos
	r.locationMap = locationMap
	r.treeMap = treeMap
	r.preposChanged = true
	r.RepoLocationList = []string{}

	for repoName, repo := range prepos {
		if repoName == "DEFAULT" {
			continue
		}
		if repo.Masters == nil {
			if r.MainRepo() != nil && repoName != r.MainRepo().Name {
				repo.MastersRepo = []*RepoConfig{r.MainRepo()}
			} else {
				repo.MastersRepo = []*RepoConfig{}
			}
		} else {
			if len(repo.Masters) > 0 {
				continue
			}
			masterRepos := []*RepoConfig{}
			for _, masterName := range repo.MastersRepo {
				if _, ok := prepos[masterName.Name]; !ok {
					layoutFilename := path.Join(repo.Location, "metadata", "layout.conf")
					msg.WriteMsgLevel(fmt.Sprintf("Unavailable repository '%s' referenced by masters entry in '%s'\n", masterName.Name, layoutFilename), 40, -1)
				} else {
					masterRepos = append(masterRepos, prepos[masterName.Name])
				}
			}
			repo.MastersRepo = masterRepos
		}
	}
	for repoName, repo := range prepos {
		if repoName == "DEFAULT" {
			continue
		}
		eclassLocations := []string{}
		for _, masterRepo := range repo.MastersRepo {
			eclassLocations = append(eclassLocations, masterRepo.Location)
		}
		if !myutil.Ins(eclassLocations, repo.Location) {
			eclassLocations = append(eclassLocations, repo.Location)
		}
		if len(repo.eclassOverrides) != 0 {
			for otherRepoName := range r.treeMap {
				if _, ok := r.treeMap[otherRepoName]; ok {
					eclassLocations = append(eclassLocations, r.GetLocationForName(otherRepoName))
				} else {
					msg.WriteMsgLevel(fmt.Sprintf("Unavailable repository '%s' referenced by eclass-overrides entry for '%s'\n", otherRepoName, repoName), 40, -1)
				}
			}
		}
		repo.eclassLocations = eclassLocations
	}

	eclassDBs := map[string]*pcache.Cache{}
	for repoName, repo := range prepos {
		if repoName == "DEFAULT" {
			continue
		}
		var eclassDB *pcache.Cache = nil
		for _, eclassLocation := range repo.eclassLocations {
			treeDb := eclassDBs[eclassLocation]
			if treeDb == nil {
				treeDb = pcache.NewCache(eclassLocation, "")
				eclassDBs[eclassLocation] = treeDb
			}
			if eclassDB == nil {
				eclassDB = treeDb.Copy()
			} else {
				eclassDB.Append(treeDb)
			}
		}
		repo.eclassDb = eclassDB
	}
	for repoName, repo := range prepos {
		if repoName == "DEFAULT" {
			continue
		}
		if repo.mastersOrig == nil && r.MainRepo() != nil && repo.Name != r.MainRepo().Name && !vars.SyncMode {
			msg.WriteMsgLevel(fmt.Sprintf("!!! Repository '%s' is missing masters attribute in '%s'\n", repo.Name, path.Join(repo.Location, "metadata", "layout.conf"))+fmt.Sprintf("!!! Set 'masters = %s' in this file for future compatibility\n", r.MainRepo().Name), 30, -1)
		}
	}
	r.preposChanged = true
	r.RepoLocationList = []string{}
	r.checkLocations()
	return r
}

func (r *RepoConfigLoader) addRepositories(portDir, portdirOverlay string, prepos map[string]*RepoConfig, ignoredMap map[string][]string, localConfig bool, defaultPortdir string) string {
	overlays := []string{}
	portDirOrig := ""
	if portDir != "" {
		portDir = msg.NormalizePath(portDir)
		portDirOrig = portDir
		overlays = append(overlays, portDir)
	}
	portOv := []string{}
	sl, err := shlex.Split(strings.NewReader(portdirOverlay), false, true)
	if err != nil {
		msg.WriteMsg(fmt.Sprintf("!!! Invalid PORTDIR_OVERLAY:%s: %s\n", err, portdirOverlay), -1, nil)
	} else {
		for _, i := range sl {
			portOv = append(portOv, msg.NormalizePath(i))
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
	if prepos["DEFAULT"].Masters != nil {
		defaultRepoOpt["aliases"] = strings.Join(prepos["DEFAULT"].Masters, "k")
	}
	if len(overlays) != 0 {
		reposConf := map[string]*RepoConfig{}
		for k, v := range prepos {
			reposConf[k] = v
		}
		basePriority := 0
		for _, ov := range overlays {
			if util.IsdirRaiseEaccess(ov) || (basePriority == 0 && ov == portDir) {
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
					if reposConfOpts.Masters != nil {
						repo.Masters = reposConfOpts.Masters
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
					oldLocation := prepos[repo.Name].Location
					if oldLocation != "" && oldLocation != repo.Location && !(basePriority == 0 && oldLocation == defaultPortdir) {
						if ignoredMap[repo.Name] == nil {
							ignoredMap[repo.Name] = []string{}
						}
						ignoredMap[repo.Name] = append(ignoredMap[repo.Name], oldLocation)
						if oldLocation == portDir {
							portDir = repo.Location
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
				if !vars.SyncMode {
					msg.WriteMsg(fmt.Sprintf("!!! Invalid PORTDIR_OVERLAY (not a dir): '%s'\n", ov), -1, nil)
				}
			}
		}
	}
	return portDir
}

func (r *RepoConfigLoader) parse(paths []string, prepos map[string]*RepoConfig, localConfig bool, defaultOpts map[string]string) error {
	args := configparser.DefaultArgument
	args.Defaults = defaultOpts
	parser := configparser.NewConfigParser(args)
	var recursivePaths []string
	for _, p := range paths {
		recursivePaths = append(recursivePaths, grab.RecursiveFileList(p)...)
	}

	if err := configs.ReadConfigs(parser, recursivePaths); err != nil {
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
		for o := range sync.ModuleSpecificOptions(repo) {
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

func (r *RepoConfigLoader) MainRepoLocation() string {
	mainRepo := r.Prepos["DEFAULT"].mainRepo
	if _, ok := r.Prepos[mainRepo]; mainRepo == "" || !ok {
		return ""
	}
	return r.Prepos[mainRepo].Location
}

func (r *RepoConfigLoader) MainRepo() *RepoConfig {
	mainRepo := r.Prepos["DEFAULT"].mainRepo
	if mainRepo == "" {
		return nil
	}
	return r.Prepos[mainRepo]
}

func (r *RepoConfigLoader) RepoLocationListF() []string {
	if r.preposChanged {
		repoLocationList := []string{}
		for _, repo := range r.PreposOrder {
			if r.Prepos[repo].Location != "" {
				repoLocationList = append(repoLocationList, r.Prepos[repo].Location)
			}
		}
		r.RepoLocationList = repoLocationList
		r.preposChanged = false
	}
	return r.RepoLocationList
}

func (r *RepoConfigLoader) checkLocations() {
	for name, re := range r.Prepos {
		if name != "DEFAULT" {
			if re.Location == "" {
				msg.WriteMsg(fmt.Sprintf("!!! Location not set for repository %s\n", name), -1, nil)
			} else {
				if !util.IsdirRaiseEaccess(re.Location) && !vars.SyncMode {
					n := []string{}
					for _, v := range r.PreposOrder {
						if v != name {
							n = append(n, v)
						}
					}
					r.PreposOrder = n
					msg.WriteMsg(fmt.Sprintf("!!! Invalid Repository Location (not a dir): '%s'\n", re.Location), -1, nil)
				}
			}
		}
	}
}

func (r *RepoConfigLoader) ReposWithProfiles() []*RepoConfig {
	rp := []*RepoConfig{}
	for _, repoName := range r.PreposOrder {
		repo := r.Prepos[repoName]
		if repo.format != "unavailable" {
			rp = append(rp, repo)
		}
	}
	return rp
}

func (r *RepoConfigLoader) getNameForLocation(location string) string {
	return r.locationMap[location]
}

func (r *RepoConfigLoader) GetLocationForName(repoName string) string {
	if repoName == "" {
		return ""
	}
	return r.treeMap[repoName]
}

func (r *RepoConfigLoader) GetRepoForLocation(location string) *RepoConfig {
	return r.Prepos[r.getNameForLocation(location)]
}

func (r *RepoConfigLoader) Getitem(repoName string) *RepoConfig {
	return r.Prepos[repoName]
}

func (r *RepoConfigLoader) delitem(repoName string) {
	if repoName == r.Prepos["DEFAULT"].mainRepo {
		r.Prepos["DEFAULT"].mainRepo = ""
	}
	location := r.Prepos[repoName].Location
	delete(r.Prepos, repoName)
	n := []string{}
	for _, v := range r.PreposOrder {
		if v != repoName {
			n = append(n, v)
		}
	}
	r.PreposOrder = n
	for k, v := range myutil.CopyMapSS(r.locationMap) {
		if v == repoName {
			delete(r.locationMap, k)
		}
	}
	if _, ok := r.treeMap[repoName]; ok {
		delete(r.treeMap, repoName)
	}
	rll := []string{}
	for _, x := range r.RepoLocationList {
		if x != location {
			rll = append(rll, x)
		}
	}
	r.RepoLocationList = rll
}

func (r *RepoConfigLoader) contains(repoName string) bool {
	_, ok := r.Prepos[repoName]
	return ok
}

func (r *RepoConfigLoader) iter() []string {
	rp := []string{}
	for _, repo := range r.PreposOrder {
		rp = append(rp, repo)
	}
	return rp
}

func (r *RepoConfigLoader) ConfigString() string {
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
		configString += fmt.Sprintf("%s = %s\n", strings.Replace("location", "_", "-", -1), repo.Location)
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
		for _, k := range repo.MastersRepo {
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

func LoadRepositoryConfig(settings *config.Config, extraFiles string) *RepoConfigLoader {
	repoConfigPaths := []string{}
	if pr, ok := settings.ValueDict["PORTAGE_REPOSITORIES"]; ok {
		repoConfigPaths = append(repoConfigPaths, pr)
	} else {
		if vars.NotInstalled {
			repoConfigPaths = append(repoConfigPaths, path.Join(_const.PORTAGE_BASE_PATH, "cnf", "repos.conf"))
		} else {
			repoConfigPaths = append(repoConfigPaths, path.Join(settings.GlobalConfigPath, "repos.conf"))
		}
	}
	repoConfigPaths = append(repoConfigPaths, path.Join(settings.ValueDict["PORTAGE_CONFIGROOT"], _const.UserConfigPath, "repos.conf"))
	if len(extraFiles) > 0 {
		repoConfigPaths = append(repoConfigPaths, extraFiles)
	}
	return NewRepoConfigLoader(repoConfigPaths, settings)
}
