package repository

import (
	"github.com/ppphp/portago/pkg/checksum"
	"github.com/ppphp/portago/pkg/const"
	eapi2 "github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/env"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/repository/validrepo"
	"github.com/ppphp/portago/pkg/util"
	"os"
	"path"
	"regexp"
	"strings"
)

var (
	invalidPathCharRe   = regexp.MustCompile("[^a-zA-Z0-9._\\-+/]")
	validProfileFormats = map[string]bool{
		"pms": true, "portage-1": true, "portage-2": true, "profile-bashrcs": true, "profile-set": true,
		"profile-default-eapi": true, "build-id": true,
	}
	Portage1ProfilesAllowDirectories = map[string]bool{"portage-1-compat": true, "portage-1": true, "portage-2": true}
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

func getRepoName(repoLocation, cached string) string {
	if cached != "" {
		return cached
	}
	name, missing := (&RepoConfig[T]{}).readRepoName(repoLocation)
	if missing {
		return ""
	}
	return name
}

func ParseLayoutConf(repoLocation, repoName string) (map[string][]string, map[string][]string) {
	eapi := util.ReadCorrespondingEapiFile(path.Join(repoLocation, _const.RepoNameLoc), "0")

	layoutFilename := path.Join(repoLocation, "metadata", "layout.conf")
	layoutFile := env.NewKeyValuePairFileLoader(layoutFilename, nil, nil)
	layoutData, layoutErrors := layoutFile.Load()

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
		data["repo-name"] = []string{validrepo.GenValidRepo(v[0])}
	} else {
		data["repo-name"] = []string{validrepo.GenValidRepo("")}
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
			if !myutil.Ins(manifestHashes, v) {
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
			if !checksum.GetValidChecksumKeys()[v] {
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
		if eapi2.EapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi) {
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
		if myutil.Ins(rawFormats, "profile-default-eapi") {
			//warnings.warn((_("Repository named '%(repo_name)s' has "
			//"profile_eapi_when_unspecified setting in "
			//"'%(layout_filename)s', but 'profile-default-eapi' is "
			//"not listed in the profile-formats field. Please "
			//"report this issue to the repository maintainer.") %
			//dict(repo_name=repo_name or 'unspecified',
			//layout_filename=layout_filename)),
			//SyntaxWarning)
		} else if !eapi2.EapiIsSupported(eapi) {
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
