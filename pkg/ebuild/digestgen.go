package ebuild

import (
	"fmt"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// nil, nil, nil
func digestgen(myarchives interface{}, mysettings *Config, myportdb *dbapi.portdbapi) int {
	if mysettings != nil|| myportdb == nil {
		//raise TypeError("portage.digestgen(): 'mysettings' and 'myportdb' parameter are required.")
	}
	portage.DoebuildManifestExemptDepend += 1
	defer func() { portage.DoebuildManifestExemptDepend -= 1}()
	distfiles_map := map[string][]string{}
	fetchlist_dict := dbapi.NewFetchlistDict(mysettings.ValueDict["O"], mysettings, myportdb)
	for _, cpv:= range fetchlist_dict.__iter__(){
		//try:
		for myfile := range fetchlist_dict.__getitem__(cpv.string) {
			distfiles_map[myfile] = append(distfiles_map[myfile], cpv.string)
		}
		//except InvalidDependString as e:
		//	WriteMsg("!!! %s\n" % str(e), noiselevel=-1)
		//	del e
		//	return 0
	}
	mytree := filepath.Dir(filepath.Dir(mysettings.ValueDict["O"]))
	//try:
	rc := mysettings.Repositories.GetRepoForLocation(mytree)
	//except KeyError:
	//mytree = os.path.realpath(mytree)
	//mf = mysettings.repositories.get_repo_for _location(mytree)

	repo_required_hashes := rc.manifestRequiredHashes
	if repo_required_hashes == nil {
		repo_required_hashes = myutil.CopyMapSB(_const.MANIFEST2_HASH_DEFAULTS)
	}
	mf := rc.load_manifest(mysettings.ValueDict["O"], mysettings.ValueDict["DISTDIR"],
		fetchlist_dict, false)

	if !mf.allow_create {
		msg.WriteMsgStdout(fmt.Sprintf(">>> Skipping creating Manifest for %s; "+
			"repository is configured to not use them\n", mysettings.ValueDict["O"]), 0)
		return 1
	}

	required_hash_types := map[string]bool{}
	required_hash_types["size"] = true
	for k := range repo_required_hashes {
		required_hash_types[k]= true
	}
	dist_hashes := mf.fhashdict["DIST"]
	if dist_hashes == nil {
		dist_hashes = map[string]map[string]string{}
	}

	missing_files := []string{}
	for myfile:= range distfiles_map {

		myhashes := dist_hashes[myfile]
		if len(myhashes) == 0 {
			st, err := os.Stat(filepath.Join(mysettings.ValueDict["DISTDIR"], myfile))
			if err != nil {
				//except OSError:
				//st = None
			}
			if st == nil || st.Size() == 0 {
				missing_files = append(missing_files, myfile)
			}
			continue
		}
		size := myhashes["size"]

		st, err := os.Stat(filepath.Join(mysettings.ValueDict["DISTDIR"], myfile))
		if err != nil {
			//except OSError as e:
			if err != syscall.ENOENT {
				//raise
			}
			//del e
			if size == "" {
				missing_files = append(missing_files, myfile)
				continue
			}
			rht := myutil.CopyMapSB(required_hash_types)
			for k := range myhashes {
				delete(rht, k)
			}
			if len(rht) != 0 {
				missing_files = append(missing_files, myfile)
				continue
			}
		} else {

			if st.Size() == 0 || size != "" && size != fmt.Sprint(st.Size()) {
				missing_files = append(missing_files, myfile)
				continue
			}
		}
	}

	for _, myfile := range missing_files{
		uris := map[string]bool{}
		all_restrict := map[string]bool{}
		for _, cpv := range distfiles_map[myfile]{
			uris.update(myportdb.getFetchMap(
				cpv, nil, mytree)[myfile])
			restrict := myportdb.aux_get(cpv, []string{"RESTRICT"}, mytree, "")[0]
			for _, k := range dep.useReduce(restrict, map[string]bool{},
				[]string{}, false, []string{}, false, "",
				false, true, nil, nil, true) {
				all_restrict[k] = true
			}

			cat, pf := versions.CatSplit(cpv)[0], versions.CatSplit(cpv)[1]
			mysettings.ValueDict["CATEGORY"] = cat
			mysettings.ValueDict["PF"] = pf
		}

		mysettings.ValueDict["PORTAGE_RESTRICT"] = myutil.joinMB(all_restrict, " ")

		//try:
		st,err  := os.Stat(filepath.Join(mysettings.ValueDict["DISTDIR"], myfile))
		if err != nil {
			//except OSError:
			//st = None
		}

		if not atom.fetch( {
		myfile:
			uris
		}, mysettings):
		myebuild := filepath.Join(mysettings.ValueDict["O"],
			versions.CatSplit(versions.cpv)[1]+".ebuild")
		spawn_nofetch(myportdb, myebuild, nil, nil)
		msg.WriteMsg(fmt.Sprintf("!!! Fetch failed for %s, can't update Manifest\n",
			myfile),  -1, nil)
		if myutil.Inmsmss(
			dist_hashes, myfile)&& st!= nil&&st.Size() > 0{
			cmd := output.Colorize("INFORM", fmt.Sprintf("ebuild --force %s manifest", filepath.Base(myebuild)))
			msg.WriteMsg(fmt.Sprintf(
				"!!! If you would like to forcefully replace the existing Manifest entry\n"+
					"!!! for %s, use the following command:\n", myfile) +
				fmt.Sprintf("!!!    %s\n" , cmd),
				-1, nil)
		}
		return 0
	}

	msg.WriteMsgStdout(fmt.Sprintf(">>> Creating Manifest for %s\n", mysettings.ValueDict["O"]), 0)
	//try:
	mf.create(false, true,
		mysettings.Features.Features["assume-digests"], nil)
	//except FileNotFound as e:
	//WriteMsg(_("!!! File %s doesn't exist, can't update Manifest\n")
	//% e, noiselevel = -1)
	//return 0
	//except PortagePackageException as e:
	//WriteMsg(("!!! %s\n") % (e, ), noiselevel = -1)
	//return 0
	//try:
	mf.write(false, false)
	//except PermissionDenied as e:
	//WriteMsg(_("!!! Permission Denied: %s\n") % (e, ), noiselevel = -1)
	//return 0
	if  !mysettings.Features.Features["assume-digests"]{
		distlist := []string{}
		for  k := range mf.fhashdict["DIST"]{
			distlist =append(distlist, k)
		}
		sort.Strings(distlist)
		auto_assumed:= []string{}
		for _, filename:= range distlist {
			if ! myutil.PathExists(
				filepath.Join(mysettings.ValueDict["DISTDIR"], filename)) {
				auto_assumed =append(auto_assumed, filename)
			}
		}
		if len(auto_assumed) > 0{
			sp := strings.Split(mysettings.ValueDict["O"],string(os.PathSeparator))
			cp := strings.Join(sp[len(sp)-2:], string(os.PathSeparator))
			pkgs := myportdb.cp_list(cp, 1,  []string{mytree})
			pkgs.sort()
			msg.WriteMsgStdout("  digest.assumed" + output.Colorize("WARN",
				fmt.Sprintf("%18d", len(auto_assumed))) + "\n", 0)
			for _, pkg_key := range pkgs{
				fetchlist := myportdb.getFetchMap(pkg_key, mytree = mytree)
				pv := strings.Split(pkg_key.string, "/")[1]
				for _, filename := range auto_assumed {
					if filename in
					fetchlist{
						msg.WriteMsgStdout(fmt.Sprintf(
							"   %s::%s\n", pv, filename), 0)
					}
				}
			}
		}
	}
	return 1
}
