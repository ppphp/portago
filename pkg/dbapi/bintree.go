package dbapi

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/ppphp/portago/pkg/binrepo"
	"github.com/ppphp/portago/pkg/checksum"
	_const "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/emerge"
	"github.com/ppphp/portago/pkg/exception"
	"github.com/ppphp/portago/pkg/getbinpkg"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/locks"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/util/permissions"
	"github.com/ppphp/portago/pkg/versions"
	"github.com/ppphp/portago/pkg/xpak"
	"github.com/ppphp/shlex"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type bindbapi[T interfaces.ISettings] struct {
	*fakedbapi[T]
	bintree  *BinaryTree
	move_ent func([]string, func(string) bool) int

	_aux_cache  map[string]string
	auxCacheKeys map[string]bool
}

// nil, true, false
func NewBinDbApi[T interfaces.ISettings](mybintree *BinaryTree, settings T, exclusive_slots, multi_instance bool) *bindbapi[T] { //
	b := &bindbapi[T]{}
	b.fakedbapi = NewFakeDbApi[T](settings, false, true)
	b.bintree = mybintree
	b.move_ent = mybintree.move_ent
	b.auxCacheKeys = map[string]bool{
		"BDEPEND":true,
		"BUILD_ID":true,
		"BUILD_TIME":true,
		"CHOST":true,
		"DEFINED_PHASES":true,
		"DEPEND":true,
		"EAPI":true,
		"IDEPEND":true,
		"IUSE":true,
		"KEYWORDS":true,
		"LICENSE":true,
		"MD5":true,
		"PDEPEND":true,
		"PROPERTIES":true,
		"PROVIDES":true,
		"RDEPEND":true,
		"repository":true,
		"REQUIRES":true,
		"RESTRICT":true,
		"SIZE":true,
		"SLOT":true,
		"USE":true,
		"_mtime_":true,
	}
	//b._aux_cache_slot_dict
	b._aux_cache = map[string]string{}
	b._aux_cache_slot_dict_cache = nil
	return b
}

func (b *bindbapi[T]) _aux_cache_slot_dict() slotDict {
	if b._aux_cache_slot_dict_cache == nil {
		b._aux_cache_slot_dict_cache = make(slotDict, len(b.auxCacheKeys))
		for key := range b.auxCacheKeys {
			b._aux_cache_slot_dict_cache[key] = make(map[string]string)
		}
	}
	return b._aux_cache_slot_dict_cache
}

func (b *bindbapi[T]) __getstate__() map[string]interface{} {
	state := make(map[string]interface{}, len(b.__dict__))
	for key, value := range b.__dict__ {
		state[key] = value
	}
	state["_aux_cache_slot_dict_cache"] = nil
	state["_instance_key"] = nil
	return state
}
func (b *bindbapi[T]) __setstate__(state map[string]interface{}) {
	for key, value := range state {
		b.__dict__[key] = value
	}
	if b._multi_instance {
		b._instance_key = b._instance_key_multi_instance()
	} else {
		b._instance_key = b._instance_key_cpv()
	}
}

func (b *bindbapi[T]) writable() bool {
	if f, err := os.Stat(util.FirstExisting(b.bintree.pkgdir)); err != nil || f == nil {
		return false
	} else {
		return true
	}
}

// 1
func (b *bindbapi[T]) match(origdep string, use_cache int) []interfaces.IPkgStr {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []*Vardbapi{})
	}
	return b.fakedbapi.Match(origdep, use_cache)
}

func (b *bindbapi[T]) cpv_exists(cpv interfaces.IPkgStr) bool {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []*Vardbapi{})
	}
	return b.fakedbapi.cpv_exists(cpv)
}

func (b *bindbapi[T]) cpv_inject(cpv interfaces.IPkgStr) {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []*Vardbapi{})
	}
	b.fakedbapi.cpv_inject(cpv, cpv.metadata)
}

func (b *bindbapi[T]) cpv_remove(cpv interfaces.IPkgStr) {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []*Vardbapi{})
	}
	b.fakedbapi.cpv_remove(cpv)
}

func (b *bindbapi[T]) aux_get(mycpv interfaces.IPkgStr, wants map[string]string) []string {
	if b.bintree != nil && !b.bintree.populated {
		b.bintree.Populate(false, true, []*Vardbapi{})
	}
	instance_key := b._instance_key(mycpv, true)
	kiwda := myutil.CopyMapSB(b._known_keys)
	for k := range kiwda {
		if !myutil.Inmss(wants, k){
			delete(kiwda, k)
		}
	}
	for k := range b._aux_cache_keys {
		delete(kiwda, k)
	}
	if len(kiwda)==0 {
		aux_cache := b.cpvdict[instance_key.String()]
		if aux_cache != nil {
			ret := []string{}
			for x := range wants {
				ret = append(ret, aux_cache[x])
			}
			return ret
		}
	}
	add_pkg := b.bintree._additional_pkgs[instance_key.String()]
	getitem := func(string) string { return "" }
	if add_pkg != nil {
		return add_pkg._db.aux_get(add_pkg, wants)
	} else if len(b.bintree._remotepkgs)==0 || !b.bintree.isremote(mycpv) {
		tbz2_path, ok := b.bintree._pkg_paths[instance_key.String()]
		if !ok {
			//except KeyError:
			//raise KeyError(mycpv)
		}
		tbz2_path = filepath.Join(b.bintree.pkgdir, tbz2_path)
		st, err := os.Lstat(tbz2_path)
		if err != nil {
			//except OSError:
			//raise KeyError(mycpv)
		}
		metadata_bytes := xpak.NewTbz2(tbz2_path).Get_data()
		getitem = func(k string) string {
			if k == "_mtime_" {
				return fmt.Sprint(st.ModTime().UnixNano())
			} else if k == "SIZE" {
				return fmt.Sprint(st.Size())
			}
			v := metadata_bytes[k]
			return v
		}
	} else {
		getitem = func(s string) string {
			return b.cpvdict[instance_key.String()][s]
		}
	}
	mydata := map[string]string{}
	mykeys := wants
	for x := range mykeys {
		myval := getitem(x)
		if myval != "" {
			mydata[x] = strings.Join(strings.Fields(myval), " ")
		}
	}

	if mydata["EAPI"] == "" {
		mydata["EAPI"] = "0"
	}

	ret := []string{}
	for x := range wants {
		ret = append(ret, mydata[x])
	}
	return ret
}

func (b *bindbapi[T]) aux_update(cpv interfaces.IPkgStr, values map[string]string) {

	if !b.bintree.populated {
		b.bintree.Populate(false, true, []*Vardbapi{})
	}
	//build_id := cpv.buildId
	//except AttributeError:
	//if b.bintree._multi_instance {
	//	//raise
	//}else {
	//	cpv = b._instance_key(cpv, true)[0]
	//	build_id = cpv.build_id
	//}

	tbz2path := b.bintree.getname(cpv.String(), false)
	if !myutil.PathExists(tbz2path) {
		//raise KeyError(cpv)
	}
	mytbz2 := xpak.NewTbz2(tbz2path)
	mydata := mytbz2.Get_data()

	for k, v := range values {
		mydata[k] = v
	}

	for k, v := range mydata {
		if v == "" {
			delete(mydata, k)
		}
	}
	mytbz2.Recompose_mem(string(xpak.Xpak_mem(mydata)), true)
	b.bintree.inject(cpv, tbz2path)
}

func (b *bindbapi[T]) unpack_metadata(versions.pkg, dest_dir){

	loop = asyncio._wrap_loop()
	if isinstance(versions.pkg, _pkg_str) {
		versions.cpv = versions.pkg
	}else {
		versions.cpv = versions.pkg.mycpv
	}
	key := b._instance_key(versions.cpv, false)
	add_pkg := b.bintree._additional_pkgs[key.String]
	if add_pkg != nil {
		yield
		add_pkg._db.unpack_metadata(versions.pkg, dest_dir)
	}else {
		tbz2_file := b.bintree.getname(versions.cpv, false)
		yield
		loop.run_in_executor(ForkExecutor(loop = loop),
		xpak.NewTbz2(tbz2_file).unpackinfo, dest_dir)
	}
}

func (b *bindbapi[T]) unpack_contents(pkg interfaces.IPkgStr, dest_dir string) interfaces.IFuture {

	loop = asyncio._wrap_loop()
	//if isinstance(pkg, _pkg_str) {
	settings := b.settings
	cpv := pkg
	//}else {
	//	settings = pkg
	//	cpv = settings.mycpv
	//}

	pkg_path := b.bintree.getname(cpv.String(), false)
	if pkg_path != "" {

		extractor := emerge.NewBinpkgExtractorAsync(
			settings.ValueDict["PORTAGE_BACKGROUND"] == "1",
			settings.environ(), settings.Features.Features, dest_dir,
			cpv,  pkg_path, settings.ValueDict["PORTAGE_LOG_FILE"],
			emerge.NewSchedulerInterface(loop))

		extractor.start()
		yield
		extractor.async_wait()
		if extractor.returncode == nil || *extractor.returncode != 0 {
			raise
			exception.PortageException("Error Extracting '{}'".format(pkg_path))
		}

	}else {
		instance_key := b._instance_key(cpv, false)
		add_pkg := b.bintree._additional_pkgs[instance_key.String]
		if add_pkg == nil {
			raise
			portage.exception.PackageNotFound(cpv)
		}
		yield
		add_pkg._db.unpack_contents(pkg, dest_dir)
	}
}

// 1
func (b *bindbapi[T]) cp_list(mycp string, use_cache int) []interfaces.IPkgStr {
	if !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.cp_list(mycp, use_cache)
}

// false
func (b *bindbapi[T]) cp_all(sort bool) []string {

	if ! b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.cp_all(sort)
}

func (b *bindbapi[T]) cpv_all() []string {

	if ! b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}
	return b.fakedbapi.cpv_all()
}

func (b *bindbapi[T]) getfetchsizes(pkg) map[string]int {
	if !b.bintree.populated {
		b.bintree.Populate(false, true, []string{})
	}

	pkg = getattr(pkg, "cpv", pkg)

	filesdict := map[string]int{}
	if !b.bintree.isremote(pkg) {
		//pass
	} else {
		metadata := b.bintree._remotepkgs[b._instance_key(pkg, false).String]
		sizeS, ok := metadata["SIZE"]
		if !ok {
			//except KeyError:
			//raise portage.exception.MissingSignature("SIZE")
		}
		size, err := strconv.Atoi(sizeS)
		if err != nil {
			//except ValueError:
			//raise portage.exception.InvalidSignature(
			//	"SIZE: %s" % metadata["SIZE"])
		} else {
			filesdict[filepath.Base(b.bintree.getname(versions.pkg, false))] = size
		}
	}
	return filesdict
}

type BinaryTree struct {
	pkgdir, _pkgindex_file                                                                                       string
	PkgIndexFile                                                                                                 interface{}
	settings                                                                                                     *config.Config
	populated, _populating, _multi_instance, _remote_has_index, _all_directory                                   bool
	_pkgindex_version                                                                                            int
	_pkgindex_hashes, _pkgindex_aux_keys, _pkgindex_use_evaluated_keys, _pkgindex_inherited_keys []string
	_remotepkgs map[string]map[string]string
	dbapi                                                                                                        *bindbapi
	update_ents                                                                                                  func(updates map[string][][]*dep.Atom, onProgress, onUpdate func(int, int))
	move_slot_ent                                                                                                func(mylist []*dep.Atom, repo_match func(string) bool) int
	tree, _additional_pkgs                                                                                       map[string]interface{}
	_pkgindex_header_keys, _pkgindex_allowed_pkg_keys,_pkgindex_keys                                                            map[string]bool
	_pkgindex_default_pkg_data, _pkgindex_default_header_data, _pkg_paths, _pkgindex_header                      map[string]string
	_pkgindex_translated_keys                                                                                    [][2]string
	invalids                                                                                                     []string
	_allocate_filename                                                                                           func(cpv interfaces.IPkgStr) string
	_binrepos_conf *binrepo.BinRepoConfigLoader
}

func NewBinaryTree(pkgDir string, settings *config.Config) *BinaryTree {
	b := &BinaryTree{}
	if pkgDir == "" {
		//raise TypeError("pkgdir parameter is required")
	}
	if settings != nil {
		//raise TypeError("Settings parameter is required")
	}

	b.pkgdir = msg.NormalizePath(pkgDir)
	b._multi_instance = settings.Features.Features["binpkg-multi-instance"]
	if b._multi_instance {
		b._allocate_filename = b._allocate_filename_multi
	} else {
		b._allocate_filename = func(cpv interfaces.IPkgStr) string {
			return filepath.Join(b.pkgdir, cpv.String()+".tbz2")
		}
	}
	b.dbapi = NewBinDbApi(b, settings, true, false)
	b.update_ents = b.dbapi.update_ents
	b.move_slot_ent = b.dbapi.move_slot_ent
	b.populated = false
	b.tree = map[string]interface{}{}
	b._remote_has_index = false
	b._remotepkgs = nil
	b._additional_pkgs = map[string]interface{}{}
	b.invalids = []string{}
	b.settings = settings
	b._pkg_paths = map[string]string{}
	b._populating = false
	st, err := os.Stat(filepath.Join(b.pkgdir, "All"))
	b._all_directory = err != nil && st != nil && st.IsDir()
	b._pkgindex_version = 0
	b._pkgindex_hashes = []string{"MD5", "SHA1"}
	b._pkgindex_file = filepath.Join(b.pkgdir, "Packages")
	b._pkgindex_keys = myutil.CopyMapSB(b.dbapi.auxCacheKeys)
	b._pkgindex_keys["CPV"] = true
	b._pkgindex_keys["SIZE"] = true
	b._pkgindex_aux_keys = []string{"BASE_URI", "BDEPEND", "BUILD_ID", "BUILD_TIME", "CHOST",
		"DEFINED_PHASES", "DEPEND", "DESCRIPTION", "EAPI",
		"IUSE", "KEYWORDS", "LICENSE", "PDEPEND",
		"PKGINDEX_URI", "PROPERTIES", "PROVIDES",
		"RDEPEND", "repository", "REQUIRES", "RESTRICT",
		"SIZE", "SLOT", "USE"}
	b._pkgindex_use_evaluated_keys = []string{"BDEPEND", "DEPEND", "LICENSE", "RDEPEND",
		"PDEPEND", "PROPERTIES", "RESTRICT"}
	b._pkgindex_header = nil

	b._pkgindex_header_keys = map[string]bool{}
	for _, k := range []string{
		"ACCEPT_KEYWORDS", "ACCEPT_LICENSE",
		"ACCEPT_PROPERTIES", "ACCEPT_RESTRICT", "CBUILD",
		"CONFIG_PROTECT", "CONFIG_PROTECT_MASK", "FEATURES",
		"GENTOO_MIRRORS", "INSTALL_MASK", "IUSE_IMPLICIT", "USE",
		"USE_EXPAND", "USE_EXPAND_HIDDEN", "USE_EXPAND_IMPLICIT",
		"USE_EXPAND_UNPREFIXED"} {
		b._pkgindex_header_keys[k] = true
	}

	b._pkgindex_default_pkg_data = map[string]string{
		"BDEPEND":        "",
		"BUILD_ID":       "",
		"BUILD_TIME":     "",
		"DEFINED_PHASES": "",
		"DEPEND":         "",
		"EAPI":           "0",
		"IUSE":           "",
		"KEYWORDS":       "",
		"LICENSE":        "",
		"PATH":           "",
		"PDEPEND":        "",
		"PROPERTIES":     "",
		"PROVIDES":       "",
		"RDEPEND":        "",
		"REQUIRES":       "",
		"RESTRICT":       "",
		"SLOT":           "0",
		"USE":            "",
	}
	b._pkgindex_inherited_keys = []string{"CHOST", "repository"}

	b._pkgindex_default_header_data = map[string]string{
		"CHOST":      b.settings.ValueDict["CHOST"],
		"repository": "",
	}

	b._pkgindex_translated_keys = [][2]string{
		{"DESCRIPTION", "DESC"},
		{"_mtime_", "MTIME"},
		{"repository", "REPO"},
	}

	b._pkgindex_allowed_pkg_keys = map[string]bool{}
	for v := range b._pkgindex_keys {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_aux_keys {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_hashes {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for v := range b._pkgindex_default_pkg_data {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_inherited_keys {
		b._pkgindex_allowed_pkg_keys[v] = true
	}
	for _, v := range b._pkgindex_translated_keys {
		b._pkgindex_allowed_pkg_keys[v[0]] = true
		b._pkgindex_allowed_pkg_keys[v[1]] = true
	}
	return b
}

// nil
func (b *BinaryTree) move_ent(mylist []string, repo_match func(string) bool) int {
	if !b.populated {
		b.Populate(false, true, []string{})
	}
	origcp := mylist[1]
	newcp := mylist[2]
	for _, atom := range []string{origcp, newcp} {
		if !dep.IsJustName(atom) {
			//raise InvalidPackageName(_unicode(atom))
		}
	}
	mynewcat := versions.CatSplit(newcp)[0]
	origmatches := b.dbapi.cp_list(origcp, 1)
	moves := 0
	if len(origmatches) == 0 {
		return moves
	}
	for _, mycpv := range origmatches {
		//try:
		mycpv := b.dbapi._pkg_str(mycpv, "")
		//except (KeyError, InvalidData):
		//continue
		mycpv_cp := versions.CpvGetKey(mycpv.String, "")
		if mycpv_cp != origcp {
			continue
		}
		if repo_match != nil && !repo_match(mycpv.repo) {
			continue
		}

		if !dep.IsValidAtom(newcp, false, false, false, mycpv.eapi, false) {
			continue
		}

		mynewcpv := strings.Replace(mycpv.String, mycpv_cp, newcp, 1)
		myoldpkg := versions.CatSplit(mycpv.String)[1]
		mynewpkg := versions.CatSplit(mynewcpv)[1]

		if _, err := os.Stat(b.getname(mynewcpv, false)); (mynewpkg != myoldpkg) && err == nil {
			msg.WriteMsg(fmt.Sprintf("!!! Cannot update binary: Destination exists.\n"), -1, nil)
			msg.WriteMsg(fmt.Sprintf("!!! "+mycpv.String+" -> "+mynewcpv+"\n"), -1, nil)
			continue
		}

		tbz2path := b.getname(mycpv.String, false)
		if _, err := os.Stat(tbz2path); err == syscall.EPERM {
			msg.WriteMsg(fmt.Sprintf("!!! Cannot update readonly binary: %s\n", mycpv), -1, nil)
			continue
		}

		moves += 1
		mytbz2 := xpak.NewTbz2(tbz2path)
		mydata := mytbz2.Get_data()
		updated_items := portage.update_dbentries([][]string{mylist}, mydata, "", mycpv)
		for k, v := range updated_items {
			mydata[k] = v
		}
		mydata["PF"] = mynewpkg + "\n"
		mydata["CATEGORY"] = mynewcat + "\n"
		if mynewpkg != myoldpkg {
			ebuild_data := mydata[myoldpkg+".ebuild"]
			delete(mydata, myoldpkg+".ebuild")
			if ebuild_data != "" {
				mydata[mynewpkg+".ebuild"] = ebuild_data
			}
		}

		mytbz2.Recompose_mem(string(xpak.Xpak_mem(mydata)), true)

		b.dbapi.cpv_remove(mycpv)
		delete(b._pkg_paths, b.dbapi._instance_key(mycpv, false).String)
		metadata := b.dbapi._aux_cache_slot_dict()
		for _, k := range b.dbapi._aux_cache_keys {
			if v, ok := mydata[k]; ok {
				metadata[k] = strings.Join(strings.Fields(v), " ")
			}
		}
		mynewcpvP := versions.NewPkgStr(mynewcpv, metadata, nil, "", "", "", 0, 0, "", 0, b.dbapi.dbapi)
		new_path := b.getname(mynewcpv, false)
		b._pkg_paths[b.dbapi._instance_key(mynewcpvP, false).String] = new_path[len(b.pkgdir)+1:]
		if new_path != mytbz2.File {
			b._ensure_dir(filepath.Dir(new_path))
			util._movefile(tbz2path, new_path, 0, nil, b.settings, nil)
		}
		b.inject(mynewcpv)
	}
	return moves
}

func (b *BinaryTree) _ensure_dir(path string) {
	pkgdir_st, err := os.Stat(b.pkgdir)
	if err != nil {
		//except OSError:
		util.EnsureDirs(path, -1, -1, -1, -1, nil, true)
		return
	}
	pkgdir_gid := pkgdir_st.Sys().(*syscall.Stat_t).Gid
	pkgdir_grp_mode := 0o2070 & pkgdir_st.Mode()
	util.EnsureDirs(path, -1, pkgdir_gid, pkgdir_grp_mode, 0, nil, true)
	//except PortageException:
	//if not PathIsDir(path):
	//raise
}

func (b *BinaryTree) _file_permissions(path string) {
	pkgdir_st, err := os.Stat(b.pkgdir)
	if err != nil {
		//except OSError:
		//pass
	} else {
		pkgdir_gid := pkgdir_st.Sys().(*syscall.Stat_t).Gid
		pkgdir_grp_mode := 0o0060 & pkgdir_st.Mode()
		permissions.ApplyPermissions(path, -1, pkgdir_gid,
			pkgdir_grp_mode, 0, nil, true)
		//except PortageException:
		//pass
	}
}

// false, true, []string{}
func (b *BinaryTree) Populate(getbinpkgs, getbinpkg_refresh bool, add_repos []*Vardbapi) {
	if b._populating {
		return
	}
	if st, _ := os.Stat(b.pkgdir); st != nil && !st.IsDir() && !(getbinpkgs || len(add_repos) != 0) {
		b.populated = true
		return
	}
	b._remotepkgs = nil

	b._populating = true
	defer func() { b._populating = false }()
	update_pkgindex := b._populate_local(!b.settings.Features.Features["pkgdir-index-trusted"])

	if update_pkgindex != nil && b.dbapi.writable() {
		l, _ := locks.Lockfile(b._pkgindex_file, true, false, "", 0)
		update_pkgindex = b._populate_local(true)
		if update_pkgindex != nil {
			b._pkgindex_write(update_pkgindex)
		}
		//if pkgindex_lock:
		locks.Unlockfile(l)
	}

	if len(add_repos) > 0 {
		b._populate_additional(add_repos)
	}

	if getbinpkgs {
		config_path := filepath.Join(
			b.settings.ValueDict["PORTAGE_CONFIGROOT"], _const.BinreposConfFile,
		)
		b._binrepos_conf = binrepo.NewBinRepoConfigLoader([]string{config_path,},
			b.settings.ValueDict["EPREFIX"], b.settings.ValueDict["EROOT"],
			b.settings.ValueDict["PORTAGE_CONFIGROOT"], b.settings.ValueDict["ROOT"],
			b.settings.ValueDict["PORTAGE_BINHOST"], )

		if b.settings.ValueDict["PORTAGE_BINHOST"] == "" {
			msg.WriteMsg(fmt.Sprintf("!!! PORTAGE_BINHOST unset, but Use is requested.\n"), -1, nil)
		} else {
			b._populate_remote(getbinpkg_refresh)
		}
	}

	b.populated = true

}

// true
func (b *BinaryTree) _populate_local(reindex bool) *getbinpkg.PackageIndex {
	b.dbapi.clear()

	_instance_key := b.dbapi._instance_key

	minimum_keys := []string{}
	for k := range b._pkgindex_keys {
		if !myutil.Ins(b._pkgindex_hashes, k) {
			minimum_keys = append(minimum_keys, k)
		}
	}
	pkg_paths := map[string]string{}
	b._pkg_paths = pkg_paths
	dir_files := map[string][]string{}
	if reindex {
		filepath.Walk(b.pkgdir, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}
			dir_files[filepath.Dir(path)] = append(dir_files[filepath.Dir(path)], filepath.Base(path))
			return nil
		})
	}

	pkgindex := b.LoadPkgIndex()
	if !b._pkgindex_version_supported(pkgindex) {
		pkgindex = b._new_pkgindex()
	}
	metadata := map[string]map[string]string{}
	basename_index := map[string][]map[string]string{}
	for _, d := range pkgindex.packages {
		cpv := versions.NewPkgStr(d["CPV"], d, b.settings, "", "", "", 0, 0, "", 0, b.dbapi.dbapi)
		d["CPV"] = cpv.String
		metadata[_instance_key(cpv, false).String] = d
		path := d["PATH"]
		if path == "" {
			path = cpv.String() + ".tbz2"
		}

		if reindex {
			basename := filepath.Base(path)
			if _, ok := basename_index[basename]; !ok {
				basename_index[basename] = []map[string]string{d}
			}
		} else {
			instance_key := _instance_key(cpv, false)
			pkg_paths[instance_key.String()] = path
			b.dbapi.cpv_inject(cpv)
		}
	}

	update_pkgindex := false
	for mydir, file_names := range dir_files {
		for _, myfile := range file_names {
			has := false
			for k := range _const.SUPPORTED_XPAK_EXTENSIONS {
				if !strings.HasSuffix(myfile, k) {
					has = true
					break
				}
			}
			if !has {
				continue
			}
			mypath := filepath.Join(mydir, myfile)
			full_path := filepath.Join(b.pkgdir, mypath)
			s, _ := os.Lstat(full_path)

			if s == nil || s.IsDir() {
				continue
			}
			possibilities := basename_index[myfile]
			if len(possibilities) != 0 {
				var match map[string]string = nil
				var d map[string]string
				for _, d = range possibilities {
					mt, err := strconv.Atoi(d["_mtime_"])
					if err != nil {
						continue
					}
					if mt != s.ModTime().Nanosecond() {
						continue
					}
					sz, err := strconv.ParseInt(d["SIZE"], 10, 64)
					if err != nil {
						continue
					}
					if sz != s.Size() {
						continue
					}
					in := true
					for _, k := range minimum_keys {
						if _, ok := d[k]; !ok {
							in = false
							break
						}
					}
					if in {
						match = d
						break
					}
				}
				if len(match) > 0 {
					mycpv := match["CPV"]
					instance_key := _instance_key(mycpv, false)
					pkg_paths[instance_key.String()] = mypath
					oldpath := d["PATH"]
					if oldpath != "" && oldpath != mypath {
						update_pkgindex = true
					}
					if mypath != mycpv+".tbz2" {
						d["PATH"] = mypath
						if oldpath == "" {
							update_pkgindex = true
						}
					} else {
						delete(d, "PATH")
						if oldpath != "" {
							update_pkgindex = true
						}
					}
					b.dbapi.cpv_inject(mycpv)
					continue
				}
			}
			if _, err := os.Stat(full_path); err != nil {
				msg.WriteMsg(fmt.Sprintf("!!! Permission denied to read binary package: '%s'\n", full_path), -1, nil)
				b.invalids = append(b.invalids, myfile[:len(myfile)-5])
				continue
			}
			chain := []string{}
			for v := range b.dbapi.auxCacheKeys {
				chain = append(chain, v)
			}
			chain = append(chain, "PF", "CATEGORY")
			pkg_metadata := b._read_metadata(full_path, s,
				chain)
			mycat := pkg_metadata["CATEGORY"]
			mypf := pkg_metadata["PF"]
			slot := pkg_metadata["SLOT"]
			mypkg := myfile[:len(myfile)-5]
			if mycat == "" || mypf == "" || slot == "" {
				msg.WriteMsg(fmt.Sprintf("\n!!! Invalid binary package: '%s'\n", full_path), -1, nil)
				missing_keys := []string{}
				if mycat == "" {
					missing_keys = append(missing_keys, "CATEGORY")
				}
				if mypf == "" {
					missing_keys = append(missing_keys, "PF")
				}
				if slot == "" {
					missing_keys = append(missing_keys, "SLOT")
				}
				msg1 := []string{}
				if len(missing_keys) > 0 {
					sort.Strings(missing_keys)
					msg1 = append(msg1, fmt.Sprintf("Missing metadata key(s): %s.",
						strings.Join(missing_keys, ", ")))
				}
				msg1 = append(msg1, fmt.Sprintf(" This binary package is not recoverable and should be deleted."))
				for _, line := range myutil.SplitSubN(strings.Join(msg1, ""), 72) {
					msg.WriteMsg(fmt.Sprintf("!!! %s\n", line), -1, nil)
				}
				b.invalids = append(b.invalids, mypkg)
				continue
			}

			multi_instance := false
			invalid_name := false
			build_id := 0
			if strings.HasSuffix(myfile, ".xpak") {
				multi_instance = true
				build_id = b._parse_build_id(myfile)
				if build_id < 1 {
					invalid_name = true
				} else if myfile != fmt.Sprintf("%s-%s.xpak", mypf, build_id) {
					invalid_name = true
				} else {
					mypkg = mypkg[:len(mypkg)-len(fmt.Sprint(build_id))-1]
				}
			} else if myfile != mypf+".tbz2" {
				invalid_name = true
			}

			if invalid_name {
				msg.WriteMsg(fmt.Sprintf("\n!!! Binary package name is invalid: '%s'\n", full_path), -1, nil)
				continue
			}

			if pkg_metadata["BUILD_ID"] != "" {
				var err error
				build_id, err = strconv.Atoi(pkg_metadata["BUILD_ID"])
				if err != nil {
					//except ValueError:
					msg.WriteMsg(fmt.Sprintf("!!! Binary package has invalid BUILD_ID: '%s'\n", full_path), -1, nil)
					continue
				}
			} else {
				build_id = 0
			}

			if multi_instance {
				name_split := versions.CatPkgSplit(mycat+"/"+mypf, 1, "")
				if name_split == [4]string{} || versions.CatSplit(mydir)[0] != name_split[0] || versions.catsplit(mydir)[1] != name_split[1] {
					continue
				}
			} else if mycat != mydir && mydir != "All" {
				continue
			}
			if mypkg != strings.TrimSpace(mypf) {
				continue
			}
			mycpvS := mycat + "/" + mypkg
			if !b.dbapi._category_re.MatchString(mycat) {
				msg.WriteMsg(fmt.Sprintf("!!! Binary package has an unrecognized category: '%s'\n", full_path), -1, nil)
				msg.WriteMsg(fmt.Sprintf("!!! '%s' has a category that is not listed in %setc/portage/categories\n", mycpvS, b.settings.ValueDict["PORTAGE_CONFIGROOT"]), -1, nil)
				continue
			}
			if build_id != 0 {
				pkg_metadata["BUILD_ID"] = fmt.Sprint(build_id)
			}
			pkg_metadata["SIZE"] = fmt.Sprint(s.Size())
			delete(pkg_metadata, "CATEGORY")
			delete(pkg_metadata, "PF")
			mycpv := versions.NewPkgStr(mycpvS, b.dbapi._aux_cache_slot_dict(pkg_metadata), b.dbapi.dbapi, "", "", "", 0, 0, "", 0, nil)
			pkg_paths[_instance_key(mycpv, false).String] = mypath
			b.dbapi.cpv_inject(mycpv)
			update_pkgindex = true
			d, ok := metadata[_instance_key(mycpv, false).String]
			if !ok {
				d = pkgindex._pkg_slot_dict()
			}
			if len(d) > 0 {
				mt, err := strconv.Atoi(d["_mtime_"])
				if err != nil {
					d = map[string]string{}
				}
				if mt != s.ModTime().Nanosecond() {
					d = map[string]string{}
				}
			}
			if len(d) > 0 {
				sz, err := strconv.ParseInt(d["SIZE"], 10, 64)
				if err != nil {
					d = map[string]string{}
				}
				if sz != s.Size() {
					d = map[string]string{}
				}
			}

			for k := range b._pkgindex_allowed_pkg_keys {
				v := pkg_metadata[k]
				if v {
					d[k] = v
				}
				d["CPV"] = mycpv.String
			}

			//try:
			b._eval_use_flags(d)
			//except portage.exception.InvalidDependString:
			//WriteMsg(fmt.Sprintf("!!! Invalid binary package: '%s'\n", b.getname(mycpv)), -1, nil)
			//b.dbapi.cpv_remove(mycpv)
			//del pkg_paths[_instance_key(mycpv)]

			if mypath != mycpv.String+".tbz2" {
				d["PATH"] = mypath
			} else {
				delete(d, "PATH")
			}
			metadata[_instance_key(mycpv, false).String] = d
		}
	}

	if reindex {
		for instance_key := range metadata {
			if _, ok := pkg_paths[instance_key]; !ok {
				delete(metadata, instance_key)
			}
		}
	}

	if update_pkgindex {
		pkgindex.packages = []map[string]string{}
		for _, v := range metadata {
			pkgindex.packages = append(pkgindex.packages, v)
		}
		b._update_pkgindex_header(pkgindex.header)
	}

	b._pkgindex_header = map[string]string{}
	b._merge_pkgindex_header(pkgindex.header, b._pkgindex_header)

	if update_pkgindex {
		return pkgindex
	} else {
		return nil
	}

}

// true
func (b *BinaryTree) _populate_remote(getbinpkg_refresh bool) {

	b._remote_has_index = false
	b._remotepkgs = map[string]map[string]string{}
	for _, base_url := range strings.Fields(b.settings.ValueDict["PORTAGE_BINHOST"]) {
		parsed_url, _ := url.Parse(base_url)
		host := parsed_url.Hostname()
		port := parsed_url.Port()
		user_passwd := parsed_url.User.String()
		user := parsed_url.User.Username()
		passwd, _ := parsed_url.User.Password()

		pkgindex_file := filepath.Join(b.settings.ValueDict["EROOT"], _const.CachePath, "binhost",
			host, strings.TrimLeft(parsed_url.Path, "/"), "Packages")
		pkgindex := b._new_pkgindex()

		f, err := os.Open(pkgindex_file)
		if err != nil {
			//except EnvironmentError as e:
			if err != syscall.ENOENT {
				//raise
			}
		} else {
			//try:
			pkgindex.read(f)
			//finally:
			f.Close()
		}

		local_timestamp := pkgindex.header["TIMESTAMP"]
		download_timestamp, err := strconv.ParseFloat(pkgindex.header["DOWNLOAD_TIMESTAMP"], 64)
		remote_timestamp := ""
		rmt_idx := b._new_pkgindex()
		var proc *exec.Cmd
		tmp_filename := ""
		//try:
		url := strings.TrimRight(base_url, "/") + "/Packages"
		f = nil

		if !getbinpkg_refresh && local_timestamp != "" {
			//raise UseCachedCopyOfRemoteIndex()
		}

		ttl, err := strconv.ParseFloat(pkgindex.header["TTL"], 64)
		if err == nil {
			if download_timestamp != 0 && ttl != 0 &&
				download_timestamp+ttl > float64(time.Now().Nanosecond()) {
				//raise UseCachedCopyOfRemoteIndex()
			}
		}

		r, err := http.NewRequest(http.MethodGet, url, nil)
		var resp *http.Response
		if err == nil {
			r.Header.Set("If-Modified-Since", local_timestamp)
			resp, err = http.DefaultClient.Do(r)
		}
		if err != nil {
			//except IOError as err:
			if parsed_url.Scheme == "ftp" || parsed_url.Scheme == "http" || parsed_url.Scheme == "https" {
				if v, ok := b.settings.ValueDict["PORTAGE_DEBUG"]; ok && v != "0" {
					//traceback.print_exc()
				}
			}
			//except ValueError:
			//raise ParseError("Invalid Portage BINHOST value '%s'"
			//% url.lstrip())
		} else if resp.StatusCode == 304 {
			//raise UseCachedCopyOfRemoteIndex()
		}
		var f_dec io.Reader
		if resp == nil {
			path := strings.TrimRight(parsed_url.Path, "/") + "/Packages"
			if parsed_url.Scheme == "ssh" {
				ssh_args := []string{"ssh"}
				if port != "" {
					ssh_args = append(ssh_args, fmt.Sprintf("-p%s", port, ))
				}
				ss, _ := shlex.Split(strings.NewReader(b.settings.ValueDict["PORTAGE_SSH_OPTS"]), false, true)

				ssh_args = append(ssh_args, ss...)
				ssh_args = append(ssh_args, user_passwd+host)
				ssh_args = append(ssh_args, "--")
				ssh_args = append(ssh_args, "cat")
				ssh_args = append(ssh_args, path)

				f_dec = &bytes.Buffer{}
				proc := exec.Command(ssh_args[0], ssh_args[1:]...)
				proc.Stdout = f_dec
				proc.Run()
			} else {
				setting := "FETCHCOMMAND_" + strings.ToUpper(parsed_url.Scheme)
				fcmd := b.settings.ValueDict[setting]
				if fcmd == "" {
					fcmd = b.settings.ValueDict["FETCHCOMMAND"]
					if fcmd == "" {
						//raise EnvironmentError("FETCHCOMMAND is unset")
					}
				}
				fd, _ := os.CreateTemp(os.TempDir(), "")
				tmp_dirname, tmp_basename := os.TempDir(), fd.Name()
				fd.Close()

				fcmd_vars := map[string]string{
					"DISTDIR": tmp_dirname,
					"FILE":    tmp_basename,
					"URI":     url,
				}

				for _, k := range []string{"PORTAGE_SSH_OPTS"} {
					v := b.settings.ValueDict[k]
					if v != "" {
						fcmd_vars[k] = v
					}
				}

				success = portage.getbinpkg.file_get(
					fcmd = fcmd, fcmd_vars = fcmd_vars)
				if not success {
					//raise EnvironmentError("%s failed" % (setting, ))
				}
				tmp_filename = filepath.Join(tmp_dirname, tmp_basename)
				f_dec, _ = os.Open(tmp_filename)
			}
		} else {
			f_dec = resp.Body
		}

		//try:
		rmt_idx.readHeader(f_dec)
		if remote_timestamp == "" {
			remote_timestamp = rmt_idx.header["TIMESTAMP"]
		}
		if remote_timestamp == "" {
			pkgindex = nil
			msg.WriteMsg("\n\n!!! Binhost package index  has no TIMESTAMP field.\n", -1, nil)
		} else {
			if !b._pkgindex_version_supported(rmt_idx) {
				msg.WriteMsg(fmt.Sprintf("\n\n!!! Binhost package index version"+
					" is not supported: '%s'\n", rmt_idx.header["VERSION"]), -1, nil)
				pkgindex = nil
			} else if local_timestamp != remote_timestamp {
				rmt_idx.readBody(f_dec)
				pkgindex = rmt_idx
			}
		}
		//	finally:
		//			try:
		//	try:
		//	AlarmSignal.register(5)
		//	f.close()
		//	finally:
		//	AlarmSignal.unregister()
		//	except AlarmSignal:
		//	WriteMsg("\n\n!!! %s\n" %
		//_("Timed out while closing connection to binhost"),
		//	noiselevel=-1)
		//	except UseCachedCopyOfRemoteIndex:
		//	WriteMsg_stdout("\n")
		//	WriteMsg_stdout(
		//	colorize("GOOD", _("Local copy of remote index is up-to-date and will be used.")) +
		//"\n")
		//	rmt_idx = pkgindex
		//	except EnvironmentError as e:
		//			WriteMsg(_("\n\n!!! Error fetching binhost package"
		//" info from '%s'\n") % _hide_url_passwd(base_url))
		//				try:
		//	error_msg = _unicode(e)
		//	except UnicodeDecodeError as uerror:
		//	error_msg = _unicode(uerror.object,
		//	encoding='utf_8', errors='replace')
		//	WriteMsg("!!! %s\n\n" % error_msg)
		//	del e
		//	pkgindex = nil
		if proc != nil {
			if proc.poll() == nil {
				proc.kill()
				proc.wait()
			}
			proc = nil
		}
		if tmp_filename != "" {
			if err := syscall.Unlink(tmp_filename); err != nil {
				//except OSError:
				//pass
			}
		}
		if pkgindex == rmt_idx {
			pkgindex.modified = false
			pkgindex.header["DOWNLOAD_TIMESTAMP"] = fmt.Sprintf("%d", time.Now().Nanosecond())
			//try:
			util.EnsureDirs(filepath.Dir(pkgindex_file), -1, -1, -1, -1, nil, true)
			f = util.NewAtomic_ofstream(pkgindex_file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
			pkgindex.write(f)
			f.close()
			//except(IOError, PortageException):
			//if os.access(filepath.Dir(pkgindex_file), os.W_OK):
			//raise
		}
		if pkgindex != nil {
			remote_base_uri := pkgindex.header["URI"]
			if remote_base_uri == "" {
				remote_base_uri = base_url
			}
			for _, d := range pkgindex.packages {
				cpv := versions.NewPkgStr(d["CPV"], d,
					b.settings, "", "", "", 0, 0, "", 0, b.dbapi)
				if b.dbapi.cpv_exists(cpv) {
					continue
				}
				d["CPV"] = cpv
				d["BASE_URI"] = remote_base_uri
				d["PKGINDEX_URI"] = url
				b._remotepkgs[b.dbapi._instance_key(cpv.String, false).String] = d
				b.dbapi.cpv_inject(cpv)
			}

			b._remote_has_index = true
			b._merge_pkgindex_header(pkgindex.header, b._pkgindex_header)
		}
	}
}

func (b *BinaryTree) _populate_additional(repos []*Vardbapi) interfaces.IPkgStr {

	for _, repo := range repos {
		aux_keys = list(set(chain(repo._aux_cache_keys, repo._pkg_str_aux_keys)))
		for _, cpv :=range repo.cpv_all() {
			metadata = dict(zip(aux_keys, repo.aux_get(cpv, aux_keys)))
			pkg := versions.NewPkgStr(cpv, metadata = metadata, settings = repo.settings, db=repo)
			instance_key = b.dbapi._instance_key(pkg)
			b._additional_pkgs[instance_key] = pkg
			b.dbapi.cpv_inject(pkg)
		}
	}
}

// ""
func (b *BinaryTree) inject(cpv interfaces.IPkgStr, filename string) interfaces.IPkgStr {
	if !b.populated {
		b.Populate(false, true, []string{})
	}
	full_path := filename
	if filename == "" {
		full_path = b.getname(cpv.String, false)
	}
	s, err := os.Stat(full_path)
	if err != nil {
		//except OSError as e:
		if err != syscall.ENOENT {
			//raise
		}
		//del e
		msg.WriteMsg(fmt.Sprintf("!!! Binary package does not exist: '%s'\n",full_path), -1, nil)
		return
	}
	metadata := b._read_metadata(full_path, s, nil)
	invalid_depend := false
	//try:
	b._eval_use_flags(metadata)
	//except portage.exception.InvalidDependString:
	//invalid_depend = true
	if invalid_depend || metadata["SLOT"]=="" {
		msg.WriteMsg(fmt.Sprintf("!!! Invalid binary package: '%s'\n",full_path), -1, nil)
		return nil
	}

	fetched := map[string]string{}
	//try:
	build_id := cpv.BuildId
	//except AttributeError:
	//build_id := 0
	//else:
	instance_key := b.dbapi._instance_key(cpv, false)
	if _, ok := b.dbapi.cpvdict[instance_key.String]; ok{
		b.dbapi.cpv_remove(cpv)
		delete(b._pkg_paths, instance_key.String)
		if b._remotepkgs != nil {
			fetched = b._remotepkgs[instance_key.String]
			delete(b._remotepkgs, instance_key.String)
		}
	}

	cpv = versions.NewPkgStr(cpv.String, metadata, b.settings,"", "", "", 0, 0, "", 0, b.dbapi)

	pkgindex_lock, err := locks.Lockfile(b._pkgindex_file,true, false, "", 0)
	defer func() {
		if pkgindex_lock!= nil {
			locks.Unlockfile(pkgindex_lock)
		}
	}()
	if filename != "" {
		new_filename := b.getname(cpv.String, true)
	try:
		samefile = os.path.samefile(filename, new_filename)
		except
	OSError:
		samefile = false
		if not samefile {
			b._ensure_dir(filepath.Dir(new_filename))
			util._movefile(filename, new_filename, 0, nil, b.settings, nil)
		}
		full_path = new_filename
	}

	basename := filepath.Base(full_path)
	if build_id == 0 && len(fetched) == 0 &&
		strings.HasSuffix(basename, ".xpak") {
		build_id = b._parse_build_id(basename)
		metadata["BUILD_ID"] = fmt.Sprint(build_id)
		cpv = versions.NewPkgStr(cpv.String,  metadata, b.settings, "", "", "", 0, 0, "", 0,b.dbapi)
		binpkg := xpak.NewTbz2(full_path)
		binary_data := binpkg.Get_data()
		binary_data["BUILD_ID"] = metadata["BUILD_ID"]
		binpkg.Recompose_mem(string(xpak.Xpak_mem(binary_data)), true)
	}

	b._file_permissions(full_path)
	pkgindex := b.LoadPkgIndex()
	if ! b._pkgindex_version_supported(pkgindex) {
		pkgindex = b._new_pkgindex()
	}

	d := b._inject_file(pkgindex, cpv, full_path)
	b._update_pkgindex_header(pkgindex.header)
	b._pkgindex_write(pkgindex)

	cpv.metadata["MD5"] = d["MD5"]

	return cpv
}

// nil
func (b *BinaryTree) _read_metadata(filename string, st os.FileInfo, keys []string) map[string]string {
	metadata :=map[string]string{}
	if keys == nil {
		keys = b.dbapi._aux_cache_keys
		metadata = b.dbapi._aux_cache_slot_dict()
	}
	binary_metadata := xpak.NewTbz2(filename).Get_data()
	for _, k := range keys {
		if k == "_mtime_" {
			metadata[k] = fmt.Sprint(st.ModTime().Nanosecond())
		} else if k == "SIZE" {
			metadata[k] = fmt.Sprint(st.Size())
		} else {
			v := binary_metadata[k]
			if v == "" {
				if k == "EAPI" {
					metadata[k] = "0"
				} else {
					metadata[k] = ""
				}
			} else {
				metadata[k] = strings.Join(strings.Fields(v), " ")
			}
		}
	}
	return metadata
}

func (b *BinaryTree) _inject_file(pkgindex *getbinpkg.PackageIndex, cpv interfaces.IPkgStr, filename string) map[string]string {

	instance_key := b.dbapi._instance_key(cpv, false)
	if b._remotepkgs != nil {
		delete(b._remotepkgs, instance_key.String)
	}

	b.dbapi.cpv_inject(cpv)
	b._pkg_paths[instance_key.String] = filename[len(b.pkgdir)+1:]
	d := b._pkgindex_entry(cpv)

	path := d["PATH"]
	for i := len(pkgindex.packages) - 1; i > -1; i-- {
		d2 := pkgindex.packages[i]
		if path != "" && path == d2["PATH"] {
			pp := []map[string]string{}
			for i2, p := range pkgindex.packages {
				if i != i2 {
					pp = append(pp, p)
				}
			}
			pkgindex.packages = pp
		} else if cpv.String == d2["CPV"] {
			if path == d2["PATH"] {
				pp := []map[string]string{}
				for i2, p := range pkgindex.packages {
					if i != i2 {
						pp = append(pp, p)
					}
				}
				pkgindex.packages = pp
			}
		}
	}

	pkgindex.packages = append(pkgindex.packages, d)
	return d
}

func (b *BinaryTree) _pkgindex_write(pkgindex *getbinpkg.PackageIndex) {
	contents := &bytes.Buffer{}
	pkgindex.write(contents)
	contentsB := contents.Bytes()
	mtime, _ := strconv.Atoi(pkgindex.header["TIMESTAMP"])
	atime := mtime
	output_files := []struct {
		io.WriteCloser
		string
		io.Closer
	}{{util.NewAtomic_ofstream(b._pkgindex_file, os.O_RDWR, true),
		b._pkgindex_file, nil}}

	if _, ok := b.settings.Features.Features["compress-index"]; ok {
		gz_fname := b._pkgindex_file + ".gz"
		fileobj := util.NewAtomic_ofstream(gz_fname, os.O_RDWR, true)
		output_files = append(output_files, struct {
			io.WriteCloser
			string
			io.Closer
		}{gzip.NewWriter(fileobj), gz_fname, fileobj})
	}

	for _, v := range output_files {
		f := v.WriteCloser
		fname := v.String
		f_close := v.Closer
		f.Write(contentsB)
		f.Close()
		if f_close != nil {
			f_close.Close()
		}
		b._file_permissions(fname)
		syscall.Utime(fname, &syscall.Utimbuf{int64(atime), int64(mtime)})
	}
}

func (b *BinaryTree) _pkgindex_entry(cpv interfaces.IPkgStr) map[string]string {

	pkg_path := b.getname(cpv.String, false)

	d := myutil.CopyMapSS(cpv.metadata)
	for k, v := range checksum.PerformMultipleChecksums(pkg_path, b._pkgindex_hashes, false) {
		d[k] = string(v)
	}

	d["CPV"] = cpv.String
	st, _ := os.Lstat(pkg_path)
	d["_mtime_"] = fmt.Sprint(st.ModTime().UnixNano())
	d["SIZE"] = fmt.Sprint(st.Size())

	rel_path := pkg_path[len(b.pkgdir)+1:]
	if rel_path != cpv.String+".tbz2" {
		d["PATH"] = rel_path
	}

	return d
}

func (b *BinaryTree) _new_pkgindex() *getbinpkg.PackageIndex {
	return getbinpkg.NewPackageIndex(b._pkgindex_allowed_pkg_keys,
		b._pkgindex_default_header_data,
		b._pkgindex_default_pkg_data,
		b._pkgindex_inherited_keys,
		b._pkgindex_translated_keys)
}

func (b *BinaryTree) _merge_pkgindex_header(src, dest map[string]string) {
	for _, i := range ebuild.IterIuseVars(src) {
		k := i[0]
		v := i[1]
		v_before := dest[k]
		if v_before != "" {
			merged_values := map[string]bool{}
			for _, v := range strings.Fields(v_before) {
				merged_values[v] = true
			}
			for _, v := range strings.Fields(v) {
				merged_values[v] = true
			}
			mv := []string{}
			for k := range merged_values {
				mv = append(mv, k)
			}
			sort.Strings(mv)
			v = strings.Join(mv, " ")
		}
		dest[k] = v
	}
	if dest["ARCH"] == "" && src["ARCH"] != "" {
		dest["ARCH"] = src["ARCH"]
	}
}

func (b *BinaryTree) _propagate_config(config *config.Config) bool {

	if b._pkgindex_header == nil {
		return false
	}

	b._merge_pkgindex_header(b._pkgindex_header,
		config.configDict["defaults"])
	config.regenerate(0)
	config.initIuse()
	return true
}

func (b *BinaryTree) _update_pkgindex_header(header map[string]string) {

	if _, ok := b.settings.ValueDict["IUSE_IMPLICIT"]; !(b.settings.profilePath != "" && ok) {
		if _, ok := header["VERSION"]; !ok {
			header["VERSION"] = fmt.Sprint(b._pkgindex_version)
		}
		return
	}
	rp, _ := filepath.EvalSymlinks(b.settings.ValueDict["PORTDIR"])
	portdir := msg.NormalizePath(rp)
	profiles_base := filepath.Join(portdir, "profiles") + string(filepath.Separator)
	profile_path := ""
	if b.settings.profilePath != "" {
		rp, _ := filepath.EvalSymlinks(b.settings.ValueDict["PORTDIR"])
		profile_path = msg.NormalizePath(rp)
	}
	if strings.HasPrefix(profile_path, profiles_base) {
		profile_path = profile_path[len(profiles_base):]
	}
	header["PROFILE"] = profile_path
	header["VERSION"] = fmt.Sprint(b._pkgindex_version)
	base_uri := b.settings.ValueDict["PORTAGE_BINHOST_HEADER_URI"]
	if base_uri != "" {
		header["URI"] = base_uri
	} else {
		delete(header, "URI")
	}
	phk := []string{}
	for k := range b._pkgindex_header_keys {
		phk = append(phk, k)
	}
	for _, k := range append(append(append([]string{}, phk...),
		strings.Fields(b.settings.ValueDict["USE_EXPAND_IMPLICIT"])...),
		strings.Fields(b.settings.ValueDict["USE_EXPAND_UNPREFIXED"])...) {
		v := b.settings.ValueDict[k]
		if v != "" {
			header[k] = v
		} else {
			delete(header, k)
		}
	}
}

func (b *BinaryTree) _pkgindex_version_supported(pkgindex *getbinpkg.PackageIndex) bool {
	version := pkgindex.header["VERSION"]
	if version != "" {
		v, err := strconv.Atoi(version)
		if err == nil {
			if v < b._pkgindex_version {
				return true
			}
		}
		if err != nil {
			//except ValueError:
			//pass
		}
	}
	return false
}

//
func (b *BinaryTree) _eval_use_flags(metadata map[string]string) {
	use := map[string]bool{}
	for _, v := range strings.Fields(metadata["USE"]) {
		use[v] = true
	}
	for _, k := range b._pkgindex_use_evaluated_keys {
		token_class := func(s string) *dep.Atom { dep.NewAtom(s, nil, false, nil, nil, "", nil, nil) }
		if !strings.HasSuffix(k, "DEPEND") {
			token_class = nil
		}

		deps := metadata[k]
		if deps == "" {
			continue
		}
		//try:
		deps1 := dep.UseReduce(deps, use, []string{}, false, []string{}, false, "", false, false, nil, token_class, false)
		deps2 := dep.ParenEncloses(deps1, false, false)
		//except portage.exception.InvalidDependString as e:
		//WriteMsg("%s: %s\n" % (k, e), noiselevel=-1)
		//raise
		metadata[k] = deps2
	}
}

// deprecated ?
func (b *BinaryTree) exists_specific(cpv string) []interfaces.IPkgStr {
	if !b.populated {
		b.Populate(false, true, []string{})
	}
	return b.dbapi.match(dep_expandS("="+cpv, b.dbapi.dbapi, 1, b.settings), 1)
}

func (b *BinaryTree) dep_bestmatch(mydep *dep.Atom) string {
	if !b.populated {
		b.Populate(false, true, []string{})
	}
	msg.WriteMsg("\n\n", 1, nil)
	msg.WriteMsg(fmt.Sprintf("mydep: %s\n", mydep), 1, nil)
	mydep = Dep_expand(mydep, b.dbapi.dbapi, 1, b.settings)
	msg.WriteMsg(fmt.Sprintf("mydep: %s\n", mydep), 1, nil)
	mykey := dep.DepGetKey(mydep.Value)
	msg.WriteMsg(fmt.Sprintf("mykey: %s\n", mykey), 1, nil)
	ml := []string{}
	for _, p := range dep.MatchFromList(mydep, b.dbapi.cp_list(mykey, 1)) {
		ml = append(ml, p.String)
	}
	mymatch := versions.Best(ml, "")
	msg.WriteMsg(fmt.Sprintf("mymatch: %s\n", mymatch), 1, nil)
	if mymatch == "" {
		return ""
	}
	return mymatch
}

// false
func (b *BinaryTree) getname(cpvS string, allocate_new bool) string {

	if !b.populated {
		b.Populate(false, true, []string{})
	}

	cpv := versions.NewPkgStr(cpvS, nil, nil, "", "", "", 0, 0, "", 0, nil)

	filename := ""
	if allocate_new {
		filename = b._allocate_filename(cpv)
	} else if b._is_specific_instance(cpv) {
		instance_key := b.dbapi._instance_key(cpv, false)
		path := b._pkg_paths[instance_key.String]
		if path != "" {
			filename = filepath.Join(b.pkgdir, path)
		}
	}

	if filename == "" && !allocate_new {
		//try:
		instance_key := b.dbapi._instance_key(cpv, true)
		//except KeyError:
		//pass
		//else:
		filename = b._pkg_paths[instance_key.String]
		if filename != "" {
			filename = filepath.Join(b.pkgdir, filename)
		} else if _, ok := b._additional_pkgs[instance_key.String]; ok {
			return ""
		}
	}

	if filename == "" {
		if b._multi_instance {
			pf := versions.CatSplit(cpv.String)[1]
			filename = fmt.Sprintf("%s-%s.xpak", filepath.Join(b.pkgdir, cpv.cp, pf), "1")
		} else {
			filename = filepath.Join(b.pkgdir, cpv.String+".tbz2")
		}
	}

	return filename
}

func (b *BinaryTree) _is_specific_instance(cpv interfaces.IPkgStr) bool {

	specific := true
	//try:
	build_time := cpv.BuildTime
	build_id := cpv.BuildId
	//except AttributeError:
	//specific = false
	//else:
	if build_time == 0 || build_id == 0 {
		specific = false
	}
	return specific
}

func (b *BinaryTree) _max_build_id(cpv interfaces.IPkgStr) int {
	max_build_id := 0
	for _, x := range b.dbapi.cp_list(cpv.Cp, 1) {
		if x.String == cpv.String && x.BuildId != 0 && x.BuildId > max_build_id {
			max_build_id = x.BuildId
		}
	}
	return max_build_id
}

func (b *BinaryTree) _allocate_filename_multi(cpv interfaces.IPkgStr) string {
	max_build_id := b._max_build_id(cpv)

	pf := versions.CatSplit(cpv.String)[1]
	build_id := max_build_id + 1

	for {
		filename := fmt.Sprintf("%s-%s.xpak",
			filepath.Join(b.pkgdir, cpv.Cp, pf), build_id)
		if _, err := os.Stat(filename); err == nil {
			build_id += 1
		} else {
			return filename
		}
	}
}

func (b *BinaryTree) _parse_build_id(filename string) int {
	build_id := -1
	suffixlen := len(".xpak")
	hyphen := strings.LastIndex(filename[0:len(filename)-(suffixlen+1)], "-")
	if hyphen != -1 {
		build_idS := filename[hyphen+1 : -suffixlen]
		var err error
		build_id, err = strconv.Atoi(build_idS)
		if err != nil {
			//pass
		}
	}
	return build_id
}

func (b *BinaryTree) isremote(pkgname interfaces.IPkgStr) bool {
	if b._remotepkgs == nil {
		return false
	}
	instance_key := b.dbapi._instance_key(pkgname, false)
	if _, ok := b._remotepkgs[instance_key.String]; !ok {
		return false
	} else if _, ok := b._additional_pkgs[instance_key.String]; ok {
		return false
	}
	return true
}

func (b *BinaryTree) get_pkgindex_uri(cpv interfaces.IPkgStr) string {
	uri := ""
	if b._remotepkgs != nil {
		metadata := b._remotepkgs[b.dbapi._instance_key(cpv, false).String]
		if metadata != nil {
			uri = metadata["PKGINDEX_URI"]
		}
	}
	return uri

}

func (b *BinaryTree) LoadPkgIndex() *getbinpkg.PackageIndex {
	pkgindex := b._new_pkgindex()
	f, err := os.Open(b._pkgindex_file)
	if err == nil {
		//try:
		pkgindex.read(f)
		//finally:
		//	f.close()
	}
	return pkgindex
}

func (b *BinaryTree) _get_digests(versions.pkg) {

try:
	versions.cpv = versions.pkg.cpv
	except
AttributeError:
	versions.cpv = versions.pkg

	_instance_key := b.dbapi._instance_key
	instance_key := _instance_key(versions.cpv, false)
	digests :=
	{
	}
	var metadata map[string]string = nil
	if b._remotepkgs != nil {
		metadata = b._remotepkgs[instance_key.String]
	}
	if metadata == nil {
		for _, d := range b.LoadPkgIndex().packages {
			if (d["CPV"] == versions.cpv && instance_key == _instance_key(versions.NewPkgStr(d["CPV"], d, b.settings, "", "", "", 0, 0, "", 0, nil), false)) {
				metadata = d
				break
			}
		}
	}

	if metadata == nil {
		return digests
	}

	for k := range checksum.getValidChecksumKeys() {
		v := metadata[k]
		if v == "" {
			continue
		}
		digests[k] = v
	}

	if myutil.Inmss(metadata,"SIZE") {
	try:
		digests["size"] = int(metadata["SIZE"])
		except
	ValueError:
		msg.WriteMsg(fmt.Sprintf("!!! Malformed SIZE attribute in remote metadata for '%s'\n", versions.cpv), -1, nil)
	}
	return digests
}

func (b *BinaryTree) getslot(mycatpkg interfaces.IPkgStr) string {

	myslot := ""
	//try:
	myslot = b.dbapi._pkg_str(mycatpkg, "").slot
	//except KeyError:
	//pass
	return myslot
}
