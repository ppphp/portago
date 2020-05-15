package binhost

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	"os"
	"sort"
	"syscall"
)

const doc = "Scan and generate metadata indexes for binary packages."
const __doc__ = doc

var module_spec = map[string]interface{}{
	"name":        "binhost",
	"description": doc,
	"provides": map[string]interface{}{
		"module1": map[string]interface{}{
			"name":        "binhost",
			"sourcefile":  "binhost",
			"class":       "BinhostHandler",
			"description": doc,
			"functions":   []string{"check", "fix"},
			"func_desc":   map[string]interface{}{},
		},
	},
}


type BinhostHandler struct {
	short_desc string
	_bintree *atom.BinaryTree
	_pkgindex_file  interface{}
	_pkgindex *atom.PackageIndex
}

func (b *BinhostHandler) name()string{
	return "binhost"
}

func(b *BinhostHandler) _need_update(cpv string, data map[string]string)bool{
	if _, ok := data["MD5"] ; ok{
		return true
	}
	size := data["SIZE"]
	if size == "" {
		return true
	}

	mtime := data["_mtime_"]
	if mtime =="" {
		return true
	}

	pkg_path := b._bintree.getname(cpv, "")
try:
	s, err  := os.Lstat(pkg_path)
	if err != nil {
		//except OSError as e:
		if err != syscall.ENOENT && err != syscall.ESTALE{
		//raise
		}
		return false
	}

try:
	if long(mtime) != stat s[stat.ST_MTIME]:
	return True
	if long(size) != long(s.st_size):
	return True
	except ValueError:
	return True

	return false
}


// nil
func(b *BinhostHandler) check( onProgress func(int, int)) (bool, []string){
	bintree := b._bintree
	bintree._populate_local(true)
	bintree.populated = true
	_instance_key := bintree.dbapi._instance_key
	cpv_all := b._bintree.dbapi.cpv_all()
	sort.Strings(cpv_all)
	maxval := len(cpv_all)
	if onProgress != nil{
		onProgress(maxval, 0)
	}
	pkgindex := b._pkgindex
	missing := []string{}
	stale := []string{}
	metadata := map[string]string{}
	for _, d := range pkgindex.packages{
		cpv := atom.NewPkgStr(d["CPV"], d, bintree.settings, "", "", "", 0, "", "", 0, nil)
		d["CPV"] = cpv.string
		metadata[_instance_key(cpv, false).string] = d
		if !bintree.dbapi.cpv_exists(cpv){
			stale =append(stale,cpv)
		}
	}
	for i, cpv := range cpv_all {
		d := metadata[_instance_key(cpv, false).string]
		if len(d)==0 || b._need_update(cpv, d){
			missing=append( missing, cpv)
		}
		if onProgress!= nil{
			onProgress(maxval, i+1)
		}
	}
	errors := []string{}
	for _, cpv := range missing{
		errors = append(errors, fmt.Sprintf("'%s' is not in Packages" ,cpv.string))
	}
	for _, cpv := range stale{
		errors =append(stale, fmt.Sprintf("'%s' is not in the repository" , cpv.string))
	}
	if len(errors) > 0 {
		return false, errors
	}
	return true, nil
}

// nil
func(b *BinhostHandler) fix( onProgress func(int, int)) (bool, []string){
	bintree := b._bintree
	bintree._populate_local(true)
	bintree.populated = true
	_instance_key := bintree.dbapi._instance_key
	cpv_all := b._bintree.dbapi.cpv_all()
	sort.Strings(cpv_all)
	maxval := 0
	if onProgress!= nil {
		onProgress(maxval, 0)
	}
	pkgindex := b._pkgindex
	missing := []*atom.pkgStr{}
	stale := []*atom.pkgStr{}
	metadata := map[string]map[string]string{}
	for _, d := range pkgindex.packages{
		cpv := atom.NewPkgStr(d["CPV"], d, bintree.settings, "", "", "", 0, "", "", 0, nil)
		d["CPV"] = cpv.string
		metadata[_instance_key(cpv, false).string] = d
		if ! bintree.dbapi.cpv_exists(cpv) {
			stale=append(stale, cpv)
		}
	}

	for _, cpv := range cpv_all{
		d := metadata[_instance_key(cpv, false).string]
		if len(d)== 0 || b._need_update(cpv, d) {
			missing=append(missing, cpv)
		}
	}

	if len(missing)!= 0 || len(stale)!= 0 {
		a, f, c, d, _ := atom.Lockfile(b._pkgindex_file, true, false, "", 0)

		pkgindex := bintree._populate_local(true)
		if pkgindex == nil {
			pkgindex = bintree.LoadPkgIndex()
		}
		b._pkgindex = pkgindex
		cpv_all = b._bintree.dbapi.cpv_all()
		cpv_all.sort()

		missing = []*atom.pkgStr{}
		stale = []*atom.pkgStr{}
		metadata = map[string]map[string]string{}
		for _ ,d := range  pkgindex.packages{
			cpv := atom.NewPkgStr(d["CPV"], d, bintree.settings,  "", "", "", 0, "", "", 0, nil)
			d["CPV"] = cpv.string
			metadata[_instance_key(cpv.string).string] = d
			if ! bintree.dbapi.cpv_exists(cpv){
				stale=append(stale, cpv)
			}
		}

		for _, cpv:= range cpv_all{
			d := metadata[_instance_key(cpv.string).string]
			if  len(d)==0 || b._need_update(cpv.string, d){
				missing =append(missing, cpv)
			}
		}

		maxval = len(missing)
		for i, cpv := range missing{
			d := bintree._pkgindex_entry(cpv)
			if err := bintree._eval_use_flags(cpv, d); err != nil {
				//except portage.exception.InvalidDependString:
				atom.WriteMsg(fmt.Sprintf("!!! Invalid binary package: \"%s\"\n" , bintree.getname(cpv)), -1, nil)
			}else {
				metadata[_instance_key(cpv, false).string] = d
			}

			if onProgress!= nil {
				onProgress(maxval, i+1)
			}
		}

		for _, cpv := range stale{
			delete(metadata,_instance_key(cpv, false).string)
		}

		bintree.populated = false

		pkgindex.packages = []map[string]string{}
		for _,  v := range metadata{
			pkgindex.packages = append(pkgindex.packages, v)
		}
		bintree._update_pkgindex_header(b._pkgindex.header)
		bintree._pkgindex_write(b._pkgindex)

		atom.Unlockfile(a,f,c,d)
	}

	if onProgress!= nil {
		if maxval == 0 {
			maxval = 1
		}
		onProgress(maxval, maxval)
	}
	return true, nil
}

func NewBinhostHandler() *BinhostHandler {
	b:= &BinhostHandler{}
	b.short_desc= "Generate a metadata index for binary packages"
	eroot := atom.Settings().ValueDict["EROOT"]
	b._bintree = atom.Db().Values()[eroot].BinTree()
	b._bintree.Populate(false, true, []string{})
	b._pkgindex_file = b._bintree.PkgIndexFile
	b._pkgindex = b._bintree.LoadPkgIndex()
	return b
}
