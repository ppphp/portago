package binhost

import (
	"fmt"
	"github.com/ppphp/portago/atom"
	"os"
	"sort"
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

func(b *BinhostHandler) _need_update(cpv, data)bool{
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
	s = os.lstat(pkg_path)
	except OSError as e:
	if e.errno not in (errno.ENOENT, errno.ESTALE):
	raise
	return False

try:
	if long(mtime) != s[stat.ST_MTIME]:
	return True
	if long(size) != long(s.st_size):
	return True
	except ValueError:
	return True

	return False
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
	missing := []string{}
	stale := []string{}
	metadata := map[string]map[string]string{}
	for _, d := range pkgindex.packages{
		cpv := atom.NewPkgStr(d["CPV"], d, bintree.settings, "", "", "", 0, "", "", 0, nil)
		d["CPV"] = cpv.string
		metadata[_instance_key(cpv, false).string] = d
		if ! bintree.dbapi.cpv_exists(cpv) {
			stale=append(stale, cpv.string)
		}
	}

	for _, cpv := range cpv_all{
		d := metadata[_instance_key(cpv, false).string]
		if len(d)== 0 || b._need_update(cpv, d) {
			missing=append(missing, cpv)
		}
	}

	if len(missing)!= 0 || len(stale)!= 0 {
		a, b, c, d, _ := atom.Lockfile(b._pkgindex_file, true, false, "", 0)
	try:
		b._pkgindex = pkgindex = (bintree._populate_local() or
		bintree._load_pkgindex())
		cpv_all = b._bintree.dbapi.cpv_all()
		cpv_all.sort()

		missing = []string{}
		stale = []string{}
		metadata = map[string]string{}
		for d in pkgindex.packages:
		cpv = _pkg_str(d["CPV"], metadata=d,
			settings=bintree.settings)
		d["CPV"] = cpv
		metadata[_instance_key(cpv)] = d
		if not bintree.dbapi.cpv_exists(cpv):
		stale.append(cpv)

		for cpv in cpv_all:
		d = metadata.get(_instance_key(cpv))
		if not d or self._need_update(cpv, d):
		missing.append(cpv)

		maxval = len(missing)
		for i, cpv in enumerate(missing):
		d = bintree._pkgindex_entry(cpv)
	try:
		bintree._eval_use_flags(cpv, d)
		except portage.exception.InvalidDependString:
		writemsg("!!! Invalid binary package: "%s"\n" % \
		bintree.getname(cpv), noiselevel=-1)
		else:
		metadata[_instance_key(cpv)] = d

		if onProgress!= nil {
			onProgress(maxval, i+1)
		}

		for _, cpv := range stale{

			delete(metadata,_instance_key(cpv, false).string)
		}

		bintree.populated = false

		delete(pkgindex.packages[:])
		pkgindex.packages.extend(metadata.values())
		bintree._update_pkgindex_header(b._pkgindex.header)
		bintree._pkgindex_write(b._pkgindex)

		atom.unlockfile(a,b,c,d)
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
	b._bintree.Populate(true, []string{})
	b._pkgindex_file = b._bintree.PkgIndexFile
	b._pkgindex = b._bintree.LoadPkgIndex()
	return b
}
