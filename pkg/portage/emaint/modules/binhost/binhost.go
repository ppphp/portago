package binhost

import (
	"github.com/ppphp/portago/atom"
	"os"
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
	_pkgindex_file, _pkgindex interface{}
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

	pkg_path := b._bintree.getname(cpv)
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



func(b *BinhostHandler) check(self, **kwargs):
onProgress = kwargs.get("onProgress", None)
bintree = self._bintree
bintree._populate_local(reindex=True)
bintree.populated = True
_instance_key = bintree.dbapi._instance_key
cpv_all = self._bintree.dbapi.cpv_all()
cpv_all.sort()
maxval = len(cpv_all)
if onProgress:
onProgress(maxval, 0)
pkgindex = self._pkgindex
missing = []
stale = []
metadata = {}
for d in pkgindex.packages:
cpv = _pkg_str(d["CPV"], metadata=d,
settings=bintree.settings)
d["CPV"] = cpv
metadata[_instance_key(cpv)] = d
if not bintree.dbapi.cpv_exists(cpv):
stale.append(cpv)
for i, cpv in enumerate(cpv_all):
d = metadata.get(_instance_key(cpv))
if not d or self._need_update(cpv, d):
missing.append(cpv)
if onProgress:
onProgress(maxval, i+1)
errors = [""%s" is not in Packages" % cpv for cpv in missing]
for cpv in stale:
errors.append(""%s" is not in the repository" % cpv)
if errors:
return (False, errors)
return (True, None)

func(b *BinhostHandler) fix(self,  **kwargs):
onProgress = kwargs.get("onProgress", None)
bintree = self._bintree
# Force reindex in case pkgdir-index-trusted is enabled.
bintree._populate_local(reindex=True)
bintree.populated = True
_instance_key = bintree.dbapi._instance_key
cpv_all = self._bintree.dbapi.cpv_all()
cpv_all.sort()
maxval = 0
if onProgress:
onProgress(maxval, 0)
pkgindex = self._pkgindex
missing = []
stale = []
metadata = {}
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

if missing or stale:
from portage import locks
pkgindex_lock = locks.lockfile(
self._pkgindex_file, wantnewlockfile=1)
try:
self._pkgindex = pkgindex = (bintree._populate_local() or
bintree._load_pkgindex())
cpv_all = self._bintree.dbapi.cpv_all()
cpv_all.sort()

missing = []
stale = []
metadata = {}
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

if onProgress:
onProgress(maxval, i+1)

for cpv in stale:
del metadata[_instance_key(cpv)]

# We"ve updated the pkgindex, so set it to
# repopulate when necessary.
bintree.populated = False

del pkgindex.packages[:]
pkgindex.packages.extend(metadata.values())
bintree._update_pkgindex_header(self._pkgindex.header)
bintree._pkgindex_write(self._pkgindex)

finally:
locks.unlockfile(pkgindex_lock)

if onProgress:
if maxval == 0:
maxval = 1
onProgress(maxval, maxval)
return (True, None)


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