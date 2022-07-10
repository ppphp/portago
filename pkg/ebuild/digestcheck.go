package ebuild

import (
	"fmt"
	"github.com/ppphp/portago/pkg/checksum"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/manifest"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/util/msg"
	"path/filepath"
)

// false, nil, nil
func Digestcheck(myfiles []string, mysettings *config.Config, strict bool, mf *manifest.Manifest) int {

	if mysettings.ValueDict["EBUILD_SKIP_MANIFEST"] == "1" {
		return 1
	}
	pkgdir := mysettings.ValueDict["O"]
	hash_filter := checksum.NewHashFilter(mysettings.ValueDict["PORTAGE_CHECKSUM_FILTER"])
	if hash_filter.trasparent {
		hash_filter = nil
	}
	if mf == nil {
		rc := mysettings.Repositories.GetRepoForLocation(
			filepath.Dir(filepath.Dir(pkgdir)))
		mf = rc.load_manifest(pkgdir, mysettings.ValueDict["DISTDIR"],nil, false)
	}
	eout := output.NewEOutput(false)
	eout.quiet = mysettings.ValueDict["PORTAGE_QUIET"] == "1"
try:
	if !mf.thin&& strict && !myutil.Inmss(mysettings.ValueDict,"PORTAGE_PARALLEL_FETCHONLY") {
		if _, ok:= mf.fhashdict["EBUILD"]; ok {
			eout.Ebegin("checking ebuild checksums ;-)")
			mf.checkTypeHashes("EBUILD", false, hash_filter)
			eout.Eend(0, "")
		}
		if _, ok := mf.fhashdict["AUX"]; ok {
			eout.Ebegin("checking auxfile checksums ;-)")
			mf.checkTypeHashes("AUX", false, hash_filter)
			eout.Eend(0, "")
		}
		if mf.strict_misc_digests &&
			mf.fhashdict.get("MISC") {
			eout.Ebegin("checking miscfile checksums ;-)")
			mf.checkTypeHashes("MISC", true, hash_filter)
			eout.Eend(0, "")
		}
	}
	for _, f := range myfiles{
		eout.Ebegin(fmt.Sprintf("checking %s ;-)", f))
		ftype := mf.findFile(f)
		if ftype == "" {
			if mf.allow_missing {
				continue
			}
			eout.Eend(1, "")
			msg.WriteMsg(fmt.Sprintf("\n!!! Missing digest for '%s'\n", f, ), -1, nil)
			return 0
		}
		mf.checkFileHashes(ftype, f, false, hash_filter)
		eout.Eend(0, "")
	}
	except
	FileNotFound
	as
e:
	eout.Eend(1, "")
	msg.WriteMsg(fmt.Sprintf("\n!!! A file listed in the Manifest could not be found: %s\n", e),
		-1, nil)
	return 0
	except
	DigestException
	as
e:
	eout.Eend(1, "")
	msg.WriteMsg("\n!!! Digest verification failed:\n",  -1, nil)
	msg.WriteMsg(fmt.Sprintf("!!! %s\n",e.value[0]),  -1, nil)
	msg.WriteMsg(fmt.Sprintf("!!! Reason: %s\n",e.value[1]),  -1, nil)
	msg.WriteMsg(fmt.Sprintf("!!! Got: %s\n",e.value[2]),  -1, nil)
	msg.WriteMsg(fmt.Sprintf("!!! Expected: %s\n",e.value[3]),  -1, nil)
	return 0
	if mf.thin || mf.allow_missing {
		return 1
	}
	lds,_:= myutil.ListDir(pkgdir)
	for _, f:= range lds {
		pf := ""
		if f[len(f)-7:] == ".ebuild" {
			pf = f[:len(f)-7]
		}
		if pf != "" &!mf.hasFile("EBUILD", f) {
			msg.WriteMsg(fmt.Sprintf("!!! A file is not listed in the Manifest: '%s'\n",
				filepath.Join(pkgdir, f), -1, nil)
			if strict {
				return 0
			}
		}
	}
	filesdir := filepath.Join(pkgdir, "files")

	for parent, dirs, files
		in
	os.walk(filesdir):
try:
	parent = _unicode_decode(parent,
		encoding = _encodings['fs'], errors = 'strict')
	except
UnicodeDecodeError:
	parent = _unicode_decode(parent,
		encoding = _encodings['fs'], errors = 'replace')
	msg.WriteMsg(_("!!! Path contains invalid "
	"character(s) for encoding '%s': '%s'")
	% (_encodings['fs'], parent), noiselevel = -1)
	if strict:
	return 0
	continue
	for d
		in
	dirs:
	d_bytes = d
try:
	d = _unicode_decode(d,
		encoding = _encodings['fs'], errors = 'strict')
	except
UnicodeDecodeError:
	d = _unicode_decode(d,
		encoding = _encodings['fs'], errors = 'replace')
	msg.WriteMsg(_("!!! Path contains invalid "
	"character(s) for encoding '%s': '%s'")
	% (_encodings['fs'], filepath.Join(parent, d)),
	noiselevel = -1)
	if strict:
	return 0
	dirs.remove(d_bytes)
	continue
	if d.startswith(".") or
	d == "CVS":
	dirs.remove(d_bytes)
	for f
		in
	files:
try:
	f = _unicode_decode(f,
		encoding = _encodings['fs'], errors = 'strict')
	except
UnicodeDecodeError:
	f = _unicode_decode(f,
		encoding = _encodings['fs'], errors = 'replace')
	if f.startswith("."):
	continue
	f = filepath.Join(parent, f)[len(filesdir)+1:]
	msg.WriteMsg(_("!!! File name contains invalid "
	"character(s) for encoding '%s': '%s'")
	% (_encodings['fs'], f), noiselevel = -1)
	if strict:
	return 0
	continue
	if f.startswith("."):
	continue
	f = filepath.Join(parent, f)[len(filesdir)+1:]
	file_type = mf.findFile(f)
	if file_type != "AUX" and
	not
	f.startswith("digest-"):
	msg.WriteMsg(_("!!! A file is not listed in the Manifest: '%s'\n") %
		filepath.Join(filesdir, f), noiselevel = -1)
	if strict:
	return 0
	return 1
}
