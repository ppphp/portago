package manifest

import (
	"fmt"
	"github.com/ppphp/portago/pkg/checksum"
	"github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/dbapi"
	"github.com/ppphp/portago/pkg/exception"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/repository"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/versions"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

var _manifest_re = regexp.MustCompile(
"^(" + "BLAKE2B|SHA512" + //strings.Join(MANIFEST2_HASH_DEFAULTS, "|") +
	") (\\S+)( \\d+( \\S+ \\S+)+)$")

type FileNotInManifestException struct {
	*exception.PortageException
}

func manifest2AuxfileFilter(filename string)bool {
	filename = strings.Trim(filename, string(os.PathSeparator))
	mysplit := strings.Split(filename, string(os.PathSeparator))
	if myutil.Ins(mysplit, "CVS") {
		return false
	}
	for _, x := range mysplit {
		if x[:1] == "." {
			return false
		}
	}
	return !(filename[:7] == "digest-")
}

func manifest2MiscfileFilter(filename string)bool {
	return !(filename == "Manifest" || strings.HasSuffix(filename,".ebuild"))
}

func guessManifestFileType(filename string)string {
	if strings.HasPrefix(filename, "files"+string(os.PathSeparator)+"digest-") {
		return ""
	}
	if strings.HasPrefix(filename, "files"+string(os.PathSeparator)) {
		return "AUX"
	} else if strings.HasSuffix(filename, ".ebuild") {
		return "EBUILD"
	} else if filename == "ChangeLog" || filename == "metadata.xml" {
		return "MISC"
	} else {
		return "DIST"
	}
}

func guessThinManifestFileType(filename string)string {
	typee := guessManifestFileType(filename)
	if typee != "DIST" {
		return ""
	}
	return "DIST"
}

func parseManifest2(line string) *Manifest2Entry {
	//if ! isinstance(line, basestring) {
	//	line = strings.Join(line, " ")
	//}
	var myentry *Manifest2Entry = nil
	match := _manifest_re.FindStringSubmatch(line)
	if match != nil {
		tokens := strings.Fields(match[3])
		hashes := map[string]string{}
		for i := 1; i < len(tokens); i += 2 {
			hashes[tokens[i]] = tokens[i+1]
		}
		hashes["size"] = tokens[0]
		myentry = NewManifest2Entry(match[1], match[2], hashes)
	}
	return myentry
}

type ManifestEntry struct {
	typee,name string
	hashes map[string]string
}

func NewManifestEntry( typee,name string,hashes map[string]string )*ManifestEntry {
	m := &ManifestEntry{}

	m.typee,m.name,m.hashes = typee,name,hashes
	return m
}

type Manifest2Entry struct {
	*ManifestEntry
}

func (m*Manifest2Entry)__str__()string {
	myline := m.typee + " " + m.name + " " + m.hashes["size"]
	myhashkeys := []string{}
	for k := range m.hashes {
		if k != "size" {
			myhashkeys = append(myhashkeys, k)
		}
	}
	sort.Strings(myhashkeys)
	for _, h := range myhashkeys {
		myline += " " + h + " " + m.hashes[h]
	}
	return myline
}

func (m*Manifest2Entry) __eq__( other *Manifest2Entry) bool {
	if m.typee != other.typee ||
		m.name != other.name {
		return false
	}
	if len(m.hashes) != len(other.hashes){
		return false
	}else {
		for k,v:= range m.hashes {
			if other.hashes[k]!= v{
				return false
			}
		}
	}
	return true
}

func (m*Manifest2Entry) __ne__(other *Manifest2Entry)  bool{
	return !m.__eq__(other)
}


func NewManifest2Entry( typee,name string,hashes map[string]string)*Manifest2Entry {
	m := &Manifest2Entry{}

	m.typee, m.name, m.hashes = typee, name, hashes
	return m
}

type Manifest struct {
	_find_invalid_path_char                                func(string)int
	pkgdir, distdir                                        string
	fhashdict                                              map[string]map[string]map[string]string
	hashes, required_hashes                                map[string]bool
	thin, allow_missing, allow_create, strict_misc_digests bool
	guessType                                              func(string) string
	parsers                                                []func(string) *Manifest2Entry
	fetchlist_dict                                         *dbapi.FetchlistDict
}

// "", nil, false, false, false, true, nil, nil, nil, true
func NewManifest( pkgdir, distdir string, fetchlist_dict *dbapi.FetchlistDict, from_scratch,
	thin, allow_missing, allow_create bool, hashes map[string]bool, required_hashes map[string]bool,
find_invalid_path_char func(string)int, strict_misc_digests bool)*Manifest {
	m := &Manifest{}
	m.parsers = []func(string)*Manifest2Entry{parseManifest2}

	if find_invalid_path_char == nil {
		find_invalid_path_char = func(s string) int {
			return repository.findInvalidPathChar(s,0,0)
		}
	}
	m._find_invalid_path_char = find_invalid_path_char
	m.pkgdir = strings.TrimRight(pkgdir, string(os.PathSeparator)) + string(os.PathSeparator)
	m.fhashdict = map[string]map[string]map[string]string{}
	m.hashes = map[string]bool{}
	m.required_hashes = map[string]bool{}

	if hashes == nil {
		hashes = _const.MANIFEST2_HASH_DEFAULTS
	}
	if required_hashes == nil {
		required_hashes = hashes
	}

	for k := range hashes {
		m.hashes[k] = true
	}

	for hashname := range m.hashes{
		if !checksum.GetValidChecksumKeys()[hashname] {
			delete(m.hashes, hashname)
		}
	}

	m.hashes["size"] = true

	for k := range required_hashes{
		m.required_hashes[k]=true
	}


	for k := range m.required_hashes{
		if !m.hashes[k]{
			delete(m.required_hashes, k)
		}
	}

	for t := range _const.MANIFEST2_IDENTIFIERS {
		m.fhashdict[t] = map[string]map[string]string{}
	}
	if ! from_scratch {
		m._read()
	}
	if fetchlist_dict != nil {
		m.fetchlist_dict = fetchlist_dict
	} else {
		m.fetchlist_dict = dbapi.NewFetchlistDict("", nil, nil)
	}
	m.distdir = distdir
	m.thin = thin
	if thin {
		m.guessType = guessThinManifestFileType
	} else {
		m.guessType = guessManifestFileType
	}
	m.allow_missing = allow_missing
	m.allow_create = allow_create
	m.strict_misc_digests = strict_misc_digests

	return m
}

func (m*Manifest) getFullname() string {
	return filepath.Join(m.pkgdir, "Manifest")
}

func (m*Manifest) getDigests() map[string]map[string]string {
	rval := map[string]map[string]string{}
	for t := range _const.MANIFEST2_IDENTIFIERS {
		for k, v := range m.fhashdict[t] {
			rval[k] = v
		}
	}
	return rval
}

func (m*Manifest) getTypeDigests( ftype string) map[string]map[string]string {
	return m.fhashdict[ftype]
}

// nil, ""
func (m*Manifest) _readManifest( file_path string, myhashdict map[string]map[string]map[string]string, mytype string) map[string]map[string]map[string]string {
	f, err := ioutil.ReadFile(file_path)
	if err != nil {
		if err == syscall.ENOENT {
			//raise FileNotFound(file_path)
		} else {
			//raise
		}
	}
	if myhashdict == nil {
		myhashdict = map[string]map[string]map[string]string{}
	}
	m._parseDigests(strings.Split(string(f), "\n"), myhashdict, mytype)
	return myhashdict
}

func (m*Manifest) _read() {
	//try{
		m._readManifest(m.getFullname(), m.fhashdict, "")
	//}except
	//FileNotFound{
	//	pass
	//}
}

func (m*Manifest) _parseManifestLines( mylines []string) []*Manifest2Entry {
	ret := []*Manifest2Entry{}
	for _, myline := range mylines {
		for _, parser := range m.parsers {
			myentry := parser(myline)
			if myentry != nil {
				ret = append(ret, myentry)
				break
			}
		}
	}
	return ret
}

// nil, ""
func (m*Manifest) _parseDigests( mylines []string, myhashdict map[string]map[string]map[string]string, mytype string) map[string]map[string]map[string]string {
	if myhashdict == nil {
		myhashdict = map[string]map[string]map[string]string{}
	}
	for _, myentry := range m._parseManifestLines(mylines) {
		myentry_type := ""
		if mytype == "" {
			myentry_type = myentry.typee
		} else {
			myentry_type = mytype
		}
		if _, ok := myhashdict[myentry_type]; !ok {
			myhashdict[myentry_type] = map[string]map[string]string{}
		}
		if _, ok := myhashdict[myentry_type][myentry.name]; !ok {
			myhashdict[myentry_type][myentry.name] = map[string]string{}
		}
		for k, v := range myentry.hashes {
			myhashdict[myentry_type][myentry.name][k] = v
		}
	}
	return myhashdict
}

func (m*Manifest) _createManifestEntries() []*Manifest2Entry {
	valid_hashes := myutil.CopyMapSB(checksum.GetValidChecksumKeys())
	valid_hashes["size"] = true
	mytypes := []string{}
	for k := range m.fhashdict {
		mytypes = append(mytypes, k)
	}
	sort.Strings(mytypes)
	ret := []*Manifest2Entry{}
	for _, t := range mytypes {
		myfiles := []string{}
		for k := range m.fhashdict[t] {
			myfiles = append(myfiles, k)
		}
		sort.Strings(myfiles)
		for _, f := range myfiles {
			myentry := NewManifest2Entry(
				t, f, myutil.CopyMapSS(m.fhashdict[t][f]))
			for h := range (myentry.hashes) {
				if !valid_hashes[h] {
					delete(myentry.hashes, h)
				}
			}
			ret = append(ret, myentry)
		}
	}
	return ret
}

func (m*Manifest) checkIntegrity() {
	for t := range m.fhashdict {
		for f := range m.fhashdict[t] {
			diff := myutil.CopyMapSB(m.required_hashes)
			for k := range m.fhashdict[t][f] {
				delete(diff, k)
			}
			if len(diff) > 0 {
				//raise MissingParameter(_("Missing %s checksum(s): %s %s") %
				//(strings.Join(diff, " "), t, f))
			}
		}
	}
}

// false, false
func (m*Manifest) write( sign, force bool) bool {

	rval := false
	if !m.allow_create {
		return rval
	}
	m.checkIntegrity()
	//try{
	myentries := m._createManifestEntries()
	update_manifest := true
	preserved_stats := map[string]*syscall.Stat_t{}
	var ps *syscall.Stat_t
	err := syscall.Stat(m.pkgdir, ps)
	if err == nil {
		preserved_stats[strings.TrimRight(m.pkgdir, string(os.PathSeparator))]=ps
		if len(myentries) > 0 && !force {
			//try{
			f, err := os.Open(m.getFullname())
			var ls []byte
			if err == nil {
				ls, err = ioutil.ReadAll(f)
			}
			var oldentries []*Manifest2Entry
			if err == nil {
				oldentries = m._parseManifestLines(strings.Split(string(ls), "\n"))
			}
			var ps *syscall.Stat_t
			if err == nil {
				err = syscall.Fstat(int(f.Fd()), ps)
			}
			if err == nil {
				preserved_stats[m.getFullname()] = ps
				if len(oldentries) == len(myentries) {
					update_manifest = false
					for i := range oldentries {
						if oldentries[i] != myentries[i] {
							update_manifest = true
							break
						}
					}
				}
			}
			if err != nil {
				//}except (IOError, OSError) as e{
				if err == syscall.ENOENT {
					//pass
				} else {
					//raise
				}
			}
		}
		if update_manifest {
			if len(myentries) > 0 || !(m.thin || m.allow_missing) {
				ms := []string{}
				for _, myentry := range myentries {
					ms = append(ms, fmt.Sprintf(myentry.__str__()))
				}
				util.write_atomic(m.getFullname(), strings.Join(ms, " "), os.O_RDWR|os.O_CREATE, true)
				m._apply_max_mtime(preserved_stats, myentries)
				rval = true
			} else {
				if err := syscall.Unlink(m.getFullname()); err != nil {
					//}except OSError as e{
					if err != syscall.ENOENT {
						//raise
					}
				}
				rval = true
			}
		}

		if sign {
			m.sign()
		}
	}
	if err !=nil {
	//}except (IOError, OSError) as e{
			if err == syscall.EACCES{
	//		raise PermissionDenied(str(e))
		}
	//		raise
	//	}
	}
	return rval
}

func (m*Manifest) _apply_max_mtime( preserved_stats map[string]*syscall.Stat_t, entries []*Manifest2Entry) {

	var max_mtime int64
	_update_max := func(st *syscall.Stat_t) int64  {
		if max_mtime != 0 && max_mtime > st.Mtim.Nano() {
			return max_mtime
		} else {
			return st.Mtim.Nano()
		}
	}
	_stat := func (path string) *syscall.Stat_t{
		if p, ok := preserved_stats[path]; ok {
			return p
		} else {
			var ps *syscall.Stat_t
			syscall.Stat(path, ps)
			return ps
		}
	}

	for _, stat_result:= range preserved_stats{
		max_mtime = _update_max(stat_result)
	}

	for _, entry:= range entries{
		if entry.typee == "DIST" {
			continue
		}
		abs_path := ""
		if entry.typee == "AUX"{
			abs_path = filepath.Join(m.pkgdir, "files", entry.name)
		} else {
			abs_path = filepath.Join(m.pkgdir, entry.name)
		}
		max_mtime = _update_max(_stat(abs_path))
	}

	if ! m.thin {
		filepath.Walk(strings.TrimRight(m.pkgdir, string(os.PathSeparator)), func(path string, info os.FileInfo, err error) error {
			max_mtime = _update_max(_stat(filepath.Dir(path)))
			return nil
		})
	}

	if max_mtime != 0 {
		for path := range preserved_stats {
			if err := syscall.Utime(path, &syscall.Utimbuf{max_mtime, max_mtime}); err != nil {
				//except OSError as e:
				util.WriteMsgLevel(fmt.Sprintf("!!! utime('%s', (%s, %s)): %s\n",
					path, max_mtime, max_mtime, err),
				30, -1)
			}
		}
	}
}

func (m*Manifest) sign() {
	//raise NotImplementedError()
}

func (m*Manifest) validateSignature() {
	//raise NotImplementedError()
}

// nil, false
func (m*Manifest) addFile( ftype, fname string, hashdict map[string]string, ignoreMissing bool) {
	if ftype == "AUX" && !strings.HasPrefix(fname, "files/") {
		fname = filepath.Join("files", fname)
	}
	if !myutil.PathExists(m.pkgdir+fname) && !ignoreMissing {
		//raise FileNotFound(fname)
	}
	if !_const.MANIFEST2_IDENTIFIERS[ftype] {
		//raise InvalidDataType(ftype)
	}
	if ftype == "AUX" && strings.HasPrefix(fname, "files") {
		fname = fname[6:]
	}
	m.fhashdict[ftype][fname] = map[string]string{}
	if hashdict != nil {
		for k,v := range hashdict {
			m.fhashdict[ftype][fname][k]=v
		}
	}
	mrh := myutil.CopyMapSB(m.required_hashes)
	for k := range m.fhashdict[ftype][fname]{
		delete(mrh, k)
	}
	if len(mrh)>0 {
		m.updateFileHashes(ftype, fname, false, ignoreMissing, false)
	}
}

func (m*Manifest) removeFile(ftype , fname string) {
	delete(m.fhashdict[ftype], fname)
}

func (m*Manifest) hasFile( ftype, fname string) bool{
	_, ok := m.fhashdict[ftype][fname]
	return ok
}

func (m*Manifest) findFile( fname string) string {
	for t := range _const.MANIFEST2_IDENTIFIERS {
		if _, ok := m.fhashdict[t][fname]; ok {
			return t
		}
	}
	return ""
}

// false, false, false, map[string]bool{}
func (m*Manifest) create( checkExisting, assumeDistHashesSometimes,
assumeDistHashesAlways bool, requiredDistfiles map[string]bool) {

	if !m.allow_create {
		return
	}
	if checkExisting {
		m.checkAllHashes(false)
	}
	distfilehashes := map[string]map[string]string{}
	if assumeDistHashesSometimes || assumeDistHashesAlways {
		distfilehashes = m.fhashdict["DIST"]
	}
	m = NewManifest(m.pkgdir, m.distdir,
		m.fetchlist_dict, true, m.thin, m.allow_missing,
		m.allow_create, m.hashes, m.required_hashes,
		m._find_invalid_path_char, m.strict_misc_digests)
	pn := filepath.Base(strings.TrimRight(m.pkgdir, string(os.PathSeparator)))
	cat := m._pkgdir_category()

	pkgdir := m.pkgdir
	cpvlist := []string{}
	if m.thin {
		cpvlist = m._update_thin_pkgdir(cat, pn, pkgdir)
	} else {
		cpvlist = m._update_thick_pkgdir(cat, pn, pkgdir)
	}

	distlist := map[string]bool{}
	for _, cpv := range cpvlist {
		distlist.update(m._getCpvDistfiles(cpv))
	}

	if requiredDistfiles == nil {
		requiredDistfiles = map[string]bool{}
	} else if len(requiredDistfiles) == 0 {
		requiredDistfiles = myutil.CopyMapSB(distlist)
	}
	required_hash_types := map[string]bool{}
	required_hash_types["size"] = true
	for k := range m.required_hashes {
		required_hash_types[k] = true
	}
	for f := range distlist {
		fname := filepath.Join(m.distdir, f)

		mystat, err := os.Stat(fname)
		if err != nil {
			//}except OSError{
			//	pass
		}
		_, ok := distfilehashes[f]
		rht := myutil.CopyMapSB(required_hash_types)
		for k := range distfilehashes[f] {
			delete(rht, k)
		}
		eq := len(distfilehashes[f]) == len(m.hashes)
		if eq {
			for k := range distfilehashes[f] {
				if !m.hashes[k] {
					eq = false
					break
				}
			}
		}
		if ok &&
			len(rht) == 0 &&
			((assumeDistHashesSometimes && mystat == nil) ||
				(assumeDistHashesAlways && mystat == nil) ||
				(assumeDistHashesAlways && mystat != nil &&
					eq && distfilehashes[f]["size"] == fmt.Sprint(mystat.Size()))) {
			m.fhashdict["DIST"][f] = distfilehashes[f]
		} else {
			//try{
			hs := []string{}
			for h := range m.hashes {
				hs = append(hs, h)
			}
			for k, v := range checksum.PerformMultipleChecksums(fname, hs, false) {
				m.fhashdict["DIST"][f][k] = string(v)
			}
			//}except FileNotFound{
			//	if f in requiredDistfiles{
			//	raise
			//}
			//}
		}
	}
}

func (m*Manifest) _is_cpv( cat, pn, filename string) string{
	if !strings.HasSuffix(filename, ".ebuild") {
		return ""
	}
	pf := filename[:len(filename)-7]
	ps := versions.pkgSplit(pf, "")
	cpv := fmt.Sprintf("%s/%s" , cat, pf)
	if ps==[3]string{} {
		//raise PortagePackageException(
		//	_("Invalid package name: '%s'") % cpv)
	}
	if ps[0] != pn {
		//raise PortagePackageException(
		//	_("Package name does not "
		//"match directory name: '%s'") % cpv)
	}
	return cpv
}

func (m*Manifest) _update_thin_pkgdir( cat, pn, pkgdir string) []string {
	var pkgdir_dirs, pkgdir_files []string
	filepath.Walk(pkgdir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			pkgdir_dirs = append(pkgdir_dirs, info.Name())
		} else {
			pkgdir_files = append(pkgdir_files, info.Name())
		}
		return filepath.SkipDir
	})
	cpvlist := []string{}
	for _, f := range pkgdir_files {
		if f[:1] == "." {
			continue
		}
		pf := m._is_cpv(cat, pn, f)
		if pf != "" {
			cpvlist = append(cpvlist, pf)
		}
	}
	return cpvlist
}

func (m*Manifest) _update_thick_pkgdir( cat, pn, pkgdir string) []string{
	var pkgdir_dirs, pkgdir_files []string
	filepath.Walk(pkgdir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			pkgdir_dirs = append(pkgdir_dirs, info.Name())
		} else {
			pkgdir_files = append(pkgdir_files, info.Name())
		}
		return filepath.SkipDir
	})

	cpvlist := []string{}
	for _, f := range pkgdir_files {
		if f[:1] == "." {
			continue
		}
		mytype := ""
		pf := m._is_cpv(cat, pn, f)
		if pf != "" {
			mytype = "EBUILD"
			cpvlist = append(cpvlist, pf)
		} else if m._find_invalid_path_char(f) == -1 &&
			manifest2MiscfileFilter(f) {
			mytype = "MISC"
		} else {
			continue
		}
		mh := []string{}
		for k := range m.hashes {
			mh = append(mh, k)
		}
		for k,v := range checksum.PerformMultipleChecksums(m.pkgdir+f, mh, false){
			m.fhashdict[mytype][f][k]=string(v)
		}
	}
	recursive_files := []string{}

	pkgdir = m.pkgdir
	cut_len := len(filepath.Join(pkgdir, "files") + string(os.PathSeparator))
	filepath.Walk(filepath.Join(pkgdir, "files"), func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			full_path := filepath.Join(path, info.Name())
			recursive_files= append(recursive_files, full_path[cut_len:])
		}
		return err
	})
	for _, f := range recursive_files {
		if m._find_invalid_path_char(f) != -1 ||
			!manifest2AuxfileFilter(f) {
			continue
		}
		mh := []string{}
		for k := range m.hashes {
			mh = append(mh, k)
		}
		for k,v := range checksum.PerformMultipleChecksums(
			filepath.Join(m.pkgdir, "files", strings.TrimLeft(f, string(os.PathSeparator))), mh, false){
			m.fhashdict["AUX"][f][k]=string(v)
		}
	}
	return cpvlist
}

func (m*Manifest) _pkgdir_category() string {
	return strings.Split(strings.TrimRight(m.pkgdir, string(os.PathSeparator)), string(os.PathSeparator))[-2]
}

func (m*Manifest) _getAbsname( ftype, fname string) string {
	absname := ""
	if ftype == "DIST" {
		absname = filepath.Join(m.distdir, fname)
	} else if ftype == "AUX" {
		absname = filepath.Join(m.pkgdir, "files", fname)
	} else {
		absname = filepath.Join(m.pkgdir, fname)
	}
	return absname
}

// false
func (m*Manifest) checkAllHashes( ignoreMissingFiles bool) {
	for t := range _const.MANIFEST2_IDENTIFIERS {
		m.checkTypeHashes(t, ignoreMissingFiles, nil)
	}
}

// false, nil
func (m*Manifest) checkTypeHashes( idtype string, ignoreMissingFiles bool, hash_filter *checksum.hashFilter) {
	for f:= range m.fhashdict[idtype]{
		m.checkFileHashes(idtype, f, ignoreMissingFiles, hash_filter)
	}
}

// false, nil
func (m*Manifest) checkFileHashes( ftype, fname string, ignoreMissing bool, hash_filter *checksum.hashFilter) (bool, string){
	digests := checksum.FilterUnaccelaratedHashes(m.fhashdict[ftype][fname])
	if hash_filter != nil {
		digests = checksum.ApplyHashFilter(digests, hash_filter)
	}
	//try{
	ok, reason, _, _ := checksum.VerifyAll(m._getAbsname(ftype, fname), digests, 0, 0)
	if !ok {
		//raise DigestException(tuple([m._getAbsname(ftype, fname)]+list(reason)))
	}
	return ok, reason
	//if err != nil {
		//}except FileNotFound as e{
		//if !ignoreMissing {
			//raise
		//}
		//return false, fmt.Sprintf("File Not Found: '%s'", err)
	//}
}

// true, false, false
func (m*Manifest) checkCpvHashes( cpv string, checkDistfiles, onlyDistfiles, checkMiscfiles bool) {

	if !onlyDistfiles {
		m.checkTypeHashes("AUX",  false, nil)
		if checkMiscfiles {
			m.checkTypeHashes("MISC",  false, nil)
		}
		ebuildname := fmt.Sprintf("%s.ebuild", m._catsplit(cpv)[1])
		m.checkFileHashes("EBUILD", ebuildname, false, nil)
	}
	if checkDistfiles || onlyDistfiles {
		for f in m._getCpvDistfiles(cpv) {
			m.checkFileHashes("DIST", f,  false, nil)
		}
	}
}

func (m*Manifest) _getCpvDistfiles( cpv string) {
	return m.fetchlist_dict.__getitem__(cpv)
}

func (m*Manifest) getDistfilesSize( fetchlist []string) int {
	total_bytes := 0
	for _, f := range fetchlist{
		sz, _ := strconv.Atoi(m.fhashdict["DIST"][f]["size"])
		total_bytes += sz
	}
	return total_bytes
}

// true, false, false
func (m*Manifest) updateFileHashes( ftype, fname string, checkExisting, ignoreMissing, reuseExisting bool) {
	if checkExisting {
		m.checkFileHashes(ftype, fname, ignoreMissing, nil)
	}
	if _, ok := m.fhashdict[ftype][fname]; !ignoreMissing && !ok {
		//raise FileNotInManifestException(fname)
	}
	if _, ok := m.fhashdict[ftype][fname]; !ok {
		m.fhashdict[ftype][fname] = map[string]string{}
	}
	myhashkeys := []string{}
	for k := range m.hashes {
		myhashkeys = append(myhashkeys, k)
	}
	if reuseExisting {
		for h := range m.fhashdict[ftype][fname] {
			if myutil.Ins(myhashkeys, h) {
				an := []string{}
				for _, v := range myhashkeys {
					if v != h {
						an = append(an, v)
					}
				}
				myhashkeys = an
			}
		}
	}
	myhashes := checksum.PerformMultipleChecksums(m._getAbsname(ftype, fname), myhashkeys, false)
	for k, v := range myhashes {
		m.fhashdict[ftype][fname][k] = string(v)
	}
}

// false, true
func (m*Manifest) updateTypeHashes( idtype string, checkExisting , ignoreMissingFiles bool) {
	for fname := range m.fhashdict[idtype]{
		m.updateFileHashes(idtype, fname, checkExisting, ignoreMissingFiles, false)
	}
}

// false, true
func (m*Manifest) updateAllHashes( checkExisting, ignoreMissingFiles bool) {
	for idtype:= range _const.MANIFEST2_IDENTIFIERS {
		m.updateTypeHashes(idtype,  checkExisting, ignoreMissingFiles)
	}
}

// true
func (m*Manifest) updateCpvHashes( cpv string, ignoreMissingFiles bool) {

	m.updateTypeHashes("AUX", false,  ignoreMissingFiles)
	m.updateTypeHashes("MISC",false,  ignoreMissingFiles)
	ebuildname := fmt.Sprintf("%s.ebuild" , m._catsplit(cpv)[1])
	m.updateFileHashes("EBUILD", ebuildname, true,ignoreMissingFiles, false)
	for f in m._getCpvDistfiles(cpv){
		m.updateFileHashes("DIST", f, true, ignoreMissingFiles, false)
	}
}

// true, false, false
func (m*Manifest) updateHashesGuessType( fname string,checkExisting, ignoreMissing, reuseExisting bool) {
	mytype := m.guessType(fname)
	if mytype == "AUX" {
		fname = fname[len("files"+string(os.PathSeparator)):]
	} else if mytype == "" {
		return
	}
	myrealtype := m.findFile(fname)
	if myrealtype != "" {
		mytype = myrealtype
	}
	m.updateFileHashes(mytype, fname, checkExisting, ignoreMissing, reuseExisting)
}

func (m*Manifest) getFileData( ftype, fname, key string) string {
	return m.fhashdict[ftype][fname][key]
}

func (m*Manifest) getVersions() []int {
	rVal := []int{}
	mfname := m.getFullname()
	if !myutil.PathExists(mfname) {
		return rVal
	}
	f, _ := ioutil.ReadFile(mfname)

	for _, l := range strings.Split(string(f), "\n") {
		mysplit := strings.Fields(l)
		if len(mysplit) > 4 && _const.MANIFEST2_IDENTIFIERS[mysplit[0]] && ((len(mysplit)-3)%2) == 0 && !myutil.Ini(rVal,2){
			rVal=append(rVal, 2)
		}
	}
	return rVal
}

func (m*Manifest) _catsplit( pkg_key string) []string {
	return strings.SplitN(pkg_key, "/", 2)
}
