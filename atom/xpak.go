package atom

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func addtolist(mylist []string, curdir string){
	curdir = NormalizePath(curdir)
	filepath.Walk(curdir, func(path string, info os.FileInfo, err error) error {
		parent := filepath.Dir(path)
		if parent != curdir{
			mylist = append(mylist, parent[len(curdir) + 1:] + string(filepath.Separator))
		}
		if !info.IsDir() {
			mylist=append(mylist, filepath.Join(parent, info.Name())[len(curdir) + 1:])
		}
		return nil
	})
}

func encodeint(myint int)string{
	a := []byte{}
	a=append(a,byte(myint >> 24) & 0xff)
	a=append(a,byte(myint >> 16) & 0xff)
	a=append(a,byte(myint >>  8) & 0xff)
	a=append(a, byte(myint & 0xff))
		return string(a)
	}

func decodeint(mystring string)int{
	myint := uint8(0)
	myint += mystring[3]
	myint += mystring[2] << 8
	myint += mystring[1] << 16
	myint += mystring[0] << 24
	return int(myint)
}

// ""
func xpak(rootdir , outfile string) []byte{
	mylist := []string{}
	addtolist(mylist, rootdir)
	sort.Strings(mylist)
	mydata := map[string]string{}
	for _, x := range mylist {
		if x == "CONTENTS" {
			continue
		}

		s, _ := ioutil.ReadFile(filepath.Join(rootdir, x))
		mydata[x] = string(s)
	}

	xpak_segment := xpak_mem(mydata)
	if outfile!= "" {
		outf, _ := os.OpenFile(outfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		outf.Write(xpak_segment)
		outf.Close()
		return nil
	} else {
		return xpak_segment
	}
}

func xpak_mem(mydata map[string]string)[]byte{
	mydata_encoded := map[string]string{}
	for k, v := range mydata{
		mydata_encoded[k] = v
	}
	mydata = mydata_encoded
	mydata_encoded = nil

	indexglob := ""
	indexpos := 0
	dataglob := ""
	datapos := 0
	for x, newglob := range mydata {
		mydatasize := len(newglob)
		indexglob = indexglob + encodeint(len(x)) + x + encodeint(datapos) + encodeint(mydatasize)
		indexpos = indexpos + 4 + len(x) + 4 + 4
		dataglob = dataglob + newglob
		datapos = datapos + mydatasize
	}
		return []byte("XPAKPACK"+ encodeint(len(indexglob))+ encodeint(len(dataglob))+ indexglob+ dataglob+ "XPAKSTOP")
	}

func xsplit(infile string) bool{
	myfile, _ := os.Open(infile)
	mydat, _ := ioutil.ReadAll(myfile)
	myfile.Close()
	splits := xsplit_mem(string(mydat))
	if splits ==[2]string{} {
		return false
	}

	myfile, _ = os.OpenFile(infile+".index", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)

	myfile.Write([]byte(splits[0]))
	myfile.Close()
	myfile, _ = os.OpenFile(infile+".dat", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)

	myfile.Write([]byte(splits[1]))
	myfile.Close()
	return true
}

func xsplit_mem(mydat string)[2]string{
	if mydat[0:8] != "XPAKPACK"{
	return [2]string{}
	}
	if mydat[-8:] != "XPAKSTOP" {
		return [2]string{}
	}
	indexsize := decodeint(mydat[8:12])
	return [2]string{mydat[16:indexsize + 16], mydat[indexsize + 16:-8]}
	}

func getindex(infile string)string {

	myfile, _ := os.Open(infile)
	myheader := make([]byte, 16)
	myfile.Read(myheader)
	if string(myheader[0:8]) != "XPAKPACK" {
		myfile.Close()
		return ""
	}
	indexsize := decodeint(string(myheader[8:12]))

	myindex := make([]byte, indexsize)
	myfile.Read(myindex)
	myfile.Close()
	return string(myindex)
}

func getboth(infile string)(string,string) {
	myfile, _ := os.Open(infile)
	myheader := make([]byte, 16)
	myfile.Read(myheader)
	if string(myheader[0:8]) != "XPAKPACK" {
		myfile.Close()
		return "", ""
	}
	indexsize := decodeint(string(myheader[8:12]))
	datasize := decodeint(string(myheader[12:16]))
	myindex := make([]byte, indexsize)
	myfile.Read(myindex)
	mydata := make([]byte, datasize)
	myfile.Read(mydata)
	myfile.Close()
	return string(myindex), string(mydata)
}

func listindex(myindex string) {
	for _, x := range getindex_mem(myindex)	{
		print(x)
	}
}

func getindex_mem(myindex string)[]string{
		myindexlen := len(myindex)
		startpos := 0
		myret := []string{}
		for ((startpos + 8) < myindexlen) {
			mytestlen := decodeint(myindex[startpos : startpos+4])
			myret = append(myret, myindex[startpos+4 : startpos+4+mytestlen])
			startpos = startpos + mytestlen + 12
		}
		return myret
	}

func searchindex(myindex, myitem string) (int,int) {
	mylen := len(myitem)
	myindexlen := len(myindex)
	startpos := 0
	for ((startpos + 8) < myindexlen) {
		mytestlen := decodeint(myindex[startpos : startpos+4])
		if mytestlen == mylen {
			if myitem == myindex[startpos+4:startpos+4+mytestlen] {
				datapos := decodeint(myindex[startpos+4+mytestlen : startpos+8+mytestlen])
				datalen := decodeint(myindex[startpos+8+mytestlen : startpos+12+mytestlen])
				return datapos, datalen
			}
		}
		startpos = startpos + mytestlen + 12
	}
	return 0,0
}

func getitem(myid []string, myitem string)  string{
	myindex := myid[0]
	mydata := myid[1]
	myloc0, myloc1 := searchindex(myindex, myitem)
	if myloc0 == 0 && myloc1 == 0 {
		return ""
	}
	return mydata[myloc0 : myloc0+myloc1]
}

func xpand(myid []string, mydest string) {
	mydest = NormalizePath(mydest) + string(filepath.Separator)
	myindex := myid[0]
	mydata := myid[1]
	myindexlen := len(myindex)
	startpos := 0
	for ((startpos + 8) < myindexlen) {
		namelen := decodeint(myindex[startpos : startpos+4])
		datapos := decodeint(myindex[startpos+4+namelen : startpos+8+namelen])
		datalen := decodeint(myindex[startpos+8+namelen : startpos+12+namelen])
		myname := myindex[startpos+4 : startpos+4+namelen]
		filename := filepath.Join(mydest, strings.TrimLeft(myname, string(filepath.Separator)))
		filename = NormalizePath(filename)
		if !strings.HasPrefix(filename, mydest) {
			continue
		}
		dirname := filepath.Dir(filename)
		if dirname != "" {
			if _, err := os.Stat(dirname); err != nil {
				os.MkdirAll(dirname, 0644)
			}
		}
		mydat, _ := os.OpenFile(filename,os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		mydat.Write([]byte(mydata[datapos : datapos+datalen]))
		mydat.Close()
		startpos = startpos + namelen + 12
	}
}

type tbz2 struct {
	file string
	filestat string
	index string
	infosize , xpaksize ,indexsize ,datasize,indexpos,datapos int
}
	func NewTbz2( myfile)*tbz2 {
t:= &tbz2{}
		t.file = myfile
		t.filestat = None
		t.index = ""
		t.infosize = 0
		t.xpaksize = 0
		t.indexsize = None
		t.datasize = None
		t.indexpos = None
		t.datapos = None
		return t
	}

	func (t *tbz2)decompose( datadir, cleanup=1){
		if not t.scan(){
			raise IOError
		if cleanup{
			t.cleanup(datadir)
		if not os.path.exists(datadir){
			os.makedirs(datadir)
		return t.unpackinfo(datadir)
	func (t *tbz2)compose( datadir, cleanup=0){

		return t.recompose(datadir, cleanup)

	func (t *tbz2)recompose( datadir, cleanup=0, break_hardlinks=True){
		xpdata = xpak(datadir)
		t.recompose_mem(xpdata, break_hardlinks=break_hardlinks)
		if cleanup{
			t.cleanup(datadir)

	func (t *tbz2)recompose_mem( xpdata, break_hardlinks=True){
		t.scan() # Don't care about condition... We'll rewrite the data anyway.

		if break_hardlinks and t.filestat and t.filestat.st_nlink > 1{
			tmp_fname = "%s.%d" % (t.file, os.getpid())
			copyfile(t.file, tmp_fname)
			try{
				portage.util.apply_stat_permissions(t.file, t.filestat)
			except portage.exception.OperationNotPermitted{
				pass
			os.rename(tmp_fname, t.file)

		myfile = open(_unicode_encode(t.file,
			encoding=_encodings['fs'], errors='strict'), 'ab+')
		if not myfile{
			raise IOError
		myfile.seek(-t.xpaksize, 2) # 0,2 or -0,2 just mean EOF.
		myfile.truncate()
		myfile.write(xpdata + encodeint(len(xpdata)) + b'STOP')
		myfile.flush()
		myfile.close()
		return 1

	func (t *tbz2)cleanup( datadir){
		datadir_split = os.path.split(datadir)
		if len(datadir_split) >= 2 and len(datadir_split[1]) > 0{
			try{
				shutil.rmtree(datadir)
			except OSError as oe{
				if oe.errno == errno.ENOENT{
					pass
				else{
					raise oe

	func(t *tbz2) scan(){
		a = None
		try{
			mystat = os.stat(t.file)
			if t.filestat{
				changed = 0
				if mystat.st_size != t.filestat.st_size \
					or mystat.st_mtime != t.filestat.st_mtime \
					or mystat.st_ctime != t.filestat.st_ctime{
					changed = True
				if not changed{
					return 1
			t.filestat = mystat
			a = open(_unicode_encode(t.file,
				encoding=_encodings['fs'], errors='strict'), 'rb')
			a.seek(-16, 2)
			trailer = a.read()
			t.infosize = 0
			t.xpaksize = 0
			if trailer[-4:] != b'STOP'{
				return 0
			if trailer[0:8] != b'XPAKSTOP'{
				return 0
			t.infosize = decodeint(trailer[8:12])
			t.xpaksize = t.infosize + 8
			a.seek(-(t.xpaksize), 2)
			header = a.read(16)
			if header[0:8] != b'XPAKPACK'{
				return 0
			t.indexsize = decodeint(header[8:12])
			t.datasize = decodeint(header[12:16])
			t.indexpos = a.tell()
			t.index = a.read(t.indexsize)
			t.datapos = a.tell()
			return 2
		except SystemExit{
			raise
		except{
			return 0
		finally{
			if a is not None{
				a.close()

	func(t *tbz2) filelist(){

		if not t.scan(){
			return None
		return getindex_mem(t.index)

	func(t *tbz2) getfile(, myfile, mydefault=None){

		if not t.scan(){
			return None
		myresult = searchindex(t.index, myfile)
		if not myresult{
			return mydefault
		a = open(_unicode_encode(t.file,
			encoding=_encodings['fs'], errors='strict'), 'rb')
		a.seek(t.datapos + myresult[0], 0)
		myreturn = a.read(myresult[1])
		a.close()
		return myreturn

	func(t *tbz2) getelements( myfile){

		mydat = t.getfile(myfile)
		if not mydat{
			return []
		return mydat.split()

	func(t *tbz2) unpackinfo( mydest){

		if not t.scan(){
			return 0
		mydest = normalize_path(mydest) + os.sep
		a = open(_unicode_encode(t.file,
			encoding=_encodings['fs'], errors='strict'), 'rb')
		if not os.path.exists(mydest){
			os.makedirs(mydest)
		startpos = 0
		while ((startpos + 8) < t.indexsize){
			namelen = decodeint(t.index[startpos:startpos + 4])
			datapos = decodeint(t.index[startpos + 4 + namelen:startpos + 8 + namelen])
			datalen = decodeint(t.index[startpos + 8 + namelen:startpos + 12 + namelen])
			myname = t.index[startpos + 4:startpos + 4 + namelen]
			myname = _unicode_decode(myname,
				encoding=_encodings['repo.content'], errors='replace')
			filename = os.path.join(mydest, myname.lstrip(os.sep))
			filename = normalize_path(filename)
			if not filename.startswith(mydest){
				# myname contains invalid ../ component(s)
				continue
			dirname = os.path.dirname(filename)
			if dirname{
				if not os.path.exists(dirname){
					os.makedirs(dirname)
			mydat = open(_unicode_encode(filename,
				encoding=_encodings['fs'], errors='strict'), 'wb')
			a.seek(t.datapos + datapos)
			mydat.write(a.read(datalen))
			mydat.close()
			startpos = startpos + namelen + 12
		a.close()
		return 1

	func(t *tbz2) get_data(){

		if not t.scan(){
			return {}
		a = open(_unicode_encode(t.file,
			encoding=_encodings['fs'], errors='strict'), 'rb')
		mydata = {}
		startpos = 0
		while ((startpos + 8) < t.indexsize){
			namelen = decodeint(t.index[startpos:startpos + 4])
			datapos = decodeint(t.index[startpos + 4 + namelen:startpos + 8 + namelen])
			datalen = decodeint(t.index[startpos + 8 + namelen:startpos + 12 + namelen])
			myname = t.index[startpos + 4:startpos + 4 + namelen]
			a.seek(t.datapos + datapos)
			mydata[myname] = a.read(datalen)
			startpos = startpos + namelen + 12
		a.close()
		return mydata

	func(t *tbz2) getboth(){

		if not t.scan(){
			return None

		a = open(_unicode_encode(t.file,
			encoding=_encodings['fs'], errors='strict'), 'rb')
		a.seek(t.datapos)
		mydata = a.read(t.datasize)
		a.close()

		return t.index, mydata
