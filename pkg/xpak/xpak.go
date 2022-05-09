package xpak

import (
	"fmt"
	"github.com/ppphp/portago/pkg/util"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

func addtolist(mylist []string, curdir string) {
	curdir = util.NormalizePath(curdir)
	filepath.Walk(curdir, func(path string, info os.FileInfo, err error) error {
		parent := filepath.Dir(path)
		if parent != curdir {
			mylist = append(mylist, parent[len(curdir)+1:]+string(filepath.Separator))
		}
		if !info.IsDir() {
			mylist = append(mylist, filepath.Join(parent, info.Name())[len(curdir)+1:])
		}
		return nil
	})
}

func encodeint(myint int) string {
	a := []byte{}
	a = append(a, byte(myint>>24)&0xff)
	a = append(a, byte(myint>>16)&0xff)
	a = append(a, byte(myint>>8)&0xff)
	a = append(a, byte(myint&0xff))
	return string(a)
}

func decodeint(mystring string) int {
	myint := uint32(0)
	myint += uint32(mystring[3])
	myint += uint32(mystring[2]) << 8
	myint += uint32(mystring[1]) << 16
	myint += uint32(mystring[0]) << 24
	return int(myint)
}

// ""
func xpak(rootdir, outfile string) []byte {
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
	if outfile != "" {
		outf, _ := os.OpenFile(outfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		outf.Write(xpak_segment)
		outf.Close()
		return nil
	} else {
		return xpak_segment
	}
}

func xpak_mem(mydata map[string]string) []byte {
	mydata_encoded := map[string]string{}
	for k, v := range mydata {
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
	return []byte("XPAKPACK" + encodeint(len(indexglob)) + encodeint(len(dataglob)) + indexglob + dataglob + "XPAKSTOP")
}

func xsplit(infile string) bool {
	myfile, _ := os.Open(infile)
	mydat, _ := ioutil.ReadAll(myfile)
	myfile.Close()
	splits := xsplit_mem(string(mydat))
	if splits == [2]string{} {
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

func xsplit_mem(mydat string) [2]string {
	if mydat[0:8] != "XPAKPACK" {
		return [2]string{}
	}
	if mydat[len(mydat)-8:] != "XPAKSTOP" {
		return [2]string{}
	}
	indexsize := decodeint(mydat[8:12])
	return [2]string{mydat[16 : indexsize+16], mydat[indexsize+16 : len(mydat)-8]}
}

func getindex(infile string) string {

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

func getboth(infile string) (string, string) {
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
	for _, x := range getindex_mem(myindex) {
		print(x)
	}
}

func getindex_mem(myindex string) []string {
	myindexlen := len(myindex)
	startpos := 0
	myret := []string{}
	for (startpos + 8) < myindexlen {
		mytestlen := decodeint(myindex[startpos : startpos+4])
		myret = append(myret, myindex[startpos+4:startpos+4+mytestlen])
		startpos = startpos + mytestlen + 12
	}
	return myret
}

func searchindex(myindex, myitem string) (int, int) {
	mylen := len(myitem)
	myindexlen := len(myindex)
	startpos := 0
	for (startpos + 8) < myindexlen {
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
	return 0, 0
}

func getitem(myid []string, myitem string) string {
	myindex := myid[0]
	mydata := myid[1]
	myloc0, myloc1 := searchindex(myindex, myitem)
	if myloc0 == 0 && myloc1 == 0 {
		return ""
	}
	return mydata[myloc0 : myloc0+myloc1]
}

func xpand(myid []string, mydest string) {
	mydest = util.NormalizePath(mydest) + string(filepath.Separator)
	myindex := myid[0]
	mydata := myid[1]
	myindexlen := len(myindex)
	startpos := 0
	for (startpos + 8) < myindexlen {
		namelen := decodeint(myindex[startpos : startpos+4])
		datapos := decodeint(myindex[startpos+4+namelen : startpos+8+namelen])
		datalen := decodeint(myindex[startpos+8+namelen : startpos+12+namelen])
		myname := myindex[startpos+4 : startpos+4+namelen]
		filename := filepath.Join(mydest, strings.TrimLeft(myname, string(filepath.Separator)))
		filename = util.NormalizePath(filename)
		if !strings.HasPrefix(filename, mydest) {
			continue
		}
		dirname := filepath.Dir(filename)
		if dirname != "" {
			if _, err := os.Stat(dirname); err != nil {
				os.MkdirAll(dirname, 0644)
			}
		}
		mydat, _ := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		mydat.Write([]byte(mydata[datapos : datapos+datalen]))
		mydat.Close()
		startpos = startpos + namelen + 12
	}
}

type tbz2 struct {
	file                                    string
	filestat                                os.FileInfo
	index                                   string
	infosize, xpaksize, indexsize, datasize int
	indexpos, datapos                       int64
}

func NewTbz2(myfile string) *tbz2 {
	t := &tbz2{}
	t.file = myfile
	t.filestat = nil
	t.index = ""
	t.infosize = 0
	t.xpaksize = 0
	t.indexsize = 0
	t.datasize = 0
	t.indexpos = 0
	t.datapos = 0
	return t
}

// 1
func (t *tbz2) decompose(datadir string, cleanup int) int {
	if t.scan() == 0 {
		//raise IOError
	}
	if cleanup != 0 {
		t.cleanup(datadir)
	}
	if _, err := os.Stat(datadir); err != nil {
		os.MkdirAll(datadir, 0755)
	}
	return t.unpackinfo(datadir)
}

// 0
func (t *tbz2) compose(datadir string, cleanup int) {
	t.Recompose(datadir, cleanup, true)
}

// 0, true
func (t *tbz2) Recompose(datadir string, cleanup int, break_hardlinks bool) {
	xpdata := xpak(datadir, "")
	t.recompose_mem(string(xpdata), break_hardlinks)
	if cleanup != 0 {
		t.cleanup(datadir)
	}
}

// true
func (t *tbz2) recompose_mem(xpdata string, break_hardlinks bool) int {
	t.scan()

	if break_hardlinks && t.filestat != nil && t.filestat.Sys().(*syscall.Stat_t).Nlink > 1 {
		tmp_fname := fmt.Sprintf("%s.%d", t.file, os.Getpid())
		util.Copyfile(t.file, tmp_fname)
		if ok := util.Apply_stat_permissions(t.file, t.filestat, -1, nil, true); !ok {
			//except portage.exception.OperationNotPermitted{
			//	pass
		}

		os.Rename(tmp_fname, t.file)
	}

	myfile, _ := os.OpenFile(t.file, os.O_APPEND|os.O_RDWR, 0755)
	if myfile == nil {
		//raise IOError
	}
	myfile.Seek(-int64(t.xpaksize), 2)
	myfile.Truncate(0)
	myfile.Write([]byte(xpdata + encodeint(len(xpdata)) + "STOP"))
	//myfile.flush()
	myfile.Close()
	return 1
}

func (t *tbz2) cleanup(datadir string) {
	dir, fname := path.Split(datadir)
	if dir != "" && fname != "" {
		if err := syscall.Rmdir(datadir); err != nil {
			//except OSError as oe{
			if err == syscall.ENOENT {
				//pass
			} else {
				//raise os
			}
		}
	}
}

func (t *tbz2) scan() int {
	var a *os.File
	defer func() {
		if a != nil {
			a.Close()
		}
	}()
	var err error
	mystat, err := os.Stat(t.file)
	if err == nil {
		if t.filestat != nil {
			changed := false
			if mystat.Size() != t.filestat.Size() || mystat.ModTime() != t.filestat.ModTime() || mystat.Sys().(*syscall.Stat_t).Ctim != t.filestat.Sys().(*syscall.Stat_t).Ctim {
				changed = true
			}
			if !changed {
				return 1
			}
		}
		t.filestat = mystat
	}
	if err == nil {
		a, err = os.Open(t.file)
	}
	if err == nil {
		_, err = a.Seek(-16, 2)
	}
	if err == nil {
		trailer, err1 := ioutil.ReadAll(a)
		err = err1
		t.infosize = 0
		t.xpaksize = 0
		if string(trailer)[len(string(trailer))-4:] != "Stop" {
			return 0
		}
		if string(trailer)[0:8] != "XPAKSTOP" {
			return 0
		}
		t.infosize = decodeint(string(trailer)[8:12])
		t.xpaksize = t.infosize + 8
	}
	if err == nil {
		_, err = a.Seek(-int64(t.xpaksize), 2)
	}
	header := make([]byte, 16)
	if err == nil {
		_, err = a.Read(header)
	}
	if err == nil {
		if string(header[0:8]) != "XPAKPACK" {
			return 0
		}
	}
	if err == nil {
		t.indexsize = decodeint(string(header)[8:12])
		t.datasize = decodeint(string(header)[12:16])
		t.indexpos, err = a.Seek(0, io.SeekCurrent)
	}
	index := make([]byte, t.indexsize)
	if err == nil {
		_, err = a.Read(index)
	}
	if err == nil {
		t.index = string(index)
		t.datapos, err = a.Seek(0, io.SeekCurrent)
	}
	if err == nil {
		return 2
	} else {
		//except SystemExit{
		//	raise
		//	except{
		return 0
	}
}

func (t *tbz2) filelist() []string {
	if t.scan() == 0 {
		return nil
	}
	return getindex_mem(t.index)
}

// ""
func (t *tbz2) getfile(myfile string, mydefault string) string {

	if t.scan() == 0 {
		return ""
	}
	myresult1, myresult2 := searchindex(t.index, myfile)
	if myresult1 == 0 && myresult2 == 0 {
		return ""
	}
	a, _ := os.Open(t.file)
	a.Seek(t.datapos+int64(myresult1), 0)

	myreturn := make([]byte, myresult2)
	a.Read(myreturn)
	a.Close()
	return string(myreturn)
}

func (t *tbz2) getelements(myfile string) []string {

	mydat := t.getfile(myfile, "")
	if mydat == "" {
		return []string{}
	}
	return strings.Fields(mydat)
}

func (t *tbz2) unpackinfo(mydest string) int {

	if t.scan() == 0 {
		return 0
	}
	mydest = util.NormalizePath(mydest) + string(filepath.Separator)
	a, _ := os.Open(t.file)
	if _, err := os.Stat(mydest); err == os.ErrNotExist {
		os.MkdirAll(mydest, 0755)
	}
	startpos := 0
	for (startpos + 8) < t.indexsize {
		namelen := decodeint(t.index[startpos : startpos+4])
		datapos := decodeint(t.index[startpos+4+namelen : startpos+8+namelen])
		datalen := decodeint(t.index[startpos+8+namelen : startpos+12+namelen])
		myname := t.index[startpos+4 : startpos+4+namelen]
		filename := filepath.Join(mydest, strings.TrimLeft(myname, string(os.PathSeparator)))
		filename = util.NormalizePath(filename)
		if !strings.HasPrefix(filename, mydest) {
			continue
		}
		dirname := filepath.Dir(filename)
		if dirname != "" {
			if _, err := os.Stat(dirname); err == os.ErrNotExist {
				os.MkdirAll(dirname, 0755)
			}
		}
		mydat, _ := os.OpenFile(filename, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		a.Seek(t.datapos+int64(datapos), 0)
		d := make([]byte, datalen)
		a.Read(d)
		mydat.Write(d)
		mydat.Close()
		startpos = startpos + namelen + 12
	}
	a.Close()
	return 1
}

func (t *tbz2) get_data() map[string]string {
	if t.scan() == 0 {
		return map[string]string{}
	}
	a, _ := os.Open(t.file)
	mydata := map[string]string{}
	startpos := 0
	for (startpos + 8) < t.indexsize {
		namelen := decodeint(t.index[startpos : startpos+4])
		datapos := decodeint(t.index[startpos+4+namelen : startpos+8+namelen])
		datalen := decodeint(t.index[startpos+8+namelen : startpos+12+namelen])
		myname := t.index[startpos+4 : startpos+4+namelen]
		a.Seek(t.datapos+int64(datapos), 0)
		d := make([]byte, datalen)
		a.Read(d)
		mydata[myname] = string(d)
		startpos = startpos + namelen + 12
	}
	a.Close()
	return mydata
}

func (t *tbz2) getboth() (string, string) {
	if t.scan() == 0 {
		return "", ""
	}

	a, _ := os.Open(t.file)
	a.Seek(t.datapos, 0)
	d := make([]byte, t.datasize)
	a.Read(d)
	mydata := string(d)
	a.Close()

	return t.index, mydata
}
