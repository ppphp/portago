package util

import (
	"encoding/json"
	"fmt"
	"github.com/ppphp/portago/pkg/data"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/portage/version"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/util/permissions"
	"io/ioutil"
	"os"
	"reflect"
	"syscall"
)

type MtimeDB struct {
	dict        map[string]interface{}
	filename    string
	_json_write bool

	_clean_data map[string]interface{}
}

func NewMtimeDB(filename string) *MtimeDB {
	m := &MtimeDB{}

	m._json_write = true

	m.dict = map[string]interface{}{}
	m.filename = filename
	m._load(filename)
	return m
}

func (m *MtimeDB) _load(filename string) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		//except EnvironmentError as e:
		if err == syscall.ENOENT || err == syscall.EACCES {
			//pass
		} else {
			msg.WriteMsg(fmt.Sprintf("!!! Error loading '%s': %s\n", filename, err), -1, nil)
		}
	}

	var d map[string]interface{} = nil
	if len(content) > 0 {
		if err := json.Unmarshal(content, &d); err != nil {
			msg.WriteMsg(fmt.Sprintf("!!! Error loading '%s': %s\n", filename, err), -1, nil)
		}
	}

	if d == nil {
		d = map[string]interface{}{}
	}

	if _, ok := d["old"]; ok {
		d["updates"] = d["old"]
		delete(d, "old")
	}
	if _, ok := d["cur"]; ok {
		delete(d, "cur")
	}

	if _, ok := d["starttime"]; !ok {
		d["version"] = 0
	}
	if _, ok := d["version"]; !ok {
		d["version"] = ""
	}
	for _, k := range []string{"info", "ldpath", "updates"} {
		if _, ok := d[k]; !ok {
			d[k] = map[string]interface{}{}
		}
	}

	mtimedbkeys := map[string]bool{"info": true, "ldpath": true, "resume": true, "resume_backup": true,
		"starttime": true, "updates": true, "version": true}

	for k := range d {
		if !mtimedbkeys[k] {
			msg.WriteMsg(fmt.Sprintf("Deleting invalid mtimedb key: %s\n", k), -1, nil)
			delete(d, k)
		}
	}
	for k, v := range d {
		m.dict[k] = v
	}
	d = myutil.CopyMapT(m._clean_data)
}

func (m *MtimeDB) Commit() {
	if m.filename == "" {
		return
	}
	d := map[string]interface{}{}
	for k, v := range m.dict {
		d[k] = v
	}
	if !reflect.DeepEqual(d, m._clean_data) {
		d["version"] = fmt.Sprint(version.VERSION)
		//try:
		f := NewAtomic_ofstream(m.filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, true)
		//except
		//EnvironmentError:
		//	pass
		//	else:
		if m._json_write {
			jd, _ := json.MarshalIndent(d, "", "\t")
			f.Write(jd)
		}
		f.Close()
		var m1 os.FileMode
		m1--
		permissions.Apply_secpass_permissions(m.filename,
			uint32(data.Uid), *data.Portage_gid, 0o644, m1, nil, true)
		m._clean_data = myutil.CopyMapT(d)
	}
}
