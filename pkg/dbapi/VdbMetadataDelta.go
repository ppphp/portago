package dbapi

import (
	"encoding/json"
	"fmt"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/versions"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
)

type vdbMetadataDelta struct {
	_vardb *vardbapi
}

func (v *vdbMetadataDelta) initialize(timestamp int) {

	f := util.NewAtomic_ofstream(v._vardb._cache_delta_filename, os.O_RDWR, true)
	ms, _ := json.Marshal(map[string]{
		"version":   v._format_version,
		"timestamp": timestamp,
	})
	f.Write(ms)
	f.Close()
}

func (v *vdbMetadataDelta) load() {

	if ! myutil.PathExists(v._vardb._aux_cache_filename) {
		return nil
	}

	f, err := ioutil.ReadFile(v._vardb._cache_delta_filename)
	cache_obj := map[string]interface{}{}
	if err == nil {
		err = json.Unmarshal(f, &cache_obj)
	}
	if err != nil {
		//except EnvironmentError as e:
		if err != syscall.ENOENT && err != syscall.ESTALE{
			//raise
		}
		//except (SystemExit, KeyboardInterrupt):
		//raise
		//except Exception:
		//	pass
	}else {
		//try:
		version, ok := cache_obj["version"]
		//except KeyError:
		//pass
		//else:
		if ok {
			if version == v._format_version {
				//try:
				deltas, ok := cache_obj["deltas"]
				//except
				//KeyError:
				if !ok {
					deltas = []
cache_obj["deltas"] = deltas
}

if _, ok := deltas.([]interface{}) {
return cache_obj
}
}
}
}
return nil
}

func (v *vdbMetadataDelta) loadRace() {
	tries := 2
	for tries > 0 {
		tries -= 1
		cache_delta := v.load()
		if cache_delta != nil &&
			cache_delta.timestamp !=
				v._vardb._aux_cache().timestamp {
			v._vardb._aux_cache_obj = nil
		} else {
			return cache_delta
		}
	}
	return nil
}

func (v *vdbMetadataDelta) recordEvent(event string, cpv *versions.PkgStr, slot, counter string) {

	v._vardb.lock()
try:
	deltas_obj := v.load()

	if deltas_obj == nil {
		return
	}

	delta_node := map[string]string{
		"event":   event,
		"package": cpv.cp,
		"version": cpv.version,
		"slot":    slot,
		"counter": fmt.Sprintf("%s", counter),
	}

	deltas_obj["deltas"] = append(deltas_obj["deltas"], delta_node)

	filtered_list := []map[string]string{}
	slot_keys := map[string]bool{}
	version_keys := map[string]bool{}
	for delta_node
		in
	myutil.Reversed(deltas_obj["deltas"]) {
		slot_key := (delta_node["package"],
			delta_node["slot"])
		version_key := (delta_node["package"],
			delta_node["version"])
		if !(slot_keys[slot_key] || version_keys[version_key]) {
			filtered_list = append(filtered_list, delta_node)
			slot_keys[slot_key] = true
			version_keys[version_key] = true
		}
	}

	myutil.ReverseSlice(filtered_list)
	deltas_obj["deltas"] = filtered_list

	f := util.NewAtomic_ofstream(v._vardb._cache_delta_filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, true)
	ms, _ := json.Marshal(deltas_obj)
	f.Write(ms)
	f.Close()
	v._vardb.unlock()
}

func (v *vdbMetadataDelta) applyDelta(data map[string][]map[string]string) {
	packages := v._vardb._aux_cache().packages
	deltas := map[string]map[string]string{}
	for _, delta := range data["deltas"] {
		cpv := delta["package"] + "-" + delta["version"]
		deltas[cpv] = delta
		event := delta["event"]
		if event == "add" {
			if _, ok := packages[cpv]; !ok {
				//try:
				v._vardb.aux_get(cpv, map[string]bool{"DESCRIPTION": true}, "")
				//except KeyError:
				//pass
			}
		} else if event == "remove" {
			delete(packages, cpv)
		}
	}

	if len(deltas) > 0 {
		for cached_cpv, v := range packages {
			metadata := v.metadata
			if myutil.Inmsmss(deltas, cached_cpv) {
				continue
			}

			removed := false
			cpv1 := ""
			for cpv, delta := range deltas {
				cpv1 = cpv
				if strings.HasPrefix(cached_cpv, delta["package"]) && metadata["SLOT"] == delta["slot"] && versions.cpvGetKey(cached_cpv, "") == delta["package"] {
					removed = true
					break
				}
			}

			if removed {
				delete(packages, cached_cpv)
				delete(deltas, cpv1)
				if len(deltas) == 0 {
					break
				}
			}
		}
	}
}

func NewVdbMetadataDelta(vardb *vardbapi) *vdbMetadataDelta {
	v := &vdbMetadataDelta{}
	v._vardb = vardb
	return v
}

type auxCache struct {
	version  int
	packages map[string]*struct {
		cache_mtime int64
		metadata    map[string]string
	}
	owners *struct {
		base_names map[string]map[struct {
			s1 string;
			int;
			s2 string
		}]string
		version int
	}
	modified map[string]bool
}
