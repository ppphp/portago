package _dyn_libs

import (
	"encoding/json"
	"fmt"
	"github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/pkg/locks"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type preservedLibsRegistry struct {
	_json_write       bool
	_json_write_opts  map[string]bool
	_root, _filename  string
	_data, _data_orig map[string]*struct {
		cpv, counter string
		paths        []string
	}
	_lock *locks.LockFileS
}

func (p *preservedLibsRegistry) lock() {
	if p._lock != nil {
		//raise AssertionError("already locked")
	}
	p._lock, _ = locks.Lockfile(p._filename, false, false, "", 0)
}

func (p *preservedLibsRegistry) unlock() {
	if p._lock == nil {
		//raise AssertionError("not locked")
	}
	locks.Unlockfile(p._lock)
	p._lock = nil
}

func (p *preservedLibsRegistry) load() {
	p._data = nil
	content, err := ioutil.ReadFile(p._filename)
	if err != nil {
		//except EnvironmentError as e:
		//if not hasattr(e, 'errno'):
		//raise
		//elif err == syscall.ENOENT:
		//pass
		//elif err == PermissionDenied.errno:
		//raise PermissionDenied(self._filename)
		//else:
		//raise
	}
	if len(content) > 0 {
		if err := json.Unmarshal(content, &p._data); err != nil {
			//except SystemExit:
			//raise
			//except Exception as e:
			//try:
			//	p._data = pickle.loads(content)
			//	except SystemExit:
			//	raise
			//	except Exception:
			WriteMsgLevel(fmt.Sprintf("!!! Error loading '%s': %s\n", p._filename, err), 40, -1)
		}
	}

	if p._data == nil {
		p._data = map[string]*struct {
			cpv, counter string
			paths        []string
		}{}
	} else {
		for k, v := range p._data {
			p._data[k] = &struct {
				cpv, counter string
				paths        []string
			}{v.cpv, v.counter, v.paths}
		}
	}

	p._data_orig = map[string]*struct {
		cpv, counter string
		paths        []string
	}{}
	for k, v := range p._data {
		p._data_orig[k] = v
	}
	p.pruneNonExisting()
}

func (p *preservedLibsRegistry) store() {

	if os.Getenv("SANDBOX_ON") == "1" || &p._data == &p._data_orig {
		return
	}
	f := NewAtomic_ofstream(p._filename, os.O_RDWR|os.O_CREATE, true)
	//if self._json_write:
	v, _ := json.Marshal(p._data)
	f.Write(v)
	//else:
	//pickle.dump(self._data, f, protocol=2)
	f.Close()
	//except EnvironmentError as e:
	//if err != PermissionDenied.errno:
	//WriteMsgLevel("!!! %s %s\n" % (e, self._filename),
	//	level=logging.ERROR, noiselevel=-1)
	//else:
	p._data_orig = map[string]*struct {
		cpv, counter string
		paths        []string
	}{}
	for k, v := range p._data {
		p._data_orig[k] = v
	}
}

func (p *preservedLibsRegistry) _normalize_counter(counter string) string {
	return strings.TrimSpace(counter)
}

func (p *preservedLibsRegistry) register(cpv, slot, counter string, paths []string) {

	cp := atom.cpvGetKey(cpv, "")
	cps := cp + ":" + slot
	counter = p._normalize_counter(counter)
	if _, ok := p._data[cps]; len(paths) == 0 && ok && p._data[cps].cpv == cpv && p._normalize_counter(p._data[cps].counter) == counter {
		delete(p._data, cps)
	} else if len(paths) > 0 {
		p._data[cps] = &struct {
			cpv, counter string
			paths        []string
		}{cpv, counter, paths}
	}
}

func (p *preservedLibsRegistry) unregister(cpv, slot, counter string) {
	p.register(cpv, slot, counter, []string{})
}

func (p *preservedLibsRegistry) pruneNonExisting() {
	for cps := range p._data {

		cpv, counter, _paths := p._data[cps].cpv, p._data[cps].counter, p._data[cps].paths

		paths := []string{}
		hardlinks := map[string]bool{}
		symlinks := map[string]string{}
		for _, f := range _paths {
			f_abs := filepath.Join(p._root, strings.TrimLeft(f, string(os.PathSeparator)))
			lst, err := os.Lstat(f_abs)
			if err != nil {
				//except OSError:
				continue
			}
			if lst.Mode()&syscall.S_IFLNK != 0 {
				symlinks[f], err = filepath.EvalSymlinks(f_abs)
				if err != nil {
					//except OSError:
					continue
				}
			} else if lst.Mode()&syscall.S_IFREG != 0 {
				hardlinks[f] = true
				paths = append(paths, f)
			}
		}

		for f, target := range symlinks {
			if hardlinks[atom.absSymlink(f, target)] {
				paths = append(paths, f)
			}
		}

		if len(paths) > 0 {
			p._data[cps] = &struct {
				cpv, counter string
				paths        []string
			}{cpv, counter, paths}
		} else {
			delete(p._data, cps)
		}
	}
}

func (p *preservedLibsRegistry) hasEntries() bool {
	if p._data == nil {
		p.load()
	}
	return len(p._data) > 0
}

func (p *preservedLibsRegistry) getPreservedLibs() map[string][]string {
	if p._data == nil {
		p.load()
	}
	rValue := map[string][]string{}
	for cps := range p._data {
		rValue[p._data[cps].cpv] = p._data[cps].paths
	}
	return rValue
}

func NewPreservedLibsRegistry(root, filename string) *preservedLibsRegistry {
	p := &preservedLibsRegistry{_json_write: true, _json_write_opts: map[string]bool{
		"ensure_ascii": false,
		"indent":       true,
		"sort_keys":    true,
	}}
	p._root = root
	p._filename = filename

	return p
}
