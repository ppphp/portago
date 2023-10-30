package cache

import "sync"

type database struct {
	autocommits        bool
	serialize_eclasses bool
	store_eclass_paths bool
	data               map[string]interface{}
	delitem            func(string)
	sync.RWMutex
}

func (db *database) setitem(name string, values interface{}) {
	db.Lock()
	defer db.Unlock()
	db.data[name] = values
}

func (db *database) getitem(cpv string) interface{} {
	db.RLock()
	defer db.RUnlock()
	return db.data[cpv]
}

func (db *database) deleteitem(name string) {
	db.Lock()
	defer db.Unlock()
	db.delitem(name)
}

func (db *database) iter() []string {
	db.RLock()
	defer db.RUnlock()
	keys := make([]string, len(db.data))
	i := 0
	for k := range db.data {
		keys[i] = k
		i++
	}
	return keys
}

func (db *database) contains(key string) bool {
	db.RLock()
	defer db.RUnlock()
	_, ok := db.data[key]
	return ok
}

func newDatabase() *database {
	return &database{
		autocommits:        true,
		serialize_eclasses: false,
		store_eclass_paths: false,
		data:               make(map[string]interface{}),
		delitem:            func(name string) { delete(db.data, name) },
	}
}
