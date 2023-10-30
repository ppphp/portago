package cache

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ppphp/portago/pkg/exception"
)

type database struct {
	completeEClassEntries bool
	autocommits           bool
	cleanseKeys           bool
	serializeEClasses     bool
	validationChf         string
	storeEClassPaths      bool
	knownKeys             []string
	location              string
	label                 string
	readonly              bool
	syncRate              int
	updates               int
}

func (db *database) __getitem__(cpv string) (map[string]interface{}, error) {
	if db.updates > db.syncRate {
		db.Commit()
		db.updates = 0
	}
	d, err := db._getitem(cpv)
	if err != nil {
		return nil, err
	}

	chfTypes := []string{db.validationChf}
	if db.serializeEClasses && d["_eclasses_"] != nil {
		for _, chfType := range chfTypes {
			if d["_"+chfType+"_"] == nil {
				continue
			}
			eclasses, err := reconstructEClasses(cpv, d["_eclasses_"], chfType, db.storeEClassPaths)
			if err == nil {
				d["_eclasses_"] = eclasses
				break
			}
			if chfType == chfTypes[len(chfTypes)-1] {
				return nil, err
			}
		}
	} else if d["_eclasses_"] == nil {
		d["_eclasses_"] = make(map[string]interface{})
	}
	// Never return INHERITED, since portdbapi.aux_get() will
	// generate it automatically from _eclasses_, and we want
	// to omit it in comparisons between cache entries like
	// those that egencache uses to avoid redundant writes.
	delete(d, "INHERITED")

	mtimeRequired := true
	for _, chfType := range chfTypes {
		if d["_"+chfType+"_"] != nil && chfType != "mtime" {
			mtimeRequired = false
			break
		}
	}

	mtime, ok := d["_mtime_"].(int)
	if !ok {
		if mtimeRequired {
			return nil, fmt.Errorf("CacheCorruption: _mtime_ field is missing")
		}
		delete(d, "_mtime_")
	} else {
		d["_mtime_"] = mtime
	}
	return d, nil
}

func (db *database) Set(cpv string, values map[string]interface{}) error {
	if db.readonly {
		return NewReadOnlyRestriction("")
	}
	d := make(map[string]interface{})
	if db.cleanseKeys {
		for k, v := range values {
			if k != "_eclasses_" && v != nil {
				d[k] = v
			}
		}
	} else {
		d = values
	}
	if values["_eclasses_"] != nil {
		if db.serializeEClasses {
			eclasses, err := serializeEClasses(values["_eclasses_"], db.validationChf, db.storeEClassPaths)
			if err != nil {
				return err
			}
			d["_eclasses_"] = eclasses
		} else {
			d["_eclasses_"] = db.internalEClasses(values["_eclasses_"], db.validationChf, db.storeEClassPaths)
		}
	} else {
		d["_eclasses_"] = make(map[string]interface{})
	}
	db.setItem(cpv, d)
	if !db.autocommits {
		db.updates++
		if db.updates > db.syncRate {
			db.Commit()
			db.updates = 0
		}
	}
	return nil
}

func (db *database) _getitem(cpv string) (map[string]interface{}, error) {
	// get cpv's values.
	// override this in derived classes
	return nil, exception.NotImplementedError{}
}

func (db *database) internalEClasses(externECDict map[string]interface{}, chfType string, paths bool) map[string]interface{} {
	// When serializeEClasses is False, we have to convert an external
	// eclass dict containing hashed_path objects into an appropriate
	// internal dict containing values of chfType (and eclass dirs
	// if storeEClassPaths is True).
	if externECDict == nil {
		return externECDict
	}
	chfGetter := func(v interface{}) interface{} {
		return v.(map[string]interface{})[chfType]
	}
	internECDict := make(map[string]interface{})
	if paths {
		for k, v := range externECDict {
			eclassDir := v.(map[string]interface{})["eclass_dir"]
			chf := chfGetter(v)
			internECDict[k] = map[string]interface{}{
				"eclass_dir": eclassDir,
				chfType:      chf,
			}
		}
	} else {
		for k, v := range externECDict {
			chf := chfGetter(v)
			internECDict[k] = chf
		}
	}
	return internECDict
}

func (db *database) __setitem__(cpv string, values map[string]interface{}) error {
	// set a cpv to values
	// This shouldn't be overriden in derived classes since it handles the readonly checks
	if db.readonly {
		return cache_errors.ReadOnlyRestriction{}
	}
	d := make(map[string]interface{})
	if db.cleanseKeys {
		d = ProtectedDict(values)
		for k, v := range d {
			if k != "_eclasses_" && v == nil {
				delete(d, k)
			}
		}
	}
	if _, ok := values["_eclasses_"]; ok {
		if d == nil {
			d = ProtectedDict(values)
		}
		if db.serializeEClasses {
			d["_eclasses_"] = serializeEClasses(
				d["_eclasses_"], db.validationChf, db.storeEClassPaths,
			)
		} else {
			d["_eclasses_"] = db.internalEClasses(
				d["_eclasses_"], db.validationChf, db.storeEClassPaths,
			)
		}
	} else if d == nil {
		d = values
	}
	db._setitem(cpv, d)
	if !db.autocommits {
		db.updates += 1
		if db.updates > db.syncRate {
			db.Commit()
			db.updates = 0
		}
	}
	return nil
}

func (db *database) _setitem(cpv string, values map[string]interface{}) error {
	return exception.NotImplementedError{}
}

func (db *database) __delitem__(cpv string) error {
	// delete a key from the cache.
	// This shouldn't be overriden in derived classes since it handles the readonly checks
	if db.readonly {
		return NewReadOnlyRestriction("")
	}
	if !db.autocommits {
		db.updates += 1
	}
	db._delitem(cpv)
	if db.updates > db.syncRate {
		db.Commit()
		db.updates = 0
	}
	return nil
}

func (db *database) _delitem(cpv string) error {
	// __delitem__ calls this after readonly checks.  override it in derived classes
	return exception.NotImplementedError{}
}

func (db *database) HasKey(cpv string) bool {
	k, err := db.__getitem__(cpv)
	if err != nil && k != nil {
		return true
	}
	return false
}

func (db *database) IterKeys() []string {
	keys := make([]string, 0)
	for _, k := range db.knownKeys {
		keys = append(keys, k)
	}
	return keys
}

func (db *database) IterItems() []map[string]interface{} {
	items := make([]map[string]interface{}, 0)
	for _, k := range db.knownKeys {
		item, _ := db.__getitem__(k)
		items = append(items, item)
	}
	return items
}

func (db *database) Sync(rate int) {
	db.syncRate = rate
	if rate == 0 {
		db.Commit()
	}
}

func (db *database) Commit() error {
	if !db.autocommits {
		return exception.NotImplementedError{}
	}
	return nil
}

func (db *database) __del__() {
	db.Sync(0)
}

func (db *database) Del(cpv string) error {
	delete(db, cpv)
	return nil
}

func (db *database) __contains__(cpv string) bool {
	// This method should always be overridden.  It is provided only for backward compatibility with modules that override has_key instead.  It will automatically raise a NotImplementedError if has_key has not been overridden.
	if db.HasKey == (*database).HasKey {
		// prevent a possible recursive loop
		panic(NotImplementedError{})
	}
	warnings.warn(
		"portage.cache.template.database.has_key() is deprecated, override __contains__ instead",
		DeprecationWarning,
	)
	return db.HasKey(cpv)
}

func (db *database) __iter__() []string {
	// This method should always be overridden.  It is provided only for backward compatibility with modules that override iterkeys instead.  It will automatically raise a NotImplementedError if iterkeys has not been overridden.
	if db.IterKeys == (*database).IterKeys {
		// prevent a possible recursive loop
		panic(NotImplementedError{})
	}
	return db.IterKeys()
}

func (db *database) Get(k string, x interface{}) interface{} {
	value, ok := db.__getitem__(k)
	if ok == nil {
		return x
	}
	return value
}

func (db *database) ValidateEntry(entry map[string]interface{}, ebuildHash string, eclassDB interface{}) bool {
	chfTypes, ok := db.chfTypes
	if !ok {
		chfTypes = []string{db.validationChf}
	}

	for _, chfType := range chfTypes {
		if db._validateEntry(chfType, entry, ebuildHash, eclassDB) {
			return true
		}
	}

	return false
}

func (db *database) _validateEntry(chfType string, entry map[string]interface{}, ebuildHash string, eclassDB interface{}) bool {
	hashKey := "_" + chfType + "_"
	entryHash, ok := entry[hashKey].(string)
	if !ok {
		return false
	}
	if entryHash != ebuildHash {
		return false
	}
	eclasses, ok := entry["_eclasses_"].([]string)
	if !ok {
		return false
	}
	update, ok := eclassDB.validateAndRewriteCache(eclasses, chfType, db.storeEclassPaths)
	if !ok {
		return false
	}
	if update != nil {
		entry["_eclasses_"] = update
	}
	return true
}

func (db *database) GetMatches(matchDict map[string]interface{}) []string {
	var matches []string
	for cpv, vals := range db.__iter__() {
		cont := true
		for key, match := range matchDict {
			if val, ok := vals[key].(string); ok {
				if !regexp.MustCompile(match.(string)).MatchString(val) {
					cont = false
					break
				}
			} else {
				cont = false
				break
			}
		}
		if cont {
			matches = append(matches, cpv)
		}
	}
	return matches
}

func (db *database) Keys() []string {
	var keys []string
	for k := range db {
		keys = append(keys, k)
	}
	return keys
}

// _keysorter = operator.itemgetter(0)Z

// "mtime", true
func serializeEclasses(eclassDict map[string]interface{}, chfType string, paths bool) string {
	if len(eclassDict) == 0 {
		return ""
	}

	var eclasses []string
	for k, v := range eclassDict {
		if paths {
			eclasses = append(eclasses, fmt.Sprintf("%s\t%s\t%s", k, v.(Eclass).EclassDir, v.(Eclass).ChfType[chfType]))
		} else {
			eclasses = append(eclasses, fmt.Sprintf("%s\t%s", k, v.(Eclass).ChfType[chfType]))
		}
	}

	sort.Strings(eclasses)
	return strings.Join(eclasses, "\t")
}

func md5Deserializer(md5 string) (string, error) {
	if len(md5) != 32 {
		return "", fmt.Errorf("expected 32 hex digits")
	}
	return md5, nil
}

func mtimeDeserializer(mtime string) (int64, error) {
	return strconv.ParseInt(mtime, 10, 64)
}

var chfDeserializers = map[string]func(string) (interface{}, error){
	"md5":   md5Deserializer,
	"mtime": mtimeDeserializer,
}

// "mtime", true
func reconstructEclasses(cpv string, eclassString string, chfType string, paths bool) (map[string]Eclass, error) {
	eclasses := strings.Split(strings.TrimSpace(eclassString), "\t")
	if len(eclasses) == 1 && eclasses[0] == "" {
		return make(map[string]Eclass), nil
	}

	converter, ok := chfDeserializers[chfType]
	if !ok {
		return nil, fmt.Errorf("unsupported chf type: %s", chfType)
	}

	if paths {
		if len(eclasses)%3 != 0 {
			return nil, fmt.Errorf("%s: _eclasses_ was of invalid len %d", cpv, len(eclasses))
		}
	} else {
		if len(eclasses)%2 != 0 {
			return nil, fmt.Errorf("%s: _eclasses_ was of invalid len %d", cpv, len(eclasses))
		}
	}

	eclassDict := make(map[string]Eclass)
	i := 0
	for i < len(eclasses) {
		if paths {
			eclassDir := eclasses[i+1]
			chfValue, err := converter(eclasses[i+2])
			if err != nil {
				return nil, fmt.Errorf("%s: _eclasses_ not valid for chf_type %s", cpv, chfType)
			}
			eclassDict[eclasses[i]] = Eclass{EclassDir: eclassDir, ChfType: map[string]string{chfType: fmt.Sprintf("%v", chfValue)}}
			i += 3
		} else {
			chfValue, err := converter(eclasses[i+1])
			if err != nil {
				return nil, fmt.Errorf("%s: _eclasses_ not valid for chf_type %s", cpv, chfType)
			}
			eclassDict[eclasses[i]] = Eclass{ChfType: map[string]string{chfType: fmt.Sprintf("%v", chfValue)}}
			i += 2
		}
	}

	return eclassDict, nil
}
