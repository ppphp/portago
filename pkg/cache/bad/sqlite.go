package cache

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type database struct {
	fs_template.FsBased

	validation_chf string
	chf_types      []string

	autocommits bool
	synchronous bool
	cache_bytes int

	_connection_info_entry struct {
		connection *sqlite3.Conn
		cursor     *sqlite3.Stmt
		pid        int
	}

	_allowed_keys      []string
	_allowed_keys_set  map[string]struct{}
	_allowed_keys_lock sync.Mutex

	_db_module         *sqlite3.SQLiteConn
	_db_error          error
	_db_connection_info *_connection_info_entry
	_db_table          map[string]map[string]string
	_db_table_lock     sync.Mutex
	_dbpath            string
}

func NewDatabase(location string, label string, readonly bool, config map[string]interface{}) (*database, error) {
	db := &database{
		FsBased: fs_template.FsBased{
			location: location,
			label:    label,
			readonly: readonly,
		},
		validation_chf: "md5",
		chf_types:      []string{"md5", "mtime"},
		autocommits:    false,
		synchronous:    false,
		cache_bytes:    1024 * 1024 * 10,
		_allowed_keys:  []string{"_eclasses_"},
	}

	db._allowed_keys = append(db._allowed_keys, db._known_keys...)
	db._allowed_keys = append(db._allowed_keys, "_"+k+"_" for k := range db.chf_types)
	sort.Strings(db._allowed_keys)
	db._allowed_keys_set = make(map[string]struct{}, len(db._allowed_keys))
	for _, k := range db._allowed_keys {
		db._allowed_keys_set[k] = struct{}{}
	}

	db.location = filepath.Join(db.location, strings.Trim(db.label, string(os.PathSeparator)))
	if !db.readonly && !fs.Exists(db.location) {
		if err := fs.MkdirAll(db.location, 0755); err != nil {
			return nil, err
		}
	}

	config.setdefault("autocommit", db.autocommits)
	config.setdefault("cache_bytes", db.cache_bytes)
	config.setdefault("synchronous", db.synchronous)
	config.setdefault("timeout", 15)
	db._config = config

	return db, nil
}

func (db *database) _import_sqlite() error {
	// sqlite3 is optional with >=python-2.5
	if _, err := sqlite3.Version(); err != nil {
		return err
	}
	db._db_module = sqlite3.Open(":memory:")
	db._db_error = sqlite3.ErrError
	return nil
}

func (db *database) _db_escape_string(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (db *database) _db_cursor() *sqlite3.Stmt {
	if db._db_connection_info == nil || db._db_connection_info.pid != os.Getpid() {
		db._db_init_connection()
	}
	return db._db_connection_info.cursor
}

func (db *database) _db_connection() *sqlite3.Conn {
	if db._db_connection_info == nil || db._db_connection_info.pid != os.Getpid() {
		db._db_init_connection()
	}
	return db._db_connection_info.connection
}

func (db *database) _db_init_connection() {
	config := db._config
	db._dbpath = db.location + ".sqlite"
	connection_kwargs := make(map[string]interface{})
	connection_kwargs["timeout"] = config["timeout"]
	var connection *sqlite3.Conn
	var cursor *sqlite3.Stmt
	var err error
	if !db.readonly {
		db._ensure_dirs()
	}
	connection, err = db._db_module.Connect(db._dbpath)
	if err != nil {
		panic(cache_errors.InitializationError{db.__class__, err})
	}
	cursor, err = connection.Prepare("")
	if err != nil {
		panic(cache_errors.InitializationError{db.__class__, err})
	}
	db._db_connection_info = &_connection_info_entry{connection, cursor, os.Getpid()}
	db._db_cursor.Execute("PRAGMA encoding = " + db._db_escape_string("UTF-8"))
	if !db.readonly && !db._ensure_access(db._dbpath) {
		panic(cache_errors.InitializationError{db.__class__, "can't ensure perms on " + db._dbpath})
	}
	db._db_init_cache_size(config["cache_bytes"])
	db._db_init_synchronous(config["synchronous"])
	db._db_init_structures()
}

func (db *database) _db_init_structures() {
	db._db_table = make(map[string]map[string]string)
	db._db_table["packages"] = make(map[string]string)
	mytable := "portage_packages"
	db._db_table["packages"]["table_name"] = mytable
	db._db_table["packages"]["package_id"] = "internal_db_package_id"
	db._db_table["packages"]["package_key"] = "portage_package_key"
	create_statement := []string{"CREATE TABLE", mytable, "("}
	table_parameters := []string{fmt.Sprintf("%s INTEGER PRIMARY KEY AUTOINCREMENT", db._db_table["packages"]["package_id"]), fmt.Sprintf("%s TEXT", db._db_table["packages"]["package_key"])}
	for _, k := range db._allowed_keys {
		table_parameters = append(table_parameters, fmt.Sprintf("%s TEXT", k))
	}
	table_parameters = append(table_parameters, fmt.Sprintf("UNIQUE(%s)", db._db_table["packages"]["package_key"]))
	create_statement = append(create_statement, strings.Join(table_parameters, ","))
	create_statement = append(create_statement, ")")
	db._db_table["packages"]["create"] = strings.Join(create_statement, " ")

	cursor := db._db_cursor()
	for k, v := range db._db_table {
		if db._db_table_exists(v["table_name"]) {
			create_statement := db._db_table_get_create(v["table_name"])
			table_ok, missing_keys := db._db_validate_create_statement(create_statement)
			if table_ok {
				if missing_keys != nil {
					for k := range missing_keys {
						cursor.Execute(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s TEXT", db._db_table["packages"]["table_name"], k))
					}
				}
			} else {
				fmt.Println("sqlite: dropping old table: ", v["table_name"])
				cursor.Execute(fmt.Sprintf("DROP TABLE %s", v["table_name"]))
				cursor.Execute(v["create"])
			}
		} else {
			cursor.Execute(v["create"])
		}
	}
}

func (db *database) _db_table_exists(table_name string) bool {
	cursor := db._db_cursor()
	cursor.Execute(fmt.Sprintf(`SELECT name FROM sqlite_master WHERE type="table" AND name=%s`, db._db_escape_string(table_name)))
	return len(cursor.FetchAll()) == 1
}

func (db *database) _db_table_get_create(table_name string) string {
	cursor := db._db_cursor()
	cursor.Execute(fmt.Sprintf(`SELECT sql FROM sqlite_master WHERE name=%s`, db._db_escape_string(table_name)))
	return cursor.FetchAll()[0][0]
}

func (db *database) _db_validate_create_statement(statement string) (bool, map[string]bool) {
	var missing_keys map[string]bool
	if statement == db._db_table["packages"]["create"] {
		return true, missing_keys
	}

	reStr := fmt.Sprintf(`^\s*CREATE\s*TABLE\s*%s\s*\(\s*%s\s*INTEGER\s*PRIMARY\s*KEY\s*AUTOINCREMENT\s*,(.*)\)\s*$`, db._db_table["packages"]["table_name"], db._db_table["packages"]["package_id"])
	m := regexp.MustCompile(reStr).FindStringSubmatch(statement)
	if m == nil {
		return false, missing_keys
	}
	return true, missing_keys
}

func (db *database) _db_table_get_create(table_name string) string {
	cursor := db._db_cursor()
	cursor.Execute(fmt.Sprintf(`SELECT sql FROM sqlite_master WHERE name=%s`, db._db_escape_string(table_name)))
	return cursor.FetchAll()[0][0]
}

func (db *database) _db_validate_create_statement(statement string) (bool, map[string]bool) {
	var missing_keys map[string]bool
	if statement == db._db_table["packages"]["create"] {
		return true, missing_keys
	}

	reStr := fmt.Sprintf(`^\s*CREATE\s*TABLE\s*%s\s*\(\s*%s\s*INTEGER\s*PRIMARY\s*KEY\s*AUTOINCREMENT\s*,(.*)\)\s*$`, db._db_table["packages"]["table_name"], db._db_table["packages"]["package_id"])
	m := regexp.MustCompile(reStr).FindStringSubmatch(statement)
	if m == nil {
		return false, missing_keys
	}

	unique_constraints := map[string]bool{db._db_table["packages"]["package_key"]: true}
	missing_keys = make(map[string]bool)
	for _, key := range db._allowed_keys {
		missing_keys[key] = true
	}
	unique_re := regexp.MustCompile(`^\s*UNIQUE\s*\(\s*(\w*)\s*\)\s*$`)
	column_re := regexp.MustCompile(`^\s*(\w*)\s*TEXT\s*$`)
	for _, x := range strings.Split(m[1], ",") {
		m := column_re.FindStringSubmatch(x)
		if len(m) > 0 {
			delete(missing_keys, m[1])
			continue
		}
		m = unique_re.FindStringSubmatch(x)
		if len(m) > 0 {
			delete(unique_constraints, m[1])
			continue
		}
	}

	if len(unique_constraints) > 0 {
		return false, missing_keys
	}

	return true, missing_keys
}

func (db *database) _db_init_cache_size(cache_bytes int) error {
	cursor := db._db_cursor()
	cursor.Execute("PRAGMA page_size")
	page_size := int(cursor.FetchOne()[0].(int64))
	cache_size := cache_bytes / page_size
	cursor.Execute(fmt.Sprintf("PRAGMA cache_size = %d", cache_size))
	cursor.Execute("PRAGMA cache_size")
	actual_cache_size := int(cursor.FetchOne()[0].(int64))
	if actual_cache_size != cache_size {
		return fmt.Errorf("actual cache_size = %d does not match requested size of %d", actual_cache_size, cache_size)
	}
	return nil
}

func (db *database) _db_init_synchronous(synchronous int) error {
	cursor := db._db_cursor()
	cursor.Execute(fmt.Sprintf("PRAGMA synchronous = %d", synchronous))
	cursor.Execute("PRAGMA synchronous")
	actual_synchronous := int(cursor.FetchOne()[0].(int64))
	if actual_synchronous != synchronous {
		return fmt.Errorf("actual synchronous = %d does not match requested value of %d", actual_synchronous, synchronous)
	}
	return nil
}

func (db *database) _getitem(cpv string) (map[string]string, error) {
	cursor := db._db_cursor()
	cursor.Execute(fmt.Sprintf("SELECT * FROM %s WHERE %s=%s",
		db._db_table["packages"]["table_name"],
		db._db_table["packages"]["package_key"],
		db._db_escape_string(cpv),
	))
	result := cursor.FetchAll()
	if len(result) == 1 {
		// pass
	} else if len(result) == 0 {
		return nil, fmt.Errorf("KeyError: %s", cpv)
	} else {
		return nil, fmt.Errorf("CacheCorruption: key is not unique for %s", cpv)
	}
	result = result[0]
	d := make(map[string]string)
	allowed_keys_set := db._allowed_keys_set
	for column_index, column_info := range cursor.Description() {
		k := column_info[0]
		if _, ok := allowed_keys_set[k]; ok {
			v := result[column_index]
			if v == nil {
				// This happens after a new empty column has been added.
				v = ""
			}
			d[k] = fmt.Sprintf("%v", v)
		}
	}
	return d, nil
}

    def _setitem(self, cpv, values):
        update_statement = []
        update_statement.append(
            "REPLACE INTO %s" % self._db_table["packages"]["table_name"]
        )
        update_statement.append("(")
        update_statement.append(
            ",".join([self._db_table["packages"]["package_key"]] + self._allowed_keys)
        )
        update_statement.append(")")
        update_statement.append("VALUES")
        update_statement.append("(")
        values_parameters = []
        values_parameters.append(self._db_escape_string(cpv))
        for k in self._allowed_keys:
            values_parameters.append(self._db_escape_string(values.get(k, "")))
        update_statement.append(",".join(values_parameters))
        update_statement.append(")")
        cursor = self._db_cursor
        try:
            s = " ".join(update_statement)
            cursor.execute(s)
        except self._db_error as e:
            writemsg("%s: %s\n" % (cpv, str(e)))
            raise

    def commit(self):
        self._db_connection.commit()

    def _delitem(self, cpv):
        cursor = self._db_cursor
        cursor.execute(
            "DELETE FROM %s WHERE %s=%s"
            % (
                self._db_table["packages"]["table_name"],
                self._db_table["packages"]["package_key"],
                self._db_escape_string(cpv),
            )
        )

func (db *database) _setitem(cpv string, values map[string]string) error {
	var updateStatement []string
	updateStatement = append(updateStatement, fmt.Sprintf("REPLACE INTO %s", db._db_table["packages"]["table_name"]))
	updateStatement = append(updateStatement, "(")
	updateStatement = append(updateStatement, fmt.Sprintf("%s,%s", db._db_table["packages"]["package_key"], strings.Join(db._allowed_keys, ",")))
	updateStatement = append(updateStatement, ")")
	updateStatement = append(updateStatement, "VALUES")
	updateStatement = append(updateStatement, "(")
	var valuesParameters []string
	valuesParameters = append(valuesParameters, db._db_escape_string(cpv))
	for _, k := range db._allowed_keys {
		valuesParameters = append(valuesParameters, db._db_escape_string(values[k]))
	}
	updateStatement = append(updateStatement, strings.Join(valuesParameters, ","))
	updateStatement = append(updateStatement, ")")
	cursor := db._db_cursor()
	s := strings.Join(updateStatement, " ")
	_, err := cursor.Exec(s)
	if err != nil {
		return fmt.Errorf("%s: %s", cpv, err.Error())
	}
	return nil
}

func (db *database) commit() error {
	return db._db_connection().Commit()
}

func (db *database) _delitem(cpv string) error {
	cursor := db._db_cursor()
	_, err := cursor.Exec(fmt.Sprintf("DELETE FROM %s WHERE %s=%s",
		db._db_table["packages"]["table_name"],
		db._db_table["packages"]["package_key"],
		db._db_escape_string(cpv),
	))
	return err
}

func (db *database) __contains__(cpv string) (bool, error) {
	cursor := db._db_cursor()
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s=%s",
		db._db_table["packages"]["package_id"],
		db._db_table["packages"]["table_name"],
		db._db_table["packages"]["package_key"],
		db._db_escape_string(cpv),
	)
	cursor.execute(query)
	result, err := cursor.fetchall()
	if err != nil {
		return false, err
	}
	if len(result) == 0 {
		return false, nil
	}
	if len(result) == 1 {
		return true, nil
	}
	return false, cache_errors.CacheCorruption{cpv, "key is not unique"}
}

func (db *database) __iter__() <-chan string {
	cursor := db._db_cursor()
	query := fmt.Sprintf("SELECT %s FROM %s",
		db._db_table["packages"]["package_key"],
		db._db_table["packages"]["table_name"],
	)
	cursor.execute(query)
	result, err := cursor.fetchall()
	if err != nil {
		return nil
	}
	keyList := make(chan string)
	go func() {
		defer close(keyList)
		for _, row := range result {
			keyList <- row[0]
		}
	}()
	return keyList
}
