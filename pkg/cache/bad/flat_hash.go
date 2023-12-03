package cache

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type FlatHashDatabase struct {
	*FsBased
	location      string
	label         string
	readonly      bool
	knownKeys     []string
	validationChf string
	writeKeys     []string
}

func NewFlatHashDatabase(location, label string, readonly bool) *database {
	db := &FlatHashDatabase{
		location:      filepath.Join(location, strings.Trim(label, string(os.PathSeparator))),
		label:         label,
		readonly:      readonly,
		knownKeys:     []string{},
		validationChf: "",
		writeKeys:     []string{},
	}

	db.writeKeys = append(db.writeKeys, db.knownKeys...)
	db.writeKeys = append(db.writeKeys, "_eclasses_")
	db.writeKeys = append(db.writeKeys, "_"+db.validationChf+"_")

	if !db.readonly && !db.exists(db.location) {
		db.ensureDirs()
	}

	return db
}

func (db *FlatHashDatabase) GetItem(cpv string) (map[string]string, error) {
	fp := db.location + string(os.PathSeparator) + cpv

	f, err := os.Open(fp)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("Key not found")
		}
		return nil, err
	}
	defer f.Close()

	lines := make([]string, 0)
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		lines = append(lines, string(buf[:n]))
	}

	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	data := make(map[string]string)
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, errors.New("Invalid data")
		}
		data[parts[0]] = parts[1]
	}

	if _, ok := data["_mtime_"]; !ok {
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		data["_mtime_"] = strconv.FormatInt(fi.ModTime().Unix(), 10)
	}

	return data, nil
}

func (db *FlatHashDatabase) SetItem(cpv string, values map[string]string) error {
	fp, err := db.createTempFile()
	if err != nil {
		return err
	}
	defer os.Remove(fp)

	f, err := os.Create(fp)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, key := range db.writeKeys {
		value, ok := values[key]
		if !ok {
			continue
		}
		_, err := f.WriteString(key + "=" + value + "\n")
		if err != nil {
			return err
		}
	}

	err = db.ensureAccess(fp)
	if err != nil {
		return err
	}

	newFp := filepath.Join(db.location, cpv)
	err = os.Rename(fp, newFp)
	if err != nil {
		if os.IsNotExist(err) {
			err = db.ensureDirs(cpv)
			if err != nil {
				return err
			}
			err = os.Rename(fp, newFp)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func (db *FlatHashDatabase) DeleteItem(cpv string) error {
	err := os.Remove(filepath.Join(db.location, cpv))
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("Key not found")
		}
		return err
	}
	return nil
}

func (db *FlatHashDatabase) Contains(cpv string) bool {
	return db.exists(filepath.Join(db.location, cpv))
}

func (db *FlatHashDatabase) Iterate() <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)

		dirs := []string{db.location}
		lenBase := len(db.location)

		for len(dirs) > 0 {
			dirPath := dirs[len(dirs)-1]
			dirs = dirs[:len(dirs)-1]

			dirList, err := db.readDir(dirPath)
			if err != nil {
				continue
			}

			for _, l := range dirList {
				p := filepath.Join(dirPath, l)
				st, err := os.Lstat(p)
				if err != nil {
					continue
				}

				if st.Mode().IsDir() {
					if lenBase-depth < 1 {
						dirs = append(dirs, p)
					}
					continue
				}

				pkgStr := p[lenBase+1:]
				if !db.isValidPkgStr(pkgStr) {
					continue
				}

				ch <- pkgStr
			}
		}
	}()

	return ch
}

type MD5Database struct {
	FlatHashDatabase
}

func NewMD5Database(location, label string, readonly bool) *MD5Database {
	return &MD5Database{
		FlatHashDatabase: FlatHashDatabase{
			location:  location,
			label:     label,
			readonly:  readonly,
			knownKeys: []string{},
			writeKeys: []string{},
		},
	}
}

type MtimeMD5Database struct {
	FlatHashDatabase
}

func NewMtimeMD5Database(location, label string, readonly bool) *MtimeMD5Database {
	return &MtimeMD5Database{
		FlatHashDatabase: FlatHashDatabase{
			location:  location,
			label:     label,
			readonly:  readonly,
			knownKeys: []string{},
			writeKeys: []string{},
		},
	}
}
