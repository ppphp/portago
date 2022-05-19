package env

import (
	"fmt"
	"github.com/ppphp/portago/pkg/util"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func recursiveFileLoader(fileName string) []string {
	st, err := os.Stat(fileName)
	if err != nil {
		return nil
	}
	if st.IsDir() {
		files := []string{}
		filepath.Walk(fileName, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() && (info.Name() == "CVS" || info.Name()[:1] == ".") {
				return filepath.SkipDir
			} else if info.Name()[:len(info.Name())-1] == "~" || info.Name()[:1] == "." {
				files = append(files, path)
			}
			return nil
		})
		return files
	} else {
		return []string{fileName}
	}
}

type dataLoader struct {
	validate func(key string) bool
}

func (d *dataLoader) Load() {}

func NewDataLoader(validator func(string) bool) *dataLoader {
	d := &dataLoader{}
	if validator != nil {
		d.validate = validator
	} else {
		d.validate = func(string) bool {
			return true
		}
	}
	return d
}

type envLoader struct {
	dataLoader
}

func (d *envLoader) Load() []string {
	return os.Environ()
}

func NewEnvLoader(validator func(string) bool) *envLoader {
	d := &envLoader{}
	if validator != nil {
		d.validate = validator
	} else {
		d.validate = func(string) bool {
			return true
		}
	}
	return d
}

type testTextLoader struct {
	dataLoader
	data   map[string]string
	errors error
}

func (d *testTextLoader) setData(text map[string]string) {
	d.data = text
}

func (d *testTextLoader) setErrors(err error) {
	d.errors = err
}

func (d *testTextLoader) Load() map[string]string {
	return d.data
}

func NewTestTextLoader(validator func(string) bool) *testTextLoader {
	d := &testTextLoader{}
	if validator != nil {
		d.validate = validator
	} else {
		d.validate = func(string) bool {
			return true
		}
	}
	return d
}

type fileLoader struct {
	dataLoader
	fname string
}

func (f *fileLoader) Load() (map[string][]string, map[string][]string) {
	data, errors := map[string][]string{}, map[string][]string{}
	fun := f.lineParser
	for _, fn := range util.RecursiveFileList(f.fname) {
		f, _ := os.Open(fn)
		m, _ := ioutil.ReadAll(f)
		lines := strings.Split(string(m), "\n")
		for lineNum, line := range lines {
			fun(line, lineNum, data, errors)
		}
	}
	return data, errors
}

func (f *fileLoader) lineParser(line string, lineNum int, data, errors map[string][]string) {}

func NewFileLoader(filename string, validator func(string) bool) *fileLoader {
	d := &fileLoader{fname: filename}
	if validator != nil {
		d.validate = validator
	} else {
		d.validate = func(string) bool {
			return true
		}
	}
	return d
}

type itemFileLoader struct {
	fileLoader
	fname string
}

func (f *itemFileLoader) lineParser(line string, lineNum int, data, errors map[string][]string) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") {
		return
	}
	if len(line) == 0 {
		return
	}
	split := strings.Fields(line)
	if len(split) == 0 {
		if _, ok := errors[f.fname]; !ok {
			errors[f.fname] = []string{}
		}
		errors[f.fname] = append(errors[f.fname], fmt.Sprintf("Malformed data at line: %v, data: %s", lineNum+1, line))
		return
	}
	key := split[0]
	if !f.validate(key) {
		if _, ok := errors[f.fname]; !ok {
			errors[f.fname] = []string{}
		}
		errors[f.fname] = append(errors[f.fname], fmt.Sprintf("Validation failed at line: %v, data %s", lineNum+1, key))
		return
	}
	data[key] = nil
}

func NewItemFileLoader(filename string, validator func(string) bool) *itemFileLoader {
	d := &itemFileLoader{fname: filename}
	if validator != nil {
		d.validate = validator
	} else {
		d.validate = func(string) bool {
			return true
		}
	}
	return d
}

type keyListFileLoader struct {
	fileLoader
	fname          string
	valueValidator func([]string) bool
}

func (f *keyListFileLoader) lineParser(line string, lineNum int, data, errors map[string][]string) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") {
		return
	}
	if len(line) == 0 {
		return
	}
	split := strings.Fields(line)
	if len(split) < 1 {
		if _, ok := errors[f.fname]; !ok {
			errors[f.fname] = []string{}
		}
		errors[f.fname] = append(errors[f.fname], fmt.Sprintf("Malformed data at line: %v, data: %s", lineNum+1, line))
		return
	}
	key := split[0]
	value := split[1:]
	if !f.validate(key) {
		if _, ok := errors[f.fname]; !ok {
			errors[f.fname] = []string{}
		}
		errors[f.fname] = append(errors[f.fname], fmt.Sprintf("Key validation failed at line: %v, data %s", lineNum+1, key))
		return
	}
	if !f.valueValidator(value) {
		if _, ok := errors[f.fname]; !ok {
			errors[f.fname] = []string{}
		}
		errors[f.fname] = append(errors[f.fname], fmt.Sprintf("Value validation failed at line: %v, data %s", lineNum+1, value))
		return
	}
	if _, ok := data[key]; ok {
		data[key] = append(data[key], value...)
	} else {
		data[key] = value
	}
}

func NewKeyListFileLoader(filename string, validator func(string) bool, valueValidator func([]string) bool) *keyListFileLoader {
	d := &keyListFileLoader{fname: filename}
	if validator != nil {
		d.validate = validator
	} else {
		d.validate = func(string) bool {
			return true
		}
	}
	if valueValidator != nil {
		d.valueValidator = valueValidator
	} else {
		d.valueValidator = func([]string) bool {
			return true
		}
	}
	return d
}

type keyValuePairFileLoader struct {
	fileLoader
	fname          string
	valueValidator func(string) bool
}

func (f *keyValuePairFileLoader) lineParser(line string, lineNum int, data map[string][]string, errors map[string][]string) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") {
		return
	}
	if len(line) == 0 {
		return
	}
	split := strings.SplitN(line, "=", 2)
	if len(split) < 2 {
		if _, ok := errors[f.fname]; !ok {
			errors[f.fname] = []string{}
		}
		errors[f.fname] = append(errors[f.fname], fmt.Sprintf("Malformed data at line: %v, data: %s", lineNum+1, line))
		return
	}
	key := strings.TrimSpace(split[0])
	value := strings.TrimSpace(split[1])
	if !f.validate(key) {
		if _, ok := errors[f.fname]; !ok {
			errors[f.fname] = []string{}
		}
		errors[f.fname] = append(errors[f.fname], fmt.Sprintf("Key validation failed at line: %v, data %s", lineNum+1, key))
		return
	}
	if !f.valueValidator(value) {
		if _, ok := errors[f.fname]; !ok {
			errors[f.fname] = []string{}
		}
		errors[f.fname] = append(errors[f.fname], fmt.Sprintf("Value validation failed at line: %v, data %s", lineNum+1, value))
		return
	}
	data[key] = []string{value}
}

func NewKeyValuePairFileLoader(filename string, validator, valueValidator func(string) bool) *keyValuePairFileLoader {
	d := &keyValuePairFileLoader{fname: filename}
	if validator != nil {
		d.validate = validator
	} else {
		d.validate = func(string) bool {
			return true
		}
	}
	if valueValidator != nil {
		d.valueValidator = valueValidator
	} else {
		d.valueValidator = func(string) bool {
			return true
		}
	}
	return d
}
