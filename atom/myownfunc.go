package atom

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"syscall"
)

func ReverseSlice(s interface{}) {
	size := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)
	for i, j := 0, size-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}

func CopyMapSS(m map[string]string) map[string]string {
	r := map[string]string{}
	for k, v := range m {
		r[k] = v
	}
	return r
}

func CopyMapSB(m map[string]bool) map[string]bool {
	r := map[string]bool{}
	for k, v := range m {
		r[k] = v
	}
	return r
}

func CopyMSMASS(m map[string]map[*Atom][]string) map[string]map[*Atom][]string {
	r := map[string]map[*Atom][]string{}
	for k, v := range m {
		r[k] = v
	}
	return r
}

func inmss(a map[string]string, b string) bool{
	for _ ,v := range a {
		if b == v {
			return true
		}
	}
	return false
}

func Ins(a []string, b string) bool{
	for _ ,v := range a {
		if b== v {
			return true
		}
	}
	return false
}

func Mountpoint(path string) (string,error) {
	pi, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	odev := pi.Sys().(*syscall.Stat_t).Dev

	for path != "/" {
		_path := filepath.Dir(path)

		in, err := os.Stat(_path)
		if err != nil {
			return "", err
		}

		if odev != in.Sys().(*syscall.Stat_t).Dev {
			break
		}

		path = _path
	}

	return path, nil
}

func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}


func CopyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cp[k] = CopyMap(vm)
		} else {
			cp[k] = v
		}
	}

	return cp
}

func pathExists(filename string) bool {
	st, _ := os.Stat(filename)
	return st != nil
}

func pathAccess(filename string) bool {
	st, _ := os.Stat(filename)
	if st == nil {
		return false
	}
	return st.Mode()&os.ModePerm== 0
}

func reversed (a []string)[]string {
	b := []string{}
	for _, v := range a {
		b = append([]string{v}, b...)
	}
	return b
}

func sorted (a []string)[]string {
	b := []string{}
	copy(b, a)
	sort.Strings(b)
	return b
}

func getNamedRegexp(re *regexp.Regexp, target, name string) string {
	match := re.FindStringSubmatch(target)
	for i, n := range re.SubexpNames() {
		if i > 0 && i <= len(match) && n == name {
			return match[i]
		}
	}
	return ""
}

func toi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
