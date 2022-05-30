package myutil

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func ReverseSlice(s interface{}) {
	size := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)
	for i, j := 0, size-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}

func ReverseSliceT[T []any](s T) {
	size := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)
	for i, j := 0, size-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}

func CopyMapT[T1 comparable, T2 any](m map[T1]T2) map[T1]T2 {
	r := map[T1]T2{}
	for k, v := range m {
		r[k] = v
	}
	return r
}

func CopyMapSS(m map[string]string) map[string]string {
	r := map[string]string{}
	for k, v := range m {
		r[k] = v
	}
	return r
}

func CopyMapSSS(m map[string][]string) map[string][]string {
	r := map[string][]string{}
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

func InmsT[T any](a map[string]T, b string) bool {
	for v := range a {
		if b == v {
			return true
		}
	}
	return false
}

func Inmss(a map[string]string, b string) bool {
	for v := range a {
		if b == v {
			return true
		}
	}
	return false
}

func Inmsi(a map[string]interface{}, b string) bool {
	for v := range a {
		if b == v {
			return true
		}
	}
	return false
}

func Inmsmss(a map[string]map[string]string, b string) bool {
	for v := range a {
		if b == v {
			return true
		}
	}
	return false
}

func Inmsss(a map[string][]string, b string) bool {
	for v := range a {
		if b == v {
			return true
		}
	}
	return false
}

func Inmssb(a map[string]map[string]bool, b string) bool {
	for v := range a {
		if b == v {
			return true
		}
	}
	return false
}

func Ins(a []string, b string) bool {
	for _, v := range a {
		if b == v {
			return true
		}
	}
	return false
}

func Ini(a []int, b int) bool {
	for _, v := range a {
		if b == v {
			return true
		}
	}
	return false
}

func Mountpoint(path string) (string, error) {
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

func PathExists(filename string) bool {
	st, _ := os.Stat(filename)
	return st != nil
}

func PathIsDir(filename string) bool {
	st, _ := os.Stat(filename)
	return st != nil && st.IsDir()
}

func PathIsFile(filename string) bool {
	st, _ := os.Stat(filename)
	return st != nil && !st.IsDir()
}

func OsAccess(filename string, mode os.FileMode) bool {
	st, _ := os.Stat(filename)
	if st == nil {
		return false
	}
	return st.Mode()&mode != 0
}

func ReversedT[T any](a []T) []T {
	b := []T{}
	for _, v := range a {
		b = append([]T{v}, b...)
	}
	return b
}

func Reversed(a []string) []string {
	b := []string{}
	for _, v := range a {
		b = append([]string{v}, b...)
	}
	return b
}

func Sorted(a []string) []string {
	b := []string{}
	copy(b, a)
	sort.Strings(b)
	return b
}

func Sortedmsb(a map[string]bool) []string {
	b := []string{}
	for k := range a {
		b = append(b, k)
	}
	sort.Strings(b)
	return b
}

func SortedMS[T any](a map[string]T) []string {
	b := []string{}
	for k := range a {
		b = append(b, k)
	}
	sort.Strings(b)
	return b
}

func sortedmss(a map[string]string) []string {
	b := []string{}
	for k := range a {
		b = append(b, k)
	}
	sort.Strings(b)
	return b
}

func GetNamedRegexp(re *regexp.Regexp, target, name string) string {
	match := re.FindStringSubmatch(target)
	for i, n := range re.SubexpNames() {
		if i > 0 && i <= len(match) && n == name {
			return match[i]
		}
	}
	return ""
}

func Toi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func joinMB(s map[string]bool, sep string) string {
	r := []string{}
	for k := range s {
		r = append(r, k)
	}
	return strings.Join(r, sep)
}

func ListDir(path string) ([]string, error) {
	ss, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	rs := []string{}
	for _, s := range ss {
		rs = append(rs, s.Name())
	}
	return rs, nil
}

// --------------------copy
func Getcwd() string {
	s, err := os.Getwd()
	if err != nil {
		os.Chdir("/")
		return "/"
	} else {
		return s
	}
}

func GetStdin() *os.File {
	return os.Stdin
}
