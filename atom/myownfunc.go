package atom

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
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

func ins(a []string, b string) bool{
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
