package ebuild

import (
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/versions"
	"regexp"
)

type PkgStr versions.PkgStr[*Config]

func NewPkgStr(cpv string, metadata map[string]string, settings *Config, eapi1 string, repo string, slot string, build_time int, build_id int, file_size string, mtime int, db interfaces.IDbApi) *PkgStr {
	pkg := versions.NewPkgStr[*Config](cpv, metadata, settings, eapi1, repo, slot, build_time, build_id, file_size, mtime, db)
	pkg1 := PkgStr(*pkg)
	return &pkg1
}

func IterIuseVars(env map[string]string) [][2]string {
	kv := make([][2]string, 0)

	for _, k := range []string{"IUSE_IMPLICIT", "USE_EXPAND_IMPLICIT", "USE_EXPAND_UNPREFIXED", "USE_EXPAND"} {
		if v, ok := env[k]; ok {
			kv = append(kv, [2]string{k, v})
		}
	}
	re := regexp.MustCompile("\\s+")
	useExpandImplicit := re.Split(env["USE_EXPAND_IMPLICIT"], -1)
	for _, v := range append(re.Split(env["USE_EXPAND_UNPREFIXED"], -1), re.Split(env["USE_EXPAND"], -1)...) {
		equal := false
		for _, k := range useExpandImplicit {
			if k == v {
				equal = true
				break
			}
		}
		if equal {
			k := "USE_EXPAND_VALUES_" + v
			v, ok := env[k]
			if ok {
				kv = append(kv, [2]string{k, v})
			}
		}
	}

	return kv
}
