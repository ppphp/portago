package ebuild

import (
	"regexp"
)

func IterIuseVars(env map[string]string) [][2]string {
	kv := make([][2]string, 0)

	for _, k := range []string{
		"IUSE_IMPLICIT",
		"USE_EXPAND_IMPLICIT",
		"USE_EXPAND_UNPREFIXED",
		"USE_EXPAND",
	} {
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
