package util

import (
	"fmt"
	"github.com/ppphp/portago/pkg/env"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/shlex"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strings"
)

func ExtractKernelVersion(base_dir string) (string, error) {
	pathname := filepath.Join(base_dir, "Makefile")
	f, err := ioutil.ReadFile(pathname)
	if err != nil {
		//except OSError as details:
		//return (None, str(details))
		//except IOError as details:
		return "", err
	}

	lines := strings.Split(string(f), "\n")[:4]
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}

	version := ""

	for _, line := range lines {
		items := strings.Split(line, "=")

		for i := range items {
			items[i] = strings.TrimSpace(items[i])
		}
		if items[0] == "VERSION" ||
			items[0] == "PATCHLEVEL" {
			version += items[1]
			version += "."
		} else if items[0] == "SUBLEVEL" {
			version += items[1]
		} else if items[0] == "EXTRAVERSION" &&
			items[len(items)-1] != items[0] {
			version += items[1]
		}
	}

	localversions, _ := myutil.ListDir(base_dir)
	for x := len(localversions) - 1; x >= 0; x-- {
		if localversions[x][:12] != "localversion" {
			lvs := []string{}
			for i, k := range localversions {
				if i != x {
					lvs = append(lvs, k)
				}
			}
			localversions = lvs
		}
	}
	sort.Strings(localversions)

	for _, lv := range localversions {
		gf := GrabFile(base_dir+"/"+lv, 0, false, false)
		fs := []string{}
		for _, k := range gf {
			fs = append(fs, k[0])
		}
		version += strings.Join(strings.Fields(strings.Join(fs, " ")), "")
	}

	loader := env.NewKeyValuePairFileLoader(filepath.Join(base_dir, ".config"), nil, nil)
	kernelconfig, loader_errors := loader.Load()
	if len(loader_errors) > 0 {
		for file_path, file_errors := range loader_errors {
			for _, error_str := range file_errors {
				WriteMsgLevel(fmt.Sprintf("%s: %s\n", file_path, error_str), 40, -1)
			}
		}
	}

	if len(kernelconfig) > 0 && myutil.Inmsss(kernelconfig, "CONFIG_LOCALVERSION") {
		ss, _ := shlex.Split(strings.NewReader(kernelconfig["CONFIG_LOCALVERSION"][0]), false, true)
		version += strings.Join(ss, "")
	}

	return version, nil
}
