package atom

import (
	"bufio"
	"regexp"
	"os"
	"path"
	"strings"
)

const (
	pmsEapiRe          = `^[ \t]*EAPI=(['\"][A-Za-z0-9+_.-]*['\"])|([A-Za-z0-9+_.-]*)[ \t]*([ \t]#.*)?$`
	commentOrBlankLine = `^\s*(#.*)?$`
)

//func init() {
//	err := ebuild("./tmp/app-misc/hello/hello-2.10.ebuild", []string{"merge"}, nil)
//	if err != nil {
//		println(err.Error())
//	}
//}

// the entrance of the ebuild
func ebuild(pkg string, action []string, config map[string]string) error {
	if len(action) == 0 {
		return nil
	}
	santinizeFds()
	if !strings.HasSuffix(pkg, ".ebuild") {
		return nil
	}
	p := path.Join(os.Getenv("PWD"), pkg)
	//d := path.Dir(p)
	//vdbPath := "/var/db/pkg"
	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	c, err := regexp.Compile(commentOrBlankLine)
	if err != nil {
		return err
	}
	e, err := regexp.Compile(pmsEapiRe)
	if err != nil {
		return err
	}
	eapi := ""
	for scanner.Scan() {
		b := scanner.Bytes()
		if c.Match(b) {
			continue
		}
		if eapi = string(e.Find(b)); eapi != "" {
			break
		}
	}

	for _, a := range action {
		if a == "merge" {
			doPhase(p, "clean")
		}
	}


	return nil
	//cpv := fmt.Sprintf("%v/%v",  strings.TrimSuffix(p, ".ebuild"))
}

func santinizeFds() {

}

//func doEbuild(ebuild, do string) {
//
//}

func iterIuseVars(env map[string]string) [][2]string {
	kv := make([][2]string, 0)

	for _, k := range []string{"IUSE_IMPLICIT", "USE_EXPAND_IMPLICIT", "USE_EXPAND_UNPREFIXED", "USE_EXPAND"}{
		if v, ok := env[k]; ok {
			kv = append(kv, [2]string{k,v})
		}
	}
	re := regexp.MustCompile("\\s+")
	useExpandImplicit := re.Split(env["USE_EXPAND_IMPLICIT"], -1)
	for _, v := range append(re.Split(env["USE_EXPAND_UNPREFIXED"], -1), re.Split(env["USE_EXPAND"], -1)...){
		equal := false
		for _, k := range useExpandImplicit {
			if k == v{
				equal = true
				break
			}
		}
		if equal{
			k := "USE_EXPAND_VALUES_" + v
			v, ok := env[k]
			if ok {
				kv = append(kv, [2]string{k,v})
			}
		}
	}

	return kv
}
