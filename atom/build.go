package atom

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
)

func Build() {
	c := exec.Command("./bin/ebuild", "./tmp/app-misc/hello/hello-2.10.ebuild", "merge")
	var in, out bytes.Buffer
	c.Stdout = &in
	c.Stderr = &out
	c.Run()
	println(string(in.Bytes()))
	println(string(out.Bytes()))
}

// function to drive ebuild.sh
func EbuildDriver(env []string, action string){
	c := exec.Command("./bin/ebuild.sh", action)
	var out, err bytes.Buffer
	c.Stdout = &out
	c.Stderr = &err
	c.Env = env
	if err := c.Run(); err != nil {
		println(err.Error())
	}
	println(string(out.Bytes()))
	println(string(err.Bytes()))
}

func ebuildConfig(ebuild string) []string {
	ebuildPath := ebuild
	pkgDir := path.Dir(ebuild)
	//myTree := path.Dir(path.Dir(pkgDir))
	//myPv := strings.TrimSuffix(path.Base(ebuild), ".ebuild")

	return []string{
		fmt.Sprintf("EBUILD=%v", ebuildPath),
		fmt.Sprintf("O=%v", pkgDir),
		//fmt.Sprintf("EBUILD=%v", ebuildPath),
		//fmt.Sprintf("EBUILD=%v", ebuildPath),
	}
}

func doPhase(ebuild, phase string) {
	env := make([]string, len(os.Environ()))
	copy(env, os.Environ())
	if phase == "clean" {
		env = append(env, strings.Split(clean(), "\n")...)
		EbuildDriver(env, "clean")
	}
}
