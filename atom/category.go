package atom

import (
	"fmt"
	"github.com/ppphp/portago/pkg/const"
	"io/ioutil"
)

func IndexCategories() []string {
	fs, err := ioutil.ReadDir(_const.EbuildDir)
	if err != nil {
		println(err.Error())
		return nil
	}
	cats := []string{}
	for _, f := range fs {
		cats = append(cats, f.Name())
	}
	fmt.Printf("%+v", cats)
	return cats
}

func IndexPackages(category string) []string {
	fs, err := ioutil.ReadDir(_const.EbuildDir + "/" + category)
	if err != nil {
		println(err.Error())
		return nil
	}
	cats := []string{}
	for _, f := range fs {
		cats = append(cats, f.Name())
	}
	fmt.Printf("%+v", cats)
	return nil
}
