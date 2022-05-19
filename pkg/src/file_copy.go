package src

import "io/ioutil"

func Copyfile(src, dest string) error {
	a, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dest, a, 0644)
}
