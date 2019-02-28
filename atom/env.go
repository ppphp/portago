package atom

import "strings"

var ValidAtomValidator = isValidAtom

func packagesFileValidator(atom string)bool{
	if strings.HasPrefix(atom, "*") || strings.HasPrefix(atom, "-"){
		atom = atom[1:]
	}
	if !isValidAtom(atom,false, false, false, "", false){
		return false
	}
	return true
}
