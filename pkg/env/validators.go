package env

import (
	"strings"
)

// var ValidAtomValidator = atom.isValidAtom

// isValidAtom
func packagesFileValidator(atom string, isValidAtom func(atom string, allowBlockers, allowWildcard, allowRepo bool, eapi string, allowBuildId bool) bool) bool {
	if strings.HasPrefix(atom, "*") || strings.HasPrefix(atom, "-") {
		atom = atom[1:]
	}
	if !isValidAtom(atom, false, false, false, "", false) {
		return false
	}
	return true
}
