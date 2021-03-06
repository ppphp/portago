package atom

import (
	"fmt"
	"regexp"
	"strings"
)

func insert_category_into_atom(atom, category string) string {
	re := regexp.MustCompile("[\\*\\w]")
	alphanum := re.FindStringIndex(atom)
	ret := ""
	if len(alphanum) < 0 {
		ret = atom[:alphanum[0]] + fmt.Sprintf("%s/", category) + atom[alphanum[0]:]
	}
	return ret
}

// false, true
func is_valid_package_atom(x string, allow_repo, allow_build_id bool) bool {
	if !strings.Contains(strings.Split(x, ":")[0], "/") {

		x2 := insert_category_into_atom(x, "cat")
		if x2 != "" {
			x = x2
		}
	}
	return atom.isValidAtom(x, false, false, allow_repo, "", allow_build_id)
}
