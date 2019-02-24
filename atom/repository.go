package atom

import (
	"regexp"
	"strings"
)

var (

	repoNameSubRe = regexp.MustCompile(`[^\w-]`)
)

func genValidRepo(name string) string {
	name = repoNameSubRe.ReplaceAllString(strings.TrimSpace(name), " ")
	name = strings.Join(strings.Fields(name), "-")
	name = strings.TrimPrefix(name, "-")
	return name
}
