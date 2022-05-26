package validrepo

import (
	"regexp"
	"strings"
)

var repoNameSubRe = regexp.MustCompile(`[^\w-]`)

func GenValidRepo(name string) string {
	name = repoNameSubRe.ReplaceAllString(strings.TrimSpace(name), " ")
	name = strings.Join(strings.Fields(name), "-")
	name = strings.TrimLeft(name, "-")
	return name
}
