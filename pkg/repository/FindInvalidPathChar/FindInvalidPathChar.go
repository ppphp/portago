package FindInvalidPathChar

import "regexp"

var invalidPathCharRe = regexp.MustCompile("[^a-zA-Z0-9._\\-+/]")

// 0, 0
func FindInvalidPathChar(path string, pos int, endpos int) int {
	if endpos == 0 {
		endpos = len(path)
	}
	if m := invalidPathCharRe.FindStringIndex(path[pos:endpos]); len(m) > 0 {
		return m[0]
	}
	return -1
}
