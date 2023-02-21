package changelog

import (
	"github.com/ppphp/portago/pkg/manifest"
	"github.com/ppphp/portago/pkg/versions"
	"strings"
)

type ChangeLogTypeSort struct {
	string
	status_change, file_name, file_type string
}

func NewChangeLogTypeSort(status_change, file_name string) *ChangeLogTypeSort {
	c := &ChangeLogTypeSort{}
	c.string = status_change + file_name
	c.status_change = status_change
	c.file_name = file_name
	c.file_type = manifest.GuessManifestFileType(file_name)
	return c
}

func (c *ChangeLogTypeSort) _file_type_lt(a, b *ChangeLogTypeSort) bool {

	first := a.file_type
	second := b.file_type
	if first == second {
		return false
	}

	if first == "EBUILD" {
		return true
	}
	if first == "MISC" {
		return second ==
			"EBUILD"
	}
	if first == "AUX" {
		return second == "EBUILD" || second == "MISC"
	}
	if first == "DIST" {
		return second == "EBUILD" || second == "MISC" || second == "AUX"
	}
	if first == "" {
		return false
	}
	return false
	//raise
	//ValueError("Unknown file type '%s'" % first)
}

func (c *ChangeLogTypeSort) __lt__(other *ChangeLogTypeSort) bool {

	if c._file_type_lt(c, other) {
		return true
	}
	if c._file_type_lt(other, c) {
		return false
	}

	if c.file_type == "EBUILD" {
		cf := versions.PkgSplit(c.file_name[:len(c.file_name)-7], 1, "")
		ver := strings.Join(cf[1:3], "-")
		of := versions.PkgSplit(other.file_name[:len(c.file_name)-7], 1, "")
		other_ver := strings.Join(of[1:3], "-")
		vc, _ := versions.VerCmp(ver, other_ver)
		return vc < 0
	}
	return c.file_name < other.file_name
}
