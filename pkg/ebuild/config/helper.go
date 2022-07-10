package config

import (
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/versions"
)

func orderedByAtomSpecificity(cpdict map[*dep.Atom[*Config]][]string, pkg *versions.PkgStr[*Config], repo string) [][]string {
	if pkg.Repo == "" && repo != "" && repo != versions.UnknownRepo {
		//pkg = pkg +repoSeparator+repo
	}
	results := [][]string{}
	keys := []*dep.Atom[*Config]{}
	for k := range cpdict {
		keys = append(keys, k)
	}
	for len(keys) > 0 {
		bestMatch := dep.BestMatchToList(pkg, keys)
		if bestMatch != nil {
			keys2 := []*dep.Atom[*Config]{}
			for k := range cpdict {
				if k != bestMatch {
					keys2 = append(keys2, k)
				}
			}
			keys = keys2
			results = append(results, cpdict[bestMatch])
		} else {
			break
		}
	}
	if len(results) != 0 {
		r := [][]string{}
		for i := 0; i < len(results); i++ {
			r = append(r, results[len(results)-1-i])
		}
		return r
	}
	return results
}

func orderedByAtomSpecificity2(cpdict map[*dep.Atom[*Config]]map[string][]string, pkg *versions.PkgStr[*Config], repo string) []map[string][]string {
	if pkg.Repo == "" && repo != "" && repo != versions.UnknownRepo {
		//pkg = pkg +repoSeparator+repo
	}
	results := []map[string][]string{}
	keys := []*dep.Atom[*Config]{}
	for k := range cpdict {
		keys = append(keys, k)
	}
	for len(keys) > 0 {
		bestMatch := dep.BestMatchToList(pkg, keys)
		if bestMatch != nil {
			keys2 := []*dep.Atom[*Config]{}
			for k := range cpdict {
				if k != bestMatch {
					keys2 = append(keys2, k)
				}
			}
			keys = keys2
			results = append(results, cpdict[bestMatch])
		} else {
			break
		}
	}
	if len(results) != 0 {
		r := []map[string][]string{}
		for i := 0; i < len(results); i++ {
			r = append(r, results[len(results)-1-i])
		}
		return r
	}
	return results
}

func pruneIncremental(split []string) []string {
	myutil.ReverseSlice(split)
	for i, x := range split {
		if x == "*" {
			split = split[len(split)-i-1:]
			break
		} else if x == "-*" {
			if i == 0 {
				split = []string{}
			} else {
				split = split[len(split)-i:]
			}
			break
		}
	}
	return split
}
