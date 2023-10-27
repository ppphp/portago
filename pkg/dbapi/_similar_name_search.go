package dbapi

import (
	"difflib"
	"strings"
)

func similarNameSearch(dbs []DB, atom Atom) []string {
	cpLower := strings.ToLower(atom.CP)
	cat, pkg := catSplit(cpLower)
	if cat == "null" {
		cat = ""
	}

	allCP := make(map[string]bool)
	for _, db := range dbs {
		for _, cp := range db.CPAll() {
			allCP[cp] = true
		}
	}

	// discard dir containing no ebuilds
	delete(allCP, atom.CP)

	origCPMap := make(map[string][]string)
	for _, cpOrig := range allCP {
		origCPMap[strings.ToLower(cpOrig)] = append(origCPMap[strings.ToLower(cpOrig)], cpOrig)
	}

	var matches []string
	if cat != "" {
		matches = difflib.GetCloseMatches(cpLower, allCP, 0, 0)
	} else {
		pkgToCP := make(map[string][]string)
		for _, otherCP := range allCP {
			otherPkg := catSplit(strings.ToLower(otherCP))[1]
			if otherPkg == pkg {
				// Check for non-identical package that
				// differs only by upper/lower case.
				identical := true
				for _, cpOrig := range origCPMap[otherCP] {
					if catSplit(cpOrig)[1] != catSplit(atom.CP)[1] {
						identical = false
						break
					}
				}
				if identical {
					// discard dir containing no ebuilds
					delete(allCP, otherCP)
					continue
				}
			}
			pkgToCP[otherPkg] = append(pkgToCP[otherPkg], otherCP)
		}

		pkgMatches := difflib.GetCloseMatches(pkg, pkgToCP, 0, 0)
		for _, pkgMatch := range pkgMatches {
			matches = append(matches, pkgToCP[pkgMatch]...)
		}
	}

	var matchesOrigCase []string
	for _, cp := range matches {
		matchesOrigCase = append(matchesOrigCase, origCPMap[strings.ToLower(cp)]...)
	}

	return matchesOrigCase
}
