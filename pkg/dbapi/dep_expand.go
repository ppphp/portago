package dbapi

import (
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/ebuild"
	"github.com/ppphp/portago/pkg/versions"
	"regexp"
	"strings"
)

//nil,1,nil
func dep_expandS(myDep string, myDb *dbapi, useCache int, settings *ebuild.Config) *dep.Atom {
	origDep := myDep
	if myDep == "" {
		return nil
	}
	if myDep[0] == '*' {
		myDep = myDep[1:]
		origDep = myDep
	}
	hasCat := strings.Contains(strings.Split(origDep, ":")[0], "/")
	if !hasCat {
		re := regexp.MustCompile("\\w")
		alphanum := re.FindStringSubmatchIndex(origDep)
		if len(alphanum) > 0 {
			myDep = origDep[:alphanum[0]] + "null/" + origDep[alphanum[0]:]
		}
	}
	allowRepo := true
	myDepA, err := dep.NewAtom(myDep, nil, false, &allowRepo, nil, "", nil, nil)
	if err != nil {
		//except InvalidAtom:
		if !dep.IsValidAtom("="+myDep, false, false, true, "", false) {
			//raise
		}
		myDepA, _ = dep.NewAtom("="+myDep, nil, false, &allowRepo, nil, "", nil, nil)
		origDep = "=" + origDep
	}

	if !hasCat {
		myDep = versions.CatSplit(myDepA.cp)[1]
	}

	if hasCat {
		if strings.HasPrefix(myDepA.cp, "virtual/") {
			return myDepA
		}
		if len(myDb.cp_list(myDepA.cp, 1)) > 0 {
			return myDepA
		}
		myDep = myDepA.cp
	}

	expanded := cpv_expand(myDep, myDb, useCache, settings)
	r := true
	a, _ := dep.NewAtom(strings.Replace(myDep, origDep, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}

//nil,1,nil
func Dep_expand(myDep *dep.Atom, myDb *dbapi, useCache int, settings *ebuild.Config) *dep.Atom {
	origDep := myDep
	d := myDep.value
	if !strings.HasPrefix(myDep.cp, "virtual/") {
		return myDep
	}
	d = myDep.cp

	expanded := cpv_expand(d, myDb, useCache, settings)
	r := true
	a, _ := dep.NewAtom(strings.Replace(d, origDep.value, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}
