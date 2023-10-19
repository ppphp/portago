package dbapi

import (
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/versions"
	"regexp"
	"strings"
)

//nil,1,nil
func dep_expandS[T interfaces.ISettings](myDep string, myDb *dbapi[T], useCache int, settings T) *dep.Atom[T] {
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
	myDepA, err := dep.NewAtom[T](myDep, nil, false, &allowRepo, nil, "", nil, nil)
	if err != nil {
		//except InvalidAtom:
		if !dep.IsValidAtom("="+myDep, false, false, true, "", false) {
			//raise
		}
		myDepA, _ = dep.NewAtom[T]("="+myDep, nil, false, &allowRepo, nil, "", nil, nil)
		origDep = "=" + origDep
	}

	if !hasCat {
		myDep = versions.CatSplit(myDepA.Cp)[1]
	}

	if hasCat {
		if strings.HasPrefix(myDepA.Cp, "virtual/") {
			return myDepA
		}
		if len(myDb.cp_list(myDepA.Cp, 1)) > 0 {
			return myDepA
		}
		myDep = myDepA.Cp
	}

	expanded := cpv_expand(myDep, myDb, useCache, settings)
	r := true
	a, _ := dep.NewAtom[T](strings.Replace(myDep, origDep, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}

//nil,1,nil
func Dep_expand[T interfaces.ISettings](myDep *dep.Atom[T], myDb *dbapi[T], useCache int, settings T) *dep.Atom[T] {
	origDep := myDep
	d := myDep.Value
	if !strings.HasPrefix(myDep.Cp, "virtual/") {
		return myDep
	}
	d = myDep.Cp

	expanded := cpv_expand(d, myDb, useCache, settings)
	r := true
	a, _ := dep.NewAtom[T](strings.Replace(d, origDep.Value, expanded, 1), nil, false, &r, nil, "", nil, nil)
	return a
}
