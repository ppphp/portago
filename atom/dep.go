package atom

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	slotSeparator = ":"
	slotLoose     = "([\\w+./*=-]+)"
	use           = "\\[.*\\]"
	op            = "([=~]|[><]=?)"
	repoSeparator = "::"
	repoName      = "[\\w][\\w-]*"
	repo          = "(?:" + repoSeparator + "(" + repoName + ")" + ")?"
	extendedCat   = "[\\w+*][\\w+.*-]*"
)

var (
	repoNameRe          = regexp.MustCompile("^" + repoName + "$")
	slotDepReCache      = map[bool]*regexp.Regexp{}
	atomReCache         = map[bool]*regexp.Regexp{}
	atomWildcardReCache = map[bool]*regexp.Regexp{}
	usedepReCache       = map[bool]*regexp.Regexp{}
	useflagReCache      = map[bool]*regexp.Regexp{}
)

func getSlotDepRe(attrs eapiAttrs) *regexp.Regexp {
	cacheKey := attrs.SlotOperator
	slotRe, ok := slotDepReCache[cacheKey]
	if ok {
		return slotRe
	}
	s := ""
	if attrs.SlotOperator {
		s = slot + "?(\\*|=|/" + slot + "=?)?"
	} else {
		s = slot
	}
	slotRe = regexp.MustCompile("^" + s + "$")
	slotDepReCache[cacheKey] = slotRe
	return slotRe
}

func getAtomRe(attrs eapiAttrs) *regexp.Regexp {
	cacheKey := attrs.DotsInPn
	atomRe, ok := atomReCache[cacheKey]
	if ok {
		return atomRe
	}
	cps := ""
	cpvs := ""
	if attrs.DotsInPn {
		cps = cp["dots_allowed_in_PN"]
		cpvs = cpv["dots_allowed_in_PN"]
	} else {
		cps = cp["dots_disallowed_in_PN"]
		cpvs = cpv["dots_disallowed_in_PN"]
	}
	atomRe = regexp.MustCompile("^(?P<without_use>(?:" +
		"(?P<op>" + op + cpvs + ")|" +
		"(?P<star>=" + cpvs + "\\*)|" +
		"(?P<simple>" + cps + "))" +
		"(" + slotSeparator + slotLoose + ")?" +
		repo + ")(" + use + ")?$")
	atomReCache[cacheKey] = atomRe
	return atomRe
}
func getAtomWildcardRe(attrs eapiAttrs) *regexp.Regexp {
	cacheKey := attrs.DotsInPn
	atomRe, ok := atomWildcardReCache[cacheKey]
	if ok {
		return atomRe
	}
	s := ""
	if attrs.DotsInPn {
		s = "[\\w+*][\\w+.*-]*?"
	} else {
		s = "[\\w+*][\\w+*-]*?"
	}
	atomRe = regexp.MustCompile("((?P<simple>(" +
		extendedCat + ")/(" + s + "(-" + vr + ")?))" +
		"|(?P<star>=((" + extendedCat + ")/(" + s + "))-(?P<version>\\*\\w+\\*)))" +
		"(:(?P<slot>" + slotLoose + "))?(" +
		repoSeparator + "(?P<repo>" + repoName + "))?$")
	atomWildcardReCache[cacheKey] = atomRe
	return atomRe
}

func getUsedepRe(attrs eapiAttrs) *regexp.Regexp {
	cacheKey := attrs.dotsInUseFlags
	useDepRe, ok := usedepReCache[cacheKey]
	if ok {
		return useDepRe
	}
	s := ""
	if attrs.dotsInUseFlags {
		s = "[A-Za-z0-9][A-Za-z0-9+_@.-]*"
	} else {
		s = "[A-Za-z0-9][A-Za-z0-9+_@-]*"
	}
	useDepRe = regexp.MustCompile("^(?P<prefix>[!-]?)(?P<flag>" +
		s + ")(?P<default>(\\(\\+\\)|\\(\\-\\))?)(?P<suffix>[?=]?)$")
	usedepReCache[cacheKey] = useDepRe
	return useDepRe
}

func getUseflagRe(eapi string) *regexp.Regexp {
	attrs := getEapiAttrs(eapi)
	cacheKey := attrs.dotsInUseFlags
	useflagRe, ok := useflagReCache[cacheKey]
	if ok {
		return useflagRe
	}
	s := ""
	if attrs.dotsInUseFlags {
		s = "[A-Za-z0-9][A-Za-z0-9+_@.-]*"
	} else {
		s = "[A-Za-z0-9][A-Za-z0-9+_@-]*"
	}
	useflagRe = regexp.MustCompile("^" + s + "$")
	useflagReCache[cacheKey] = useflagRe
	return useflagRe
}

func cpvequal(cpv1, cpv2 string) bool {
	c1 := NewPkgStr(cpv1, nil, nil, "", "", "", "", "", "", "", "")
	split1 := c1.cpv_split
	c2 := NewPkgStr(cpv2, nil, nil, "", "", "", "", "", "", "", "")
	split2 := c2.cpv_split
	if split1[0] != split2[0] || split1[1] != split2[1] {
		return false
	}
	v, _ := verCmp(cpv1, cpv2)
	return v == 0
}

func parenEnclose(myList [][]string, unevaluatedAtom, opconvert bool) string {
	myStrParts := []string{}
	for _, x := range myList {
		if opconvert && len(x) > 0 && x[0] != "||" {
			myStrParts = append(myStrParts, fmt.Sprintf("%s ( %s )"), x[0], parenEncloses(x[1:], false, false))
		} else {
			myStrParts = append(myStrParts, fmt.Sprintf("( %s )", parenEncloses(x, false, false)))
		}
	}
	return strings.Join(myStrParts, " ")
}

func parenEncloses(myList []string, unevaluatedAtom, opconvert bool) string {
	myStrParts := []string{}
	for _, x := range myList {
		myStrParts = append(myStrParts, x)
	}
	return strings.Join(myStrParts, " ")
}

type overlap struct {
	forbid bool
}

func newOverlap(forbid bool) *overlap {
	return &overlap{forbid: forbid}
}

type blocker struct {
	overlap *overlap
}

func newBlocker(forbidOverlap bool) *blocker {
	return &blocker{overlap: newOverlap(forbidOverlap)}
}

type atom struct {
	valueDict         map[string]string
	ispackage, soname bool
	blocker           *blocker
}

func NewAtom(s string, unevaluatedAtom string, allowWildcard bool, allowRepo *bool, use, eapi string, isValidFlag, allowBuildId *bool) (*atom, error) {
	a := &atom{}
	eapiAttrs := getEapiAttrs(eapi)
	atomRe := getAtomRe(eapiAttrs)
	a.valueDict["eapi"] = eapi
	if eapi != "" {
		allowRepo = &eapiAttrs.repoDeps
	} else {
		if allowRepo == nil {
			allowRepo = new(bool)
			*allowRepo = true
		}
		if allowBuildId == nil {
			allowBuildId = new(bool)
			*allowBuildId = true

		}
	}
	blockerPrefix := ""
	blocker := &blocker{}
	if "!" == s[:1] {
		blocker = newBlocker("!" == s[1:2])
		if blocker.overlap.forbid {
			blockerPrefix = s[:2]
			s = s[:2]
		} else {
			blockerPrefix = s[:1]
			s = s[:1]
		}
	} else {
		blocker = nil
	}
	a.blocker = blocker
	buildId := 0
	extendedSyntax := false
	extendedVersion := ""
	m := atomRe.FindAllString(s, -1)
	op, base, cp, cpv, slot, repo, useStr := "", 0, "", "", "", "", ""
	if !atomRe.MatchString(s) {
		if allowWildcard {
			atomRe := getAtomWildcardRe(eapiAttrs)
			if !atomRe.MatchString(s) {
				return nil, errors.New("InvalidAtom") // InvalidAtom(self)
			}
			if getNamedRegexp(atomRe, s, "star") != "" {
				op = "=*"
				ar := atomRe.SubexpNames()
				base := 0
				for k, v := range ar {
					if v == "star" {
						base = k
					}
				}
				cp = atomRe.FindAllString(s, -1)[base+1]
				cpv = getNamedRegexp(atomRe, s, "star")[1:]
				extendedVersion = atomRe.FindAllString(s, -1)[base+4]
			} else {
				op = ""
				cp = getNamedRegexp(atomRe, s, "simple")
				cpv = cp
				if len(atomRe.FindAllString(s, -1)) >= 4 {
					return nil, errors.New("InvalidAtom")
				}
			}
			if !strings.Contains(cpv, "**") {
				return nil, errors.New("InvalidAtom")
			}
			slot = getNamedRegexp(atomRe, s, "slot")
			repo = getNamedRegexp(atomRe, s, "repo")
			useStr = ""
			extendedSyntax = true
		} else {
			return nil, errors.New("InvalidAtom")
		}
	} else if getNamedRegexp(atomRe, s, "op") != "" {
		base := 0
		ar := atomRe.SubexpNames()
		for k, v := range ar {
			if v == "op" {
				base = k
			}
		}
		op = atomRe.FindAllString(s, -1)[base+1]
		cpv = atomRe.FindAllString(s, -1)[base+2]
		cp = atomRe.FindAllString(s, -1)[base+3]
		slot = atomRe.FindAllString(s, -1)[base-2]
		repo = atomRe.FindAllString(s, -1)[base-1]
		useStr = atomRe.FindAllString(s, -1)[len(atomRe.SubexpNames())]
		version := atomRe.FindAllString(s, -1)[base+4]
		if version != "" {
			if *allowBuildId {
				cpvBuildId := cpv
				cpv = cp
				cp = cp[:len(cp)-len(version)]
				bid := cpvBuildId[len(cpv)+1:]
				if len(bid) > 1 && bid[:1] == "0" {
					return nil, errors.New("InvalidAtom")
				}
				buildId, _ = strconv.Atoi(bid)
			} else {
				return nil, errors.New("InvalidAtom")
			}
		}
	} else if getNamedRegexp(atomRe, s, "star") != "" {
		base := 0
		ar := atomRe.SubexpNames()
		for k, v := range ar {
			if v == "star" {
				base = k
			}
		}
		op = "=*"
		cpv = atomRe.FindAllString(s, -1)[base+1]
		cp = atomRe.FindAllString(s, -1)[base+2]
		slot = atomRe.FindAllString(s, -1)[len(atomRe.SubexpNames())-2]
		repo = atomRe.FindAllString(s, -1)[len(atomRe.SubexpNames())-1]
		useStr = atomRe.FindAllString(s, -1)[len(atomRe.SubexpNames())]
		if len(atomRe.FindAllString(s, -1)) >= base+3 {
			return nil, errors.New("InvalidAtom")
		}
	} else if getNamedRegexp(atomRe, s, "simple") != "" {
		op = ""
		base := 0
		ar := atomRe.SubexpNames()
		for k, v := range ar {
			if v == "simple" {
				base = k
			}
		}
		cp = atomRe.FindAllString(s, -1)[base+1]
		cpv = cp
		slot = atomRe.FindAllString(s, -1)[len(atomRe.SubexpNames())-2]
		repo = atomRe.FindAllString(s, -1)[len(atomRe.SubexpNames())-1]
		useStr = atomRe.FindAllString(s, -1)[len(atomRe.SubexpNames())]
		if len(atomRe.FindAllString(s, -1)) >= base+2 {
			return nil, errors.New("InvalidAtom")
		}

	} else {
		return nil, fmt.Errorf("required group not found in atom: '%s'", a)
	}
	a.valueDict["cp"] = cp
	a.valueDict["cpv"] = cpv
	a.valueDict["cp"] = extendedVersion
	a.valueDict["repo"] = repo
	return a, nil
}
