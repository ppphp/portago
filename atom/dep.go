package atom

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
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

func inSliceS(str string, slice []string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func parenEncloses(myList []string, unevaluatedAtom, opconvert bool) string {
	myStrParts := []string{}
	for _, x := range myList {
		//if unevaluated_atom: // TODO
		//    x = getattr(x, 'unevaluated_atom', x)
		myStrParts = append(myStrParts, x)
	}
	return strings.Join(myStrParts, " ")
}

func isActive(conditional string, uselist, masklist []string, matchall bool, excludeall []string, is_src_uri bool, eapi string, opconvert, flat bool, isValidFlag func(string) bool, tokenClass func(string) *atom, matchnone bool, useFlagRe *regexp.Regexp) bool {
	flag := ""
	isNegated := false
	if strings.HasPrefix(conditional, "!") {
		flag = conditional[1 : len(conditional)-1]
		isNegated = true
	} else {
		flag = conditional[:len(conditional)-1]
		isNegated = false
	}
	if isValidFlag != nil {
		if !isValidFlag(flag) {
			//e = InvalidData(msg, category='IUSE.missing') // TODO
			//raise InvalidDependString(msg, errors=(e,))
		}
	} else {
		if !useFlagRe.MatchString(flag) {
			//raise InvalidDependString(
			//	_("invalid use flag '%s' in conditional '%s'") % (flag, conditional))
		}
	}

	if isNegated && inSliceS(flag, excludeall) {
		return false
	}
	if inSliceS(flag, masklist) {
		return false
	}
	if matchall {
		return true
	}
	if matchnone {
		return false
	}
	return (inSliceS(flag, uselist) && !isNegated) || (!inSliceS(flag, uselist) && isNegated)
}

func missingWhiteSpaceCheck(token string, pos int) error {
	for _, x := range []string{")", "(", "||"} {
		if strings.HasPrefix(token, x) || strings.HasSuffix(token, x) {
			return fmt.Errorf("missing whitespace around '%s' at '%s', token %s", x, token, pos+1)
		}
	}
	return nil
}

func useReduce(depstr string, uselist, masklist []string, matchall bool, excludeall []string, isSrcUri bool, eapi string, opconvert, flat bool, isValidFlag func(string) bool, tokenClass func(string) *atom, matchnone bool) []string {
	if opconvert && flat {
		// ValueError("portage.dep.use_reduce: 'opconvert' and 'flat' are mutually exclusive")
	}
	if matchall && matchnone {
		// ValueError("portage.dep.use_reduce: 'opconvert' and 'flat' are mutually exclusive")
	}
	eapiAttrs := getEapiAttrs(eapi)
	useFlagRe := getUseflagRe(eapi)
	mySplit := strings.Fields(depstr)
	level := 0
	stack := [][]string{}
	needBracket := false
	needSimpleToken := false
	for pos, token := range mySplit {
		if token == "(" {
			if needSimpleToken {
				//raise InvalidDependString(
				//	_("expected: file name, got: '%s', token %s") % (token, pos+1))
			}
			if len(mySplit) >= pos+2 && mySplit[pos+1] == ")" {
				//raise InvalidDependString(
				//	_("expected: dependency string, got: ')', token %s") % (pos+1,))
			}
			needBracket = false
			stack = append(stack, []string{})
			level += 1
		} else if token == "(" {
			if needBracket {
				//raise InvalidDependString(
				//	_("expected: '(', got: '%s', token %s") % (token, pos+1))
			}
			if needSimpleToken {
				//raise InvalidDependString(
				//	_("expected: file name, got: '%s', token %s") % (token, pos+1))
			}
			if level > 0 {
				level -= 1
				l := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				isSingle := len(l) == 1 || (opconvert && len(l) != 0 && l[0] == "||") || (!opconvert && len(l) == 2 && l[0] == "||")
				ignore := false
				if flat {
					if len(stack[level]) != 0 && strings.HasSuffix(stack[level][len(stack[level])-1], "?") {
						if isActive(stack[level][len(stack[level])-1], uselist, masklist, matchall, excludeall, isSrcUri, eapi, opconvert, flat, isValidFlag, tokenClass, matchnone, useFlagRe) {
							stack[level] = stack[level][:len(stack[level])-1]
							stack[level] = append(stack[level], l...)
						} else {
							stack[level] = stack[level][:len(stack[level])-1]
						}
					} else {
						stack[level] = append(stack[level], l...)
					}
					continue
				}
				if len(stack[level]) != 0 {
					if stack[level][len(stack[level])-1] == "||" && len(l) != 0 {
						if !eapiAttrs.emptyGroupsAlwaysTrue {
							l = append(l, "__const__/empty-any-of")
						}
						stack[level] = stack[level][:len(stack[level])-1]
					} else if strings.HasSuffix(stack[level][len(stack[level])-1], "?") {
						if !isActive(stack[level][len(stack[level])-1], uselist, masklist, matchall, excludeall, isSrcUri, eapi, opconvert, flat, isValidFlag, tokenClass, matchnone, useFlagRe) {
							ignore = true
						}
						stack[level] = stack[level][:len(stack[level])-1]
					}
				}
				endsInAnyOfDep := func(k int) bool { return k >= 0 && len(stack) != 0 && stack[level][len(stack[level])-1] == "||" }
				//lastAnyOfOperatorLevel := func(k int) int {
				//	for k >= 0 {
				//		if len(stack[k]) > 0 && stack[k][len(stack[k])-1] != "" {
				//			if stack[k][len(stack[k])-1] == "||" {
				//				return k
				//			} else if !strings.HasSuffix(stack[k][len(stack[k])-1], "?") {
				//				return -1
				//			}
				//		}
				//	}
				//	return -1
				//}
				specialAppend := func() {
					if isSingle {
						if l[0] == "||" && endsInAnyOfDep(level-1) {
							if opconvert {
								stack[level] = append(stack[level], l[1:]...)
							} else {
								stack[level] = append(stack[level], l[1])
							}
						} else {
							stack[level] = append(stack[level], l[0])
						}
					} else {
						//if opconvert && len(stack[level])!=0 && stack[level][len(stack[level] )-1]== "||" { //TODO check?
						//	stack[level][len(stack[level] )-1] = "||"+l
						//}
					}
				}
				if len(l) != 0 && !ignore {
					if !endsInAnyOfDep(level - 1) && !endsInAnyOfDep(level) {
						stack[level] = append(stack[level], l...)
					} else if len(stack[level]) == 0 {
						specialAppend()
					} else if isSingle && endsInAnyOfDep(level) {
						stack[level] = stack[level][:len(stack[level])-1]
						specialAppend()
					} else if endsInAnyOfDep(level) && endsInAnyOfDep(level-1) {
						stack[level] = stack[level][:len(stack[level])-1]
						stack[level] = append(stack[level], l...)
					} else {
						if opconvert && endsInAnyOfDep(level) {
							stack[level] = append(stack[level], "||")
							stack[level] = append(stack[level], l...)
						} else {
							specialAppend()
						}
					}
				}
			} else {
				//raise InvalidDependString( // TODO
				//	_("no matching '%s' for '%s', token %s") % ("(", ")", pos+1))
			}
		} else if token == "||" {
			if isSrcUri {
				//raise InvalidDependString(
				//	_("any-of dependencies are not allowed in SRC_URI: token %s") % (pos+1,))
			}
			if needBracket {
				//raise InvalidDependString(
				//_("expected: '(', got: '%s', token %s") % (token, pos+1))
			}
			needBracket = true
			stack[level] = append(stack[level], token)
		} else if token == "->" {
			if needSimpleToken {
				//raise InvalidDependString(
				//	_("expected: file name, got: '%s', token %s") % (token, pos+1))
			}
			if !isSrcUri {
				//raise InvalidDependString(
				//	_("SRC_URI arrow are only allowed in SRC_URI: token %s") % (pos+1,))
			}
			if !eapiAttrs.srcUriArrows {
				//raise InvalidDependString(
				//	_("SRC_URI arrow not allowed in EAPI %s: token %s") % (eapi, pos+1))
			}
			needSimpleToken = true
			stack[level] = append(stack[level], token)
		} else {
			if needBracket {
				//raise InvalidDependString(
				//	_("expected: '(', got: '%s', token %s") % (token, pos+1))
			}
			if needSimpleToken && strings.Contains(token, "/") {
				//raise InvalidDependString(
				//	_("expected: file name, got: '%s', token %s") % (token, pos+1))
			}
			if strings.HasSuffix(token, "?") {
				needBracket = true
			} else {
				needBracket = false
				if tokenClass != nil && !isSrcUri {
					//token = tokenClass()// TODO
					t := tokenClass(token)
					if !matchall {
						token = t.evaluateConditionals(uselist)
					}
				}
			}
			stack[level] = append(stack[level], token)
		}
	}
	if level != 0 {
		//raise InvalidDependString(
		//	_("Missing '%s' at end of string") % (")",))
	}

	if needBracket {
		//raise InvalidDependString(
		//	_("Missing '%s' at end of string") % ("(",))
	}

	if needSimpleToken {
		//raise InvalidDependString(
		//	_("Missing file name at end of string"))
	}
	return stack[0]
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

func (a *atom) evaluateConditionals(use []string) *atom {
	return nil
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

func extractAffectingUse(mystr string, atom *atom, eapi string) map[string]bool{
	useflagRe := getUseflagRe(eapi)
	mySplit := strings.Fields(mystr)
	level := 0
	stack := [][]string{}
	needBracket := false
	affectingUse := map[string]bool{}
	flag := func(conditional string)string{
		flag := ""
		if strings.HasPrefix(conditional, "!") {
			flag = conditional[1:len(conditional)-1]
		} else {
			flag = conditional[:len(conditional)-1]
		}
		if !useflagRe.MatchString(flag){
			//raise InvalidDependString(
			//	_("invalid use flag '%s' in conditional '%s'") % \
			//(flag, conditional))
		}
		return flag
	}
	for _, token := range mySplit {
		if token =="(" {
			needBracket = false
			stack = append(stack, []string{})
			level += 1
		}else if token ==")" {
			if needBracket {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % mystr)
			}
			if level>0{
				level-=1
				l := stack[len(stack)-1]
				stack=stack[:len(stack)-1]
				//isSingle := (len(l) == 1 ||(len(l) == 2 &&(l[0] == "||"||strings.HasSuffix(l[0], "?"))))

				endsInAnyOfDep := func(k int) bool { return k >= 0 && len(stack) != 0 && stack[level][len(stack[level])-1] == "||" }
				endsInOperator := func(k int) bool {return k >= 0 && len(stack) != 0 && (stack[level][len(stack[level])-1] == "||" || strings.HasSuffix(stack[level][len(stack[level])-1], "?")) }
				specialAppend := func() {
							stack[level] = append(stack[level], l[0])
				}
				if len(l)!= 0 {
					if !endsInAnyOfDep(level-1) && !endsInOperator(level) {
						stack[level] = append(stack[level], l...)
					} else if len(stack[level]) ==0{
						specialAppend()
					} else if len(stack[level]) == 1 && endsInAnyOfDep(level) {
						stack=stack[:len(stack)-1]
						specialAppend()
						if strings.HasSuffix(l[0], "?") {
							affectingUse[flag(l[0])] = true
						}
					} else{
						if len(stack[level]) != 0 && (stack[level][len(stack[level])-1] == "||"|| strings.HasSuffix(stack[level][len(stack[level])-1], "?")){
							stack=stack[:len(stack)-1]
						}
						specialAppend()
					}
				} else {
					if len(stack[level]) != 0 && (stack[level][len(stack[level])-1] == "||"|| strings.HasSuffix(stack[level][len(stack[level])-1], "?")){
						stack=stack[:len(stack)-1]
					}
				}
			} else {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % mystr)
			}
		} else if token == "||"{
			if needBracket {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % mystr)
			}
			needBracket = true
			stack[level] = append(stack[level], token)
		} else {
			if needBracket {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % mystr)
			}
			if strings.HasSuffix(token, "?") {
				needBracket = true
				stack[level] = append(stack[level], token)
			}
			//else if token == atom
			//	stack[level].append(token)
		}
	}
	if level != 0 && needBracket {
		//raise InvalidDependString(
		//	_("malformed syntax: '%s'") % mystr)
	}
	return affectingUse
}

func extractUnpackDependencies(srcUri string, unpackers map[string]string) string {
	srcUris := strings.Fields(srcUri)
	depend := []string{}
	for i := range srcUris {
		if strings.HasSuffix(srcUris[i], "?") || srcUris[i] == "(" || srcUris[i] == ")" {
			depend = append(depend, srcUris[i])
		} else if (i+1 < len(srcUris) && srcUris[i+1] == "->") || srcUris[i] == "->"{
			continue
		} else {
			keys := []string{}
			for k := range unpackers {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, suffix := range keys {
				suffix = strings.ToLower(suffix)
				if strings.HasSuffix(strings.ToLower(srcUris[i]), suffix){
					depend = append(depend, unpackers[suffix])
				}
				break
			}
		}
	}
	for {
		cleanedDepend := CopySliceS(depend)
		for i := range cleanedDepend {
			if cleanedDepend[i] == "" {
				continue
			} else if cleanedDepend[i] == "(" && cleanedDepend[i+1] == ")" {
				cleanedDepend[i] = ""
				cleanedDepend[i+1] = ""
			} else if strings.HasSuffix(cleanedDepend[i], "?") &&cleanedDepend[i+1] == "(" && cleanedDepend[i+2] == ")"{
				cleanedDepend[i] = ""
				cleanedDepend[i+1] = ""
				cleanedDepend[i+2] = ""
			}
		}
		if reflect.DeepEqual(cleanedDepend, depend) {
			break
		} else {
			depend = []string{}
			for _, x := range cleanedDepend {
				depend = append(depend, x)
			}
		}
	}
	return strings.Join(depend, " ")
}

func isValidAtom(atom string, allow_blockers, allowWildcard, allowRepo bool, eapi string, allowBuildId bool)bool{ //false, false, false, none, false
	a, err := NewAtom(atom, "", allowWildcard, &allowRepo, "",eapi, nil, &allowBuildId)
	if err != nil {
		return false
	}
	if !allow_blockers &&a.blocker!= nil{
		return false
	}
	return true
}
