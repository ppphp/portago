package atom

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
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
	c1 := NewPkgStr(cpv1, nil, nil, "", "", "", 0, "", "", 0, "")
	split1 := c1.cpvSplit
	c2 := NewPkgStr(cpv2, nil, nil, "", "", "", 0, "", "", 0, "")
	split2 := c2.cpvSplit
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

func matchSlot(atom *Atom, pkg *pkgStr) bool {
	if pkg.slot == atom.slot {
		if atom.subSlot == "" {
			return true
		} else if atom.subSlot == pkg.subSlot {
			return true
		}
	}
	return false
}

func useReduce(depstr string, uselist map[string]bool, masklist []string, matchall bool, excludeall []string, isSrcUri bool, eapi string, opconvert, flat bool, isValidFlag func(string) bool, tokenClass func(string) *Atom, matchnone bool) []string { // map[string]bool{}, []string{}, false, []string{}, false, "", false, false, nil, nil, false
	if opconvert && flat {
		// ValueError("portage.dep.use_reduce: 'opconvert' and 'flat' are mutually exclusive")
	}
	if matchall && matchnone {
		// ValueError("portage.dep.use_reduce: 'opconvert' and 'flat' are mutually exclusive")
	}
	eapiAttrs := getEapiAttrs(eapi)
	useFlagRe := getUseflagRe(eapi)

	isActive := func(conditional string) bool {
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
		return (uselist[flag] && !isNegated) || (!uselist[flag] && isNegated)
	}

	//missingWhiteSpaceCheck := func(token string, pos int) error {
	//	for _, x := range []string{")", "(", "||"} {
	//		if strings.HasPrefix(token, x) || strings.HasSuffix(token, x) {
	//			return fmt.Errorf("missing whitespace around '%s' at '%s', token %v", x, token, pos+1)
	//		}
	//	}
	//	return nil
	//}

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
						if isActive(stack[level][len(stack[level])-1]) {
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
						if !isActive(stack[level][len(stack[level])-1]) {
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
					if !endsInAnyOfDep(level-1) && !endsInAnyOfDep(level) {
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
						token = t.EvaluateConditionals(uselist).value
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

type conditionalClass struct {
	enabled, disabled, equal, notEqual map[string]bool
}

type SMSB struct {
	S   string
	MSB map[string]bool
}

func (c *conditionalClass) items() []SMSB {
	r := []SMSB{}
	if c.enabled != nil {
		r = append(r, SMSB{"enabled", c.enabled})
	}
	if c.disabled != nil {
		r = append(r, SMSB{"disabled", c.disabled})
	}
	if c.equal != nil {
		r = append(r, SMSB{"equal", c.equal})
	}
	if c.notEqual != nil {
		r = append(r, SMSB{"not_equal", c.notEqual})
	}
	return r
}

func (c *conditionalClass) values() []map[string]bool {
	r := []map[string]bool{}
	if c.enabled != nil {
		r = append(r, c.enabled)
	}
	if c.disabled != nil {
		r = append(r, c.disabled)
	}
	if c.equal != nil {
		r = append(r, c.equal)
	}
	if c.notEqual != nil {
		r = append(r, c.notEqual)
	}
	return r
}

func NewConditionalClass() *conditionalClass {
	return &conditionalClass{}
}

var conditionalStrings = map[string]string{
	"enabled":   "%s?",
	"disabled":  "!%s?",
	"equal":     "%s=",
	"not_equal": "!%s=",
}

type useDep struct {
	eapiAttrs                                                    *eapiAttrs
	missingEnabled, missingDisabled, disabled, enabled, required map[string]bool
	conditional                                                  *conditionalClass
	tokens                                                       []string
	conditionalStrings                                           map[string]string
}

func (u *useDep) evaluateConditionals(use map[string]bool) *useDep {
	enabledFlags := CopyMapSB(u.enabled)
	disabledFlags := CopyMapSB(u.disabled)
	tokens := []string{}
	usedepRe := getUsedepRe(*u.eapiAttrs)
	for _, x := range u.tokens {
		operator := getNamedRegexp(usedepRe, x, "prefix") + getNamedRegexp(usedepRe, x, "suffix")
		flag := getNamedRegexp(usedepRe, x, "flag")
		defaults := getNamedRegexp(usedepRe, x, "default")
		if operator == "?" {
			enabledFlags[flag] = true
			tokens = append(tokens, flag+defaults)
		} else if operator == "=" {
			if use[flag] {
				enabledFlags[flag] = true
				tokens = append(tokens, flag+defaults)
			} else {
				disabledFlags[flag] = true
				tokens = append(tokens, "-"+flag+defaults)
			}
		} else if operator == "!=" {
			if use[flag] {
				disabledFlags[flag] = true
				tokens = append(tokens, "-"+flag+defaults)
			} else {
				enabledFlags[flag] = true
				tokens = append(tokens, flag+defaults)
			}
		} else if operator == "!?" {
			if !use[flag] {
				disabledFlags[flag] = true
				tokens = append(tokens, "-"+flag+defaults)
			}
		} else {
			tokens = append(tokens, x)
		}
	}
	return NewUseDep(tokens, u.eapiAttrs, enabledFlags, disabledFlags, u.missingEnabled, u.missingDisabled, nil, u.required)
}

func (u *useDep) violatedConditionals(otherUse map[string]bool, isValidFlag func(string) bool, parentUse map[string]bool) *useDep {
	if parentUse == nil && u.conditional != nil {
		//raise InvalidAtom("violated_conditionals needs 'parent_use'" + \
		//" parameter for conditional flags.")
	}
	enabledFlags := CopyMapSB(u.enabled)
	disabledFlags := CopyMapSB(u.disabled)
	conditional := map[string]map[string]bool{}
	tokens := []string{}
	allDefaults := map[string]bool{}
	for x := range u.missingEnabled {
		allDefaults[x] = true
	}
	for x := range u.missingDisabled {
		allDefaults[x] = true
	}
	validateFlag := func(flag string) bool {
		return isValidFlag(flag) || allDefaults[flag]
	}

	usedepRe := getUsedepRe(*u.eapiAttrs)
	for _, x := range u.tokens {
		operator := getNamedRegexp(usedepRe, x, "prefix") + getNamedRegexp(usedepRe, x, "suffix")
		flag := getNamedRegexp(usedepRe, x, "flag")
		if !validateFlag(flag) {
			tokens = append(tokens, flag)
			if operator == "" {
				enabledFlags[flag] = true
			} else if operator == "-" {
				disabledFlags[flag] = true
			} else if operator == "?" {
				if conditional["enabled"] == nil {
					conditional["enabled"] = map[string]bool{flag: true}
				} else {
					conditional["enabled"][flag] = true
				}
			} else if operator == "=" {
				if conditional["equal"] == nil {
					conditional["equal"] = map[string]bool{flag: true}
				} else {
					conditional["equal"][flag] = true
				}
			} else if operator == "!=" {
				if conditional["not_equal"] == nil {
					conditional["not_equal"] = map[string]bool{flag: true}
				} else {
					conditional["not_equal"][flag] = true
				}
			} else if operator == "!?" {
				if conditional["disabled"] == nil {
					conditional["disabled"] = map[string]bool{flag: true}
				} else {
					conditional["disabled"][flag] = true
				}
			}
			continue
		}
		if operator == "" {
			if !otherUse[flag] {
				if isValidFlag(flag) || u.missingDisabled[flag] {
					tokens = append(tokens, x)
					enabledFlags[flag] = true
				}
			}
		} else if operator == "-" {
			if !otherUse[flag] {
				if !isValidFlag(flag) {
					if u.missingEnabled[flag] {
						tokens = append(tokens, x)
						disabledFlags[flag] = true
					}
				}
			} else {
				tokens = append(tokens, x)
				disabledFlags[flag] = true
			}
		} else if operator == "?" {
			if !parentUse[flag] || otherUse[flag] {
				continue
			}
			if isValidFlag(flag) || u.missingDisabled[flag] {
				tokens = append(tokens, x)
				if conditional["enabled"] == nil {
					conditional["enabled"] = map[string]bool{flag: true}
				} else {
					conditional["enabled"][flag] = true
				}
			}
		} else if operator == "=" {
			if parentUse[flag] && !otherUse[flag] {
				if isValidFlag(flag) {
					tokens = append(tokens, x)
					if conditional["equal"] == nil {
						conditional["equal"] = map[string]bool{flag: true}
					} else {
						conditional["equal"][flag] = true
					}
				} else {
					if u.missingDisabled[flag] {
						tokens = append(tokens, x)
						if conditional["equal"] == nil {
							conditional["equal"] = map[string]bool{flag: true}
						} else {
							conditional["equal"][flag] = true
						}
					}
				}
			} else if !parentUse[flag] {
				if !otherUse[flag] {
					if !isValidFlag(flag) {
						if u.missingEnabled[flag] {
							tokens = append(tokens, x)
							if conditional["equal"] == nil {
								conditional["equal"] = map[string]bool{flag: true}
							} else {
								conditional["equal"][flag] = true
							}
						}
					}
				} else {
					tokens = append(tokens, x)
					if conditional["equal"] == nil {
						conditional["equal"] = map[string]bool{flag: true}
					} else {
						conditional["equal"][flag] = true
					}
				}
			}
		} else if operator == "!=" {
			if !parentUse[flag] && !otherUse[flag] {
				if isValidFlag(flag) {
					tokens = append(tokens, x)
					if conditional["not_equal"] == nil {
						conditional["not_equal"] = map[string]bool{flag: true}
					} else {
						conditional["not_equal"][flag] = true
					}
				} else {
					if u.missingDisabled[flag] {
						tokens = append(tokens, x)
						if conditional["not_equal"] == nil {
							conditional["not_equal"] = map[string]bool{flag: true}
						} else {
							conditional["not_equal"][flag] = true
						}
					}
				}
			} else if parentUse[flag] {
				if !otherUse[flag] {
					if !isValidFlag(flag) {
						if u.missingEnabled[flag] {
							tokens = append(tokens, x)
							if conditional["not_equal"] == nil {
								conditional["not_equal"] = map[string]bool{flag: true}
							} else {
								conditional["not_equal"][flag] = true
							}
						}
					}
				} else {
					tokens = append(tokens, x)
					if conditional["not_equal"] == nil {
						conditional["not_equal"] = map[string]bool{flag: true}
					} else {
						conditional["not_equal"][flag] = true
					}
				}
			}
		} else if operator == "!?" {
			if parentUse[flag] {
				if !otherUse[flag] {
					if !isValidFlag(flag) && u.missingEnabled[flag] {
						tokens = append(tokens, x)
						if conditional["disabled"] == nil {
							conditional["disabled"] = map[string]bool{flag: true}
						} else {
							conditional["disabled"][flag] = true
						}
					}
				} else {
					tokens = append(tokens, x)
					if conditional["disabled"] == nil {
						conditional["disabled"] = map[string]bool{flag: true}
					} else {
						conditional["disabled"][flag] = true
					}
				}
			}
		}
	}
	return NewUseDep(tokens, u.eapiAttrs, enabledFlags, disabledFlags, u.missingEnabled, u.missingDisabled, conditional, u.required)
}

func (u *useDep) evalQaConditionals(useMask, useForce map[string]bool) *useDep {
	enabledFlags := CopyMapSB(u.enabled)
	disabledFlags := CopyMapSB(u.disabled)
	tokens := []string{}
	usedepRe := getUsedepRe(*u.eapiAttrs)
	for _, x := range u.tokens {
		operator := getNamedRegexp(usedepRe, x, "prefix") + getNamedRegexp(usedepRe, x, "suffix")
		flag := getNamedRegexp(usedepRe, x, "flag")
		defaults := getNamedRegexp(usedepRe, x, "default")
		if operator == "?" {
			if !useMask[flag] {
				tokens = append(tokens, flag+defaults)
				enabledFlags[flag] = true
			}
		} else if operator == "=" {
			if !useMask[flag] {
				tokens = append(tokens, flag+defaults)
				enabledFlags[flag] = true
			}
			if !useForce[flag] {
				tokens = append(tokens, "-"+flag+defaults)
				disabledFlags[flag] = true
			}
		} else if operator == "!=" {
			if !useForce[flag] {
				tokens = append(tokens, flag+defaults)
				enabledFlags[flag] = true
			}
			if !useMask[flag] {
				tokens = append(tokens, "-"+flag+defaults)
				disabledFlags[flag] = true
			}
		} else if operator == "!?" {
			if !useForce[flag] {
				tokens = append(tokens, "-"+flag+defaults)
				disabledFlags[flag] = true
			}
		} else {
			tokens = append(tokens, x)
		}
	}
	return NewUseDep(tokens, u.eapiAttrs, enabledFlags, disabledFlags, u.missingEnabled, u.missingDisabled, nil, u.required)
}

func NewUseDep(use []string, eapiAttrs *eapiAttrs, enabledFlags, disabledFlags, missingEnabled, missingDisabled map[string]bool, conditional map[string]map[string]bool, required map[string]bool) *useDep { // none
	u := &useDep{conditionalStrings: conditionalStrings}
	u.eapiAttrs = eapiAttrs
	if enabledFlags != nil {
		u.tokens = use
		u.required = required
		u.enabled = enabledFlags
		u.disabled = disabledFlags
		u.missingEnabled = missingEnabled
		u.missingDisabled = missingDisabled
		u.conditional = nil
		if conditional != nil {
			u.conditional = NewConditionalClass()
			if len(conditional["enabled"]) > 0 {
				u.conditional.enabled = conditional["enabled"]
			} else {
				u.conditional.enabled = map[string]bool{}
			}
			if len(conditional["disabled"]) > 0 {
				u.conditional.disabled = conditional["disabled"]
			} else {
				u.conditional.disabled = map[string]bool{}
			}
			if len(conditional["equal"]) > 0 {
				u.conditional.equal = conditional["equal"]
			} else {
				u.conditional.equal = map[string]bool{}
			}
			if len(conditional["not_equal"]) > 0 {
				u.conditional.notEqual = conditional["not_equal"]
			} else {
				u.conditional.notEqual = map[string]bool{}
			}
		}
		return u
	}

	enabledFlags = map[string]bool{}
	disabledFlags = map[string]bool{}
	missingEnabled = map[string]bool{}
	missingDisabled = map[string]bool{}
	noDefault := map[string]bool{}
	conditional = map[string]map[string]bool{}
	usedepRe := getUsedepRe(*u.eapiAttrs)

	for _, x := range use {
		if !usedepRe.MatchString(x) {
			//raise InvalidAtom(_("Invalid use dep: '%s'") % (x,))
		}
		operator := getNamedRegexp(usedepRe, x, "prefix") + getNamedRegexp(usedepRe, x, "suffix")
		flag := getNamedRegexp(usedepRe, x, "flag")
		defaults := getNamedRegexp(usedepRe, x, "default")
		if operator == "" {
			enabledFlags[flag] = true
		} else if operator == "-" {
			disabledFlags[flag] = true
		} else if operator == "?" {
			if len(conditional["enabled"]) == 0 {
				conditional["enabled"] = map[string]bool{flag: true}
			} else {
				conditional["enabled"][flag] = true
			}
		} else if operator == "=" {
			if len(conditional["equal"]) == 0 {
				conditional["equal"] = map[string]bool{flag: true}
			} else {
				conditional["equal"][flag] = true
			}
		} else if operator == "!=" {
			if len(conditional["not_equal"]) == 0 {
				conditional["not_equal"] = map[string]bool{flag: true}
			} else {
				conditional["not_equal"][flag] = true
			}
		} else if operator == "!?" {
			if len(conditional["disabled"]) == 0 {
				conditional["disabled"] = map[string]bool{flag: true}
			} else {
				conditional["disabled"][flag] = true
			}
		} else {
			//raise InvalidAtom(_("Invalid use dep: '%s'") % (x,))
		}
		if len(defaults) != 0 {
			if defaults == "(+)" {
				if missingDisabled[flag] || noDefault[flag] {
					//raise InvalidAtom(_("Invalid use dep: '%s'") % (x,))
				}
				missingEnabled[flag] = true
			} else {
				if missingEnabled[flag] || noDefault[flag] {
					//raise InvalidAtom(_("Invalid use dep: '%s'") % (x,))
				}
				missingDisabled[flag] = true
			}
		} else {
			if missingEnabled[flag] || missingDisabled[flag] {
				//raise InvalidAtom(_("Invalid use dep: '%s'") % (x,))
			}
			noDefault[flag] = true
		}
	}
	u.tokens = use

	u.required = noDefault
	u.enabled = enabledFlags
	u.disabled = disabledFlags
	u.missingEnabled = missingEnabled
	u.missingDisabled = missingDisabled
	u.conditional = nil

	if conditional != nil {
		u.conditional = NewConditionalClass()
		if len(conditional["enabled"]) > 0 {
			u.conditional.enabled = conditional["enabled"]
		} else {
			u.conditional.enabled = map[string]bool{}
		}
		if len(conditional["disabled"]) > 0 {
			u.conditional.disabled = conditional["disabled"]
		} else {
			u.conditional.disabled = map[string]bool{}
		}
		if len(conditional["equal"]) > 0 {
			u.conditional.equal = conditional["equal"]
		} else {
			u.conditional.equal = map[string]bool{}
		}
		if len(conditional["not_equal"]) > 0 {
			u.conditional.notEqual = conditional["not_equal"]
		} else {
			u.conditional.notEqual = map[string]bool{}
		}
	}
	return u
}

func (u *useDep) bool() bool {
	return len(u.tokens) != 0
}

func (u *useDep) str() string {
	if len(u.tokens) == 0 {
		return ""
	}
	return fmt.Sprintf("[%s]", strings.Join(u.tokens, ","))
}

func (u *useDep) repr() string {
	return fmt.Sprintf("portage.dep._use_dep(%s)", u.tokens)
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

type Atom struct {
	value                                                          string
	ispackage, soname, extendedSyntax                              bool
	buildId                                                        int
	blocker                                                        *blocker
	slotOperator, subSlot, repo, slot, eapi, cp, version, operator string
	cpv                                                            *pkgStr
	use                                                            *useDep
	withoutUse, unevaluatedAtom                                    *Atom
}

func (a *Atom) withoutSlot() *Atom {
	if a.slot == "" && a.slotOperator == "" {
		return a
	}
	atom := removeSlot(a.value)
	if a.repo != "" {
		atom += repoSeparator + a.repo
	}
	if a.use != nil {
		atom += a.use.str()
	}
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) withRepo(repo string) *Atom {
	atom := removeSlot(a.value)
	if a.slot != "" || a.slotOperator != "" {
		atom += slotSeparator
		if a.slot != "" {
			atom += a.slot
		}
		if a.subSlot != "" {
			atom += fmt.Sprintf("/%s", a.subSlot)
		}
		if a.slotOperator != "" {
			atom += a.slotOperator
		}
	}
	atom += repoSeparator + repo
	if a.use != nil {
		atom += a.use.str()
	}
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) withSlot(slot string) *Atom {
	atom := removeSlot(a.value) + slotSeparator + slot
	if a.repo != "" {
		atom += repoSeparator + a.repo
	}
	if a.use != nil {
		atom += a.use.str()
	}
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) EvaluateConditionals(use map[string]bool) *Atom {
	if !(a.use != nil && a.use.conditional != nil) {
		return a
	}
	atom := removeSlot(a.value)
	if a.slot != "" || a.slotOperator != "" {
		atom += slotSeparator
		if a.slot != "" {
			atom += a.slot
		}
		if a.subSlot != "" {
			atom += fmt.Sprintf("/%s", a.subSlot)
		}
		if a.slotOperator != "" {
			atom += a.slotOperator
		}
	}
	useDep := a.use.evaluateConditionals(use)
	atom += useDep.str()
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) violatedConditionals(otherUse map[string]bool, isValidFlag func(string) bool, parentUse map[string]bool) *Atom { // none
	if a.use == nil {
		return a
	}
	atom := removeSlot(a.value)
	if a.slot != "" || a.slotOperator != "" {
		atom += slotSeparator
		if a.slot != "" {
			atom += a.slot
		}
		if a.subSlot != "" {
			atom += fmt.Sprintf("/%s", a.subSlot)
		}
		if a.slotOperator != "" {
			atom += a.slotOperator
		}
	}
	useDep := a.use.violatedConditionals(otherUse, isValidFlag, parentUse)
	atom += useDep.str()
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) evalQaConditionals(useMask, useForce map[string]bool) *Atom {
	if a.use == nil || a.use.conditional == nil {
		return a
	}
	atom := removeSlot(a.value)
	if a.slot != "" || a.slotOperator != "" {
		atom += slotSeparator
		if a.slot != "" {
			atom += a.slot
		}
		if a.subSlot != "" {
			atom += fmt.Sprintf("/%s", a.subSlot)
		}
		if a.slotOperator != "" {
			atom += a.slotOperator
		}
	}
	useDep := a.use.evalQaConditionals(useMask, useForce)
	atom += useDep.str()
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) slotOperatorBuilt() bool {
	return a.slotOperator == "=" && a.subSlot != ""
}

func (a *Atom) withoutRepo() *Atom {
	if a.repo == "" {
		return a
	}
	b, _ := NewAtom(strings.Replace(a.value, repoSeparator+a.repo, "", 1), nil, true, nil, nil, "", nil, nil)
	return b
}

func (a *Atom) intersects(other *Atom) bool {
	if a == other {
		return true
	}
	if a.cp != other.cp || a.use != other.use || a.operator != other.operator || a.cpv != other.cpv {
		return false
	}
	if a.slot == "" || other.slot == "" || a.slot == other.slot {
		return true
	}
	return false
}

func (a *Atom) copy() *Atom {
	return a
}

func (a *Atom) deepcopy() *Atom { // memo=None, memo[id(self)] = self
	return a
}

func (a *Atom) match(pkg *pkgStr) bool {
	return len(matchFromList(a, []*pkgStr{pkg})) > 0
}

func NewAtom(s string, unevaluatedAtom *Atom, allowWildcard bool, allowRepo *bool, _use *useDep, eapi string, isValidFlag func(string) bool, allowBuildId *bool) (*Atom, error) { //s, nil, false, nil, nil, "", nil, nil
	a := &Atom{value: s, ispackage: true, soname: false}
	eapiAttrs := getEapiAttrs(eapi)
	atomRe := getAtomRe(eapiAttrs)
	a.eapi = eapi
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
	op, cp, cpv, slot, repo, useStr := "", "", "", "", "", ""
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
		return nil, fmt.Errorf("required group not found in Atom: '%v'", a)
	}
	a.cp = cp
	a.cpv = NewPkgStr(cpv, nil, nil, "", "", "", 0, "", "", 0, "")
	a.version = extendedVersion
	a.version = a.cpv.version
	a.repo = repo
	if slot == "" {
		a.slot = ""
		a.subSlot = ""
		a.slotOperator = ""
	} else {
		slotRe := getSlotDepRe(eapiAttrs)
		if !slotRe.MatchString(slot) {
			//raise InvalidAtom(self)
		}
		if eapiAttrs.SlotOperator {
			a.slot = slotRe.FindStringSubmatch(slot)[1]
			subSlot := slotRe.FindStringSubmatch(slot)[2]
			if subSlot != "" {
				subSlot = strings.TrimPrefix(subSlot, "/")
			}
			if subSlot == "*" || subSlot == "=" {
				a.subSlot = ""
				a.slotOperator = subSlot
			} else {
				slotOperator := ""
				if subSlot != "" && subSlot[len(subSlot)-1:] == "=" {
					slotOperator = subSlot[len(subSlot)-1:]
					subSlot = subSlot[:len(subSlot)-1]
				}
				a.subSlot = subSlot
				a.slotOperator = slotOperator
			}
			if a.slot != "" && a.slotOperator == "*" {
				//raise InvalidAtom(self)
			}
		} else {
			a.slot = slot
			a.subSlot = ""
			a.slotOperator = ""
		}
	}

	a.operator = op
	a.extendedSyntax = extendedSyntax
	a.buildId = buildId
	if !(repo == "" || *allowRepo) {
		//raise InvalidAtom(self)
	}
	use := &useDep{}
	withoutUse := &Atom{}
	if useStr != "" {
		if _use != nil {
			use = _use
		} else {
			use = NewUseDep(strings.Split(useStr[1:len(useStr)-1], ","), &eapiAttrs, nil, nil, nil, nil, nil, nil)
		}
		withoutUse, _ = NewAtom(blockerPrefix+getNamedRegexp(atomRe, s, "without_use"), nil, false, allowRepo, nil, "", nil, nil)
	} else {
		use = nil
		if unevaluatedAtom != nil && unevaluatedAtom.use != nil {
			withoutUse, _ = NewAtom(blockerPrefix+getNamedRegexp(atomRe, s, "without_use"), nil, false, allowRepo, nil, "", nil, nil)
		} else {
			withoutUse = a
		}
	}
	a.use = use
	a.withoutUse = withoutUse

	if unevaluatedAtom != nil {
		a.unevaluatedAtom = unevaluatedAtom
	} else {
		a.unevaluatedAtom = a
	}

	if eapi != "" {
		if a.slot != "" && !eapiAttrs.slotDeps {
			//raise InvalidAtom(
			//	_("Slot deps are not allowed in EAPI %s: '%s'") \
			//% (eapi, self), category='EAPI.incompatible')
		}
		if a.use != nil {
			if !eapiAttrs.useDeps {
				//raise InvalidAtom(
				//	_("Use deps are not allowed in EAPI %s: '%s'") \
				//% (eapi, self), category='EAPI.incompatible')
			} else if !eapiAttrs.useDepDefaults && (len(a.use.missingEnabled) != 0 || len(a.use.missingDisabled) != 0) {
				//raise InvalidAtom(
				//	_("Use dep defaults are not allowed in EAPI %s: '%s'") \
				//% (eapi, self), category='EAPI.incompatible')
			}
			if isValidFlag != nil && a.use.conditional != nil {
				var invalidFlag *SMSB = nil
				for _, v := range a.use.conditional.items() {
					flags := v.MSB
					for flag := range flags {
						if !isValidFlag(flag) {
							invalidFlag = &v
							//raise StopIteration()
							goto endloop
						}
					}
				}
			endloop:
				if invalidFlag != nil {
					//conditionalType := invalidFlag.S
					//flag := invalidFlag.MSB
					//conditionalStr := useDep{}.conditionalStrings[conditionalType]
					//msg = _("USE flag '%s' referenced in " + \
					//"conditional '%s' in Atom '%s' is not in IUSE") \
					//% (flag, conditional_str % flag, self)
					//raise InvalidAtom(msg, category='IUSE.missing')
				}
			}
		}
		if a.blocker != nil && a.blocker.overlap.forbid && !eapiAttrs.strongBlocks {
			//raise InvalidAtom(
			//	_("Strong blocks are not allowed in EAPI %s: '%s'") \
			//% (eapi, self), category='EAPI.incompatible')
		}
	}

	return a, nil
}

func extractAffectingUse(mystr string, atom *Atom, eapi string) map[string]bool {
	useflagRe := getUseflagRe(eapi)
	mySplit := strings.Fields(mystr)
	level := 0
	stack := [][]string{}
	needBracket := false
	affectingUse := map[string]bool{}
	flag := func(conditional string) string {
		flag := ""
		if strings.HasPrefix(conditional, "!") {
			flag = conditional[1 : len(conditional)-1]
		} else {
			flag = conditional[:len(conditional)-1]
		}
		if !useflagRe.MatchString(flag) {
			//raise InvalidDependString(
			//	_("invalid use flag '%s' in conditional '%s'") % \
			//(flag, conditional))
		}
		return flag
	}
	for _, token := range mySplit {
		if token == "(" {
			needBracket = false
			stack = append(stack, []string{})
			level += 1
		} else if token == ")" {
			if needBracket {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % mystr)
			}
			if level > 0 {
				level -= 1
				l := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				//isSingle := (len(l) == 1 ||(len(l) == 2 &&(l[0] == "||"||strings.HasSuffix(l[0], "?"))))

				endsInAnyOfDep := func(k int) bool { return k >= 0 && len(stack) != 0 && stack[level][len(stack[level])-1] == "||" }
				endsInOperator := func(k int) bool {
					return k >= 0 && len(stack) != 0 && (stack[level][len(stack[level])-1] == "||" || strings.HasSuffix(stack[level][len(stack[level])-1], "?"))
				}
				specialAppend := func() {
					stack[level] = append(stack[level], l[0])
				}
				if len(l) != 0 {
					if !endsInAnyOfDep(level-1) && !endsInOperator(level) {
						stack[level] = append(stack[level], l...)
					} else if len(stack[level]) == 0 {
						specialAppend()
					} else if len(stack[level]) == 1 && endsInAnyOfDep(level) {
						stack = stack[:len(stack)-1]
						specialAppend()
						if strings.HasSuffix(l[0], "?") {
							affectingUse[flag(l[0])] = true
						}
					} else {
						if len(stack[level]) != 0 && (stack[level][len(stack[level])-1] == "||" || strings.HasSuffix(stack[level][len(stack[level])-1], "?")) {
							stack = stack[:len(stack)-1]
						}
						specialAppend()
					}
				} else {
					if len(stack[level]) != 0 && (stack[level][len(stack[level])-1] == "||" || strings.HasSuffix(stack[level][len(stack[level])-1], "?")) {
						stack = stack[:len(stack)-1]
					}
				}
			} else {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % mystr)
			}
		} else if token == "||" {
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
			//else if token == Atom
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
		} else if (i+1 < len(srcUris) && srcUris[i+1] == "->") || srcUris[i] == "->" {
			continue
		} else {
			keys := []string{}
			for k := range unpackers {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, suffix := range keys {
				suffix = strings.ToLower(suffix)
				if strings.HasSuffix(strings.ToLower(srcUris[i]), suffix) {
					depend = append(depend, unpackers[suffix])
				}
				break
			}
		}
	}
	for {
		cleanedDepend := append(depend[:0:0], depend...)
		for i := range cleanedDepend {
			if cleanedDepend[i] == "" {
				continue
			} else if cleanedDepend[i] == "(" && cleanedDepend[i+1] == ")" {
				cleanedDepend[i] = ""
				cleanedDepend[i+1] = ""
			} else if strings.HasSuffix(cleanedDepend[i], "?") && cleanedDepend[i+1] == "(" && cleanedDepend[i+2] == ")" {
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

func isValidAtom(atom string, allowBlockers, allowWildcard, allowRepo bool, eapi string, allowBuildId bool) bool { //false, false, false, "", false
	a, err := NewAtom(atom, nil, allowWildcard, &allowRepo, nil, eapi, nil, &allowBuildId)
	if err != nil {
		return false
	}
	if !allowBlockers && a.blocker != nil {
		return false
	}
	return true
}

var extendedCpReCache = map[string]*regexp.Regexp{}

func extendedCpMatch(extendedCp, otherCp string) bool {
	extendedCpRe := extendedCpReCache[extendedCp]
	if extendedCpRe == nil {
		extendedCpRe = regexp.MustCompile("^" + strings.Replace(regexp.QuoteMeta(extendedCp), "\\*", "[^/]*", -1) + "$")
		extendedCpReCache[extendedCp] = extendedCpRe
	}
	return extendedCpRe.MatchString(otherCp)
}

func removeSlot(mydep string) string {
	colon := strings.Index(mydep, slotSeparator)
	if colon != -1 {
		mydep = mydep[:colon]
	} else {
		bracket := strings.Index(mydep, "[")
		if bracket != -1 {
			mydep = mydep[:bracket]
		}
	}
	return mydep
}

func getOperator(mydep string) string {
	a, _ := NewAtom(mydep, nil, false, nil, nil, "", nil, nil)
	return a.operator
}

func depGetcpv(mydep string) *pkgStr {
	a, _ := NewAtom(mydep, nil, false, nil, nil, "", nil, nil)
	return a.cpv
}

func depGetslot(mydep string) string {
	mydep = strings.Split(mydep, repoSeparator)[0]
	colon := strings.Index(mydep, slotSeparator)
	if colon != -1 {
		bracket := strings.Index(mydep[colon:], "[")
		if bracket == -1 {
			return mydep[colon+1:]
		} else {
			return mydep[colon+1 : colon+bracket]
		}
	}
	return ""
}

func depGetrepo(mydep string) string {
	colon := strings.Index(mydep, repoSeparator)
	if colon != -1 {
		bracket := strings.Index(mydep[colon:], "[")
		if bracket == -1 {
			return mydep[colon+2:]
		} else {
			return mydep[colon+2 : colon+bracket]
		}
	}
	return ""
}

func depGetUseDeps(depend string) []string {
	useList := []string{}
	openBracket := strings.Index(depend, "[")
	commaSeparated := false
	bracketCount := 0
	for openBracket != -1 {
		bracketCount += 1
		if bracketCount > 1 {
			//raise InvalidAtom(_("USE Dependency with more "
			//"than one set of brackets: %s") % (depend,))
		}
		closeBracket := strings.Index(depend[openBracket:], "]")
		if closeBracket == -1 {
			//raise InvalidAtom(_("USE Dependency with no closing bracket: %s") % depend )
		}
		use := depend[openBracket+1 : closeBracket+openBracket]
		if len(use) == 0 {
			//raise InvalidAtom(_("USE Dependency with "
			//"no use flag ([]): %s") % depend )
		}
		if !commaSeparated {
			commaSeparated = strings.Contains(use, ",")
		}
		if commaSeparated && bracketCount > 1 {
			//raise InvalidAtom(_("USE Dependency contains a mixture of "
			//"comma and bracket separators: %s") % depend )
		}

		if commaSeparated {
			for _, x := range strings.Split(use, ",") {
				if x != "" {
					useList = append(useList, x)
				} else {
					//raise InvalidAtom(_("USE Dependency with no use "
					//"flag next to comma: %s") % depend )
				}
			}
		} else {
			useList = append(useList, use)
		}
		openBracket = strings.Index(depend[openBracket+1:], "[")
	}
	return useList
}

func isJustName(mypkg string) bool {
	a, err := NewAtom(mypkg, nil, false, nil, nil, "", nil, nil)
	if err == nil {
		return mypkg == a.cp
	}
	p := strings.Split(mypkg, "-")
	for _, x := range p[len(p)-2:] {
		if verVerify(x) {
			return false
		}
	}
	return true
}

func isSpecific(mypkg string) bool {
	a, err := NewAtom(mypkg, nil, false, nil, nil, "", nil, nil)
	if err == nil {
		return mypkg != a.cp
	}
	return !isJustName(mypkg)
}

func depGetKey(mydep string) string {
	a, _ := NewAtom(mydep, nil, false, nil, nil, "", nil, nil)
	return a.cp
}

func matchToList(mypkg *pkgStr, mylist []*Atom) []*Atom {
	matches := map[*Atom]bool{}
	result := []*Atom{}
	pkgs := []*pkgStr{mypkg}
	for _, x := range mylist {
		if !matches[x] && len(matchFromList(x, pkgs)) > 0 {
			matches[x] = true
			result = append(result, x)
		}
	}
	return result
}

func bestMatchToList(mypkg *pkgStr, mylist []*Atom) *Atom {
	operatorValues := map[string]int{"=": 6, "~": 5, "=*": 4, ">": 2, "<": 2, ">=": 2, "<=": 2, "": 1}
	maxvalue := -99
	var bestm *Atom = nil
	var mypkgCpv *pkgStr = nil
	for _, x := range matchToList(mypkg, mylist) {
		if x.extendedSyntax {
			if x.operator == "=*" {
				if maxvalue < 0 {
					maxvalue = 0
					bestm = x
				}
			} else if x.slot != "" {
				if maxvalue < -1 {
					maxvalue = -1
					bestm = x
				}
			} else {
				if maxvalue < -2 {
					maxvalue = -2
					bestm = x
				}
			}
			continue
		}
		if depGetslot(x.value) != "" {
			if maxvalue < 3 {
				maxvalue = 3
				bestm = x
			}
		}
		opVal := operatorValues[x.operator]
		if opVal > maxvalue {
			maxvalue = opVal
			bestm = x
		} else if opVal == maxvalue && opVal == 2 {
			if mypkgCpv == nil {
				mypkgCpv = mypkg.cpv
			}
			if mypkgCpv == nil {
				mypkgCpv = NewPkgStr(removeSlot(mypkg.string), nil, nil, "", "", "", 0, "", "", 0, "")
			}
			if bestm.cpv == mypkgCpv || bestm.cpv == x.cpv {
			} else if x.cpv == mypkgCpv {
				bestm = x
			} else {
				cpvList := []*pkgStr{bestm.cpv, mypkgCpv, x.cpv}
				sort.Slice(cpvList, func(i, j int) bool {
					b, _ := verCmp(cpvList[i].version, cpvList[j].version)
					return b < 0
				})
				if cpvList[0] == mypkgCpv || cpvList[len(cpvList)-1] == mypkgCpv {
					if cpvList[1] == x.cpv {
						bestm = x
					}
				} else {
				}
			}
		}
	}
	return bestm

}

func matchFromList(mydep *Atom, candidateList []*pkgStr) []*pkgStr {
	if len(candidateList) == 0 {
		return []*pkgStr{}
	}
	mydepA := mydep
	if "!" == mydep.value[:1] {
		mydepS := ""
		if "!" == mydep.value[1:2] {
			mydepS = mydep.value[2:]
		} else {
			mydepS = mydep.value[1:]
		}
		ar := true
		mydepA, _ = NewAtom(mydepS, nil, true, &ar, nil, "", nil, nil)
	}

	mycpv := mydepA.cpv
	mycpvCps := catPkgSplit(mycpv.string, 0, "")
	//slot      := mydepA.slot
	buildId := mydepA.buildId

	_, _, ver, rev := "", "", "", ""
	if mycpvCps == [4]string{} {
		cp := catsplit(mycpv.string)
		_ = cp[0]
		_ = cp[1]
		ver = ""
		rev = ""
	} else {
		_, _, ver, rev = mycpvCps[0], mycpvCps[1], mycpvCps[2], mycpvCps[3]
	}
	if mydepA.value == mycpv.string {
		//raise KeyError(_("Specific key requires an operator"
		//" (%s) (try adding an '=')") % (mydep))
	}

	operator := ""
	if ver != "" && rev != "" {
		operator = mydepA.operator
		if operator == "" {
			WriteMsg(fmt.Sprintf("!!! Invalid Atom: %s\n", mydep.value), -1, nil)
		}
		return []*pkgStr{}
	} else {
		operator = ""
	}
	mylist := []*pkgStr{}
	if mydepA.extendedSyntax {
		for _, x := range candidateList {
			cp := x.cp
			if cp == "" {
				mysplit := catPkgSplit(removeSlot(x.string), 1, "")
				if mysplit != [4]string{} {
					cp = mysplit[0] + "/" + mysplit[1]
				}
			}
			if cp == "" {
				continue
			}
			if cp == mycpv.string || extendedCpMatch(mydepA.cp, cp) {
				mylist = append(mylist, x)
			}
		}
		if len(mylist) > 0 && mydepA.operator == "=*" {
			candidateList = mylist
			mylist = []*pkgStr{}
			ver = mydepA.version[1 : len(mydepA.version)-1]
			for _, x := range candidateList {
				xVer := x.version
				if xVer == "" {
					xs := catPkgSplit(removeSlot(x.string), 1, "")
					if xs == [4]string{} {
						continue
					}
					xVer = strings.Join(xs[len(xs)-2:], "-")
				}
				if strings.Contains(xVer, ver) {
					mylist = append(mylist, x)
				}
			}
		}
	} else if operator == "" {
		for _, x := range candidateList {
			cp := x.cp
			if cp == "" {
				mysplit := catPkgSplit(removeSlot(x.string), 1, "")
				if mysplit != [4]string{} {
					cp = mysplit[0] + "/" + mysplit[1]
				}
				if cp == "" {
					continue
				}
			}
			if cp == mydepA.cp {
				mylist = append(mylist, x)
			}
		}
	} else if operator == "=" {
		for _, x := range candidateList {
			xcpv := x.cpv
			if xcpv == nil {
				xcpv = &pkgStr{string: removeSlot(x.string)}
			}
			if !cpvequal(xcpv.string, mycpv.string) {
				continue
			}
			if buildId != 0 {
				continue
			}
			mylist = append(mylist, x)
		}
	} else if operator == "=*" {
		myver := strings.TrimPrefix(mycpvCps[2], "0")
		if myver == "" || !unicode.IsDigit(rune(myver[0])) {
			myver = "0" + myver
		}
		mycpvCmp := ""
		if myver == mycpvCps[2] {
			mycpvCmp = mycpv.string
		} else {
			mycpvCmp = strings.Replace(mycpv.string, mydepA.cp+"-"+mycpvCps[2], mydepA.cp+"-"+myver, 1)
		}
		for _, x := range candidateList {
			pkg := x
			if pkg.cp == "" {
				pkg = NewPkgStr(removeSlot(x.string), nil, nil, "", "", "", 0, "", "", 0, "")
			}
			xs := pkg.cpvSplit
			myver := strings.TrimPrefix(xs[2], "0")
			if len(myver) == 0 || !unicode.IsDigit(rune(myver[0])) {
				myver = "0" + myver
			}
			xcpv := ""
			if myver == xs[2] {
				xcpv = pkg.cpv.string
			} else {
				xcpv = strings.Replace(pkg.cpv.string, pkg.cp+"-"+xs[2], pkg.cp+"-"+myver, 1)
			}
			if strings.HasPrefix(xcpv, mycpvCmp) {
				nextChar := xcpv[len(mycpvCmp) : len(mycpvCmp)+1]
				if nextChar == "" || nextChar == "." || nextChar == "_" || nextChar == "-" || unicode.IsDigit(rune(mycpvCmp[len(mycpvCmp)-1])) != unicode.IsDigit(rune(nextChar[0])) {
					mylist = append(mylist, x)
				}
			}
		}
	} else if operator == "~" {
		for _, x := range candidateList {
			xs := x.cpvSplit
			if xs == [4]string{} {
				xs = catPkgSplit(removeSlot(x.string), 1, "")
			}
			if xs == [4]string{} {
				//raise InvalidData(x)
			}
			if !cpvequal(xs[0]+"/"+xs[1]+"-"+xs[2], mycpvCps[0]+"/"+mycpvCps[1]+"-"+mycpvCps[2]) {
				continue
			}
			if xs[2] != ver {
				continue
			}
			mylist = append(mylist, x)
		}
	} else if operator == ">" || operator == ">=" || operator == "<" || operator == "<=" {
		for _, x := range candidateList {
			pkg := x
			if x.cp == "" {
				pkg = NewPkgStr(removeSlot(x.string), nil, nil, "", "", "", 0, "", "", 0, "")
			}

			if pkg.cp != mydepA.cp {
				continue
			}
			result, err := verCmp(pkg.version, mydepA.version)
			if err != nil {
				WriteMsg(fmt.Sprintf("\nInvalid package name: %s\n", x), -1, nil)
				//raise
			}
			if operator == ">" {
				if result > 0 {
					mylist = append(mylist, x)
				}
			} else if operator == ">=" {
				if result >= 0 {
					mylist = append(mylist, x)
				}
			} else if operator == "<" {
				if result < 0 {
					mylist = append(mylist, x)
				}
			} else if operator == "<=" {
				if result <= 0 {
					mylist = append(mylist, x)
				}
			} else {
				//raise KeyError(_("Unknown operator: %s") % mydep)
			}
		}
	} else {
		//raise KeyError(_("Unknown operator: %s") % mydep)
	}

	if mydepA.slot != "" {
		candidateList = mylist
		mylist = []*pkgStr{}
		for _, x := range candidateList {
			xPkg := x
			if xPkg.cpv == nil {
				xslot := depGetslot(x.string)
				if xslot != "" {
					xPkg = NewPkgStr(removeSlot(x.string), nil, nil, "", "", xslot, 0, "", "", 0, "")
				} else {
					continue
				}
			}

			if xPkg == nil {
				mylist = append(mylist, x)
			} else {
				if xPkg.slot == "" {
					mylist = append(mylist, x)
				} else {
					if matchSlot(mydepA, xPkg) {
						mylist = append(mylist, x)
					}
				}
			}
		}
	}

	if mydepA.unevaluatedAtom.use != nil {
		candidateList = mylist
		mylist = []*pkgStr{}
		for _, x := range candidateList {
			//use = getattr(x, "use", None)
			//if use is not None:
			//if mydep.unevaluated_atom.use and \
			//not x.iuse.is_valid_flag(
			//	mydep.unevaluated_atom.use.required):
			//continue
			//
			//if mydep.use:
			//is_valid_flag = x.iuse.is_valid_flag
			//missing_enabled = frozenset(flag for flag in
			//mydep.use.missing_enabled if not is_valid_flag(flag))
			//missing_disabled = frozenset(flag for flag in
			//mydep.use.missing_disabled if not is_valid_flag(flag))
			//
			//if mydep.use.enabled:
			//if any(f in mydep.use.enabled for f in missing_disabled):
			//continue
			//need_enabled = mydep.use.enabled.difference(use.enabled)
			//if need_enabled:
			//if any(f not in missing_enabled for f in need_enabled):
			//continue
			//
			//if mydep.use.disabled:
			//if any(f in mydep.use.disabled for f in missing_enabled):
			//continue
			//need_disabled = mydep.use.disabled.intersection(use.enabled)
			//if need_disabled:
			//if any(f not in missing_disabled for f in need_disabled):
			//continue

			mylist = append(mylist, x)
		}
	}

	if mydepA.repo != "" {
		candidateList = mylist
		mylist = []*pkgStr{}
		for _, x := range candidateList {
			repo := x.repo
			if repo == "" {
				repo = depGetrepo(x.string)
			}
			if repo != "" && repo != unknownRepo && repo != mydepA.repo {
				continue
			}
			mylist = append(mylist, x)
		}
	}

	return mylist
}

func humanReadableRequiredUse(requiredUse string) string {
	return strings.Replace(strings.Replace(strings.Replace(requiredUse, "^^", "exactly-one-of", -1), "||", "any-of", -1), "??", "at-most-one-of", -1)
}

func get_required_use_flags(requiredUse, eapi string) map[string]bool { //n
	eapiAttrs := getEapiAttrs(eapi)
	validOperators := map[string]bool{}
	if eapiAttrs.requiredUseAtMostOneOf {
		validOperators = map[string]bool{"||": true, "^^": true, "??": true}
	} else {
		validOperators = map[string]bool{"||": true, "^^": true}
	}

	mysplit := strings.Fields(requiredUse)
	level := 0
	stack := [][]string{{}}
	needBracket := false
	usedFlags := map[string]bool{}
	registerToken := func(token string) {
		if strings.HasSuffix(token, "?") {
			token = token[:len(token)-1]
		}
		if strings.HasPrefix(token, "!") {
			token = token[1:]
		}
		usedFlags[token] = true
	}
	for _, token := range mysplit {
		if token == "(" {
			needBracket = false
			stack = append(stack, []string{})
			level += 1
		} else if token == ")" {
			if needBracket {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % required_use)
			}
			if level > 0 {
				level -= 1
				l := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				ignore := false
				if len(stack[level]) > 0 {
					if validOperators[stack[level][len(stack[level])-1]] || stack[level][len(stack[level])-1] == "" && strings.HasSuffix(stack[level][len(stack[level])-1], "?") {
						ignore = true
						stack[level] = stack[level][:len(stack[level])-1]
						stack[level] = append(stack[level], "")
					}
				}
				if len(l) > 0 && !ignore {
					for _, x := range l {
						stack[level] = append(stack[level], x)
					}
				}
			} else {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % required_use)
			}
		} else if validOperators[token] {
			if needBracket {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % required_use)
			}
			needBracket = true
			stack[level] = append(stack[level], token)
		} else {
			if needBracket {
				//raise InvalidDependString(
				//	_("malformed syntax: '%s'") % required_use)
			}
			if strings.HasSuffix(token, "?") {
				needBracket = true
				stack[level] = append(stack[level], token)
			} else {
				stack[level] = append(stack[level], "")
			}
			registerToken(token)
		}
	}
	if level != 0 || needBracket {
		//raise InvalidDependString(
		//	_("malformed syntax: '%s'") % required_use)

	}
	return usedFlags
}
