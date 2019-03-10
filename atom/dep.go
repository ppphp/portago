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
	c1 := NewPkgStr(cpv1, nil, nil, "", "", "", "", "", "", 0, "")
	split1 := c1.cpv_split
	c2 := NewPkgStr(cpv2, nil, nil, "", "", "", "", "", "", 0, "")
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

func matchSlot(atom, pkg *atom) bool {
	if pkg.slot == atom.slot {
		if atom.subSlot == "" {
			return true
		} else if atom.subSlot == pkg.subSlot {
			return true
		}
	}
	return false
}

func useReduce(depstr string, uselist map[string]bool, masklist []string, matchall bool, excludeall []string, isSrcUri bool, eapi string, opconvert, flat bool, isValidFlag func(string) bool, tokenClass func(string) *atom, matchnone bool) []string {
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
						token = t.evaluateConditionals(uselist).value
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

type atom struct {
	value string
	ispackage, soname, extendedSyntax                              bool
	buildId                                                        int
	blocker                                                        *blocker
	slotOperator, subSlot, repo, slot, eapi, cp, version, operator string
	cpv                                                            *pkgStr
	use                                                            *useDep
	withoutUse, unevaluatedAtom                                    *atom
}

func (a *atom) withoutSlot() *atom {
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

func (a *atom) withRepo(repo string) *atom {
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

func (a *atom) withSlot(slot string) *atom {
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

func (a *atom) evaluateConditionals(use map[string]bool) *atom {
	if !(a.use!= nil && a.use.conditional!= nil) {
		return a
	}
	atom := removeSlot(a.value)
	if a.slot!= "" ||a.slotOperator!=""{
		atom += slotSeparator
		if a.slot != ""{
			atom += a.slot
		}
		if a.subSlot != "" {
			atom += fmt.Sprintf("/%s", a.subSlot)
		}
		if a.slotOperator!= "" {
			atom += a.slotOperator
		}
	}
	useDep := a.use.evaluateConditionals(use)
	atom += useDep.str()
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *atom) violatedConditionals(otherUse map[string]bool, isValidFlag func(string)bool, parentUse map[string]bool) *atom{ // none
	if a.use == nil {
		return a
	}
	atom := removeSlot(a.value)
	if a.slot!="" || a.slotOperator!= ""{
		atom += slotSeparator
		if a.slot!= "" {
			atom += a.slot
		}
		if a.subSlot != "" {
			atom += fmt.Sprintf("/%s", a.subSlot)
		}
		if a.slotOperator!= "" {
			atom += a.slotOperator
		}
	}
	useDep := a.use.violatedConditionals(otherUse, isValidFlag, parentUse)
	atom += useDep.str()
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *atom) slotOperatorBuilt() bool {
	return a.slotOperator == "=" && a.subSlot != ""
}

func (a *atom) withoutRepo() *atom {
	if a.repo == "" {
		return a
	}
	b, _ := NewAtom(strings.Replace(a.value, repoSeparator+a.repo, "", 1), nil, true, nil, nil, "", nil, nil)
	return b
}

func (a *atom) intersects(other *atom) bool {
	if a == other {
		return true
	}
	if a.cp != other.cp || a.use != other.use ||	a.operator != other.operator ||	a.cpv != other.cpv{
		return false
	}
	if a.slot =="" ||	other.slot =="" ||	a.slot == other.slot{
		return true
	}
	return false
}

func NewAtom(s string, unevaluatedAtom *atom, allowWildcard bool, allowRepo *bool, _use *useDep, eapi string, isValidFlag func(string) bool, allowBuildId *bool) (*atom, error) { //s, None, False, None, None, None, None, None
	a := &atom{value: s, ispackage: true, soname: false}
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
		return nil, fmt.Errorf("required group not found in atom: '%v'", a)
	}
	a.cp = cp
	a.cpv = NewPkgStr(cpv, nil, nil, "", "", "", "", "", "", 0, "")
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
	withoutUse := &atom{}
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
					//"conditional '%s' in atom '%s' is not in IUSE") \
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

func extractAffectingUse(mystr string, atom *atom, eapi string) map[string]bool {
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
		cleanedDepend := CopySliceS(depend)
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

func isValidAtom(atom string, allowBlockers, allowWildcard, allowRepo bool, eapi string, allowBuildId bool) bool { //false, false, false, none, false
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

func extended_cp_match(extendedCp, otherCp string) bool {
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
