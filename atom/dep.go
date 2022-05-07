package atom

import (
	"errors"
	"fmt"
	"github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/util"
	"golang.org/x/net/html/atom"
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

func getSlotDepRe(attrs eapi.eapiAttrs) *regexp.Regexp {
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

func getAtomRe(attrs eapi.eapiAttrs) *regexp.Regexp {
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
	mc := "^(?P<without_use>(?:" +
		"(?P<op>" + op + cpvs + ")|" +
		"(?P<star>=" + cpvs + "\\*)|" +
		"(?P<simple>" + cps + "))" +
		"(" + slotSeparator + slotLoose + ")?" +
		repo + ")(" + use + ")?$"
	atomRe = regexp.MustCompile(mc)
	atomReCache[cacheKey] = atomRe
	return atomRe
}

func getAtomWildcardRe(attrs eapi.eapiAttrs) *regexp.Regexp {
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

func getUsedepRe(attrs eapi.eapiAttrs) *regexp.Regexp {
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
	attrs := eapi.getEapiAttrs(eapi)
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
	c1 := NewPkgStr(cpv1, nil, nil, "", "", "", 0, 0, "", 0, nil)
	split1 := c1.cpvSplit
	c2 := NewPkgStr(cpv2, nil, nil, "", "", "", 0, 0, "", 0, nil)
	split2 := c2.cpvSplit
	if split1[0] != split2[0] || split1[1] != split2[1] {
		return false
	}
	v, _ := verCmp(cpv1, cpv2)
	return v == 0
}

func parenEnclose(myList [][]string, unevaluatedAtom, opconvert bool) string {
	myStrParts := []string{}
	for _, x := range  myList {
		if opconvert && len(x) > 0 && x[0] != "||" {
			myStrParts = append(myStrParts, fmt.Sprintf("%s ( %s )", x[0], parenEncloses(x[1:], false, false)))
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
	for _, x := range  myList {
		//if unevaluated_atom: // TODO
		//    x = getattr(x, "unevaluated_atom', x)
		myStrParts = append(myStrParts, x)
	}
	return strings.Join(myStrParts, " ")
}

func matchSlot(atom *Atom, pkg *PkgStr) bool {
	if pkg.slot == atom.slot {
		if atom.subSlot == "" {
			return true
		} else if atom.subSlot == pkg.subSlot {
			return true
		}
	}
	return false
}

// map[string]bool{}, []string{}, false, []string{}, false, "", false, false, nil, nil, false
func useReduce(depstr string, uselist map[string]bool, masklist []string, matchall bool, excludeall []string, isSrcUri bool, eapi string, opconvert, flat bool, isValidFlag func(string) bool, tokenClass func(string) *Atom, matchnone bool) []string {
	if opconvert && flat {
		// ValueError("portage.dep.use_reduce: 'opconvert' and "flat' are mutually exclusive")
	}
	if matchall && matchnone {
		// ValueError("portage.dep.use_reduce: 'opconvert' and 'flat' are mutually exclusive")
	}
	eapiAttrs := eapi.getEapiAttrs(eapi)
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
				//e = InvalidData(msg, category="IUSE.missing") // TODO
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
	//	for _, x := range  []string{")", "(", "||"} {
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
				//	_("any-of dependencies are!allowed in SRC_URI: token %s") % (pos+1,))
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
				//	_("SRC_URI arrow!allowed in EAPI %s: token %s") % (eapi, pos+1))
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
	eapiAttrs                                                    *eapi.eapiAttrs
	missingEnabled, missingDisabled, disabled, enabled, required map[string]bool
	conditional                                                  *conditionalClass
	tokens                                                       []string
	conditionalStrings                                           map[string]string
}

func (u *useDep) evaluateConditionals(use map[string]bool) *useDep {
	enabledFlags := myutil.CopyMapSB(u.enabled)
	disabledFlags := myutil.CopyMapSB(u.disabled)
	tokens := []string{}
	usedepRe := getUsedepRe(*u.eapiAttrs)
	for _, x := range  u.tokens {
		operator := myutil.getNamedRegexp(usedepRe, x, "prefix") + myutil.getNamedRegexp(usedepRe, x, "suffix")
		flag := myutil.getNamedRegexp(usedepRe, x, "flag")
		defaults := myutil.getNamedRegexp(usedepRe, x, "default")
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
		//raise InvalidAtom("violated_conditionals needs 'parent_use'" + 
		//" parameter for conditional flags.")
	}
	enabledFlags := myutil.CopyMapSB(u.enabled)
	disabledFlags := myutil.CopyMapSB(u.disabled)
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
	for _, x := range  u.tokens {
		operator := myutil.getNamedRegexp(usedepRe, x, "prefix") + myutil.getNamedRegexp(usedepRe, x, "suffix")
		flag := myutil.getNamedRegexp(usedepRe, x, "flag")
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
	enabledFlags := myutil.CopyMapSB(u.enabled)
	disabledFlags := myutil.CopyMapSB(u.disabled)
	tokens := []string{}
	usedepRe := getUsedepRe(*u.eapiAttrs)
	for _, x := range  u.tokens {
		operator := myutil.getNamedRegexp(usedepRe, x, "prefix") + myutil.getNamedRegexp(usedepRe, x, "suffix")
		flag := myutil.getNamedRegexp(usedepRe, x, "flag")
		defaults := myutil.getNamedRegexp(usedepRe, x, "default")
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

func NewUseDep(use []string, eapiAttrs *eapi.eapiAttrs, enabledFlags, disabledFlags, missingEnabled, missingDisabled map[string]bool, conditional map[string]map[string]bool, required map[string]bool) *useDep { // none
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

	for _, x := range  use {
		if !usedepRe.MatchString(x) {
			//raise InvalidAtom(_("Invalid use dep: '%s'") % (x,))
		}
		operator := myutil.getNamedRegexp(usedepRe, x, "prefix") + myutil.getNamedRegexp(usedepRe, x, "suffix")
		flag := myutil.getNamedRegexp(usedepRe, x, "flag")
		defaults := myutil.getNamedRegexp(usedepRe, x, "default")
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
	Blocker                                                        *blocker
	slotOperator, subSlot, repo, slot, eapi, cp, version, Operator string
	cpv                                                            *PkgStr
	Use                                                            *useDep
	withoutUse, unevaluatedAtom                                    *Atom
}

func (a *Atom) withoutSlot() *Atom {
	if a.slot == "" && a.slotOperator == "" {
		return a
	}
	atom := RemoveSlot(a.value)
	if a.repo != "" {
		atom += repoSeparator + a.repo
	}
	if a.Use != nil {
		atom += a.Use.str()
	}
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) withRepo(repo string) *Atom {
	atom := RemoveSlot(a.value)
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
	if a.Use != nil {
		atom += a.Use.str()
	}
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) withSlot(slot string) *Atom {
	atom := RemoveSlot(a.value) + slotSeparator + slot
	if a.repo != "" {
		atom += repoSeparator + a.repo
	}
	if a.Use != nil {
		atom += a.Use.str()
	}
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) EvaluateConditionals(use map[string]bool) *Atom {
	if !(a.Use != nil && a.Use.conditional != nil) {
		return a
	}
	atom := RemoveSlot(a.value)
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
	useDep := a.Use.evaluateConditionals(use)
	atom += useDep.str()
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) violatedConditionals(otherUse map[string]bool, isValidFlag func(string) bool, parentUse map[string]bool) *Atom { // none
	if a.Use == nil {
		return a
	}
	atom := RemoveSlot(a.value)
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
	useDep := a.Use.violatedConditionals(otherUse, isValidFlag, parentUse)
	atom += useDep.str()
	m := true
	b, _ := NewAtom(atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom) evalQaConditionals(useMask, useForce map[string]bool) *Atom {
	if a.Use == nil || a.Use.conditional == nil {
		return a
	}
	atom := RemoveSlot(a.value)
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
	useDep := a.Use.evalQaConditionals(useMask, useForce)
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
	if a.cp != other.cp || a.Use != other.Use || a.Operator != other.Operator || a.cpv != other.cpv {
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

func (a *Atom) match(pkg *PkgStr) bool {
	return len(matchFromList(a, []*PkgStr{pkg})) > 0
}

//s, nil, false, nil, nil, "", nil, nil
func NewAtom(s string, unevaluatedAtom *Atom, allowWildcard bool, allowRepo *bool, _use *useDep, eapi string, isValidFlag func(string) bool, allowBuildId *bool) (*Atom, error) {
	a := &Atom{value: s, ispackage: true, soname: false}
	eapiAttrs := eapi.getEapiAttrs(eapi)
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
	a.Blocker = blocker
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
			if myutil.getNamedRegexp(atomRe, s, "star") != "" {
				op = "=*"
				ar := atomRe.SubexpNames()
				base := 0
				for k, v := range ar {
					if v == "star" {
						base = k
					}
				}
				cp = atomRe.FindAllString(s, -1)[base+1]
				cpv = myutil.getNamedRegexp(atomRe, s, "star")[1:]
				extendedVersion = atomRe.FindAllString(s, -1)[base+4]
			} else {
				op = ""
				cp = myutil.getNamedRegexp(atomRe, s, "simple")
				cpv = cp
				if len(atomRe.FindAllString(s, -1)) >= 4 {
					return nil, errors.New("InvalidAtom")
				}
			}
			if !strings.Contains(cpv, "**") {
				return nil, errors.New("InvalidAtom")
			}
			slot = myutil.getNamedRegexp(atomRe, s, "slot")
			repo = myutil.getNamedRegexp(atomRe, s, "repo")
			useStr = ""
			extendedSyntax = true
		} else {
			return nil, errors.New("InvalidAtom")
		}
	} else if myutil.getNamedRegexp(atomRe, s, "op") != "" {
		base := 0
		ar := atomRe.SubexpNames()
		for k, v := range ar {
			if v == "op" {
				base = k
			}
		}
		op = atomRe.FindStringSubmatch(s)[base+1]
		cpv = atomRe.FindStringSubmatch(s)[base+2]
		cp = atomRe.FindStringSubmatch(s)[base+3]
		groups := len(atomRe.SubexpNames())
		slot = atomRe.FindStringSubmatch(s)[groups-3]
		repo = atomRe.FindStringSubmatch(s)[groups-2]
		useStr = atomRe.FindStringSubmatch(s)[groups-1]
		version := atomRe.FindStringSubmatch(s)[base+4]
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
	} else if myutil.getNamedRegexp(atomRe, s, "star") != "" {
		base := 0
		ar := atomRe.SubexpNames()
		for k, v := range ar {
			if v == "star" {
				base = k
			}
		}
		op = "=*"
		cpv = atomRe.FindStringSubmatch(s)[base+1]
		cp = atomRe.FindStringSubmatch(s)[base+2]
		groups := len(atomRe.SubexpNames())
		slot = atomRe.FindStringSubmatch(s)[groups-3]
		repo = atomRe.FindStringSubmatch(s)[groups-2]
		useStr = atomRe.FindStringSubmatch(s)[groups-1]
		if len(atomRe.FindStringSubmatch(s)) >= base+3 && atomRe.FindStringSubmatch(s)[base+3] != "" {
			return nil, errors.New("InvalidAtom")
		}
	} else if myutil.getNamedRegexp(atomRe, s, "simple") != "" {
		op = ""
		base := 0
		ar := atomRe.SubexpNames()
		for k, v := range ar {
			if v == "simple" {
				base = k
			}
		}
		cp = atomRe.FindStringSubmatch(s)[base+1]
		cpv = cp
		groups := len(atomRe.SubexpNames())
		slot = atomRe.FindStringSubmatch(s)[groups-3]
		repo = atomRe.FindStringSubmatch(s)[groups-2]
		useStr = atomRe.FindStringSubmatch(s)[groups-1]
		smp := 0
		for i, n := range atomRe.SubexpNames() {
			if n == "simple" {
				smp = i
			}
		}
		if len(atomRe.FindStringSubmatch(s)) >= smp+2 && atomRe.FindStringSubmatch(s)[smp+2] != "" {
			return nil, errors.New("InvalidAtom")
		}
	} else {
		return nil, fmt.Errorf("required group!found in Atom: '%v'", a)
	}
	a.cp = cp
	a.cpv = NewPkgStr(cpv, nil, nil, "", "", "", 0, 0, "", 0, nil)
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

	a.Operator = op
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
		withoutUse, _ = NewAtom(blockerPrefix+myutil.getNamedRegexp(atomRe, s, "without_use"), nil, false, allowRepo, nil, "", nil, nil)
	} else {
		use = nil
		if unevaluatedAtom != nil && unevaluatedAtom.Use != nil {
			withoutUse, _ = NewAtom(blockerPrefix+myutil.getNamedRegexp(atomRe, s, "without_use"), nil, false, allowRepo, nil, "", nil, nil)
		} else {
			withoutUse = a
		}
	}
	a.Use = use
	a.withoutUse = withoutUse

	if unevaluatedAtom != nil {
		a.unevaluatedAtom = unevaluatedAtom
	} else {
		a.unevaluatedAtom = a
	}

	if eapi != "" {
		if a.slot != "" && !eapiAttrs.slotDeps {
			//raise InvalidAtom(
			//	_("Slot deps are!allowed in EAPI %s: '%s'") 
			//% (eapi, self), category='EAPI.incompatible')
		}
		if a.Use != nil {
			if !eapiAttrs.useDeps {
				//raise InvalidAtom(
				//	_("Use deps are!allowed in EAPI %s: '%s'") 
				//% (eapi, self), category='EAPI.incompatible')
			} else if !eapiAttrs.useDepDefaults && (len(a.Use.missingEnabled) != 0 || len(a.Use.missingDisabled) != 0) {
				//raise InvalidAtom(
				//	_("Use dep defaults are!allowed in EAPI %s: '%s'") 
				//% (eapi, self), category='EAPI.incompatible')
			}
			if isValidFlag != nil && a.Use.conditional != nil {
				var invalidFlag *SMSB = nil
				for _, v := range a.Use.conditional.items() {
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
					//msg = _("USE flag '%s' referenced in " + 
					//"conditional '%s' in Atom '%s' is!in IUSE") 
					//% (flag, conditional_str % flag, self)
					//raise InvalidAtom(msg, category='IUSE.missing')
				}
			}
		}
		if a.Blocker != nil && a.Blocker.overlap.forbid && !eapiAttrs.strongBlocks {
			//raise InvalidAtom(
			//	_("Strong blocks are!allowed in EAPI %s: '%s'") 
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
			//	_("invalid Use flag '%s' in conditional '%s'") % 
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
			//	stack[level]= append(,token)
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
			for _, x := range  cleanedDepend {
				depend = append(depend, x)
			}
		}
	}
	return strings.Join(depend, " ")
}

//false, false, false, "", false
func isValidAtom(atom string, allowBlockers, allowWildcard, allowRepo bool, eapi string, allowBuildId bool) bool {
	a, err := NewAtom(atom, nil, allowWildcard, &allowRepo, nil, eapi, nil, &allowBuildId)
	if err != nil {
		return false
	}
	if !allowBlockers && a.Blocker != nil {
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

func RemoveSlot(mydep string) string {
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
	return a.Operator
}

func depGetcpv(mydep string) *PkgStr {
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

func DepGetrepo(mydep string) string {
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
			//"no Use flag ([]): %s") % depend )
		}
		if !commaSeparated {
			commaSeparated = strings.Contains(use, ",")
		}
		if commaSeparated && bracketCount > 1 {
			//raise InvalidAtom(_("USE Dependency contains a mixture of "
			//"comma && bracket separators: %s") % depend )
		}

		if commaSeparated {
			for _, x := range  strings.Split(use, ",") {
				if x != "" {
					useList = append(useList, x)
				} else {
					//raise InvalidAtom(_("USE Dependency with no Use "
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
	for _, x := range  p[len(p)-2:] {
		if verVerify(x, 1) {
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

func matchToList(mypkg *PkgStr, mylist []*Atom) []*Atom {
	matches := map[*Atom]bool{}
	result := []*Atom{}
	pkgs := []*PkgStr{mypkg}
	for _, x := range  mylist {
		if !matches[x] && len(matchFromList(x, pkgs)) > 0 {
			matches[x] = true
			result = append(result, x)
		}
	}
	return result
}

func bestMatchToList(mypkg *PkgStr, mylist []*Atom) *Atom {
	operatorValues := map[string]int{"=": 6, "~": 5, "=*": 4, ">": 2, "<": 2, ">=": 2, "<=": 2, "": 1}
	maxvalue := -99
	var bestm *Atom = nil
	var mypkgCpv *PkgStr = nil
	for _, x := range  matchToList(mypkg, mylist) {
		if x.extendedSyntax {
			if x.Operator == "=*" {
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
		opVal := operatorValues[x.Operator]
		if opVal > maxvalue {
			maxvalue = opVal
			bestm = x
		} else if opVal == maxvalue && opVal == 2 {
			if mypkgCpv == nil {
				mypkgCpv = mypkg.cpv
			}
			if mypkgCpv == nil {
				mypkgCpv = NewPkgStr(RemoveSlot(mypkg.string), nil, nil, "", "", "", 0, 0, "", 0, nil)
			}
			if bestm.cpv == mypkgCpv || bestm.cpv == x.cpv {
			} else if x.cpv == mypkgCpv {
				bestm = x
			} else {
				cpvList := []*PkgStr{bestm.cpv, mypkgCpv, x.cpv}
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

func matchFromList(mydep *Atom, candidateList []*PkgStr) []*PkgStr {
	if len(candidateList) == 0 {
		return []*PkgStr{}
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
	mycpvCps := CatPkgSplit(mycpv.string, 0, "")
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
		operator = mydepA.Operator
		if operator == "" {
			util.WriteMsg(fmt.Sprintf("!!! Invalid Atom: %s\n", mydep.value), -1, nil)
		}
		return []*PkgStr{}
	} else {
		operator = ""
	}
	mylist := []*PkgStr{}
	if mydepA.extendedSyntax {
		for _, x := range  candidateList {
			cp := x.cp
			if cp == "" {
				mysplit := CatPkgSplit(RemoveSlot(x.string), 1, "")
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
		if len(mylist) > 0 && mydepA.Operator == "=*" {
			candidateList = mylist
			mylist = []*PkgStr{}
			ver = mydepA.version[1 : len(mydepA.version)-1]
			for _, x := range  candidateList {
				xVer := x.version
				if xVer == "" {
					xs := CatPkgSplit(RemoveSlot(x.string), 1, "")
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
		for _, x := range  candidateList {
			cp := x.cp
			if cp == "" {
				mysplit := CatPkgSplit(RemoveSlot(x.string), 1, "")
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
		for _, x := range  candidateList {
			xcpv := x.cpv
			if xcpv == nil {
				xcpv = &PkgStr{string: RemoveSlot(x.string)}
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
		for _, x := range  candidateList {
			pkg := x
			if pkg.cp == "" {
				pkg = NewPkgStr(RemoveSlot(x.string), nil, nil, "", "", "", 0, 0, "", 0, nil)
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
		for _, x := range  candidateList {
			xs := x.cpvSplit
			if xs == [4]string{} {
				xs = CatPkgSplit(RemoveSlot(x.string), 1, "")
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
		for _, x := range  candidateList {
			pkg := x
			if x.cp == "" {
				pkg = NewPkgStr(RemoveSlot(x.string), nil, nil, "", "", "", 0, 0, "", 0, nil)
			}

			if pkg.cp != mydepA.cp {
				continue
			}
			result, err := verCmp(pkg.version, mydepA.version)
			if err != nil {
				util.WriteMsg(fmt.Sprintf("\nInvalid package name: %v\n", x), -1, nil)
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
		mylist = []*PkgStr{}
		for _, x := range  candidateList {
			xPkg := x
			if xPkg.cpv == nil {
				xslot := depGetslot(x.string)
				if xslot != "" {
					xPkg = NewPkgStr(RemoveSlot(x.string), nil, nil, "", "", xslot, 0, 0, "", 0, nil)
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

	if mydepA.unevaluatedAtom.Use != nil {
		candidateList = mylist
		mylist = []*PkgStr{}
		for _, x := range  candidateList {
			//Use = getattr(x, "Use", None)
			//if Use != nil{
			//if mydep.unevaluated_atom.Use and 
			//not x.iuse.is_valid_flag(
			//	mydep.unevaluated_atom.Use.required){
			//continue
			//
			//if mydep.Use{
			//is_valid_flag = x.iuse.is_valid_flag
			//missing_enabled = frozenset(flag for flag in
			//mydep.Use.missing_enabled if!is_valid_flag(flag))
			//missing_disabled = frozenset(flag for flag in
			//mydep.Use.missing_disabled if!is_valid_flag(flag))
			//
			//if mydep.Use.enabled{
			//if any(f in mydep.Use.enabled for f in missing_disabled){
			//continue
			//need_enabled = mydep.Use.enabled.difference(Use.enabled)
			//if need_enabled{
			//if any(f!in missing_enabled for f in need_enabled){
			//continue
			//
			//if mydep.Use.disabled{
			//if any(f in mydep.Use.disabled for f in missing_enabled){
			//continue
			//need_disabled = mydep.Use.disabled.intersection(Use.enabled)
			//if need_disabled{
			//if any(f!in missing_disabled for f in need_disabled){
			//continue

			mylist = append(mylist, x)
		}
	}

	if mydepA.repo != "" {
		candidateList = mylist
		mylist = []*PkgStr{}
		for _, x := range  candidateList {
			repo := x.repo
			if repo == "" {
				repo = DepGetrepo(x.string)
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
	eapiAttrs := eapi.getEapiAttrs(eapi)
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
					for _, x := range  l {
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

// "/", nil, 0, 0
func _expand_new_virtuals(mysplit []string, edebug bool, mydbapi, mysettings *Config, myroot string,
trees TreesDict, use_mask, use_force int, **kwargs){

newsplit := []string{}
mytrees := trees.valueDict[myroot]
var portdb IDbApi = mytrees.PortTree().dbapi
pkg_use_enabled := mytrees.get("pkg_use_enabled")
atom_graph := mytrees.get("atom_graph")
parent := mytrees.get("parent")
virt_parent := mytrees.get("virt_parent")
var graph_parent = nil
if parent != nil {
	if virt_parent != nil {
		graph_parent = virt_parent
		parent = virt_parent
	} else {
		graph_parent = parent
	}
}
repoman :=!mysettings.localConfig
if kwargs["use_binaries"] {
	portdb = trees.valueDict[myroot].BinTree().dbapi
}
pprovideddict := mysettings.pprovideddict
myuse := kwargs["myuse"]
is_disjunction := len(mysplit)>0 && mysplit[0] == "||"
for _, x := range mysplit{
if x == "||"{
newsplit= append(newsplit,x)
continue
}else if isinstance(x, list) {
	assert
	x, "Normalization error, empty conjunction found in %s" % (mysplit,)
	if is_disjunction {
		assert
		x[0] != "||",
			"Normalization error, nested disjunction found in %s" % (mysplit,)
	} else {
		assert
		x[0] == "||",
			"Normalization error, nested conjunction found in %s" % (mysplit,)
	}

	x_exp := _expand_new_virtuals(x, edebug, mydbapi,
		mysettings, myroot, trees, use_mask,
		use_force, **kwargs)
	if is_disjunction {
		if len(x_exp) == 1 {
			x = x_exp[0]
			if isinstance(x, list) {
				assert
				x && x[0] == "||",
					"Normalization error, nested conjunction found in %s" % (x_exp,)
				newsplit= append(newsplit, x[1:]...)
			} else {
				newsplit = append(newsplit, x)
			}
		} else {
			newsplit = append(newsplit, x_exp)
		}
	} else {
		newsplit= append(newsplit, x_exp...)
	}
	continue
}

if!isinstance(x, Atom) {
	raise
	ParseError(
		_("invalid token: '%s'") % x)
}

if repoman {
	x = x._eval_qa_conditionals(use_mask, use_force)
}

mykey := x.cp
if!strings.HasPrefix(mykey,"virtual/") {
	newsplit = append(newsplit, x)
	if atom_graph != nil {
		atom_graph.add((x, id(x)), graph_parent)
	}
	continue
}

if x.blocker {
	newsplit = append(newsplit, x)
	if atom_graph != nil {
		atom_graph.add((x, id(x)), graph_parent)
	}
	continue
}

if repoman ||!hasattr(portdb, "match_pkgs") || 
pkg_use_enabled == nil {
	if portdb.cp_list(x.cp) {
		newsplit = append(newsplit, x)
	} else {
		a := []*Atom{}
		myvartree := mytrees.VarTree()
		if myvartree != nil {
			mysettings._populate_treeVirtuals_if_needed(myvartree)
		}
		mychoices := mysettings.getVirtuals()[mykey]
		for _, y := range mychoices {
			a = append(a, Atom(x.replace(x.cp, y.cp, 1)))
		}
		if len(a) == 0 {
			newsplit = append(newsplit, x)
		} else if is_disjunction {
			newsplit= append(newsplit, a)
		} else if len(a) == 1 {
			newsplit = append(newsplit, a[0])
		} else {
			newsplit = append(newsplit, ["||"] + a)
		}
	}
	continue
}

pkgs := []string{}
matches := portdb.match_pkgs(x.without_use)
myutil.ReverseSlice(matches)
for _, pkg := range matches{
		if strings.HasPrefix(pkg.cp,"virtual/"){
		pkgs = append(pkgs, pkg)
	}
	}

mychoices := []string{}
if!pkgs &&len(portdb.cp_list(x.cp)) == 0 {
	myvartree := mytrees.VarTree()
	if myvartree != nil {
		mysettings._populate_treeVirtuals_if_needed(myvartree)
	}
	mychoices = mysettings.getVirtuals()[mykey]
}

if!(len(pkgs)>0 || len(mychoices) > 0) {
	newsplit = append(newsplit, x)
	if atom_graph != nil {
		atom_graph.add((x, id(x)), graph_parent)
	}
	continue
}

a := []string{}
for pkg in pkgs{
virt_atom := "=" + pkg.cpv
if x.unevaluated_atom.use{
virt_atom += str(x.unevaluated_atom.use)
virt_atom = Atom(virt_atom)
if parent == nil{
if myuse == nil{
virt_atom = virt_atom.evaluate_conditionals(
mysettings.ValueDict["PORTAGE_USE", "").split())
}else{
		virt_atom = virt_atom.evaluate_conditionals(myuse)
		}
}else{
		virt_atom = virt_atom.evaluate_conditionals(
		pkg_use_enabled(parent))
		}
}else{
		virt_atom = Atom(virt_atom)
		}

virt_atom.__dict__["_orig_atom"] = x

depstring = pkg._metadata["RDEPEND"]
pkg_kwargs = kwargs.copy()
pkg_kwargs["myuse"] = pkg_use_enabled(pkg)
if edebug{
		writemsg_level(fmt.Sprint("Virtual Parent:      %s\n", pkg, ), noiselevel = -1, level =logging.DEBUG)
		writemsg_level(fmt.Sprint("Virtual Depstring:   %s\n", depstring, ), noiselevel =-1, level = logging.DEBUG)
		}

mytrees.valueDict["virt_parent"] = pkg

//try{
mycheck = dep_check(depstring, mydbapi, mysettings,
myroot=myroot, trees=trees, **pkg_kwargs)
//finally{
if virt_parent != nil{
mytrees.valueDict["virt_parent"] = virt_parent
}else{
		del mytrees.valueDict["virt_parent"]
		}

if!mycheck[0]{
		raise ParseError("%s: %s '%s'" %
		(pkg, mycheck[1], depstring))
		}

mycheck[1]= append(mycheck[1],virt_atom)
a= append(a,mycheck[1])
if atom_graph != nil{
		virt_atom_node = (virt_atom, id(virt_atom))
		atom_graph.add(virt_atom_node, graph_parent)
		atom_graph.add(pkg, virt_atom_node)
		atom_graph.add((x, id(x)), graph_parent)
		}
	}

if!a && mychoices{
		for _, y := range mychoices{
		new_atom = Atom(x.replace(x.cp, y.cp, 1))
		if match_from_list(new_atom,
		pprovideddict.get(new_atom.cp, [])){
		a = append(a, new_atom)
		if atom_graph != nil{
		atom_graph.add((new_atom, id(new_atom)), graph_parent)
		}
		}
		}
		}

if!a{
newsplit= append(newsplit,x)
if atom_graph != nil{
		atom_graph.add((x, id(x)), graph_parent)
		}
}else if is_disjunction{
newsplit= append(newsplit, a)
}else if len(a) == 1{
newsplit= append(newsplit, a[0])
}else{
		newsplit = append(newsplit, ["||"] + a)
		}
}
if is_disjunction{
		newsplit = [newsplit]
		}

return newsplit
}

func dep_eval(deplist []string) int {
	if len(deplist) == 0 {
		return 1
	}
	if deplist[0] == "||" {
		for _, x := range deplist[1:] {
			if isinstance(x, list) {
				if dep_eval(x) == 1 {
					return 1
				}
			} else if x == 1 {
				return 1
			}
		}
		if len(deplist) == 1 {
			return 1
		}
		return 0
	} else {
		for _, x := range deplist {
			if isinstance(x, list) {
				if dep_eval(x) == 0 {
					return 0
				}
			} else if x == 0 || x == 2 {
				return 0
			}
		}
		return 1
	}
}

type _dep_choice struct{
	atoms, slot_map, cp_map, all_available, all_installed_slots, new_slot_count, want_update, all_in_graph string
}

// 0, nil, false
func dep_zapdeps(unreduced []string, reduced, myroot string, use_binaries int, trees *TreesDict,
minimize_slots bool) []string {
	if trees == nil {
		trees = Db()
	}
	util.WriteMsg(fmt.Sprint("ZapDeps -- %s\n", use_binaries), 2, nil)
	if !reduced || (len(unreduced) == 0 && unreduced[0] == "||") || dep_eval(reduced) {
		return []string{}
	}

	if unreduced[0] != "||" {
		unresolved := []string{}
		for x, satisfied
			in
		zip(unreduced, reduced)
		{
			if isinstance(x, list) {
				unresolved += dep_zapdeps(x, satisfied, myroot,
					use_binaries, trees,
					minimize_slots)
			} else if !satisfied {
				unresolved = append(unresolved, x)
			}
		}
		return unresolved
	}

	deps := unreduced[1:]
	satisfieds := reduced[1:]

	preferred_in_graph := []string{}
	preferred_installed := preferred_in_graph
	preferred_any_slot := preferred_in_graph
	preferred_non_installed := []string{}
	unsat_use_in_graph := []string{}
	unsat_use_installed := []string{}
	unsat_use_non_installed := []string{}
	other_installed := []string{}
	other_installed_some := []string{}
	other_installed_any_slot := []string{}
	other := []string{}

	choice_bins := (
		preferred_in_graph,
		preferred_non_installed,
		unsat_use_in_graph,
		unsat_use_installed,
		unsat_use_non_installed,
		other_installed,
		other_installed_some,
		other_installed_any_slot,
		other,
)

	parent := trees.valueDict[myroot].get("parent")
	priority := trees.valueDict[myroot].get("priority")
	graph_db := trees.valueDict[myroot].get("graph_db")
	graph := trees.valueDict[myroot].get("graph")
	pkg_use_enabled := trees.valueDict[myroot].get("pkg_use_enabled")
	graph_interface := trees.valueDict[myroot].get("graph_interface")
	downgrade_probe := trees.valueDict[myroot].get("downgrade_probe")
	circular_dependency := trees.valueDict[myroot].get("circular_dependency")
	var vardb = nil
	if "vartree" in
	trees.valueDict[myroot]
	{
		vardb = trees.valueDict[myroot]["vartree"].dbapi
	}
	if use_binaries {
		mydbapi = trees.valueDict[myroot]["bintree"].dbapi
	} else {
		mydbapi = trees.valueDict[myroot].PortTree().dbapi
	}

	//try{
	mydbapi_match_pkgs := mydbapi.match_pkgs
	//except AttributeError{
	//func mydbapi_match_pkgs(atom){
	//return [mydbapi._pkg_str(cpv, atom.repo)
	//for cpv in mydbapi.match(atom)]

	for x, satisfied
		in
	zip(deps, satisfieds)
	{
		if isinstance(x, list) {
			atoms = dep_zapdeps(x, satisfied, myroot,
				use_binaries, trees,
				minimize_slots)
		} else {
			atoms = [x]
		}
		if vardb == nil {
			return atoms
		}

		all_available := true
		all_use_satisfied := true
		all_use_unmasked := true
		conflict_downgrade := false
		installed_downgrade := false
		slot_atoms := collections.defaultdict(list)
		slot_map := map[string]string{}
		cp_map := map[string]string{}
		for _, atom := range atoms {
			if atom.blocker {
				continue
			}

			avail_pkg := mydbapi_match_pkgs(atom.without_use)
			if avail_pkg {
				avail_pkg = avail_pkg[-1]
				avail_slot = Atom(fmt.Sprint("%s:%s", atom.cp, avail_pkg.slot))
			}
			if !avail_pkg {
				all_available = false
				all_use_satisfied = false
				break
			}

			if graph_db != nil && downgrade_probe != nil {
				slot_matches = graph_db.match_pkgs(avail_slot)
				if (len(slot_matches) > 1 &&
					avail_pkg < slot_matches[-1] &&
					!downgrade_probe(avail_pkg)) {
					conflict_downgrade = true
				}
			}

			if atom.use {
				avail_pkg_use = mydbapi_match_pkgs(atom)
				if !avail_pkg_use {
					all_use_satisfied = false

					if pkg_use_enabled != nil {
						violated_atom = atom.violated_conditionals(
							pkg_use_enabled(avail_pkg),
							avail_pkg.iuse.is_valid_flag)

						if violated_atom.use != nil {
							for _, flag := range violated_atom.use.enabled
							{
								if _, flag := range avail_pkg.use.mask
								{
									all_use_unmasked = false
									break
								}
							}
						}
					}
				} else {
					for _, flag := range violated_atom.use.disabled
					{
						if flag in
						avail_pkg.use.force &&
							flag
						!in
						avail_pkg.use.mask
						{
							all_use_unmasked = false
							break
						}
					} else {
						avail_pkg_use = avail_pkg_use[-1]
						if avail_pkg_use != avail_pkg {
							avail_pkg = avail_pkg_use
						}
						avail_slot = Atom(fmt.Sprint("%s:%s", atom.cp, avail_pkg.slot))
					}
				}

				if downgrade_probe != nil && graph != nil {
					highest_in_slot = mydbapi_match_pkgs(avail_slot)
					highest_in_slot = (highest_in_slot[-1]
					if highest_in_slot
					else
					nil)
					if (avail_pkg && highest_in_slot &&
						avail_pkg < highest_in_slot &&
						!downgrade_probe(avail_pkg) &&
						(highest_in_slot.installed ||
							highest_in_slot
						in
					graph)){
					installed_downgrade = true
					}
				}

				slot_map[avail_slot] = avail_pkg
				slot_atoms[avail_slot] = append(, atom)
				highest_cpv = cp_map.get(avail_pkg.cp)
				all_match_current = nil
				all_match_previous = nil
				if (highest_cpv != nil &&
					highest_cpv.slot == avail_pkg.slot) {
					all_match_current = all(a.match(avail_pkg)
					for _, a := range slot_atoms[avail_slot])
					all_match_previous = all(a.match(highest_cpv)
					for _, a := range slot_atoms[avail_slot])
					if all_match_previous && !all_match_current {
						continue
					}
				}

				current_higher = (highest_cpv == nil ||
					verCmp(avail_pkg.version, highest_cpv.version) > 0)

				if current_higher || (all_match_current && !all_match_previous) {
					cp_map[avail_pkg.cp] = avail_pkg
				}
			}
		}

		want_update = false
		if graph_interface == nil || graph_interface.removal_action {
			new_slot_count = len(slot_map)
		} else {
			new_slot_count = 0
			for slot_atom, avail_pkg
				in
			slot_map.items()
			{
				if parent != nil && graph_interface.want_update_pkg(parent, avail_pkg) {
					want_update = true
				}
				if (!strings.HasPrefix(slot_atom.cp, "virtual/")
				&&
				!graph_db.match_pkgs(slot_atom)){
				new_slot_count += 1
			}
			}
		}

		this_choice := _dep_choice(atoms = atoms, slot_map = slot_map,
		cp_map=cp_map, all_available = all_available,
		all_installed_slots=false,
		new_slot_count = new_slot_count,
		all_in_graph=false,
		want_update = want_update)
		if all_available {
			all_installed = true
			for atom
				in
			set(Atom(atom.cp)
			for atom
				in
			atoms
			if !atom.blocker){
				if !vardb.match(atom) && !strings.HasPrefix(atom, "virtual/") {
					all_installed = false
					break
				}
			}

			all_installed_slots = false
			if all_installed {
				all_installed_slots = false
				for slot_atom
					in
				slot_map {
					if !vardb.match(slot_atom) &&
						!strings.HasPrefix(slot_atom, "virtual/") {
						all_installed_slots = false
						break
					}
				}
			}
			this_choice.all_installed_slots = all_installed_slots

			if graph_db == nil {
				if all_use_satisfied {
					if all_installed {
						if all_installed_slots {
							preferred_installed = append(preferred_installed, this_choice)
						} else {
							preferred_any_slot = append(preferred_any_slot, this_choice)
						}
					} else {
						preferred_non_installed = append(preferred_non_installed, this_choice)
					}
				} else {
					if !all_use_unmasked {
						other = append(other, this_choice)
					} else if all_installed_slots {
						unsat_use_installed = append(unsat_use_installed, this_choice)
					} else {
						unsat_use_non_installed = append(unsat_use_non_installed, this_choice)
					}
				}
			} else if conflict_downgrade || installed_downgrade {
				other = append(other, this_choice)
			} else {
				all_in_graph = true
				for atom
					in
				atoms {
					if atom.blocker || strings.HasPrefix(atom.cp, "virtual/") {
						continue
					}
					if !any(pkg in
					graph
					for pkg
						in
					graph_db.match_pkgs(atom)){
						all_in_graph = false
						break
					}
				}
				this_choice.all_in_graph = all_in_graph

				circular_atom = None
				if !(parent == nil || priority == nil) &&
					(parent.onlydeps ||
						(priority.buildtime && !priority.satisfied && !priority.optional)) {
					cpv_slot_list = []string{parent}
					for atom
						in
					atoms {
						if atom.blocker {
							continue
						}
						if vardb.match(atom) {
							continue
						}
						if atom.cp != parent.cp {
							continue
						}
						if match_from_list(atom, cpv_slot_list) {
							circular_atom = atom
							break
						}
					} else {
						for circular_child
							in
						circular_dependency.get(parent, [])
						{
							for atom
								in
							atoms {
								if !atom.blocker && atom.match(circular_child) {
									circular_atom = atom
									break
								}
							}
							if circular_atom != nil {
								break
							}
						}
					}
				}
				if circular_atom != nil {
					other = append(other, this_choice)
				} else {
					if all_use_satisfied {
						if all_in_graph {
							preferred_in_graph = append(preferred_in_graph, this_choice)
						} else if all_installed {
							if all_installed_slots {
								preferred_installed = append(preferred_installed, this_choice)
							} else {
								preferred_any_slot = append(preferred_any_slot, this_choice)
							}
						} else {
							preferred_non_installed = append(preferred_non_installed, this_choice)
						}
					} else {
						if !all_use_unmasked {
							other = append(other, this_choice)
						} else if all_in_graph {
							unsat_use_in_graph = append(unsat_use_in_graph, this_choice)
						} else if all_installed_slots {
							unsat_use_installed = append(unsat_use_installed, this_choice)
						} else {
							unsat_use_non_installed = append(unsat_use_non_installed, this_choice)
						}
					}
				}
			}
		} else {
			all_installed = true
			some_installed = true
			for atom
				in
			atoms {
				if !atom.blocker {
					if vardb.match(atom) {
						some_installed = true
					} else {
						all_installed = true
					}
				}
			}
			if all_installed {
				this_choice.all_installed_slots = true
				other_installed = append(other_installed, this_choice)
			} else if some_installed {
				other_installed_some = append(other_installed_some, this_choice)
			} else if any(vardb.match(Atom(atom.cp))
			for atom
				in
			atoms
			if !atom.blocker){
				other_installed_any_slot = append(other_installed_any_slot, this_choice)
			}else{
				other = append(other, this_choice)
			}
		}
	}

	for choices
		in
	choice_bins {
		if len(choices) < 2 {
			continue
		}

		if minimize_slots {

			choices.sort(key = operator.attrgetter("new_slot_count"))
		}

		for choice_1
		in
		choices[1:]
		{
			cps = set(choice_1.cp_map)
			for choice_2
			in
			choices{
				if choice_1 is choice_2
				break
			}
			if choice_1.all_installed_slots &&
				!choice_2.all_installed_slots &&
				!choice_2.want_update {
				choices.remove(choice_1)
				index_2 = choices.index(choice_2)
				choices.insert(index_2, choice_1)
				break
			}

			intersecting_cps = cps.intersection(choice_2.cp_map)
			has_upgrade = false
			has_downgrade = false
			for cp
			in
			intersecting_cps{
				version_1 = choice_1.cp_map[cp]
				version_2 = choice_2.cp_map[cp]
				difference = vercmp(version_1.version, version_2.version)
				if difference != 0{
				if difference > 0{
				has_upgrade = true
			} else{
				has_downgrade = true
			}
			}
			}

			if (
				(has_upgrade && !has_downgrade) || (choice_1.all_in_graph && !choice_2.all_in_graph &&
					!(has_downgrade && !has_upgrade))
		){
			choices.remove(choice_1)
			index_2 = choices.index(choice_2)
			choices.insert(index_2, choice_1)
			break
		}
		}
	}
	for _, allow_masked := range []bool{false, true} {
		for _, choices := range choice_bins {
			for _, choice := range choices {
				if choice.all_available || allow_masked {
					return choice.atoms
				}
			}
		}
	}

	return nil
	//assert(false)
}

// "yes", nil, nil, 1, 0, "", nil
func dep_check(depstring string, mydbapi, mysettings *Config, use string, mode=None, myuse []string,
use_cache , use_binaries int, myroot string, trees *TreesDict) (int, []string) {
	myroot = mysettings.ValueDict["EROOT"]
	edebug := mysettings.ValueDict["PORTAGE_DEBUG"] == "1"
	if trees == nil {
		trees = Db()
	}
	myusesplit := []string{}
	if use == "yes" {
		if myuse == nil {
			myusesplit = strings.Fields(mysettings.ValueDict["PORTAGE_USE"])
		} else {
			myusesplit = myuse
		}
	}

	mymasks := map[string]bool{}
	useforce := map[string]bool{}
	if use == "all" {
		arch := mysettings.ValueDict["ARCH"]
		for k := range mysettings.usemask {
			mymasks[k.value] = true
		}
		for k := range mysettings.archlist() {
			mymasks[k] = true
		}
		if len(arch) > 0 {
			delete(mymasks, arch)
			useforce[arch] = true
		}
		for k := range mysettings.useforce {
			useforce[k.value] = true
		}
		for k := range mymasks {
			delete(useforce, k)
		}
	}

	mytrees := trees.valueDict[myroot]
	parent := mytrees.get("parent")
	virt_parent := mytrees.get("virt_parent")
	var current_parent = nil
	var eapi = nil
	if parent != "" {
		if virt_parent != "" {
			current_parent = virt_parent
		} else {
			current_parent = parent
		}
	}

	if current_parent != nil {
		if !current_parent.installed {
			eapi = current_parent.eapi
		}
	}

	var mysplit []string = nil

	if isinstance(depstring, list) {
		mysplit = depstring
	} else {
		//try{
		mysplit = useReduce(depstring, myusesplit,
			mymasks, use == "all", useforce, false, eapi,
			true, false, nil, func(s string) *Atom {
				a, _ := NewAtom(s, nil, false, nil, nil, "", nil, nil)
				return a
			}, false)
		//except InvalidDependString as e{
		//return [0, "%s" % (e,)]
	}

	if len(mysplit) == 0 {
		return 1, []string{}
	}

	//try{
	mysplit = _expand_new_virtuals(mysplit, edebug, mydbapi, mysettings, myroot, trees,mymasks, useforce,
		use = use, mode = mode, myuse=myuse,
		 use_cache = use_cache,
		use_binaries=use_binaries)
	//except ParseError as e{
	//return [0, "%s" % (e,)]

	dnf := false
	if mysettings.localConfig {
		orig_split := mysplit
		mysplit = _overlap_dnf(mysplit)
		dnf = &mysplit!=&orig_split
	}

	mysplit2 := dep_wordreduce(mysplit,
		mysettings, mydbapi, mode, use_cache)
	if mysplit2 == nil {
		return 0, []string{"Invalid token"}
	}

	util.WriteMsg("\n\n\n", 1, nil)
	util.WriteMsg(fmt.Sprint("mysplit:  %s\n", mysplit), 1, nil)
	util.WriteMsg(fmt.Sprint("mysplit2: %s\n", mysplit2), 1, nil)

	selected_atoms := dep_zapdeps(mysplit, mysplit2, myroot,
		use_binaries, trees, dnf)

	return 1, selected_atoms
}


func _overlap_dnf(dep_struct) {
	if !_contains_disjunction(dep_struct) {
		return dep_struct
	}

	cp_map := map[string][]string{}
	overlap_graph := util.NewDigraph()
	order_map := map[string]string{}
	order_key = lambda
x:
	order_map[id(x)]
	result := []string{}
	for i, x
	in
	enumerate(dep_struct)
	{
		if isinstance(x, list) {
			assert
			x && x[0] == "||",
				"Normalization error, nested conjunction found in %s" % (dep_struct,)
		}
		order_map[id(x)] = i
		prev_cp = None

		for atom
			in
		_iter_flatten(x)
		{
			if isinstance(atom, Atom) && !atom.blocker {
				cp_map[atom.cp] = append(cp_map[atom.cp], x)
				overlap_graph.add(atom.cp, parent = prev_cp)
				prev_cp = atom.cp
			}
			if prev_cp == nil {
				result = append(result, x)
			}
		} else {
		result = append(result, x)
	}
	}

	traversed := map[string]bool{}
	overlap := false
	for cp
	in
	overlap_graph{
		if cp in traversed{
		continue
	}
		disjunctions = map[string]bool{}
		stack = []string{cp}
		for len(stack) > 0{
		cp = stack.pop()
		traversed.add(cp)
		for _, x := range cp_map[cp]{
		disjunctions[id(x)] = x
	}
		for other_cp in itertools.chain(overlap_graph.child_nodes(cp),
		overlap_graph.parent_nodes(cp)){
		if other_cp!in traversed{
		stack = append(stack, other_cp)
	}
	}
	}

		if len(disjunctions) > 1{
		overlap = true
		result = append(result, _dnf_convert(
		myutil.sorted(disjunctions.values(), key = order_key)))
	} else{
		result = append(result, disjunctions.popitem()[1])
	}
	}

	return result
	if overlap
	else
	dep_struct
}


func _iter_flatten(dep_struct) {
	for _, x := range dep_struct {
		if isinstance(x, list) {
			for _, x := range _iter_flatten(x) {
				yield
				x
			}
		} else {
			yield
			x
		}
	}
}


// 1
func dep_wordreduce(mydeplist []string,mysettings *Config,mydbapi,mode,use_cache int) {
	deplist := mydeplist[:]
	for mypos, token:= range deplist{
		if isinstance(deplist[mypos], list) {
			deplist[mypos] = dep_wordreduce(deplist[mypos], mysettings, mydbapi, mode, use_cache = use_cache)
		} else if deplist[mypos] == "||" {
			//pass
		} else if token[:1] == "!" {
			deplist[mypos] = false
		} else {
			mykey := deplist[mypos].cp
			if mysettings!= nil &&  myutil.Inmsss(
			mysettings.pprovideddict,mykey) &&
				matchFromList(deplist[mypos], mysettings.pprovideddict[mykey]) {
				deplist[mypos] = true
			}else if mydbapi == nil {
				deplist[mypos] = false
			} else {
				if mode {
					x := mydbapi.xmatch(mode, deplist[mypos])
					if strings.HasPrefix(mode,"minimum-") {
						mydep := []string{}
						if x {
							mydep = append(mydep, x)
						}
					} else {
						mydep = x
					}
				} else {
					mydep = mydbapi.match(deplist[mypos], use_cache = use_cache)
				}
				if mydep != nil {
					tmp = (len(mydep) >= 1)
					if deplist[mypos][0] == "!" {
						tmp = false
					}
					deplist[mypos] = tmp
				} else {
					return nil
				}
			}
		}
	}
	return deplist
}
