package dep

import (
	"errors"
	"fmt"
	"github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
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
	RepoNameRe     = regexp.MustCompile("^" + repoName + "$")
	slotDepReCache = map[bool]*regexp.Regexp{}
	usedepReCache  = map[bool]*regexp.Regexp{}
	useflagReCache = map[bool]*regexp.Regexp{}
)

func getSlotDepRe(attrs eapi.EapiAttrs) *regexp.Regexp {
	cacheKey := attrs.SlotOperator
	slotRe, ok := slotDepReCache[cacheKey]
	if ok {
		return slotRe
	}
	s := ""
	if attrs.SlotOperator {
		s = versions.Slot + "?(\\*|=|/" + versions.Slot + "=?)?"
	} else {
		s = versions.Slot
	}
	slotRe = regexp.MustCompile("^" + s + "$")
	slotDepReCache[cacheKey] = slotRe
	return slotRe
}

func _match_slot[T interfaces.ISettings](atom *Atom[T], pkg *versions.PkgStr[T]) bool {
	if pkg.Slot == atom.slot {
		if atom.subSlot == "" {
			return true
		}
		if atom.subSlot == pkg.SubSlot {
			return true
		}
	}
	return false
}

func matchSlot[T interfaces.ISettings](atom *Atom[T], pkg *versions.PkgStr[T]) bool {
	if pkg.Slot == atom.slot {
		if atom.subSlot == "" {
			return true
		} else if atom.subSlot == pkg.SubSlot {
			return true
		}
	}
	return false
}

var atomRe *regexp.Regexp

func getAtomRe(attrs eapi.EapiAttrs) *regexp.Regexp {
	if atomRe != nil {
		return atomRe
	}

	cp_re := versions.Cp
	cpv_re := versions.Cpv

	_atom_re := regexp.MustCompile(
		"^(?P<without_use>(?:" + "(?P<op>" + op + cpv_re + ")|" +
			"(?P<star>=" + cpv_re + "\\*)|" + "(?P<simple>" + cp_re + "))" +
			"(" + slotSeparator + slotLoose + ")?" + repo + ")(" + use + ")?$")
	return _atom_re
}

var _atom_wildcard_re *regexp.Regexp

func getAtomWildcardRe(attrs eapi.EapiAttrs) *regexp.Regexp {
	if _atom_wildcard_re != nil {
		return _atom_wildcard_re
	}
	pkg_re := "[\\w+*][\\w+*-]*?"

	_atom_wildcard_re = regexp.MustCompile(
		"((?P<simple>(" + extendedCat + ")/(" + pkg_re + "(-" +
			versions.Vr + ")?))" + "|(?P<star>=((" + extendedCat +
			")/(" + pkg_re + "))-(?P<version>\\*\\w+\\*)))" + "(:(?P<slot>" +
			slotLoose + "))?(" + repoSeparator + "(?P<repo>" + repoName + "))?$")
	return _atom_wildcard_re
}

var usedepRe *regexp.Regexp

func getUsedepRe(attrs eapi.EapiAttrs) *regexp.Regexp {
	if usedepRe != nil {
		return usedepRe
	}

	usedepRe = regexp.MustCompile("^(?P<prefix>[!-]?)(?P<flag>[A-Za-z0-9][A-Za-z0-9+_@-]*)(?P<default>(\\(\\+\\)|\\(\\-\\))?)(?P<suffix>[?=]?)$")
	return usedepRe
}

var _useflag_re *regexp.Regexp

func GetUseflagRe(eapi1 string) *regexp.Regexp {
	if _useflag_re != nil {
		return _useflag_re
	}

	_useflag_re = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9+_@-]*$")
	return _useflag_re
}

func cpvequal(cpv1, cpv2 string) bool {
	c1 := versions.NewPkgStr(cpv1, nil, nil, "", "", "", 0, 0, "", 0, nil)
	split1 := c1.CpvSplit
	c2 := versions.NewPkgStr(cpv2, nil, nil, "", "", "", 0, 0, "", 0, nil)
	split2 := c2.CpvSplit
	if split1[0] != split2[0] || split1[1] != split2[1] {
		return false
	}
	v, _ := versions.VerCmp(cpv1, cpv2)
	return v == 0
}

func ParenEncloses[T string | []string | interface {
	UnevaluatedAtom() *Atom[interfaces.ISettings]
}](myList []T, unevaluatedAtom, opconvert bool) string {
	myStrParts := []string{}
	for _, x := range myList {
		switch y := x.(type) {
		case []string:
			if opconvert && len(y) > 0 && y[0] != "||" {
				myStrParts = append(myStrParts, fmt.Sprintf("%s ( %s )", y[0], ParenEncloses(y[1:], false, false)))
			} else {
				myStrParts = append(myStrParts, fmt.Sprintf("( %s )", ParenEncloses(y, false, false)))
			}
		case string:
			myStrParts = append(myStrParts, y)
		case interface {
			UnevaluatedAtom() *Atom[interfaces.ISettings]
		}:
			myStrParts = append(myStrParts, y.UnevaluatedAtom().Value)
		}
	}
	return strings.Join(myStrParts, " ")
}

func UseReduceCached[T interfaces.ISettings](depstr string, uselist map[string]bool, masklist []string, matchall bool, excludeall []string, isSrcUri bool, eapi1 string, opconvert, flat bool, isValidFlag func(string) bool, tokenClass func(string) *Atom[T], matchnone bool, subset map[string]bool) []string {
	if opconvert && flat {
		// ValueError("portage.dep.use_reduce: 'opconvert' and "flat' are mutually exclusive")
	}
	if matchall && matchnone {
		// ValueError("portage.dep.use_reduce: 'opconvert' and 'flat' are mutually exclusive")
	}
	EapiAttrs := eapi.GetEapiAttrs(eapi1)
	useFlagRe := GetUseflagRe(eapi1)

	isActive := func(conditional string) (bool, error) {
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

		if isNegated && myutil.Ins(excludeall, flag) {
			return false, nil
		}
		if myutil.Ins(masklist, flag) {
			return false, nil
		}
		if matchall {
			return true, nil
		}
		if matchnone {
			return false, nil
		}
		return (uselist[flag] && !isNegated) || (!uselist[flag] && isNegated), nil
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
		} else if token == ")" {
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
						if ok, err := isActive(stack[level][len(stack[level])-1]); ok && err == nil {
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
					if stack[level][len(stack[level])-1] == "||" && len(l) == 0 {
						if !EapiAttrs.EmptyGroupsAlwaysTrue {
							l = append(l, "__const__/empty-any-of")
						}
						stack[level] = stack[level][:len(stack[level])-1]
					} else if strings.HasSuffix(stack[level][len(stack[level])-1], "?") {
						if ok, err := isActive(stack[level][len(stack[level])-1]); !ok && err == nil {
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
			if !EapiAttrs.SrcUriArrows {
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
				if isSrcUri {
					if !EapiAttrs.SelectiveSrcUriRestriction && (strings.HasPrefix(token, "fetch+") || strings.HasPrefix(token, "mirror+")) {
						//raise InvalidDependString(_(
						//		"Selective fetch/mirror restriction not allowed "
						//"in EAPI %s: token %s")% (eapi, pos + 1))
					}
				} else if tokenClass != nil {
					t := tokenClass(token) // eapi=eapi, is_valid_flag=is_valid_flag
					if !matchall {
						token = t.EvaluateConditionals(uselist).Value
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

// map[string]bool{}, []string{}, false, []string{}, false, "", false, false, nil, nil, false, nil
func UseReduce[T interfaces.ISettings](depstr string, uselist map[string]bool, masklist []string, matchall bool, excludeall []string, isSrcUri bool, eapi1 string, opconvert, flat bool, isValidFlag func(string) bool, tokenClass func(string) *Atom[T], matchnone bool, subset map[string]bool) []string {
	result := UseReduceCached(
		depstr,
		uselist,
		masklist,
		matchall,
		excludeall,
		isSrcUri,
		eapi1,
		opconvert,
		flat,
		isValidFlag,
		tokenClass,
		matchnone,
		subset,
	)

	return result[:]
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
	EapiAttrs                                                    *eapi.EapiAttrs
	missingEnabled, missingDisabled, disabled, enabled, required map[string]bool
	conditional                                                  *conditionalClass
	tokens                                                       []string
	conditionalStrings                                           map[string]string
}

// nil, nil, nil, nil, nil, nil
func NewUseDep(use []string, EapiAttrs *eapi.EapiAttrs, enabledFlags, disabledFlags, missingEnabled, missingDisabled map[string]bool, conditional map[string]map[string]bool, required map[string]bool) *useDep {
	u := &useDep{conditionalStrings: conditionalStrings}
	u.EapiAttrs = EapiAttrs
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
	usedepRe := getUsedepRe(*u.EapiAttrs)

	for _, x := range use {
		if !usedepRe.MatchString(x) {
			//raise InvalidAtom(_("Invalid use dep: '%s'") % (x,))
		}
		operator := myutil.GetNamedRegexp(usedepRe, x, "prefix") + myutil.GetNamedRegexp(usedepRe, x, "suffix")
		flag := myutil.GetNamedRegexp(usedepRe, x, "flag")
		defaults := myutil.GetNamedRegexp(usedepRe, x, "default")
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

	if len(conditional) > 0 {
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

func (u *useDep) evaluateConditionals(use map[string]bool) *useDep {
	enabledFlags := myutil.CopyMapT(u.enabled)
	disabledFlags := myutil.CopyMapT(u.disabled)
	tokens := []string{}
	usedepRe := getUsedepRe(*u.EapiAttrs)
	for _, x := range u.tokens {
		operator := myutil.GetNamedRegexp(usedepRe, x, "prefix") + myutil.GetNamedRegexp(usedepRe, x, "suffix")
		flag := myutil.GetNamedRegexp(usedepRe, x, "flag")
		defaults := myutil.GetNamedRegexp(usedepRe, x, "default")
		if operator == "?" {
			if use[flag] {
				enabledFlags[flag] = true
				tokens = append(tokens, flag+defaults)
			}
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
	return NewUseDep(tokens, u.EapiAttrs, enabledFlags, disabledFlags, u.missingEnabled, u.missingDisabled, nil, u.required)
}

func (u *useDep) violatedConditionals(otherUse map[string]bool, isValidFlag func(string) bool, parentUse map[string]bool) *useDep {
	if parentUse == nil && u.conditional != nil {
		//raise InvalidAtom("violated_conditionals needs 'parent_use'" +
		//" parameter for conditional flags.")
	}
	enabledFlags := myutil.CopyMapT(u.enabled)
	disabledFlags := myutil.CopyMapT(u.disabled)
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

	usedepRe := getUsedepRe(*u.EapiAttrs)
	for _, x := range u.tokens {
		operator := myutil.GetNamedRegexp(usedepRe, x, "prefix") + myutil.GetNamedRegexp(usedepRe, x, "suffix")
		flag := myutil.GetNamedRegexp(usedepRe, x, "flag")
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
	return NewUseDep(tokens, u.EapiAttrs, enabledFlags, disabledFlags, u.missingEnabled, u.missingDisabled, conditional, u.required)
}

func (u *useDep) evalQaConditionals(useMask, useForce map[string]bool) *useDep {
	enabledFlags := myutil.CopyMapT(u.enabled)
	disabledFlags := myutil.CopyMapT(u.disabled)
	tokens := []string{}
	usedepRe := getUsedepRe(*u.EapiAttrs)
	for _, x := range u.tokens {
		operator := myutil.GetNamedRegexp(usedepRe, x, "prefix") + myutil.GetNamedRegexp(usedepRe, x, "suffix")
		flag := myutil.GetNamedRegexp(usedepRe, x, "flag")
		defaults := myutil.GetNamedRegexp(usedepRe, x, "default")
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
	return NewUseDep(tokens, u.EapiAttrs, enabledFlags, disabledFlags, u.missingEnabled, u.missingDisabled, nil, u.required)
}

type overlap struct {
	forbid bool
}

// false
func newOverlap(forbid bool) *overlap {
	return &overlap{forbid: forbid}
}

type blocker struct {
	overlap *overlap
}

// false
func newBlocker(forbidOverlap bool) *blocker {
	return &blocker{overlap: newOverlap(forbidOverlap)}
}

type Atom[T interfaces.ISettings] struct {
	// inherit
	Value string

	// class
	ispackage, soname bool

	// object
	extendedSyntax                                                 bool
	buildId                                                        int
	Blocker                                                        *blocker
	slotOperator, subSlot, Repo, slot, eapi, Cp, version, Operator string
	cpv                                                            *versions.PkgStr[T]
	Use                                                            *useDep
	withoutUse, unevaluatedAtom                                    *Atom[T]
}

//s, nil, false, nil, nil, "", nil, nil
func NewAtom[T interfaces.ISettings](s string, unevaluatedAtom *Atom[T], allowWildcard bool, allowRepo *bool, _use *useDep, eapi1 string, isValidFlag func(string) bool, allowBuildId *bool) (*Atom[T], error) {
	a := &Atom[T]{Value: s, ispackage: true, soname: false}
	EapiAttrs := eapi.GetEapiAttrs(eapi1)
	atomRe := getAtomRe(EapiAttrs)
	a.eapi = eapi1
	if eapi1 != "" {
		allowRepo = &EapiAttrs.RepoDeps
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
			atomRe := getAtomWildcardRe(EapiAttrs)
			if !atomRe.MatchString(s) {
				return nil, errors.New("InvalidAtom") // InvalidAtom(self)
			}
			if myutil.GetNamedRegexp(atomRe, s, "star") != "" {
				op = "=*"
				ar := atomRe.SubexpNames()
				base := 0
				for k, v := range ar {
					if v == "star" {
						base = k
					}
				}
				cp = atomRe.FindAllString(s, -1)[base+1]
				cpv = myutil.GetNamedRegexp(atomRe, s, "star")[1:]
				extendedVersion = atomRe.FindAllString(s, -1)[base+4]
			} else {
				op = ""
				cp = myutil.GetNamedRegexp(atomRe, s, "simple")
				cpv = cp
				if len(atomRe.FindAllString(s, -1)) >= 4 {
					return nil, errors.New("InvalidAtom")
				}
			}
			if !strings.Contains(cpv, "**") {
				return nil, errors.New("InvalidAtom")
			}
			slot = myutil.GetNamedRegexp(atomRe, s, "slot")
			repo = myutil.GetNamedRegexp(atomRe, s, "repo")
			useStr = ""
			extendedSyntax = true
		} else {
			return nil, errors.New("InvalidAtom")
		}
	} else if myutil.GetNamedRegexp(atomRe, s, "op") != "" {
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
	} else if myutil.GetNamedRegexp(atomRe, s, "star") != "" {
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
	} else if myutil.GetNamedRegexp(atomRe, s, "simple") != "" {
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
	a.Cp = cp
	a.cpv = versions.NewPkgStr[T](cpv, nil, nil, "", "", "", 0, 0, "", 0, nil)
	a.version = extendedVersion
	a.version = a.cpv.Version
	a.Repo = repo
	if slot == "" {
		a.slot = ""
		a.subSlot = ""
		a.slotOperator = ""
	} else {
		slotRe := getSlotDepRe(EapiAttrs)
		if !slotRe.MatchString(slot) {
			//raise InvalidAtom(self)
		}
		if EapiAttrs.SlotOperator {
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
	withoutUse := &Atom[T]{}
	if useStr != "" {
		if _use != nil {
			use = _use
		} else {
			use = NewUseDep(strings.Split(useStr[1:len(useStr)-1], ","), &EapiAttrs, nil, nil, nil, nil, nil, nil)
		}
		withoutUse, _ = NewAtom(blockerPrefix+myutil.GetNamedRegexp(atomRe, s, "without_use"), nil, false, allowRepo, nil, "", nil, nil)
	} else {
		use = nil
		if unevaluatedAtom != nil && unevaluatedAtom.Use != nil {
			withoutUse, _ = NewAtom(blockerPrefix+myutil.GetNamedRegexp(atomRe, s, "without_use"), nil, false, allowRepo, nil, "", nil, nil)
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

	if eapi1 != "" {
		if a.slot != "" && !EapiAttrs.SlotDeps {
			//raise InvalidAtom(
			//	_("Slot deps are!allowed in EAPI %s: '%s'")
			//% (eapi, self), category='EAPI.incompatible')
		}
		if a.Use != nil {
			if !EapiAttrs.UseDeps {
				//raise InvalidAtom(
				//	_("Use deps are!allowed in EAPI %s: '%s'")
				//% (eapi, self), category='EAPI.incompatible')
			} else if !EapiAttrs.UseDepDefaults && (len(a.Use.missingEnabled) != 0 || len(a.Use.missingDisabled) != 0) {
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
		if a.Blocker != nil && a.Blocker.overlap.forbid && !EapiAttrs.StrongBlocks {
			//raise InvalidAtom(
			//	_("Strong blocks are!allowed in EAPI %s: '%s'")
			//% (eapi, self), category='EAPI.incompatible')
		}
	}

	return a, nil
}

func (a *Atom[T]) withoutSlot() *Atom[T] {
	if a.slot == "" && a.slotOperator == "" {
		return a
	}
	atom := RemoveSlot(a.Value)
	if a.Repo != "" {
		atom += repoSeparator + a.Repo
	}
	if a.Use != nil {
		atom += a.Use.str()
	}
	m := true
	b, _ := NewAtom[T](atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom[T]) WithRepo(repo string) *Atom[T] {
	atom := RemoveSlot(a.Value)
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
	b, _ := NewAtom[T](atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom[T]) withSlot(slot string) *Atom[T] {
	atom := RemoveSlot(a.Value) + slotSeparator + slot
	if a.Repo != "" {
		atom += repoSeparator + a.Repo
	}
	if a.Use != nil {
		atom += a.Use.str()
	}
	m := true
	b, _ := NewAtom[T](atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom[T]) EvaluateConditionals(use map[string]bool) *Atom[T] {
	if !(a.Use != nil && a.Use.conditional != nil) {
		return a
	}
	atom := RemoveSlot(a.Value)
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
	b, _ := NewAtom[T](atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom[T]) violatedConditionals(otherUse map[string]bool, isValidFlag func(string) bool, parentUse map[string]bool) *Atom[T] { // none
	if a.Use == nil {
		return a
	}
	atom := RemoveSlot(a.Value)
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
	b, _ := NewAtom[T](atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom[T]) evalQaConditionals(useMask, useForce map[string]bool) *Atom[T] {
	if a.Use == nil || a.Use.conditional == nil {
		return a
	}
	atom := RemoveSlot(a.Value)
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
	b, _ := NewAtom[T](atom, nil, true, &m, nil, "", nil, nil)
	return b
}

func (a *Atom[T]) slotOperatorBuilt() bool {
	return a.slotOperator == "=" && a.subSlot != ""
}

func (a *Atom[T]) withoutRepo() *Atom[T] {
	if a.Repo == "" {
		return a
	}
	b, _ := NewAtom[T](strings.Replace(a.Value, repoSeparator+a.Repo, "", 1), nil, true, nil, nil, "", nil, nil)
	return b
}

func (a *Atom[T]) intersects(other *Atom[T]) bool {
	if a == other {
		return true
	}
	if a.Cp != other.Cp || a.Use != other.Use || a.Operator != other.Operator || a.cpv != other.cpv {
		return false
	}
	if a.slot == "" || other.slot == "" || a.slot == other.slot {
		return true
	}
	return false
}

func (a *Atom[T]) copy() *Atom[T] {
	return a
}

func (a *Atom[T]) deepcopy() *Atom[T] { // memo=None, memo[id(self)] = self
	return a
}

func (a *Atom[T]) match(pkg *versions.PkgStr[T]) bool {
	return len(MatchFromList(a, []*versions.PkgStr[T]{pkg})) > 0
}

func (a *Atom[T]) UnevaluatedAtom() *Atom[T] {
	return a.unevaluatedAtom
}

func extractAffectingUse[T interfaces.ISettings](mystr string, atom *Atom[T], eapi string) map[string]bool {
	useflagRe := GetUseflagRe(eapi)
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
			for _, x := range cleanedDepend {
				depend = append(depend, x)
			}
		}
	}
	return strings.Join(depend, " ")
}

//false, false, false, "", false
func IsValidAtom(atom string, allowBlockers, allowWildcard, allowRepo bool, eapi string, allowBuildId bool) bool {
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

func depGetcpv[T interfaces.ISettings](mydep string) *versions.PkgStr[T] {
	a, _ := NewAtom[T](mydep, nil, false, nil, nil, "", nil, nil)
	return a.cpv
}

func DepGetslot(mydep string) string {
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
			for _, x := range strings.Split(use, ",") {
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

func IsJustName(mypkg string) bool {
	a, err := NewAtom(mypkg, nil, false, nil, nil, "", nil, nil)
	if err == nil {
		return mypkg == a.Cp
	}
	p := strings.Split(mypkg, "-")
	for _, x := range p[len(p)-2:] {
		if versions.VerVerify(x, 1) {
			return false
		}
	}
	return true
}

func isSpecific(mypkg string) bool {
	a, err := NewAtom(mypkg, nil, false, nil, nil, "", nil, nil)
	if err == nil {
		return mypkg != a.Cp
	}
	return !IsJustName(mypkg)
}

func DepGetKey(mydep string) string {
	a, _ := NewAtom(mydep, nil, false, nil, nil, "", nil, nil)
	return a.Cp
}

func matchToList[T interfaces.ISettings](mypkg *versions.PkgStr[T], mylist []*Atom[T]) []*Atom[T] {
	matches := map[*Atom[T]]bool{}
	result := []*Atom[T]{}
	pkgs := []*versions.PkgStr[T]{mypkg}
	for _, x := range mylist {
		if !matches[x] && len(MatchFromList(x, pkgs)) > 0 {
			matches[x] = true
			result = append(result, x)
		}
	}
	return result
}

func BestMatchToList[T interfaces.ISettings](mypkg *versions.PkgStr[T], mylist []*Atom[T]) *Atom[T] {
	operatorValues := map[string]int{"=": 6, "~": 5, "=*": 4, ">": 2, "<": 2, ">=": 2, "<=": 2, "": 1}
	maxvalue := -99
	var bestm *Atom[T] = nil
	var mypkgCpv *versions.PkgStr[T] = nil
	for _, x := range matchToList(mypkg, mylist) {
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
		if DepGetslot(x.Value) != "" {
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
				mypkgCpv = mypkg.Cpv
			}
			if mypkgCpv == nil {
				mypkgCpv = versions.NewPkgStr[T](RemoveSlot(mypkg.String), nil, nil, "", "", "", 0, 0, "", 0, nil)
			}
			if bestm.cpv == mypkgCpv || bestm.cpv == x.cpv {
			} else if x.cpv == mypkgCpv {
				bestm = x
			} else {
				cpvList := []*versions.PkgStr[T]{bestm.cpv, mypkgCpv, x.cpv}
				sort.Slice(cpvList, func(i, j int) bool {
					b, _ := versions.VerCmp(cpvList[i].Version, cpvList[j].Version)
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

func MatchFromList[T interfaces.ISettings](mydep *Atom[T], candidateList []*versions.PkgStr[T]) []*versions.PkgStr[T] {
	if len(candidateList) == 0 {
		return []*versions.PkgStr[T]{}
	}
	mydepA := mydep
	if "!" == mydep.Value[:1] {
		mydepS := ""
		if "!" == mydep.Value[1:2] {
			mydepS = mydep.Value[2:]
		} else {
			mydepS = mydep.Value[1:]
		}
		ar := true
		mydepA, _ = NewAtom[T](mydepS, nil, true, &ar, nil, "", nil, nil)
	}

	mycpv := mydepA.cpv
	mycpvCps := versions.CatPkgSplit(mycpv.String, 0, "")
	//slot      := mydepA.slot
	buildId := mydepA.buildId

	_, _, ver, rev := "", "", "", ""
	if mycpvCps == [4]string{} {
		cp := versions.CatSplit(mycpv.String)
		_ = cp[0]
		_ = cp[1]
		ver = ""
		rev = ""
	} else {
		_, _, ver, rev = mycpvCps[0], mycpvCps[1], mycpvCps[2], mycpvCps[3]
	}
	if mydepA.Value == mycpv.String {
		//raise KeyError(_("Specific key requires an operator"
		//" (%s) (try adding an '=')") % (mydep))
	}

	operator := ""
	if ver != "" && rev != "" {
		operator = mydepA.Operator
		if operator == "" {
			msg.WriteMsg(fmt.Sprintf("!!! Invalid Atom: %s\n", mydep.Value), -1, nil)
		}
		return []*versions.PkgStr[T]{}
	} else {
		operator = ""
	}
	mylist := []*versions.PkgStr[T]{}
	if mydepA.extendedSyntax {
		for _, x := range candidateList {
			cp := x.Cp
			if cp == "" {
				mysplit := versions.CatPkgSplit(RemoveSlot(x.String), 1, "")
				if mysplit != [4]string{} {
					cp = mysplit[0] + "/" + mysplit[1]
				}
			}
			if cp == "" {
				continue
			}
			if cp == mycpv.String || extendedCpMatch(mydepA.Cp, cp) {
				mylist = append(mylist, x)
			}
		}
		if len(mylist) > 0 && mydepA.Operator == "=*" {
			candidateList = mylist
			mylist = []*versions.PkgStr[T]{}
			ver = mydepA.version[1 : len(mydepA.version)-1]
			for _, x := range candidateList {
				xVer := x.Version
				if xVer == "" {
					xs := versions.CatPkgSplit(RemoveSlot(x.String), 1, "")
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
			cp := x.Cp
			if cp == "" {
				mysplit := versions.CatPkgSplit(RemoveSlot(x.String), 1, "")
				if mysplit != [4]string{} {
					cp = mysplit[0] + "/" + mysplit[1]
				}
				if cp == "" {
					continue
				}
			}
			if cp == mydepA.Cp {
				mylist = append(mylist, x)
			}
		}
	} else if operator == "=" {
		for _, x := range candidateList {
			xcpv := x.Cpv
			if xcpv == nil {
				xcpv = &versions.PkgStr[T]{String: RemoveSlot(x.String)}
			}
			if !cpvequal(xcpv.String, mycpv.String) {
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
			mycpvCmp = mycpv.String
		} else {
			mycpvCmp = strings.Replace(mycpv.String, mydepA.Cp+"-"+mycpvCps[2], mydepA.Cp+"-"+myver, 1)
		}
		for _, x := range candidateList {
			pkg := x
			if pkg.Cp == "" {
				pkg = versions.NewPkgStr[T](RemoveSlot(x.String), nil, nil, "", "", "", 0, 0, "", 0, nil)
			}
			xs := pkg.CpvSplit
			myver := strings.TrimPrefix(xs[2], "0")
			if len(myver) == 0 || !unicode.IsDigit(rune(myver[0])) {
				myver = "0" + myver
			}
			xcpv := ""
			if myver == xs[2] {
				xcpv = pkg.Cpv.String
			} else {
				xcpv = strings.Replace(pkg.Cpv.String, pkg.Cp+"-"+xs[2], pkg.Cp+"-"+myver, 1)
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
			xs := x.CpvSplit
			if xs == [4]string{} {
				xs = versions.CatPkgSplit(RemoveSlot(x.String), 1, "")
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
			if x.Cp == "" {
				pkg = versions.NewPkgStr[T](RemoveSlot(x.String), nil, nil, "", "", "", 0, 0, "", 0, nil)
			}

			if pkg.Cp != mydepA.Cp {
				continue
			}
			result, err := versions.VerCmp(pkg.Version, mydepA.version)
			if err != nil {
				msg.WriteMsg(fmt.Sprintf("\nInvalid package name: %v\n", x), -1, nil)
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
		mylist = []*versions.PkgStr[T]{}
		for _, x := range candidateList {
			xPkg := x
			if xPkg.Cpv == nil {
				xslot := DepGetslot(x.String)
				if xslot != "" {
					xPkg = versions.NewPkgStr[T](RemoveSlot(x.String), nil, nil, "", "", xslot, 0, 0, "", 0, nil)
				} else {
					continue
				}
			}

			if xPkg == nil {
				mylist = append(mylist, x)
			} else {
				if xPkg.Slot == "" {
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
		mylist = []*versions.PkgStr[T]{}
		for _, x := range candidateList {
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

	if mydepA.Repo != "" {
		candidateList = mylist
		mylist = []*versions.PkgStr[T]{}
		for _, x := range candidateList {
			repo := x.Repo
			if repo == "" {
				repo = DepGetrepo(x.String)
			}
			if repo != "" && repo != versions.UnknownRepo && repo != mydepA.Repo {
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

func get_required_use_flags(requiredUse, eapi1 string) map[string]bool { //n
	EapiAttrs := eapi.GetEapiAttrs(eapi1)
	validOperators := map[string]bool{}
	if EapiAttrs.RequiredUseAtMostOneOf {
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

type ExtendedAtomDict[T interfaces.ISettings] map[string]map[*Atom[T]][]string
