package atom

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	_unknown_repo = "__unknown__"
	slot = `([\w+][\w+.-]*)`
	cat  = `[\w+][\w+.-]*`
	v    = `(?P<major>\d+)(?P<minors>(?P<minor>\.\d+)*)(?P<letter>[a-z]?)(?P<additional>(?P<suffix>_(?P<status>pre|p|beta|alpha|rc)\d*)*)`
	rev  = `\d+`
	vr   = v + "(?P<revision>-r(" + rev + "))?"
)

var (
	pkg = map[string]string{
		"dots_disallowed_in_PN": `[\w+][\w+-]*?`,
		"dots_allowed_in_PN":    `[\w+][\w+.-]*?`,
	}
	cp = map[string]string{
		"dots_disallowed_in_PN": "(" + cat + "/" + pkg["dots_disallowed_in_PN"] + "(-" + vr + ")?)",
		"dots_allowed_in_PN":    "(" + cat + "/" + pkg["dots_allowed_in_PN"] + "(-" + vr + ")?)",
	}
	cpv = map[string]string{
		"dots_disallowed_in_PN": "(" + cp["dots_disallowed_in_PN"] + "-" + vr + ")",
		"dots_allowed_in_PN":    "(" + cp["dots_allowed_in_PN"] + "-" + vr + ")",
	}
	pv = map[string]string{
		"dots_disallowed_in_PN": "(?P<pn>" + pkg["dots_disallowed_in_PN"] + "(?P<pn_inval>-" + vr + ")?)" + "-(?P<ver>" + v + ")(-r(?P<rev>" + rev + "))?",
		"dots_allowed_in_PN":    "(?P<pn>" + pkg["dots_allowed_in_PN"] + "(?P<pn_inval>-" + vr + ")?)" + "-(?P<ver>" + v + ")(-r(?P<rev>" + rev + "))?",
	}
	verRegexp       = regexp.MustCompile("^" + vr + "$")
	suffix_regexp   = regexp.MustCompile("^(alpha|beta|rc|pre|p)(\\d*)$")
	suffix_value    = map[string]int{"pre": -2, "p": 0, "alpha": -4, "beta": -3, "rc": -1}
	endversion_keys = []string{"pre", "p", "alpha", "beta", "rc"}

	slotReCache = map[string]*regexp.Regexp{}
	pvReCache   = map[bool]*regexp.Regexp{}
)

func getSlotRe(eapiAttrs interface{ SlotOperator() string }) *regexp.Regexp {

	cache_key := eapiAttrs.SlotOperator()
	slotRe, ok := slotReCache[cache_key]
	if ok {
		return slotRe
	}

	s := ""
	if eapiAttrs.SlotOperator() != "" {
		s = slot + "(/" + slot + ")?"
	} else {

		s = slot
	}

	slotRe = regexp.MustCompile("^" + s + "$")

	slotReCache[cache_key] = slotRe
	return slotRe
}

func getPvRe(eapiAttrs eapiAttrs) *regexp.Regexp {

	cacheKey := eapiAttrs.DotsInPn
	pvRe, ok := pvReCache[cacheKey]
	if ok {
		return pvRe
	}

	p := ""
	if eapiAttrs.DotsInPn {
		p = pv["dots_allowed_in_PN"]
	} else {
		p = pv["dots_disallowed_in_PN"]
	}

	pvRe = regexp.MustCompile("^" + p + "$")

	pvReCache[cacheKey] = pvRe
	return pvRe
}

func verVerify(myver string) bool {
	return verRegexp.MatchString(myver)
}

func getNamedRegexp(re *regexp.Regexp, target, name string) string {
	match := re.FindStringSubmatch(target)
	for i, n := range re.SubexpNames() {
		if i > 0 && i <= len(match) && n == name {
			return match[i]
		}
	}
	return ""
}

func toi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func verCmp(ver1, ver2 string) (int, error) {
	if ver1 == ver2 {
		return 0, nil
	}

	if !verRegexp.MatchString(ver1) || !verRegexp.MatchString(ver2) {
		return 0, errors.New("a")
	}
	v1, err := strconv.Atoi(verRegexp.FindString(ver1))
	if err != nil {
		return 0, err
	}
	v2, err := strconv.Atoi(verRegexp.FindString(ver2))
	if err != nil {
		return 0, err
	}
	list1 := []int{v1}
	list2 := []int{v2}

	if getNamedRegexp(verRegexp, ver1, "minors") != "" || getNamedRegexp(verRegexp, ver2, "minors") != "" {
		vlist1 := strings.Split(getNamedRegexp(verRegexp, ver1, "minors")[1:], ".")
		vlist2 := strings.Split(getNamedRegexp(verRegexp, ver2, "minors")[1:], ".")

		l := len(vlist1)
		if len(vlist2) > l {
			l = len(vlist2)
		}

		for i := 0; i < l; i++ {
			if len(vlist1) <= i || len(vlist1[i]) == 0 {
				list1 = append(list1, -1)
				n, _ := strconv.Atoi(vlist2[i])
				list2 = append(list2, n)
			} else if len(vlist1) <= i || len(vlist1[i]) == 0 {
				list2 = append(list1, -1)
				n, _ := strconv.Atoi(vlist1[i])
				list1 = append(list1, n)
			} else if vlist1[i][0] != '0' && vlist2[i][0] != '0' {
				n1, _ := strconv.Atoi(vlist1[i])
				list1 = append(list1, n1)
				n2, _ := strconv.Atoi(vlist2[i])
				list2 = append(list2, n2)
			} else {
				ml := len(vlist1[i])
				if len(vlist2) > ml {
					ml = len(vlist2[i])
				}
				n1, _ := strconv.Atoi(fmt.Sprintf("%-0"+string(ml)+"v", vlist1[i]))
				list1 = append(list1, n1)
				n2, _ := strconv.Atoi(fmt.Sprintf("%-0"+string(ml)+"v", vlist2[i]))
				list2 = append(list2, n2)
			}
		}
	}
	if getNamedRegexp(verRegexp, ver1, "letter") != "" {
		list1 = append(list1, int([]byte(getNamedRegexp(verRegexp, ver1, "letter"))[0]))
	}
	if getNamedRegexp(verRegexp, ver2, "letter") != "" {
		list2 = append(list2, int([]byte(getNamedRegexp(verRegexp, ver2, "letter"))[0]))
	}
	for i := 0; i < len(list1) && i < len(list2); i++ {
		if len(list1) <= i {
			return -1, nil
		} else if len(list2) <= i {
			return 1, nil
		} else if list1[i] != list2[i] {
			if list1[i] > list2[i] {
				return 2, nil
			} else if list1[i] > list2[i] {
				return -1, nil
			} else {
				return 0, nil
			}
		}
	}
	l1 := strings.Split(getNamedRegexp(verRegexp, ver1, "suffix")[1:], "_")
	l2 := strings.Split(getNamedRegexp(verRegexp, ver2, "suffix")[1:], "_")
	for i := 0; i < len(l1) && i < len(l2); i++ {
		var s1, s2 []string
		if len(list1) <= i {
			s1 = []string{"p", "-1"}
		} else {
			s1 = suffix_regexp.FindStringSubmatch(l1[i])
		}
		if len(list2) <= i {
			s2 = []string{"p", "-1"}
		} else {
			s2 = suffix_regexp.FindStringSubmatch(l2[i])
		}
		if s1[0] != s2[0] {
			return suffix_value[s1[0]] - suffix_value[s2[0]], nil
		}
		if s1[1] != s2[1] {
			n1, _ := strconv.Atoi(s1[1])
			n2, _ := strconv.Atoi(s2[1])
			return n1 - n2, nil
		}
	}
	n1, _ := strconv.Atoi(getNamedRegexp(verRegexp, ver1, "revision"))
	n2, _ := strconv.Atoi(getNamedRegexp(verRegexp, ver1, "revision"))
	if n1 > n2 {
		return 1, nil
	} else if n1 == n2 {
		return 0, nil
	} else {
		return -1, nil
	}

}

func pkgCmp(pkg1, pkg2 [3]string) (int, error){
	if pkg1[0] !=pkg2[0]{
		return 0, errors.New("")
	}
	return verCmp(strings.Join(pkg1[1:], "-"),strings.Join(pkg2[1:], "-"))
}

func pkgSplit(mypkg, eapi string) (string,string,string){
	if !getPvRe(getEapiAttrs(eapi)).MatchString(mypkg) {
		return "","",""
	}
	re := getPvRe(getEapiAttrs(eapi))
	if getNamedRegexp(re, mypkg, "pn_inval") != ""{
		return "","",""
	}
	rev := getNamedRegexp(re, mypkg, "pn_inval")
	if rev == "" {
		rev = "0"
	}
	rev = "r" + rev
	return getNamedRegexp(re, mypkg, "pn"), getNamedRegexp(re, mypkg, "ver"), rev
}

func catPkgSplit(mydata string, silent int, eapi string){

}

func catsplit(mydep string) []string {
	return strings.SplitN(mydep, "/", 2)
}
