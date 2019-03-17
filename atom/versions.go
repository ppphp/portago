package atom

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	unknownRepo = "__unknown__"
	slot        = `([\w+][\w+.-]*)`
	cat         = `[\w+][\w+.-]*`
	v           = `(?P<major>\d+)(?P<minors>(?P<minor>\.\d+)*)(?P<letter>[a-z]?)(?P<additional>(?P<suffix>_(?P<status>pre|p|beta|alpha|rc)\d*)*)`
	rev         = `\d+`
	vr          = v + "(?P<revision>-r(" + rev + "))?"
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

	slotReCache = map[bool]*regexp.Regexp{}
	pvReCache   = map[bool]*regexp.Regexp{}
)

func getSlotRe(eapiAttrs eapiAttrs) *regexp.Regexp {

	cache_key := eapiAttrs.SlotOperator
	slotRe, ok := slotReCache[cache_key]
	if ok {
		return slotRe
	}

	s := ""
	if eapiAttrs.SlotOperator {
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

func pkgCmp(pkg1, pkg2 [3]string) (int, error) {
	if pkg1[0] != pkg2[0] {
		return 0, errors.New("")
	}
	return verCmp(strings.Join(pkg1[1:], "-"), strings.Join(pkg2[1:], "-"))
}

func pkgSplit(mypkg, eapi string) [3]string {
	if !getPvRe(getEapiAttrs(eapi)).MatchString(mypkg) {
		return [3]string{}
	}
	re := getPvRe(getEapiAttrs(eapi))
	if getNamedRegexp(re, mypkg, "pn_inval") != "" {
		return [3]string{}
	}
	rev := getNamedRegexp(re, mypkg, "pn_inval")
	if rev == "" {
		rev = "0"
	}
	rev = "r" + rev
	return [3]string{getNamedRegexp(re, mypkg, "pn"), getNamedRegexp(re, mypkg, "ver"), rev}
}

var (
	catRe      = regexp.MustCompile(fmt.Sprintf("^%s$", cat))
	missingCat = "null"
)

func catPkgSplit(mydata string, silent int, eapi string) [4]string { // 1n
	// return mydata.cpv_split // if can
	mySplit := strings.SplitN(mydata, "/", 1)
	var cat string
	var p [3]string
	if len(mySplit) == 1 {
		cat = missingCat
		p = pkgSplit(mydata, eapi)
	} else if len(mySplit) == 2 {
		cat = mySplit[0]
		if catRe.MatchString(cat) {
			p = pkgSplit(mySplit[1], eapi)
		}
	}
	if p == [3]string{} {
		return [4]string{}
	}
	return [4]string{cat, p[0], p[1], p[2]}
}

type pkgStr struct {
	string
	metadata                                                                              map[string]string
	settings                                                                              *Config
	eapi, repo, slot, buildTime, buildId, fileSize, db, cp, version, subSlot, slotInvalid string
	mtime                                                                                 int
	_stable                                                                               *bool
	cpvSplit                                                                              [4]string
	cpv                                                                                   *pkgStr
}

func (p *pkgStr) stable() bool {
	if p._stable != nil {
		return *p._stable
	}
	settings := p.settings
	if settings == nil {
		return false
	}
	p._stable = new(bool)
	*p._stable = settings.isStable(p)
	return *p._stable
}

func NewPkgStr(cpv string, metadata map[string]string, settings *Config, eapi, repo, slot, build_time, build_id, file_size string, mtime int, db string) *pkgStr {
	p := &pkgStr{string: cpv}
	if len(metadata) != 0 {
		p.metadata = metadata
		if a, ok := metadata["SLOT"]; ok {
			slot = a
		}
		if a, ok := metadata["repository"]; ok {
			repo = a
		}
		if a, ok := metadata["EAPI"]; ok {
			slot = a
		}
		if a, ok := metadata["BUILD_TIME"]; ok {
			build_time = a
		}
		if a, ok := metadata["SIZE"]; ok {
			file_size = a
		}
		if a, ok := metadata["BUILD_ID"]; ok {
			build_id = a
		}
		if a, ok := metadata["_mtime_"]; ok {
			mtime, _ = strconv.Atoi(a)
		}
	}
	if settings != nil {
		p.settings = settings
	}
	if db != "" {
		p.db = db
	}
	if eapi != "" {
		p.eapi = eapi
	}
	p.buildTime = build_time // int
	p.fileSize = file_size   // int
	p.buildId = build_id     // int
	p.mtime = mtime          // int
	p.cpvSplit = catPkgSplit(cpv, 1, eapi)
	p.cp = p.cpvSplit[0] + "/" + p.cpvSplit[1]
	if p.cpvSplit[len(p.cpvSplit)-1] == "r0" && cpv[len(cpv)-3:] != "-r0" {
		p.version = strings.Join(p.cpvSplit[2:4], "-")
	} else {
		p.version = strings.Join(p.cpvSplit[2:], "-")
	}
	p.cpv = p
	if slot != "" {
		eapiAttrs := getEapiAttrs(eapi)
		slotMatch := getSlotRe(eapiAttrs).FindAllString(slot, -1)
		if len(slotMatch) == 0 {
			p.slot = "0"
			p.subSlot = "0"
			p.slotInvalid = slot
		} else {
			if eapiAttrs.SlotOperator {
				slotSplit := strings.Split(slot, "/")
				p.slot = slotSplit[0]
				if len(slotSplit) > 1 {
					p.subSlot = slotSplit[1]
				} else {
					p.subSlot = slotSplit[0]
				}
			} else {
				p.slot = slot
				p.subSlot = slot
			}
		}
		if repo != "" {
			repo = genValidRepo(repo)
			if repo == "" {
				repo = unknownRepo
			}
			p.repo = repo
		}
	}
	return p
}

func PkgSplit(mypkg string, silent int, eapi string) [3]string {
	catPSplit := catPkgSplit(mypkg, 1, eapi)
	if catPSplit == [4]string{} {
		return [3]string{}
	}
	cat, pn, ver, rev := catPSplit[0], catPSplit[1], catPSplit[2], catPSplit[3]
	if cat == missingCat && !strings.Contains(mypkg, "/") {
		return [3]string{pn, ver, rev}
	}
	return [3]string{cat + "/" + pn, ver, rev}
}

func cpvGetKey(mycpv, eapi string) string {
	//return mycpv.cp //TODO
	mySplit := catPkgSplit(mycpv, 1, eapi)
	if mySplit != [4]string{} {
		return mySplit[0] + "/" + mySplit[1]
	}
	// warnings.warn("portage.versions.cpv_getkey() " + \
	// "called with invalid cpv: '%s'" % (mycpv,),
	// DeprecationWarning, stacklevel=2) //TODO
	mySlash := strings.SplitN(mycpv, "/", 2)
	myNSplit := pkgSplit(mySlash[0], eapi)
	if myNSplit == [3]string{} {
		return ""
	}
	myLen := len(mySlash)
	if myLen == 2 {
		return mySlash[0] + "/" + mySplit[0]
	} else {
		return mySplit[0]
	}
}

func cpvGetVersion(mycpv, eapi string) string {
	//return mycpv.version //TODO
	cp := cpvGetKey(mycpv, eapi)
	if cp == "" {
		return ""
	}
	return mycpv[len(cp+"-"):]
}

var splitCache = map[string]*pkgStr{}

func cmpCpv(cpv1, cpv2, eapi string) (int, error) {
	split1, ok := splitCache[cpv1]
	if !ok {
		//split1 = cpv1.pv //TODO
		split1 = NewPkgStr(cpv1, nil, nil, eapi, "", "", "", "", "", 0, "")
		splitCache[cpv1] = split1
	}
	split2 := NewPkgStr(cpv1, nil, nil, eapi, "", "", "", "", "", 0, "")
	splitCache[cpv2] = split2
	//return verCmp(cpv1.version, cpv2.version)
	return verCmp(cpv1, cpv2)
}

func cpvSortKey(eapi string) func(string, string, string) (int, error) {
	return cmpCpv // a sort key
}

func catsplit(mydep string) []string {
	return strings.SplitN(mydep, "/", 2)
}

func best(myMatches []string, eapi string) string {
	if len(myMatches) == 0 {
		return ""
	}
	if len(myMatches) == 1 {
		return myMatches[0]
	}
	bestMatch := myMatches[0]
	//v2 := bestmatch.version //TODO
	//v2 := NewPkgStr(bestMatch, nil, nil, eapi, "", "", "", "", "", "", "")
	v2 := bestMatch
	for _, x := range myMatches[1:] {
		//v1 := x.version //TODO
		//v1 := NewPkgStr(x, nil, nil, eapi, "", "", "", "", "", "", "")
		v1 := x
		v, _ := verCmp(v1, v2)
		if v > 0 {
			bestMatch = x
			v2 = v1
		}
	}
	return bestMatch
}
