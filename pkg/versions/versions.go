package versions

import (
	"errors"
	"fmt"
	"github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/interfaces"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/repository/validrepo"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

const (
	unknownRepo = "__unknown__"
	slot        = `([\w+][\w+.-]*)`
	cat         = `[\w+][\w+.-]*`
	pkg         = `[\w+][\w+-]*?`
	v           = `(?P<major>\d+)(?P<minors>(?P<minor>\.\d+)*)(?P<letter>[a-z]?)(?P<additional>(?P<suffix>_(?P<status>pre|p|beta|alpha|rc)\d*)*)`
	rev         = `\d+`
	vr          = v + "(?P<revision>-r(" + rev + "))?"
	cp          = "(" + cat + "/" + pkg + "(-" + vr + ")?)"
	cpv         = "(" + cp + "-" + vr + ")"
	pv          = "(?P<pn>" + pkg + "(?P<pn_inval>-" + vr + ")?)" + "-(?P<ver>" + v + ")(-r(?P<rev>" + rev + "))?"
)

var (
	verRegexp      = regexp.MustCompile(vr)
	suffixRegexp   = regexp.MustCompile("^(alpha|beta|rc|pre|p)(\\d*)$")
	suffix_value   = map[string]int{"pre": -2, "p": 0, "alpha": -4, "beta": -3, "rc": -1}
	endversionKeys = []string{"pre", "p", "alpha", "beta", "rc"}

	slotReCache = map[bool]*regexp.Regexp{}
)

func getSlotRe(eapiAttrs eapi.EapiAttrs) *regexp.Regexp {

	cacheKey := eapiAttrs.SlotOperator
	slotRe, ok := slotReCache[cacheKey]
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

	slotReCache[cacheKey] = slotRe
	return slotRe
}

var pvRe *regexp.Regexp

func getPvRe(eapiAttrs eapi.EapiAttrs) *regexp.Regexp {
	if pvRe != nil {
		return pvRe
	}

	pvRe = regexp.MustCompile("^" + pv + "$")
	return pvRe
}

// 1
func VerVerify(myver string, silent int) bool {
	if verRegexp.MatchString(myver) {
		return true
	}
	if silent != 0 {
		fmt.Printf("!!! syntax error in version: %s", myver)
	}
	return false

}

type VersionStatus string

const (
	VersionStatusPre   = "pre"
	VersionStatusP     = "p"
	VersionStatusAlpha = "alpha"
	VersionStatusBeta  = "beta"
	VersionStatusRC    = "rc"
)

var suffixValue = map[VersionStatus]int{
	VersionStatusPre:   -2,
	VersionStatusP:     0,
	VersionStatusAlpha: -4,
	VersionStatusBeta:  -3,
	VersionStatusRC:    -1}

type VersionString struct {
	Exists bool
	Value  string
}

func (v VersionString) Cmp(v2 VersionString) int {
	return 0 // TODO
}

type Version struct {
	Major   VersionString
	Minors  []string
	Letter  string
	Suffix  string
	Status  string
	Revison string
}

func (v Version) Cmp(v2 Version) int {
	return 0 // TODO
}

func NewVersion(ver string) (*Version, error) {
	v := &Version{}
	if !verRegexp.MatchString(ver) {
		return nil, fmt.Errorf("!!! syntax error in version: %s", ver)
	}
	major := myutil.GetNamedRegexp(verRegexp, ver, "major")
	if major != "" {
		v.Major.Exists = true
		v.Major.Value = major
	}
	return nil, nil
}

func cmpString(s1, s2 string) (int, error) {

	major1, ok1 := new(big.Int).SetString(s1, 10)
	if !ok1 {
		return 0, fmt.Errorf("!!! syntax error in version: %s", s1)
	}
	major2, ok2 := new(big.Int).SetString(s2, 10)
	if !ok2 {
		return 0, fmt.Errorf("!!! syntax error in version: %s", s2)
	}
	c := major1.Cmp(major2)
	return c, nil
}

func VerCmp(ver1, ver2 string) (int, error) {
	if ver1 == ver2 {
		return 0, nil
	}

	var verRegexp = regexp.MustCompile("^(?P<major>\\d+)(?P<minors>(?P<minor>\\.\\d+)*)(?P<letter>[a-z]?)(?P<additional>(?P<suffix>_(?P<status>pre|p|beta|alpha|rc)\\d*)*)(-r(?P<revision>\\d+))?$")
	if !verRegexp.MatchString(ver1) {
		return 0, fmt.Errorf("!!! syntax error in version: %s", ver1)
	}
	if !verRegexp.MatchString(ver2) {
		return 0, fmt.Errorf("!!! syntax error in version: %s", ver2)
	}
	v1 := verRegexp.FindStringSubmatch(ver1)[1]
	v2 := verRegexp.FindStringSubmatch(ver2)[1]

	major1, _ := strconv.Atoi(v1)
	major2, _ := strconv.Atoi(v2)
	if major1 > major2 {
		return 1, nil
	} else if major1 < major2 {
		return -1, nil
	}

	list1 := []string{v1}
	list2 := []string{v2}

	if myutil.GetNamedRegexp(verRegexp, ver1, "minors") != "" || myutil.GetNamedRegexp(verRegexp, ver2, "minors") != "" {
		g1 := myutil.GetNamedRegexp(verRegexp, ver1, "minors")
		if len(g1) >= 1 {
			g1 = g1[1:]
		}
		vlist1 := strings.Split(g1, ".")
		g2 := myutil.GetNamedRegexp(verRegexp, ver2, "minors")
		if len(g2) >= 1 {
			g2 = g2[1:]
		}
		vlist2 := strings.Split(g2, ".")

		l := len(vlist1)
		if len(vlist2) > l {
			l = len(vlist2)
		}

		for i := 0; i < l; i++ {
			v1 := "-1"
			v2 := "-1"
			if len(vlist1) <= i || len(vlist1[i]) == 0 {
				v2 = vlist2[i]
			} else if len(vlist2) <= i || len(vlist2[i]) == 0 {
				v1 = vlist1[i]
			} else if vlist1[i][0] != '0' && vlist2[i][0] != '0' {
				v2 = vlist2[i]
				v1 = vlist1[i]
			} else {
				v2 = vlist2[i]
				v1 = vlist1[i]
				ml := len(vlist1[i])
				if len(vlist2) > ml {
					ml = len(vlist2[i])
				}
				for i := 0; i < ml; i++ {
					if len(v1) < i {
						v1 = v1 + "0"
					}
					if len(v2) < i {
						v2 = v2 + "0"
					}
				}
			}
			c, err := cmpString(v1, v2)
			if err != nil {
				return 0, err
			}
			if c != 0 {
				return c, nil
			}
		}
	}
	if myutil.GetNamedRegexp(verRegexp, ver1, "letter") != "" {
		list1 = append(list1, string(myutil.GetNamedRegexp(verRegexp, ver1, "letter")[0]))
	}
	if myutil.GetNamedRegexp(verRegexp, ver2, "letter") != "" {
		list2 = append(list2, string(myutil.GetNamedRegexp(verRegexp, ver2, "letter")[0]))
	}
	for i := 0; i < len(list1) || i < len(list2); i++ {
		if len(list1) <= i {
			return -1, nil
		} else if len(list2) <= i {
			return 1, nil
		} else if list1[i] != list2[i] {
			if list1[i] > list2[i] {
				return 2, nil
			} else if list1[i] < list2[i] {
				return -2, nil
			} else {
				return 0, nil
			}
		}
	}
	g1 := myutil.GetNamedRegexp(verRegexp, ver1, "suffix")
	if len(g1) >= 1 {
		g1 = g1[1:]
	}
	l1 := strings.Split(g1, "_")
	g2 := myutil.GetNamedRegexp(verRegexp, ver2, "suffix")
	if len(g2) >= 1 {
		g2 = g2[1:]
	}
	l2 := strings.Split(g2, "_")
	for i := 0; i < len(l1) || i < len(l2); i++ {
		var s1, s2 []string
		if len(list1) <= i {
			s1 = []string{"p", "-1"}
		} else {
			s1 = suffixRegexp.FindStringSubmatch(l1[i])
		}
		if len(list2) <= i {
			s2 = []string{"p", "-1"}
		} else {
			s2 = suffixRegexp.FindStringSubmatch(l2[i])
		}
		if len(s1) > 1 && len(s2) > 1 && s1[1] != s2[2] {
			return suffixValue[VersionStatus(s1[1])] - suffixValue[VersionStatus(s2[1])], nil
		}
		if len(s1) > 2 && len(s2) > 2 && s1[2] != s2[2] {
			n1, _ := strconv.Atoi(s1[2])
			n2, _ := strconv.Atoi(s2[2])
			return n1 - n2, nil
		}
	}
	n1, _ := strconv.Atoi(myutil.GetNamedRegexp(verRegexp, ver1, "revision"))
	n2, _ := strconv.Atoi(myutil.GetNamedRegexp(verRegexp, ver2, "revision"))
	if n1 > n2 {
		return 1, nil
	} else if n1 == n2 {
		return 0, nil
	} else {
		return -1, nil
	}

}

func PkgCmp(pkg1, pkg2 [3]string) (int, error) {
	if pkg1[0] != pkg2[0] {
		return 0, errors.New("")
	}
	return VerCmp(strings.Join(pkg1[1:], "-"), strings.Join(pkg2[1:], "-"))
}

// ""
func PkgSplit_(mypkg, eapi1 string) [3]string {
	re := getPvRe(eapi.GetEapiAttrs(eapi1))
	if !re.MatchString(mypkg) {
		return [3]string{}
	}
	if myutil.GetNamedRegexp(re, mypkg, "pn_inval") != "" {
		return [3]string{}
	}
	rev := myutil.GetNamedRegexp(re, mypkg, "rev")
	if rev == "" {
		rev = "0"
	}
	rev = "r" + rev
	return [3]string{myutil.GetNamedRegexp(re, mypkg, "pn"), myutil.GetNamedRegexp(re, mypkg, "ver"), rev}
}

var (
	catRe      = regexp.MustCompile(fmt.Sprintf("^%s$", cat))
	missingCat = "null"
)

// 1, ""
func CatPkgSplit(mydata string, silent int, eapi string) [4]string {
	// return mydata.cpv_split // if can
	mySplit := strings.SplitN(mydata, "/", 2)
	var cat string
	var p [3]string
	if len(mySplit) == 1 {
		cat = missingCat
		p = PkgSplit_(mydata, eapi)
	} else if len(mySplit) == 2 {
		cat = mySplit[0]
		if catRe.MatchString(cat) {
			p = PkgSplit_(mySplit[1], eapi)
		}
	}
	if p == [3]string{} {
		return [4]string{}
	}
	return [4]string{cat, p[0], p[1], p[2]}
}

type PkgStr[T interfaces.ISettings] struct {
	string
	metadata                                                      map[string]string
	settings                                                      T
	eapi, repo, slot, fileSize, cp, version, subSlot, slotInvalid string

	db                        interfaces.IDbApi
	BuildId, BuildTime, mtime int
	_stable                   *bool
	cpvSplit                  [4]string
	cpv                       *PkgStr[T]
}

// nil, nil, "", "", "", 0, 0, "", 0, nil
func NewPkgStr[T interfaces.ISettings](cpv string, metadata map[string]string, settings T, eapi1, repo, slot string, build_time, build_id int, file_size string, mtime int, db interfaces.IDbApi) *PkgStr[T] {
	p := &PkgStr[T]{string: cpv}
	if metadata != nil {
		p.metadata = metadata
		if a, ok := metadata["SLOT"]; ok {
			slot = a
		}
		if a, ok := metadata["repository"]; ok {
			repo = a
		}
		if a, ok := metadata["EAPI"]; ok {
			eapi1 = a
		}
		if a, ok := metadata["BUILD_TIME"]; ok {
			build_time, _ = strconv.Atoi(a)
		}
		if a, ok := metadata["SIZE"]; ok {
			file_size = a
		}
		if a, ok := metadata["BUILD_ID"]; ok {
			b, _ := strconv.Atoi(a)
			build_id = b
		}
		if a, ok := metadata["_mtime_"]; ok {
			mtime, _ = strconv.Atoi(a)
		}
	}
	var empty T
	if settings != empty {
		p.settings = settings
	}
	if db != nil {
		p.db = db
	}
	if eapi1 != "" {
		p.eapi = eapi1
	}
	p.BuildTime = build_time
	p.fileSize = file_size
	p.BuildId = build_id
	p.mtime = mtime
	p.cpvSplit = CatPkgSplit(cpv, 1, eapi1)
	if p.cpvSplit == [4]string{} {
		//raise InvalidData(cpv)
	}
	p.cp = p.cpvSplit[0] + "/" + p.cpvSplit[1]
	if p.cpvSplit[len(p.cpvSplit)-1] == "r0" && cpv[len(cpv)-3:] != "-r0" {
		p.version = strings.Join(p.cpvSplit[2:4], "-")
	} else {
		p.version = strings.Join(p.cpvSplit[2:], "-")
	}
	p.cpv = p
	if slot != "" {
		eapiAttrs := eapi.GetEapiAttrs(eapi1)
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
			repo = validrepo.GenValidRepo(repo)
			if repo == "" {
				repo = unknownRepo
			}
			p.repo = repo
		}
	}
	return p
}

func (p PkgStr[T]) _long(vari, defaulti int) int {
	if vari != 0 {
		//try:
		vari = int(vari)
		//except ValueError:
		if vari != 0 {
			vari = -1
		} else {
			vari = defaulti
		}
	}
	return vari
}

func (p *PkgStr[T]) stable() bool {
	if p._stable != nil {
		return *p._stable
	}
	settings := p.settings
	var empty T
	if settings == empty {
		return false
	}
	p._stable = new(bool)
	*p._stable = settings.IsStable(p)
	return *p._stable
}

func (p *PkgStr[T]) binpkg_format() string {
	//try:
	return p.metadata["BINPKG_FORMAT"]
	//except (AttributeError, KeyError):
	//raise AttributeError("binpkg_format")
}

// 1, nil
func PkgSplit(mypkg string, silent int, eapi string) [3]string {
	catPSplit := CatPkgSplit(mypkg, 1, eapi)
	if catPSplit == [4]string{} {
		return [3]string{}
	}
	cat, pn, ver, rev := catPSplit[0], catPSplit[1], catPSplit[2], catPSplit[3]
	if cat == missingCat && !strings.Contains(mypkg, "/") {
		return [3]string{pn, ver, rev}
	}
	return [3]string{cat + "/" + pn, ver, rev}
}

// ""
func CpvGetKey(mycpv, eapi string) string {
	//return mycpv.cp //TODO
	mySplit := CatPkgSplit(mycpv, 1, eapi)
	if mySplit != [4]string{} {
		return mySplit[0] + "/" + mySplit[1]
	}
	// warnings.warn("portage.versions.cpv_getkey() " + \
	// "called with invalid cpv: '%s'" % (mycpv,),
	// DeprecationWarning, stacklevel=2) //TODO
	mySlash := strings.SplitN(mycpv, "/", 2)
	myNSplit := PkgSplit_(mySlash[0], eapi)
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

// ""
func CpvGetVersion(mycpv, eapi string) string {
	//return mycpv.version //TODO
	cp := CpvGetKey(mycpv, eapi)
	if cp == "" {
		return ""
	}
	return mycpv[len(cp+"-"):]
}

func CmpSortKey(_cmp_func func(cpv1, cpv2, eapi string) (int, error)) func(string, string) bool {
	return func(lhs, rhs string) bool {
		i, _ := _cmp_func(lhs, rhs, "")
		return i < 0
	}
}

func CpvSortKey[T interfaces.ISettings](eapi string) func(string, string) bool {
	var splitCache = map[string]*PkgStr[T]{}
	cmpCpv := func(cpv1, cpv2, eapi string) (int, error) {
		split1, ok := splitCache[cpv1]
		var empty T
		if !ok {
			//split1 = cpv1.pv //TODO
			split1 = NewPkgStr[T](cpv1, nil, empty, eapi, "", "", 0, 0, "", 0, nil)
			splitCache[cpv1] = split1
		}
		split2 := NewPkgStr[T](cpv1, nil, empty, eapi, "", "", 0, 0, "", 0, nil)
		splitCache[cpv2] = split2
		//return VerCmp(cpv1.version, cpv2.version)
		return VerCmp(cpv1, cpv2)
	}
	return CmpSortKey(cmpCpv)
}

func CatSplit(mydep string) []string {
	return strings.SplitN(mydep, "/", 2)
}

func Best(myMatches []string, eapi string) string {
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
		v, _ := VerCmp(v1, v2)
		if v > 0 {
			bestMatch = x
			v2 = v1
		}
	}
	return bestMatch
}
