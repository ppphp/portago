package ebuild

import (
	"fmt"
	"github.com/ppphp/portago/pkg/dep"
	"github.com/ppphp/portago/pkg/util"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"path"
	"sort"
	"strings"
)

type LicenseManager struct {
	acceptLicenseStr string
	acceptLicense    []string
	_plicensedict    map[string]map[*dep.Atom][]string
	undefLicGroups   map[string]bool
	licenseGroups    map[string]map[string]bool
}

func NewLicenseManager(licenseGroupLocations []string, absUserConfig string, userConfig bool) *LicenseManager { // t
	l := &LicenseManager{}
	l.acceptLicenseStr = ""
	l.acceptLicense = nil
	l.licenseGroups = map[string]map[string]bool{}
	l._plicensedict = map[string]map[*dep.Atom][]string{}
	l.undefLicGroups = map[string]bool{}
	if userConfig {
		licenseGroupLocations = append(licenseGroupLocations, absUserConfig)
	}
	l.readLicenseGroups(licenseGroupLocations)
	if userConfig {
		l.readUserConfig(absUserConfig)
	}
	return l
}

func (l *LicenseManager) readUserConfig(absUserConfig string) {
	licDictt := util.GrabDictPackage(path.Join(absUserConfig, "package.license"), false, true, false, true, true, false, false, false, "", "")
	for k, v := range licDictt {
		if _, ok := l._plicensedict[k.cp]; !ok {
			l._plicensedict[k.cp] = map[*dep.Atom][]string{k: v}
		} else {
			l._plicensedict[k.cp][k] = v
		}
	}
}

func (l *LicenseManager) readLicenseGroups(locations []string) {
	for _, loc := range locations {
		for k, v := range util.GrabDict(path.Join(loc, "license_groups"), false, false, false, true, false) {
			if _, ok := l.licenseGroups[k]; !ok {
				l.licenseGroups[k] = map[string]bool{}
			}
			for _, w := range v {
				l.licenseGroups[k][w] = true
			}
		}
	}
}

func (l *LicenseManager) extractGlobalChanges(old string) string { // ""
	ret := old
	atomLicenseMap := l._plicensedict["*/*"]
	if len(atomLicenseMap) > 0 {
		var v []string = nil
		for a, m := range atomLicenseMap {
			if a.value == "*/*" {
				v = m
				delete(atomLicenseMap, a)
				break
			}
		}
		if v != nil {
			ret = strings.Join(v, " ")
			if old != "" {
				ret = old + " " + ret
			}
			if len(atomLicenseMap) == 0 {
				delete(l._plicensedict, "*/*")
			}
		}
	}
	return ret
}

func (l *LicenseManager) expandLicenseTokens(tokens []string) []string {
	expandedTokens := []string{}
	for _, x := range tokens {
		expandedTokens = append(expandedTokens, l._expandLicenseToken(x, nil)...)
	}
	return expandedTokens
}

func (l *LicenseManager) _expandLicenseToken(token string, traversedGroups map[string]bool) []string {
	negate := false
	rValue := []string{}
	licenseName := ""
	if strings.HasPrefix(token, "-") {
		negate = true
		licenseName = token[1:]
	} else {
		licenseName = token
	}
	if !strings.HasPrefix(licenseName, "@") {
		rValue = append(rValue, token)
		return rValue
	}

	groupName := licenseName[1:]
	if traversedGroups == nil {
		traversedGroups = map[string]bool{}
	}
	licenseGroup := l.licenseGroups[groupName]
	if traversedGroups[groupName] {
		msg.WriteMsg(fmt.Sprintf("Circular license group reference detected in '%s'\n", groupName), -1, nil)
		rValue = append(rValue, "@"+groupName)
	} else if len(licenseGroup) > 0 {
		traversedGroups[groupName] = true
		for li := range licenseGroup {
			if strings.HasPrefix(li, "-") {
				msg.WriteMsg(fmt.Sprintf("Skipping invalid element %s in license group '%s'\n", li, groupName), -1, nil)
			} else {
				rValue = append(rValue, l._expandLicenseToken(li, traversedGroups)...)
			}
		}
	} else {
		if len(l.licenseGroups) > 0 && !l.undefLicGroups[groupName] {
			l.undefLicGroups[groupName] = true
			msg.WriteMsg(fmt.Sprintf("Undefined license group '%s'\n", groupName), -1, nil)
			rValue = append(rValue, "@"+groupName)
		}
	}
	if negate {
		for k := range rValue {
			rValue[k] = "-" + rValue[k]
		}
	}
	return rValue
}

func (l *LicenseManager) _getPkgAcceptLicense(cpv *versions.PkgStr, slot, repo string) []string {
	acceptLicense := l.acceptLicense
	cp := versions.cpvGetKey(cpv.string, "")
	cpdict := l._plicensedict[cp]
	if len(cpdict) > 0 {
		if cpv.slot == "" {
			cpv = versions.NewPkgStr(cpv.string, nil, nil, "", repo, slot, 0, 0, "", 0, nil)
		}
		plicenceList := orderedByAtomSpecificity(cpdict, cpv, "")
		if len(plicenceList) > 0 {
			acceptLicense = append(l.acceptLicense[:0:0], l.acceptLicense...)
		}
		for _, x := range plicenceList {
			acceptLicense = append(acceptLicense, x...)
		}
	}
	return acceptLicense
}

func (l *LicenseManager) getPrunnedAcceptLicense(cpv *versions.PkgStr, use map[string]bool, lic, slot, repo string) string {
	licenses := map[string]bool{}
	for _, u := range dep.useReduce(lic, use, nil, false, nil, false, "", false, true, nil, nil, false) {
		licenses[u] = true
	}
	acceptLicense := l._getPkgAcceptLicense(cpv, slot, repo)
	if len(acceptLicense) > 0 {
		acceptableLicenses := map[string]bool{}
		for _, x := range acceptLicense {
			if x == "*" {
				for k := range licenses {
					acceptableLicenses[k] = true
				}
			} else if x == "-*" {
				acceptableLicenses = map[string]bool{}
			} else if x[:1] == "-" {
				delete(acceptableLicenses, x[1:])
			} else if licenses[x] {
				acceptableLicenses[x] = true
			}
		}
		licenses = acceptableLicenses
	}
	licensesS := []string{}
	for k := range licenses {
		licensesS = append(licensesS, k)
	}
	sort.Strings(licensesS)
	return strings.Join(licensesS, " ")
}

func (l *LicenseManager) getMissingLicenses(cpv *versions.PkgStr, use, lic, slot, repo string) []string {
	licenses := map[string]bool{}
	for _, u := range dep.useReduce(lic, nil, nil, true, nil, false, "", false, true, nil, nil, false) {
		licenses[u] = true
	}
	delete(licenses, "||")

	acceptableLicenses := map[string]bool{}
	for _, x := range l._getPkgAcceptLicense(cpv, slot, repo) {
		if x == "*" {
			for k := range licenses {
				acceptableLicenses[k] = true
			}
		} else if x == "-*" {
			acceptableLicenses = map[string]bool{}
		} else if x[:1] == "-" {
			delete(acceptableLicenses, x[1:])
		} else {
			acceptableLicenses[x] = true
		}
	}
	licenseStr := lic
	useM := map[string]bool{}
	if strings.Contains(licenseStr, "?") {
		for _, u := range strings.Fields(use) {
			useM[u] = true
		}
	}
	licenseStruct := dep.useReduce(licenseStr, useM, []string{}, false, []string{}, false, "", false, false, nil, nil, false)

	return l._getMaskedLicenses(licenseStruct, acceptableLicenses)
}

func (l *LicenseManager) _getMaskedLicenses(licenseStruct []string, acceptableLicenses map[string]bool) []string {
	if len(licenseStruct) == 0 {
		return []string{}
	}
	if licenseStruct[0] == "||" {
		ret := []string{}
		for _, element := range licenseStruct[1:] {
			if acceptableLicenses[element] {
				return []string{}
			}
			ret = append(ret, element)
		}
		return ret
	}
	ret := []string{}
	for _, element := range licenseStruct {
		if !acceptableLicenses[element] {
			ret = append(ret, element)
		}
	}
	return ret
}

func (l *LicenseManager) setAcceptLicenseStr(acceptLicenseStr string) {
	if acceptLicenseStr != l.acceptLicenseStr {
		l.acceptLicenseStr = acceptLicenseStr
		l.acceptLicense = l.expandLicenseTokens(strings.Fields(acceptLicenseStr))
	}
}
