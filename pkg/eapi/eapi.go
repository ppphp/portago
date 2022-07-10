package eapi

import (
	"fmt"
	cons "github.com/ppphp/portago/pkg/const"
	"github.com/ppphp/portago/pkg/myutil"
	"strings"
)

func eapiHasIuseDefaults(eapi string) bool {
	return eapi != "0"
}

func eapiHasIuseEffective(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true}[eapi]
}

func eapiHasSlotDeps(eapi string) bool {
	return eapi != "0"
}

func eapiHasSlotOperator(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true}[eapi]
}

func eapiHasSrcUriArrows(eapi string) bool {
	return !map[string]bool{"0": true, "1": true}[eapi]
}

func eapiHasSelectiveSrcUriRestriction(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true,
		"5": true, "5-progress": true, "6": true, "7": true}[eapi]
}

func eapiHasUseDeps(eapi string) bool {
	return !map[string]bool{"0": true, "1": true}[eapi]
}

func eapiHasStrongBlocks(eapi string) bool {
	return !map[string]bool{"0": true, "1": true}[eapi]
}

func eapiHasSrcPrepareAndSrcConfigure(eapi string) bool {
	return !map[string]bool{"0": true, "1": true}[eapi]
}

func eapiSupportsPrefix(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true}[eapi]
}

func EapiExportsAa(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiExportsKv(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func EapiExportsMergeType(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func EapiExportsReplaceVars(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiExportsEbuildPhaseFunc(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true}[eapi]
}

func eapiExportsPortdir(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "6": true}[eapi]
}

func eapiExportsEclassdir(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "6": true}[eapi]
}

func eapiHasPkgPretend(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiHasImplicitRdepend(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiHasDosedDohard(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiHasRequiredUse(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiHasRequiredUseAtMostOneOf(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true}[eapi]
}

func eapiHasUseDepDefaults(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiRequiresPosixishLocale(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "5-hdepend": true}[eapi]
}

func EapiHasRepoDeps(eapi string) bool {
	return map[string]bool{"4-python": true, "5-progress": true}[eapi]
}

func EapiSupportsStableUseForcingAndMasking(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true}[eapi]
}

func EapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-slot-abi": true, "5": true, "6": true}[eapi]
}

func eapiAllowsPackageProvided(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "6": true}[eapi]
}

func eapiHasBdepend(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "6": true}[eapi]
}

func eapiHasIdepend(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "6": true, "7": true}[eapi]
}

func eapiEmptyGroupsAlwaystrue(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "6": true}[eapi]
}

func eapiPathVariablesEndWithTrailingSlash(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "6": true}[eapi]
}

func eapiHasBroot(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "5-hdepend": true, "6": true}[eapi]
}

func eapiHasSysroot(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "5-hdepend": true, "6": true}[eapi]
}

var (
	testingEapis    = map[string]bool{}
	deprecatedEapis = map[string]bool{"3_pre1": true, "3_pre2": true, "4_pre1": true, "4-slot-abi": true, "5_pre1": true, "5_pre2": true, "6_pre1": true, "7_pre1": true}
	SupportedEapis  = myutil.CopyMapSB(deprecatedEapis)
)

func init() {
	for x := 0; x <= cons.EAPI; x++ {
		SupportedEapis[fmt.Sprint(x)] = true
	}
}

func eapiIsDeprecated(eapi string) bool {
	return deprecatedEapis[eapi]
}

func EapiIsSupported(eapi string) bool {
	return SupportedEapis[strings.TrimSpace(eapi)]
}

type EapiAttrs struct {
	AllowsPackageProvided, bdepend, Broot, exportsAa, ExportsEbuildPhaseFunc,
	ExportsEclassdir, exportsKv, exportsMergeType, ExportsPortdir,
	exportsReplaceVars, FeatureFlagTest, idepend, iuseDefaults,
	IuseEffective, PosixishLocale, PathVariablesEndWithTrailingSlash,
	prefix, RepoDeps, requiredUse, RequiredUseAtMostOneOf,
	SelectiveSrcUriRestriction, SlotOperator, SlotDeps, SrcUriArrows,
	StrongBlocks, UseDeps, UseDepDefaults, EmptyGroupsAlwaysTrue, Sysroot bool
}

type Eapi struct {
	_eapi_val int

	ALL_EAPIS []string
}

func NewEapi(eapi_string string) *Eapi {
	e := &Eapi{_eapi_val: -1}
	ALL_EAPIS := []string{
		"0",
		"1",
		"2",
		"3",
		"4",
		"4-slot-abi",
		"5",
		"6",
		"7",
		"8"}

	if !myutil.Ins(ALL_EAPIS, eapi_string) {
		//raise ValueError(f"'{eapi_string}' not recognized as a valid EAPI")
	}
	e._eapi_val = myutil.Toi(strings.Split(eapi_string, "-")[0])

	return e
}

func (e *Eapi) ge(other *Eapi) bool {
	return e._eapi_val >= other._eapi_val
}

func (e *Eapi) le(other *Eapi) bool {
	return e._eapi_val <= other._eapi_val
}

// ""
func GetEapiAttrs(eapi_str string) EapiAttrs {
	//logging.info("cache info: {}".format(_get_eapi_attrs.cache_info()))
	if eapi_str == "" || !EapiIsSupported(eapi_str) {
		return EapiAttrs{
			true,
			false,
			true,
			false,
			true,
			false,
			false,
			true,
			true,
			true,
			false,
			false,
			true,
			false,
			false,
			false,
			true,
			true,
			true,
			true,
			true,
			true,
			true,
			true,
			true,
			true,
			true,
			false,
			true,
		}
	} else {
		eapi := NewEapi(eapi_str)
		return EapiAttrs{
			eapi.le(NewEapi("6")),
			eapi.ge(NewEapi("7")),
			eapi.ge(NewEapi("7")),
			eapi.le(NewEapi("3")),
			eapi.ge(NewEapi("5")),
			eapi.le(NewEapi("6")),
			eapi.le(NewEapi("3")),
			eapi.ge(NewEapi("4")),
			eapi.le(NewEapi("6")),
			eapi.ge(NewEapi("4")),
			false,
			eapi.ge(NewEapi("8")),
			eapi.ge(NewEapi("1")),
			eapi.ge(NewEapi("5")),
			eapi.ge(NewEapi("6")),
			eapi.le(NewEapi("6")),
			eapi.ge(NewEapi("3")),
			false,
			eapi.ge(NewEapi("4")),
			eapi.ge(NewEapi("5")),
			eapi.ge(NewEapi("8")),
			eapi.ge(NewEapi("5")),
			eapi.ge(NewEapi("1")),
			eapi.ge(NewEapi("2")),
			eapi.ge(NewEapi("2")),
			eapi.ge(NewEapi("2")),
			eapi.ge(NewEapi("4")),
			eapi.le(NewEapi("6")),
			eapi.ge(NewEapi("7")),
		}
	}
}
