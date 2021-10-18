package atom

import "strings"

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

func eapiExportsAa(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiExportsKv(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiExportsMergeType(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true}[eapi]
}

func eapiExportsReplaceVars(eapi string) bool {
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

func eapiExportsRepository(eapi string) bool {
	return map[string]bool{"4-python": true, "5-progress": true}[eapi]
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

func eapiAllowsDotsInPn(eapi string) bool {
	return map[string]bool{"4-python": true, "5-progress": true}[eapi]
}

func eapiAllowsDotsInUseFlags(eapi string) bool {
	return map[string]bool{"4-python": true, "5-progress": true}[eapi]
}

func eapiSupportsStableUseForcingAndMasking(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true}[eapi]
}

func eapiAllowsDirectoriesOnProfileLevelAndRepositoryLevel(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-slot-abi": true, "5": true, "6": true}[eapi]
}

func eapiHasUseAliases(eapi string) bool {
	return map[string]bool{"4-python": true, "5-progress": true}[eapi]
}

func eapiHasAutomaticUnpackDependencies(eapi string) bool {
	return map[string]bool{"5-progress": true}[eapi]
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

func eapiEmptyGroupsAlwaysTrue(eapi string) bool {
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
	testingEapis    = map[string]bool{"4-python": true, "4-slot-abi": true, "5-progress": true, "5-hdepend": true, "7_pre1": true, "7": true}
	deprecatedEapis = map[string]bool{"4_pre1": true, "3_pre2": true, "3_pre1": true, "5_pre1": true, "5_pre2": true, "6_pre1": true}
	supportedEapis  = map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "5": true, "6": true,
		"4-python": true, "4-slot-abi": true, "5-progress": true, "5-hdepend": true, "7_pre1": true, "7": true,
		"4_pre1": true, "3_pre2": true, "3_pre1": true, "5_pre1": true, "5_pre2": true, "6_pre1": true}
)

func eapiIsDeprecated(eapi string) bool {
	return deprecatedEapis[eapi]
}
func eapiIsSupported(eapi string) bool {
	return supportedEapis[strings.TrimSpace(eapi)]
}

type eapiAttrs struct {
	allowsPackageProvided, bdepend, broot, DotsInPn, dotsInUseFlags,
	emptyGroupsAlwaysTrue, exportsAa, exportsEbuildPhaseFunc,
	exportsEclassdir, exportsKv, exportsMergeType, exportsPortdir,
	exportsReplaceVars, featureFlagTest, idepend, iuseDefaults,
	iuseEffective, posixishLocale, pathVariablesEndWithTrailingSlash,
	prefix, repoDeps, requiredUse, requiredUseAtMostOneOf,
	selectiveSrcUriRestriction, slotOperator, slotDeps, srcUriArrows,
	strongBlocks, useDeps, useDepDefaults, sysroot bool
}

var eapiAttrsCache = map[string]eapiAttrs{}

func getEapiAttrs(eapi string) eapiAttrs {
	if e, ok := eapiAttrsCache[eapi]; ok {
		return e
	}
	if eapi != "" && !eapiIsSupported(eapi) {
		e := eapiAttrs{}
		eapiAttrsCache[eapi] = e
		return e
	}
	e := eapiAttrs{
		eapi == "" || eapiAllowsPackageProvided(eapi),
		eapi != "" && eapiHasBdepend(eapi),
		eapi == "" || eapiHasBroot(eapi),
		eapi == "" || eapiAllowsDotsInPn(eapi),
		eapi == "" || eapiAllowsDotsInUseFlags(eapi),
		eapi != "" && eapiHasUseDepDefaults(eapi),
		eapi != "" && eapiEmptyGroupsAlwaysTrue(eapi),
		eapi == "" || eapiExportsEbuildPhaseFunc(eapi),
		eapi != "" && eapiExportsEclassdir(eapi),
		eapi != "" && eapiExportsKv(eapi),
		eapi == "" || eapiExportsMergeType(eapi),
		eapi == "" || eapiExportsPortdir(eapi),
		eapi == "" || eapiExportsReplaceVars(eapi),
		false,
		eapi != "" && eapiHasIdepend(eapi),
		eapi == "" || eapiHasIuseDefaults(eapi),
		eapi != "" && eapiHasIuseEffective(eapi),
		eapi != "" && eapiRequiresPosixishLocale(eapi),
		eapi != "" && eapiPathVariablesEndWithTrailingSlash(eapi),
		eapi == "" || eapiSupportsPrefix(eapi),
		eapi == "" || EapiHasRepoDeps(eapi),
		eapi == "" || eapiHasRequiredUse(eapi),
		eapi == "" || eapiHasRequiredUseAtMostOneOf(eapi),
		eapi == "" || eapiHasSelectiveSrcUriRestriction(eapi),
		eapi == "" || eapiHasSlotOperator(eapi),
		eapi == "" || eapiHasSlotDeps(eapi),
		eapi == "" || eapiHasSrcUriArrows(eapi),
		eapi == "" || eapiHasStrongBlocks(eapi),
		eapi == "" || eapiHasUseDeps(eapi),
		eapi == "" || eapiHasUseDepDefaults(eapi),
		eapi == "" || eapiHasSysroot(eapi),
	}
	eapiAttrsCache[eapi] = e
	return e
}
