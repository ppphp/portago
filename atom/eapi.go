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

func eapiHasHdepend(eapi string) bool {
	return map[string]bool{"5-hdepend": true}[eapi]
}

func eapiAllowsPackageProvided(eapi string) bool {
	return map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "6": true}[eapi]
}

func eapiHasBdepend(eapi string) bool {
	return !map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true, "4-python": true, "4-slot-abi": true, "5": true, "5-progress": true, "6": true}[eapi]
}

func eapiHasTargetroot(eapi string) bool {
	return map[string]bool{"5-hdepend": true}[eapi]
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
	emptyGroupsAlwaysTrue, exportsEbuildPhaseFunc, exportsPortdir,
	exportsEclassdir, featureFlagTest, featureFlagTargetroot, hdepend,
	iuseDefaults, iuseEffective, pathVariablesEndWithTrailingSlash,
	posixishLocale, repoDeps, requiredUse, requiredUseAtMostOneOf,
	slotDeps, SlotOperator, srcUriArrows, strongBlocks, sysroot,
	useDeps, useDepDefaults bool
}

var eapiAttrsCache map[string]eapiAttrs

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
		eapiAllowsPackageProvided(eapi),
		eapiHasBdepend(eapi),
		eapiHasBroot(eapi),
		eapiAllowsDotsInPn(eapi),
		eapiAllowsDotsInUseFlags(eapi),
		eapiEmptyGroupsAlwaysTrue(eapi),
		eapiExportsEbuildPhaseFunc(eapi),
		eapiExportsPortdir(eapi),
		eapiExportsEclassdir(eapi),
		false,
		eapiHasTargetroot(eapi),
		eapiHasHdepend(eapi),
		eapiHasIuseDefaults(eapi),
		eapiHasIuseEffective(eapi),
		eapiPathVariablesEndWithTrailingSlash(eapi),
		eapiRequiresPosixishLocale(eapi),
		EapiHasRepoDeps(eapi),
		eapiHasRequiredUse(eapi),
		eapiHasRequiredUse(eapi),
		eapiHasSlotDeps(eapi),
		eapiHasSlotOperator(eapi),
		eapiHasSrcUriArrows(eapi),
		eapiHasStrongBlocks(eapi),
		eapiHasSysroot(eapi),
		eapiHasUseDeps(eapi),
		eapiHasUseDepDefaults(eapi),
	}
	eapiAttrsCache[eapi] = e
	return e
}
