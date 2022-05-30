package emerge

import (
	"fmt"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/util/msg"
)

func create_depgraph_params(myopts map[string]string, myaction string) map[string]interface{} {
	myparams := map[string]interface{}{"recurse": true}

	binpkg_respect_use, ok := myopts["--binpkg-respect-use"]
	if ok {
		myparams["binpkg_respect_use"] = binpkg_respect_use
	} else if !myutil.Inmss(myopts, "--usepkgonly") {
		myparams["binpkg_respect_use"] = "auto"
	}

	autounmask_keep_keywords := myopts["--autounmask-keep-keywords"]
	autounmask_keep_masks := myopts["--autounmask-keep-masks"]

	autounmask, aok := myopts["--autounmask"]
	autounmask_license, ok := myopts["--autounmask-license"]
	if !ok {
		if autounmask != "" {
			autounmask_license = "y"
		} else {
			autounmask_license = "n"
		}
	}
	autounmask_use := myopts["--autounmask-use"]
	if myparams["binpkg_respect_use"] == "y" {
		autounmask_use = "n"
	}

	autounmaskB := false
	if autounmask != "n" {
		if !aok {
			if autounmask_use == "" || autounmask_use == "y" {
				autounmaskB = true
			}
			if autounmask_license == "y" {
				autounmaskB = true
			}

			if autounmask_keep_keywords == "" {
				autounmask_keep_keywords = "true"
			}
			if autounmask_keep_masks == "" {
				autounmask_keep_masks = "true"
			}
		} else {
			autounmaskB = true
		}
	}

	myparams["autounmask"] = autounmaskB
	myparams["autounmask_keep_use"] = false
	if autounmask_use == "n" {
		myparams["autounmask_keep_use"] = true
	}
	myparams["autounmask_keep_license"] = true
	if autounmask_license == "y" {
		myparams["autounmask_keep_license"] = false
	}
	myparams["autounmask_keep_keywords"] = true
	if autounmask_keep_keywords == "" || autounmask_keep_keywords == "n" {
		myparams["autounmask_keep_keywords"] = false
	}
	myparams["autounmask_keep_masks"] = true
	if autounmask_keep_masks == "" || autounmask_keep_masks == "n" {
		myparams["autounmask_keep_masks"] = false
	}

	bdeps, ok := myopts["--with-bdeps"]
	if ok {
		myparams["bdeps"] = bdeps
	} else if myaction == "remove" || (myopts["--with-bdeps-auto"] != "n" &&
		!myutil.Inmss(myopts, "--usepkg")) {
		myparams["bdeps"] = "auto"
	}

	ignore_built_slot_operator_deps, ok := myopts["--ignore-built-slot-operator-deps"]
	if ok {
		myparams["ignore_built_slot_operator_deps"] = ignore_built_slot_operator_deps
	}

	myparams["ignore_soname_deps"], ok = myopts["--ignore-soname-deps"]
	if !ok {
		myparams["ignore_soname_deps"] = "y"
	}

	dynamic_deps := myopts["--dynamic-deps"] != "n" && !myutil.Inmss(myopts, "--nodeps")
	if dynamic_deps {
		myparams["dynamic_deps"] = true
	}

	myparams["implicit_system_deps"] = myopts["--implicit-system-deps"] != "n"

	if myaction == "remove" {
		myparams["remove"] = true
		myparams["complete"] = true
		myparams["selective"] = true
		return myparams
	}

	if myopts["--ignore-world"] == "true" {
		myparams["ignore_world"] = true
	}

	rebuild_if_new_slot, ok := myopts["--rebuild-if-new-slot"]
	if ok {
		myparams["rebuild_if_new_slot"] = rebuild_if_new_slot
	}

	changed_slot := myopts["--changed-slot"] == "true"
	if changed_slot {
		myparams["changed_slot"] = true
	}

	if myutil.Inmss(myopts, "--update") || myutil.Inmss(myopts, "--newrepo") ||
		myutil.Inmss(myopts, "--newuse") || myutil.Inmss(myopts, "--reinstall") ||
		myutil.Inmss(myopts, "--noreplace") ||
		(!myutil.Inmss(myopts, "--changed-deps") || myopts["--changed-deps"] != "n") ||
		changed_slot || (!myutil.Inmss(myopts, "--selective") || myopts["--selective"] != "n") {
		myparams["selective"] = true
	}

	deep, ok := myopts["--deep"]
	if ok && deep != "0" {
		myparams["deep"] = deep
	}

	complete_if_new_use, ok := myopts["--complete-graph-if-new-use"]
	if ok {
		myparams["complete_if_new_use"] = complete_if_new_use
	}

	complete_if_new_ver, ok := myopts["--complete-graph-if-new-ver"]
	if ok {
		myparams["complete_if_new_ver"] = complete_if_new_ver
	}

	if myutil.Inmss(myopts, "--complete-graph") ||
		myutil.Inmss(myopts, "--rebuild-if-new-rev") ||
		myutil.Inmss(myopts, "--rebuild-if-new-ver") ||
		myutil.Inmss(myopts, "--rebuild-if-unbuilt") {
		myparams["complete"] = true
	}
	if myutil.Inmss(myopts, "--emptytree") {
		myparams["empty"] = true
		myparams["deep"] = true
		delete(myparams, "selective")
	}

	if myutil.Inmss(myopts, "--nodeps") {
		delete(myparams, "recurse")
		delete(myparams, "deep")
		delete(myparams, "complete")
	}

	rebuilt_binaries := myopts["--rebuilt-binaries"]
	if rebuilt_binaries == "true" || rebuilt_binaries != "n" &&
		myutil.Inmss(myopts, "--usepkgonly") && myopts["--deep"] == "true" &&
		myutil.Inmss(myopts, "--update") {
		myparams["rebuilt_binaries"] = true
	}

	binpkg_changed_deps, ok := myopts["--binpkg-changed-deps"]
	if ok {
		myparams["binpkg_changed_deps"] = binpkg_changed_deps
	} else if !myutil.Inmss(myopts, "--usepkgonly") {
		myparams["binpkg_changed_deps"] = "auto"
	}

	changed_deps, ok := myopts["--changed-deps"]
	if ok {
		myparams["changed_deps"] = changed_deps
	}

	changed_deps_report := myopts["--changed-deps-report"] == "y"
	if changed_deps_report {
		myparams["changed_deps_report"] = true
	}

	if myopts["--selective"] == "n" {
		delete(myparams, "selective")
	}

	with_test_deps, ok := myopts["--with-test-deps"]
	if ok {
		myparams["with_test_deps"] = with_test_deps
	}

	if myutil.Inmss(myopts, "--debug") {
		msg.WriteMsgLevel(fmt.Sprintf("\n\nmyparams %s\n\n", myparams), -1, 10)
	}

	return myparams
}
