package dbapi

import "strings"

func expandNewVirt(vardb *VarDB, atom Atom) <-chan Atom {
	out := make(chan Atom)

	if _, ok := atom.(Atom); !ok {
		atom = Atom(atom)
	}

	if !strings.HasPrefix(atom.CP(), "virtual/") {
		out <- atom
		close(out)
		return out
	}

	traversed := make(map[string]bool)
	stack := []Atom{atom}

	for len(stack) > 0 {
		atom := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if atom.Blocker() || !strings.HasPrefix(atom.CP(), "virtual/") {
			out <- atom
			continue
		}

		matches := vardb.Match(atom)
		if len(matches) == 0 || !strings.HasPrefix(matches[len(matches)-1], "virtual/") {
			out <- atom
			continue
		}

		virtCPV := matches[len(matches)-1]
		if traversed[virtCPV] {
			continue
		}

		traversed[virtCPV] = true
		eapi, iuse, rdepend, use := vardb.AuxGet(virtCPV, []string{"EAPI", "IUSE", "RDEPEND", "USE"})
		if !portage.EAPIIsSupported(eapi) {
			out <- atom
			continue
		}

		eapiAttrs := getEAPIAttrs(eapi)
		// Validate IUSE and IUSE, for early detection of vardb corruption.
		useflagRe := getUseflagRe(eapi)
		validIUSE := []string{}
		for _, x := range strings.Split(iuse, " ") {
			if len(x) > 0 && (x[0] == '+' || x[0] == '-') {
				x = x[1:]
			}
			if useflagRe.MatchString(x) {
				validIUSE = append(validIUSE, x)
			}
		}
		validIUSESet := strset.New(validIUSE...)

		var iuseImplicitMatch func(string) bool
		if eapiAttrs.IUSEEffective {
			iuseImplicitMatch = vardb.Settings.IUSEEffectiveMatch
		} else {
			iuseImplicitMatch = vardb.Settings.IUSEImplicitMatch
		}

		validUSE := []string{}
		for _, x := range strings.Split(use, " ") {
			if validIUSESet.Has(x) || iuseImplicitMatch(x) {
				validUSE = append(validUSE, x)
			}
		}
		validUSESet := strset.New(validUSE...)

		success, atoms := portage.DepCheck(
			rdepend,
			nil,
			vardb.Settings,
			portage.DepCheckOpts{
				MyUse:  validUSESet,
				MyRoot: vardb.Settings["EROOT"],
				Trees: map[string]portage.DepCheckTree{
					vardb.Settings["EROOT"]: {
						PortTree: vardb.VarTree,
						VarTree:  vardb.VarTree,
					},
				},
			},
		)

		if success {
			for _, a := range atoms {
				stack = append(stack, a)
			}
		} else {
			out <- atom
		}
	}

	close(out)
	return out
}
