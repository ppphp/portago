package atom

import "github.com/ppphp/portago/pkg/output"

func emergeHelp() {
	bold := output.Bold
	turquoise := output.Turquoise
	green := output.Green
	println(bold("emerge:") + " command-line interface to the Portage system")
	println(bold("Usage:"))
	println("   " + turquoise("emerge") + " [ " + green("options") + " ] [ " + green("action") + " ] [ " + turquoise("ebuild") + " | " + turquoise("tbz2") + " | " + turquoise("file") + " | " + turquoise("@set") + " | " + turquoise("atom") + " ] [ ... ]")
	println("   " + turquoise("emerge") + " [ " + green("options") + " ] [ " + green("action") + " ] < " + turquoise("@system") + " | " + turquoise("@world") + " >")
	println("   " + turquoise("emerge") + " < " + turquoise("--sync") + " | " + turquoise("--metadata") + " | " + turquoise("--info") + " >")
	println("   " + turquoise("emerge") + " " + turquoise("--resume") + " [ " + green("--pretend") + " | " + green("--ask") + " | " + green("--skipfirst") + " ]")
	println("   " + turquoise("emerge") + " " + turquoise("--help"))
	println(bold("Options:") + " " + green("-") + "[" + green("abBcCdDefgGhjkKlnNoOpPqrsStuUvVw") + "]")
	println("          [ " + green("--color") + " < " + turquoise("y") + " | " + turquoise("n") + " >            ] [ " + green("--columns") + "    ]")
	println("          [ " + green("--complete-graph") + "             ] [ " + green("--deep") + "       ]")
	println("          [ " + green("--jobs") + " " + turquoise("JOBS") + " ] [ " + green("--keep-going") + " ] [ " + green("--load-average") + " " + turquoise("LOAD") + "            ]")
	println("          [ " + green("--newrepo") + "   ] [ " + green("--newuse") + "     ] [ " + green("--noconfmem") + "  ] [ " + green("--nospinner") + "   ]")
	println("          [ " + green("--oneshot") + "   ] [ " + green("--onlydeps") + "   ] [ " + green("--quiet-build") + " [ " + turquoise("y") + " | " + turquoise("n") + " ]        ]")
	println("          [ " + green("--reinstall ") + turquoise("changed-use") + "      ] [ " + green("--with-bdeps") + " < " + turquoise("y") + " | " + turquoise("n") + " >         ]")
	println(bold("Actions:") + "  [ " + green("--depclean") + " | " + green("--list-sets") + " | " + green("--search") + " | " + green("--sync") + " | " + green("--version") + "        ]")
	println()
	println("   For more help consult the man page.")
}
