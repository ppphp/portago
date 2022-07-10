package ebuild

import (
	"bytes"
	"fmt"
	"github.com/ppphp/portago/pkg/dep"
	eapi2 "github.com/ppphp/portago/pkg/eapi"
	"github.com/ppphp/portago/pkg/ebuild/config"
	"github.com/ppphp/portago/pkg/elog"
	"github.com/ppphp/portago/pkg/myutil"
	"github.com/ppphp/portago/pkg/output"
	"github.com/ppphp/portago/pkg/portage"
	"github.com/ppphp/portago/pkg/util/msg"
	"github.com/ppphp/portago/pkg/versions"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type QueryCommand struct {
	phase    string
	settings *config.Config
}

var QueryCommand_db *portage.TreesDict = nil

func (q *QueryCommand) get_db() *portage.TreesDict {
	if QueryCommand_db != nil {
		return QueryCommand_db
	}
	return portage.Db()
}

func NewQueryCommand(settings *config.Config, phase string) *QueryCommand {
	q := &QueryCommand{}
	q.settings = settings
	q.phase = phase
	return q
}

func (q *QueryCommand) __call__(argv []string) (string, string, int) {
	cmd := argv[0]
	root := argv[1]
	args := argv[2:]

	warnings := []string{}
	warnings_str := ""

	db := q.get_db()
	eapi := q.settings.ValueDict["EAPI"]

	if root == "" {
		root = string(os.PathSeparator)
	}
	root = strings.TrimRight(msg.NormalizePath(root), string(os.PathSeparator)) + string(os.PathSeparator)
	if _, ok := db.Values()[root]; !ok {
		return "", fmt.Sprintf("%s: Invalid ROOT: %s\n", cmd, root), 3
	}

	portdb := db.Values()[root].PortTree().dbapi
	vardb := db.Values()[root].VarTree().dbapi

	var atom1 *dep.Atom
	if cmd == "best_version" || cmd == "has_version" {
		allow_repo := eapi2.EapiHasRepoDeps(eapi)
		var err error
		atom1, err = dep.NewAtom(args[0], nil, false, &allow_repo, nil, "", nil, nil)
		if err != nil {
			//except InvalidAtom:
			return "", fmt.Sprintf("%s: Invalid atom: %s\n", cmd, args[0]), 2
		}

		atom1, err = dep.NewAtom(args[0], nil, false, &allow_repo, nil, eapi, nil, nil)
		if err != nil {
			//except InvalidAtom:
			warnings = append(warnings, fmt.Sprintf("QA Notice: %s: %s", cmd, err))
		}

		use := q.settings.ValueDict["PORTAGE_BUILT_USE"]
		if use == "" {
			use = q.settings.ValueDict["PORTAGE_USE"]
		}

		useSB := map[string]bool{}
		for _, v := range strings.Fields(use) {
			useSB[v] = true
		}
		atom1 = atom1.EvaluateConditionals(useSB)
	}

	if len(warnings) > 0 {
		warnings_str = q._elog("eqawarn", warnings)
	}

	if cmd == "has_version" {
		returncode := 1
		if len(vardb.match(atom1.Value, 1)) > 0 {
			returncode = 0
		}
		return "", warnings_str, returncode
	} else if cmd == "best_version" {
		ps := []string{}
		for _, p := range vardb.match(atom1.Value, 1) {
			ps = append(ps, p.string)
		}
		m := versions.Best(ps, "")
		return fmt.Sprintf("%s\n", m), warnings_str, 0
	} else if myutil.Ins([]string{"master_repositories", "repository_path", "available_eclasses", "eclass_path", "license_path"}, cmd) {
		if !dep.RepoNameRe.MatchString(args[0]) {
			return "", fmt.Sprintf("%s: Invalid repository: %s\n", cmd, args[0]), 2
		}
		//try:
		repo := portdb.repositories.Prepos[args[0]]
		//except
		//KeyError:
		//	return ("", warnings_str, 1)

		if cmd == "master_repositories" {
			return fmt.Sprintf("%s\n", strings.Join(repo.masters, " ")), warnings_str, 0
		} else if cmd == "repository_path" {
			return fmt.Sprintf("%s\n", repo.Location), warnings_str, 0
		} else if cmd == "available_eclasses" {
			ree := []string{}
			for k := range repo.eclassDb.eclasses {
				ree = append(ree, k)
			}
			return fmt.Sprintf("%s\n", strings.Join(myutil.Sorted(ree), " ")), warnings_str, 0
		} else if cmd == "eclass_path" {
			//try:
			eclass := repo.eclassDb.eclasses[args[1]]
			//except
			//KeyError:
			//	return ("", warnings_str, 1)
			return fmt.Sprintf("%s\n", eclass.location), warnings_str, 0
		} else if cmd == "license_path" {
			paths := []string{}
			for _, x := range repo.MastersRepo {
				paths = append(paths, filepath.Join(x.Location, "licenses", args[1]))
			}
			paths = append(paths, filepath.Join(repo.Location, "licenses", args[1]))
			paths = myutil.Reversed(paths)

			for _, path := range paths {
				if myutil.PathExists(path) {
					return fmt.Sprintf("%s\n", path), warnings_str, 0
				}
			}
			return "", warnings_str, 1
		}
	} else {
		return "", fmt.Sprintf("Invalid command: %s\n", cmd), 3
	}
	return "", "", 0
}

func (q *QueryCommand) _elog(elog_funcname string, lines []string) string {
	out := &bytes.Buffer{}
	phase := q.phase

	var elog_func func(msg string, phase string, key string, out io.Writer)
	switch elog_funcname {
	case "eqawarn":
		elog_func = elog.eqawarn
	}
	global_havecolor := output.HaveColor
	//try:
	if strings.ToLower(q.settings.ValueDict["NOCOLOR"]) == "no" || strings.ToLower(q.settings.ValueDict["NOCOLOR"]) == "false" || strings.ToLower(q.settings.ValueDict["NOCOLOR"]) == "" {
		output.HaveColor = 1
	} else {
		output.HaveColor = 0
	}
	for _, line := range lines {
		elog_func(line, phase, q.settings.mycpv.string, out)
	}
	//finally:
	output.HaveColor = global_havecolor
	msg := out.String()
	return msg
}
