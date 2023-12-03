package index

import (
	"fmt"
	"strings"
)

type pkgDescIndexNode struct {
	cp      string
	cpvList []pkgNode
	desc    string
}

type pkgNode struct {
	cp        string
	version   string
	repo      string
	buildTime string
}

func NewPkgNode(cp, version, repo string) pkgNode {
	return pkgNode{
		cp:      cp,
		version: version,
		repo:    repo,
	}
}

func (p pkgNode) String() string {
	return fmt.Sprintf("%s-%s", p.cp, p.version)
}

func pkgDescIndexLineFormat(cp string, pkgs []pkgNode, desc string) string {
	var versions []string
	for _, pkg := range pkgs {
		versions = append(versions, pkg.version)
	}
	return fmt.Sprintf("%s %s: %s\n", cp, strings.Join(versions, " "), desc)
}

func pkgDescIndexLineRead(line string, repo string) *pkgDescIndexNode {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	desc := strings.TrimSpace(parts[1])

	pkgsStr, cp := strings.TrimSpace(parts[0]), ""
	if i := strings.Index(pkgsStr, " "); i != -1 {
		cp, pkgsStr = pkgsStr[:i], pkgsStr[i+1:]
	} else {
		return nil
	}

	var pkgs []pkgNode
	for _, ver := range strings.Fields(pkgsStr) {
		pkgs = append(pkgs, NewPkgNode(cp, ver, repo))
	}

	return &pkgDescIndexNode{
		cp:      cp,
		cpvList: pkgs,
		desc:    desc,
	}
}
