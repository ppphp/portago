package cache

type pkgDescIndexNode struct {
	pkgDescIndexNode string
	cp               string
	cpvList          string
	desc             string
}

type pkgNode struct {
	dict map[string]string
}

func NewPkgNode(cp, version, repo string) *pkgNode {
	return &pkgNode{map[string]string{"cp": cp, "version": version, "repo": repo, "build_time": ""}}
}

//func pkgDescIndexLineFormat(cp, pkgs[]string, desc string) {
//	s := []string{}
//	for _, cpv := range pkgs {
//		s = append(s, )
//	}
//}
