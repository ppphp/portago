package atom

type cvsSync struct {

}

func NewCvsSync() *cvsSync{
	return &cvsSync{}
}

type gitSync struct {

}

func NewGitSync() *gitSync{
	return &gitSync{}
}

type rsyncSync struct {

}

func NewRsyncSync() *rsyncSync{
	return &rsyncSync{}
}

type svnSync struct {

}

func NewSvnSync() *svnSync{
	return &svnSync{}
}

type webrsyncSync struct {

}

func NewWebrsyncSync() *webrsyncSync{
	return &webrsyncSync{}
}

type modules struct {
	modules map[string]map[string][]string
}

var moduleController modules

func moduleSpecificOptions(repo *repoConfig) map[string]bool{
	r := map[string]bool{}
	if repo.syncType != ""{
		for _, v := range moduleController.modules[repo.syncType]["module_specific_options"]{
			r[v]=true
		}
	}
	return r
}
