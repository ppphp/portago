package atom

import "fmt"

type syncBase struct {
	options                                                                                         map[string]string
	settings, logger, repo, xtermTitles, spawnKwargs, _repoStorage, downloadDir, binCommand, binPkg string
}

func (s *syncBase) repoStorage() {
}

func (s *syncBase) hasBin() bool {
	if s.binCommand == "" {
		msg := []string{fmt.Sprintf("Command not found: %s", s.binCommand),
			fmt.Sprintf("Type \"emerge %s\" to enable %s support.", s.binPkg, s.binCommand)}
		for _, l := range msg {
			WriteMsgLevel(fmt.Sprintf("!!! %s", l), -40, -1)
		}
		return false
	}

	return true
}

func NewSyncBase(binCommand, binPkg string) *syncBase {
	if binCommand != "" {
		binCommand = FindBinary(binCommand)
	}
	s := &syncBase{}
	s.binCommand = binCommand
	s.binPkg = binPkg
	return s
}

type newBase struct {
	*syncBase
}

func (n *newBase) sync() {

}

func NewNewBase(binCommand, binPkg string) *newBase {
	n := &newBase{syncBase: NewSyncBase(binCommand, binPkg)}
	return n
}

type cvsSync struct {
}

func NewCvsSync() *cvsSync {
	return &cvsSync{}
}

type gitSync struct {
}

func NewGitSync() *gitSync {
	return &gitSync{}
}

type rsyncSync struct {
	*newBase
}

func (r *rsyncSync) name() string {
	return "RsyncSync"
}

func NewRsyncSync() *rsyncSync {
	return &rsyncSync{newBase: NewNewBase("rsync", RsyncPackageAtom)}
}

type svnSync struct {
}

func NewSvnSync() *svnSync {
	return &svnSync{}
}

type webrsyncSync struct {
}

func NewWebrsyncSync() *webrsyncSync {
	return &webrsyncSync{}
}

type modules struct {
	modules map[string]map[string][]string
}

var moduleController modules

func moduleSpecificOptions(repo *RepoConfig) map[string]bool {
	r := map[string]bool{}
	if repo.SyncType != "" {
		for _, v := range moduleController.modules[repo.SyncType]["module_specific_options"] {
			r[v] = true
		}
	}
	return r
}
