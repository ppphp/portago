package modules

type SyncRepos struct {
}

func (s *SyncRepos) Name() string {
	return "sync"
}

func (s *SyncRepos) CanProgressbar() bool {
	return false
}

func NewSyncRepos(emergeConfig *opt) *SyncRepos {
	s := &SyncRepos{}

	return s
}
