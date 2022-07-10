package interfaces

type ISettings interface {
	comparable
	IsStable(str IPkgStr) bool
	GetValueDict() map[string]string
	GetLocalConfig() bool
	GetGlobalConfigPath() string
}
