package interfaces

type ISettings interface {
	comparable
	IsStable(str IPkgStr) bool
}
