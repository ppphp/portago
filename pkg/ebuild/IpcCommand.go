package ebuild

type IpcCommand interface {
	Call(argv []string) (string, string, int)
}
