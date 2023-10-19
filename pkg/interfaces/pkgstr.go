package interfaces

type IPkgStr interface {
	String() string
	Metadata() map[string]string
	Eapi() string
	Repo() string
	Slot() string
	FileSize() string
	Cp() string
	Version() string
	SubSlot() string
	BuildId() int
	BuildTime() int
	Mtime() int
	CpvSplit() [4]string
	Cpv() IPkgStr
}
