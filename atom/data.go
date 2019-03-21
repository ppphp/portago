package atom

import (
	"os"
)

func targetEprefix() string {
	if a := os.Getenv("EPREFIX"); a != "" {
		return NormalizePath(a)
	}
	return EPREFIX
}

func targetRoot() string {
	if a := os.Getenv("ROOT"); a != "" {
		return NormalizePath(a)
	}
	return string(os.PathSeparator)
}

func portageGroupWarining() {

}

func data_init(settings *Config){

}
