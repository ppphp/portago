package atom

import (
	"regexp"
)

var (
	categoryRe = regexp.MustCompile("^\\w[-.+\\w]*$")
	knownKeys = map[string]bool{
	"DEPEND": true, "RDEPEND": true, "SLOT": true, "SRC_URI": true,
	"RESTRICT": true, "HOMEPAGE": true, "LICENSE": true, "DESCRIPTION": true,
	"KEYWORDS": true, "INHERITED": true, "IUSE": true, "REQUIRED_USE": true,
	"PDEPEND": true, "BDEPEND": true, "EAPI": true,
	"PROPERTIES": true, "DEFINED_PHASES": true, "HDEPEND": true,
}
	pkgStrAuxKeys = map[string]bool{"BUILD_TIME": true, "EAPI":true, "BUILD_ID":true,
		"KEYWORDS":true, "SLOT":true, "repository":true}
)

type dbapi struct {
	categories string
	useMutable bool
}

func NewDbapi()*dbapi{
	return &dbapi{}
}

type ContentsCaseSensitivityManager struct{
	getContents string
	unmapKey string
	keys string
	contentInsensitive string
	reverseKeyMap string
}

func NewContentsCaseSensitivityManager(db string) *ContentsCaseSensitivityManager{
	return nil
}
