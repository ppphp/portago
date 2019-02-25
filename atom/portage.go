package atom

import (
	"os"
	"path"
	"regexp"
	"strings"
)

var shellQuoteRe = regexp.MustCompile("[\\s><=*\\\\\\\"'$`]")
var initializingGlobals *bool

func ShellQuote(s string) string {

	if shellQuoteRe.MatchString(s) {
		return s
	}
	for _, letter := range "\\\"$`" {
		if strings.Contains(s, string(letter)) {
			s = strings.Replace(s, string(letter), "\\"+string(letter), -1)
		}
	}
	return "\"" + s + "\""
}

func getStdin() *os.File{
	return os.Stdin
}

func getcwd() string {
	s, err := os.Getwd()
	if err != nil {
		os.Chdir("/")
		return "/"
	}else {
		return s
	}
}
func init(){
	getcwd()
}

var auxdbkeys = map[string]bool{
	"DEPEND":true,    "RDEPEND":true,   "SLOT":true,      "SRC_URI":true,
	"RESTRICT":true,  "HOMEPAGE":true,  "LICENSE":true,   "DESCRIPTION":true,
	"KEYWORDS":true,  "INHERITED":true, "IUSE":true, "REQUIRED_USE":true,
	"PDEPEND":true,   "BDEPEND":true, "EAPI":true,
	"PROPERTIES":true, "DEFINED_PHASES":true, "HDEPEND":true, "UNUSED_04":true,
	"UNUSED_03":true, "UNUSED_02":true, "UNUSED_01":true,
}
var auxdbkeylen = len(auxdbkeys)

type treesDict struct {
	runningEroot, targetEroot string
}

func NewTreesDict() *treesDict{
	return &treesDict{}
}

func absSymlink(symlink, target string) string {
	mylink := ""
	if target != "" {
		mylink = target
	} else {
		mylink, _ = os.Readlink(symlink)
	}
	if mylink[0] != '/' {
		mydir := path.Dir(symlink)
		mylink = mydir + "/" +mylink
	}
	return path.Clean(mylink)
}

var doebuildManifestExemptDepend = 0

func parseEapiEbuildHead(f []string) (string, int){
	eapi := ""
	eapiLineno := 0
	lineno := 0
	for _, line := range f {
		lineno += 1
		if !commentOrBlankLine.MatchString(line) {
			eapiLineno = lineno
			if pmsEapiRe.MatchString(line) {
				eapi := pmsEapiRe.FindAllString(line, -1)[2]
			}
			break
		}
	}
	return eapi,eapiLineno
}
