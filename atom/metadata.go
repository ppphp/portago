package atom

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
)

// https://devmanual.gentoo.org/ebuild-writing/misc-files/metadata/

var m Metadata

// catmetadata for category and pkgmetadata for package
type Metadata struct {
	Maintainers []Maintainer `xml:"maintainer"`
}

type Maintainer struct {
	Type   string  `xml:"type,attr"`
	Names  []Name  `xml:"name"`
	Emails []Email `xml:"email"`
}

type Name struct {
	Name string `xml:",chardata"`
}

type Email struct {
	Email string `xml:",chardata"`
}

type LongDescription struct {
	LongDescription string `xml:",chardata"`
}

type Description struct {
	Description string `xml:",chardata"`
}

type Slots struct {
	Slots string `xml:",chardata"`
}

type Slot struct {
	Slot string `xml:",chardata"`
}

type Subslots struct {
	Subslots string `xml:",chardata"`
}

type Use struct {
	Use string `xml:",chardata"`
}

type Flag struct {
	Flag string `xml:",chardata"`
}

type Upstream struct {
	Upstream string `xml:",chardata"`
}

type Changelog struct {
	Changelog string `xml:",chardata"`
}

type Doc struct {
	Doc string `xml:",chardata"`
}

type BugsTo struct {
	BugsTo string `xml:",chardata"`
}

type RemoteId struct {
	RemoteId string `xml:",chardata"`
}

type Pkg struct {
	Pkg string `xml:",chardata"`
}

type Cat struct {
	Cat string `xml:",chardata"`
}

//func init() {
//	Read("app-misc/hello")
//}

func Read(cvp string) {
	a, err := ioutil.ReadFile(fmt.Sprintf("./tmp/%v/metadata.xml", cvp))
	if err != nil {
		panic(err.Error())
	}
	xml.Unmarshal(a, &m)
	fmt.Printf("%+v", m)
}
