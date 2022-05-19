package env

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

func TestPackageKeywordsFile(t *testing.T) {
	cpv := "sys-apps/portage"
	keywords := []string{"~x86", "amd64", "-mips"}

	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Error(err)
	}
	f.Write([]byte(fmt.Sprintf("%s %s\n", cpv, strings.Join(keywords, " "))))
	f.Close()

	ff := NewPackageKeywordsFile(f.Name())
	ff.load()
	/*
			i = 0
			for cpv, keyword in f.items():
			self.assertEqual(cpv, self.cpv[i])
		[k for k in keyword if self.assertTrue(k in self.keywords)]
			i = i + 1
			finally:
			self.NukeFile()


			def NukeFile(self):
			os.unlink(self.fname)*/
}
