package atom

import (
	"golang.org/x/sys/unix"
	"os"
	"path"
	"strings"
)

func FindBinary(binary string) string {
	paths := strings.Split(os.Getenv("PATH"), ":")
	for _, p := range paths {
		fname := path.Join(p, binary)
		s, _ := os.Stat(fname)
		if (s.Mode()&unix.X_OK != 0) && (!s.IsDir()) {
			return fname
		}
	}
	return ""
}
