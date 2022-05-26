package msg

import (
	"os"
	"path"
	"strings"
)

var noiseLimit = 0

//0, nil
func WriteMsg(myStr string, noiseLevel int, fd *os.File) {
	if fd == nil {
		fd = os.Stderr
	}
	if noiseLevel <= noiseLimit {
		fd.Write([]byte(myStr))
	}
}

// 0
func WriteMsgStdout(myStr string, noiseLevel int) {
	WriteMsg(myStr, noiseLevel, os.Stdout)
}

// 0, 0
func WriteMsgLevel(msg string, level, noiseLevel int) {
	var fd *os.File
	if level >= 30 {
		fd = os.Stderr
	} else {
		fd = os.Stdout
	}
	WriteMsg(msg, noiseLevel, fd)
}

func NormalizePath(myPath string) string {
	return path.Clean(myPath)
}

func ExpandEnv() map[string]string {
	m := map[string]string{}
	for _, v := range os.Environ() {
		s := strings.SplitN(v, "=", 2)
		if len(s) == 2 {
			m[s[0]] = s[1]
		}
	}
	return m
}
