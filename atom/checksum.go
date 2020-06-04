package atom

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/jzelinskie/whirlpool"
	"github.com/martinlindhe/gogost/gost34112012256"
	"github.com/martinlindhe/gogost/gost34112012512"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

var (
	hashFuncMap   = map[string]*generateHashFunction{}
	hashOriginMap = map[string]string{}
	hashFuncKeys  = map[string]bool{}
)

func openFile(fname string) *os.File {
	f, _ := os.OpenFile(fname, os.O_RDWR, 0755)
	return f
}

type generateHashFunction struct {
	hashObject hash.Hash
}

func (g *generateHashFunction) checksumStr(data string) []byte {
	checksum := g.hashObject
	checksum.Write([]byte(data))
	return checksum.Sum(nil)
}

func (g *generateHashFunction) checksumFile(fname string) ([]byte, int) {
	f := openFile(fname)
	defer f.Close()
	blockSize := HashingBlocksize
	size := 0
	checksum := g.hashObject
	data := make([]byte, blockSize)
	f.Read(data)
	for len(data) != 0 {
		checksum.Write(data)
		size += len(data)
		f.Read(data)
	}
	return checksum.Sum(nil), size
}

func NewGenerateHashFunction(hashType string, hashObject hash.Hash, origin string) *generateHashFunction {
	g := &generateHashFunction{hashObject: hashObject}
	hashFuncMap[hashType] = g
	hashOriginMap[hashType] = origin
	return g
}

func init() {
	NewGenerateHashFunction("MD5", md5.New(), "hashlib")
	NewGenerateHashFunction("SHA1", sha1.New(), "hashlib")
	NewGenerateHashFunction("SHA256", sha256.New(), "hashlib")
	NewGenerateHashFunction("SHA512", sha512.New(), "hashlib")
	NewGenerateHashFunction("RMD160", ripemd160.New(), "hashlib")
	NewGenerateHashFunction("WHIRLPOOL", whirlpool.New(), "hashlib")
	b, _ := blake2b.New256([]byte{})
	NewGenerateHashFunction("BLAKE2B", b, "hashlib")
	s, _ := blake2s.New256([]byte{})
	NewGenerateHashFunction("BLAKE2S", s, "hashlib")
	NewGenerateHashFunction("SHA3_256", sha3.New256(), "hashlib")
	NewGenerateHashFunction("SHA3_512", sha3.New512(), "hashlib")
	NewGenerateHashFunction("STREEBOG256", gost34112012256.New(), "pygost")
	NewGenerateHashFunction("STREEBOG512", gost34112012512.New(), "pygost")
	NewGenerateHashFunction("size", &SizeHash{}, "pygost")
	for k := range hashFuncMap {
		hashFuncKeys[k] = true
	}
}

type SizeHash struct {
	size int
}

func (s *SizeHash) Write(p []byte) (int, error) {
	s.size += len(p)
	return len(p), nil
}
func (s *SizeHash) Sum(b []byte) []byte {
	return make([]byte, s.size)
}
func (s *SizeHash) Reset() {
	s.size = 0
}
func (s *SizeHash) Size() int {
	return s.size
}

func (s *SizeHash) BlockSize() int {
	return 256
}

var prelinkCapable = false

func init() {
	if _, err := os.Stat(PrelinkBinary); !os.IsNotExist(err) {
		cmd := exec.Command(PrelinkBinary, "--version")
		if err := cmd.Run(); err != nil {
			prelinkCapable = true
		}
	}
}

func isPrelinkElf(fname string) bool {
	f := openFile(fname)
	defer f.Close()
	magic := make([]byte, 17)
	f.Read(magic)
	return len(magic) == 17 && bytes.HasPrefix(magic, []byte{'\x7f', 'E', 'L', 'F'}) && (magic[16] == '\x02' || magic[16] == '\x03')
}

func performMd5(x string, calcPrelink int) []byte {
	b, _ := performChecksum(x, "MD5", calcPrelink)
	return b
}

func performMd5Merge(x string, calcPrelink int) []byte {
	return performMd5(x, calcPrelink)
}

func performAll(x string, calcPrelink int) map[string][]byte {
	myDict := make(map[string][]byte)
	for k := range hashFuncKeys {
		b, _ := performChecksum(x, k, calcPrelink)
		myDict[k] = b
	}
	return myDict
}

func getValidChecksumKeys() map[string]bool {
	return hashFuncKeys
}

func getHashOrigin(hashtype string) string {
	v, ok := hashOriginMap[hashtype]
	if ok {
		return v
	} else {
		return "unknown"
	}
}

func filterUnaccelaratedHashes(digests map[string]string) map[string]string {
	return digests
}

type hashFilter struct {
	trasparent bool
	tokens     []string
}

func (h *hashFilter) Call(hashName string) bool {
	if h.trasparent {
		return true
	}
	for _, token := range h.tokens {
		if token == "*" || token == hashName {
			return true
		} else if token[:1] == "-" {
			if token[1:] == "*" || token[1:] == hashName {
				return false
			}
		}
	}
	return false
}

func NewHashFilter(filterStr string) *hashFilter {
	tokens := strings.Fields(strings.ToUpper(filterStr))
	if len(tokens) == 0 || tokens[len(tokens)-1] == "*" {
		tokens = nil
	}
	return &hashFilter{tokens == nil, tokens}
}

func applyHashFilter(digests map[string]string, hashFilter *hashFilter) map[string]string {
	verifiableHashTypes := make(map[string]bool)
	for v := range digests {
		verifiableHashTypes[v] = true
	}
	for v := range hashFuncKeys {
		verifiableHashTypes[v] = true
	}
	delete(verifiableHashTypes, "size")
	modified := false
	if len(verifiableHashTypes) > 1 {
		for k := range verifiableHashTypes {
			if !hashFilter.Call(k) {
				modified = true
				delete(verifiableHashTypes, k)
				if len(verifiableHashTypes) == 1 {
					break
				}
			}
		}
	}
	if modified {
		d := make(map[string]string)
		for k, v := range digests {
			if k == "size" || verifiableHashTypes[k] {
				d[k] = v
			}
		}
		return d
	} else {
		return digests
	}
}

// 0, 0
func verifyAll(fname string, mydict map[string]string, calcPrelink int, strict int) (bool, string, string, string) {
	fileIsOk := true
	//reason := "Reason unknown"
	s, _ := os.Stat(fname)
	mySize := s.Size()
	if size, ok := mydict["size"]; ok && fmt.Sprintf("%v", mySize) == size {
		return false, "Filesize does not match recorded size", fmt.Sprintf("%v", mySize), mydict["size"]
	}
	verifiableHashTypes := make(map[string]bool)
	for v := range mydict {
		verifiableHashTypes[v] = true
	}
	for v := range hashFuncKeys {
		verifiableHashTypes[v] = true
	}
	delete(verifiableHashTypes, "size")
	if len(verifiableHashTypes) == 0 {
		expected := make(map[string]bool)
		for v := range hashFuncKeys {
			expected[v] = true
		}
		delete(expected, "size")
		s := []string{}
		for v := range expected {
			s = append(s, v)
		}
		sort.Strings(s)
		t := strings.Join(s, " ")
		got := make(map[string]bool)
		for v := range hashFuncKeys {
			got[v] = true
		}
		delete(got, "size")
		u := []string{}
		for v := range expected {
			u = append(u, v)
		}
		sort.Strings(u)
		w := strings.Join(s, " ")
		return false, "Insufficient data for checksum verification", w, t
	}
	l := []string{}
	for v := range mydict {
		l = append(l, v)
	}
	sort.Strings(l)
	for _, x := range l {
		if x == "size" {
			continue
		} else if hashFuncKeys[x] {
			myHash, _ := performChecksum(fname, x, calcPrelink)
			if mydict[x] != string(myHash) {
				if strict != 0 {
					return false, "", "", ""
				}
			} else {
				fileIsOk = false
				return false, fmt.Sprintf("Failed on %s verification", x), string(myHash), mydict[x]
			}
		}
	}
	return fileIsOk, "", "", ""
}

func performChecksum(fname, hashname string, calcPrelink int) ([]byte, int) {
	prelinkTmpFile := ""
	myFileName := fname
	if calcPrelink != 0 && prelinkCapable && isPrelinkElf(fname) {
		tmpFileFd, err := ioutil.TempFile("", "*")
		if err != nil {
			defer tmpFileFd.Close()
		}
		prelinkTmpFile = tmpFileFd.Name()
		cmd := exec.Command(PrelinkBinary, "--verify", fname)
		cmd.Stdout = tmpFileFd
		if err := cmd.Run(); err != nil {
			myFileName = prelinkTmpFile
		}
		tmpFileFd.Close()
	}
	return hashFuncMap[hashname].checksumFile(myFileName)
}

// []string{"MD5"}, 0
func performMultipleChecksums(fname string, hashes []string, calcPrelink int) map[string][]byte {
	rVal := map[string][]byte{}

	for _, x := range hashes {
		if !hashFuncKeys[x] {
			return rVal
		}
		y, _ := performChecksum(fname, x, calcPrelink)
		rVal[x] = y
	}

	return rVal
}

func checksumStr(data, hashname string) []byte {
	if !hashFuncKeys[hashname] {
		return []byte{}
	}
	return hashFuncMap[hashname].checksumStr(data)
}
