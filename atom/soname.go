package atom

// an ugly tranlation of lib/portage/util/{endian,elf}

import (
	"encoding/binary"
	"fmt"
	"os"
)

const (
	EI_CLASS   = 4
	ELFCLASS32 = 1
	ELFCLASS64 = 2

	EI_DATA     = 5
	ELFDATA2LSB = 1
	ELFDATA2MSB = 2

	E_TYPE  = 16
	ET_REL  = 1
	ET_EXEC = 2
	ET_DYN  = 3
	ET_CORE = 4

	E_MACHINE       = 18
	EM_SPARC        = 2
	EM_386          = 3
	EM_68K          = 4
	EM_MIPS         = 8
	EM_PARISC       = 15
	EM_SPARC32PLUS  = 18
	EM_PPC          = 20
	EM_PPC64        = 21
	EM_S390         = 22
	EM_ARM          = 40
	EM_SH           = 42
	EM_SPARCV9      = 43
	EM_IA_64        = 50
	EM_X86_64       = 62
	EM_ALTERA_NIOS2 = 113
	EM_AARCH64      = 183
	EM_ALPHA        = 0x9026

	E_ENTRY           = 24
	EF_MIPS_ABI       = 0x0000f000
	EF_MIPS_ABI2      = 0x00000020
	E_MIPS_ABI_O32    = 0x00001000
	E_MIPS_ABI_O64    = 0x00002000
	E_MIPS_ABI_EABI32 = 0x00003000
	E_MIPS_ABI_EABI64 = 0x00004000
)

var (
	_machine_prefix_map = map[uint16]string{
		EM_386:          "x86",
		EM_68K:          "m68k",
		EM_AARCH64:      "arm",
		EM_ALPHA:        "alpha",
		EM_ALTERA_NIOS2: "nios2",
		EM_ARM:          "arm",
		EM_IA_64:        "ia64",
		EM_MIPS:         "mips",
		EM_PARISC:       "hppa",
		EM_PPC:          "ppc",
		EM_PPC64:        "ppc",
		EM_S390:         "s390",
		EM_SH:           "sh",
		EM_SPARC:        "sparc",
		EM_SPARC32PLUS:  "sparc",
		EM_SPARCV9:      "sparc",
		EM_X86_64:       "x86",
	}

	_mips_abi_map = map[uint32]string{
		E_MIPS_ABI_EABI32: "eabi32",
		E_MIPS_ABI_EABI64: "eabi64",
		E_MIPS_ABI_O32:    "o32",
		E_MIPS_ABI_O64:    "o64",
	}
)

type ELFHeader struct {
	EiClass int
	EiData  int

	EFlags   uint32
	EMachine uint16
	EType    uint16
}

func ReadELFHeader(f os.File) ELFHeader {
	f.Seek(EI_CLASS, 0)
	oneByte := make([]byte, 1)
	f.Read(oneByte)
	eiClass := int(oneByte[0])
	f.Read(oneByte)
	eiData := int(oneByte[0])

	elfHeader := ELFHeader{EiClass: eiClass, EiData: eiData}

	width := 0
	if eiClass == ELFCLASS32 {
		width = 32
	} else if eiClass == ELFCLASS64 {
		width = 64
	}

	if width == 0 || (eiData != ELFDATA2LSB && eiData != ELFDATA2MSB) {
		return elfHeader
	}
	twoByte1 := make([]byte, 2)
	twoByte2 := make([]byte, 2)
	fourByte := make([]byte, 4)
	f.Seek(E_TYPE, 0)
	f.Read(twoByte1)
	f.Seek(E_MACHINE, 0)
	f.Read(twoByte2)
	e_flags_offset := E_ENTRY + 3*width/8
	f.Seek(int64(e_flags_offset), 0)
	f.Read(fourByte)

	if eiData == ELFDATA2LSB {
		elfHeader.EType = binary.LittleEndian.Uint16(twoByte1)
		elfHeader.EMachine = binary.LittleEndian.Uint16(twoByte2)
		elfHeader.EFlags = binary.LittleEndian.Uint32(fourByte)
	} else if eiData == ELFDATA2MSB {
		elfHeader.EType = binary.BigEndian.Uint16(twoByte1)
		elfHeader.EMachine = binary.BigEndian.Uint16(twoByte2)
		elfHeader.EFlags = binary.BigEndian.Uint32(fourByte)
	}
	return elfHeader
}

func _compute_suffix_mips(elf_header ELFHeader) string {
	mipsAbi := elf_header.EFlags & EF_MIPS_ABI
	name := ""
	if mipsAbi != 0 {
		name = _mips_abi_map[mipsAbi]
	} else if elf_header.EFlags&EF_MIPS_ABI2 != 0 {
		name = "n32"
	} else if elf_header.EiClass == ELFCLASS64 {
		name = "n64"
	}
	return name
}
func compute_multilib_category(elf_header ELFHeader) string {

	category := ""
	if elf_header.EMachine != 0 {

		prefix := _machine_prefix_map[elf_header.EMachine]
		suffix := ""

		if prefix == "mips" {
			suffix = _compute_suffix_mips(elf_header)
		} else if elf_header.EiClass == ELFCLASS64 {

			suffix = "64"
		} else if elf_header.EiClass == ELFCLASS32 {

			if elf_header.EMachine == EM_X86_64 {

				suffix = "x32"
			} else {

				suffix = "32"
			}
		}

		if prefix == "" || suffix == "" {

		} else {
			category = fmt.Sprintf("%s_%s", prefix, suffix)
		}
	}

	return category
}

type sonameAtom struct {
	multilib_category, soname string
	packagee                  bool
}

func (s *sonameAtom) match(pkg *Package) bool {
	return pkg._provides != ""
}

func NewSonameAtom(multilibCategory, soname string) *sonameAtom {
	s := &sonameAtom{packagee: false}
	s.multilib_category = multilibCategory
	s.soname = soname
	return s
}
