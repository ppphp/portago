package atom

// an ugly tranlation of lib/portage/util/{endian,elf}

import (
	"fmt"
	"github.com/ppphp/portago/pkg/util/elf"
	"strings"
)

var (
	_machine_prefix_map = map[uint16]string{
		elf.EM_386:          "x86",
		elf.EM_68K:          "m68k",
		elf.EM_AARCH64:      "arm",
		elf.EM_ALPHA:        "alpha",
		elf.EM_ALTERA_NIOS2: "nios2",
		elf.EM_ARM:          "arm",
		elf.EM_IA_64:        "ia64",
		elf.EM_MIPS:         "mips",
		elf.EM_PARISC:       "hppa",
		elf.EM_PPC:          "ppc",
		elf.EM_PPC64:        "ppc",
		elf.EM_S390:         "s390",
		elf.EM_SH:           "sh",
		elf.EM_SPARC:        "sparc",
		elf.EM_SPARC32PLUS:  "sparc",
		elf.EM_SPARCV9:      "sparc",
		elf.EM_X86_64:       "x86",
	}

	_mips_abi_map = map[uint32]string{
		elf.E_MIPS_ABI_EABI32: "eabi32",
		elf.E_MIPS_ABI_EABI64: "eabi64",
		elf.E_MIPS_ABI_O32:    "o32",
		elf.E_MIPS_ABI_O64:    "o64",
	}
)

func _compute_suffix_mips(elf_header elf.ELFHeader) string {
	mipsAbi := elf_header.EFlags & elf.EF_MIPS_ABI
	name := ""
	if mipsAbi != 0 {
		name = _mips_abi_map[mipsAbi]
	} else if elf_header.EFlags&elf.EF_MIPS_ABI2 != 0 {
		name = "n32"
	} else if elf_header.EiClass == elf.ELFCLASS64 {
		name = "n64"
	}
	return name
}

func _compute_suffix_riscv(elf_header elf.ELFHeader) string {
	name := ""
	if elf_header.EiClass == elf.ELFCLASS64 {
		if elf_header.EFlags == elf.EF_RISCV_RVC {
			name = "lp64"
		} else if elf_header.EFlags == elf.EF_RISCV_RVC|elf.EF_RISCV_FLOAT_ABI_DOUBLE {
			name = "lp64d"
		}
	} else if elf_header.EiClass == elf.ELFCLASS32 {
		if elf_header.EFlags == elf.EF_RISCV_RVC {
			name = "ilp32"
		} else if elf_header.EFlags == elf.EF_RISCV_RVC|elf.EF_RISCV_FLOAT_ABI_DOUBLE {
			name = "ilp32d"
		}
	}

	return name
}

var _specialized_funcs = map[string]func(header elf.ELFHeader) string{
	"mips":  _compute_suffix_mips,
	"riscv": _compute_suffix_riscv,
}

func compute_multilib_category(elf_header elf.ELFHeader) string {
	category := ""
	if elf_header.EMachine != 0 {
		prefix := _machine_prefix_map[elf_header.EMachine]
		specialized_func := _specialized_funcs[prefix]
		suffix := ""

		if specialized_func != nil {
			suffix = specialized_func(elf_header)
		} else if elf_header.EiClass == elf.ELFCLASS64 {
			suffix = "64"
		} else if elf_header.EiClass == elf.ELFCLASS32 {
			if elf_header.EMachine == elf.EM_X86_64 {
				suffix = "x32"
			} else {
				suffix = "32"
			}
		}

		if prefix == "" || suffix == "" {
			category = ""
		} else {
			category = fmt.Sprintf("%s_%s", prefix, suffix)
		}
	}

	return category
}

func parse_soname_deps(s string) []*sonameAtom {
	ret := []*sonameAtom{}
	categories := map[string]bool{}
	category := ""
	previous_soname := ""
	for _, soname := range strings.Fields(s) {
		if strings.HasSuffix(soname, ":") {
			if category != "" && previous_soname == "" {
				//raise InvalidData(_error_empty_category % category)
			}

			category = soname[:len(soname)-1]
			previous_soname = ""
			if categories[category] {
				//raise InvalidData(_error_duplicate_category % category)
			}
			categories[category] = true
		} else if category == "" {
			//raise InvalidData(_error_missing_category % soname)
		} else {
			previous_soname = soname
			ret = append(ret, NewSonameAtom(category, soname)) // yield
		}
	}

	if category != "" && previous_soname == "" {
		//raise InvalidData(_error_empty_category % category)
	}
	return ret
}

type sonameAtom struct {
	packagee bool

	multilib_category, soname string
}

func (s *sonameAtom) eq(sa *sonameAtom) bool {
	return s.multilib_category == sa.multilib_category && s.soname == sa.soname
}

func (s *sonameAtom) match(pkg *Package) bool {
	return pkg._provides != nil && pkg._provides[[2]string{s.multilib_category, s.soname}] == s
}

func NewSonameAtom(multilibCategory, soname string) *sonameAtom {
	s := &sonameAtom{packagee: false}
	s.multilib_category = multilibCategory
	s.soname = soname
	return s
}
