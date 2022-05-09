package elf

import (
	"encoding/binary"
	"os"
)

type ELFHeader struct {
	EiClass int
	EiData  int

	EFlags   uint32
	EMachine uint16
	EType    uint16
}

func ReadELFHeader(f *os.File) ELFHeader {
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

	var uint16 func([]byte) uint16
	var uint32 func([]byte) uint32
	if eiData == ELFDATA2LSB {
		uint16 = binary.LittleEndian.Uint16
		uint32 = binary.LittleEndian.Uint32
	} else if eiData == ELFDATA2MSB {
		uint16 = binary.BigEndian.Uint16
		uint32 = binary.BigEndian.Uint32
	}

	if width == 0 || uint16 == nil {
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

	elfHeader.EType = uint16(twoByte1)
	elfHeader.EMachine = uint16(twoByte2)
	elfHeader.EFlags = uint32(fourByte)
	return elfHeader
}
