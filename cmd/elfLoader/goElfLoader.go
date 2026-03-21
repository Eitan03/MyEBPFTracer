package elfLoader

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
)

type ElfFile struct {
	FilePath           string
	Symbols            []Symbol
	textSectionAddress uint64
	textSectionOffset  uint64
}

type Symbol struct {
	Name    string
	Address uint64
}

func (elfFile ElfFile) GetRuntimeAddress(address uint64) uint64 {
	/*
		f.Entry is relative to .text section, we need to get the absolute location in the ELF file
		to pass the the tracer
		we calculate it by running (<Virtual Address> - <Section Virtual Address>) + <File Offset>
		where:
		Section Virtual Address = the starting point in ram of the exec file
		File Offset = the offset to the text file within the executable (the ELF Header)
	*/
	return (address - elfFile.textSectionAddress) + elfFile.textSectionOffset
}

func LoadGoFile(elfFilePath string) (*ElfFile, error) {
	elfFile, err := elf.Open(elfFilePath)
	if err != nil {
		return nil, fmt.Errorf("Error opening elf file %v: %v", elfFilePath, err)
	}
	defer elfFile.Close()

	lineTableData, err := elfFile.Section(".gopclntab").Data()
	if err != nil {
		return nil, fmt.Errorf("Error reading .gopclntab data: %v", err)
	}

	txtSection := elfFile.Section(".text")
	lineTable := gosym.NewLineTable(lineTableData, txtSection.Addr)
	symTable, err := gosym.NewTable([]byte{}, lineTable)
	if err != nil {
		return nil, fmt.Errorf("Error creating symbol table: %v", err)
	}

	functionsSymbols := make([]Symbol, len(symTable.Funcs))

	for i, f := range symTable.Funcs {
		functionsSymbols[i] = Symbol{Name: f.Name, Address: f.Entry}
	}
	return &ElfFile{FilePath: elfFilePath, Symbols: functionsSymbols, textSectionAddress: txtSection.Addr, textSectionOffset: txtSection.Offset}, nil

}
