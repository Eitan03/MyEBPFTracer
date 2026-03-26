package elfLoader

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
)

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
