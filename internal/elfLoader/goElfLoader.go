package elfLoader

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
)

func filterFunctionSymbols(functions []gosym.Func, filter FunctionFilter) (ret []Symbol) {
	for _, f := range functions {
		if filter.Package != nil && *filter.Package != f.PackageName() {
			continue
		}
		ret = append(ret, Symbol{Name: f.Name, Address: f.Entry})
	}
	return
}

func LoadGoFile(elfFilePath string, filter FunctionFilter) (*ElfFile, error) {
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

	functionSymbols := filterFunctionSymbols(symTable.Funcs, filter)

	return &ElfFile{FilePath: elfFilePath, Symbols: functionSymbols, textSectionAddress: txtSection.Addr, textSectionOffset: txtSection.Offset}, nil

}
