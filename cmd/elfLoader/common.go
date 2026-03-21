package elfLoader

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
