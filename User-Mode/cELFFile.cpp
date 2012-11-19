#include "stdafx.h"
#include <vector>
#include <cstdlib>
#include "SRDF.h"
#include <iostream>


#ifdef UNICODE
#define DefWindowProc  DefWindowProcW
#else
#define DefWindowProc  DefWindowProcA
#endif // !UNICODE

using namespace std;
using namespace Security::Targets::Files;

cELFFile::cELFFile(char* szFilename) : cFile(szFilename)
{
	FileLoaded = ParseELF();
}

cELFFile::cELFFile(char* buffer,DWORD size) : cFile(buffer,size) 
{
	FileLoaded = ParseELF();
}
bool cELFFile::identify(cFile* File) {
	return true;
}
bool cELFFile::ParseELF() 
{	
	if (BaseAddress == NULL) return false;

	ExeHeader = (elf32_header*)BaseAddress;
	
	/*check if elf format*/
	if (ExeHeader->e_ident[EI_MAG0] != 0x7F) return false;
	if (ExeHeader->e_ident[EI_MAG1] != 'E') return false;
	if (ExeHeader->e_ident[EI_MAG2] != 'L') return false;
	if (ExeHeader->e_ident[EI_MAG3] != 'F') return false;
	
	/*check if 32bit intel */
	//if (ExeHeader->e_ident[EI_CLASS] != ELFCLASS32) return false;
	//if (ExeHeader->e_ident[EI_DATA] != ELFDATA2LSB) return false;

	Magic = ExeHeader->e_ident[EI_MAG0];
	Subsystem = ExeHeader->e_ident[EI_MAG2];
	Entrypoint = ExeHeader->e_entry;
	SizeOfHeader = ExeHeader->e_ehsize;
	Type = ExeHeader->e_type;

	initSections();
	initDynSymbols();
	initImports();

}
void cELFFile::initSections()
{
	SHeader = (elf32_section_header*)malloc(ExeHeader->e_shnum * ExeHeader->e_shentsize);
	SHeader = (elf32_section_header*)(BaseAddress + ExeHeader->e_shoff);

	nSections = ExeHeader->e_shnum;
	Sections = (SECTIONS*)malloc(nSections * sizeof(SECTIONS));

	sStringTable = (char*)malloc(SHeader[ExeHeader->e_shstrndx].sh_size);
	sStringTable = (char*)(SHeader[ExeHeader->e_shstrndx].sh_offset + BaseAddress);

	for (unsigned int i=0;i<nSections;i++) {
		Sections[i].Address = SHeader[i].sh_addr;
		Sections[i].Offset = SHeader[i].sh_offset;
		Sections[i].Size = SHeader[i].sh_size;
		Sections[i].Name = (char*)(sStringTable + SHeader[i].sh_name);

		if (SHeader[i].sh_addr != 0) SizeOfImage += SHeader[i].sh_size;
	}
}

void cELFFile::initDynSymbols() 
{
	for(unsigned i=0; i<nSections; i++) 
	{
		if ((SHeader[i].sh_type==SHT_DYNSYM)) 
		{
		DynSymArray = i;
		}
	}
	
	SymbolsTable = (Elf32_Sym*)malloc(SHeader[DynSymArray].sh_size);
	SymbolsTable = (Elf32_Sym*)(BaseAddress + SHeader[DynSymArray].sh_offset);
	
	dStringTable = (char*)malloc(SHeader[SHeader[DynSymArray].sh_link].sh_size);
	dStringTable = (char*)(SHeader[SHeader[DynSymArray].sh_link].sh_offset + BaseAddress);

	nSymbols = (SHeader[DynSymArray].sh_size/sizeof(Elf32_Sym));

	Symbols = (SYMBOLS*)malloc(sizeof(SYMBOLS) * nSymbols);

	for (unsigned int i=0; i < nSymbols; i++) 
	{
		Symbols[i].Name = (char*)(dStringTable + SymbolsTable[i].st_name);
		Symbols[i].Address = SymbolsTable[i].st_value;
	}
}

void cELFFile::initDynamics()
{
	for(unsigned i=0; i<nSections; i++) 
	{
		if ((SHeader[i].sh_type==SHT_DYNAMIC)) 
		{
		DynArray = i;
		}
	}

	DynamicTable = (Elf32_Dyn*)malloc(SHeader[DynArray].sh_size);
	DynamicTable = (Elf32_Dyn*)(BaseAddress + SHeader[DynArray].sh_offset);
	nDynamics = (SHeader[DynArray].sh_size/sizeof(Elf32_Dyn));
	Dynamics = (DYNAMICS*)malloc(sizeof(DYNAMICS) * nDynamics);

	for (unsigned int i=0; i < nDynamics; i++)
	{
		Dynamics[i].Tag = DynamicTable[i].d_tag;
		Dynamics[i].Offset = DynamicTable[i].d_un.d_off;
		Dynamics[i].Value = DynamicTable[i].d_un.d_val;
		Dynamics[i].Address = DynamicTable[i].d_un.d_ptr;
	}
}

void cELFFile::initImports()
{
		for(unsigned i=0; i<nSections; i++) 
	{
		if ((SHeader[i].sh_type==SHT_DYNAMIC)) 
		{
		DynArray = i;
		}
	}

	dStringTable = (char*)malloc(SHeader[SHeader[DynArray].sh_link].sh_size);
	dStringTable = (char*)(SHeader[SHeader[DynArray].sh_link].sh_offset + BaseAddress);

	DynamicTable = (Elf32_Dyn*)malloc(SHeader[DynArray].sh_size);
	DynamicTable = (Elf32_Dyn*)(BaseAddress + SHeader[DynArray].sh_offset);
	nDynamics = (SHeader[DynArray].sh_size/sizeof(Elf32_Dyn));
	Dynamics = (DYNAMICS*)malloc(sizeof(DYNAMICS) * nDynamics);

	vector<int> nnImports;
	for (unsigned int i=0; i < nDynamics; i++)
	{
		if (DynamicTable[i].d_tag==1)
		{
			nnImports.push_back(i);
		}
	}

	nImports = nnImports.size();
	Imports = (IMPORTS*)malloc(sizeof(IMPORTS) * nnImports.size());

	for (unsigned int i=0; i < nnImports.size(); i++)
	{
		Imports[i].Value =  DynamicTable[nnImports[i]].d_un.d_val;
		Imports[i].Name = (char*)(dStringTable + DynamicTable[nnImports[i]].d_un.d_val);
	}

}