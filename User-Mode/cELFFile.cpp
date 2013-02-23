/*
 *
 *  Copyright (C) 2013  Anwar Mohamed <anwarelmakrahy[at]gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to Anwar Mohamed
 *  anwarelmakrahy[at]gmail.com
 *
 */

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
	initSharedLibraries();
	initDynSymbols();
	initSymbols();
	initImportedFunctions();

	return true;
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
	
	DynamicSymbolsTable = (Elf32_Sym*)malloc(SHeader[DynSymArray].sh_size);
	DynamicSymbolsTable = (Elf32_Sym*)(BaseAddress + SHeader[DynSymArray].sh_offset);
	
	dStringTable = (char*)malloc(SHeader[SHeader[DynSymArray].sh_link].sh_size);
	dStringTable = (char*)(SHeader[SHeader[DynSymArray].sh_link].sh_offset + BaseAddress);

	nDynamicSymbols = (SHeader[DynSymArray].sh_size/sizeof(Elf32_Sym));

	DynamicSymbols = (DYNAMICSYMBOLS*)malloc(sizeof(DYNAMICSYMBOLS) * nDynamicSymbols);

	for (unsigned int i=0; i < nDynamicSymbols; i++) 
	{
		DynamicSymbols[i].Name = (char*)(dStringTable + DynamicSymbolsTable[i].st_name);
		DynamicSymbols[i].Address = DynamicSymbolsTable[i].st_value;
	}
}

void cELFFile::initSymbols()
{
	for(unsigned int i=0; i<nSections; i++) 
	{
		if ((SHeader[i].sh_type==SHT_SYMTAB)) 
		{
			SymArray = i;
		}
	}

	dStringTable = (char*)malloc(SHeader[SHeader[SymArray].sh_link].sh_size);
	dStringTable = (char*)(SHeader[SHeader[SymArray].sh_link].sh_offset + BaseAddress);

	SymbolsTable = (Elf32_Sym*)malloc(SHeader[SymArray].sh_size);
	SymbolsTable = (Elf32_Sym*)(BaseAddress + SHeader[SymArray].sh_offset);
	nSymbols = (SHeader[SymArray].sh_size/sizeof(Elf32_Sym));
	Symbols = (SYMBOLS*)malloc(sizeof(SYMBOLS) * nSymbols);

	for (unsigned int i=0; i < nSymbols; i++)
	{
		Symbols[i].Name = (char*)(dStringTable + SymbolsTable[i].st_name);
		Symbols[i].Address = SymbolsTable[i].st_value;
	}
}

void cELFFile::initSharedLibraries()
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

	unsigned int libssize = 0;

	for (unsigned int i=0; i < nDynamics; i++)
	{
		DWORD t = DynamicTable[i].d_tag;
		if (t==DT_NEEDED) libssize++;
	}

	nSharedLibraries = libssize;
	SharedLibraries = (IMPORTS*)malloc(sizeof(IMPORTS) * nSharedLibraries);

	unsigned int counter=0;
	for (unsigned int i=0; i < nDynamics; i++)
	{
		DWORD t = DynamicTable[i].d_tag;
		if (t==DT_NEEDED) 
		{
			SharedLibraries[counter].Name = (char*)(dStringTable + DynamicTable[i].d_un.d_val);
			counter++;
		}
	}
}

void cELFFile::initImportedFunctions()
{
	unsigned int pltindex = NULL;
	nImportedFunctions = 0;

	for (unsigned i=0; i<nSections; i++)
	{
		if (SHeader[i].sh_type == SHT_REL && strcmp(".rel.plt",Sections[i].Name) == 0) 
		{
			pltindex = i;
		}
	}

	if (pltindex == NULL) return;

	nImportedFunctions = SHeader[pltindex].sh_size/sizeof(elf32_rel);

	PLTRelocationsTable = (elf32_rel*)malloc(SHeader[pltindex].sh_size);
	PLTRelocationsTable = (elf32_rel*)(BaseAddress + SHeader[pltindex].sh_offset);
	
	ImportedFunctions = (DYNAMICSYMBOLS*)malloc(sizeof(DYNAMICSYMBOLS) * nImportedFunctions);

	for (unsigned int j=0; j<nImportedFunctions; j++)
	{
		ImportedFunctions[j].Address = PLTRelocationsTable[j].r_offset;
		ImportedFunctions[j].Name = DynamicSymbols[ELF32_R_SYM(PLTRelocationsTable[j].r_info)].Name;
	}
};