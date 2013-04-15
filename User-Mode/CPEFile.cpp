/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet and Anwar Mohamed
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
 *  along with this program; if not, write to Amr Thabet
 *  amr.thabet[at]student.alx.edu.eg
 *
 */

#include "stdafx.h"
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

#define MakePtr(cast, ptr, addValue) (cast)( (DWORD)(ptr) + (DWORD)(addValue))

cPEFile::cPEFile(char* szFilename) : cFile(szFilename)
{
	FileLoaded = false;
	if (identify(this))
		FileLoaded = ParsePE();

}

cPEFile::cPEFile(char* buffer,DWORD size) : cFile(buffer,size)
{
	FileLoaded = ParsePE();
}
bool cPEFile::identify(cFile* File)
{
	if (File->IsFound() == false) return false;
	if (File->BaseAddress == NULL)return false;
	dos_header* DosHeader = (dos_header*)File->BaseAddress;
	
	if (DosHeader->e_magic != 'ZM') return false;
	
	image_header* PEHeader = (image_header*)(File->BaseAddress + DosHeader->e_lfanew);
	if (DosHeader->e_lfanew > File->FileLength)return false;
	if(PEHeader->signature != 'EP') return false;
	return true;
}
bool cPEFile::ParsePE()
{
	dos_header* DosHeader;
	DosHeader = (dos_header*)BaseAddress;
	PEHeader = (image_header*)(BaseAddress + DosHeader->e_lfanew);
	
	Magic = PEHeader->optional.magic;
	Subsystem = PEHeader->optional.subsystem;
	Imagebase = PEHeader->optional.image_base;
	Entrypoint = PEHeader->optional.address_of_entry_point + PEHeader->optional.image_base;
	FileAlignment = PEHeader->optional.file_alignment;
	SectionAlignment = PEHeader->optional.section_alignment;
	SizeOfImage = PEHeader->optional.size_of_image;
	initDataDirectory();
	initSections();
	initExportTable();	// export table
	initImportTable();
	//initRelocations();	//Still under testing
	return true;
}
void cPEFile::initExportTable()
{
	ExportTable.Functions = NULL;
	DWORD ExportRVA = PEHeader->optional.data_directory[0].virtual_address;
	if (ExportRVA == NULL)return;
	image_export_directory* Exports = (image_export_directory*)(RVAToOffset(ExportRVA)+BaseAddress);

	ExportTable.nNames = Exports->number_of_names;
	ExportTable.nFunctions = Exports->number_of_functions;
	ExportTable.Base = Exports->base;
	ExportTable.pFunctions = (PDWORD)(RVAToOffset(Exports->address_of_functions)+BaseAddress); 
	ExportTable.pNames = (PDWORD)(RVAToOffset(Exports->address_of_names)+BaseAddress); 
	ExportTable.pNamesOrdinals = (PWORD)(RVAToOffset(Exports->address_of_name_ordinals)+BaseAddress);

	ExportTable.Functions = (EXPORTFUNCTION*)malloc(sizeof(EXPORTFUNCTION) * ExportTable.nFunctions);

	for (DWORD i =0;i<ExportTable.nFunctions;i++)
	{
		if (i < ExportTable.nNames)
		{
			ExportTable.Functions[i].funcName = (char*)(DWORD*)RVAToOffset(ExportTable.pNames[i]) + BaseAddress;
			ExportTable.Functions[i].funcOrdinal = ExportTable.pNamesOrdinals[i];
		}
		else
		{
			ExportTable.Functions[i].funcName = NULL;
			ExportTable.Functions[i].funcOrdinal = i;
		}
		ExportTable.Functions[i].funcRVA = ExportTable.pFunctions[ExportTable.Functions[i].funcOrdinal];
		ExportTable.Functions[i].funcOrdinal++;
	}
}
VOID cPEFile::initImportTable()
{
	ImportTable.DLL = NULL;
	DWORD ImportRVA = PEHeader->optional.data_directory[1].virtual_address;
	if (ImportRVA == NULL)return;
	image_import_descriptor* Imports = (image_import_descriptor*)(RVAToOffset(ImportRVA)+BaseAddress);
	
	//Getting The Number of DLLs inside
	ImportTable.nDLLs = 0;
	while ((Imports->original_first_thunk != 0 && Imports->first_thunk != 0) || Imports->name != 0)
	{
		Imports = (image_import_descriptor*)((DWORD)Imports + (DWORD)sizeof(image_import_descriptor));
		ImportTable.nDLLs++;
	};
	
	ImportTable.DLL = (IMPORTTABLE_DLL*)malloc(sizeof(IMPORTTABLE_DLL) * ImportTable.nDLLs);
	Imports = (image_import_descriptor*)(RVAToOffset(ImportRVA)+BaseAddress);
	
	//Getting DLLs and APIs
    for (DWORD l=0; l < ImportTable.nDLLs; l++)
	{
		ImportTable.DLL[l].DLLName = (char*)(RVAToOffset((DWORD)Imports->name) + BaseAddress);
        image_import_by_name** APINames;
        DWORD* APIAddresses;                           
        if (Imports->original_first_thunk != 0)
		{
           APINames = (image_import_by_name**)Imports->original_first_thunk;
        }
		else
		{
              APINames = (image_import_by_name**)Imports->first_thunk;
        };

		if (RVAToOffset((DWORD)APINames) == NULL) APINames = NULL;
        else APINames = (image_import_by_name**)(RVAToOffset((DWORD)APINames) + BaseAddress);
        APIAddresses = (DWORD*)(Imports->first_thunk + Imagebase);
		
		//Getting The Number of APIs
		ImportTable.DLL[l].nAPIs = 0;
		while (APINames[ImportTable.DLL[l].nAPIs] != 0)
		{
			ImportTable.DLL[l].nAPIs++;
		}

		ImportTable.DLL[l].API = (IMPORTTABLE_API*)malloc(ImportTable.DLL[l].nAPIs * sizeof(IMPORTTABLE_API));

		//Getting APIs
        for (DWORD i = 0; i < ImportTable.DLL[l].nAPIs; i++)
		{
            if(!(*(DWORD*)(RVAToOffset((DWORD)APINames[i]->name) + BaseAddress) & 0x80000000))
			{
				ImportTable.DLL[l].API[i].APIName = (char*)(RVAToOffset((DWORD)APINames[i]->name) + BaseAddress);

				if (APIAddresses != (DWORD*)Imagebase) ImportTable.DLL[l].API[i].APIAddressPlace = (DWORD)(&APIAddresses[i]);
            }
        };

		//Next DLL Element
        Imports = (image_import_descriptor*)((DWORD)Imports + (DWORD)sizeof(image_import_descriptor));  
    };
};

void cPEFile::initRelocations()
{
	/*find reloc section*/
	Relocations = NULL;
	unsigned short int RelocSection;
	for (unsigned int i = 0; i < nSections;i++)
	{
		if (strcmp(Section[i].SectionName,".reloc") ==0) 
			RelocSection = i;
	}

	char *RelocTypes[] = {"ABSOLUTE","HIGH","LOW","HIGHLOW","HIGHADJ","MIPS_JMPADDR","I860_BRADDR","I860_SPLIT" };

	char *RelocType;
	WORD relocType;

	DWORD RelocRVA = PEHeader->optional.data_directory[5].virtual_address;
	if (RelocRVA == NULL) return;

	PIMAGE_BASE_RELOCATION baseReloc;
	baseReloc = (PIMAGE_BASE_RELOCATION)(BaseAddress+RelocRVA-(Section[RelocSection].VirtualAddress - Section[RelocSection].PointerToRawData));
	while ( baseReloc->SizeOfBlock != 0 )
	{
		nRelocations++;
		baseReloc = (PIMAGE_BASE_RELOCATION)((DWORD)(baseReloc) + (DWORD)(baseReloc->SizeOfBlock));
	}


	Relocations = (RELOCATIONS*)malloc(sizeof(RELOCATIONS) * nRelocations);
	memset (Relocations,0,sizeof(RELOCATIONS) * nRelocations);
	baseReloc = (PIMAGE_BASE_RELOCATION)(BaseAddress+RelocRVA-(Section[4].VirtualAddress - Section[4].PointerToRawData));
	for (unsigned int i = 0; i < nRelocations;i++)
	{
		unsigned int nEntries = (baseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		Relocations[i].nEntries = nEntries;
		Relocations[i].VirtualAddress = baseReloc->VirtualAddress;
		DWORD* pEntry = MakePtr( DWORD*, baseReloc, sizeof(*baseReloc) );

		Relocations[i].Entries = (RELOCATION_ENTRIES*)malloc(sizeof(RELOCATION_ENTRIES) * nEntries);
		memset (Relocations[i].Entries,0,sizeof(RELOCATION_ENTRIES) * nEntries);
		for (unsigned int j = 0; j<nEntries ;j++)
		{
			relocType = (*pEntry & 0xF000) >> 12;
			RelocType = (relocType < 8) ? RelocTypes[relocType] : "unknown";

			Relocations[i].Entries[j].Offset = (DWORD)(*pEntry & 0x0FFF)+baseReloc->VirtualAddress;
			Relocations[i].Entries[j].Type = (char *)RelocType;

			pEntry++;
		}

		baseReloc = (PIMAGE_BASE_RELOCATION)((DWORD)(baseReloc) + (DWORD)(baseReloc->SizeOfBlock));
	}
};
cPEFile::~cPEFile()
{
	if (FileLoaded == false)return;
	//Free Section Table
	free(Section);

	//Free Export Table
	if (ExportTable.Functions != NULL)free(ExportTable.Functions);

	//Free Import Table
	if (ImportTable.DLL != NULL)
	{
		for (DWORD i = 0;i < ImportTable.nDLLs;i++)
		{
			free(ImportTable.DLL[i].API);
		}
		free(ImportTable.DLL);
	}
	/*
	if (Relocations != NULL)
	{
		cout << "Here\n";
		cout << Relocations << "\n";
		for (int i = 0;i < Relocations->nEntries; i++)
		{
			cout << i << "\n";
			if (Relocations[i].Entries)free(Relocations[i].Entries);
		}
		free(Relocations);	
		cout << "Here2\n";
	}*/
}
VOID cPEFile::initDataDirectory()
{
	DataDirectories = 0;
	for (unsigned int i =0; i< PEHeader->optional.number_of_rva_and_sizes;i++)
	{
		if (PEHeader->optional.data_directory[i].virtual_address !=0 && PEHeader->optional.data_directory[i].size != 0)
							DataDirectories |= (1 << i);
	}
}

VOID cPEFile::initSections()
{
	nSections = PEHeader->header.number_of_sections;

	Section = (SECTION_STRUCT*)malloc(nSections * sizeof(SECTION_STRUCT));
	for (DWORD i = 0;i < nSections;i++)
	{
		Section[i].SectionName = PEHeader->sections[i].name;
		Section[i].VirtualAddress = PEHeader->sections[i].virtual_address;
		Section[i].VirtualSize = PEHeader->sections[i].virtual_size;
		Section[i].PointerToRawData = PEHeader->sections[i].pointer_to_raw_data;
		Section[i].SizeOfRawData = PEHeader->sections[i].size_of_raw_data;
		Section[i].RealAddr = BaseAddress + PEHeader->sections[i].pointer_to_raw_data;
	};
}
DWORD cPEFile::RVAToOffset(DWORD RVA)
{
	if (RVA > SizeOfImage)return 0;

	for (DWORD i = 0; i < nSections;i++)
	{
		if (RVA >= Section[i].VirtualAddress && RVA < (Section[i].VirtualAddress + Section[i].VirtualSize))
						return (RVA - Section[i].VirtualAddress + Section[i].PointerToRawData);
	}
	return 0;
};

DWORD cPEFile::OffsetToRVA(DWORD RawOffset)
{
	if (RawOffset > FileLength)return 0;

	for (DWORD i = 0; i < nSections;i++)
	{
		if (RawOffset > Section[i].PointerToRawData && RawOffset < (Section[i].PointerToRawData + Section[i].SizeOfRawData))
						return (RawOffset + Section[i].VirtualAddress - Section[i].PointerToRawData);
	}
	return 0;
};

