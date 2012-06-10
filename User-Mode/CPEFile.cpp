#include "stdafx.h"
#include <cstdlib>
#include "SRDF.h"
#include <iostream>

using namespace std;
using namespace Security::Elements::Files;

cPEFile::cPEFile(char* szFilename) : cFile(szFilename)
{
	dos_header* DosHeader;
	FileLoaded = false;

	if (BaseAddress == NULL) return;

	DosHeader = (dos_header*)BaseAddress;
	
	if (DosHeader->e_magic != 'ZM') return;
	
	PEHeader = (image_header*)(BaseAddress + DosHeader->e_lfanew);
	
	if(PEHeader->signature != 'EP') return;

	Magic = PEHeader->optional.magic;
	Subsystem = PEHeader->optional.subsystem;
	Imagebase = PEHeader->optional.image_base;
	Entrypoint = PEHeader->optional.address_of_entry_point;
	FileAlignment = PEHeader->optional.file_alignment;
	SectionAlignment = PEHeader->optional.section_alignment;
	SizeOfImage = PEHeader->optional.size_of_image;
	initDataDirectory();
	initSections();
	initImportTable();

	FileLoaded = true;

};

cPEFile::~cPEFile()
{
	free(Section);
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
	for (int i = 0;i < nSections;i++)
	{
		Section[i].SectionName = PEHeader->sections[i].name;
		Section[i].VirtualAddress = PEHeader->sections[i].virtual_address;
		Section[i].VirtualSize = PEHeader->sections[i].virtual_size;
		Section[i].PointerToRawData = PEHeader->sections[i].pointer_to_raw_data;
		Section[i].SizeOfRawData = PEHeader->sections[i].size_of_raw_data;
		Section[i].RealAddr = BaseAddress + PEHeader->sections[i].pointer_to_raw_data;
	};
}

VOID cPEFile::initImportTable()
{
	DWORD ImportRVA = PEHeader->optional.data_directory[1].virtual_address;
	image_import_descriptor* Imports = (image_import_descriptor*)(RVAToOffset(ImportRVA)+BaseAddress);
	
	//Getting The Number of DLLs inside
	
	ImportTable.nDLLs = 0;
	while (Imports->original_first_thunk != 0 || Imports->first_thunk != 0 || Imports->name != 0)
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

        APINames = (image_import_by_name**)(RVAToOffset((DWORD)APINames) + BaseAddress);
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
            if(!((RVAToOffset((DWORD)APINames[i]->name) + BaseAddress) & 0x80000000))
			{
				ImportTable.DLL[l].API[i].APIName = (char*)(RVAToOffset((DWORD)APINames[i]->name) + BaseAddress);

				if (APIAddresses != (DWORD*)Imagebase) ImportTable.DLL[l].API[i].APIAddressPlace = (DWORD)(&APIAddresses[i]);

                //else ImportHeader_ptr[index]=(dword)&names[i]-BaseAddress+process->GetImagebase();
            }
        };

		//Next DLL Element
        Imports = (image_import_descriptor*)((DWORD)Imports + (DWORD)sizeof(image_import_descriptor));  
    };
};
DWORD cPEFile::RVAToOffset(DWORD RVA)
{
	if (RVA > SizeOfImage)return 0;

	for (int i = 0; i < nSections;i++)
	{
		if (RVA > Section[i].VirtualAddress && RVA < (Section[i].VirtualAddress + Section[i].VirtualSize))
						return (RVA - Section[i].VirtualAddress + Section[i].PointerToRawData);
	}
	return 0;
};

DWORD cPEFile::OffsetToRVA(DWORD RawOffset)
{
	if (RawOffset > FileLength)return 0;

	for (int i = 0; i < nSections;i++)
	{
		if (RawOffset > Section[i].PointerToRawData && RawOffset < (Section[i].PointerToRawData + Section[i].SizeOfRawData))
						return (RawOffset + Section[i].VirtualAddress - Section[i].PointerToRawData);
	}
	return 0;
};

