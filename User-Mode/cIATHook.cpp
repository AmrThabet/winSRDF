/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet <amr.thabet[at]student.alx.edu.eg>
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
#include <windows.h>
#include "SRDF.h"
#include <cstdio>


using namespace std;
using namespace Security::Libraries::Malware::Behavioral;

typedef NTSTATUS (NTAPI *MYPROC)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG); 

//Get my Process Environment Block (PEB) to start parsing the loaded modules
DWORD cIATHook::GetPEB()
{
	HMODULE hinstLib = LoadLibrary(TEXT("ntdll.dll")); 
	PEB = NULL;
	MYPROC ProcAdd = (MYPROC) GetProcAddress(hinstLib, "NtQueryInformationProcess"); 
	if (NULL != ProcAdd) 
	{
		__PROCESS_BASIC_INFORMATION pbi;
		DWORD data_length = 0;

		(ProcAdd)((HANDLE)GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &data_length);
		PEB = (__PEB*)pbi.PebBaseAddress;
	}
	return (DWORD)PEB;
}

// Get all loaded modules and skip the modules that will not be hooked
cHash* cIATHook::GetModules(cHash* SkippedModules)
{
	HookedModules = new cHash();
	GetPEB();
	_PEB_LDR_DATA2 * LoaderData = PEB->LoaderData;
	_LDR_DATA_TABLE_ENTRY2*	ModuleEntry;
	
	if(LoaderData)
	{
		ModuleEntry = (_LDR_DATA_TABLE_ENTRY2*)&LoaderData->InLoadOrderModuleList;
		DWORD FirstDLL = ModuleEntry->DllBase;
		do
		{
			if(ModuleEntry->DllBase == NULL)
			{
				ModuleEntry = (_LDR_DATA_TABLE_ENTRY2*)ModuleEntry->InLoadOrderLinks.Flink;
				continue;
			}
			if (SkippedModules != NULL)
			{
				bool Found = false;
				for (int i = 0;i<SkippedModules->GetNumberOfItems();i++)
				{
					if (ModuleEntry->DllBase == (DWORD)GetModuleHandle((LPCSTR)SkippedModules->GetValue(i).GetChar()))
					{
						Found = true;
						break;
					}
				}
				if (Found)	//Skip
				{
					ModuleEntry = (_LDR_DATA_TABLE_ENTRY2*)ModuleEntry->InLoadOrderLinks.Flink;
					continue;
				}
			}
			HookedModules->AddItem("Hooked",ModuleEntry->DllBase);
			ModuleEntry = (_LDR_DATA_TABLE_ENTRY2*)ModuleEntry->InLoadOrderLinks.Flink;

		} while(FirstDLL != ModuleEntry->DllBase);
	}
	return NULL;
}

//Hook all modules by parsing their import table
void cIATHook::Hook(cString DLLName, cString APIName, DWORD NewFunc, cHash* SkippedModules)
{
	GetModules(SkippedModules);
	HookedAddresses = new cHash();
	HookedAPIName = APIName;
	HookedAPI = (DWORD)GetProcAddress(GetModuleHandle(DLLName),APIName);

	for (int i =0; i< HookedModules->GetNumberOfItems();i++)
	{
		DWORD BaseAddress = atoi(HookedModules->GetValue(i));
		dos_header* DosHeader = (dos_header*)BaseAddress;
		if (DosHeader->e_magic != 'ZM') continue;

		image_header* PEHeader = (image_header*)(BaseAddress + DosHeader->e_lfanew);
		if(PEHeader->signature != 'EP') continue;

		DWORD ImportRVA = PEHeader->optional.data_directory[1].virtual_address;
		if (ImportRVA == NULL)continue;
		image_import_descriptor* Imports = (image_import_descriptor*)(ImportRVA + BaseAddress);

		//Getting The Needed DLL
		bool Found = false;
		while ((Imports->original_first_thunk != 0 && Imports->first_thunk != 0) || Imports->name != 0)
		{
			//cout << (char*)(Imports->name + BaseAddress) << "\n";
			if (GetModuleHandle((char*)(Imports->name + BaseAddress)) == GetModuleHandle(DLLName))
			{
				Found = true;
				break;
			}
			Imports = (image_import_descriptor*)((DWORD)Imports + (DWORD)sizeof(image_import_descriptor));
		};

		if (!Found) continue;

		//Hooking DLL Function
		DWORD* AddressesArray = (DWORD*)(Imports->first_thunk + BaseAddress);
		for (int l = 0;AddressesArray[l] != NULL;l++)
		{
			//cout << (int*)HookedAPI << "\n";
			if (AddressesArray[l] == HookedAPI)
			{
				//Do Hooking
				//cout << "API Found: " << l << "\t" << (int*)AddressesArray[l] << "\n";
				
				DWORD nProtect = NULL;
				//cout << (int*)(&AddressesArray[l]) << "\n";
				DWORD Success = VirtualProtect(&AddressesArray[l],4,PAGE_READWRITE,&nProtect);
				if (!Success)
				{
					//cout << "Error\n";
					continue;
				}
				AddressesArray[l] = NewFunc;//AddressesArray[l];

				HookedAddresses->AddItem(BaseAddress,(DWORD)&AddressesArray[l]);
				VirtualProtect(&AddressesArray[l],4,nProtect,&nProtect);
			}
		}
	}
}

void cIATHook::Unhook()
{
	for (int i = 0;i < HookedAddresses->GetNumberOfItems();i++)
	{
		//Get Hooked Address
		//cout << (int*)atoi(HookedAddresses->GetValue(i)) << "\n";
		DWORD* AddressToAPI = (DWORD*)atoi(HookedAddresses->GetValue(i));

		//Unhook API
		DWORD nProtect = NULL;
		DWORD Success = VirtualProtect(AddressToAPI,4,PAGE_READWRITE,&nProtect);
		if (!Success)
		{
			//cout << "Error Unhooking API\n";
			continue;
		}
		*AddressToAPI = HookedAPI;		//Set to the real Address of the API
		VirtualProtect(AddressToAPI,4,nProtect,&nProtect);
	}
}