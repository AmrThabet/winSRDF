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
cHash* cIATHook::GetModules(cHash* SkippedModules,bool HookThese)
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
					
					if (HookThese)
					{
						HookedModules->AddItem("Hooked",ModuleEntry->DllBase);
						
						//ModuleEntry = (_LDR_DATA_TABLE_ENTRY2*)ModuleEntry->InLoadOrderLinks.Flink;
						cString x;
						x.Format("Hooking DLL: %X\n",ModuleEntry->DllBase);
						cout << x;
						//FILE* file = fopen("mem3.log","a");
						//fwrite(x.GetChar(),x.GetLength(),1,file);
						//fclose(file);
					}
					else 
					{
						ModuleEntry = (_LDR_DATA_TABLE_ENTRY2*)ModuleEntry->InLoadOrderLinks.Flink;
						continue;
					}
				}
			}
			if (!HookThese)
			{
				//cout << "Hooking DLL:" << (int*)ModuleEntry->DllBase << "\n";
				HookedModules->AddItem("Hooked",ModuleEntry->DllBase);
			}
			ModuleEntry = (_LDR_DATA_TABLE_ENTRY2*)ModuleEntry->InLoadOrderLinks.Flink;

		} while(FirstDLL != ModuleEntry->DllBase);
	}
	
	return NULL;
}

//Hook all modules by parsing their import table
void cIATHook::Hook(cString DLLName, cString APIName, DWORD NewFunc, cHash* SkippedModules,bool HookThese)
{
	GetModules(SkippedModules,HookThese);
	HookedAddresses = new cHash();
	HookedAPIName = APIName;
	HookedAPI = (DWORD)GetProcAddress(LoadLibraryA(DLLName.GetChar()),APIName.GetChar());
	cString x;
	//if(HookedAPI == 0x76F024F1)HookedAPI = 0x74CAE4A6;
	
	x.Format("Found API: %s = %X at %X",APIName.GetChar(),HookedAPI,GetModuleHandleA(DLLName.GetChar()));
	//MessageBoxA(0,x.GetChar(),"MemMirtigation",0);
	if (HookedAPI == 0x74CAE4A6) ;
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
			if (1)//GetModuleHandle((char*)(Imports->name + BaseAddress)) == GetModuleHandle(DLLName))
			{
				Found = true;
				//Hooking DLL Function
				DWORD* AddressesArray = (DWORD*)(Imports->first_thunk + BaseAddress);
				for (int l = 0;AddressesArray[l] != NULL;l++)
				{
					//cout << (int*)HookedAPI << "\n";
					if (AddressesArray[l] == HookedAPI)
					{
						//76F024F1 ==> 74CAE4A6
						//76EEE046
						//76EEDFA5
						//76EF302A
						//74C914C9
						//Do Hooking
						//cout << "API Found: " << l << "\t" << (int*)AddressesArray[l] << "\n";
						
						DWORD nProtect = NULL;
						//cout << (int*)(&AddressesArray[l]) << "\n";
						if (BaseAddress == 0x74B20000)
						{
							cString x;
							x.Format("Found API: %X = %X",&AddressesArray[l],AddressesArray[l]);
							//MessageBoxA(0,x.GetChar(),"MemMitigation",0);
						}
						if ((DWORD)&AddressesArray[l] == 0x74B219E8)
						{
							//MessageBoxA(0,"Hooked","MemMitigation",0);
						}
						DWORD Success = VirtualProtect(&AddressesArray[l],4,PAGE_READWRITE,&nProtect);
						if (!Success)
						{
							cout << "Error\n";
							continue;
						}
						AddressesArray[l] = NewFunc;//AddressesArray[l];
						HookedAddresses->AddItem(BaseAddress,(DWORD)&AddressesArray[l]);
						VirtualProtect(&AddressesArray[l],4,nProtect,&nProtect);
					}
				}
			}
			Imports = (image_import_descriptor*)((DWORD)Imports + (DWORD)sizeof(image_import_descriptor));
		};

		//if (!Found) continue;

		
		
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