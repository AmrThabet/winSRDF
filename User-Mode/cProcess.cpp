/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet <amr.thabet@student.alx.edu.eg>
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
#include "SRDF.h"
#include "tlhelp32.h"

using namespace std;
using namespace Security::Targets::Memory;
using namespace Security::Storage::Files;
using namespace Security::Targets::Files;

typedef NTSTATUS (NTAPI *MYPROC)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG); 

BOOL sm_EnableTokenPrivilege()
{
	HANDLE hToken		 = 0;
	TOKEN_PRIVILEGES tkp = {0}; 

	// Get a token for this process. 
	if (!OpenProcessToken(GetCurrentProcess(),
						  TOKEN_ALL_ACCESS , 
						  &hToken))
	{
        return FALSE;
	}

	// Get the LUID for the privilege. 
	if(LookupPrivilegeValue(NULL, SE_DEBUG_NAME,
						    &tkp.Privileges[0].Luid)) 
	{
        tkp.PrivilegeCount = 1;  // one privilege to set    
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		// Set the privilege for this process. 
		AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
							  (PTOKEN_PRIVILEGES)NULL, 0); 

		if (GetLastError() != ERROR_SUCCESS)
			return FALSE;
		
		return TRUE;
	}

	return FALSE;
}

cString cProcess::Unicode2Ansi(const LPWSTR unicodeString_,int stringLength)
{
	if (unicodeString_ == NULL || stringLength == 0)return "";

	char* x = (char*)unicodeString_;
	char* y;

	y = (char *)malloc(stringLength/2+1);
	memset(y , 0 , stringLength/2+1);				
	for (int i=0 ; i<stringLength ; i+=2)
	{
		y[i/2]=x[i];
		
	}
	cString ansiString = y;
	free(y);
	return ansiString;
	
}

cProcess::cProcess(int processId,bool SkipThreads)
{

	ProcessId = processId;
	Threads = NULL;
	sm_EnableTokenPrivilege();

	HINSTANCE hinstLib; 
	MYPROC ProcAdd; 
	BOOL fRunTimeLinkSuccess; 
	isFound = false;
	this->SkipThreads = SkipThreads;
	hinstLib = LoadLibrary(TEXT("ntdll.dll")); 
	 
	    
	if (hinstLib != NULL) 
	{ 
		ProcAdd = (MYPROC) GetProcAddress(hinstLib, "NtQueryInformationProcess"); 
		if (NULL != ProcAdd) 
		{
			fRunTimeLinkSuccess = TRUE;
			procHandle = (DWORD)OpenProcess(PROCESS_ALL_ACCESS , FALSE, DWORD(processId)); // setting process handle PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME
			if (procHandle != NULL)
			{
				__PROCESS_BASIC_INFORMATION pbi;
				DWORD data_length = 0;

				(ProcAdd)((HANDLE)procHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &data_length);
				ppeb = (__PEB*)pbi.PebBaseAddress;  // setting PEB address	
				if(ppeb == NULL) return;
				ParentID = pbi.InheritedFromUniqueProcessId;
				AnalyzeProcess();
				isFound = true;
			}
		}
			
	}
	

}

bool cProcess::IsFound()
{
	return isFound;
}

void cProcess::AnalyzeProcess()
{	
	// setting process ImageBase
	processName = "";
	ReadProcessMemory((HANDLE)procHandle,&(ppeb->ImageBaseAddress),&ImageBase,sizeof(ImageBase),NULL);

	if (ImageBase == NULL)return;
	// setting process commandline
	DWORD addressToProcessParameters , bytes1;
	__RTl_USER_PROCESS_PARAMETERS  tmp3;
	LPWSTR command ;
	
	ReadProcessMemory((HANDLE)procHandle,&(ppeb->ProcessParameters),&addressToProcessParameters,sizeof(addressToProcessParameters),NULL);
	ReadProcessMemory((HANDLE)procHandle,(LPCVOID)addressToProcessParameters,&tmp3,sizeof(tmp3),NULL);
	command = (LPWSTR) malloc ((tmp3.Commandline.Length + 1)*2);
	memset(command , 0 ,(tmp3.Commandline.Length + 1)*2);
	ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(tmp3.Commandline.Buffer),command,(tmp3.Commandline.Length + 1)*2,&bytes1);

	CommandLine = Unicode2Ansi( command ,(tmp3.Commandline.Length+1)*2);
	free(command);

	//setting  processSizeOfImage , processPath , processName ,MODULE_INFO

	_PEB_LDR_DATA2 *LoaderData = NULL;
	_LDR_DATA_TABLE_ENTRY2	ModuleEntry;
	LPWSTR pathBuffer,nameBuffer,moduleNameBuffer,modulePathBuffer;
	DWORD bytesRead;
	DWORD myFlag;
	MODULE_INFO mod;
	modulesList =cList(sizeof(MODULE_INFO));
	ReadProcessMemory((HANDLE)procHandle,&(ppeb->LoaderData),&LoaderData,sizeof(LoaderData),NULL);
	if(LoaderData)
	{
		if (!ReadProcessMemory((HANDLE)procHandle,&(LoaderData->InLoadOrderModuleList),&ModuleEntry,sizeof(ModuleEntry),&bytesRead))return;
		
		myFlag = ModuleEntry.DllBase;
			
		do{	
			ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(ModuleEntry.InLoadOrderLinks.Flink),&ModuleEntry,sizeof(ModuleEntry),&bytesRead);
			if (ImageBase == ModuleEntry.DllBase)
			{
				//Initializing The Variables
				mod.moduleName = new cString(" ");
				mod.modulePath = new cString(" ");
				mod.moduleMD5 = new cString(" ");
				mod.moduleImageBase = 0;
				mod.moduleSizeOfImage = 0;
				mod.ImportedDLLs = new cHash();

				SizeOfImage = ModuleEntry.SizeOfImage;

				pathBuffer = (LPWSTR) malloc((ModuleEntry.FullDllName.Length+1)*2);
				memset(pathBuffer , 0 ,(ModuleEntry.FullDllName.Length+1)*2);
				ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(ModuleEntry.FullDllName.Buffer),pathBuffer,(ModuleEntry.FullDllName.Length+1)*2,&bytesRead);
				processPath = Unicode2Ansi(pathBuffer,(ModuleEntry.FullDllName.Length+1)*2);
				free(pathBuffer);
				nameBuffer = (LPWSTR) malloc((ModuleEntry.BaseDllName.Length+1)*2);
				memset(nameBuffer , 0 ,(ModuleEntry.BaseDllName.Length+1)*2);
				ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(ModuleEntry.BaseDllName.Buffer),nameBuffer,(ModuleEntry.BaseDllName.Length+1)*2,&bytesRead);
				processName = Unicode2Ansi(nameBuffer , (ModuleEntry.BaseDllName.Length+1)*2);
				free(nameBuffer);
				mod.moduleName = &processName;
				mod.moduleImageBase = ModuleEntry.DllBase;
				mod.moduleSizeOfImage = ModuleEntry.SizeOfImage;
				mod.modulePath = &processPath;
				mod.nExportedAPIs = 0;
				cPEFile* ModuleFile = new cPEFile(mod.modulePath->GetChar());
				if (!ModuleFile->IsFound())
				{
					mod.moduleMD5 = new cString("");
					mod.ImportedDLLs = new cHash();
				}
				else
				{
					cMD5String* MD5 = new cMD5String();
					processMD5 = MD5->Encrypt((char*)ModuleFile->BaseAddress,ModuleFile->FileLength);
					mod.moduleMD5 = &processMD5;
					if (ModuleFile->IsFound())mod.ImportedDLLs = ModuleImportedDlls(ModuleFile);
					else mod.ImportedDLLs = new cHash();
					delete MD5;
				}
				delete ModuleFile;
				modulesList.AddItem((char*)&mod);
			}
			else
			{
				//Initializing The Variables
				mod.moduleName = new cString(" ");
				mod.modulePath = new cString(" ");
				mod.moduleMD5 = new cString(" ");
				mod.moduleImageBase = 0;
				mod.moduleSizeOfImage = 0;
				mod.ImportedDLLs = new cHash();

				if (ModuleEntry.DllBase == 0)continue;

				mod.moduleImageBase = ModuleEntry.DllBase;
				mod.moduleSizeOfImage = ModuleEntry.SizeOfImage;
				modulePathBuffer = (LPWSTR) malloc((ModuleEntry.FullDllName.Length+1)*2);
				memset(modulePathBuffer , 0 ,(ModuleEntry.FullDllName.Length+1)*2);
				ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(ModuleEntry.FullDllName.Buffer),modulePathBuffer,(ModuleEntry.FullDllName.Length+1)*2,&bytesRead);
				mod.modulePath = new cString(Unicode2Ansi(modulePathBuffer,(ModuleEntry.FullDllName.Length+1)*2));
				free(modulePathBuffer);
				moduleNameBuffer = (LPWSTR) malloc((ModuleEntry.BaseDllName.Length+1)*2);
				memset(moduleNameBuffer , 0 ,(ModuleEntry.BaseDllName.Length+1)*2);
				ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(ModuleEntry.BaseDllName.Buffer),moduleNameBuffer,(ModuleEntry.BaseDllName.Length+1)*2,&bytesRead);
				mod.moduleName = new cString(Unicode2Ansi(moduleNameBuffer , (ModuleEntry.BaseDllName.Length+1)*2));
				free(moduleNameBuffer);
				if (mod.modulePath->GetLength() == 0)
				{
					mod.moduleMD5 = new cString("");
					mod.ImportedDLLs = new cHash();
					continue;
				}
				cPEFile* ModuleFile = new cPEFile(mod.modulePath->GetChar());
				if (!ModuleFile->IsFound())
				{
					mod.moduleMD5 = new cString("");
					mod.ImportedDLLs = new cHash();
					mod.nExportedAPIs = 0;
				}
				cMD5String* MD5 = new cMD5String();
				mod.moduleMD5 = new cString(MD5->Encrypt((char*)ModuleFile->BaseAddress,ModuleFile->FileLength));
				delete MD5;
				if (mod.moduleImageBase != 0)
				{
					if (ModuleFile->IsFound())mod.ImportedDLLs = ModuleImportedDlls(ModuleFile);
					else mod.ImportedDLLs = new cHash();
					mod.nExportedAPIs = ModuleFile->ExportTable.nFunctions;
					modulesList.AddItem((char*)&mod);
				}
				delete ModuleFile;
			}
				
		} while(myFlag != ModuleEntry.DllBase);
		
	}
	GetMemoryMap();
	if(!SkipThreads)
		RefreshThreads();

}
cHash* cProcess::ModuleImportedDlls(cPEFile* Module)
{
	cHash* hash = new cHash("ImportedDlls","DLL","DLLNo","DLLName");
	if (Module->DataDirectories & DATADIRECTORY_IMPORT)
		for (int i = 0;i < Module->ImportTable.nDLLs;i++)
		{
			hash->AddItem(cString(i),Module->ImportTable.DLL[i].DLLName);
		}
	return hash;
}
BOOL cProcess::GetMemoryMap()
{
	
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	char *pMin = (char*)si.lpMinimumApplicationAddress;
	char *pMax = (char*)si.lpMaximumApplicationAddress;

	MEMORY_MAP memMap;
	MemoryMap = cList(sizeof(MEMORY_MAP));
	for (char* pAddress = pMin; pAddress<pMax; /*Empty*/)
	{
		MEMORY_BASIC_INFORMATION mbi;
		DWORD res = VirtualQueryEx((HANDLE)procHandle,pAddress, &mbi, sizeof(mbi));
		//cout << res << "\n";
		if (res != sizeof(mbi))
		{
			continue;
		}
		if (mbi.State == MEM_COMMIT)
		{

			memMap.Address = (DWORD)mbi.BaseAddress;
			memMap.Size	= (DWORD)mbi.RegionSize;
			memMap.AllocationBase = (DWORD)mbi.AllocationBase;
			memMap.Protection = (DWORD)mbi.AllocationProtect;
			MemoryMap.AddItem((char*)&memMap);
		}
 
		pAddress += mbi.RegionSize;
	}
 
	return true;
}
cProcess::~cProcess()
{
	if (!isFound)return;
	for (int i = 0;i < modulesList.GetNumberOfItems();i++)
	{
		MODULE_INFO* mod = (MODULE_INFO*)modulesList.GetItem(i);
		//Free by setting small buffer;
		*mod->moduleName = " ";
		*mod->moduleMD5 = " ";
		*mod->modulePath = " ";
		if (mod->ImportedDLLs)delete mod->ImportedDLLs;
	}
	if (Threads)delete Threads;
	CloseHandle((HANDLE)procHandle);
}
//in all cases .. it return a pointer to a place in memory ... that's to avoid bugs ... but it should return null if it can\t find the address
DWORD cProcess::Read(DWORD startAddress,DWORD size)
{
	LPVOID buffer;
	DWORD bytesRead;
	buffer = (LPVOID)malloc(size+1);
	memset(buffer , 0 , size+1);
	ReadProcessMemory((HANDLE)procHandle , (LPCVOID) startAddress ,  buffer , size , &bytesRead);
	return (DWORD)buffer;
}

DWORD cProcess::Allocate(DWORD preferedAddress,DWORD size)
{

	DWORD address2AllocatedMemory = NULL;

	if (preferedAddress == NULL)
	{
		address2AllocatedMemory = (DWORD) VirtualAllocEx((HANDLE)procHandle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	else
	{
		address2AllocatedMemory = (DWORD) VirtualAllocEx((HANDLE)procHandle, (LPVOID) preferedAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	return address2AllocatedMemory;

}


DWORD cProcess::Write (DWORD startAddressToWrite ,DWORD buffer ,DWORD sizeToWrite)
{
	DWORD sizeWritten;


	if (startAddressToWrite == NULL)
	{
		startAddressToWrite	= Allocate(NULL, sizeToWrite);
	}
	
	if (startAddressToWrite != NULL)
	{
		if (WriteProcessMemory((HANDLE) procHandle , (LPVOID) startAddressToWrite , (LPCVOID) buffer , sizeToWrite , &sizeWritten))
		{
			FlushInstructionCache((HANDLE)procHandle,(LPCVOID)startAddressToWrite,sizeToWrite);
			return startAddressToWrite;
		}
	}
	
	return 0;

}



DWORD cProcess::DllInject(cString DLLFilename)
{
	DWORD remoteAddress;
	DWORD hThread = NULL;
	DWORD threadId = NULL;
	
	remoteAddress = Allocate(NULL ,(DWORD)strlen((char*) DLLFilename));

	HMODULE handleToKernel32 = GetModuleHandle("kernel32.dll");
	if (Write(remoteAddress , (DWORD)DLLFilename.GetChar() ,(DWORD)strlen( (char*) DLLFilename)))
	{
		hThread = (DWORD)CreateRemoteThread((HANDLE)procHandle ,NULL , 0 , ( LPTHREAD_START_ROUTINE)GetProcAddress(handleToKernel32 , "LoadLibraryA") , (LPVOID)remoteAddress , 0 , &threadId);
	
	}
	
	return hThread;
	

}
  
DWORD cProcess::CreateThread (DWORD addressToFunction , DWORD addressToParameter)
{
	DWORD threadId;
	
	CreateRemoteThread((HANDLE)procHandle ,NULL , 0 , ( LPTHREAD_START_ROUTINE) addressToFunction , (LPVOID)addressToParameter , 0 , & threadId);

	return threadId;

}

void cProcess::RefreshThreads()
{
	HANDLE hThreadSnap;
	THREADENTRY32 te32;
	if (Threads != NULL)delete Threads;
	Threads = NULL;
	 hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	 if (hThreadSnap == INVALID_HANDLE_VALUE )
	 {
			return;	
	 }
	 Threads = new cList(sizeof(THREAD_INFO));
	 memset(&te32,0,sizeof(te32));
	 te32.dwSize = sizeof( THREADENTRY32 );
	if (!Thread32First( hThreadSnap, &te32 ) )
	{
		CloseHandle( hThreadSnap );          
		return;	
	}
	if (te32.th32OwnerProcessID == ProcessId)
	{
		THREAD_INFO ti;
		ti.ThreadId = te32.th32ThreadID;
		EnumerateThread(&ti);
		Threads->AddItem((char*)&ti);
	}

	memset(&te32,0,sizeof(te32));
	te32.dwSize = sizeof( THREADENTRY32 );
	while (Thread32Next( hThreadSnap, &te32 ))
	{
		if (te32.th32OwnerProcessID == ProcessId)
		{
			THREAD_INFO ti;
			memset(&ti,0, sizeof(THREAD_INFO));

			ti.ThreadId = te32.th32ThreadID;
			EnumerateThread(&ti);
			Threads->AddItem((char*)&ti);
		}
		memset(&te32,0,sizeof(te32));
		te32.dwSize = sizeof( THREADENTRY32 );
	}
	CloseHandle( hThreadSnap );
}

void cProcess::EnumerateThread(THREAD_INFO* ti)
{
	LDT_ENTRY entry;
	memset(&ti->Context,0,sizeof(CONTEXT));
	ti->Context.ContextFlags = CONTEXT_ALL;

	ti->Handle = OpenThread(THREAD_ALL_ACCESS,FALSE,ti->ThreadId);
	if (ti->Handle == NULL)return;
	//SuspendThread(hThread);
	if (GetThreadContext(ti->Handle,&ti->Context) == 0)
	{
		//ResumeThread(hThread);
		return;
	}
	//ResumeThread(hThread);
	
	if (GetThreadSelectorEntry(ti->Handle,ti->Context.SegFs,&entry))
	{
		ti->TEB = (entry.HighWord.Bits.BaseHi << 24) | (entry.HighWord.Bits.BaseMid << 16) | (entry.BaseLow);
		DWORD TEB = Read(ti->TEB,100);
		if (TEB != NULL)
		{
			DWORD* SEHAddr = (DWORD*)(TEB);
			DWORD*  StackLimitAddr = (DWORD*)(TEB+4);
			DWORD*  StackBaseAddr = (DWORD*)(TEB+8);
			ti->SEH = *SEHAddr;
			ti->StackBase = *StackBaseAddr;
			ti->StackLimit = *StackLimitAddr;
			free((void*)TEB);
		}
	}
	CloseHandle(ti->Handle);
}

DWORD align(DWORD src, DWORD Alignment, bool lower)
{
    DWORD aligned_ptr = src;

    if (src % Alignment != 0)
	{
        if (lower)
		{
            aligned_ptr -= src % Alignment;
        }
		else
		{
            aligned_ptr += Alignment - (src % Alignment);
        }
    }
    return aligned_ptr;
}

//Here .. entrypoint RVA
bool cProcess::DumpProcess(cString Filename, DWORD Entrypoint, DWORD ImportUnloadingType)
{
	image_header         * PEHeader;
    DWORD                  FileHandler, PEHeader_ptr;
	
	FileHandler = Read(ImageBase,SizeOfImage);
	if (FileHandler == NULL) return false;
	if (!(*((short *) FileHandler) == 0x5a4d)) return false;
    PEHeader_ptr = ((dos_header *) FileHandler)->e_lfanew + FileHandler;
    if (!(*((short *) PEHeader_ptr) == 0x4550)) return false;

	PEHeader = (image_header *) PEHeader_ptr;
    image_section_header * sections = (image_section_header *) (PEHeader->header.size_of_optional_header + (DWORD) &PEHeader->optional);
    if (PEHeader->header.number_of_sections != 0) 
	{
        for (int i = 0; i < PEHeader->header.number_of_sections - 1; i++) 
		{
            sections[i].size_of_raw_data    = sections[i + 1].virtual_address - sections[i].virtual_address;
            sections[i].pointer_to_raw_data = sections[i].virtual_address;
            sections[i].characteristics    |= 0x80000000;
        }

        DWORD index = PEHeader->header.number_of_sections - 1;
        
		if (sections[index].virtual_size != 0)
		{
            sections[index].size_of_raw_data = align(sections[index].virtual_size, PEHeader->optional.section_alignment, false);
        }
        sections[index].pointer_to_raw_data = sections[index].virtual_address;
        sections[index].characteristics    |= 0x80000000;
    }
	if (Entrypoint != 0) PEHeader->optional.address_of_entry_point = Entrypoint; 
	if (ImportUnloadingType == PROC_DUMP_ZEROIMPORTTABLE)
		UnloadImportTable(FileHandler);
	else
	{
		PEHeader->optional.data_directory[1].virtual_address = 0;
		PEHeader->optional.data_directory[1].size            = 0;
	}

	cFileToWrite* ExeFile = new cFileToWrite(Filename,false);
	if (ExeFile->IsFound() == false)return false;
	ExeFile->write((char*)FileHandler,SizeOfImage);

	delete ExeFile; // To force it to close the File
	free((void*)FileHandler);
	return true;

}

DWORD cProcess::UnloadImportTable(DWORD NewImagebase)
{
	
    DWORD                     FileHandler = (DWORD) NewImagebase;
    image_header            * PEHeader    = (image_header *) (((dos_header *) FileHandler)->e_lfanew + FileHandler);
    image_import_descriptor * Imports     = (image_import_descriptor *) (PEHeader->optional.data_directory[1].virtual_address + FileHandler);
	if (Imports == 0)return 0;


	cPEFile* PEFile = new cPEFile(this->processPath);

    while(1)
	{

        if ((Imports->original_first_thunk == 0 && Imports->first_thunk == 0) || (Imports->name == 0))
		{
            break;
        }

        image_import_by_name** names;
        DWORD* namesInFile;              // pointer to the the place that we will put the addresses there 

		names    = (image_import_by_name **) Imports->original_first_thunk;
		namesInFile    = (DWORD*) Imports->original_first_thunk;

        if (Imports->original_first_thunk == 0)		//Will fail
		{
			names = (image_import_by_name **) Imports->first_thunk;
			namesInFile = (DWORD *) Imports->first_thunk;
        }
       
        names    = (image_import_by_name **) ((DWORD) names + FileHandler);
		namesInFile = (DWORD *) (PEFile->RVAToOffset((DWORD)namesInFile) + PEFile->BaseAddress);

		int i = 0;
        while(names[i] != 0 && namesInFile[i] != 0)
		{
            memcpy(&names[i], &namesInFile[i], 4);
			i++;
        }
		Imports = (image_import_descriptor*)((DWORD)Imports + sizeof(image_import_descriptor));
	}
	delete PEFile;
	return 0;
}


MemoryDump::MemoryDump(cProcess* Process,bool DumpFullMemory)
{
	RootName = "Process";
	MemoryMap = NULL;
	nMemoryRegions = 0;
	this->Process = Process;
	ImageBase = Process->ImageBase;
	SizeOfImage = Process->SizeOfImage;
	processName = Process->processName;
	processPath = Process->processPath;
	ParentID = Process->ParentID;
	ProcessId = Process->ProcessId;
	CommandLine = Process->CommandLine;
	processMD5 = Process->processMD5;
	modulesList = &Process->modulesList;

	nMemoryRegions =  Process->MemoryMap.GetNumberOfItems();
	
	MemoryMap = (MemoryRegion**)malloc(sizeof(MemoryRegion*) * Process->MemoryMap.GetNumberOfItems());
	memset(MemoryMap,0,sizeof(MemoryRegion*) * Process->MemoryMap.GetNumberOfItems());
	for (DWORD i =0; i < Process->MemoryMap.GetNumberOfItems();i++)
	{
		MEMORY_MAP* MemMap = (MEMORY_MAP*)Process->MemoryMap.GetItem(i);
		
		cString Filename = cString(Process->ProcessId);
		Filename += "\\Dump_";
		Filename += cString(Process->ProcessId).GetChar(); 
		Filename += "_"; 
		Filename += cString(MemMap->Address).GetChar();
		//cout << Filename << "\n";
		char* Address = NULL;
		if (DumpFullMemory == false)
		{
			Filename = " ";		//this means no File (Don't dump the memory into file .. just the process info)
		}
		else
		{
			CreateDirectory((LPCSTR)Process->processName,NULL);
			char* Address = (char*)Process->Read(MemMap->Address,MemMap->Size);
			if (Address == NULL)continue;			//Not Found .. so chance
		}
		MemoryMap[i] = new MemoryRegion(Address,MemMap->Size,MemMap->AllocationBase,MemMap->Protection,MemMap->Address,Filename);
	}
}

MemoryDump::MemoryDump()
{
	Process = NULL;
	RootName = "Process";
	MemoryMap = NULL;
	nMemoryRegions = 0;
}
MemoryDump::~MemoryDump()
{
	if (MemoryMap)
	{
		for (DWORD i =0; i < Process->MemoryMap.GetNumberOfItems();i++)
		{
			if (MemoryMap[i])delete MemoryMap[i];
		}
		free(MemoryMap);
	}
}

void MemoryDump::SetSerialize(cXMLHash& XMLParams)
{

	XMLParams.AddText("ImageBase",Process->ImageBase);		//Will be converted automatically to string
	XMLParams.AddText("SizeOfImage",Process->SizeOfImage);
	XMLParams.AddText("processName",Process->processName);
	XMLParams.AddText("processPath",Process->processPath);
	XMLParams.AddText("ParentID",Process->ParentID);
	XMLParams.AddText("ProcessId",Process->ProcessId);
	XMLParams.AddText("CommandLine",Process->CommandLine);
	XMLParams.AddText("processMD5",Process->processMD5);
	XMLParams.AddText("nMemoryRegions",nMemoryRegions);

	//Saving Modules
	for (DWORD i = 0; i < Process->modulesList.GetNumberOfItems(); i++)
	{
		
		MODULE_INFO* mod = (MODULE_INFO*)Process->modulesList.GetItem(i);
		if (mod->moduleImageBase == NULL)continue;
		cXMLHash ModHash;

		ModHash.AddText("moduleName",*mod->moduleName);
		ModHash.AddText("modulePath",*mod->modulePath);
		ModHash.AddText("moduleMD5",*mod->moduleMD5);
		ModHash.AddText("moduleImageBase",mod->moduleImageBase);
		ModHash.AddText("moduleSizeOfImage",mod->moduleSizeOfImage);
		ModHash.AddText("modulenExportedAPIs",mod->nExportedAPIs);
		ModHash.AddItem("ImportedDLLs",mod->ImportedDLLs->Serialize());
		cString ModXML = SerializeObject(&ModHash);
		XMLParams.AddItem("Module",ModXML);
	}

	//Saving Memory Regions
	for (DWORD i = 0; i < nMemoryRegions; i++)
	{
		XMLParams.AddItem("MemoryRegion",MemoryMap[i]->Serialize());
	}
}

void MemoryDump::GetSerialize(cXMLHash& XMLParams)
{
	ImageBase = atoi(XMLParams["ImageBase"]);
	SizeOfImage =atoi( XMLParams["SizeOfImage"]);
	processName = XMLParams["processName"];
	processPath = XMLParams["processPath"];
	ParentID = atoi(XMLParams["ParentID"]);
	ProcessId = atoi(XMLParams["ProcessId"]);
	CommandLine = XMLParams["CommandLine"];
	processMD5 = XMLParams["processMD5"];

	//Getting Modules
	modulesList = new cList(sizeof(MODULE_INFO)+1000);
	for (DWORD i = 0; i < XMLParams.GetNumberOfItems("Module"); i++)
	{
		MODULE_INFO mod;
		cXMLHash* ModHash = DeserializeObject(XMLParams.GetText("Module",i));
		if (ModHash != NULL)
		{
			mod.moduleName = new cString(ModHash->GetText("moduleName",i));
			mod.modulePath = new cString(ModHash->GetText("modulePath",i));
			mod.moduleMD5 = new cString(ModHash->GetText("moduleMD5",i));
			mod.moduleImageBase = atoi(ModHash->GetText("moduleImageBase",i));
			mod.moduleSizeOfImage = atoi(ModHash->GetText("moduleSizeOfImage",i));
			mod.nExportedAPIs = atoi(ModHash->GetText("modulenExportedAPIs",i));
			mod.ImportedDLLs = new cHash();
			mod.ImportedDLLs->Deserialize(ModHash->GetValue("ImportedDLLs",i));
			modulesList->AddItem((char*)&mod);
			delete ModHash;
		}
	}

	//Getting Memory Regions
	nMemoryRegions = atoi(XMLParams["nMemoryRegions"]);
	MemoryMap = (MemoryRegion**)malloc(sizeof(MemoryRegion*) * nMemoryRegions);
	memset(MemoryMap,0,sizeof(MemoryRegion*) * nMemoryRegions);
	for (DWORD i = 0; i < nMemoryRegions; i++)
	{
		MemoryMap[i] = new MemoryRegion();
		MemoryMap[i]->Deserialize(XMLParams.GetValue("MemoryRegion",i));
	}
}

MemoryRegion::MemoryRegion(char* buffer, DWORD size,DWORD allocationBase, DWORD protection, DWORD RealAddress,cString filename)
{
	Buffer = buffer;
	Size = size;
	Address = RealAddress;
	Filename = filename;
	IsFound = true;
	allocationBase = AllocationBase;
	protection = Protection;
}

MemoryRegion::MemoryRegion()
{
	Buffer = NULL;
	Address = NULL;
	Filename = "";
	Size = 0;
	AllocationBase = NULL;
	Protection = NULL;
	IsFound = false;
}

MemoryRegion::~MemoryRegion()
{
	if (Buffer != NULL)free((char*)Buffer);
}
void MemoryRegion::SetSerialize(cXMLHash& XMLParams)
{
	XMLParams.AddText("Address",Address);
	XMLParams.AddText("Size",Size);
	XMLParams.AddText("AllocationBase",AllocationBase);
	XMLParams.AddText("Protection",Protection);
	XMLParams.AddText("Filename",Filename);

	if (Filename == cString(" ")) return;
	if (Address == NULL) return;
	cFileToWrite* MemoryRegionFile = new cFileToWrite(Filename,false);
	MemoryRegionFile->write(Buffer,Size);
	delete MemoryRegionFile;
}

void MemoryRegion::GetSerialize(cXMLHash& XMLParams)
{
	Address = atoi(XMLParams["Address"]);
	Size = atoi(XMLParams["Size"]);
	AllocationBase = atoi(XMLParams["AllocationBase"]);
	Protection = atoi(XMLParams["Protection"]);
	Filename = XMLParams["Filename"];

	if (Filename == cString(" ")) return;

	cFile* File = new cFile(Filename);
	if (File->IsFound() == false)
	{
		IsFound = false;
		return;
	}
	Buffer = (char*)File->BaseAddress;
	if (Size != File->FileLength) IsFound = false;
	else IsFound = true;
}
