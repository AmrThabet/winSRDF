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

cString cProcess::Unicode2Ansi(LPWSTR unicodeString_,int stringLength)
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

	return ansiString;
	
}

cProcess::cProcess(int processId)
{

	ProcessId = processId;
	Threads = 0;
	sm_EnableTokenPrivilege();

	HINSTANCE hinstLib; 
	MYPROC ProcAdd; 
	BOOL fRunTimeLinkSuccess; 
	isFound = false;
	    
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
	CommandLine = cString (Unicode2Ansi( command ,(tmp3.Commandline.Length+1)*2));


	//setting  processSizeOfImage , processPath , processName ,MODULE_INFO

	_PEB_LDR_DATA2 *tmp1=NULL;
	_LDR_DATA_TABLE_ENTRY2	tmp2;
	LPWSTR pathBuffer,nameBuffer,moduleNameBuffer,modulePathBuffer;
	DWORD bytesRead;
	DWORD myFlag;
	MODULE_INFO mod;
	modulesList =cList(sizeof(MODULE_INFO));
	ReadProcessMemory((HANDLE)procHandle,&(ppeb->LoaderData),&tmp1,sizeof(tmp1),NULL);
	if(tmp1)
	{
		if (!ReadProcessMemory((HANDLE)procHandle,&(tmp1->InLoadOrderModuleList),&tmp2,sizeof(tmp2),&bytesRead))return;
		
		myFlag = tmp2.DllBase;
			
		do{	
			ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(tmp2.InLoadOrderLinks.Flink),&tmp2,sizeof(tmp2),&bytesRead);
			if (ImageBase == tmp2.DllBase)
			{
				SizeOfImage = tmp2.SizeOfImage;

				pathBuffer = (LPWSTR) malloc((tmp2.FullDllName.Length+1)*2);
				memset(pathBuffer , 0 ,(tmp2.FullDllName.Length+1)*2);
				ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(tmp2.FullDllName.Buffer),pathBuffer,(tmp2.FullDllName.Length+1)*2,&bytesRead);
				processPath = cString(Unicode2Ansi(pathBuffer,(tmp2.FullDllName.Length+1)*2));
				
				nameBuffer = (LPWSTR) malloc((tmp2.BaseDllName.Length+1)*2);
				memset(pathBuffer , 0 ,(tmp2.BaseDllName.Length+1)*2);
				ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(tmp2.BaseDllName.Buffer),nameBuffer,(tmp2.BaseDllName.Length+1)*2,&bytesRead);
				processName = cString(Unicode2Ansi(nameBuffer , (tmp2.BaseDllName.Length+1)*2));

				mod.moduleImageBase = tmp2.DllBase;
				mod.moduleSizeOfImage = tmp2.SizeOfImage;
				mod.modulePath = &processPath;
				cFile* ModuleFile = new cFile(mod.modulePath->GetChar());
				cMD5String* MD5 = new cMD5String();
				processMD5 = MD5->Encrypt((char*)ModuleFile->BaseAddress,ModuleFile->FileLength);
				mod.moduleMD5 = &processMD5;
				delete ModuleFile;
				mod.moduleName = &processName;
				modulesList.AddItem((char*)&mod);
			}
			else
			{
				mod.moduleImageBase = tmp2.DllBase;
				mod.moduleSizeOfImage = tmp2.SizeOfImage;

				modulePathBuffer = (LPWSTR) malloc((tmp2.FullDllName.Length+1)*2);
				memset(modulePathBuffer , 0 ,(tmp2.FullDllName.Length+1)*2);
				ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(tmp2.FullDllName.Buffer),modulePathBuffer,(tmp2.FullDllName.Length+1)*2,&bytesRead);
				mod.modulePath = new cString(Unicode2Ansi(modulePathBuffer,(tmp2.FullDllName.Length+1)*2));
				moduleNameBuffer = (LPWSTR) malloc((tmp2.BaseDllName.Length+1)*2);
				memset(moduleNameBuffer , 0 ,(tmp2.BaseDllName.Length+1)*2);
				ReadProcessMemory((HANDLE)procHandle,(LPCVOID)(tmp2.BaseDllName.Buffer),moduleNameBuffer,(tmp2.BaseDllName.Length+1)*2,&bytesRead);
				mod.moduleName = new cString(Unicode2Ansi(moduleNameBuffer , (tmp2.BaseDllName.Length+1)*2));
				if (mod.modulePath->GetLength() == 0)
				{
					mod.moduleMD5 = new cString("");
					continue;
				}
				cFile* ModuleFile = new cFile(mod.modulePath->GetChar());
				cMD5String* MD5 = new cMD5String();
				mod.moduleMD5 = new cString(MD5->Encrypt((char*)ModuleFile->BaseAddress,ModuleFile->FileLength));
				delete ModuleFile;
				if (mod.moduleImageBase != 0)
				{
					modulesList.AddItem((char*)&mod);		
				}
			}
				
		}while(myFlag != tmp2.DllBase);
		
	}
	GetMemoryMap();
	RefreshThreads();

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

//in all cases .. it return a pointer to a place in memory ... that's to avoid bugs ... but it should return null if it can\t find the address
DWORD cProcess::Read(DWORD startAddress,DWORD size)
{
	LPVOID buffer;
	DWORD bytesRead;
	buffer = (LPVOID)malloc(size+1024);
	memset(buffer , 0 , size+1024);
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
	DWORD threadId = NULL;
	
	
	remoteAddress = Allocate(NULL ,(DWORD)strlen((char*) DLLFilename));

	HMODULE handleToKernel32 = GetModuleHandle("KERNEL32");

	if (Write(remoteAddress , (DWORD)DLLFilename.GetChar() ,(DWORD)strlen( (char*) DLLFilename)))
	{
		CreateRemoteThread((HANDLE)procHandle ,NULL , 0 , ( LPTHREAD_START_ROUTINE)GetProcAddress(handleToKernel32 , "LoadLibraryA") , (LPVOID)remoteAddress , 0 , & threadId);
	
	}
	
	return threadId;
	

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
		}
	}
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

	return 0;
}


MemoryDump::MemoryDump(cProcess* Process,bool DumpFullMemory)
{
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

		if (DumpFullMemory == false)Filename = " ";		//this means no File (Don't dump the memory into file .. just the process info)
		char* Address = (char*)Process->Read(MemMap->Address,MemMap->Size);
		if (Address == NULL)continue;
		MemoryMap[i] = new MemoryRegion(Address,MemMap->Size,MemMap->Address,Filename);
	}
}

MemoryDump::MemoryDump()
{
	Process = NULL;
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
		XMLParams.AddText("moduleName",*mod->moduleName);
		XMLParams.AddText("modulePath",*mod->modulePath);
		XMLParams.AddText("moduleMD5",*mod->moduleMD5);
		XMLParams.AddText("moduleImageBase",mod->moduleImageBase);
		XMLParams.AddText("moduleSizeOfImage",mod->moduleSizeOfImage);
	}
	//Saving Memory Regions
	CreateDirectory((LPCSTR)Process->processName,NULL);
	for (DWORD i = 0; i < nMemoryRegions; i++)
	{
		XMLParams.AddItem("MemoryRegion",MemoryMap[i]->Serialize());
	}
	cout << "Finished\n";
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
	for (DWORD i = 0; i < XMLParams.GetNumberOfItems("moduleName"); i++)
	{
		MODULE_INFO mod;

		mod.moduleName = new cString(XMLParams.GetText("moduleName",i));
		mod.modulePath = new cString(XMLParams.GetText("modulePath",i));
		mod.moduleMD5 = new cString(XMLParams.GetText("moduleMD5",i));
		mod.moduleImageBase = atoi(XMLParams.GetText("moduleImageBase",i));
		mod.moduleSizeOfImage = atoi(XMLParams.GetText("moduleSizeOfImage",i));
		modulesList->AddItem((char*)&mod);
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

MemoryRegion::MemoryRegion(char* buffer, DWORD size, DWORD RealAddress,cString filename)
{
	Buffer = buffer;
	Size = size;
	Address = RealAddress;
	Filename = filename;
	IsFound = true;
}

MemoryRegion::MemoryRegion()
{
	Buffer = NULL;
	Size = 0;
	IsFound = true;
}

void MemoryRegion::SetSerialize(cXMLHash& XMLParams)
{
	XMLParams.AddText("Address",Address);
	XMLParams.AddText("Size",Size);
	XMLParams.AddText("Filename",Filename);
	
	if (Filename == cString(" ")) return;
	cFileToWrite* MemoryRegionFile = new cFileToWrite(Filename,false);
	MemoryRegionFile->write(Buffer,Size);
	delete MemoryRegionFile;
}

void MemoryRegion::GetSerialize(cXMLHash& XMLParams)
{
	Address = atoi(XMLParams["Address"]);
	Size = atoi(XMLParams["Size"]);
	Filename = XMLParams["Filename"];
	if (Filename == cString(" ")) return;

	cFile* File = new cFile(Filename);
	if (File->IsFound() == false)
	{
		IsFound = false;
		return;
	}
	Buffer = (char*)File->BaseAddress;
	cout << Filename << " Base Address: " << (int*)File->BaseAddress << "\n";
	if (Size != File->FileLength) IsFound = false;
	else IsFound = true;
}
