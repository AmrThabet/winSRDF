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


using namespace std;
using namespace Security::Targets;

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
	char* x = (char*)unicodeString_;
	char *y;

	y = (char *)malloc(stringLength/2);
	memset(y , 0 , stringLength/2);				
	for (int i=0 ; i<stringLength ; i+=2)
	{

		y[i/2]=x[i];
		
	}
	//cout << x <<endl << y<<endl;
	cString ansiString(y);
	//cout << ansiString  <<endl;

	return ansiString;
	
}

cProcess::cProcess(int processId)
{
	ProcessId = processId;
	if(sm_EnableTokenPrivilege() == TRUE)
	{

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

				//procHandle = (DWORD)OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,FALSE,DWORD(processId)); // setting process handle
				procHandle = (DWORD)OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(processId)); // setting process handle
				if (procHandle != NULL)
				{

					__PROCESS_BASIC_INFORMATION pbi;
					DWORD data_length = 0;

					(ProcAdd)((HANDLE)procHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &data_length);
					ppeb = (__PEB*)pbi.PebBaseAddress;  // setting PEB address		
					ParentID = pbi.InheritedFromUniqueProcessId;
					AnalyzeProcess();
					isFound = true;
				}
	       
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

	if(ppeb != NULL)
	{
		// setting process ImageBase
		processName = "";
		ReadProcessMemory((HANDLE)procHandle,&(ppeb->ImageBaseAddress),&ImageBase,sizeof(ImageBase),NULL);

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

		_PEB_LDR_DATA *tmp1=NULL;
		_LDR_DATA_TABLE_ENTRY	tmp2;
		LPWSTR pathBuffer,nameBuffer,moduleNameBuffer,modulePathBuffer;
		DWORD bytesRead;
		DWORD myFlag;
		MODULE_INFO mod;
		modulesList =cList(sizeof(MODULE_INFO));

		ReadProcessMemory((HANDLE)procHandle,&(ppeb->LoaderData),&tmp1,sizeof(tmp1),NULL);
		if(tmp1)
		{
			ReadProcessMemory((HANDLE)procHandle,&(tmp1->InLoadOrderModuleList),&tmp2,sizeof(tmp2),&bytesRead);
			
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

					if (mod.moduleImageBase != 0)
					{
						modulesList.AddItem((char*)&mod);		
					}
				}
				
			}while(myFlag != tmp2.DllBase);
		
		}
		GetMemoryMap();
	}

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
		if (res != sizeof(mbi))
		{
			return false;
		}
 
		if (mbi.State == MEM_COMMIT)
		{
			memMap.Address = (DWORD)mbi.BaseAddress;
			memMap.Size	= (DWORD)mbi.RegionSize;
			memMap.Protection = (DWORD)mbi.AllocationProtect;
			MemoryMap.AddItem((char*)&memMap);
		}
 
		pAddress += mbi.RegionSize;
	}
 
	return true;
}


DWORD cProcess::Read(DWORD startAddress,DWORD size)
{
	LPVOID buffer;
	DWORD bytesRead;
	

	buffer = (LPVOID)malloc(size);
	memset(buffer , 0 , size);
	ReadProcessMemory((HANDLE)procHandle , (LPCVOID) startAddress ,  buffer , size , &bytesRead);
	
	unsigned char* x =(unsigned char*) buffer;
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



DWORD cProcess::DllInject(DWORD pointerToDll)
{
	DWORD remoteAddress;
	DWORD threadId = NULL;
	
	
	remoteAddress = Allocate(NULL ,(DWORD)strlen((char*) pointerToDll));

	HMODULE handleToKernel32 = GetModuleHandle("KERNEL32");

	if (Write(remoteAddress , pointerToDll ,(DWORD)strlen( (char*) pointerToDll)))
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



