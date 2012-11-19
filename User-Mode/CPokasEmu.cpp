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
#include "SRDF.h"
#include <stdio.h>
#include <math.h>
#include <iostream>


using namespace Security::Libraries::Malware::OS::Win32::Emulation;
using namespace Security::Targets::Files;
using namespace std;
 
CPokasEmu::CPokasEmu(char *szFileName,char* DLLPath)
{
	 m_szFileName = szFileName;
	 process = NULL;
	 m_objSystem = NULL;
	 m_objEnvVar = NULL;
	 m_objEnvVar = (EnviromentVariables*)malloc(sizeof(EnviromentVariables)); 
	 memset( m_objEnvVar,0,sizeof(EnviromentVariables));
	 m_objEnvVar->dllspath=DLLPath; 
	 m_objEnvVar->kernel32=(DWORD)LoadLibraryA("kernel32.dll");
	 m_objEnvVar->user32=(DWORD)LoadLibraryA("user32.dll");
	 m_objEnvVar->MaxIterations=10000000;  
	 m_objSystem = new System(m_objEnvVar);
     process = new Process(m_objSystem,szFileName);
}

CPokasEmu::CPokasEmu(cPEFile* PEFile,char* DLLPath)
{
	m_szFileName = NULL;
     process = NULL;
     m_objEnvVar = NULL;
     m_objEnvVar = (EnviromentVariables*)malloc(sizeof(EnviromentVariables)); 
     memset( m_objEnvVar,0,sizeof(EnviromentVariables));
     m_objEnvVar->dllspath=DLLPath; 
     m_objEnvVar->kernel32=(DWORD)LoadLibraryA("kernel32.dll");
     m_objEnvVar->user32=(DWORD)LoadLibraryA("user32.dll");
	 m_objEnvVar->MaxIterations=10000000;  
	 m_objSystem = new System(m_objEnvVar);
     process = new Process(m_objSystem,(char*)PEFile->BaseAddress,PEFile->FileLength,PROCESS_UNLOADEDIMAGE);
}
CPokasEmu::CPokasEmu(char *buff,int size,int ImageType,char* DLLPath)
{
	 m_szFileName = NULL;
     process = NULL;
     m_objEnvVar = NULL;
     m_objEnvVar = (EnviromentVariables*)malloc(sizeof(EnviromentVariables)); 
     memset( m_objEnvVar,0,sizeof(EnviromentVariables));
     m_objEnvVar->dllspath=DLLPath; 
     m_objEnvVar->kernel32=(DWORD)LoadLibraryA("kernel32.dll");
     m_objEnvVar->user32=(DWORD)LoadLibraryA("user32.dll");
	 m_objEnvVar->MaxIterations=10000000;  
	 m_objSystem = new System(m_objEnvVar);
     process = new Process(m_objSystem,buff,size,ImageType);
}

CPokasEmu::~CPokasEmu()
{
      m_szFileName = NULL;
      nSystemObjUses--;
      if (nSystemObjUses == 0)
      {
          delete m_objSystem;
          m_objSystem = NULL;
      }
}

int CPokasEmu::Emulate()
{ 
	process->MaxIterations = 1000000;
	return process->emulate("C:\\EmuFile.txt");
}

int CPokasEmu::Step()
{
	return process->emulatecommand();
}
//Breakpoints:
//------------

int CPokasEmu::SetBreakpoint(char* Breakpoint)
{
    	return process->debugger->AddBp(Breakpoint);
}

int  CPokasEmu::SetBreakpoint(char* FuncName ,DWORD BreakpointFunc)
{
        char* buffer = (char*)malloc(strlen(FuncName)+11);
        memset(buffer,0,strlen(FuncName)+11);
        _snprintf(buffer,10+strlen(FuncName),"__%s()",FuncName);
    	process->debugger->define_func(FuncName,0,BreakpointFunc,0);
    	return process->debugger->AddBp(buffer);
}

VOID CPokasEmu::DisableBreakpoint(int index)
{
     process->debugger->RemoveBp(index);
}


//Memory Functions:
//-----------------

int CPokasEmu::GetNumberOfMemoryPages()
{
    return process->SharedMem->vmem_length;
}
MEMORY_STRUCT* CPokasEmu::GetMemoryPage(int index)
{
      return (MEMORY_STRUCT*)process->SharedMem->vmem[index];
}
MEMORY_STRUCT* CPokasEmu::GetMemoryPageByVA(DWORD vAddr)
{
      for (int i = 0; i < process->SharedMem->vmem_length; i++)
      {
		  if (vAddr >= process->SharedMem->vmem[i]->vmem && vAddr < (process->SharedMem->vmem[i]->vmem + process->SharedMem->vmem[i]->size))
			  return (MEMORY_STRUCT*)process->SharedMem->vmem[i];
      }
      return NULL;   
}

DWORD CPokasEmu::GetRealAddr(DWORD vAddr)
{
    for (int i = 0; i < process->SharedMem->vmem_length; i++)
    {
        if (vAddr >= process->SharedMem->vmem[i]->vmem && vAddr < (process->SharedMem->vmem[i]->vmem + process->SharedMem->vmem[i]->size))
                  return process->SharedMem->vmem[i]->rmem + (vAddr - process->SharedMem->vmem[i]->vmem);
    }
	return NULL;
}
int CPokasEmu::GetNumberOfDirtyPages()
{
    return process->SharedMem->cmem_length;
}
DIRTYPAGES_STRUCT* CPokasEmu::GetDirtyPage(int index)
{
    return (DIRTYPAGES_STRUCT*)process->SharedMem->cmem[index];               
}
VOID CPokasEmu::ClearDirtyPages()
{
  process->SharedMem->cmem_length = 0;   
}
int CPokasEmu::MakeDumpFile(char* OutputFile, int ImportFixType)
{
	if (ImportFixType == DUMP_ZEROIMPORTTABLE)
	{
		ZeroImportTable(process);
	}
	else if (ImportFixType == DUMP_UNLOADIMPORTTABLE)
	{
		UnloadImportTable(process);
	}
	else if (ImportFixType == DUMP_FIXIMPORTTABLE)
	{
		ReconstructImportTable(process);
	}
    return PEDump(process->GetThread(0)->Eip,process,OutputFile);
}

//Working With Registers:
//-----------------------
DWORD CPokasEmu::GetReg(int index)
{
    return process->GetThread(0)->Exx[index];
}

DWORD CPokasEmu::GetEip()
{
  return process->GetThread(0)->Eip;  
}

DWORD CPokasEmu::GetEFLAGS()
{
  return process->GetThread(0)->EFlags;  
}

void CPokasEmu::SetReg(int index,DWORD value)
{
	process->GetThread(0)->Exx[index] = value;
}

void CPokasEmu::SetEip(DWORD value)
{
	process->GetThread(0)->EFlags = value;
}

void CPokasEmu::SetEFLAGS(DWORD value)
{
	process->GetThread(0)->Eip = value;
}

DWORD CPokasEmu::GetTIB()
{
	return process->GetThread(0)->GetFS();
}

DWORD CPokasEmu::GetImagebase()
{
    return process->GetImagebase();
}

//Disassembling:
//-------------
cString CPokasEmu::GetDisassembly(char* ptr,DWORD &InsLength)
{
    string strInst;
    DISASM_INSTRUCTION ins;
	memset(&ins,0,sizeof(DISASM_INSTRUCTION));
    char* byBuffer = (char*)process->SharedMem->read_virtual_mem((DWORD)ptr);
    m_objSystem->disasm(&ins, byBuffer, strInst);
    InsLength = (DWORD)ins.hde.len;
    return strInst.c_str();
}

//Working with APIs:
//------------------
DWORD CPokasEmu::DefineDLL(char* DLLName,char* DLLPath, DWORD VirtualAddress)
{
	int DLLIndex = m_objSystem->define_dll(DLLName,DLLPath,VirtualAddress);
	return m_objSystem->DLLs[DLLIndex].vAddr;
}

#define API_INTERNAL_FUNC int (*)(Thread *, DWORD *)

DWORD CPokasEmu::DefineAPI(DWORD DLLBase,char* APIName,int nArgs,DWORD APIFunc)
{
	int DLLIndex = 0;
	for (int i = 0;i< m_objSystem->dll_entries;i++)
	{
		if (DLLBase == m_objSystem->DLLs[i].vAddr)
		{
			DLLIndex = i;
			goto DLL_FOUND;
		}
	}
	return 0;

DLL_FOUND:
	int APIIndex = m_objSystem->define_api(APIName,&m_objSystem->DLLs[DLLIndex],nArgs,(API_INTERNAL_FUNC)APIFunc);
	return m_objSystem->APITable[APIIndex].addr;
}