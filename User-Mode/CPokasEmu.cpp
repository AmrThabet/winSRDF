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
#include <iostream>

using namespace Security::Libraries::Malware::OS::Win32::Emulation;
using namespace std;
HMODULE PokasEmuDLL;


CPokasEmu::CPokasEmu(char *szFileName,char* DLLPath)
{
      PokasEmuDLL = LoadLibrary("Emulator.dll");
	  if (PokasEmuDLL == NULL)return;
	  PokasEmuConstructorFunc = (PokasEmuConstructor)GetProcAddress(PokasEmuDLL,"_Z20CPokasEmuConstructorPcS_");
	  PokasEmuDestructorFunc = (PokasEmuDestructor)GetProcAddress(PokasEmuDLL,"_Z19CPokasEmuDestructorP9CPokasEmu"); 
	  CPokasEmu_EmulateFunc = (CPokasEmu_Emulate)GetProcAddress(PokasEmuDLL,"_Z7EmulateP9CPokasEmu"); 
	  CPokasEmu_SetBreakpoint1Func = (CPokasEmu_SetBreakpoint1)GetProcAddress(PokasEmuDLL,"_Z13SetBreakpointP9CPokasEmuPc"); 
	  CPokasEmu_SetBreakpoint2Func = (CPokasEmu_SetBreakpoint2)GetProcAddress(PokasEmuDLL,"_Z13SetBreakpointP9CPokasEmuPcm"); 
	  CPokasEmu_DisableBreakpointFunc = (CPokasEmu_DisableBreakpoint)GetProcAddress(PokasEmuDLL,"_ZN9CPokasEmu17DisableBreakpointEi "); 
	  CPokasEmu_GetNumberOfMemoryPagesFunc = (CPokasEmu_GetNumberOfMemoryPages)GetProcAddress(PokasEmuDLL,"_Z22GetNumberOfMemoryPagesP9CPokasEmu"); 
	  CPokasEmu_GetMemoryPageFunc = (CPokasEmu_GetMemoryPage)GetProcAddress(PokasEmuDLL,"_ZN9CPokasEmu13GetMemoryPageEi"); 
	  CPokasEmu_GetMemoryPageByVAFunc = (CPokasEmu_GetMemoryPageByVA)GetProcAddress(PokasEmuDLL,"_Z17GetMemoryPageByVAP9CPokasEmum"); 
	  CPokasEmu_GetRealAddrFunc = (CPokasEmu_GetRealAddr)GetProcAddress(PokasEmuDLL,"_Z11GetRealAddrP9CPokasEmum"); 
	  CPokasEmu_GetNumberOfDirtyPagesFunc = (CPokasEmu_GetNumberOfDirtyPages)GetProcAddress(PokasEmuDLL,"_Z21GetNumberOfDirtyPagesP9CPokasEmu"); 
	  CPokasEmu_GetDirtyPageFunc = (CPokasEmu_GetDirtyPage)GetProcAddress(PokasEmuDLL,"_Z12GetDirtyPageP9CPokasEmui"); 
	  CPokasEmu_ClearDirtyPagesFunc = (CPokasEmu_ClearDirtyPages)GetProcAddress(PokasEmuDLL,"_Z15ClearDirtyPagesP9CPokasEmu");
	  CPokasEmu_MakeDumpFileFunc = (CPokasEmu_MakeDumpFile)GetProcAddress(PokasEmuDLL,"_Z12MakeDumpFileP9CPokasEmuPci");
	  CPokasEmu_GetRegFunc = (CPokasEmu_GetReg)GetProcAddress(PokasEmuDLL,"_Z6GetRegP9CPokasEmui");
	  CPokasEmu_GetEipFunc = (CPokasEmu_GetEip)GetProcAddress(PokasEmuDLL,"_Z6GetEipP9CPokasEmu");
	  CPokasEmu_GetImagebaseFunc = (CPokasEmu_GetImagebase)GetProcAddress(PokasEmuDLL,"_Z12GetImagebaseP9CPokasEmu");
	  CPokasEmu_GetDisassemblyFunc = (CPokasEmu_GetDisassembly)GetProcAddress(PokasEmuDLL,"_Z14GetDisassemblyP9CPokasEmuPcS1_");
	  PokasEmuObj = PokasEmuConstructorFunc(szFileName,DLLPath);
}
CPokasEmu::~CPokasEmu()
{
    PokasEmuDestructorFunc(PokasEmuObj);
}

int CPokasEmu::Emulate()
{ 
	return CPokasEmu_EmulateFunc(PokasEmuObj);
	
}

//Breakpoints:
//------------

int CPokasEmu::SetBreakpoint(char* Breakpoint)
{
    return CPokasEmu_SetBreakpoint1Func(PokasEmuObj,Breakpoint);
}
int CPokasEmu::SetBreakpoint(char* FuncName ,DWORD BreakpointFunc)
{
    return CPokasEmu_SetBreakpoint2Func(PokasEmuObj,FuncName,BreakpointFunc);
}
VOID CPokasEmu::DisableBreakpoint(int index)
{
     CPokasEmu_DisableBreakpointFunc(PokasEmuObj,index);
}


//Memory Functions:
//-----------------

int CPokasEmu::GetNumberOfMemoryPages()
{
    return CPokasEmu_GetNumberOfMemoryPagesFunc(PokasEmuObj);
}
MEMORY_STRUCT* CPokasEmu::GetMemoryPage(int index)
{
      return (MEMORY_STRUCT*)CPokasEmu_GetMemoryPageFunc(PokasEmuObj,index);
}
MEMORY_STRUCT* CPokasEmu::GetMemoryPageByVA(DWORD vAddr)
{
      return (MEMORY_STRUCT*)CPokasEmu_GetMemoryPageByVAFunc(PokasEmuObj,vAddr);
}
DWORD CPokasEmu::GetRealAddr(DWORD vAddr)
{
	return CPokasEmu_GetRealAddrFunc(PokasEmuObj,vAddr);
}
int CPokasEmu::GetNumberOfDirtyPages()
{
    return CPokasEmu_GetNumberOfDirtyPagesFunc(PokasEmuObj);
}
DIRTYPAGES_STRUCT* CPokasEmu::GetDirtyPage(int index)
{
    return (DIRTYPAGES_STRUCT*)CPokasEmu_GetDirtyPageFunc(PokasEmuObj,index);
}
VOID CPokasEmu::ClearDirtyPages()
{
  return CPokasEmu_ClearDirtyPagesFunc(PokasEmuObj);
}
int CPokasEmu::MakeDumpFile(char* OutputFile, int ImportFixType)
{
	if (ImportFixType == DUMP_ZEROIMPORTTABLE)
	{
		
	}else if (ImportFixType == DUMP_FIXIMPORTTABLE)
	{
		//ReconstructImportTable(process);
	}else
	{
		//UnloadImportTable(process);
	}
    return CPokasEmu_MakeDumpFileFunc(PokasEmuObj,OutputFile,ImportFixType);
}

DWORD CPokasEmu::GetReg(int index)
{
	return CPokasEmu_GetRegFunc(PokasEmuObj,index);
}
DWORD CPokasEmu::GetEip()
{
	return CPokasEmu_GetEipFunc(PokasEmuObj);
}
DWORD CPokasEmu::GetImagebase()
{
	return CPokasEmu_GetImagebaseFunc(PokasEmuObj);
}
int CPokasEmu::GetDisassembly(char* ptr, char* OutputString)
{
	return CPokasEmu_GetDisassemblyFunc(PokasEmuObj,ptr,OutputString);
};