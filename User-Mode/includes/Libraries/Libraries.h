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

#include "x86emu.h"
#include "cYaraScanner.h"
using namespace Security::Elements::String;
//PokasEmu
//---------

#define DUMP_ZEROIMPORTTABLE    0
#define DUMP_FIXIMPORTTABLE     1
#define DUMP_UNLOADIMPORTTABLE  2


struct MEMORY_STRUCT
{
       DWORD VirtualAddr;
       DWORD RealAddr;
       DWORD Size;
       DWORD Flags;
};

struct DIRTYPAGES_STRUCT         //the changes in the memory during the emulation
{                               
       DWORD vAddr;             //here the pointer to the virtual memory not the real pointer
       DWORD Size;
       DWORD Flags;
}; 

class DLLIMPORT Security::Libraries::Malware::OS::Win32::Emulation::CPokasEmu
{
	System*  m_objSystem;
     int     nSystemObjUses;
     char *m_szFileName;
     Process *process;
     EnviromentVariables *m_objEnvVar;
     int nDebuggerFunctions;

public:
       CPokasEmu(char *szFileName,char* DLLPath);
	   CPokasEmu(Security::Targets::Files::cPEFile* PEFile,char* DLLPath);
	   CPokasEmu(char *buff,int size,int ImageType,char* DLLPath);
       ~CPokasEmu();
       int Emulate();
	   int Step();
       int SetBreakpoint(char* Breakpoint);
       int SetBreakpoint(char* FuncName,DWORD BreakpointFunc);
       VOID DisableBreakpoint(int index);
       int GetNumberOfMemoryPages();
       MEMORY_STRUCT* GetMemoryPage(int index);
       MEMORY_STRUCT* GetMemoryPageByVA(DWORD vAddr);
       int GetNumberOfDirtyPages();
       DIRTYPAGES_STRUCT* GetDirtyPage(int index);
       VOID ClearDirtyPages();
       int MakeDumpFile(char* OutputFile, int ImportFixType);
	   DWORD GetReg(int index);
	   DWORD GetEip();
	   DWORD GetEFLAGS();
	   DWORD GetTIB();
	   void SetReg(int index,DWORD value);
	   void SetEip(DWORD value);
	   void SetEFLAGS(DWORD value);
	   DWORD GetRealAddr(DWORD vAddr);
	   DWORD GetImagebase();
	   int GetDisassembly(char* ptr, char* OutputString);
	   DWORD DefineDLL(char* DLLName,char* DLLPath, DWORD VirtualAddress);	//The Desired Virtual Address
	   DWORD DefineAPI(DWORD DLLBase,char* APIName,int nArgs,DWORD APIFunc);
};

class DLLIMPORT Security::Libraries::Malware::Assembly::x86::CPokasAsm
{
	DWORD PokasAsmObj;
	System*  m_objSystem;
    EnviromentVariables *m_objEnvVar;
public:
	CPokasAsm();
	~CPokasAsm();
	char* Assemble(char* InstructionString, DWORD &Length);
	char* Disassemble(char* Buffer, DWORD &InstructionLength);
	DISASM_INSTRUCTION* Disassemble(char* Buffer,DISASM_INSTRUCTION* ins);
};


class DLLIMPORT Security::Libraries::Malware::OS::Win32::Scanning::cRecursiveScanner
{
	DWORD Level;
	WIN32_FIND_DATA file_data;
public:
	int nDirectories;
	int nFiles;
	cRecursiveScanner();
	cHash* GetDrives();
	void Scan(cString DirectoryName);
	~cRecursiveScanner();
	void FindFiles(cString wrkdir);
	virtual bool DirectoryCallback(cString DirName,cString FullName,int Level);
	virtual void FileCallback(cString Filename,cString FullName,int Level);
};

class  DLLIMPORT Security::Libraries::Malware::OS::Win32::Scanning::cProcessScanner
{
	bool isSuccess;
public:
	cHash ProcessList;
	bool IsSuccess();
	cProcessScanner(Security::Storage::Files::cLog* logObj = NULL);
};