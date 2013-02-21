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

//PokasAsm
//---------
class DLLIMPORT Security::Libraries::Malware::Assembly::x86::CPokasAsm
{
	DWORD PokasAsmObj;
	System*  m_objSystem;
    EnviromentVariables *m_objEnvVar;
public:
	CPokasAsm();
	~CPokasAsm();
	char* Assemble(char* InstructionString, DWORD &Length);
	char* Assemble(DISASM_INSTRUCTION* ins, DWORD &Length);
	char* Disassemble(char* Buffer, DWORD &InstructionLength);
	DISASM_INSTRUCTION* Disassemble(char* Buffer,DISASM_INSTRUCTION* ins);
};


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

class DLLIMPORT Security::Libraries::Malware::OS::Win32::Dynamic::CPokasEmu
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
	   DWORD GetRealAddr(DWORD vAddr);
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
	   DWORD GetImagebase();
	   cString GetDisassembly(char* ptr,DWORD &InsLength);
	   DWORD DefineDLL(char* DLLName,char* DLLPath, DWORD VirtualAddress);	//The Desired Virtual Address
	   DWORD DefineAPI(DWORD DLLBase,char* APIName,int nArgs,DWORD APIFunc);
};


class DLLIMPORT Security::Libraries::Malware::OS::Win32::Enumeration::cRecursiveScanner
{
	DWORD Level;
	WIN32_FIND_DATA file_data;
	void FindFiles(cString wrkdir);
public:
	int nDirectories;
	int nFiles;
	cRecursiveScanner();
	cHash* GetDrives();
	void Scan(cString DirectoryName);
	~cRecursiveScanner();
	virtual bool DirectoryCallback(cString DirName,cString FullName,int Level);
	virtual void FileCallback(cString Filename,cString FullName,int Level);
};

class DLLIMPORT Security::Libraries::Malware::OS::Win32::Enumeration::cProcessScanner
{
	bool isSuccess;
public:
	cHash ProcessList;
	bool IsSuccess();
	cProcessScanner(Security::Storage::Files::cLog* logObj = NULL);
};

//#define DBG_STOP		0
//#define DBG_CONTINUE	1

#define DBG_BP_TYPE_CODE		0 
#define DBG_BP_TYPE_READWRITE	1
#define DBG_BP_TYPE_WRITE		3

#define DBG_BP_SIZE_1			0
#define DBG_BP_SIZE_2			1
#define DBG_BP_SIZE_4			3

#define DBG_STATUS_STEP				4
#define DBG_STATUS_HARDWARE_BP		3
#define DBG_STATUS_MEM_BREAKPOINT	2
#define DBG_STATUS_BREAKPOINT		1
#define DBG_STATUS_EXITPROCESS		0
#define DBG_STATUS_ERROR			-1
#define DBG_STATUS_INTERNAL_ERROR	-2

struct DBG_BREAKPOINT
{
	DWORD Address;
	DWORD UserData;
	BYTE  OriginalByte;
	BOOL  IsActive;
	WORD  wReserved;
};

struct DBG_HARDWARE_BREAKPOINT
{
	DWORD Address;
	DWORD UserData;
	DWORD Type;
	DWORD Size;
};

struct DBG_MEMORY_BREAKPOINT
{
	DWORD Address;
	DWORD UserData;
	DWORD OldProtection;
	DWORD NewProtection;
	DWORD Size;
	BOOL IsActive;
	CHAR cReserved;				//they are written for padding
	WORD wReserved;
};

class DLLIMPORT Security::Libraries::Malware::OS::Win32::Dynamic::cDebugger
{
protected:
	Security::Storage::Files::cLog* Log;
	BOOL bContinueDebugging;
	cString Filename;
	cString Commandline;
	cList* Breakpoints;
	cList* MemoryBreakpoints;
	DBG_HARDWARE_BREAKPOINT HardwareBreakpoints[4];
	
	void RefreshRegisters();		//Get The Registers from the context
			//Save the updates of the registers to the context
	void RefreshDebugRegisters();
public:
	BOOL IsDebugging;
	Security::Targets::Memory::cProcess* DebuggeeProcess;
	Security::Targets::Files::cPEFile* DebuggeePE;
	DEBUG_EVENT debug_event;
	DWORD Reg[8];
	DWORD EFlags;
	DWORD Eip;
	DWORD DebugStatus;
	DWORD ProcessId;
	DWORD ThreadId;
	DWORD hThread;
	DWORD hProcess;
	DWORD ExceptionCode;
	DWORD LastBreakpoint;
	DWORD LastMemoryBreakpoint;

	//Functions
	void UpdateRegisters();	
	cDebugger(cString Filename, cString Commandline = cString(""));
	cDebugger(Security::Targets::Memory::cProcess* Process);
	int Run();
	int Step();
	void Pause();
	void Resume();
	void Terminate();
	void Exit();
	DBG_BREAKPOINT* GetBreakpoint(DWORD Address);		// returns the index of this breakpoint in the list
	BOOL SetBreakpoint(DWORD Address);
	void RemoveBreakpoint(DWORD Address);
	BOOL SetHardwareBreakpoint(DWORD Address,DWORD Type, int Size);
	void RemoveHardwareBreakpoint(DWORD Address);
	DBG_MEMORY_BREAKPOINT* GetMemoryBreakpoint(DWORD Address);
	BOOL SetMemoryBreakpoint(DWORD Address,DWORD Size, DWORD Type);		//usually Size is multiply of 0x1000
	void RemoveMemoryBreakpoint(DWORD Address);
	~cDebugger();

	virtual void DLLLoadedNotifyRoutine(){};
	virtual void DLLUnloadedNotifyRoutine(){};
	virtual void ThreadCreatedNotifyRoutine(){};
	virtual void ThreadExitNotifyRoutine(){};
	virtual void ProcessExitNotifyRoutine(){};
};

class DLLIMPORT Security::Libraries::Malware::OS::Win32::Static::SSDeep
{
	int count;
public:
	static const int Max_Result = 116;
	SSDeep(void);
	~SSDeep(void);
	static int Compare(const char *sig1, const char *sig2);
	cString Hash(const unsigned char *buf,  DWORD  buf_len);
	cString Hash(const char * filename);
};

class DLLIMPORT Security::Libraries::Malware::OS::Win32::Behavioral::cAPIHook
{
public:

	static const int  SIZE = 6;

	BYTE oldBytes[SIZE] ; 
	BYTE JMP[SIZE];	
	DWORD oldProtect, myProtect; 
	char debugBuffer[128]; 
	DWORD pOrigMBAddress;
	DWORD pNewFunc;

	cAPIHook( DWORD pOrigMBAddress , DWORD pNewFunc);
	BYTE* myHook();
	void myUnHook();

};