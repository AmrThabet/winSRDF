#include "Disassembler.h"

using namespace Security::Elements::String;
//PokasEmu
//---------
DWORD typedef (*PokasEmuConstructor)(char *szFileName,char* DLLPath);
VOID typedef (*PokasEmuDestructor)(DWORD CPokasEmuObj);
int typedef (*CPokasEmu_Emulate)(DWORD CPokasEmuObj);
int typedef (*CPokasEmu_SetBreakpoint1)(DWORD CPokasEmuObj,char* Breakpoint);
int typedef (*CPokasEmu_SetBreakpoint2)(DWORD CPokasEmuObj,char* FuncName ,DWORD BreakpointFunc);
VOID typedef (*CPokasEmu_DisableBreakpoint)(DWORD CPokasEmuObj,int index);
int typedef (*CPokasEmu_GetNumberOfMemoryPages)(DWORD CPokasEmuObj);
DWORD typedef (*CPokasEmu_GetMemoryPage)(DWORD CPokasEmuObj,int index);
DWORD typedef (*CPokasEmu_GetMemoryPageByVA)(DWORD CPokasEmuObj,DWORD vAddr);
int typedef (*CPokasEmu_GetNumberOfDirtyPages)(DWORD CPokasEmuObj);
DWORD typedef (*CPokasEmu_GetDirtyPage)(DWORD CPokasEmuObj,int index);
VOID typedef (*CPokasEmu_ClearDirtyPages)(DWORD CPokasEmuObj);
int typedef (*CPokasEmu_MakeDumpFile)(DWORD CPokasEmuObj, char* OutputFile, int ImportFixType);
DWORD typedef (*CPokasEmu_GetReg)(DWORD CPokasEmuObj,int index);
DWORD typedef (*CPokasEmu_GetEip)(DWORD CPokasEmuObj);
DWORD typedef (*CPokasEmu_GetImagebase)(DWORD CPokasEmuObj);
int typedef (*CPokasEmu_GetDisassembly)(DWORD CPokasEmuObj,char* ptr, char *OutputString);
DWORD typedef (*CPokasEmu_GetRealAddr)(DWORD CPokasEmuObj,DWORD vAddr);

#define DUMP_ZEROIMPORTTABLE    0
#define DUMP_FIXIMPORTTABLE     1
#define DUMP_UNLOADIMPORTTABLE  2

#ifndef MEM_READWRITE

#define MEM_READWRITE           0
#define MEM_READONLY            1
#define MEM_IMAGEBASE           2             //mixing readonly & readwrite so it needs to be check
#define MEM_DLLBASE             3
#define MEM_VIRTUALPROTECT      4

#endif
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
	DWORD PokasEmuObj;
	PokasEmuConstructor PokasEmuConstructorFunc;
	PokasEmuDestructor	PokasEmuDestructorFunc;
	CPokasEmu_Emulate  CPokasEmu_EmulateFunc;
	CPokasEmu_SetBreakpoint1 CPokasEmu_SetBreakpoint1Func;
	CPokasEmu_SetBreakpoint2 CPokasEmu_SetBreakpoint2Func;
	CPokasEmu_DisableBreakpoint CPokasEmu_DisableBreakpointFunc;
	CPokasEmu_GetNumberOfMemoryPages CPokasEmu_GetNumberOfMemoryPagesFunc;
	CPokasEmu_GetMemoryPage CPokasEmu_GetMemoryPageFunc;
	CPokasEmu_GetMemoryPageByVA CPokasEmu_GetMemoryPageByVAFunc;
	CPokasEmu_GetNumberOfDirtyPages CPokasEmu_GetNumberOfDirtyPagesFunc;
	CPokasEmu_GetDirtyPage CPokasEmu_GetDirtyPageFunc;
	CPokasEmu_ClearDirtyPages CPokasEmu_ClearDirtyPagesFunc;
	CPokasEmu_MakeDumpFile CPokasEmu_MakeDumpFileFunc;
	CPokasEmu_GetReg CPokasEmu_GetRegFunc;
	CPokasEmu_GetEip CPokasEmu_GetEipFunc;
	CPokasEmu_GetImagebase CPokasEmu_GetImagebaseFunc;
	CPokasEmu_GetDisassembly CPokasEmu_GetDisassemblyFunc;
	CPokasEmu_GetRealAddr CPokasEmu_GetRealAddrFunc;

public:
       CPokasEmu(char *szFileName,char* DLLPath);
       ~CPokasEmu();
       int Emulate();
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
	   DWORD GetRealAddr(DWORD vAddr);
	   DWORD GetImagebase();
	   int GetDisassembly(char* ptr, char* OutputString);
};
//------------------------------------------------------------------------

DWORD typedef (*PokasAsmConstructor)(char* DLLPath);
VOID typedef (*PokasAsmDestructor)(DWORD CPokasAsmObj);
DWORD typedef (*CPokasAsm_Assemble)(DWORD CPokasAsmObj, char* InstructionString, DWORD &Length);
DWORD typedef (*CPokasAsm_Disassemble)(DWORD CPokasAsmObj, char* Buffer, DWORD &InstructionLength);
DWORD typedef (*CPokasAsm_Disassemble2)(DWORD CPokasAsmObj,char* Buffer,DISASM_INSTRUCTION* ins);

class DLLIMPORT Security::Libraries::Malware::Assembly::x86::CPokasAsm
{
	DWORD PokasAsmObj;
	PokasAsmConstructor PokasAsmConstructorFunc;
	PokasAsmDestructor	PokasAsmDestructorFunc;
	CPokasAsm_Assemble	CPokasAsm_AssembleFunc;
	CPokasAsm_Disassemble CPokasAsm_DisassembleFunc;
	CPokasAsm_Disassemble2 CPokasAsm_Disassemble2Func;
public:
	CPokasAsm(char* DLLPath);
	~CPokasAsm();
	char* Assemble(char* InstructionString, DWORD &Length);
	char* Disassemble(char* Buffer, DWORD &InstructionLength);
	DISASM_INSTRUCTION* Disassemble(char* Buffer,DISASM_INSTRUCTION* ins);
};


class DLLIMPORT Security::Libraries::Malware::OS::Win32::Scanning::cRecursiveScanner
{
	WIN32_FIND_DATA file_data;
public:
	int nDirectories;
	int nFiles;
	cRecursiveScanner();
	cHash* GetDrives();
	void Scan(cString DirectoryName);
	~cRecursiveScanner();
	void FindFiles(cString wrkdir);
	virtual bool DirectoryCallback(cString DirName);
	virtual void FileCallback(cString Filename,cString FullName);
};