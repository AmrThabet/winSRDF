#include "stdafx.h"
#include "SRDF.h"
#include <iostream>
using namespace Security::Libraries::Malware::Assembly::x86;
using namespace std;

HMODULE PokasAsmDLL;


CPokasAsm::CPokasAsm(char* DLLPath)
{
      PokasAsmDLL = LoadLibrary("Emulator.dll");
	  if (PokasAsmDLL == NULL)return;
	  PokasAsmConstructorFunc = (PokasAsmConstructor)GetProcAddress(PokasAsmDLL,"_Z20CPokasAsmConstructorPc");
	  PokasAsmDestructorFunc = (PokasAsmDestructor)GetProcAddress(PokasAsmDLL,"_Z19CPokasAsmDestructorP9CPokasAsm"); 
	  CPokasAsm_AssembleFunc = (CPokasAsm_Assemble)GetProcAddress(PokasAsmDLL,"_Z8AssembleP9CPokasAsmPcRm");
	  CPokasAsm_DisassembleFunc = (CPokasAsm_Disassemble)GetProcAddress(PokasAsmDLL,"_Z11DisassembleP9CPokasAsmPcRm");
	  CPokasAsm_Disassemble2Func = (CPokasAsm_Disassemble2)GetProcAddress(PokasAsmDLL,"_Z11DisassembleP9CPokasAsmPcP10ins_disasm"); 
	  PokasAsmObj = PokasAsmConstructorFunc(DLLPath);
}
CPokasAsm::~CPokasAsm()
{
    PokasAsmDestructorFunc(PokasAsmObj);
}
char* CPokasAsm::Assemble(char* InstructionString, DWORD &Length)
{
    return (char*)CPokasAsm_AssembleFunc(PokasAsmObj,InstructionString,Length);
}
char* CPokasAsm::Disassemble(char* Buffer, DWORD &InstructionLength)
{
    return (char*)CPokasAsm_DisassembleFunc(PokasAsmObj,Buffer,InstructionLength);
}
DISASM_INSTRUCTION* CPokasAsm::Disassemble(char* Buffer,DISASM_INSTRUCTION* ins)
{
	return (DISASM_INSTRUCTION*)CPokasAsm_Disassemble2Func(PokasAsmObj,Buffer,ins);
}
/*DISASM_INSTRUCTION* CPokasAsm::Disassemble(char* Buffer, DWORD &InstructionLength)
{
    return (char*)CPokasAsm_DisassembleFunc(PokasAsmObj,Buffer,InstructionLength);
}
*/