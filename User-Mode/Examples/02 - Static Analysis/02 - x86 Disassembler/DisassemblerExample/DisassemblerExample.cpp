// DisassemblerExample.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../../../SRDF.h"
#include <iostream>

using namespace Security::Libraries::Malware::Static;

using namespace std;
int _tmain(int argc, _TCHAR* argv[])
{
	
	//------------------------------------------------------------------------
	//Assembling an Instruction

	CPokasAsm* Asm = new CPokasAsm();
	DWORD InsLength = 0;
	char* insstr;
	insstr = Asm->Assemble("mov eax,dword ptr [ecx+ 00401000h]",InsLength);
	

	cout << "Assembling Instruction : mov eax,dword ptr [ecx+ 00401000h]\n\n"; 
	for (DWORD i = 0;i < InsLength; i++)
	{
		cout << (int*)insstr[i] << " ";
	}
	cout << "\n\n";

	//------------------------------------------------------------------------
	//Disassembling an Instruction into mnemonics 

	cout << "Disassembling the same Instruction Again\n\n";
	cout << Asm->Disassemble(insstr,InsLength) << " ... and the instruction length : " << InsLength << "\n\n";

	DISASM_INSTRUCTION ins;
	Asm->Disassemble(insstr,&ins);


	//------------------------------------------------------------------------
	//Disassembling an Instruction into undersandable struct

	cout << "-*-*-*-*- Disassembling Instruction : " << insstr << " -*-*-*-*-\n";

    if (ins.flags & NO_SRCDEST)cout << "Shape : op\n";
    else if (ins.flags & SRC_NOSRC)cout << "Shape : op dest\n";
    else cout << "Shape : op dest, src\n";
    
    cout << "Opcode : "<< *ins.opcode << "\n";
    
    if (ins.flags & DEST_RM){
        cout << "DEST : dword ptr [modrm]\nThe ModRM : \n";
        for (int i = 0; i < ins.modrm.length;i++)
		{
			cout << "The Item No."<< i << " : ";
			if (ins.modrm.flags[i] & RM_REG)
			{
				cout << "Register ";
				if (ins.modrm.flags[i] & RM_MUL2)cout << "Multiplied (*) by 2 ";
				if (ins.modrm.flags[i] & RM_MUL4)cout << "Multiplied (*) by 4 ";
				if (ins.modrm.flags[i] & RM_MUL8)cout << "Multiplied (*) by 8 ";  
				cout << "and the Register is No." << ins.modrm.items[i] << "\n";
			}
			else if(ins.modrm.flags[i] & RM_DISP) 
			{
				if(ins.modrm.flags[i] & RM_DISP8)cout << "Displacement with Size 8 bytes ";
				if(ins.modrm.flags[i] & RM_DISP16)cout << "Displacement with Size 8 bytes ";
				if(ins.modrm.flags[i] & RM_DISP32)cout << "Displacement with Size 8 bytes ";
				cout << "and the displacement is equal to" << (int*)ins.modrm.items[i] << "\n";
			}
        }
    }
	else if (ins.flags & DEST_REG)
		cout << "DEST : Register and its No." << ins.ndest << "\n";
	
    else cout << "DEST : Immediate and equal to " << ins.ndest << "\n";

    if (!(ins.flags & SRC_NOSRC))
	{
        if (ins.flags & SRC_RM)
		{
			cout << "SRC : dword ptr [modrm]\nThe ModRM : \n";
			for (int i = 0; i < ins.modrm.length;i++)
			{
				cout << "The Item No."<< i << " : ";
				if (ins.modrm.flags[i] & RM_REG)
				{
					cout << "Register ";
					if (ins.modrm.flags[i] & RM_MUL2)cout << "Multiplied (*) by 2 ";
					if (ins.modrm.flags[i] & RM_MUL4)cout << "Multiplied (*) by 4 ";
					if (ins.modrm.flags[i] & RM_MUL8)cout << "Multiplied (*) by 8 ";  
					cout << "and the Register is No." << ins.modrm.items[i] << "\n";
				}
				else if(ins.modrm.flags[i] & RM_DISP) 
				{
					if(ins.modrm.flags[i] & RM_DISP8)cout << "Displacement with Size 8 bytes ";
					if(ins.modrm.flags[i] & RM_DISP16)cout << "Displacement with Size 8 bytes ";
					if(ins.modrm.flags[i] & RM_DISP32)cout << "Displacement with Size 8 bytes ";
					cout << "and the displacement is equal to " << (int*)ins.modrm.items[i] << "\n";
				}
			}
        }
		else if (ins.flags & SRC_REG)cout << "SRC : Register and its No." << ins.nsrc << "\n";
        else cout << "SRC : Immediate and equal to " << ins.nsrc << "\n";
    }
	return 0;
}

