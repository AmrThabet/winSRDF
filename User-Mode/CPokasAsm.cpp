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
using namespace Security::Libraries::Malware::Static;
using namespace std;

#ifdef USE_POKAS_EMULATOR

CPokasAsm::CPokasAsm()
{
	 m_objSystem = new System();
}

CPokasAsm::~CPokasAsm()
{
      delete m_objSystem;
      m_objSystem = NULL;
}

char* CPokasAsm::Disassemble(char* Buffer,DWORD &InstructionLength)
{
    string strInst = "";
    DISASM_INSTRUCTION* ins;
    ins = (DISASM_INSTRUCTION*)malloc(sizeof(DISASM_INSTRUCTION)+1);
    ins = m_objSystem->disasm(ins, Buffer,strInst);
    char* cIns = (char*)malloc(strInst.length()+2);
    memset(cIns,0,strInst.length()+1);
    memcpy(cIns, strInst.c_str(), strInst.length());
    InstructionLength = (DWORD)ins->hde.len;
    free(ins);
    return cIns;
};

DISASM_INSTRUCTION* CPokasAsm::Disassemble(char* Buffer,DISASM_INSTRUCTION* ins)
{
    ins = m_objSystem->disasm(ins, Buffer);
    return ins;
};

char* CPokasAsm::Assemble(char* InstructionString, DWORD &Length)
{
      std::string s = InstructionString;
      bytes* Data = m_objSystem->assembl(InstructionString);
      Length = Data->length;
      return (char*)Data->s;
}
char* CPokasAsm::Assemble(DISASM_INSTRUCTION* ins, DWORD &Length)
{
    bytes* Data = m_objSystem->assembl(ins);
    Length = Data->length;
    return (char*)Data->s;
}
#endif