/*
 *
 *  Copyright (C) 2010-2011 Amr Thabet <amr.thabet@student.alx.edu.eg>
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
 *  amr.thabet@student.alx.edu.eg
 *
 */
// #ifndef __EMU__
 //#define __EMU__
//typedef unsigned long DWORD;
#define EXP_IGNORE 0
#define EXP_ERROR  -1
class Process;
class Log; 
class Thread;

#ifndef DWORD 
	#define DWORD unsigned long
#endif
#if BUILDING_DLL
#include "hde28c/hde32.h"
#include "disasm/disassembler.h"
#include "apis/apis.h"
#include "emu/emu.h"
#include "seh.h"
#include "os/os.h"
#include "macros.h"
#endif
//------
#include "tib.h"
#include "pe.h"
#include <iostream>
#include <string.h>

//FLAGS

#define EFLG_OF (1<<11)
#define EFLG_SF (1<<7) 
#define EFLG_ZF (1<<6)
#define EFLG_AF (1<<4)
#define EFLG_PF (1<<2)
#define EFLG_CF (1<<0)
#define EFLG_SYS (0x202)
//-------
//CUSTOM FLAGS SETTING

#define UPDATEFLAGS_CMP 1
#define UPDATEFLAGS_ADD 2
#define UPDATEFLAGS_SUB 4
//------
//MEMORY FLAGS

#define MEM_READWRITE 0
#define MEM_READONLY 1
#define MEM_IMAGEBASE 2             //mixing readonly & readwrite so it needs to be check
#define MEM_DLLBASE 3
#define MEM_VIRTUALPROTECT 4
//--------
//EXCEPTIONS

#define EXP_EXCEED_MAX_ITERATIONS 0
#define EXP_INVALIDPOINTER 1
#define EXP_WRITEACCESS_DENIED 2
#define EXP_INVALID_OPCODE 3
#define EXP_DIVID_BY_ZERO 4
#define EXP_INVALID_INSTRUCTION 5
#define EXP_DIV_OVERFLOW 6
#define EXP_BREAKPOINT 7
//--------
//PROCESS FLAGS

#define PROCESS_FILENAME		0
#define PROCESS_LOADEDIMAGE		1
#define PROCESS_UNLOADEDIMAGE	2
#define PROCESS_SHELLCODE		3


#define ERROR_FILENAME 8
using namespace std;
#ifndef DLLIMPORT
#ifdef WIN32
#if BUILDING_DLL
    # define DLLIMPORT __declspec (dllexport)
             
#else /* Not BUILDING_DLL */
    # define DLLIMPORT __declspec (dllimport)
#endif /* Not BUILDING_DLL */
 #else
    #define DLLIMPORT
  #endif
#endif
struct DISASM_INSTRUCTION;
struct bytes;
struct FLAGTABLE;
struct hde32s;
struct DLL;
struct API;
//==================================
//APIs
struct DLL{
       char* name;
       DWORD imagebase;
       DWORD size;
       DWORD vAddr;
};
struct API{
       char* name;
       DLL*  lib;
       DWORD args;
       DWORD addr;
       int (*emu_func)(Thread*,DWORD*);
};
//===================================
//Debugger 

#define NO_OF_BP_FUNCTIONS 100
#define BP_RUN 0
#define BP_PAUSE 1
#define BP_REMOVE 2
struct BPFunction{ 
           int params;
           DWORD dbg_func;
           string name;
           int flags;
};

//===================================
struct FLAGTABLE{ 
           int opcode;
           int reg;
           int (*emu_func)(Thread&,DISASM_INSTRUCTION*);
           string mnemonics;
           int flags;
           };
struct Exception{
       int Type;
       char* error;
       DWORD ptr;
       };

struct EnviromentVariables{
       DWORD date;
       DWORD time;
       DWORD kernel32;
       DWORD ntdll;
       DWORD user32;
       char* dllspath;
       DWORD MaxIterations;
       };
#define MAX_NUM_APIS_PER_DLL 200
struct Imports{
       DWORD name;
       DWORD addr;
       bool defined;
       DWORD napis;
       DWORD apis[MAX_NUM_APIS_PER_DLL];                              //Maximum Number of Apis is 300 per 1 DLL
};
class DLLIMPORT System{
      public:
          int dis_entries;
          FLAGTABLE FlagTable[512*7];
          DLL DLLs[20];
          API APITable[100];
          int dll_entries;
          int api_entries;
          EnviromentVariables enVars;
          System(EnviromentVariables* v);
		  System();								//For Disassembling only
          ~System();
          string getversion();
          string getCopyrights();
          // Assembler
          bytes* assembl(string instruction);
          DISASM_INSTRUCTION* disasm(DISASM_INSTRUCTION* bIns,char* ins_bytes);
          DISASM_INSTRUCTION* disasm(DISASM_INSTRUCTION* bIns,char* ins_bytes,string& str);
          int define_opcodes(unsigned int opcode,int reg,int (*emu_func)(Thread&,DISASM_INSTRUCTION*),string mnemonics,int flags);
          int opcodes_init();
          void init_vars(EnviromentVariables* v);
          //APIs
          int define_dll(char* name,char* path,DWORD vAddr);
          int define_api(char* name,DLL* lib,DWORD args,int (*emu_func)(Thread*,DWORD*));
          bool IsApiCall(Thread&,DISASM_INSTRUCTION*&);
          int CallToAPI(Thread*,DISASM_INSTRUCTION*);
          unsigned long GetAPI(char* func,unsigned long dll);
          char* GetAPIbyAddress(unsigned long ptr,unsigned long dll);
          unsigned long GetDllBase(char*);
          unsigned long GetDllIndex(char* s);
          char* GetTiggeredAPI(Thread& thread);
          void init_apis(char* path);
};
extern "C"
class DLLIMPORT Debugger{
protected:
    struct {
             DWORD ptr;
             int state;
      } bp[1000];
      DWORD nbp;
      Process* process;
      BPFunction funcs[NO_OF_BP_FUNCTIONS];
      int func_entries;
      DWORD parser(string);
      string lasterror;
public:
     
     virtual bool TestBp(Thread& thread,DISASM_INSTRUCTION* ins);
     virtual int AddBp(string s);
     void RemoveBp(int index);
     void PauseBp(int index);
     void ActivateBp(int index);
     int define_func(string name,int params,DWORD func,int flags);
     int init_funcs();
     Debugger(Process&);
     Debugger();
     string GetLastError();
private:
    bool TestBp(int num,Thread& thread,DISASM_INSTRUCTION* ins);
};
class DLLIMPORT AsmDebugger : public Debugger{
      DWORD parser(string);
      public:
             virtual bool TestBp(Thread& thread,DISASM_INSTRUCTION* ins);
             virtual int AddBp(string s);
             AsmDebugger(Process&);
      private:
            bool TestBp(int num,Thread& thread,DISASM_INSTRUCTION* ins);
            //expressions solvers
            DWORD boolexp(string&);
            DWORD boolexp2(string&);
            DWORD mathexp(string&);
            DWORD mulexp(string&);
            DWORD getnum(string&);
            //math
            DWORD domul(string&);
            DWORD dodiv(string&);
            DWORD doand(string&);
            DWORD domod(string&);
            DWORD doadd(string&);
            DWORD dosub(string&);
            DWORD door(string&);
            DWORD doxor(string&);
            DWORD donot(string&);
            DWORD doneg(string&);
            //boolean
            DWORD dogreaterequal(string&);
            DWORD dolowerequal(string&);
            DWORD doequal(string&);
            DWORD donotequal(string&);
            DWORD dogreater(string&);
            DWORD dolower(string&);
            DWORD doandbool(string&);
            DWORD doorbool(string&);
            //Variables
            DWORD doreg32(int);
            //functions
            DWORD callfunc(string&);
            DWORD strfunc(string&);
            //---
            void add_to_buffer(bytes*);
      };
class DLLIMPORT VirtualMemory{
      struct vMem{
             DWORD vmem;
             DWORD rmem;
             DWORD size;
             DWORD flags;
             };    
      struct cMem{          //the changes in the memory during the emulation
             DWORD ptr;     //here the pointer to the virtual memory not the real pointer
             DWORD size;
             DWORD flags;
             };
      Log* last_accessed;
      Log* last_modified;
      public:
             DWORD CommittedPages;
             int vmem_length;
             int cmem_length;
             vMem** vmem;
             cMem** cmem;
             VirtualMemory ();
             DWORD get_virtual_pointer(DWORD ptr);
             DWORD* read_virtual_mem(DWORD ptr);
             DWORD write_virtual_mem(DWORD ptr,DWORD size,unsigned char* buff); //ptr , size, buff -return-> valid or not
             bool get_memory_flags(DWORD ptr);
             void set_memory_flags(DWORD ptr,int size);
             DWORD get_last_accessed(int index);
             DWORD get_last_modified(int index);
             void _cdecl add_pointer(DWORD rptr,DWORD vptr,DWORD size,int=MEM_READWRITE);
             DWORD delete_pointer(DWORD ptr);
             bool check_writeaccess(DWORD ptr,DWORD imagebase);
      };

class DLLIMPORT Stack{
      Thread* thread;
      public:
             DWORD stackTop;
             DWORD stackBottom;
             Stack(Thread&);
             void push(DWORD);
             int pop();
      };
class DLLIMPORT Thread{
      TIB* tib;
      TEB* teb;
      DWORD fs;
      bool seh_enable;
      
      DWORD entry_point;
      DWORD tls_callback_index;
      public:
             Process* process;
             Log* log;
             Stack* stack;
             VirtualMemory* mem;
             DWORD EFlags;
             DWORD Eip;
             bool still_tls;
             DWORD Exx[8];
             double ST[8];
             DWORD GetFS();
             Process* GetProcess();
             void updateflags(DWORD,DWORD,DWORD,int,DWORD);
             void generateException(DWORD code);
             int doException(DWORD rec);
             void sehReturn();
             void TLSContinue();
             Thread(DWORD,Process&);
             Thread();
             void CreateTEB();
             ///*
             DWORD FPUControlWord; //(FCW)
             DWORD FPUStatusWord; //(FST)
             DWORD FPUTagWord;
             DWORD FPUDataPointer;
             DWORD FPUInstructionPointer;
             DWORD FPULastInstructionOpcode;
             
             int SelectedReg;               //the reg that will be the next to push in 
             //*/
      friend class Process;
      };

class DLLIMPORT Process {
      private:
              System* sys;
              Thread* threads[100];
              int nthreads;
              int error;
              int Imagebase;
              int ImportTableFixup(DWORD);
              int APIsFixup(DWORD,image_import_descriptor*,DWORD);
              void CreatePEB();
              DISASM_INSTRUCTION* ins;
              bool TiggeredBreakpoint;
      public:
             bool IsDLL;
			 int AppType;
             DWORD MaxIterations;
             DWORD nimports;
             Imports* imports[20];
             PEB* peb;
             Debugger* debugger;
             VirtualMemory* SharedMem;
             System* getsystem();
             int emulate();
             int emulate(string);
             int emulatecommand(int);
             int emulatecommand();
             int CreateThread(DWORD);
             Thread* GetThread(int);
             int GetNumOfThreads(){return nthreads;};
             DISASM_INSTRUCTION* GetLastIns();
             DWORD GetImagebase();
             void SkipIt();
             Process (System* sys,string filename);
			 Process (System* sys,char* buff,int size,int Flags);
             ~Process();
      };
class DLLIMPORT Log {
      private:
              DWORD log[10];
              int cur;
      public:
             Log(DWORD);
             void addlog(DWORD);
             DWORD getlog(int);
      };
//strings
int compare_array(string,string[],int);
int compare_array(string,string[],int,int);
string DLLIMPORT to_lower_case(string);
string DLLIMPORT trim(string); 
int DLLIMPORT imm_to_dec(string);

//important functions

int call_to_func(DWORD,DWORD,DWORD);     
DWORD DLLIMPORT PELoader(char* buff);
DWORD DLLIMPORT PELoader(string filename);
DWORD DLLIMPORT PEDump(DWORD Eip,Process* c,char* filename);
DWORD DLLIMPORT FindAPI(Process* c,DWORD ApiName,DWORD DllHandle,DWORD napi,DWORD ndll,bool defined);
DWORD DLLIMPORT ReconstructImportTable(Process* c);
DWORD DLLIMPORT UnloadImportTable(Process* c);
DWORD DLLIMPORT ZeroImportTable(Process * c);
DWORD DLLIMPORT modrm_calc(Thread&,DISASM_INSTRUCTION*);
//==========================================
// Hacker Disassmbler Engine
#ifndef _HDE32_H_
#define _HDE32_H_
//#include <stdint.h>

#define F_MODRM         0x00000001
#define F_SIB           0x00000002
#define F_IMM8          0x00000004
#define F_IMM16         0x00000008
#define F_IMM32         0x00000010
#define F_DISP8         0x00000020
#define F_DISP16        0x00000040
#define F_DISP32        0x00000080
#define F_RELATIVE      0x00000100
#define F_2IMM16        0x00000800
#define F_ERROR         0x00001000
#define F_ERROR_OPCODE  0x00002000
#define F_ERROR_LENGTH  0x00004000
#define F_ERROR_LOCK    0x00008000
#define F_ERROR_OPERAND 0x00010000
#define F_PREFIX_REPNZ  0x01000000
#define F_PREFIX_REPX   0x02000000
#define F_PREFIX_REP    0x03000000
#define F_PREFIX_66     0x04000000
#define F_PREFIX_67     0x08000000
#define F_PREFIX_LOCK   0x10000000
#define F_PREFIX_SEG    0x20000000
#define F_PREFIX_ANY    0x3f000000

#define PREFIX_SEGMENT_CS   0x2e
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3e
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xf0
#define PREFIX_REPNZ        0xf2
#define PREFIX_REPX         0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

#endif

#pragma pack(push,1)

struct hde32sexport{
    unsigned char len;
    unsigned char p_rep;
    unsigned char p_lock;
    unsigned char p_seg;
    unsigned char p_66;
    unsigned char p_67;
    unsigned char opcode;
    unsigned char opcode2;
    unsigned char modrm;
    unsigned char modrm_mod;
    unsigned char modrm_reg;
    unsigned char modrm_rm;
    unsigned char sib;
    unsigned char sib_scale;
    unsigned char sib_index;
    unsigned char sib_base;
    union {
        unsigned char imm8;
        unsigned short imm16;
        unsigned int imm32;
    } imm;
    union {
        unsigned char disp8;
        unsigned short disp16;
        unsigned int disp32;
    } disp;
    int flags;
};
#pragma pack(pop)
//==============================
//Disassembler

//the register flags

#define OP_REG_EAX 0x00000001
#define OP_REG_ECX 0x00000002
#define OP_REG_EDX 0x00000004
#define OP_REG_EBX 0x00000008
#define OP_REG_ESP 0x00000010
#define OP_REG_EBP 0x00000020
#define OP_REG_ESI 0x00000040
#define OP_REG_EDI 0x00000080

//FPU Registers

#define OP_REG_ST0 0x00000001
#define OP_REG_ST1 0x00000002
#define OP_REG_ST2 0x00000003
#define OP_REG_ST3 0x00000004
#define OP_REG_ST4 0x00000005
#define OP_REG_ST5 0x00000006
#define OP_REG_ST6 0x00000007
#define OP_REG_ST7 0x00000008

//for all registers
#define OP_REG_ALL 0x000000FF
#define OP_REG_ALL_EXP_EAX 0x000000FE

//Opcode States
#define OP_IMM8     0x00000100
#define OP_IMM32    0x00000200
#define OP_IMM      0x00000300        //IMM8 or IMM32 
#define OP_BITS8    0x00000400 
#define OP_BITS32   0x00000800
#define OP_RM_R     0x00001000        //Eb,Gb or Ev,Gv
#define OP_R_RM     0x00002000        //Gb,Eb or Gv,Ev
#define OP_RM_IMM   0x00004000        //Eb,Ib
#define OP_R_IMM    0x00008000        //Gb,Ib
#define OP_REG_EXT  0x00010000        //reg used as an opcode extention
#define OP_REG_ONLY 0x00020000       // like inc or dec
#define OP_RM_ONLY  0x00040000
#define OP_IMM_ONLY 0x00080000       // for push & pop
#define OP_RM_DISP  0x00100000        //disp only
#define OP_GROUP    0x00200000
#define OP_LOCK     0x00400000
#define OP_0F       0x00800000        //for 2 bytes opcode
#define OP_SRC8     0x01000000        //for movzx
#define OP_SRC16    0x02000000        //for movzx
#define OP_ANY      0x04000000        //no source and no destination
#define OP_FPU      0x08000000        //FPU Instructions
#define OP_UNUSED   0x10000000        //ignored entry in the FlagTables

//Assembler states
#define NO_SRCDEST  0x80000000         // no opcodes     

#define DEST_REG    0x00000100
#define DEST_RM     0x00000200
#define DEST_IMM    0x00000400        //IMM8 or IMM32 
#define DEST_BITS32 0x00000800
#define DEST_BITS16 0x00001000
#define DEST_BITS8  0x00002000

#define SRC_REG     0x00004000
#define SRC_NOSRC   0x00008000
#define SRC_RM      0x00010000
#define SRC_IMM     0x00020000        //IMM8 or IMM32 
#define SRC_BITS32  0x00040000
#define SRC_BITS16  0x00001000        //the same as  DEST_BITS16
#define SRC_BITS8   0x00080000

#define RM_SIB      0x00100000       // it will not differ dest or src because it should be one rm
#define INS_UNDEFINED 0x00200000    //for the disasembler only
#define INS_INVALID 0x00400000       //invalid instruction (returned by hde32) 
#define MOVXZ_SRC16 0x00800000
#define MOVXZ_SRC8  0x01000000
#define EIP_UPDATED 0x02000000
#define API_CALL    0x04000000
//ModRM states
#define RM_REG      0x00000001
#define RM_DISP8    0x00000002
#define RM_DISP16   0x00000004
#define RM_DISP32   0x00000008
#define RM_DISP     0x00000010
#define RM_MUL2     0x00000020
#define RM_MUL4     0x00000040
#define RM_MUL8     0x00000080
#define RM_ADDR16   0x00000100

//FPU States

#define FPU_NULL        0x00000100       //no source or destinaion
#define FPU_DEST_ONLY   0x00000200       // Destination only 
#define FPU_SRCDEST     0x00000400        // with source and destination
#define FPU_DEST_ST     0x00000800        // destination == ST0
#define FPU_SRC_STi     0x00000800        // source == STi (the same as before)
#define FPU_DEST_STi    0x00001000        // destination == STi
#define FPU_SRC_ST      0x00001000        // source == ST0 (the same as before)
#define FPU_DEST_RM     0x00002000        // destination is RM
#define FPU_MODRM       0x00002000        // destination is RM & there's a ModRM
#define FPU_BITS32      0x00004000        
#define FPU_BITS16      0x00008000        



struct DISASM_INSTRUCTION{
          hde32sexport hde;
          int entry;                 //the index of this opcode in the FlagTable
          string* opcode;
          int ndest;
          int nsrc;
          int other;      //used for mul to save the imm and used for any call to api to save the index of the api(it's num in APITable)
          struct {
                 int length;
                 int items[3];
                 int flags[3];
          } modrm;
          int (*emu_func)(Thread&,DISASM_INSTRUCTION*);
          int flags;
    };
  //assembler & disassembler
   struct bytes {
           int length;
           unsigned char s[16];
   };

/*
#ifdef WIN32
  #ifdef EXPORT_CLASS_FOO
    #define CLASS_FOO __declspec(dllexport)    //while building the dll
  #else
    #define CLASS_FOO __declspec(dllimport)    //while use the dll
  #endif
#else
  #define CLASS_FOO
#endif

class CLASS_Foo foo
{ ... };
//*/
//#endif
