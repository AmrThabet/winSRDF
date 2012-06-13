//==========================================
// Hacker Disassmbler Engine
#ifndef _HDE32_H_
#define _HDE32_H_

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
    char len;
    char p_rep;
    char p_lock;
    char p_seg;
    char p_66;
    char p_67;
    char opcode;
    char opcode2;
    char modrm;
    char modrm_mod;
    char modrm_reg;
    char modrm_rm;
    char sib;
    char sib_scale;
    char sib_index;
    char sib_base;
    union {
        char imm8;
        short imm16;
        DWORD imm32;
    } imm;
    union {
        char disp8;
        short disp16;
        DWORD disp32;
    } disp;
    DWORD flags;
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



struct DISASM_INSTRUCTION
{
          hde32sexport hde;
          int unused1;                 //the index of this opcode in the FlagTable
          DWORD unused2;			//unused
          int ndest;
          int nsrc;
          int other;      //used for mul to save the imm and used for any call to api to save the index of the api(it's num in APITable)
          struct {
                 int length;
                 int items[3];
                 int flags[3];
          } modrm;
          DWORD unused3;
          int flags;
 };