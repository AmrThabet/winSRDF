//
// PE Executable file format
//
// Copyright (C) 2002 Michael Ringgaard. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 
// 1. Redistributions of source code must retain the above copyright 
//    notice, this list of conditions and the following disclaimer.  
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.  
// 3. Neither the name of the project nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission. 
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
// SUCH DAMAGE.
// 
#ifndef PE_H
#define PE_H
#define IMAGE_PE_SIGNATURE 0x00004550  // PE00
//
// DOS image header
//
//#pragma pack(push)
//#pragma pack(1)
struct dos_header 
{
  unsigned short e_magic;                     // Magic number
  unsigned short e_cblp;                      // Bytes on last page of file
  unsigned short e_cp;                        // Pages in file
  unsigned short e_crlc;                      // Relocations
  unsigned short e_cparhdr;                   // Size of header in paragraphs
  unsigned short e_minalloc;                  // Minimum extra paragraphs needed
  unsigned short e_maxalloc;                  // Maximum extra paragraphs needed
  unsigned short e_ss;                        // Initial (relative) SS value
  unsigned short e_sp;                        // Initial SP value
  unsigned short e_csum;                      // Checksum
  unsigned short e_ip;                        // Initial IP value
  unsigned short e_cs;                        // Initial (relative) CS value
  unsigned short e_lfarlc;                    // File address of relocation table
  unsigned short e_ovno;                      // Overlay number
  unsigned short e_res[4];                    // Reserved words
  unsigned short e_oemid;                     // OEM identifier (for e_oeminfo)
  unsigned short e_oeminfo;                   // OEM information; e_oemid specific
  unsigned short e_res2[10];                  // Reserved words
  unsigned long  e_lfanew;                    // File address of new exe header
};
//#pragma pack(pop)
//
// PE image file header
//
struct image_file_header
{
  unsigned short machine;                     //+4
  unsigned short number_of_sections;          //+6
  unsigned long  timestamp;                   //+8
  unsigned long  pointer_to_symboltable;      //+C
  unsigned long  number_of_symbols;           //+10
  unsigned short size_of_optional_header;     //+14
  unsigned short characteristics;             //+16
};
#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved externel references)
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Agressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file
#define IMAGE_FILE_SYSTEM                    0x1000  // System File
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed
#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
//
// Image directory
//
struct image_directory
{
  unsigned long virtual_address;
  unsigned long size;
};
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_OPTIONAL_HDR32_MAGIC          0x10B
//
// Optional image header
//
struct image_optional_header
{
  unsigned short magic;                          //+18
  unsigned char  major_linker_version;           //+1A
  unsigned char  minor_linker_version;           //+1B
  unsigned long  size_of_code;                   //+1C
  unsigned long  size_of_initialized_data;       //+20
  unsigned long  size_of_uninitialized_data;     //+24
  unsigned long  address_of_entry_point;         //+28
  unsigned long  base_of_code;                   //+2C
  unsigned long  base_of_data;                   //+30
  unsigned long  image_base;                     //+34
  unsigned long  section_alignment;              //+38
  unsigned long  file_alignment;                 //+3C
  unsigned short major_operating_system_version; //+40
  unsigned short minor_operating_system_version; //+42
  unsigned short major_image_version;			 //+44
  unsigned short minor_image_version;			 //+46
  unsigned short major_subsystem_version;		 //+48
  unsigned short minor_subsystem_version;		 //+4A
  unsigned long  win32_version_value;			 //+4C
  unsigned long  size_of_image;					 //+50
  unsigned long  size_of_headers;				 //+54
  unsigned long  checksum;						 //+58
  unsigned short subsystem;						 //+5C
  unsigned short dll_characteristics;			 //+5E
  unsigned long  size_of_stack_reserve;			 //+60
  unsigned long  size_of_stack_commit;			 //+64
  unsigned long  size_of_heap_reserve;			 //+68
  unsigned long  size_of_heap_commit;			 //+6C
  unsigned long  loader_flags;					 //+70
  unsigned long  number_of_rva_and_sizes;		 //+74
  struct image_directory data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory					//+78
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory					//+80
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory				//+88
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
//
// Image section header
//
#define IMAGE_SIZEOF_SHORT_NAME 8
struct image_section_header
{
  char name[IMAGE_SIZEOF_SHORT_NAME];        //+00
  unsigned long virtual_size;                //+08
  unsigned long  virtual_address;            //+0C
  unsigned long  size_of_raw_data;           //+10
  unsigned long  pointer_to_raw_data;        //+14
  unsigned long  pointer_to_relocations;     //+18
  unsigned long  pointer_to_linenumbers;     //+1C
  unsigned short number_of_relocations;      //+20
  unsigned short number_of_linenumbers;      //+22
  unsigned long  characteristics;            //+24
};                                           //Size=28
//
// Section characteristics
//
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.
#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000
#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  //
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  //
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  //
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  //
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  //
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  //
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  //
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000
#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.
//
//
// Combined image header
//
struct image_header
{
  unsigned long signature;
  struct image_file_header header;
  struct image_optional_header optional;
  struct image_section_header sections[1];
};
  
//
// Based relocation format
//
struct image_base_relocation
{
  unsigned long virtual_address;
  unsigned long size_of_block;
};
//
// Based relocation types.
//
#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_SECTION               6
#define IMAGE_REL_BASED_REL32                 7
//
// Export Format
//
#ifndef IMAGE_ORDINAL_FLAG
	#define IMAGE_ORDINAL_FLAG 0x80000000
#endif

struct image_export_directory
{
  unsigned long characteristics;
  unsigned long timestamp;
  unsigned short major_version;
  unsigned short minor_version;
  unsigned long name;
  unsigned long base;
  unsigned long number_of_functions;
  unsigned long number_of_names;
  unsigned long address_of_functions;      // RVA from base of image
  unsigned long address_of_names;          // RVA from base of image
  unsigned long address_of_name_ordinals;  // RVA from base of image
};
//
// Import Format
//
struct image_import_by_name
{
  unsigned short hint;
  char name[1];
};
struct image_import_descriptor
{
  union										                    //																											+00
  {
    unsigned long characteristics;            // 0 for terminating null import descriptor
    unsigned long original_first_thunk;       // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
  };
  unsigned long timestamp;										//																											+04
  unsigned long forwarder_chain;              // -1 if no forwarders																	+08
  unsigned long name;													//																											+0C
  unsigned long first_thunk;                  // RVA to IAT (if bound this IAT has actual addresses)	+10
};
struct image_bound_import_descriptor
{
  unsigned long timestamp;
  unsigned short offset_module_name;
  unsigned short number_of_module_forwarder_refs;
  // array of zero or more struct image_bound_forwarder_ref follows
};
struct image_bound_forwarder_ref
{
  unsigned long timestamp;
  unsigned short offset_module_name;
  unsigned short reserved;
};
//
// Resource Format
//
struct image_resource_directory 
{
  unsigned long characteristics;
  unsigned long timestamp;
  unsigned short major_version;
  unsigned short minor_version;
  unsigned short number_of_named_entries;
  unsigned short number_of_id_entries;
  // struct image_resource_directory_entry directoryentries[];
};
#define IMAGE_RESOURCE_NAME_IS_STRING        0x80000000
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY     0x80000000
struct image_resource_directory_entry 
{
  union 
  {
    struct 
    {
      unsigned long name_offset : 31;
      unsigned long name_is_string : 1;
    };
    unsigned long name;
    unsigned short id;
  };
  union 
  {
    unsigned long offset_to_data;
    struct 
    {
      unsigned long offset_to_directory : 31;
      unsigned long data_is_directory : 1;
    };
  };
};
struct image_resource_directory_string
{
 unsigned short length;
 char name_string[1];
};
struct image_resource_data_entry 
{
  unsigned long offset_to_data;
  unsigned long size;
  unsigned long codepage;
  unsigned long reserved;
};
#define TLS_MAGIC 0xABABABAB
struct _IMAGE_TLS_DIRECTORY {
    unsigned long StartAddressOfRawData;
    unsigned long EndAddressOfRawData;
    unsigned long* AddressOfIndex;
    unsigned long* AddressOfCallBacks;
    unsigned long SizeOfZeroFill;
    unsigned long Characteristics;
};
//typedef void (MODENTRY *PIMAGE_TLS_CALLBACK) ( PTR DllHandle, UINT32 Reason, PTR Reserved );
#endif
