/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet <amr.thabet@student.alx.edu.eg>
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

#include "cThread.h"
#include "pe.h"
#include "elf.h"
//#include "tib.h"

using namespace Security::Elements::String;


//--------------------------------------//
//--          Files Namespace         --//
//--------------------------------------//


class DLLIMPORT Security::Targets::Files::cFile
{
	HANDLE        hFile;
    HANDLE        hMapping;
	BOOL		  IsFile;
public:
    DWORD        BaseAddress;
    DWORD        FileLength;
	DWORD		 Attributes;
	char*		 Filename;
	cFile(char* szFilename);
	cFile(char* buffer,DWORD size);
	int OpenFile(char* szFilename);
	~cFile();
};

//--------------------------------------------------------------
// PE Parser
//----------

/*export table */
struct EXPORTFUNCTION {
	char* funcName;
	WORD funcOrdinal;
	DWORD funcRVA;
};
struct EXPORTTABLE 
{
	DWORD nFunctions;
	DWORD nNames;
	DWORD Base;
	PDWORD pFunctions;
	PDWORD pNames;
	PWORD pNamesOrdinals;
	EXPORTFUNCTION *Functions;
};
/****       ****/
struct IMPORTTABLE_DLL;
struct IMPORTTABLE_API;

struct SECTION_STRUCT
{
	char* SectionName;
	DWORD VirtualAddress;
	DWORD VirtualSize;
	DWORD PointerToRawData;
	DWORD SizeOfRawData;
	DWORD Characterisics;
	DWORD RealAddr;
};
struct IMPORTTABLE
{
	DWORD nDLLs;
	IMPORTTABLE_DLL* DLL;
};
struct IMPORTTABLE_DLL
{
	char* DLLName;
	DWORD nAPIs;
	IMPORTTABLE_API* API;
};
struct IMPORTTABLE_API
{
	char* APIName;
	DWORD APIAddressPlace;
};

#define DATADIRECTORY_EXPORT		0x0001
#define DATADIRECTORY_IMPORT		0x0002
#define DATADIRECTORY_RESOURCE		0x0004
#define DATADIRECTORY_EXCEPTION		0x0008
#define DATADIRECTORY_CERTIFICATE	0x0010
#define DATADIRECTORY_RELOCATION	0x0020
#define DATADIRECTORY_DEBUG			0x0040
#define DATADIRECTORY_ARCHITECT		0x0080
#define DATADIRECTORY_MACHINE		0x0100
#define DATADIRECTORY_TLS			0x0200
#define DATADIRECTORY_CONF			0x0400
#define DATADIRECTORY_BOUNDIMPORT	0x0800
#define DATADIRECTORY_IAT			0x1000
#define DATADIRECTORY_DELAYIMPORT	0x2000
#define DATADIRECTORY_RUNTIME		0x4000
#define DATADIRECTORY_RESERVED		0x8000

class DLLIMPORT Security::Targets::Files::cPEFile : public Security::Targets::Files::cFile
{
private:

	//Functions:
	bool ParsePE();
	VOID initDataDirectory();
	VOID initSections();
	VOID initImportTable();
	void initExportTable();	//export table
public:
	//Variables
	bool FileLoaded;
	image_header* PEHeader;
	DWORD Magic;
	DWORD Subsystem;
	DWORD Imagebase;
	DWORD SizeOfImage;
	DWORD Entrypoint;
	DWORD FileAlignment;
	DWORD SectionAlignment;
	WORD DataDirectories;
	unsigned long nSections;
	SECTION_STRUCT* Section;
	IMPORTTABLE ImportTable;

	/* for exports */
	EXPORTTABLE ExportTable;

	//Functions
	cPEFile(char* szFilename);
	cPEFile(char* buffer,DWORD size);
	~cPEFile();
	static bool identify(cFile* File);
	DWORD RVAToOffset(DWORD RVA);
	DWORD OffsetToRVA(DWORD RawOffset);

};

//--------------------------------------------------------------
// ELF Parser
//----------

/* elf parser */
struct SECTIONS 
{
	char* Name;
	DWORD Address;
	DWORD Offset;
	DWORD Size;
};

struct SYMBOLS 
{
	char* Name;
	DWORD Address;
	DWORD Offset;
	//DWORD Size;
};

struct DYNAMICS
{
	DWORD Address;
	DWORD Offset;
	DWORD Value;
	DWORD Tag;
	char* Name;
};

struct IMPORTS
{
	//DWORD Address;
	//DWORD Offset;
	DWORD Value;
	char* Name;
};

class DLLIMPORT Security::Targets::Files::cELFFile : public Security::Targets::Files::cFile
{
private:

	//Functions:
	bool ParseELF();
	void initSections();
	void initDynSymbols();
	void initImports();
	void initDynamics();

	char* sStringTable;
	char* dStringTable;
	unsigned int DynSymArray;
	unsigned int DynArray;
	Elf32_Sym* SymbolsTable;
	Elf32_Dyn* DynamicTable;
	
public:
	//Variables
	bool FileLoaded;
	elf32_header* ExeHeader;
	elf32_program_header* PHeader;
	elf32_section_header* SHeader;

	unsigned int nSections;
	unsigned int nDynamics;
	unsigned int nImports;
	unsigned int nSymbols;
	SECTIONS* Sections;
	SYMBOLS* Symbols;
	DYNAMICS* Dynamics;
	IMPORTS* Imports;
	
	DWORD Magic;
	DWORD Subsystem;
	DWORD SizeOfImage;
	DWORD SizeOfHeader;
	DWORD SizeOfProgramHeader;
	DWORD Entrypoint;
	unsigned short int Type;

	//Functions
	cELFFile(char* szFilename);
	cELFFile(char* buffer,DWORD size);
	~cELFFile();
	static bool identify(cFile* File);
	DWORD RVAToOffset(DWORD RVA);
	DWORD OffsetToRVA(DWORD RawOffset);

};

//--------------------------------------//
//--          Process Class           --//
//--------------------------------------//


struct MODULE_INFO
{
	DWORD moduleImageBase;
	DWORD moduleSizeOfImage;
	cString* moduleName;
	cString* modulePath;
};

struct MEMORY_MAP
{
	DWORD Address;
	DWORD Size;
	DWORD Protection;
};

class DLLIMPORT Security::Targets::cProcess
{
	void AnalyzeProcess();
	cString Unicode2Ansi(LPWSTR,int);
	BOOL GetMemoryMap();
public:
	// parameters
	DWORD procHandle;
	__PEB  *ppeb;
	DWORD ImageBase;
	ULONG SizeOfImage;
	cString processName;
	cString processPath;
	DWORD ParentID;
	DWORD ProcessId;
	cString CommandLine;
	cList modulesList;
	cList MemoryMap;
	bool isFound;
	
	//methods
	cProcess(int processId);
	
	DWORD Read(DWORD startAddress,DWORD size);
	DWORD Allocate (DWORD preferedAddress,DWORD size);
	DWORD Write(DWORD startAddressToWrite ,DWORD buffer ,DWORD sizeToWrite);
	DWORD DllInject(cString DLLFilename);
	DWORD CreateThread(DWORD addressToFunction , DWORD addressToParameter);
	bool IsFound();
};