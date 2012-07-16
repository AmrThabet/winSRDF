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
//#include "tib.h"

using namespace Security::Elements::String;


//--------------------------------------//
//--          Files Namespace         --//
//--------------------------------------//


class DLLIMPORT Security::Targets::Files::cFile
{
	HANDLE        hFile;
    HANDLE        hMapping;
public:
    DWORD        BaseAddress;
    DWORD        FileLength;
	DWORD		 Attributes;
	char*		 Filename;
	cFile(char* szFilename);
	int OpenFile(char* szFilename);
	~cFile();
};

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
	VOID initDataDirectory();
	VOID initSections();
	VOID initImportTable();
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
	DWORD DataDirectories;
	short nSections;
	SECTION_STRUCT* Section;
	IMPORTTABLE ImportTable;
	//Functions
	cPEFile(char* szFilename);
	~cPEFile();
	DWORD RVAToOffset(DWORD RVA);
	DWORD OffsetToRVA(DWORD RawOffset);

};

//--------------------------------------//
//--          Process Class           --//
//--------------------------------------//


struct ModuleInfo
{
	DWORD moduleImageBase;
	DWORD moduleSizeOfImage;
	cString* moduleName;
	cString* modulePath;
};

class DLLIMPORT Security::Targets::cProcess
{
	void AnalyzeProcess();
	cString Unicode2Ansi(LPWSTR,int);
public:
	// parameters
	DWORD procHandle;
	__PEB  *ppeb;
	DWORD processImageBase;
	ULONG processSizeOfImage;
	cString processName;
	cString processPath;
	DWORD processParentID;
	cString processCommandLine;
	cList modulesList;
	bool isFound;
	
	//methods
	cProcess(int);
	
	DWORD Read(DWORD ,DWORD);
	DWORD Allocate (DWORD,DWORD);
	BOOL Write (DWORD,DWORD,DWORD);
	DWORD DllInject(DWORD);
	DWORD CreateThread(DWORD,DWORD);
	
	
};