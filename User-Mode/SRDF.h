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

#pragma once


#include <windows.h>

#include <winsock2.h>
#ifndef DLLIMPORT
#define DLLIMPORT 
#endif
#include <iostream>

using namespace std;

//Development Framework Design:
//-----------------------------
namespace Security
{
	namespace Targets
	{
		namespace Files
		{
			class cFile;
			class cPEFile;
		}
		namespace Packets
		{
			class cPacket;
		}
		class cProcess;
	}

	namespace Elements
	{
		namespace String
		{
			class cString;
			class cEncodedString;
			class cBase64String;
			class cEncryptedString;
			class cMD5String;
			class cHash;
			class cList;
		}
		namespace Code
		{
			class cStoredProcedure;
			class cNativeCode;
		}
		namespace XML
		{
			class cSerializer;
			class cXMLHash;
			class cXMLEncodedString;
		}
			
	}
	namespace Connections
	{
		namespace Internet
		{
			class cTCPSocket;
			class cHTTPSocket;
		}
		namespace InterProcess
		{

		}
		namespace KernelMode
		{
			class cDevice;
			class cDriver;
		}
	}
	namespace Storage
	{
		namespace Databases
		{
			class cDatabase;
			class cSQLiteDatabase;
		}
		namespace Files
		{
			class cLog;
			class cFileToWrite;
		}
		namespace Registry
		{
			class cRegistryEntry;
			class cRegistryKey;
		}
	}
	namespace Libraries
	{
		namespace Malware
		{
			namespace OS
			{
				namespace Win32
				{
					namespace Scanning
					{
						class cRecursiveScanner;
						class cProcessScanner;
						class cYaraScanner;
						class ssdeep;
					}
					namespace Hooking
					{

					}
					namespace Emulation
					{
						class CPokasEmu;
					}
				}
			}
			namespace Assembly
			{
				namespace x86
				{
					class CPokasAsm;
				}
			}
		}
		namespace Network
		{
			namespace Firewalls
			{

			}
			namespace PacketCapture
			{
				
			}
			namespace ProtocolAnalyzers
			{
				
			}
		}
	}

	//Core Managment System

	namespace Core
	{
		class cApp;
		class cThread;
		class cThreadException;
		class Mutex;
		class cMemoryManager;
	}
}


using namespace Security::Elements::String;

class DLLIMPORT Security::Storage::Registry::cRegistryKey;

#include "includes\ELements\Elements.h"
#include "includes\Connections\Connections.h"
#include "includes\Storage\Storage.h"
#include "includes\Libraries\Libraries.h"
#include "includes\Targets\Targets.h"


//--------------------------------------//
//--         Core Namespace           --//
//--------------------------------------//

using namespace Security::Storage;
using namespace Security::Core;


#define APP_NOANOTHERINSTANCE	0x01
#define APP_ADDLOG				0x02
#define APP_DEFINEDATABASE		0x04
#define APP_REGISTRYSETTINGS	0x08


class DLLIMPORT Security::Core::cApp
{
	int optind;
	int opterr;
	char *optarg;
	int getopt(int argc, char *argv[], char *optstring);
	DWORD Flags;
	cString Options;
	cString LogFilename;
	void SetDefaultSettings();
	cString AppPath;
	cString RegistryPath;
	HKEY RegistryType;
	void GetRequest(int argc, char *argv[]);
public:
	cString AppName;
	Mutex InstanceMutex;
	Mutex LogMutex;
	Mutex DatabaseMutex;
	Databases::cDatabase* Database;
	Security::Storage::Files::cLog* Log;
	Registry::cRegistryKey Settings;
	cHash Request;
	cApp(cString AppName);
	~cApp();
	void SetCustomSettings();
	cString GetApplicationFilename();
	cString GetApplicationPath();
	void Initialize(int argc, char *argv[]);
	int Run();
};

//----------------------------------------------------------

struct HEAP_INFO
{
	
	DWORD	LastAllocatedHeader;
	DWORD	LastAllocatedBuffer;
	WORD	nHeaderAllocatedBlocks;
	WORD	nBufferAllocatedBlocks;
	WORD	nElements;
	WORD	Reserved;
	DWORD	HeapBegin;
	DWORD	AllocatedSeparateBlocks;
	DWORD	FreeSeparateBlocks;
	DWORD	LargeFreeList;
	DWORD	FreeLists[128];
};

struct HEADER_HEAP_ELEMENT
{
	DWORD	pNextFreeListItem;
	DWORD	CanaryValue;
	DWORD	PointerToBuffer;
	DWORD	Tid;
	WORD	Size;
	WORD	Index;
	WORD	Reserved;
	BOOL	IsAllocated;
	BOOL	IsGlobal;
};

struct BUFFER_HEAP_ELEMENT
{
	DWORD	CanaryValue;
	WORD	NullBytes;
	WORD	Index;
};

class DLLIMPORT Security::Core::cMemoryManager
{
	DWORD pHeaderHeap;
	DWORD pBufferHeap;
	HEAP_INFO* HeapInfo;
	CRITICAL_SECTION 	CriticalSection;
protected:
	HEADER_HEAP_ELEMENT* AllocateHeaderElement();
	BUFFER_HEAP_ELEMENT* AllocateBufferElement(DWORD size);
	HEADER_HEAP_ELEMENT* GetElement(BUFFER_HEAP_ELEMENT* AllocatedBuffer);
public:
	cMemoryManager();
	~cMemoryManager();
	void* Allocate(WORD size,BOOL IsGlobal);
	void Free(void* ptr);

};

