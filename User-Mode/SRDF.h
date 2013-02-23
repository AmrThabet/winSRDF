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
#include <new>
#include <winsock2.h>
#ifndef DLLIMPORT
#define DLLIMPORT 
#endif
#include <iostream>
#include "includes\Network\hPackets.h"

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
			class cELFFile;
		}
		namespace Memory
		{
			class cProcess;
			class MemoryDump;
			class MemoryRegion;
		}
		namespace Packets
		{
			class cPacket;
			class cPcapFile;
			class cConStream;
		}
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
			class cEventIPC;
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
					namespace Enumeration
					{
						class cRecursiveScanner;
						class cProcessScanner;
					}
					namespace Static
					{
						class cYaraScanner;
						class SSDeep;
					}
					namespace Dynamic
					{
						class CPokasEmu;
						class cDebugger;
					}
					namespace Behavioral
					{
						class cAPIHook;
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
			namespace PacketGeneration
			{
				class cPacketGen;
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
		class cConsoleApp;
	}
}


using namespace Security::Elements::String;

class DLLIMPORT Security::Storage::Registry::cRegistryKey;

#include "includes\ELements\Elements.h"
#include "includes\Connections\Connections.h"
#include "includes\Storage\Storage.h"
#include "includes\Libraries\Libraries.h"
#include "includes\Targets\Targets.h"
#include "includes\Network\Network.h"


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
protected:
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
	Databases::cDatabase* Database;
	Security::Storage::Files::cLog* Log;
	Registry::cRegistryKey Settings;
	cHash Request;
	cApp(cString AppName);
	~cApp();
	virtual void SetCustomSettings();
	cString GetApplicationFilename();
	cString GetApplicationPath();
	void Initialize(int argc, char *argv[]);
	virtual int Run(){return 0;};
};

class DLLIMPORT Security::Core::cConsoleApp : public cApp
{
protected:
	typedef void CmdFunc(cConsoleApp* App,int argc,char* argv[]);
	typedef CmdFunc *PCmdFunc;
	
	struct CONSOLE_COMMAND
	{
		cString* Name;
		cString* Description;
		cString* Format;
		DWORD	 nArgs;
		PCmdFunc CommandFunc;
	};
	cList* CmdList;
	cString Intro;
	cString Prefix; 
	void AddCommand(char* Name,char* Description,char* Format,DWORD nArgs,PCmdFunc CommandFunc);
	
	void StartConsole();
public:
	cConsoleApp(cString AppName);
	~cConsoleApp();
	virtual void SetCustomSettings();
	virtual int Run();
	virtual int Exit();

	//Default Commands
	void Help(int argc,char* argv[]);
	void Quit(int argc,char* argv[]);
};

void HelpFunc(cConsoleApp* App,int argc,char* argv[]); 
void QuitFunc(cConsoleApp* App,int argc,char* argv[]); 
//----------------------------------------------------------
