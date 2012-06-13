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
	namespace Elements
	{
		namespace Files
		{
			class cFile;
			class cPEFile;
		}
		namespace String
		{
			class cString;
			class cEncodedString;
			class cBase64String;
			class cEncryptedString;
			class cMD5String;
			class cHash;
			class cXMLHash;
			class cXMLEncodedString;
			class cList;
		}
		namespace Packets
		{
			class cPacket;
		}
		namespace Code
		{
			class cStoredProcedure;
			class cNativeCode;
		}
		namespace Application
		{
			class cApp;
			class cThread;
			class cThreadException;
			class Mutex;
		}
		
		class cProcess;		
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
			class cSerializer;
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
					}
					namespace Injection
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
}

//-------------------------------------------------------------------
//XML Serializer
//--------------
using namespace Security::Elements::String;
class DLLIMPORT Security::Storage::Databases::cSerializer
{
private:
	DWORD SkipInside(cString XMLDocument,int offset);		//it returns the new offset of the end;
public:
	cSerializer(){};
	~cSerializer(){};
	cString Serialize();
	void Deserialize(cString XMLDocument);
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash& XMLParams);
};
class DLLIMPORT Security::Storage::Registry::cRegistryKey;

#include "includes\ELements\Elements.h"
#include "includes\Connections\Connections.h"
#include "includes\Storage\Storage.h"
#include "includes\Libraries\Libraries.h"


//--------------------------------------//
//--      Application Namespace       --//
//--------------------------------------//

using namespace Security::Storage;

#define APP_NOANOTHERINSTANCE	0x01
#define APP_ADDLOG				0x02
#define APP_REGISTRYSETTINGS	0x04

class DLLIMPORT Security::Elements::Application::cApp
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
	Security::Elements::Application::Mutex LogMutex;
	Security::Elements::Application::Mutex DatabaseMutex;
	Security::Storage::Files::cLog* Log;
	Registry::cRegistryKey Settings;
	Databases::cDatabase Database;
	cHash Request;
	cApp(cString AppName);
	~cApp();
	void SetCustomSettings();
	cString GetApplicationFilename();
	cString GetApplicationPath();
	void Initialize(int argc, char *argv[]);
	int Run();
};
