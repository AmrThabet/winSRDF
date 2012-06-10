#pragma once


#include <windows.h>
#include "pe.h"
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
				class UserModeFirewall;
				class WinPcapFirewall;
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

using namespace Security::Elements::String;
//----------------------------------------------------------------------
//Classes:
//--------
//Elements
//-------------

class DLLIMPORT Security::Elements::Files::cFile
{
	HANDLE        hFile;
    HANDLE        hMapping;
public:
    DWORD        BaseAddress;
    DWORD        FileLength;
	char*		 Filename;
	cFile(char* szFilename);
	int OpenFile(char* szFilename);
	~cFile();
};
//--------------------------------------------------------------------------
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

class DLLIMPORT Security::Elements::Files::cPEFile : public Security::Elements::Files::cFile
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
//-------------------------------------------

#include "cString.h"


//-------------------------------------------
//PokasEmu
//---------
DWORD typedef (*PokasEmuConstructor)(char *szFileName,char* DLLPath);
VOID typedef (*PokasEmuDestructor)(DWORD CPokasEmuObj);
int typedef (*CPokasEmu_Emulate)(DWORD CPokasEmuObj);
int typedef (*CPokasEmu_SetBreakpoint1)(DWORD CPokasEmuObj,char* Breakpoint);
int typedef (*CPokasEmu_SetBreakpoint2)(DWORD CPokasEmuObj,char* FuncName ,DWORD BreakpointFunc);
VOID typedef (*CPokasEmu_DisableBreakpoint)(DWORD CPokasEmuObj,int index);
int typedef (*CPokasEmu_GetNumberOfMemoryPages)(DWORD CPokasEmuObj);
DWORD typedef (*CPokasEmu_GetMemoryPage)(DWORD CPokasEmuObj,int index);
DWORD typedef (*CPokasEmu_GetMemoryPageByVA)(DWORD CPokasEmuObj,DWORD vAddr);
int typedef (*CPokasEmu_GetNumberOfDirtyPages)(DWORD CPokasEmuObj);
DWORD typedef (*CPokasEmu_GetDirtyPage)(DWORD CPokasEmuObj,int index);
VOID typedef (*CPokasEmu_ClearDirtyPages)(DWORD CPokasEmuObj);
int typedef (*CPokasEmu_MakeDumpFile)(DWORD CPokasEmuObj, char* OutputFile, int ImportFixType);
DWORD typedef (*CPokasEmu_GetReg)(DWORD CPokasEmuObj,int index);
DWORD typedef (*CPokasEmu_GetEip)(DWORD CPokasEmuObj);
DWORD typedef (*CPokasEmu_GetImagebase)(DWORD CPokasEmuObj);
int typedef (*CPokasEmu_GetDisassembly)(DWORD CPokasEmuObj,char* ptr, char *OutputString);
DWORD typedef (*CPokasEmu_GetRealAddr)(DWORD CPokasEmuObj,DWORD vAddr);

#define DUMP_ZEROIMPORTTABLE    0
#define DUMP_FIXIMPORTTABLE     1
#define DUMP_UNLOADIMPORTTABLE  2

#ifndef MEM_READWRITE

#define MEM_READWRITE           0
#define MEM_READONLY            1
#define MEM_IMAGEBASE           2             //mixing readonly & readwrite so it needs to be check
#define MEM_DLLBASE             3
#define MEM_VIRTUALPROTECT      4

#endif
struct MEMORY_STRUCT
{
       DWORD VirtualAddr;
       DWORD RealAddr;
       DWORD Size;
       DWORD Flags;
};
//Sm@rtNtr@CrtP@ssw0rd123
struct DIRTYPAGES_STRUCT         //the changes in the memory during the emulation
{                               
       DWORD vAddr;             //here the pointer to the virtual memory not the real pointer
       DWORD Size;
       DWORD Flags;
}; 




class DLLIMPORT Security::Libraries::Malware::OS::Win32::Emulation::CPokasEmu
{
	DWORD PokasEmuObj;
	PokasEmuConstructor PokasEmuConstructorFunc;
	PokasEmuDestructor	PokasEmuDestructorFunc;
	CPokasEmu_Emulate  CPokasEmu_EmulateFunc;
	CPokasEmu_SetBreakpoint1 CPokasEmu_SetBreakpoint1Func;
	CPokasEmu_SetBreakpoint2 CPokasEmu_SetBreakpoint2Func;
	CPokasEmu_DisableBreakpoint CPokasEmu_DisableBreakpointFunc;
	CPokasEmu_GetNumberOfMemoryPages CPokasEmu_GetNumberOfMemoryPagesFunc;
	CPokasEmu_GetMemoryPage CPokasEmu_GetMemoryPageFunc;
	CPokasEmu_GetMemoryPageByVA CPokasEmu_GetMemoryPageByVAFunc;
	CPokasEmu_GetNumberOfDirtyPages CPokasEmu_GetNumberOfDirtyPagesFunc;
	CPokasEmu_GetDirtyPage CPokasEmu_GetDirtyPageFunc;
	CPokasEmu_ClearDirtyPages CPokasEmu_ClearDirtyPagesFunc;
	CPokasEmu_MakeDumpFile CPokasEmu_MakeDumpFileFunc;
	CPokasEmu_GetReg CPokasEmu_GetRegFunc;
	CPokasEmu_GetEip CPokasEmu_GetEipFunc;
	CPokasEmu_GetImagebase CPokasEmu_GetImagebaseFunc;
	CPokasEmu_GetDisassembly CPokasEmu_GetDisassemblyFunc;
	CPokasEmu_GetRealAddr CPokasEmu_GetRealAddrFunc;

public:
       CPokasEmu(char *szFileName,char* DLLPath);
       ~CPokasEmu();
       int Emulate();
       int SetBreakpoint(char* Breakpoint);
       int SetBreakpoint(char* FuncName,DWORD BreakpointFunc);
       VOID DisableBreakpoint(int index);
       int GetNumberOfMemoryPages();
       MEMORY_STRUCT* GetMemoryPage(int index);
       MEMORY_STRUCT* GetMemoryPageByVA(DWORD vAddr);
       int GetNumberOfDirtyPages();
       DIRTYPAGES_STRUCT* GetDirtyPage(int index);
       VOID ClearDirtyPages();          
       int MakeDumpFile(char* OutputFile, int ImportFixType);
	   DWORD GetReg(int index);
	   DWORD GetEip();
	   DWORD GetRealAddr(DWORD vAddr);
	   DWORD GetImagebase();
	   int GetDisassembly(char* ptr, char* OutputString);
};
//------------------------------------------------------------------------
#include "Disassembler.h"
DWORD typedef (*PokasAsmConstructor)(char* DLLPath);
VOID typedef (*PokasAsmDestructor)(DWORD CPokasAsmObj);
DWORD typedef (*CPokasAsm_Assemble)(DWORD CPokasAsmObj, char* InstructionString, DWORD &Length);
DWORD typedef (*CPokasAsm_Disassemble)(DWORD CPokasAsmObj, char* Buffer, DWORD &InstructionLength);
DWORD typedef (*CPokasAsm_Disassemble2)(DWORD CPokasAsmObj,char* Buffer,DISASM_INSTRUCTION* ins);
//DISASM_INSTRUCTION* typedef (*CPokasAsm_Disassemble2)(DWORD CPokasAsmObj,char* Buffer,DISASM_INSTRUCTION* ins);

class DLLIMPORT Security::Libraries::Malware::Assembly::x86::CPokasAsm
{
	DWORD PokasAsmObj;
	PokasAsmConstructor PokasAsmConstructorFunc;
	PokasAsmDestructor	PokasAsmDestructorFunc;
	CPokasAsm_Assemble	CPokasAsm_AssembleFunc;
	CPokasAsm_Disassemble CPokasAsm_DisassembleFunc;
	CPokasAsm_Disassemble2 CPokasAsm_Disassemble2Func;
public:
	CPokasAsm(char* DLLPath);
	~CPokasAsm();
	char* Assemble(char* InstructionString, DWORD &Length);
	char* Disassemble(char* Buffer, DWORD &InstructionLength);
	DISASM_INSTRUCTION* Disassemble(char* Buffer,DISASM_INSTRUCTION* ins);
};


//-------------------------------------------------------------------------------
//Network
//--------
//TCPSocket
//---------

#include "Socket.h"

/*
class Security::Network::Connection::TCPSocket
{
	HANDLE hStopEvent;
	HANDLE NetworkEvent;
	HANDLE hServerThread;

};*/

//-------------------------------------------------------------------
//Log:
//----
#include <fstream>
using namespace std;
class DLLIMPORT Security::Storage::Files::cLog
{
  private:
	cString szLogName;
	cString Filename;
	ofstream LogFile;
	bool isFound;
  public:
    cLog(cString LogName,cString Filename);
    ~cLog();
	bool IsFound();
    void WriteToLog(cString szText);
};

class DLLIMPORT Security::Storage::Files::cFileToWrite
{
	cString Filename;
	bool isFound;
	ofstream hFile;
public:
	cFileToWrite(cString szFilename,bool Append);
	~cFileToWrite();
	bool IsFound();
	void write(char* buffer,DWORD length);
};
//*/
//-----------------------------------------------------------------

class DLLIMPORT Security::Storage::Registry::cRegistryKey
{
	HKEY hKey;
	bool isFound;
	DWORD nEntries;
	Security::Storage::Registry::cRegistryEntry** Entries;
public:
	cRegistryKey();
	cRegistryKey(HKEY Key,cString KeyPath,bool Create){Initialize(Key,KeyPath,Create);}
	void Initialize(HKEY Key,cString KeyPath,bool Create);
	~cRegistryKey();
	//Security::Storage::Registry::cRegistryEntry* operator [](cString Value);
	Security::Storage::Registry::cRegistryEntry operator [](char* Value);
	Security::Storage::Registry::cRegistryEntry operator [](DWORD index);
	int GetNumberOfEntries();
	bool IsFound();									//Always == true if you set Create = true
	void EnumerateValues(DWORD &nValues);			//Array of cString
	HKEY GetKeyHandle();
	void RefreshEntries();

};

class DLLIMPORT Security::Storage::Registry::cRegistryEntry
{
	cString ValueName;
	HKEY hKey;
	DWORD Type;
	bool isFound;
	DWORD Reserved;
public:
	cRegistryEntry(cRegistryKey* RegKey,cString Valuename);
	cRegistryEntry(HKEY hKey,cString Valuename);
	cString GetEntryName();
	bool IsFound();
	bool operator ==(cString Value) {cString str = GetValue(Reserved); return (str == Value);}
	bool operator ==(char* Value) {cString str = GetValue(Reserved);return (str == Value);}
	cString operator =(cString Value){SetValue(Value,strlen(Value),REG_SZ);return Value;}
	operator char* ()	{return GetValue(Reserved);}
	char* GetValue(DWORD &len);
	void SetValue(char* buff,DWORD Len,DWORD Type);
	~cRegistryEntry();
};

class DLLIMPORT Security::Elements::String::cHash
{
	struct HASH_STRUCT
	{
		cString* Name;
		cString* Value;
	};
	HASH_STRUCT* HashArray;
public:
	cHash();
	~cHash();
	DWORD nItems;
	int GetNumberOfItems(cString Name);
	void AddItem(cString Name,cString Value);
	cString operator[](cString Name);
	cString operator[](DWORD id);
	cString GetKey(DWORD id);
	cString GetValue(DWORD id);
	cString GetItem(cString Name,int id = 0);
	bool IsFound(cString Name);
	DWORD GetNumberOfItems();
};

class DLLIMPORT Security::Elements::String::cXMLHash : public Security::Elements::String::cHash
{
public:
	void AddXML(cString Name, cString XMLItem);
	void AddText(cString Name, cString str);
	void AddBinary(cString Name, char* buff, DWORD length);
	cXMLHash() : cHash(){};
	~cXMLHash(){};
};
//-------------------------------------------------------------------
//XML Serializer
//--------------
class DLLIMPORT cSerializer
{
private:
	DWORD SkipInside(cString XMLDocument,int offset);		//it returns the new offset of the end;
public:
	cString Serialize();
	void Deserialize(cString XMLDocument);
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash XMLParams);
};
//--------------------------
//cThread
#include "cThread.h"

//--------------------------------------------------------------------
//The Main Element for any application

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

//--------
 
#include "cRecursiveScanner.h"

class DLLIMPORT Security::Elements::String::cEncryptedString
{
protected:
	cString EncryptedString;
public:
	cEncryptedString(){};
	cEncryptedString(char* buff,DWORD length){EncryptedString = Encrypt(buff,length);}
	virtual cString Encrypt(char* buff,DWORD length){return "";};
	cEncryptedString(cString str){EncryptedString = Encrypt((char*)str,str.GetLength());}
	~cEncryptedString(void){};
	cString GetEncrypted(){return EncryptedString;}
	operator char*(){return EncryptedString.GetChar();}
	bool operator == (char* x){return (EncryptedString == x);}

};
#include <Wincrypt.h>
class DLLIMPORT Security::Elements::String::cMD5String : public Security::Elements::String::cEncryptedString
{
	HCRYPTPROV	hProv;
    HCRYPTHASH  hHash;

public:
	cMD5String(){};
	cMD5String(char* buff,DWORD length) : cEncryptedString(buff,length){hProv = NULL;hHash = 0;};
	virtual cString Encrypt(char* buff,DWORD length);
	cMD5String(cString str) : cEncryptedString(str){};
	~cMD5String(void){};
};

class DLLIMPORT Security::Elements::String::cEncodedString
{
protected:
	cString EncodedString;
public:
	cEncodedString(){};
	cEncodedString(cString str){EncodedString = Encode((char*)str,str.GetLength());}
	cEncodedString(char* buff,DWORD length){EncodedString = Encode(buff,length);}
	virtual cString Encode(char* buff,DWORD length){cout << "Encoded Error\n\n\n";return "";};
	virtual char* Decode(DWORD &len){len = NULL;return NULL;}
	operator char*(){return EncodedString.GetChar();}
	bool operator == (char* x){return (EncodedString == x);}
};

class DLLIMPORT Security::Elements::String::cBase64String : public Security::Elements::String::cEncodedString
{
public:
	cBase64String(){};
	cBase64String(cString str){EncodedString = Encode((char*)str,str.GetLength());}
	cBase64String(char* buff,DWORD length){EncodedString = Encode(buff,length);}
	virtual cString Encode(char* buff,DWORD length);
	virtual char* Decode(DWORD &len);
	
};

class DLLIMPORT Security::Elements::String::cXMLEncodedString : public Security::Elements::String::cEncodedString
{
public:
	cXMLEncodedString(){};
	//cXMLEncodedString(char* buff,DWORD length) : cEncodedString(buff,length) {}
	cXMLEncodedString(cString str){EncodedString = Encode((char*)str,str.GetLength());}
	cXMLEncodedString(char* buff,DWORD length){EncodedString = Encode(buff,length);}
	virtual cString Encode(char* buff,DWORD length);
	virtual char* Decode(DWORD &len);
};

class DLLIMPORT Security::Storage::Databases::cDatabase
{
	cString Filename;
public:
	cDatabase(){};
	~cDatabase(){};
	cDatabase(cString Filename){OpenDatabase(Filename);}
	virtual bool OpenDatabase(cString Filename){return false;};
	virtual void CloseDatabase(){};
	virtual cHash* GetItems(cString TableName){return NULL;};
	virtual bool AddItem(cString TableName,cString Item){return false;};
	virtual bool RemoveItem(cString TableName,cString Item){return false;};
	virtual bool CreateTable(cString TableName){return false;};
};
#include "sqlite3.h"
class DLLIMPORT Security::Storage::Databases::cSQLiteDatabase : public Security::Storage::Databases::cDatabase
{
	sqlite3* DB;
	sqlite3_stmt* CreateTableStm;
	sqlite3_stmt* UpdateTableStm;
	sqlite3_stmt* InsertTableStm;
	sqlite3_stmt* QueryTableStm;
	sqlite3_stmt* DeleteTableStm;
	sqlite3_stmt* DropTableStm;
public:
	cSQLiteDatabase(){};
	~cSQLiteDatabase();
	cSQLiteDatabase(cString Filename){OpenDatabase(Filename);}
	virtual bool OpenDatabase(cString Filename);
	virtual void CloseDatabase();
	virtual cHash* GetItems(cString TableName);
	virtual bool AddItem(cString TableName,cString Item);
	virtual bool RemoveItem(cString TableName,cString Item);
	virtual bool CreateTable(cString TableName);
};
#include "winInet.h"
class DLLIMPORT Security::Connections::Internet::cHTTPSocket
{
	HINTERNET hINet;
	HINTERNET hConnection;
public:
	cHTTPSocket(cString URL,INTERNET_PORT Port){open(URL,Port);};
	cHTTPSocket();
	bool open(cString URL,INTERNET_PORT Port);
	void close();
	bool SendRequest(cString Request);
	bool DownloadFile(cString Request,cString Filename);
	~cHTTPSocket(){close();};
};
//class DLLIMPORT 