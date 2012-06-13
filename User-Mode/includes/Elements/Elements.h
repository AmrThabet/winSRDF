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
#include "cString.h"
#include "cThread.h"
#include <Wincrypt.h>
#include "pe.h"

using namespace Security::Elements::String;


//--------------------------------------//
//--          Files Namespace         --//
//--------------------------------------//


class DLLIMPORT Security::Elements::Files::cFile
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
//--------------------------------------//
//--        Strings Namespace         --//
//--------------------------------------//

class DLLIMPORT Security::Elements::String::cHash : public Security::Storage::Databases::cSerializer
{
protected:
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
	DWORD GetNumberOfItems(cString Name);
	DWORD GetNumberOfItems();
	void AddItem(cString Name,cString Value);
	cString operator[](cString Name);
	cString operator[](DWORD id);
	cString GetKey(DWORD id);
	cString GetValue(DWORD id);
	cString GetValue(cString Name,int id = 0);
	void RemoveItem(DWORD id);
	void RemoveItem(cString Name,int id = 0);
	void ClearItems();
	bool IsFound(cString Name);
	
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash& XMLParams);
};

class DLLIMPORT Security::Elements::String::cXMLHash : public Security::Elements::String::cHash
{
public:
	void AddXML(cString Name, cString XMLItem);
	void AddText(cString Name, cString str);
	void AddBinary(cString Name, char* buff, DWORD length);
	cString GetXML(cString Name,int id = 0);
	cString GetText(cString Name,int id = 0);
	cString GetBinary(cString Name,DWORD &len,int id = 0);
	cString GetXML(int id);
	cString GetText(int id);
	cString GetBinary(int id,DWORD &len);
	cXMLHash() : cHash(){};
	~cXMLHash(){};
};


 class DLLIMPORT Security::Elements::String::cList
{
	
	char* head;
	DWORD nItems;
	int Ssize;
	
public:
	cList(int size);
	~cList();
	void AddItem(char* item);
	DWORD GetNumberOfItems();
	char* GetItem(int size);
	char* GetLastItem();
};


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
	void SetEncrypted(cString encryptedString){EncryptedString = encryptedString;}
	bool operator == (char* x){return (EncryptedString == x);}

};

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
	void SetEncoded(cString encodedString){EncodedString = encodedString;}
	virtual cString Encode(char* buff,DWORD length){cout << "Encoded Error\n\n\n";return "";};
	virtual char* Decode(DWORD &len){len = NULL;return NULL;}
	operator char*(){return EncodedString.GetChar();}
	cString GetEncoded(){return EncodedString;}
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
//--------------------------------------//
//--         Code Namespace           --//
//--------------------------------------//

class DLLIMPORT Security::Elements::Code::cStoredProcedure : public Security::Storage::Databases::cSerializer
{
public:
	cString Name;
	cString Discription;
	cString Author;
	cString DLLName;
	cString APIName;
	cStoredProcedure();
	cStoredProcedure(cString Name,cString Discription,cString Author,cString DLLName,cString APIName);
	void Run(void* UserData = NULL);
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash& XMLParams);
};

class DLLIMPORT Security::Elements::Code::cNativeCode : public Security::Storage::Databases::cSerializer
{
	char* buff;
	DWORD length;
public:
	cString Name;
	cString Discription;
	cString Author;
	cString Encoder;
	cNativeCode();
	cNativeCode(cString Name,cString Discription,cString Author,char* buff,DWORD length);
	void Run(void* UserData = NULL);
	char* GetCode();
	DWORD GetLength();
	void SetCode(char* buff,DWORD length);
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash& XMLParams);
};
