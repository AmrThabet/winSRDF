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
#include <Wincrypt.h>

using namespace Security::Elements::String;
using namespace Security::Elements::XML;

//--------------------------------------//
//--       Serializer Namespace       --//
//--------------------------------------//

class DLLIMPORT Security::Elements::XML::cSerializer
{
private:
	DWORD SkipInside(cString XMLDocument,int offset);		//it returns the new offset of the end;
protected:
	cString RootName;
public:
	cSerializer(){RootName = "SerializableObject";};
	~cSerializer(){};
	cString _cdecl Serialize(bool AddRoot = false);
	void Deserialize(cString XMLDocument,bool WithRoot = false);
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash& XMLParams);
	cString SerializeObject(cXMLHash* XMLParams);
	cXMLHash* DeserializeObject(cString XMLDocument);
};


//--------------------------------------//
//--        Strings Namespace         --//
//--------------------------------------//

class DLLIMPORT Security::Elements::String::cHash : public Security::Elements::XML::cSerializer
{
protected:
	struct HASH_STRUCT
	{
		cString* Name;
		cString* Value;
	};
	HASH_STRUCT* HashArray;
public:
	//To be used in XML
	cString ItemName;
	cString KeyName;
	cString ValueName;
public:
	cHash();
	cHash(cString rootName,cString itemName,cString keyName,cString valueName);
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

class DLLIMPORT Security::Elements::XML::cXMLHash : public Security::Elements::String::cHash
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
	~cXMLHash();
};


 class DLLIMPORT Security::Elements::String::cList : public Security::Elements::XML::cSerializer
{
	
	char* head;
	DWORD nItems;
	int Ssize;

public:
	cList();
	cList(int size);
	~cList();
	void AddItem(char* item);
	DWORD GetNumberOfItems();
	char* GetItem(int index);
	char* GetLastItem();
	void SetSize(int size);
	int GetSize();
	char* operator[](int index);
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash& XMLParams);
};


class DLLIMPORT Security::Elements::String::cEncryptedString
{

public:
	cString EncryptedString;
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

class DLLIMPORT Security::Elements::XML::cXMLEncodedString : public Security::Elements::String::cEncodedString
{
public:
	cXMLEncodedString(){};
	//cXMLEncodedString(char* buff,DWORD length) : cEncodedString(buff,length) {}
	cXMLEncodedString(cString str){EncodedString = Encode((char*)str,str.GetLength());}
	cXMLEncodedString(char* buff,DWORD length){EncodedString = Encode(buff,length);}
	virtual cString Encode(char* buff,DWORD length);
	virtual char* Decode(DWORD &len);
};

class DLLIMPORT Security::Elements::XML::cXMLElement : public Security::Elements::XML::cSerializer
{
public:
	cString Key;
	cString Value;
	cXMLElement(cString key,cString value){Key = key;Value = value;};
	cXMLElement(){Key = "";Value = "";};
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash& XMLParams);

};
//--------------------------------------//
//--         Code Namespace           --//
//--------------------------------------//

class DLLIMPORT Security::Elements::Code::cStoredProcedure : public Security::Elements::XML::cSerializer
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

class DLLIMPORT Security::Elements::Code::cNativeCode : public Security::Elements::XML::cSerializer
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
