#include <fstream>
#include "sqlite3.h"

using namespace std;
using namespace Security::Elements::String;

//-------------------------------------------------------------------
//Log:
//----
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
	virtual cString GetItem(cString TableName,int id){return "";};
	virtual bool AddItem(cString TableName,cString Item){return false;};
	virtual bool RemoveItem(cString TableName,cString Item){return false;};
	virtual bool RemoveItem(cString TableName,int id){return false;};
	virtual bool CreateTable(cString TableName){return false;};
};

class DLLIMPORT Security::Storage::Databases::cSQLiteDatabase : public Security::Storage::Databases::cDatabase
{
	sqlite3* DB;
public:
	cSQLiteDatabase(){};
	~cSQLiteDatabase();
	cSQLiteDatabase(cString Filename){OpenDatabase(Filename);}
	virtual bool OpenDatabase(cString Filename);
	virtual void CloseDatabase();
	virtual cHash* GetItems(cString TableName);
	virtual cString GetItem(cString TableName,int id);
	virtual bool AddItem(cString TableName,cString Item);
	virtual bool RemoveItem(cString TableName,cString Item);
	virtual bool RemoveItem(cString TableName,int id);
	virtual bool CreateTable(cString TableName);
};
