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

#include "stdafx.h"
#include "SRDF.h"

using namespace Security::Storage::Registry;
using namespace Security::Elements::String;

cRegistryKey::cRegistryKey()
{

}
void cRegistryKey::Initialize(HKEY Key,cString KeyPath, bool Create)
{
	int ret = 0;
	if (!Create)ret = (int)RegOpenKeyEx( Key,KeyPath.GetChar() , 0, KEY_ALL_ACCESS ,&hKey);
	else ret = (int)RegCreateKey(Key,KeyPath.GetChar(),&hKey);
	if (ret == ERROR_SUCCESS)
	{
		isFound = true;
		EnumerateValues(nEntries);
	}
	else isFound = false;

}
cRegistryKey::~cRegistryKey()
{
	for(DWORD i = 0;i< nEntries;i++){
		delete Entries[i];
	}
	if(isFound)RegCloseKey(hKey);
}
bool cRegistryKey::IsFound()
{
	return isFound;
}
void cRegistryKey::EnumerateValues(DWORD &nValues)
{
	DWORD maxValueLength = 0;
	RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,&nValues,&maxValueLength,NULL,NULL,NULL);
	maxValueLength++;
	Entries = (cRegistryEntry**)malloc(nValues * sizeof(cRegistryEntry*));
	memset((PVOID)Entries,0, nValues * sizeof(cRegistryEntry*));
	
	char* buff = (char*)malloc(maxValueLength);	
	memset(buff,0,maxValueLength);
	DWORD ValueSize = maxValueLength;
	for (DWORD i = 0;i < nValues;i++)
	{
		if (RegEnumValue(hKey,i,buff,&ValueSize,NULL,NULL,NULL,NULL) == ERROR_NO_MORE_ITEMS)break;
		Entries[i] = new cRegistryEntry(this,buff);
		memset(buff,0,maxValueLength);
		ValueSize = maxValueLength;		//Set the ValueSize to The Maximum to accept any ValueName
		
	}
	return;
}
void cRegistryKey::RefreshEntries()
{
	for(DWORD i = 0;i< nEntries;i++){
		delete Entries[i];
	}
	free((PVOID)Entries);
	EnumerateValues(nEntries);
}
cRegistryEntry cRegistryKey::operator [](char* Value)
{
	for (DWORD i =0; i < nEntries; i++)
	{
		if (Entries[i]->GetEntryName() == Value)return *Entries[i];
	}
	return *new cRegistryEntry(this,Value);
}
cRegistryEntry cRegistryKey::operator [](DWORD index)
{
	if (index < nEntries)return *Entries[index];
	return *new cRegistryEntry(this,cString(index));
}
HKEY cRegistryKey::GetKeyHandle()
{
	return hKey;
}
int cRegistryKey::GetNumberOfEntries()
{
	return nEntries;
}
//-----------------------------------------------------------------------------
cRegistryEntry::cRegistryEntry(cRegistryKey* RegKey,cString Valuename)
{
	if (RegQueryValueEx(RegKey->GetKeyHandle(),Valuename,NULL,&Type,NULL,NULL) == ERROR_SUCCESS)isFound = true;
	else isFound = false;
	hKey = RegKey->GetKeyHandle();
	ValueName = Valuename;
}
cRegistryEntry::cRegistryEntry(HKEY hKey,cString Valuename)
{
	if (RegQueryValueEx(hKey,Valuename,NULL,&Type,NULL,NULL) == ERROR_SUCCESS)isFound = true;
	else isFound = false;
	this->hKey = hKey;
	ValueName = Valuename;
}
bool cRegistryEntry::IsFound()
{
	return isFound;
}
char* cRegistryEntry::GetValue(DWORD &len)
{
	
	if (RegQueryValueEx(hKey,ValueName,NULL,NULL,NULL,&len) != ERROR_SUCCESS) return NULL;
	
	char* buff = (char*)malloc(len+1);
	memset(buff,0,len);
	if (RegQueryValueEx(hKey,ValueName,NULL,NULL,(LPBYTE)buff,&len) != ERROR_SUCCESS) return NULL;
	return buff;
	
}
void cRegistryEntry::SetValue(char* buff,DWORD Len,DWORD Type)
{
	int ret = (int)RegSetValueEx(hKey,ValueName,NULL,Type,(BYTE*)buff,Len);
   
}
cRegistryEntry::~cRegistryEntry()
{
	
}
cString cRegistryEntry::GetEntryName()
{
	return ValueName;
}