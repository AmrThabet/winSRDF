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

#include "stdafx.h"
#include "SRDF.h"
#include <iostream>

using namespace std;
using namespace Security::Elements::String;

cHash::cHash()
{
	nItems = 0;
	HashArray = 0;
};
cHash::~cHash()
{
	free(HashArray);
};
void cHash::AddItem(cString Name,cString Value)
{
	if (nItems == 0)
	{
		HashArray = (HASH_STRUCT*)malloc(sizeof(HASH_STRUCT)+1);
		HashArray[0].Name = new cString(Name);
		HashArray[0].Value = new cString(Value);
		nItems = 1;
	}
	else
	{
		HASH_STRUCT* NewArray = (HASH_STRUCT*)malloc(sizeof(HASH_STRUCT)*(nItems+1));
		memset(NewArray,0,sizeof(HASH_STRUCT)*(nItems+1));
		memcpy(NewArray,HashArray,sizeof(HASH_STRUCT)*nItems);
		NewArray[nItems].Name = new cString(Name);
		NewArray[nItems].Value = new cString(Value);
		nItems++;
		free(HashArray);
		HashArray = NewArray;
	}
}
void cHash::RemoveItem(DWORD id)
{
	if (id >= nItems) return;
	if (nItems == 1)
	{
		free(HashArray);
		nItems = 0;
		return;
	}
	
	HASH_STRUCT* NewArray = (HASH_STRUCT*)malloc(sizeof(HASH_STRUCT)*(nItems-1));
	memset(NewArray,0,sizeof(HASH_STRUCT)*(nItems-1));
	if (id > 0)memcpy(NewArray,HashArray,sizeof(HASH_STRUCT)*id);
	memcpy(&NewArray[id],&HashArray[id+1],sizeof(HASH_STRUCT)*(nItems-id-1));
	nItems--;
	free(HashArray);
	HashArray = NewArray;

}
void cHash::RemoveItem(cString Name,int id)
{
	for (DWORD i=0;i<nItems;i++)
	{
		if (*HashArray[i].Name == Name)
		{
			if (id == 0)
			{
				RemoveItem(i);
				return;
			}
			id--;
		}
	}
}

void cHash::ClearItems()
{
	nItems = 0;
	free(HashArray);
}
cString cHash::GetValue(cString Name,int id)
{
	for (DWORD i=0;i<nItems;i++)
	{
		if (*HashArray[i].Name == Name)
		{
			if (id == 0)return *HashArray[i].Value;
			id--;
		}
	}
	return * new cString("");
}
cString cHash::operator[](cString Name)
{
	return GetValue(Name);
}

cString cHash::operator[](DWORD id)
{
	if (id < nItems)return *HashArray[id].Value;
	return cString("");
}

cString cHash::GetKey(DWORD id)
{
	if (id < nItems)return *HashArray[id].Name;
	return cString("");
}
cString cHash::GetValue(DWORD id)
{
	if (id < nItems)return *HashArray[id].Value;
	return cString("");
}
bool cHash::IsFound(cString Name)
{
	for (DWORD i=0;i<nItems;i++)
	{
		if (*HashArray[i].Name == Name)return true;
	}
	return false;
}

DWORD cHash::GetNumberOfItems()
{
	return nItems;
}

DWORD cHash::GetNumberOfItems(cString Name)
{
	int nThisItem = 0;
	for (DWORD i=0; i < nItems; i++)
	{
		if (*HashArray[i].Name == Name)nThisItem++;
	}
	return nThisItem;
}

void cHash::SetSerialize(cXMLHash& XMLParams)
{
	for(DWORD i = 0;i< nItems;i++)
	{
		XMLParams.AddText(*HashArray[i].Name,*HashArray[i].Value);
	}
}
void cHash::GetSerialize(cXMLHash& XMLParams)
{
	cout << XMLParams.GetText(0) << "\n";
	for(DWORD i = 0;i< XMLParams.GetNumberOfItems();i++)
	{
		cout << "The New Value : " << XMLParams.GetText(i) << "\n";
		AddItem(XMLParams.GetKey(i),XMLParams.GetText(i));
	}
	cout << "Here :)\n";
}

void cXMLHash::AddXML(cString Name,cString XMLItem)
{
	AddItem(Name,XMLItem);
}

void cXMLHash::AddText(cString Name,cString str)
{
	AddItem(Name,(char*)cXMLEncodedString(str));
}

void cXMLHash::AddBinary(cString Name,char *buff, DWORD length)
{
	AddItem(Name,(char*)cBase64String(buff,length));
}

cString cXMLHash::GetXML(cString Name,int id)
{
	return GetValue(Name,id);
}
cString cXMLHash::GetText(cString Name,int id)
{
	DWORD len = 0;
	cXMLEncodedString EncodedStr;
	EncodedStr.SetEncoded(GetValue(Name,id));
	return EncodedStr.Decode(len);
}
cString cXMLHash::GetBinary(cString Name,DWORD &len,int id)
{
	cBase64String EncodedStr;
	EncodedStr.SetEncoded(GetValue(Name,id));
	return EncodedStr.Decode(len);
}
cString cXMLHash::GetXML(int id)
{
	return GetValue(id);
}
cString cXMLHash::GetText(int id)
{
	DWORD len = 0;
	cXMLEncodedString EncodedStr;
	EncodedStr.SetEncoded(GetValue(id));
	return EncodedStr.Decode(len);
}
cString cXMLHash::GetBinary(int id,DWORD &len)
{
	cBase64String EncodedStr;
	EncodedStr.SetEncoded(GetValue(id));
	return EncodedStr.Decode(len);
}