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
cString cHash::GetItem(cString Name,int id)
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
	return GetItem(Name);
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

int cHash::GetNumberOfItems(cString Name)
{
	int nThisItem = 0;
	for (DWORD i=0; i < nItems; i++)
	{
		if (*HashArray[i].Name == Name)nThisItem++;
	}
	return nThisItem;
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