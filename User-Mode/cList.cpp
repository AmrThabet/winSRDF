/*
 *
 *  Copyright (C) 2011-2012 Ghareeb Saad El-Deen
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


cList::cList()
{
	nItems = 0;
}
cList::cList(int size)
{
	nItems = 0;
	Ssize = size;
};

cList::~cList()
{
	if (nItems > 0)
	{
		nItems = 0;
		free(head);
	}
};

      
void cList::AddItem(char* item)
{
	if (nItems == 0)
	{
		head = (char*)malloc(Ssize+1);
        memset(head,0,Ssize);
		memcpy(head,item,Ssize);
	
		nItems = 1;
	}
	else
	{
		char* NewArray = (char*)malloc(Ssize*(nItems+1));
		memset(NewArray,0,Ssize*(nItems+1));
		memcpy(NewArray,head,Ssize*(nItems));
		memset(&NewArray[nItems*Ssize],0,Ssize);
		memcpy(&NewArray[nItems*Ssize],item,Ssize);
		nItems++;
		free(head);
		head = NewArray;
	}
}

DWORD cList::GetNumberOfItems()
{
	return nItems;
}

char* cList::GetItem(int index)
{
	if(nItems > 0 && (index < nItems))
	{
		return &head[index*Ssize];
	}
	return NULL;
}

char* cList::GetLastItem()
{
	if(nItems>0)
		return &head[(nItems-1)*Ssize];
	return NULL;
}

void cList::SetSize(int size)
{
	Ssize = size;
}
int cList::GetSize()
{
	return Ssize;
}
char* cList::operator[](int index)
{
	return GetItem(index);
}
void cList::SetSerialize(cXMLHash& XMLParams)
{
	XMLParams.AddText("nItems",nItems);
	XMLParams.AddText("Ssize",cString(Ssize));
	XMLParams.AddBinary("Data",head,nItems*Ssize);
}
void cList::GetSerialize(cXMLHash& XMLParams)
{
	DWORD length = 0;
	nItems = atoi(XMLParams.GetText("nItems"));
	Ssize = atoi(XMLParams.GetText("Ssize"));
	head = XMLParams.GetBinary("Data",length);
}