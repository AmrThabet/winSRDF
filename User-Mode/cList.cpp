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



cList::cList(int size)
{
	nItems=0;
	Ssize=size;
};

cList::~cList()
{

	if(nItems>0)
	{
	nItems=0;
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

/*
cString cHash::operator[](cString Name)
{
	for (DWORD i=0;i<nItems;i++)
	{
		if (*HashArray[i].Name == Name)return *HashArray[i].Value;
	}
	return * new cString("");
}
*/

/*
bool cHash::IsFound(cString Name)
{
	for (DWORD i=0;i<nItems;i++)
	{
		if (*HashArray[i].Name == Name)return true;
	}
	return false;
}
*/

DWORD cList::GetNumberOfItems()
{
	return nItems;
}

char* cList::GetItem(int index)
{
	if(nItems>0)
	return &head[index*Ssize];
	return NULL;
}

char* cList::GetLastItem()
{
	if(nItems>0)
	return &head[(nItems-1)*Ssize];
	return NULL;
}