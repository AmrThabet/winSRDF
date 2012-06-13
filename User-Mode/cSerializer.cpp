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
using namespace Security::Storage::Databases;

cString cSerializer::Serialize()
{
	cXMLHash XMLParams;
	SetSerialize(XMLParams);
	cString XML = "";
	for(DWORD i = 0;i < XMLParams.nItems; i++)
	{
		XML << "\n<" << (char*)XMLParams.GetKey(i) << ">";
		XML<< XMLParams[i];
		XML<< "</" << (char*)XMLParams.GetKey(i) << ">";
	}
	cout << (char*)XML << "\n";
	return XML;
}

void cSerializer::Deserialize(cString XMLDocument)
{
	cXMLHash XMLParams;
	int i = 0;
	cString Key;
	cString CheckKey;		//To check the begining and the end if identical <X> </X>
	cString Value;
	while(XMLDocument[i] != '\0')
	{
		if(XMLDocument[i] == ' ' || XMLDocument[i] == '\n')
		{
			i++;
			continue;
		}
		if(XMLDocument[i] == '<' && XMLDocument[i+1] != '/')
		{
			i++;
			int KeyBegin = i;
			//Search for '>' to get the key
			while(1)
			{
				if (XMLDocument[i] == '>')break;
				if (XMLDocument[i] == '\0')goto FINISH;
				i++;
			}
			Key.Substr(XMLDocument,KeyBegin,i-KeyBegin);
			cout << "Key = " << (char*)Key << "\n";
			i++;
			int ValueBegin = i;
			i = SkipInside(XMLDocument,i);
			Value.Substr(XMLDocument,ValueBegin,i-ValueBegin);
			cout << "Value = " << (char*)Value << "\n";;
			if(XMLDocument[i] == '<' && XMLDocument[i+1] == '/')
			{
				i+=2;				//Skip The "</"
				int CheckKeyBegin = i;
				//Search for '>' to get the key
				while(1)
				{
					if (XMLDocument[i] == '>')break;
					if (XMLDocument[i] == '\0')goto FINISH;
					i++;
				}
				CheckKey.Substr(XMLDocument,CheckKeyBegin,i-CheckKeyBegin);
				cout << "CheckKey = " << (char*)CheckKey << "\n\n";
				XMLParams.AddItem(Key,Value);
				if (Key != CheckKey)return;
				i++;
			}else return;
			
		}
		else return;
	}
FINISH:
	GetSerialize(XMLParams);
	cout << "Here 2 :) :)\n";
}

DWORD cSerializer::SkipInside(cString XMLDocument,int offset)
{
	int i = offset;
	while(XMLDocument[i] != '\0')
	{
		if(XMLDocument[i] == '<' && XMLDocument[i+1] != '/')
		{
			i++;
			while(1)
			{
				if(XMLDocument[i] == '\0')return i-1;
				if(XMLDocument[i] == '>')break;
				i++;
			}
			cout << i << "\n";
			i = SkipInside(XMLDocument,i);
			if(XMLDocument[i] == '<' && XMLDocument[i+1] == '/')
			{
				i+=2;
				while(1)
				{
					if(XMLDocument[i] == '\0')return i-1;
					if(XMLDocument[i] == '>')break;
					i++;
				}	
			}
			i++;
			continue;
		}
		if(XMLDocument[i] == '<' && XMLDocument[i+1] == '/')
		{
			return i;
		}
		i++;
	}
	return i-1;
}

void cSerializer::SetSerialize(cXMLHash& XMLParams)
{
	cout << "Error Inside !!!\n";
}

void cSerializer::GetSerialize(cXMLHash& XMLParams)
{
	cout << "Error Inside !!!\n";
}

