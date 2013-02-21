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

#pragma once
#include "yara.h"

#define RULE_ALL_OF_THEM	1
#define RULE_ANY_OF_THEM	0
typedef struct _MSTRING
{
	int             flags;
    char*           identifier;
    unsigned int    length;
    unsigned char*  string;

    size_t          offset;
    unsigned char*  data;
    unsigned int    mlength;
   

}MSTRING;
typedef struct _YARA_RESULT
{ 
	char*           RuleIdentifier;
	cList*			Matches;
     
} YARA_RESULT;

using namespace Security::Elements::String;
using namespace Security::Libraries::Malware::OS::Win32::Static;

class DLLIMPORT Security::Libraries::Malware::OS::Win32::Static::cYaraScanner
{
	YARA_CONTEXT* YContext;
	
public:

	cList* Results;
	cYaraScanner(void);
	void FreeResults(void);
	int AddRule(cString rule);
	cList* Scan(unsigned char* buffer,DWORD buffer_size);
	cList* Scan(Security::Targets::Memory::cProcess* Process);
	int ScannerCallback(RULE* rule);
	char* CreatRule(cString name,cList strings,cString condition);
	char* CreatRule(cString name,cList strings,int condition);
	char* CreatRule(cString name,cString strings,int condition);
	char* GetLastError();
	~cYaraScanner(void);
};
