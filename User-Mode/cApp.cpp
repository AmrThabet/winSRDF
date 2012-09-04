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
using namespace Security::Core;
using namespace Security::Elements::String;
using namespace Security::Storage::Files;
using namespace Security::Storage::Databases;
cApp::cApp(cString AppName)
{
	this->AppName = AppName;
	char* lpBuffer = (char*)malloc(MAX_PATH);
	GetCurrentDirectory(MAX_PATH , lpBuffer);
	AppPath = lpBuffer;
	Log = NULL;
	optind = 0;
	optarg = NULL;
	SetDefaultSettings();
}
cApp::~cApp()
{
	if (Flags & APP_NOANOTHERINSTANCE) InstanceMutex.release();
	if (Log != NULL) delete Log; 
}
cString cApp::GetApplicationFilename()
{
	char buff[MAX_PATH];
	DWORD nSize = MAX_PATH;
	DWORD NewSize = 0;
	if (NewSize = GetModuleFileName(0,buff,nSize) > nSize)
	{
			NewSize++;
			char* Filename= (char*)malloc(NewSize);
			memset(Filename,0,NewSize);
			GetModuleFileName(0,Filename,NewSize);
			return cString(Filename);
	};
	return buff;
}
cString cApp::GetApplicationPath()
{
	return AppPath;
}
///////////////////////////////////////////////////////////////////////////////
// XGetopt.cpp  Version 1.2
//
// Author:  Hans Dietrich
//          hdietrich2@hotmail.com
//
// Description:
//     XGetopt.cpp implements getopt(), a function to parse command lines.
//
// History
//     Version 1.2 - 2003 May 17
//     - Added Unicode support
//
//     Version 1.1 - 2002 March 10
//     - Added example to XGetopt.cpp module header 
//
// This software is released into the public domain.
// You are free to use it in any way you like.
//
// This software is provided "as is" with no expressed
// or implied warranty.  I accept no liability for any
// damage or loss of business that this software may cause.
//
///////////////////////////////////////////////////////////////////////////////

int cApp::getopt(int argc, char *argv[], char *optstring)
{
	static char *next = NULL;
	if (optind == 0)
		next = NULL;

	optarg = NULL;
	
	if (next == NULL || *next == '\0')
	{
		if (optind == 0)
			optind++;
		if (optind == argc)return EOF;
		if (optind > argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
		{
			
			optarg = NULL;
			if (optind < argc)
				optarg = argv[optind];
			
			return EOF;
		}
		if (strcmp(argv[optind], "--") == 0)
		{
			optind++;
			optarg = NULL;
			if (optind < argc)
				optarg = argv[optind];
			return EOF;
		}
		next = argv[optind];
		next++;		// skip past -
		optind++;
	}
	char c = *next++;
	char *cp = strchr(optstring, c);
	if (cp == NULL || c == ':')
		return '?';
	cp++;
	if (*cp == ':')
	{
		if (*next != '\0')
		{
			optarg = next;
			next = NULL;
		}

		else if (optind < argc)
		{
			optarg = argv[optind];
			optind++;
		}
		else
		{
			return '?';
		}
	}
	return c;
}
//////////////////////////////////////////////////////////////////////////////////////
void cApp::SetDefaultSettings()
{
	Flags |= (APP_NOANOTHERINSTANCE | APP_ADDLOG | APP_REGISTRYSETTINGS | APP_DEFINEDATABASE);
	Options = "a:bcCdef";
	LogFilename = AppPath;
	LogFilename += "\\LogFile.txt";
	RegistryPath = "Software\\";
	RegistryPath += AppName;
	RegistryType = HKEY_CURRENT_USER;
}
void cApp::SetCustomSettings()
{
	
}
void cApp::Initialize(int argc, char *argv[])
{
	if (Flags & APP_NOANOTHERINSTANCE)
	{
		if (!InstanceMutex.create(AppName))ExitProcess(0);
	}
	GetRequest(argc,argv);
	if (Flags & APP_ADDLOG)
	{
		Log = new cLog(AppName,LogFilename);
	}
	if (Flags & APP_REGISTRYSETTINGS)Settings.Initialize(RegistryType,RegistryPath,true);
	if (Flags & APP_DEFINEDATABASE)
	{
		Database = new cSQLiteDatabase(AppName+".db");
	}
}
void cApp::GetRequest(int argc, char *argv[])
{
	char c;
	while ((c = getopt(argc, argv, Options)) != EOF)
	{
		if (optarg != NULL)
		{
			Request.AddItem(cString(&c),optarg);
		}
		else Request.AddItem(cString(&c),"");
	}
	cString LastArg = "";
	if (optind < argc)
	{
		while (optind < argc)
		{
			LastArg += argv[optind];
			optind++;
		}
	}
}