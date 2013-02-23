/*
 *
 *  Copyright (C) 2011-2012 Mohamed Abdl Latief <Mohamed.AbdlLatief[at]gmail.com>
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
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <tchar.h>
#include "SRDF.h"

using namespace std;
using namespace Security::Elements::String;
using namespace Security::Storage::Files;
using namespace Security::Libraries::Malware::OS::Win32::Enumeration;

bool cProcessScanner::IsSuccess()
{
	return isSuccess;
}

cProcessScanner::cProcessScanner(cLog* logObj)
{
		 HANDLE hProcessSnap;
		 PROCESSENTRY32 pe32;
		 
		 //cLog logObj("Logging cProcessTest","C:\\Documents and Settings\\Administrator\\My Documents\\Visual Studio 2008\\Projects\\SRDF\\cProcessTestLog.txt");
 	
   		 hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		 if( hProcessSnap == INVALID_HANDLE_VALUE )
		{
			
			isSuccess=false;
			if (logObj==NULL)
				logObj->WriteToLog("CreateToolhelp32Snapshot (of processes)");
		}
			
		 pe32.dwSize = sizeof( PROCESSENTRY32 );

		if( !Process32First( hProcessSnap, &pe32 ) )
		{
			isSuccess=false;
			if (logObj==NULL)
				logObj->WriteToLog("Process32First");
			CloseHandle( hProcessSnap );          
			
		}
		
		ProcessList.AddItem((cString)pe32.szExeFile,(cString)pe32.th32ProcessID);


		while( Process32Next( hProcessSnap, &pe32 ))
		{
			ProcessList.AddItem((cString)pe32.szExeFile,(cString)pe32.th32ProcessID);		
			
		}

		CloseHandle( hProcessSnap );
		isSuccess = true;
}