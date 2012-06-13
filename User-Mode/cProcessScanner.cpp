#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <tchar.h>
#include "SRDF.h"

using namespace std;
using namespace Security::Elements::String;
using namespace Security::Storage::Files;
using namespace Security::Libraries::Malware::OS::Win32::Scanning;

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