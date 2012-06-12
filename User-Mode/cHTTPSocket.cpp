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
#include "winInet.h"
#include <iostream>

using namespace std;
using namespace Security::Elements::String;
using namespace Security::Connections::Internet;

bool cHTTPSocket::open(cString URL,INTERNET_PORT Port)
{
	hINet = InternetOpen("InetURL/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0 );
	if ( !hINet )
	{
		//Afx//MessageBox("InternetOpen Failed");
		return FALSE;
	}
	hConnection = InternetConnect(hINet,URL, Port, " "," ", INTERNET_SERVICE_HTTP, 0, 0 );
	if ( !hConnection )
	{
		InternetCloseHandle(hINet);
		return FALSE;
	}
	return TRUE;
}

void cHTTPSocket::close()
{
	if (hConnection != NULL) InternetCloseHandle(hConnection);
	if (hINet != NULL) InternetCloseHandle(hINet);
}

bool cHTTPSocket::SendRequest(cString Request)
{
	HINTERNET hData = HttpOpenRequest( hConnection, "GET", Request, NULL, NULL, NULL, INTERNET_FLAG_KEEP_CONNECTION, 0 );
	if ( !hData )
	{
		return FALSE;
	}
	HttpSendRequest( hData, NULL, 0, NULL, 0);
	InternetCloseHandle(hData);
	return TRUE;
}

bool cHTTPSocket::DownloadFile(cString Request,cString Filename)
{
	HINTERNET hData = HttpOpenRequest( hConnection, "GET", Request, NULL, NULL, NULL, INTERNET_FLAG_KEEP_CONNECTION, 0 );
	if ( !hData )
	{
		return FALSE;
	}
	HttpSendRequest( hData, NULL, 0, NULL, 0);

	HANDLE sFile = CreateFile(Filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
	
	// make sure that our file handle is valid
	if (sFile < (HANDLE)1)
	{
		InternetCloseHandle(hData);
		return FALSE;
	}
	DWORD ReadSize;
	int total = 1;
	DWORD d;
	char buffer[255];
	do
	{
		memset(buffer, 0, 255);
		InternetReadFile( hData, buffer, 255, &ReadSize);
		WriteFile(sFile, buffer, ReadSize, &d, NULL);
		total = total + ReadSize;
	} while (ReadSize > 0);

	CloseHandle(sFile);
	InternetCloseHandle(hData);
	return TRUE;
}

/*
BOOL GetFile(LPSTR url,LPSTR request,LPSTR filename)
{
	HINTERNET hINet, hConnection, hData;
	CHAR buffer[2048] ; 
	LPSTR m_strContents ;
	DWORD dwRead, dwFlags, dwStatus ;
	hINet = InternetOpen("InetURL/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0 );
	if ( !hINet )
	{
		//Afx//MessageBox("InternetOpen Failed");
		return FALSE;
	}
	try 
	{
		hConnection = InternetConnect(hINet,url, 80, " "," ", INTERNET_SERVICE_HTTP, 0, 0 );
		if ( !hConnection )
		{
			InternetCloseHandle(hINet);
			return FALSE;
		}
		// Get data
		hData = HttpOpenRequest( hConnection, "GET", request, NULL, NULL, NULL, INTERNET_FLAG_KEEP_CONNECTION, 0 );
		if ( !hData )
		{
			InternetCloseHandle(hConnection);
			InternetCloseHandle(hINet);
			return FALSE;
		}
		HttpSendRequest( hData, NULL, 0, NULL, 0);
		//Added Code

		if (filename == NULL)
		{
			InternetCloseHandle(hConnection);
			InternetCloseHandle(hINet);
			InternetCloseHandle(hData);
			return TRUE;
		}
		HANDLE sFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, 0);
		
		// make sure that our file handle is valid
		if (sFile < (HANDLE)1)
		{
			InternetCloseHandle(hConnection);
			InternetCloseHandle(hINet);
			InternetCloseHandle(hData);
			return FALSE;
		}
		DWORD ReadSize;
		int total = 1;
		DWORD d;
		do
		{
			memset(buffer, 0, 255);
			InternetReadFile( hData, buffer, 255, &ReadSize);
			WriteFile(sFile, buffer, ReadSize, &d, NULL);
			total = total + ReadSize;
		} while (ReadSize > 0);

		CloseHandle(sFile);
	}catch(...)
	{

	}
	
	InternetCloseHandle(hConnection);
	InternetCloseHandle(hINet);
	InternetCloseHandle(hData);
	return TRUE;
}
*/