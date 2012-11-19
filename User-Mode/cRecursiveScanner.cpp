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

#include "StdAfx.h"
#include "SRDF.h"
#include <iostream>

using namespace std;
using namespace Security::Elements::String;
using namespace Security::Libraries::Malware::OS::Win32::Scanning;

cRecursiveScanner::cRecursiveScanner()
{
	nDirectories = 0;
	nFiles = 0;
}

cRecursiveScanner::~cRecursiveScanner()
{

}

cHash* cRecursiveScanner::GetDrives()
{
	char* buff = (char*)malloc(200);
	memset(buff,0,200);
	cHash* DriveHash = new cHash();
	DWORD nLength = GetLogicalDriveStrings(200,(LPSTR)buff);
	if (nLength > 195)
	{
		char* buff = (char*)malloc(nLength+5);
		memset(buff,0,nLength+5);
		GetLogicalDriveStrings(nLength+5,(LPSTR)buff);
		
	}
	cString str;
	int i =0;
	while(buff[i] != 0)
	{
		buff[2] = 0;
		str = buff;
		switch (GetDriveType((LPSTR)str.GetChar()))
		{
		case DRIVE_FIXED:
				DriveHash->AddItem(str,"HardDrive");
				break;
			case DRIVE_REMOVABLE:
				DriveHash->AddItem(str,"RemovableMedia");
				break;
			case DRIVE_REMOTE:
				DriveHash->AddItem(str,"NetworkDrive");
				break;
			case DRIVE_CDROM:
				DriveHash->AddItem(str,"CDROM");
				break;
			default:
				DriveHash->AddItem(str,"Unknown");
				break;
		}
		buff+=4;
	}

	return DriveHash;
}
void cRecursiveScanner::Scan(cString DirectoryName)
{
	char* buff = (char*)malloc(MAX_PATH);
	memset(buff,0,MAX_PATH);
	DWORD Length = 0;
	if (Length = ExpandEnvironmentStrings(DirectoryName,buff,MAX_PATH) > MAX_PATH)
	{
		char* buff = (char*)malloc(Length);
		memset(buff,0,Length);
		ExpandEnvironmentStrings(DirectoryName,buff,MAX_PATH);
	}
	DirectoryName = buff;
	Level = 0;
	FindFiles(DirectoryName);
}

void cRecursiveScanner::FindFiles(cString wrkdir)
{
	Level++;
    cString temp;
	HANDLE fHandle;
    temp = wrkdir + "\\" + "*";
    fHandle = FindFirstFile( temp, &file_data );

    if( fHandle == INVALID_HANDLE_VALUE )
    {
         return;
    }
    else 
    { 
		if( file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                    strcmp(file_data.cFileName, ".") != 0 && 
                    strcmp(file_data.cFileName, "..") != 0 )
                
		{
				if (DirectoryCallback(file_data.cFileName,wrkdir + "\\" + file_data.cFileName,Level))
				{
					nDirectories++;
					FindFiles(wrkdir + "\\" + file_data.cFileName);
				}
		}
		else 
		{
			
			if	(strcmp(file_data.cFileName, ".") != 0 && 
				strcmp(file_data.cFileName, "..") != 0)
			{
				nFiles++;
				FileCallback(file_data.cFileName,wrkdir + "\\" + file_data.cFileName, Level);
			}
		}
        while( FindNextFile( fHandle, &file_data ) ) 
        {
                if( file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                    strcmp(file_data.cFileName, ".") != 0 && 
                    strcmp(file_data.cFileName, "..") != 0 )
                {
						if (DirectoryCallback(file_data.cFileName,wrkdir + "\\" + file_data.cFileName,Level))
						{
							nDirectories++;
							FindFiles(wrkdir + "\\" + file_data.cFileName);
						}
                }
                else 
				{
					if	(strcmp(file_data.cFileName, ".") != 0 && 
						 strcmp(file_data.cFileName, "..") != 0)
					{
						nFiles++;
						FileCallback(file_data.cFileName,wrkdir + "\\" + file_data.cFileName,Level);
					}
				}
        }
    }
	Level--;
}


bool cRecursiveScanner::DirectoryCallback(cString DirName,cString FullName,int Level)
{
	
	return true;
}

void cRecursiveScanner::FileCallback(cString Filename,cString FullName,int Level)
{

}