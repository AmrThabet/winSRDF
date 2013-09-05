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
#include < conio.h >

using namespace Security::Targets::Files;

cFile::cFile(char* szFilename)
{
	isFound = FALSE;
	BaseAddress = NULL;
	FILETIME ftCreation, ftLastaccess, ftLastwrite;
    SYSTEMTIME stCreation, stLastaccess, stLastwrite;

	if (szFilename == NULL)return;
	char* buff = (char*)malloc(MAX_PATH);
	memset(buff,0,MAX_PATH);
	DWORD Length = 0;
	if (Length = ExpandEnvironmentStrings(szFilename,buff,MAX_PATH) > MAX_PATH)
	{
		buff = (char*)realloc(buff,Length);
		memset(buff,0,Length);
		ExpandEnvironmentStrings(szFilename,buff,MAX_PATH);
	}
	szFilename = buff;
	Attributes = GetFileAttributes(szFilename);
	if (Attributes == INVALID_FILE_ATTRIBUTES)return;

    hFile = CreateFileA(szFilename,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        0);
    if (hFile == INVALID_HANDLE_VALUE)
	{
        BaseAddress = NULL;
		FileLength = NULL;
		free(buff);
		return;
    }

	if (GetFileTime(hFile, &ftCreation, &ftLastaccess, &ftLastwrite)
        && FileTimeToSystemTime(&ftCreation, &stCreation)
        && FileTimeToSystemTime(&ftLastaccess, &stLastaccess)
        && FileTimeToSystemTime(&ftLastwrite, &stLastwrite)) 
    {
		CreatedTime.Year = stCreation.wYear;
		CreatedTime.Month = stCreation.wMonth;
		CreatedTime.Day = stCreation.wDay;
		CreatedTime.Hour = stCreation.wHour;
		CreatedTime.Min = stCreation.wMonth;
		CreatedTime.Sec = stCreation.wSecond;

		AccessedTime.Year = stLastaccess.wYear;
		AccessedTime.Month = stLastaccess.wMonth;
		AccessedTime.Day = stLastaccess.wDay;
		AccessedTime.Hour = stLastaccess.wHour;
		AccessedTime.Min = stLastaccess.wMonth;
		AccessedTime.Sec = stLastaccess.wSecond;

		ModifiedTime.Year = stLastwrite.wYear;
		ModifiedTime.Month = stLastwrite.wMonth;
		ModifiedTime.Day = stLastwrite.wDay;
		ModifiedTime.Hour = stLastwrite.wHour;
		ModifiedTime.Min = stLastwrite.wMonth;
		ModifiedTime.Sec = stLastwrite.wSecond;

    }
	else
    {
        BaseAddress = NULL;
		FileLength = NULL;
		free(buff);
		return;
    }

    hMapping = CreateFileMappingW(hFile,
                                  NULL,
                                  PAGE_READONLY,
                                  0,
                                  0,
                                  NULL);
    if (hMapping == 0)
	{
        CloseHandle(hFile);
		BaseAddress = NULL;
		FileLength = NULL;
		free(buff);
        return;
    }
    BaseAddress = (unsigned long) MapViewOfFile(hMapping,
                                                FILE_MAP_READ,
                                                0,
                                                0,
                                                0);
    if (BaseAddress == 0)
	{
        UnmapViewOfFile(hMapping);
        CloseHandle(hFile);
		BaseAddress = NULL;
		FileLength = NULL;
		free(buff);
        return;
    }

    FileLength  = (DWORD) GetFileSize(hFile,NULL);
	IsFile = TRUE;
	isFound = TRUE;
	free(buff);
	return;
}
cFile::cFile(char* buffer,DWORD size)
{
	BaseAddress = (DWORD)buffer;
	FileLength = size;
	Attributes = NULL;
	Filename = NULL;
	IsFile = FALSE;
	isFound = TRUE;
}
cFile::~cFile()
{
	if (BaseAddress != NULL && IsFile && isFound)
	{
		UnmapViewOfFile((LPVOID)BaseAddress);
		CloseHandle(hMapping);
		CloseHandle(hFile);
	}
}

BOOL cFile::IsFound()
{
	return isFound;
}