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

using namespace Security::Targets::Files;

cFile::cFile(char* szFilename)
{
	isFound = FALSE;
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
        return;
    }
    BaseAddress = (unsigned long) MapViewOfFile(hMapping,
                                                FILE_MAP_READ,
                                                0,
                                                0,
                                                0);
    if (hMapping == 0)
	{
        UnmapViewOfFile(hMapping);
        CloseHandle(hFile);
		BaseAddress = NULL;
		FileLength = NULL;
        return;
    }
    FileLength  = (DWORD) GetFileSize(hFile,NULL);
	IsFile = TRUE;
	isFound = TRUE;
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
	if (BaseAddress != NULL && IsFile)
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