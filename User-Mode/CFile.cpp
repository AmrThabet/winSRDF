#include "stdafx.h"
#include "SRDF.h"

using namespace Security::Elements::Files;

cFile::cFile(char* szFilename)
{

    hFile = CreateFileA(szFilename,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
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
	return;
}

cFile::~cFile()
{
	if (BaseAddress != NULL)
	{
		UnmapViewOfFile((LPVOID)BaseAddress);
		CloseHandle(hMapping);
		CloseHandle(hFile);
	}
}