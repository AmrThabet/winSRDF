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
	FindFiles(DirectoryName);
}

void cRecursiveScanner::FindFiles(cString wrkdir)
{
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
				if (DirectoryCallback(wrkdir + "\\" + file_data.cFileName))
				{
					nDirectories++;
					FindFiles(wrkdir + "\\" + file_data.cFileName);
					//cout << "Exiting The FindFiles\n\n";
				}
		}
		else 
		{
			
			if	(strcmp(file_data.cFileName, ".") != 0 && 
				strcmp(file_data.cFileName, "..") != 0)
			{
				nFiles++;
				FileCallback(file_data.cFileName,wrkdir + "\\" + file_data.cFileName);
			}
		}
        while( FindNextFile( fHandle, &file_data ) ) 
        {
                if( file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                    strcmp(file_data.cFileName, ".") != 0 && 
                    strcmp(file_data.cFileName, "..") != 0 )
                {
						if (DirectoryCallback(wrkdir + "\\" + file_data.cFileName))
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
						FileCallback(file_data.cFileName,wrkdir + "\\" + file_data.cFileName);
					}
				}
        }
    }

}


bool cRecursiveScanner::DirectoryCallback(cString DirName)
{
	
	return true;
}

void cRecursiveScanner::FileCallback(cString Filename,cString FullName)
{
	//cout << Filename << "\n";
	
}