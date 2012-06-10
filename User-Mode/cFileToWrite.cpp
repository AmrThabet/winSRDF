#include "stdafx.h"
#include "SRDF.h"
#include <cstdlib>
#include <fstream>

using namespace std;
using namespace Security::Storage::Files;
using namespace Security::Elements::String;

cFileToWrite::cFileToWrite(cString szFilename, bool Append)
{
	Filename = szFilename;

	if(Append) hFile.open((char*)Filename,ios::out | ios::app | ios::binary);
	else hFile.open((char*)Filename,ios::out | ios::binary);

	if (hFile.is_open())
	 {
		isFound = true;
	 }
	 else
	 {
		isFound = false;
		return;
	 }
}

cFileToWrite::~cFileToWrite()
{
	hFile.close();
}

void cFileToWrite::write(char *buffer, DWORD length)
{
	hFile.write( buffer, length );
}

bool cFileToWrite::IsFound()
{
	return isFound;
}