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