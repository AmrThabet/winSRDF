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
#include <fstream>
#include <time.h>
#include <iostream>
using namespace std;
using namespace Security::Elements::String;
using namespace Security::Storage::Files;


cLog::cLog(cString LogName,cString Filename)
{
	
	LogFile.open((char*)Filename,ios::app);
	if (LogFile.is_open())
	 {
		isFound = true;
	 }
	 else
	 {
		isFound = false;
		return;
	 }
	time_t now = time(0);
	struct tm* tm = localtime(&now);
	LogFile << tm->tm_mday << '/' << tm->tm_mon << '/' << (1900 + tm->tm_year)
         << ' ' << tm->tm_hour << ':' << tm->tm_min << ':' << tm->tm_sec << ": ";
	cString msg = "LogFile : ";
	msg += LogName + " Opened";
	LogFile << (char*)msg << "\n";
}
cLog::~cLog()
{
	LogFile.close();
}

void cLog::WriteToLog(cString szText)
{
	if(!isFound)return;
    time_t now = time(0);
    struct tm* tm = localtime(&now);
    LogFile << tm->tm_year << '/' << tm->tm_mon << '/' << tm->tm_mday
         << ' ' << tm->tm_hour << ':' << tm->tm_min << ':' << tm->tm_sec << ": ";
    LogFile << (char*)szText << "\n";
}
bool cLog::IsFound()
{
	return isFound;
}