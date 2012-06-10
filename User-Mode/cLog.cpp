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
	LogFile << tm->tm_year << '/' << tm->tm_mon << '/' << tm->tm_mday
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