#include "StdAfx.h"
#include "ssdeep/main.h"


#include "SRDF.h"
#include <iostream>
using namespace Security::Elements::String;
using namespace Security::Libraries::Malware::OS::Win32::Static;


SSDeep::SSDeep(void)
{
	
}

SSDeep::~SSDeep(void)
{

}
//return a value from 0 to 100 representing the match and -1 if error
int SSDeep::Compare(const char *sig1, const char *sig2)
{

	return fuzzy_compare(sig1,sig2);
}

cString SSDeep::Hash(const unsigned char *buffer,  DWORD  size)
{
	char* result = (char*)malloc(Max_Result);
	memset(result,0,Max_Result);
	if (fuzzy_hash_buf(buffer,size,result) ==0 )
	{
		cString Result = result;
		free(result);
		return Result;
	}
	free(result);
	return "";
}

cString SSDeep::Hash(const char * filename)
{
	char* result = (char*)malloc(Max_Result);
	memset(result,0,Max_Result);
	if (fuzzy_hash_filename(filename,result) ==0 )
	{
	cString Result = result;
		free(result);
		return Result;
	}
	free(result);
	return "";
}