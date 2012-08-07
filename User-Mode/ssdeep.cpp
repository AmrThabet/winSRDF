#include "StdAfx.h"
#include "ssdeep/main.h"


#include "SRDF.h"
#include <iostream>
using namespace Security::Elements::String;
using namespace Security::Libraries::Malware::OS::Win32::Scanning;



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

//return zero if succsed and non-zero if error
int SSDeep::ScanBuffer(const unsigned char *buf,  DWORD  buf_len, char  *result)
{
	 return fuzzy_hash_buf(buf,buf_len,result);
}

//return zero if succsed and non-zero if error
int SSDeep::ScanHandle(FILE *handle,char *result)
{
	return fuzzy_hash_file(handle,result);
}

//return zero if succsed and non-zero if error
int SSDeep::ScanFileName(const char * filename,char * result)
{
	return fuzzy_hash_filename(filename,result);
}