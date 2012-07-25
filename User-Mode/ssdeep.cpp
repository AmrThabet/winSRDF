#include "StdAfx.h"
#include "ssdeep/main.h"


#include "SRDF.h"
#include <iostream>
using namespace Security::Elements::String;
using namespace Security::Libraries::Malware::OS::Win32::Scanning;



ssdeep::ssdeep(void)
{
	
}

ssdeep::~ssdeep(void)
{
}
//return a value from 0 to 100 representing the match and -1 if error
 int ssdeep::ssdeepcompare(const char *sig1, const char *sig2){
	 int x;
	
	x=fuzzy_compare(sig1,sig2);
	 return x;
 }

//return zero if succsed and non-zero if error
 int ssdeep::ssdeepScan_Buf(const unsigned char *buf,  DWORD  buf_len, char  *result)
 {
	 int x;
	 x=fuzzy_hash_buf(buf,buf_len,result);
	 return x;
 }
//return zero if succsed and non-zero if error
 int ssdeep::ssdeepScan_Handle(FILE *handle,char *result){
	 int x;
	 x=fuzzy_hash_file(handle,result);
	 return 0;
 }
 //return zero if succsed and non-zero if error
 int ssdeep::ssdeepScan_FileName(const char * filename,char * result){
	 int x;
	 x=fuzzy_hash_filename(filename,result);
	 return 0;
 }