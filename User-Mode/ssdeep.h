#pragma once
using namespace Security::Elements::String;
using namespace Security::Libraries::Malware::OS::Win32::Scanning;


class DLLIMPORT Security::Libraries::Malware::OS::Win32::Scanning::ssdeep
{
	
	int count;
	
public:
	static const int Max_Result=116;
	ssdeep(void);
	~ssdeep(void);
	static int ssdeepcompare(const char *sig1, const char *sig2);
	static int ssdeepScan_Buf(const unsigned char *buf,  DWORD  buf_len, char  *result);
	static int ssdeepScan_Handle(FILE *handle,char *result);
	static int ssdeepScan_FileName(const char * filename,char * result);

	
};
