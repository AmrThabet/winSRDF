#pragma once
#include "yara.h"

#define RULE_ALL_OF_THEM	1
#define RULE_ANY_OF_THEM	0
typedef struct _MSTRING
{
	int             flags;
    char*           identifier;
    unsigned int    length;
    unsigned char*  string;

    size_t          offset;
    unsigned char*  data;
    unsigned int    mlength;
   

}MSTRING;
typedef struct _YARA_RESULT
{ 
	char*           RuleIdentifier;
	cList*			Matches;
     
} YARA_RESULT;

using namespace Security::Elements::String;
using namespace Security::Libraries::Malware::OS::Win32::Scanning;

class DLLIMPORT Security::Libraries::Malware::OS::Win32::Scanning::cYaraScanner
{
	YARA_CONTEXT* YContext;
	
public:

	cList* Results;
	cYaraScanner(void);
	void FreeResults(void);
	cYaraScanner(cString,cString);
	void AddRule(cString rule);
	cList* Scan(unsigned char* buffer,DWORD buffer_size);
	int ScannerCallback(RULE* rule);
	char* CreatRule(cString name,cList strings,cString condition);
	char* CreatRule(cString name,cList strings,int condition);
	char* CreatRule(cString name,cString strings,int condition);
	~cYaraScanner(void);
};
