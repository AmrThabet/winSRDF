// YaraFileScanner.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../../../SRDF.h"

using namespace Security::Targets::Files;
using namespace Security::Libraries::Malware::OS::Win32::Static;

int _tmain(int argc, _TCHAR* argv[])
{
	cFile* File;
	cYaraScanner* yara = new cYaraScanner();

	yara->CreatRule("Test", "Hello World");

	
	return 0;
}

