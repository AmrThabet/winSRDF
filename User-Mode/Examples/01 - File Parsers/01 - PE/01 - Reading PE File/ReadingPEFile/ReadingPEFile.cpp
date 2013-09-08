// ReadingPEFile.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../../../../SRDF.h";

using namespace Security::Targets::Files;


int _tmain(int argc, _TCHAR* argv[])
{
	cout << "Loading a a PE File: file.exe\n";
	cPEFile* PE = new cPEFile("file.exe");
	
	//Check if the File loaded successfully
	if (PE->IsFound())
	{
		cout << "Error: File Not Found\n";
		return 0;
	}
	
	//Print the important information ( int* to force cout to print in hex)
	cout << "Subsystem: " << (int*)PE->Subsystem << "\n";
	cout << "Magic: " << (int*)PE->Magic << "\n";

	cout << "Imagebase: " << (int*)PE->Imagebase << "\n";
	cout << "SizeOfImage: " << (int*)PE->SizeOfImage << "\n";
	cout << "Entrypoint: " << (int*)PE->Entrypoint << "\n";
	cout << "Number of Sections: " << (int*)PE->nSections << "\n";

	//Check if there's an import table
	if (PE->DataDirectories & DATADIRECTORY_IMPORT)
	{
		cout << "\nImport Table: \n-------------\n";
		//Loop on all DLLs
		for (int i = 0; i < PE->ImportTable.nDLLs; i++)
		{
			//Loop on all APIs inside every dll
			for (int l = 0; l < PE->ImportTable.DLL[i].nAPIs; l++)
			{
				cout << PE->ImportTable.DLL[i].DLLName << "." << PE->ImportTable.DLL[i].API[l].APIName << 
					"\t" << (int*)PE->ImportTable.DLL[i].API[l].APIAddressPlace << "\n";
			}
		}
	}

	if (PE->DataDirectories & DATADIRECTORY_EXPORT)
	{
		cout << "\nExport Table: \n-------------\n";
		//Loop on All Exported Functions
		for (int i = 0; i < PE->ExportTable.nFunctions; i++)
		{
			//If the function is by Name not Ordinal (Number) print its name
			if(PE->ExportTable.Functions[i].funcName != NULL)
				cout << PE->ExportTable.Functions[i].funcName << "\n";
		}
	}

	cout << "\nSection Table: \n-------------\n";
	cout << "Name\tVirtualAddress\tVirtualSize\n";

	//Print the section table information
	for (int i = 0; i < PE->nSections; i++)
	{
		cout << PE->Section[i].SectionName << "\t" << (int*)PE->Section[i].VirtualAddress 
			<< "\t" << (int*)PE->Section[i].VirtualSize << "\n";
	}

	cout << "\nFinished File Analysis\n";

	return 0;
}

