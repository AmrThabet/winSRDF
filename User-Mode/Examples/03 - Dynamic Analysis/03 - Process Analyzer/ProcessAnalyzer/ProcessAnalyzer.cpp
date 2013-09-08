// ProcessAnalyzer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../../../SRDF.h"

using namespace Security::Targets::Memory;
using namespace Security::Libraries::Malware::Enumeration;
int _tmain(int argc, _TCHAR* argv[])
{
	//Process scanner get the process list running on the machine
	cProcessScanner ProcScan;
	DWORD Pid;
	Pid =  atoi(ProcScan.ProcessList["explorer.exe"]);

	//Prining The Process List
	for (int i = 0; i < ProcScan.ProcessList.GetNumberOfItems();i++)
	{
		cout << ProcScan.ProcessList[i] << "\t" << ProcScan.ProcessList.GetKey(i) << "\n";
	}
	cout << "Enter the process id for the process you need to analyze: " << "\n";
	cin >> Pid;

	//Anaylze the given process
	cProcess* Process = new cProcess(Pid);

	//If not opened correctly
	if (!Process->IsFound()) 
	{
		cout << "Unable to Open Process ... Check the Pid again\n";
		return 0;
	}

	cout<<"Process: "<<Process->processName << endl;
	cout<<"Process Parent ID: "<< Process->ParentID << endl;
	cout<< "Process Command Line: "<< Process->CommandLine << endl;
	
	cout<<"Process PEB:\t"<<Process->ppeb << endl;
	cout<<"Process ImageBase:\t"<<hex<<Process->ImageBase << endl;
	cout<<"Process SizeOfImageBase:\t"<<dec<<Process->SizeOfImage<<" byte" << endl;

	//Print all loaded modules (DLLs)

	cout<<"Process Modules\n";
	for (int i=0 ; i<(int)(Process->modulesList.GetNumberOfItems()) ;i++)
	{
		cout << "Module "<< ((MODULE_INFO*)Process->modulesList.GetItem(i))->moduleName->GetChar();
		cout <<"\tImageBase:  "<<hex<<((MODULE_INFO*)Process->modulesList.GetItem(i))->moduleImageBase<<endl;
	
	}
	system("pause");

	//Print all Allocated Memory Chunks allocated and its size
	cout << "Memory Map:\n";
	for (int i=0 ; i<(int)(Process->MemoryMap.GetNumberOfItems()) ;i++)
	{
		cout<<"Memory Address "<< ((MEMORY_MAP*)Process->MemoryMap.GetItem(i))->Address;
		cout <<" Size:  "<<hex<<((MEMORY_MAP*)Process->MemoryMap.GetItem(i))->Size <<endl;
	}
	system("pause");
	return 0;
}

