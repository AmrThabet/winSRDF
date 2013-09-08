// DebuggerExample.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../../../SRDF.h";

using namespace Security::Core;
using namespace Security::Libraries::Malware::Enumeration;
using namespace Security::Libraries::Malware::Dynamic;
using namespace Security::Targets::Memory;
using namespace Security::Targets::Files;
using namespace Security::Libraries::Malware::Static;
class cDebuggerApp : public cConsoleApp
{
	cDebugger*	Debugger;
	CPokasAsm*	Asm;
public:
	cDebuggerApp(cString AppName);
	~cDebuggerApp();
	virtual void SetCustomSettings();
	virtual int Run();
	virtual int Exit();
	void Step();
	void Info();
	void PEInfo();
	void MemoryMap();
	void Search(int argc,char* argv[]);
	void DebugRun();
	void ShowRegisters();
	void Getaddr(int argc,char* argv[]);
	void SetBreakpoint(int argc,char* argv[]);
	void SetHardBreakpoint(int argc,char* argv[]);
	void SetMemoryBreakpoint(int argc,char* argv[]);
	void Dump(int argc,char* argv[]);
	void Procdump(int argc,char* argv[]);
	void Disassemble(int argc,char* argv[]);
	void String(int argc,char* argv[]);
	void RemoveBreakpoint(int argc,char* argv[]);
	void RemoveHardBreakpoint(int argc,char* argv[]);
	void RemoveMemoryBreakpoint(int argc,char* argv[]);
};

void StepFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Step();};
void InfoFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Info();};
void PEInfoFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->PEInfo();};
void MemoryMapFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->MemoryMap();};
void SearchFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Search(argc,argv);};
void RunFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->DebugRun();};
void RegsFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->ShowRegisters();};
void BpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->SetBreakpoint(argc,argv);}; 
void HardbpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->SetHardBreakpoint(argc,argv);}; 
void MembpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->SetMemoryBreakpoint(argc,argv);}; 
void DumpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Dump(argc,argv);}; 
void ProcdumpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Procdump(argc,argv);}; 
void DisasmFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Disassemble(argc,argv);}; 
void StringFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->String(argc,argv);}; 
void RemovebpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->RemoveBreakpoint(argc,argv);}; 
void RemovehardbpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->RemoveHardBreakpoint(argc,argv);};
void RemovemembpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->RemoveMemoryBreakpoint(argc,argv);};
void GetaddrFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Getaddr(argc,argv);};

int _tmain(int argc, char* argv[])
{
	cDebuggerApp* Debugger = new cDebuggerApp("Win32Debugger");
	Debugger->SetCustomSettings();
	Debugger->Initialize(argc,argv);
	Debugger->Run();
	return 0;
}

cDebuggerApp::cDebuggerApp(cString AppName) : cConsoleApp(AppName)
{
	Debugger = NULL;
	Asm = NULL;
}
cDebuggerApp::~cDebuggerApp()
{
	((cConsoleApp*)this)->~cConsoleApp();
}

void cDebuggerApp::SetCustomSettings()
{

	Intro = "\
	***********************************\n\
	**       Win32 Debugger          **\n\
	***********************************\n";
	AddCommand("step","one Step through code","step",0,&StepFunc);
	AddCommand("info","Get detailed information about the process","info",0,&InfoFunc);
	AddCommand("memory","Get the memory map of the process","memory",0,&MemoryMapFunc);
	AddCommand("peinfo","Get detailed information about the process pe file","peinfo",0,&PEInfoFunc);
	AddCommand("search","search for a string or hex string in memory using yara","search [string or hex eg. \"string\" or {EF:AD:FF:D4}]",1,&SearchFunc);
	AddCommand("run","Run the application until the first breakpoint","run",0,&RunFunc);
	AddCommand("regs","Show Registers","regs",0,&RegsFunc);
	AddCommand("getaddr","gets the address of an API","getaddr [dll-name] [api-name]",2,&GetaddrFunc);
	AddCommand("bp","Set an Int3 Breakpoint","bp [address]",1,&BpFunc);
	AddCommand("hardbp","Set a Hardware Breakpoint","hardbp [address] [size (1,2,4)] [type .. 0 = access .. 1 = write .. 2 = execute]",3,&HardbpFunc);
	AddCommand("membp","Set Memory Breakpoint","membp [address] [size] [type .. 0 = access .. 1 = write]",3,&MembpFunc);
	AddCommand("dump","Dump a place in memory in hex","dump [address] [size]",2,&DumpFunc);
	AddCommand("procdump","Dump the process and unload its import table","procdump [filename] [new entrypoint]",2,&ProcdumpFunc);
	AddCommand("disasm","Disassemble a place in memory","disasm [address] [size]",2,&DisasmFunc);
	AddCommand("string","Print string at a specific address","string [address] [max size]",2,&StringFunc);
	AddCommand("removebp","Remove an Int3 Breakpoint","removebp [address]",1,&RemovebpFunc);
	AddCommand("removehardbp","Remove a Hardware Breakpoint","removehardbp [address]",1,&RemovehardbpFunc);
	AddCommand("removemembp","Remove Memory Breakpoint","removemembp [address]",1,&RemovemembpFunc);
}
int cDebuggerApp::Run()
{
	//Get the commandline argument .. default is the normal argument for no command 
	//like Debug.exe xxx.exe
	Debugger = new cDebugger(Request.GetValue("default"));


	Asm = new CPokasAsm();
	if (Debugger->IsDebugging)
	{
		//Set Breakpoint on The Entrypoint (Avoid ASLR-based Applications)
		Debugger->SetBreakpoint(Debugger->DebuggeePE->Entrypoint - Debugger->DebuggeePE->Imagebase + Debugger->DebuggeeProcess->ImageBase);
		Debugger->Run();
		Prefix = Debugger->DebuggeeProcess->processName;
		if (Debugger->IsDebugging)StartConsole();
	}
	else
	{
		cout << Intro << "\n\n";
		cout << Request.GetValue("default") << "\n";
		cout << "Error: File not Found";
	}
	return 0;
}
int cDebuggerApp::Exit()
{
	cout << "Thanks For using our Debugger\n";
	if (Debugger->IsDebugging)Debugger->Terminate();
	delete Asm;
	return 0;
}
void cDebuggerApp::Step()
{
	int ret = Debugger->Step();

	if (ret == DBG_STATUS_BREAKPOINT)
	{
		cout << "Int3 Breakpoint Triggered at: " << (int*)Debugger->Eip << "\n";
	}
	else if (ret == DBG_STATUS_MEM_BREAKPOINT)
	{
		cout << "Memory Breakpoint Triggered at: " << (int*)Debugger->Eip << "\n";
	}
	else if (ret == DBG_STATUS_HARDWARE_BP)
	{
		cout << "Hardware Breakpoint Triggered at: " << (int*)Debugger->Eip << "\n";
	}
	else if (ret == DBG_STATUS_EXITPROCESS)
	{
		cout << "The Process Exited\n";
	}
	else if (ret == DBG_STATUS_ERROR)
	{
		cout << "ERROR at: " << (int*)Debugger->Eip << " Exception Code: " << (int*)Debugger->ExceptionCode << "\n";
	}
}
void cDebuggerApp::DebugRun()
{
	int ret = Debugger->Run();

	if (ret == DBG_STATUS_BREAKPOINT)
	{
		cout << "Int3 Breakpoint Triggered at: " << (int*)Debugger->Eip << "\n";
	}
	else if (ret == DBG_STATUS_MEM_BREAKPOINT)
	{
		cout << "Memory Breakpoint Triggered at: " << (int*)Debugger->Eip << "\n";
	}
	else if (ret == DBG_STATUS_HARDWARE_BP)
	{
		cout << "Hardware Breakpoint Triggered at: " << (int*)Debugger->Eip << "\n";
	}
	else if (ret == DBG_STATUS_EXITPROCESS)
	{
		cout << "The Process Exited\n";
	}
	else if (ret == DBG_STATUS_ERROR)
	{
		cout << "ERROR at: " << (int*)Debugger->Eip << " Exception Code: " << (int*)Debugger->ExceptionCode << "\n";
	}
}
void cDebuggerApp::ShowRegisters()
{
	cout << "\n";
	cout << "EAX:	" << (int*)Debugger->Reg[0] << " ECX:	" << (int*)Debugger->Reg[1] << " EDX:	" << (int*)Debugger->Reg[2] << " EBX:	" << (int*)Debugger->Reg[3] << "\n";
	cout << "ESP:	" << (int*)Debugger->Reg[4] << " EBP:	" << (int*)Debugger->Reg[5] << " ESI:	" << (int*)Debugger->Reg[6] << " EDI:	" << (int*)Debugger->Reg[7] << "\n";
	cout << "EIP:	" << (int*)Debugger->Eip << " EFLAGS:" << (int*)Debugger->EFlags << "\nException Code:	" << (int*)Debugger->ExceptionCode << "\n";
	cout << "\n";

}
void cDebuggerApp::SetBreakpoint(int argc,char* argv[])
{
	DWORD Address = 0;
	sscanf(argv[0], "%x", &Address);
	if (Debugger->SetBreakpoint(Address))cout << "Breakpoint Added Successfully at: " << (int*)Address << "\n";
	else cout << "Failed to add breakpoint\n";
}
void cDebuggerApp::SetHardBreakpoint(int argc,char* argv[])
{
	DWORD Address = 0;
	DWORD Size = atoi(argv[1]);
	DWORD Code = atoi(argv[2]);
	sscanf(argv[0], "%x", &Address);
	DWORD Type = 0;
	if (Code == 0)
	{
		Type = DBG_BP_TYPE_READWRITE;
	}
	else if (Code == 1)
	{
		Type = DBG_BP_TYPE_WRITE;
	}
	else if (Code == 2)
	{
		Type = DBG_BP_TYPE_CODE;
	}
	if (Size == 1)
	{
		Size = DBG_BP_SIZE_1;
	}
	else if (Size == 2)
	{
		Size = DBG_BP_SIZE_2;
	}
	else if (Size == 4)
	{
		Size = DBG_BP_SIZE_4;
	}
	if (Debugger->SetHardwareBreakpoint(Address,Type,Size))cout << "Breakpoint Added Successfully at: " << (int*)Address << "\n";
	else cout << "Failed to add breakpoint\n";
}
void cDebuggerApp::SetMemoryBreakpoint(int argc,char* argv[])
{
	DWORD Address = 0;
	DWORD Size = 0;
	int Code = atoi(argv[2]);
	DWORD Type = 0;
	sscanf(argv[0], "%x", &Address);
	sscanf(argv[1], "%x", &Size);
	if (Code == 0)
	{
		Type = DBG_BP_TYPE_READWRITE;
	}
	else if (Code == 1)
	{
		Type = DBG_BP_TYPE_WRITE;
	}
	if (Debugger->SetMemoryBreakpoint(Address,Size,Type))cout << "Breakpoint Added Successfully at: " << (int*)Address << "\n";
	else cout << "Failed to add breakpoint\n";
}
void cDebuggerApp::Dump(int argc,char* argv[])
{
	DWORD Address = 0;
	DWORD Size = 0;
	sscanf(argv[0], "%x", &Address);
	sscanf(argv[1], "%x", &Size);
	unsigned char* Buffer = (unsigned char*)Debugger->DebuggeeProcess->Read(Address,Size);
	if (Buffer != NULL)
	for (DWORD i =0; i< Size;i++)
	{
		if((i % 10) == 0)cout << "\n" << (int*)Address << ": ";
		//cout << Buffer[i] << " ";
		printf("%02x ",Buffer[i]);
		Address++;
	}
	cout << "\n";

}
void cDebuggerApp::String(int argc,char* argv[])
{
	DWORD Address = 0;
	DWORD Size = 0;
	sscanf(argv[0], "%x", &Address);
	sscanf(argv[1], "%x", &Size);
	unsigned char* Buffer = (unsigned char*)Debugger->DebuggeeProcess->Read(Address,Size);
	if (Buffer != NULL)cout << (int*)Address << ": " << Buffer << "\n";
}
void cDebuggerApp::Disassemble(int argc,char* argv[])
{
	DWORD Address = 0;
	DWORD Size = 0;
	sscanf(argv[0], "%x", &Address);
	sscanf(argv[1], "%x", &Size);
	DWORD Buffer = Debugger->DebuggeeProcess->Read(Address,Size+16);
	if (Buffer == NULL)return;
	DWORD InsLength = 0;
	
	for (DWORD InsBuff = Buffer;InsBuff < Buffer+ Size ;InsBuff+=InsLength)
	{
		cout << (int*)Address << ": " << Asm->Disassemble((char*)InsBuff,InsLength) << "\n";
		Address+=InsLength;
	}
}	
void cDebuggerApp::RemoveBreakpoint(int argc,char* argv[])
{
	DWORD Address = 0;
	sscanf(argv[0], "%x", &Address);
	Debugger->RemoveBreakpoint(Address);
	cout << "Breakpoint Removed\n";
}
void cDebuggerApp::RemoveHardBreakpoint(int argc,char* argv[])
{
	DWORD Address = 0;
	sscanf(argv[0], "%x", &Address);
	Debugger->RemoveHardwareBreakpoint(Address);
	cout << "Breakpoint Removed\n";
}
void cDebuggerApp::RemoveMemoryBreakpoint(int argc,char* argv[])
{
	DWORD Address = 0;
	sscanf(argv[0], "%x", &Address);
	Debugger->RemoveMemoryBreakpoint(Address);
	cout << "Breakpoint Removed\n";
}

void cDebuggerApp::Info()
{
	cProcess* ScannedProcess = Debugger->DebuggeeProcess;

	cout << "Process: "<<ScannedProcess->processName<<endl;
	cout << "Process Parent ID: "<< ScannedProcess->ParentID <<endl;
	cout << "Process Command Line: "<< ScannedProcess->CommandLine << endl;
	cout << "Process Filename: "<< ScannedProcess->processPath << endl;
	cout << "Process PEB:\t"<<ScannedProcess->ppeb<<endl;
	cout << "Process ImageBase:\t"<<hex<<ScannedProcess->ImageBase<<endl;
	cout << "Process SizeOfImageBase:\t"<<dec<<ScannedProcess->SizeOfImage<<" bytes"<<endl;
	cout << "Process MD5:\t"<<ScannedProcess->processMD5<<endl;
	cout << "\nProcess Modules:\n----------------\n";
	
	for (int i=0 ; i<(int)(ScannedProcess->modulesList.GetNumberOfItems()) ;i++)
	{
		cout << "\nModule "<< ((MODULE_INFO*)ScannedProcess->modulesList.GetItem(i))->moduleName->GetChar();
		cout << "\nModule MD5: " << ((MODULE_INFO*)ScannedProcess->modulesList.GetItem(i))->moduleMD5->GetChar();
		cout << "\nImageBase:  "<<hex<<((MODULE_INFO*)ScannedProcess->modulesList.GetItem(i))->moduleImageBase<<endl;
	
	}
}

void cDebuggerApp::MemoryMap()
{
	cProcess* ScannedProcess = Debugger->DebuggeeProcess;
	for (int i=0 ; i<(int)(ScannedProcess->MemoryMap.GetNumberOfItems()) ;i++)
	{
		cout << "Memory Address "<< ((MEMORY_MAP*)ScannedProcess->MemoryMap.GetItem(i))->Address;
		cout << "\tAllocationBase "<< ((MEMORY_MAP*)ScannedProcess->MemoryMap.GetItem(i))->AllocationBase;
		cout << "\tSize:  "<<hex<<((MEMORY_MAP*)ScannedProcess->MemoryMap.GetItem(i))->Size <<endl;
	}
}
void cDebuggerApp::PEInfo()
{
	cPEFile* PEFile = Debugger->DebuggeePE;

	cout << "Filename: " << Debugger->DebuggeeProcess->processName << "\n";
	cout << "MD5Hash: " << Debugger->DebuggeeProcess->processMD5 << "\n";
	cout << "Magic: " << hex << PEFile->Magic << "\n";
	cout << "Subsystem: " << hex << PEFile->Subsystem << "\n";
	cout << "Imagebase: " << hex << PEFile->Imagebase << "\n";
	cout << "SizeOfImage: " << hex << PEFile->SizeOfImage << "\n";
	cout << "Entrypoint: " << hex << PEFile->Entrypoint << "\n";
	cout << "FileAlignment: " << hex << PEFile->FileAlignment << "\n";
	cout << "SectionAlignment: " << hex << PEFile->SectionAlignment << "\n";
	cout << "NumberOfSections: " << PEFile->nSections << "\n";
	if (PEFile->DataDirectories & DATADIRECTORY_IMPORT)
	{
		cout << "\nImport Table:\n------------\n";
		for (int i = 0;i < PEFile->ImportTable.nDLLs;i++)
		{
			cString DLLName = PEFile->ImportTable.DLL[i].DLLName;
			for (int l = 0; l < PEFile->ImportTable.DLL[i].nAPIs;l++)
			{
				cout << DLLName << ": " << PEFile->ImportTable.DLL[i].API[l].APIName << "\n";
			}
			cout << "\n";
		}
	}
	if (PEFile->DataDirectories & DATADIRECTORY_EXPORT)
	{
		cout << "\nExport Table:\n------------\n";
		for (int i = 0;i < PEFile->ExportTable.nNames;i++)
		{
			cout << hex << PEFile->ExportTable.Functions[i].funcRVA << ": " << PEFile->ExportTable.Functions[i].funcName << "\n";
		}
	}
	cout << "\nSection Table:\n------------\n";
	for (int i = 0; i < PEFile->nSections;i++)
	{
		cout << "Name: " << PEFile->Section[i].SectionName << "\n";
		cout << "PointerToRawData: " << hex << PEFile->Section[i].PointerToRawData << "\n";
		cout << "SizeOfRawData: " << hex << PEFile->Section[i].SizeOfRawData << "\n";
		cout << "VirtualAddress: " << hex << PEFile->Section[i].VirtualAddress << "\n";
		cout << "VirtualSize: " << hex << PEFile->Section[i].VirtualSize << "\n";
		cout << "\n";
	}
}

void cDebuggerApp::Search(int argc,char* argv[])
{
	cString Signature = argv[0];
	Signature.Replace(':',' ');
	cYaraScanner* YaraScan = new cYaraScanner();
	
	cString Rule = YaraScan->CreateRule("DebuggerSearch",Signature);
	int x = YaraScan->AddRule(Rule);
	cProcess* ScannedProcess = Debugger->DebuggeeProcess;
	int nResults = 0;
	for (int i=0 ; i<(int)(ScannedProcess->MemoryMap.GetNumberOfItems()) ;i++)
	{
		MEMORY_MAP* MemMap =  (MEMORY_MAP*)ScannedProcess->MemoryMap.GetItem(i);
		unsigned char* Address = (unsigned char*)ScannedProcess->Read(MemMap->Address,MemMap->Size);
		if (Address == NULL)continue;
		cList* Results = YaraScan->Scan(Address,MemMap->Size);
		if (Results == NULL)continue;
		_YARA_RESULT* Result = (_YARA_RESULT*)Results->GetItem(0);
		if (Result == NULL)continue;
		//cout << Result->Matches->GetNumberOfItems() << "\n";
		for (int l = 0; l < Result->Matches->GetNumberOfItems();l++)
		{
			MSTRING* Match = (MSTRING*)Result->Matches->GetItem(l);
			cout << "FOUND: " << (int*)(MemMap->Address + Match->offset) << "\n";
			nResults++;
		}
		
	}
	cout << nResults << " Found\n";
}
void cDebuggerApp::Getaddr(int argc,char* argv[])
{
	cString DLLName = argv[0];
	cString APIName = argv[1];

	HMODULE DLLAddress = LoadLibraryA(DLLName);
	if (DLLAddress == NULL)
	{
		cout << "Error: Unvalid DLL name\n";
		return;
	}
	DWORD APIAddress = (DWORD)GetProcAddress(DLLAddress,APIName);
	if (APIAddress == NULL)
	{
		cout << "Error: Unvalid API name\n";
		return;
	}
	cout << "API Address: " << (int*)APIAddress << "\n";
}

void cDebuggerApp::Procdump(int argc,char* argv[])
{
	cString Filename = argv[0];
	DWORD Address = 0;
	sscanf(argv[1], "%x", &Address);
	Address -= Debugger->DebuggeePE->Imagebase;
	cout << (int*)Address << "\n";
	cProcess* ScannedProcess = Debugger->DebuggeeProcess;
	if ( ScannedProcess->DumpProcess(Filename,Address,PROC_DUMP_UNLOADIMPORTTABLE) == true)
	{
		cout << "File Dumped Successfully\n";
	}
	else
	{
		"Error: Wrong Filename\n";
	}
}