// DebuggerExample.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../SRDF.h"

using namespace Security::Core;
using namespace Security::Libraries::Malware::OS::Win32::Debugging;
using namespace Security::Libraries::Malware::Assembly::x86;

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
	void DebugRun();
	void ShowRegisters();
	void SetBreakpoint(int argc,char* argv[]);
	void SetHardBreakpoint(int argc,char* argv[]);
	void SetMemoryBreakpoint(int argc,char* argv[]);
	void Dump(int argc,char* argv[]);
	void Disassemble(int argc,char* argv[]);
	void String(int argc,char* argv[]);
	void RemoveBreakpoint(int argc,char* argv[]);
	void RemoveHardBreakpoint(int argc,char* argv[]);
	void RemoveMemoryBreakpoint(int argc,char* argv[]);
};

void StepFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Step();};
void RunFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->DebugRun();};
void RegsFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->ShowRegisters();};
void BpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->SetBreakpoint(argc,argv);}; 
void HardbpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->SetHardBreakpoint(argc,argv);}; 
void MembpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->SetMemoryBreakpoint(argc,argv);}; 
void DumpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Dump(argc,argv);}; 
void DisasmFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->Disassemble(argc,argv);}; 
void StringFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->String(argc,argv);}; 
void RemovebpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->RemoveBreakpoint(argc,argv);}; 
void RemovehardbpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->RemoveHardBreakpoint(argc,argv);};
void RemovemembpFunc(cConsoleApp* App,int argc,char* argv[]){((cDebuggerApp*)App)->RemoveMemoryBreakpoint(argc,argv);};

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
	
}
cDebuggerApp::~cDebuggerApp()
{
	((cApp*)this)->~cApp();
}

void cDebuggerApp::SetCustomSettings()
{
	Intro = "\
	***********************************\n\
	**       Win32 Debugger          **\n\
	***********************************\n";
	AddCommand("step","one Step through code","step",0,&StepFunc);
	AddCommand("run","Run the application until the first breakpoint","run",0,&RunFunc);
	AddCommand("regs","Show Registers","regs",0,&RegsFunc);
	AddCommand("bp","Set an Int3 Breakpoint","bp [address]",1,&BpFunc);
	AddCommand("hardbp","Set a Hardware Breakpoint","hardbp [address] [size (1,2,4)] [type .. 0 = access .. 1 = write .. 2 = execute]",3,&HardbpFunc);
	AddCommand("membp","Set Memory Breakpoint","membp [address] [size] [type .. 0 = access .. 1 = write]",3,&MembpFunc);
	AddCommand("dump","Dump a place in memory in hex","dump [address] [size]",2,&DumpFunc);
	AddCommand("disasm","Disassemble a place in memory","disasm [address] [size]",2,&DisasmFunc);
	AddCommand("string","Print string at a specific address","string [address] [max size]",2,&StringFunc);
	AddCommand("removebp","Remove an Int3 Breakpoint","removebp [address]",1,&RemovebpFunc);
	AddCommand("removehardbp","Remove a Hardware Breakpoint","removehardbp [address]",1,&RemovehardbpFunc);
	AddCommand("removemembp","Remove Memory Breakpoint","removemembp [address]",1,&RemovemembpFunc);
}
int cDebuggerApp::Run()
{
	//Get the commandline argument .. default is the normal argument for no command 
	//not like Debug.exe -o:444 .. but like Debug.exe xxx.exe

	Debugger = new cDebugger(Request.GetValue("default"));
	Asm = new CPokasAsm();
	if (Debugger->IsDebugging)
	{
		Debugger->Run();
		Prefix = Debugger->DebuggeeProcess->processName;
		if (Debugger->IsDebugging)StartConsole();
	}
	else
	{
		cout << Intro << "\n\n";
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
	cout << (int*)Address << ": " << Buffer << "\n";
}
void cDebuggerApp::Disassemble(int argc,char* argv[])
{
	DWORD Address = 0;
	DWORD Size = 0;
	sscanf(argv[0], "%x", &Address);
	sscanf(argv[1], "%x", &Size);
	DWORD Buffer = Debugger->DebuggeeProcess->Read(Address,Size+16);
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
