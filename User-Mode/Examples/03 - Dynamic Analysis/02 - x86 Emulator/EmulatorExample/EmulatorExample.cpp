// EmulatorExample.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../../../SRDF.h"

using namespace Security::Libraries::Malware::Dynamic;

int _tmain(int argc, _TCHAR* argv[])
{
	CPokasEmu* emu = new CPokasEmu("upx01.exe","C:\\WINDOWS\\SYSTEM32\\");
	emu->SetBreakpoint("__isdirty(eip)");
	cout << "Start Emulation From : " <<(int*)emu->GetEip() << "\n";
	cout << "-------------------------------\n";
	//system("pause");

	emu->Emulate(); //"FileLog.txt"

	cout << "Emulated Successfully\n\nThe Disassembled Code:\n----------------------\n";
	DWORD ptr = emu->GetEip();
	for (int i = 0; i < 30; i++)
	{
		DWORD Len = 0;
		cout << (int*)ptr << " : ";
		cout <<  emu->GetDisassembly((char*)ptr,Len) << "\n";
		ptr += Len;
	}
	emu->MakeDumpFile("upx01_unpacked.exe",DUMP_FIXIMPORTTABLE);
 
	delete emu;
	return 0;
}

