/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet <amr.thabet[at]student.alx.edu.eg>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to Amr Thabet
 *  amr.thabet[at]student.alx.edu.eg
 *
 */

#include "stdafx.h"
#include "SRDF.h"
#include <iostream>

using namespace std;
using namespace Security::Libraries::Malware::Dynamic;
using namespace Security::Targets;
using namespace Security::Targets::Files;
using namespace Security::Targets::Memory;

cDebugger::cDebugger(cString Filename,cString Commandline)
{
	DWORD dwContinueStatus = DBG_CONTINUE;
	bContinueDebugging = 1;
	IsDebugging = FALSE;
	//if (Filename == NULL)return;
	Breakpoints = new cList(sizeof(DBG_BREAKPOINT));
	MemoryBreakpoints = new cList(sizeof(DBG_MEMORY_BREAKPOINT));
	memset (&debug_event,0,sizeof(debug_event));
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(si);
	this->Filename = Filename;
	this->Commandline = Commandline;
	HardwareBreakpoints[0].Address = 0;
	HardwareBreakpoints[1].Address = 0;
	HardwareBreakpoints[2].Address = 0;
	HardwareBreakpoints[3].Address = 0;
	//Creating The Process For Debugging
	if (!CreateProcess(Filename.GetChar(), Commandline.GetChar(), NULL, NULL, false, DEBUG_ONLY_THIS_PROCESS,NULL,NULL, &si, &pi))
	{
		 IsDebugging = FALSE;
		 return;
	}
	ProcessId = pi.dwProcessId;
	ThreadId = pi.dwThreadId;
	hProcess = (DWORD)pi.hProcess;
	hThread = (DWORD)pi.hThread;

	DebuggeePE = new cPEFile(Filename);
		
	while(bContinueDebugging)
	{
		if (!WaitForDebugEvent(&debug_event, INFINITE))
		{
			return;
		};
		switch(debug_event.dwDebugEventCode)
		{

		case LOAD_DLL_DEBUG_EVENT:
			DLLLoadedNotifyRoutine();	
			break;

		case EXCEPTION_DEBUG_EVENT:
			{
				EXCEPTION_DEBUG_INFO& exception = debug_event.u.Exception;
				RefreshRegisters();
				switch( exception.ExceptionRecord.ExceptionCode)
				{
				case STATUS_BREAKPOINT:
					DebuggeeProcess = new cProcess(ProcessId);
					SetBreakpoint(DebuggeePE->Imagebase + DebuggeePE->Entrypoint);
					IsDebugging = TRUE;
					
					return;

				default:
					ExceptionCode = exception.ExceptionRecord.ExceptionCode;
					Eip = (DWORD)exception.ExceptionRecord.ExceptionAddress;
				}

				break;
			}
		}
		ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus);
		dwContinueStatus = DBG_CONTINUE;
	}
}

cDebugger::cDebugger(cProcess* Process)
{
	DWORD dwContinueStatus = DBG_CONTINUE;
	bContinueDebugging = 1;
	DebuggeeProcess = Process;
	Breakpoints = new cList(sizeof(DBG_BREAKPOINT));
	MemoryBreakpoints = new cList(sizeof(DBG_MEMORY_BREAKPOINT));
	memset (&debug_event,0,sizeof(debug_event));
	IsDebugging = FALSE;
	this->Filename = Process->processPath;
	this->Commandline = Process->CommandLine;
	HardwareBreakpoints[0].Address = 0;
	HardwareBreakpoints[1].Address = 0;
	HardwareBreakpoints[2].Address = 0;
	HardwareBreakpoints[3].Address = 0;
	//Creating The Process For Debugging
	////cout << Filename.GetChar() << "\n";
	if (!DebugActiveProcess(Process->ProcessId))
	{
		 ////cout << "Error in Creating The Process\n";
		 IsDebugging = FALSE;
		 return;
	}
	ProcessId = Process->ProcessId;
	DebuggeePE = new cPEFile(Filename);
	while(bContinueDebugging)
	{
		if (!WaitForDebugEvent(&debug_event, INFINITE))
		{
			return;
		};
		switch(debug_event.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			//Get all missed information from here
			hProcess = (DWORD)debug_event.u.CreateProcessInfo.hProcess;
			hThread = (DWORD)debug_event.u.CreateProcessInfo.hThread;
			ThreadId = NULL;			//(DWORD)GetThreadId((HANDLE)hThread);  works only on Vista and above 
			break;
		case LOAD_DLL_DEBUG_EVENT:
			DLLLoadedNotifyRoutine();	
			break;

		case EXCEPTION_DEBUG_EVENT:
			{
				EXCEPTION_DEBUG_INFO& exception = debug_event.u.Exception;
				RefreshRegisters();
				switch( exception.ExceptionRecord.ExceptionCode)
				{
				
				case STATUS_BREAKPOINT:
					DebuggeeProcess = new cProcess(ProcessId);
					IsDebugging = TRUE;
					RefreshRegisters();
					return;

				default:
					ExceptionCode = exception.ExceptionRecord.ExceptionCode;
					Eip = (DWORD)exception.ExceptionRecord.ExceptionAddress;
				}

				break;
			}
		}
		ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus);
		dwContinueStatus = DBG_CONTINUE;
	}
}

int cDebugger::Step()
{
	DWORD LastBp = LastBreakpoint;
	DWORD LastMemBp = LastMemoryBreakpoint;
	LastBreakpoint = 0;
	LastMemoryBreakpoint = 0;
	RefreshRegisters();
	EFlags |= 0x100;
	UpdateRegisters();
	int x = Run();
	if (LastBp != 0)
	{
		if (GetBreakpoint((DWORD)LastBp) != NULL)
		{
			DBG_BREAKPOINT* bp = (DBG_BREAKPOINT*) GetBreakpoint((DWORD)LastBp);
			if (bp->IsActive == FALSE)return x;
			unsigned char b = 0xCC;
			DebuggeeProcess->Write(LastBp,(DWORD)&b,1);
		}
	}
	if (LastMemBp !=0)
	{	
		if (GetMemoryBreakpoint((DWORD)LastMemBp) != NULL)
		{
			DBG_MEMORY_BREAKPOINT* bp = (DBG_MEMORY_BREAKPOINT*) GetMemoryBreakpoint((DWORD)LastMemBp);
			if (bp->IsActive == FALSE)return x;
			DWORD OldProtection;
			if (bp->NewProtection == PAGE_GUARD)
			{
				VirtualProtectEx((HANDLE)hProcess,(LPVOID)bp->Address,bp->Size,PAGE_GUARD,&OldProtection);
			}
			else
			{
				VirtualProtectEx((HANDLE)hProcess,(LPVOID)bp->Address,bp->Size,PAGE_READONLY,&OldProtection);
			}
			
		}
	}
	if (x == DBG_STATUS_HARDWARE_BP) return DBG_STATUS_STEP;
	return x;
}

int cDebugger::Run()
{
	DWORD dwContinueStatus = DBG_CONTINUE;
	bContinueDebugging = 1;
	CONTEXT lcContext;
	//usually it will continue after pause
	ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus);
	while(bContinueDebugging)
	{
		if (!WaitForDebugEvent(&debug_event, INFINITE))
		{
			return -1;
		};
		switch(debug_event.dwDebugEventCode)
		{

		case CREATE_THREAD_DEBUG_EVENT:
			ThreadCreatedNotifyRoutine();
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			ThreadExitNotifyRoutine();
			break;

		case LOAD_DLL_DEBUG_EVENT:
			DLLLoadedNotifyRoutine();	
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			DLLUnloadedNotifyRoutine();	
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			ProcessExitNotifyRoutine();
			return DBG_STATUS_EXITPROCESS;
		case EXCEPTION_DEBUG_EVENT:
			{
				EXCEPTION_DEBUG_INFO& exception = debug_event.u.Exception;
				RefreshRegisters();
				ExceptionCode = exception.ExceptionRecord.ExceptionCode;
				switch( exception.ExceptionRecord.ExceptionCode)
				{
				case STATUS_BREAKPOINT:
					{
						DBG_BREAKPOINT* bp = GetBreakpoint((DWORD)exception.ExceptionRecord.ExceptionAddress);
						LastBreakpoint = (DWORD)exception.ExceptionRecord.ExceptionAddress;
						if (bp == NULL)LastBreakpoint = 0;
						else if (bp->IsActive == false)LastBreakpoint = 0;
						else
						{
							/*
							 * Rewrite the original byte and set the EFlags to Single Step (to step
							 * on this instruction ... and rewrite again the "int3" for the next
							 * break on this breakpoint
							 */
							
							LastBreakpoint = (DWORD)exception.ExceptionRecord.ExceptionAddress;
							lcContext.ContextFlags = CONTEXT_ALL;
							GetThreadContext((HANDLE)hThread, &lcContext);
							lcContext.Eip--;
							DebuggeeProcess->Write(LastBreakpoint,(DWORD)&bp->OriginalByte,1);
							lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
							SetThreadContext((HANDLE)hThread,&lcContext);
							RefreshRegisters();
						}
						return DBG_STATUS_BREAKPOINT;
					}

				case STATUS_SINGLE_STEP:
					
					// Set the Breakpoint Again
					if (LastBreakpoint != 0)
					{
						if (GetBreakpoint((DWORD)LastBreakpoint) != NULL )
						{
							//No need to rewrite the int3 breakpoint .. continue execution
							if (GetBreakpoint((DWORD)LastBreakpoint)->IsActive == FALSE) break;
							unsigned char b = 0xCC;
							DebuggeeProcess->Write(LastBreakpoint,(DWORD)&b,1);
							LastBreakpoint = 0;
							break;
						}
						else return DBG_STATUS_HARDWARE_BP;
					}
					else if (LastMemoryBreakpoint != 0)
					{
						DBG_MEMORY_BREAKPOINT* bp = GetMemoryBreakpoint(LastMemoryBreakpoint);
						if (bp == NULL)return DBG_STATUS_STEP;
						if (bp->IsActive == FALSE) break;
						DWORD OldProtection;
						if (bp->NewProtection == PAGE_GUARD)
						{
							VirtualProtectEx((HANDLE)hProcess,(LPVOID)bp->Address,bp->Size,PAGE_GUARD,&OldProtection);
						}
						else
						{
							VirtualProtectEx((HANDLE)hProcess,(LPVOID)bp->Address,bp->Size,PAGE_READONLY,&OldProtection);
						}
						LastMemoryBreakpoint = 0;
						break;
					}
					else return DBG_STATUS_HARDWARE_BP;
					
				default:
					ExceptionCode = exception.ExceptionRecord.ExceptionCode;
					if ((ExceptionCode == EXCEPTION_ACCESS_VIOLATION) && (GetMemoryBreakpoint((DWORD)exception.ExceptionRecord.ExceptionInformation[1]) != NULL))
					{
						DWORD OldProtection;
						LastMemoryBreakpoint = (DWORD)exception.ExceptionRecord.ExceptionInformation[1];
						DBG_MEMORY_BREAKPOINT* bp = GetMemoryBreakpoint(LastMemoryBreakpoint);
						if (bp->NewProtection == PAGE_READONLY)
						{
							VirtualProtectEx((HANDLE)hProcess,(LPVOID)bp->Address,bp->Size,bp->OldProtection,&OldProtection); //bp->OldProtection
						}
						lcContext.ContextFlags = CONTEXT_ALL;
						GetThreadContext((HANDLE)hThread, &lcContext);
						lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
						SetThreadContext((HANDLE)hThread,&lcContext);
						return DBG_STATUS_MEM_BREAKPOINT;
					}
					Eip = (DWORD)exception.ExceptionRecord.ExceptionAddress;
					return DBG_STATUS_ERROR;
				}

				break;
			}
		}
		ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus);

		// Reset
		dwContinueStatus = DBG_CONTINUE;
	}
	return -1;
}

void cDebugger::RefreshRegisters()
{
	CONTEXT lcContext;
	lcContext.ContextFlags = CONTEXT_ALL;
	GetThreadContext((HANDLE)hThread, &lcContext);
	Reg[0]	= lcContext.Eax;
	Reg[1]	= lcContext.Ecx;
	Reg[2]	= lcContext.Edx;
	Reg[3]	= lcContext.Ebx;
	Reg[4]	= lcContext.Esp;
	Reg[5]	= lcContext.Ebp;
	Reg[6]	= lcContext.Esi;
	Reg[7]	= lcContext.Edi;
	Eip		= lcContext.Eip;
	EFlags	= lcContext.EFlags;
	DebugStatus = lcContext.Dr6;
}

void cDebugger::UpdateRegisters()
{
	CONTEXT lcContext;
	lcContext.ContextFlags = CONTEXT_ALL;
	GetThreadContext((HANDLE)hThread, &lcContext);
	lcContext.Eax = Reg[0];
	lcContext.Ecx = Reg[1];
	lcContext.Edx = Reg[2];
	lcContext.Ebx = Reg[3];
	lcContext.Esp = Reg[4];
	lcContext.Ebp = Reg[5];
	lcContext.Esi = Reg[6];
	lcContext.Edi = Reg[7];
	lcContext.Eip = Eip;
	lcContext.Dr6 = 0;
	lcContext.EFlags = EFlags;
	SetThreadContext((HANDLE)hThread,&lcContext);
}
DBG_BREAKPOINT* cDebugger::GetBreakpoint(DWORD Address)
{
	DBG_BREAKPOINT* bp;
	for (DWORD i =0; i< Breakpoints->GetNumberOfItems(); i++)
	{
		bp = (DBG_BREAKPOINT*)Breakpoints->GetItem(i);
		if ( bp->Address == Address) return bp;
	}
	return NULL;
}
BOOL cDebugger::SetBreakpoint(DWORD Address)
{
	BYTE* Ins = (BYTE*)DebuggeeProcess->Read(Address,1);

	if (Ins == NULL)return false;
	
	if (GetBreakpoint((DWORD)Address) != NULL)
	{
		DBG_BREAKPOINT* NewBp = GetBreakpoint((DWORD)Address);
		NewBp->Address = (DWORD)Address;
		NewBp->OriginalByte = *Ins;
		NewBp->IsActive = TRUE;
	}
	else
	{
		DBG_BREAKPOINT NewBp;
		NewBp.Address = (DWORD)Address;
		NewBp.OriginalByte = *Ins;
		NewBp.IsActive = TRUE;
		Breakpoints->AddItem((char*)&NewBp);
	}
	*Ins = 0xCC;
	if (DebuggeeProcess->Write(Address,(DWORD)Ins,1) == NULL) return false;
	return true;
}

void cDebugger::RemoveBreakpoint(DWORD Address)
{
	DBG_BREAKPOINT* bp = GetBreakpoint((DWORD)Address);
	if (bp == NULL)return;
	DebuggeeProcess->Write(Address,(DWORD)&bp->OriginalByte,1);
	bp->IsActive = FALSE;
}
void cDebugger::RefreshDebugRegisters()
{
	CONTEXT lcContext;
	lcContext.ContextFlags = CONTEXT_ALL;
	GetThreadContext((HANDLE)hThread, &lcContext);
	lcContext.Dr7 = 0;
	for (int i =0;i< 4; i++)
	{
		if (HardwareBreakpoints[i].Address != 0)
		{
			DWORD x = (1 << (2*i));
			lcContext.Dr7 |= x;
			x = HardwareBreakpoints[i].Type;
			x = (x << (15+(2*i)));
			lcContext.Dr7 |= x;
			x = HardwareBreakpoints[i].Size;
			x = (x << (23+(2*i)));
			lcContext.Dr7 |= x;	
		}
	}
	lcContext.Dr0 = HardwareBreakpoints[0].Address;
	lcContext.Dr1 = HardwareBreakpoints[1].Address;
	lcContext.Dr2 = HardwareBreakpoints[2].Address;
	lcContext.Dr3 = HardwareBreakpoints[3].Address;
	SetThreadContext((HANDLE)hThread,&lcContext);
}
BOOL cDebugger::SetHardwareBreakpoint(DWORD Address,DWORD Type, int Size)
{
	for (int i =0;i< 4; i++)
	{
		if (HardwareBreakpoints[i].Address != 0) continue;
		HardwareBreakpoints[i].Address = Address;
		HardwareBreakpoints[i].Type = Type;
		if (Size == 1)HardwareBreakpoints[i].Size = DBG_BP_SIZE_1;
		if (Size == 2)HardwareBreakpoints[i].Size = DBG_BP_SIZE_2;
		if (Size == 4)HardwareBreakpoints[i].Size = DBG_BP_SIZE_4;
		RefreshDebugRegisters();
		return TRUE;
	}
	return FALSE;
}

void cDebugger::RemoveHardwareBreakpoint(DWORD Address)
{
	for (int i =0;i< 4; i++)
	{
		if (HardwareBreakpoints[i].Address != Address) continue;
		HardwareBreakpoints[i].Address = 0;
		HardwareBreakpoints[i].Type = 0;
		HardwareBreakpoints[i].Size = 0;
		RefreshDebugRegisters();
	}
}

DBG_MEMORY_BREAKPOINT* cDebugger::GetMemoryBreakpoint(DWORD Address)
{
	for (DWORD i = 0;i < MemoryBreakpoints->GetNumberOfItems();i++)
	{
		DBG_MEMORY_BREAKPOINT* Bp = (DBG_MEMORY_BREAKPOINT*)MemoryBreakpoints->GetItem(i);
		if ((Address >= Bp->Address) && (Address < (Bp->Address + Bp->Size))) return Bp;
	}
	return NULL;
}

BOOL cDebugger::SetMemoryBreakpoint(DWORD Address,DWORD Size , DWORD Type)
{
	DWORD OldProtection;
	bool ShouldBeAdded = false;
	//Already found?
	DBG_MEMORY_BREAKPOINT* bp = GetMemoryBreakpoint(Address);
	if ((Size % 1000) != 0) Size = Size - (Size %1000) + 1000;

	if (bp == NULL)
	{
		//a new entry ... create it
		bp = (DBG_MEMORY_BREAKPOINT*)malloc(sizeof(DBG_MEMORY_BREAKPOINT));
		memset(bp,0,sizeof(DBG_MEMORY_BREAKPOINT));
		ShouldBeAdded = true;
	}

	switch (Type)
	{
	case DBG_BP_TYPE_READWRITE:
		if (VirtualProtectEx((HANDLE)hProcess,(LPVOID)Address,Size,PAGE_GUARD,&OldProtection) == 0)return false;
		bp->Address = Address;
		bp->Size = Size;
		bp->NewProtection = PAGE_GUARD;
		bp->IsActive = true;
	case DBG_BP_TYPE_WRITE:
		if (VirtualProtectEx((HANDLE)hProcess,(LPVOID)Address,Size,PAGE_READONLY,&OldProtection) == 0)return false;
		bp->Address = Address;
		bp->Size = Size;
		bp->NewProtection = PAGE_READONLY;
		bp->IsActive = true;
	}

	if (ShouldBeAdded)
	{
		bp->OldProtection = OldProtection;
		MemoryBreakpoints->AddItem((char*)bp);
	}
	return true;
}


void cDebugger::RemoveMemoryBreakpoint(DWORD Address)
{
	DBG_MEMORY_BREAKPOINT* bp = GetMemoryBreakpoint(Address);
	if (bp == NULL)return;
	DWORD OldProtection;
	VirtualProtectEx((HANDLE)hProcess,(LPVOID)bp->Address,bp->Size,bp->OldProtection,&OldProtection);
	bp->IsActive = FALSE;
}

void cDebugger::Pause()
{
	SuspendThread((HANDLE)hThread);
}

void cDebugger::Resume()
{
	ResumeThread((HANDLE)hThread);
}

void cDebugger::Terminate()
{
	TerminateProcess((HANDLE)hProcess,0);
}

void cDebugger::Exit()
{
	DebugActiveProcessStop(ProcessId);
}