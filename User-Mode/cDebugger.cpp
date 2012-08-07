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
using namespace Security::Libraries::Malware::OS::Win32::Debugging;
using namespace Security::Targets;
using namespace Security::Targets::Files;

cDebugger::cDebugger(cString Filename,cString Commandline)
{
	DWORD dwContinueStatus = DBG_CONTINUE;
	bContinueDebugging = 1;

	Breakpoints = new cList(sizeof(DBG_BREAKPOINT));
	memset (&debug_event,0,sizeof(debug_event));
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(si);
	IsDebugging = FALSE;
	this->Filename = Filename;
	this->Commandline = Commandline;

	//Creating The Process For Debugging
	cout << Filename.GetChar() << "\n";
	if (!CreateProcess(Filename.GetChar(), Commandline.GetChar(), NULL, NULL, false, DEBUG_ONLY_THIS_PROCESS,NULL,NULL, &si, &pi))
	{
		 cout << "Error in Creating The Process\n";
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
int cDebugger::Step()
{
	DWORD LastBp = 0;
	RefreshRegisters();
	if (LastBreakpoint != 0)
	{
		DWORD x = GetBreakpoint((DWORD)LastBreakpoint);
		DBG_BREAKPOINT* bp = (DBG_BREAKPOINT*)Breakpoints->GetItem(x);
		DebuggeeProcess->Write(LastBreakpoint,(DWORD)&bp->OriginalByte,1);
		LastBp = LastBreakpoint;
		Eip--;
		LastBreakpoint = 0;
	}
	EFlags |= 0x100;
	UpdateRegisters();
	int x = Run();
	if (LastBp != 0)
	{
		if (GetBreakpoint((DWORD)LastBp) != -1)
		{
			DWORD y = GetBreakpoint((DWORD)LastBp);
			DBG_BREAKPOINT* bp = (DBG_BREAKPOINT*)Breakpoints->GetItem(y);
			if (bp->IsActive == FALSE)return x;
			unsigned char b = 0xCC;
			DebuggeeProcess->Write(LastBp,(DWORD)&b,1);
		}
	}
	return x;
}

int cDebugger::Run()
{
	DWORD dwContinueStatus = DBG_CONTINUE;
	bContinueDebugging = 1;
	CONTEXT lcContext;

	if (LastBreakpoint != 0)
	{
		//cout << "Last Breakpoint: " << LastBreakpoint << "\n";
		DWORD x = GetBreakpoint((DWORD)LastBreakpoint);
		DBG_BREAKPOINT* bp = (DBG_BREAKPOINT*)Breakpoints->GetItem(x);
		lcContext.ContextFlags = CONTEXT_ALL;
		GetThreadContext((HANDLE)hThread, &lcContext);
		lcContext.Eip--;
		if (bp->IsActive == FALSE)
		{
			
			LastBreakpoint = 0;
		}
		else
		{
			DebuggeeProcess->Write(LastBreakpoint,(DWORD)&bp->OriginalByte,1);
			lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
		}
		SetThreadContext((HANDLE)hThread,&lcContext);
	}
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
			break;
		case EXCEPTION_DEBUG_EVENT:
			{
				EXCEPTION_DEBUG_INFO& exception = debug_event.u.Exception;
				RefreshRegisters();
				ExceptionCode = exception.ExceptionRecord.ExceptionCode;
				switch( exception.ExceptionRecord.ExceptionCode)
				{
				case STATUS_BREAKPOINT:
					{
						cout << "Here1 !!!\n\n";
						int bp = GetBreakpoint((DWORD)exception.ExceptionRecord.ExceptionAddress);
						if (bp == -1)LastBreakpoint = 0;
						LastBreakpoint = (DWORD)exception.ExceptionRecord.ExceptionAddress;
						return bp;
					}

				case STATUS_SINGLE_STEP:

					// Set the Breakpoint Again
					if (LastBreakpoint != 0)
					{
						if (GetBreakpoint((DWORD)LastBreakpoint) != -1)
						{
							unsigned char b = 0xCC;
							DebuggeeProcess->Write(LastBreakpoint,(DWORD)&b,1);
							LastBreakpoint = 0;
							break;
						}
						else return DBG_STATUS_STEP;
					}
					else return DBG_STATUS_STEP;
				default:
					cout << "Here2 !!!\n\n";
					ExceptionCode = exception.ExceptionRecord.ExceptionCode;
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
int cDebugger::GetBreakpoint(DWORD Address)
{
	DBG_BREAKPOINT* bp;
	//cout << "Breakpoint: " << hex << Address << "\n";
	for (DWORD i =0; i< Breakpoints->GetNumberOfItems(); i++)
	{
		bp = (DBG_BREAKPOINT*)Breakpoints->GetItem(i);
		//cout << "bp: " << bp->Address << "\n";
		if ( bp->Address == Address && bp->IsActive == TRUE) return i;
	}
	return -1;
}
BOOL cDebugger::SetBreakpoint(DWORD Address)
{
	BYTE* Ins = (BYTE*)DebuggeeProcess->Read(Address,1);

	if (Ins == NULL)return false;
	
	DWORD x = GetBreakpoint((DWORD)Address);
	if (x != -1)
	{
		DBG_BREAKPOINT* NewBp = (DBG_BREAKPOINT*)Breakpoints->GetItem(x);
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
	DWORD x = GetBreakpoint((DWORD)Address);
	DBG_BREAKPOINT* bp = (DBG_BREAKPOINT*)Breakpoints->GetItem(x);
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
			cout << hex << x << "\n";
			lcContext.Dr7 |= x;
			x = HardwareBreakpoints[i].Type;
			x = (x << (15+(2*i)));
			cout << hex << x << "\n";
			lcContext.Dr7 |= x;
			x = HardwareBreakpoints[i].Size;
			x = (x << (23+(2*i)));
			cout << hex << x << "\n";
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