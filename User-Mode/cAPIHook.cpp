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
#include <windows.h>
//#include <Winternl.h>
#include "SRDF.h"
#include <cstdio>


using namespace std;
using namespace Security::Libraries::Malware::Behavioral;

cAPIHook::cAPIHook( DWORD originalAddr, DWORD hookFunc)
{

	 memset(oldBytes,0,sizeof(oldBytes));
	 memset(JMP,0,sizeof(JMP));
	 OrgMemoryProtection = PAGE_EXECUTE_READWRITE;
	 this->OriginalAddr = originalAddr; 
	 this->HookFunc = hookFunc;
	 Hooked = false;
}

char* cAPIHook::HookAPI()
{
	if (Hooked)return oldBytes;
	
	JMP[0] = 0xE9;													//jmp long
	JMP[5] = 0x90;													//nop
	DWORD JMPSize = ((DWORD)HookFunc - (DWORD)OriginalAddr - 5);	//Get address difference

	if (!VirtualProtect((LPVOID)OriginalAddr, APIHOOK_BYTES_SIZE, PAGE_EXECUTE_READWRITE, &OrgMemoryProtection))
		MessageBoxA(0,"API HOOKING: Failed to ReadWrite ","Hooking",0);;
	
	memcpy(oldBytes, (DWORD*)OriginalAddr, APIHOOK_BYTES_SIZE);

	memcpy(&JMP[1], &JMPSize, 4);
	cString x = "";
	x.Format("API HOOKING: %x",OriginalAddr);
	//MessageBoxA(0,x.GetChar(),"Hooking",0);
	//x.Format("API HOOKING: %x",hookFunc);
	//MessageBoxA(0,x.GetChar(),"Hooking",0);
	memcpy((void*)OriginalAddr, JMP, APIHOOK_BYTES_SIZE);
	VirtualProtect((LPVOID)OriginalAddr, APIHOOK_BYTES_SIZE, OrgMemoryProtection, NULL);
	Hooked = true;
	return oldBytes;
	
}


void cAPIHook::UnhookAPI()
{
	if (!Hooked)return;
	VirtualProtect((LPVOID)OriginalAddr, APIHOOK_BYTES_SIZE, PAGE_EXECUTE_READWRITE, &OrgMemoryProtection); //ReadWrite again
	memcpy((void*)OriginalAddr, oldBytes, APIHOOK_BYTES_SIZE);
	DWORD NewProtection = 0;
	VirtualProtect((LPVOID)OriginalAddr, APIHOOK_BYTES_SIZE, OrgMemoryProtection, &NewProtection);
	Hooked = false;
}