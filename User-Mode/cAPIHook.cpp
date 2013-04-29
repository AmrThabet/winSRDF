#include "stdafx.h"
//#include <windows.h>
//#include <Winternl.h>
#include "SRDF.h"
#include <cstdio>


using namespace std;
using namespace Security::Libraries::Malware::OS::Win32::Behavioral;

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
	DWORD JMPSize = ((DWORD)HookFunc - (DWORD)OriginalAddr - 5);	//Get address difference

	VirtualProtect((LPVOID)OriginalAddr, APIHOOK_BYTES_SIZE, PAGE_EXECUTE_READWRITE, &OrgMemoryProtection);
	memcpy(oldBytes, (DWORD*)OriginalAddr, APIHOOK_BYTES_SIZE);

	memcpy(&JMP[1], &JMPSize, 4);
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