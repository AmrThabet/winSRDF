#include "stdafx.h"
//#include <windows.h>
//#include <Winternl.h>
#include "SRDF.h"
#include <cstdio>


using namespace std;
using namespace Security::Libraries::Malware::OS::Win32::Hooking;

cAPIHook::cAPIHook( DWORD pOrigMBAddress, DWORD pNewFunc)
{

 oldBytes[0] = 0; //This will hold the overwritten bytes
 JMP[0] = 0;	//This holds the JMP to our code
 oldProtect, myProtect = PAGE_EXECUTE_READWRITE; //Protection settings on memory
 this->pOrigMBAddress = pOrigMBAddress; 
 this->pNewFunc = pNewFunc;

}

BYTE* cAPIHook::myHook()
{


    sprintf_s(debugBuffer, 128, "pOrigMBAddress: %x , %x", pOrigMBAddress,pNewFunc);
	OutputDebugString(debugBuffer);
	BYTE tempJMP[SIZE] = {0xE9, 0x90, 0x90, 0x90, 0x90, 0x90};		//JMP <NOP>  for now
	memcpy(JMP, tempJMP, SIZE);										//Copy into global for convenience later
	DWORD JMPSize = ((DWORD)pNewFunc - (DWORD)pOrigMBAddress - 5);	//Get address difference

	//Change memory settings to make sure we can write the JMP in
	
	VirtualProtect((LPVOID)pOrigMBAddress, SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(oldBytes, (DWORD*)pOrigMBAddress, SIZE);							//Copy old bytes before writing JMP
	sprintf_s(debugBuffer, 128, "Old bytes: %x%x%x%x%x", oldBytes[0], oldBytes[1],oldBytes[2], oldBytes[3], oldBytes[4], oldBytes[5]);
	OutputDebugString(debugBuffer);
	memcpy(&JMP[1], &JMPSize, 4);									//Write the address to JMP to
	sprintf_s(debugBuffer, 128, "JMP: %x%x%x%x%x%x", JMP[0], JMP[1],JMP[2], JMP[3], JMP[4], JMP[5]);
	OutputDebugString(debugBuffer);
	memcpy((void*)pOrigMBAddress, JMP, SIZE);						//Write it in process memory
	VirtualProtect((LPVOID)pOrigMBAddress, SIZE, oldProtect, NULL); //Change setts back
	
	return oldBytes;
	
}


void cAPIHook::myUnHook()
{
	VirtualProtect((LPVOID)pOrigMBAddress, SIZE, myProtect, NULL); //ReadWrite again
	memcpy((void*)pOrigMBAddress, oldBytes, SIZE);
}