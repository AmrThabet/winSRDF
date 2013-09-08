// APIHooking.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../../../SRDF.h"

using namespace Security::Libraries::Malware::Behavioral;

DLLIMPORT int  WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uiType);
cAPIHook* cAPIHook_obj;


int _tmain(int argc, _TCHAR* argv[])
{
	DWORD pOrigMBAddress = (DWORD) GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxW");
	cAPIHook_obj = new cAPIHook(pOrigMBAddress ,(DWORD)&MyMessageBoxW);
	cAPIHook_obj->HookAPI();
	MessageBoxW(NULL, L"Not Hooked !!!", L"Not Hooked", MB_ICONEXCLAMATION);
	return 0;
}

DLLIMPORT int  WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uiType)
{

	cAPIHook_obj->UnhookAPI();
	MessageBoxW(NULL, L"The API Has been Hooked !!!", L"Hooked", MB_ICONEXCLAMATION);
	cAPIHook_obj->HookAPI();
	return 0;
}
