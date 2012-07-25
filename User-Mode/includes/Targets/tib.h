/*
 *
 *  Copyright (C) 2010-2011 Amr Thabet <amr.thabet@student.alx.edu.eg>
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
 *  amr.thabet@student.alx.edu.eg
 *
 */
//#include <windows.h>
#include <winternl.h>

/*typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
*/

struct PEXCEPTION_REGISTRATION_RECORD
{
     PEXCEPTION_REGISTRATION_RECORD* Next;
     DWORD Handler;
};

struct TIB
{
     PEXCEPTION_REGISTRATION_RECORD* ExceptionList;  //FS:[0x00]
     DWORD StackBase;                               //FS:[0x04]
     DWORD StackLimit;                              //FS:[0x08]
     DWORD SubSystemTib;                            //FS:[0x0C]
     DWORD FiberData;                               //FS:[0x10]
     DWORD ArbitraryUserPointer;                    //FS:[0x14]
     DWORD TIBOffset;                                //FS:[0x18]
};
struct __PEB;
struct __TEB {

  DWORD                   EnvironmentPointer;			 				//+1C
  DWORD                   ProcessId;											//+20
  DWORD                   threadId;												//+24
  DWORD                   ActiveRpcInfo;									//+28
  DWORD                   ThreadLocalStoragePointer;			//+2C
  __PEB*                  Peb;														//+30
  DWORD                   LastErrorValue;                 //+34
  DWORD                   CountOfOwnedCriticalSections;
  DWORD                   CsrClientThread;
  DWORD                   Win32ThreadInfo;
  DWORD                   Win32ClientInfo[0x1F];
  DWORD                   WOW32Reserved;
  DWORD                   CurrentLocale;
  DWORD                   FpSoftwareStatusRegister;
  DWORD                   SystemReserved1[0x36];
  DWORD                   Spare1;
  DWORD                   ExceptionCode;
  DWORD                   SpareBytes1[0x28];
  DWORD                   SystemReserved2[0xA];
  DWORD                   GdiRgn;
  DWORD                   GdiPen;
  DWORD                   GdiBrush;
  DWORD                   RealClientId1;
  DWORD                   RealClientId2;
  DWORD                   GdiCachedProcessHandle;
  DWORD                   GdiClientPID;
  DWORD                   GdiClientTID;
  DWORD                   GdiThreadLocaleInfo;
  DWORD                   UserReserved[5];
  DWORD                   GlDispatchTable[0x118];
  DWORD                   GlReserved1[0x1A];
  DWORD                   GlReserved2;
  DWORD                   GlSectionInfo;
  DWORD                   GlSection;
  DWORD                   GlTable;
  DWORD                   GlCurrentRC;
  DWORD                   GlContext;
  DWORD                   LastStatusValue;
  char*                   StaticUnicodeString;
  char                    StaticUnicodeBuffer[0x105];
  DWORD                   DeallocationStack;
  DWORD                   TlsSlots[0x40];
  DWORD                   TlsLinks;
  DWORD                   Vdm;
  DWORD                   ReservedForNtRpc;
  DWORD                   DbgSsReserved[0x2];
  DWORD                   HardErrorDisabled;
  DWORD                   Instrumentation[0x10];
  DWORD                   WinSockData;
  DWORD                   GdiBatchCount;
  DWORD                   Spare2;
  DWORD                   Spare3;
  DWORD                   Spare4;
  DWORD                   ReservedForOle;
  DWORD                   WaitingOnLoaderLock;
  DWORD                   StackCommit;
  DWORD                   StackCommitMax;
  DWORD                   StackReserved;
};

struct __LIST_ENTRY{
        DWORD              Flink;        // Ptr32 _LIST_ENTRY
        DWORD              Blink;       // Ptr32 _LIST_ENTRY
};

struct _LDR_DATA_TABLE_ENTRY{
  __LIST_ENTRY               InLoadOrderLinks;              //+00
  __LIST_ENTRY               InMemoryOrderLinks;            //+08
  __LIST_ENTRY               InInitializationOrderLinks;    //+10
  DWORD                     DllBase;                        //+18
  DWORD                     EntryPoint;                     //+1C
  ULONG                     SizeOfImage;        //DWORD            //+20
  //DWORD                     FullDllNameLength;              //+24
  UNICODE_STRING            FullDllName; //_UNICODE_STRING  //+28
  //DWORD                     BaseDllNameLength;              //+2C
  UNICODE_STRING           BaseDllName; //_UNICODE_STRING  //+30
  DWORD                     Flags;                          //+34
  short                     LoadCount;                      //+38
  short                     TlsIndex;                       //+3C
  union{
  __LIST_ENTRY               HashLinks;
  DWORD                     SectionPointer;
  };
  DWORD                     CheckSum;
  union{
    DWORD                   TimeDateStamp;
    DWORD                   LoadedImports;
  };
  DWORD                     EntryPointActivationContext;
  DWORD                     PatchInformation;
  __LIST_ENTRY               ForwarderLinks;
  __LIST_ENTRY               ServiceTagLinks;
  __LIST_ENTRY               StaticLinks;
};

struct _PEB_LDR_DATA {
    DWORD                 Length_;                      //+00
    DWORD                 Initialized;                  //+04
    DWORD                 SsHandle;                     //+08
    __LIST_ENTRY           InLoadOrderModuleList;       //+0C
    __LIST_ENTRY           InMemoryOrderModuleList;     //+14
    __LIST_ENTRY           InInitializationOrderModuleList;//+1C
    DWORD                 EntryInProgress;              //+24  
    DWORD                 ShutdownInProgress;           //+28
    DWORD                 ShutdownThreadId;             //+2C
};  //size = 30


struct __RTl_USER_PROCESS_PARAMETERS;
struct __PEB {
  char                    InheritedAddressSpace;				//+00
  char                    ReadImageFileExecOptions;			//+01
  char                    BeingDebugged;
  char                    Spare;
  DWORD                   Mutant;												//+04
  DWORD                   ImageBaseAddress;							//+08
  _PEB_LDR_DATA*          LoaderData;										//+0C
  __RTl_USER_PROCESS_PARAMETERS*            ProcessParameters;						//+10
  DWORD                   SubSystemData;								//+14
  DWORD                   ProcessHeap;									//+18
  DWORD                   FastPebLock;								//+1C
  DWORD                   FastPebLockRoutine;						//+20
  DWORD                   FastPebUnlockRoutine;                     //+24
  DWORD                   EnvironmentUpdateCount;                   //+28
  DWORD                   KernelCallbackTable;                      //+2C
  DWORD                   EventLogSection;                          //+30
  DWORD                   EventLog;                                 //+34
  DWORD                   FreeList;                                 //+38
  DWORD                   TlsExpansionCounter;                      //+3C
  DWORD                   TlsBitmap;                                //+40
  DWORD                   TlsBitmapBits[0x2];
  DWORD                   ReadOnlySharedMemoryBase;
  DWORD                   ReadOnlySharedMemoryHeap;
  DWORD                   ReadOnlyStaticServerData;
  DWORD                   AnsiCodePageData;
  DWORD                   OemCodePageData;
  DWORD                   UnicodeCaseTableData;
  DWORD                   NumberOfProcessors;
  DWORD                   NtGlobalFlag;
  char                    Spare2[0x4];
  DWORD                   CriticalSectionTimeout1;
  DWORD                   CriticalSectionTimeout2;
  DWORD                   HeapSegmentReserve;
  DWORD                   HeapSegmentCommit;
  DWORD                   HeapDeCommitTotalFreeThreshold;
  DWORD                   HeapDeCommitFreeBlockThreshold;
  DWORD                   NumberOfHeaps;                               //+88
  DWORD                   MaximumNumberOfHeaps;                        //+8C
  DWORD                   *ProcessHeaps;                               //+90
  DWORD                   GdiSharedHandleTable;
  DWORD                   ProcessStarterHelper;
  DWORD                   GdiDCAttributeList;
  DWORD                   LoaderLock;
  DWORD                   OSMajorVersion;
  DWORD                   OSMinorVersion;
  DWORD                   OSBuildNumber;
  DWORD                   OSPlatformId;
  DWORD                   ImageSubSystem;
  DWORD                   ImageSubSystemMajorVersion;
  DWORD                   ImageSubSystemMinorVersion;
  DWORD                   GdiHandleBuffer[0x22];
  DWORD                   PostProcessInitRoutine;
  DWORD                   TlsExpansionBitmap;
  char                    TlsExpansionBitmapBits[0x80];
  DWORD                   SessionId;
};


struct __RTl_USER_PROCESS_PARAMETERS
{
BYTE Reservedl[56];
UNICODE_STRING ImagePathName;
UNICODE_STRING Commandline;
BYTE Reserved2[92];
};

struct __PROCESS_BASIC_INFORMATION {
    LONG ExitStatus;
    __PEB* PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

