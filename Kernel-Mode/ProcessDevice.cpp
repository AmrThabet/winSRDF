/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "SRDF.h"
#include <ntifs.h>
using namespace SRDF;

typedef NTSTATUS (*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );
    

typedef VOID (*INITIALIZE_APC) (
    PKAPC               Apc,
    PKTHREAD            Thread,
    UCHAR               StateIndex,
    PKKERNEL_ROUTINE    KernelRoutine,
    PKRUNDOWN_ROUTINE   RundownRoutine,
    PKNORMAL_ROUTINE    NormalRoutine,
    KPROCESSOR_MODE     ApcMode,
    PVOID               NormalContext
);

typedef BOOLEAN (*INSERTQUEUE_APC) (
    IN PKAPC        Apc,
    IN PVOID        SystemArgument1,
    IN PVOID        SystemArgument2,
    IN KPRIORITY    Increment
);

QUERY_INFO_PROCESS ZwQueryInformationProcess;
INITIALIZE_APC KeInitializeApc;
INSERTQUEUE_APC KeInsertQueueApc;
void ApcKernelRoutine( IN struct _KAPC *Apc, IN OUT PKNORMAL_ROUTINE *NormalRoutine, 
										   IN OUT PVOID *NormalContext, IN OUT PVOID *SystemArgument1, IN OUT PVOID *SystemArgument2 );


BOOLEAN ProcessDevice::AnalyzeProcess(DWORD ProcessId,DWORD ThreadId)
{
    NTSTATUS ntStatus;
    OBJECT_ATTRIBUTES ObjectAttributes; 
    ULONG ReturnedSize;
    CLIENT_ID clientID;
    
    if(KeGetCurrentIrql() > DISPATCH_LEVEL)
    {
		DbgPrint("AnalyzeProcess: IRQL too high. IRQL: %d", KeGetCurrentIrql());
		return FALSE;
	}
    Pid = ProcessId;
    Tid = ThreadId;
    InitializeObjectAttributes (&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    if (ZwQueryInformationProcess == NULL)
    {
    
        UNICODE_STRING routineName;
    
        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
    
        ZwQueryInformationProcess =(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
    
        if (ZwQueryInformationProcess == NULL)
        {
            DbgPrint("Cannot resolve ZwQueryInformationProcess");
            return FALSE;
        }
    }
    clientID.UniqueProcess = (HANDLE)ProcessId;
    clientID.UniqueThread = (HANDLE)ThreadId;
    
    ntStatus = ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientID);
    if (ntStatus != STATUS_SUCCESS)
    { 
       DbgPrint("Failed to open process\n");
       return FALSE;
    }
    ntStatus = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, (PVOID)&ProcessBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &ReturnedSize);

    if(ntStatus != STATUS_SUCCESS)
    { 
        DbgPrint("ZwQueryInformationProcess failed\n");
        ZwClose(ProcessHandle);
        return FALSE;
    }
    ntStatus = PsLookupProcessByProcessId((HANDLE)ProcessId, (PEPROCESS*)&EProcess);
    if(ntStatus != STATUS_SUCCESS)
    { 
        DbgPrint("PsLookupProcessByProcessId failed\n");
        ZwClose(ProcessHandle);
        return FALSE;
    }
    Peb = ProcessBasicInfo.PebBaseAddress;
    IsFound = TRUE;
    return TRUE;
}

BOOLEAN ProcessDevice::AttachProcess()
{
        if (IsFound == FALSE)return FALSE;
        KPCState = (KAPC_STATE*)malloc(sizeof(KAPC_STATE));
        KeStackAttachProcess((PRKPROCESS)&EProcess->Pcb, KPCState);
        IsAttached = TRUE;
        return TRUE;
}

VOID ProcessDevice::DetachProcess()
{
     if (IsAttached == FALSE)return;
     KeUnstackDetachProcess(KPCState);
     free(KPCState);
     IsAttached = FALSE;
} 

DWORD ProcessDevice::Allocate(DWORD Size,DWORD Protect)
{
      NTSTATUS ntStatus;
      DWORD BaseAddress = NULL;
      if (Size == 0)return NULL;
      ntStatus = ZwAllocateVirtualMemory(ProcessHandle,(PVOID*)&BaseAddress,0,&Size,MEM_RESERVE|MEM_COMMIT,Protect);
      if (ntStatus != STATUS_SUCCESS)
      {           
         DbgPrint("ZwAllocateVirtualMemory failed: %x", ntStatus);
         //DbgPrint("NT_STATUS_INVALID_PARAMETER_2 : %x", NT_STATUS_INVALID_PARAMETER_2);
         return NULL;
      }
      return BaseAddress;
}

char* ProcessDevice::Read(DWORD BufferPtr,DWORD Size)
{
        BOOLEAN ToDetach = FALSE;
        if (Size == 0)return NULL;
        if (IsAttached == FALSE)
        {
          if (!AttachProcess())return NULL;
          DbgPrint("Yes Here 1");
          ToDetach = TRUE;
        }
        DbgPrint("Yes Here 2");
        char* NewPlace = (char*)malloc(Size);
        memcpy(NewPlace,(char*)BufferPtr,Size);
        
        if (ToDetach) DetachProcess();
        return NewPlace;
}

BOOLEAN ProcessDevice::Write(DWORD Dest, char* Src, DWORD Size)
{
        BOOLEAN ToDetach = FALSE;
        if (Dest == NULL || Src == NULL || Size == 0)return FALSE;
        if (IsAttached == FALSE)
        {
          if (!AttachProcess())return FALSE;
          ToDetach = TRUE;
        }
        
        memcpy( (char*)Dest,Src,Size);
        
        if (ToDetach) DetachProcess();
        return TRUE;
}

BOOLEAN ProcessDevice::Execute (DWORD Entrypoint, PVOID Context)
{
        NTSTATUS ntStatus;
        PKAPC pkaApc;
        PETHREAD PEThread;
        UNICODE_STRING routineName;
        
        if (Tid == NULL || Entrypoint == NULL)return FALSE;
        ntStatus = PsLookupThreadByThreadId((HANDLE)Tid,&PEThread);
        if(ntStatus != STATUS_SUCCESS)
        { 
            DbgPrint("PsLookupThreadByThreadId failed");
            return FALSE;
        }

        RtlInitUnicodeString(&routineName, L"KeInitializeApc");
        KeInitializeApc =(INITIALIZE_APC)MmGetSystemRoutineAddress(&routineName);
        
        RtlInitUnicodeString(&routineName, L"KeInsertQueueApc");
        KeInsertQueueApc =(INSERTQUEUE_APC)MmGetSystemRoutineAddress(&routineName);
        
        if (KeInitializeApc == NULL || KeInsertQueueApc == NULL)
        {
           DbgPrint("Getting APC Functions Address Failed");
           return FALSE;
        }
        
        pkaApc= (PKAPC)malloc(sizeof(KAPC));
         if(pkaApc!=0)
         {
            KeInitializeApc(pkaApc,PEThread,0,ApcKernelRoutine,0,(PKNORMAL_ROUTINE)Entrypoint,UserMode,Context);
            KeInsertQueueApc(pkaApc,0,0,IO_NO_INCREMENT);
            return TRUE;
         }

        return FALSE;
}
void ApcKernelRoutine( IN struct _KAPC *Apc, IN OUT PKNORMAL_ROUTINE *NormalRoutine, 
										   IN OUT PVOID *NormalContext, IN OUT PVOID *SystemArgument1, IN OUT PVOID *SystemArgument2 ) 
{
	DbgPrint("ApcKernelRoutine called");
}
