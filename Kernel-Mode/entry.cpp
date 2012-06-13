/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet <amr.thabet@student.alx.edu.eg>
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

#include "RDF.h"
//#include <ntddk.h>

using namespace RDF;
using namespace RDF::misc;
using namespace RDF::FileManager;

VOID SetFastIoDispatch(IN PDRIVER_OBJECT pDriverObject);


NTSTATUS IrpDispatcherToDriver(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);

Driver* driver;

NTSTATUS FsFilterDispatchPassThrough(
    __in PDEVICE_OBJECT DeviceObject, 
    __in PIRP           Irp
    );
    
VOID SfCleanupMountedDevice (IN PDEVICE_OBJECT DeviceObject)
/*++

Routine Description:

    This cleans up any necessary data in the device extension to prepare for
    this memory to be freed.

Arguments:

    DeviceObject - The device we are cleaning up

Return Value:

    None

--*/
{        

    UNREFERENCED_PARAMETER( DeviceObject );
}


VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING usDosDeviceName;
	DbgPrint("HideProc_Unload Called\n");
    PFAST_IO_DISPATCH fastIoDispatch;
    LARGE_INTEGER interval;
	if(driver->FSIsRegistered)IoUnregisterFsRegistrationChange(driver->pDriverObject, (PDRIVER_FS_NOTIFICATION)FileFilterNotificationDispatcher);
	
	driver->OnUnload();
	
    interval.QuadPart = (5 * DELAY_ONE_SECOND);      //delay 5 seconds
    KeDelayExecutionThread( KernelMode, FALSE, &interval );
    fastIoDispatch = DriverObject->FastIoDispatch;
    DriverObject->FastIoDispatch = NULL;
    free( fastIoDispatch );
    free(driver);
}
VOID FileFilterNotificationDispatcher(PDEVICE_OBJECT TargetDevice,int command)
{
     return driver->FileFilterNotificationDispatcher(TargetDevice,command);
}
extern "C" 
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING theRegistryPath )
{
	PDEVICE_OBJECT pDeviceObject;
	NTSTATUS ntStatus;
	driver = (Driver*)CreateClass(sizeof(Driver));
	driver->pDriverObject = pDriverObject;
	DbgPrint("DriverEntry : 0x%x",(DWORD)DriverEntry);
	
	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) 
    {
        pDriverObject->MajorFunction[i] = IrpDispatcherToDriver;
    }
    
    pDriverObject->DriverUnload	= OnUnload;
    
    SetFastIoDispatch(pDriverObject);
    
    driver->DriverMain(pDriverObject,theRegistryPath);
    
    if(driver->nFSRegisteredDevices != 0)
    {
       IoRegisterFsRegistrationChange(driver->pDriverObject, (PDRIVER_FS_NOTIFICATION)FileFilterNotificationDispatcher); 
       driver->FSIsRegistered = TRUE;                            
    }
     
	return STATUS_SUCCESS;
};


VOID SetFastIoDispatch(IN PDRIVER_OBJECT pDriverObject)
{
     PFAST_IO_DISPATCH fastIoDispatch;
     fastIoDispatch = (PFAST_IO_DISPATCH)malloc(sizeof( FAST_IO_DISPATCH ));
     RtlZeroMemory( fastIoDispatch, sizeof( FAST_IO_DISPATCH ) );

    fastIoDispatch->SizeOfFastIoDispatch = sizeof( FAST_IO_DISPATCH );
    fastIoDispatch->FastIoCheckIfPossible = FsFilterFastIoCheckIfPossible;
    fastIoDispatch->FastIoRead = FsFilterFastIoRead;
    fastIoDispatch->FastIoWrite = FsFilterFastIoWrite;
    fastIoDispatch->FastIoQueryBasicInfo = FsFilterFastIoQueryBasicInfo;
    fastIoDispatch->FastIoQueryStandardInfo = FsFilterFastIoQueryStandardInfo;
    fastIoDispatch->FastIoLock = FsFilterFastIoLock;
    fastIoDispatch->FastIoUnlockSingle = FsFilterFastIoUnlockSingle;
    fastIoDispatch->FastIoUnlockAll = FsFilterFastIoUnlockAll;
    fastIoDispatch->FastIoUnlockAllByKey = FsFilterFastIoUnlockAllByKey;
    fastIoDispatch->FastIoDeviceControl = FsFilterFastIoDeviceControl;
    fastIoDispatch->FastIoDetachDevice = FsFilterFastIoDetachDevice;
    fastIoDispatch->FastIoQueryNetworkOpenInfo = FsFilterFastIoQueryNetworkOpenInfo;
    fastIoDispatch->MdlRead = FsFilterFastIoMdlRead;
    fastIoDispatch->MdlReadComplete = FsFilterFastIoMdlReadComplete;
    fastIoDispatch->PrepareMdlWrite = FsFilterFastIoPrepareMdlWrite;
    fastIoDispatch->MdlWriteComplete = FsFilterFastIoMdlWriteComplete;
    fastIoDispatch->FastIoReadCompressed = FsFilterFastIoReadCompressed;
    fastIoDispatch->FastIoWriteCompressed = FsFilterFastIoWriteCompressed;
    fastIoDispatch->MdlReadCompleteCompressed = FsFilterFastIoMdlReadCompleteCompressed;
    fastIoDispatch->MdlWriteCompleteCompressed = FsFilterFastIoMdlWriteCompleteCompressed;
    fastIoDispatch->FastIoQueryOpen = FsFilterFastIoQueryOpen;

    pDriverObject->FastIoDispatch = fastIoDispatch;
}
/*
VOID SetFastIoDispatch(IN PDRIVER_OBJECT pDriverObject)
{
     PFAST_IO_DISPATCH fastIoDispatch;
     fastIoDispatch = (PFAST_IO_DISPATCH)malloc(sizeof( FAST_IO_DISPATCH ));
     RtlZeroMemory( fastIoDispatch, sizeof( FAST_IO_DISPATCH ) );

    fastIoDispatch->SizeOfFastIoDispatch = sizeof( FAST_IO_DISPATCH );
    fastIoDispatch->FastIoCheckIfPossible = SfFastIoCheckIfPossible;
    fastIoDispatch->FastIoRead = SfFastIoRead;
    fastIoDispatch->FastIoWrite = SfFastIoWrite;
    fastIoDispatch->FastIoQueryBasicInfo = SfFastIoQueryBasicInfo;
    fastIoDispatch->FastIoQueryStandardInfo = SfFastIoQueryStandardInfo;
    fastIoDispatch->FastIoLock = SfFastIoLock;
    fastIoDispatch->FastIoUnlockSingle = SfFastIoUnlockSingle;
    fastIoDispatch->FastIoUnlockAll = SfFastIoUnlockAll;
    fastIoDispatch->FastIoUnlockAllByKey = SfFastIoUnlockAllByKey;
    fastIoDispatch->FastIoDeviceControl = SfFastIoDeviceControl;
    fastIoDispatch->FastIoDetachDevice = SfFastIoDetachDevice;
    fastIoDispatch->FastIoQueryNetworkOpenInfo = SfFastIoQueryNetworkOpenInfo;
    fastIoDispatch->MdlRead = SfFastIoMdlRead;
    fastIoDispatch->MdlReadComplete = SfFastIoMdlReadComplete;
    fastIoDispatch->PrepareMdlWrite = SfFastIoPrepareMdlWrite;
    fastIoDispatch->MdlWriteComplete = SfFastIoMdlWriteComplete;
    fastIoDispatch->FastIoReadCompressed = SfFastIoReadCompressed;
    fastIoDispatch->FastIoWriteCompressed = SfFastIoWriteCompressed;
    fastIoDispatch->MdlReadCompleteCompressed = SfFastIoMdlReadCompleteCompressed;
    fastIoDispatch->MdlWriteCompleteCompressed = SfFastIoMdlWriteCompleteCompressed;
    fastIoDispatch->FastIoQueryOpen = SfFastIoQueryOpen;

    pDriverObject->FastIoDispatch = fastIoDispatch;
}
*/
NTSTATUS IrpDispatcherToDriver(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp){

    return driver->MultiDeviceIrpDispatcher(DeviceObject,Irp);
};

PVOID RDF::misc::CreateClass(unsigned long nLength)
{
    PVOID x = malloc(nLength);
    memset(x,0,nLength);
    return x;
}

bool RDF::misc::AllocateMDL(PMDL &Mdl,char* Buffer, DWORD size)
{
    Mdl = IoAllocateMdl(Buffer, size, FALSE, FALSE, NULL);
    if(Mdl)
    {

        __try {

            MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);

        } __except (EXCEPTION_EXECUTE_HANDLER) {
                IoFreeMdl(Mdl);
                Mdl = NULL;
        };

        if(Mdl)return TRUE;
        else return FALSE;
     }
};

NTSTATUS FsFilterDispatchPassThrough(
    __in PDEVICE_OBJECT DeviceObject, 
    __in PIRP           Irp
    )
{
    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(pDevExt->AttachedToDeviceObject, Irp);
}
