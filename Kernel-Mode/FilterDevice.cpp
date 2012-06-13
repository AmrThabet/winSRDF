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

using namespace RDF;

extern POBJECT_TYPE* IoDriverObjectType;

NTSTATUS FilterDevice::IrpDispatcher(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    NTSTATUS NtStatus;  
       
    UCHAR MJ = Irp->Tail.Overlay.CurrentStackLocation->MajorFunction;
    
    if (QueryDeviceObject(DeviceObject) != -1){
        DWORD retType = FILTER_SKIP;
        if (FilteredMajorFunction[MJ].PreModification != NULL)retType = (DWORD)(*FilteredMajorFunction[MJ].PreModification)(this,DeviceObject,Irp);
        if (retType != FILTER_SKIP)DbgPrint("RetType Now == 0x%x",retType);
        switch(retType)
        {
         case FILTER_SKIP:
              //DbgPrint("Skip Function");     
              IoSkipCurrentIrpStackLocation(Irp);
              return IoCallDriver(((PFILTERDEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedDeviceObject, Irp);
              
         case FILTER_COMPLETE_REQUEST_SUCCESS:
              DbgPrint("Complete Request Success");
              Irp->IoStatus.Status = STATUS_SUCCESS;   
              IoCompleteRequest(Irp, IO_NO_INCREMENT);   
              return STATUS_SUCCESS;
              
         case FILTER_COMPLETE_REQUEST:
              DbgPrint("Complete Request");
              NtStatus = Irp->IoStatus.Status;   
              IoCompleteRequest(Irp, IO_NO_INCREMENT);
              return NtStatus;
              
         case FILTER_CALLDRIVER:
              return IoCallDriver(((PFILTERDEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedDeviceObject, Irp);
              
         case FILTER_SET_POST_MODFICATION:
              DbgPrint("Set Compeletion Routine");
              if (FilteredMajorFunction[MJ].PostModification != NULL)
              {
                  PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
                  IoCopyCurrentIrpStackLocationToNext(Irp);
                  IoSetCompletionRoutine(Irp, (PIO_COMPLETION_ROUTINE) &FDCompletionRoutine, NULL, TRUE, FALSE, FALSE);
                  NtStatus = IoCallDriver(((PFILTERDEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedDeviceObject, Irp);
                  return NtStatus;
              }
              else
              {
                  IoSkipCurrentIrpStackLocation(Irp);
                  NtStatus = IoCallDriver(((PFILTERDEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedDeviceObject, Irp);
                  return NtStatus;
              }
        }
        
    }else if(pDeviceObject == DeviceObject){
        
        NtStatus = STATUS_SUCCESS;
        if (MajorFunction[MJ] != NULL)NtStatus = (*MajorFunction[MJ])(this,DeviceObject,Irp);
        Irp->IoStatus.Status = NtStatus;   
        IoCompleteRequest(Irp, IO_NO_INCREMENT);   
        return STATUS_SUCCESS;   
    }
};

VOID FilterDevice::Pending(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    KEVENT   event;
    NTSTATUS ntStatus;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,FDCompletionRoutine,&event,TRUE,TRUE,TRUE);
    ntStatus = IoCallDriver(((PFILTERDEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedDeviceObject, Irp);
    if (ntStatus == STATUS_PENDING) {
        
       KeWaitForSingleObject(&event,Executive,KernelMode,FALSE,NULL);
       ntStatus = Irp->IoStatus.Status;
    }
}
NTSTATUS RDF::FDCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
         
    NTSTATUS status;
    DbgPrint("Completion Routine Complete Request");
    if(Context != NULL)
    {
        if (Irp->PendingReturned == TRUE) {
              KeSetEvent ((PKEVENT) Context, IO_NO_INCREMENT, FALSE);                   
        }
        return STATUS_MORE_PROCESSING_REQUIRED;  
    }
    else
    {
        status = Irp->IoStatus.Status;
        return STATUS_SUCCESS;    
        
        UCHAR MJ = Irp->Tail.Overlay.CurrentStackLocation->MajorFunction;
        FilterDevice* FDevice = ((PFILTERDEVICE_EXTENSION)DeviceObject->DeviceExtension)->FilterDevicePtr;
        DWORD RetType = FILTER_SKIP;
        if (FDevice->FilteredMajorFunction[MJ].PostModification != NULL)
           RetType = (*FDevice->FilteredMajorFunction[MJ].PostModification)(FDevice,DeviceObject,Irp);
           
        switch(RetType)
        {
         case FILTER_COMPLETE_REQUEST:
              DbgPrint("Compeletion Routine Complete Request");
              status = Irp->IoStatus.Status;
              IoCompleteRequest( Irp, IO_NO_INCREMENT );
              return status;
         default:
              return STATUS_MORE_PROCESSING_REQUIRED;
        }   
    }
}

int FilterDevice::QueryDeviceObject(PDEVICE_OBJECT DeviceObject){
    for (int l=0;l<nDeviceObjects;l++){
        if (inheritedDeviceObject[l] == DeviceObject){
            return l;
        }
    };
    return -1;
};

int FilterDevice::AddDeviceObject(PDEVICE_OBJECT DeviceObject){
    int DeviceId = QueryDeviceObject(DeviceObject);
    
    if (DeviceId != -1)return DeviceId;
    
    if (nDeviceObjects >= MAX_DEVICES)return -1;
    
    inheritedDeviceObject[nDeviceObjects] = DeviceObject;
    nDeviceObjects++;
    DbgPrint("Added Device No.%x",nDeviceObjects);
    return (nDeviceObjects-1);
}

int FilterDevice::RemoveDeviceObject(PDEVICE_OBJECT DeviceObject){
    int DeviceId = QueryDeviceObject(DeviceObject);
    
    if (DeviceId == -1)return -1;
    
    for (int i = DeviceId;i<nDeviceObjects-1 ;i++){
          inheritedDeviceObject[i] = inheritedDeviceObject[i+1];
    };
    nDeviceObjects--;
    
    return 0;
};
NTSTATUS FilterDevice::AttachToDevice(__in WCHAR* DeviceName)
{
        DbgPrint("Attach to Device (with Name)"); 
        NTSTATUS ntStatus;
        PDEVICE_OBJECT DeviceObject = NULL;
        PFILE_OBJECT fileObject;
        UNICODE_STRING nameString;
        
        RtlInitUnicodeString(&nameString, DeviceName);
        ntStatus = IoGetDeviceObjectPointer( &nameString,FILE_READ_DATA, &fileObject, &DeviceObject);
        if (ntStatus != STATUS_SUCCESS)
        {
           DbgPrint("Failed To Attach Device");
           return ntStatus;
        }
        AttachToDevice(DeviceObject);
        DbgPrint("Device Attached");
        return STATUS_SUCCESS;
}
NTSTATUS FilterDevice::AttachToDevice(__in PDEVICE_OBJECT DeviceObject)
{        
         NTSTATUS ntStatus;
         PDEVICE_OBJECT newDeviceObject = NULL;
         int DeviceId = 0;
         if (IsAlreadyAttached(DeviceObject))return STATUS_SUCCESS;                         //Already Attached
         
         
         ntStatus = IoCreateDevice(pDriver->pDriverObject, sizeof(FILTERDEVICE_EXTENSION), NULL, DeviceObject->DeviceType, 0, FALSE, &newDeviceObject);
         memset(newDeviceObject->DeviceExtension, 0,sizeof(FILTERDEVICE_EXTENSION));
         if(ntStatus != STATUS_SUCCESS)return ntStatus;
         DbgPrint("IRQL = %x",(DWORD)KeGetCurrentIrql());
         
         IoAttachDeviceToDeviceStackSafe( newDeviceObject,DeviceObject,&((PFILTERDEVICE_EXTENSION)newDeviceObject->DeviceExtension)->AttachedDeviceObject);
         if(ntStatus != STATUS_SUCCESS){
                      IoDeleteDevice(newDeviceObject);
                      return ntStatus;
         }
         if ( DeviceObject->Flags & DO_BUFFERED_IO) {
            newDeviceObject->Flags |= DO_BUFFERED_IO;
         }
         if (DeviceObject->Flags & DO_DIRECT_IO ) {
            newDeviceObject->Flags |= DO_DIRECT_IO;
         }
         if (DeviceObject->Characteristics & FILE_DEVICE_SECURE_OPEN) {
            newDeviceObject->Characteristics |= FILE_DEVICE_SECURE_OPEN;
         }
         newDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
         DeviceId = AddDeviceObject(newDeviceObject);
         DbgPrint("Device Attached");
         return STATUS_SUCCESS;
}

BOOLEAN FilterDevice::IsAlreadyAttached(__in PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_OBJECT currentDevObj;
    PDEVICE_OBJECT nextDevObj;
    currentDevObj = IoGetAttachedDeviceReference(DeviceObject);
    do 
    {
        if (QueryDeviceObject(currentDevObj) != -1)
        {
           ObDereferenceObject( currentDevObj );
           return TRUE;
        }
        nextDevObj = currentDevObj->AttachedDevice;
        ObDereferenceObject( currentDevObj );
        currentDevObj = nextDevObj;
        
    }while (NULL != currentDevObj);
    
    DbgPrint("It's not Attached");
    return FALSE;
}

VOID FilterDevice::Initialize(Driver* driver)
{
     pDriver = driver;
     Type = _FILTERDEVICE;
};

VOID FilterDevice::Unload()
{
    for (int l=0;l<nDeviceObjects;l++){
        if (inheritedDeviceObject[l]->DeviceExtension != NULL)
        {
           _try
           {                                           
                IoDetachDevice(((PFILTERDEVICE_EXTENSION)inheritedDeviceObject[l]->DeviceExtension)->AttachedDeviceObject);
                DbgPrint("Device Detached");
           }_finally
           {
             
           }
        }
    };
    if (DeviceCreated){
        IoDeleteSymbolicLink(&SymbolicName);
    	IoDeleteDevice(pDeviceObject); 
    	DbgPrint("Device Unloaded");
    }
    
    //Delay For 5 Seconds
    LARGE_INTEGER interval;
    interval.QuadPart = 5 * DELAY_ONE_SECOND;
    KeDelayExecutionThread(KernelMode,FALSE,&interval);
    for (int l=0;l<nDeviceObjects;l++)IoDeleteDevice(inheritedDeviceObject[l]);
}
NTSTATUS FilterDevice::DetachDevice(__in WCHAR* DeviceName)
{
        DbgPrint("Detach From Device (with Name)"); 
        NTSTATUS ntStatus;
        PDEVICE_OBJECT DeviceObject = NULL;
        PFILE_OBJECT fileObject;
        UNICODE_STRING nameString;
        
        RtlInitUnicodeString(&nameString, DeviceName);
        ntStatus = IoGetDeviceObjectPointer( &nameString,FILE_READ_DATA, &fileObject, &DeviceObject);
        if (ntStatus != STATUS_SUCCESS)
        {
           DbgPrint("Failed To Detach Device");
           return ntStatus;
        }
        DetachDevice(DeviceObject);
        DbgPrint("Device Detached");
        return STATUS_SUCCESS;
}
VOID FilterDevice::DetachDevice(PDEVICE_OBJECT DeviceObject)
{
     PDEVICE_OBJECT ourAttachedDevice;
     PFILTERDEVICE_EXTENSION devExt;
     
     ourAttachedDevice = DeviceObject->AttachedDevice;

    while (NULL != ourAttachedDevice) {
        for (int l=0;l<nDeviceObjects;l++){
            if (ourAttachedDevice == inheritedDeviceObject[l]){
                devExt = (PFILTERDEVICE_EXTENSION)ourAttachedDevice->DeviceExtension;
    
                //
                //  Detach
                //
    
                UNREFERENCED_PARAMETER( ourAttachedDevice );
                IoDetachDevice( DeviceObject );
                IoDeleteDevice( ourAttachedDevice );
                RemoveDeviceObject(ourAttachedDevice);
                DbgPrint("Device Detached");
                return;
            }
        };
        //
        //  Look at the next device up in the attachment chain
        //

        DeviceObject = ourAttachedDevice;
        ourAttachedDevice = ourAttachedDevice->AttachedDevice;
    }
    DbgPrint("Device Not Found");
}
/*
VOID GetBuffers(__in PDEVICE_OBJECT DeviceObject,__in PIRP IrpIrp,WCHAR* &InputBuffer,WCHAR* &OutputBuffer,DWORD &InputLength,DWORD &OutputLength)
{
     NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
     PIO_STACK_LOCATION pIoStackIrp = NULL;
     
     pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);    
     if(DeviceObject->Flags & DO_BUFFERED_IO)
     {
                            
     }else if (DeviceObject->Flags & DO_DIRECT_IO)
     {
           
     }
}
GetBuffers()
{
        if(Irp->IoStatus.Information)
        {
            /*
             * Our filter device is dependent upon the compliation settings of how we compiled example.sys
             * That means we need to dynamically figure out if we're using Direct, Buffered or Neither.
             /
            if(DeviceObject->Flags & DO_BUFFERED_IO)
            {

                    DbgPrint("ExampleFilter_Read - Use Buffered I/O \r\n");
                    /*
                     * Implementation for Buffered I/O
                     /

                    pReadDataBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
                
                    if(pReadDataBuffer && pIoStackIrp->Parameters.Read.Length > 0)
                    {                             
                        ExampleFilter_FixNullString(pReadDataBuffer, (UINT)Irp->IoStatus.Information);
                    }
            }
            else
            {
                if(DeviceObject->Flags & DO_DIRECT_IO)
                {
                    DbgPrint("ExampleFilter_Read - Use Direct I/O \r\n");
                    /*
                     * Implementation for Direct I/O
                     /
                    if(pIoStackIrp && Irp->MdlAddress)
                    {
                        pReadDataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                    
                        if(pReadDataBuffer && pIoStackIrp->Parameters.Read.Length)
                        {                             
                            ExampleFilter_FixNullString(pReadDataBuffer, (UINT)Irp->IoStatus.Information);
                        }
                    }
                }
                else
                {

                    DbgPrint("ExampleFilter_Read - Use Neither I/O \r\n");

                    /*
                     * Implementation for Neither I/O
                     /
                    __try {
        
                            if(pIoStackIrp->Parameters.Read.Length > 0 && Irp->UserBuffer)
                            {
                    
                                ProbeForWrite(Irp->UserBuffer, pIoStackIrp->Parameters.Read.Length, TYPE_ALIGNMENT(char));
                                pReadDataBuffer = Irp->UserBuffer;
                    
                                ExampleFilter_FixNullString(pReadDataBuffer, (UINT)Irp->IoStatus.Information);
                            }
                    
                        } __except( EXCEPTION_EXECUTE_HANDLER ) {
                    
                              NtStatus = GetExceptionCode();     
                        }
                }
            }

        }            
}
*/
