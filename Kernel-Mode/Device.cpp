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
using namespace RDF::FileManager;
using namespace RDF::RegistryManager;

int UserComm_DeviceIO(Device* device,__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);


Device::Device(){
         //SetValue(MajorFunction[1].PostModification,Device::CreateDevice);
}                


NTSTATUS Device::CreateDevice(WCHAR* DeviceName,WCHAR* SymbolicName){
    
    DbgPrint("New Device Created at %x",this);
    RtlInitUnicodeString(&this->DeviceName, DeviceName);
    RtlInitUnicodeString(&this->SymbolicName, SymbolicName); 
    DbgPrint("DriverObject : %x",(DWORD)pDriver->pDriverObject);
	NTSTATUS ntStatus = IoCreateDevice(pDriver->pDriverObject,0, &this->DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &this->pDeviceObject);
	if(NT_SUCCESS(ntStatus)){
		
		pDeviceObject->Flags |= DO_DIRECT_IO;
		pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
		IoCreateSymbolicLink(&this->SymbolicName, &this->DeviceName);
		DbgPrint("Created The Device Sucessfully\n");
		DeviceCreated = true;
		SetValue(MajorFunction[IRP_MJ_DEVICE_CONTROL],Device::UserComm_DeviceIO);
		//MajorFunction[IRP_MJ_DEVICE_CONTROL] = &UserComm_DeviceIO;
		
	}else {
	      DbgPrint("Failed To create The Device\n");
	      DeviceCreated = false;
    }
    return ntStatus;
}
VOID Device::Unload()
{
    if (DeviceCreated){
        IoDeleteSymbolicLink(&SymbolicName);
    	IoDeleteDevice(pDeviceObject); 
    	DbgPrint("Device Unloaded");
    }
}
NTSTATUS Device::IrpDispatcher(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp){
    UCHAR MJ = Irp->Tail.Overlay.CurrentStackLocation->MajorFunction;
    NTSTATUS status = STATUS_SUCCESS;
    if (MajorFunction[MJ] != NULL)status = (*MajorFunction[MJ])(this,DeviceObject,Irp);
    DbgPrint("Device : MJ Called : %x",MJ);
    Irp->IoStatus.Status = status;   
    IoCompleteRequest(Irp, IO_NO_INCREMENT);   
    return STATUS_SUCCESS;   
};
VOID Device::Initialize(Driver* driver)
{
     pDriver = driver;
     Type = _DEVICE;
}
//================================================================================================
//User Communication

NTSTATUS Device::UserCommunication::Write(char msgcode,DWORD status,char* data,DWORD size)
{
    if(NeedToSend != true){
        buffer.msgcode = msgcode;
        buffer.status = status;
        buffer.size = size;
        this->data = data;
        NeedToSend = true;
        return STATUS_SUCCESS;
    }else{
        return STATUS_ERROR;
    }
};

VOID Device::UserCommunication::RegisterReadFunction(PReadFunc readfunction)
{
   ReadFunction = readfunction;
}

VOID Device::UserCommunication::RegisterFastMsgFunction(PFastMsgFunc fastmsgfunction)
{
    FastMsgFunction = fastmsgfunction;
}

int _cdecl Device::UserComm_DeviceIO(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    DbgPrint("DeviceIO");
    _IO_STACK_LOCATION* IrpStack = Irp->Tail.Overlay.CurrentStackLocation;
    UserCommunication::CommChannel* pInputBuffer = (UserCommunication::CommChannel*)Irp->AssociatedIrp.SystemBuffer;
    UserCommunication::CommChannel* pOutputBuffer = (UserCommunication::CommChannel*)Irp->AssociatedIrp.SystemBuffer;
    DWORD OutputMaxLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
    
    //IOCTL_WRITEDATA
    if (IrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_WRITEDATA)
    {
       if (UserComm.ReadFunction !=NULL)
            (*UserComm.ReadFunction)(pInputBuffer->msgcode,pInputBuffer->status,pInputBuffer->size,&pInputBuffer->data);
            DbgPrint("%s",&pInputBuffer->data);
    
    //IOCTL_FASTMSG
    }else if (IrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_FASTMSG){
        
       DWORD ReturnSize = 0;
       DWORD ReturnStatus = 0;
       if (UserComm.FastMsgFunction !=NULL){
                (*UserComm.FastMsgFunction)(pInputBuffer->msgcode,pInputBuffer->status,pInputBuffer->size,
                        &pInputBuffer->data,&pOutputBuffer->data,OutputMaxLength,ReturnStatus,ReturnSize);
                        pOutputBuffer->status = ReturnStatus;
                        Irp->IoStatus.Information = ReturnSize + sizeof(UserCommunication::CommChannel);
                    }
    
    //IOCTL_READREQUEST
    }else if (IrpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_READREQUEST && UserComm.NeedToSend){
       
       if (UserComm.buffer.size >= OutputMaxLength){
            pOutputBuffer->size = UserComm.buffer.size; 
            Irp->IoStatus.Information =sizeof(UserCommunication::CommChannel); 
        }else{
            pOutputBuffer->msgcode = UserComm.buffer.msgcode;
            pOutputBuffer->status = UserComm.buffer.status;
            pOutputBuffer->size = UserComm.buffer.size;
            RtlCopyMemory(&pOutputBuffer->data,UserComm.data,UserComm.buffer.size);
            Irp->IoStatus.Information = UserComm.buffer.size + sizeof(UserCommunication::CommChannel); 
            UserComm.NeedToSend = false;
        };
    }
    return 0;
}
