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

#include "SRDF.h"

using namespace SRDF;
using namespace SRDF::FileManager;

Driver::Driver()
{ 
}
NTSTATUS Driver::AddDevice(Device* device)
{
         if (nDevices >= MAX_DEVICES)return STATUS_ERROR;
         this->device[nDevices] = device;
         this->nDevices++;
         return STATUS_SUCCESS;
         
}
VOID Driver::OnUnload()
{
     int i=0;
     DriverUnload();
     
     for(i = 0;i<nDevices;i++){
           if (device[i]->Type ==_FILTERDEVICE)((FilterDevice*)device[i])->Unload();
           else device[i]->Unload();
     }//*/
}
NTSTATUS Driver::MultiDeviceIrpDispatcher(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    for (int i=0;i<nDevices;i++){
          if (device[i]->Type !=_FILTERDEVICE){
              if(device[i]->pDeviceObject == DeviceObject){
                    return device[i]->IrpDispatcher(DeviceObject,Irp);
              };
          }else{
                if(device[i]->pDeviceObject == DeviceObject){
                    return ((FilterDevice*)device[i])->IrpDispatcher(DeviceObject,Irp);
                }else{
                    if(((FilterDevice*)device[i])->QueryDeviceObject(DeviceObject) !=-1)
                                    return ((FilterDevice*)device[i])->IrpDispatcher(DeviceObject,Irp);
                };
          };
    }
     
    Irp->IoStatus.Status = STATUS_SUCCESS;   
    IoCompleteRequest(Irp, IO_NO_INCREMENT);   
    return STATUS_SUCCESS;
};

VOID Driver::FileFilterNotificationDispatcher(PDEVICE_OBJECT TargetDevice,int command)
{
    if(nFSRegisteredDevices !=0)
    {
        for (int i = 0;i < nFSRegisteredDevices;i++)
        {
            if (FSRegisteredDevices[i] != NULL)FSRegisteredDevices[i]->FileFilterNotificationRoutine(TargetDevice,command);
        }
    }
};
