#include "RDF.h"

using namespace RDF;
using namespace RDF::FileManager;

Driver::Driver(){
             DbgPrint("New Driver Created at 0x%x",this);    
}
NTSTATUS Driver::AddDevice(Device* device)
{
         if (nDevices >= MAX_DEVICES)return STATUS_ERROR;
         DbgPrint("nDevices == 0x%x",nDevices);
         this->device[nDevices] = device;
         this->nDevices++;
         DbgPrint("Device Added Successfully");
         return STATUS_SUCCESS;
         
}
VOID Driver::OnUnload()
{
     int i=0;
     DriverUnload();
     
     DbgPrint("nDevices == 0x%x",nDevices);
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
    
    DbgPrint("Unknown Device"); 
    Irp->IoStatus.Status = STATUS_SUCCESS;   
    IoCompleteRequest(Irp, IO_NO_INCREMENT);   
    return STATUS_SUCCESS;
};

VOID Driver::FileFilterNotificationDispatcher(PDEVICE_OBJECT TargetDevice,int command)
{
    DbgPrint("FileFilterNotificationRoutine Called");
    if(nFSRegisteredDevices !=0)
    {
        for (int i = 0;i < nFSRegisteredDevices;i++)
        {
            if (FSRegisteredDevices[i] != NULL)FSRegisteredDevices[i]->FileFilterNotificationRoutine(TargetDevice,command);
        }
    }
};
