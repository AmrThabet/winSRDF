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

using namespace SRDF;
using namespace SRDF::FileManager;
using namespace SRDF::RegistryManager;
using namespace SRDF::Tdi;
FileFilterDevice* FileFilter;
PDRIVER_OBJECT DriverObject;

int _cdecl MJCreate(FileFilterDevice* FFDevice,__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);

bool FileFilter_AskAttach(FileFilterDevice* device,__in PDEVICE_OBJECT DeviceObject)
{
     DbgPrint("Try to Attach to Device ... Accept !!!");
     return true;     
}

NTSTATUS Driver::DriverMain(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING theRegistryPath){
      DbgPrint("File Creation Monitor DriverEntry Called\n");
      DriverObject = pDriverObject;
          
      FileFilter=(FileFilterDevice*)misc::CreateClass(sizeof(FileFilterDevice));
      FileFilter->Initialize(this);
      AddDevice(FileFilter);
      FileFilter->CreateDevice(L"\\Device\\rootkit02",L"\\DosDevices\\FileMonitor");
      
      SetValue(FileFilter->AskAttachFunc,FileFilter_AskAttach);
      SetValue(FileFilter->FilteredMajorFunction[IRP_MJ_CREATE].PreModification,MJCreate);
      FileFilter->BeginHooking(true);

      return STATUS_SUCCESS;
}

VOID Driver::DriverUnload()
{
     //s->close();
     DbgPrint("Device Detached");
     //Amr3->DeinitializeConnection();
     //IoUnregisterFsRegistrationChange(DriverObject, (PDRIVER_FS_NOTIFICATION)DriverNotificationRoutine);
     //Amr->Detach();
}
int _cdecl MJCreate(FileFilterDevice* FFDevice,__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    DbgPrint("File Created !!!");         
    DbgPrint("%wZ\n", &pFileObject->FileName);
    return FILTER_SKIP;
}
