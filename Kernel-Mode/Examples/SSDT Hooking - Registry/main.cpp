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
SSDTDevice* Amr;

PDRIVER_OBJECT DriverObject;
typedef NTSTATUS ZwSetValueKeyPtr(
            IN HANDLE KeyHandle,
            IN PUNICODE_STRING ValueName,
            IN ULONG TitleIndex OPTIONAL,
            IN ULONG Type,
            IN PVOID Data,
            IN ULONG DataSize
            );
            
ZwSetValueKeyPtr* oldZwSetValueKey;

NTSTATUS newZwSetValueKey(IN HANDLE KeyHandle,IN PUNICODE_STRING ValueName,IN ULONG TitleIndex OPTIONAL,IN ULONG Type,IN PVOID Data,IN ULONG DataSize)
{   
    DbgPrint("Yes %wZ\n",ValueName);
    return (*oldZwSetValueKey)(KeyHandle,ValueName,TitleIndex,Type,Data,DataSize);
}

NTSTATUS Driver::DriverMain(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING theRegistryPath){
      DbgPrint("SSDT Hooking Registry DriverEntry Called\n");
      DriverObject = pDriverObject;
     
      Amr=(SSDTDevice*)misc::CreateClass(sizeof(SSDTDevice));
      Amr->Initialize(this);
      AddDevice(Amr);
      
      Amr->CreateDevice(L"\\Device\\rootkit03",L"\\DosDevices\\RegSSDTHook");
      
      int old = Amr->GetRealAddress(L"ZwSetValueKey");
      DbgPrint("Real Address : 0x%x",old);
      SetValue(oldZwSetValueKey,old);
      Amr->AttachTo(L"ZwSetValueKey",(DWORD)newZwSetValueKey);
      
      return STATUS_SUCCESS;
}

VOID Driver::DriverUnload()
{
     DbgPrint("Device Detached");
     Amr->Detach();
}
