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
using namespace SRDF::Tdi;

cTdiFirewall* TdiFirewall;

int MyReceiveEvent(TdiTcpSocket* Sock,int PID, char* Buffer,DWORD* Size,PVOID UserContext)
{
     return TDIFIREWALL_ALLOW;
}

NTSTATUS Driver::DriverMain(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING theRegistryPath){
      DbgPrint("TdiFirewall DriverEntry Called\n");
      DriverObject = pDriverObject;
  
      Amr4=(cTdiFirewall*)misc::CreateClass(sizeof(cTdiFirewall));
      Amr4->Initialize(this);
      AddDevice(Amr4);
      
      Amr4->BeginHooking(true);
      SetValue(Amr4->ReceiveEvent,MyReceiveEvent);
      SetValue(Amr4->SendEvent,MyReceiveEvent);
      
      return STATUS_SUCCESS;
}

VOID Driver::DriverUnload()
{
     DbgPrint("Device Detached");
}

