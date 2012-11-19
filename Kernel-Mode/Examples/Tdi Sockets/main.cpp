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

TdiTcpSocket* TdiSocket;

PDRIVER_OBJECT DriverObject;

VOID TdiReceiveEvent(TdiTcpSocket* Sock,char* Buffer,DWORD Size,PVOID UserContext)
{
     DbgPrint("RECEIVED DATA !!!");
}
VOID TdiDisconnectEvent(TdiTcpSocket* Sock)
{
     DbgPrint("DISCONNECTED !!!");
     //if(TdiSocket->Listen() != STATUS_SUCCESS)DbgPrint("Error");
}
NTSTATUS Driver::DriverMain(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING theRegistryPath){
      DbgPrint("HideProc DriverEntry Called\n");
      DriverObject = pDriverObject;
       
      TdiSocket = (TdiTcpSocket*)misc::CreateClass(sizeof(TdiTcpSocket));
      TdiSocket->Initialize(this);
      AddDevice(TdiSocket);
      
      TdiSocket->ReceiveEventFunc = TdiReceiveEvent;
      TdiSocket->DisconnectEventFunc = TdiDisconnectEvent;
      TdiSocket->CreateDevice(L"\\Device\\rootkit02",L"\\DosDevices\\TdiSocket");
      //TCP_SOCKET_CLIENT or TCP_SOCKET_SERVER and your port number
      if (TdiSocket->InitializeConnection(TCP_SOCKET_CLIENT,4003) != STATUS_SUCCESS)DbgPrint("Error Initializing Connection");
      //TdiSocket->Listen();
      TdiSocket->Connect(127,0,0,1,4400);
      DWORD DataSent;
      
      TdiSocket->Send("TdiSocket Message",strlen("TdiSocket Message"),&DataSent);

      TdiSocket->Disconnect();
      TdiSocket->DeinitializeConnection();
      
      return STATUS_SUCCESS;
}

VOID Driver::DriverUnload()
{
     DbgPrint("Device Detached");
}
