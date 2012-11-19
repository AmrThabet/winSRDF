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
using namespace SRDF::misc;

#include <tdi.h>
#include <tdikrnl.h>
#define HTONS(a) (((0xFF&a)<<8) + ((0xFF00&a)>>8))
#define INETADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
NTSTATUS TdiTcpEventReceive(PVOID TdiEventContext, CONNECTION_CONTEXT ConnectionContext, ULONG ReceiveFlags, ULONG  BytesIndicated, ULONG  BytesAvailable, ULONG  *BytesTaken, PVOID  Tsdu, PIRP  *IoRequestPacket);

NTSTATUS
 TdiTcpEventDisconnect(
    IN PVOID  TdiEventContext,
    IN CONNECTION_CONTEXT  ConnectionContext,
    IN LONG  DisconnectDataLength,
    IN PVOID  DisconnectData,
    IN LONG  DisconnectInformationLength,
    IN PVOID  DisconnectInformation,
    IN ULONG  DisconnectFlags
    );
    
NTSTATUS    
 ClientEventConnect(
    IN PVOID  TdiEventContext,
    IN LONG  RemoteAddressLength,
    IN PVOID  RemoteAddress,
    IN LONG  UserDataLength,
    IN PVOID  UserData,
    IN LONG  OptionsLength,
    IN PVOID  Options,
    OUT CONNECTION_CONTEXT  *ConnectionContext,
    OUT PIRP  *AcceptIrp
    );

NTSTATUS 
  ClientEventReceive(
    IN PVOID  TdiEventContext,
    IN CONNECTION_CONTEXT  ConnectionContext,
    IN ULONG  ReceiveFlags,
    IN ULONG  BytesIndicated,
    IN ULONG  BytesAvailable,
    OUT ULONG  *BytesTaken,
    IN PVOID  Tsdu,
    OUT PIRP  *IoRequestPacket
    );
 
NTSTATUS TdiTcpSocket::InitializeConnection(DWORD SocketType,USHORT port)
{
    NTSTATUS ntStatus;
    //Initialize the TDI
    ntStatus = CreateTransportAddress(port);
    if (ntStatus != STATUS_SUCCESS)return ntStatus;
    DbgPrint("Transport Created Successfully");
    //Initialize The Connection
    ntStatus = OpenConnection();
    if (ntStatus != STATUS_SUCCESS)return ntStatus;
    DbgPrint("Connection Created Successfully");
    //Assoicate the The Transport and the Connection
    
    ntStatus = AssociateTransport();
    if (ntStatus != STATUS_SUCCESS)return ntStatus;
    DbgPrint("Association Done Successfully");
    
    //Set The Receive Handler
    ntStatus = SetEventHandler(TDI_EVENT_RECEIVE, TdiTcpEventReceive, (PVOID)this);
    if (ntStatus != STATUS_SUCCESS)return ntStatus;
    
    //Set The Disconnect Handler
    ntStatus = SetEventHandler(TDI_EVENT_DISCONNECT, TdiTcpEventDisconnect, (PVOID)this);
    if (ntStatus != STATUS_SUCCESS)return ntStatus;
    
    //Set The Connect Handler for TCP Servers
    if (SocketType == TCP_SOCKET_SERVER)
    {
        //ntStatus = SetEventHandler(TDI_EVENT_CONNECT, TdiExample_ClientEventReceive, (PVOID)this);
        if (ntStatus != STATUS_SUCCESS)return ntStatus;
    }
    Initialized = true;
    return STATUS_SUCCESS;
}
NTSTATUS TdiTcpSocket::DeinitializeConnection()
{
    if (!Initialized)return STATUS_SUCCESS;
    NTSTATUS ntStatus;
    
    //Disassoicate the The Transport and the Connection
    ntStatus = DisassociateTransport();
    if (ntStatus != STATUS_SUCCESS)return ntStatus;
    
    //Close The Connection
    ntStatus = CloseConnection();
    if (ntStatus != STATUS_SUCCESS)return ntStatus;
    
    //Deinitialize the TDI
    //ntStatus = CloseTransport();
    if (ntStatus != STATUS_SUCCESS)return ntStatus;
    if (ntStatus == STATUS_SUCCESS)
    {
       DbgPrint("Deinitialized");
       Initialized = false;
    }
    return STATUS_SUCCESS;
}
NTSTATUS TdiTcpSocket::CreateTransportAddress(USHORT port)
{
    NTSTATUS ntStatus;
    PTRANSPORT_ADDRESS pTransportAddress;
    PTDI_ADDRESS_IP pTdiAddressIp;
    UNICODE_STRING TdiString;
    OBJECT_ATTRIBUTES TdiAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    DWORD EASize;
    
    //Prepare the buffer
    static char EaBuffer[sizeof(FILE_FULL_EA_INFORMATION) + TDI_TRANSPORT_ADDRESS_LENGTH + sizeof(TDI_ADDRESS_IP)+ sizeof(TRANSPORT_ADDRESS)+15];
    PFILE_FULL_EA_INFORMATION pEAInfo = (PFILE_FULL_EA_INFORMATION)&EaBuffer;
    memset(pEAInfo,0,sizeof(EaBuffer));

    //Prepare the String
    RtlInitUnicodeString(&TdiString, L"\\Device\\Tcp");
    InitializeObjectAttributes(&TdiAttributes, &TdiString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
     
     //Set the Extended Attributes.
     memcpy(&pEAInfo->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH);
     
	 pEAInfo->NextEntryOffset = 0;
	 pEAInfo->Flags = 0;
     pEAInfo->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;
     pEAInfo->EaValueLength = TDI_TRANSPORT_ADDRESS_LENGTH + sizeof(TRANSPORT_ADDRESS) + sizeof(TDI_ADDRESS_IP);
     pTransportAddress =  (PTRANSPORT_ADDRESS)(&pEAInfo->EaName + TDI_TRANSPORT_ADDRESS_LENGTH + 1);

     pTransportAddress->TAAddressCount = 1;
     
     pTransportAddress->Address[0].AddressType    = TDI_ADDRESS_TYPE_IP;
     pTransportAddress->Address[0].AddressLength  = sizeof(TDI_ADDRESS_IP);
     pTdiAddressIp = (TDI_ADDRESS_IP*)&pTransportAddress->Address[0].Address;
     memset(pTdiAddressIp,0, sizeof(TDI_ADDRESS_IP));
     
     
     //Set the port
     pTdiAddressIp->sin_port = HTONS(port);
     
     EASize = sizeof(EaBuffer);
     
     ntStatus = ZwCreateFile(&this->TransportAddr, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &TdiAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, 0, pEAInfo, EASize);
     
     if(ntStatus != STATUS_SUCCESS) return ntStatus;
     DbgPrint("!!! Continued !!!");
     ntStatus = ObReferenceObjectByHandle(this->TransportAddr, GENERIC_READ | GENERIC_WRITE, NULL, KernelMode, (PVOID*)&this->FileObjTransportAddr, NULL);      

     if (ntStatus != STATUS_SUCCESS) ZwClose(this->TransportAddr);

     return ntStatus;
}


NTSTATUS TdiTcpSocket::OpenConnection()
{
    NTSTATUS ntStatus;
    UNICODE_STRING TdiString;
    OBJECT_ATTRIBUTES TdiAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    CONNECTION_CONTEXT ConnectionContext = NULL;
    DWORD EASize;
    
    //Prepare the buffer
    char EaBuffer[sizeof(FILE_FULL_EA_INFORMATION) + 1 + TDI_CONNECTION_CONTEXT_LENGTH + sizeof(CONNECTION_CONTEXT)];
    PFILE_FULL_EA_INFORMATION pEAInfo = (PFILE_FULL_EA_INFORMATION)&EaBuffer;
    
    //Prepare The String
    RtlInitUnicodeString(&TdiString, L"\\Device\\Tcp");
    InitializeObjectAttributes(&TdiAttributes, &TdiString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    //prepare the Extended Buffer
     memset(pEAInfo,0,sizeof(EaBuffer));
     memcpy(&pEAInfo->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH+1);

     pEAInfo->EaNameLength = TDI_CONNECTION_CONTEXT_LENGTH;
     pEAInfo->EaValueLength = 4;                                                //Sizeof Connection Context
     *(CONNECTION_CONTEXT*)(pEAInfo->EaName+(pEAInfo->EaNameLength + 1)) = ConnectionContext; 
     EASize = sizeof(EaBuffer);

     ntStatus = ZwCreateFile(&this->Connection, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &TdiAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, 0, pEAInfo, EASize);

     if (ntStatus != STATUS_SUCCESS)return ntStatus;
     
      ntStatus = ObReferenceObjectByHandle(this->Connection, GENERIC_READ | GENERIC_WRITE, NULL, KernelMode, (PVOID*)&this->FileObjConnection, NULL);      

      if(ntStatus != STATUS_SUCCESS) ZwClose(this->Connection);
     
     return ntStatus;
}

NTSTATUS TdiTcpSocket::AssociateTransport()
{
    NTSTATUS ntStatus;
    PIRP pIrp;
    IO_STATUS_BLOCK IoStatusBlock;
    PDEVICE_OBJECT pTdiDevice;
    KEVENT CompleteEvent;

    KeInitializeEvent(&CompleteEvent, NotificationEvent, FALSE);

    pTdiDevice = IoGetRelatedDeviceObject(this->FileObjConnection);
    
    pIrp = TdiBuildInternalDeviceControlIrp(TDI_ASSOCIATE_ADDRESS, pTdiDevice, this->FileObjConnection, &CompleteEvent, &IoStatusBlock);

    if(!pIrp) return STATUS_INSUFFICIENT_RESOURCES;

    TdiBuildAssociateAddress(pIrp, pTdiDevice, this->FileObjConnection, NULL, NULL, this->TransportAddr);

    ntStatus = IoCallDriver(pTdiDevice, pIrp);

    if (ntStatus == STATUS_PENDING)
    {
        KeWaitForSingleObject(&CompleteEvent, Executive, KernelMode, FALSE, NULL);
        ntStatus = IoStatusBlock.Status;
    }
    
    return ntStatus;
}

NTSTATUS TdiTcpSocket::SetEventHandler(LONG InEventType, PVOID InEventHandler, PVOID InEventContext)
{
    NTSTATUS ntStatus;
    PIRP pIrp;
    IO_STATUS_BLOCK IoStatusBlock;
    PDEVICE_OBJECT pTdiDevice;
    KEVENT CompleteEvent;

    KeInitializeEvent(&CompleteEvent, NotificationEvent, FALSE);

    pTdiDevice = IoGetRelatedDeviceObject(this->FileObjTransportAddr);

    pIrp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER, pTdiDevice, this->FileObjConnection, &CompleteEvent, &IoStatusBlock);

    if(!pIrp) return STATUS_INSUFFICIENT_RESOURCES;

    TdiBuildSetEventHandler(pIrp, pTdiDevice, this->FileObjTransportAddr, NULL, NULL, InEventType, InEventHandler, InEventContext);

    ntStatus = IoCallDriver(pTdiDevice, pIrp);

    if(ntStatus == STATUS_PENDING)
    {
        KeWaitForSingleObject(&CompleteEvent, Executive, KernelMode, FALSE, NULL);
        ntStatus = IoStatusBlock.Status;
    }
    
    return ntStatus;
}

NTSTATUS TdiTcpSocket::Connect(DWORD charIP1,DWORD charIP2,DWORD charIP3,DWORD charIP4, USHORT Port)
{
    if (!Initialized)return STATUS_ERROR;
    NTSTATUS ntStatus;
    PIRP pIrp;
    IO_STATUS_BLOCK IoStatusBlock;
    PDEVICE_OBJECT pTdiDevice;
    KEVENT CompleteEvent;
    TDI_CONNECTION_INFORMATION  RequestConnectionInfo = {0};
    TDI_CONNECTION_INFORMATION  ReturnConnectionInfo = {0};
    
    char cBuffer[256];
    PTRANSPORT_ADDRESS pTransportAddress = (PTRANSPORT_ADDRESS)&cBuffer;
    memset(pTransportAddress,0,sizeof(cBuffer));
    
    PTDI_ADDRESS_IP pTdiAddressIp;

    KeInitializeEvent(&CompleteEvent, NotificationEvent, FALSE);

    pTdiDevice = IoGetRelatedDeviceObject(this->FileObjConnection);
    
    pIrp = TdiBuildInternalDeviceControlIrp(TDI_CONNECT, pTdiDevice, this->FileObjConnection, &CompleteEvent, &IoStatusBlock);

    if(!pIrp) return STATUS_INSUFFICIENT_RESOURCES;


    RequestConnectionInfo.RemoteAddress       = (PVOID)pTransportAddress;
    RequestConnectionInfo.RemoteAddressLength = sizeof(PTRANSPORT_ADDRESS) + sizeof(TDI_ADDRESS_IP); 

    pTransportAddress->TAAddressCount = 1;
    pTransportAddress->Address[0].AddressType    = TDI_ADDRESS_TYPE_IP;
    pTransportAddress->Address[0].AddressLength  = sizeof(TDI_ADDRESS_IP);
    pTdiAddressIp = (TDI_ADDRESS_IP *)&pTransportAddress->Address[0].Address;

    pTdiAddressIp->sin_port = HTONS(Port);
    pTdiAddressIp->in_addr  = INETADDR(charIP1,charIP2,charIP3,charIP4);
    
    LARGE_INTEGER interval;
    interval.QuadPart = 5*60 * DELAY_ONE_SECOND;
    
    TdiBuildConnect(pIrp, pTdiDevice, this->FileObjConnection, NULL, NULL, &interval, &RequestConnectionInfo, &ReturnConnectionInfo);

    ntStatus = IoCallDriver(pTdiDevice, pIrp);

    if(ntStatus == STATUS_PENDING)
    {
        KeWaitForSingleObject(&CompleteEvent, Executive, KernelMode, FALSE, NULL);
        DbgPrint("Connection Finished");
        ntStatus = IoStatusBlock.Status;
    }
    if (ntStatus == STATUS_SUCCESS)
    {
       DbgPrint("Device Now Connected !!!");
       Connected = true;
    }
    return ntStatus;
}

NTSTATUS TdiTcpSocket::Listen()
{
    if (!Initialized)return STATUS_ERROR;
    DbgPrint("Listening ...");     
    NTSTATUS ntStatus;
    PIRP pIrp;
    IO_STATUS_BLOCK IoStatusBlock;
    PDEVICE_OBJECT pTdiDevice;
    KEVENT CompleteEvent;
    TDI_CONNECTION_INFORMATION  RequestConnectionInfo = {0};
    TDI_CONNECTION_INFORMATION  ReturnConnectionInfo = {0};
    
    char cBuffer[256];
    PTRANSPORT_ADDRESS pTransportAddress = (PTRANSPORT_ADDRESS)&cBuffer;
    PTDI_ADDRESS_IP pTdiAddressIp;

    KeInitializeEvent(&CompleteEvent, NotificationEvent, FALSE);

    pTdiDevice = IoGetRelatedDeviceObject(this->FileObjConnection);
    
    pIrp = TdiBuildInternalDeviceControlIrp(TDI_LISTEN, pTdiDevice, this->FileObjConnection, &CompleteEvent, &IoStatusBlock);

    if(!pIrp) return STATUS_INSUFFICIENT_RESOURCES;


    RequestConnectionInfo.RemoteAddress       = (PVOID)pTransportAddress;
    RequestConnectionInfo.RemoteAddressLength = sizeof(PTRANSPORT_ADDRESS) + sizeof(TDI_ADDRESS_IP); 

    pTransportAddress->TAAddressCount = 1;
    pTransportAddress->Address[0].AddressType    = TDI_ADDRESS_TYPE_IP;
    pTransportAddress->Address[0].AddressLength  = sizeof(TDI_ADDRESS_IP);
    pTdiAddressIp = (TDI_ADDRESS_IP *)&pTransportAddress->Address[0].Address;
    memset(pTdiAddressIp,0,sizeof(TDI_ADDRESS_IP));
    
    TdiBuildListen(pIrp, pTdiDevice, this->FileObjConnection, NULL, NULL,0,&RequestConnectionInfo,&ReturnConnectionInfo);

    ntStatus = IoCallDriver(pTdiDevice, pIrp);

    if(ntStatus == STATUS_PENDING)
    {
        KeWaitForSingleObject(&CompleteEvent, Executive, KernelMode, FALSE, NULL);

        ntStatus = IoStatusBlock.Status;
    }
    Connected = true;
    return ntStatus;
}

NTSTATUS TdiTcpSocket::Disconnect()
{
    if(!Connected)return STATUS_SUCCESS;  
    NTSTATUS ntStatus;
    PIRP pIrp;
    IO_STATUS_BLOCK IoStatusBlock;
    PDEVICE_OBJECT pTdiDevice;
    KEVENT CompleteEvent;
    TDI_CONNECTION_INFORMATION  ReturnConnectionInfo;
    
    KeInitializeEvent(&CompleteEvent, NotificationEvent, FALSE);

    pTdiDevice = IoGetRelatedDeviceObject(this->FileObjConnection);
    
    pIrp = TdiBuildInternalDeviceControlIrp(TDI_DISCONNECT, pTdiDevice, this->FileObjConnection, &CompleteEvent, &IoStatusBlock);

    if(!pIrp) return STATUS_INSUFFICIENT_RESOURCES;

    LARGE_INTEGER interval;
    interval.QuadPart = 5 * DELAY_ONE_SECOND;
          
    TdiBuildDisconnect(pIrp, pTdiDevice, this->FileObjConnection, NULL, NULL, &interval, TDI_DISCONNECT_ABORT, NULL, &ReturnConnectionInfo);

    ntStatus = IoCallDriver(pTdiDevice, pIrp);

    if(ntStatus == STATUS_PENDING)
    {
        KeWaitForSingleObject(&CompleteEvent, Executive, KernelMode, FALSE, NULL);

        ntStatus = IoStatusBlock.Status;
    }
    if (ntStatus == STATUS_SUCCESS)
    {
       DbgPrint("Disconnected");
       Connected = false;
    }
    return ntStatus;
}

NTSTATUS TdiTcpSocket::DisassociateTransport()
{
    NTSTATUS ntStatus;
    PIRP pIrp;
    IO_STATUS_BLOCK IoStatusBlock;
    PDEVICE_OBJECT pTdiDevice;
    KEVENT CompleteEvent;

    KeInitializeEvent(&CompleteEvent, NotificationEvent, FALSE);

    pTdiDevice = IoGetRelatedDeviceObject(this->FileObjConnection);

    pIrp = TdiBuildInternalDeviceControlIrp(TDI_DISASSOCIATE_ADDRESS, pTdiDevice, this->FileObjConnection, &CompleteEvent, &IoStatusBlock);

    if(!pIrp) return STATUS_INSUFFICIENT_RESOURCES;

    TdiBuildDisassociateAddress(pIrp, pTdiDevice, this->FileObjConnection, NULL, NULL);

    ntStatus = IoCallDriver(pTdiDevice, pIrp);

    if(ntStatus == STATUS_PENDING)
    {
        KeWaitForSingleObject(&CompleteEvent, Executive, KernelMode, FALSE, NULL);
        ntStatus = IoStatusBlock.Status;
    }

    return ntStatus;
}

NTSTATUS TdiTcpSocket::CloseConnection()
{
    ObDereferenceObject(this->FileObjConnection);
    ZwClose(this->Connection);

    return STATUS_SUCCESS;
}

NTSTATUS TdiTcpSocket::CloseTransport()
{
    ObDereferenceObject(this->FileObjTransportAddr);
    ZwClose(this->TransportAddr);

    return STATUS_SUCCESS;
}

NTSTATUS TdiTcpSocket::Send(char* Buffer, DWORD size, DWORD* pDataSent)
{
    if(!Connected)return STATUS_ERROR;     
    NTSTATUS ntStatus;
    PIRP pIrp;
    IO_STATUS_BLOCK IoStatusBlock = {0};
    PDEVICE_OBJECT pTdiDevice;
    KEVENT CompleteEvent;
    PMDL pSendMdl = NULL;

    KeInitializeEvent(&CompleteEvent, NotificationEvent, FALSE);

    pTdiDevice = IoGetRelatedDeviceObject(this->FileObjConnection);
    
    *pDataSent = 0;
    
    if(!AllocateMDL(pSendMdl,Buffer, size)) return STATUS_INSUFFICIENT_RESOURCES;
    
    pIrp = TdiBuildInternalDeviceControlIrp(TDI_SEND, pTdiDevice, this->FileObjConnection, &CompleteEvent, &IoStatusBlock);
    
    if(!pIrp) return STATUS_INSUFFICIENT_RESOURCES;

    TdiBuildSend(pIrp, pTdiDevice, this->FileObjConnection, NULL, NULL, pSendMdl, 0, size);
    
    ntStatus = IoCallDriver(pTdiDevice, pIrp);

    if(ntStatus == STATUS_PENDING)
    {
        KeWaitForSingleObject(&CompleteEvent, Executive, KernelMode, FALSE, NULL);

    }
    ntStatus   = IoStatusBlock.Status;
    *pDataSent = (DWORD)IoStatusBlock.Information;
    return ntStatus;
}
NTSTATUS TdiTcpEventReceive(PVOID TdiEventContext, CONNECTION_CONTEXT ConnectionContext, ULONG ReceiveFlags, ULONG  BytesIndicated, ULONG  BytesAvailable, ULONG  *BytesTaken, PVOID  Tsdu, PIRP  *IoRequestPacket)
{
         TdiTcpSocket* TcpSocket = (TdiTcpSocket*)TdiEventContext;
         return TcpSocket->Receive(ReceiveFlags,BytesIndicated,BytesAvailable,BytesTaken,Tsdu, IoRequestPacket);
}
NTSTATUS TdiTcpSocket::Receive(ULONG ReceiveFlags, ULONG  BytesIndicated, ULONG  BytesAvailable, ULONG  *BytesTaken, PVOID  Tsdu, PIRP  *IoRequestPacket)
{
    DbgPrint("TdiExample_ClientEventReceive 0x%0x, %i, %i\n", ReceiveFlags, BytesIndicated, BytesAvailable);

    *BytesTaken = BytesAvailable;
    
    char* Buffer = (char*)malloc(BytesAvailable+1);
    memset(Buffer,0,BytesAvailable+1);
    memcpy(Buffer, Tsdu, BytesAvailable);
    DbgPrint("Recieved : %s",Buffer);
    *IoRequestPacket = NULL;
    if(ReceiveEventFunc != NULL)(*ReceiveEventFunc)(this,Buffer,BytesAvailable);
    return STATUS_SUCCESS;
}
NTSTATUS TdiTcpEventDisconnect(IN PVOID  TdiEventContext,IN CONNECTION_CONTEXT  ConnectionContext,IN LONG  DisconnectDataLength,IN PVOID  DisconnectData,IN LONG  DisconnectInformationLength,IN PVOID  DisconnectInformation,IN ULONG  DisconnectFlags)
{
   TdiTcpSocket* TcpSocket = (TdiTcpSocket*)TdiEventContext;
   TcpSocket->Connected = false;
   if (TcpSocket->DisconnectEventFunc != NULL)(*TcpSocket->DisconnectEventFunc)(TcpSocket);
   return STATUS_SUCCESS;
}                       
