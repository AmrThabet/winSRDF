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
using namespace RDF::Tdi;
using namespace RDF::misc;
using namespace RDF::FileManager;
#include <tdi.h>
#include <tdikrnl.h>
#define HTONS(a) (((0xFF&a)<<8) + ((0xFF00&a)>>8))
#define INETADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
#define SEPARATEADDR(Addr,a,b,c,d) a = Addr & 0xFF;                 \
                                   b = (Addr & 0x0000FF00) >> 8;    \
                                   c = (Addr & 0x00FF0000) >> 16;   \
                                   d = (Addr & 0xFF000000) >> 24;

int InternalIOControl(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
NTSTATUS ClientEventConnectDispatch(IN PVOID TdiEventContext,IN LONG  RemoteAddressLength,IN PVOID  RemoteAddress,IN LONG  UserDataLength,IN PVOID  UserData,IN LONG  OptionsLength,IN PVOID  Options,OUT CONNECTION_CONTEXT *ConnectionContext,OUT PIRP  *AcceptIrp);
NTSTATUS ClientEventReceiveDispatch(IN PVOID TdiEventContext,IN CONNECTION_CONTEXT ConnectionContext,IN ULONG ReceiveFlags,IN ULONG BytesIndicated,IN ULONG BytesAvailable,OUT ULONG *BytesTaken,IN PVOID Tsdu,OUT PIRP *IoRequestPacket);
NTSTATUS ClientEventChainedReceiveDispatch(IN PVOID  TdiEventContext,IN CONNECTION_CONTEXT ConnectionContext,IN ULONG  ReceiveFlags,IN ULONG  ReceiveLength,IN ULONG  StartingOffset,IN PMDL Tsdu,IN PVOID  TsduDescriptor);


NTSTATUS TdiSniffer::BeginHooking(bool OnlyThroughFirewall)
{
         AttachToDevice(L"\\Device\\Tcp");
         this->OnlyThroughFirewall = OnlyThroughFirewall;
         SetValue(FilteredMajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL].PreModification,TdiSniffer::MJInternalIOControl);
         SetValue(FilteredMajorFunction[IRP_MJ_CREATE].PreModification,TdiSniffer::MJCreate);
         SetValue(FilteredMajorFunction[IRP_MJ_CLOSE].PreModification,TdiSniffer::MJClose);
}
int _cdecl TdiSniffer::MJCreate(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    NTSTATUS status;
    PTRANSPORT_ADDRESS pTransportAddress;
    PTDI_ADDRESS_IP pTdiAddressIp;
    USHORT port = 0;
    DWORD PID = 0;
	FILE_FULL_EA_INFORMATION* pEAInfo = (FILE_FULL_EA_INFORMATION *)Irp->AssociatedIrp.SystemBuffer;
	PFILE_OBJECT* PFileObject = NULL;
	int FilterRet = TDISNIFFER_ALLOW;
	PVOID UserContext = NULL;
	if (pEAInfo == NULL)
    {       
        return FILTER_SKIP;
    }
	//CreateTransportAddress
	if (pEAInfo->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH && memcmp(pEAInfo->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH) == 0)
    {                                                 
       pTransportAddress = (PTRANSPORT_ADDRESS)(&pEAInfo->EaName + TDI_TRANSPORT_ADDRESS_LENGTH + 1);
       if (pTransportAddress->Address[0].AddressType == TDI_ADDRESS_TYPE_IP)
       {                                               
           pTdiAddressIp = (TDI_ADDRESS_IP*)&pTransportAddress->Address[0].Address;
           port = HTONS(pTdiAddressIp->sin_port);
           PID = (DWORD)PsGetCurrentProcessId();
           DbgPrint("Port %d and PID %d",port,PID);
           if (CreateConnectionEvent != NULL)FilterRet = (*CreateConnectionEvent)(this,PID,port,UserContext);
           
           if (FilterRet == TDISNIFFER_DENY)
           {
              DbgPrint("Access Denied");           
              Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
              return FILTER_COMPLETE_REQUEST;
           }
		   
           this->Pending(DeviceObject,Irp); 
           
           if (NT_SUCCESS(Irp->IoStatus.Status))
           {
              PIO_STACK_LOCATION StackLoc = IoGetCurrentIrpStackLocation(Irp); 
              DbgPrint("FileObject From Create %x",StackLoc->FileObject);
              AddToConnectionContext(StackLoc->FileObject,UserContext);
              if (PFileObject != NULL)*PFileObject = StackLoc->FileObject;
           }
           return FILTER_COMPLETE_REQUEST;
       }
    }
    return FILTER_SKIP;
}

int _cdecl TdiSniffer::MJClose(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    PIO_STACK_LOCATION StackLoc = IoGetCurrentIrpStackLocation(Irp);
    DWORD PID = (DWORD)PsGetCurrentProcessId();
    
    PVOID UserContext = NULL;
    if (RemoveFromConnectionContext(StackLoc->FileObject,UserContext))
    {
       DbgPrint("Close PID %d",PID);
       if(CloseConnectionEvent != NULL)(*CloseConnectionEvent)(this,PID,UserContext);
    }
    return FILTER_SKIP;
}
int _cdecl TdiSniffer::MJInternalIOControl(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    PIO_STACK_LOCATION StackLoc = IoGetCurrentIrpStackLocation(Irp);
    PVOID UserContext = NULL; 
    
    switch(StackLoc->MinorFunction)
    {
      case TDI_ASSOCIATE_ADDRESS:
           return MNAssociateAddress(DeviceObject,Irp);                             
                                   
      case TDI_CONNECT:
           if (!IsConnectionObjectFound(StackLoc->FileObject,UserContext))
           {
                if (OnlyThroughFirewall)
                {
                    Irp->IoStatus.Status = STATUS_REMOTE_NOT_LISTENING;
                    return FILTER_COMPLETE_REQUEST;
                 }
           }
           return MNTcpConnect(DeviceObject,Irp,UserContext);
      case TDI_LISTEN:
      case TDI_ACCEPT:
           Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
           return FILTER_COMPLETE_REQUEST;
      case TDI_SET_EVENT_HANDLER:
           return MNSetEventHandler(DeviceObject,Irp);
      case TDI_SEND:
           return MNSend(DeviceObject,Irp);
      default:
           return FILTER_SKIP;
    }
}

int TdiSniffer::MNAssociateAddress(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    NTSTATUS status;
    PFILE_OBJECT TransportAddrObject = NULL;
    PIO_STACK_LOCATION StackLoc = IoGetCurrentIrpStackLocation(Irp);
    TDI_REQUEST_KERNEL_ASSOCIATE* Request = (TDI_REQUEST_KERNEL_ASSOCIATE*)&StackLoc->Parameters;
    
    status = ObReferenceObjectByHandle(Request->AddressHandle, GENERIC_READ, NULL, KernelMode, (PVOID*)&TransportAddrObject, NULL);
    if (status != STATUS_SUCCESS)return FILTER_SKIP;
    
    //ConnectionObject : FileObject ... TransportAddrObject : TransportAddrObject ... let's associate them
    AssociateConnectionContext(TransportAddrObject,StackLoc->FileObject);
    return FILTER_SKIP;
}

int TdiSniffer::MNTcpConnect(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp,PVOID UserContext)
{
    DWORD PID = (DWORD)PsGetCurrentProcessId();
    int Result = TDISNIFFER_ALLOW;
    DbgPrint("Connect PID %d",PID);
    PIO_STACK_LOCATION StackLoc = IoGetCurrentIrpStackLocation(Irp);
    PTDI_REQUEST_KERNEL Request = (PTDI_REQUEST_KERNEL)&StackLoc->Parameters;
    TDI_ADDRESS_IP* RemoteAddr = (TDI_ADDRESS_IP*)((TA_ADDRESS*)((TRANSPORT_ADDRESS *)(Request->RequestConnectionInformation->RemoteAddress))->Address)->Address;
    IPADDR IPAddress;
    SEPARATEADDR(RemoteAddr->in_addr,IPAddress.ip1,IPAddress.ip2,IPAddress.ip3,IPAddress.ip4);
    if (ConnectEvent != NULL)Result = (*ConnectEvent)(this,PID,TYPE_TO_CLIENT,&IPAddress,RemoteAddr->sin_port,UserContext);
    
    DbgPrint("IP = %d.%d.%d.%d and Port %d",IPAddress.ip1,IPAddress.ip2,IPAddress.ip3,IPAddress.ip4,HTONS(RemoteAddr->sin_port));
    if (Result == TDISNIFFER_ALLOW)return FILTER_SKIP;
    else{
         Irp->IoStatus.Status = STATUS_REMOTE_NOT_LISTENING;
         return FILTER_COMPLETE_REQUEST;
    }
}

int TdiSniffer::MNSend(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    DWORD PID = (DWORD)PsGetCurrentProcessId();
    PIO_STACK_LOCATION StackLoc = IoGetCurrentIrpStackLocation(Irp);
    PVOID UserContext = NULL;
    TDI_REQUEST_KERNEL_SEND *Request = (TDI_REQUEST_KERNEL_SEND*)(&StackLoc->Parameters);
    char* Buffer = (char*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    if (!(IsConnectionObjectFound(StackLoc->FileObject,UserContext)))
    { 
       return FILTER_COMPLETE_REQUEST;
    }
    if(SendEvent != NULL)(*SendEvent)(this,PID,Buffer,&Request->SendLength,UserContext);
    return FILTER_SKIP;
}

int TdiSniffer::MNSetEventHandler(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    PIO_STACK_LOCATION StackLoc = IoGetCurrentIrpStackLocation(Irp); 
    PTDI_REQUEST_KERNEL_SET_EVENT Request = (PTDI_REQUEST_KERNEL_SET_EVENT)&StackLoc->Parameters;
    
    if (Request->EventHandler == NULL)return FILTER_SKIP;
    
    //Allocating TdiContext
    EVENT_HANDLER_IDENTIFIER* EventHandlerIdentifier = (EVENT_HANDLER_IDENTIFIER*)malloc(sizeof(EVENT_HANDLER_IDENTIFIER)+1);
    memset(EventHandlerIdentifier,0,sizeof(EVENT_HANDLER_IDENTIFIER)+1);
    EventHandlerIdentifier->TdiClass = this;
    EventHandlerIdentifier->PID = (DWORD)PsGetCurrentProcessId();
    EventHandlerIdentifier->OriginalContext = Request->EventContext;
    EventHandlerIdentifier->EventHandler = Request->EventHandler;
    PVOID UserContext = EventHandlerIdentifier->UserContext;
    
    if (!(IsConnectionObjectFound(StackLoc->FileObject,UserContext)))
    {                                                    
         if (!OnlyThroughFirewall)return FILTER_SKIP;
         DbgPrint("Through Firewall Detected !!!");
         Request->EventContext = NULL;
         Request->EventHandler = NULL;
         return FILTER_SKIP;
    }
    
    KeInitializeSpinLock(&EventHandlerIdentifier->SpinLock);
    switch (Request->EventType)
    {
      case TDI_EVENT_CONNECT:
            DbgPrint("TDI_EVENT_CONNECT Hooked");
            Request->EventContext = EventHandlerIdentifier;
            Request->EventHandler = ClientEventConnectDispatch;
            
      case TDI_EVENT_RECEIVE:
           DbgPrint("TDI_EVENT_RECEIVE Hooked");
           Request->EventContext = EventHandlerIdentifier;
           Request->EventHandler = ClientEventReceiveDispatch;
           
      case TDI_EVENT_RECEIVE_EXPEDITED:
           DbgPrint("TDI_EVENT_RECEIVE_EXPEDITED Hooked");
           Request->EventContext = EventHandlerIdentifier;
           Request->EventHandler = ClientEventReceiveDispatch;
           
      case TDI_EVENT_CHAINED_RECEIVE:
           //DbgPrint("TDI_EVENT_CHAINED_RECEIVE Hooked");
           //Request->EventContext = EventHandlerIdentifier;
           //Request->EventHandler = ClientEventChainedReceiveDispatch;
           
      case TDI_EVENT_CHAINED_RECEIVE_EXPEDITED:
           //DbgPrint("TDI_EVENT_CHAINED_RECEIVE_EXPEDITED Hooked");
           //Request->EventContext = EventHandlerIdentifier;
           //Request->EventHandler = ClientEventChainedReceiveDispatch;
      default:
           return FILTER_SKIP;
    }
    return FILTER_SKIP;
}

NTSTATUS ClientEventConnectDispatch(IN PVOID TdiEventContext,IN LONG  RemoteAddressLength,IN PVOID  RemoteAddress,IN LONG  UserDataLength,IN PVOID  UserData,IN LONG  OptionsLength,IN PVOID  Options,OUT CONNECTION_CONTEXT *ConnectionContext,OUT PIRP  *AcceptIrp)
{
        EVENT_HANDLER_IDENTIFIER*  SnifferContext = (EVENT_HANDLER_IDENTIFIER*)TdiEventContext;
        TdiSniffer* Tdisniffer =  SnifferContext->TdiClass;
        return Tdisniffer->EventConnect(SnifferContext,RemoteAddressLength,RemoteAddress,UserDataLength,UserData,OptionsLength,Options,ConnectionContext,AcceptIrp);
}

typedef ClientEventConnect(IN PVOID TdiEventContext,IN LONG  RemoteAddressLength,IN PVOID  RemoteAddress,IN LONG  UserDataLength,IN PVOID  UserData,IN LONG  OptionsLength,IN PVOID  Options,OUT CONNECTION_CONTEXT  *ConnectionContext,OUT PIRP  *AcceptIrp);
typedef ClientEventConnect* PClientEventConnect;

NTSTATUS TdiSniffer::EventConnect(EVENT_HANDLER_IDENTIFIER* TdiSnifferContext, IN LONG  RemoteAddressLength,IN PVOID  RemoteAddress,IN LONG  UserDataLength,IN PVOID  UserData,IN LONG  OptionsLength,IN PVOID  Options,OUT CONNECTION_CONTEXT *ConnectionContext,OUT PIRP  *AcceptIrp)
{
        int Result = TDISNIFFER_ALLOW;
        PClientEventConnect OriginalEvent = (PClientEventConnect)TdiSnifferContext->EventHandler;
        TDI_ADDRESS_IP* RemoteAddr = (TDI_ADDRESS_IP*)((TA_ADDRESS*)((TRANSPORT_ADDRESS *)RemoteAddress)->Address)->Address;
        IPADDR IPAddress;
        SEPARATEADDR(RemoteAddr->in_addr,IPAddress.ip1,IPAddress.ip2,IPAddress.ip3,IPAddress.ip4);
        if (ConnectEvent != NULL)Result = (*ConnectEvent)(this,TdiSnifferContext->PID,TYPE_TO_SERVER,&IPAddress,RemoteAddr->sin_port,TdiSnifferContext->UserContext);
        
        DbgPrint("Server : IP = %d.%d.%d.%d and Port %d",IPAddress.ip1,IPAddress.ip2,IPAddress.ip3,IPAddress.ip4,HTONS(RemoteAddr->sin_port));
        
        if (Result == TDISNIFFER_ALLOW)
        {
           NTSTATUS status = (OriginalEvent)(TdiSnifferContext->OriginalContext,RemoteAddressLength,RemoteAddress,UserDataLength,UserData,OptionsLength,Options,ConnectionContext,AcceptIrp);
           return status;
        }
        else{
             return STATUS_CONNECTION_REFUSED;
        }
}

typedef ClientEventReceive(IN PVOID TdiEventContext,IN CONNECTION_CONTEXT ConnectionContext,IN ULONG ReceiveFlags,IN ULONG BytesIndicated,IN ULONG BytesAvailable,OUT ULONG *BytesTaken,IN PVOID Tsdu,OUT PIRP *IoRequestPacket);
typedef ClientEventReceive* PClientEventReceive;

NTSTATUS ClientEventReceiveDispatch(IN PVOID TdiEventContext,IN CONNECTION_CONTEXT ConnectionContext,IN ULONG ReceiveFlags,IN ULONG BytesIndicated,IN ULONG BytesAvailable,OUT ULONG *BytesTaken,IN PVOID Tsdu,OUT PIRP *IoRequestPacket)
{
        if (BytesTaken == NULL)
        {
           NTSTATUS status;           
           EVENT_HANDLER_IDENTIFIER*  SnifferContext = (EVENT_HANDLER_IDENTIFIER*)TdiEventContext;  
           PClientEventReceive OriginalEvent = (PClientEventReceive)SnifferContext->EventHandler;   
           status = (OriginalEvent)(SnifferContext->OriginalContext,ConnectionContext,ReceiveFlags,BytesIndicated,BytesAvailable,BytesTaken,Tsdu,IoRequestPacket);
           return status;
        }
        DbgPrint("Receive Command");
        *BytesTaken = BytesAvailable;
        *IoRequestPacket = NULL;
        EVENT_HANDLER_IDENTIFIER*  SnifferContext = (EVENT_HANDLER_IDENTIFIER*)TdiEventContext;
        TdiSniffer* Tdisniffer =  SnifferContext->TdiClass;
        return Tdisniffer->EventReceive(SnifferContext,ConnectionContext,ReceiveFlags,BytesIndicated,BytesAvailable,BytesTaken,Tsdu,IoRequestPacket);
}

NTSTATUS TdiSniffer::EventReceive(EVENT_HANDLER_IDENTIFIER* TdiSnifferContext,IN CONNECTION_CONTEXT ConnectionContext,IN ULONG ReceiveFlags,IN ULONG BytesIndicated,IN ULONG BytesAvailable,OUT ULONG *BytesTaken,IN PVOID Tsdu,OUT PIRP *IoRequestPacket)
{
        int Result = TDISNIFFER_ALLOW;
        PClientEventReceive OriginalEvent = (PClientEventReceive)TdiSnifferContext->EventHandler;
        DbgPrint("TdiSniffer : Bytes Received");
        char* Buffer = (char*)malloc(BytesAvailable+1);
        memset(Buffer,0,BytesAvailable+1);
        memcpy(Buffer, Tsdu, BytesAvailable);
        DWORD size = BytesAvailable;
        if (ReceiveEvent != NULL)Result = (*ReceiveEvent)(this,TdiSnifferContext->PID,Buffer,&size, TdiSnifferContext->UserContext);
        
        if (Result == TDISNIFFER_ALLOW)
        {
           return (OriginalEvent)(TdiSnifferContext->OriginalContext,ConnectionContext,ReceiveFlags,BytesIndicated,size,BytesTaken,Buffer,IoRequestPacket);
        }
        else{
             return STATUS_DATA_NOT_ACCEPTED;
        } 
}
typedef NTSTATUS ClientEventChainedReceive(IN PVOID  TdiEventContext,IN CONNECTION_CONTEXT ConnectionContext,IN ULONG  ReceiveFlags,IN ULONG  ReceiveLength,IN ULONG  StartingOffset,IN PMDL  Tsdu,IN PVOID  TsduDescriptor);
typedef ClientEventChainedReceive* PClientEventChainedReceive;

NTSTATUS ClientEventChainedReceiveDispatch(IN PVOID TdiEventContext,IN CONNECTION_CONTEXT ConnectionContext,IN ULONG  ReceiveFlags,IN ULONG  ReceiveLength,IN ULONG  StartingOffset,IN PMDL  Tsdu,IN PVOID  TsduDescriptor)
{
        NTSTATUS status;
        DbgPrint("Chained Receive Invoked");
        if (ReceiveLength == 0 || Tsdu == NULL || TdiEventContext == NULL || ConnectionContext == NULL)
        {
           DbgPrint("NULL Tsdu or TdiEventContext !!!");               
           return STATUS_DATA_NOT_ACCEPTED;
        }
        EVENT_HANDLER_IDENTIFIER*  SnifferContext = (EVENT_HANDLER_IDENTIFIER*)TdiEventContext;
        PClientEventChainedReceive OriginalEvent = (PClientEventChainedReceive)SnifferContext->EventHandler;
        if (OriginalEvent == NULL)
        {
           DbgPrint("NULL OriginalEvent !!!");               
           return STATUS_DATA_NOT_ACCEPTED;
        }
        //return STATUS_SUCCESS;
        DbgPrint("Context : 0x%x ConnectionContext : 0x%x ReceiveFlags : 0x%x ReceiveLength : 0x%x StartingOffset : 0x%x TsduDescriptor : 0x%x",SnifferContext->OriginalContext,ConnectionContext,ReceiveFlags,ReceiveLength,StartingOffset,Tsdu,TsduDescriptor);
        status = (OriginalEvent)(SnifferContext->OriginalContext,ConnectionContext,ReceiveFlags,ReceiveLength,StartingOffset,Tsdu,TsduDescriptor);
        return status;
        
        /*
        DbgPrint("Acquire Spinlock");
        //KeAcquireSpinLockAtDpcLevel(&SnifferContext->SpinLock);
        
        char* TsduBuffer = (char*)MmGetSystemAddressForMdlSafe(Tsdu, NormalPagePriority);
        if (TsduBuffer == NULL)
        {
            DbgPrint("NULL Buffer !!!");        
        }
        char* Buffer = (char*)malloc(ReceiveLength+1);
        memset(Buffer,0,ReceiveLength+1);
        memcpy(Buffer, (char*)((DWORD)TsduBuffer+StartingOffset), ReceiveLength-StartingOffset-1);
        //DbgPrint("Recieved : %s",Buffer);
        DbgPrint("Recieved : TsduBuffer = %x StartingOffset = %x TsduDescriptor = %x  ReceiveFlags = %x",TsduBuffer,StartingOffset,TsduDescriptor,ReceiveFlags);
        DbgPrint("IRQL = %d",KeGetCurrentIrql());
        PMDL newTsdu;
        if (AllocateMDL(newTsdu,Buffer,ReceiveLength))
        {
            DbgPrint("Calling OriginalEvent");
            //(OriginalEvent)(SnifferContext->OriginalContext,ConnectionContext,ReceiveFlags,ReceiveLength-StartingOffset-1,0,newTsdu,TsduDescriptor);
        }
        
        
        
        //KeReleaseSpinLockFromDpcLevel(&SnifferContext->SpinLock);
        DbgPrint("Release Spinlock");
        return status;
        return STATUS_SUCCESS;
        return (OriginalEvent)(SnifferContext->OriginalContext,ConnectionContext,ReceiveFlags,ReceiveLength,StartingOffset,Tsdu,TsduDescriptor);
        
        //EVENT_HANDLER_IDENTIFIER*  SnifferContext = (EVENT_HANDLER_IDENTIFIER*)TdiEventContext;
        //PClientEventChainedReceive OriginalEvent = (PClientEventChainedReceive)SnifferContext->EventHandler;
        //status = (OriginalEvent)(SnifferContext->OriginalContext,ConnectionContext,ReceiveFlags,ReceiveLength,StartingOffset,Tsdu,TsduDescriptor);
        //return status;
        //*/
}

//--------------------------------------------------------------------------------------------
//Connection Dynamic Array Functions:
//--------------------------------------
VOID TdiSniffer::AddToConnectionContext(CONNECTION_CONTEXT ConnectionContext,PVOID UserContext)
{
     CONNECTION_CONTEXT_ARRAY* ConnectionObj = (CONNECTION_CONTEXT_ARRAY*)malloc(sizeof(CONNECTION_CONTEXT_ARRAY));
     memset(ConnectionObj,0,sizeof(CONNECTION_CONTEXT_ARRAY));
     CONNECTION_CONTEXT_ARRAY* ObjArray = &ConnObjs;
     
     while (ObjArray->FLink !=0)
     {
           ObjArray = ObjArray->FLink;
     }
     DbgPrint("ConnectionContext Added : 0x%x",ConnectionContext); 
     ObjArray->ConnectionContext = ConnectionContext;
     ObjArray->UserContext = UserContext;
     ObjArray->FLink = ConnectionObj;
}
VOID TdiSniffer::AssociateConnectionContext(PVOID ConnectionContext,PVOID AssociatedObject)
{
     CONNECTION_CONTEXT_ARRAY* ObjArray = &ConnObjs;
     if (ObjArray->ConnectionContext == ConnectionContext)return;
     while (ObjArray->FLink !=0)
     {
           ObjArray = ObjArray->FLink;
           if (ObjArray->ConnectionContext == ConnectionContext)
           {
              DbgPrint("ConnectionContext Found : 0x%x",ConnectionContext); 
              ObjArray->AssociatedObject = AssociatedObject;
           }
     }
}
bool TdiSniffer::IsConnectionObjectFound(CONNECTION_CONTEXT ConnectionContext,OUT PVOID &UserContext)
{
     CONNECTION_CONTEXT_ARRAY* ObjArray = &ConnObjs;
     if (ObjArray->ConnectionContext == ConnectionContext)return true;
     while (ObjArray->FLink !=0)
     {
           ObjArray = ObjArray->FLink;
           if (ObjArray->ConnectionContext == ConnectionContext || ObjArray->AssociatedObject == ConnectionContext)
           {
              DbgPrint("ConnectionContext Found : 0x%x",ConnectionContext); 
              UserContext = ObjArray->UserContext;                            
              return true;
           }
     }
     return false;
}

bool TdiSniffer::RemoveFromConnectionContext(CONNECTION_CONTEXT ConnectionContext,OUT PVOID &UserContext)
{
     CONNECTION_CONTEXT_ARRAY* ObjArray = &ConnObjs;
     CONNECTION_CONTEXT_ARRAY* OldObjArray;
     if (ObjArray->ConnectionContext == ConnectionContext)
     {
         ObjArray->ConnectionContext = NULL;
         UserContext = ObjArray->UserContext;
         DbgPrint("ConnectionContext Removed : 0x%x",ConnectionContext); 
         return true;
     }
     while (ObjArray->FLink !=0)
     {
             OldObjArray = ObjArray;
             ObjArray = ObjArray->FLink;
             if (ObjArray->ConnectionContext == ConnectionContext)
             {
                 ObjArray->ConnectionContext = NULL;
                 UserContext = ObjArray->UserContext;
                 OldObjArray->FLink = ObjArray->FLink;
                 free(ObjArray);
                 DbgPrint("ConnectionContext Removed : 0x%x",ConnectionContext);
                 return true;
             }
             
     }
     return false;
     
}
