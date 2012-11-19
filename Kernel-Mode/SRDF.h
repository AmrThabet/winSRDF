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

//#include "ntddk.h"
#include <ntifs.h>
#include <tdikrnl.h>
#include "ntdddisk.h"
#include "wdmsec.h"
#define __ENABLE_DEBUG_MSGS__ 1
#pragma once
#define MAX_DEVICES 64
#define DEVOBJ_LIST_SIZE 150  
//The Type Of Devices
#define _DEVICE 0
#define _SSDTDEVICE 1
#define _DKOMDEVICE 2
#define _FILTERDEVICE 3
#define _NDISFILTERDEVICE 4

#define IOCTL_FASTMSG           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_READREQUEST       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_WRITEDATA         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define STATUS_ERROR STATUS_UNSUCCESSFUL
#define DWORD unsigned long
#define BYTE char
#define malloc(nbytes) ExAllocatePool(NonPagedPool,nbytes)
#define free(ptr) ExFreePool(ptr)
#define SetValue(dest,src)                      \
    while(1){                                   \
        DWORD* nt_dest=(DWORD*)&dest;           \
        __asm {                                 \
            __asm PUSH EBX                      \
            __asm MOV EBX,src                   \
            __asm PUSH EAX                      \
            __asm MOV EAX,nt_dest               \
            __asm MOV [EAX],EBX                 \
            __asm POP EAX                       \
            __asm POP EBX                       \
        }                                       \
        break;                                  \
    }                                           \

#define SetValueCont(dest,src)                  \
    nt_dest=(DWORD*)&dest;                      \
    __asm {                                     \
        __asm PUSH EBX                          \
        __asm MOV EBX,src                       \
        __asm PUSH EAX                          \
        __asm MOV EAX,nt_dest                   \
        __asm MOV [EAX],EBX                     \
        __asm POP EAX                           \
        __asm POP EBX                           \
}
#define DELAY_ONE_MICROSECOND   (-10)
#define DELAY_ONE_MILLISECOND   (DELAY_ONE_MICROSECOND * 1000)
#define DELAY_ONE_SECOND        (DELAY_ONE_MILLISECOND * 1000)
#define UNREFERENCED_PARAMETER(P) {(P)=(P);}
extern "C" 
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING theRegistryPath );
VOID FileFilterNotificationDispatcher(PDEVICE_OBJECT TargetDevice,int command);

//  Macro to test if FAST_IO_DISPATCH handling routine is valid
#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName) \
    (((_FastIoDispatchPtr) != NULL) && \
    (((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
    (FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void *))) && \
    ((_FastIoDispatchPtr)->_FieldName != NULL))


typedef struct _DEVICE_EXTENSION
{
    PDEVICE_OBJECT AttachedToDeviceObject;
} _DEVICE_EXTENSION, *PDEVICE_EXTENSION;

namespace SRDF 
{
    //Prototypes
          
    class Device;
    class FilterDevice;
    class Driver;
    typedef int DeviceMJ(Device* device,__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
    typedef DeviceMJ* PDeviceMJ;
    typedef void ReadFunc(char msgcode,DWORD status,DWORD size,char* data);
    typedef ReadFunc *PReadFunc;
    typedef void FastMsgFunc(char msgcode,DWORD status,DWORD size,char* data,char* output,DWORD outputsize,DWORD &return_status,DWORD &return_size);
    typedef FastMsgFunc *PFastMsgFunc;
    
    //Classes
    
    //Device
    
    class Device { 
      public:
       //Variables
      int Type;
      bool DeviceCreated;
      PDeviceMJ MajorFunction[IRP_MJ_MAXIMUM_FUNCTION+1];
      PDEVICE_OBJECT pDeviceObject;
      UNICODE_STRING DeviceName;
      UNICODE_STRING SymbolicName;
      Driver* pDriver;
      
      class UserCommunication
      {
           public:
           //Varaibles
           struct CommChannel
           {
            char msgcode;
            DWORD status;
            DWORD size;
            char  data;       //expandable buffer    
           };
           CommChannel buffer;
           char* data;
           bool NeedToSend;
           PReadFunc ReadFunction;
           PFastMsgFunc FastMsgFunction;
           
           //Functions
           VOID RegisterReadFunction(PReadFunc readfunction);
           VOID RegisterFastMsgFunction(PFastMsgFunc fastmsgfunction);
           NTSTATUS Write(char msgcode,DWORD status,char* data,DWORD size);
      }UserComm;
      
      //Functions
      NTSTATUS CreateDevice(WCHAR* DeviceName,WCHAR* SymbolicName);
      VOID Initialize(Driver* driver);
      Device();
      
      VOID Unload();
      NTSTATUS IrpDispatcher(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
      
      private:
      int _cdecl UserComm_DeviceIO(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
    };
    //------------------------------------------------------------------------------------------
    //SSDT Device
    
    class SSDTDevice;
    typedef NTSTATUS FUNC(SSDTDevice* device,int Args[]);
    typedef FUNC *PFUNC;
    
    class SSDTDevice : public Device
    {
          public:
           //Variables
          bool Attached; 
          DWORD FuncIndex;
          DWORD realAddr;
          
          //Functions
          SSDTDevice();
          NTSTATUS AttachTo(WCHAR* FunctionName,DWORD newFunction);
          DWORD GetRealAddress(WCHAR* FunctionName);
          VOID Initialize(Driver* driver);
          VOID Detach();

          private:
          DWORD GetSSDTIndex(WCHAR* zwFunctionName);
          VOID EnableWriteProtection();
          VOID DisableWriteProtection();
    };
    struct HookingDevices{
        PDEVICE_OBJECT DeviceObject;
        PDEVICE_OBJECT NextDeviceObject;
    }; 
    //----------------------------------------------------------
    //Filter Device
    
    #define FILTER_SKIP                       0
    #define FILTER_COMPLETE_REQUEST           1
    #define FILTER_COMPLETE_REQUEST_SUCCESS   2
    #define FILTER_CALLDRIVER                 3 
    #define FILTER_SET_POST_MODFICATION       4
    
    NTSTATUS FDCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);
    
    typedef DeviceMJ* PDeviceMJ;
    struct FilteredMajorFunctionStruct
    {
      PDeviceMJ PreModification;
      PDeviceMJ PostModification;
    };
    typedef struct FILTERDEVICE_EXTENSION
    {
        PDEVICE_OBJECT AttachedDeviceObject;
        FilterDevice*  FilterDevicePtr;
        DWORD          Reserved;
    
    } *PFILTERDEVICE_EXTENSION;

    class FilterDevice : public Device
    {
        public:
        //Variables
        FilteredMajorFunctionStruct FilteredMajorFunction[IRP_MJ_MAXIMUM_FUNCTION+1];
        PDEVICE_OBJECT inheritedDeviceObject[MAX_DEVICES];
        DWORD nDeviceObjects;
        //Functions
        NTSTATUS IrpDispatcher(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
        int QueryDeviceObject(PDEVICE_OBJECT DeviceObject);
        int AddDeviceObject(PDEVICE_OBJECT DeviceObject);
        int RemoveDeviceObject(PDEVICE_OBJECT DeviceObject);
        NTSTATUS AttachToDevice(__in PDEVICE_OBJECT DeviceObject);
        NTSTATUS AttachToDevice(__in WCHAR* DeviceName);
        BOOLEAN IsAlreadyAttached(__in PDEVICE_OBJECT DeviceObject);
        VOID Initialize(Driver* driver);
        VOID Unload();
        NTSTATUS DetachDevice(__in WCHAR* DeviceName);
        VOID DetachDevice(PDEVICE_OBJECT DeviceObject);
        VOID Pending(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
    };
    //--------------------------------------------------
    // File Filter Device
    
    VOID FileFilterNotificationRoutine(PDEVICE_OBJECT TargetDevice,int command);
    
    #define FIELD_NOT_FOUND -1
    
    class FileFilterDevice;
    typedef bool AskAttach(FileFilterDevice* device,__in PDEVICE_OBJECT DeviceObject);
    typedef AskAttach* PAskAttach;
    struct FileInformationOffsets
    {
        DWORD FileName;
        DWORD ShortName;
        DWORD ShortNameLength;
        DWORD FileNameLength;
        DWORD FileAttributes;
        DWORD AllocationSize;
        DWORD EndOfFile;
        DWORD FileIndex;
        DWORD CreationTime;
        DWORD LastAccessTime;
        DWORD LastWriteTime;
        DWORD ChangeTime;
        DWORD EaSize;
        DWORD FileId;
        DWORD OpFileReference;
        DWORD OpObjectId;
        DWORD OpBirthObjectId;
        DWORD NextEntryOffset;
    };
    
    class FileFilterDevice : public FilterDevice
    {
          private:
          //Variables             
          BOOLEAN HookNewlyMountedVolumes;
          FAST_MUTEX AttachLock;
          //Functions
          NTSTATUS EnumerateVolumes(PDEVICE_OBJECT FileSystemDevice);
          int _cdecl MountNewVolumesPre(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
          public: 
          //Variables
          PAskAttach AskAttachFunc;
          //Functions
          VOID FileFilterNotificationRoutine(PDEVICE_OBJECT TargetDevice,int command);          
          NTSTATUS BeginHooking(BOOLEAN HookNewlyMountedVolumes);
          FileInformationOffsets* GetFileInformationOffsets(__in PIRP Irp);
    };
    //-------------------------------------------------------------------------------------------
    // Process Device - Process Analysis and APC Injection
    
    //__declspec(naked) void ApcUserRoutine(PVOID NormalContext, PVOID  SystemArgument1, PVOID SystemArgument2)	
    typedef struct _THREAD_BASIC_INFORMATION
    {
        NTSTATUS ExitStatus; 
        PVOID TebBaseAddress; 
        CLIENT_ID ClientId; 
        KAFFINITY AffinityMask; 
        KPRIORITY Priority; 
        KPRIORITY BasePriority;

    } THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
    
    //That's what I need right now
    typedef struct _EPROCESS
    {
          ULONG Pcb;
    } EPROCESS;
    class ProcessDevice : public Device
    {
          public:
          //Variables
          DWORD Pid;
          DWORD Tid;             //If avariable or NULL instead
          HANDLE ProcessHandle;
          PPEB   Peb;           //Process Environmenr Block
          EPROCESS* EProcess;
          PROCESS_BASIC_INFORMATION ProcessBasicInfo;
          KAPC_STATE* KPCState;
          BOOLEAN IsFound;     //True if you call to Analyze Process and everything works fine
          BOOLEAN IsAttached;
          //Functions
          BOOLEAN AnalyzeProcess(DWORD ProcessId,DWORD ThreadId = NULL);
          BOOLEAN AttachProcess();
          VOID DetachProcess(); 
          char* Read(DWORD BufferPtr,DWORD Size);
          DWORD Allocate(DWORD Size,DWORD Protect);
          BOOLEAN Write(DWORD Dest, char* Src, DWORD Size);
          BOOLEAN Execute (DWORD Entrypoint, PVOID Context);
    };
    
    //-------------------------------------------------------------------------------------------
    //TDI
    
    namespace Tdi
    {
         #define TCP_SOCKET_CLIENT 0     
         #define TCP_SOCKET_SERVER 1
         class TdiTcpSocket;
         
         typedef int ReceiveEvent(TdiTcpSocket* Sock,char* Buffer,DWORD Size);
         typedef ReceiveEvent* PReceiveEvent;
         typedef VOID DisconnectEvent(TdiTcpSocket* Sock);
         typedef DisconnectEvent* PDisconnectEvent;    
         
         class TdiTcpSocket : public Device
         { 
               //Variables
               HANDLE TransportAddr;
               PFILE_OBJECT FileObjTransportAddr;
               HANDLE Connection;
               PFILE_OBJECT FileObjConnection;
               bool Initialized;
               //Functions
               NTSTATUS CreateTransportAddress(USHORT port);
               NTSTATUS OpenConnection();
               NTSTATUS AssociateTransport();
               NTSTATUS SetEventHandler(LONG InEventType, PVOID InEventHandler, PVOID InEventContext);
               NTSTATUS DisassociateTransport();
               NTSTATUS CloseTransport();
               NTSTATUS CloseConnection();
               public:
               PReceiveEvent ReceiveEventFunc;
               PDisconnectEvent DisconnectEventFunc;
               bool Connected;
               NTSTATUS Send(char* Buffer, DWORD size, DWORD *pDataSent);
               NTSTATUS InitializeConnection(DWORD SocketType,USHORT port);
               NTSTATUS Listen();
               NTSTATUS DeinitializeConnection();
               NTSTATUS Connect(DWORD charIP1,DWORD charIP2,DWORD charIP3,DWORD charIP4, USHORT Port);
               NTSTATUS Disconnect();
               NTSTATUS Receive(ULONG ReceiveFlags, ULONG  BytesIndicated, ULONG  BytesAvailable, ULONG  *BytesTaken, PVOID  Tsdu, PIRP  *IoRequestPacket);
         };
         class TdiUdpSocket : public Device
         {
               
         };
         class cTdiFirewall;
         
         #define TDIFIREWALL_ALLOW 0
         #define TDIFIREWALL_DENY  1
         
         typedef int CreateConnectionEventFunc(cTdiFirewall* Sock,DWORD PID,USHORT Port,OUT PVOID &UserContext);
         typedef CreateConnectionEventFunc* PCreateConnectionEventFunc;
         
         typedef int CloseConnectionEventFunc(cTdiFirewall* Sock,DWORD PID,PVOID UserContext);
         typedef CloseConnectionEventFunc* PCloseConnectionEventFunc;
         
         #define TYPE_TO_CLIENT 0
         #define TYPE_TO_SERVER 1
         struct IPADDR;
         
         typedef int ConnectEventFunc(cTdiFirewall* Sock,DWORD PID,DWORD ConnectionType,IPADDR* IPAddress,DWORD Port,PVOID UserContext);
         typedef ConnectEventFunc* PConnectEventFunc;
         
         typedef int SendEventFunc(cTdiFirewall* Sock,DWORD PID,char* Buffer,DWORD* Size,PVOID UserContext);
         typedef SendEventFunc* PSendEventFunc;
          
         typedef int ReceiveEventFunc(cTdiFirewall* Sock,DWORD PID,char* Buffer,DWORD* Size,PVOID UserContext);
         typedef ReceiveEventFunc* PReceiveEventFunc;
         
         struct EVENT_HANDLER_IDENTIFIER
         {
                cTdiFirewall* TdiClass;
                DWORD PID;
                PVOID OriginalContext;
                PVOID EventHandler;
                KSPIN_LOCK SpinLock;
                PVOID UserContext;
         };
         struct CONNECTION_CONTEXT_ARRAY
         {
                PVOID ConnectionContext;
                PVOID AssociatedObject;
                PVOID UserContext;
                CONNECTION_CONTEXT_ARRAY* FLink;
         };
         struct IPADDR
         {
                DWORD ip1;
                DWORD ip2;
                DWORD ip3;
                DWORD ip4;
         };
         class cTdiFirewall : public FilterDevice
         {
               public:
               //Varaibles
               PCreateConnectionEventFunc CreateConnectionEvent;
               PCloseConnectionEventFunc CloseConnectionEvent;
               PConnectEventFunc ConnectEvent;
               PSendEventFunc SendEvent;
               PReceiveEventFunc ReceiveEvent;
               bool OnlyThroughFirewall;
               CONNECTION_CONTEXT_ARRAY ConnObjs;
               
               //functions       
               NTSTATUS BeginHooking(bool OnlyThroughFirewall);
               int _cdecl MJInternalIOControl(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
               int _cdecl MJCreate(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
               int _cdecl MJClose(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
               int MNTcpConnect(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp,PVOID UserContext);
               int MNAssociateAddress(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
               int MNTcpListen(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
               int MNSetEventHandler(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
               int MNSend(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
               int MNReceive(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
               VOID AddToConnectionContext(CONNECTION_CONTEXT ConnectionContext,PVOID UserContext);
               VOID AssociateConnectionContext(PVOID ConnectionContext,PVOID AssociatedObject);
               bool IsConnectionObjectFound(CONNECTION_CONTEXT ConnectionContext,OUT PVOID &UserContext);
               bool RemoveFromConnectionContext(CONNECTION_CONTEXT ConnectionContext,OUT PVOID &UserContext);
               NTSTATUS EventConnect(EVENT_HANDLER_IDENTIFIER* TdiFirewallContext, IN LONG  RemoteAddressLength,IN PVOID  RemoteAddress,IN LONG  UserDataLength,IN PVOID  UserData,IN LONG  OptionsLength,IN PVOID  Options,OUT CONNECTION_CONTEXT *ConnectionContext,OUT PIRP  *AcceptIrp);
               NTSTATUS EventReceive(EVENT_HANDLER_IDENTIFIER* TdiFirewallContext,IN CONNECTION_CONTEXT ConnectionContext,IN ULONG ReceiveFlags,IN ULONG BytesIndicated,IN ULONG BytesAvailable,OUT ULONG *BytesTaken,IN PVOID Tsdu,OUT PIRP *IoRequestPacket);
         };
    };
    //==========================================================================
    //Driver
    
    class Driver{
          public:
          //Variables
          PDRIVER_OBJECT pDriverObject;
          PUNICODE_STRING theRegistryPath;
          Device* device[MAX_DEVICES];
          int nDevices;
          BOOLEAN FSIsRegistered;
          FileFilterDevice* FSRegisteredDevices[MAX_DEVICES];
          DWORD nFSRegisteredDevices;
          
          //Functions
          VOID OnUnload();
          NTSTATUS AddDevice(Device* device);
          Driver();
          VOID FileFilterNotificationDispatcher(PDEVICE_OBJECT TargetDevice,int command);
          NTSTATUS MultiDeviceIrpDispatcher(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
          //User Functions
          VOID DriverUnload();
          NTSTATUS DriverMain(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING theRegistryPath); 
    };
    
    namespace misc
    {
        PVOID CreateClass(unsigned long nLength);
        bool AllocateMDL(PMDL &Mdl,char* Buffer, DWORD size);
    }
    /*
     * File Manager
     */
    namespace FileManager
    {
        #define FileToWriteType 0
        #define FileToReadType 1
        class File
        {
            public:
            //Variables
            struct DataOpr{
                PFAST_MUTEX mutex;
                char* data;
                DWORD size;
                bool IsNewData;
                NTSTATUS status;
            };
            DataOpr data;
            HANDLE FileHandle;
            HANDLE ThreadHandle;
            PETHREAD ThreadObject;
            bool ThreadContRunning;
            OBJECT_ATTRIBUTES FileAttr;
            int Type;
            //Functions
            NTSTATUS close();
        };
        class FileToWrite : public File
        {
            public:
            //Variables
    
            bool Append;
            //Functions
            NTSTATUS write(char* data,DWORD size);
            NTSTATUS open(WCHAR* Filename,bool Append);
        };
        
        class FileToRead : public File
        {
            public:
            //Variables
            DWORD* size;
            //Functions
            NTSTATUS read(char* &data,DWORD &size);   //if size == zero ... we will return the data & the size ... otherwise we will return the actual size in size
            NTSTATUS open(WCHAR* Filename);
        };
    };
    /*
     * Registry Manager
     */
    namespace RegistryManager
    {
       char* RegRead(WCHAR* KeyName,WCHAR* ValueName,DWORD &Length);
       NTSTATUS RegWrite(WCHAR* KeyName,WCHAR* ValueName,char* buffer,DWORD BufType,DWORD Length);
    };

};
//////////////////////////////////////////////////////////////////////////
// Fast-IO Handlers

BOOLEAN FsFilterFastIoCheckIfPossible(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in BOOLEAN            Wait,
    __in ULONG              LockKey,
    __in BOOLEAN            CheckForReadOperation,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoRead(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in BOOLEAN            Wait,
    __in ULONG              LockKey,
    __out PVOID             Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoWrite(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in BOOLEAN            Wait,
    __in ULONG              LockKey,
    __in PVOID              Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoQueryBasicInfo(
    __in PFILE_OBJECT       FileObject,
    __in BOOLEAN            Wait,
    __out PFILE_BASIC_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoQueryStandardInfo(
    __in PFILE_OBJECT       FileObject,
    __in BOOLEAN            Wait,
    __out PFILE_STANDARD_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoLock(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in PLARGE_INTEGER     Length,
    __in PEPROCESS          ProcessId,
    __in ULONG              Key,
    __in BOOLEAN            FailImmediately,
    __in BOOLEAN            ExclusiveLock,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoUnlockSingle(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in PLARGE_INTEGER     Length,
    __in PEPROCESS          ProcessId,
    __in ULONG              Key,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoUnlockAll(
    __in PFILE_OBJECT       FileObject,
    __in PEPROCESS          ProcessId,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoUnlockAllByKey(
    __in PFILE_OBJECT       FileObject,
    __in PVOID              ProcessId,
    __in ULONG              Key,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoDeviceControl(
    __in PFILE_OBJECT       FileObject,
    __in BOOLEAN            Wait,
    __in_opt PVOID          InputBuffer,
    __in ULONG              InputBufferLength,
    __out_opt PVOID         OutputBuffer,
    __in ULONG              OutputBufferLength,
    __in ULONG              IoControlCode,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

VOID FsFilterFastIoDetachDevice(
    __in PDEVICE_OBJECT     SourceDevice,
    __in PDEVICE_OBJECT     TargetDevice
    );

BOOLEAN FsFilterFastIoQueryNetworkOpenInfo(
    __in PFILE_OBJECT       FileObject,
    __in BOOLEAN            Wait,
    __out PFILE_NETWORK_OPEN_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoMdlRead(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in ULONG              LockKey,
    __out PMDL*             MdlChain,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoMdlReadComplete(
    __in PFILE_OBJECT       FileObject,
    __in PMDL               MdlChain,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoPrepareMdlWrite(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in ULONG              LockKey,
    __out PMDL*             MdlChain,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoMdlWriteComplete(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in PMDL               MdlChain,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoReadCompressed(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in ULONG              LockKey,
    __out PVOID             Buffer,
    __out PMDL*             MdlChain,
    __out PIO_STATUS_BLOCK  IoStatus,
    __out struct _COMPRESSED_DATA_INFO* CompressedDataInfo,
    __in ULONG              CompressedDataInfoLength,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoWriteCompressed(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in ULONG              Length,
    __in ULONG              LockKey,
    __in PVOID              Buffer,
    __out PMDL*             MdlChain,
    __out PIO_STATUS_BLOCK  IoStatus,
    __in struct _COMPRESSED_DATA_INFO*  CompressedDataInfo,
    __in ULONG              CompressedDataInfoLength,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoMdlReadCompleteCompressed(
    __in PFILE_OBJECT       FileObject,
    __in PMDL               MdlChain,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoMdlWriteCompleteCompressed(
    __in PFILE_OBJECT       FileObject,
    __in PLARGE_INTEGER     FileOffset,
    __in PMDL               MdlChain,
    __in PDEVICE_OBJECT     DeviceObject
    );

BOOLEAN FsFilterFastIoQueryOpen(
    __in PIRP               Irp,
    __out PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in PDEVICE_OBJECT     DeviceObject
    );

/*
//FastIo Routines:

BOOLEAN
SfFastIoCheckIfPossible(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN BOOLEAN CheckForReadOperation,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoRead(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoWrite(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoQueryBasicInfo(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_BASIC_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoQueryStandardInfo(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_STANDARD_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoLock(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    PEPROCESS ProcessId,
    ULONG Key,
    BOOLEAN FailImmediately,
    BOOLEAN ExclusiveLock,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoUnlockSingle(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    PEPROCESS ProcessId,
    ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoUnlockAll(
    IN PFILE_OBJECT FileObject,
    PEPROCESS ProcessId,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoUnlockAllByKey(
    IN PFILE_OBJECT FileObject,
    PVOID ProcessId,
    ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoDeviceControl(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    IN ULONG IoControlCode,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

VOID
SfFastIoDetachDevice(
    IN PDEVICE_OBJECT SourceDevice,
    IN PDEVICE_OBJECT TargetDevice
    );

BOOLEAN
SfFastIoQueryNetworkOpenInfo(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoMdlRead(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );


BOOLEAN
SfFastIoMdlReadComplete(
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoPrepareMdlWrite(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoMdlWriteComplete(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );
BOOLEAN
SfFastIoReadCompressed(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoWriteCompressed(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoMdlReadCompleteCompressed(
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
SfFastIoMdlWriteCompleteCompressed(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );
BOOLEAN
SfFastIoQueryOpen(
    IN PIRP Irp,
    OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    IN PDEVICE_OBJECT DeviceObject
    );

*/
