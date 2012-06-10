#include "RDF.h"

using namespace RDF;
using namespace RDF::RegistryManager;

//Registry Manager

VOID RegReadThread(PVOID pContext);

struct RegData
{
       PKEY_VALUE_FULL_INFORMATION Information;
       char* buffer;
       DWORD length;
       DWORD BufType;              //For Write Only
       HANDLE ThreadHandle;
       UNICODE_STRING KeyName;
       UNICODE_STRING ValueName;
       OBJECT_ATTRIBUTES RegAttr;
       PETHREAD ThreadObject;
       NTSTATUS ntStatus;
}; 
char* RegistryManager::RegRead(WCHAR* KeyName,WCHAR* ValueName,DWORD &Length)
{
        DbgPrint("Registry Read ...");
        NTSTATUS ntStatus;
        RegData reg;
        reg.length = 0;
        reg.buffer = 0;
        RtlInitUnicodeString(&reg.KeyName, KeyName);
        RtlInitUnicodeString(&reg.ValueName, ValueName);
        InitializeObjectAttributes(&reg.RegAttr,&reg.KeyName,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
        ntStatus = PsCreateSystemThread(&reg.ThreadHandle,(ACCESS_MASK)0,NULL,(HANDLE)0,NULL,RegReadThread,&reg);  //Will take the Class as an argument
        if(ntStatus != STATUS_SUCCESS)
        {
            return NULL;
        }
        DbgPrint("Create RegReadThread Successful");
        ntStatus = ObReferenceObjectByHandle(reg.ThreadHandle,THREAD_ALL_ACCESS,NULL,KernelMode,(PVOID*)&reg.ThreadObject,NULL);
        if(ntStatus != STATUS_SUCCESS)
        {
            return NULL;
        }
        KeWaitForSingleObject(reg.ThreadObject,Executive,KernelMode,FALSE,NULL);
        Length = reg.length;
        if (reg.ntStatus !=STATUS_SUCCESS)return NULL;
        return reg.buffer;
}
VOID RegReadThread(PVOID pContext)
{
     NTSTATUS ntStatus;
     IO_STATUS_BLOCK ioStatus;
     HANDLE hKey;
     RegData* reg = (RegData*)pContext;
     reg->ntStatus = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &reg->RegAttr);
     
     if (!NT_SUCCESS(reg->ntStatus))
     {
        DbgPrint("Failed To Open the Registry Key");
        PsTerminateSystemThread(STATUS_SUCCESS);
     }
     DbgPrint("Opening Registry Key Success !!!");
     reg->ntStatus = ZwQueryValueKey(hKey,&reg->ValueName,KeyValueFullInformation,NULL,0,&reg->length);
     if ((reg->ntStatus != STATUS_BUFFER_TOO_SMALL) && (reg->ntStatus != STATUS_BUFFER_OVERFLOW))
     {
        DbgPrint("Failed To Query on Registry Value");
        PsTerminateSystemThread(STATUS_SUCCESS);
     }
     reg->Information = (PKEY_VALUE_FULL_INFORMATION)malloc(reg->length+1);
     if (reg->Information == NULL)PsTerminateSystemThread(STATUS_SUCCESS);
     memset(reg->Information,0,reg->length+1);
     reg->ntStatus = ZwQueryValueKey(hKey,&reg->ValueName,KeyValueFullInformation,(char*)reg->Information,reg->length,&reg->length);
     if (!NT_SUCCESS(reg->ntStatus))
     {
        DbgPrint("Failed To Query on Registry Value");
        PsTerminateSystemThread(STATUS_SUCCESS);
     };
     reg->length = reg->Information->DataLength;
     reg->buffer = (char*)malloc(reg->length + 2);                     // for the string-terminator 
     memset(reg->buffer,0,reg->length + 2);
     ULONG_PTR   pSrc = NULL;
     pSrc = (ULONG_PTR) ((CHAR*)reg->Information + reg->Information->DataOffset);
     memcpy(reg->buffer,(PVOID)pSrc,reg->length);
     ZwClose(hKey);
     PsTerminateSystemThread(STATUS_SUCCESS);
     
}
//---------------------------------------------------------------------------------------------------
VOID RegWriteThread(PVOID pContext);

NTSTATUS RegistryManager::RegWrite(WCHAR* KeyName,WCHAR* ValueName,char* buffer,DWORD BufType,DWORD Length)
{
        DbgPrint("Registry Write ...");
        NTSTATUS ntStatus;
        RegData reg;
        reg.length = Length;
        reg.buffer = buffer;
        reg.BufType = BufType; 
        RtlInitUnicodeString(&reg.KeyName, KeyName);
        RtlInitUnicodeString(&reg.ValueName, ValueName);
        InitializeObjectAttributes(&reg.RegAttr,&reg.KeyName,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
        ntStatus = PsCreateSystemThread(&reg.ThreadHandle,(ACCESS_MASK)0,NULL,(HANDLE)0,NULL,RegWriteThread,&reg);  //Will take the Class as an argument
        if(ntStatus != STATUS_SUCCESS)
        {
            return ntStatus;
        }
        DbgPrint("Create RegWriteThread Successful");
        ntStatus = ObReferenceObjectByHandle(reg.ThreadHandle,THREAD_ALL_ACCESS,NULL,KernelMode,(PVOID*)&reg.ThreadObject,NULL);
        if(ntStatus != STATUS_SUCCESS)
        {
            return ntStatus;
        }
        KeWaitForSingleObject(reg.ThreadObject,Executive,KernelMode,FALSE,NULL);
        Length = reg.length;
        return reg.ntStatus;
}
VOID RegWriteThread(PVOID pContext)
{
     NTSTATUS ntStatus;
     IO_STATUS_BLOCK ioStatus;
     HANDLE hKey;
     RegData* reg = (RegData*)pContext;
     reg->ntStatus = ZwCreateKey(&hKey,KEY_WRITE,&reg->RegAttr,0,NULL,REG_OPTION_VOLATILE,NULL);
     if (!NT_SUCCESS(reg->ntStatus))
     {
        DbgPrint("Failed To Create the Registry Key");
        PsTerminateSystemThread(STATUS_SUCCESS);
     }
     DbgPrint("Opening Registry Key Success !!!");
     reg->ntStatus = ZwSetValueKey(hKey,&reg->ValueName,0,reg->BufType,reg->buffer,reg->length);
     if (!NT_SUCCESS(reg->ntStatus))
     {
        DbgPrint("Failed To Write on Registry Value");
        PsTerminateSystemThread(STATUS_SUCCESS);
     };
     ZwClose(hKey);
     PsTerminateSystemThread(STATUS_SUCCESS);
}
