#include "RDF.h"

using namespace RDF;

typedef struct SystemServiceTable
{
    DWORD *KiServiceTable;
    DWORD *CounterBaseTable;
    DWORD nSystemCalls;
    DWORD *KiArgumentTable;
};
typedef struct ServiceDescriptorTable
{
    SystemServiceTable ServiceDescriptor[4];
};

extern "C" ServiceDescriptorTable* KeServiceDescriptorTable;

VOID SSDTDevice::Initialize(Driver* driver)
{
     pDriver = driver;
     this->Type = _SSDTDEVICE;
}

NTSTATUS SSDTDevice::AttachTo(WCHAR* FunctionName,DWORD newFunction)
{

      this->FuncIndex = GetSSDTIndex(FunctionName);
      DbgPrint("Function Index = 0x%x",FuncIndex);
      if (this->FuncIndex == 0)return STATUS_ERROR;
      this->realAddr = KeServiceDescriptorTable->ServiceDescriptor[0].KiServiceTable[this->FuncIndex];
      DbgPrint("Function Address = 0x%x",realAddr);
      DbgPrint("New Function Address = 0x%x",newFunction);
      DbgPrint("New Function Address2 = 0x%x",*((DWORD*)newFunction));
      DisableWriteProtection();
      InterlockedExchange((PLONG)&KeServiceDescriptorTable->ServiceDescriptor[0].KiServiceTable[this->FuncIndex],newFunction);
      EnableWriteProtection();
      
      Attached = true;
      return STATUS_SUCCESS;
}
DWORD SSDTDevice::GetRealAddress(WCHAR* FunctionName)
{
  DWORD FunctionIndex;
  
  FunctionIndex = GetSSDTIndex(FunctionName);
  if (FunctionIndex == 0)return 0;
  return KeServiceDescriptorTable->ServiceDescriptor[0].KiServiceTable[this->FuncIndex]; 
}
VOID SSDTDevice::Detach()
{
    if (Attached){
        
        DbgPrint("Function Address = 0x%x",realAddr);
        DbgPrint("Function Address = 0x%x",KeServiceDescriptorTable->ServiceDescriptor[0].KiServiceTable[this->FuncIndex]);
        DisableWriteProtection();
        InterlockedExchange((PLONG)&KeServiceDescriptorTable->ServiceDescriptor[0].KiServiceTable[this->FuncIndex],realAddr);
        EnableWriteProtection();
    }
}
DWORD SSDTDevice::GetSSDTIndex(WCHAR* zwFunctionName)
{
     UNICODE_STRING FuncName;
     RtlInitUnicodeString(&FuncName,zwFunctionName);
     PVOID FuncAddr = MmGetSystemRoutineAddress(&FuncName);
     if (FuncAddr == NULL)return 0;
     if (*((char*)FuncAddr) != (char)0xB8)return 0; 
     DWORD FuncIndex = *(DWORD*)((char*)FuncAddr + 1);
     
     return FuncIndex;
}
VOID SSDTDevice::EnableWriteProtection()
{
    _asm{
        PUSH EBX
        MOV EBX, CR0
        OR EBX, 0x00010000
        MOV CR0,EBX
        POP EBX
    }
}
VOID SSDTDevice::DisableWriteProtection()
{
    _asm{
        PUSH EBX
        MOV EBX, CR0
        AND EBX, 0xFFFEFFFF
        MOV CR0,EBX
        POP EBX
    }
}
