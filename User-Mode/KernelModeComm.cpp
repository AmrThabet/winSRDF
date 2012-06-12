#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <iostream>
#include "SRDF.h"


using namespace Security::Connections::KernelMode;
using namespace std;

cDriver::cDriver(char* servicename,char* filename)
{
     ServiceName = servicename;
     Filename = filename;
};
cDriver::cDriver()
{
}
int cDriver::LoadDriver()
{
    SC_HANDLE sh1;
	SC_HANDLE sh2;
	sh1 = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if ( !sh1 )
	{
		printf( "OpenSCManager Failed!\n" );
		return -1;
	}
	sh2 = CreateService(	sh1,
							ServiceName,
							ServiceName,
							SERVICE_ALL_ACCESS,
							SERVICE_KERNEL_DRIVER,
							SERVICE_DEMAND_START,
							SERVICE_ERROR_NORMAL,
							Filename,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL );
	if ( !sh2 )
	{
             cout << "Service Exists\n";
             return -1;
	}
	CloseServiceHandle(sh2);
	sh2 = OpenService(	sh1,
						ServiceName,
						0x0F01FF );
	BOOL x = StartService( sh2, NULL,NULL );
	if (x == TRUE)
	{
       //printf("\nDriver Started Successfully!\n");
  }
  else
  {
    printf("\nDriver Failed To Start!\n");
    return -1;
  }
  CloseServiceHandle(sh2);
  CloseServiceHandle(sh1);
  return 0;
};
int cDriver::UnloadDriver()
{
   SC_HANDLE sh1;
   SC_HANDLE sh2;
   SERVICE_STATUS ss;
	
	sh1 = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if ( !sh1 )
	{
		//printf( "OpenSCManager Failed!\n" );
		return -1 ;
	}
	sh2 = OpenService(	sh1,
						ServiceName,
						SERVICE_ALL_ACCESS );
	if ( !sh2 )
	{
			//printf("OpenService Failed!\n");
			CloseServiceHandle( sh1 );
			return -1;
	}
	ControlService( sh2, SERVICE_CONTROL_STOP, &ss );
	if ( !DeleteService( sh2 ) ){
		//printf("Could not unload MyDeviceDriver!\n");
		return -1;
	}else
		//printf("Unloaded MyDeviceDriver.\n");
	CloseServiceHandle( sh2 );
	CloseServiceHandle( sh1 );
    return 0; 
}
//==============================================================================================================
cDevice::cDevice(char* devicename)
{
    DeviceName = devicename;
    DeviceHandle = 
    CreateFile( DeviceName,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL );
    if(DeviceHandle == INVALID_HANDLE_VALUE)cout << "Error Handle\n";
    DWORD ThreadID = 0;
    hThread = CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)&ReadThread,this,0,&ThreadID);
}

bool cDevice::Write(char msgcode,DWORD status,char* data,DWORD size)
{
    char output[256];
    memset(output,0,256);
    DWORD return_size;
    DWORD InputSize = size+sizeof(CommChannel);
    CommChannel* InputData = (CommChannel*)malloc(InputSize);
    memset(InputData,0,InputSize);
    memcpy(&InputData->data,data,size);
    InputData->msgcode = msgcode;
    InputData->size = size;
    InputData->status = 0;
    if (!DeviceIoControl(DeviceHandle,
                         IOCTL_WRITEDATA,
                         InputData, InputSize,  // Input
                         output, 256,           // Output
                         &return_size,
                         NULL) )//*/
		return false;
	return true;
}
bool cDevice::SendFastMsg(char msgcode,DWORD status,char* data,DWORD size,DWORD& return_status,char* Output,DWORD MaxOutputSize)
{
    char* output = (char*)malloc(MaxOutputSize+sizeof(CommChannel));
    memset(output,0,256);
    DWORD return_size;
    DWORD InputSize = size+sizeof(CommChannel);
    CommChannel* InputData = (CommChannel*)malloc(InputSize);
    memset(InputData,0,InputSize);
    memcpy(&InputData->data,data,size);
    InputData->msgcode = msgcode;
    InputData->size = size;
    InputData->status = status;
    if (!DeviceIoControl(DeviceHandle,
                         IOCTL_WRITEDATA,
                         InputData, InputSize,               // Input
                         output, MaxOutputSize+sizeof(CommChannel),           // Output
                         &return_size,
                         NULL) )//*/
		return false;
    CommChannel* OutputBuffer = (CommChannel*)output;
    return_status = OutputBuffer->status;
    memcpy(Output,&OutputBuffer->data,return_size-sizeof(CommChannel));
    return true;
}
 void _cdecl ReadThread(cDevice* device)
{
    CommChannel InputData;
    char output[256];
    memset(output,0,256);
    DWORD return_size;
    while(1){
        Sleep(100);
        if( !DeviceIoControl(device->DeviceHandle,
                             IOCTL_READREQUEST,
                             &InputData, sizeof(CommChannel),  // Input
                             output, 256,           // Output
                             &return_size,
                             NULL) )//*/
                             continue;
                
        CommChannel* OutputBuffer = (CommChannel*)output;
        if (OutputBuffer->size > 256){
           OutputBuffer = (CommChannel*)malloc(OutputBuffer->size);
           if( !DeviceIoControl(device->DeviceHandle,
                             IOCTL_READREQUEST,
                             &InputData, sizeof(CommChannel),  // Input
                             OutputBuffer, OutputBuffer->size,  // Output
                             &return_size,
                             NULL) )//*/
                             continue;
        }else if (return_size == 0)
              continue;
        free(OutputBuffer);
    }
}
cDevice::~cDevice()
{
    TerminateThread(hThread,0);
    CloseHandle(DeviceHandle);
}
