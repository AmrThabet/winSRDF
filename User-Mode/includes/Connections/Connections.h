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

#include "Socket.h"
#include "winInet.h"

using namespace Security::Elements::String;



class DLLIMPORT Security::Connections::Internet::cHTTPSocket
{
	HINTERNET hINet;
	HINTERNET hConnection;
public:
	cHTTPSocket(cString URL,INTERNET_PORT Port){open(URL,Port);};
	cHTTPSocket(){};
	bool open(cString URL,INTERNET_PORT Port);
	void close();
	bool SendRequest(cString Request);
	bool DownloadFile(cString Request,cString Filename);
	bool UploadFile(cString urlpath,cString Filename, cString FileArgName, cHash* OtherArgs);
	~cHTTPSocket(){close();}
};


#define MAX_DEVICES 64
#define DWORD unsigned long

#define IOCTL_FASTMSG           0x22E004
#define IOCTL_READREQUEST       0x22E008
#define IOCTL_WRITEDATA         0x22E00C

struct CommChannel
{
char msgcode;
DWORD status;
DWORD size;
char  data;       //expandable buffer    
};

typedef void ReadFunc(char msgcode,DWORD status,DWORD size,char* data);
typedef ReadFunc *PReadFunc;
 
class Security::Connections::KernelMode::cDevice
{
	
	PReadFunc ReadFunction;
	char* DeviceName;
	DWORD FileObject;
	
   HANDLE hThread;

public:
  HANDLE DeviceHandle;
  //Functions
  cDevice(char* devicename);
  ~cDevice();
  int RegisterReadFunction(PReadFunc readfunction);
  bool Write(char msgcode,DWORD status,char* data,DWORD size);
  bool SendFastMsg(char msgcode,DWORD status,char* data,DWORD size,DWORD& return_status,char* Output,DWORD MaxOutputSize);
  
};
void _cdecl ReadThread(Security::Connections::KernelMode::cDevice* device);             
class Security::Connections::KernelMode::cDriver
{     
   public:
   //Variables
    Security::Connections::KernelMode::cDevice* UserComm[MAX_DEVICES];
   char* ServiceName;
   char* Filename;
   
   //Function
   cDriver(char* servicename,char* filename);
   cDriver();
   int LoadDriver();
   int UnloadDriver();
   
};

#define EVENT_IPC_CLIENT 0
#define EVENT_IPC_SERVER 1
#define WAIT_TIME_OUT 300
typedef void ReadNotifyFunc(char* buffer,DWORD size);
typedef ReadNotifyFunc *PReadNotifyFunc;


class DLLIMPORT Security::Connections::InterProcess::cEventIPC
{
	HANDLE ReadEvent[2];
	HANDLE WriteEvent[2];
	HANDLE SharedMemory[2];
	char* Buffer[2];
	DWORD SrcType;		// it's the type of you ... you are a server or client
	DWORD DestType;		// it will be the type of the destination ... the opposite of SrcType ... just to make it easier
	HANDLE hThread;
	PReadNotifyFunc ReadNotify;
	DWORD Size;
	bool Continue;
public:
	VOID Read();
	bool IsCreatedSuccessfully;
	DWORD Write(char* Data,DWORD DataSize);
	VOID SetReadNotifyFunction(PReadNotifyFunc NotifyRoutine);
	cEventIPC(cString Name,DWORD Type, DWORD MaxSize);
	~cEventIPC();
};

//==========================================================================================
//Pipe Connections:
//==========================================================================================

typedef void PipeReadNotifyFunc(Security::Connections::InterProcess::cPipeServerSession* Session, char* buffer,DWORD size,int ProcessId);
typedef PipeReadNotifyFunc *PPipeReadNotifyFunc;

typedef void PipeClientReadNotifyFunc(Security::Connections::InterProcess::cPipeClient* Session, char* buffer,DWORD size);
typedef PipeClientReadNotifyFunc *PPipeClientReadNotifyFunc;
class DLLIMPORT Security::Connections::InterProcess::cPipeClient
{
	
	cString PipeName;
	HANDLE hPipe;
	HANDLE hThread;
	PPipeClientReadNotifyFunc ReadRoutine;
public:
	bool IsConnected;
	cPipeClient(cString PipeName,bool WaitForRead = false);
	bool SendFastMessage(char* InputBuffer,int InputLength,char* &OutputBuffer,int &OutputLength);
	void SetReadNotifyRoutine(PPipeClientReadNotifyFunc ReadFunc);
	void WaitForRead();
	void ReadThread();
	~cPipeClient();
};



class DLLIMPORT Security::Connections::InterProcess::cPipeServer
{
	cString PipeName;
	cPipeServerSession** Sessions;
	int nSessions;
	PPipeReadNotifyFunc ReadNotifyRoutine;
	HANDLE hPipe;
	HANDLE hThread;
public:
	cPipeServer(cString PipeName,PPipeReadNotifyFunc ReadNotifyRoutine,bool AutoWaitForConnections = true);
	bool ListenForConnection();
	void SetReadNotifyRoutine(PPipeReadNotifyFunc ReadFunc);
	~cPipeServer();
};

class DLLIMPORT Security::Connections::InterProcess::cPipeServerSession
{
	HANDLE hPipe;
	cPipeServer* Server;
	HANDLE hThread;
	PPipeReadNotifyFunc ReadNotifyRoutine;
public:
	cPipeServerSession(cPipeServer* Server, HANDLE hPipe);
	void Listen();
	void ReadThread();
	void Write(char* buff, DWORD len);
	~cPipeServerSession();
	void SetReadNotifyRoutine(PPipeReadNotifyFunc ReadFunc);
};