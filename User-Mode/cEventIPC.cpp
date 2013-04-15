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

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <iostream>
#include "SRDF.h"


using namespace Security::Connections::InterProcess;
using namespace std;

DWORD _cdecl EventIPC_ReadThread(cEventIPC* EventIPC)
{
	EventIPC->Read();
	return 0;
}
cEventIPC::cEventIPC(cString Name,DWORD Type, DWORD MaxSize)
{
	SrcType = Type;
	if (Type == EVENT_IPC_CLIENT)DestType = EVENT_IPC_SERVER;
	else DestType = EVENT_IPC_CLIENT;
	Size = MaxSize;

	cString ReadClient = Name + "ReadClientEvent";
	cString ReadServer = Name + "ReadServerEvent";
	cString WriteClient = Name + "WriteClientEvent";
	cString WriteServer = Name + "WriteServerEvent";
	cString ClientSharedMemory = Name + "ClientSharedMemory";	//where the client writes to
	cString ServerSharedMemory = Name + "ServerSharedMemory";	//where the Server writes to

	ReadEvent[EVENT_IPC_CLIENT] = CreateEvent( NULL, false, true, ReadClient.GetChar());
	ReadEvent[EVENT_IPC_SERVER] = CreateEvent( NULL, false, true, ReadServer.GetChar());
	WriteEvent[EVENT_IPC_CLIENT] = CreateEvent( NULL, false, true, WriteClient.GetChar());
	WriteEvent[EVENT_IPC_SERVER] = CreateEvent( NULL, false, true, WriteServer.GetChar());

	 SharedMemory[EVENT_IPC_CLIENT] = CreateFileMapping(
          INVALID_HANDLE_VALUE,
          NULL,
          PAGE_READWRITE,
          0,
          Size + 4,					//this "4" is for writing the size at the beginning
          ClientSharedMemory);    // name of mapping object
     
     if (NULL ==  SharedMemory[EVENT_IPC_CLIENT] || INVALID_HANDLE_VALUE ==  SharedMemory[EVENT_IPC_CLIENT]) 
     { 
          IsCreatedSuccessfully = false;
     }

	 SharedMemory[EVENT_IPC_SERVER] = CreateFileMapping(
          INVALID_HANDLE_VALUE,
          NULL,
          PAGE_READWRITE,
          0,
          Size + 4,					//this "4" is for writing the size at the beginning
          ServerSharedMemory);    // name of mapping object
     
     if (NULL ==  SharedMemory[EVENT_IPC_SERVER] || INVALID_HANDLE_VALUE ==  SharedMemory[EVENT_IPC_SERVER]) 
     { 
          IsCreatedSuccessfully = false;
     }
	 
	 Buffer[EVENT_IPC_CLIENT] = (char*) MapViewOfFile(SharedMemory[EVENT_IPC_CLIENT],   // handle to map object
          FILE_MAP_ALL_ACCESS, // read/write permission
          0,                   
          0,                   
          Size + 4);           
     
     if (NULL == Buffer[EVENT_IPC_CLIENT]) 
     { 
		 IsCreatedSuccessfully = false;
     }
	 memset(Buffer[EVENT_IPC_CLIENT],0,Size + 4);
	  Buffer[EVENT_IPC_SERVER] = (char*) MapViewOfFile(SharedMemory[EVENT_IPC_SERVER],   // handle to map object
          FILE_MAP_ALL_ACCESS, // read/write permission
          0,                   
          0,                   
          Size + 4);           
     
     if (Buffer[EVENT_IPC_SERVER] == NULL) 
     { 
          IsCreatedSuccessfully = false;
     }
	 memset(Buffer[EVENT_IPC_SERVER],0,Size + 4);
	 DWORD ThreadID = 0;
	 hThread = CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)&EventIPC_ReadThread,this,0,&ThreadID);
	 IsCreatedSuccessfully = true;
}
DWORD cEventIPC::Write(char* Data,DWORD DataSize)
{
	if (DataSize > Size) return 0;		//is too big
	if (DataSize == 0) return 0;
	//There's no other write?
	DWORD dwWaitResult = WaitForSingleObject(WriteEvent[SrcType], WAIT_TIME_OUT);
	if (dwWaitResult == WAIT_OBJECT_0)
    {
		 //Any read is finished
		 dwWaitResult = WaitForSingleObject(ReadEvent[DestType], WAIT_TIME_OUT);
		 if (WAIT_OBJECT_0 == dwWaitResult) 
		 {
			 SetEvent(ReadEvent[DestType]);
			
			DWORD BufferPtr = (DWORD)Buffer[SrcType];
			char* NewBuffer = (char*)(BufferPtr + 4); //Get the next 4 bytes
			memcpy(NewBuffer,Data,DataSize);
			*((DWORD*)Buffer[SrcType]) = DataSize;
			SetEvent(WriteEvent[SrcType]);
			
			return DataSize;
		 }
	}
	return 0xFFFFFFFF;
}
VOID cEventIPC::SetReadNotifyFunction(PReadNotifyFunc NotifyRoutine)
{
	ReadNotify = NotifyRoutine;
}
VOID cEventIPC::Read()
{
	Continue = true;
	while(Continue)
	{
		DWORD dwWaitResult = WaitForSingleObject(WriteEvent[DestType], WAIT_TIME_OUT);
		if (dwWaitResult == WAIT_OBJECT_0)
        {
			dwWaitResult = WaitForSingleObject(ReadEvent[SrcType], WAIT_TIME_OUT);
			 if (WAIT_OBJECT_0 == dwWaitResult) 
			 {
				
				SetEvent(WriteEvent[DestType]);
				DWORD WrittenSize = *(DWORD*)Buffer[DestType]; //The First 4 bytes
				
				if (WrittenSize == 0)
				{
					//No data was written
					SetEvent(ReadEvent[SrcType]);
					continue;
				}
				else
				{
					char* DataWritten = (char*)malloc(WrittenSize);
					memset(DataWritten,0,WrittenSize);	
					char* NewBuffer = (char*)((DWORD)Buffer[DestType] + 4); //Get the next 4 bytes
					memcpy(DataWritten, NewBuffer,WrittenSize);
					memset(Buffer[DestType],0,Size);			//with Maximum Size
					SetEvent(ReadEvent[SrcType]);
					(*ReadNotify)(DataWritten,WrittenSize);
					free(DataWritten);
				}
			}
		}
		else
		{
			Continue = false;
			IsCreatedSuccessfully = false;
			return;
		}
	}
	
}
cEventIPC::~cEventIPC()
{
	 for (int i = 0; i < 2; i++)
     {
          CloseHandle(ReadEvent[i]);
		  CloseHandle(WriteEvent[i]);
		  UnmapViewOfFile(Buffer[i]);
		  CloseHandle(SharedMemory[i]);
     }
	 Continue = false;
	 WaitForSingleObject(hThread,INFINITE);
}