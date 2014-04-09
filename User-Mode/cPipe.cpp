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

#define BUFSIZE 1024

typedef BOOL WINAPI GetNamedPipeClientProcessIdAPI( __in HANDLE Pipe, __out PULONG ClientProcessId);

typedef GetNamedPipeClientProcessIdAPI *PGetNamedPipeClientProcessIdAPI;


DWORD WINAPI ServerThread(LPVOID param)
{
	cout << "Here\n";
	cPipeServer* Server = (cPipeServer*)param;
	while (1)
	{
		Server->ListenForConnection();
	}
	
}

cPipeServer::cPipeServer(cString PipeName, PPipeReadNotifyFunc ReadNotifyRoutine,bool AutoWaitForConnections)
{
	this->PipeName = "\\\\.\\Pipe\\";
	this->PipeName += PipeName;
	nSessions = 0;
	Sessions = (cPipeServerSession**)malloc(0);
	this->ReadNotifyRoutine = ReadNotifyRoutine;
	if (AutoWaitForConnections)
	{
		//cout << "Server Creating Thread\n";
		DWORD dwThreadId;
		hThread = CreateThread(NULL,0,ServerThread,(LPVOID) this,0,&dwThreadId);
		if (hThread == NULL) 
        {
			printf(TEXT("CreateThread failed, GLE=%d.\n"), GetLastError()); 
			cout << "Error\n";
			return;
        }
		Sleep(200);		//wait until Pipe Created

	}
	else
		hThread = NULL;
}

bool cPipeServer::ListenForConnection()
{
	//cout << "Here\n";
	    hPipe = CreateNamedPipe( 
		PipeName.GetChar(),       // pipe name 
		PIPE_ACCESS_DUPLEX,       // read/write access 
		PIPE_TYPE_MESSAGE |       // message type pipe 
		PIPE_READMODE_MESSAGE |   // message-read mode 
		PIPE_WAIT,                // blocking mode 
		PIPE_UNLIMITED_INSTANCES, // max. instances  
		BUFSIZE,                  // output buffer size 
		BUFSIZE,                  // input buffer size 
		0,                        // client time-out 
		NULL);                    // default security attribute 
	
	if (hPipe == INVALID_HANDLE_VALUE) 
	{
		cout << "Server Error Pipe\n";
		return false;
	}
	//cout << "Server waiting connection\n";
	BOOL fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 
	//cout << "Server Connected\n";
	if (fConnected) 
	{ 
		Sessions = (cPipeServerSession**)realloc(Sessions,(nSessions+1) * sizeof(DWORD));
		Sessions[nSessions] = new cPipeServerSession(this,hPipe);
		Sessions[nSessions]->SetReadNotifyRoutine(this->ReadNotifyRoutine);
		Sessions[nSessions]->Listen();
		nSessions++;
	}
	return true;
}

void cPipeServer::SetReadNotifyRoutine(PPipeReadNotifyFunc ReadFunc)
{
	ReadNotifyRoutine = ReadFunc;
}

cPipeServer::~cPipeServer()
{
	//Terminate the thread waiting for connections
	if (hThread != NULL)
	{
		TerminateThread(hThread,0);
	}

	//close all connections' sessions
	for (int i = 0; i < nSessions; i++)
	{
		delete Sessions[i];
	}

	//free buffer
	free(Sessions);
}

DWORD WINAPI SessionThread(LPVOID param)
{
	cPipeServerSession* Session = (cPipeServerSession*)param;
	Session->ReadThread();
	return 0;
}


cPipeServerSession::cPipeServerSession(cPipeServer* Server, HANDLE hPipe)
{
	this->hPipe = hPipe;
	this->Server = Server;
}

void cPipeServerSession::Listen()
{
	DWORD dwThreadId;
	hThread = CreateThread(NULL,0,SessionThread,(LPVOID) this,0,&dwThreadId);
	Sleep(200);
}

void cPipeServerSession::ReadThread()
{
	//cout << "Server Read Thread Started\n";
	while (1)
	{
		char* InputBuffer = (char*)malloc(BUFSIZE);
		DWORD Offset = 0; 
		DWORD cbBytesRead;
		bool fSuccess = ReadFile( 
			hPipe,			// handle to pipe 
			InputBuffer,	// buffer to receive data 
			BUFSIZE,		// size of buffer 
			&cbBytesRead,	// number of bytes read 
			NULL);			// not overlapped I/O 

		if (!fSuccess || cbBytesRead == 0)
		{   
			if (GetLastError() == ERROR_MORE_DATA)
			{
				while (!fSuccess)
				{
					Offset += BUFSIZE;
					InputBuffer = (char*)realloc(InputBuffer,Offset + BUFSIZE);
					fSuccess = ReadFile( 
						hPipe,									// handle to pipe 
						(char*)((DWORD)InputBuffer + Offset),    // buffer to receive data 
						BUFSIZE,								// size of buffer 
						&cbBytesRead,							// number of bytes read 
						NULL);
				}
			}
			else continue;
		}
		DWORD ProcessId;
		PGetNamedPipeClientProcessIdAPI GetPipeProcessId = (PGetNamedPipeClientProcessIdAPI)GetProcAddress(LoadLibraryA("Kernel32"),"GetNamedPipeClientProcessId");

		if (GetPipeProcessId == NULL) ProcessId = NULL;
		if (!(*GetPipeProcessId)(hPipe,&ProcessId)) ProcessId = NULL;
		if(ReadNotifyRoutine)
		{
			ReadNotifyRoutine(this,InputBuffer,Offset + cbBytesRead,ProcessId);
		}
		free(InputBuffer);
	}
}

void cPipeServerSession::Write(char* buff, DWORD len)
{
	DWORD cbWritten;

	bool fSuccess = WriteFile( 
		hPipe,			// handle to pipe 
		buff,			// buffer to write from 
		len,			// number of bytes to write 
		&cbWritten,		// number of bytes written 
		NULL);			// not overlapped I/O 

	FlushFileBuffers(hPipe);
}

cPipeServerSession::~cPipeServerSession()
{
	TerminateThread(hThread,0);
	DisconnectNamedPipe(hPipe); 
	CloseHandle(hPipe);
}

void cPipeServerSession::SetReadNotifyRoutine(PPipeReadNotifyFunc ReadFunc)
{
	ReadNotifyRoutine = ReadFunc;
}

cPipeClient::cPipeClient(cString PipeName,bool WaitForRead)
{
	IsConnected = false;
	this->PipeName = "\\\\.\\Pipe\\";
	this->PipeName += PipeName;
	while (1) 
	{ 
		hPipe = CreateFile( 
			this->PipeName.GetChar(),   // pipe name 
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE, 
			0,              // no sharing 
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file 

		// Break if the pipe handle is valid. 
		if (hPipe != INVALID_HANDLE_VALUE) 
			break; 

		if (GetLastError() != ERROR_PIPE_BUSY) 
		{
			cout << "Client Error Pipe busy\n";
			return;
		}

		if (! WaitNamedPipe(PipeName, 20000) ) 
		{
			cout << "Client Can't Connect\n";
			return;
		}
	}

	DWORD dwMode = PIPE_READMODE_MESSAGE; 

	bool fSuccess = SetNamedPipeHandleState( 
		hPipe,    // pipe handle 
		&dwMode,  // new pipe mode 
		NULL,     // don't set maximum bytes 
		NULL);    // don't set maximum time 

	if (!fSuccess) 
	{
		return;
	}
	cout << "Client Connected\n";
	IsConnected = true;
}

bool cPipeClient::SendFastMessage(char* InputBuffer,int InputLength,char* &OutputBuffer,int &OutputLength)
{
	char* Buffer = (char*)malloc(BUFSIZE);
	DWORD Offset = 0; 
	DWORD cbBytesRead;

	bool fSuccess = TransactNamedPipe( 
		hPipe,                  // pipe handle 
		InputBuffer,              // message to server
		InputLength,			// message length 
		Buffer,              // buffer to receive reply
		BUFSIZE,  // size of read buffer
		&cbBytesRead,                // bytes read
		NULL);                  // not overlapped 

	if (!fSuccess && (GetLastError() == ERROR_MORE_DATA)) 
	{
		while (!fSuccess)
		{
			Offset += BUFSIZE;
			Buffer = (char*)realloc(Buffer,Offset + BUFSIZE);
			fSuccess = ReadFile( 
				hPipe,									// handle to pipe 
				(char*)((DWORD)Buffer + Offset),    // buffer to receive data 
				BUFSIZE,								// size of buffer 
				&cbBytesRead,							// number of bytes read 
				NULL);
		}
	}
	else if (!fSuccess) return false;

	OutputBuffer = Buffer;
	OutputLength = Offset + cbBytesRead;
	return true;
}

cPipeClient::~cPipeClient()
{
	CloseHandle(hPipe);
}

void cPipeClient::SetReadNotifyRoutine(PPipeClientReadNotifyFunc ReadFunc)
{
	ReadRoutine = ReadFunc;
}

void ClientReadThread(LPVOID param)
{
	cPipeClient* Client = (cPipeClient*)param;
	Client->WaitForRead();
}

void cPipeClient::WaitForRead()
{
	while (1)
	{
		char* InputBuffer = (char*)malloc(BUFSIZE);
		DWORD Offset = 0; 
		DWORD cbBytesRead;
		bool fSuccess = ReadFile( 
			hPipe,			// handle to pipe 
			InputBuffer,	// buffer to receive data 
			BUFSIZE,		// size of buffer 
			&cbBytesRead,	// number of bytes read 
			NULL);			// not overlapped I/O 

		if (!fSuccess || cbBytesRead == 0)
		{   
			if (GetLastError() == ERROR_MORE_DATA)
			{
				while (!fSuccess)
				{
					Offset += BUFSIZE;
					InputBuffer = (char*)realloc(InputBuffer,Offset + BUFSIZE);
					fSuccess = ReadFile( 
						hPipe,									// handle to pipe 
						(char*)((DWORD)InputBuffer + Offset),    // buffer to receive data 
						BUFSIZE,								// size of buffer 
						&cbBytesRead,							// number of bytes read 
						NULL);
				}
			}
			else continue;
		}
		if (ReadRoutine != NULL)
			ReadRoutine(this,InputBuffer,Offset + cbBytesRead);
		free(InputBuffer);
	}
}