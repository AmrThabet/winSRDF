
/***************************************************************************************
****************************************************************************************

	class cTCPSocket

	Description:
	A universal asynchronous bidirectional TCP Winsock Socket class for client and server.
	The server supports up to 62 connections at the same time.
	This class may run within one single thread.

	All functions in this class return an API error code or 0 on success.

	Author: 
	Elmü (www.netcult.ch/elmue)

****************************************************************************************
****************************************************************************************/
#include "stdafx.h"
#include "SRDF.h"

using namespace Security::Connections::Internet;
/*
----------------------------------------------------------------------------------
Using these conventions results in better readable code and less coding errors !
----------------------------------------------------------------------------------

     cName  for generic class definitions
     CName  for MFC     class definitions
     tName  for type    definitions
     eName  for enum    definitions
     kName  for struct  definitions

    e_Name  for enum variables
    E_Name  for enum constant values

    i_Name  for instances of classes
    h_Name  for handles

    M_Name  for macros
    T_Name  for Templates
    t_Name  for TCHAR or LPTSTR

    s_Name  for strings
   sa_Name  for Ascii strings
   sw_Name  for Wide (Unicode) strings
   bs_Name  for BSTR
    f_Name  for function pointers
    k_Name  for contructs (struct)

    b_Name  bool,BOOL 1 Bit

   s8_Name    signed  8 Bit (char)
  s16_Name    signed 16 Bit (SHORT)
  s32_Name    signed 32 Bit (LONG, int)
  s64_Name    signed 64 Bit (LONGLONG)

   u8_Name  unsigned  8 Bit (BYTE)
  u16_Name  unsigned 16 bit (WORD, WCHAR)
  u32_Name  unsigned 32 Bit (DWORD, UINT)
  u64_Name  unsigned 64 Bit (ULONGLONG)

    d_Name  for double

  ----------------

    m_Name  for member variables of a class (e.g. ms32_Name for int member variable)
    g_Name  for global (static) variables   (e.g. gu16_Name for global WORD)
    p_Name  for pointer                     (e.g.   ps_Name  *pointer to string)
   pp_Name  for pointer to pointer          (e.g.  ppd_Name **pointer to double)
*/


cTCPSocket::cTCPSocket()
{
	mb_Initialized    = FALSE;
	mu32_WaitIndex    = 0;
	ms8_ReadBuffer    = 0;
	mu32_Tick64Lo     = 0;
	mu32_Tick64Hi     = 0;
	ms64_MaxIdleTime  = 0;
	mu32_EventTimeout = 0;
}

cTCPSocket::~cTCPSocket()
{
	if (mb_Initialized) 
	{
		Close();
		WSACleanup();
	}

	if (ms8_ReadBuffer) delete ms8_ReadBuffer;
}

// protected
// Load ws2_32.dll and initialize Windsock 2.0
DWORD cTCPSocket::Initialize()
{
	if (mb_Initialized)
		return 0;

	// Winsock version 2.0 is available on ALL Windows operating systems 
	// except Windows 95 which comes with Winsock 1.1
	WSADATA k_Data;
	DWORD u32_Error = WSAStartup(MAKEWORD(2,0), &k_Data);
	if (u32_Error)
		return u32_Error;

	ms8_ReadBuffer = new char[READ_BUFFER_SIZE];
	mb_Initialized = TRUE;
	return 0;
}

// Closes all open sockets
DWORD cTCPSocket::Close()
{
	if (!mi_List.mu32_Count)
		return WSAENOTCONN; // no socket open

	#if TRACE_EVENTS || TRACE_LOCK
		TraceA("Close()");
	#endif
		
	// Request thread safe access to mi_List
	cLock i_Lock;
	DWORD u32_Error = i_Lock.Request(&mk_Lock);
	if (u32_Error)
		return u32_Error;

	mi_List.RemoveAll();
	return 0;
}

// returns the current state of the socket
cTCPSocket::eState cTCPSocket::GetState()
{
	return mi_List.me_State;
}

// Get the count of open sockets
DWORD cTCPSocket::GetSocketCount()
{
	return mi_List.mu32_Count;
}

// returns all open sockets: Key = socket handle, Value = peer IP
DWORD cTCPSocket::GetAllConnectedSockets(cHash<SOCKET,DWORD>* pi_SockList)
{
	#if TRACE_EVENTS || TRACE_LOCK
		TraceA("GetAllConnectedSockets()");
	#endif

	pi_SockList->Clear();

	// Request thread safe access to mi_List
	cLock i_Lock;
	DWORD u32_Error = i_Lock.Request(&mk_Lock);
	if (u32_Error)
		return u32_Error;

	for (DWORD i=0; i<mi_List.mu32_Count; i++)
	{
		// On a server do not return socket[0] which is never connected
		if (!mi_List.mk_Data[i].u32_IP)
			continue;

		if (mi_List.mk_Data[i].b_Shutdown || mi_List.mk_Data[i].b_Closed)
			continue;

		pi_SockList->Append(mi_List.mk_Data[i].h_Socket, mi_List.mk_Data[i].u32_IP);
	}

	#if TRACE_EVENTS
		TraceA("Returning list with %d connected Sockets", pi_SockList->GetCount());
	#endif
	return 0;
}

// protected
// Create a new unbound socket and add it to mi_List at index 0
DWORD cTCPSocket::CreateSocket()
{
	DWORD u32_Error = Initialize();
	if (u32_Error)
		return u32_Error;

	if (mi_List.mu32_Count)
		return WSAEISCONN; // Socket already created

	SOCKET h_Socket = socket(AF_INET, SOCK_STREAM, 0);
	if (h_Socket == INVALID_SOCKET)
		return WSAGetLastError();

	HANDLE h_Event = WSACreateEvent();
	if (h_Event == WSA_INVALID_EVENT)
	{
		u32_Error = WSAGetLastError();
		closesocket(h_Socket);
		return u32_Error;
	}

	// Monitor all events on the socket
	if (WSAEventSelect(h_Socket, h_Event, FD_ALL_EVENTS) == SOCKET_ERROR)
	{
		u32_Error = WSAGetLastError();
		closesocket  (h_Socket);
		WSACloseEvent(h_Event);
		return u32_Error;
	}

	mi_List.Add(h_Socket, h_Event);
	return 0;
}

// Creates a Server socket
// You must wait for FD_ACCEPT events before sending data
// u32_BindIP = 0          --> listen on all network adapters
// u32_BindIP = 10.1.0.143 --> listen only on the network adapter with local IP 10.1.0.143
// u32_BindIP = 10.1.2.208 --> listen only on the network adapter with local IP 10.1.2.208
// u32_EventTimeout = the timeout after which ProcessEvents() will abort waiting for an event
// If u32_MaxIdleTime > 0  --> automatically disconnect clients which are idle for a longer time (in seconds)
DWORD cTCPSocket::Listen(DWORD u32_BindIP, USHORT u16_Port, DWORD u32_EventTimeout, DWORD u32_MaxIdleTime)
{
	#if TRACE_EVENTS || TRACE_LOCK
		TraceA("Listen()");
	#endif

	// Create a server socket which waits for Accept events
	// This socket itself will never be connected to any client!
	DWORD u32_Error = CreateSocket();
	if (u32_Error)
		return u32_Error;

	// get the new socket's data structure which has been filled in CreateSocket()
	kData* pk_Data = &mi_List.mk_Data[0];

	SOCKADDR_IN k_Addr;
	k_Addr.sin_family      = AF_INET;
	k_Addr.sin_addr.s_addr = u32_BindIP;
	k_Addr.sin_port        = htons(u16_Port);

	// Bind the socket to the given port
	if (bind(pk_Data->h_Socket, (LPSOCKADDR)&k_Addr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
	{
		u32_Error = WSAGetLastError();
		mi_List.RemoveAll();
		return u32_Error;
	}

	// Start listening for connection requests
	if (listen(pk_Data->h_Socket, WSA_MAXIMUM_WAIT_EVENTS) == SOCKET_ERROR)
	{
		u32_Error = WSAGetLastError();
		mi_List.RemoveAll();
		return u32_Error;
	}

	// The server is not yet connected (wait for FD_ACCEPT!)
	mi_List.me_State  = E_Server;
	ms64_MaxIdleTime  = u32_MaxIdleTime * 1000; // seconds -> ms
	mu32_EventTimeout = u32_EventTimeout; // ms
	return 0;
}

// Creates a Client socket
// u32_ServIP = 0x6401a8c0 -> 192.168.1.100
// If u32_MaxIdleTime > 0  -> automatically disconnect from server if idle for a longer time (in seconds)
// u32_EventTimeout = the timeout after which ProcessEvents() will abort waiting for an event
// *************************** ATTENTION ************************************
// When this funcion returns without error the socket is NOT YET connected!
// You must wait for the FD_CONNECT event before sending data to this socket!
// *************************** ATTENTION ************************************
DWORD cTCPSocket::ConnectTo(DWORD u32_ServIP, USHORT u16_Port, DWORD u32_EventTimeout, DWORD u32_MaxIdleTime)
{
	#if TRACE_EVENTS || TRACE_LOCK
		TraceA("ConnectTo()");
	#endif

	// Create a client socket which will connect to the server
	DWORD u32_Error = CreateSocket();
	if (u32_Error)
		return u32_Error;

	// get the new socket's data structure which has been filled in CreateSocket()
	kData* pk_Data = &mi_List.mk_Data[0];

	SOCKADDR_IN k_Addr;
	k_Addr.sin_family      = AF_INET;
	k_Addr.sin_addr.s_addr = u32_ServIP;
	k_Addr.sin_port        = htons(u16_Port);

	// Connect the socket to the given IP and port
	if (connect(pk_Data->h_Socket, (LPSOCKADDR)&k_Addr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
	{
		u32_Error = WSAGetLastError();
		if (u32_Error != WSAEWOULDBLOCK)
		{
			mi_List.RemoveAll();
			return u32_Error;
		}
	}

	// The client is not yet connected (wait for FD_CONNECT!)
	mi_List.me_State  = E_Client;
	ms64_MaxIdleTime  = u32_MaxIdleTime * 1000; // seconds -> ms
	mu32_EventTimeout = u32_EventTimeout; // ms

	// s64_IdleSince MUST be set HERE otherwise the socket will be closed before FD_CONNECT is received
	pk_Data->s64_IdleSince = GetTickCount64();
	pk_Data->u32_IP = u32_ServIP;
	return 0;
}

// This function is for use on a server only
// It can be called to force a disconnect of a specific client from the server
DWORD cTCPSocket::DisconnectClient(SOCKET h_Socket)
{
	#if TRACE_EVENTS || TRACE_LOCK
		TraceA("DisconnectClient(%X)", h_Socket);
	#endif

	// Request thread safe access to mi_List
	cLock i_Lock;
	DWORD u32_Error = i_Lock.Request(&mk_Lock);
	if (u32_Error)
		return u32_Error;
	
	// On a server Socket 0 is not connected
	int s32_Index = mi_List.FindSocket(h_Socket);
	if (s32_Index < 1)
		return ERROR_INVALID_PARAMETER;

	// Ignore all events on this socket except FD_CLOSE
	mi_List.mk_Data[s32_Index].b_Shutdown = TRUE;

	// DO NOT call closesocket() here !!!
	// shutdown() --> FD_CLOSE --> b_Shutdown=TRUE --> cList::Remove() --> closesocket()
	shutdown(h_Socket, SD_BOTH);
	return 0;
}

// Waits for incoming events on the port and processes them (used on Server + Client)
// returns the event(s) that occurred and the socket and it's IP-address which has caused the event.
// If the event is FD_READ the data will be returned in ppi_RecvMem which MUST be cleared with DeleteLeft() by the caller.
// If the event is FD_WRITE the remaining data in the send buffer will be sent and pu32_Sent receives the bytes sent.
// If there is more data to be read or sent, the next call to ProcessEvents() will process the next block of data.
// returns ERROR_TIMEOUT if during the given timeout no event occurres
// pu32_IP = 0x6401a8c0 -> 192.168.1.100
DWORD cTCPSocket::ProcessEvents(DWORD*   pu32_Events,  // OUT
                                  DWORD*   pu32_IP,      // OUT
								  SOCKET*    ph_Socket,  // OUT
                                  cMemory** ppi_RecvMem, // OUT
                                  DWORD*   pu32_Read,    // OUT
								  DWORD*   pu32_Sent)    // OUT
{
	#if TRACE_EVENTS || TRACE_LOCK
		TraceA("Entering ProcessEvents()");
	#endif

	DWORD u32_Error;
	kData* pk_Data;
	WSANETWORKEVENTS k_Events;

	*ph_Socket   = 0;
	*pu32_Events = 0;
	*pu32_IP     = 0;
	*pu32_Read   = 0;
	*pu32_Sent   = 0;
	*ppi_RecvMem = 0;

	// Block here if SendTo() or Close() have requested thread safe access to manipulate mi_List.
	cLock i_Lock;
	u32_Error = i_Lock.Loop(&mk_Lock);
	if (u32_Error)
		return u32_Error;

	// Remove all sockets which had a FD_CLOSE event in the last round
	mi_List.RemoveClosed();

	if (!mi_List.mu32_Count)
		return WSAENOTCONN; // No socket open

	// This timer is set to escape from WaitForMultiplEventsEx
	mi_List.mh_Events[0] = mk_Lock.h_ExitTimer;

	#if TRACE_EVENTS || TRACE_LOCK
		TraceA("!!!!! ProcessEvents WAIT");
	#endif

	// Wait until an event occurred or the timeout has elapsed
	// u32_Index is the index in the eventlist mh_Events of the event that has occurred
	DWORD u32_Index = WSAWaitForMultipleEventsEx(mi_List.mu32_Count+1, &mu32_WaitIndex, mi_List.mh_Events, mu32_EventTimeout);
	if (u32_Index == WSA_WAIT_FAILED)
		return WSAGetLastError();

	#if TRACE_EVENTS || TRACE_LOCK
		TraceA("");
		TraceA(">>>>> ProcessEvents CONTINUE");
	#endif

	// -------------------------------------------

	if (u32_Index == WSA_WAIT_TIMEOUT)
	{
		#if TRACE_EVENTS
			TraceA("# WSA_WAIT_TIMEOUT");
		#endif
		u32_Error = ERROR_TIMEOUT;
		goto _Exit;
	}

	// -------------------------------------------

	u32_Index -= WSA_WAIT_EVENT_0;

	// mi_List.mh_Events[0] is used for the Timer. It is not associated with a socket.
	if (u32_Index == 0)
	{
		#if TRACE_EVENTS
			TraceA("# Idle/Request Timer elapsed");
		#endif
		u32_Error = 0; // no error
		goto _Exit;
	}

	// Convert the 1-based event index into the zero-based socket index
	u32_Index--;

	// Get the data associated with the socket that has signaled the event
	pk_Data = &mi_List.mk_Data[u32_Index];

	// -------------------------------------------

	// Get the event(s) that occurred and their associated error array
	if (WSAEnumNetworkEvents(pk_Data->h_Socket, mi_List.mh_Events[u32_Index+1], &k_Events) == SOCKET_ERROR)
	{
		u32_Error = WSAGetLastError();
		mi_List.Remove(u32_Index); // remove socket with problem
		goto _Exit;
	}

	// After shutdown(pk_Data->h_Socket) has been called remove all events except FD_CLOSE
	if (pk_Data->b_Shutdown) k_Events.lNetworkEvents &= FD_CLOSE;

	// Signal the FD_TIMEOUT flag always together with FD_CLOSE
	if (pk_Data->b_Timeout && k_Events.lNetworkEvents & FD_CLOSE) 
		k_Events.lNetworkEvents |= FD_TIMEOUT;

	#if TRACE_EVENTS
		char s8_Buf[200];
		FormatEvents(k_Events.lNetworkEvents, s8_Buf);
		TraceA("# Socket %X: Events: %s", pk_Data->h_Socket, s8_Buf);
	#endif

	*pu32_Events = k_Events.lNetworkEvents;

	// -------------------------------------------

	if (k_Events.lNetworkEvents & FD_ACCEPT)
	{
		if (k_Events.iErrorCode[FD_ACCEPT_BIT])
		{
			u32_Error = k_Events.iErrorCode[FD_ACCEPT_BIT];
			goto _Exit;
		}

		SOCKADDR_IN k_Addr;
		int s32_Len = sizeof(k_Addr);
		// Accept the connect request from a client (k_Addr receives peer IP of connecting client)
		// The callback AcceptCondition() checks if the maximum count of connected clients was exceeded
		// If there are already 63 sockets open, the connect request is rejected.
		SOCKET h_Socket = WSAAccept(pk_Data->h_Socket, (LPSOCKADDR)&k_Addr, &s32_Len, AcceptCondition, (DWORD_PTR)this);
		if (h_Socket == INVALID_SOCKET)
		{
			u32_Error = WSAGetLastError();
			goto _Exit;
		}

		HANDLE h_Event = WSACreateEvent();
		if (h_Event == WSA_INVALID_EVENT)
		{
			u32_Error = WSAGetLastError();
			closesocket(h_Socket);
			goto _Exit;
		}
		
		// Monitor events on the newly connected client socket
		if (WSAEventSelect(h_Socket, h_Event, FD_ALL_EVENTS) == SOCKET_ERROR)
		{
			u32_Error = WSAGetLastError();
			closesocket  (h_Socket);
			WSACloseEvent(h_Event);
			goto _Exit;
		}

		// Append the new socket to the socket list
		pk_Data = mi_List.Add(h_Socket, h_Event);
		// Store the client's IP in the socket list
		pk_Data->u32_IP = k_Addr.sin_addr.s_addr;
		// Store the time when the last action was executed on the socket
		pk_Data->s64_IdleSince = GetTickCount64();

		// successfully connected
		if (mi_List.me_State & E_Server)
			mi_List.me_State = (eState)(E_Server | E_Connected);

		// This is a workaround for Windows CE:
		// Without the following code Socket[0] would be dead (deaf) after the first connection.
		// So no further connection could be made after the first connection.
		// This may be a bug but if it is, this bug has never been confirmed by Microsoft.
		// On the other hand Microsoft did not document that this behaviour is normal for Windows CE.
		// So it is an enigma. At least this is a workaround which solves the problem.
		#ifdef _WIN32_WCE
			if (WSAEventSelect(mi_List.mk_Data[0].h_Socket, mi_List.mh_Events[1], FD_ALL_EVENTS) == SOCKET_ERROR)
			{
				u32_Error = WSAGetLastError();
				mi_List.RemoveAll();
				return u32_Error;
			}
		#endif
		
		// Multiple events may be set!
	}

	*ph_Socket = pk_Data->h_Socket;
	*pu32_IP   = pk_Data->u32_IP;
	
	// -------------------------------------------

	if (k_Events.lNetworkEvents & FD_CONNECT)
	{
		if (k_Events.iErrorCode[FD_CONNECT_BIT])
		{
			u32_Error = k_Events.iErrorCode[FD_CONNECT_BIT];
			// The connection has failed -> remove faulty socket from the socket list
			mi_List.Remove(u32_Index);
			goto _Exit;
		}

		// Store the time when the last action was executed on the socket
		pk_Data->s64_IdleSince = GetTickCount64();

		// successfully connected
		// NOTE: on Windows CE a server signals FD_ACCEPT and FD_CONNECT at the same time! (Bug?)
		// So ignore this FD_CONNECT on a Server.
		if (mi_List.me_State & E_Client)
			mi_List.me_State = (eState)(E_Client | E_Connected);
		
		// Multiple events may be set!
	}

	// -------------------------------------------

	if (k_Events.lNetworkEvents & FD_READ)
	{
		if (k_Events.iErrorCode[FD_READ_BIT])
		{
			u32_Error = k_Events.iErrorCode[FD_READ_BIT];
			mi_List.Remove(u32_Index); // remove socket with Read error
			goto _Exit;
		}

		// Read the data into the read buffer
		DWORD u32_Flags = 0;
		WSABUF  k_Buf;
		k_Buf.buf = ms8_ReadBuffer;
		k_Buf.len = READ_BUFFER_SIZE;
		if (WSARecv(pk_Data->h_Socket, &k_Buf, 1, pu32_Read, &u32_Flags, 0, 0) == SOCKET_ERROR)
		{
			u32_Error = WSAGetLastError();

			if (u32_Error == WSAEWOULDBLOCK) u32_Error = 0;
			if (u32_Error)
			{	
				mi_List.Remove(u32_Index); // remove socket with Read error
				goto _Exit;
			}
		}

		#if TRACE_EVENTS
			TraceA("Received %d Bytes", *pu32_Read);
		#endif

		if (!pk_Data->pi_RecvMem)
			 pk_Data->pi_RecvMem = new cMemory(MEMORY_INITIAL_SIZE);
		
		pk_Data->pi_RecvMem->Append(ms8_ReadBuffer, *pu32_Read);

		// Store the time when the last action was executed on the socket
		pk_Data->s64_IdleSince = GetTickCount64();

		*ppi_RecvMem = pk_Data->pi_RecvMem;
		
		// Multiple events may be set!
	}

	// -------------------------------------------

	if (k_Events.lNetworkEvents & FD_WRITE)
	{
		if (k_Events.iErrorCode[FD_WRITE_BIT])
		{
			u32_Error = k_Events.iErrorCode[FD_WRITE_BIT];
			mi_List.Remove(u32_Index); // remove socket with Write error
			goto _Exit;
		}

		// Is there pending data in the send buffer waiting to be sent ?
		if (pk_Data->s8_SendBuf)
		{
			// Send as much as possible data from the send buffer
			DWORD u32_Before = pk_Data->u32_SendPos;
			u32_Error = SendDataBlock(pk_Data->h_Socket, pk_Data->s8_SendBuf, &pk_Data->u32_SendPos, pk_Data->u32_SendLen);
			*pu32_Sent = pk_Data->u32_SendPos - u32_Before;

			if (pk_Data->u32_SendPos == pk_Data->u32_SendLen)
			{
				// All data has been sent successfully -> delete the buffer
				delete pk_Data->s8_SendBuf;
				pk_Data->s8_SendBuf = 0;
			}

			if (u32_Error == WSAEWOULDBLOCK) u32_Error = 0;
			if (u32_Error)
			{
				mi_List.Remove(u32_Index); // remove socket with Write error
				goto _Exit;
			}
		}

		// Store the time when the last action was executed on the socket
		pk_Data->s64_IdleSince = GetTickCount64();
		
		// Multiple events may be set!
	}

	// -------------------------------------------

	if (k_Events.lNetworkEvents & FD_CLOSE)
	{
		// ATTENTION: The socket must NOT yet be removed from mi_List!
		// Sometimes a FD_READ comes at the same time as a FD_CLOSE.
		// In this case the read data would be lost.
		// The socket will be removed in mi_List.RemoveClosed() in the next round
		pk_Data->b_Closed = TRUE;

		if (k_Events.iErrorCode[FD_CLOSE_BIT]) // e.g. WSAECONNABORTED
		{
			u32_Error = k_Events.iErrorCode[FD_CLOSE_BIT];
			goto _Exit;
		}
		
		// Multiple events may be set!
	}

	u32_Error = 0; // Success

	// -------------------------------------------

	_Exit:
	// 1.) Shutdown all connected sockets that are idle for longer than mi_List.ms64_MaxIdleTime
	// 2.) Set the timer mk_Lock.h_ExitTimer to fire when the socket with the longest idle time will be due
	// When cLock::Request() is called, WsaWaitForMultipleEventsEx() must stop blocking.
	// Therefore ProcessIdleSockets() must not be called between cLock::Loop() and WsaWaitForMultipleEventsEx()
	// because it sets the same timer!
	DWORD u32_IdleErr = ProcessIdleSockets("ProcessEvents()");
	if (u32_IdleErr)
		return u32_IdleErr;

	return u32_Error;
}

// This is a special Wait function which eliminates a problem of WSAWaitForMultipleEvents:
// WSAWaitForMultipleEvents scans the events in the event array ph_Events from zero on.
// When it finds one that is signaled it stops and retruns it's index.
// This may cause a problem on a server with high load near 100% CPU power:
// When multiple events are signaled always the ones at the begin of the event array will be preferred
// and the events at the end of the array will be in disadvantage.
// To avoid this, this function uses a pointer pu32_Index from which on a signaled event is searched.
// This pointer is incremented until the last event and then starts from the first again.
// So every client on a server has the same priority in being served.
// ph_Events  = array of event handles
// u32_Count  = count of events in array
// pu32_Index = rotating index
DWORD cTCPSocket::WSAWaitForMultipleEventsEx(DWORD u32_Count, DWORD* pu32_Index, WSAEVENT* ph_Events, DWORD u32_Timeout)
{
	// Here *pu32_Index is at the position where the last time an event has been signaled
	// Search for a signaled event from *pu32_Index +1 upwards
	for (DWORD C=0; C<u32_Count; C++)
	{
		(*pu32_Index)++;

		if (*pu32_Index >= u32_Count)
			*pu32_Index = 0;

		// Check if the event is set (Timeout = 0)
		DWORD u32_Res = WaitForSingleObject(ph_Events[*pu32_Index], 0);
		if (u32_Res == WAIT_OBJECT_0)
			return WSA_WAIT_EVENT_0 + *pu32_Index;
	}

	// There is no event signaled -> this means that the server is not under stress
	// There is no reason to check the events one by one anymore.
	DWORD u32_Res = WSAWaitForMultipleEvents(u32_Count, ph_Events, FALSE, u32_Timeout, FALSE);
	if (u32_Res != WSA_WAIT_FAILED && u32_Res != WSA_WAIT_TIMEOUT)
	{
		*pu32_Index = u32_Res - WSA_WAIT_EVENT_0;
	}
	return u32_Res;
}

// static
// Decides if a connection request from a client is accepted. (Max 63 open sockets possible)
// WSAAccept() will return WSAECONNREFUSED if AcceptCondition() returns CF_REJECT
int WINAPI cTCPSocket::AcceptCondition(WSABUF* pk_CallerId, WSABUF* pk_CallerData, QOS* pk_SQOS, QOS* pk_GQOS, 
										 WSABUF* pk_CalleeId, WSABUF* pk_CalleeData, UINT* pu32_Group, DWORD_PTR p_Param)
{
	cTCPSocket* p_This = (cTCPSocket*)p_Param;

	if (p_This->mi_List.mu32_Count >= WSA_MAXIMUM_WAIT_EVENTS-1)
		return CF_REJECT;
	else
		return CF_ACCEPT;
}

// Shutdown all sockets that are idle for longer than ms64_MaxIdleTime milliseconds
// Set timer mk_Lock.h_ExitTimer to fire when the socket with the longest idle time will become due
// s8_Caller = the calling function, only used for debugging (Trace)
DWORD cTCPSocket::ProcessIdleSockets(char* s8_Caller)
{
	if (!ms64_MaxIdleTime)
		return 0;

	LONGLONG s64_Now    = GetTickCount64(); // current tick count in ms
	LONGLONG s64_Oldest = s64_Now +1;

	for (DWORD i=0; i<mi_List.mu32_Count; i++)
	{
		kData* pk_Data = &mi_List.mk_Data[i];

		if (!pk_Data->u32_IP || pk_Data->b_Shutdown)
			continue; // Ignore socket 0 on a server (IP = 0.0.0.0)

		// Add 100 ms to assure that the max idle time surely has elapsed because
		// GetTickCount() increments in 17 ms steps (clock interrupt) and is not as exact as SetWaitableTimer()
		if (s64_Now - pk_Data->s64_IdleSince + 100 >= ms64_MaxIdleTime)
		{
			#if TRACE_EVENTS
				TraceA("+ Shutting down idle Socket %X", pk_Data->h_Socket);
			#endif

			// Set FD_TIMEOUT flag when FD_CLOSE will be fired
			pk_Data->b_Timeout = TRUE;
			// Ignore all events on this socket except FD_CLOSE
			pk_Data->b_Shutdown = TRUE;

			// DO NOT call closesocket() here !!!
			// shutdown() --> FD_CLOSE --> b_Shutdown=TRUE --> cList::Remove() --> closesocket()
			shutdown(pk_Data->h_Socket, SD_BOTH);
		}
		else if (s64_Oldest > pk_Data->s64_IdleSince)
		{
			// Get the oldest "last activity"
			s64_Oldest = pk_Data->s64_IdleSince;
		}
	}

	// Do not set the timer if there is no socket connected (s64_Oldest == s64_Now +1)
	if (s64_Oldest <= s64_Now)
	{
		DWORD u32_Interval = (DWORD)max(0, ms64_MaxIdleTime - (s64_Now - s64_Oldest));

		// If the event timeout is short there is no need to set the timer
		if (u32_Interval > mu32_EventTimeout)
			return 0;
		
		#if TRACE_EVENTS
			TraceA("+ %s Setting Timer: Idle Interval= %d ms", s8_Caller, u32_Interval);
		#endif

		// k_Interval must be negative value with 100 nano seconds resolution to set a relative time
		LARGE_INTEGER k_Interval;
		k_Interval.QuadPart = (LONGLONG)u32_Interval * -10000;
		
		// mh_Events[0] == mk_Lock.h_ExitTimer
		if (!SetWaitableTimer(mi_List.mh_Events[0], &k_Interval, 0, 0, 0, FALSE))
			return GetLastError();
	}
	return 0;
}

// protected
// Send the remaining data and adjust the pu32_Pos pointer.
// If the data was sent only partially (WSAEWOULDBLOCK) this function must be called again
DWORD cTCPSocket::SendDataBlock(SOCKET h_Socket, char* s8_Buf, DWORD* pu32_Pos, DWORD u32_Len)
{
	while (*pu32_Pos < u32_Len)
	{
		WSABUF k_Buf;
		k_Buf.buf =  s8_Buf + *pu32_Pos;
		k_Buf.len = u32_Len - *pu32_Pos;
		
		DWORD u32_Sent = 0;
		if (WSASend(h_Socket, &k_Buf, 1, &u32_Sent, 0, 0, 0) == SOCKET_ERROR)
			return WSAGetLastError();

		#if TRACE_EVENTS
			TraceA("SendDataBlock has sent %d Bytes", u32_Sent);
		#endif

		*pu32_Pos += u32_Sent;
	};
	return 0;
}

// Send the data in s8_Buf to the given socket (Server + Client)
// This function will not block.
// If the data cannot be sent immediately, the function returns WSAEWOULDBLOCK and the data is buffered until the next 
// FD_WRITE event which will be signaled when the correct time has come to send more data to that socket.
// It is possible that a part of the data is sent immediately and the rest is buffered to be sent after next FD_WRITE.
// If you call this function while a previous Send operation is still pending, the function returns WSA_IO_PENDING.
// In this case try again later!
// ATTENTION:
// When this function returns without error, this does not mean that all data has already arrived at the recipient!
// WinSock uses a transport buffer and the real transmision of the data may take a long time after this function has returned.
DWORD cTCPSocket::SendTo(SOCKET h_Socket, char* s8_Buf, DWORD u32_Len)
{
	#if TRACE_EVENTS || TRACE_LOCK
		TraceA("SendTo(Socket %X, %d Bytes)", h_Socket, u32_Len);
	#endif

	// Request thread safe access to mi_List
	cLock i_Lock;
	DWORD u32_Error = i_Lock.Request(&mk_Lock);
	if (u32_Error)
		return u32_Error;

	if (!(mi_List.me_State & E_Connected))
		return WSAENOTCONN; // Socket is not connected

	int s32_Index = mi_List.FindSocket(h_Socket);
	if (s32_Index < 0)
		return ERROR_INVALID_PARAMETER; // Invalid Socket handle passed

	kData* pk_Data = &mi_List.mk_Data[s32_Index];
	if (pk_Data->b_Shutdown || pk_Data->b_Closed)
		return WSAESHUTDOWN; // The socket has already been shut down, but mi_List.Remove() has not yet been called

	pk_Data->s64_IdleSince = GetTickCount64();

	// Set Idle Timer
	if (u32_Error = ProcessIdleSockets("SendTo()       "))
		return u32_Error;

	if (pk_Data->s8_SendBuf)
		return WSA_IO_PENDING; // a Send operation is still in progress on this socket

	// Sends as much data as possible at this moment, increases u32_Pos
	DWORD u32_Pos = 0;
	u32_Error = SendDataBlock(h_Socket, s8_Buf, &u32_Pos, u32_Len);

	// Not all the data could be sent right now:
	// The remaining data is copied into a buffer and will be sent when FD_WRITE becomes signaled.
	if (u32_Error == WSAEWOULDBLOCK)
	{
		u32_Len -= u32_Pos;
		s8_Buf  += u32_Pos;

		pk_Data-> s8_SendBuf = new char[u32_Len];
		pk_Data->u32_SendLen = u32_Len;
		pk_Data->u32_SendPos = 0;
		memcpy(pk_Data->s8_SendBuf, s8_Buf, u32_Len);
		return u32_Error;
	}

	if (u32_Error && u32_Error != WSA_IO_PENDING)
		mi_List.Remove(s32_Index); // remove socket with Write error
	
	return u32_Error;
}

// LocalIp = 0x6401a8c0 -> 192.168.1.100
// returns a list of all local IP's on this computer (multiple IP's if multiple network adapters)
// cHash is used as an array with Key= 0, Value= local IP
DWORD cTCPSocket::GetLocalIPs(cHash<DWORD,DWORD>* pi_IpList)
{
	pi_IpList->Clear();

	DWORD u32_Error = Initialize();
	if (u32_Error)
		return u32_Error;

	char s8_Host[500];
	if (gethostname(s8_Host, sizeof(s8_Host)) == SOCKET_ERROR)
		return WSAGetLastError();
	
	struct hostent* pk_Host = gethostbyname(s8_Host);
	if (!pk_Host)
		return WSAGetLastError();

	for (DWORD i=0; TRUE; i++)
	{
		if (!pk_Host->h_addr_list[i])
			break; // The IP list is zero terminated
	
		pi_IpList->Append(0, *((DWORD*)pk_Host->h_addr_list[i]));
	}

	if (!pi_IpList->GetCount())
		return WSAENETDOWN; // no local IP means no network available

	return 0;
}

// GetTickCount() flows over to zero after 49 days.
// GetTickCount64() runs eternally.
// Why not use GetSystemTimeAsFileTime() ?
// Because the Systemtime jumps if someone adjusts the Windows clock.
// And when daylight saving time becomes winter time it will always jump by one hour.
// The tick counter runs continously and is not affected by any external influence.
LONGLONG cTCPSocket::GetTickCount64()
{
	DWORD u32_Tick = GetTickCount(); // UNSIGNED!!

	if (u32_Tick < mu32_Tick64Lo) 
		mu32_Tick64Hi ++; // Increment once every 49 days	

	mu32_Tick64Lo = u32_Tick;

	return 0x100000000 * mu32_Tick64Hi + u32_Tick;
}

// Pass a buffer of 200 characters!
// Can be used for debugging: TraceA("Events: %s", s8_Buf);
void cTCPSocket::FormatEvents(DWORD u32_Events, char* s8_Buf)
{
	s8_Buf[0] = 0;
 	if (u32_Events & FD_ACCEPT)                   strcat(s8_Buf, "FD_ACCEPT ");
	if (u32_Events & FD_CONNECT)                  strcat(s8_Buf, "FD_CONNECT ");
	if (u32_Events & FD_CLOSE)                    strcat(s8_Buf, "FD_CLOSE ");
	if (u32_Events & FD_TIMEOUT)                  strcat(s8_Buf, "FD_TIMEOUT ");
	if (u32_Events & FD_READ)                     strcat(s8_Buf, "FD_READ ");
	if (u32_Events & FD_WRITE)                    strcat(s8_Buf, "FD_WRITE ");
	if (u32_Events & FD_OOB)                      strcat(s8_Buf, "FD_OOB ");
	if (u32_Events & FD_QOS)                      strcat(s8_Buf, "FD_QOS ");
	if (u32_Events & FD_GROUP_QOS)                strcat(s8_Buf, "FD_GROUP_QOS ");
	if (u32_Events & FD_ROUTING_INTERFACE_CHANGE) strcat(s8_Buf, "FD_ROUTING_INTERFACE_CHANGE ");
	if (u32_Events & FD_ADDRESS_LIST_CHANGE)      strcat(s8_Buf, "FD_ADDRESS_LIST_CHANGE ");

	if (!u32_Events) strcpy(s8_Buf, "----");
}

// static
// Use this to write Debug output to DebugView from www.sysinternals.com
// TraceA("Closing Socket %X", h_Socket);
void cTCPSocket::TraceA(const char* s8_Format, ...)
{
#if _DEBUG && (TRACE_EVENTS || TRACE_LOCK)

	static DWORD u32_LastTick   = 0;
	static DWORD u32_LastThread = 0;

	DWORD u32_Tick   = GetTickCount();
	DWORD u32_Thread = GetCurrentThreadId();

	char* s8_Delim = "";
	if (u32_LastThread != u32_Thread)
	{
		s8_Delim = "+++++++++++++++++++++++++++++++++++++\r\n";
	}
	else if (u32_Tick - u32_LastTick > 100) 
	{
		s8_Delim = "- - - - - - - - - - - - - - - - - - -\r\n";
	}

	u32_LastTick   = u32_Tick;
	u32_LastThread = u32_Thread;

	const int BUF_SIZE = 5000;
	char s8_Buf[BUF_SIZE+1];
	
	sprintf(s8_Buf, "%s{%04d} ", s8_Delim, u32_Thread);
	DWORD u32_Len = strlen(s8_Buf);
	
	va_list  args;
	va_start(args, s8_Format);
	_vsnprintf(s8_Buf+u32_Len, BUF_SIZE-u32_Len, s8_Format, args);
	
	OutputDebugStringA(s8_Buf);
#endif
}

/***************************************************************************************
****************************************************************************************

	embedded class cList

	Description:
	Stores for all open sockets: their Handle, Wait Event, IP address, Write buffer for pending data

	CLIENT:
	- uses only Index=0 which holds the socket that is connect to the server.

	SERVER:
	- uses a socket at Index=0 which only waits for incomming connection requests. (always: mk_Data[0].u32_IP==0)
	- The socket at Index=0 is never connected to any client.
	- Each of the following sockets Index=1,2,3... may be connected to one client.

	Author: 
	Elmü (www.netcult.ch/elmue)

****************************************************************************************
****************************************************************************************/

cTCPSocket::cList::cList()
{
	mu32_Count = 0;
	me_State   = E_Disconnected;
}

cTCPSocket::cList::~cList()
{
	RemoveAll();
}

cTCPSocket::kData* cTCPSocket::cList::Add(SOCKET h_Socket, HANDLE h_Event)
{
	// Store max 63 sockets
	if (mu32_Count >= WSA_MAXIMUM_WAIT_EVENTS-1)
		return 0;

	memset(&mk_Data[mu32_Count], 0, sizeof(kData));

	mk_Data  [mu32_Count].h_Socket = h_Socket;
	// mh_Events[0] is used for the lock. It is not associated with a socket.
	mh_Events[mu32_Count+1] = h_Event;

	return &mk_Data[mu32_Count++];
}

void cTCPSocket::cList::RemoveAll()
{
	while (mu32_Count)
	{
		Remove(mu32_Count-1);
	}
}

// Remove sockets that have already received a FD_CLOSE
void cTCPSocket::cList::RemoveClosed()
{
	for (int i=(int)mu32_Count-1; i>=0; i--)
	{
		if (mk_Data[i].b_Closed) Remove(i);
	}
}

BOOL cTCPSocket::cList::Remove(DWORD u32_Index)
{
	if (u32_Index >= mu32_Count)
		return FALSE;

	shutdown   (mk_Data[u32_Index].h_Socket, SD_BOTH);
	closesocket(mk_Data[u32_Index].h_Socket);

	// mh_Events[0] is used for the lock. It is not associated with a socket.
	WSACloseEvent(mh_Events[u32_Index+1]);

	if (mk_Data[u32_Index].s8_SendBuf) delete mk_Data[u32_Index].s8_SendBuf;
	if (mk_Data[u32_Index].pi_RecvMem) delete mk_Data[u32_Index].pi_RecvMem;

	// Close the gap by copying the last socket to the deleted location
	mu32_Count--;
	mk_Data  [u32_Index]   = mk_Data  [mu32_Count];
	mh_Events[u32_Index+1] = mh_Events[mu32_Count+1];
	
	if (mu32_Count==0) 
		me_State = E_Disconnected;

	// remove E_Connected flag from the server (Socket[0] is never connected)
	if (mu32_Count==1 && (me_State & E_Server))
		me_State = E_Server;

	return TRUE;
}

// returns the index of the given socket in the socket list
// returns -1 if not found
int cTCPSocket::cList::FindSocket(SOCKET h_Socket)
{
	for (DWORD i=0; i<mu32_Count; i++)
	{
		if (mk_Data[i].h_Socket == h_Socket)
			return i;
	}
	return -1;
}

/***************************************************************************************
****************************************************************************************

	embedded struct kLock and class cLock
	
	Description:
	This class is used to mutually lock the access to mi_List if cSocket is running multithreaded.
	cLock must be created on the stack in a function requesting write access to mi_List:
	The function Loop()    locks when entering into the endless loop ProcessEvents()
	The function Request() locks when entering into Close() or SendTo(),
	The destructor of cLock releases the lock when these functions have exited.
	
	ATTENTION:
	A Mutex alone will not work here because ProcessEvents() is an endless loop,
	which re-enters before the thread context has been switched to the other thread!
	
	If multithreading is not in use this class does not block in neither function.
	
	Author: 
	Elmü (www.netcult.ch/elmue)

****************************************************************************************
****************************************************************************************/

cTCPSocket::kLock::kLock()
{
	h_LoopEvent = 0;
	h_ExitTimer = 0;
	h_Mutex     = 0;
}

cTCPSocket::kLock::~kLock()
{
	CloseHandle(h_LoopEvent);
	CloseHandle(h_ExitTimer);
	CloseHandle(h_Mutex);
}

DWORD cTCPSocket::kLock::Init()
{
	if (!h_LoopEvent) h_LoopEvent = CreateEvent(0, TRUE,  TRUE,  0); // manual-reset, default= run
	if (!h_LoopEvent) return GetLastError();
	
	if (!h_ExitTimer) h_ExitTimer = CreateWaitableTimer(0, FALSE, 0); // auto-reset,  default= block
	if (!h_ExitTimer) return GetLastError();

	if (!h_Mutex)     h_Mutex     = CreateMutex(0, FALSE, 0);
	if (!h_Mutex)     return GetLastError();

	return 0;
}

// -------------------------------------------------------------------------------------

cTCPSocket::cLock::cLock()
{
	mh_Mutex = 0;
}

// Blocks a Request in SendTo() and Close()
// If cSocket is used single-threaded, Request() will never block
DWORD cTCPSocket::cLock::Request(kLock* pk_Lock)
{
	DWORD u32_Error = pk_Lock->Init();
	if (u32_Error)
		return u32_Error;

	// FIRST: Block ProcessEvents() the next time BEFORE WaitForMultipleEvents() is reached
	if (!ResetEvent(pk_Lock->h_LoopEvent))
		return GetLastError();

	// SECOND: Escape from a blocking WaitForMultipleEvents()
	LARGE_INTEGER k_Interval;
	k_Interval.QuadPart = -1; // negative due time = set a relative time => fire timer in 100 nanoseconds

	#if TRACE_EVENTS || TRACE_LOCK
		cSocket::TraceA("Setting Timer: Lock Request Interval= 1 ns");
	#endif

	if (!SetWaitableTimer(pk_Lock->h_ExitTimer, &k_Interval, 0, 0, 0, FALSE))
		return GetLastError();

	#if TRACE_LOCK
		cSocket::TraceA("!!! cLock::Request WAIT");
	#endif
	
	// THIRD: Wait until ProcessEvents() has exited (only if multithreading)
	if (WaitForSingleObject(pk_Lock->h_Mutex, INFINITE) == WAIT_FAILED)
		return GetLastError();

	#if TRACE_LOCK
		cSocket::TraceA(">>> cLock::Request CONTINUE");
	#endif
	
	// Now we grabbed the Mutex -> allow ProcessEvents to continue
	if (!SetEvent(pk_Lock->h_LoopEvent))
		return GetLastError();

	// Store the mutex to be released in the destructor
	mh_Mutex = pk_Lock->h_Mutex;
	return 0;
}

// Blocks the endless loop ProcessEvents() after a Request() was made.
// If cSocket is used single-threaded, Loop() will never block
DWORD cTCPSocket::cLock::Loop(kLock* pk_Lock)
{
	DWORD u32_Error = pk_Lock->Init();
	if (u32_Error)
		return u32_Error;

	#if TRACE_LOCK
		cSocket::TraceA("!!! cLock::Loop WAIT");
	#endif

	// The following line normally does not block (Event always set). Only after a Request() it
	// will block to give Request() a chance to grab the Mutex before the endless loop re-enters
	if (WaitForSingleObject(pk_Lock->h_LoopEvent, INFINITE) == WAIT_FAILED)
		return GetLastError();

	// Wait until SendTo() or Close() have exited
	if (WaitForSingleObject(pk_Lock->h_Mutex, INFINITE) == WAIT_FAILED)
		return GetLastError();

	#if TRACE_LOCK
		cSocket::TraceA(">>> cLock::Loop CONTINUE");
	#endif

	mh_Mutex = pk_Lock->h_Mutex;
	return 0;
}

// Destructor is executed, when the calling function (SendTo(), Close(), ProcessEvents()) has exited
cTCPSocket::cLock::~cLock()
{
	#if TRACE_LOCK
		cSocket::TraceA("--- Release Mutex");
	#endif

	// Allow the other thread to continue its work
	ReleaseMutex(mh_Mutex);
}

/***************************************************************************************
****************************************************************************************

	embedded class cMemory
	
	Description:
	This tiny class allocates memory dynamically.
	The caller does not have to care about buffer sizes.
	This class is used to realize a FIFO memory for dynamic length datablocks.
	
	ATTENTION:
	With intention I do NOT use any functionalty of the STL library here.
	This would create a dependency to MSVCP70.DLL or MSVCP71.DLL or MSVCP80.DLL depending on the compiler.
	These DLLs are NOT available on every computer and must be installed with your application!
	
	Author: 
	Elmü (www.netcult.ch/elmue)

****************************************************************************************
****************************************************************************************/

cTCPSocket::cMemory::cMemory(DWORD u32_InitialSize)
{
	 ms8_Mem  = new char[u32_InitialSize];
	mu32_Size = u32_InitialSize;
	mu32_Len  = 0;
}
cTCPSocket::cMemory::~cMemory()
{
	delete ms8_Mem;
}
char* cTCPSocket::cMemory::GetBuffer()
{
	return ms8_Mem;
}
DWORD cTCPSocket::cMemory::GetLength()
{
	return mu32_Len;
}

// Append data to the end. If more memory is required, the current size is doubled.
void cTCPSocket::cMemory::Append(char* s8_Data, DWORD u32_Count)
{
	DWORD u32_NewLen = mu32_Len + u32_Count;
	if (u32_NewLen > mu32_Size)
	{
		mu32_Size = max(u32_NewLen, mu32_Size *2);

		char*  s8_NewMem = new char[mu32_Size];
		memcpy(s8_NewMem, ms8_Mem, mu32_Len);
		
		delete ms8_Mem;
		ms8_Mem = s8_NewMem;
	}
	memcpy(ms8_Mem+mu32_Len, s8_Data, u32_Count);
	mu32_Len += u32_Count;
}

// Deletes the first u32_Count Bytes from the buffer by shifting down the Bytes that follow 
void cTCPSocket::cMemory::DeleteLeft(DWORD u32_Count)
{
	u32_Count = min(u32_Count, mu32_Len);
	memmove(ms8_Mem, ms8_Mem+u32_Count, mu32_Len-u32_Count);
	mu32_Len -= u32_Count;
}

/***************************************************************************************
****************************************************************************************

	embedded template class cHash
	
	Description:
	This tiny class allows to pass a list of unlimited size from a function to it's caller.
	The caller does not have to care to free the memory after using the data.
	This avoids memory leaks if the programmer forgets to call delete.
	
	ATTENTION:
	With intention I do NOT use any functionalty of the STL library here.
	This would create a dependency to MSVCP70.DLL or MSVCP71.DLL or MSVCP80.DLL depending on the compiler.
	These DLLs are NOT available on every computer and must be installed with your application!
	
	Author: 
	Elmü (www.netcult.ch/elmue)

****************************************************************************************
****************************************************************************************/


//  Due to the way the C++ compiler works the template class must be defined in the header file

