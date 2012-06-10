
#pragma once


#pragma comment(lib, "ws2_32")
#pragma warning(disable: 4996) // _vsnwprintf is deprecated

// Enable Trace output in DebugView from www.sysinternals.com
#define TRACE_EVENTS  _DEBUG && FALSE  // Trace Socket Events and Request/Lock Timer
#define TRACE_LOCK    _DEBUG && FALSE  // Trace Lock Mutex and LoopEvent

// With this buffer cSocket reads data from Winsock
// This buffer should have a similar size as the internal Winsock buffer (which has 64 kB)
// There is no reason why you should modify this value! (except for testing)
#define READ_BUFFER_SIZE   64*1024

// With this size cMemory is initialized.
// If the value is too big you waste memory. (If 62 sockets are open you occupy at least 62 * MEMORY_INITIAL_SIZE Byte)
// If the value is too small there are multiple re-allocations necessary which are slow.
// This value depends on the size of the datablocks that you want to receive (e.g. when using length-prefixed mode)
// This value should be READ_BUFFER_SIZE or more.
#define MEMORY_INITIAL_SIZE  64*1024


// for older Visual Studio versions. (DWORD_PTR is required to compile correctly as 64 Bit)
#ifndef DWORD_PTR
#define DWORD_PTR DWORD
#endif

// This flag is used to notify the caller that the socket has been closed due to a timeout (idle for too long)
// This flag is always signaled in combination with FD_CLOSE
#define FD_TIMEOUT  (1 << 20)

class DLLIMPORT Security::Connections::Internet::cTCPSocket
	{
	public:
		enum eState
		{
			E_Disconnected = 0,
			E_Connected    = 1,
			E_Server       = 2,
			E_Client       = 4,
		};

		class DLLIMPORT cMemory
		{
		public:
			 cMemory(DWORD u32_InitialSize);
			~cMemory();
			char* GetBuffer();
			DWORD GetLength();
			void  Append(char* s8_Data, DWORD u32_Count);
			void  DeleteLeft(DWORD u32_Count);

		private:
			char*  ms8_Mem;
			DWORD mu32_Size;
			DWORD mu32_Len;
		};

		// Template classes must always be declared in the header file.
		// Example: tValue = DWORD, SOCKET, ULONGLONG,...
		template <class tKey, class tValue>
		class DLLIMPORT cHash
		{
		public:
			cHash(DWORD u32_InitialCount=10) 
				: mi_Keys(u32_InitialCount * sizeof(tKey)),
				  mi_Vals(u32_InitialCount * sizeof(tValue))
			{
			}
			void Append(tKey t_Key, tValue t_Value)
			{ 
				mi_Keys.Append((char*)&t_Key,   sizeof(tKey));
				mi_Vals.Append((char*)&t_Value, sizeof(tValue));
			}
			DWORD GetCount()
			{ 
				return mi_Keys.GetLength() / sizeof(tKey); 
			}
			void Clear()
			{
				mi_Keys.DeleteLeft(0xFFFFFFFF);
				mi_Vals.DeleteLeft(0xFFFFFFFF);
			}
			tKey GetKeyByIndex(DWORD u32_Index)
			{
				if (u32_Index >= GetCount()) return NULL;
				tKey* p_Key = (tKey*)mi_Keys.GetBuffer();
				return p_Key[u32_Index]; 
			}
			tValue GetValueByIndex(DWORD u32_Index)
			{
				if (u32_Index >= GetCount()) return NULL;
				tValue* p_Val = (tValue*)mi_Vals.GetBuffer();
				return p_Val[u32_Index]; 
			}
			tValue GetValueByKey(tKey t_Key)
			{
				tKey*   p_Key = (tKey*)   mi_Keys.GetBuffer();
				tValue* p_Val = (tValue*) mi_Vals.GetBuffer();
				for (DWORD i=0; i<GetCount(); i++)
				{
					if (p_Key[i] == t_Key) return p_Val[i]; 
				}
				return NULL;
			}

		private:
			cMemory mi_Keys;
			cMemory mi_Vals;
		};

	protected:
		struct kData
		{
			SOCKET      h_Socket;
			DWORD     u32_IP;
			char*      s8_SendBuf;
			DWORD     u32_SendLen;
			DWORD     u32_SendPos;
			LONGLONG  s64_IdleSince;
			BOOL        b_Closed;
			BOOL        b_Timeout;
			BOOL        b_Shutdown;
			cMemory*   pi_RecvMem;
		};

		class DLLIMPORT cList
		{
		public:
			 cList();
			~cList();
			void     RemoveAll();
			void     RemoveClosed();
			kData*   Add(SOCKET h_Sock, HANDLE h_Event);
			BOOL     Remove(DWORD u32_Index);
			int      FindSocket(SOCKET h_Socket);

			DWORD    mu32_Count;
			eState   me_State;

			// The first event is used for the lock. It is not associated with a socket.
			HANDLE  mh_Events[WSA_MAXIMUM_WAIT_EVENTS];
			kData   mk_Data  [WSA_MAXIMUM_WAIT_EVENTS-1];
		};

		struct DLLIMPORT kLock
		{
		public:
			 kLock();
			~kLock();
			DWORD  Init();

			HANDLE h_Mutex;
			HANDLE h_ExitTimer;  // set to escape from WSAWaitForMultipleEvents
			HANDLE h_LoopEvent;  // blocks the endless loop ProcessEvents()
		};

		class DLLIMPORT cLock
		{
		public:
			 cLock();
			~cLock();
			DWORD Request(kLock* pk_Lock);
			DWORD Loop   (kLock* pk_Lock);

		private:
			HANDLE mh_Mutex;
		};

	public:
		 cTCPSocket();
		~cTCPSocket();

		DWORD  Close();
		DWORD  GetSocketCount();
		DWORD  GetAllConnectedSockets(cHash<SOCKET,DWORD>* pi_SockList);
		DWORD  Listen   (DWORD u32_BindIP, USHORT u16_Port, DWORD u32_EventTimeout, DWORD u32_MaxIdleTime=0);
		DWORD  ConnectTo(DWORD u32_ServIP, USHORT u16_Port, DWORD u32_EventTimeout, DWORD u32_MaxIdleTime=0);
		DWORD  DisconnectClient(SOCKET h_Socket);
		DWORD  ProcessEvents(DWORD* pu32_Events, DWORD* pu32_IP, SOCKET* ph_Socket, cMemory** ppi_RecvMem, DWORD* pu32_Read, DWORD* pu32_Sent);
		DWORD  SendTo(SOCKET h_Socket, char* s8_SendBuf, DWORD u32_Len);
		DWORD  GetLocalIPs(cHash<DWORD,DWORD>* pi_IpList);
		eState GetState();
		void   FormatEvents(DWORD u32_Events, char* s8_Buf);

		static void TraceA(const char* s8_Format, ...);
		
	protected:
		DWORD    CreateSocket();
		DWORD    Initialize();
		DWORD    SendDataBlock(SOCKET h_Socket, char* s8_Buf, DWORD* pu32_Pos, DWORD u32_Len);
		DWORD    WSAWaitForMultipleEventsEx(DWORD u32_Count, DWORD* pu32_Index, WSAEVENT* ph_Events, DWORD u32_Timeout);
		DWORD    ProcessIdleSockets(char* s8_Caller);
		LONGLONG GetTickCount64();
		
		static int  WINAPI AcceptCondition(WSABUF* pk_CallerId, WSABUF* pk_CallerData, QOS* pk_SQOS, QOS* pk_GQOS, WSABUF* pk_CalleeId, WSABUF* pk_CalleeData, UINT* pu32_Group, DWORD_PTR p_Param);

		BOOL       mb_Initialized;
		DWORD    mu32_WaitIndex;
		cList      mi_List;
		kLock      mk_Lock;
		char*     ms8_ReadBuffer;
		LONGLONG ms64_MaxIdleTime;
		DWORD    mu32_EventTimeout; // UNSIGNED!!
		DWORD    mu32_Tick64Lo;     // UNSIGNED!!
		DWORD    mu32_Tick64Hi;
	};

