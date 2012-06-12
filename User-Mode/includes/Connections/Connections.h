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
  public:
  //Variables
  char* DeviceName;
  DWORD FileObject;
  PReadFunc ReadFunction;
  HANDLE DeviceHandle;
  HANDLE hThread;
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
