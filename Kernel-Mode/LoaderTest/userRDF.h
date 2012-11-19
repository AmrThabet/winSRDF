
#define MAX_DEVICES 64
#define DWORD unsigned long

#define IOCTL_FASTMSG           0x22E004
#define IOCTL_READREQUEST       0x22E008
#define IOCTL_WRITEDATA         0x22E00C


namespace RDF
{
 struct CommChannel
 {
    char msgcode;
    DWORD status;
    DWORD size;
    char  data;       //expandable buffer    
 };
 
 typedef void ReadFunc(char msgcode,DWORD status,DWORD size,char* data);
 typedef ReadFunc *PReadFunc;
 
 class cDevice
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
      int Write(DWORD msgcode,DWORD status,char* data,DWORD size);
      int SendFastMsg(char msgcode,DWORD status,char* data,DWORD size,DWORD& return_status,char* Output,DWORD MaxOutputSize);
      
 };
 void _cdecl ReadThread(cDevice* device);             
 class cDriver
 {     
       public:
       //Variables
       cDevice* UserComm[MAX_DEVICES];
       char* ServiceName;
       char* Filename;
       
       //Function
       cDriver(char* servicename,char* filename);
       int LoadDriver();
       int UnloadDriver();
       
 };
          
};
