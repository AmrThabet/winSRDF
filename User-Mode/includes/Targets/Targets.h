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

#include "cThread.h"
#include "pe.h"
#include "elf.h"
#include <map>
#include "hPackets.h"
#include <regex>

//#include "tib.h"
#include "unzip.h"
using namespace Security::Elements::String;


//--------------------------------------//
//--          Files Namespace         --//
//--------------------------------------//

struct FILE_DATE_TIME
{
	DWORD Year;
	DWORD Month;
	DWORD Day;
	DWORD Hour;
	DWORD Min;
	DWORD Sec;
};

class DLLIMPORT Security::Targets::Files::cFile
{
	HANDLE        hFile;
    HANDLE        hMapping;
	BOOL		  IsFile;
	BOOL		  isFound;
public:
    DWORD        BaseAddress;
    DWORD        FileLength;
	DWORD		 Attributes;
	FILE_DATE_TIME CreatedTime;
	FILE_DATE_TIME ModifiedTime;
	FILE_DATE_TIME AccessedTime;
	char*		 Filename;
	cFile(char* szFilename);
	cFile(char* buffer,DWORD size);
	int OpenFile(char* szFilename);
	BOOL IsFound();
	~cFile();
	BOOL		IsReassembled;
};

//--------------------------------------------------------------
// PE Parser
//----------

/*export table */
struct EXPORTFUNCTION {
	char* funcName;
	WORD funcOrdinal;
	DWORD funcRVA;
};
struct EXPORTTABLE 
{
	DWORD nFunctions;
	DWORD nNames;
	DWORD Base;
	PDWORD pFunctions;
	PDWORD pNames;
	PWORD pNamesOrdinals;
	EXPORTFUNCTION *Functions;
};
/****       ****/
struct IMPORTTABLE_DLL;
struct IMPORTTABLE_API;

struct SECTION_STRUCT
{
	char* SectionName;
	DWORD VirtualAddress;
	DWORD VirtualSize;
	DWORD PointerToRawData;
	DWORD SizeOfRawData;
	DWORD Characterisics;
	DWORD RealAddr;
};
struct IMPORTTABLE
{
	DWORD nDLLs;
	IMPORTTABLE_DLL* DLL;
};
struct IMPORTTABLE_DLL
{
	char* DLLName;
	DWORD nAPIs;
	IMPORTTABLE_API* API;
};
struct IMPORTTABLE_API
{
	char* APIName;
	DWORD APIAddressPlace;
};
struct RELOCATION_ENTRIES
{
	DWORD Offset;
	char* Type;
};
struct RELOCATIONS
{
	DWORD VirtualAddress;
	unsigned int nEntries;
	RELOCATION_ENTRIES* Entries;
};

#define DATADIRECTORY_EXPORT		0x0001
#define DATADIRECTORY_IMPORT		0x0002
#define DATADIRECTORY_RESOURCE		0x0004
#define DATADIRECTORY_EXCEPTION		0x0008
#define DATADIRECTORY_CERTIFICATE	0x0010
#define DATADIRECTORY_RELOCATION	0x0020
#define DATADIRECTORY_DEBUG			0x0040
#define DATADIRECTORY_ARCHITECT		0x0080
#define DATADIRECTORY_MACHINE		0x0100
#define DATADIRECTORY_TLS			0x0200
#define DATADIRECTORY_CONF			0x0400
#define DATADIRECTORY_BOUNDIMPORT	0x0800
#define DATADIRECTORY_IAT			0x1000
#define DATADIRECTORY_DELAYIMPORT	0x2000
#define DATADIRECTORY_RUNTIME		0x4000
#define DATADIRECTORY_RESERVED		0x8000

class DLLIMPORT Security::Targets::Files::cPEFile : public Security::Targets::Files::cFile
{
private:

	//Functions:
	bool ParsePE();
	VOID initDataDirectory();
	VOID initSections();
	VOID initImportTable();
	void initExportTable();	//export table
	void initRelocations();
public:
	//Variables
	bool FileLoaded;
	image_header* PEHeader;
	DWORD Magic;
	DWORD Subsystem;
	DWORD Imagebase;
	DWORD SizeOfImage;
	DWORD Entrypoint;
	DWORD FileAlignment;
	DWORD SectionAlignment;
	WORD DataDirectories;
	unsigned long nSections;
	unsigned int nRelocations;
	SECTION_STRUCT* Section;
	IMPORTTABLE ImportTable;
	RELOCATIONS* Relocations;

	/* for exports */
	EXPORTTABLE ExportTable;

	//Functions
	cPEFile(char* szFilename);
	cPEFile(char* buffer,DWORD size);
	~cPEFile();
	static bool identify(cFile* File);
	DWORD RVAToOffset(DWORD RVA);
	DWORD OffsetToRVA(DWORD RawOffset);

};

//--------------------------------------------------------------
// ELF Parser
//----------

struct SECTIONS 
{
	char* Name;
	DWORD Address;
	DWORD Offset;
	DWORD Size;
};

struct SYMBOLS 
{
	char* Name;
	DWORD Address;
	DWORD Offset;
	//DWORD Size;
};

struct DYNAMICS
{
	DWORD Address;
	DWORD Offset;
	DWORD Value;
	DWORD Tag;
	char* Name;
};

struct IMPORTS
{
	//DWORD Address;
	//DWORD Offset;
	DWORD Value;
	char* Name;
};

class DLLIMPORT Security::Targets::Files::cELFFile : public Security::Targets::Files::cFile
{
private:

	//Functions:
	bool ParseELF();
	void initSections();
	void initDynSymbols();
	void initImports();
	void initDynamics();

	char* sStringTable;
	char* dStringTable;
	unsigned int DynSymArray;
	unsigned int DynArray;
	Elf32_Sym* SymbolsTable;
	Elf32_Dyn* DynamicTable;
	
public:
	//Variables
	bool FileLoaded;
	elf32_header* ExeHeader;
	elf32_program_header* PHeader;
	elf32_section_header* SHeader;

	unsigned int nSections;
	unsigned int nDynamics;
	unsigned int nImports;
	unsigned int nSymbols;
	SECTIONS* Sections;
	SYMBOLS* Symbols;
	DYNAMICS* Dynamics;
	IMPORTS* Imports;
	
	DWORD Magic;
	DWORD Subsystem;
	DWORD SizeOfImage;
	DWORD SizeOfHeader;
	DWORD SizeOfProgramHeader;
	DWORD Entrypoint;
	unsigned short int Type;

	//Functions
	cELFFile(char* szFilename);
	cELFFile(char* buffer,DWORD size);
	~cELFFile();
	static bool identify(cFile* File);

};

//--------------------------------------------------------------
// PDF Parser
//----------

struct object{
    int offset;
    vector<string> data;
    vector<string> streams;
};   

struct xref_item{
    string name;
    int start;
    int end;
    int offset;
    int revision_no;
    char marker;
};
    
struct xref
{
    string name;// = "xref";
    int start;
    int end;
    vector<xref_item> xref_table;
};
struct trailer
{
   vector<string> trailer_data;
};
class DLLIMPORT Security::Targets::Files::cPDFFile : public Security::Targets::Files::cFile
{
private:
   
	//xref_item xref_list;
	bool FileLoaded;

	//Functions:
	bool ParsePDF();
	bool get_version_pdf();
	bool get_objects_pdf();
	//bool get_object(int offset, vector<string> &v);
	bool get_object(int offset, object &o);
	DWORD getline(DWORD NewAddress, string& line);
	DWORD GetValue(char* Addr, string& Value);
	bool get_stream(DWORD& Addr, vector<string> &stream);
	bool get_xref_table();
	bool get_trailer_pdf();
	bool get_objects_from_xref();
public:

	string FileVersion;
    vector<object> pdf_objects;
    vector<string> objects; // should be deleted when the pdf_objects works perfectly
    xref xref_obj;
	trailer trailer_table;
	int stream_no;
	bool IsFound(){return FileLoaded;};
	cPDFFile(char* szFilename);
	cPDFFile(char* buffer,DWORD size);
	~cPDFFile();
	static bool identify(cFile* File);

};


//--------------------------------------//
//--          Process Class           --//
//--------------------------------------//


struct MODULE_INFO
{
	DWORD moduleImageBase;
	DWORD moduleSizeOfImage;
	cString* moduleName;
	cString* modulePath;
	cString* moduleMD5;
	DWORD	 nExportedAPIs;
	cHash*	 ImportedDLLs;
};

struct MEMORY_MAP
{
	DWORD Address;
	DWORD Size;
	DWORD Protection;
	DWORD AllocationBase;
};

struct THREAD_INFO
{
	DWORD ThreadId;
	HANDLE Handle;
	CONTEXT Context;
	DWORD TEB;
	DWORD StackBase;
	DWORD StackLimit;
	DWORD SEH;
};

class DLLIMPORT Security::Targets::Memory::MemoryRegion : public Security::Elements::XML::cSerializer
{
public:
	char* Buffer;
	DWORD Address;
	DWORD Size;
	DWORD AllocationBase;
	DWORD Protection;
	bool IsFound;
	cString Filename;
	MemoryRegion(char* buffer, DWORD size, DWORD allocationBase, DWORD protection, DWORD RealAddress,cString filename);
	MemoryRegion();
	~MemoryRegion();
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash& XMLParams);
};

class DLLIMPORT Security::Targets::Memory::MemoryDump : public Security::Elements::XML::cSerializer
{
	cProcess* Process;
	DWORD ImageBase;
	ULONG SizeOfImage;
	cString processName;
	cString processPath;
	cString processMD5;
	DWORD ParentID;
	DWORD ProcessId;
	cString CommandLine;
	DWORD nMemoryRegions;
	cList* modulesList;
	MemoryRegion** MemoryMap;
public:
	MemoryDump(cProcess* Process,bool DumpFullMemory);
	MemoryDump();
	~MemoryDump();
	virtual void SetSerialize(cXMLHash& XMLParams);
	virtual void GetSerialize(cXMLHash& XMLParams);
};


#define PROC_DUMP_ZEROIMPORTTABLE 0
#define PROC_DUMP_UNLOADIMPORTTABLE 1
class DLLIMPORT Security::Targets::Memory::cProcess
{
	void AnalyzeProcess();
	cString Unicode2Ansi(LPWSTR,int);
	BOOL GetMemoryMap();
	void EnumerateThread(THREAD_INFO* ti);
	cHash* ModuleImportedDlls(Security::Targets::Files::cPEFile* Module);
public:
	// parameters
	DWORD procHandle;
	__PEB  *ppeb;
	DWORD ImageBase;
	ULONG SizeOfImage;
	cString processName;
	cString processPath;
	cString processMD5;
	DWORD ParentID;
	DWORD ProcessId;
	cString CommandLine;
	cList modulesList;
	cList MemoryMap;
	bool isFound;
	cList* Threads;
	//methods
	cProcess(int processId);
	~cProcess();
	DWORD Read(DWORD startAddress,DWORD size);
	DWORD Allocate (DWORD preferedAddress,DWORD size);
	DWORD Write(DWORD startAddressToWrite ,DWORD buffer ,DWORD sizeToWrite);
	DWORD DllInject(cString DLLFilename);
	DWORD CreateThread(DWORD addressToFunction , DWORD addressToParameter);
	bool IsFound();
	void RefreshThreads();
	bool DumpProcess(cString Filename, DWORD Entrypoint, DWORD ImportUnloadingType); // Entrypoint == 0 means the same Entrypoint, ImportUnloadingType == PROC_DUMP_ZEROIMPORTTABLE or PROC_DUMP_UNLOADIMPORTTABLE
	DWORD UnloadImportTable(DWORD NewImagebase);
};



#define PACKET_NOERROR			0x0
#define PACKET_IP_CHECKSUM		0x1
#define PACKET_TCP_CHECKSUM		0x2
#define PACKET_UDP_CHECKSUM		0x3
#define PACKET_ICMP_CHECKSUM	0x4
#define PACKET_IP_TTL			0x5

#define CPACKET_OPTIONS_NONE	0x0000
#define CPACKET_OPTIONS_MALFORM_CHECK	0x0001

class DLLIMPORT Security::Targets::Packets::cPacket
{
	UINT sHeader;
	UINT eType;
	void ResetIs();
	USHORT GlobalChecksum(USHORT *buffer, UINT length);
	BOOL ProcessPacket(UINT network, UINT Options);
	Security::Targets::Files::cFile* File;

public:
	cPacket(string filename, time_t timestamp = NULL ,UINT network = LINKTYPE_ETHERNET, UINT Options = CPACKET_OPTIONS_NONE);
	cPacket(UCHAR* buffer, UINT size, time_t timestamp = NULL ,UINT network = LINKTYPE_ETHERNET, UINT Options = CPACKET_OPTIONS_NONE);
	~cPacket();

	BOOL FixIPChecksum();
	BOOL FixTCPChecksum();
	BOOL FixUDPChecksum();
	BOOL FixICMPChecksum();

	time_t Timestamp;

	DWORD BaseAddress;
	UINT Size;

	SLL_HEADER* SLLHeader;
	ETHER_HEADER*	EthernetHeader;
	IP_HEADER*		IPHeader;
	TCP_HEADER*	TCPHeader;
	ARP_HEADER*	ARPHeader;
	UDP_HEADER*	UDPHeader;
	ICMP_HEADER*	ICMPHeader;
	IGMP_HEADER*	IGMPHeader;

	UCHAR* RawPacket;
	UINT PacketSize;

	BOOL isParsed;
	WORD PacketError;

	BOOL isTCPPacket;
	BOOL isUDPPacket;
	BOOL isICMPPacket;
	BOOL isIGMPPacket;
	BOOL isARPPacket;
	BOOL isIPPacket;
	BOOL isMalformed;
	BOOL isIPv6Packet;
	BOOL isUnknownPacket;

	BOOL hasSLLHeader;
	BOOL hasEtherHeader;

	UCHAR* TCPData;
	UINT TCPDataSize;
	UCHAR* TCPOptions;
	UINT TCPOptionsSize;

	UCHAR* UDPData;
	UINT UDPDataSize;

	UCHAR* ICMPData;
	UINT ICMPDataSize;

	void CheckIfMalformed();
};

#define CONN_NETWORK_UNKNOWN		0
#define CONN_NETWORK_ETHERNET		1
#define CONN_NETWORK_SSL			2

#define CONN_TRANSPORT_UNKNOWN		0
#define CONN_TRANSPORT_TCP			1
#define CONN_TRANSPORT_UDP			2
#define CONN_TRANSPORT_ICMP			3
#define CONN_TRANSPORT_IGMP			4

#define CONN_ADDRESSING_UNKOWN		0
#define CONN_ADDRESSING_ARP			1
#define CONN_ADDRESSING_IP			2

#define CONN_APPLICATION_UNKOWN		0
#define CONN_APPLICATION_DNS		1
#define CONN_APPLICATION_HTTP		2


class DLLIMPORT Security::Targets::Packets::cConnection
{
protected:
	virtual BOOL AnalyzePackets();
	virtual BOOL CheckPacket(cPacket* Packet);
public:
	cConnection();
	virtual ~cConnection();

	cPacket**	Packets;
	UINT		nPackets;

	virtual BOOL	AddPacket(cPacket* Packet);
	BOOL	ClearActivePackets(UINT NumberToBeKeeped);

	UCHAR	ClientMAC[ETHER_ADDR_LEN];
	UCHAR	ServerMAC[ETHER_ADDR_LEN];
	USHORT	Protocol;

	DWORD NetworkType;
	DWORD TransportType;
	DWORD AddressingType;
	DWORD ApplicationType;

	BOOL isIPConnection;
};

class DLLIMPORT Security::Targets::Packets::cConStream : public Security::Targets::Packets::cConnection
{
public:
	cConStream();
	virtual ~cConStream();

	UINT	ClientIP;
	UINT	ServerIP; 

	BOOL isTCPConnection;
	BOOL isUDPConnection;

	BOOL AddPacket(cPacket* Packet);
	static BOOL Identify(cPacket* Packet);
};

class DLLIMPORT Security::Targets::Packets::cARPStream : public Security::Targets::Packets::cConnection
{
	void AnalyzeProtocol();
public:
	cARPStream();
	virtual ~cARPStream();

	BOOL AddPacket(cPacket* Packet);
	static BOOL Identify(cPacket* Packet);

	UCHAR RequesterMAC[ETHER_ADDR_LEN];
	UINT RequesterIP;

	UCHAR RequestedMAC[ETHER_ADDR_LEN];
	BOOL GotReply;
	UINT RequestedMACIP;

	UCHAR ReplierMAC[ETHER_ADDR_LEN];
};

class DLLIMPORT Security::Targets::Packets::cUDPStream : public Security::Targets::Packets::cConStream
{
public:
	cUDPStream(void);
	virtual ~cUDPStream(void);

	USHORT ClientPort;
	USHORT ServerPort;

	BOOL AddPacket(cPacket* Packet);
	static BOOL Identify(cPacket* Packet);
};


class DLLIMPORT Security::Targets::Packets::cDNSStream : public Security::Targets::Packets::cUDPStream
{
private:
	DNS_HEADER* DNSHeader;
	QUERY* DNSQuery;
	RES_RECORD* QueryResponse;
	UCHAR* ResponseBase;

	UINT NameSize;
	UINT current,offset, step, i;
	void AnalyzeProtocol();
public:
	static BOOL Identify(cPacket* Packet);

	UCHAR* RequestedDomain;

	UINT* ResolvedIPs;
	UINT nResolvedIPs;

	UINT Requester;
	BOOL DomainIsFound;

	cDNSStream();
	virtual ~cDNSStream();

	BOOL AddPacket(cPacket* Packet);
};

class DLLIMPORT Security::Targets::Packets::cTCPStream : public Security::Targets::Packets::cConStream
{
	virtual BOOL CheckPacket(cPacket* Packet);
	virtual void AnalyzeProtocol();

public:
	cTCPStream();
	virtual ~cTCPStream();

	USHORT ClientPort;
	USHORT ServerPort;

	BOOL AddPacket(cPacket* Packet);
	static BOOL Identify(cPacket* Packet);
};


struct REQUEST
{
	UCHAR*	RequestType;
	cString*	Address;
	cHash*	Arguments;
	UINT	ReplyNumber;
};

class DLLIMPORT Security::Targets::Packets::cHTTPStream : public Security::Targets::Packets::cTCPStream
{
	static BOOL CheckType(UCHAR* buffer);
	void AnalyzeProtocol();
	BOOL CheckPacket(cPacket* Packet);	

	CHAR* RegxData;	
	UINT RegxDataSize;
	cmatch RegxResult;

	cString* Cookie;
	CHAR* ArgumentBuffer;
	char* main;
	char* buffer; 
	UINT pos;
	UINT content_length;

	cmatch TmpRegxResult;
	UINT TmpContentLength;
	UINT TmpHTTPBodySize;

	Security::Targets::Files::cFile* ExtFile;
	UINT length, i;

	cTCPReassembler* Reassembler;
	void ExtractFile(cPacket* Packet);
public:



	static BOOL Identify(cPacket* Packet);
	static UCHAR* GetHttpHeader(cPacket* Packet, UINT *EndPos);
	BOOL NeedsReassembly(cPacket* Packet, UINT* ContentLength);

	cHTTPStream();
	virtual ~cHTTPStream();

	cString** Cookies;
	UINT nCookies;

	cString* UserAgent;
	cString* Referer;
	cString* ServerType;

	Security::Targets::Files::cFile** Files;
	UINT nFiles;

	REQUEST* Requests;
	UINT nRequests;
};

class DLLIMPORT Security::Targets::Packets::cICMPStream : public Security::Targets::Packets::cConnection
{
	void AnalyzeProtocol();
public:
	cICMPStream();
	virtual ~cICMPStream();

	BOOL AddPacket(cPacket* Packet);
	static BOOL Identify(cPacket* Packet);

	UINT	ClientIP;
	UINT	ServerIP; 

	UINT PingRequester ;
	UINT PingReceiver;

	UINT nPingRequests, nPingResponses;

	UCHAR* PingReceivedData;
	UINT PingReceivedDataSize;
	UCHAR* PingSentData;
	UINT PingSentDataSize;
};

class DLLIMPORT Security::Targets::Packets::cTraffic
{
	cConnection* TmpConnection;
public:
	UINT nConnections;
	cConnection** Connections;

	BOOL AddPacket(cPacket* Packet, time_t TimeStamp);

	cTraffic();
	~cTraffic();
};

#ifdef USE_WINPCAP

#include <pcap.h>
struct NETWORK_ADAPTERS_SEND
{
	CHAR Name[200];
	CHAR ID[200];
};

class DLLIMPORT Security::Targets::Packets::cWinpcapSend
{
	#define LINE_LEN 16
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	CHAR errbuf[PCAP_ERRBUF_SIZE];

	BOOL InitializeAdapters();

public:
	BOOL isReady;

	NETWORK_ADAPTERS_SEND *Adapters;
	UINT nAdapters;

	BOOL SendPacket(UINT AdapterIndex, cPacket* Packet);

	cWinpcapSend();
	~cWinpcapSend();
};


struct NETWORK_ADAPTERS_CAPTURE
{
	CHAR Name[200];
	CHAR ID[200];
};

class DLLIMPORT Security::Targets::Packets::cWinpcapCapture
{

	VOID AnalyzeTraffic();

#define LINE_LEN 16
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	int res;
	struct pcap_pkthdr * PacketHeader;
	const u_char * PacketData;
	CHAR errbuf[PCAP_ERRBUF_SIZE];

	BOOL InitializeAdapters();
public:
	BOOL isReady;
	BOOL CapturePackets(UINT AdapterIndex, UINT MaxNumOfPackets, const CHAR* Filter = NULL);

	NETWORK_ADAPTERS_CAPTURE *Adapters;
	UINT nAdapters;

	UINT nCapturedPackets;

	cTraffic Traffic;

	cWinpcapCapture();
	~cWinpcapCapture();
};

#endif

#define GENERATE_TCP		1
#define GENERATE_UDP		2
#define GENERATE_ARP		3
#define GENERATE_ICMP		4

#define TCP_ACK				1
#define TCP_SYN				2
#define TCP_FIN				4
#define TCP_RST				8
#define TCP_PSH				16
#define TCP_URG				32

class DLLIMPORT Security::Targets::Packets::cPacketGen
{
	cPacket* Packet;

	UCHAR src_mac_hex[6], dest_mac_hex[6];
	UINT src_ip_hex, dest_ip_hex;
	UCHAR data_offset;
	USHORT total_length;
	UCHAR PacketType;

public:
	cPacketGen(UINT type);
	~cPacketGen();

	UINT GeneratedPacketSize;
	UCHAR* GeneratedPacket;

	UINT IPToLong(const CHAR ip[]);

	BOOL SetMACAddress(string src_mac, string dest_mac);
	BOOL SetIPAddress(string src_ip, string dest_ip);
	BOOL SetPorts(USHORT src_port, USHORT dest_port);

	BOOL CustomizeTCP(UCHAR* tcp_options, UINT tcp_options_size, UCHAR* tcp_data, UINT tcp_data_size, USHORT tcp_flags);
	BOOL CustomizeUDP(UCHAR* udp_data, UINT udp_data_size);
	BOOL CustomizeICMP(UCHAR icmp_type, UCHAR icmp_code, UCHAR* icmp_data, UINT icmp_data_size);
};










#define CPCAP_OPTIONS_NONE				0x0000
#define CPCAP_OPTIONS_MALFORM_CHECK		0x0001

struct FOLLOW_STREAM
{
	UCHAR	ether_dhost[ETHER_ADDR_LEN];
	UCHAR	ether_shost[ETHER_ADDR_LEN];
	UINT	ip_srcaddr;
	UINT	ip_destaddr;
	UCHAR	ip_protocol;
	USHORT	source_port;
	USHORT	dest_port;
};

class DLLIMPORT Security::Targets::Files::cPcapFile : public Security::Targets::Files::cFile
{
	PCAP_GENERAL_HEADER* PCAP_General_Header;
	PCAP_PACKET_HEADER* PCAP_Packet_Header;

	cPacket* Packet;

	BOOL ProcessPCAP(UINT Options);
	void GetStreams();
	
	UINT PSize;
	DWORD PBaseAddress;

public:

	UINT nPackets;

	BOOL FileLoaded;

	void DetectMalformedPackets();

	cTraffic *Traffic;
	
	cPcapFile(char* szFilename, UINT Options = CPCAP_OPTIONS_NONE);
	~cPcapFile();
};


class DLLIMPORT Security::Targets::Packets::cTCPReassembler
{
	struct DATASTREAM
	{
		UCHAR* Pointer;
		UINT Size;
	}; 

	map<UINT, DATASTREAM*>::iterator DataStreamIterator;
	map<UINT, DATASTREAM*> DataStream;
	UCHAR* Stream;
	UINT PositionPointer;
	DATASTREAM* DataStreamContainer;

public:

	BOOL AddPacket(cPacket* Packet);
	BOOL isReassembled;
	BOOL BelongsToStream(cPacket* Packet);

	UCHAR* GetReassembledStream();

	cTCPReassembler(cPacket* Packet, UINT TotalLength, UINT BodySize);
	~cTCPReassembler();

	cPacket* RefPacket;
	UINT TotalSize, CurrentSize;

	void Empty();
	static BOOL Identify(cPacket* Packet, UINT AssumendDataSize);
};



//
//
// cAndroidFile CLASS
//
//

struct DEX_HEADER 
{
    UCHAR	magic[8];       /* includes version number */
    UINT	checksum;		/* adler32 checksum */
    UCHAR	signature[20];	/* SHA-1 hash */
    UINT	fileSize;       /* length of entire file */
    UINT	headerSize;     /* offset to start of next section */
    UINT	endianTag;
    UINT	linkSize;
    UINT	linkOff;
    UINT	mapOff;
    UINT	stringIdsSize;
    UINT	stringIdsOff;
    UINT	typeIdsSize;
    UINT	typeIdsOff;
    UINT	protoIdsSize;
    UINT	protoIdsOff;
    UINT	fieldIdsSize;
    UINT	fieldIdsOff;
    UINT	methodIdsSize;
    UINT	methodIdsOff;
    UINT	classDefsSize;
    UINT	classDefsOff;
    UINT	dataSize;
    UINT	dataOff;
};

struct DEX_OPT_HEADER 
{
    UCHAR	magic[8];           /* includes version number */

    UINT	dexOffset;          /* file offset of DEX header */
    UINT	dexLength;
    UINT	depsOffset;         /* offset of optimized DEX dependency table */
    UINT	depsLength;
    UINT	optOffset;          /* file offset of optimized data tables */
    UINT	optLength;

    UINT	flags;              /* some info flags */
    UINT	checksum;           /* adler32 checksum covering deps/opt */

    /* pad for 64-bit alignment if necessary */
};

struct DEX_FIELD_ID
{
    USHORT	ClassIndex;           /* index into typeIds list for defining class */
    USHORT	TypeIdex;            /* index into typeIds for field type */
    UINT	StringIndex;            /* index into stringIds for field name */
};

struct DEX_METHOD_ID
{
    USHORT  ClassIndex;           /* index into typeIds list for defining class */
    USHORT  PrototypeIndex;           /* index into protoIds for method prototype */
    UINT	StringIndex;            /* index into stringIds for method name */
};

struct DEX_PROTO_ID
{
    UINT	StringIndex;          /* index into stringIds for shorty descriptor */
    UINT	returnTypeIdx;      /* index into typeIds list for return type */
    UINT	parametersOff;      /* file offset to type_list for parameter types */
};

struct DEX_CLASS_DATA_HEADER 
{
    UINT staticFieldsSize;
    UINT instanceFieldsSize;
    UINT directMethodsSize;
    UINT virtualMethodsSize;
};

struct DEX_FIELD
{
    UINT fieldIdx;    /* index to a field_id_item */
    UINT accessFlags;
};

struct DEX_METHOD 
{
    UINT methodIdx;    /* index to a method_id_item */
    UINT accessFlags;
    UINT codeOff;      /* file offset to a code_item */
};

struct DEX_CLASS_DATA 
{
	DEX_CLASS_DATA_HEADER header;
	DEX_FIELD*          staticFields;
    DEX_FIELD*          instanceFields;
    DEX_METHOD*         directMethods;
    DEX_METHOD*         virtualMethods;
};

struct DEX_CLASS_DEF 
{
    UINT	classIdx;           /* index into typeIds for this class */
    UINT	accessFlags;
    UINT	superclassIdx;      /* index into typeIds for superclass */
    UINT	interfacesOff;      /* file offset to DexTypeList */
    UINT	sourceFileIdx;      /* index into stringIds for source file name */
    UINT	annotationsOff;     /* file offset to annotations_directory_item */
    UINT	classDataOff;       /* file offset to class_data_item */
    UINT	staticValuesOff;    /* file offset to DexEncodedArray */
};

struct DEX_TYPE_ITEM	{ USHORT	typeIdx; };
struct DEX_LINK			{ USHORT	bleargh; };
struct DEX_STRING_ID	{ UINT		stringDataOff; };
struct DEX_TYPE_ID		{ UINT		StringIndex; };

struct DEX_CLASS_LOOKUP
{
    INT     size;                       // total size, including "size"
    INT     numEntries;                 // size of table[]; always power of 2
    struct {
        UINT	classDescriptorHash;    // class descriptor hash code
        INT     classDescriptorOffset;  // in bytes, from start of DEX
        INT     classDefOffset;         // in bytes, from start of DEX
    } table[1];
};

struct DEX_STRING_ITEM
{
	UINT	StringSize;
	UCHAR*	Data;
};

struct DEX_FILE {
	//const DEX_OPT_HEADER* DexOptHeader;

	const DEX_HEADER*		DexHeader;
	const DEX_STRING_ID*	DexStringIds;
    const DEX_TYPE_ID*		DexTypeIds;
	const DEX_FIELD_ID*		DexFieldIds;
	const DEX_METHOD_ID*	DexMethodIds;
	const DEX_PROTO_ID*		DexProtoIds;
	const DEX_CLASS_DEF*	DexClassDefs;
	const DEX_LINK*			DexLinkData;

    const DEX_CLASS_LOOKUP* DexClassLookup;
    const void*				RegisterMapPool;
    const UCHAR*			baseAddr;
    INT						overhead;
};

struct DEX_CODE 
{
    USHORT  registersSize;
    USHORT  insSize;
    USHORT  outsSize;
    USHORT  triesSize;
    UINT	debugInfoOff;       /* file offset to debug info stream */
    UINT	insnsSize;          /* size of the insns array, in u2 units */
    USHORT  insns[1];
    /* followed by optional u2 padding */
    /* followed by try_item[triesSize] */
    /* followed by uleb128 handlersSize */
    /* followed by catch_handler_item[handlersSize] */
};

#define DEX_MAGIC				"dex\n"
#define DEX_MAGIC_VERS			"036\0"
#define DEX_MAGIC_VERS_API_13	"035\0"
#define DEX_OPT_MAGIC			"dey\n"
#define DEX_OPT_MAGIC_VERS		"036\0"
#define DEX_DEP_MAGIC			"deps"

enum {
    ACC_PUBLIC       = 0x00000001,       // class, field, method, ic
    ACC_PRIVATE      = 0x00000002,       // field, method, ic
    ACC_PROTECTED    = 0x00000004,       // field, method, ic
    ACC_STATIC       = 0x00000008,       // field, method, ic
    ACC_FINAL        = 0x00000010,       // class, field, method, ic
    ACC_SYNCHRONIZED = 0x00000020,       // method (only allowed on natives)
    ACC_SUPER        = 0x00000020,       // class (not used in Dalvik)
    ACC_VOLATILE     = 0x00000040,       // field
    ACC_BRIDGE       = 0x00000040,       // method (1.5)
    ACC_TRANSIENT    = 0x00000080,       // field
    ACC_VARARGS      = 0x00000080,       // method (1.5)
    ACC_NATIVE       = 0x00000100,       // method
    ACC_INTERFACE    = 0x00000200,       // class, ic
    ACC_ABSTRACT     = 0x00000400,       // class, method, ic
    ACC_STRICT       = 0x00000800,       // method
    ACC_SYNTHETIC    = 0x00001000,       // field, method, ic
    ACC_ANNOTATION   = 0x00002000,       // class, ic (1.5)
    ACC_ENUM         = 0x00004000,       // class, field, ic (1.5)
    ACC_CONSTRUCTOR  = 0x00010000,       // method (Dalvik only)
    ACC_DECLARED_SYNCHRONIZED =
                       0x00020000,       // method (Dalvik only)
    ACC_CLASS_MASK =
        (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT
                | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),
    ACC_INNER_CLASS_MASK =
        (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),
    ACC_FIELD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),
    ACC_METHOD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
                | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
                | ACC_DECLARED_SYNCHRONIZED),
};

struct DEX_CLASS_STRUCTURE
{
	UCHAR*	Descriptor;
	UINT	AccessFlags;
	UCHAR*	SuperClass;
	UCHAR*	SourceFile;

	struct CLASS_DATA
	{
		UINT StaticFieldsSize;
		UINT InstanceFieldsSize;
		UINT DirectMethodsSize;
		UINT VirtualMethodsSize;

		struct CLASS_FIELD 
		{
			UCHAR* Name;
			UINT AccessFlags;
			UCHAR* Type;
		}	*StaticFields, 
			*InstanceFields;

		struct CLASS_METHOD 
		{
			UCHAR* Name;
			UINT AccessFlags;
			UCHAR* Type;
			UCHAR* ProtoType;

			struct CLASS_CODE
			{
				UINT t;
			}	*CodeArea;

		}	*DirectMethods, 
			*VirtualMethods;

	}*	ClassData;
};


class DLLIMPORT Security::Targets::Files::cAndroidFile : public Security::Targets::Files:: cFile
{

	HZIP	ZipHandler;

	INT		ReadUnsignedLeb128(const UCHAR** pStream);
	UINT	ULEB128toUINT(UCHAR *data);
	UCHAR*	ULEB128toUCHAR(UCHAR *data, UINT *v);

	long	Decompress();
	BOOL	ProcessApk();
	BOOL	ParseDex();
	BOOL	ValidChecksum();
	void	GetCodeArea(DEX_CLASS_STRUCTURE::CLASS_DATA::CLASS_METHOD::CLASS_CODE *CodeArea, UINT Offset);

	DEX_CODE* DexCode;

public:
	cAndroidFile(CHAR* ApkFilename);
	~cAndroidFile();

	CHAR*	ApkFilename;
	BOOL	isReady;

	CHAR*	DexBuffer;
	long	DexBufferSize;

	UCHAR		DexVersion[4];
	UINT		nStringIDs,
				nFieldIDs,
				nTypeIDs,
				nMethodIDs,
				nPrototypeIDs,
				nClassDefinitions,
				
				nStringItems;

	DEX_HEADER*		DexHeader;
	DEX_STRING_ID*	DexStringIds;
    DEX_TYPE_ID*	DexTypeIds;
	DEX_FIELD_ID*	DexFieldIds;
	DEX_METHOD_ID*	DexMethodIds;
	DEX_PROTO_ID*	DexProtoIds;
	DEX_CLASS_DEF*	DexClassDefs;
	DEX_LINK*		DexLinkData;
	DEX_CLASS_DATA*	DexClassData;

	DEX_STRING_ITEM*		StringItems;

	UINT nClasses;
	DEX_CLASS_STRUCTURE* DexClasses;

	UCHAR** ResourceFiles;
	UINT	nResourceFiles;

	cFile**	DecompressResourceFiles(/*INT Index = -1*/);
};

