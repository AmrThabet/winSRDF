/*
 *
 *  Copyright (C) 2013  Anwar Mohamed <anwarelmakrahy[at]gmail.com>
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
 *  along with this program; if not, write to Anwar Mohamed
 *  anwarelmakrahy[at]gmail.com
 *
 */

#include "stdafx.h"
#include "SRDF.h"
#include <iostream>
#include <intrin.h>
#include <algorithm>
#include <ctime>


#pragma comment(lib, "ws2_32.lib")
using namespace std;
using namespace Security::Targets::Packets;
using namespace Security::Targets::Files;

cPacket::cPacket(string filename, time_t timestamp, UINT network, UINT Options)
{
	BaseAddress = 0;
	Size = 0;
	File = new cFile((char*)filename.c_str());
	if (File->FileLength == 0) return;
	BaseAddress = File->BaseAddress;
	Size = File->FileLength;
	Timestamp = timestamp;
	RawPacket = (UCHAR*)BaseAddress;
	isParsed = ProcessPacket(network, Options);
	return;
};

cPacket::cPacket(UCHAR* buffer, UINT size, time_t timestamp, UINT network, UINT Options)
{
	BaseAddress = 0;
	Size = 0;
	BaseAddress = (DWORD)buffer;
	Size = size;
	Timestamp = timestamp;
	RawPacket = buffer;
	File = NULL;
	isParsed = ProcessPacket(network, Options);
	return;
};

BOOL cPacket::ProcessPacket(UINT network, UINT Options)
{
	ResetIs();
	if (BaseAddress == 0 || Size == 0) return false;

	PacketSize = Size;

	switch(network)
	{
	case LINKTYPE_LINUX_SLL:
		SLLHeader = (SLL_HEADER*)BaseAddress;
		sHeader = sizeof(SLL_HEADER);
		eType = ntohs(SLLHeader->ProtocolType);
		hasSLLHeader = TRUE;
		break;
	case LINKTYPE_ETHERNET:
		EthernetHeader = (ETHER_HEADER*)BaseAddress;
		sHeader = sizeof(ETHER_HEADER);
		eType = ntohs(EthernetHeader->ProtocolType);
		hasEtherHeader = TRUE;
		break;
	default:
		return FALSE;
	}

	/* check for sll or ethernet*/
	if (hasEtherHeader || hasSLLHeader)
	{
		/* packet ether type */
		if (eType == ETHERTYPE_IP)
		{
			isIPPacket = true;
			IPHeader = (IP_HEADER*)(BaseAddress + sHeader);

			if ((USHORT)(IPHeader->Protocol) == TCP_PACKET)
			{
				isTCPPacket = true;
				TCPHeader = (TCP_HEADER*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4));
			
				TCPDataSize =  Size - sHeader - (IPHeader->HeaderLength*4) - (TCPHeader->DataOffset*4);
				TCPOptionsSize = (TCPHeader->DataOffset*4) - sizeof(TCP_HEADER);

				if (TCPOptionsSize != 0)
					TCPOptions = (UCHAR*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4) + 
						(TCPHeader->DataOffset*4) - TCPOptionsSize);

				if (TCPDataSize != 0)
					TCPData= (UCHAR*)(BaseAddress) + sHeader + (IPHeader->HeaderLength*4) + 
						(TCPHeader->DataOffset*4);
			}
			else if ((USHORT)(IPHeader->Protocol) == UDP_PACKET)
			{
				isUDPPacket = true;
				UDPHeader = (UDP_HEADER*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4));

				UDPDataSize = ntohs(UDPHeader->DatagramLength) - sizeof(UDP_HEADER);
				UDPData = (UCHAR*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4) + sizeof(UDP_HEADER));

			}
			else if ((USHORT)(IPHeader->Protocol) == ICMP_PACKET)
			{
				isICMPPacket = true;
				ICMPHeader = (ICMP_HEADER*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4));

				ICMPDataSize = Size - sHeader - (IPHeader->HeaderLength*4) - sizeof(ICMP_HEADER);
				ICMPData = (UCHAR*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4) + sizeof(ICMP_HEADER));

			}
			else if ((USHORT)(IPHeader->Protocol) == IGMP_PACKET)
			{
				isIGMPPacket = true;
				IGMPHeader = (IGMP_HEADER*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4));
			}
		}
		else if (eType == ETHERTYPE_ARP)
		{
			isARPPacket = true;
			ARPHeader = (ARP_HEADER*)(BaseAddress + sHeader);
		}
		else if (eType == ETHERTYPE_IPV6)
		{

		}
		else
		{
			isUnknownPacket = TRUE;
			return FALSE;
		}

		if (Options & CPACKET_OPTIONS_MALFORM_CHECK) CheckIfMalformed();
		return true;
	}
	else return FALSE;
};

void cPacket::CheckIfMalformed()
{
	isMalformed = false;
	PacketError = PACKET_NOERROR;
	if (isIPPacket)
	{
		IP_HEADER *ipheader = new IP_HEADER;
		memcpy(ipheader,IPHeader,sizeof(IP_HEADER));
		ipheader->Checksum =0x0000;

		if(GlobalChecksum((USHORT*)ipheader,sizeof(IP_HEADER)) != IPHeader->Checksum)
		{
			isMalformed = true;
			PacketError = PACKET_IP_CHECKSUM;
			delete ipheader;
		}	
		else if (isTCPPacket)
		{
			TCP_HEADER *tcpheader = new TCP_HEADER;
			memcpy(tcpheader,TCPHeader,sizeof(TCP_HEADER));
			tcpheader->Checksum = 0x0000;

			PSEUDO_HEADER *psheader = new PSEUDO_HEADER;
			memcpy(&psheader->daddr, &IPHeader->DestinationAddress, sizeof(UINT));
			memcpy(&psheader->saddr, &IPHeader->SourceAddress, sizeof(UINT));
			psheader->protocol = IPHeader->Protocol;
			psheader->length = htons((USHORT)(sizeof(TCP_HEADER) + TCPOptionsSize + TCPDataSize));
			psheader->zero = 0;

			UINT packet_size = sizeof(TCP_HEADER) + TCPOptionsSize + TCPDataSize + sizeof(PSEUDO_HEADER);
			packet_size = packet_size + ((packet_size%2)*2);
			UCHAR *tcppacket = (UCHAR*)malloc(packet_size);

			memset(tcppacket,0, packet_size);
			memcpy(&tcppacket[0], psheader, sizeof(PSEUDO_HEADER));
			memcpy(&tcppacket[sizeof(PSEUDO_HEADER)], tcpheader,sizeof(TCP_HEADER));
			memcpy(&tcppacket[sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER)],TCPOptions,TCPOptionsSize);
			memcpy(&tcppacket[sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER) + TCPOptionsSize],TCPData, TCPDataSize);

			if (GlobalChecksum((USHORT*)tcppacket,packet_size) != TCPHeader->Checksum)
			{
				isMalformed = true;
				PacketError = PACKET_TCP_CHECKSUM;
			}

			delete ipheader;
			delete tcpheader;
			delete psheader;
			free(tcppacket);
		}
		else if (isUDPPacket)
		{
			UDP_HEADER *udpheader = new UDP_HEADER;
			memcpy(udpheader,UDPHeader,sizeof(UDP_HEADER));
			udpheader->Checksum = 0;

			PSEUDO_HEADER *psheader = new PSEUDO_HEADER;
			memcpy(&psheader->daddr, &IPHeader->DestinationAddress, sizeof(UINT));
			memcpy(&psheader->saddr, &IPHeader->SourceAddress, sizeof(UINT));
			psheader->protocol = IPHeader->Protocol;
			psheader->length = htons((USHORT)(sizeof(UDP_HEADER) + UDPDataSize));
			psheader->zero = 0;

			UCHAR *udppacket;
			UINT packet_size = sizeof(UDP_HEADER) + UDPDataSize + sizeof(PSEUDO_HEADER);
			packet_size = packet_size + ((packet_size%2)*2);
			udppacket = (UCHAR*)malloc(packet_size);
			memset(udppacket,0, packet_size);
			memcpy(&udppacket[0], psheader, sizeof(PSEUDO_HEADER));
			memcpy(&udppacket[sizeof(PSEUDO_HEADER)], udpheader,sizeof(UDP_HEADER));
			memcpy(&udppacket[sizeof(PSEUDO_HEADER) + sizeof(UDP_HEADER)],UDPData,UDPDataSize);

			if (GlobalChecksum((USHORT*)udppacket,packet_size) != UDPHeader->Checksum)
			{
				isMalformed = true;
				PacketError = PACKET_UDP_CHECKSUM;
			}

			delete ipheader;
			delete udpheader;
			delete psheader;
			free(udppacket);
		}
		else if (isICMPPacket)
		{
			ICMP_HEADER *icmpheader = new ICMP_HEADER;
			memcpy(icmpheader,ICMPHeader,sizeof(ICMP_HEADER));
			icmpheader->Checksum = 0x0000;

			UINT packet_size = sizeof(ICMP_HEADER) + ICMPDataSize;
			packet_size = packet_size + ((packet_size%2)*2);
			UCHAR *icmppacket = (UCHAR*)malloc(packet_size);

			memset(icmppacket,0, packet_size);
			memcpy(icmppacket, icmpheader,sizeof(ICMP_HEADER));
			memcpy(&icmppacket[sizeof(ICMP_HEADER)],ICMPData,ICMPDataSize);

			if (GlobalChecksum((USHORT*)icmppacket,packet_size) != ICMPHeader->Checksum)
			{
				isMalformed = true;
				PacketError = PACKET_ICMP_CHECKSUM;
			}	

			delete ipheader;
			delete icmpheader;
			free(icmppacket);
		} 
		
		if (isIPPacket && IPHeader->TimeToLive <= 10)
		{
			isMalformed = true;
			PacketError = PACKET_IP_TTL;
		}
	}
};

USHORT cPacket::GlobalChecksum(USHORT *buffer, UINT length)
{
	register int sum = 0;
	USHORT answer = 0;
	register USHORT *w = buffer;
	register int nleft = length;

	while(nleft > 1){
	sum += *w++;
	nleft -= 2;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}

cPacket::~cPacket()
{
	if (File != NULL) delete File;
};
 
void cPacket::ResetIs()
{
	isTCPPacket = FALSE;
	isUDPPacket = FALSE;
	isICMPPacket = FALSE;
	isIGMPPacket = FALSE;
	isARPPacket = FALSE;
	isIPPacket = FALSE;
	PacketError = PACKET_NOERROR;
	isMalformed = FALSE;
	isParsed = FALSE;
	isIPv6Packet = FALSE;

	TCPDataSize = 0;
	TCPOptionsSize = 0;
	ICMPDataSize = 0;
	UDPDataSize = 0;

	SLLHeader = NULL;
	EthernetHeader = NULL;
	IPHeader = NULL;
	TCPHeader = NULL;
	ARPHeader = NULL;
	UDPHeader = NULL;
	ICMPHeader = NULL;
	IGMPHeader = NULL;

	hasSLLHeader = FALSE;
	hasEtherHeader = FALSE;

	isUnknownPacket = FALSE;
};

BOOL cPacket::FixICMPChecksum()
{
	if (!isICMPPacket) return FALSE;

	ICMP_HEADER *icmpheader = new ICMP_HEADER;
	memcpy(icmpheader,ICMPHeader,sizeof(ICMP_HEADER));
	icmpheader->Checksum = 0;

	UINT packet_size = sizeof(ICMP_HEADER) + ICMPDataSize;
	packet_size = packet_size + ((packet_size%2)*2);
	UCHAR* icmppacket = (UCHAR*)malloc(packet_size);

	memset(icmppacket,0, packet_size);
	memcpy(icmppacket, icmpheader,sizeof(ICMP_HEADER));
	memcpy(&icmppacket[sizeof(ICMP_HEADER)],ICMPData,ICMPDataSize);

	USHORT crc = GlobalChecksum((USHORT*)icmppacket,packet_size);

	delete icmpheader;
	free(icmppacket);

	if(crc != ICMPHeader->Checksum)
	{
		memcpy(&ICMPHeader->Checksum,&crc,sizeof(USHORT));
		CheckIfMalformed();
		return true;
	} 
	else return false; 			
};

BOOL cPacket::FixIPChecksum()
{
	if (!isIPPacket) return FALSE;

	IP_HEADER *ipheader = new IP_HEADER;
	memcpy(ipheader,IPHeader,sizeof(IP_HEADER));
	ipheader->Checksum =0;

	USHORT crc = GlobalChecksum((USHORT*)ipheader,sizeof(IP_HEADER));
	
	delete ipheader;

	if(crc != IPHeader->Checksum)
	{
		memcpy(&IPHeader->Checksum,&crc,sizeof(USHORT));
		CheckIfMalformed();
		return true;
	} 
	else return false; 
};

BOOL cPacket::FixTCPChecksum()
{
	if (!isTCPPacket) return FALSE;

	TCP_HEADER *tcpheader = new TCP_HEADER;
	memcpy(tcpheader,TCPHeader,sizeof(TCP_HEADER));
	tcpheader->Checksum = 0;

	PSEUDO_HEADER *psheader = new PSEUDO_HEADER;
	memcpy(&psheader->daddr, &IPHeader->DestinationAddress, sizeof(UINT));
	memcpy(&psheader->saddr, &IPHeader->SourceAddress, sizeof(UINT));
	psheader->protocol = IPHeader->Protocol;
	psheader->length = htons((USHORT)(sizeof(TCP_HEADER) + TCPOptionsSize + TCPDataSize));
	psheader->zero = 0;

	UINT packet_size = sizeof(TCP_HEADER) + TCPOptionsSize + TCPDataSize + sizeof(PSEUDO_HEADER);
	packet_size = packet_size + ((packet_size%2)*2);
	UCHAR* tcppacket = (UCHAR*)malloc(packet_size);

	memset(tcppacket,0, packet_size);
	memcpy(tcppacket, psheader, sizeof(PSEUDO_HEADER));
	memcpy(&tcppacket[sizeof(PSEUDO_HEADER)], tcpheader,sizeof(TCP_HEADER));
	memcpy(&tcppacket[sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER)],TCPOptions,TCPOptionsSize);
	memcpy(&tcppacket[sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER) + TCPOptionsSize],TCPData, TCPDataSize);

	USHORT crc = GlobalChecksum((USHORT*)tcppacket,packet_size);

	delete psheader;
	delete tcpheader;
	free(tcppacket);
	if (crc != TCPHeader->Checksum)
	{
		memcpy(&TCPHeader->Checksum,&crc,sizeof(USHORT));
		CheckIfMalformed();
		return true;
	} 
	else return false; 
};

BOOL cPacket::FixUDPChecksum()
{
	if (!isUDPPacket) return FALSE;

	UDP_HEADER *udpheader = new UDP_HEADER;
	memcpy(udpheader,UDPHeader,sizeof(UDP_HEADER));
	udpheader->Checksum = 0;

	PSEUDO_HEADER *psheader = new PSEUDO_HEADER;
	memcpy(&psheader->daddr, &IPHeader->DestinationAddress, sizeof(UINT));
	memcpy(&psheader->saddr, &IPHeader->SourceAddress, sizeof(UINT));
	psheader->protocol = IPHeader->Protocol;
	psheader->length = htons((USHORT)(sizeof(UDP_HEADER) + UDPDataSize));
	psheader->zero = 0;

	UINT packet_size = sizeof(UDP_HEADER) + UDPDataSize + sizeof(PSEUDO_HEADER);
	packet_size = packet_size + ((packet_size%2)*2);
	UCHAR* udppacket = (UCHAR*)malloc(packet_size);
	memset(udppacket,0, packet_size);
	memcpy(&udppacket, psheader, sizeof(PSEUDO_HEADER));
	memcpy(&udppacket[sizeof(PSEUDO_HEADER)], udpheader,sizeof(UDP_HEADER));
	memcpy(&udppacket[sizeof(PSEUDO_HEADER) + sizeof(UDP_HEADER)],UDPData,UDPDataSize);

	USHORT crc = GlobalChecksum((USHORT*)udppacket,packet_size);

	delete psheader;
	delete udpheader;
	free(udppacket);

	if (crc != UDPHeader->Checksum)
	{
		memcpy(&UDPHeader->Checksum,&crc,sizeof(USHORT));
		CheckIfMalformed();
		return true;
	} 
	else return false; 
};