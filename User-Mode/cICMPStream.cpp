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

using namespace Security::Targets::Packets;

cICMPStream::cICMPStream()
{
	nPingRequests = 0;
	nPingResponses = 0;

	PingReceivedData = NULL;
	PingReceivedDataSize = 0;

	PingSentData = NULL;
	PingSentDataSize = 0;

	PingRequester = NULL;
	PingReceiver = NULL;
}


cICMPStream::~cICMPStream()
{
}

BOOL cICMPStream::Identify(cPacket* Packet)
{
	return Packet->isICMPPacket;
}

BOOL cICMPStream::AddPacket(cPacket* Packet)
{
	if (!Identify(Packet)) return FALSE;

	if (nPackets > 0)
	{
		if ( (	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress ) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress ) )
		{
			nPackets++;
			Packets = (cPacket**)realloc(Packets, nPackets * sizeof(cPacket*));
			memcpy(&Packets[(nPackets-1)], &Packet, sizeof(cPacket*));
			
			AnalyzeProtocol();
			return TRUE;
		}
		else return FALSE;
	}
	else
	{
		nPackets++;
		Packets = (cPacket**)realloc(Packets, nPackets * sizeof(cPacket*));
		memcpy(&Packets[(nPackets-1)], &Packet, sizeof(cPacket*));

		isIPConnection = Packet->isIPPacket; 

		if (Packets[0]->hasEtherHeader)
		{
			memcpy(&ServerMAC, &Packets[0]->EthernetHeader->DestinationHost, ETHER_ADDR_LEN);
			memcpy(&ClientMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
			Protocol = Packets[0]->EthernetHeader->ProtocolType;
		}
		else if (Packets[0]->hasSLLHeader && ntohs(Packets[0]->SLLHeader->AddressLength) == ETHER_ADDR_LEN)
		{
			memset(&ServerMAC, 0, ETHER_ADDR_LEN);
			memcpy(&ClientMAC, &Packets[0]->SLLHeader->Address, ETHER_ADDR_LEN);
			Protocol = Packets[0]->SLLHeader->ProtocolType;
		}
		//set else statement 

		ServerIP = Packets[0]->IPHeader->DestinationAddress;
		ClientIP = Packets[0]->IPHeader->SourceAddress;

		AnalyzeProtocol();
		return TRUE;
	}
}

void cICMPStream::AnalyzeProtocol()
{
	if (Packets[nPackets - 1]->ICMPDataSize > 0 && PingReceivedData == NULL && 
		Packets[nPackets - 1]->ICMPHeader->Type == ICMP_ECHOREPLY)
	{
		PingReceivedData = Packets[nPackets - 1]->ICMPData;
		PingReceivedDataSize = Packets[nPackets - 1]->ICMPDataSize;
	} 
	else if (Packets[nPackets - 1]->ICMPDataSize > 0 && PingSentData == NULL && 
		Packets[nPackets - 1]->ICMPHeader->Type == ICMP_ECHO)
	{
		PingSentData = Packets[nPackets - 1]->ICMPData;
		PingSentDataSize = Packets[nPackets - 1]->ICMPDataSize;
	}


	if (PingRequester == NULL || PingReceiver == NULL)
	{
		 if (Packets[0]->ICMPHeader->Type == ICMP_ECHO)
		 {
			 PingRequester = ClientIP;
			 PingReceiver = ServerIP;
		 }
		 else
		 {
			 PingRequester = ServerIP;
			 PingReceiver = ClientIP;
		 }
	}

	if (nPackets > 0)
	{
		if (Packets[nPackets - 1]->ICMPHeader->Type == ICMP_ECHO) nPingRequests++;
		else if (Packets[nPackets - 1]->ICMPHeader->Type == ICMP_ECHOREPLY) nPingResponses++;
	}
}