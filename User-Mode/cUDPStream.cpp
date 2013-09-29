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

cUDPStream::cUDPStream() : cConStream()
{
	ServerPort = NULL;
	ClientPort = NULL;
	TransportType = CONN_TRANSPORT_UDP;
}

cUDPStream::~cUDPStream(void)
{

}

BOOL cUDPStream::Identify(cPacket* Packet) { return Packet->isUDPPacket; }

BOOL cUDPStream::AddPacket(cPacket* Packet)
{
	if (!Packet->isUDPPacket) return FALSE;

	if (nPackets > 0)
	{
		if ( (	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress &&
				ServerPort == ntohs(Packet->UDPHeader->DestinationPort) && ClientPort == ntohs(Packet->UDPHeader->SourcePort)) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress &&
				ClientPort == ntohs(Packet->UDPHeader->DestinationPort) && ServerPort == ntohs(Packet->UDPHeader->SourcePort)) )
		{
			nPackets++;
			Packets = (cPacket**)realloc((void*)Packets, nPackets * sizeof(cPacket*));
			memcpy((void**)&Packets[(nPackets-1)], (void**)&Packet, sizeof(cPacket*));
			

			return TRUE;
		}
		else return FALSE;
	}
	else
	{
		nPackets++;
		Packets = (cPacket**)realloc((void*)Packets, nPackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(nPackets-1)], (void**)&Packet, sizeof(cPacket*));
		
		isIPConnection = Packet->isIPPacket;
		isTCPConnection = Packet->isTCPPacket;
		isUDPConnection = Packet->isUDPPacket;

		if (Packets[0]->hasEtherHeader)
		{
			memcpy(&ServerMAC, &Packets[0]->EthernetHeader->DestinationHost, ETHER_ADDR_LEN);
			memcpy(&ClientMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
			Protocol = Packets[0]->EthernetHeader->ProtocolType;
		}
		else if (Packets[0]->hasSLLHeader && ntohs(Packets[0]->SLLHeader->AddressLength) == ETHER_ADDR_LEN)
		{
			memset(&ServerMAC, 0,ETHER_ADDR_LEN);
			memcpy(&ClientMAC, &Packets[0]->SLLHeader->Address, ETHER_ADDR_LEN);
			Protocol = Packets[0]->SLLHeader->ProtocolType;
		}
		//set else statemet

		ServerIP = Packets[0]->IPHeader->DestinationAddress;
		ClientIP = Packets[0]->IPHeader->SourceAddress;
		ServerPort = ntohs(Packets[0]->UDPHeader->DestinationPort);
		ClientPort = ntohs(Packets[0]->UDPHeader->SourcePort);

		return TRUE;
	}
}