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

cARPStream::cARPStream()
{
	memset(&RequesterMAC, 0, ETHER_ADDR_LEN);
	memset(&RequestedMAC, 0, ETHER_ADDR_LEN);
	memset(&ReplierMAC, 0, ETHER_ADDR_LEN);

	RequesterIP = NULL;
	RequestedMACIP = NULL;

	GotReply = FALSE;
}

cARPStream::~cARPStream()
{
}

BOOL cARPStream::Identify(cPacket* Packet)
{
	return Packet->isARPPacket;
}

BOOL cARPStream::AddPacket(cPacket* Packet)
{
	if (!Identify(Packet)) return FALSE;

	if (nPackets == 0)
	{
		nPackets++;
		Packets = (cPacket**)realloc((void*)Packets, nPackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(nPackets-1)], (void**)&Packet, sizeof(cPacket*));

		if (ntohs(Packets[0]->ARPHeader->OperationCode) == ARPOP_REQUEST)
		{
			RequestedMACIP = Packets[0]->ARPHeader->TargetProtocolAddress;

			RequesterIP = Packets[0]->ARPHeader->SourceProtocolAddress;
			memcpy(&RequesterMAC, &Packets[0]->ARPHeader->SourceHardwareAddress, ETHER_ADDR_LEN);
		}
		else if (ntohs(Packets[0]->ARPHeader->OperationCode) == ARPOP_REPLY)
		{
			GotReply = TRUE;
			RequestedMACIP = Packets[0]->ARPHeader->SourceProtocolAddress;
			memcpy(&RequestedMAC, &Packets[0]->ARPHeader->SourceHardwareAddress, ETHER_ADDR_LEN);

			if (Packets[0]->hasEtherHeader)
				memcpy(&ReplierMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
			else if (Packets[0]->hasSLLHeader)
				memcpy(&ReplierMAC, &Packets[0]->SLLHeader->Address, ETHER_ADDR_LEN);

			RequesterIP = Packets[0]->ARPHeader->TargetProtocolAddress;
			memcpy(&RequesterMAC, &Packets[0]->ARPHeader->TargetHardwareAddress, ETHER_ADDR_LEN);
		}

		AnalyzeProtocol();
		return TRUE;
	}
	else
	{
		if (		Packet->isARPPacket && 
					Packet->ARPHeader->HardwareType == Packets[0]->ARPHeader->HardwareType &&
					Packet->ARPHeader->ProtocolType == Packets[0]->ARPHeader->ProtocolType &&
				((	RequestedMACIP == Packet->ARPHeader->TargetProtocolAddress && 
					RequesterIP == Packet->ARPHeader->SourceProtocolAddress ) ||
				(	RequestedMACIP == Packet->ARPHeader->SourceProtocolAddress &&
					RequesterIP == Packet->ARPHeader->TargetProtocolAddress )))
		{

			nPackets++;
			Packets = (cPacket**)realloc((void*)Packets, nPackets * sizeof(cPacket*));
			memcpy((void**)&Packets[(nPackets-1)], (void**)&Packet, sizeof(cPacket*));

			AnalyzeProtocol();
			return TRUE;
		}
		else return FALSE;
	}
}

void cARPStream::AnalyzeProtocol()
{
	if (nPackets > 0 && ntohs(Packets[nPackets - 1]->ARPHeader->OperationCode) == ARPOP_REPLY && !GotReply)
	{
		GotReply = TRUE;
		memcpy(&RequestedMAC, &Packets[nPackets - 1]->ARPHeader->SourceHardwareAddress, ETHER_ADDR_LEN);

		if (Packets[nPackets - 1]->hasEtherHeader)
			memcpy(&ReplierMAC, &Packets[nPackets - 1]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
		else if (Packets[nPackets - 1]->hasSLLHeader && ntohs(Packets[nPackets - 1]->SLLHeader->AddressLength) == ETHER_ADDR_LEN)
			memcpy(&ReplierMAC, &Packets[nPackets - 1]->SLLHeader->Address, ETHER_ADDR_LEN);
		//need to set else statement
	}
}