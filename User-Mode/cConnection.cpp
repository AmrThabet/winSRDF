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

using namespace std;
using namespace Security::Targets::Packets;

cConnection::cConnection()
{
	nPackets = 0;
	isIPConnection = FALSE;
	NetworkType = 0;
	TransportType = 0;
	AddressingType = 0;
	ApplicationType = 0;
	Packets = (cPacket**)malloc(nPackets * sizeof(cPacket*));
};

cConnection::~cConnection()
{
	for (UINT i=0; i<nPackets; i++) delete Packets[i];
	free(Packets);
};

BOOL cConnection::AddPacket(cPacket* Packet)
{
	if (!CheckPacket(Packet)) return FALSE;
	if (nPackets == 0)
	{
		nPackets++;
		Packets = (cPacket**)realloc(Packets, nPackets * sizeof(cPacket*));
		memcpy(&Packets[( nPackets-1)], &Packet, sizeof(cPacket*));
		isIPConnection = Packet->isIPPacket;
		AddressingType = CONN_ADDRESSING_IP;
		return AnalyzePackets();
	}
	else
	{
		if (	(	Packet->hasSLLHeader && 
					memcmp(&Protocol, &Packet->SLLHeader->ProtocolType, sizeof(USHORT)) == 0 &&
				(	memcmp(&ClientMAC, &Packet->SLLHeader->Address, ETHER_ADDR_LEN) == 0	||
					memcmp(&ServerMAC, &Packet->SLLHeader->Address, ETHER_ADDR_LEN) == 0 ))	||

				(	Packet->hasEtherHeader && 
					memcmp(&Protocol, &Packet->EthernetHeader->ProtocolType, sizeof(USHORT)) == 0 &&
				((	memcmp(&ClientMAC, &Packet->EthernetHeader->SourceHost, ETHER_ADDR_LEN) == 0 && 
					memcmp(&ServerMAC, &Packet->EthernetHeader->DestinationHost, ETHER_ADDR_LEN) == 0) ||
				(	memcmp(&ServerMAC, &Packet->EthernetHeader->SourceHost, ETHER_ADDR_LEN) == 0 &&
					memcmp(&ClientMAC, &Packet->EthernetHeader->DestinationHost, ETHER_ADDR_LEN) == 0))))
		{
			nPackets++;
			Packets = (cPacket**)realloc((void*)Packets, nPackets * sizeof(cPacket*));
			memcpy((void**)&Packets[(nPackets-1)], (void**)&Packet, sizeof(cPacket*));
			isIPConnection = Packet->isIPPacket;
			return AnalyzePackets();
		}
		else return FALSE;
	}
};

BOOL cConnection::AnalyzePackets()
{
	if (nPackets > 0)
	{
		if (Packets[0]->hasEtherHeader)
		{
			memcpy(&ServerMAC, &Packets[0]->EthernetHeader->DestinationHost, ETHER_ADDR_LEN);
			memcpy(&ClientMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
			Protocol = Packets[0]->EthernetHeader->ProtocolType;
			NetworkType = CONN_NETWORK_ETHERNET;
			return true;
		}
		else if (Packets[0]->hasSLLHeader && ntohs(Packets[0]->SLLHeader->AddressLength) == 6)
		{
			memset(&ServerMAC, 0,ETHER_ADDR_LEN);
			memcpy(&ClientMAC, &Packets[0]->SLLHeader->Address, ETHER_ADDR_LEN);
			Protocol = Packets[0]->SLLHeader->ProtocolType;
			NetworkType = CONN_NETWORK_SSL;
			return true;
		}
		else return false;
	}
	else return FALSE;  //revise
};

BOOL cConnection::ClearActivePackets(UINT NumberToBeKeeped)
{
	if (NumberToBeKeeped > 0 && NumberToBeKeeped <= nPackets)
	{
		for (UINT i=0; i<nPackets - NumberToBeKeeped; i++) delete Packets[i];
		memcpy(Packets, &Packets[nPackets - NumberToBeKeeped], NumberToBeKeeped * sizeof(cPacket*));
		Packets = (cPacket**)realloc(Packets, NumberToBeKeeped * sizeof(cPacket*));
		nPackets = NumberToBeKeeped;
		return true;
	}
	else if (NumberToBeKeeped == 0)
	{
		for (UINT i=0; i<nPackets; i++) delete Packets[i];
		free(Packets);
		nPackets = 0;
		Packets = (cPacket**)malloc(nPackets * sizeof(cPacket*));
		return true;
	}
	else return false;
};

BOOL cConnection::CheckPacket(cPacket* Packet) { return TRUE; }