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

cTCPStream::cTCPStream() : cConStream()
{
	ServerPort = NULL;
	ClientPort = NULL;
	TransportType = CONN_TRANSPORT_TCP;
	//ExtractedFilesCursor = 0;
	//Segmented = FALSE;
}

cTCPStream::~cTCPStream() {}

BOOL cTCPStream::Identify(cPacket* Packet) { return Packet->isTCPPacket; }

BOOL cTCPStream::AddPacket(cPacket* Packet)
{
	if (!Packet->isTCPPacket) return FALSE;

	if (nPackets > 0)
	{
		if ((	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress &&
				ServerPort == ntohs(Packet->TCPHeader->DestinationPort) && ClientPort == ntohs(Packet->TCPHeader->SourcePort)) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress &&
				ClientPort == ntohs(Packet->TCPHeader->DestinationPort) && ServerPort == ntohs(Packet->TCPHeader->SourcePort)) )
		{
			if (!CheckPacket(Packet)) return FALSE;
			//if (PushProtocol(Packet)) { Segmented = TRUE; return TRUE; }

			//nActivePackets++;
			nPackets++;
			Packets = (cPacket**)realloc((void*)Packets, /*nActivePackets*/ nPackets * sizeof(cPacket*));
			memcpy((void**)&Packets[(/*nActivePackets*/ nPackets-1)], (void**)&Packet, sizeof(cPacket*));

			AnalyzeProtocol();
			return TRUE;
		}
		else return FALSE;
	}
	else
	{
		if (!CheckPacket(Packet)) return FALSE;
		//if (PushProtocol(Packet)) { Segmented = TRUE; return TRUE; }

		//nActivePackets++;
		nPackets++;
		Packets = (cPacket**)realloc((void*)Packets, /*nActivePackets*/ nPackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(/*nActivePackets*/ nPackets-1)], (void**)&Packet, sizeof(cPacket*));


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
		//set else statement

		ServerIP = Packets[0]->IPHeader->DestinationAddress;
		ClientIP = Packets[0]->IPHeader->SourceAddress;
		ServerPort = ntohs(Packets[0]->TCPHeader->DestinationPort);
		ClientPort = ntohs(Packets[0]->TCPHeader->SourcePort);

		AnalyzeProtocol();
		return TRUE;
	}
}

BOOL cTCPStream::CheckPacket(cPacket* Packet) {	return Packet->isTCPPacket; }
void cTCPStream::AnalyzeProtocol() { }

/*BOOL cTCPStream::PushProtocol(cPacket* Packet)
{
	if (!ExtractedFiles.AddPacket(Packet)) return FALSE;
	if (ExtractedFiles.nExtractedData > ExtractedFilesCursor)
	{
		Packet->TCPDataSize = ExtractedFiles.ExtractedData[ExtractedFiles.nExtractedData - 1].Size * sizeof(UCHAR);
		Packet->TCPData = (UCHAR*)malloc( Packet->TCPDataSize );
		memset(Packet->TCPData, 0, Packet->TCPDataSize);
		memcpy(Packet->TCPData, ExtractedFiles.ExtractedData[ExtractedFiles.nExtractedData - 1].Buffer, Packet->TCPDataSize);
		ExtractedFilesCursor++;
	}

	return TRUE;
}*/