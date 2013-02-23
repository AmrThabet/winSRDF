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

#include "StdAfx.h"
#include "SRDF.h"
#include <iostream>

using namespace std;
using namespace Security::Targets::Packets;

cConStream::cConStream()
{
	isTCPPacket = false;
	isUDPPacket = false;
	isIPPacket = false;
	nActivePackets = 0;
	nPackets = 0;
	Packets = (cPacket**)malloc(nActivePackets * sizeof(cPacket*));
};

cConStream::~cConStream()
{
};

BOOL cConStream::AddPacket(cPacket* packet)
{
	if (nPackets == 0)
	{
		nActivePackets++;
		Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(nActivePackets-1)], (void**)&packet, sizeof(cPacket*));

		nPackets++;

		return AnalyzePackets();
	}
	else if (nPackets > 0)
	{	
		if ((packet->isIPPacket && Packets[0]->isIPPacket) &&
			(packet->IPHeader->DestinationAddress == Packets[0]->IPHeader->DestinationAddress &&
			packet->IPHeader->SourceAddress == Packets[0]->IPHeader->SourceAddress))
		{
			if ((packet->isTCPPacket && Packets[0]->isTCPPacket) &&
				(packet->TCPHeader->DestinationPort == Packets[0]->TCPHeader->DestinationPort &&
				packet->TCPHeader->SourcePort == Packets[0]->TCPHeader->SourcePort))
			{
				nActivePackets++;
				Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
				memcpy((void**)&Packets[(nActivePackets-1)], (void**)&packet, sizeof(cPacket*));

				nPackets++;
				return AnalyzePackets();
			}
			else if ((packet->isUDPPacket && Packets[0]->isUDPPacket) &&
				(packet->UDPHeader->DestinationPort == Packets[0]->UDPHeader->DestinationPort &&
				packet->UDPHeader->SourcePort == Packets[0]->UDPHeader->SourcePort))
			{
				nActivePackets++;
				Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
				memcpy((void**)&Packets[(nActivePackets-1)], (void**)&packet, sizeof(cPacket*));

				nPackets++;
				return AnalyzePackets();
			}
			else
			{
				return false;
			}
		}
		else if ((packet->isIPPacket && Packets[0]->isIPPacket) &&
			(packet->IPHeader->DestinationAddress == Packets[0]->IPHeader->SourceAddress &&
			packet->IPHeader->SourceAddress == Packets[0]->IPHeader->DestinationAddress))
		{
			if ((packet->isTCPPacket && Packets[0]->isTCPPacket) &&
				(packet->TCPHeader->DestinationPort == Packets[0]->TCPHeader->SourcePort &&
				packet->TCPHeader->SourcePort == Packets[0]->TCPHeader->DestinationPort))
			{
				nActivePackets++;
				Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
				memcpy((void**)&Packets[(nActivePackets-1)], (void**)&packet, sizeof(cPacket*));

				nPackets++;
				return AnalyzePackets();
			}
			else if ((packet->isUDPPacket && Packets[0]->isUDPPacket) &&
				(packet->UDPHeader->DestinationPort == Packets[0]->UDPHeader->SourcePort &&
				packet->UDPHeader->SourcePort == Packets[0]->UDPHeader->DestinationPort))
			{
				nActivePackets++;
				Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
				memcpy((void**)&Packets[(nActivePackets-1)], (void**)&packet, sizeof(cPacket*));

				nPackets++;
				return AnalyzePackets();
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}
};

BOOL cConStream::AnalyzePackets()
{
	if (nPackets > 0)
	{
		if (Packets[0]->isTCPPacket)
		{
			isTCPPacket = true;
			isIPPacket = true;
			if (ntohs(Packets[0]->TCPHeader->DestinationPort) < 1024)
			{
				ServerPort = ntohs(Packets[0]->TCPHeader->DestinationPort);
				ServerIP = Packets[0]->IPHeader->DestinationAddress;
				ClientPort = ntohs(Packets[0]->TCPHeader->SourcePort);
				ClientIP = Packets[0]->IPHeader->SourceAddress;
			}
			else if (ntohs(Packets[0]->TCPHeader->SourcePort) < 1024)
			{
				ClientPort = ntohs(Packets[0]->TCPHeader->DestinationPort);
				ClientIP = Packets[0]->IPHeader->DestinationAddress;
				ServerPort = ntohs(Packets[0]->TCPHeader->SourcePort);
				ServerIP = Packets[0]->IPHeader->SourceAddress;			
			}
			else
			{
				/* assign client as first packet*/
				ServerPort = ntohs(Packets[0]->TCPHeader->DestinationPort);
				ServerIP = Packets[0]->IPHeader->DestinationAddress;
				ClientPort = ntohs(Packets[0]->TCPHeader->SourcePort);
				ClientIP = Packets[0]->IPHeader->SourceAddress;
			}
		}
		else if (Packets[0]->isUDPPacket)
		{
			isUDPPacket = true;
			isIPPacket = true;
			if (ntohs(Packets[0]->UDPHeader->DestinationPort) < 1024)
			{
				ServerPort = ntohs(Packets[0]->UDPHeader->DestinationPort);
				ServerIP = Packets[0]->IPHeader->DestinationAddress;
				ClientPort = ntohs(Packets[0]->UDPHeader->SourcePort);
				ClientIP = Packets[0]->IPHeader->SourceAddress;
			}
			else if (ntohs(Packets[0]->UDPHeader->SourcePort) < 1024)
			{
				ClientPort = ntohs(Packets[0]->UDPHeader->DestinationPort);
				ClientIP = Packets[0]->IPHeader->DestinationAddress;
				ServerPort = ntohs(Packets[0]->UDPHeader->SourcePort);
				ServerIP = Packets[0]->IPHeader->SourceAddress;			
			}
			else
			{
				ServerPort = ntohs(Packets[0]->UDPHeader->DestinationPort);
				ServerIP = Packets[0]->IPHeader->DestinationAddress;
				ClientPort = ntohs(Packets[0]->UDPHeader->SourcePort);
				ClientIP = Packets[0]->IPHeader->SourceAddress;
			}
		}
		return true;
	}
	else
	{
		return false;
	}
};

BOOL cConStream::ClearActivePackets(UINT keeped)
{
	if (keeped > 0 && keeped <= nActivePackets)
	{
		
		memcpy((void**)&Packets[0], (void**)&Packets[nActivePackets-keeped], keeped * sizeof(cPacket*));
		Packets = (cPacket**)realloc((void**)Packets, keeped * sizeof(cPacket*));
		nActivePackets = (nActivePackets + 1) - keeped;
		return true;
	}
	else if (keeped = 0)
	{
		free(Packets);
		Packets = (cPacket**)malloc(nActivePackets * sizeof(cPacket*));
		nActivePackets = 0;
		return true;
	}
	else
	{
		return false;
	}
};
