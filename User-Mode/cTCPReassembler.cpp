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
#include <map>
#include <fstream>

using namespace std;
using namespace Security::Targets::Packets;

cTCPReassembler::cTCPReassembler(cPacket* Packet, UINT TotalSize, UINT BodySize)
{
	RefPacket = Packet;
	this->TotalSize = TotalSize;
	CurrentSize = BodySize;
	isReassembled = FALSE;

	DataStreamContainer = new DATASTREAM;
	DataStreamContainer->Pointer = Packet->TCPData;
	DataStreamContainer->Size = BodySize;

	DataStream[ntohl(Packet->TCPHeader->Sequence)] = DataStreamContainer;
}

BOOL cTCPReassembler::AddPacket(cPacket* Packet)
{
	if (isReassembled || 
		!Packet->isTCPPacket || 
		!BelongsToStream(Packet)) 
		return FALSE;

	DataStreamContainer = new DATASTREAM;
	DataStreamContainer->Pointer = Packet->TCPData;
	DataStreamContainer->Size = Packet->TCPDataSize;
	CurrentSize += Packet->TCPDataSize;

	if (DataStream[ntohl(Packet->TCPHeader->Sequence)] == NULL)
		DataStream[ntohl(Packet->TCPHeader->Sequence)] = DataStreamContainer;
	else {
		CurrentSize -= DataStream[ntohl(Packet->TCPHeader->Sequence)]->Size;
		delete DataStream[ntohl(Packet->TCPHeader->Sequence)];
		DataStream[ntohl(Packet->TCPHeader->Sequence)] = DataStreamContainer;
	}

	if (CurrentSize == TotalSize)
		isReassembled = TRUE;
	return TRUE;
}

cTCPReassembler::~cTCPReassembler()
{
	Empty();
}

void cTCPReassembler::Empty()
{
	for (DataStreamIterator = DataStream.begin(); 
		DataStreamIterator != DataStream.end(); 
		++DataStreamIterator) 
	{
		delete DataStreamIterator->second;
	}

	DataStream.clear();
}

BOOL cTCPReassembler::BelongsToStream(cPacket* Packet)
{
	if (Packet->IPHeader->DestinationAddress == RefPacket->IPHeader->DestinationAddress &&
		Packet->IPHeader->SourceAddress == RefPacket->IPHeader->SourceAddress &&
		Packet->TCPHeader->DestinationPort == RefPacket->TCPHeader->DestinationPort &&
		Packet->TCPHeader->SourcePort == RefPacket->TCPHeader->SourcePort &&
		Packet->TCPHeader->Acknowledge == RefPacket->TCPHeader->Acknowledge &&
		Packet->TCPDataSize > 0) 
		return TRUE;
	return FALSE;
}

BOOL cTCPReassembler::Identify(cPacket* Packet, UINT AssumedDataSize)
{
	if (Packet->TCPHeader->SynchroniseFlag == 1 &&
		Packet->TCPHeader->AcknowledgmentFlag == 0 &&
		Packet->TCPHeader->PushFlag == 0 &&
		Packet->TCPHeader->FinishFlag == 0 &&
		Packet->TCPDataSize == 0)
		return TRUE;
	else 
		return FALSE;
}

UCHAR* cTCPReassembler::GetReassembledStream() 
{
	Stream = new UCHAR[TotalSize];
	PositionPointer = 0;
	for (DataStreamIterator = DataStream.begin(); 
		DataStreamIterator != DataStream.end(); 
		++DataStreamIterator) 
	{
		memcpy(
			&Stream[PositionPointer], 
			DataStreamIterator->second->Pointer, 
			DataStreamIterator->second->Size);

		PositionPointer += DataStreamIterator->second->Size;
	}

	return Stream;
}