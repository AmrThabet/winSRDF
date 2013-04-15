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
#include <iostream>
#include "SRDF.h"

using namespace Security::Targets::Files;
using namespace std;

cPcapFile::cPcapFile(char* szFilename) : cFile(szFilename)
{
	FileLoaded = ProcessPCAP();
}
bool cPcapFile::identify(cFile* File)
{
	if (File->BaseAddress == 0 || File->FileLength == 0) return false;
	PCAP_GENERAL_HEADER* PCAP_General_Header = (PCAP_GENERAL_HEADER*)File->BaseAddress;
	if (PCAP_General_Header->magic_number != 0xA1B2C3D4) return false;
	return true;
}
BOOL cPcapFile::ProcessPCAP()
{
	nPackets = 0;
	if (BaseAddress == 0 || FileLength == 0) return false;
	PCAP_General_Header = (PCAP_GENERAL_HEADER*)BaseAddress;
	if (PCAP_General_Header->magic_number != 0xA1B2C3D4) return false;
	UINT psize = 0;

	PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(BaseAddress + sizeof(PCAP_GENERAL_HEADER));
	psize = psize + PCAP_Packet_Header->incl_len;
	
	/* getting number of packets inside file */
	for(UINT i=1; PCAP_Packet_Header->incl_len !=0 ;i++)
	{
		PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(BaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER) * i) + psize);
		psize = psize + PCAP_Packet_Header->incl_len;
		nPackets = nPackets + 1;
	}

	/* parse each packet*/
	UINT fsize = 0;
	UINT lsize = 0;

	Packets = (cPacket**)malloc(sizeof(cPacket*) * nPackets);
	for (UINT i=0; i < nPackets; i++)
	{
		DWORD PBaseAddress = (BaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER)*(i+1)) + fsize);
		PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(BaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER)*(i)) + fsize);
		
		fsize = fsize + PCAP_Packet_Header->incl_len;
		UINT PSize = PCAP_Packet_Header->incl_len;
		
		Packet = new cPacket((UCHAR*)PBaseAddress,PSize);
		memcpy((void**)&Packets[i],(void**)&Packet,sizeof(cPacket*));
	}

	GetStreams();
	return true;
};

cPcapFile::~cPcapFile(void)
{

};

void cPcapFile::GetStreams()
{
	nConStreams = 0;
	ConStreams = (cConStream**)malloc( sizeof(cConStream*) * nConStreams);

	for (UINT i=0; i<nPackets; i++)
	{
		if (nConStreams > 0)
		{
			for (UINT j=0; j<nConStreams; j++)
			{
				if (ConStreams[j]->isIPPacket && Packets[i]->isIPPacket)
				{
					if (ConStreams[j]->AddPacket(Packets[i]))
					{
						break;
					}
					else if (j == (nConStreams - 1))
					{
						cConStream* tmp1 = new cConStream();
						tmp1->AddPacket(Packets[i]);

						nConStreams++;
						ConStreams = (cConStream**)realloc((void*)ConStreams, nConStreams * sizeof(cConStream*));
						memcpy((void**)&ConStreams[nConStreams-1],(void**)&tmp1, sizeof(cConStream*));
						break;
					}
				}
			}
		}
		else
		{
			if (Packets[i]->isIPPacket && (Packets[i]->isTCPPacket || Packets[i]->isUDPPacket))
			{
				//allocate new stream
				cConStream* tmp2 = new cConStream();
				tmp2->AddPacket(Packets[i]);

				nConStreams++;
				ConStreams = (cConStream**)realloc((void*)ConStreams, nConStreams * sizeof(cConStream*));
				memcpy((void**)&ConStreams[nConStreams-1],(void**)&tmp2, sizeof(cConStream*));
			}
		}
	}
};