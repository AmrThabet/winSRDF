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
using namespace Security::Targets::Files;

cPcapFile::cPcapFile(char* szFilename, UINT Options) : cFile(szFilename)
{
	Traffic = new cTraffic;
	FileLoaded = ProcessPCAP(Options);
}

BOOL cPcapFile::ProcessPCAP(UINT Options)
{
	nPackets = 0;
	if (BaseAddress == 0 || FileLength == 0) return false;
	PCAP_General_Header = (PCAP_GENERAL_HEADER*)BaseAddress;
	UINT psize = 0;

	PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(BaseAddress + sizeof(PCAP_GENERAL_HEADER));
	psize = psize + PCAP_Packet_Header->incl_len;
	
	/* parse each packet*/
	UINT fsize = 0;
	UINT lsize = 0;

	/* getting number of packets inside file */
	for(UINT i=1; PCAP_Packet_Header->incl_len !=0 ;i++)
	{
		PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(BaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER) * i) + psize);
		psize = psize + PCAP_Packet_Header->incl_len;
		nPackets++;


		PBaseAddress = (BaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER)*(nPackets)) + fsize);
		PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(BaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER)*(nPackets-1)) + fsize);
		
		fsize = fsize + PCAP_Packet_Header->incl_len;
		PSize = PCAP_Packet_Header->incl_len;
		
		Packet = new cPacket((UCHAR*)PBaseAddress,PSize, PCAP_Packet_Header->ts_sec + PCAP_Packet_Header->ts_usec/1000000, 
			PCAP_General_Header->network, (Options & CPCAP_OPTIONS_MALFORM_CHECK) ? CPACKET_OPTIONS_MALFORM_CHECK : CPACKET_OPTIONS_NONE);

		Traffic->AddPacket(Packet, Packet->Timestamp);
	}

	return true;
};

cPcapFile::~cPcapFile()
{
	delete Traffic;
};
