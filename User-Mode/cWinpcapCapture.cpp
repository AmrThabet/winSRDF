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
#include <string>

using namespace Security::Targets::Packets;
using namespace std;

#ifdef USE_WINPCAP

BOOL cWinpcapCapture::InitializeAdapters()
{
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) return FALSE;
        
	nAdapters = 0;
	Adapters = (NETWORK_ADAPTERS_CAPTURE*)malloc(nAdapters * sizeof(NETWORK_ADAPTERS_CAPTURE));

	for(d=alldevs; d; d=d->next)
	{
		Adapters = (NETWORK_ADAPTERS_CAPTURE*)realloc(Adapters, (nAdapters + 1) * sizeof(NETWORK_ADAPTERS_CAPTURE));
		strcpy_s((CHAR*)Adapters[nAdapters].ID,strlen(d->name) + 1, d->name);

		if (d->description)
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen(d->description) + 1, d->description);
		else
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen("No description available"), "No description available");

		nAdapters++;
	}

	return TRUE;
};

cWinpcapCapture::cWinpcapCapture()
{
	isReady = InitializeAdapters();
};

BOOL cWinpcapCapture::CapturePackets(UINT AdapterIndex, UINT MaxNumOfPackets, const CHAR* Filter)
{

	INT retValue;	UINT i, n = 0;	nCapturedPackets = 0;
	//CapturedPackets = (cPacket*)malloc(MaxNumOfPackets * sizeof(cPacket));

	if (AdapterIndex< 1 || AdapterIndex > nAdapters) return FALSE;
	for (d=alldevs, i=0; i< AdapterIndex-1 ;d=d->next, i++);        
	if ((fp=pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) return FALSE;

	UINT netmask;
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	struct bpf_program fcode;
	if ( pcap_compile(fp, &fcode, Filter, 1, netmask) < 0) return FALSE;
	if ( pcap_setfilter(fp, &fcode) < 0) return FALSE;

	while((retValue = pcap_next_ex( fp, &PacketHeader, &PacketData )) >= 0 && n < MaxNumOfPackets)
	{
		if(retValue == 0 ) continue;	n++;
		cPacket TempPacket((UCHAR*)PacketData, PacketHeader->len, time(0));
		Traffic.AddPacket(&TempPacket, NULL);
		nCapturedPackets++;
	}
    
    if( retValue == -1 ) return FALSE;

	//AnalyzeTraffic();
	return TRUE;
};

cWinpcapCapture::~cWinpcapCapture()
{
	pcap_freealldevs(alldevs);
	free(Adapters);
};

#endif
