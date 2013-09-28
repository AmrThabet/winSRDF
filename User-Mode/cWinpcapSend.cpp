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

#ifdef USE_WINPCAP

using namespace Security::Targets::Packets;

cWinpcapSend::cWinpcapSend()
{
	isReady = InitializeAdapters();
};

BOOL cWinpcapSend::SendPacket(UINT AdapterIndex, cPacket* Packet)
{
	UINT i=0;
	if (AdapterIndex< 1 || AdapterIndex > nAdapters) return FALSE;
	for (d=alldevs, i=0; i< AdapterIndex-1 ;d=d->next, i++);        
	if ((fp=pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) return FALSE;
	if (pcap_sendpacket(fp, Packet->RawPacket, Packet->PacketSize) != 0) return FALSE;
	return TRUE;
}

BOOL cWinpcapSend::InitializeAdapters()
{
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) return FALSE;
        
	nAdapters = 0;
	Adapters = (NETWORK_ADAPTERS_SEND*)malloc(nAdapters * sizeof(NETWORK_ADAPTERS_SEND));

	for(d=alldevs; d; d=d->next)
	{
		Adapters = (NETWORK_ADAPTERS_SEND*)realloc(Adapters, (nAdapters + 1) * sizeof(NETWORK_ADAPTERS_SEND));
		strcpy_s((CHAR*)Adapters[nAdapters].ID,strlen(d->name) + 1, d->name);

		if (d->description)
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen(d->description) + 1, d->description);
		else
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen("No description available"), "No description available");

		nAdapters++;
	}

	return TRUE;
};


cWinpcapSend::~cWinpcapSend()
{
	pcap_freealldevs(alldevs);
	free(Adapters);
}
#endif