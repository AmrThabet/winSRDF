// ProtocolAnalyzer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../../../SRDF.h"

using namespace Security::Targets::Files;
using namespace Security::Targets::Packets;

char* PrintIP(UINT nIP)
{
	char buf[255] = {0};
	unsigned char* IP = (unsigned char*)&nIP;
	sprintf(buf,"%d.%d.%d.%d",IP[0],IP[1],IP[2],IP[3]);
	return buf;
}

int _tmain(int argc, _TCHAR* argv[])
{
	cout << "\n\n [*] Loading from pcap file" << endl;
	cPcapFile* Pcap = new cPcapFile("http.pcap");
	if (!Pcap->IsFound())
	{
		cout << " [x] Unable to Open File\n";
		return 0;
	}
	cout << " Number of Packets: " << Pcap->nPackets << "\n";
	cout << " Number of Sessions: " << Pcap->Traffic->nConnections << "\n\n";


	for (UINT i = 0; i < Pcap->Traffic->nConnections;i++)
	{
		if (Pcap->Traffic->Connections[i]->ApplicationType == CONN_APPLICATION_DNS)
		{
			cDNSStream* DNS = (cDNSStream*)Pcap->Traffic->Connections[i];
			cout << " Found DNS Stream No." << i << "\n";
			cout << "  [+] DNS Query: " << DNS->RequestedDomain << "\n";
			cout << "  [+] Resolved IP (1st IP): " << PrintIP(DNS->ResolvedIPs[0]) << "\n";
			cout << "\n";
		}
		if (Pcap->Traffic->Connections[i]->ApplicationType == CONN_APPLICATION_HTTP)
		{
			cHTTPStream* HTTP = (cHTTPStream*)Pcap->Traffic->Connections[i];
			cout << " Found HTTP Stream No." << i << "\n";
			cout << "  [+] Server IP: " << PrintIP(HTTP->ServerIP) << "\n";
			cout << "  [+] Number of Requests: " << HTTP->nRequests << "\n";
			if (HTTP->nRequests != 0)
				cout << "  [+] 1st Request: " << (char*)HTTP->Requests[0].Address->GetChar() << "\n";
			cout << "  [+] UserAgent: " << HTTP->UserAgent->GetChar() << "\n";
			cout << "  [+] Referer: " << (char*)HTTP->Referer->GetChar() << "\n";
			cout << "\n";
		
		}
	}

	system("PAUSE"); 
	return 0;
}

