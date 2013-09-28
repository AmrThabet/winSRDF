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
	cPcapFile* Pcap = new cPcapFile("http.pcap");
	if (!Pcap->IsFound())
	{
		cout << "Unable to Open File\n";
		return 0;
	}
	cout << "Number of Sessions: " << Pcap->Traffic->nConnections << "\n\n";
	for (int i = 0; i < Pcap->Traffic->nConnections;i++)
	{
		if (Pcap->Traffic->Connections[i]->Packets[0]->isUDPPacket)
		{
			//Check if it's a DNS Connection
			cUDPStream* UDP =  (cUDPStream*)Pcap->Traffic->Connections[i];
			if (UDP->ServerPort == 53)
			{
				cDNSStream* DNS = (cDNSStream*)Pcap->Traffic->Connections[i];
				cout << "Found DNS Stream No." << i << "\n";
				cout << "\t[+] DNS Query: " << DNS->RequestedDomain << "\n";
				cout << "\t[+] Resolved IP (1st IP): " << PrintIP(DNS->ResolvedIPs[0]) << "\n";
				cout << "\n";
			}
		}
		if (Pcap->Traffic->Connections[i]->Packets[0]->isTCPPacket)
		{
			cTCPStream* TCP =  (cTCPStream*)Pcap->Traffic->Connections[i];
			if (TCP->ServerPort == 80)
			{
				cHTTPStream* HTTP = (cHTTPStream*)Pcap->Traffic->Connections[i];
				cout << "Found HTTP Stream No." << i << "\n";
				cout << "\t[+] Server IP: " << PrintIP(HTTP->ServerIP) << "\n";
				cout << "\t{+] Number of Requests: " << HTTP->nRequests << "\n";
				cout << HTTP->Requests[0].Arguments->GetNumberOfItems() << "\n";
				for (int l = 0; l < HTTP->Requests[0].Arguments->GetNumberOfItems();l++)
				{
					cout << "\t\t" << HTTP->Requests[0].Arguments->GetKey(l) << "\t" << HTTP->Requests[0].Arguments->GetValue(l) << "\n";
				}
				if (HTTP->nRequests != 0 && HTTP->Requests[0].Arguments->GetNumberOfItems() != 0)
					cout << "\t[+] 1st Request: " << (char*)HTTP->Requests[0].Arguments->GetValue("url") << "\n";
				cout << "\t[+] UserAgent: " << (char*)HTTP->UserAgent << "\n";
				cout << "\t[+] Referer: " << (char*)HTTP->Referer << "\n";
				cout << "\n";
			}
		}
	}
	return 0;
}

