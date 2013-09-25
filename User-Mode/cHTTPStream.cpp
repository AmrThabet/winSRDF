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
#include <iostream>
#include "SRDF.h"
#include <string>
#include <fstream>

using namespace std;
using namespace std::tr1;
using namespace Security::Targets::Packets;
using namespace Security::Targets::Files;

const CHAR head[][5] = {"GET", "POST", "HEAD", "HTTP"};

cHTTPStream::cHTTPStream()
{
	nCookies = 0;
	Cookies = (cString**)malloc(nCookies * sizeof(cString*));

	UserAgent = NULL;
	Referer = NULL;
	ServerType = NULL;

	Files = (cFile**)malloc(nFiles * sizeof(cFile*));
	nFiles = 0;

	nRequests = 0;
	Requests = (REQUEST*)malloc(nRequests * sizeof(REQUEST)); 

	Reassembler = NULL;
};

BOOL cHTTPStream::Identify(cPacket* Packet)
{
	if (!Packet->isTCPPacket) return FALSE;
	if (ntohs(Packet->TCPHeader->DestinationPort) != 80 && ntohs(Packet->TCPHeader->SourcePort) != 80) return FALSE;
	return TRUE;
}

BOOL cHTTPStream::CheckPacket(cPacket* Packet) { return Identify(Packet); }

void cHTTPStream::AnalyzeProtocol()
{
	if (Packets[nPackets - 1]->TCPDataSize > 0 && 
		(CheckType(Packets[nPackets - 1]->TCPData) ||
		Reassembler != NULL))
	{
		RegxData = (CHAR*)Packets[nPackets - 1]->TCPData;
		RegxDataSize = Packets[nPackets - 1]->TCPDataSize;

		ExtractFile(Packets[nPackets - 1]);
	}	else return;
		
	if (CheckType(Packets[nPackets - 1]->TCPData))
	{
		/* check new cookies */
		if (regex_search(RegxData, RegxResult, regex("Set-Cookie:\\s(.*?)\\r\\n")))
		{
			Cookie = new cString(RegxResult[1].str().c_str());
			Cookies = (cString**)realloc(Cookies, (nCookies + 1) * sizeof(cString*));
			memcpy(&Cookies[nCookies], &Cookie, sizeof(cString*));
			nCookies++;
		}
		
		/* get user-agent */
		if (UserAgent == NULL && regex_search(RegxData, RegxResult, regex("User-Agent:\\s(.*?)\\r\\n")))
			UserAgent = new cString(RegxResult[1].str().c_str());

		/* get server */
		if (ServerType == NULL && regex_search(RegxData, RegxResult, regex("Server:\\s(.*?)\\r\\n")))
			ServerType = new cString(RegxResult[1].str().c_str());

		/* get referer */
		if (Referer == NULL && regex_search(RegxData, RegxResult, regex("Referer:\\s(.*?)\\r\\n")))
			Referer = new cString(RegxResult[1].str().c_str());
	}
	
	/* check requests */
	if (regex_search(RegxData, RegxResult, regex("GET\\s(.*?)\\s(.*?)\\r\\n")) ||
		regex_search(RegxData, RegxResult, regex("POST\\s(.*?)\\s(.*?)\\r\\n")))
	{
		nRequests ++;
		Requests = (REQUEST*)realloc(Requests, nRequests * sizeof(REQUEST));
		memset(&Requests[nRequests - 1], 0, sizeof(REQUEST)); 

		Requests[nRequests - 1].Address = new cString(RegxResult[1].str().c_str());
		Requests[nRequests - 1].Arguments = new cHash();

		ArgumentBuffer = NULL;

		/* parse for get */
		if (memcmp(RegxResult[0].str().c_str(), &head[0], strlen((const char*)head[0])) == 0)
		{
			Requests[nRequests-1].RequestType = (UCHAR*)(head[0]);
			
			/* parse arguments */
			main = strtok(Requests[nRequests-1].Address->GetChar(),"?");
			main = strtok(NULL,"?");	
			ArgumentBuffer = strtok(main,"&");
		}

		/* parse for post */
		else if (memcmp(RegxResult[0].str().c_str(), &head[1], strlen((const char*)head[1])) == 0)
		{
			Requests[nRequests-1].RequestType = (UCHAR*)(head[1]);
			
			if (regex_search(RegxData, RegxResult, regex("Content-Type:\\s(.*?)\\r\\n")) &&
				RegxResult[1].str().find("application/x-www-form-urlencoded") != string::npos &&
				string(RegxData).find("Content-Length:") != string::npos &&
				regex_search(RegxData, RegxResult, regex("Content-Length:\\s(.*?)\\r\\n")))
			{
				content_length = atoi(RegxResult[1].str().c_str());
				ArgumentBuffer = (CHAR*)(RegxData) + RegxDataSize - content_length;
			}
		}
	
		while (ArgumentBuffer != NULL)
		{
			pos = string(ArgumentBuffer).find("=");
			if (pos != string::npos)
				Requests[nRequests - 1].Arguments->AddItem(cString(string(ArgumentBuffer).erase(pos, string(ArgumentBuffer).size() - pos).c_str()), cString(string(ArgumentBuffer + pos + 1).c_str()));
			else
				Requests[nRequests - 1].Arguments->AddItem(cString(string(ArgumentBuffer).c_str()), cString("None"));
			ArgumentBuffer = strtok (NULL, "&");
		}
	}

	RegxResult.empty();
}

void cHTTPStream::ExtractFile(cPacket* Packet)
{
	if (!NeedsReassembly(Packets[nPackets - 1], &length))
	{
		if (Reassembler != NULL &&
			/*Reassembler->BelongsToStream(Packets[nPackets - 1]) &&*/
			Reassembler->AddPacket(Packets[nPackets - 1]) &&
			Reassembler->isReassembled)
		{
			Files = (cFile**)realloc(Files, (nFiles + 1) * sizeof(cFile*));
			ExtFile = new cFile((CHAR*)Reassembler->GetReassembledStream(), Reassembler->TotalSize);
			ExtFile->IsReassembled = TRUE;
			memcpy(&Files[nFiles], &ExtFile, sizeof(cFile*));
			nFiles++;

			delete Reassembler;
			Reassembler = NULL;
		}
		else if (regex_search(RegxData, RegxResult, regex("Content-Type:\\s(.*?)\\r\\n")) &&
			RegxResult[1].str().find("application/x-javascript") == string::npos &&
			RegxResult[1].str().find("text/css") == string::npos &&
			RegxResult[1].str().find("text/javascript") == string::npos &&
			RegxResult[1].str().find("text/html") == string::npos &&
			regex_search(RegxData, RegxResult, regex("Content-Length:\\s(.*?)\\r\\n")))
		{
			length = atoi(RegxResult[1].str().c_str());

			if (length > 0) {
				Files = (cFile**)realloc(Files, (nFiles + 1) * sizeof(cFile*));
				ExtFile = new cFile((CHAR*)Packets[nPackets-1]->TCPData[Packets[nPackets-1]->TCPDataSize-length], length);
				memcpy(&Files[nFiles], &ExtFile, sizeof(cFile*));
				nFiles++;
			}
		}
	}
	else 
	{
		if (Reassembler == NULL) 
			Reassembler = new cTCPReassembler(Packets[nPackets - 1], length, Packets[nPackets - 1]->TCPDataSize - TmpHTTPBodySize);
	}
}

cHTTPStream::~cHTTPStream() 
{
	if (Cookies != NULL) {
		for (i=0; i<nCookies; i++)
			delete Cookies[i];
		free(Cookies);
	}

	if (Requests != NULL) {
		for (i=0; i<nRequests; i++) {
			delete Requests[i].Address;
			delete Requests[i].Arguments;
		}
		free(Requests);
	}

	if (Files != NULL) {
		for (i=0; i<nFiles; i++)
			delete Files[i];
		free(Files);
	}

	if (UserAgent != NULL)
		delete UserAgent;

	if (Referer != NULL)
		delete Referer;

	if (ServerType != NULL)
		delete ServerType;

	if (Reassembler != NULL)
		delete Reassembler;
};

BOOL cHTTPStream::CheckType(UCHAR* buffer)
{
	for (UINT i=0; i< ARRAYSIZE(head); i++)
		if ( memcmp(buffer, &head[i], strlen((const char*)head[i])) == 0) 
			return TRUE;

	return FALSE;
}

BOOL cHTTPStream::NeedsReassembly(cPacket* Packet, UINT* ContentLength)
{
	*ContentLength = 0;
	if (regex_search(
			(CHAR*)Packet->TCPData, 
			TmpRegxResult, 
			regex("Content-Length:\\s(.*?)\\r\\n")) &&
			GetHttpHeader(Packet, &TmpHTTPBodySize) != NULL &&
			TmpHTTPBodySize != NULL) 
	{
		TmpContentLength = atoi(TmpRegxResult[1].str().c_str());
		length = Packet->TCPDataSize - TmpHTTPBodySize;
		if (TmpContentLength > length) {
			*ContentLength = TmpContentLength;
			return TRUE;
		}
		else return FALSE;
	}
	else return false;
}

UCHAR* cHTTPStream::GetHttpHeader(cPacket* Packet, UINT *EndPos)
{
	*EndPos = string((CHAR*)Packet->TCPData).find("\r\n\r\n");
	if (*EndPos == string::npos)
	{
		*EndPos = NULL;
		return NULL;
	}

	*EndPos += 4;
	return Packet->TCPData;
}