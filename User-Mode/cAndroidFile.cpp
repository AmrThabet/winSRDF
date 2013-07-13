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
#include <stdio.h>
#include <string>
#include <regex>

using namespace std;
using namespace Security::Targets::Files;

UINT NO_INDEX = 0xffffffff; 

cAndroidFile::cAndroidFile(CHAR* ApkFilename) : cFile(ApkFilename)
{
	this->ApkFilename = ApkFilename;
	DexBuffer = NULL;
	isReady = ProcessApk();
}

BOOL cAndroidFile::ProcessApk()
{
	if (Decompress() < 0) return FALSE;

	if (DexBuffer == NULL ||
	DexBufferSize < sizeof(DEX_HEADER)) 
	return FALSE;

	return ParseDex();
}

BOOL cAndroidFile::ParseDex()
{
	UCHAR* BufPtr;
	DexHeader = (DEX_HEADER*)DexBuffer;

	//check for magic code for opt header
	if (memcmp(DexHeader->magic, DEX_MAGIC, 4) != 0)
		return FALSE;

	memcpy_s((UCHAR*)DexVersion, 4, (UCHAR*)DexHeader->magic + 4, 4);

	if (DexBufferSize != DexHeader->fileSize)
		return FALSE;

	/* Start String Items */
	nStringIDs = DexHeader->stringIdsSize;
	nStringItems = nStringIDs;
	DexStringIds = (DEX_STRING_ID*)(DexBuffer + DexHeader->stringIdsOff);
	StringItems = (DEX_STRING_ITEM*)malloc(nStringItems * sizeof(DEX_STRING_ITEM));

	for (UINT i=0; i<nStringIDs; i++)
	{
		BufPtr = (UCHAR*)DexBuffer + DexStringIds[i].stringDataOff;
		StringItems[i].StringSize = ReadUnsignedLeb128((const UCHAR**)&BufPtr);
		StringItems[i].Data = BufPtr;
	}
	/* End String Items */

	/* Start Field IDs */
	nFieldIDs = DexHeader->fieldIdsSize;
	DexFieldIds = (DEX_FIELD_ID*)(DexBuffer + DexHeader->fieldIdsOff);
	/* End Field IDs */

	/* Start Type IDs */
	nTypeIDs = DexHeader->typeIdsSize;
	DexTypeIds = (DEX_TYPE_ID*)(DexBuffer + DexHeader->typeIdsOff);
	/* End Type IDs */

	/* Start Method IDs */
	nMethodIDs = DexHeader->methodIdsSize;
	DexMethodIds = (DEX_METHOD_ID*)(DexBuffer + DexHeader->methodIdsOff);
	/* End Method IDs */

	/* Start Prototype IDs */
	nPrototypeIDs = DexHeader->protoIdsSize;
	DexProtoIds = (DEX_PROTO_ID*)(DexBuffer + DexHeader->protoIdsOff);
	/* End Prototype IDs */

	/* Start Class Definitions */
	nClassDefinitions = DexHeader->classDefsSize;
	nClasses = nClassDefinitions;

	DexClasses = (DEX_CLASS_STRUCTURE*)malloc(nClasses * sizeof(DEX_CLASS_STRUCTURE));
	DexClassDefs = (DEX_CLASS_DEF*)(DexBuffer + DexHeader->classDefsOff);

	for (UINT i=0; i<nClasses; i++)
	{
		DexClasses[i].Descriptor = StringItems[DexTypeIds[DexClassDefs[i].classIdx].StringIndex].Data;
		DexClasses[i].AccessFlags = DexClassDefs[i].accessFlags;
		DexClasses[i].SuperClass = StringItems[DexTypeIds[DexClassDefs[i].superclassIdx].StringIndex].Data;

		if (DexClassDefs[i].sourceFileIdx != NO_INDEX)
			DexClasses[i].SourceFile = StringItems[DexClassDefs[i].sourceFileIdx].Data;
		else
			DexClasses[i].SourceFile = (UCHAR*)"No Information Found";

		if (DexClassDefs[i].classDataOff != NULL)
		{
			DexClasses[i].ClassData = new DEX_CLASS_STRUCTURE::CLASS_DATA;
			DexClassData = (DEX_CLASS_DATA*)(DexBuffer + DexClassDefs[i].classDataOff);

			BufPtr = (UCHAR*)DexClassData;

			DexClasses[i].ClassData->StaticFieldsSize = ReadUnsignedLeb128((const UCHAR**)&BufPtr);
			DexClasses[i].ClassData->InstanceFieldsSize = ReadUnsignedLeb128((const UCHAR**)&BufPtr);
			DexClasses[i].ClassData->DirectMethodsSize = ReadUnsignedLeb128((const UCHAR**)&BufPtr);	
			DexClasses[i].ClassData->VirtualMethodsSize = ReadUnsignedLeb128((const UCHAR**)&BufPtr);

			DexClasses[i].ClassData->StaticFields = 
				new DEX_CLASS_STRUCTURE::CLASS_DATA::CLASS_FIELD[DexClasses[i].ClassData->StaticFieldsSize];
			DexClasses[i].ClassData->InstanceFields = 
				new DEX_CLASS_STRUCTURE::CLASS_DATA::CLASS_FIELD[DexClasses[i].ClassData->InstanceFieldsSize];
			DexClasses[i].ClassData->DirectMethods = 
				new DEX_CLASS_STRUCTURE::CLASS_DATA::CLASS_METHOD[DexClasses[i].ClassData->DirectMethodsSize];
			DexClasses[i].ClassData->VirtualMethods = 
				new DEX_CLASS_STRUCTURE::CLASS_DATA::CLASS_METHOD[DexClasses[i].ClassData->VirtualMethodsSize];

			UINT CurIndex = 0;

			for (UINT j=0; j<DexClasses[i].ClassData->StaticFieldsSize; j++)
			{	
				CurIndex += ReadUnsignedLeb128((const UCHAR**)&BufPtr);
				DexClasses[i].ClassData->StaticFields[j].Type = StringItems[DexTypeIds[ DexFieldIds[CurIndex].TypeIdex ].StringIndex].Data;
				DexClasses[i].ClassData->StaticFields[j].Name = StringItems[DexFieldIds[CurIndex].StringIndex].Data;
				DexClasses[i].ClassData->StaticFields[j].AccessFlags = ReadUnsignedLeb128((const UCHAR**)&BufPtr);
			}

			CurIndex = 0;
			for (UINT j=0; j<DexClasses[i].ClassData->InstanceFieldsSize; j++)
			{
				CurIndex += ReadUnsignedLeb128((const UCHAR**)&BufPtr);
				DexClasses[i].ClassData->InstanceFields[j].Type = StringItems[DexTypeIds[DexFieldIds[CurIndex].TypeIdex].StringIndex].Data;
				DexClasses[i].ClassData->InstanceFields[j].Name = StringItems[DexFieldIds[CurIndex].StringIndex].Data;
				DexClasses[i].ClassData->InstanceFields[j].AccessFlags = ReadUnsignedLeb128((const UCHAR**)&BufPtr);
			}

			CurIndex = 0;
			for (UINT j=0; j<DexClasses[i].ClassData->DirectMethodsSize; j++)
			{
				CurIndex += ReadUnsignedLeb128((const UCHAR**)&BufPtr);
				DexClasses[i].ClassData->DirectMethods[j].ProtoType = 
					StringItems[DexTypeIds[DexProtoIds[DexMethodIds[CurIndex].PrototypeIndex].returnTypeIdx].StringIndex].Data;

				//DexClasses[i].ClassData->DirectMethods[j].Type = StringItems[DexTypeIds[DexMethodIds[CurIndex].ClassIndex].StringIndex].Data;
				DexClasses[i].ClassData->DirectMethods[j].Name = StringItems[DexMethodIds[CurIndex].StringIndex].Data;
				DexClasses[i].ClassData->DirectMethods[j].AccessFlags = ReadUnsignedLeb128((const UCHAR**)&BufPtr);

				UINT code_offset = ReadUnsignedLeb128((const UCHAR**)&BufPtr);
				if (code_offset == NULL)
					DexClasses[i].ClassData->DirectMethods[j].CodeArea = NULL;
				else
					GetCodeArea(DexClasses[i].ClassData->DirectMethods[j].CodeArea, code_offset);

			}

			CurIndex = 0;
			for (UINT j=0; j<DexClasses[i].ClassData->VirtualMethodsSize; j++)
			{
				CurIndex += ReadUnsignedLeb128((const UCHAR**)&BufPtr);
				DexClasses[i].ClassData->VirtualMethods[j].ProtoType = 
					StringItems[DexTypeIds[DexProtoIds[DexMethodIds[CurIndex].PrototypeIndex].returnTypeIdx].StringIndex].Data;

				//DexClasses[i].ClassData->VirtualMethods[j].Type = 
				//	StringItems[DexProtoIds[DexMethodIds[CurIndex].PrototypeIndex].StringIndex].Data;

				DexClasses[i].ClassData->VirtualMethods[j].Name = StringItems[DexMethodIds[CurIndex].StringIndex].Data;
				DexClasses[i].ClassData->VirtualMethods[j].AccessFlags = ReadUnsignedLeb128((const UCHAR**)&BufPtr);

				UINT code_offset = ReadUnsignedLeb128((const UCHAR**)&BufPtr);
				if (code_offset == NULL)
					DexClasses[i].ClassData->VirtualMethods[j].CodeArea = NULL;
				else
					GetCodeArea(DexClasses[i].ClassData->VirtualMethods[j].CodeArea, code_offset);
			}
		}
	}

	/* End Class Definitions */

	return TRUE;
}

long cAndroidFile::Decompress()
{
	string str;
	tr1::regex rx("res/");
	nResourceFiles = 0;
	ResourceFiles = (UCHAR**)malloc( nResourceFiles * sizeof(UCHAR*));

	ZipHandler = OpenZip((PVOID)BaseAddress, FileLength, 0);

	ZIPENTRY ArchieveEntry;
	INT ZipItemIndex;

	FindZipItem(ZipHandler, "classes.dex", true, &ZipItemIndex, &ArchieveEntry);

	DexBufferSize = ArchieveEntry.unc_size;
	DexBuffer = new char[DexBufferSize];
	UnzipItem(ZipHandler, ZipItemIndex, DexBuffer, DexBufferSize);

	GetZipItem(ZipHandler, -1, &ArchieveEntry); 
	UINT numitems=ArchieveEntry.index;

	for (UINT i=0; i<numitems; i++)
	{ 
		GetZipItem(ZipHandler, i, &ArchieveEntry);
		str = ArchieveEntry.name;
		if (regex_match(str.begin(), str.begin() + 4, rx))
		{
			nResourceFiles++;
			ResourceFiles = (UCHAR**)realloc(ResourceFiles, nResourceFiles * sizeof(UCHAR*));
			ResourceFiles[nResourceFiles-1] = new UCHAR[str.length()];
			memset(ResourceFiles[nResourceFiles-1], 0, str.length());
			int len = str.length();
			memcpy_s(ResourceFiles[nResourceFiles-1], str.length(), &ArchieveEntry.name, str.length());
		}
		
	}
	
	return DexBufferSize;
}

cAndroidFile::~cAndroidFile()
{
	CloseZip(ZipHandler);

	if (isReady)
	{
		free(StringItems);
		delete DexBuffer;

		for (UINT i=0; i<nResourceFiles; i++)
			delete ResourceFiles[i];

		free(ResourceFiles);
	}

}

INT cAndroidFile::ReadUnsignedLeb128(const UCHAR** pStream) 
{
    const UCHAR* ptr = *pStream;
    int result = *(ptr++);

    if (result > 0x7f) 
	{
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) 
		{
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) 
			{
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) 
				{
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }

    *pStream = ptr;
    return result;
};

void cAndroidFile::GetCodeArea(DEX_CLASS_STRUCTURE::CLASS_DATA::CLASS_METHOD::CLASS_CODE *
						   CodeArea, UINT Offset)
{
	CodeArea =  new DEX_CLASS_STRUCTURE::CLASS_DATA::CLASS_METHOD::CLASS_CODE;
	DexCode = (DEX_CODE*)(DexBuffer + Offset);
};

cFile**	cAndroidFile::DecompressResourceFiles(/*INT Index*/)
{
	ZIPENTRY ArchieveEntry;
	INT ZipItemIndex;
	UINT BufferSize;
	CHAR* Buffer;
	cFile**	ResFiles;

	ResFiles = new cFile*[nResourceFiles];
	for (UINT i=0; i<nResourceFiles; i++)
	{
		memset(&ArchieveEntry, 0, sizeof(ZIPENTRY));

		FindZipItem(ZipHandler, (const TCHAR*)ResourceFiles[i], TRUE, &ZipItemIndex, &ArchieveEntry);
		BufferSize = ArchieveEntry.unc_size;
		Buffer = new CHAR[DexBufferSize];
		UnzipItem(ZipHandler, ZipItemIndex, Buffer, BufferSize);
		ResFiles[i] = new cFile(Buffer, BufferSize);
	}

	return ResFiles;
}