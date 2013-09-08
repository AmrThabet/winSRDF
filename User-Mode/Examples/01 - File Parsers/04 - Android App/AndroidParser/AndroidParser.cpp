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
#include <Windows.h>
#include <stdio.h>
#include "../../../../SRDF.h"

using namespace Security::Targets::Files;

int _tmain(int argc, TCHAR* argv[])
{
	//printf("Dedroid Apk parser:\n\tusage: dedroid.exe [apkfile]\n");

	cAndroidFile android("HelloWorld.apk");
	if (android.isReady)
	{
		cFile** tmp = android.DecompressResourceFiles();
		printf("DexFile Loaded at 0x%08x with size %d bytes\n\n", android.DexBuffer, android.DexBufferSize);

		printf("= Strings ==========\n");
		for (UINT i=0; i<android.nStringItems; i++)
			printf("%s\n", android.StringItems[i].Data);

		
		printf(	"Total String Items: \t%d\n"
				"      Type Descripters \t%d\n"
				"      Method Items \t%d\n"
				"      Field Items \t%d\n"
				"      Prototype Items \t%d\n", 
				android.nStringIDs,
				android.nTypeIDs,
				android.nMethodIDs,
				android.nFieldIDs,
				android.nPrototypeIDs);

		system("pause");

		printf("\n= ResourceFiles ======\n\n");
		for (UINT i=0; i<android.nResourceFiles; i++)
			printf("%s\n", android.ResourceFiles[i]);//*/

		system("pause");

		printf("\n= Field Items ======\n\n");
		for (UINT i=0; i<android.nFieldIDs; i++)
			printf("%s\n", android.StringItems[android.DexFieldIds[i].StringIndex].Data);

		system("pause");

		printf("\n= Type Descripters =\n\n");
		for (UINT i=0; i<android.nTypeIDs; i++)
			printf("%s\n", android.StringItems[android.DexTypeIds[i].StringIndex].Data);

		system("pause");

		printf("\n= Method Items =====\n\n");
		for (UINT i=0; i<android.nMethodIDs; i++)
			printf("%s\n", android.StringItems[android.DexMethodIds[i].StringIndex].Data);

		system("pause");

		printf("\n= Prototype Items ==\n\n");
		for (UINT i=0; i<android.nPrototypeIDs; i++)
			printf("%s\n", android.StringItems[android.DexProtoIds[i].StringIndex].Data);

		system("pause");


		for (UINT i=0; i<android.nClassDefinitions; i++)
		{
			printf("%s\n", android.StringItems[android.DexClassDefs[i].sourceFileIdx].Data);
			printf("\nClass #%d:\n" 
				"\tClass Descriptor: '%s'\n"	"\tAccess Flags: 0x%04x\n"
				"\tSuper Class: '%s'\n"			"\tSource File: '%s'\n\n",
				i, android.DexClasses[i].Descriptor,
				android.DexClasses[i].AccessFlags, android.DexClasses[i].SuperClass,
				android.DexClasses[i].SourceFile);

			printf("\tStatic Fields: %d\n", android.DexClasses[i].ClassData->StaticFieldsSize);
			for (UINT j=0; j< android.DexClasses[i].ClassData->StaticFieldsSize; j++)
			{
				printf("\t#%d\n", j);
				printf("\t\tName: '%s'\n", android.DexClasses[i].ClassData->StaticFields[j].Name);
				printf("\t\tType: '%s'\n", android.DexClasses[i].ClassData->StaticFields[j].Type);
				printf("\t\tAccess: 0x%x\n", android.DexClasses[i].ClassData->StaticFields[j].AccessFlags);
			}

			printf("\n\tInstance Fields: %d\n", android.DexClasses[i].ClassData->InstanceFieldsSize);
			for (UINT j=0; j< android.DexClasses[i].ClassData->InstanceFieldsSize; j++)
			{
				printf("\t#%d\n", j);
				printf("\t\tName: '%s'\n", android.DexClasses[i].ClassData->InstanceFields[j].Name);
				printf("\t\tType: '%s'\n", android.DexClasses[i].ClassData->InstanceFields[j].Type);
				printf("\t\tAccess: 0x%x\n", android.DexClasses[i].ClassData->InstanceFields[j].AccessFlags);
			}

			printf("\n\tDirect Methods: %d\n", android.DexClasses[i].ClassData->DirectMethodsSize);
			for (UINT j=0; j< android.DexClasses[i].ClassData->DirectMethodsSize; j++)
			{
				printf("\t#%d\n", j);
				printf("\t\tName: '%s'\n", android.DexClasses[i].ClassData->DirectMethods[j].Name);
				printf("\t\tType: '%s'\n", android.DexClasses[i].ClassData->DirectMethods[j].ProtoType);
				printf("\t\tAccess: 0x%x\n", android.DexClasses[i].ClassData->DirectMethods[j].AccessFlags);
			}

			printf("\n\tVirtual Methods: %d\n", android.DexClasses[i].ClassData->VirtualMethodsSize);
			for (UINT j=0; j< android.DexClasses[i].ClassData->VirtualMethodsSize; j++)
			{
				printf("\t#%d\n", j);
				printf("\t\tName: '%s'\n", android.DexClasses[i].ClassData->VirtualMethods[j].Name);
				printf("\t\tType: '%s'\n", android.DexClasses[i].ClassData->VirtualMethods[j].ProtoType);
				printf("\t\tAccess: 0x%x\n", android.DexClasses[i].ClassData->VirtualMethods[j].AccessFlags);
			}
		}
	}
	else 
		cout << "Unable to load your APK file\n";

	return 0;
}

