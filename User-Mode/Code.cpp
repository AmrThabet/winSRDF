/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet <amr.thabet@student.alx.edu.eg>
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
 *  along with this program; if not, write to Amr Thabet
 *  amr.thabet[at]student.alx.edu.eg
 *
 */
#include "stdafx.h"
#include "SRDF.h"

using namespace Security::Elements::Code;

typedef int (*StoredProcedureAPI)(void* UserData);

cStoredProcedure::cStoredProcedure(cString Name,cString Discription,cString Author,cString DLLName,cString APIName)
{
	this->Name = Name;
	this->Discription = Discription;
	this->Author = Author;
	this->DLLName = DLLName;
	this->APIName = APIName;
}

void cStoredProcedure::Run(void* UserData)
{
	HMODULE DLL;
	StoredProcedureAPI API;
	DLL = LoadLibraryA((LPCSTR)DLLName.GetChar());

	if(DLL != NULL)
	{
		API = (StoredProcedureAPI)GetProcAddress(DLL,(LPCSTR)APIName.GetChar());
		(*API)(UserData);
	}
}

void cStoredProcedure::SetSerialize(cXMLHash& XMLParams)
{
	XMLParams.AddText("Name",Name);
	XMLParams.AddText("Discription",Discription);
	XMLParams.AddText("Author",Author);
	XMLParams.AddText("DLLName",DLLName);
	XMLParams.AddText("APIName",APIName);
}

void cStoredProcedure::GetSerialize(cXMLHash& XMLParams)
{
	Name = XMLParams.GetText("Name");
	Discription = XMLParams.GetText("Discription");
	Author = XMLParams.GetText("Author");
	DLLName = XMLParams.GetText("DLLName");
	APIName = XMLParams.GetText("APIName");
}

void cNativeCode::SetSerialize(cXMLHash& XMLParams)
{

}
void cNativeCode::GetSerialize(cXMLHash& XMLParams)
{

}