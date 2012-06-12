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