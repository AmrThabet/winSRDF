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
#include "../../../../SRDF.h"

using namespace Security::Targets::Files;

int _tmain(int argc, _TCHAR* argv[])
{
	cELFFile *file = new cELFFile("ls");

	if (!file->FileLoaded) 
	{
		cout << "File can't be loaded\n";
		return 0;
	}
	cout << endl << "Sections: " << file->nSections << endl << endl;

	for (UINT j=0; j<file->nSections; j++)
	{
		cout << "\t" << file->Sections[j].Name << "\t" << (PDWORD)file->Sections[j].Offset << endl;
	}

	cout << endl << "Imports: " << file->nImports << endl << endl;

	for (UINT i=0; i<file->nImports; i++)
	{
		DWORD t = file->Imports[i].Value;
			cout << "\t" << file->Imports[i].Name << endl;
	}

	cout << endl << "Symbols: " << file->nSymbols << endl << endl;

	for (UINT k=0; k<file->nSymbols; k++)
	{
		cout << "\t" << (PDWORD)file->Symbols[k].Address << "\t" << file->Symbols[k].Name << endl;
	}

	return 0;
}

