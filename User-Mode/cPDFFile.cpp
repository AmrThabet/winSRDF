/*
 *
 *  Copyright (C) 2012-2013 Ibrahim Mossad and Amr Thabet 
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
#include <cstdlib>
#include "SRDF.h"
#include <iostream>

#ifdef UNICODE
#define DefWindowProc  DefWindowProcW
#else
#define DefWindowProc  DefWindowProcA
#endif // !UNICODE

using namespace std;
using namespace Security::Targets::Files;


cPDFFile::cPDFFile(char* szFilename) : cFile(szFilename)
{
	FileLoaded = false;
	if (identify(this))
		FileLoaded = ParsePDF();
}

cPDFFile::cPDFFile(char* buffer,DWORD size) : cFile(buffer,size)
{
	FileLoaded = ParsePDF();
}
bool cPDFFile::identify(cFile* File)
{
	if (File->IsFound() == false) return false;
	if (File->BaseAddress == NULL) return false;
	if(strcmp((char*)File->BaseAddress,"%PDF") < 0) return false;
	return true;
}
bool cPDFFile::ParsePDF()
{
	if(strcmp((char*)BaseAddress,"%PDF") < 0) return false;

	if(get_version_pdf() && get_xref_table() && get_trailer_pdf() && get_objects_from_xref())
    {
        return true;
    }
	return false;
}

DWORD cPDFFile::getline(DWORD NewAddress, string& line)
{

	char* addr = (char*)NewAddress;
	DWORD FileSize = FileLength + (NewAddress - BaseAddress);
	for (int i = 0;i < FileSize; i++)
	{
		if (addr[i] == '\n')
		{
			char* x = (char*)malloc(i+1);
			memset(x,0,i+1);
			memcpy(x,addr,i);
			line = x;
			free(x);
			return (DWORD)&addr[i+1];
		}
	}
	char* x = (char*)malloc(FileSize);
	memset(x,0,FileSize);
	memcpy(x,addr,FileSize);
	line = x;
	free(x);
	return (DWORD)&addr[FileSize];
}
DWORD cPDFFile::GetValue(char* Addr, string& Value)
{
	DWORD Size = FileLength + ((DWORD)Addr - BaseAddress);
	//First .. trim
	for (int i = 0; i < Size; i++)
	{
		if (Addr[i] == ' ' || Addr[i] == '\n') continue;
		else
		{
			Addr += i;
			Size -= i;
			break;
		}
	}
	//Get the Value;
	for (int i = 0; i < Size; i++)
	{
		if (Addr[i] == ' ' || Addr[i] == '\n')
		{
			char* num = (char*)malloc(i+1);
			memset(num,0,i+1);
			memcpy(num,Addr,i);
			Value = num;
			free(num);
			return (DWORD)&Addr[i + 1];
		}
	}
	return (DWORD)(Addr + Size);
}

bool cPDFFile::get_version_pdf()
{
    string line ;
	getline(BaseAddress,line);
    line = line.substr(1,line.length());
    FileVersion = line;
    return true;
}

bool cPDFFile::get_objects_pdf()
{
    string line;
    regex obj_start ("(\\d*)(\\s*)(\\d*)(\\s*)(obj)(\\s*)(%.*)?"); // to check the object start
    regex obj_end ("(\\s*)(endobj)(\\s*)(%.*)?"); // check the end of object
    regex obj_start_seperator ("(\\s*)(<<)(\\s*)((%.*)?)");
    regex obj_end_seperator("(\\s*)(>>)(\\s*)((%.*)?)");
    vector<string> obj;
	DWORD Addr = BaseAddress;
    while (Addr < BaseAddress + FileLength)
    {
		Addr = getline(Addr, line);	//set it to the next line
        if(regex_match(line, obj_start)) // then it is obj
        {
            obj.push_back(line);
            Addr = getline(Addr, line);
            while((regex_match(line, obj_start_seperator)))
            {
                do
                {
                    obj.push_back(line); // push the content of the object
                    Addr = getline(Addr, line);
                }
                while(!regex_match(line, obj_end_seperator)); //object is closed
                   
                {
                    //To-do check that it is not EOF
                    obj.push_back(line);
                    do {
                        Addr = getline(Addr, line);
                        obj.push_back(line);    
                    }
                    while(!regex_match(line, obj_end));
                }
            }
        }
    
        objects = obj;
        return true;
	}
	return false;
}


bool cPDFFile::get_stream(DWORD& Addr, vector<string> &stream)
{
    regex streamEnd ("(.)?(endstream)(.)?(%.*)?");
    string line = "";
    Addr = getline(Addr, line);
    while(!regex_match(line, streamEnd) && Addr < (BaseAddress + FileLength))
    {
        stream.push_back(line);
        Addr = getline(Addr, line);
    }
    if(regex_match(line, streamEnd))
    {
        stream.push_back(line);
        
        return true;
    }
    else
    {
        return false; //can't find the end of the stream !!
    }
    

}


bool cPDFFile::get_object(int offset, object &o)
{
    string line;
    o.offset = offset;

    regex obj_start ("(\\d*)(\\s*)(\\d*)(\\s*)(obj)(\\s*)(%.*)?"); // to check the object start
    regex obj_end ("(\\s*)(endobj)(\\s*)(%.*)?"); // check the end of object
    regex obj_start_seperator ("(\\s*)(.)*(<<)(.)*(\\s*)((%.*)?)");
    regex obj_end_seperator("(\\s*)(.)*(>>)(.)*(\\s*)((%.*)?)");
    regex streamStart ("(.)*(stream)(.)*(%.*)?");
    regex streamEnd ("(.)*(endstream)(.)*(%.*)?");
    vector<string> obj;
    vector<string> Stream;

	DWORD Addr = BaseAddress + offset;
    Addr = getline(Addr, line);
    if(regex_match(line, obj_start)) // then it is obj
    {
        obj.push_back(line);
        Addr = getline(Addr, line);
        if((regex_match(line, obj_start_seperator)))
        {
            do
            {
                obj.push_back(line); // push the content of the object
                Addr = getline(Addr, line);
            }
            while(!regex_match(line, obj_end_seperator) && (!regex_match(line, streamStart))); //object is closed
                
                
                //To-do check that it is not EOF
                
               
                if(regex_match(line, streamStart)) // if it is stream  then get it 
                {
                        
                    Stream.push_back(line);
                    get_stream(Addr, Stream);
                        
                    do {
                            
                        Addr = getline(Addr, line);
                        obj.push_back(line);
                            
                    }
                    while(!regex_match(line, obj_end));
                    //obj.push_back(line);
                }
            else
            {
                do {
                    obj.push_back(line);
                    Addr = getline(Addr, line);
                        
                }while(!regex_match(line, obj_end) && (!regex_match(line, streamStart)));
                    
                //obj.push_back(line);
                if(regex_match(line, streamStart))
                {
                    //vector<string> Stream;
                    Stream.push_back(line);
                    get_stream(Addr, Stream);
                        
                    do {
                            
                        Addr = getline(Addr, line);
                        obj.push_back(line);
                            
                    }
                    while(!regex_match(line, obj_end));
                    //obj.push_back(line);
                }
                else
                {
                    obj.push_back(line);
                }
                    
            }

        }
        else
            return false;
        o.streams = Stream;
        o.data = obj;
        return true;
    }

    return false;
  
}


///*
bool cPDFFile::get_xref_table()
{
        regex xref_start ("(\\s*)(xref)(\\s*)((%.*)?)");
        DWORD Addr = BaseAddress;
		string line;
        while(Addr < (BaseAddress + FileLength))
        {
            Addr = getline(Addr, line);
            if(regex_match(line, xref_start))
            {
				xref_obj.name = line;
				Addr = GetValue((char*)Addr,line);
				xref_obj.start = atoi(line.c_str());
				Addr = GetValue((char*)Addr,line);
				xref_obj.end = atoi(line.c_str());

				xref_obj.xref_table.resize(xref_obj.end - xref_obj.start);
				for(int i= xref_obj.start; i< xref_obj.end; i++)
				{
					Addr = GetValue((char*)Addr,line);
					xref_obj.xref_table[i].offset = atoi(line.c_str());
					Addr = GetValue((char*)Addr,line);
					xref_obj.xref_table[i].revision_no = atoi(line.c_str());
					Addr = GetValue((char*)Addr,line);
					xref_obj.xref_table[i].marker = line.c_str()[0];
				}
                return true;
            }
        }
        return false;
}
//*/

bool cPDFFile::get_trailer_pdf()
{
    string line;
    regex trailer_start ("(trailer)");
    regex trailer_body_start ("(.*)(<<)(.*)(%.*)?");
    regex trailer_body_end ("(.*)(>>)");
	DWORD Addr = BaseAddress;
    while(Addr < (BaseAddress + FileLength))
    {
        Addr = getline(Addr, line);
        if(regex_match(line, trailer_start))
        {
        
            while(Addr < (BaseAddress + FileLength))
            {
                Addr = getline(Addr, line);
                if (regex_match(line, trailer_body_start))
                {
                    trailer_table.trailer_data.push_back(line);
                    bool flag = true;
                    while(flag)
                    {
                        Addr = getline(Addr, line);
                        if(!regex_match(line, trailer_body_end))
                            trailer_table.trailer_data.push_back(line);
                        else
                        {
                            trailer_table.trailer_data.push_back(line);
                            flag = false;
                        }
					}
				}
			}
            return true;
		}
         
	}
    return false; // return error because the file has only EOF 

}

bool cPDFFile::get_objects_from_xref()
{
    stream_no = 0;
    for(int i=1; i< xref_obj.xref_table.size();i++)
    {
        object o;
        get_object(xref_obj.xref_table[i].offset, o);
        if(!o.streams.empty())
            stream_no++;
        pdf_objects.push_back(o);
    }
    return true;

}
