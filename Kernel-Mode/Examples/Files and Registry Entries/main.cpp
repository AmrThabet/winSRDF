/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include "SRDF.h"

using namespace SRDF;
using namespace SRDF::FileManager;
using namespace SRDF::RegistryManager;

PDRIVER_OBJECT DriverObject;

NTSTATUS Driver::DriverMain(IN PDRIVER_OBJECT pDriverObject,IN PUNICODE_STRING theRegistryPath){
      DbgPrint("Files & Registry DriverEntry Called\n");
      DriverObject = pDriverObject;
       
      FileToRead* readfile = (FileToRead*)misc::CreateClass(sizeof(FileToRead));
      NTSTATUS ntStatus = readfile->open(L"\\DosDevices\\c:\\Log.txt");
      if (ntStatus != STATUS_SUCCESS)DbgPrint("01.cpp : Failed To ReadFile");
      readfile->close();
      ///*
      else DbgPrint("01.cpp : ReadFile Opened Successfully");
      char* data;
      DWORD size;
      readfile->read(data,size);
      DbgPrint("FileData at : %x ... and FileSize is : %x",data,size);
      DbgPrint("Text: %s",data);
      readfile->close();
      
      FileToWrite* s = (FileToWrite*)misc::CreateClass(sizeof(FileToWrite));
      s->open(L"\\DosDevices\\c:\\NewData.txt",false);
      s->write("From KernelMode\n",strlen("From KernelMode\n"));
      s->close();
      
      char* buf = RegRead(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",L"ProgramFilesDir",size);
      if(buf != 0)DbgPrint("Registry Read : %x",buf);
      
      s = (FileToWrite*)misc::CreateClass(sizeof(FileToWrite));
      s->open(L"\\DosDevices\\c:\\Reg.txt",false);
      s->write(buf,size);
      s->close();
      
      RegWrite(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",L"SRDF",(char*)L"From Kernel Mode",REG_SZ,strlen("From Kernel Mode")*2);
      
      return STATUS_SUCCESS;
}
VOID Driver::DriverUnload()
{
     DbgPrint("Device Detached");
}
