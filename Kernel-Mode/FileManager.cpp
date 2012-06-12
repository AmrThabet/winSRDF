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

#include "RDF.h"

using namespace RDF;
using namespace RDF::FileManager;

//File Management

VOID FileThread(PVOID pContext);

NTSTATUS FileToWrite::write(char* data,DWORD size)
{
         
    ExAcquireFastMutexUnsafe(this->data.mutex); 
    if (this->data.IsNewData == false)
    {
       this->data.IsNewData = true;
       char* buffer = (char*)malloc(size + 10);
       memcpy(buffer,data,size);
       this->data.data = buffer;
       this->data.size = size;
    }
    else
    {
        char* buffer = (char*)malloc(this->data.size + size + 10);
        memcpy(buffer,this->data.data,this->data.size);
        //memcpy(&buffer[this->data.size],data,size);
        free(this->data.data);
        this->data.data = buffer;
        //this->data.size += size;
    }
    ExReleaseFastMutexUnsafe(this->data.mutex);
    /*if (this->data.IsNewData == true)return STATUS_SUCCESS;
    this->data.data = data;
    this->data.size = size;
    this->data.IsNewData = true;
    while(this->data.IsNewData)
    {
        break;//wait until writing finish
    }*/
    return STATUS_SUCCESS;
}
NTSTATUS FileToRead::read(char* &data,DWORD &size)
{
    
    this->data.IsNewData = true;
    while(this->data.IsNewData)
    {
        //wait until writing finish
    }
    data = this->data.data;
    size = this->data.size;
    return STATUS_SUCCESS;
}
//Open For Write
NTSTATUS FileToWrite::open(WCHAR* Filename,bool Append)
{
        NTSTATUS ntStatus;
        ThreadContRunning = TRUE;
        PUNICODE_STRING wFileName= (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
        
        Type = FileToWriteType;
        RtlInitUnicodeString(wFileName, Filename);
        InitializeObjectAttributes(&FileAttr,wFileName,OBJ_CASE_INSENSITIVE,NULL,NULL);
        this->Append = Append;
        this->data.mutex = (PFAST_MUTEX)malloc(sizeof(FAST_MUTEX));
        ExInitializeFastMutex(this->data.mutex);
        DbgPrint("Mutex Initialized");
        ntStatus = PsCreateSystemThread(&ThreadHandle,(ACCESS_MASK)0,NULL,(HANDLE)0,NULL,FileThread,this);  //Will take the Class as an argument
        if(ntStatus != STATUS_SUCCESS)
        {
            return (ntStatus);
        }
        DbgPrint("Create FileWriteThread Successful");
        ntStatus = ObReferenceObjectByHandle(ThreadHandle,THREAD_ALL_ACCESS,NULL,KernelMode,(PVOID*)&ThreadObject,NULL);
        if(ntStatus != STATUS_SUCCESS)
        {
            return (ntStatus);
        }
        DbgPrint("ObReferenceObjectByHandle Successful");
        while(this->data.IsNewData)
        {
            //wait until Opening finish
        }
        return this->data.status;
}

//Open For Read
NTSTATUS FileToRead::open(WCHAR* Filename)
{
        NTSTATUS ntStatus;
        ThreadContRunning = TRUE;
        UNICODE_STRING wFileName;
        
        Type = FileToReadType;
        RtlInitUnicodeString(&wFileName, Filename);
        InitializeObjectAttributes(&FileAttr,&wFileName,OBJ_CASE_INSENSITIVE,NULL,NULL);
        this->data.IsNewData = true;
        ntStatus = PsCreateSystemThread(&ThreadHandle,(ACCESS_MASK)0,NULL,(HANDLE)0,NULL,FileThread,this);  //Will take the Class as an argument
        if(ntStatus != STATUS_SUCCESS)
        { 
            return (ntStatus);
        }
        DbgPrint("Create FileReadThread Successful");
        ntStatus = ObReferenceObjectByHandle(ThreadHandle,THREAD_ALL_ACCESS,NULL,KernelMode,(PVOID*)&ThreadObject,NULL);
        if(ntStatus != STATUS_SUCCESS)
        {
            return (ntStatus);
        }
        DbgPrint("ObReferenceObjectByHandle Successful");
        while(this->data.IsNewData)
        {
            //wait until Opening finish
        }
        return this->data.status;
}

NTSTATUS File::close()
{
    ThreadContRunning = FALSE;
    KeWaitForSingleObject(ThreadObject,Executive,KernelMode,FALSE,NULL);
    //ZwClose(ThreadHandle);
    return STATUS_SUCCESS;
}

VOID FileThread(PVOID pContext)
{
    NTSTATUS ntStatus;
    IO_STATUS_BLOCK ioStatus;
    File* wFile = (FileToWrite*)pContext;
    if (wFile->Type == FileToWriteType)
    {
        if (!(((FileToWrite*)wFile)->Append)){
            ntStatus = ZwCreateFile(&wFile->FileHandle,GENERIC_WRITE,&wFile->FileAttr,&ioStatus,NULL,FILE_ATTRIBUTE_NORMAL,0,FILE_OVERWRITE_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
            DbgPrint("Creating New File");
        }else{
            ntStatus = ZwCreateFile(&wFile->FileHandle,FILE_APPEND_DATA,&wFile->FileAttr,&ioStatus,NULL,FILE_ATTRIBUTE_NORMAL,0,FILE_OPEN_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
            DbgPrint("Failed To Open File Error No: %x",ntStatus);
            if(ntStatus != STATUS_SUCCESS)
                        ntStatus = ZwCreateFile(&wFile->FileHandle,GENERIC_WRITE,&wFile->FileAttr,&ioStatus,NULL,FILE_ATTRIBUTE_NORMAL,0,FILE_OPEN_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
            DbgPrint("Appending File");
        }
    }else
    {
        ntStatus = ZwCreateFile(&wFile->FileHandle,GENERIC_READ,&wFile->FileAttr,&ioStatus,NULL,FILE_ATTRIBUTE_NORMAL,0,FILE_OPEN_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
    };
    if(ntStatus != STATUS_SUCCESS)
    {
        DbgPrint("Failed To Open File Error No: %x",ntStatus);
        wFile->FileHandle = NULL;
    }else{
        DbgPrint("Open File Finished Successfully : %x",wFile->FileHandle);
    }
    wFile->data.status = ntStatus;
    wFile->data.IsNewData = false;
    
    while(wFile->ThreadContRunning)
    { 
        if(wFile->data.IsNewData == true && wFile->FileHandle != NULL)
        {
            //The Read Operation
            if (wFile->Type == FileToReadType)
            {
                FILE_STANDARD_INFORMATION FileInformation;
                
                FileToRead* rFile = (FileToRead*)wFile;
                ntStatus = ZwQueryInformationFile(rFile->FileHandle,&ioStatus,&FileInformation,sizeof (FileInformation),FileStandardInformation);
                if(!(NT_SUCCESS(ntStatus)))
                {
                    DbgPrint("Error in ZwQueryInformationFile");
                    rFile->data.IsNewData = false;
                    break;
                };
                rFile->data.size = FileInformation.EndOfFile.LowPart; 
                DbgPrint("The FileSize = %x",rFile->data.size);
                rFile->data.data = (char*)malloc(rFile->data.size);
                ntStatus = ZwReadFile(rFile->FileHandle,NULL,NULL,NULL,&ioStatus,rFile->data.data,rFile->data.size,NULL,NULL);
                if(!(NT_SUCCESS(ntStatus)))
                {
                    DbgPrint("Error in reading the File") ;
                    rFile->data.IsNewData = false;
                    break;
                }
                rFile->data.IsNewData = false;
            }
            else
            {
                char* buffer = NULL;
                DWORD size;
                ExAcquireFastMutexUnsafe(wFile->data.mutex); 
                if (wFile->data.IsNewData == true)
                {
                   buffer = (char*)malloc(wFile->data.size+1);
                   memcpy(buffer,wFile->data.data,wFile->data.size);
                   size = wFile->data.size;
                   free(wFile->data.data);
                   wFile->data.data = NULL;
                   wFile->data.size = 0;
                   wFile->data.IsNewData = false;      
                }
                ExReleaseFastMutexUnsafe(wFile->data.mutex);
                if (buffer != NULL)
                   ntStatus = ZwWriteFile(wFile->FileHandle,NULL,NULL,NULL,&ioStatus,buffer,size,NULL,NULL);
                if(!(NT_SUCCESS(ntStatus)))
                {
                    DbgPrint("Error in writing on File") ;
                    wFile->data.IsNewData = false;
                    break;
                }
                wFile->data.data = NULL;
                wFile->data.size = 0;
                wFile->data.IsNewData = false;
            }
        }
    }
    if (wFile->FileHandle != NULL)ZwClose(wFile->FileHandle);
    DbgPrint("File Closed");
    PsTerminateSystemThread(STATUS_SUCCESS);
};
