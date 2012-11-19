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

#include "SRDF.h"
using namespace SRDF;

//Variables For the File System Notification Routine


VOID FileFilterDevice::FileFilterNotificationRoutine(PDEVICE_OBJECT TargetDevice,int command)
{
    if (command == TRUE)
    {       
       if (HookNewlyMountedVolumes) AttachToDevice(TargetDevice);
       EnumerateVolumes(TargetDevice);
       DbgPrint("Notification : Device Attached");
    }else
    {
       if (HookNewlyMountedVolumes) DetachDevice(TargetDevice);
       DbgPrint("Notification : Device Detached"); 
    }
}
NTSTATUS FileFilterDevice::BeginHooking(BOOLEAN HookNewlyMountedVolumes)
{
         this->HookNewlyMountedVolumes = HookNewlyMountedVolumes;
         pDriver->FSRegisteredDevices[pDriver->nFSRegisteredDevices] = this;
         pDriver->nFSRegisteredDevices++;
         
         
         if (HookNewlyMountedVolumes){                         
            SetValue(FilteredMajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL].PreModification,FileFilterDevice::MountNewVolumesPre);
         };
         
         return STATUS_SUCCESS;
}

int _cdecl FileFilterDevice::MountNewVolumesPre(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
    PDEVICE_OBJECT TargetDevice;
    PDEVICE_OBJECT TempDevice;
    PDEVICE_OBJECT newDeviceObject;
    PIO_STACK_LOCATION StackLoc;
    NTSTATUS ntStatus;
    DWORD DeviceId;
    PVPB vpb;
    PFILTERDEVICE_EXTENSION devExt;
    LARGE_INTEGER Interval;
    int i;
    
    StackLoc = IoGetCurrentIrpStackLocation(Irp);
    switch (StackLoc->MinorFunction)
    {
        case IRP_MN_MOUNT_VOLUME:
            
            DbgPrint("MountVolume !!!");
            
            TargetDevice = StackLoc->Parameters.MountVolume.Vpb->RealDevice;
            
            this->Pending(DeviceObject,Irp);            
            
            TargetDevice = TargetDevice->Vpb->DeviceObject;
            
            if (NT_SUCCESS(Irp->IoStatus.Status))
            {                         
                 bool Attach = true;
                 if (AskAttachFunc != NULL) Attach = (*AskAttachFunc)(this,TargetDevice);
                 
                 if (Attach == true) 
                 {
                     DbgPrint("Will Attach ... ");
                     for (i = 0;i<8; i++){
                         if (AttachToDevice(TargetDevice) == STATUS_SUCCESS) break;
                         DbgPrint("Try Again :(");
                         Interval.QuadPart = -5000000;
                         KeDelayExecutionThread(0,FALSE,&Interval);
                     }
                     if (i != 8)DbgPrint("Device Attached");
                 }
            }
            else DbgPrint("Mount Chancelled ... "); 
            
            
            DbgPrint("After Mounting !!!");

            return FILTER_COMPLETE_REQUEST;
            
        case IRP_MN_LOAD_FILE_SYSTEM:

            break;

        case IRP_MN_USER_FS_REQUEST:
        {
            switch (StackLoc->Parameters.FileSystemControl.FsControlCode)
            {
                case FSCTL_DISMOUNT_VOLUME:
                {
                    devExt = (PFILTERDEVICE_EXTENSION)DeviceObject->DeviceExtension;
                    
                    DetachDevice(devExt->AttachedDeviceObject);
                    break;
                }
            }
            break;
        }
    }
    return FILTER_SKIP;
}

NTSTATUS FileFilterDevice::EnumerateVolumes(PDEVICE_OBJECT FileSystemDevice)
{
    PDEVICE_OBJECT *VolumeDeviceObjects;
    PDEVICE_OBJECT TargetDevice;
    NTSTATUS ntStatus;
    DWORD numDevices;
    ULONG i;
    
    DbgPrint("Enumerate Volumes");
    ntStatus = IoEnumerateDeviceObjectList(FileSystemDevice->DriverObject,NULL,0,&numDevices);
    if (ntStatus == STATUS_BUFFER_TOO_SMALL)
    {
        DbgPrint("Enumerate Volumes nDevices = %x",numDevices);         
        numDevices += 8;
        VolumeDeviceObjects = (PDEVICE_OBJECT*)malloc(numDevices * 4);
        
        if (VolumeDeviceObjects == NULL)return STATUS_ERROR;

        ntStatus = IoEnumerateDeviceObjectList(FileSystemDevice->DriverObject,VolumeDeviceObjects,(numDevices * 4),&numDevices);

        if (ntStatus != STATUS_SUCCESS)  {

            free(VolumeDeviceObjects);
            return ntStatus;
        }
     }
     else return ntStatus;

    for (i=0; i < numDevices; i++) {
        TargetDevice = NULL;
        if ((VolumeDeviceObjects[i] == FileSystemDevice) || (VolumeDeviceObjects[i]->DeviceType != FileSystemDevice->DeviceType))
        {
           continue;
        }
        TargetDevice = VolumeDeviceObjects[i];
        bool Attach = true;
        if (AskAttachFunc != NULL) Attach = (*AskAttachFunc)(this,TargetDevice);
        if (Attach == true) 
        {
            AttachToDevice(TargetDevice);
            DbgPrint("Enumerate : Device Attached");
        }
        ObDereferenceObject( VolumeDeviceObjects[i] );
    }
    
    free(VolumeDeviceObjects);
    return STATUS_SUCCESS;
}

FileInformationOffsets* FileFilterDevice::GetFileInformationOffsets(__in PIRP Irp)
{
       FileInformationOffsets* FileOffs = (FileInformationOffsets*)misc::CreateClass(sizeof(FileInformationOffsets));
       PIO_STACK_LOCATION StackLoc;
       
       StackLoc = IoGetCurrentIrpStackLocation(Irp);
       switch ( StackLoc->Parameters.QueryDirectory.FileInformationClass )
       {
          case FileBothDirectoryInformation:
                  FileOffs->FileName        =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,FileName);
                  FileOffs->ShortName       =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,ShortName);
                  FileOffs->ShortNameLength =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,ShortNameLength);
                  FileOffs->FileNameLength  =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,FileNameLength);
                  FileOffs->FileAttributes  =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,FileAttributes);
                  FileOffs->AllocationSize  =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,AllocationSize);
                  FileOffs->EndOfFile       =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,EndOfFile);
                  FileOffs->FileIndex       =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,FileIndex);
                  FileOffs->CreationTime    =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,CreationTime);
                  FileOffs->LastAccessTime  =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,LastAccessTime);
                  FileOffs->LastWriteTime   =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,LastWriteTime);
                  FileOffs->ChangeTime      =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,ChangeTime);
                  FileOffs->EaSize          =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,EaSize);
                  FileOffs->FileId          =       FIELD_NOT_FOUND;
                  FileOffs->OpFileReference =       FIELD_NOT_FOUND;
                  FileOffs->OpObjectId      =       FIELD_NOT_FOUND;
                  FileOffs->OpBirthObjectId =       FIELD_NOT_FOUND;
                  FileOffs->NextEntryOffset =       FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION,NextEntryOffset);
                  
          case FileDirectoryInformation:
                  FileOffs->FileName        =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,FileName);
                  FileOffs->ShortName       =       FIELD_NOT_FOUND;
                  FileOffs->ShortNameLength =       FIELD_NOT_FOUND;
                  FileOffs->FileNameLength  =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,FileNameLength);
                  FileOffs->FileAttributes  =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,FileAttributes);
                  FileOffs->AllocationSize  =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,AllocationSize);
                  FileOffs->EndOfFile       =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,EndOfFile);
                  FileOffs->FileIndex       =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,FileIndex);
                  FileOffs->CreationTime    =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,CreationTime);
                  FileOffs->LastAccessTime  =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,LastAccessTime);
                  FileOffs->LastWriteTime   =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,LastWriteTime);
                  FileOffs->ChangeTime      =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,ChangeTime);
                  FileOffs->EaSize          =       FIELD_NOT_FOUND;
                  FileOffs->FileId          =       FIELD_NOT_FOUND;
                  FileOffs->OpFileReference =       FIELD_NOT_FOUND;
                  FileOffs->OpObjectId      =       FIELD_NOT_FOUND;
                  FileOffs->OpBirthObjectId =       FIELD_NOT_FOUND;
                  FileOffs->NextEntryOffset =       FIELD_OFFSET(FILE_DIRECTORY_INFORMATION,NextEntryOffset);
          
          case FileFullDirectoryInformation:
                  FileOffs->FileName        =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,FileName);
                  FileOffs->ShortName       =       FIELD_NOT_FOUND;
                  FileOffs->ShortNameLength =       FIELD_NOT_FOUND;
                  FileOffs->FileNameLength  =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,FileNameLength);
                  FileOffs->FileAttributes  =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,FileAttributes);
                  FileOffs->AllocationSize  =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,AllocationSize);
                  FileOffs->EndOfFile       =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,EndOfFile);
                  FileOffs->FileIndex       =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,FileIndex);
                  FileOffs->CreationTime    =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,CreationTime);
                  FileOffs->LastAccessTime  =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,LastAccessTime);
                  FileOffs->LastWriteTime   =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,LastWriteTime);
                  FileOffs->ChangeTime      =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,ChangeTime);
                  FileOffs->EaSize          =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,EaSize);
                  FileOffs->FileId          =       FIELD_NOT_FOUND;
                  FileOffs->OpFileReference =       FIELD_NOT_FOUND;
                  FileOffs->OpObjectId      =       FIELD_NOT_FOUND;
                  FileOffs->OpBirthObjectId =       FIELD_NOT_FOUND;
                  FileOffs->NextEntryOffset =       FIELD_OFFSET(FILE_FULL_DIR_INFORMATION,NextEntryOffset);
          
          case FileIdBothDirectoryInformation:
                  FileOffs->FileName        =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,FileName);
                  FileOffs->ShortName       =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,ShortName);
                  FileOffs->ShortNameLength =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,ShortNameLength);
                  FileOffs->FileNameLength  =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,FileNameLength);
                  FileOffs->FileAttributes  =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,FileAttributes);
                  FileOffs->AllocationSize  =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,AllocationSize);
                  FileOffs->EndOfFile       =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,EndOfFile);
                  FileOffs->FileIndex       =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,FileIndex);
                  FileOffs->CreationTime    =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,CreationTime);
                  FileOffs->LastAccessTime  =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,LastAccessTime);
                  FileOffs->LastWriteTime   =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,LastWriteTime);
                  FileOffs->ChangeTime      =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,ChangeTime);
                  FileOffs->EaSize          =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,EaSize);
                  FileOffs->FileId          =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,FileId);
                  FileOffs->OpFileReference =       FIELD_NOT_FOUND;
                  FileOffs->OpObjectId      =       FIELD_NOT_FOUND;
                  FileOffs->OpBirthObjectId =       FIELD_NOT_FOUND;
                  FileOffs->NextEntryOffset =       FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION,NextEntryOffset);
          
          case FileIdFullDirectoryInformation:
                  FileOffs->FileName        =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,FileName);
                  FileOffs->ShortName       =       FIELD_NOT_FOUND;
                  FileOffs->ShortNameLength =       FIELD_NOT_FOUND;
                  FileOffs->FileNameLength  =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,FileNameLength);
                  FileOffs->FileAttributes  =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,FileAttributes);
                  FileOffs->AllocationSize  =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,AllocationSize);
                  FileOffs->EndOfFile       =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,EndOfFile);
                  FileOffs->FileIndex       =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,FileIndex);
                  FileOffs->CreationTime    =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,CreationTime);
                  FileOffs->LastAccessTime  =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,LastAccessTime);
                  FileOffs->LastWriteTime   =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,LastWriteTime);
                  FileOffs->ChangeTime      =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,ChangeTime);
                  FileOffs->EaSize          =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,EaSize);
                  FileOffs->FileId          =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,FileId);
                  FileOffs->OpFileReference =       FIELD_NOT_FOUND;
                  FileOffs->OpObjectId      =       FIELD_NOT_FOUND;
                  FileOffs->OpBirthObjectId =       FIELD_NOT_FOUND;
                  FileOffs->NextEntryOffset =       FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION,NextEntryOffset);
          
          case FileNamesInformation:
                  FileOffs->FileName        =       FIELD_OFFSET(FILE_NAMES_INFORMATION,FileName);
                  FileOffs->ShortName       =       FIELD_NOT_FOUND;
                  FileOffs->ShortNameLength =       FIELD_NOT_FOUND;
                  FileOffs->FileNameLength  =       FIELD_OFFSET(FILE_NAMES_INFORMATION,FileNameLength);
                  FileOffs->FileAttributes  =       FIELD_NOT_FOUND;
                  FileOffs->AllocationSize  =       FIELD_NOT_FOUND;
                  FileOffs->EndOfFile       =       FIELD_NOT_FOUND;
                  FileOffs->FileIndex       =       FIELD_OFFSET(FILE_NAMES_INFORMATION,FileIndex);
                  FileOffs->CreationTime    =       FIELD_NOT_FOUND;
                  FileOffs->LastAccessTime  =       FIELD_NOT_FOUND;
                  FileOffs->LastWriteTime   =       FIELD_NOT_FOUND;
                  FileOffs->ChangeTime      =       FIELD_NOT_FOUND;
                  FileOffs->EaSize          =       FIELD_NOT_FOUND;
                  FileOffs->FileId          =       FIELD_NOT_FOUND;
                  FileOffs->OpFileReference =       FIELD_NOT_FOUND;
                  FileOffs->OpObjectId      =       FIELD_NOT_FOUND;
                  FileOffs->OpBirthObjectId =       FIELD_NOT_FOUND;
                  FileOffs->NextEntryOffset =       FIELD_OFFSET(FILE_NAMES_INFORMATION,NextEntryOffset);
          
          case FileObjectIdInformation:
                  FileOffs->FileName        =       FIELD_NOT_FOUND;
                  FileOffs->ShortName       =       FIELD_NOT_FOUND;
                  FileOffs->ShortNameLength =       FIELD_NOT_FOUND;
                  FileOffs->FileNameLength  =       FIELD_NOT_FOUND;
                  FileOffs->FileAttributes  =       FIELD_NOT_FOUND;
                  FileOffs->AllocationSize  =       FIELD_NOT_FOUND;
                  FileOffs->EndOfFile       =       FIELD_NOT_FOUND;
                  FileOffs->FileIndex       =       FIELD_NOT_FOUND;
                  FileOffs->CreationTime    =       FIELD_NOT_FOUND;
                  FileOffs->LastAccessTime  =       FIELD_NOT_FOUND;
                  FileOffs->LastWriteTime   =       FIELD_NOT_FOUND;
                  FileOffs->ChangeTime      =       FIELD_NOT_FOUND;
                  FileOffs->EaSize          =       FIELD_NOT_FOUND;
                  FileOffs->FileId          =       FIELD_NOT_FOUND;
                  FileOffs->OpFileReference =       FIELD_OFFSET(FILE_OBJECTID_INFORMATION,FileReference);
                  FileOffs->OpObjectId      =       FIELD_OFFSET(FILE_OBJECTID_INFORMATION,ObjectId);
                  FileOffs->OpBirthObjectId =       FIELD_OFFSET(FILE_OBJECTID_INFORMATION,BirthObjectId);
                  FileOffs->NextEntryOffset =       FIELD_NOT_FOUND;
          
          case FileReparsePointInformation:
                  FileOffs->FileName        =       FIELD_NOT_FOUND;
                  FileOffs->ShortName       =       FIELD_NOT_FOUND;
                  FileOffs->ShortNameLength =       FIELD_NOT_FOUND;
                  FileOffs->FileNameLength  =       FIELD_NOT_FOUND;
                  FileOffs->FileAttributes  =       FIELD_NOT_FOUND;
                  FileOffs->AllocationSize  =       FIELD_NOT_FOUND;
                  FileOffs->EndOfFile       =       FIELD_NOT_FOUND;
                  FileOffs->FileIndex       =       FIELD_NOT_FOUND;
                  FileOffs->CreationTime    =       FIELD_NOT_FOUND;
                  FileOffs->LastAccessTime  =       FIELD_NOT_FOUND;
                  FileOffs->LastWriteTime   =       FIELD_NOT_FOUND;
                  FileOffs->ChangeTime      =       FIELD_NOT_FOUND;
                  FileOffs->EaSize          =       FIELD_NOT_FOUND;
                  FileOffs->FileId          =       FIELD_NOT_FOUND;
                  FileOffs->OpFileReference =       FIELD_OFFSET(FILE_REPARSE_POINT_INFORMATION,FileReference);
                  FileOffs->OpObjectId      =       FIELD_NOT_FOUND;
                  FileOffs->OpBirthObjectId =       FIELD_NOT_FOUND;
                  FileOffs->NextEntryOffset =       FIELD_NOT_FOUND;
       };
       return FileOffs;
}
