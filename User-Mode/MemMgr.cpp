/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet <amr.thabet[at]student.alx.edu.eg>
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
#include <iostream>

using namespace std;
using namespace Security::Elements::String;
using namespace Security::Core;

cMemoryManager::cMemoryManager()
{
	InitializeCriticalSection(&CriticalSection);
	pHeaderHeap = (DWORD)VirtualAlloc(0,0x10000000,MEM_RESERVE,PAGE_READWRITE);
	pBufferHeap = (DWORD)VirtualAlloc(0,0x10000000,MEM_RESERVE,PAGE_READWRITE);

	pHeaderHeap = (DWORD)VirtualAlloc((LPVOID)pHeaderHeap,0x3000,MEM_COMMIT,PAGE_READWRITE);
	VirtualAlloc((LPVOID)pBufferHeap,0x3000,MEM_COMMIT,PAGE_READWRITE);

	//Setting the Heap Information Structure

	HeapInfo = (HEAP_INFO*)pHeaderHeap;

	HeapInfo->HeapBegin = pBufferHeap;
	HeapInfo->LastAllocatedHeader = pHeaderHeap + sizeof(HEAP_INFO);
	HeapInfo->LastAllocatedBuffer = pBufferHeap;
	HeapInfo->nHeaderAllocatedBlocks = 3;
	HeapInfo->nBufferAllocatedBlocks = 3;
	HeapInfo->nElements = 0;
	HeapInfo->AllocatedSeparateBlocks = NULL;
	HeapInfo->FreeSeparateBlocks = NULL;
}

HEADER_HEAP_ELEMENT* cMemoryManager::AllocateHeaderElement()
{
	//Check the Maximum Size that we need to the size of the allocated blocks

	if ((DWORD)(HeapInfo->LastAllocatedHeader + sizeof(HEADER_HEAP_ELEMENT)) >
		(DWORD)(HeapInfo->nHeaderAllocatedBlocks * 0x1000))
	{
		// if the size is insufficient ... Allocate more blocks
		VirtualAlloc((LPVOID)(pHeaderHeap+(HeapInfo->nHeaderAllocatedBlocks * 0x1000)),0x3000,MEM_COMMIT,PAGE_READWRITE);
		HeapInfo->nHeaderAllocatedBlocks +=3;
	}
	// Now allocate the Header Block and increase the number of Elements
	HEADER_HEAP_ELEMENT* HeaderElement = (HEADER_HEAP_ELEMENT*)HeapInfo->LastAllocatedHeader;
	HeapInfo->LastAllocatedHeader += sizeof(HEADER_HEAP_ELEMENT);
	HeapInfo->nElements++;
	return HeaderElement;
}

BUFFER_HEAP_ELEMENT* cMemoryManager::AllocateBufferElement(DWORD size)
{
	if ((DWORD)(HeapInfo->LastAllocatedBuffer + sizeof(BUFFER_HEAP_ELEMENT)+ size)  >
		(DWORD)(pBufferHeap + (HeapInfo->nBufferAllocatedBlocks-1) * 0x1000))
	{
		//cout << "VirtualAlloc: " << (int*)(HeapInfo->LastAllocatedBuffer + sizeof(BUFFER_HEAP_ELEMENT)+ size) << "   " << (int*)(pBufferHeap + HeapInfo->nBufferAllocatedBlocks * 0x1000) << "\n";
		VirtualAlloc((LPVOID)(pBufferHeap+(HeapInfo->nBufferAllocatedBlocks * 0x1000)),0x3000,MEM_COMMIT,PAGE_READWRITE);
		HeapInfo->nBufferAllocatedBlocks +=3;
		
	}
	BUFFER_HEAP_ELEMENT* BufferElement = (BUFFER_HEAP_ELEMENT*)HeapInfo->LastAllocatedBuffer;
	HeapInfo->LastAllocatedBuffer += sizeof(BUFFER_HEAP_ELEMENT)+ size;
	return BufferElement;
}

void* cMemoryManager::Allocate(DWORD size, BOOL IsGlobal)
{
	HEADER_HEAP_ELEMENT* AllocatedBlockHeader;
	BUFFER_HEAP_ELEMENT* AllocatedBlock;
	EnterCriticalSection(&CriticalSection);
	register DWORD Size = size;
	if (Size == 0)Size = 8;
	if (size % 8) Size += (8 - size % 8);			//make it multiply by 8
	if (Size > 4096)
	{
		//Allocating a new Header
		if (HeapInfo->FreeSeparateBlocks != NULL)
		{
			//Restore a  block from the free list and put it in the allocated list
			AllocatedBlockHeader = (HEADER_HEAP_ELEMENT*)HeapInfo->FreeSeparateBlocks;
			HeapInfo->FreeSeparateBlocks = AllocatedBlockHeader->pNextFreeListItem;
			AllocatedBlockHeader->pNextFreeListItem = HeapInfo->AllocatedSeparateBlocks;
			HeapInfo->AllocatedSeparateBlocks = (DWORD)AllocatedBlockHeader;
		}
		else
		{
			//Allocate a new block, initialize it and put in the allocated list
			AllocatedBlockHeader = AllocateHeaderElement();
			AllocatedBlockHeader->pNextFreeListItem = HeapInfo->AllocatedSeparateBlocks;
			HeapInfo->AllocatedSeparateBlocks = (DWORD)AllocatedBlockHeader;
			AllocatedBlockHeader->Index = HeapInfo->nElements;
		}
		//Initialize the Header
		AllocatedBlockHeader->PointerToBuffer = (DWORD)VirtualAlloc(0,size,MEM_COMMIT,PAGE_READWRITE);
		AllocatedBlockHeader->CanaryValue = 0; // no Canary Value for separate blocks
		AllocatedBlockHeader->Tid = GetCurrentThreadId();
		AllocatedBlockHeader->IsAllocated = TRUE;
		AllocatedBlockHeader->IsGlobal = FALSE;
		AllocatedBlockHeader->Size = Size;
		//cout << "Alloc 1: Size: " << AllocatedBlockHeader->Size << "  Buffer: " << (int*)AllocatedBlockHeader->PointerToBuffer << " Elements: " << (DWORD)HeapInfo->nElements << " Index: " << (DWORD)AllocatedBlockHeader->Index <<"\n";
		LeaveCriticalSection(&CriticalSection);
		return (void*)AllocatedBlockHeader->PointerToBuffer;
	}
	else if (Size < 1024)
	{
		DWORD index = Size /8;
		if (HeapInfo->FreeLists[index] != 0)
		{
			//Pop an Element from the FreeList
			AllocatedBlockHeader = (HEADER_HEAP_ELEMENT*)HeapInfo->FreeLists[index];
			HeapInfo->FreeLists[index] =  AllocatedBlockHeader->pNextFreeListItem;
			memset((void*)AllocatedBlockHeader->PointerToBuffer,0,Size + sizeof(BUFFER_HEAP_ELEMENT));
			AllocatedBlock = (BUFFER_HEAP_ELEMENT*)AllocatedBlockHeader->PointerToBuffer;
		}
		else
		{
			//Allocate a new Element
			AllocatedBlockHeader = AllocateHeaderElement();
			AllocatedBlockHeader->Index = HeapInfo->nElements;
			AllocatedBlockHeader->Tid = GetCurrentThreadId();
			AllocatedBlockHeader->IsAllocated = TRUE;
			AllocatedBlockHeader->IsGlobal = FALSE;
			AllocatedBlockHeader->Size = Size;
			AllocatedBlock = AllocateBufferElement(Size);
			AllocatedBlockHeader->PointerToBuffer = (DWORD)AllocatedBlock;
			memset((void*)AllocatedBlockHeader->PointerToBuffer,0,Size + sizeof(BUFFER_HEAP_ELEMENT));

		}
		AllocatedBlockHeader->CanaryValue = 0; // will be added soon
		AllocatedBlock->Index = AllocatedBlockHeader->Index;
		//cout << "Alloc 2: Size: " << AllocatedBlockHeader->Size << "  Buffer: " << (int*)AllocatedBlockHeader->PointerToBuffer << " Elements: " <<HeapInfo->nElements << " Index: " << AllocatedBlockHeader->Index <<"\n";
		LeaveCriticalSection(&CriticalSection);
		return (void*)(AllocatedBlockHeader->PointerToBuffer + sizeof(BUFFER_HEAP_ELEMENT));
	}
	else 
	{
		HEADER_HEAP_ELEMENT* PrevBlockHeader = NULL;
		AllocatedBlockHeader = (HEADER_HEAP_ELEMENT*)HeapInfo->LargeFreeList;
		// Loop on the Elements of the LargeFreeList
		do
		{
			if (AllocatedBlockHeader == NULL)
			{
				//Allocate a new Element
				AllocatedBlockHeader = AllocateHeaderElement();
				AllocatedBlockHeader->Index = HeapInfo->nElements;
				AllocatedBlockHeader->Tid = GetCurrentThreadId();
				AllocatedBlockHeader->IsAllocated = TRUE;
				AllocatedBlockHeader->IsGlobal = FALSE;
				AllocatedBlockHeader->Size = Size;
				AllocatedBlock = AllocateBufferElement(Size);
				AllocatedBlockHeader->PointerToBuffer = (DWORD)AllocatedBlock;
				memset((void*)AllocatedBlockHeader->PointerToBuffer,0,Size + sizeof(BUFFER_HEAP_ELEMENT));
				AllocatedBlock->Index = AllocatedBlockHeader->Index;
				
				break;
			}
			else if ((AllocatedBlockHeader->Size >= Size) && (AllocatedBlockHeader->Size <= (Size+ 100)))	//Range 100 bytes only
			{
				//Pop an Element from the FreeList
				Size = AllocatedBlockHeader->Size;
				if ( PrevBlockHeader != NULL)PrevBlockHeader->pNextFreeListItem = AllocatedBlockHeader->pNextFreeListItem;
				else HeapInfo->LargeFreeList = AllocatedBlockHeader->pNextFreeListItem;
				AllocatedBlockHeader->pNextFreeListItem = NULL;
				memset((void*)AllocatedBlockHeader->PointerToBuffer,0,Size + sizeof(BUFFER_HEAP_ELEMENT));
				AllocatedBlock = (BUFFER_HEAP_ELEMENT*)AllocatedBlockHeader->PointerToBuffer;
				break;
			}
			PrevBlockHeader = AllocatedBlockHeader;
			AllocatedBlockHeader = (HEADER_HEAP_ELEMENT*)AllocatedBlockHeader->pNextFreeListItem;
		}while(1);
		//Initialize the Buffer
		AllocatedBlockHeader->CanaryValue = 0; // will be added soon
		AllocatedBlock->Index = AllocatedBlockHeader->Index;
		//cout << "Alloc 3: Size: " << AllocatedBlockHeader->Size << "  Buffer: " << (int*)AllocatedBlockHeader->PointerToBuffer << " Elements: " <<HeapInfo->nElements << " Index: " << AllocatedBlockHeader->Index <<"\n";
		LeaveCriticalSection(&CriticalSection);
		return (void*)(AllocatedBlockHeader->PointerToBuffer + sizeof(BUFFER_HEAP_ELEMENT));

	}
	LeaveCriticalSection(&CriticalSection);
	return NULL;
}

HEADER_HEAP_ELEMENT* cMemoryManager::GetElement(BUFFER_HEAP_ELEMENT* AllocatedBuffer)
{
	
	HEADER_HEAP_ELEMENT* AllocatedHeader;
	WORD index = AllocatedBuffer->Index;
	if (index > HeapInfo->nElements)return NULL;
	index -=1;
	AllocatedHeader = (HEADER_HEAP_ELEMENT*)(pHeaderHeap + sizeof(HEAP_INFO));
	if (AllocatedHeader[index].PointerToBuffer == (DWORD)AllocatedBuffer)
	{
		return &AllocatedHeader[index];
	}
	else
	{
		for (int i = 0;i < HeapInfo->nElements;i++)
		{
			if (AllocatedHeader[i].PointerToBuffer == (DWORD)AllocatedBuffer)
			{
				AllocatedBuffer->Index = i;		//unimportant but for investigations
				return &AllocatedHeader[i];
			}
		}
	}
	return NULL;
}

void cMemoryManager::Free(void *ptr)
{
	
	HEADER_HEAP_ELEMENT* AllocatedHeader;
	if (ptr == NULL) return;
	EnterCriticalSection(&CriticalSection);
	if ((DWORD)ptr > HeapInfo->HeapBegin && (DWORD)ptr < HeapInfo->LastAllocatedBuffer)
	{
		BUFFER_HEAP_ELEMENT* AllocatedBuffer = (BUFFER_HEAP_ELEMENT*)((DWORD)ptr - sizeof(BUFFER_HEAP_ELEMENT));
		AllocatedHeader = GetElement(AllocatedBuffer);
		if ((DWORD)AllocatedHeader == NULL)
		{
			LeaveCriticalSection(&CriticalSection);
			return;
		}
		AllocatedHeader->IsAllocated = FALSE;
		if (AllocatedHeader->Size < 1024)
		{
			if ((AllocatedHeader->Size % 8) != 0)
			{
				//cout << "Error on Free 1\n";
				LeaveCriticalSection(&CriticalSection);
				return;				//Error
			}
			DWORD index = AllocatedHeader->Size / 8;
			AllocatedHeader->pNextFreeListItem = HeapInfo->FreeLists[index];
			HeapInfo->FreeLists[index] = (DWORD)AllocatedHeader;
			//cout << "Free 1: Index: " << index << " Size: " << AllocatedHeader->Size << " New Item: " << (int*)AllocatedHeader << " Old Item: " << (int*)AllocatedHeader->pNextFreeListItem << "\n";
		}
		else if (AllocatedHeader->Size < 4096 && AllocatedHeader->Size > 1024)
		{
			AllocatedHeader->pNextFreeListItem = HeapInfo->LargeFreeList;
			HeapInfo->LargeFreeList = (DWORD)AllocatedHeader;
			//cout << "Free 2: Size: " << AllocatedHeader->Size << " New Item: " << (int*)AllocatedHeader << " Old Item: " << (int*)AllocatedHeader->pNextFreeListItem << "\n";
		}
		else
		{
			//cout << "Error on Free 2\n";
			LeaveCriticalSection(&CriticalSection);
			return;		//Error (should be in the next else)
		}

	}
	else
	{
		HEADER_HEAP_ELEMENT* PrevBlockHeader = NULL;
		AllocatedHeader = (HEADER_HEAP_ELEMENT*)HeapInfo->AllocatedSeparateBlocks;
		do
		{
			if (AllocatedHeader == NULL)
			{
				LeaveCriticalSection(&CriticalSection);
				return;
			}
			else if (AllocatedHeader->PointerToBuffer == (DWORD)ptr)
			{
				if ( PrevBlockHeader != NULL)AllocatedHeader->pNextFreeListItem = AllocatedHeader->pNextFreeListItem;
				AllocatedHeader->pNextFreeListItem = HeapInfo->FreeSeparateBlocks;
				HeapInfo->FreeSeparateBlocks = (DWORD)AllocatedHeader;
				AllocatedHeader->IsAllocated = FALSE;
				VirtualFree(ptr,0,MEM_RELEASE);
				break;
			}
			PrevBlockHeader = AllocatedHeader;
			AllocatedHeader = (HEADER_HEAP_ELEMENT*)AllocatedHeader->pNextFreeListItem;
		}while(1);
		//cout << "Free 3: Size: " << AllocatedHeader->Size << " New Item: " << (int*)AllocatedHeader << " Old Item: " << (int*)AllocatedHeader->pNextFreeListItem << "\n";
	}
	LeaveCriticalSection(&CriticalSection);
}

cMemoryManager::~cMemoryManager()
{
	HEADER_HEAP_ELEMENT* AllocatedHeader = (HEADER_HEAP_ELEMENT*)HeapInfo->AllocatedSeparateBlocks;
	do
	{
		if (AllocatedHeader == NULL)
		{
			break;
		}
		else
		{
			VirtualFree((LPVOID)AllocatedHeader->PointerToBuffer,0,MEM_RELEASE);
		}
		AllocatedHeader = (HEADER_HEAP_ELEMENT*)AllocatedHeader->pNextFreeListItem;
	}while(1);

	VirtualFree((LPVOID)pHeaderHeap,0,MEM_RELEASE);
	VirtualFree((LPVOID)pBufferHeap,0,MEM_RELEASE);
}

void cMemoryManager::FreeMemThread(DWORD Tid)
{
	HEADER_HEAP_ELEMENT* AllocatedHeader = (HEADER_HEAP_ELEMENT*)(pHeaderHeap + sizeof(HEAP_INFO));
	for (int i = 0;i < HeapInfo->nElements;i++)
	{
		if (AllocatedHeader[i].Tid == Tid && AllocatedHeader[i].IsAllocated == FALSE && AllocatedHeader[i].IsGlobal == FALSE)
		{
			Free((void*)(AllocatedHeader[i].PointerToBuffer + sizeof(BUFFER_HEAP_ELEMENT)));
		}
	}
}

//-----------------------------------------------------------
//Memory Allocation:
//------------------

cMemoryManager* mem = NULL;

void SetMemoryAllocator(cMemoryManager* MemoryAllocator)
{
	mem = MemoryAllocator;
}

void * __cdecl malloc_t(_In_ size_t _Size)
{
	if (mem != NULL)
	{
		//cout << "MemAlloc: ";
		return mem->Allocate(_Size);
	}
	else
	{
		//cout << mem << "\n";
		//cout << "HeapAlloc: " << _Size << "\n";
		return (void*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,_Size);
	};
};
void __cdecl free_t(_Inout_opt_ void * _Memory)
{
	if (mem != NULL)
	{
		return mem->Free(_Memory);
	}else
	{
		//cout << "HeapFree: " << _Memory << "\n";
		HeapFree(GetProcessHeap(),NULL,_Memory);
	}
};

void *operator new(size_t size)
{
	void *p = malloc(size);

	if (!p)
	{
		throw std::bad_alloc();
	}

	return p;
}

void operator delete(void *p)
{
	free(p);
}

void *operator new(size_t size, const std::nothrow_t &) throw() 
{
	return malloc(size);
}

void operator delete(void *p, const std::nothrow_t &)
{
	free(p);
}

void *operator new[](size_t size)
{
	void *p = malloc(size);

	if (!p)
	{
		throw std::bad_alloc();
	}

	return p;
}

void operator delete[](void *p) 
{
	free(p);
}

void *operator new[](size_t size, const std::nothrow_t &)
{
	return malloc(size);
}

void operator delete[](void *p, const std::nothrow_t &)
{
	free(p);
}