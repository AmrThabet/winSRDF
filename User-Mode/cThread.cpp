/** cThread.cpp
  * implements the Thread class
  * Author: Vijay Mathew Pandyalakal
  * Date: 13-OCT-2003
**/

/* Copyright 2000 - 2005 Vijay Mathew Pandyalakal.  All rights reserved.
 *
 * This software may be used or modified for any purpose, personal or
 * commercial.  Open Source redistributions are permitted.  
 *
 * Redistributions qualify as "Open Source" under  one of the following terms:
 *   
 *    Redistributions are made at no charge beyond the reasonable cost of
 *    materials and delivery.
 *
 *    Redistributions are accompanied by a copy of the Source Code or by an
 *    irrevocable offer to provide a copy of the Source Code for up to three
 *    years at the cost of materials and delivery.  Such redistributions
 *    must allow further use, modification, and redistribution of the Source
 *    Code under substantially the same terms as this license.
 *
 * Redistributions of source code must retain the copyright notices as they
 * appear in each source code file, these license terms, and the
 * disclaimer/limitation of liability set forth as paragraph 6 below.
 *
 * Redistributions in binary form must reproduce this Copyright Notice,
 * these license terms, and the disclaimer/limitation of liability set
 * forth as paragraph 6 below, in the documentation and/or other materials
 * provided with the distribution.
 *
 * The Software is provided on an "AS IS" basis.  No warranty is
 * provided that the Software is free of defects, or fit for a
 * particular purpose.  
 *
 * Limitation of Liability. The Author shall not be liable
 * for any damages suffered by the Licensee or any third party resulting
 * from use of the Software.
 */
#include "stdafx.h"

#include <windows.h>
#include "SRDF.h"
using namespace Security::Elements::Application;

const int cThread::P_ABOVE_NORMAL = THREAD_PRIORITY_ABOVE_NORMAL;
const int cThread::P_BELOW_NORMAL = THREAD_PRIORITY_BELOW_NORMAL;
const int cThread::P_HIGHEST = THREAD_PRIORITY_HIGHEST;
const int cThread::P_IDLE = THREAD_PRIORITY_IDLE;
const int cThread::P_LOWEST = THREAD_PRIORITY_LOWEST;
const int cThread::P_NORMAL = THREAD_PRIORITY_NORMAL;
const int cThread::P_CRITICAL = THREAD_PRIORITY_TIME_CRITICAL;

/**@ The Thread class implementation
**@/

/** cThread()
  * default constructor
**/  
cThread::cThread()
{
	m_hThread = NULL;
	m_strName = "null";
}

/** Thread(const char* nm)
  * overloaded constructor
  * creates a Thread object identified by "nm"
**/  
cThread::cThread(const char* nm,cApp* App)
{
	m_hThread = NULL;
	m_strName = nm;
	this->App = App;
}

cThread::~cThread()
{
	if(m_hThread != NULL) {
		stop();
	}
}

/** setName(const char* nm)
  * sets the Thread object's name to "nm"
**/  
void cThread::setName(const char* nm) {	
	m_strName = nm;
}

/** getName()
  * return the Thread object's name as a cString
**/  
cString cThread::getName() const {	
	return m_strName;
}

/** run()
  * called by the thread callback _ou_thread_proc()
  * to be overridden by child classes of Thread
**/ 
void cThread::run() {
	// Base run
}

/** sleep(long ms)
  * holds back the thread's execution for
  * "ms" milliseconds
**/ 
void cThread::sleep(long ms) {
	Sleep(ms);
}

/** start()
  * creates a low-level thread object and calls the
  * run() function
**/ 
DWORD cThread::start() {
	DWORD tid = 0;	
	m_hThread = (unsigned long*)CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)_ou_thread_proc,(cThread*)this,0,&tid);
	if(m_hThread == NULL) {
		throw cThreadException("Failed to create thread");
	}else {
		setPriority(cThread::P_NORMAL);
	}
	return tid;
}

/** stop()
  * stops the running thread and frees the thread handle
**/ 
void cThread::stop() {
	if(m_hThread == NULL) return;	
	WaitForSingleObject(m_hThread,INFINITE);
	CloseHandle(m_hThread);
	m_hThread = NULL;
}

/** setPriority(int tp)
  * sets the priority of the thread to "tp"
  * "tp" must be a valid priority defined in the
  * Thread class
**/ 
void cThread::setPriority(int tp) {
	if(m_hThread == NULL) {
		throw cThreadException("Thread object is null");
	}else {
		if(SetThreadPriority(m_hThread,tp) == 0) {
			throw cThreadException("Failed to set priority");
		}
	}
}

/** suspend()  
  * suspends the thread
**/ 
void cThread::suspend() {
	if(m_hThread == NULL) {
		throw cThreadException("Thread object is null");
	}else {
		if(SuspendThread(m_hThread) < 0) {
			throw cThreadException("Failed to suspend thread");
		}
	}
}

/** resume()  
  * resumes a suspended thread
**/ 
void cThread::resume() {
	if(m_hThread == NULL) {
		throw cThreadException("Thread object is null");
	}else {
		if(ResumeThread(m_hThread) < 0) {
			throw cThreadException("Failed to resume thread");
		}
	}
}

/** wait(const char* m,long ms)  
  * makes the thread suspend execution until the
  * mutex represented by "m" is released by another thread.
  * "ms" specifies a time-out for the wait operation.
  * "ms" defaults to 5000 milli-seconds
**/ 
bool cThread::wait(const char* m,long ms) {
	HANDLE h = OpenMutex(MUTEX_ALL_ACCESS,FALSE,m);
	if(h == NULL) {
		throw cThreadException("Mutex not found");
	}
	DWORD d = WaitForSingleObject(h,ms);
	switch(d) {
	case WAIT_ABANDONED:
		throw cThreadException("Mutex not signaled");
		break;
	case WAIT_OBJECT_0:
		return true;
	case WAIT_TIMEOUT:
		throw cThreadException("Wait timed out");
		break;
	}
	return false;
}

/** release(const char* m)  
  * releases the mutex "m" and makes it 
  * available for other threads
**/ 
void cThread::release(const char* m) {
	HANDLE h = OpenMutex(MUTEX_ALL_ACCESS,FALSE,m);
	if(h == NULL) {
		throw cThreadException("Invalid mutex handle");
	}
	if(ReleaseMutex(h) == 0) {
		throw cThreadException("Failed to release mutex");
	}
}

/**@ The Mutex class implementation
**@/

/** Mutex()
  * default constructor
**/  
Mutex::Mutex() {
	m_hMutex = NULL;
	m_strName = "";
}

/** Mutex(const char* nm)
  * overloaded constructor
  * creates a Mutex object identified by "nm"
**/  
Mutex::Mutex(const char* nm) {	
	m_strName = nm;	
	m_hMutex = (unsigned long*)CreateMutex(NULL,FALSE,nm);
	if(m_hMutex == NULL) {
		throw cThreadException("Failed to create mutex");
	}
}

/** create(const char* nm)
  * frees the current mutex handle.
  * creates a Mutex object identified by "nm"
**/  
void Mutex::create(const char* nm) {
	if(m_hMutex != NULL) {
		CloseHandle(m_hMutex);
		m_hMutex = NULL;
	}
	m_strName = nm;
	m_hMutex = (unsigned long*)CreateMutex(NULL,FALSE,nm);
	if(m_hMutex == NULL) {
		throw cThreadException("Failed to create mutex");
	}
}
/** getMutexHandle()
  * returns the handle of the low-level mutex object
**/  
unsigned long* Mutex::getMutexHandle() {
	return m_hMutex;
}

/** getName()
  * returns the name of the mutex
**/ 
cString Mutex::getName() {
	return m_strName;
}

void Mutex::release() {
	if(m_hMutex != NULL) {
		CloseHandle(m_hMutex);
	}
}

Mutex::~Mutex()
{
	/*if(m_hMutex != NULL) {
		CloseHandle(m_hMutex);
	}*/
}

// ThreadException
cThreadException::cThreadException(const char* m) {
	msg = m;
}

cString cThreadException::getMessage() const {
	return msg;
}

// global thread callback
unsigned int _ou_thread_proc(void* param) {
	cThread* tp = (cThread*)param;
	tp->run();
	return 0;
}