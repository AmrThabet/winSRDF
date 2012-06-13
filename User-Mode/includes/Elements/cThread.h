/** ou_thread.h
  * declares the Thread interface and associated classes
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

using namespace Security::Elements::Application;
using namespace Security::Elements::String;
/** class Thread
  * Represents a thread of execution
  * in the process. To create a new Thread
  * write an inherited class ot Thread and
  * override the run() function
**/
class DLLIMPORT Security::Elements::Application::cThread
{

private:
	// unsigned long* to the low-level thread object
	unsigned long* m_hThread;
	// a name to identify the thread
	cString m_strName;
	cApp* App;
public:
	cThread();
	cThread(const char* nm,cApp* App);
	virtual ~cThread();
	void setName(const char* nm);
	cString getName() const;
	DWORD start();
	virtual void run();
	void sleep(long ms);
	void suspend();
	void resume();
	void stop();

	void setPriority(int p);
	bool wait(Mutex* m,long ms=5000);
	bool wait(const char* m,long ms=5000);
	void release(Mutex* m);
	void release(const char* m);

public:
	// Thread priorities
	static const int P_ABOVE_NORMAL;
	static const int P_BELOW_NORMAL;
	static const int P_HIGHEST;
	static const int P_IDLE;
	static const int P_LOWEST;
	static const int P_NORMAL;
	static const int P_CRITICAL;
private:				
};// class Thread	

/** class Mutex
  * Represents a Mutex object to synchronize
  * access to shaed resources.
**/
class DLLIMPORT Security::Elements::Application::Mutex {
private:
	// unsigned long* to the low-level mutex object
	unsigned long* m_hMutex;
	// name to identify the mutex
	cString m_strName;
public:
	Mutex();
	Mutex(const char* nm);
	bool create(const char* nm);
	unsigned long* getMutexHandle();
	cString getName();
	void release();
	~Mutex();
};

/** class ThreadException
  * thrown by Thread and Mutex function 
  * calls
**/
class DLLIMPORT Security::Elements::Application::cThreadException {
private:
	cString msg;
public:
	cThreadException(const char* m);
	cString getMessage() const;
};	

extern "C" {
	unsigned int _ou_thread_proc(void* param);
}


				
