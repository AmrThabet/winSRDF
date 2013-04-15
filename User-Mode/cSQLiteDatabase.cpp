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
using namespace Security::Storage::Databases;
#ifdef USE_SQLITE
cSQLiteDatabase::~cSQLiteDatabase()
{
	CloseDatabase();
}
bool cSQLiteDatabase::OpenDatabase(cString Filename)
{
	EnterCriticalSection(&CriticalSection);
	if(sqlite3_open(Filename, &DB) != SQLITE_OK)return false;
	IsDatabaseOpened = true;
	LeaveCriticalSection(&CriticalSection);
    return true;  
}


cHash* cSQLiteDatabase::GetItems(cString TableName)
{

	sqlite3_stmt* QueryTableStm;
	cString Query;
	int result = 0;
	cHash* Values = new cHash();
	Query << "select * from " << TableName;
	if (!IsDatabaseOpened) return NULL;
	EnterCriticalSection(&CriticalSection);
	if(sqlite3_prepare_v2(DB, Query, -1, &QueryTableStm, 0) != SQLITE_OK)return NULL;

    while(true)
    {
        result = sqlite3_step(QueryTableStm);
        if(result == SQLITE_ROW)
        {
			Values->AddItem(cString(sqlite3_column_int(QueryTableStm, 0)),cString((char*)sqlite3_column_text(QueryTableStm, 1)));
        }
        else
        {
            break;  
        }
    }
    sqlite3_finalize(QueryTableStm);
	LeaveCriticalSection(&CriticalSection);
	return Values;
}
cString cSQLiteDatabase::GetItem(cString TableName,int id)
{
	sqlite3_stmt* QueryTableStm;
	cString Query;
	int result = 0;
	cString Value;
	Query << "select * from " << TableName << " where id = ? ";
	if (!IsDatabaseOpened) return "";
	EnterCriticalSection(&CriticalSection);
	if(sqlite3_prepare_v2(DB, Query, -1, &QueryTableStm, 0) != SQLITE_OK)return "";
	sqlite3_reset(QueryTableStm);
	sqlite3_bind_int(QueryTableStm,1,id);
    result = sqlite3_step(QueryTableStm);
    if(result == SQLITE_ROW)
    {
		Value = (char*)sqlite3_column_text(QueryTableStm, 1);
    }
    else
    {
        Value = "";  
    }
    sqlite3_finalize(QueryTableStm);
	LeaveCriticalSection(&CriticalSection);
	return Value;
}
bool cSQLiteDatabase::AddItem(cString TableName,cString Item)
{
	sqlite3_stmt* InsertTableStm;
	cString Query;
	Query << "insert into " << TableName << " (XML) values (?)";
	if (!IsDatabaseOpened) return false;
	EnterCriticalSection(&CriticalSection);
	if(sqlite3_prepare_v2(DB, Query, -1, &InsertTableStm, 0) != SQLITE_OK)return false;
	sqlite3_reset(InsertTableStm);
	sqlite3_bind_text(InsertTableStm,1,Item,-1,SQLITE_TRANSIENT);
	int result = sqlite3_step(InsertTableStm);
	if(result != SQLITE_DONE)
	{
		sqlite3_finalize(InsertTableStm);
		LeaveCriticalSection(&CriticalSection);
		return false;
	}
	sqlite3_finalize(InsertTableStm);
	LeaveCriticalSection(&CriticalSection);
	return true;
}
bool cSQLiteDatabase::RemoveItem(cString TableName,cString Item)
{
	sqlite3_stmt* DeleteTableStm;
	cString Query;
	Query << "delete from " << TableName << " where XML = ? ";
	if (!IsDatabaseOpened) return false;
	EnterCriticalSection(&CriticalSection);
	if(sqlite3_prepare_v2(DB, Query, -1, &DeleteTableStm, 0) != SQLITE_OK)
	sqlite3_reset(DeleteTableStm);
	sqlite3_bind_text(DeleteTableStm,1,Item,-1,SQLITE_TRANSIENT);
	int result = sqlite3_step(DeleteTableStm);
	if(result != SQLITE_DONE)
	{
		sqlite3_finalize(DeleteTableStm);
		LeaveCriticalSection(&CriticalSection);
		return false;
	}
	sqlite3_finalize(DeleteTableStm);
	LeaveCriticalSection(&CriticalSection);
	return true;
}
bool cSQLiteDatabase::RemoveItem(cString TableName,int id)
{
	sqlite3_stmt* DeleteTableStm;
	cString Query;
	Query << "delete from " << TableName << " where id = ? ";
	if (!IsDatabaseOpened) return false;
	EnterCriticalSection(&CriticalSection);
	if(sqlite3_prepare_v2(DB, Query, -1, &DeleteTableStm, 0) != SQLITE_OK)
	sqlite3_reset(DeleteTableStm);
	sqlite3_bind_int(DeleteTableStm,1,id);
	int result = sqlite3_step(DeleteTableStm);
	if(result != SQLITE_DONE)
	{
		sqlite3_finalize(DeleteTableStm);
		LeaveCriticalSection(&CriticalSection);
		return false;
	}
	sqlite3_finalize(DeleteTableStm);
	LeaveCriticalSection(&CriticalSection);
	return true;
}
bool cSQLiteDatabase::CreateTable(cString TableName)
{
	sqlite3_stmt* CreateTableStm;
	cString Query;
	Query << "create table " << TableName << " (id INTEGER PRIMARY KEY ASC, XML TEXT)";
	if (!IsDatabaseOpened) return false;
	EnterCriticalSection(&CriticalSection);
	if(sqlite3_prepare_v2(DB, Query, -1, &CreateTableStm, 0) != SQLITE_OK) return false;
	int result = sqlite3_step(CreateTableStm);
	if(result != SQLITE_DONE)
	{
		sqlite3_finalize(CreateTableStm);
		LeaveCriticalSection(&CriticalSection);
		return false;
	}
	sqlite3_finalize(CreateTableStm);
	LeaveCriticalSection(&CriticalSection);
	return true;
}

void cSQLiteDatabase::CloseDatabase()
{
	EnterCriticalSection(&CriticalSection);
	sqlite3_close(DB);
	IsDatabaseOpened = false;
	LeaveCriticalSection(&CriticalSection);
}
#endif