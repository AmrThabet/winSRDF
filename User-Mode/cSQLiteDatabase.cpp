#include "stdafx.h"
#include "SRDF.h"
#include <iostream>

using namespace std;
using namespace Security::Elements::String;
using namespace Security::Storage::Databases;

#define CREATETABLE_QUERY	"create table ? (XML TEXT)"
#define QUERYTABLE_QUERY	"select * from ?"
#define INSERTTABLE_QUERY	"insert into ? (XML) values (?)"
#define DELETETABLE_QUERY	"delete from ? where XML = ? " 
#define DROPTABLE_QUERY		"drop table ?"
cSQLiteDatabase::~cSQLiteDatabase()
{
}
bool cSQLiteDatabase::OpenDatabase(cString Filename)
{
	int x = 0;
	cout << "01\n";
	if(sqlite3_open(Filename, &DB) != SQLITE_OK)return false;
	//if(x = sqlite3_prepare_v2(DB, DROPTABLE_QUERY, -1, &DropTableStm, 0) != SQLITE_OK)cout << x << "\n";//return false;
    return true;  
}


cHash* cSQLiteDatabase::GetItems(cString TableName)
{
	cString Query;
	Query << "select * from " << TableName;
	if(sqlite3_prepare_v2(DB, Query, -1, &QueryTableStm, 0) != SQLITE_OK)return NULL;
    int result = 0;
	int id = 0;
	cHash* Values = new cHash();
    while(true)
    {
        result = sqlite3_step(QueryTableStm);
        if(result == SQLITE_ROW)
        {
			Values->AddItem(cString(id),(char*)sqlite3_column_text(QueryTableStm, 0));
			id++;
        }
        else
        {
            break;  
        }
    }
    sqlite3_finalize(QueryTableStm);
	return Values;
}
bool cSQLiteDatabase::AddItem(cString TableName,cString Item)
{
	cString Query;
	Query << "insert into " << TableName << " (XML) values (?)";
	if(sqlite3_prepare_v2(DB, Query, -1, &InsertTableStm, 0) != SQLITE_OK)return false;
	sqlite3_reset(InsertTableStm);
	sqlite3_bind_text(InsertTableStm,1,Item,-1,SQLITE_TRANSIENT);
	int result = sqlite3_step(InsertTableStm);
	if(result != SQLITE_DONE)
	{
		sqlite3_finalize(InsertTableStm);
		return false;
	}
	sqlite3_finalize(InsertTableStm);
	return true;
}
bool cSQLiteDatabase::RemoveItem(cString TableName,cString Item)
{
	cString Query;
	Query << "delete from " << TableName << " where XML = ? ";
	if(sqlite3_prepare_v2(DB, Query, -1, &DeleteTableStm, 0) != SQLITE_OK)
	sqlite3_reset(DeleteTableStm);
	sqlite3_bind_text(DeleteTableStm,1,Item,-1,SQLITE_TRANSIENT);
	int result = sqlite3_step(DeleteTableStm);
	if(result != SQLITE_DONE)
	{
		sqlite3_finalize(DeleteTableStm);
		return false;
	}
	sqlite3_finalize(DeleteTableStm);
	return true;
}

bool cSQLiteDatabase::CreateTable(cString TableName)
{
	cString Query;
	Query << "create table " << TableName << " (XML TEXT)";
	if(sqlite3_prepare_v2(DB, Query, -1, &CreateTableStm, 0) != SQLITE_OK) return false;
	int result = sqlite3_step(CreateTableStm);
	if(result != SQLITE_DONE)
	{
		sqlite3_finalize(CreateTableStm);
		return false;
	}
	sqlite3_finalize(CreateTableStm);
	return true;
}

void cSQLiteDatabase::CloseDatabase()
{
	sqlite3_close(DB);
}