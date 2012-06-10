//Copyrights (c) by Yuantu Huang at 2000 ... and all rights reserved to him
//potions of this code are copyrighted by Amr Thabet at 2012 under GPL Licence

#include "stdafx.h"
#include "SRDF.h"
#include <math.h>
#include <stdio.h>
#include <iostream>

using namespace std;
using namespace Security::Elements::String;
cString::cString(const char* str)
{
	if(str == 0)
	{
		m_nLength = 0;
		m_pString = 0;
	}
	else
	{
		m_nLength = strlen(str);
		m_pString = (char*)malloc(m_nLength + 1);
		memset(m_pString,0,m_nLength + 1);
		memcpy(m_pString, str,m_nLength);
	}
}

cString::cString(const cString& str)
{ 
	if(str == 0)
	{
		m_nLength = 0;
		m_pString = 0;
	}
	else
	{
		m_nLength = str.m_nLength;
		m_pString = (char*)malloc(m_nLength + 1);
		memset(m_pString,0,m_nLength+1);
		memcpy(m_pString, str.m_pString,m_nLength); 
	}
}

cString& cString::operator +=(const cString& str)
{
	unsigned int OldLength = m_nLength;
	m_nLength += str.m_nLength;
	char* pNew = (char*)malloc(m_nLength + 1);
	memset(pNew,0,m_nLength + 1);
	memcpy(pNew, m_pString,OldLength);
	memcpy(&pNew[OldLength], str.m_pString,str.m_nLength);
	free(m_pString);
	m_pString = pNew;
	return *this;
}
cString& cString::operator <<(const cString& str)
{
	unsigned int OldLength = m_nLength;
	m_nLength += str.m_nLength;
	char* pNew = (char*)malloc(m_nLength + 1);
	memset(pNew,0,m_nLength + 1);
	memcpy(pNew, m_pString,OldLength);
	memcpy(&pNew[OldLength], str.m_pString,str.m_nLength);
	free(m_pString);
	m_pString = pNew;
	return *this;
}
cString& cString::operator =(const char* str)
{
	if (m_pString) free(m_pString);
	m_nLength = strlen(str);
	m_pString = (char*)malloc(m_nLength + 1);
	memset(m_pString,0,m_nLength+1);
	memcpy(m_pString, str,m_nLength);
	return *this;
}

cString& cString::operator =(const cString& str)
{
	if (m_pString) free(m_pString);
	m_nLength = strlen(str.m_pString);
	m_pString = (char*)malloc(m_nLength + 1);
	memset(m_pString,0,m_nLength+1);
	memcpy(m_pString, str.m_pString,m_nLength);

	return *this;
}

void cString::VarToString(const double var)
{
	char str[32];

	gcvt(var, 16, str);
	m_nLength = strlen(str);
	if (str[m_nLength - 1] == '.')
	{
		str[m_nLength - 1] = '\0';
		m_nLength --;
	}
	m_nLength = strlen(str);
	m_pString = (char*)malloc(m_nLength + 1);
	memset(m_pString,0,m_nLength+1);
	memcpy(m_pString, str,m_nLength);
}

int cString::Format(const char* format, ...)
{
	int len;
	char* MaxBuf;
	for(int i = 5; ; i ++)
	{
		len = (int)pow((float)2, i);
		MaxBuf = (char*)malloc(len+1);
		memset(MaxBuf,0,len+1);
		if (!MaxBuf) return 0;
		// some UNIX's do not support vsnprintf and snprintf
		len = _vsnprintf(MaxBuf, len, format, (char*)(&format + 1));
		if (len > 0) break;
		if (len == 0) return 0;
	}

	if (!m_pString)
	{
		m_nLength = len;
		m_pString = (char*)malloc(m_nLength + 1);
		memset(m_pString,0,m_nLength+1);
	}
	else if (m_nLength < len)
	{
		free(m_pString);
		m_nLength = len;
		m_pString = (char*)malloc(m_nLength + 1);
		memset(m_pString,0,m_nLength+1);
	}
	if (m_pString) 
		memcpy(m_pString, MaxBuf,m_nLength);
	else
		len = 0;
	free(MaxBuf);

	return len;
}

bool cString::Match(char* Wildcards, char* str)
{
	bool Yes = 1;

	//iterate and delete '?' and '*' one by one
	while(*Wildcards != '\0' && Yes && *str != '\0')
	{
		if (*Wildcards == '?') str ++;
		else if (*Wildcards == '*')
		{
			Yes = Scan(Wildcards, str);
			Wildcards --;
		}
		else
		{
			Yes = (*Wildcards == *str);
			str ++;
		}
		Wildcards ++;
	}
	while (*Wildcards == '*' && Yes)  Wildcards ++;

	return Yes && *str == '\0' && *Wildcards == '\0';
}

// scan '?' and '*'
bool cString::Scan(char*& Wildcards, char*& str)
{
	// remove the '?' and '*'
	for(Wildcards ++; *str != '\0' && (*Wildcards == '?' || *Wildcards == '*'); Wildcards ++)
		if (*Wildcards == '?') str ++;
	while ( *Wildcards == '*') Wildcards ++;
	
	// if str is empty and Wildcards has more characters or,
	// Wildcards is empty, return 
	if (*str == '\0' && *Wildcards != '\0') return false;
	if (*str == '\0' && *Wildcards == '\0')	return true; 
	// else search substring
	else
	{
		char* wdsCopy = Wildcards;
		char* strCopy = str;
		bool  Yes     = 1;
		do 
		{
			if (!Match(Wildcards, str))	strCopy ++;
			Wildcards = wdsCopy;
			str		  = strCopy;
			while ((*Wildcards != *str) && (*str != '\0')) str ++;
			wdsCopy = Wildcards;
			strCopy = str;
		}while ((*str != '\0') ? !Match(Wildcards, str) : (Yes = false) != false);

		if (*str == '\0' && *Wildcards == '\0')	return true;

		return Yes;
	}
}
int cString::Search(const char* str)
{
	char* StrCopy = m_pString;
	DWORD nBytes = strlen(str);
	if (nBytes > strlen(StrCopy))return -1;
	while(1)
	{
		for (DWORD i = 0;i <= nBytes; i++)
		{
			if (StrCopy[i] == '\0')return -1;
			if (str[i] == '\0') return ((int)StrCopy - (int)m_pString);
			if (StrCopy[i] != str[i])
			{
				break;
			}
		}
		StrCopy++;
	}
	return -1;
}

int cString::Search(const char c)
{
	char* StrCopy = m_pString;
	for (DWORD i = 0;i < (DWORD)m_nLength; i++)
	{
		if (StrCopy[i] == c)
		{
			return i;
		}
	}
	return -1;
}

bool cString::NumericParse(void* pvar, char flag)
{
	char* pTmpStr = m_pString;

	// remove the leading ' ' and '\t' at the beginning
	while (*pTmpStr == ' ' || *pTmpStr == '\t')
		pTmpStr++;

	// no desired character found
	if (strlen(pTmpStr) == 0)
		return false;

	char a = pTmpStr[0];
	if ((flag == 'b' || flag == 'C' || flag == 'S' || 
		flag == 'I' || flag == 'L') && a == '-')
		return false;

	if (flag == 'b')
	{
		bool var;
		if (strcmp(pTmpStr, "true") == 0 || strcmp(pTmpStr, "1") == 0 ||
			strcmp(pTmpStr, "TRUE") == 0) var = true;
		else if (strcmp(pTmpStr, "false") == 0 || strcmp(pTmpStr, "0") == 0 ||
			strcmp(pTmpStr, "FALSE") == 0) var = false;
		else // failed
			return false;
		memcpy(pvar, &var, sizeof(bool));
		return true;
	}
	else
	{
		double tmpvar = strtod(pTmpStr, (char**)&pTmpStr);
		if (tmpvar == 0.0 && a != '0')
			return false;   // convertion wrong

		if (flag == 'f' || flag == 'd')
		{
			// allow any float value with one 'f' or 'F' terminated
			if (*pTmpStr == 'f' || *pTmpStr == 'F') 
				pTmpStr++;
		}
		else if (flag == 'l' || flag == 'L')
		{
			// allow any float value with one 'l' or 'L terminated
			if (*pTmpStr == 'l' || *pTmpStr == 'L') 
				pTmpStr++;
		}

		switch(flag)
		{
		case 'c':
			{
				//if (tmpvar < -(0xff / 2 + 1) || tmpvar > 0xff / 2)
				if (tmpvar < -128 || tmpvar > 127)
					return false;   // onerflow
				char var = (char)tmpvar;
				memcpy(pvar, &var, sizeof(char));
			}
			break;
		case 's':
			{
				//if (tmpvar < -(0xffff / 2 + 1) || tmpvar > 0xffff / 2)
				if (tmpvar < -32768.0 || tmpvar > 32768.0)
					return false;   // onerflow
				short var = (short)tmpvar;
				memcpy(pvar, &var, sizeof(short));
			}
			break;
		case 'i':
			{
				//if (tmpvar < -(0xffffffff / 2 + 1) || tmpvar > 0xffffffff / 2)
				if (tmpvar < -2147483648.0 || tmpvar > 2147483647.0)
					return false;   // onerflow
				int var = (int)tmpvar;
				memcpy(pvar, &var, sizeof(int));
			}
			break;
		case 'l':
			{
				//if (tmpvar < -(0xffffffff / 2 + 1) || tmpvar > 0xffffffff / 2)
				if (tmpvar < -2147483648.0 || tmpvar > 2147483647.0)
					return false;   // onerflow
				long var = (long)tmpvar;
				memcpy(pvar, &var, sizeof(long));

			}
			break;
		case 'C':
			{
				//if (tmpvar < 0 || tmpvar > 0xff)
				if (tmpvar < 0.0 || tmpvar > 255)
					return false;   // onerflow
				unsigned char var = (unsigned char)tmpvar;
				memcpy(pvar, &var, sizeof(unsigned char));
			}
			break;
		case 'S':
			{
				//if (tmpvar < 0 || tmpvar > 0xffff)
				if (tmpvar < 0.0 || tmpvar > 65535.0)
					return false;   // onerflow
				unsigned short var = (unsigned short)tmpvar;
				memcpy(pvar, &var, sizeof(unsigned short));
			}
			break;
		case 'I':
			{
				//if (tmpvar < 0 || tmpvar > 0xffffffff)
				if (tmpvar < 0.0 || tmpvar > 4294967295.0)
					return false;   // onerflow
				unsigned int var = (unsigned int)tmpvar;
				memcpy(pvar, &var, sizeof(unsigned int));
			}
			break;
		case 'L':
			{
				//if (tmpvar < 0 || tmpvar > 0xffffffff)
				if (tmpvar < 0.0 || tmpvar > 4294967295.0)
					return false;   // onerflow
				unsigned long var = (unsigned long)tmpvar;
				memcpy(pvar, &var, sizeof(unsigned long));
			}
			break;
		case 'f':
			{
				if (tmpvar < -3.402823466e+38 || tmpvar > 3.402823466e+38)
					return false;   // onerflow
				float var = (float)tmpvar;
				memcpy(pvar, &var, sizeof(float));
			}
			break;
		case 'd':
			memcpy(pvar, &tmpvar, sizeof(double));
			break;
		}

		// remove the leading ' ' and '\t' at the end
		while (*pTmpStr == ' ' || *pTmpStr == '\t')
			pTmpStr++;

		if (*pTmpStr != '\0')
			return false;   // non digital character detected

		return true;
	}
}

void cString::Substr(cString Str, DWORD offset,DWORD length)
{
	if (strlen(Str) >= (length+offset))
	{
		char* buff = (char*)malloc(length+1);
		memset(buff,0,length+1);
		memcpy(buff,(char*)&(Str.GetChar()[offset]),length);
		if(m_pString != 0)free(m_pString);
		m_pString = buff;
		m_nLength = length;
	}
	//cout << strlen(Str) << "   " <<length << "   " << offset << "\n";
}
char cString::operator [](int i)
{
	if (i< m_nLength) return m_pString[i];
	else return '\0';
}