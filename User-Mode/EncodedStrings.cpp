#include "StdAfx.h"
#include "SRDF.h"
#include <stdio.h>
#include <Wincrypt.h>
#include <iostream>

using namespace std;
using namespace Security::Elements::String;
cString cMD5String::Encrypt(char* buff,DWORD length)
{
    DWORD cbRead = 0;
    BYTE rgbHash[16];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
	cString MD5Hash = "";
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;

	if (!CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))return "";
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))return "";
	if (!CryptHashData(hHash, (BYTE*)buff, length, 0))return "";
	cbHash = 16;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
		char* buff = (char*)malloc(33);
		memset(buff,0,33);
        for (DWORD i = 0; i < cbHash; i++)
        {
            sprintf(&buff[i*2],"%c%c", rgbDigits[rgbHash[i] >> 4],
                rgbDigits[rgbHash[i] & 0xf]);
        }
		MD5Hash = buff;
		//cout << "MD5Hash = "<< (char*)MD5Hash << "\n";
    }
	CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
	EncryptedString = MD5Hash;
	return MD5Hash;
}
/* 
   base64.cpp and base64.h

   Copyright (C) 2004-2008 René Nyffenegger
	
   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   René Nyffenegger rene.nyffenegger@adp-gmbh.ch

   Portions Modified by AmrThabet 2012
*/
cString base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

cString cBase64String::Encode(char *buff, DWORD length)
{
	  int i = 0;
	  int j = 0;
	  unsigned char char_array_3[3];
	  unsigned char char_array_4[4];
	  char charstr[2];
	  charstr[1] = 0;
	  while (length--)
	  {
		char_array_3[i++] = *(buff++);
		if (i == 3)
		{
		  char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		  char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		  char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		  char_array_4[3] = char_array_3[2] & 0x3f;

		  for(i = 0; (i <4) ; i++)
		  {
			charstr[0] = base64_chars[char_array_4[i]];
			EncodedString += (const char*)&charstr;
		  }
		  
		  i = 0;
		}
	  }
	  if (i)
	  {
		for(j = i; j < 3; j++)
		  char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
		{
		  charstr[0] = base64_chars[char_array_4[i]];
		  EncodedString += (const char*)&charstr;
		}

		while((i++ < 3))
		{
		  charstr[0] = '=';
		  EncodedString += (const char*)&charstr;
		}

	  }
	  return EncodedString;


}

char* cBase64String::Decode(DWORD &len)
{
  int in_len = EncodedString.GetLength();
  int i = 0;
  int j = 0;
  int in_ = 0;
  int buffIndex = 0;
  unsigned char char_array_4[4], char_array_3[3];
  len = EncodedString.GetLength()*3/4;
  char* buff = (char*)malloc(len);
  memset(buff,0,len);

  while (in_len-- && ( EncodedString[in_] != '=') && is_base64(EncodedString[in_]))
  {
    char_array_4[i++] = EncodedString[in_]; in_++;
    if (i ==4)
	{
      for (i = 0; i <4; i++)
	  {
        char_array_4[i] = (char)base64_chars.Search((const char)char_array_4[i]);
		
	  }
      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
	  {
        buff[buffIndex] = char_array_3[i];
		buffIndex++;
	  }
      i = 0;
    }
  }

  if (i)
  {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars[char_array_4[j]];

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++)
	{
		buff[buffIndex] = char_array_3[j];
		buffIndex++;
	}
  }
  return buff;
}


cString cXMLEncodedString::Encode(char* buff,DWORD length)
{
	char* newBuff = (char*)malloc(length*4);
	memset(newBuff,0,length*4);
	int j = 0;
    for( DWORD i =0; i < length; i++ )
    {
         unsigned char c = (unsigned char)buff[i];
		 
         switch( c )
         {
             case '&': memcpy(&newBuff[j],"&amp;",4);j+=4; break;
             case '<': memcpy(&newBuff[j],"&lt;",4);j+=4; break;
             case '>': memcpy(&newBuff[j],"&gt;",4);j+=4; break;
             case '"': memcpy(&newBuff[j],"&quot;",4);j+=4;break;
             case '\'': memcpy(&newBuff[j],"&apos;",4);j+=4;break;
             default:
              if ( c<32 || c>127 )
              {
				  j+= sprintf(&newBuff[j],"&#%d;",c);
                   //sRet << "&#" << (unsigned int)c << ";";
				   //j+=4;
              }
              else
              {
                  newBuff[j] = c;
				  j++;
              }
         }
    }
	EncodedString = newBuff;
	free(newBuff);
    return EncodedString;
}

char* cXMLEncodedString::Decode(DWORD &len)
{
	char* buff = (char*)malloc(EncodedString.GetLength());
	memset(buff,0,EncodedString.GetLength());
	char* str = EncodedString;
	char c;
	int i = 0;
	int j = 0;
	do
	{
		c = EncodedString[i];
		if (c == '&')
		{
			if (strncmp((char*)&str[i],"&amp;",5) == 0)
			{
				buff[j] = '&';
				j++;
				i+=5;
			}
			else if (strncmp(&str[i],"&lt;",4) == 0)
			{
				buff[j] = '<';
				j++;
				i+=4;
			}
			else if (strncmp(&str[i],"&gt;",4) == 0)
			{
				buff[j] = '>';
				j++;
				i+=4;
			}
			else if (strncmp(&str[i],"&quot;",6) == 0)
			{
				buff[j] = '"';
				j++;
				i+=6;
			}
			else if (strncmp(&str[i],"&apos;",6) == 0)
			{
				buff[j] = '\'';
				j++;
				i+=6;
			}
			else
			{
				int n = 0;
				for (n = 1; n< 6; n++)
				{
					c = str[i+n];
					if (c == ';')break;
				}
				if (n<4)return NULL;		//error
				char* num = (char*)malloc(n-2+1);
				memset(num,0,n-2+1);
				memcpy(num,&str[i+2],n-2);
				buff[j] = (char)atoi(num);
				j++;
				i+=n+1;
			}

		}
		else
		{
			buff[j] = c;
			i++;
			j++;
		}
	}while(c != 0);

	return buff;
}