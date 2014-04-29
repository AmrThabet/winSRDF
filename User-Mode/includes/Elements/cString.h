#if !defined(__STR_H__)
#define __STR_H__

#include <string.h>
#include <stdlib.h>

class DLLIMPORT Security::Elements::String::cString
{
public:
	// constructors and destructor
	cString(const cString& str);
	cString(const char* str);
	cString(const double var)				{ VarToString(var); }
	cString()								{ m_nLength = 0; m_pString = 0; }
	~cString();

	// operator overloading helper
	//template <class T> friend cString _cdecl operator +(T var, const cString& str);

	// operator overloading
	cString& operator  =(const char* str);
	cString& operator  =(const cString& str);
	cString& operator  =(const double var)	{ VarToString(var); return *this; }
	template <class T>
	cString  operator  +(T var)			{ cString tstr = *this; return tstr += var; }
	cString& operator +=(double str)		{ return *this += (cString)str; }
	cString& operator +=(const char* str)	{ return *this += (cString)str; }
	cString& operator +=(const char str)	{ return *this += (cString)str; }
	cString& operator +=(const cString& str);
	cString& operator <<(const cString& str);
	char operator [](int i);
	// add more logic comparison operators as following, for example, although not efficient
	virtual bool operator !=(char* str)	{ return strcmp(str, m_pString) != 0; }
	virtual bool operator ==(char* str)	{ return strcmp(str, m_pString) == 0; }
	virtual bool operator ==(const char str[])	{ return strcmp(str, m_pString) == 0; }
	// c type string conversion
	operator char* ()					{ return m_pString; }
	operator const char* ()	const		{ return m_pString; }
	char* GetChar()						{ return m_pString; }

	// numeric conversion
	template <class T> int GetValue(T& var)	{ return GetVar(var); }

	// search the match string : WildCards can be '?' and '*' combination
	// return value : true (pattern matchs string), false (no match)
	bool ScanWildcard(const char* WildCards)	{ return Match((char*)WildCards, m_pString); }
	int Search(const char* str);
	int Search(const char c);
	void Replace(char src, char dest);
	void Replace(const char *src, const char *dest);
	// format string
	int Format(const char* format, ...);
	void Substr(cString Str, DWORD offset,DWORD length);
	void Substr(cString Str, DWORD offset){Substr(Str,offset,strlen(Str)-offset); }
	DWORD GetLength(){return m_nLength;};
protected:
	// can use faster algorithm for search ?
	virtual bool Match(char*, char*);
	virtual bool Scan(char*&, char*&);

	// have any good conversion method ?
	virtual void VarToString(const double var);

	// numeric conversion helpers
	bool NumericParse(void* pvar, char flag);
	bool GetVar(bool& var)				{ return NumericParse((void*)&var, 'b'); }
	bool GetVar(char& var)				{ return NumericParse((void*)&var, 'c'); }
	bool GetVar(short& var)				{ return NumericParse((void*)&var, 's'); }
	bool GetVar(int& var)				{ return NumericParse((void*)&var, 'i'); }
	bool GetVar(long& var)				{ return NumericParse((void*)&var, 'l'); }
	bool GetVar(float& var)				{ return NumericParse((void*)&var, 'f'); }
	bool GetVar(double& var)			{ return NumericParse((void*)&var, 'd'); }
	bool GetVar(unsigned char& var)		{ return NumericParse((void*)&var, 'C'); }
	bool GetVar(unsigned short& var)	{ return NumericParse((void*)&var, 'S'); }
	bool GetVar(unsigned int& var)		{ return NumericParse((void*)&var, 'I'); }
	bool GetVar(unsigned long& var)		{ return NumericParse((void*)&var, 'L'); }

	// data block
	int   m_nLength;
public:
	char* m_pString;
};

/*template <class T>
Security::Elements::String::cString operator +(T var, const Security::Elements::String::cString& str) 
{ 
	Security::Elements::String::cString svar = var;
	return svar += str; 
};*/

#endif
