using namespace Security::Elements::String;

class DLLIMPORT Security::Libraries::Malware::OS::Win32::Scanning::cRecursiveScanner
{
	WIN32_FIND_DATA file_data;
public:
	int nDirectories;
	int nFiles;
	cRecursiveScanner();
	cHash* GetDrives();
	void Scan(cString DirectoryName);
	~cRecursiveScanner();
	void FindFiles(cString wrkdir);
	virtual bool DirectoryCallback(cString DirName);
	virtual void FileCallback(cString Filename,cString FullName);
};
