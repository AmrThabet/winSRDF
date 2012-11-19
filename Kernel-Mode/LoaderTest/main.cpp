#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <iostream>
#include "userRDF.h"


using namespace RDF;
using namespace std;

int main( int argc, char *argv[ ] ){
    //
  if (argc < 3)
  {
       cout << "Loader.exe <DriverName> <DriverFilename>  ... ex: Loader.exe driver.sys C:\\driver.sys"; 
       return 0;
  } 
  cDriver* Amr = new cDriver(argv[1], argv[2]);
  Amr->LoadDriver();   
  system("pause");
  cout << argv[1] <<"\n";
  /*Amr->UserComm[0] = new cDevice("\\\\.\\rootkit03");
  Amr->UserComm[0]->Write(1,0,"SRDF Kernel Mode ",sizeof("SRDF Kernel Mode "));
  Amr->UserComm[1] = new cDevice("\\\\.\\rootkit03");
  Amr->UserComm[1]->Write(1,0,"SRDF Kernel Mode !!! ",sizeof("SRDF Kernel Mode !!! "));
  Sleep(1000);
  delete Amr->UserComm[0];
  delete Amr->UserComm[1];
  */
  system("pause");
  Amr->UnloadDriver();
  system("pause");
};
 
