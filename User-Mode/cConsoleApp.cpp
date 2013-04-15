#include "stdafx.h"
#include "SRDF.h"
#include <iostream>
#include <string>
using namespace std;
using namespace Security::Core;
cConsoleApp::cConsoleApp(cString AppName) : cApp(AppName)
{
	CmdList = new cList(sizeof(CONSOLE_COMMAND));
	Prefix = "";
	AddCommand("help","Show Help","help",0,&HelpFunc);
	AddCommand("quit","Exit the Console","Quit",0,&QuitFunc);
}
cConsoleApp::~cConsoleApp()
{
	((cApp*)this)->~cApp();
}

void cConsoleApp::AddCommand(char* Name,char* Description,char* Format,DWORD nArgs,PCmdFunc CommandFunc)
{
	CONSOLE_COMMAND cmd;
	cmd.Name = new cString(Name);
	cmd.Description = new cString(Description);
	cmd.Format = new cString(Format);
	cmd.nArgs = nArgs;
	cmd.CommandFunc = CommandFunc;
	CmdList->AddItem((char*)&cmd);
}

void cConsoleApp::StartConsole()
{
	cout << Intro << "\n\n";
	
	string input;
	while(1)
	{	
		cout << Prefix << ">";
		std::getline(cin,input);
		DWORD x = input.find_first_of(" ");
		cString cmd;
		if (x < strlen(input.c_str()))
		{
			cmd = input.substr(0,x).c_str();
			input = input.substr(x+1,input.size());
		}
		else
		{
			cmd = input.c_str();
			input = "";
		}
		for (DWORD i =0;i< CmdList->GetNumberOfItems();i++)
		{
			CONSOLE_COMMAND* cmdstruct = (CONSOLE_COMMAND*)CmdList->GetItem(i);
			if (strcmp(cmd,cmdstruct->Name->GetChar()) == 0)
			{
				char** argv = (char**)malloc(sizeof(char*) * cmdstruct->nArgs);
				memset(argv,0,sizeof(char*) * cmdstruct->nArgs);
				DWORD WrittenArgs = 0;
				if (input.size() != 0)
				for (DWORD l = 0;l< cmdstruct->nArgs;l++)
				{
					DWORD next = input.find_first_of(" ");
					cString Arg;
					if (next < strlen(input.c_str()))
					{
						Arg = input.substr(0,next).c_str();
						input = input.substr(next+1,input.size());
						argv[l] = (char*)malloc(Arg.GetLength()+1);
						memset(argv[l],0,Arg.GetLength()+1);
						memcpy(argv[l],Arg.GetChar(),Arg.GetLength());
						WrittenArgs++;
					}
					else
					{
						Arg = input.c_str();
						input = "";
						argv[l] = (char*)malloc(Arg.GetLength()+1);
						memset(argv[l],0,Arg.GetLength()+1);
						memcpy(argv[l],Arg.GetChar(),Arg.GetLength());
						WrittenArgs++;
						break;
					}
					
				}
				if (WrittenArgs < cmdstruct->nArgs)
				{
					cout << "Error: Missing " << cmdstruct->nArgs - WrittenArgs << " Argument(s)\n";
					cout << "Format: " << cmdstruct->Format->GetChar() << "\n";
				}
				else
				{
					(*cmdstruct->CommandFunc)(this,cmdstruct->nArgs,argv);
				}
				for (int i = 0; i < WrittenArgs;i++)
				{
					free(argv[i]);
				}
				free(argv);
				goto CONTINUE;
			}
		}
		//didn't find the command ... return an error
		cout << "Error: Unknown Command\n";
CONTINUE:;
	}
}

void HelpFunc(cConsoleApp* App,int argc,char* argv[])
{
	App->Help(argc,argv);
}

void cConsoleApp::Help(int argc,char* argv[])
{
	cout << "\nThe Commands List:\n-------------------\n\n";
	for (DWORD i =0;i< CmdList->GetNumberOfItems();i++)
	{
		CONSOLE_COMMAND* cmdstruct = (CONSOLE_COMMAND*)CmdList->GetItem(i);
		string spacesToMargin =  ":		";
		if (strlen(cmdstruct->Name->GetChar()) > 7)spacesToMargin = ":	";
		cout << cmdstruct->Name->GetChar() << spacesToMargin << cmdstruct->Description->GetChar() << "\n";
	}
}

void QuitFunc(cConsoleApp* App,int argc,char* argv[])
{
	App->Quit(argc,argv);
}

void cConsoleApp::Quit(int argc,char* argv[])
{
	ExitProcess(Exit());
}
//-----------------------------
void cConsoleApp::SetCustomSettings()
{
	
}
int cConsoleApp::Run()
{
	return 0;
}
int cConsoleApp::Exit()
{
	return 0;
}

