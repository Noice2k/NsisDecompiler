#include "stdafx.h"
#include "NSISDebuggerCore.h"
#include <string>
#include "NsisDecompiler.h"
#include "Utils.h"
#include "TlHelp32.h"
#include "Psapi.h"


/************************************************************************/
/*                                                                      */
/************************************************************************/
CNSISDebuggerCore::CNSISDebuggerCore(void)
{
	_need_do_step = false;
	_need_run_to_point = false;
	_need_terminate_main_tread = false;
}


/************************************************************************/
/*                                                                      */
/************************************************************************/
CNSISDebuggerCore::~CNSISDebuggerCore(void)
{

}


void EnableSetDebugPrivilege()
{
	// Enable SeDebugPrivilege
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPriv;
	LUID luidDebug;
	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) != FALSE) 
	{
		if(LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug) != FALSE)
		{
			tokenPriv.PrivilegeCount           = 1;
			tokenPriv.Privileges[0].Luid       = luidDebug;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if(AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL) != FALSE)
			{
				// Always successful, even in the cases which lead to OpenProcess failure
				//cout << "SUCCESSFULLY CHANGED TOKEN PRIVILEGES" << endl;
				int i=0;
			}
			else
			{
				//cout << "FAILED TO CHANGE TOKEN PRIVILEGES, CODE: " << GetLastError() << endl;
				int i=0;
			}
		}
	}
	CloseHandle(hToken);
	// Enable SeDebugPrivilege
	/////////////////////////////////////////////////////////
}

DWORD WINAPI ThreadProc(CONST LPVOID lpParam) 
{
	CNSISDebuggerCore * debugger = (CNSISDebuggerCore*) lpParam;
	if (debugger->AttachToProcess())
	{
		debugger->Run();
	}
	
	ExitThread(0);
}

/************************************************************************/
//	получить список процессов
/************************************************************************/
HANDLE CNSISDebuggerCore::FindProcess()
{
	HANDLE hProcessSnap;
	HANDLE hfindProcess = NULL;
	std::string process_string;
	PROCESSENTRY32 pe32;
	

	// Take a snapshot of all processes in #the system.
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE ) 
	{
		return( FALSE );
	}
	// Set the size of the structure before using it.
	pe32.dwSize = sizeof( PROCESSENTRY32 );

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if( !Process32First( hProcessSnap, &pe32 ) )
	{
		CloseHandle( hProcessSnap );          // clean the snapshot object
		return( FALSE );
	}
	TCHAR name[MAX_PATH];
	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		HANDLE hProcessHandle = NULL;
		
		hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS , FALSE, pe32.th32ProcessID);
		if (hProcessHandle != NULL) 
		{
			DWORD res = GetModuleFileNameEx(hProcessHandle, NULL, name, MAX_PATH);
			if ( res != 0) 
			{
				process_string = name;
				if (process_string == filename)
				{
					hfindProcess = hProcessHandle;
					break;
				}
			} 
			
			CloseHandle(hProcessHandle);
		}
		
	} while( Process32Next( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );
	return hfindProcess;
}

/************************************************************************/
//	
/************************************************************************/
bool CNSISDebuggerCore::AttachToProcess()
{
	EnableSetDebugPrivilege();

	CloseProcess();

	STARTUPINFO cif;
	ZeroMemory(&cif,sizeof(STARTUPINFO));
	memset(&_debug_process_info,0,sizeof(_debug_process_info));
	std::string cmdline = filename + " /NCRC";
	BOOL bres = CreateProcess(filename.c_str(),(LPSTR)cmdline.c_str(),NULL,NULL,FALSE,0,NULL,NULL,&cif,&_debug_process_info);
	Sleep(1000);

	hproc = FindProcess();
	/*HANDLE hproc = FindProcess();

	stack_t st;
	DWORD pst = ReadReg("vars");
	DWORD size = NSIS_MAX_STRLEN*sizeof(WCHAR)*_nsis_core->_global_vars._max_var_count;
	DWORD ret = 0;
	WCHAR *uservar  = (WCHAR*) GlobalAlloc(GPTR,size);
	
	ReadProcessMemory(hproc,(LPVOID)pst,uservar,size,&ret);
	*/

	return true;

}

/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNSISDebuggerCore::CopyStrToWstr(char * in,WCHAR *out)
{
	std::wstring ws;
	ws.insert(ws.begin(),in,in+strlen(in));
	memset(out,0,NSIS_MAX_STRLEN*sizeof(WCHAR));
	memcpy(out,&ws[0],ws.size()*sizeof(WCHAR));
}

/************************************************************************/
//
/************************************************************************/
void CNSISDebuggerCore::CreateStack()
{
	/*
	g_st = NULL;
	stack_t * next = NULL;
	for (unsigned i = 0x00;i<_stack.size();i++)
	{
		std::string str = _stack[i];
		stack_t *st = (stack_t *)GlobalAlloc(GPTR,sizeof(stack_t));
		//stack_t *st = new stack_t;
		CopyStrToWstr((char*)str.c_str(),st->text);
		if (g_st == NULL)
		{
			g_st = st;
			st->next = NULL;
			next = g_st;
		}
		else
		{
			next->next = st;
			st->next = NULL;
			next = st;
		}
		
	}

	g_usrvars = (WCHAR*) GlobalAlloc(GPTR,NSIS_MAX_STRLEN*sizeof(WCHAR)*file->_global_vars._max_var_count);
	for (int i = 0x00; i< file->_global_vars._max_var_count -1; i++)
	{
		std::string var = file->_global_vars.GetVarValue(i);
		WCHAR *w =  g_usrvars+ i * NSIS_MAX_STRLEN;
		CopyStrToWstr((char*)var.c_str(),w);
	}
	*/
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNSISDebuggerCore::Execute()
{
	CreateThread(NULL, 0, &ThreadProc, this, 0, NULL);
}

/************************************************************************/
//
/************************************************************************/
DWORD CNSISDebuggerCore::ReadReg(char *key)
{
	DWORD res = 0;
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_CURRENT_USER,"Software\\NSIS_debug", 0, KEY_READ , &hKey) == ERROR_SUCCESS)
	{
		DWORD l = sizeof(DWORD);
		DWORD t;
		// Jim Park: If plain text in p or binary data in p,
		// user must be careful in accessing p correctly.
		if (RegQueryValueEx(hKey,key,NULL,&t,(LPBYTE)&res,&l) != ERROR_SUCCESS ||(t != REG_DWORD && t != REG_SZ && t != REG_EXPAND_SZ))
		{
			res = 0;
		}
	}
	RegCloseKey(hKey);
	return res;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
bool CNSISDebuggerCore::CloseProcess()
{
	HANDLE proc = FindProcess();
	while (proc!= NULL)
	{
		TerminateProcess(proc,0);
		proc = FindProcess();
	}
	return true;
}
/************************************************************************/
//
/************************************************************************/
void  CNSISDebuggerCore::WriteReg(char*key, DWORD value)
{
	DWORD res = 0;
	HKEY hKey;
	
	if (RegOpenKeyEx(HKEY_CURRENT_USER,"Software\\NSIS_debug", 0, KEY_WRITE , &hKey) == ERROR_SUCCESS)
	{
		RegSetValueEx(hKey,key,0,REG_DWORD,(const BYTE *)&value,sizeof(DWORD));
		RegCloseKey(hKey);
	}
}

/************************************************************************/
//	
/************************************************************************/
void CNSISDebuggerCore::ReadSteckAndVars()
{
	DWORD size = NSIS_MAX_STRLEN*sizeof(WCHAR)*(_nsis_core->_global_vars._max_var_count-3);
	DWORD ret = 0;
	BYTE *uservar  = new BYTE[size];
	DWORD pst = ReadReg("vars");
	//ReadProcessMemory(_debug_process_info.hProcess,(LPVOID)pst,uservar,size,&ret);
	BOOL res = ReadProcessMemory(hproc,(LPVOID)pst,uservar,size,&ret);
	if (ret == size)
	{
		CFile file;
		file.Open("d:\\dump.txt",CFile::modeCreate|CFile::modeWrite,NULL);
		file.Write(uservar,size);
		file.Close();
		for (int i = 0x00;i < _nsis_core->_global_vars._max_var_count -3;i++)
		{
			byte * pp = uservar+ i*(NSIS_MAX_STRLEN*sizeof(WCHAR))+i*8;
			WCHAR *w = (WCHAR*)(uservar+ i*(NSIS_MAX_STRLEN*sizeof(WCHAR))+i*8);
			std::string str(w,w+lstrlenW(w));
			_nsis_core->_global_vars.SetVarValue(i,str);
			
		}
	}
	delete uservar;
	_stack.resize(0);

	stack_t stack;
	pst = ReadReg("stack");
	
	while (pst != 0)
	{
		size = sizeof(stack_t);
		res = ReadProcessMemory(hproc,(LPVOID)pst,&stack,size,&ret);
		if (ret == size)
		{
			pst = (DWORD)stack.next;
			WCHAR *w = (WCHAR*)stack.text;
			std::string str(w,w+lstrlenW(w));
			_stack.push_back(str);

		}
		else
		{
			break;
		}
	}
	
}

/************************************************************************/
//	
/************************************************************************/
DWORD CNSISDebuggerCore::FindReturnPoint()
{
	DWORD pos = ReadReg("pos");
	DWORD startpos = pos;
	while (pos < _nsis_core->_nsis_script_code.size())
	{
		std::string str = _nsis_core->_nsis_script_code[pos];
		if (str.find("return") == 0x00)
		{
			break;
		}
		pos ++;
	}
	if (startpos == pos)
	{
		pos = 0xFFFFFFFF;
	}
	return pos;
}

/************************************************************************/
//	основной цикл программы
/************************************************************************/
void CNSISDebuggerCore::Run()
{
	DWORD last_code_position = 0;

	//	крутимся в цикле
	while ( false == _need_terminate_main_tread )
	{
		// read the current point
		DWORD pos = ReadReg("pos");

		if (_need_run_to_point == true)
		{
			if (pos == _run_to_point)
			{
				_need_run_to_point = false;
				_need_do_step = false;
				last_code_position = pos;
				ReadSteckAndVars();
				SendMessage(theApp.GetMainWnd()->GetSafeHwnd(),WM_USER+100,(WPARAM)pos,0);
			}
			else
			{
				Sleep(10);

				DWORD NeedWait = ReadReg("wait");
				if (NeedWait == 0)
				{
					WriteReg("wait",1);
				}
			}
			continue;
		}

		if (pos != last_code_position)
		{
			last_code_position = pos;
			ReadSteckAndVars();
			SendMessage(theApp.GetMainWnd()->GetSafeHwnd(),WM_USER+100,(WPARAM)pos,0);
		}
		if (_need_do_step == true)
		{
			//	write do step
			WriteReg("wait",1);
			_need_do_step = false;
		}
		else
		{
			Sleep(1);
		}
	}
	

}