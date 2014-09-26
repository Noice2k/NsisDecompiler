#include "stdafx.h"
#include "NSISEmulator.h"
#include <string>
#include "NsisDecompiler.h"
#include "Utils.h"


CNSISEmulator::CNSISEmulator(void)
{
	_breakByStep = false;
	_runtoPoint = true;
	
	g_hres = OleInitialize(NULL);

	plugin_extra_parameters.exec_flags = &g_exec_flags;
	plugin_extra_parameters.ExecuteCodeSegment = NULL;
	plugin_extra_parameters.RegisterPluginCallback = NULL;
	plugin_extra_parameters.validate_filename = NULL;

}


typedef struct _loaded_plugin
{
	struct _loaded_plugin* next;
	NSISPLUGINCALLBACK proc;
	HMODULE dll;
}
loaded_plugin;

static loaded_plugin* g_plugins = 0; // not thread safe!


BOOL NSISCALL Plugins_CanUnload(HANDLE pluginHandle)
{
	loaded_plugin* p;

	for (p = g_plugins; p; p = p->next)
	{
		if (p->dll == pluginHandle)
		{
			return FALSE;
		}
	}
	return TRUE;
}

int NSISCALL RegisterPluginCallback(HMODULE pluginHandle, NSISPLUGINCALLBACK proc)
{
	loaded_plugin* p;

	if (!Plugins_CanUnload(pluginHandle))
	{
		// already registered
		return 1;
	}

	p = (loaded_plugin*) GlobalAlloc(GPTR, sizeof(loaded_plugin));
	if (p)
	{
		p->proc   = proc;
		p->dll    = pluginHandle;
		p->next   = g_plugins;

		g_plugins = p;

		return 0;
	}

	return -1;
}


CNSISEmulator::~CNSISEmulator(void)
{
}


void CNSISEmulator::Init()
{
	_source_code_view->InsertColumn(0,"line",LVCFMT_LEFT,50);
	_source_code_view->InsertColumn(1,"code",LVCFMT_LEFT,350);

	CString num;
	for (unsigned i = 0x00;i< file->_nsis_script_code.size();i++)
	{
		num.Format("%4.4i",i);
		_source_code_view->InsertItem(i,num,0);
		_source_code_view->SetItemText(i,1,file->_nsis_script_code[i].c_str());
	}
	//SendMessage(theApp.GetMainWnd()->GetSafeHwnd(),WM_USER+100,10,0);


	_variables_vew->InsertColumn(0,"name",LVCFMT_LEFT,50);
	_variables_vew->InsertColumn(1,"value",LVCFMT_LEFT,450);
	for (int i = 0;i < file->_global_vars._max_var_count;i++)
	{
		_variables_vew->InsertItem(i,file->_global_vars.GetVarName(i).c_str(),0);

	}

	

}

void CNSISEmulator::PushPopExch(entry ent)
{
	

	if (ent.offsets[2] > 0 )
	{
		std::string str = _stack[0];
		_stack[0] = _stack[ent.offsets[2]];
		_stack[ent.offsets[2]] = str;
	}
	else
	{
		if (0 != ent.offsets[1])	// pop
		{
			file->_global_vars.SetVarValue(ent.offsets[0],_stack[0]);
			_stack.erase(_stack.begin());
		}
		else
		{	// push
			_stack.insert(_stack.begin(),file->GetNsisString(ent.offsets[0],true));

		}
	}


}



/**
 * If v is negative, then the address to resolve is actually
 * stored in the global user variables.  Convert the value
 * to integer and return.
 */
int CNSISEmulator::resolveaddr(int v)
{
  if (v < 0)
  {
	  return 0;
    //return myatoi(g_usrvars[-(v+1)]);
  }
  return v;
}

#define EXEC_ERROR 0x7FFFFFFF

int CNSISEmulator::ExecuteCodeSegment(std::string FunctionName,int pos)
{
	// create call stack
	_function_call_stack.insert(_function_call_stack.begin(),FunctionName);

	while (pos >= 0)
	{
		if (_runtoPoint == true)
		{
			if (pos == 1148)
			{
				_runtoPoint = false;
			}
		}
		else
		{
			SendMessage(theApp.GetMainWnd()->GetSafeHwnd(),WM_USER+100,pos,0);
			while (_breakByStep == false)
			{
				Sleep(1);
			}
		}
		
		_breakByStep = false;
		int rv;
		if (file->_nsis_entry[pos].which == EW_RET) 
		{
			//	remove call back
			_function_call_stack.erase(_function_call_stack.begin());
			//
			return 0;
		}
		rv=ExecuteEntry(pos);
		if (rv == EXEC_ERROR) return EXEC_ERROR;
		rv=resolveaddr(rv);
		if (!rv) 
		{ rv++; pos++; }
		else
		{
			int t=pos;
			rv--; // rv is decremented here by 1, since it was +1 on the other end.
			pos=rv; // set new position
			rv-=t; // set rv to delta for progress adjustment
		}

	}
	_function_call_stack.erase(_function_call_stack.begin());
	return 0;
	
}

HKEY CNSISEmulator::GetRegRootKey(int hRootKey)
{
	if (hRootKey)
		return (HKEY) hRootKey;

	// HKEY_LOCAL_MACHINE - HKEY_CURRENT_USER == 1
	return (HKEY) ((int) HKEY_CURRENT_USER /*+ file->_globalheader..all_user_var*/);
}


HKEY  CNSISEmulator::myRegOpenKey(entry ent,REGSAM samDesired)
{
	HKEY hKey;
	std::string path =  file->GetStringFromParm(ent,0x22,true);
	if (RegOpenKeyEx(GetRegRootKey(ent.offsets[1]),path.c_str(), 0, samDesired, &hKey) == ERROR_SUCCESS)
	{
		return hKey;
	}
	return NULL;
}


int CNSISEmulator::GetIntFromParm(int id)
{
	std::string str = file->GetNsisString(id,true);
	int i = atoi(str.c_str());
	return i;
}


TCHAR * my_GetTempFileName(TCHAR *buf, const TCHAR *dir)
{
  int n = 100;
  while (n--)
  {
    TCHAR prefix[4] = _T("nsa");
    //*(LPDWORD)prefix = CHAR4_TO_DWORD('n', 's', 'a', 0);
    prefix[2] += (TCHAR)(GetTickCount() % 26);
    if (GetTempFileName(dir, prefix, 0, buf))
      return buf;
  }
  *buf = 0;
  return 0;
}

DWORD WINAPI ThreadProc(CONST LPVOID lpParam) 
{
	CNSISEmulator * emul = (CNSISEmulator*) lpParam;
	emul->Run();
	ExitThread(0);
}


/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNSISEmulator::CopyStrToWstr(char * in,WCHAR *out)
{
	std::wstring ws;
	ws.insert(ws.begin(),in,in+strlen(in));
	memset(out,0,NSIS_MAX_STRLEN*sizeof(WCHAR));
	memcpy(out,&ws[0],ws.size()*sizeof(WCHAR));
}

/************************************************************************/
//
/************************************************************************/
void CNSISEmulator::CreateStack()
{
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

}
/************************************************************************/
//
/************************************************************************/
void CNSISEmulator::DeleteStack()
{
	_stack.resize(0);
	while (g_st != NULL)
	{
		std::string str;
		str.insert(str.begin(),g_st->text,g_st->text+wcslen(g_st->text));
		_stack.push_back(str);
		stack_t *d = g_st;
		g_st = g_st->next;
		GlobalFree((HGLOBAL)d);
	}


	for (int i = 0x00; i< file->_global_vars._max_var_count-1; i++)
	{
		WCHAR *w =  g_usrvars+ i * NSIS_MAX_STRLEN;
		std::string str;
		str.insert(str.begin(),w,w+wcslen(w));
		file->_global_vars.SetVarValue(i,str);
	}
	GlobalFree((HGLOBAL)g_usrvars);
//	delete []g_usrvars;


}

void CNSISEmulator::Execute()
{
	CreateThread(NULL, 0, &ThreadProc, this, 0, NULL);
}


int CNSISEmulator::ExecuteEntry(int entry_id)
{
	TCHAR buff[NSIS_MAX_STRLEN] = {0};
	int exec_error = 0;
	//	 get current entry
	entry	_ent = file->_nsis_entry[entry_id];

#define parm0 (_ent.offsets[0])
#define parm1 (_ent.offsets[1])
#define parm2 (_ent.offsets[2])
#define parm3 (_ent.offsets[3])
#define parm4 (_ent.offsets[4])
#define parm5 (_ent.offsets[5])

	//	execute entry
	switch (_ent.which)
	{
	case EW_CALL:
		{
			int v=resolveaddr(_ent.offsets[0]-1);  // address is -1, since we encode it as +1
			sprintf_s(buff,0x100,"function %4.4i",v);
			return ExecuteCodeSegment(buff,v);
			break;
		}
	case EW_PUSHPOP: 
		{
			PushPopExch(_ent);
		}
		break;
	case EW_STRCMP:
		{
			std::string  buf2 =file->GetStringFromParm(_ent,0x20,true);
			std::string  buf3 =file->GetStringFromParm(_ent,0x31,true);
			if (!parm4) {
				// case insensitive
				if (!lstrcmpi(buf2.c_str(),buf3.c_str())) return parm2;
			}
			else {
				// case sensitive
				if (!lstrcmp(buf2.c_str(),buf3.c_str())) return parm2;
			}
		}
		return parm3;
	case EW_ASSIGNVAR:
		{
			int newlen=GetIntFromParm(parm2);
			int start=GetIntFromParm(parm3);
			std::string buff = file->GetStringFromParm(_ent,1,true);
			int l = buff.length();
			if (start<0) start=l+start;
			if (start>=0)
			{
				if (start>l) start=l;
				std::string val = &buff[start];
				if (newlen)
				{
					if (newlen<0) newlen=val.length()+newlen;
					if (newlen<0) newlen=0;
					val.resize(newlen);
				}
				file->_global_vars.SetVarValue(parm0,val);
			}
		}
		break;
	case EW_READREGSTR: // read registry string
		{
			HKEY hKey=myRegOpenKey(_ent,KEY_READ);
			TCHAR *p=buff;
			std::string buf3 = file->GetStringFromParm(_ent,0x33,true); // buf3 == key name
			p[0]=0;
			if (hKey)
			{
				DWORD l = NSIS_MAX_STRLEN*sizeof(TCHAR);
				DWORD t;

				// Jim Park: If plain text in p or binary data in p,
				// user must be careful in accessing p correctly.
				if (RegQueryValueEx(hKey,buf3.c_str(),NULL,&t,(LPBYTE)p,&l) != ERROR_SUCCESS ||(t != REG_DWORD && t != REG_SZ && t != REG_EXPAND_SZ))
				{
					p[0]=0;
				}
				else
				{
					if (t==REG_DWORD)
					{
						myitoa(p,*((DWORD*)p));
					}
					else
					{
						p[l]=0;
					}
				}
				RegCloseKey(hKey);
			}
			file->_global_vars.SetVarValue(parm0,p);
		}break;
	case EW_CREATEDIR: 
		{
			std::string path = file->GetNsisString(parm0,true);
			TCHAR *buf1= (TCHAR *)path.c_str();
			{
				TCHAR *p = skip_root(buf1);
				TCHAR c = _T('c');
				if (p)
				{
					while (c)
					{
						p = findchar(p, _T('\\'));
						c = *p;
						*p = 0;
						if (!CreateDirectory(buf1, NULL))
						{
							if (GetLastError() != ERROR_ALREADY_EXISTS)
							{                
								int i = 0;
							}
							else if ((GetFileAttributes(buf1) & FILE_ATTRIBUTE_DIRECTORY) == 0)
							{
								int i = 0;
							}
						}
						else
						{
						}
						*p++ = c;
					}
				}
			}
			if (parm1)
			{
				//mystrcpy(state_output_directory,buf1);
				SetCurrentDirectory(buf1);
			}
		}break;
	case EW_GETTEMPFILENAME:
		{
			std::string tempfolder = file->GetNsisString(parm1,true);
			TCHAR *textout=buff;
			my_GetTempFileName(textout, tempfolder.c_str());
			file->_global_vars.SetVarValue(parm0,buff);
		}
		break;
	case EW_DELETEFILE:
		{
			std::string path = file->GetNsisString(parm0,true);
			myDelete((TCHAR *)path.c_str(),parm1);
		}
		break;
	case EW_SETFLAG:
		break;
	case EW_IFFLAG:
		{
			return parm1;
			/*int f=lent.offsets[!FIELDN(g_exec_flags,parm2)];
			FIELDN(g_exec_flags,parm2)&=parm3;
			return f;
			*/
		}break;
	case EW_EXTRACTFILE:
		{
			HANDLE hOut;
			int ret;
			std::string str = file->GetNsisString(parm1,true);
			TCHAR *buf3 = (TCHAR *)str.c_str();
			TCHAR *buf0 = &buff[0];
			int overwriteflag = parm0 & 7;

			
			if (validpathspec(buf3))
			{
				mystrcpy(buf0,buf3);
			}
			else mystrcat(addtrailingslash(mystrcpy(buf0,state_output_directory.c_str())),buf3);
			validate_filename(buf0);
			if (overwriteflag >= 3) // check date and time
			{
				WIN32_FIND_DATA *ffd=file_exists(buf0);
				// if it doesn't exist, overwrite flag will be off (though it doesn't really matter)
				int cmp=0;
				if (ffd)
				{
					cmp=CompareFileTime(&ffd->ftLastWriteTime, (FILETIME*)(_ent.offsets + 3));
				}
				overwriteflag=!(cmp & (0x80000000 | (overwriteflag - 3)));
			}
			// remove read only flag if overwrite mode is on
			if (!overwriteflag)
			{
				remove_ro_attr(buf0);
			}
			hOut=myOpenFile(buf0,GENERIC_WRITE,(overwriteflag==1)?CREATE_NEW:CREATE_ALWAYS);
			if (hOut == INVALID_HANDLE_VALUE)
			{
				if (overwriteflag)
				{
					int exec_error = 0;
					if (overwriteflag==2) exec_error++;
					
					break;
				}
			}
			{
				ret=GetCompressedDataFromDataBlock(parm2,hOut);
			}
			if (parm3 != 0xffffffff || parm4 != 0xffffffff)
				SetFileTime(hOut,(FILETIME*)(_ent.offsets+3),NULL,(FILETIME*)(_ent.offsets+3));

			CloseHandle(hOut);

			if (ret < 0)
			{
				return EXEC_ERROR;
			}

		}break;
	case EW_REGISTERDLL:
		{
			int exec_error = 0;
			if (SUCCEEDED(g_hres))
			{
				HANDLE h=NULL;
				std::string str0 = file->GetNsisString(parm0,true);
				std::string str1 = file->GetNsisString(parm1,true);
				TCHAR *buf1=(TCHAR *)str0.c_str();
				TCHAR *buf0=(TCHAR *)str1.c_str();

				if (parm4)
					h=GetModuleHandle(buf1);
				if (!h)
					h=LoadLibraryEx(buf1, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
				if (h)
				{
					// Jim Park: Need to use our special NSISGetProcAddress to convert
					// buf0 to char before calling GetProcAddress() which only takes 
					// chars.
					FARPROC funke = (FARPROC)NSISGetProcAddress(h,buf0);
					if (funke)
					{
						
						if (parm2)
						{
							if (funke())
							{
								exec_error++;
							}
						}
						else
						{
							CreateStack();
							void (*func)(HWND,int,TCHAR*,void*,void*);
							func=(void (*)(HWND,int,TCHAR*,void*,void*))funke;
							memset(&g_exec_flags,0,sizeof(g_exec_flags));
							plugin_extra_parameters.RegisterPluginCallback = RegisterPluginCallback;
							func(theApp.GetMainWnd()->GetSafeHwnd(),NSIS_MAX_STRLEN,(TCHAR*)g_usrvars,(void*)&g_st,&plugin_extra_parameters);
							DeleteStack();
						}
					}
					else
					{
						//update_status_text(LANG_CANNOTFINDSYMBOL,buf0);
						//log_printf3(_T("Error registering DLL: %s not found in %s"),buf0,buf1);
					}
					//if (!parm3 && Plugins_CanUnload(h)) FreeLibrary(h);
				}
				else
				{
					//update_status_text_buf1(LANG_COULDNOTLOAD);
					//log_printf2(_T("Error registering DLL: Could not load %s"),buf1);
				}
			}
			else
			{
				//update_status_text_buf1(LANG_NOOLE);
				//log_printf(_T("Error registering DLL: Could not initialize OLE"));
			}

		}break;
	case EW_INTFMT: 
		{
			std::string str = file->GetNsisString(parm1,true);
			std::string val = file->GetNsisString(parm2,true);
			
			sprintf_s(buff,0x100,str.c_str(),myatoi((char*)val.c_str()));
			file->_global_vars.SetVarValue(parm0,buff);

		}break;
	case EW_INTOP:
		{
			int v,v2;
			TCHAR *p=&buff[0];
			v=myatoi((TCHAR *)file->GetNsisString(parm1,true).c_str());
			v2=GetIntFromParm(2);
			switch (parm3)
			{
			case 0: v+=v2; break;
			case 1: v-=v2; break;
			case 2: v*=v2; break;
			case 3: if (v2) v/=v2; else { v=0; exec_error++; } break;
			case 4: v|=v2; break;
			case 5: v&=v2; break;
			case 6: v^=v2; break;
			case 7: v=!v; break;
			case 8: v=v||v2; break;
			case 9: v=v&&v2; break;
			case 10: if (v2) v%=v2; else { v=0; exec_error++; } break;
			case 11: v=v<<v2; break;
			case 12: v=v>>v2; break;
			}
			myitoa(p,v);
			file->_global_vars.SetVarValue(parm0,buff);
		}
		break;
	case EW_INTCMP:
		{
			int v,v2;
			v=GetIntFromParm(0);
			v2=GetIntFromParm(1);
			if (!parm5) {
				// signed
				if (v<v2) return parm3;
				if (v>v2) return parm4;
			}
			else {
				// unsigned
				if ((unsigned int)v<(unsigned int)v2) return parm3;
				if ((unsigned int)v>(unsigned int)v2) return parm4;
			}
		}
		return parm2;

	default:

		int f= 0;
		break;
	}
	return 0;
}


int CNSISEmulator::GetCompressedDataFromDataBlock(int off,HANDLE hfile)
{
	
	for (unsigned i = 0x00; i<file->_nsis_files.size();i++)
	{
		sfile s = file->_nsis_files[i];
		if (off == s.offset)
		{
			DWORD ret = 0;
			WriteFile(hfile,s.pointer,s.size,&ret,NULL);
		}
	}

	return 0;
}
void CNSISEmulator::Run()
{
	
	if (file->_globalheader.code_onInit>0)
	{
		ExecuteCodeSegment("Function OnInit",file->_globalheader.code_onInit);
	}
	
	
	

}