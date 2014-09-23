#include "stdafx.h"
#include "NSISEmulator.h"
#include <string>
#include "NsisDecompiler.h"


CNSISEmulator::CNSISEmulator(void)
{
	_breakByStep = false;
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
		_source_code_view->InsertItem(i,num);
		_source_code_view->SetItemText(i,1,file->_nsis_script_code[i].c_str());
	}
	SendMessage(theApp.GetMainWnd()->GetSafeHwnd(),WM_USER+100,10,0);

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
		SendMessage(theApp.GetMainWnd()->GetSafeHwnd(),WM_USER+100,pos,0);
		while (_breakByStep == false)
		{
			Sleep(1);
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

void  myitoa(TCHAR *s, int d)
{
	static const TCHAR c[] = _T("%d");
	sprintf_s(s,NSIS_MAX_STRLEN,c,d);
}

DWORD WINAPI ThreadProc(CONST LPVOID lpParam) 
{
	CNSISEmulator * emul = (CNSISEmulator*) lpParam;
	emul->Run();
	ExitThread(0);
}

void CNSISEmulator::Execute()
{
	CreateThread(NULL, 0, &ThreadProc, this, 0, NULL);
}

int CNSISEmulator::ExecuteEntry(int entry_id)
{
	char buff[0x1000];
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
			TCHAR buff[NSIS_MAX_STRLEN] = {0};
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
	default:
		int f= 0;
		break;
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