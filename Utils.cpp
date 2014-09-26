#include "stdafx.h"
#include "Utils.h"

// Jim Park: Keep these as chars since there's only ANSI version of
// GetProcAddress.
struct MGA_FUNC
{
	const char *dll;
	const char *func;
};

struct MGA_FUNC MGA_FUNCS[] = {
	{"KERNEL32", "GetDiskFreeSpaceExA"},
	{"KERNEL32", "MoveFileExA"},
	{"ADVAPI32", "RegDeleteKeyExA"},
	{"ADVAPI32", "OpenProcessToken"},
	{"ADVAPI32", "LookupPrivilegeValueA"},
	{"ADVAPI32", "AdjustTokenPrivileges"},
	{"KERNEL32", "GetUserDefaultUILanguage"},
	{"SHLWAPI",  "SHAutoComplete"},
	{"SHFOLDER", "SHGetFolderPathA"}
};


TCHAR * mystrcpy(TCHAR *out, const TCHAR *in)
{
	return lstrcpyn(out, in, NSIS_MAX_STRLEN);
}


void  myitoa(TCHAR *s, int d)
{
	static const TCHAR c[] = _T("%d");
	sprintf_s(s,NSIS_MAX_STRLEN,c,d);
}

TCHAR * findchar(TCHAR *str, TCHAR c)
{
	while (*str && *str != c)
	{
		str = CharNext(str);
	}
	return str;
}

TCHAR * skip_root(TCHAR *path)
{
	TCHAR *p = CharNext(path);
	TCHAR *p2 = CharNext(p);

	if (*path && p[0] == _T(':') && p[1] == _T('\\')) // *(WORD*)p == CHAR2_TO_WORD(_T(':'), _T('\\')))
	{
		return CharNext(p2);
	}
	else if (path[0] == _T('\\') && path[1] == _T('\\')) // *(WORD*)path == CHAR2_TO_WORD(_T('\\'),_T('\\')))
	{
		// skip host and share name
		int x = 2;
		while (x--)
		{
			p2 = findchar(p2, _T('\\'));
			if (!*p2)
				return NULL;
			p2++; // skip backslash
		}

		return p2;
	}
	else
		return NULL;
}


int myatoi(TCHAR *s)
{
	unsigned int v=0;
	int sign=1; // sign of positive
	TCHAR m=10; // base of 10
	TCHAR t=_T('9'); // cap top of numbers at 9

	if (*s == _T('-'))
	{
		s++;  //skip over -
		sign=-1; // sign flip
	}

	if (*s == _T('0'))
	{
		s++; // skip over 0
		if (s[0] >= _T('0') && s[0] <= _T('7'))
		{
			m=8; // base of 8
			t=_T('7'); // cap top at 7
		}
		if ((s[0] & ~0x20) == _T('X'))
		{
			m=16; // base of 16
			s++; // advance over 'x'
		}
	}

	for (;;)
	{
		int c=*s++;
		if (c >= _T('0') && c <= t) c-=_T('0');
		// clever little trick to do both upper and lowercase A-F.
		else if (m==16 && (c & ~0x20) >= _T('A') && (c & ~0x20) <= _T('F')) c = (c & 7) + 9;
		else break;
		v*=m;
		v+=c;
	}
	return ((int)v)*sign;
}

// mini_memcpy takes the number of bytes to copy.
void  mini_memcpy(void *out, const void *in, int len)
{
	char *c_out=(char*)out;
	char *c_in=(char *)in;
	while (len-- > 0)
	{
		*c_out++=*c_in++;
	}
}

int validpathspec(TCHAR *ubuf)
{
	TCHAR dl = ubuf[0] | 0x20; // convert alleged drive letter to lower case
	// TCHAR dl = _totlower(ubuf[0]);
	//  return ((*(WORD*)ubuf==CHAR2_TO_WORD(_T('\\'),_T('\\'))) || (dl >= _T('a') && dl <= _T('z') && ubuf[1]==_T(':')));
	return ((ubuf[0] == _T('\\') && ubuf[1] == _T('\\')) ||
		(dl >= _T('a') && dl <= _T('z') && ubuf[1] == _T(':')));
}

void validate_filename(TCHAR *in) 
{
	TCHAR *nono = _T("*?|<>/\":");
	TCHAR *out;
	TCHAR *out_save;

	// ignoring spaces is wrong, _T(" C:\blah") is invalid
	//while (*in == _T(' ')) in = CharNext(in);

	if (in[0] == _T('\\') && in[1] == _T('\\') && in[2] == _T('?') && in[3] == _T('\\'))
	{
		// at least four bytes
		in += 4;
	}
	if (*in)
	{
		// at least two bytes
		if (validpathspec(in)) in += 2;
	}
	out = out_save = in;
	while (*in)
	{
		if ((_TUCHAR)*in > 31 && !*findchar(nono, *in))
		{
			mini_memcpy(out, in, CharNext(in) - in);
			out = CharNext(out);
		}
		in = CharNext(in);
	}
	*out = 0;
	do
	{
		out = CharPrev(out_save, out);
		if (*out == _T(' ') || *out == _T('\\'))
			*out = 0;
		else
			break;
	} while (out_save < out);
}

int mystrlen(const TCHAR *in)
{
	return lstrlen(in);
}

// Jim Park: This function is non-reentrant because of the static.
WIN32_FIND_DATA * file_exists(TCHAR *buf)
{
	HANDLE h;
	static WIN32_FIND_DATA fd;
	h = FindFirstFile(buf,&fd);
	if (h != INVALID_HANDLE_VALUE)
	{
		FindClose(h);
		return &fd;
	}
	return NULL;
}

int is_valid_instpath(TCHAR *s)
{
	static TCHAR tmp[NSIS_MAX_STRLEN];
	TCHAR *root;

	mystrcpy(tmp, s);

	root = skip_root(tmp);

	if (!root)
		return 0;

	// must be called after skip_root or AllowRootDirInstall won't work.
	// validate_filename removes trailing blackslashes and so converts
	// "C:\" to "C:" which is not a valid directory. skip_root returns
	// NULL for "C:" so the above test returns 0.
	// validate_filename is called so directories such as "C:\ " will
	// not pass as a valid non-root directory.
	validate_filename(root);

	if (!*root || *root == _T('\\'))
		return 0;

	while (mystrlen(tmp) > root - tmp)
	{
		WIN32_FIND_DATA *fd = file_exists(tmp);
		// if the directory bit not set then it's a file, which is not a valid inst dir...
		// GetFileAttributes is not used because it doesn't work with certain files (error 32)
		// as for concerns of the user using * or ?, that's invalid anyway...
		if (fd && !(fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			return 0;
		trimslashtoend(tmp);
	}

	// if the root drive exists
	addtrailingslash(tmp); // don't check the current directory, check the root directory
	if (GetFileAttributes(tmp) == INVALID_FILE_ATTRIBUTES)
		return 0;

	return 1;
}

TCHAR * mystrcat(TCHAR *out, const TCHAR *concat)
{
	return lstrcat(out, concat);
}

TCHAR *addtrailingslash(TCHAR *str)
{
	if (lastchar(str)!=_T('\\')) mystrcat(str,_T("\\"));
	return str;
}

// Separates a full path to the directory portion and file name portion
// and returns the pointer to the filename portion.
TCHAR *  trimslashtoend(TCHAR *buf)
{
	TCHAR *p = buf + mystrlen(buf);
	do
	{
		if (*p == _T('\\'))
			break;
		p = CharPrev(buf, p);
	} while (p > buf);

	*p = 0;

	return p + 1;
}

void remove_ro_attr(TCHAR *file)
{
	int attr = GetFileAttributes(file);
	if (attr != INVALID_FILE_ATTRIBUTES)
		SetFileAttributes(file,attr&(~FILE_ATTRIBUTE_READONLY));
}

void *  myGetProcAddress(const enum myGetProcAddressFunctions func)
{
	const char *dll = MGA_FUNCS[func].dll;
	HMODULE hModule = GetModuleHandleA(dll);
	if (!hModule)
		hModule = LoadLibraryA(dll);
	if (!hModule)
		return NULL;

	return GetProcAddress(hModule, MGA_FUNCS[func].func);
}


/**
 * MoveFileOnReboot tries to move a file by the name of pszExisting to the
 * name pszNew.
 *
 * @param pszExisting The old name of the file.
 * @param pszNew The new name of the file.
 */
void  MoveFileOnReboot(LPCTSTR pszExisting, LPCTSTR pszNew)
{
  BOOL fOk = 0;
  typedef BOOL (WINAPI *mfea_t)(LPCTSTR lpExistingFileName,LPCTSTR lpNewFileName,DWORD dwFlags);
  mfea_t mfea;
  mfea=(mfea_t) myGetProcAddress(MGA_MoveFileEx);
  if (mfea)
  {
    fOk=mfea(pszExisting, pszNew, MOVEFILE_DELAY_UNTIL_REBOOT|MOVEFILE_REPLACE_EXISTING);
  }
  
   if (!fOk)
  {
   // RenameViaWininit(pszExisting, pszNew);
  }

#ifdef NSIS_SUPPORT_REBOOT
  g_exec_flags.exec_reboot++;
#endif
}

void myDelete(TCHAR *buf, int flags)
{
	static TCHAR lbuf[NSIS_MAX_STRLEN];

	HANDLE h;
	WIN32_FIND_DATA fd;
	TCHAR *fn;
	int valid_dir=is_valid_instpath(buf);

	if ((flags & DEL_SIMPLE))
	{
		DeleteFile(buf);
		return;
	}
	if (!(flags & DEL_DIR) || (valid_dir && (flags & DEL_RECURSE)))
	{
		mystrcpy(lbuf,buf);

		if (flags & DEL_DIR)
			mystrcat(lbuf,_T("\\*.*"));
		else
			trimslashtoend(buf);

		// only append backslash if the path isn't relative to the working directory [bug #1851273]
		if (*buf || *lbuf == _T('\\'))
			mystrcat(buf,_T("\\"));

		fn=buf+mystrlen(buf);

		h = FindFirstFile(lbuf,&fd);
		if (h != INVALID_HANDLE_VALUE)
		{
			do
			{
				TCHAR *fdfn = fd.cFileName;
				if (*findchar(fdfn, _T('?')) && *fd.cAlternateFileName)
					// name contains unicode, use short name
						fdfn = fd.cAlternateFileName;


				if (fdfn[0] == _T('.') && !fdfn[1]) continue;
				if (fdfn[0] == _T('.') && fdfn[1] == _T('.') && !fdfn[2]) continue;
				{
					mystrcpy(fn,fdfn);
					if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						if ((flags & (DEL_DIR | DEL_RECURSE)) == (DEL_DIR | DEL_RECURSE))
						{
							myDelete(buf,flags);
						}
					}
					else
					{
						
						remove_ro_attr(buf);
						if (!DeleteFile(buf))
						{
							if (flags & DEL_REBOOT)
							{
								MoveFileOnReboot(buf,NULL);
							}
							else
							{
								
							}
						}
						else
						{
						}
					}
				}
			} while (FindNextFile(h,&fd));
			FindClose(h);
		}

		if (flags & DEL_DIR)
			fn[-1]=0;
	}

}


HANDLE  myOpenFile(const TCHAR *fn, DWORD da, DWORD cd)
{
	int attr = GetFileAttributes(fn);
	return CreateFile(
		fn,
		da,
		FILE_SHARE_READ,
		NULL,
		cd,
		attr == INVALID_FILE_ATTRIBUTES ? 0 : attr,
		NULL
		);
}

void *  NSISGetProcAddress(HANDLE dllHandle, TCHAR* funcName)
{
#ifdef _UNICODE
	char* ansiName;
	void* funcPtr = NULL;

	ansiName = (char*) GlobalAlloc(GPTR, NSIS_MAX_STRLEN);

	if (WideCharToMultiByte(CP_ACP, 0, funcName, -1, ansiName, NSIS_MAX_STRLEN, NULL, NULL) != 0)
	{
		funcPtr = GetProcAddress(dllHandle, ansiName);
	}
	else
	{
		funcPtr = NULL;
	}

	GlobalFree((HGLOBAL)ansiName);
	return funcPtr;

#else
	return GetProcAddress((HMODULE)dllHandle, funcName);
#endif
}

