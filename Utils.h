#pragma once

#include "Header.h"
void myDelete(TCHAR *buf, int flags);
int is_valid_instpath(TCHAR *s);
TCHAR * mystrcpy(TCHAR *out, const TCHAR *in);
TCHAR * skip_root(TCHAR *path);
void  myitoa(TCHAR *s, int d);
void validate_filename(TCHAR *in);
TCHAR * findchar(TCHAR *str, TCHAR c);
int validpathspec(TCHAR *ubuf);
// mini_memcpy takes the number of bytes to copy.
void  mini_memcpy(void *out, const void *in, int len);
int mystrlen(const TCHAR *in);
WIN32_FIND_DATA * file_exists(TCHAR *buf);
// Separates a full path to the directory portion and file name portion
// and returns the pointer to the filename portion.
TCHAR *  trimslashtoend(TCHAR *buf);
TCHAR *addtrailingslash(TCHAR *str);
#define lastchar(str) *CharPrev(str,str+mystrlen(str))
TCHAR * mystrcat(TCHAR *out, const TCHAR *concat);
void remove_ro_attr(TCHAR *file);
void  MoveFileOnReboot(LPCTSTR pszExisting, LPCTSTR pszNew);

enum myGetProcAddressFunctions {
	MGA_GetDiskFreeSpaceEx,
	MGA_MoveFileEx,
	MGA_RegDeleteKeyEx,
	MGA_OpenProcessToken,
	MGA_LookupPrivilegeValue,
	MGA_AdjustTokenPrivileges,
	MGA_GetUserDefaultUILanguage,
	MGA_SHAutoComplete,
	MGA_SHGetFolderPath
};

void *  myGetProcAddress(const enum myGetProcAddressFunctions func);
HANDLE	myOpenFile(const TCHAR *fn, DWORD da, DWORD cd);
void *  NSISGetProcAddress(HANDLE dllHandle, TCHAR* funcName);
int myatoi(TCHAR *s);
