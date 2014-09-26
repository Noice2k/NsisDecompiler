#pragma once
#include "GlobalVars.h"
#include <vector>
#include <string>
#include "NsisFile.h"
#include "Header.h"

#ifndef NSISCALL
#  define NSISCALL __stdcall
#endif

typedef UINT_PTR (*NSISPLUGINCALLBACK)(enum NSPIM);

typedef struct {
	exec_flags_t *exec_flags;
	int (NSISCALL *ExecuteCodeSegment)(int, HWND);
	void (NSISCALL *validate_filename)(TCHAR *);
	int (NSISCALL *RegisterPluginCallback)(HMODULE, NSISPLUGINCALLBACK); // returns 0 on success, 1 if already registered and < 0 on errors
} extra_parameters;


typedef struct _stack_t 
{
	struct _stack_t *next;
	WCHAR text[NSIS_MAX_STRLEN];
} stack_t;




/************************************************************************/
//	класс эмул€ции выполнени€ NSIS
/************************************************************************/
class CNSISEmulator
{
public:
	CNSISEmulator(void);
	~CNSISEmulator(void);

	void Init();

	void Run();

	void Execute();

	//	the main file header, this header in compressed
	
	std::vector<std::string> _function_call_stack;
	std::vector<std::string> _stack;

	int CNSISEmulator::GetIntFromParm(int id);
	HKEY  CNSISEmulator::myRegOpenKey(entry ent,REGSAM samDesired);
	HKEY CNSISEmulator::GetRegRootKey(int hRootKey);

	CNsisFile * file;

	stack_t *g_st;
	WCHAR   *g_usrvars;

	void CopyStrToWstr(char * in,WCHAR *out);
	CListCtrl *_source_code_view;
	CListCtrl *_stack_view;
	CListCtrl *_variables_vew;
	CListCtrl *_call_stack_view;

	std::string state_output_directory;

	int GetCompressedDataFromDataBlock(int off,HANDLE hfile);

	int CNSISEmulator::resolveaddr(int v);
	void CNSISEmulator::PushPopExch(entry _ent);


	int ExecuteCodeSegment(std::string FunctionName,int entry_id);
	int ExecuteEntry(int entry_id);
	
	bool _breakByStep;
	bool _runtoPoint;
	

	void CreateStack();
	void DeleteStack();

	exec_flags_t g_exec_flags;

	extra_parameters plugin_extra_parameters;

	HRESULT g_hres;
};

