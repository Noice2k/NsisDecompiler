#pragma once
#include "GlobalVars.h"
#include <vector>
#include <string>
#include "NsisCore.h"
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

	CNsisCore * _nsis_core;
	std::string		filename;

	DWORD ReadReg(char *key);
	void  WriteReg(char*key, DWORD value);

	void CopyStrToWstr(char * in,WCHAR *out);
	HANDLE CNSISEmulator::FindProcess();
	void ReadSteckAndVars();
	bool AttachToProcess();
	bool CloseProcess();
	bool _need_do_step;
	bool _need_do_step_out;
	bool _runtoPoint;
	bool _need_terminate_main_tread;

	HANDLE hproc;
	PROCESS_INFORMATION		_debug_process_info;
	
	//	копируем стек из дочерней программы в нвше адрессное пространство
	void CreateStack();
	
	
};

