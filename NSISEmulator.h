#pragma once
#include "GlobalVars.h"
#include <vector>
#include <string>
#include "NsisFile.h"
#include "Header.h"

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


	CListCtrl *_source_code_view;
	CListCtrl *_stack_view;
	CListCtrl *_variables_vew;
	CListCtrl *_call_stack_view;

	int CNSISEmulator::resolveaddr(int v);
	void CNSISEmulator::PushPopExch(entry _ent);


	int ExecuteCodeSegment(std::string FunctionName,int entry_id);
	int ExecuteEntry(int entry_id);
	
	bool _breakByStep;
	
};

