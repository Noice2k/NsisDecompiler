#include "stdafx.h"
#include "GlobalVars.h"

/************************************************************************/
/*                                                                      */
/************************************************************************/
CGlobalVars::CGlobalVars(void)
{
	SetVarCount(28);
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
CGlobalVars::~CGlobalVars(void)
{
}

/************************************************************************/
//	
/************************************************************************/
void CGlobalVars::SetVarCount(int count)
{
	_max_var_count = count+1; 
	_values.resize(_max_var_count);

}

/************************************************************************/
//	 получим значение переменной по 
/************************************************************************/
std::string CGlobalVars::GetVarValue(int id)
{
	return _values[id];
}

/************************************************************************/
//
/************************************************************************/
void CGlobalVars::SetVarValue(int id,std::string var)
{
	if ((id >=0) && (id<_max_var_count))
	{
		_values[id] = var;
	}
}

/************************************************************************/
//	получим имя переменной по его имени.
/************************************************************************/
std::string CGlobalVars::GetVarName(int id)
{
	std::string str;
	if (id < _max_var_count)
	{
		switch (id)
		{
		case 0: str = "$0";break;
		case 1: str = "$1";break;
		case 2: str = "$2";break;
		case 3: str = "$3";break;
		case 4: str = "$4";break;
		case 5: str = "$5";break;
		case 6: str = "$6";break;
		case 7: str = "$7";break;
		case 8: str = "$8";break;
		case 9: str = "$9";break;
		case 10: str = "$R0";break;
		case 11: str = "$R1";break;
		case 12: str = "$R2";break;
		case 13: str = "$R3";break;
		case 14: str = "$R4";break;
		case 15: str = "$R5";break;
		case 16: str = "$R6";break;
		case 17: str = "$R7";break;
		case 18: str = "$R8";break;
		case 19: str = "$R9";break;
		case 20: str = "$CMDLINE";break;       // 20 everything before here doesn't have trailing slash removal
		case 21: str = "$INSTDIR";break;       // 21
		case 22: str = "$OUTDIR";break;        // 22
		case 23: str = "$EXEDIR";break;        // 23
		case 24: str = "$LANGUAGE";break;      // 24
		case 25: str = "$TEMP";break;         // 25
		case 26: str = "$PLUGINSDIR";break;   // 26
		case 27: str = "$EXEPATH";break;      // 27
		case 28: str = "$EXEFILE";break;      // 28
		case 29: str = "$HWNDPARENT";break;   // 29
		case 30: str = "$_CLICK";break;       // 30
		case 31: str = "$OUTDIR";break;       // 31

		default:
			{
				char buff[0x100];
				sprintf_s(buff,"$var_%i", id);
				str = buff;
			}break;
		}
	}
	else
	{
		str = "_error_var_id";
	}

	return str;
}