#pragma once
#include <string>
//	обертка над классом глобальной переменной
class CGlobalVars
{
public:
	CGlobalVars(void);
	~CGlobalVars(void);

	void SetVarCount(int i = 0);

	//	получим имя переменной по его имени.
	std::string GetVarName(int id);
	//	максимальное кол-во переменных
	int	_max_var_count;
};

