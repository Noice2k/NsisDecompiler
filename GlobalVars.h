#pragma once
#include <string>
#include <vector>

//	обертка над классом глобальной переменной
class CGlobalVars
{
public:
	CGlobalVars(void);
	~CGlobalVars(void);

	void SetVarCount(int i = 0);

	//	получим имя переменной по его имени.
	std::string GetVarName(int id);
	
	//	 получим значение переменной по 
	std::string GetVarValue(int id);
	
	void SetVarValue(int id,std::string var);


	//	
	std::vector<std::string> _values;
	//	максимальное кол-во переменных
	int	_max_var_count;
};

