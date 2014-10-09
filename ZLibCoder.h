#pragma once
#include <vector>
#include "zlib/zlib.h"


class CZLib
{
public:
	CZLib(void);
	~CZLib(void);
	//	extract buffer
	bool Inflate(byte* inbuff,size_t inlength,std::vector<byte> *out_vect);
};

