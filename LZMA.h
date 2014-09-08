#pragma once
#include "stdafx.h"

#include <vector>

class CLZMA
{
public:
	CLZMA(void);
	~CLZMA(void);
	//	extract buffer
	bool Inflate(byte* inbuff,size_t inlength,std::vector<byte> *out_vect);

private:
};

