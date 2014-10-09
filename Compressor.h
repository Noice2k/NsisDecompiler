#pragma once
#include "stdafx.h"
#include <vector>
#include "LZMA.h"
#include "ZLibCoder.h"

//	the compresion wrapper


enum  EMethod
{
	zlma_solid = 0,
	zlib,
	zlib_solid

};



class CCompressor
{
public:
	CCompressor(void);
	~CCompressor(void);
	
	void SetCompressionMethod(std::string method);

	bool Reset();
	
	bool DecompressAndCopyToBuffer(byte* inbuff,int inlength,std::vector<byte> *out_vect);

	//CLZMA	_lzmacoder;
	CZLib	_zlibcoder;
	EMethod _method;
	
};

