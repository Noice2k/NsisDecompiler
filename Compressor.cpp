#include "stdafx.h"
#include "Compressor.h"


CCompressor::CCompressor(void)
{
}


CCompressor::~CCompressor(void)
{
}

/************************************************************************/
//
/***********************************************************************/
bool CCompressor::Reset()
{
	memset(&_stream,0,sizeof(z_stream_s));
	//inflateInit(&_stream);
	
	return true;
}
/************************************************************************/
//	
/************************************************************************/
bool CCompressor::DecompressAndCopyToBuffer(byte* inbuff,int inlength,std::vector<byte> *out_vect)
{
	lzmacoder.Inflate(inbuff,inlength,out_vect);

	return false;
}