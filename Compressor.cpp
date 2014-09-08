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
	inflateInit(&_stream);
	return true;
}
/************************************************************************/
//	
/************************************************************************/
bool CCompressor::DecompressAndCopyToBuffer(byte* inbuff,int inlength,std::vector<byte> *out_vect)
{
	Reset();
	_stream.avail_in = inlength;
	_stream.next_in  = inbuff;
	byte temp[0x100] = {0};
	_stream.next_out	= temp;
	_stream.avail_out	= 0x100;

	int res = inflate(&_stream,0);
	//Z_BUF_ERROR;

	return false;
}