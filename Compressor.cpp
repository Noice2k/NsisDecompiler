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
	return true;
}
/************************************************************************/
//	
/************************************************************************/
bool CCompressor::DecompressAndCopyToBuffer(byte* inbuff,int inlength,std::vector<byte> *out_vect)
{
	switch (_method)
	{
	case zlma_solid:
		//	_lzmacoder.Inflate(inbuff,inlength,out_vect);
		break;
	case zlib:
		break;
	case zlib_solid:
			_zlibcoder.Inflate(inbuff,inlength,out_vect);
		break;
	default:
		break;
	}
	return false;
}

void CCompressor::SetCompressionMethod(std::string method)
{

	if (method.find("cb807804553819b70f6e16b8a094d327") == 0)
	{
		_method = zlib_solid;
	}

	return ;
}