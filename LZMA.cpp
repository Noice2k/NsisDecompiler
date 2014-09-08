#include "stdafx.h"
#include "LZMA.h"
#include "lzma/LzmaDec.h"
#include "lzma/LzmaLib.c"

/************************************************************************/
/*                                                                      */
/************************************************************************/
CLZMA::CLZMA(void)
{
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
CLZMA::~CLZMA(void)
{
}

#define IBUFSIZE 16384
#define OBUFSIZE 32768


/************************************************************************/
//	extract buffer
/************************************************************************/
bool CLZMA::Inflate(byte* inbuff,size_t ilength,std::vector<byte> *out_vect)
{
	SRes result = 0;
	//	lzma decoder state
	CLzmaDec _state;
	ELzmaStatus status;

	//	 simple check;
	if (ilength < LZMA_PROPS_SIZE+1) return false;
	out_vect->resize(0);
	
	/* header: 5 bytes of LZMA properties*/
	unsigned char lheader[LZMA_PROPS_SIZE ];
	memcpy(lheader,inbuff,LZMA_PROPS_SIZE);
	ilength -= (LZMA_PROPS_SIZE);
	inbuff  += (LZMA_PROPS_SIZE);

	//	init header
	LzmaDec_Construct(&_state);
	result = LzmaDec_Allocate(&_state, lheader, LZMA_PROPS_SIZE, &g_Alloc);
	if (0 != result ) return false;
	LzmaDec_Init(&_state);

	int sss = OBUFSIZE;
	byte buff[OBUFSIZE];
	SizeT oprocessed = OBUFSIZE;
	SizeT  iprocessed = ilength;
	ELzmaFinishMode finishMode = LZMA_FINISH_ANY;
	


	while (true)
	{
		result = LzmaDec_DecodeToBuf(&_state, buff, &oprocessed,inbuff, &iprocessed, finishMode, &status);
		for (unsigned i = 0x00;i< oprocessed; i++)
		{
			out_vect->push_back(buff[i]);
		}
		ilength-= iprocessed;
		iprocessed = ilength;
		inbuff += iprocessed;
		oprocessed = OBUFSIZE;
		if (ilength  == 0)
		{
			break;;
		}
		if (result != 0)
		{
			int i =0;
			break;
		}
	}
	
	
	
	
	return true;
}
