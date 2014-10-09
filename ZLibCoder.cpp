#include "stdafx.h"
#include "ZLibCoder.h"


CZLib::CZLib(void)
{
}


CZLib::~CZLib(void)
{
}

#define OBUFSIZE 32768

/************************************************************************/
//	extract buffer
/************************************************************************/
bool CZLib::Inflate(byte* inbuff,size_t inlength,std::vector<byte> *out_vect)
{
	byte outbuff[OBUFSIZE];
	
	while (inlength > 4 )
	{
		// get the file length
		DWORD currentlen = *(DWORD*)inbuff;
		currentlen &= 0x7FFFFFFF;
		inbuff += 4;
		inlength-=4;
		memset(outbuff,0,OBUFSIZE);

		// zlib struct
		z_stream infstream;
		inflateReset(&infstream);
		infstream.avail_in = currentlen;
		infstream.next_in = inbuff;
		infstream.avail_out = OBUFSIZE; // size of output
		infstream.next_out = outbuff; // output char array
		
		int res = 0 ;
		int start = out_vect->size();
		int size =0;
		while (res >= 0)
		{

			res = inflate(&infstream);
			int u= infstream.next_out - outbuff;
			if (u)
			{
				size+= u;
				out_vect->insert(out_vect->begin()+out_vect->size(),outbuff,outbuff+u);
				infstream.avail_out = OBUFSIZE; // size of output
				infstream.next_out = outbuff; // output char array
			}
			else
			{
				break;
			}
			if ( res == Z_STREAM_END)
			{
				out_vect->insert(out_vect->begin()+start,(byte*)&size,(byte*)&size+4);
				break;
			}
		}
		inflateReset(&infstream);
		inlength -= currentlen;
		inbuff   += currentlen;
	}

	//Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FINISH,Z_BLOCK, or Z_TREES
	


	


	// the actual compression work.
	
	
	
	
//	inflateEnd(&infstream);

	return true;
}

