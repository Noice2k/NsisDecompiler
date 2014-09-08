#include "stdafx.h"
#include "NsisFile.h"


CNsisFile::CNsisFile(void)
{
}


CNsisFile::~CNsisFile(void)
{
}

/************************************************************************/
//	load dump
/************************************************************************/
void CNsisFile::LoadDump(char * filename)
{
	CFile file;
	if (TRUE == file.Open(filename,CFile::modeRead,NULL))
	{
		int length = (int)file.GetLength();
		_dump.resize(length);
		file.Read(&_dump[0],length);
		file.Close();
	}
}

/************************************************************************/
//	processing header
/************************************************************************/
bool	CNsisFile::ProcessingHeader()
{
	if (_dump.size() <  (sizeof (firstheader) + sizeof(header))) return false;
	memcpy(&_firstheader,&_dump[0],sizeof(firstheader));
	//	check the first header
	if ((_firstheader.flags & (~FH_FLAGS_MASK)) == 0 &&_firstheader.siginfo == FH_SIG &&_firstheader.nsinst[2] == FH_INT3 &&
		_firstheader.nsinst[1] == FH_INT2 &&_firstheader.nsinst[0] == FH_INT1)
	{
		_offset = sizeof(firstheader);
		DWORD hsize = *(DWORD*)  &_dump[_offset];
		if (0 != (hsize&0x80000000))
		{
			hsize &= 0x7FFFFFFF;
		}
		
		//_offset+= 4;
		// crc
		for (int i = 0;i < 60;i++)
		{
			
			byte * p= &_dump[_offset+i];
			_compressor.DecompressAndCopyToBuffer(p,hsize,&_dump_globalheader);

		}
		
		
	}
	return false;
}