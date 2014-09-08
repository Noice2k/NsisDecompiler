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
	//	for (int i = 0;i < 60;i++)
		{
			byte * p= &_dump[_offset];
			CFile file;
			file.Open("D:\\ConduitInstaller\\spinstaller_s_exe\\123.dat",CFile::modeWrite|CFile::modeCreate,NULL);
			
			file.Write(p,_firstheader.length_of_header);
			file.Close();
			
			
			_compressor.DecompressAndCopyToBuffer(p,hsize,&_dump_globalheader);
			
			_offset+=hsize;

			p= &_dump[_offset];

			 p= &_dump_globalheader[0]; 

			DWORD hsize1 = *(DWORD*)  &_dump_globalheader[0];
			DWORD hsize2 = *(DWORD*)  &_dump_globalheader[300];
			DWORD hsize3 = *(DWORD*)  &_dump_globalheader[304];

			memcpy(&_globalheader,&_dump_globalheader[4],sizeof(_globalheader));

			//	read pages 
			page *page1  =  (page *)&_dump_globalheader[30];
			int h = 0;
		}
		
		
	}
	return false;
}