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
			//	remove compress flag
			hsize &= 0x7FFFFFFF;
			byte * p= &_dump[_offset];
			//	 decompress all data to 
			_compressor.DecompressAndCopyToBuffer(p,_dump.size()-_offset,&_global_dump);
			
			
			// 4 bytes - length of header;
			DWORD s = *(DWORD*)&_global_dump[0];
			if (s == _firstheader.length_of_header)
			{
				_header_dump.resize(s);
				memcpy(&_header_dump[0],&_global_dump[4],s);
			}
			DWORD s2 = *(DWORD*)&_global_dump[s+4];

			//	copy the header
			memcpy(&_globalheader,&_header_dump[0],sizeof(header));
			

			if (false == LoadPages()) 
				return false;
			if (false == LoadSection())
				return false;
			if (false == LoadEntries())
			{
			}
						
			CFile file;
			file.Open("D:\\ConduitInstaller\\spinstaller_s_exe\\all.dat",CFile::modeWrite|CFile::modeCreate,NULL);
			file.Write(p,_global_dump.size());
			file.Close();
		}
	}
	return false;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
bool CNsisFile::LoadEntries()
{
	int offset	= _globalheader.blocks[NB_ENTRIES].offset;
	int count	= _globalheader.blocks[NB_ENTRIES].num;
	if (offset+count*sizeof(entry) > _header_dump.size()) return false;
	//	copy page structure. this is work only for 32 bytes aligment
	for (int i = 0x00;i < count;i++)
	{
		int oi = EW_WRITEINI;
		entry en = *(entry*)&_header_dump[i*sizeof(entry)+offset];
		_ientry.push_back(en);
	}
	return true;
}

/************************************************************************/
//	load page structs
/************************************************************************/
bool CNsisFile::LoadPages()
{
	int offset	= _globalheader.blocks[NB_PAGES].offset;
	int count	= _globalheader.blocks[NB_PAGES].num;
	if (offset+count*sizeof(page) > _header_dump.size()) return false;
	//	copy page structure. this is work only for 32 bytes aligment
	for (int i = 0x00;i < count;i++)
	{
		page pg = *(page*)&_header_dump[i*sizeof(page)+offset];
		_ipages.push_back(pg);
	}
	return true;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
bool CNsisFile::LoadSection()
{
	int offset	= _globalheader.blocks[NB_SECTIONS].offset;
	int count	= _globalheader.blocks[NB_SECTIONS].num;
	//	
	if (offset+count*sizeof(section) > _header_dump.size()) return false;
	for (int i = 0x00;i < count;i++)
	{
		section sc = *(section*)&_header_dump[i*sizeof(section)+offset];
		_isection.push_back(sc);
	}

	return true;
}