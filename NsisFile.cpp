#include "stdafx.h"
#include "NsisFile.h"
#include "crc32.h"

CNsisFile::CNsisFile(void)
{
}


CNsisFile::~CNsisFile(void)
{
}

/************************************************************************/
// this is based on the (slow,small) CRC32 implementation from zlib.
/************************************************************************/
DWORD CNsisFile::PE_CRC(DWORD  crc, const unsigned char *buf, unsigned int len)
{
	crc = 0;
	WORD * w = (WORD*) buf;
	unsigned  wl = len/2;

	while (wl > 0 )
	{
		crc += *w;
		w++;
		wl--;
		crc = (crc&0xffff) + (crc>>16);
	}
	crc = (crc&0xffff) + (crc>>16);
	return crc;	
}

// Macro to find the offset of a field of a structure
#ifndef offsetof
#define offsetof(st, m) ((size_t) ( (char *)&((st *)(0))->m - (char *)0 ))
#endif

// NT Signature + IMAGE_FILE_HEADER + Most of IMAGE_OPTIONAL_HEADER
// This is relative to the PE Header Offset
#define CHECKSUM_OFFSET sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+offsetof(IMAGE_OPTIONAL_HEADER, CheckSum)


//////////////////////////////////////////////////////////////////////////
//	exe file dump
// [IMAGE_DOS_HEADER .e_lfanew offset to the IMAGE_NT_HEADERS][DOS stub][IMAGE_NT_HEADERS]
// [IMAGE_SECTION_HEADER * IMAGE_NT_HEADERS.IMAGE_FILE_HEADER.NumberOfSections]
// [Sections * IMAGE_NT_HEADERS.IMAGE_FILE_HEADER.NumberOfSections]
//		-	offet - IMAGE_SECTION_HEADER.PointerToRawData; size -  IMAGE_SECTION_HEADER.SizeOfRawData
//	[.text]		- executable code
//	[.rdata]	- resource data
//	[.data]		- initializing data
//  [.rsec]		- resource table 
//	[nsis data]
//	[certificate table] - IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER.DataDirectory[4]
//				Certificate table address and size

/************************************************************************/
//	load exe dump
/************************************************************************/
void    CNsisFile::LoadExeDump(char * filename)
{
	_exe_dump.resize(0);
	CFile file;
	if (TRUE == file.Open(filename,CFile::modeRead,NULL))
	{
		int length = (int)file.GetLength();
		_exe_dump.resize(length+1);
		file.Read(&_exe_dump[0],length);
		file.Close();
	}
	if (_exe_dump.size() == 0)
	{
		return;
	}

	

	int off = 0;
	//	copy dos header
	memcpy(&_dos_header,&_exe_dump[off],sizeof(_dos_header));
	off +=_dos_header.e_lfanew;
	//	copy ms dos stab
	_msdos_stub.insert(_msdos_stub.begin(),&_exe_dump[sizeof(_dos_header)],&_exe_dump[off]);
	//	copy nt header
	memcpy(&_nt_header,&_exe_dump[off],sizeof(_nt_header));

	

	DWORD oldcrc = _nt_header.OptionalHeader.CheckSum;
	_nt_header.OptionalHeader.CheckSum = 0;
	memcpy(&_exe_dump[off],&_nt_header,sizeof(_nt_header));
	off+= sizeof(_nt_header);

	
	//	copy section header
	int count = _nt_header.FileHeader.NumberOfSections;
	for (int i= 0x00;i<count;i++)
	{
		IMAGE_SECTION_HEADER ish  = *(IMAGE_SECTION_HEADER*)&_exe_dump[off];
		off+= sizeof(IMAGE_SECTION_HEADER);
		_section_headers.push_back(ish);
	}
	//	copy the section data
	unsigned soff = 0;
	unsigned ssize = 0;
	unsigned nsisoff = 0;
	for (unsigned i= 0x00;i<_section_headers.size();i++)
	{
		IMAGE_SECTION_HEADER ish = _section_headers[i];
		soff = ish.PointerToRawData;
		ssize = ish.SizeOfRawData;
		DWORD sname = *(DWORD*)&ish.Name[0];
		switch (sname)
		{
		// .tex
		case 0x7865742e:
			_dot_text_section.insert(_dot_text_section.begin(),&_exe_dump[soff],&_exe_dump[soff+ssize]);
			nsisoff = max(soff+ssize,nsisoff);
			break;
		case 0x6164722e:
			_dot_rdata_section.insert(_dot_rdata_section.begin(),&_exe_dump[soff],&_exe_dump[soff+ssize]);
			nsisoff = max(soff+ssize,nsisoff);
			break;
		case 0x7461642e:
			_dot_data_section.insert(_dot_data_section.begin(),&_exe_dump[soff],&_exe_dump[soff+ssize]);
			nsisoff = max(soff+ssize,nsisoff);
			break;
		case 0x7273722e:
			_dot_rsrc_section.insert(_dot_rsrc_section.begin(),&_exe_dump[soff],&_exe_dump[soff+ssize]);
			nsisoff = max(soff+ssize,nsisoff);
			break;
		default:
			break;
		}
	}
	
	unsigned nsissize = 0;
	//	load nsis data;
	if (_nt_header.OptionalHeader.DataDirectory[4].VirtualAddress > 0)
	{
		nsissize = _nt_header.OptionalHeader.DataDirectory[4].VirtualAddress - nsisoff;
	}
	else
	{
		nsisoff = _exe_dump.size()-1-nsisoff;
	}
	_dump.insert(_dump.begin(),&_exe_dump[nsisoff],&_exe_dump[nsisoff+nsissize]);

	//  copy certificate table;
	soff = _nt_header.OptionalHeader.DataDirectory[4].VirtualAddress;
	ssize = _nt_header.OptionalHeader.DataDirectory[4].Size;
	ssize = min(ssize,_exe_dump.size()-1 - soff);
	_certificatr_table.insert(_certificatr_table.begin(),&_exe_dump[soff],&_exe_dump[soff+ssize]);

/*//	.text 
	//	Certificate tabel 
	std::vector<byte> _certificatr_table;
	*/
}

/************************************************************************/
//	save exe dump afer changes
/************************************************************************/
void	CNsisFile::SaveExeDump(char * filename)
{
	//	выходной буфер
	std::vector<byte> _out;
	byte * p = (byte*)&_dos_header;
	//	dos header
	_out.insert(_out.begin(),p,p+ sizeof(_dos_header));
	//	dos stub
	p = (byte*)&_msdos_stub[0];
	_out.insert(_out.begin()+_out.size(),p,p+_msdos_stub.size());
	
	//	обнулим crc
	_nt_header.OptionalHeader.CheckSum = 0x00;
	//	удалим сигнатуру.
	_nt_header.OptionalHeader.DataDirectory[4].Size = 0;
	_nt_header.OptionalHeader.DataDirectory[4].VirtualAddress = 0;
	//	
	p = (byte*)&_nt_header;
	_out.insert(_out.begin()+_out.size(),p,p+sizeof(_nt_header));

	
	//	copy section header
	int count = _nt_header.FileHeader.NumberOfSections;
	for (int i= 0x00;i<count;i++)
	{
		IMAGE_SECTION_HEADER ish  = _section_headers[i];
		p = (byte*)&ish;
		_out.insert(_out.begin()+_out.size(),p,p+sizeof(IMAGE_SECTION_HEADER));
	}

	//	copy the section data
	for (unsigned i= 0x00;i<_section_headers.size();i++)
	{
		
		IMAGE_SECTION_HEADER ish = _section_headers[i];
		DWORD sname = *(DWORD*)&ish.Name[0];
		unsigned size =0;
		unsigned offset	= ish.PointerToRawData; 

		switch (sname)
		{
			// .tex
		case 0x7865742e:
			size	= _dot_text_section.size();
			p		= (byte*)&_dot_text_section[0];
			break;
		case 0x6164722e:
			size	= _dot_rdata_section.size();
			p		= (byte*)&_dot_rdata_section[0];
			
			break;
		case 0x7461642e:
			size	= _dot_data_section.size();
			p		= (byte*)&_dot_data_section[0];
			break;
		case 0x7273722e:
			size	= _dot_rsrc_section.size();
			p		= (byte*)&_dot_rsrc_section[0];
			break;
		default:
			break;
		}

		if (size > 0 )
		{
			if (offset != _out.size())
			{
				_out.resize(offset);
				int err=1;
			}
			_out.insert(_out.begin()+_out.size(),p,p+size);
		}
	}
	// copy nsis dump
	if (_dump.size()>0)
	{
		p = &_dump[0];
		_out.insert(_out.begin()+_out.size(),p,p+_dump.size());
	}
	

	/**/
	
	_crc_offset = CHECKSUM_OFFSET;
	DWORD crc = PE_CRC(0,&_out[0],_out.size());


	crc = (crc & 0xffff) + (crc >> 16);
	crc = (crc) + (crc >> 16);
	crc = crc & 0xffff;
	crc += _out.size();
	
	_nt_header.OptionalHeader.CheckSum = crc;
	memcpy(&_out[_dos_header.e_lfanew],&_nt_header,sizeof(_nt_header));

	CFile file;
	file.Open(filename,CFile::modeCreate|CFile::modeWrite,NULL);
	file.Write(&_out[0],_out.size());
	file.Close();
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
//	save all nsis files to disk
/************************************************************************/
void	CNsisFile::DumpFiles(char * path)
{
	for (unsigned i = 0;i < _files.size(); i++)
	{
		sfile sf = _files[i];

		char name[0x100];
		sprintf_s(name,0x100,"%s\\%4.4i.dat",path,i);
		
		CFile file;
		file.Open(name,CFile::modeCreate|CFile::modeWrite);
		file.Write(sf.pointer,sf.size);
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
			//	copy the header
			memcpy(&_globalheader,&_header_dump[0],sizeof(header));
			unsigned  off = s + 4;
			while (off < _global_dump.size())
			{
				sfile sf;
				DWORD size = *(DWORD*)&_global_dump[off];
				off+=4;
				
				sf.pointer = &_global_dump[off];
				sf.size    = size;
				_files.push_back(sf);
				off+= size;
				

			}

			if (false == LoadPages()) 
				return false;
			if (false == LoadSection())
				return false;
			if (false == LoadEntries())
				return false;
			if (false == LoadStrings())
				return false;

			/*

			DWORD s2 = *(DWORD*)&_global_dump[s+4];
			p  = &_global_dump[s+8];
			memcpy(&_uheader ,&_global_dump[s+8],sizeof(header));

			int off = s+s2 + 8;
			DWORD s3 = *(DWORD*)&_global_dump[off];
			p =  &_global_dump[off];

			off+= s3;
			off+= 4;

			DWORD s4 = *(DWORD*)&_global_dump[off];
			p =  &_global_dump[off];

			 

			CFile file;
			file.Open("D:\\ConduitInstaller\\spinstaller_s_exe\\all.dat",CFile::modeWrite|CFile::modeCreate,NULL);
			file.Write(p,_global_dump.size());
			file.Close();
			*/
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

/************************************************************************/
/*                                                                      */
/************************************************************************/
bool CNsisFile::LoadStrings()
{
	int offset	= _globalheader.blocks[NB_STRINGS].offset;
	int count	= _globalheader.blocks[NB_STRINGS].num;
	//	
	_istrings   = &_header_dump[offset];
	return false;
}