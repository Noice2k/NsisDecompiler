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
	_pe_full_dump.resize(0);
	CFile file;
	if (TRUE == file.Open(filename,CFile::modeRead,NULL))
	{
		int length = (int)file.GetLength();
		_pe_full_dump.resize(length+1);
		file.Read(&_pe_full_dump[0],length);
		file.Close();
	}
	if (_pe_full_dump.size() == 0)
	{
		return;
	}

	

	int off = 0;
	//	copy dos header
	memcpy(&_pe_dos_header,&_pe_full_dump[off],sizeof(_pe_dos_header));
	off +=_pe_dos_header.e_lfanew;
	//	copy ms dos stab
	_pe_msdos_stub.insert(_pe_msdos_stub.begin(),&_pe_full_dump[sizeof(_pe_dos_header)],&_pe_full_dump[off]);
	//	copy nt header
	memcpy(&_pe_nt_header,&_pe_full_dump[off],sizeof(_pe_nt_header));

	

	DWORD oldcrc = _pe_nt_header.OptionalHeader.CheckSum;
	_pe_nt_header.OptionalHeader.CheckSum = 0;
	memcpy(&_pe_full_dump[off],&_pe_nt_header,sizeof(_pe_nt_header));
	off+= sizeof(_pe_nt_header);

	
	//	copy section header
	int count = _pe_nt_header.FileHeader.NumberOfSections;
	for (int i= 0x00;i<count;i++)
	{
		IMAGE_SECTION_HEADER ish  = *(IMAGE_SECTION_HEADER*)&_pe_full_dump[off];
		off+= sizeof(IMAGE_SECTION_HEADER);
		_pe_section_headers.push_back(ish);
	}
	//	copy the section data
	unsigned soff = 0;
	unsigned ssize = 0;
	unsigned nsisoff = 0;
	for (unsigned i= 0x00;i<_pe_section_headers.size();i++)
	{
		IMAGE_SECTION_HEADER ish = _pe_section_headers[i];
		soff = ish.PointerToRawData;
		ssize = ish.SizeOfRawData;
		DWORD sname = *(DWORD*)&ish.Name[0];
		switch (sname)
		{
		// .tex
		case 0x7865742e:
			_pe_dot_text_section.insert(_pe_dot_text_section.begin(),&_pe_full_dump[soff],&_pe_full_dump[soff+ssize]);
			nsisoff = max(soff+ssize,nsisoff);
			break;
		case 0x6164722e:
			_pe_dot_rdata_section.insert(_pe_dot_rdata_section.begin(),&_pe_full_dump[soff],&_pe_full_dump[soff+ssize]);
			nsisoff = max(soff+ssize,nsisoff);
			break;
		case 0x7461642e:
			_pe_dot_data_section.insert(_pe_dot_data_section.begin(),&_pe_full_dump[soff],&_pe_full_dump[soff+ssize]);
			nsisoff = max(soff+ssize,nsisoff);
			break;
		case 0x7273722e:
			_pe_dot_rsrc_section.insert(_pe_dot_rsrc_section.begin(),&_pe_full_dump[soff],&_pe_full_dump[soff+ssize]);
			nsisoff = max(soff+ssize,nsisoff);
			break;
		case 0x6c65722e:
			_pe_dot_reloc_section.insert(_pe_dot_reloc_section.begin(),&_pe_full_dump[soff],&_pe_full_dump[soff+ssize]);
			nsisoff = max(soff+ssize,nsisoff+ssize);
			break;
		case 0x61646e2e:
			{
				int c = ish.Misc.VirtualSize;
				c/= NSIS_MAX_STRLEN;
				_global_vars.SetVarCount(c);
			}
			break;
		default:
			break;
		}
	}
	
	unsigned nsissize = 0;
	//	load nsis data;
	if (_pe_nt_header.OptionalHeader.DataDirectory[4].VirtualAddress > 0)
	{
		nsissize = _pe_nt_header.OptionalHeader.DataDirectory[4].VirtualAddress - nsisoff;
	}
	else
	{
		nsissize = _pe_full_dump.size()-1-nsisoff;
	}
	_dump.insert(_dump.begin(),&_pe_full_dump[nsisoff],&_pe_full_dump[nsisoff+nsissize]);

	//  copy certificate table;
	soff = _pe_nt_header.OptionalHeader.DataDirectory[4].VirtualAddress;
	ssize = _pe_nt_header.OptionalHeader.DataDirectory[4].Size;
	ssize = min(ssize,_pe_full_dump.size()-1 - soff);
	_pe_certificatr_table.insert(_pe_certificatr_table.begin(),&_pe_full_dump[soff],&_pe_full_dump[soff+ssize]);

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
	byte * p = (byte*)&_pe_dos_header;
	//	dos header
	_out.insert(_out.begin(),p,p+ sizeof(_pe_dos_header));
	//	dos stub
	p = (byte*)&_pe_msdos_stub[0];
	_out.insert(_out.begin()+_out.size(),p,p+_pe_msdos_stub.size());
	
	//	обнулим crc
	_pe_nt_header.OptionalHeader.CheckSum = 0x00;
	//	удалим сигнатуру.
	_pe_nt_header.OptionalHeader.DataDirectory[4].Size = 0;
	_pe_nt_header.OptionalHeader.DataDirectory[4].VirtualAddress = 0;
	//	
	p = (byte*)&_pe_nt_header;
	_out.insert(_out.begin()+_out.size(),p,p+sizeof(_pe_nt_header));

	
	//	copy section header
	int count = _pe_nt_header.FileHeader.NumberOfSections;
	for (int i= 0x00;i<count;i++)
	{
		IMAGE_SECTION_HEADER ish  = _pe_section_headers[i];
		p = (byte*)&ish;
		_out.insert(_out.begin()+_out.size(),p,p+sizeof(IMAGE_SECTION_HEADER));
	}

	//	copy the section data
	for (unsigned i= 0x00;i<_pe_section_headers.size();i++)
	{
		
		IMAGE_SECTION_HEADER ish = _pe_section_headers[i];
		DWORD sname = *(DWORD*)&ish.Name[0];
		unsigned size =0;
		unsigned offset	= ish.PointerToRawData; 

		switch (sname)
		{
			// .tex
		case 0x7865742e:
			size	= _pe_dot_text_section.size();
			p		= (byte*)&_pe_dot_text_section[0];
			break;
		case 0x6164722e:
			size	= _pe_dot_rdata_section.size();
			p		= (byte*)&_pe_dot_rdata_section[0];
			
			break;
		case 0x7461642e:
			size	= _pe_dot_data_section.size();
			p		= (byte*)&_pe_dot_data_section[0];
			break;
		case 0x7273722e:
			size	= _pe_dot_rsrc_section.size();
			p		= (byte*)&_pe_dot_rsrc_section[0];
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
	
	_pe_nt_header.OptionalHeader.CheckSum = crc;
	memcpy(&_out[_pe_dos_header.e_lfanew],&_pe_nt_header,sizeof(_pe_nt_header));

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
	for (unsigned i = 0;i < _nsis_files.size(); i++)
	{
		sfile sf = _nsis_files[i];

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
			
		/*	CFile file;
			file.Open("D:\\ConduitInstaller\\spinstaller_s_exe\\all.dat",CFile::modeWrite|CFile::modeCreate,NULL);
			
			file.Write(&_global_dump[0],_global_dump.size());
			file.Close();
            */
			
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
			unsigned beginoff = s+4;
			while (off < _global_dump.size())
			{
				sfile sf;
				DWORD size = *(DWORD*)&_global_dump[off];
				sf.size    = size;
				sf.offset  = off-beginoff;
				off+=4;
				sf.pointer = &_global_dump[off];
				_nsis_files.push_back(sf);
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
			if (false == LoadLandTables())
			{
			}

			ProcessingEntries();
			ProcessingFunctions();

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
		_nsis_entry.push_back(en);
	}
	return true;
}

/************************************************************************/
//
/************************************************************************/
void CNsisFile::FunctionFormatText(int entstart,std::string functiontype, std::string name)
{

	std::string str = ""+functiontype+" "+ name + "  ";
	int stroff = str.size();
	str += _nsis_script_code[entstart];
	//str.insert(stroff+5,"   ");
	_nsis_script_code[entstart] = str;
	for (unsigned i = entstart+1; i < _nsis_script_code.size();i++)
	{
		std::string var = _nsis_script_code[i];
		int pos = var.find("return from function call");

		if ( pos > 0)
		{
			break;
		}
		str = _nsis_script_code[i];
		//str.insert(5, "   ");
		str.insert(0, "   ");
		_nsis_script_code[i] = str;
	}

}

/************************************************************************/
//
/************************************************************************/
void CNsisFile::ProcessingFunctions()
{
	// function on Init
	if (_globalheader.code_onInit >= 0)
	{
		FunctionFormatText(_globalheader.code_onInit,"Function","OnInit");
	}
	for (unsigned i = 0x00; i<_nsis_section.size();i++)
	{
		section s = _nsis_section[i];
		if (s.code > 0)
		{
			FunctionFormatText(s.code,"Section",GetNsisString(s.name_ptr));
		}
	}

	char buff[0x100];
	for ( unsigned i= 0;  i< _nsis_function_entry.size(); i++)
	{
		sprintf_s(buff,0x100,"function%4.4i",_nsis_function_entry[i]);
		FunctionFormatText(_nsis_function_entry[i],"Function",buff);
	}

	std::string allcode;
	for (unsigned  i= 0x00; i< _nsis_script_code.size(); i++)
	{
		if (_nsis_script_code[i].size() > 8)
		{
			allcode += _nsis_script_code[i];
			allcode += "\r\n";
		}
	}



	CFile file;
	file.Open("D:\\ConduitInstaller\\spinstaller_s_exe\\code.txt",CFile::modeWrite|CFile::modeCreate,NULL);
	file.Write(allcode.c_str(),allcode.size());
	file.Close();
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
		_nsis_pages.push_back(pg);
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
		_nsis_section.push_back(sc);
	}

	return true;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
bool CNsisFile::LoadStrings()
{
	int offset	= _globalheader.blocks[NB_STRINGS].offset;
	int count	= (_globalheader.blocks[NB_LANGTABLES].offset  - _globalheader.blocks[NB_STRINGS].offset)/2;
	//	
	WCHAR * wc = (WCHAR *)&_header_dump[offset];
	_nsis_string_table.insert(_nsis_string_table.begin(),wc,wc+count);

	return true;
}

/************************************************************************/
//	
/************************************************************************/
bool CNsisFile::LoadLandTables()
{
	int offset	= _globalheader.blocks[NB_LANGTABLES].offset + sizeof(LANGID)+2*sizeof(int);
	int count	= (_globalheader.langtable_size)/4;
    
/*
    char *language_table=0;
    int lang_num;
    int *selected_langtable=0;

    // Jim Park: We are doing byte offsets to get to various data structures so
    // no TCHARs here.

    WCHAR * wc = (WCHAR *)&_header_dump[offset];
    lang_num= _globalheader.blocks[NB_LANGTABLES].num;
    language_table=((char*)&_header_dump[offset]);
    selected_langtable=(int*)(language_table+sizeof(LANGID)+2*sizeof(int));

/*            dlg_offset=*(int*)(language_table+sizeof(LANGID));
            g_exec_flags.rtl=*(int*)(language_table+sizeof(LANGID)+sizeof(int));
            
            break;
        
    

    */
    int * t = (int*) &_header_dump[offset];
    
    _nsis_launguage_table.insert(_nsis_launguage_table.begin(),t,t+count);
	
    

	return true;
}

#define LANG_STR_TAB(x) cur_langtable[-((int)x+1)]
#define GetNSISTab(strtab) (strtab < 0 ? LANG_STR_TAB(strtab) : strtab)
#define GetNSISStringNP(strtab) ((const TCHAR *)_globalheader.blocks[NB_STRINGS].offset+(strtab))

#define NS_SKIP_CODE 0xE000
#define NS_VAR_CODE 0xE001
#define NS_SHELL_CODE 0xE002
#define NS_LANG_CODE 0xE003
#define NS_CODES_START NS_SKIP_CODE
#define NS_IS_CODE(x) ((x) & 0xE000)

#define DECODE_SHORT(c) ((WORD)(c[0]&0x7FFF))
/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::GetNsisString(int offset,bool isvalue)
{
	std::wstring wstr;

	// the real offset in the string table
	int real_offset = 0x00;
	//	 lang table
	if (offset < 0)
	{
		// make offset to positive value
		offset *= -1;
		//	make +1 to convert -1 => 0 
		offset +=1;
		real_offset = (int)_nsis_launguage_table[offset];
	}
	//	string table
	else 
	{
		real_offset = offset;
	}
	// try to decode string in 

	WCHAR * in = &_nsis_string_table[real_offset];


	while (true)
	{
		WCHAR nVarIdx = _nsis_string_table[real_offset];
		real_offset++;
		in = &_nsis_string_table[real_offset];
		if (nVarIdx == 0x00)  break;

		int nData;
		int fldrs[4];

		// Looks redundant for ASCII but is not for Unicode.
		if (NS_IS_CODE(nVarIdx) && nVarIdx > NS_CODES_START)
		{
			// nData = ((in[1] & 0x7F) << 7) | (in[0] & 0x7F);
			// DECODE_SHORT is the Unicode/ANSI version of the above.
			nData = DECODE_SHORT(in);

			// Special folders identified by their Constant Special Item ID (CSIDL)

			fldrs[1] = *in & 0x00FF; // current user
			fldrs[0] = fldrs[1] | CSIDL_FLAG_CREATE;
			fldrs[3] = (*in & 0xFF00) >> 8; // all users
			fldrs[2] = fldrs[3] | CSIDL_FLAG_CREATE;

			real_offset++;
			if (nVarIdx == NS_SHELL_CODE)
			{
				//LPITEMIDLIST idl;

				int x = 2;
				DWORD ver = GetVersion();
			}
			if (nVarIdx == NS_LANG_CODE)
			{

				std::string str1 = GetNsisString(-nData+1);
				wstr.insert(wstr.end(),str1.begin(),str1.end());

				//GetNSISString(out, -nData-1);
			}


			if (nVarIdx == NS_VAR_CODE)
			{
				if (nData == 29)
				{
					wstr += L"$HWNDPARENT";
				}
				else
				{
					std::string var;
					if (isvalue)
					{
						var =  _global_vars.GetVarValue(nData);
					}
					else
					{
						 var = _global_vars.GetVarName(nData);
					}
					
					wstr.insert(wstr.end(),var.begin(),var.end());
					
					
				}
			}
		}
		else
		{
			wstr.insert(wstr.end(),nVarIdx);
		}
	}
	//	convert wstring to string
	std::string str(wstr.begin(),wstr.end());
	//	return result
	return str;

}

/************************************************************************/
//  decode push/pop string
/************************************************************************/
std::string CNsisFile::DecodePushPop(entry ent)
{
	char buff[0x100];

	if (ent.offsets[2] > 0 )
	{
		sprintf_s(buff,0x100,"Exch %i",ent.offsets[2]);
	}
	else
	{
		if (0 != ent.offsets[1])
		{
			std::string var = _global_vars.GetVarName(ent.offsets[0]);
			sprintf_s(buff,0x100,"Pop %s",var.c_str());
		}
		else
		{
			std::string str = GetNsisString(ent.offsets[0]);
			sprintf_s(buff,0x100,"Push [%s]",str.c_str());
		}
	}




	// sprintf_s(buff,0x100,"Push/Pop/Exchange: 3 [variable/string, ?pop:push, ?exch] [%i,%i,%i,%i,%i,%i]",ent.offsets[0],ent.offsets[1],ent.offsets[2],ent.offsets[3],ent.offsets[4],ent.offsets[5]);
	std::string result = buff;

	return result;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::DecodeAssign(entry ent)
{
	std::string var = _global_vars.GetVarName(ent.offsets[0]);
	std::string text = GetNsisString(ent.offsets[1]);
	std::string start = GetNsisString(ent.offsets[2]);
	std::string off = GetNsisString(ent.offsets[3]);
	std::string result = "StrCpy "+var + " [" + text + "] " + start + " " + off;
	return result;
}

/************************************************************************/
//	decode IntOp 
/************************************************************************/
std::string CNsisFile::DecodeIntOp(entry ent)
{
	//
	std::string str;
	std::string out = _global_vars.GetVarName(ent.offsets[0]);
	std::string var1 = GetNsisString(ent.offsets[1]);
	std::string var2 = GetNsisString(ent.offsets[2]);
	std::string operand;
	switch (ent.offsets[3])
	{
	case 0: operand =var1 +  " + "+  var2; break;
	case 1: operand =var1 +  " - "+  var2; break;
	case 2: operand =var1 +  " * "+  var2; break;
	case 3: operand =var1 +  " / "+  var2;break;
	case 4: operand =var1 +  " | "+  var2;; break;
	case 5: operand =var1 +  " & "+  var2;; break;
	case 6: operand =var1 +  " ^ "+  var2; break;
	case 7: operand =var1 +  " ! "+  var2; break;
	case 8: operand =var1 +  " || "+  var2; break;
	case 9: operand =var1 +  " && "+  var2;; break;
	case 10: operand =var1 +  " % "+  var2;break;
	case 11: operand =var1 +  " << "+  var2; break;
	case 12: operand =var1 +  " >> "+  var2; break;
	}
	//	"IntOp: 4 [output, input1, input2, op] where op: 0=add, 1=sub, 2=mul, 3=div, 4=bor, 5=band, 6=bxor, 7=bnot input1, 8=lnot input1, 9=lor, 10=land], 11=1%2"	
	str = "IntOp " + out +" "+ operand;
	return str;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::GetStringFromParm(entry ent,int id_,bool isvalue)
{
	int id = id_ < 0 ? -id_ : id_;
	std::string str = GetNsisString( ent.offsets[id & 0xF],isvalue);
	return str;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::DecodeStrCmp(entry ent)
{
	std::string str;
	std::string var1 = GetStringFromParm(ent,0x20);
	std::string var2 = GetStringFromParm(ent,0x31);

	int off2 = ent.offsets[2] == 0 ? 0 : ent.offsets[2] -1;
	int off3 = ent.offsets[3] == 0 ? 0 : ent.offsets[3] -1;
	
	char buff[0x10];
	sprintf_s(buff,0x10,"] %i %i",off2,off3);
	str = "StrCmp [" + var1 + "] ["+ var2;
	str += buff;
	//	"StrCmp: 5 [str1, str2, jump_if_equal, jump_if_not_equal, case-sensitive?]"
	return str;

}

/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::DecodeNopJump(entry ent)
{
	//" Nop/Jump, do nothing: 1, [?new address+1:advance one]"
	
	char buff[0x10];
	if (ent.offsets[0] == 0)
	{
		sprintf_s(buff,0x10,"Nop");
	}
	else
	{
		sprintf_s(buff,0x10,"Goto  %i",ent.offsets[0]);
	}

	return buff;
}


/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::DecodeExtractFile(entry ent)
{
	//	"File to extract: 6 [overwriteflag, output filename, compressed filedata, filedatetimelow, filedatetimehigh, allow ignore] overwriteflag: 0x1 = no. 0x0=force, 0x2=try, 0x3=if date is newer"
	std::string name = GetStringFromParm(ent,0x31);
	for (unsigned i=0x00;i<_nsis_files.size();i++)
	{
		sfile *sf = &_nsis_files[i];
		if (sf->offset == ent.offsets[2])
		{
			memset(sf->filename,0,sizeof(sf->filename));
			int len = min(sizeof(sf->filename)-1,name.length());
			memcpy(sf->filename,name.c_str(),len);
		}
	}
	int overwriteflag = ent.offsets[0] & 7;

	std::string str = "File "+ name;
	return str;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::DecodeFileOperation(entry ent)
{
	std::string str ;
	std::string handle = _global_vars.GetVarName(ent.offsets[0]);
	
	switch (ent.which)
	{
	case EW_FCLOSE:
		{
			str = "FileClose " + _global_vars.GetVarName(ent.offsets[0]);
		}
		break;
	case EW_FOPEN: // FileOpen: 4  [name, openmode, createmode, outputhandle]
		{
			std::string name = GetStringFromParm(ent,-0x13);
			std::string mode = GetNsisString(ent.offsets[2]); 
			str = "FileOpen " + handle + " " + name ; 
		}
		break;
	case EW_FPUTS:
		{
			std::string out = _global_vars.GetVarName(ent.offsets[0]);
			std::string buff = GetNsisString(ent.offsets[1]);

			str = "FileWriteA " + out + " " + buff;break;
		}
		break;
	case EW_FGETS:
		{
			std::string out = _global_vars.GetVarName(ent.offsets[1]);
			std::string maxlen = GetNsisString(ent.offsets[2]);
			if (1 == ent.offsets[3])
			{
				str = "FileReadByteA " + handle + " " + out;
			}
			else
			{
				str = "FileReadA " + handle + " " + out;
			}
		}	
		break;
	case EW_FPUTWS:
		{
			std::string out = _global_vars.GetVarName(ent.offsets[0]);
			std::string buff = GetNsisString(ent.offsets[1]);
			//str = "FileWriteUTF16LE: 3 [handle, string, ?int:string]";break;
			str = "FileWriteW " + out + " " + buff;break;
		}
		break;
	case EW_FGETWS:
		{
			std::string out = _global_vars.GetVarName(ent.offsets[1]);
			std::string maxlen = GetNsisString(ent.offsets[2]);
			if (0 == ent.offsets[3])
			{
				str = "FileReadByteW " + handle + " " + out;
			}
			else
			{
				str = "FileReadW " + handle + " " + out;
			}
		}break;
	case EW_FSEEK:
		{
			//#  define FILE_BEGIN 0
			//#  define FILE_CURRENT 1
			//	#  define FILE_END 2
			std::string mode ;
			if (0 == ent.offsets[3]) mode = "FILE_BEGIN";
			if (1 == ent.offsets[3]) mode = "FILE_CURRENT";
			if (2 == ent.offsets[3]) mode = "FILE_END";
			

			// FileSeek: 4  [handle, offset, mode, >=0?positionoutput]
			std::string handle = _global_vars.GetVarName(ent.offsets[0]);
			std::string offset = GetNsisString(ent.offsets[2]);

			str = "FileSeek " + handle + " " + offset + " " + mode;
		}break;
	default:
		break;
	}
	return str;
}

/************************************************************************/
//
/************************************************************************/
std::string CNsisFile::DecodeCall(entry ent)
{

	int newent = ent.offsets[0];
	char buff[0x100];

	if (newent > 0 )
	{
		sprintf_s(buff,0x100,"Call Function%4.4i",ent.offsets[0]-1);
	}
	else
	{
		std::string str = _global_vars.GetVarName(-(newent+1));
		sprintf_s(buff,0x100,"Call %s",str.c_str());
		return buff;
	}


	for (unsigned i=0x00;i<_nsis_function_entry.size();i++)
	{
		if ((ent.offsets[0]-1) == _nsis_function_entry[i])
		{
			return buff;
		}
	}
	_nsis_function_entry.push_back(ent.offsets[0]-1);

	return buff;
}

/************************************************************************/
//	
/************************************************************************/
std::string CNsisFile::DecodeIfFileExists(entry ent)
{
	//	"IfFileExists: 3, [file name, jump amount if exists, jump amount if not exists]"
	char buff[0x100];
	std::string  filename = GetNsisString(ent.offsets[0]);
	sprintf_s(buff,0x100,"IfFileExists %s %4.4i %4.4i",filename.c_str(),ent.offsets[1],ent.offsets[2]);
	return buff;
}

/************************************************************************/
//	
/************************************************************************/
std::string CNsisFile::DecodeCallDllFunction(entry ent)
{
	// 
	std::string str = "Call_Dll_Function " + GetNsisString(ent.offsets[0]) + ":" + GetNsisString(ent.offsets[1]);

	std::string param =  GetNsisString(ent.offsets[2]);

	if (ent.offsets[4] == 0)
	{
		int o=0;
	}
	return str;
	// "Register DLL: 3,[DLL file name, string ptr of function to call, text to put in display (<0 if none/pass parms), 1 - no unload, 0 - unload]"
}

/************************************************************************/
//	
/************************************************************************/
std::string CNsisFile::DecodeExecute(entry ent)
{
	//	"Execute program: 3,[complete command line,waitflag,>=0?output errorcode"
	std::string str;
	if (ent.offsets[2] == 0x0)
	{
		str = "Exec " + GetNsisString(ent.offsets[0]);
	}
	else
	{
		str = "ExecWait [" + GetNsisString(ent.offsets[0]) + "] " +_global_vars.GetVarName(ent.offsets[1]);
	}
	
	return str;
}

/************************************************************************/
//
/************************************************************************/
std::string CNsisFile::DecodeStrLen(entry ent)
{
	std::string str = "StrLen "  + _global_vars.GetVarName(ent.offsets[0]) + " " + GetNsisString(ent.offsets[1]);
	return str;
}

/************************************************************************/
//
/************************************************************************/
std::string CNsisFile::DecodeIfFlag(entry ent)
{
	char buff[0x100];	
	//	"!If a flag: 4 [on, off, id, new value mask]"
	if (ent.offsets[2] == 2) // exec_error
	{
		sprintf_s(buff,0x100,"if_exec_error == 1 goto %4.4i else goto %4.4i",ent.offsets[0],ent.offsets[1]);
	}
	else
	{
		sprintf_s(buff,0x100,"unkow if_flag");
	}
	return buff;
}
/************************************************************************/
//
/************************************************************************/
std::string CNsisFile::DecodeSetFlag(entry ent)
{
	std::string str;
	switch (ent.offsets[0])
	{
	case 0x00: str = "SetFlag AutoClose " + GetNsisString(ent.offsets[1]); break;
	case 0x01: str = "SetFlag all_user_var " + GetNsisString(ent.offsets[1]); break;
	case 0x02: str = "SetFlag exec_error " + GetNsisString(ent.offsets[1]); 	break;
	case 0x03: str = "SetFlag abort " + GetNsisString(ent.offsets[1]); break;
	case 0x04: str = "SetFlag ExecReboot " + GetNsisString(ent.offsets[1]);break;
	case 0x05: str = "SetFlag RebootCalled " + GetNsisString(ent.offsets[1]);break;
	case 0x06: str = "SetFlag depricated " + GetNsisString(ent.offsets[1]);break;
	case 0x07: str = "SetFlag Plugin_api_version " + GetNsisString(ent.offsets[1]);break;
	case 0x08: str = "SetFlag Silent " + GetNsisString(ent.offsets[1]);break;
	case 0x09: str = "SetFlag instdir_error " + GetNsisString(ent.offsets[1]);break;
	case 0x0A: str = "SetFlag rtl " + GetNsisString(ent.offsets[1]);break;
	case 0x0B: str = "SetFlag errlevel " + GetNsisString(ent.offsets[1]);break;
	case 0x0C: str = "SetFlag alter_reg_view " + GetNsisString(ent.offsets[1]);break;
	case 0x0D: str = "SetFlag status_update " + GetNsisString(ent.offsets[1]);break;

	default:
			str = "SetFlag __unknow_flag";
		break; 
	}
	return str;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::DecodeIntCmp(entry ent)
{
	// "IntCmp: 6 [val1, val2, equal, val1<val2, val1>val2, unsigned?]"
	std::string var1 = GetStringFromParm(ent,0x20);
	std::string var2 = GetStringFromParm(ent,0x31);
	std::string str = "IntCmp " + var1 + " " + var2;
	int off2 = ent.offsets[2] == 0 ? 0 : ent.offsets[2] -1;
	int off3 = ent.offsets[3] == 0 ? 0 : ent.offsets[3] -1;
	int off4 = ent.offsets[4] == 0 ? 0 : ent.offsets[4] -1;

	char buff[0x10];
	sprintf_s(buff,0x10," %4.4i %4.4i %4.4i",off2,off3,off4);
	str += buff;

	return str;
}

/************************************************************************/
//
/************************************************************************/
std::string CNsisFile::DecodeIntFmt(entry ent)
{
	char buff[0x1000];
	std::string str = GetNsisString(ent.offsets[1]);
	sprintf_s(buff,0x1000,"IntFmt %s %s %i",_global_vars.GetVarName(ent.offsets[0]).c_str(),str.c_str(),ent.offsets[2]);
	
	return buff;
}

/************************************************************************/
//
/************************************************************************/
std::string CNsisFile::DecodeFindFiles(entry ent)
{
	std::string str;
	if (ent.which == EW_FINDFIRST)
	{
		//"!FindFirst: 2 [filespec, output, handleoutput]"
		std::string output = _global_vars.GetVarName(ent.offsets[0]);
		std::string handle = _global_vars.GetVarName(ent.offsets[1]);
		std::string filespec = GetNsisString(ent.offsets[2]);
		str = "FindFirst " + handle + " " + output + " " + filespec;
	}
	if (ent.which == EW_FINDCLOSE)
	{
		//	"!FindClose: 1 [handle]"
		std::string handle = _global_vars.GetVarName(ent.offsets[0]);
		str = "FindClose " + handle;
	}
	if (ent.which == EW_FINDNEXT)
	{
		// "!FindNext: 2  [output, handle]"
		std::string output = _global_vars.GetVarName(ent.offsets[0]);
		std::string handle = _global_vars.GetVarName(ent.offsets[1]);
		str = "FindNext " + handle + " " + output;
	}
	return str;
}

const TCHAR * _RegKeyHandleToName(HKEY hKey)
{
	if (hKey == HKEY_CLASSES_ROOT)
		return _T("HKEY_CLASSES_ROOT");
	else if (hKey == HKEY_CURRENT_USER)
		return _T("HKEY_CURRENT_USER");
	else if (hKey == HKEY_LOCAL_MACHINE)
		return _T("HKEY_LOCAL_MACHINE");
	else if (hKey == HKEY_USERS)
		return _T("HKEY_USERS");
	else if (hKey == HKEY_PERFORMANCE_DATA)
		return _T("HKEY_PERFORMANCE_DATA");
	else if (hKey == HKEY_CURRENT_CONFIG)
		return _T("HKEY_CURRENT_CONFIG");
	else if (hKey == HKEY_DYN_DATA)
		return _T("HKEY_DYN_DATA");
	else
		return _T("invalid registry key");
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::DecodeReadRegStr(entry ent)
{
	//	"!ReadRegStr: 5 [output, rootkey(int), keyname, itemname, ==1?int::str]"
	std::string var  = _global_vars.GetVarName(ent.offsets[0]);
	std::string root = _RegKeyHandleToName((HKEY)ent.offsets[1]);
	std::string path = GetNsisString(ent.offsets[2]);
	std::string key  = GetNsisString(ent.offsets[3]);
	std::string str ;
	if (1 == ent.offsets[4])
	{
		str = "ReadRegDWORD " + var + " " + root + " " + path + " " + key;
	}
	else
	{
		str = "ReadRegStr " + var + " " + root + " " + path + " " + key;
	}
	return str;	
}

/************************************************************************/
//	
/************************************************************************/
std::string CNsisFile::DecodeCreateDir(entry ent)
{
	std::string  path = "CreateDirectory "+ GetNsisString(ent.offsets[0]);
	if (ent.offsets[1])
	{
		path += " ; Set_as_default";
	}
	//	"!Create directory: 2, [path, ?update$INSTDIR]"
	return path;
}

/************************************************************************/
//
/************************************************************************/
std::string CNsisFile::DecodeDeleteFile(entry ent)
{
	std::string str = "Delete " +  GetNsisString(ent.offsets[0]) + " ;";
	str+= ent.offsets[1] & 0x01 ? "DEL_DIR | " : "";
	str+= ent.offsets[1] & 0x02 ? "DEL_RECURSE | " : "";
	str+= ent.offsets[1] & 0x04 ? "DEL_REBOOT | " : "";
	str+= ent.offsets[1] & 0x08 ? "DEL_SIMPLE | " : "";
	/*
	"!Delete File: 2, [filename, rebootok]"
#define DEL_DIR 1
#define DEL_RECURSE 2
#define DEL_REBOOT 4
#define DEL_SIMPLE 8

	*/
	return str;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string CNsisFile::DecodeSleep(entry ent)
{
	char buff[0x100];
	//	"!Sleep: 1 [sleep time in milliseconds]"
	sprintf_s(buff,0x100,"Sleep %i",ent.offsets[0]);
	return buff;
}

/************************************************************************/
//	
/************************************************************************/
std::string CNsisFile::DecodeGetTempFileName(entry ent)
{
	std::string str = "GetTempFileName " + _global_vars.GetVarName(ent.offsets[0]) + " " +  GetNsisString(ent.offsets[1]);
	//	"!GetTempFileName: 2 [output, base_dir]"
	return str;
}

/************************************************************************/
//
/************************************************************************/
std::string CNsisFile::DecodeMessageBox(entry ent)
{

	#define MBD(x) {x,_T(#x)},
	struct
	{
		int id;
		const TCHAR *str;
	} list[]=
	{
		MBD(MB_ABORTRETRYIGNORE)
		MBD(MB_OK)
		MBD(MB_OKCANCEL)
		MBD(MB_RETRYCANCEL)
		MBD(MB_YESNO)
		MBD(MB_YESNOCANCEL)
		MBD(MB_ICONEXCLAMATION)
		MBD(MB_ICONINFORMATION)
		MBD(MB_ICONQUESTION)
		MBD(MB_ICONSTOP)
		MBD(MB_USERICON)
		MBD(MB_TOPMOST)
		MBD(MB_SETFOREGROUND)
		MBD(MB_RIGHT)
		MBD(MB_RTLREADING)
		MBD(MB_DEFBUTTON1)
		MBD(MB_DEFBUTTON2)
		MBD(MB_DEFBUTTON3)
		MBD(MB_DEFBUTTON4)
	};

	std::string flags = "";
	for (unsigned i = 0x00; i<19; i++)
	{
		if ((ent.offsets[0] & list[i].id) == list[i].id)			
		{
			flags += flags.empty() ? "" : "|";
			flags += list[i].str;
		}
	}

	//"!MessageBox: 5,[MB_flags,text,retv1:retv2,moveonretv1:moveonretv2]"
	std::string str = "MessageBox " + flags  + " \""+ GetNsisString(ent.offsets[1]); 
	char buff[0x100];
	sprintf_s(buff,0x100,"\" %4.4i %4.4i", ent.offsets[3],ent.offsets[5]);
	str += buff;
	//	"!GetTempFileName: 2 [output, base_dir]"
	return str;
}

std::string CNsisFile::EntryToString(entry ent)
{
	std::string str;
	switch ( ent.which)
	{
		//case EW_INVALID_OPCODE:		str = " zero is invalid. useful for catching errors. (otherwise an all zeroes instruction does nothing, which is easily ignored but means something is wrong."; break;
		case EW_INVALID_OPCODE:		str = " "; break;
		case EW_RET:				str = "return from function call";break;
		case EW_NOP:				str = DecodeNopJump(ent);break;
		case EW_ABORT:				str = "Abort: 1 [status]";break;
		case EW_QUIT:				str = "Quit: 0";break;
		case EW_CALL:				str = DecodeCall(ent);break;
		case EW_UPDATETEXT:			str = "!Update status text: 2 [update str, ui_st_updateflag=?ui_st_updateflag:this]";break;
		case EW_SLEEP:				str = DecodeSleep(ent);break;
		case EW_BRINGTOFRONT:		str = "!BringToFront: 0";break;
		case EW_CHDETAILSVIEW:		str = "!SetDetailsView: 2 [listaction,buttonaction]";break;
		case EW_SETFILEATTRIBUTES:	str = "!SetFileAttributes: 2 [filename, attributes]";break;
		case EW_CREATEDIR:			str = DecodeCreateDir(ent);break;
		case EW_IFFILEEXISTS:		str = DecodeIfFileExists(ent);break;
		case EW_SETFLAG:			str = DecodeSetFlag(ent);break;
		case EW_IFFLAG:				str = DecodeIfFlag(ent);break;
		case EW_GETFLAG:			str = "!Gets a flag: 2 [output, id]";break;
		case EW_RENAME:				str = "!Rename: 3 [old, new, rebootok]";break;
		case EW_GETFULLPATHNAME:	str = "!GetFullPathName: 2 [output, input, ?lfn:sfn]";break;
		case EW_SEARCHPATH:			str = "!SearchPath: 2 [output, filename]";break;
		case EW_GETTEMPFILENAME:	str = DecodeGetTempFileName(ent);break;
		case EW_EXTRACTFILE:		str = DecodeExtractFile(ent);break;
		case EW_DELETEFILE:			str =  DecodeDeleteFile(ent);break;
		case EW_MESSAGEBOX:			str = DecodeMessageBox(ent);break;
		case EW_RMDIR:				str = "!RMDir: 2 [path, recursiveflag]";break;
		case EW_STRLEN:				str = DecodeStrLen(ent);break;
		case EW_ASSIGNVAR:			str = DecodeAssign(ent);break;
		case EW_STRCMP:				str = DecodeStrCmp(ent);break;
		case EW_READENVSTR:			str = "!ReadEnvStr/ExpandEnvStrings: 3 [output, string_with_env_variables, IsRead]";break;
		case EW_INTCMP:				str = DecodeIntCmp(ent);break;
		case EW_INTOP:				str = DecodeIntOp(ent);break;
		case EW_INTFMT:				str = DecodeIntFmt(ent);break;
		case EW_PUSHPOP:			str = DecodePushPop(ent);break;
		case EW_FINDWINDOW:			str = "!FindWindow: 5, [outputvar, window class,window name, window_parent, window_after]";break;
		case EW_SENDMESSAGE:		str = "!SendMessage: 6 [output, hwnd, msg, wparam, lparam, [wparamstring?1:0 | lparamstring?2:0 | timeout<<2]";break;
		case EW_ISWINDOW:			str = "!IsWindow: 3 [hwnd, jump_if_window, jump_if_notwindow]";break;
		case EW_GETDLGITEM:			str = "!GetDlgItem:        3: [outputvar, dialog, item_id]";break;
		case EW_SETCTLCOLORS:		str = "!SerCtlColors:      3: [hwnd, pointer to struct colors]";break;
		case EW_SETBRANDINGIMAGE:	str = "!SetBrandingImage:  1: [Bitmap file]";break;
		case EW_CREATEFONT:			str = "!CreateFont:        5: [handle output, face name, height, weight, flags]";break;
		case EW_SHOWWINDOW:			str = "!ShowWindow:        2: [hwnd, show state]";break;
		case EW_SHELLEXEC:			str = "!ShellExecute program: 4, [shell action, complete commandline, parameters, showwindow]";break;
		case EW_EXECUTE:			str = DecodeExecute(ent);break;
		case EW_GETFILETIME:		str = "!GetFileTime; 3 [file highout lowout]";break;
		case EW_GETDLLVERSION:		str = "!GetDLLVersion: 3 [file highout lowout]";break;
	//	case EW_GETFONTVERSION:		str = "GetFontVersion: 2 [file version]";break;
	//	case EW_GETFONTNAME:		str = "GetFontName: 2 [file fontname]";break;
		case EW_REGISTERDLL:		str = DecodeCallDllFunction(ent);break;
		case EW_CREATESHORTCUT:		str = "!Make Shortcut: 5, [link file, target file, parameters, icon file, iconindex|show mode<<8|hotkey<<16]";break;
		case EW_COPYFILES:			str = "CopyFiles: 3 [source mask, destination location, flags]";break;
		case EW_REBOOT:				str = "!Reboot: 0";break;
		case EW_WRITEINI:			str = "!Write INI String: 4, [Section, Name, Value, INI File]";break;
		case EW_READINISTR:			str = "!ReadINIStr: 4 [output, section, name, ini_file";break;
		case EW_DELREG:				str = "!DeleteRegValue/DeleteRegKey: 4, [root key(int), KeyName, ValueName, delkeyonlyifempty]. ValueName is -1 if delete key";break;
		case EW_WRITEREG:			str = "!Write Registry value: 5, [RootKey(int),KeyName,ItemName,ItemData,typelen]  typelen=1 for str, 2 for dword, 3 for binary, 0 for expanded str";break;
		case EW_READREGSTR:			str = DecodeReadRegStr(ent);;break;
		case EW_REGENUM:			str = "!RegEnum: 5 [output, rootkey, keyname, index, ?key:value]";break;
		case EW_FCLOSE:				str = DecodeFileOperation(ent);break;
		case EW_FOPEN:				str = DecodeFileOperation(ent);break;
		case EW_FPUTS:				str = DecodeFileOperation(ent);break;
		case EW_FGETS:				str = DecodeFileOperation(ent);break;
		case EW_FPUTWS:				str = DecodeFileOperation(ent);break;
		case EW_FGETWS:				str = DecodeFileOperation(ent);break;
		case EW_FSEEK:				str = DecodeFileOperation(ent);break;
		case EW_FINDCLOSE:			str = DecodeFindFiles(ent);break;
		case EW_FINDNEXT:			str = DecodeFindFiles(ent);break;
		case EW_FINDFIRST:			str = DecodeFindFiles(ent);break;
		case EW_WRITEUNINSTALLER:	str = "!WriteUninstaller: 3 [name, offset, icon_size]";break;
	//	case EW_LOG:				str = "LogText: 2 [0, text] / LogSet: [1, logstate]";break;
		case EW_SECTIONSET:			str = "!SectionSetText:    3: [idx, 0, text] / SectionGetText:    3: [idx, 1, output] / SectionSetFlags:   3: [idx, 2, flags] /  SectionGetFlags:   3: [idx, 3, output] / InstTypeGetFlags:  3: [idx, 1, output]";break;
		case EW_GETLABELADDR:		str = "!both of these get converted to EW_ASSIGNVAR";break;
		case EW_GETFUNCTIONADDR:	str = "!both of these get converted to EW_ASSIGNVAR";break;
		case EW_LOCKWINDOW:			str = "!EW_LOCKWINDOW";break;
		case EW_FINDPROC:			str = "!FindProc: 1 [process_name]";break;
	default:
		 str = " !! __  unknow __ !!";
		break;
	}
	return str;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNsisFile::ProcessingEntries()
{
	
	char buff[0x10];
	for (unsigned i = 0x00;i<_nsis_entry.size(); i++ )
	{
		entry ent = _nsis_entry[i];
		sprintf_s(buff,0x10,"%4.4i   ",i );
		std::string str ;//= buff;
		str += EntryToString(ent);
		_nsis_script_code.push_back(str);
	}
}