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
			
			CFile file;
			file.Open("D:\\ConduitInstaller\\spinstaller_s_exe\\all.dat",CFile::modeWrite|CFile::modeCreate,NULL);
			
			file.Write(&_global_dump[0],_global_dump.size());
			file.Close();

			
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
	int offset	= _globalheader.blocks[NB_LANGTABLES].offset;
	int count	= _globalheader.blocks[NB_CTLCOLORS].offset - _globalheader.blocks[NB_LANGTABLES].offset;
	WCHAR * wc = &_nsis_string_table[0x0409];



	return true;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNsisFile::ProcessingEntries()
{
	std::string all;
	for (unsigned i = 0x00;i<_nsis_entry.size(); i++ )
	{
		entry ent = _nsis_entry[i];
		std::string str = EntryToString(ent);
		_nsis_script_code.push_back(str);
		all += str;
		all += "\r\n";

	}


}



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
			sprintf_s(buff,0x100,"Push string #%i",ent.offsets[0]);

		}
	}



	
	// sprintf_s(buff,0x100,"Push/Pop/Exchange: 3 [variable/string, ?pop:push, ?exch] [%i,%i,%i,%i,%i,%i]",ent.offsets[0],ent.offsets[1],ent.offsets[2],ent.offsets[3],ent.offsets[4],ent.offsets[5]);
	std::string result = buff;

	return result;
}

std::string CNsisFile::DecodeAssign(entry ent)
{
	char buff[0x100];
	"Assign: 4 [variable (0-9) to assign, string to assign, maxlen, startpos]";
	sprintf_s(buff,0x100,"Assign: 4 [variable (0-9) to assign, string to assign, maxlen, startpos] [%i,%i,%i,%i]",ent.offsets[0],ent.offsets[1],ent.offsets[2],ent.offsets[3]);
	std::string result = buff;

	return result;
}

std::string CNsisFile::EntryToString(entry ent)
{
	std::string str;
	switch ( ent.which)
	{
		case EW_INVALID_OPCODE:		str = " zero is invalid. useful for catching errors. (otherwise an all zeroes instruction does nothing, which is easily ignored but means something is wrong."; break;
		case EW_RET:				str = "return from function call";break;
		case EW_NOP:				str = " Nop/Jump, do nothing: 1, [?new address+1:advance one]";break;
		case EW_ABORT:				str = "Abort: 1 [status]";break;
		case EW_QUIT:				str = "Quit: 0";break;
		case EW_CALL:				str = "Call: 1 [new address+1]";break;
		case EW_UPDATETEXT:			str = "Update status text: 2 [update str, ui_st_updateflag=?ui_st_updateflag:this]";break;
		case EW_SLEEP:				str = "Sleep: 1 [sleep time in milliseconds]";break;
		case EW_BRINGTOFRONT:		str = " BringToFront: 0";break;
		case EW_CHDETAILSVIEW:		str = "SetDetailsView: 2 [listaction,buttonaction]";break;
		case EW_SETFILEATTRIBUTES:	str = "SetFileAttributes: 2 [filename, attributes]";break;
		case EW_CREATEDIR:			str = "Create directory: 2, [path, ?update$INSTDIR]";break;
		case EW_IFFILEEXISTS:		str = "IfFileExists: 3, [file name, jump amount if exists, jump amount if not exists]";break;
		case EW_SETFLAG:			str = "Sets a flag: 2 [id, data]";break;
		case EW_IFFLAG:				str = "If a flag: 4 [on, off, id, new value mask]";break;
		case EW_GETFLAG:			str = "Gets a flag: 2 [output, id]";break;
		case EW_RENAME:				str = " Rename: 3 [old, new, rebootok]";break;
		case EW_GETFULLPATHNAME:	str = "GetFullPathName: 2 [output, input, ?lfn:sfn]";break;
		case EW_SEARCHPATH:			str = "SearchPath: 2 [output, filename]";break;
		case EW_GETTEMPFILENAME:	str = "GetTempFileName: 2 [output, base_dir]";break;
		case EW_EXTRACTFILE:		str = "File to extract: 6 [overwriteflag, output filename, compressed filedata, filedatetimelow, filedatetimehigh, allow ignore] overwriteflag: 0x1 = no. 0x0=force, 0x2=try, 0x3=if date is newer";break;
		case EW_DELETEFILE:			str = "Delete File: 2, [filename, rebootok]";break;
		case EW_MESSAGEBOX:			str = "MessageBox: 5,[MB_flags,text,retv1:retv2,moveonretv1:moveonretv2]";break;
		case EW_RMDIR:				str = "RMDir: 2 [path, recursiveflag]";break;
		case EW_STRLEN:				str = " StrLen: 2 [output, input]";break;
		case EW_ASSIGNVAR:			str = DecodeAssign(ent);break;
		case EW_STRCMP:				str = "StrCmp: 5 [str1, str2, jump_if_equal, jump_if_not_equal, case-sensitive?]";break;
		case EW_READENVSTR:			str = "ReadEnvStr/ExpandEnvStrings: 3 [output, string_with_env_variables, IsRead]";break;
		case EW_INTCMP:				str = "IntCmp: 6 [val1, val2, equal, val1<val2, val1>val2, unsigned?]";break;
		case EW_INTOP:				str = "IntOp: 4 [output, input1, input2, op] where op: 0=add, 1=sub, 2=mul, 3=div, 4=bor, 5=band, 6=bxor, 7=bnot input1, 8=lnot input1, 9=lor, 10=land], 11=1%2";break;
		case EW_INTFMT:				str = "IntFmt: [output, format, input]";break;
		case EW_PUSHPOP:			str = DecodePushPop(ent);break;
		case EW_FINDWINDOW:			str = "FindWindow: 5, [outputvar, window class,window name, window_parent, window_after]";break;
		case EW_SENDMESSAGE:		str = "SendMessage: 6 [output, hwnd, msg, wparam, lparam, [wparamstring?1:0 | lparamstring?2:0 | timeout<<2]";break;
		case EW_ISWINDOW:			str = "IsWindow: 3 [hwnd, jump_if_window, jump_if_notwindow]";break;
		case EW_GETDLGITEM:			str = "GetDlgItem:        3: [outputvar, dialog, item_id]";break;
		case EW_SETCTLCOLORS:		str = "SerCtlColors:      3: [hwnd, pointer to struct colors]";break;
		case EW_SETBRANDINGIMAGE:	str = "SetBrandingImage:  1: [Bitmap file]";break;
		case EW_CREATEFONT:			str = "CreateFont:        5: [handle output, face name, height, weight, flags]";break;
		case EW_SHOWWINDOW:			str = "ShowWindow:        2: [hwnd, show state]";break;
		case EW_SHELLEXEC:			str = "ShellExecute program: 4, [shell action, complete commandline, parameters, showwindow]";break;
		case EW_EXECUTE:			str = " Execute program: 3,[complete command line,waitflag,>=0?output errorcode";break;
		case EW_GETFILETIME:		str = "GetFileTime; 3 [file highout lowout]";break;
		case EW_GETDLLVERSION:		str = "GetDLLVersion: 3 [file highout lowout]";break;
		case EW_GETFONTVERSION:		str = "GetFontVersion: 2 [file version]";break;
		case EW_GETFONTNAME:		str = "GetFontName: 2 [file fontname]";break;
		case EW_REGISTERDLL:		str = "Register DLL: 3,[DLL file name, string ptr of function to call, text to put in display (<0 if none/pass parms), 1 - no unload, 0 - unload]";break;
		case EW_CREATESHORTCUT:		str = "Make Shortcut: 5, [link file, target file, parameters, icon file, iconindex|show mode<<8|hotkey<<16]";break;
		case EW_COPYFILES:			str = "CopyFiles: 3 [source mask, destination location, flags]";break;
		case EW_REBOOT:				str = "Reboot: 0";break;
		case EW_WRITEINI:			str = "Write INI String: 4, [Section, Name, Value, INI File]";break;
		case EW_READINISTR:			str = "ReadINIStr: 4 [output, section, name, ini_file";break;
		case EW_DELREG:				str = "DeleteRegValue/DeleteRegKey: 4, [root key(int), KeyName, ValueName, delkeyonlyifempty]. ValueName is -1 if delete key";break;
		case EW_WRITEREG:			str = "Write Registry value: 5, [RootKey(int),KeyName,ItemName,ItemData,typelen]  typelen=1 for str, 2 for dword, 3 for binary, 0 for expanded str";break;
		case EW_READREGSTR:			str = "ReadRegStr: 5 [output, rootkey(int), keyname, itemname, ==1?int::str]";break;
		case EW_REGENUM:			str = "RegEnum: 5 [output, rootkey, keyname, index, ?key:value]";break;
		case EW_FCLOSE:				str = "FileClose: 1 [handle]";break;
		case EW_FOPEN:				str = "FileOpen: 4  [name, openmode, createmode, outputhandle]";break;
		case EW_FPUTS:				str = "FileWrite: 3 [handle, string, ?int:string]";break;
		case EW_FGETS:				str = "FileRead: 4  [handle, output, maxlen, ?getchar:gets]";break;
		case EW_FPUTWS:				str = "FileWriteUTF16LE: 3 [handle, string, ?int:string]";break;
		case EW_FGETWS:				str = "FileReadUTF16LE: 4 [handle, output, maxlen, ?getchar:gets]";break;
		case EW_FSEEK:				str = "FileSeek: 4  [handle, offset, mode, >=0?positionoutput]";break;
		case EW_FINDCLOSE:			str = "FindClose: 1 [handle]";break;
		case EW_FINDNEXT:			str = " FindNext: 2  [output, handle]";break;
		case EW_FINDFIRST:			str = "FindFirst: 2 [filespec, output, handleoutput]";break;
		case EW_WRITEUNINSTALLER:	str = "WriteUninstaller: 3 [name, offset, icon_size]";break;
		case EW_LOG:				str = "LogText: 2 [0, text] / LogSet: [1, logstate]";break;
		case EW_SECTIONSET:			str = "SectionSetText:    3: [idx, 0, text] / SectionGetText:    3: [idx, 1, output] / SectionSetFlags:   3: [idx, 2, flags] /  SectionGetFlags:   3: [idx, 3, output] / InstTypeGetFlags:  3: [idx, 1, output]";break;
		case EW_GETLABELADDR:		str = "both of these get converted to EW_ASSIGNVAR";break;
		case EW_GETFUNCTIONADDR:	str = "both of these get converted to EW_ASSIGNVAR";break;
		case EW_LOCKWINDOW:			str = "EW_LOCKWINDOW";break;
		case EW_FINDPROC:			str = "FindProc: 1 [process_name]";break;
	default:
		 str = " !! __  unknow __ !!";
		break;
	}
	return str;
}