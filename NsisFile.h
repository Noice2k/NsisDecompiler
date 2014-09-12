#pragma once
#include "stdafx.h"
#include <vector>
#include "Header.h"
#include "Compressor.h"
#include "LZMA.h"
#include "crc32.h"

struct sfile
{
	byte * pointer;
	DWORD  size;
};

class CNsisFile
{
public:
	CNsisFile(void);
	~CNsisFile(void);

	//	load dump
	void	LoadDump(char * filename);
	//	load exe dump
	void    LoadExeDump(char * filename);

	
	//	save all nsis files to disk
	void	DumpFiles(char * path);
		

	//	save exe dump afer changes
	void	SaveExeDump(char * filename);

	//	processing header
	bool	ProcessingHeader();

	//	the data dump
	std::vector<byte> _dump;
	//	the first header, used to detect the begin of nsis compressed data 
	firstheader		_firstheader;
	//	the main file header, this header in compressed
	header			_globalheader;
	header			_uheader;
	//	the current offset;
	int				_offset;

	//	the dump structure:  global_dump = [4 bytes size header dump][header dump][...]

	//	the global dump
	std::vector<byte> _global_dump;
	//	the header dump
	std::vector<byte> _header_dump;

	
	

	//	compressor/decompresor
	CCompressor	    _compressor;
	DWORD			PE_CRC(DWORD  crc, const unsigned char *buf, unsigned int len);
	unsigned		_crc_offset;

private:
	bool LoadPages();
	bool LoadSection();
	bool LoadEntries();
	bool LoadStrings();

	//	install pages
	std::vector<page> _ipages;

	//	install section
	std::vector<section> _isection;

	//	install entries
	std::vector<entry>  _ientry;

	byte			    * _istrings;

	std::vector<sfile>  _files;

	
private:

	std::vector<byte> _exe_dump;
	IMAGE_DOS_HEADER _dos_header;
	IMAGE_NT_HEADERS _nt_header;

	std::vector<IMAGE_SECTION_HEADER>	_section_headers;

	
	//	.text 
	std::vector<unsigned char> _dot_text_section;
	//  .rdata
	std::vector<byte> _dot_rdata_section;
	//	.data
	std::vector<byte> _dot_data_section;
	//	.rsrc
	std::vector<byte> _dot_rsrc_section;

	//	msdosstab 
	std::vector<byte> _msdos_stub;
	//	Certificate tabel 
	std::vector<byte> _certificatr_table;
	//	resource table
	std::vector<byte> _resource_table;


	
};

