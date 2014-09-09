#pragma once
#include "stdafx.h"
#include <vector>
#include "Header.h"
#include "Compressor.h"
#include "LZMA.h"


class CNsisFile
{
public:
	CNsisFile(void);
	~CNsisFile(void);

	//	load dump
	void	LoadDump(char * filename);
	//	processing header
	bool	ProcessingHeader();

	//	the data dump
	std::vector<byte> _dump;
	//	the first header, used to detect the begin of nsis compressed data 
	firstheader		_firstheader;
	//	the main file header, this header in compressed
	header			_globalheader;
	//	the current offset;
	int				_offset;

	//	the dump structure:  global_dump = [4 bytes size header dump][header dump][...]

	//	the global dump
	std::vector<byte> _global_dump;
	//	the header dump
	std::vector<byte> _header_dump;

	
	

	//	compressor/decompresor
	CCompressor	    _compressor;

private:
	bool LoadPages();
	bool LoadSection();
	bool LoadEntries();

	//	install pages
	std::vector<page> _ipages;

	//	install section
	std::vector<section> _isection;

	//	install entries
	std::vector<entry>  _ientry;
};

