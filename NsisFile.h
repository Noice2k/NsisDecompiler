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
	//	the global header dump
	std::vector<byte> _dump_globalheader;
	//	the current offset;
	int				_offset;


	//	compressor/decompresor
	CCompressor	    _compressor;
};

