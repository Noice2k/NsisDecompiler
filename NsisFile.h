#pragma once
#include "stdafx.h"
#include <vector>
#include "Header.h"
#include "Compressor.h"
#include "LZMA.h"
#include "crc32.h"
#include "GlobalVars.h"

struct sfile
{
	byte *	pointer;
	DWORD	size;
	int		offset;
	char	filename[0x200];
};

static int *cur_langtable;
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

	CGlobalVars		_global_vars;

private:
	bool LoadPages();
	bool LoadSection();
	bool LoadEntries();
	bool LoadStrings();
	bool LoadLandTables();
	
	//	
	void ProcessingEntries();

	void ProcessingFunctions();

	std::string EntryToString(entry ent);

    //  decode functions
	std::string DecodePushPop(entry ent);
    std::string DecodeAssign(entry ent);
	std::string DecodeIntOp(entry ent);
	std::string DecodeStrCmp(entry ent);
	std::string DecodeCall(entry ent);
	std::string DecodeNopJump(entry ent);
	std::string DecodeExtractFile(entry ent);
	std::string DecodeFileOperation(entry ent);
	std::string DecodeIfFileExists(entry ent);
	std::string DecodeExecute(entry ent);
	std::string DecodeCallDllFunction(entry ent);
	std::string DecodeStrLen(entry ent);
	std::string DecodeSetFlag(entry ent);

	std::string FormatFunction(int start);

    std::string GetNsisString(int offset);

	std::string GetStringFromParm(entry ent,int id);

	//	install pages
	std::vector<page> _nsis_pages;

	//	install section
	std::vector<section> _nsis_section;

	//	install entries - the executabled code
	std::vector<entry>  _nsis_entry;
	//	install entries - the human relabile text code
	std::vector<std::string> _nsis_script_code;

	//	byte array to the stings
	std::vector<WCHAR>	_nsis_string_table;
    std::vector<int>  _nsis_launguage_table;
	

	//	vector to nsis files (inclide uninstaller, plugins and installation files)
	std::vector<sfile>  _nsis_files;
	std::vector<int>	_nsis_function_entry;

	//////////////////////////////////////////////////////////////////////////
	//
	//	PE variables and funcrions 
private:
	//	all variables for PE format start from _pe_ 
	
	// full exe file dump 
	std::vector<byte> _pe_full_dump;
	//	msdos file header	
	IMAGE_DOS_HEADER  _pe_dos_header;
	//	msdos stab  - short programm to show string "this progamm dont work in msdos"
	std::vector<byte> _pe_msdos_stub;
	//	PE file header
	IMAGE_NT_HEADERS  _pe_nt_header;
	//	vector of sections
	std::vector<IMAGE_SECTION_HEADER>	_pe_section_headers;

	//	.text 
	std::vector<unsigned char> _pe_dot_text_section;
	//  .rdata
	std::vector<byte> _pe_dot_rdata_section;
	//	.data
	std::vector<byte> _pe_dot_data_section;
	//	.rsrc
	std::vector<byte> _pe_dot_rsrc_section;
	//	.reloc
	std::vector<byte> _pe_dot_reloc_section;



	//	Certificate tabel 
	std::vector<byte> _pe_certificatr_table;
	//	resource table
	std::vector<byte> _pe_resource_table;


	
};

