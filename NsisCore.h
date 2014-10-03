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

// NT Signature + IMAGE_FILE_HEADER + Most of IMAGE_OPTIONAL_HEADER
// This is relative to the PE Header Offset



static int *cur_langtable;
class CNsisCore
{
public:
	CNsisCore(void);
	~CNsisCore(void);

	//	load dump
	void	SetNsisDump(std::vector<byte> *source);

	
	
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
	
	unsigned		_crc_offset;

	CGlobalVars		_global_vars;

//private:
	bool LoadPages();
	bool LoadSection();
	bool LoadEntries();
	bool LoadStrings();
	bool LoadLandTables();
	
	//	
	void ProcessingEntries();

	void ProcessingFunctions();
	void FunctionFormatText(int entstart,std::string functiontype,  std::string  name);
	void myRegGetStr(HKEY root, const TCHAR *sub, const TCHAR *name, TCHAR *out, int x64);

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
	std::string DecodeIntCmp(entry ent);
	std::string DecodeIntFmt(entry ent);
	std::string DecodeFindFiles(entry ent);
	std::string DecodeIfFlag(entry ent);
	std::string DecodeReadRegStr(entry ent);
	std::string DecodeCreateDir(entry ent);
	std::string DecodeDeleteFile(entry ent);
	std::string DecodeSleep(entry ent);
	std::string DecodeGetTempFileName(entry ent);
	std::string DecodeMessageBox(entry ent);
	std::string FormatFunction(int start);
    std::string GetNsisString(int offset,bool isvalue = false);
	std::string GetStringFromParm(entry ent,int id,bool isvalue = false);

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

	




	
};

