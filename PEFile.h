#pragma once
#include "stdafx.h"
#include <vector>
#include "Header.h"

#define CHECKSUM_OFFSET sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+offsetof(IMAGE_OPTIONAL_HEADER, CheckSum)
/************************************************************************/
//	the class to work with PE file format
/************************************************************************/
class CPEFile
{
public:
	CPEFile(void);
	~CPEFile(void);

	//	load and parsing file
	bool	LoadAndParseFile(char * filename);

	std::vector<byte> * GetEOFSegnemt();
	bool SetEofSegnemt(std::vector<byte> *eofseg,int varcount);

	std::vector<byte> * GetRCRSSegnemt();
	bool SetRCRSSegnemt(std::vector<byte> *eofseg,int varcount);

	std::string GetCodeSegmentHash();
	std::string GetDumpHash();
	int GetNDataSize();
	//	save exe dump afer changes
	void	SaveExeDump(char * filename);

	DWORD	PE_CRC(DWORD  crc, const unsigned char *buf, unsigned int len);

	//	update text segment and all data	
	void ReplaceTextSegment(CPEFile* source);

	int GetNsisVarCount() ;

private:
	//////////////////////////////////////////////////////////////////////////
	//
	//	PE variables and funcrions 

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
	std::vector<byte> _pe_dot_text_section;
	//  .rdata
	std::vector<byte> _pe_dot_rdata_section;
	//	.data
	std::vector<byte> _pe_dot_data_section;
	//	.rsrc
	std::vector<byte> _pe_dot_rsrc_section;
	//	.reloc
	std::vector<byte> _pe_dot_reloc_section;
	//	.eof  - all data what plased after all section and before sign table
	std::vector<byte> _eof_dump;


	IMAGE_SECTION_HEADER * _text_header;
	IMAGE_SECTION_HEADER * _data_header;
	IMAGE_SECTION_HEADER * _rsrc_header;
	IMAGE_SECTION_HEADER * _rdata_header;
	IMAGE_SECTION_HEADER * _ndata_header;


	//	Certificate tabel 
	std::vector<byte> _pe_certificatr_table;
	//	resource table
	std::vector<byte> _pe_resource_table;

	int _ndata_size;
	
};

