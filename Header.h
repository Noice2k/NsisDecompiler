#pragma once
#define NSIS_MAX_STRLEN 1024
#define NSIS_MAX_INST_TYPES 32
#define NSIS_DEFAULT_LANG 1033


#define FH_FLAGS_MASK 15
#define FH_FLAGS_UNINSTALL 1
#define FH_FLAGS_SILENT 2
#define FH_FLAGS_NO_CRC 4
#define FH_FLAGS_FORCE_CRC 8

#define FH_SIG 0xDEADBEEF

// neato surprise signature that goes in firstheader. :)
#define FH_INT1 0x6C6C754E
#define FH_INT2 0x74666F73
#define FH_INT3 0x74736E49

typedef struct
{
	int flags; // FH_FLAGS_*
	int siginfo;  // FH_SIG

	int nsinst[3]; // FH_INT1,FH_INT2,FH_INT3

	// these point to the header+sections+entries+stringtable in the datablock
	int length_of_header;

	// this specifies the length of all the data (including the firstheader and CRC)
	int length_of_all_following_data;
} firstheader;

enum {
	NB_PAGES,
	NB_SECTIONS,
	NB_ENTRIES,
	NB_STRINGS,
	NB_LANGTABLES,
	NB_CTLCOLORS,
	NB_BGFONT,
	NB_DATA,
	BLOCKS_NUM
};

// nsis blocks
struct block_header {
	int offset;
	int num;
};

// Settings common to both installers and uninstallers
typedef struct
{
	int flags; // CH_FLAGS_*
	struct block_header blocks[BLOCKS_NUM];

	// InstallDirRegKey stuff
	int install_reg_rootkey;
	// these two are not processed!
	int install_reg_key_ptr, install_reg_value_ptr;
	int bg_color1, bg_color2, bg_textcolor;
	// installation log window colors
	int lb_bg, lb_fg;
	// langtable size
	int langtable_size;
	// license background color
	int license_bg;
	// .on* calls
	int code_onInit;
	int code_onInstSuccess;
	int code_onInstFailed;
	int code_onUserAbort;
	int code_onGUIInit;
	int code_onGUIEnd;
	int code_onMouseOverSection;
	int code_onVerifyInstDir;
	int code_onSelChange;
	int code_onRebootFailed;
	int install_types[NSIS_MAX_INST_TYPES+1];
	int install_directory_ptr; // default install dir.
	int install_directory_auto_append; // auto append part
	int str_uninstchild;
	int str_uninstcmd;
	int str_wininit;
} header;
