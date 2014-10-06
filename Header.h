#pragma once
#define NSIS_MAX_STRLEN 8*1024
#define NSIS_MAX_INST_TYPES 32
#define NSIS_DEFAULT_LANG 1033


#define FH_FLAGS_MASK 15
#define FH_FLAGS_UNINSTALL 1Inflate
#define FH_FLAGS_SILENT 2
#define FH_FLAGS_NO_CRC 4
#define FH_FLAGS_FORCE_CRC 8

#define DEL_DIR 1
#define DEL_RECURSE 2
#define DEL_REBOOT 4
#define DEL_SIMPLE 8

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


typedef struct
{
	int dlg_id; // dialog resource id
	int wndproc_id;
	// called before the page is created, or if custom to show the page
	// use Abort to skip the page
	int prefunc;
	// called right before page is shown
	int showfunc;
	// called when the user leaves to the next page
	// use Abort to force the user to stay on this page
	int leavefunc;

	int flags;

	int caption;
	int back;
	int next;
	int clicknext; // caption button next
	int cancel;

	int parms[5];
} page;


typedef struct
{
	int name_ptr; // initial name pointer
	int install_types; // bits set for each of the different install_types, if any.
	int flags; // SF_* - defined above
	// for labels, it looks like it's only used to track how often it is used.
	int code;       // The "address" of the start of the code in count of struct entries.
	int code_size;  // The size of the code in num of entries?
	int size_kb;
	TCHAR name[NSIS_MAX_STRLEN*2]; // '' for invisible sections
	//	так как у нас уникод, то два символа на символ
} section;

#define MAX_ENTRY_OFFSETS 6

typedef struct
{
	int which;   // EW_* enum.  Look at the enum values to see what offsets mean.
	int offsets[MAX_ENTRY_OFFSETS]; // count and meaning of offsets depend on 'which'
	// sometimes they are just straight int values or bool
	// values and sometimes they are indices into string
	// tables.
} entry;


enum
{
	EW_INVALID_OPCODE,    // zero is invalid. useful for catching errors. (otherwise an all zeroes instruction
	// does nothing, which is easily ignored but means something is wrong.
	EW_RET,               // return from function call
	EW_NOP,               // Nop/Jump, do nothing: 1, [?new address+1:advance one]
	EW_ABORT,             // Abort: 1 [status]
	EW_QUIT,              // Quit: 0
	EW_CALL,              // Call: 1 [new address+1]
	EW_UPDATETEXT,        // Update status text: 2 [update str, ui_st_updateflag=?ui_st_updateflag:this]
	EW_SLEEP,             // Sleep: 1 [sleep time in milliseconds]
	EW_BRINGTOFRONT,      // BringToFront: 0
	EW_CHDETAILSVIEW,     // SetDetailsView: 2 [listaction,buttonaction]
	EW_SETFILEATTRIBUTES, // SetFileAttributes: 2 [filename, attributes]
	EW_CREATEDIR,         // Create directory: 2, [path, ?update$INSTDIR]
	EW_IFFILEEXISTS,      // IfFileExists: 3, [file name, jump amount if exists, jump amount if not exists]
	EW_SETFLAG,           // Sets a flag: 2 [id, data]
	EW_IFFLAG,            // If a flag: 4 [on, off, id, new value mask]
	EW_GETFLAG,           // Gets a flag: 2 [output, id]
	EW_RENAME,            // Rename: 3 [old, new, rebootok]
	EW_GETFULLPATHNAME,   // GetFullPathName: 2 [output, input, ?lfn:sfn]
	EW_SEARCHPATH,        // SearchPath: 2 [output, filename]
	EW_GETTEMPFILENAME,   // GetTempFileName: 2 [output, base_dir]
	EW_EXTRACTFILE,       // File to extract: 6 [overwriteflag, output filename, compressed filedata, filedatetimelow, filedatetimehigh, allow ignore]
	//  overwriteflag: 0x1 = no. 0x0=force, 0x2=try, 0x3=if date is newer
	EW_DELETEFILE,        // Delete File: 2, [filename, rebootok]
	EW_MESSAGEBOX,        // MessageBox: 5,[MB_flags,text,retv1:retv2,moveonretv1:moveonretv2]
	EW_RMDIR,             // RMDir: 2 [path, recursiveflag]
	EW_STRLEN,            // StrLen: 2 [output, input]
	EW_ASSIGNVAR,         // Assign: 4 [variable (0-9) to assign, string to assign, maxlen, startpos]
	EW_STRCMP,            // StrCmp: 5 [str1, str2, jump_if_equal, jump_if_not_equal, case-sensitive?]
	EW_READENVSTR,        // ReadEnvStr/ExpandEnvStrings: 3 [output, string_with_env_variables, IsRead]
	EW_INTCMP,            // IntCmp: 6 [val1, val2, equal, val1<val2, val1>val2, unsigned?]
	EW_INTOP,             // IntOp: 4 [output, input1, input2, op] where op: 0=add, 1=sub, 2=mul, 3=div, 4=bor, 5=band, 6=bxor, 7=bnot input1, 8=lnot input1, 9=lor, 10=land], 11=1%2
	EW_INTFMT,            // IntFmt: [output, format, input]
	EW_PUSHPOP,           // Push/Pop/Exchange: 3 [variable/string, ?pop:push, ?exch]
	EW_FINDWINDOW,        // FindWindow: 5, [outputvar, window class,window name, window_parent, window_after]
	EW_SENDMESSAGE,       // SendMessage: 6 [output, hwnd, msg, wparam, lparam, [wparamstring?1:0 | lparamstring?2:0 | timeout<<2]
	EW_ISWINDOW,          // IsWindow: 3 [hwnd, jump_if_window, jump_if_notwindow]
	EW_GETDLGITEM,        // GetDlgItem:        3: [outputvar, dialog, item_id]
	EW_SETCTLCOLORS,      // SerCtlColors:      3: [hwnd, pointer to struct colors]
	EW_SETBRANDINGIMAGE,  // SetBrandingImage:  1: [Bitmap file]
	EW_CREATEFONT,        // CreateFont:        5: [handle output, face name, height, weight, flags]
	EW_SHOWWINDOW,        // ShowWindow:        2: [hwnd, show state]
	EW_SHELLEXEC,         // ShellExecute program: 4, [shell action, complete commandline, parameters, showwindow]
	EW_EXECUTE,           // Execute program: 3,[complete command line,waitflag,>=0?output errorcode]
	EW_GETFILETIME,       // GetFileTime; 3 [file highout lowout]
	//EW_GETDLLVERSION,     // GetDLLVersion: 3 [file highout lowout]
	//EW_GETFONTVERSION,     // GetFontVersion: 2 [file version]
	EW_GETFONTNAME,     // GetFontName: 2 [file fontname]

	EW_REGISTERDLL,       // Register DLL: 3,[DLL file name, string ptr of function to call, text to put in display (<0 if none/pass parms), 1 - no unload, 0 - unload]
	EW_CREATESHORTCUT,    // Make Shortcut: 5, [link file, target file, parameters, icon file, iconindex|show mode<<8|hotkey<<16]
	EW_COPYFILES,         // CopyFiles: 3 [source mask, destination location, flags]
	EW_REBOOT,            // Reboot: 0
	EW_WRITEINI,          // Write INI String: 4, [Section, Name, Value, INI File]
	EW_READINISTR,        // ReadINIStr: 4 [output, section, name, ini_file]
	EW_DELREG,            // DeleteRegValue/DeleteRegKey: 4, [root key(int), KeyName, ValueName, delkeyonlyifempty]. ValueName is -1 if delete key
	EW_WRITEREG,          // Write Registry value: 5, [RootKey(int),KeyName,ItemName,ItemData,typelen]
	//  typelen=1 for str, 2 for dword, 3 for binary, 0 for expanded str
	EW_READREGSTR,        // ReadRegStr: 5 [output, rootkey(int), keyname, itemname, ==1?int::str]
	EW_REGENUM,           // RegEnum: 5 [output, rootkey, keyname, index, ?key:value]
	EW_FCLOSE,            // FileClose: 1 [handle]
	EW_FOPEN,             // FileOpen: 4  [name, openmode, createmode, outputhandle]
	EW_FPUTS,             // FileWrite: 3 [handle, string, ?int:string]
	EW_FGETS,             // FileRead: 4  [handle, output, maxlen, ?getchar:gets]
	EW_FPUTWS,            // FileWriteUTF16LE: 3 [handle, string, ?int:string]
	EW_FGETWS,            // FileReadUTF16LE: 4 [handle, output, maxlen, ?getchar:gets]
	EW_FSEEK,             // FileSeek: 4  [handle, offset, mode, >=0?positionoutput]
	EW_FINDCLOSE,         // FindClose: 1 [handle]
	EW_FINDNEXT,          // FindNext: 2  [output, handle]
	EW_FINDFIRST,         // FindFirst: 2 [filespec, output, handleoutput]
	EW_WRITEUNINSTALLER,  // WriteUninstaller: 3 [name, offset, icon_size]
//	EW_LOG,               // LogText: 2 [0, text] / LogSet: [1, logstate]
	EW_SECTIONSET,        // SectionSetText:    3: [idx, 0, text]
	// SectionGetText:    3: [idx, 1, output]
	// SectionSetFlags:   3: [idx, 2, flags]
	// SectionGetFlags:   3: [idx, 3, output]
	// InstTypeGetFlags:  3: [idx, 1, output]

	// instructions not actually implemented in exehead, but used in compiler.
	EW_GETLABELADDR,      // both of these get converted to EW_ASSIGNVAR
	EW_GETFUNCTIONADDR,

	EW_LOCKWINDOW,
	EW_FINDPROC,    // FindProc: 1 [process_name]
};


// extra_parameters data structures containing other interesting stuff
// but the stack, variables and HWND passed on to plug-ins.
typedef struct
{
	int autoclose;
	int all_user_var;
	int exec_error;
	int abort;
	int exec_reboot; // NSIS_SUPPORT_REBOOT
	int reboot_called; // NSIS_SUPPORT_REBOOT
	int XXX_cur_insttype; // depreacted
	int plugin_api_version; // see NSISPIAPIVER_CURR
	// used to be XXX_insttype_changed
	int silent; // NSIS_CONFIG_SILENT_SUPPORT
	int instdir_error;
	int rtl;
	int errlvl;
	int alter_reg_view;
	int status_update;
} exec_flags_t;
