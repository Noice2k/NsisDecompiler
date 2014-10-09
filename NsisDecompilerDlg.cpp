
// NsisDecompilerDlg.cpp : implementation file
//

#include "stdafx.h"
#include "NsisDecompiler.h"
#include "NsisDecompilerDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CNsisDecompilerDlg dialog



CNsisDecompilerDlg::CNsisDecompilerDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CNsisDecompilerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CNsisDecompilerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST2, m_SourceCode);
	DDX_Control(pDX, IDC_LIST3, m_Stack);
	DDX_Control(pDX, IDC_LIST4, m_Variables);
	DDX_Control(pDX, IDC_LIST5, m_CallSteck);
	DDX_Control(pDX, IDC_EDIT1, m_EditFileName);
	DDX_Control(pDX, IDC_EDIT2, m_EditGotoLine);
}

BEGIN_MESSAGE_MAP(CNsisDecompilerDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CNsisDecompilerDlg::OnBnClickedLoadFile)
	ON_BN_CLICKED(IDOK, &CNsisDecompilerDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CNsisDecompilerDlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_BUTTON2, &CNsisDecompilerDlg::OnBnClickedStep)
	ON_BN_CLICKED(IDC_BUTTON3, &CNsisDecompilerDlg::OnBnClickedStepOut)
	ON_BN_CLICKED(IDC_BUTTON4, &CNsisDecompilerDlg::OnBnClickedSelectFile)
	ON_BN_CLICKED(IDC_BUTTON5, &CNsisDecompilerDlg::OnBnClickedGoto)
	ON_BN_CLICKED(IDC_BUTTON6, &CNsisDecompilerDlg::OnBnClickedStepIn)
END_MESSAGE_MAP()


// CNsisDecompilerDlg message handlers

BOOL CNsisDecompilerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	HICON h1 = LoadIcon(AfxGetInstanceHandle(),MAKEINTRESOURCE(IDI_ICON1));
	HICON h2 = LoadIcon(AfxGetInstanceHandle(),MAKEINTRESOURCE(IDI_ICON2));
	m_ImageList.Create(16,16,ILC_COLOR24,0,0);
	m_ImageList.Add(h1);
	m_ImageList.Add(h2);

	m_lastitem = -1;

//	m_SourceCode.SetImageList(&m_ImageList,LVSIL_STATE);
	m_SourceCode.SetImageList(&m_ImageList,LVSIL_SMALL);
	//m_SourceCode.SetImageList(&m_ImageList,LVSIL_NORMAL);
	
	// TODO: Add extra initialization here
	m_SourceCode.SetExtendedStyle(m_SourceCode.GetExtendedStyle() |LVS_EX_FULLROWSELECT|LVS_EX_SIMPLESELECT);

	//	
	m_SourceCode.InsertColumn(0,"line",LVCFMT_LEFT,60);
	m_SourceCode.InsertColumn(1,"code",LVCFMT_LEFT,480);
	//
	m_Variables.InsertColumn(0,"name",LVCFMT_LEFT,70);
	m_Variables.InsertColumn(1,"value",LVCFMT_LEFT,700);
	//
	m_Stack.InsertColumn(0,"id",LVCFMT_LEFT,70);
	m_Stack.InsertColumn(1,"value",LVCFMT_LEFT,700);
	
	//	load last used file name
	m_EditFileName.SetWindowText(theApp.GetProfileString("main","last_used_file",""));

	

	return TRUE;  // return TRUE  unless you set the focus to a control
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNsisDecompilerDlg::LoadSourceCode()
{
	CString num;
	for (unsigned i = 0x00;i< _nsis_core._nsis_script_code.size();i++)
	{
		num.Format("%4.4i",i);
		m_SourceCode.InsertItem(i,num,0);
		m_SourceCode.SetItemText(i,1,_nsis_core._nsis_script_code[i].c_str());
	}

	for (int i = 0;i < _nsis_core._global_vars._max_var_count;i++)
	{
		m_Variables.InsertItem(i,_nsis_core._global_vars.GetVarName(i).c_str(),0);

	}

}

/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNsisDecompilerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CNsisDecompilerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


/************************************************************************/
//	start decompile file
/************************************************************************/
void CNsisDecompilerDlg::OnBnClickedLoadFile()
{

	CString filename;
	m_EditFileName.GetWindowText(filename);
	theApp.WriteProfileString("main","last_used_file",filename);

	if (true == filename.IsEmpty())
	{
		return;
	}

	_nsis_debugger._nsis_core = &_nsis_core;
	_nsis_debugger.filename =  filename;
	_nsis_debugger.CloseProcess();

	CPEFile source_pe;
	CPEFile dest_pe;

	// load the test file
	if (source_pe.LoadAndParseFile(filename.GetBuffer()))
	{

		std::string str2 = source_pe.GetDumpHash();

		//	this is nsis "Nullsoft Install System v2.46.1-Unicode lzma_solid stub"  ?
		std::string str = source_pe.GetCodeSegmentHash();
		_nsis_core.SetCompressionMethod(str);
		
		//if (str == "3291075913c14a1799655a261fb21cca")
		{
			//	load the "Nullsoft Install System v2.46.1-Unicode lzma_solid stub with debug code"
			if (dest_pe.LoadAndParseFile("D:\\Nsis_debug\\stubs\\2.46.1_unicode_debug\\zlib_solid"))
			{
				dest_pe.ReplaceTextSegment(&source_pe);
				//source_pe.ReplaceTextSegment(&dest_pe);
				filename+="_dbg.exe";

				_nsis_debugger.filename =  filename;
				_nsis_debugger.CloseProcess();
				//source_pe.SaveExeDump(filename.GetBuffer());
				//dest_pe.SaveExeDump(filename.GetBuffer());
				
                dest_pe.SaveExeDump_v2(filename.GetBuffer());
				str2 = dest_pe.GetDumpHash();
			} 
		}
	}
	
	
	if (true == _pe_file.LoadAndParseFile(filename.GetBuffer()))
	{

		_pe_file.GetCodeSegmentHash();
		_nsis_core.SetNsisDump(_pe_file.GetEOFSegnemt());
		_nsis_core._global_vars.SetVarCount(_pe_file.GetNsisVarCount());
		_nsis_core.ProcessingHeader();
		_nsis_core.DumpFiles("d:\\1234");
		LoadSourceCode();
		_nsis_debugger.Execute();
	}
}


/************************************************************************/
//
/************************************************************************/
void CNsisDecompilerDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	CDialogEx::OnOK();
}


void CNsisDecompilerDlg::OnBnClickedCancel()
{
	// TODO: Add your control notification handler code here
	CDialogEx::OnCancel();
}

void	CNsisDecompilerDlg::ShowVariables()
{
	for (int i = 0;i < _nsis_core._global_vars._max_var_count;i++)
	{
		m_Variables.SetItemText(i,1,_nsis_core._global_vars.GetVarValue(i).c_str());
	}

}

void	CNsisDecompilerDlg::ShowStack()
{
	m_Stack.DeleteAllItems();
	CString num;
	for (unsigned i = 0x00;i< _nsis_debugger._stack.size();i++)
	{
		num.Format("%4.4i",i);
		m_Stack.InsertItem(i,num,0);
		m_Stack.SetItemText(i,1,_nsis_debugger._stack[i].c_str());
	}
}

void	CNsisDecompilerDlg::ShowCallStack()
{
	m_CallSteck.DeleteAllItems();
	m_CallSteck.InsertColumn(0,"id",LVCFMT_LEFT,50);
	m_CallSteck.InsertColumn(1,"value",LVCFMT_LEFT,450);

	CString num;
	for (unsigned i = 0x00;i< _nsis_debugger._function_call_stack.size();i++)
	{
		num.Format("%4.4i",i);
		m_CallSteck.InsertItem(i,num,0);
		m_CallSteck.SetItemText(i,1,_nsis_debugger._function_call_stack[i].c_str());
	}
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
LRESULT CNsisDecompilerDlg::DefWindowProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	if (message == WM_USER+100)
	{
		if ((-1 != m_lastitem) && (m_lastitem != wParam))
		{
			m_SourceCode.SetItem(m_lastitem,0,LVIF_IMAGE,NULL,0,0,0,NULL,0);
		}
		m_lastitem = wParam;

		m_SourceCode.SetItem(m_lastitem,0,LVIF_IMAGE,NULL,1,0,0,NULL,0);

		

		int top = m_SourceCode.GetTopIndex();
		int bottom = top + m_SourceCode.GetCountPerPage();
		CRect rt;
		m_SourceCode.GetItemRect(0,&rt,LVIR_BOUNDS);
		CSize size;


		if (m_lastitem < top)
		{
			size.cy = rt.Height()*(m_lastitem - top);
			m_SourceCode.Scroll(size);
		}
		
		if (m_lastitem > bottom)
		{
			size.cy = rt.Height()*(m_lastitem - top);
			m_SourceCode.Scroll(size/*(m_lastitem - top)*0x10000*/);
		}
		
		ShowVariables();
		ShowStack();
		//ShowCallStack();
		return true;
	}

	return CDialogEx::DefWindowProc(message, wParam, lParam);
}


/************************************************************************/
//
/************************************************************************/
static int CALLBACK BrowseCallbackProc(HWND hwnd,UINT uMsg, LPARAM lParam, LPARAM lpData)
{

	if(uMsg == BFFM_INITIALIZED)
	{
		std::string tmp = (const char *) lpData;
		//std::cout << "path: " << tmp << std::endl;
		SendMessage(hwnd, BFFM_SETSELECTION, TRUE, lpData);
	}

	return 0;
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
std::string BrowseFolder(std::string saved_path)
{
	TCHAR path[MAX_PATH];

	const char * path_param = saved_path.c_str();

	BROWSEINFO bi = { 0 };
	bi.lpszTitle  = ("Browse for folder...");
	bi.ulFlags    = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
	bi.lpfn       = BrowseCallbackProc;
	bi.lParam     = (LPARAM) path_param;

	LPITEMIDLIST pidl = SHBrowseForFolder ( &bi );

	if ( pidl != 0 )
	{
		//get the name of the folder and put it in path
		SHGetPathFromIDList ( pidl, path );

		//free memory used
		IMalloc * imalloc = 0;
		if ( SUCCEEDED( SHGetMalloc ( &imalloc )) )
		{
			imalloc->Free ( pidl );
			imalloc->Release ( );
		}

		return path;
	}

	return "";
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNsisDecompilerDlg::OnBnClickedSelectFile()
{
	CFileDialog dlg(true,"All Files(*.*)|*.*||","*.*",OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR, "*.*");
	auto result = dlg.DoModal();
	if(result != IDOK) return ; // failed
	m_EditFileName.SetWindowText(dlg.GetPathName());
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNsisDecompilerDlg::OnBnClickedGoto()
{
	CString str;
	m_EditGotoLine.GetWindowText(str);
	DWORD pos = (DWORD)atoi(str);

	if (pos > _nsis_core._nsis_script_code.size())
	{
		return;
	}

	_nsis_debugger._need_run_to_point = true;
	_nsis_debugger._run_to_point = pos;
	
}

/************************************************************************/
// just go to the next instuction
/************************************************************************/
void CNsisDecompilerDlg::OnBnClickedStepIn()
{
	_nsis_debugger._need_do_step = true;

}

/************************************************************************/
//	find the pos with "return" and go to it
/************************************************************************/
void CNsisDecompilerDlg::OnBnClickedStepOut()
{
	DWORD pos =  _nsis_debugger.FindReturnPoint();
	if (pos != 0xFFFFFFFF)
	{
		_nsis_debugger._run_to_point =pos;
		_nsis_debugger._need_run_to_point = true;
	}
	else
	{
		_nsis_debugger._need_do_step = true;
	}
}

/************************************************************************/
/*                                                                      */
/************************************************************************/
void CNsisDecompilerDlg::OnBnClickedStep()
{

	DWORD pos = _nsis_debugger.ReadReg("pos");
	std::string str = _nsis_core._nsis_script_code[pos];
	if (str.find("Call") == 0x00)
	{
		_nsis_debugger._run_to_point =pos+1;
		_nsis_debugger._need_run_to_point = true;
		_nsis_debugger._need_do_step = false;
	}
	else
	{
		_nsis_debugger._need_do_step = true;
	}
}