
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
}

BEGIN_MESSAGE_MAP(CNsisDecompilerDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CNsisDecompilerDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDOK, &CNsisDecompilerDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CNsisDecompilerDlg::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_BUTTON2, &CNsisDecompilerDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CNsisDecompilerDlg message handlers

BOOL CNsisDecompilerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	m_SourceCode.SetExtendedStyle(m_SourceCode.GetExtendedStyle() |LVS_EX_FULLROWSELECT);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

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
void CNsisDecompilerDlg::OnBnClickedButton1()
{
	//_nsisFile.LoadDump("D:\\ConduitInstaller\\spinstaller_s_exe\\spinstaller_s.EOF");
	//_nsisFile.LoadDump("D:\\ConduitInstaller\\spinstaller_s_exe\\1.zip");
	//_nsisFile.LoadExeDump("D:\\ConduitInstaller\\spinstaller_s_exe\\spinstaller.exe");
	_nsisFile.LoadExeDump("D:\\ConduitInstaller\\spinstaller_s_exe\\spnocrc.exe");
	//_nsisFile.LoadExeDump("D:\\ConduitInstaller\\spinstaller_s_exe\\FPSetup.exe");
    //_nsisFile.LoadExeDump("D:\\NSIS_uni\\test.exe");
	
	_nsisFile.ProcessingHeader();
	//_nsisFile.DumpFiles("d:\\ConduitInstaller\\_dump");
//	_nsisFile.SaveExeDump("D:\\ConduitInstaller\\spinstaller_s_exe\\spnocrc_t.exe");
	

	//_nsisFile.LoadExeDump("D:\\ConduitInstaller\\_dump\\0002.dll");
	//_nsisFile.SaveExeDump("D:\\ConduitInstaller\\_dump\\0002t.dll");

	_nsisEmulator.file = &_nsisFile;
	_nsisEmulator._source_code_view = &m_SourceCode;
	_nsisEmulator.Init();
	
	_nsisEmulator.Execute();
}



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


void CNsisDecompilerDlg::OnBnClickedButton2()
{
	_nsisEmulator._breakByStep = true;
}


LRESULT CNsisDecompilerDlg::DefWindowProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	if (message == WM_USER+100)
	{
		POSITION pos = m_SourceCode.GetFirstSelectedItemPosition();
		while( pos >0) 
		{
			int  index = m_SourceCode.GetNextSelectedItem( pos );
			m_SourceCode.SetItemState(index, 0, LVS_SHOWSELALWAYS|LVS_SINGLESEL);
		}
		int id = wParam;
		//m_SourceCode.SetSelectionMark(pos);
		m_SourceCode.SetItemState(id,LVS_SINGLESEL, LVS_SINGLESEL);
		m_SourceCode.Invalidate();
	}

	return CDialogEx::DefWindowProc(message, wParam, lParam);
}
