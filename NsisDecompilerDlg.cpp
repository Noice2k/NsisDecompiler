
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
}

BEGIN_MESSAGE_MAP(CNsisDecompilerDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CNsisDecompilerDlg::OnBnClickedButton1)
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
	//_nsisFile.LoadExeDump("D:\\ConduitInstaller\\spinstaller_s_exe\\spnocrc.exe");
	//_nsisFile.LoadExeDump("D:\\ConduitInstaller\\spinstaller_s_exe\\FPSetup.exe");
    _nsisFile.LoadExeDump("D:\\NSIS_uni\\test.exe");
	
	_nsisFile.ProcessingHeader();
	_nsisFile.DumpFiles("d:\\ConduitInstaller\\_dump");
//	_nsisFile.SaveExeDump("D:\\ConduitInstaller\\spinstaller_s_exe\\spnocrc_t.exe");
	

	//_nsisFile.LoadExeDump("D:\\ConduitInstaller\\_dump\\0002.dll");
	//_nsisFile.SaveExeDump("D:\\ConduitInstaller\\_dump\\0002t.dll");


	
}
