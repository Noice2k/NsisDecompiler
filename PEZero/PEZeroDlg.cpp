
// PEZeroDlg.cpp : implementation file
//

#include "stdafx.h"
#include "PEZero.h"
#include "PEZeroDlg.h"
#include "afxdialogex.h"
#include "PEFile.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CPEZeroDlg dialog



CPEZeroDlg::CPEZeroDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CPEZeroDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPEZeroDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CPEZeroDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CPEZeroDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CPEZeroDlg message handlers

BOOL CPEZeroDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CPEZeroDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CPEZeroDlg::OnPaint()
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
HCURSOR CPEZeroDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


/************************************************************************/
/*                                                                      */
/************************************************************************/
void CPEZeroDlg::OnBnClickedButton1()
{
	CPEFile file;
	file.LoadAndParseFile("D:\\1234\\SPTool.dll");

	int offset;
	int size ;

	CFile f;
	f.Open("D:\\1234\\SPTool_.dll",CFile::modeWrite|CFile::modeRead|CFile::modeCreate,NULL,NULL);
	
/*	int offset = file._rsrc_header->PointerToRawData;
	int size =file._rsrc_header->SizeOfRawData;
	for (int i =0;i < size;i++ )
	{
		file._pe_full_dump[offset+i] = 0;
	}
	*/
	offset = file._text_header->PointerToRawData;
	size =file._text_header->SizeOfRawData;
	for (int i =0;i < size;i++ )
	{
		file._pe_full_dump[offset+i] = 0;
	}
	

	offset = file._rdata_header->PointerToRawData;
	size =file._rdata_header->SizeOfRawData;
	for (int i =0;i < size;i++ )
	{
		file._pe_full_dump[offset+i] = 0;
	}
	/*

	offset = file._data_header->PointerToRawData;
	size =file._data_header->SizeOfRawData;
	for (int i =0;i < size;i++ )
	{
		file._pe_full_dump[offset+i] = 0;
	}
 
	offset = 0x290600;
	size   = 0x17d0;

	for (int i =0;i < size;i++ )
	{
		file._pe_full_dump[offset+i] = 0;
	}

	*/
	f.Write(&file._pe_full_dump[0],file._pe_full_dump.size());
	f.Close();
	
}
