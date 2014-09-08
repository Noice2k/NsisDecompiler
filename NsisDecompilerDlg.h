
// NsisDecompilerDlg.h : header file
//

#pragma once
#include "NsisFile.h"

// CNsisDecompilerDlg dialog
class CNsisDecompilerDlg : public CDialogEx
{
// Construction
public:
	CNsisDecompilerDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_NSISDECOMPILER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	//	 file processor
	CNsisFile	_nsisFile;

	
};
