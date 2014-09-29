
// NsisDecompilerDlg.h : header file
//

#pragma once
#include "NsisFile.h"
#include "afxcmn.h"
#include "NSISEmulator.h"

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
	CNSISEmulator _nsisEmulator;
	
	void LoadSourceCode();


	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	CListCtrl m_SourceCode;
	CListCtrl m_Stack;
	CListCtrl m_Variables;
	CListCtrl m_CallSteck;
	CImageList m_ImageList;

	void	ShowVariables();
	void	ShowStack();
	void	ShowCallStack();

	int m_lastitem;
	afx_msg void OnBnClickedButton2();
	virtual LRESULT DefWindowProc(UINT message, WPARAM wParam, LPARAM lParam);
};
