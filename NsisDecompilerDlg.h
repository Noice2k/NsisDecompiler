
// NsisDecompilerDlg.h : header file
//

#pragma once
#include "afxcmn.h"
#include "NsisCore.h"
#include "NSISDebuggerCore.h"
#include "PEFile.h"
#include "afxwin.h"

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
	
	
	
	//	nsis core 
	CNsisCore	_nsis_core;
	//	nsis debug engine
	CNSISDebuggerCore _nsis_debugger;
	//	pe file
	CPEFile		_pe_file;

	
	void LoadSourceCode();

	


	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	CListCtrl m_SourceCode;
	CListCtrl m_Stack;
	CListCtrl m_Variables;
	CListCtrl m_CallSteck;
	CImageList m_ImageList;
	CEdit m_EditFileName;

	void	ShowVariables();
	void	ShowStack();
	void	ShowCallStack();

	virtual LRESULT DefWindowProc(UINT message, WPARAM wParam, LPARAM lParam);
	int m_lastitem;
	
	afx_msg void OnBnClickedLoadFile();
	afx_msg void OnBnClickedStep();
	afx_msg void OnBnClickedStepOut();
	afx_msg void OnBnClickedSelectFile();
	CEdit m_EditGotoLine;
	afx_msg void OnBnClickedGoto();
	afx_msg void OnBnClickedStepIn();
};
