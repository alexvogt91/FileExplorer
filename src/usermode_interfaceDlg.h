
// usermode_interfaceDlg.h : header file
//

#pragma once

#include "resource.h"
#include "afxwin.h"

#define FAT_VOLUME_ALREADY_MOUNTED 1
#define FLAG_TRAVERSE_BACKWARDS 10
#define FLAG_TRAVERSE_FORWARD 20
#define FLAG_DISK_NOT_AVAILABLE 30
#define FLAG_APP_NOT_PE 40
#define ARGUMENT_PRESENT(x) ((x) != NULL)


#define RemoveTailList(ListHead) \
    (ListHead)->Blink;\
    {RemoveEntryList((ListHead)->Blink);}

typedef struct _VOLUMES_LIST
{
	LIST_ENTRY Entry;
	WCHAR VolumeName[MAX_PATH];
	WCHAR DeviceName[MAX_PATH];
	WCHAR RootPath[MAX_PATH];
}VOLUMES_LIST, *PVOLUMES_LIST;

extern LIST_ENTRY g_volumelist;

// CusermodeinterfaceDlg dialog
class CusermodeinterfaceDlg : public CDialogEx
{
// Construction
public:
	CusermodeinterfaceDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_USERMODE_INTERFACE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

// Implementation
protected:
	HICON m_hIcon;
	CImageList m_ImageList;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:

	CListCtrl m_list_main;



	afx_msg void OnNMRClickListMainWindow(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSecurevolmainmenuInstallfilesystem();
	afx_msg void OnSecurevolmainmenuMountvolume();
	afx_msg void OnSecurevolmainmenuFilesysteminformation();
	CEdit m_top_bar;
	afx_msg void OnNMDblclkListMainWindow(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnBegindragListMainWindow(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnHdnEnddragListMainWindow(NMHDR *pNMHDR, LRESULT *pResult);

	CusermodeinterfaceDlg(const CusermodeinterfaceDlg&) = default;
	CusermodeinterfaceDlg& operator = (const CusermodeinterfaceDlg&) = default;
	afx_msg void OnHdnBegindragListMainWindow(NMHDR *pNMHDR, LRESULT *pResult);
	CWinThread *Th1 = NULL;
	afx_msg void OnDropFiles(HDROP hDropInfo);
	CListBox m_log;
	//afx_msg void OnNMClickListMainWindow(NMHDR *pNMHDR, LRESULT *pResult);

	afx_msg void OnSecurevolmainmenuCreatedirectory();
	afx_msg void OnLvnBeginlabeleditListMainWindow(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnLvnEndlabeleditListMainWindow(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnFileoperationsDeletefile();
};

DWORD WINAPI OnUpdateMasterFile(LPVOID lParam);