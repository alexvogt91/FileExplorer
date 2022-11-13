#pragma once

#include "resource.h"
#include "usermode_interfaceDlg.h"
#include "Common.h"
#include "afxwin.h"

// FsInformation dialog

class FsInformation : public CDialogEx
{
	DECLARE_DYNAMIC(FsInformation)

public:
	FsInformation(CWnd* pParent = NULL);   // standard constructor
	virtual ~FsInformation();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_FS_INFORMATION };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
public:
	CEdit m_edit_fs;
};

typedef struct _BIOS_PARAMETER_BLOCK
{
	BYTE jumpCode[3];
	BYTE oemName[8];
	WORD bytes_Sector;
	BYTE sec_Cluster;
	WORD size_Sector_Reserved;
	BYTE fatCount;
	WORD Max_Root_Entry;
	WORD Total_Sector_FS;
	BYTE Media_Type;
	WORD sectors_per_fat;
	WORD sectors_per_track;
	WORD total_Head_Count;
	DWORD no_Sectors_Before_Part;
	DWORD no_Sector_FS32;
	BYTE BIOS_13h_Drive_No;
	BYTE reserved;
	BYTE ext_Boot_Part_Signature;
	DWORD vol_Serial_Number;
	BYTE vol_Lebel_Name[11];
	BYTE FS_Type[8];
	BYTE boot_Code[448];
	WORD signature;
} BIOS_PARAMETER_BLOCK, *PBIOS_PARAMETER_BLOCK;


extern WCHAR DevicePath[MAX_PATH];

#define BYTES_PER_KB                    1024LL
#define BYTES_PER_MB                    1048576LL
#define BYTES_PER_GB                    1073741824LL
#define BYTES_PER_TB                    1099511627776LL