#pragma once

#include "resource.h"
#include <winioctl.h>

// DisksWindowPopUp dialog

class DisksWindowPopUp : public CDialogEx
{
	DECLARE_DYNAMIC(DisksWindowPopUp)

public:
	DisksWindowPopUp(CWnd* pParent = nullptr);   // standard constructor
	virtual ~DisksWindowPopUp();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DISKS_WINDOW };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_list_disks;
	void GetDisksData(PWCHAR RegistryPath);
	afx_msg void OnNMRClickListDisksInformation(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnFormatdiskFormatdisk();
};


typedef struct _FAT32_BOOT_SECTOR
{
	unsigned char 	Jump[3];
	unsigned char 	OEMName[8];
	unsigned short 	BytesPerSector;
	unsigned char 	SectorsPerCluster;
	unsigned short 	ReservedSectors;
	unsigned char 	FATCount;
	unsigned short 	RootEntries;
	unsigned short 	Sectors;
	unsigned char 	Media;
	unsigned short 	FATSectors;
	unsigned short 	SectorsPerTrack;
	unsigned short 	Heads;
	unsigned long 	HiddenSectors;
	unsigned long 	SectorsHuge;
	unsigned long 	FATSectors32;
	unsigned short 	ExtFlag;
	unsigned short 	FSVersion;
	unsigned long 	RootCluster;
	unsigned short 	FSInfoSector;
	unsigned short 	BootBackup;
	unsigned char 	Res3[12];
	unsigned char 	Drive;
	unsigned char 	Res4;
	unsigned char 	ExtBootSignature;
	unsigned long 	VolumeID;
	unsigned char 	VolumeLabel[11];
	unsigned char 	SysType[8];
	unsigned char 	Res2[418];
	unsigned long 	Signature1;

}FAT32_BOOT_SECTOR, * PFAT32_BOOT_SECTOR;

typedef struct _FAT32_FSINFO
{
	unsigned long 	LeadSig;
	unsigned char 	Res1[480];
	unsigned long 	StrucSig;
	unsigned long 	FreeCount;
	unsigned long 	NextFree;
	unsigned long 	Res2[3];
	unsigned long 	TrailSig;

}FAT32_FSINFO, * PFAT32_FSINFO;

ULONG SHIFT(ULONG Value);
LONG Fat32WriteFsInfo(HANDLE FileHandle, PFAT32_BOOT_SECTOR BootSector);
LONG Fat32WriteBootSector(HANDLE FileHandle, PFAT32_BOOT_SECTOR BootSector);
LONG Fat32WriteFAT(HANDLE FileHandle,
	ULONG SectorOffset,
	PFAT32_BOOT_SECTOR BootSector);
LONG Fat32WriteRootDirectory(HANDLE FileHandle, PFAT32_BOOT_SECTOR BootSector);

extern DWORD diskid;