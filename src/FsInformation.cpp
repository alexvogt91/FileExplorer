// FsInformation.cpp : implementation file
//

#include "pch.h"

#include "stdafx.h"
#include "usermode_interface.h"
#include "FsInformation.h"
#include "afxdialogex.h"
#include <Windows.h>
#include <winioctl.h>
#include "ntos.h"

#define PAGE_SIZE 0x1000
#define ROUND_TO_PAGES(Size)  (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

// FsInformation dialog

IMPLEMENT_DYNAMIC(FsInformation, CDialogEx)

FsInformation::FsInformation(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_FS_INFORMATION, pParent)
{

}

FsInformation::~FsInformation()
{
}

void FsInformation::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_edit_fs);
}


BEGIN_MESSAGE_MAP(FsInformation, CDialogEx)
END_MESSAGE_MAP()


// FsInformation message handlers


/*///////////////////////////////////////////////////////////////////////////////

	Gathers disk + fs information


*////////////////////////////////////////////////////////////////////////////////

BOOL FsInformation::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	HANDLE hDevice = 0;
	LONG Status;
	IO_STATUS_BLOCK Iosb = { 0 };
	DISK_GEOMETRY_EX disk;
	DISK_PERFORMANCE perf = { 0 };
	CString a, b, c, d, e, f, g, h, i, j, k;
	CString bytessec, diskbytes, diskmegs, diskgigs, str;
	TIME_FIELDS read, write, idle;
	BYTE BootSector[512] = { 0 };
	BIOS_PARAMETER_BLOCK *bpb = 0;
	DWORD bytes = 0;
	UNICODE_STRING Uni;
	OBJECT_ATTRIBUTES ObjectAttributes;
	PVOLUMES_LIST pvoldata = NULL;
	DWORD psize = 0;
	WCHAR bpbinfo[MAX_PATH*2] = { 0 };

	COMMON::SV_LoadConfigData(L"\\??\\C:\\Program Files (x86)\\SecureVol\\SecureVolConfigData",
		&pvoldata,
		&psize);
	if(pvoldata == NULL)
		return FALSE;

	RtlInitUnicodeString(&Uni,pvoldata->DeviceName);
	InitializeObjectAttributes(&ObjectAttributes, &Uni, OBJ_CASE_INSENSITIVE, 0, 0);

	Status = ZwCreateFile(&hDevice, FILE_GENERIC_READ, &ObjectAttributes, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE |
		FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(Status)) {
		
		WCHAR err[10];
		wsprintf(err, L"0x%X", Status);
		OutputDebugString(err);

		return FALSE;
	}

	Status = ZwReadFile(hDevice, NULL, 0, 0, &Iosb, BootSector, 512, 0, 0);
	if (!NT_SUCCESS(Status))
		return FALSE;

	bpb = (BIOS_PARAMETER_BLOCK*)BootSector;
	if (bpb == NULL)
		return FALSE;
	
	m_edit_fs.Clear();

	wsprintf(bpbinfo, L"\r\n[*] Dumping FS Data...\r\n\r\n[+] Signature: %u\r\n[+] Boot Code: 0x%X\r\n[+] Jump Code: 0x%X\r\n[+] Max Root Entry: %u\r\n[+] Number of Sectors: %lu\r\n[+] Sectors per fat: %u\r\n[+] Sectors per Track: %lu\r\n[+] Sector per Cluster: %u\r\n[+] Size Sector Reserved: %u\r\n[+] Serial Number: %lu\r\n[+] Number of Sectors before Partition: %lu",bpb->signature, bpb->boot_Code,
		bpb->jumpCode,
		bpb->Max_Root_Entry,
		bpb->no_Sector_FS32,
		bpb->sectors_per_fat,
		bpb->sectors_per_track,
		bpb->sec_Cluster,
		bpb->size_Sector_Reserved,
		bpb->vol_Serial_Number,
		bpb->no_Sectors_Before_Part);

	m_edit_fs.SetWindowTextW(bpbinfo);

	Status = ZwDeviceIoControlFile(hDevice,
		NULL,
		NULL,
		NULL,
		&Iosb,
		IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
		NULL,
		0,
		&disk,
		sizeof(DISK_GEOMETRY_EX));
	if (!NT_SUCCESS(Status))
		return FALSE;

	Status = ZwDeviceIoControlFile(hDevice,
		NULL, NULL, NULL, &Iosb,
		IOCTL_DISK_UPDATE_PROPERTIES,
		NULL, 0,
		NULL, 0);
	if (!NT_SUCCESS(Status))
		return FALSE;

	Status = ZwDeviceIoControlFile(hDevice,
		NULL,
		NULL,
		NULL, &Iosb, IOCTL_DISK_PERFORMANCE,
		NULL,
		0,
		&perf,
		sizeof(DISK_PERFORMANCE));
	if (NT_SUCCESS(Status))
	{

		RtlTimeToTimeFields(&perf.ReadTime, &read);
		RtlTimeToTimeFields(&perf.WriteTime, &write);

		ZwQuerySystemTime(&perf.IdleTime);
		RtlTimeToTimeFields(&perf.IdleTime, &idle);

		a.Format(L"%.2f", (float)perf.BytesRead.LowPart / (1024 * 1024));
		b.Format(L"%.2f", (float)perf.BytesWritten.LowPart / (1024 * 1024));
		c.Format(L"%02u:%03u",read.Second,read.Milliseconds);
		d.Format(L"%02u:%03u",write.Second,write.Milliseconds);
		e.Format(L"%02u:%02u:%02u:%03u",idle.Hour + 2,idle.Minute,idle.Second,idle.Milliseconds);
		f.Format(L"%lu", perf.QueueDepth);
		g.Format(L"%lu", perf.ReadCount);
		h.Format(L"%lu", perf.WriteCount);
		i.Format(L"%ws",perf.StorageManagerName);
		j.Format(L"%lu", perf.SplitCount);
		k.Format(L"%lu", perf.StorageDeviceNumber);
		bytessec.Format(L"%lu", disk.Geometry.BytesPerSector);
		diskbytes.Format(L"%lu", disk.DiskSize.LowPart);
		diskmegs.Format(L"%.2f", (float)disk.DiskSize.LowPart / (1024 * 1024));
		diskgigs.Format(L"%.2f", (float)disk.DiskSize.LowPart / (1024 * 1024 * 1024));
		
		SetDlgItemText(IDC_STATIC_14, a);
		SetDlgItemText(IDC_STATIC_15, b);
		SetDlgItemText(IDC_STATIC_16, c);
		SetDlgItemText(IDC_STATIC_17, d);
		SetDlgItemText(IDC_STATIC_18, e);
		SetDlgItemText(IDC_STATIC_19, f);
		SetDlgItemText(IDC_STATIC_20, g);
		SetDlgItemText(IDC_STATIC_21, h);
		SetDlgItemText(IDC_STATIC_22, i);
		SetDlgItemText(IDC_STATIC_23, j);
		SetDlgItemText(IDC_STATIC_24, k);
		SetDlgItemText(IDC_STATIC_25, bytessec);
		SetDlgItemText(IDC_STATIC_26, diskbytes);
		SetDlgItemText(IDC_STATIC_27, diskmegs);
		SetDlgItemText(IDC_STATIC_28, diskgigs);

	}

	ZwClose(hDevice);

	return TRUE;
}