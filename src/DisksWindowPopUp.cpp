// DisksWindowPopUp.cpp : implementation file
//

#include "pch.h"
#include "usermode_interface.h"
#include "DisksWindowPopUp.h"
#include "afxdialogex.h"

#include "ntos.h"


// DisksWindowPopUp dialog

typedef struct _SECUREVOL_DISK_INFORMATION
{
	DWORD disk_id;

}SECUREVOL_DISK_INFORMATION, *PSECUREVOL_DISK_INFORMATION;

IMPLEMENT_DYNAMIC(DisksWindowPopUp, CDialogEx)

DisksWindowPopUp::DisksWindowPopUp(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DISKS_WINDOW, pParent)
{

}

DisksWindowPopUp::~DisksWindowPopUp()
{
}

void DisksWindowPopUp::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_DISKS_INFORMATION, m_list_disks);
}


BEGIN_MESSAGE_MAP(DisksWindowPopUp, CDialogEx)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_DISKS_INFORMATION, &DisksWindowPopUp::OnNMRClickListDisksInformation)
	ON_COMMAND(ID_FORMATDISK_FORMATDISK, &DisksWindowPopUp::OnFormatdiskFormatdisk)
END_MESSAGE_MAP()


// DisksWindowPopUp message handlers

BOOL DisksWindowPopUp::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	m_list_disks.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
	m_list_disks.InsertColumn(0, _T("Disk Number"), LVCFMT_CENTER, 120);
	m_list_disks.InsertColumn(1, _T("Disk Data"), LVCFMT_CENTER, 400);

	GetDisksData(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\disk\\Enum");
	
	return TRUE;
}

VOID DisksWindowPopUp::GetDisksData(PWCHAR RegistryPath)
{
	HANDLE hKey = 0;
	PKEY_VALUE_FULL_INFORMATION pkeyinfo = NULL;
	PKEY_VALUE_PARTIAL_INFORMATION ppartial = NULL;
	ULONG NeededBytes = 0;
	PVOID Alloc = 0;
	UNICODE_STRING UnicodeString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	LONG Status;
	CString name, data;
	UINT item = 0;

	RtlInitUnicodeString(&UnicodeString,RegistryPath);
	InitializeObjectAttributes(&ObjectAttributes,
		&UnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	Status = ZwOpenKey(&hKey,
		KEY_ALL_ACCESS,
		&ObjectAttributes);
	if (!NT_SUCCESS(Status))
		return;

	ULONG i = 0;

	while (Status != STATUS_NO_MORE_ENTRIES)
	{
		Status = ZwEnumerateValueKey(hKey, i, KeyValueFullInformation, NULL, 0, &NeededBytes);
		if (Status == STATUS_BUFFER_TOO_SMALL)
		{
			pkeyinfo = (PKEY_VALUE_FULL_INFORMATION)malloc(NeededBytes);
			if (pkeyinfo != NULL)
			{
				RtlSecureZeroMemory(pkeyinfo, NeededBytes);
				Status = ZwEnumerateValueKey(hKey, i, KeyValueFullInformation, pkeyinfo, NeededBytes, &NeededBytes);
				if (NT_SUCCESS(Status))
				{
					PWCHAR pname = (PWCHAR)malloc(pkeyinfo->NameLength + sizeof(WCHAR));
					memset(pname, 0, pkeyinfo->NameLength + sizeof(WCHAR));
					memcpy(pname, pkeyinfo->Name, pkeyinfo->NameLength);
					UNICODE_STRING uni;
					ULONG bb = 0;

					RtlInitUnicodeString(&uni, pname);
					Status = ZwQueryValueKey(hKey, &uni, KeyValuePartialInformation, NULL, 0, &bb);
					if (Status == STATUS_BUFFER_TOO_SMALL)
					{
						ppartial = (PKEY_VALUE_PARTIAL_INFORMATION)malloc(bb);
						Status = ZwQueryValueKey(hKey, &uni, KeyValuePartialInformation, ppartial, bb, &bb);
						if (NT_SUCCESS(Status))
						{

							if (ppartial->Type == REG_SZ ||
								ppartial->Type == REG_MULTI_SZ ||
								ppartial->Type == REG_EXPAND_SZ)
							{
								PWCHAR mem = (PWCHAR)malloc(bb);
								memset(mem, 0, ppartial->DataLength + sizeof(WCHAR));
								memcpy(mem, ppartial->Data, ppartial->DataLength);
								
								name.Format(L"%ws", pname);
								data.Format(L"%ws", mem);

								m_list_disks.InsertItem(0, name);
								m_list_disks.SetItemText(item, 1, data);

								free(mem);
							}
						}
					}
					free(pname);
				}

				free(pkeyinfo);
			}
		}

		i += 1;
	}

	if (hKey)
		ZwClose(hKey);
}

void DisksWindowPopUp::OnNMRClickListDisksInformation(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	
	CMenu menu;
	CMenu topmenu;
	RECT rect;
	CPoint point;

	VERIFY(menu.LoadMenuW(IDR_MENU2));
	CMenu* pop = menu.GetSubMenu(0);

	GetWindowRect(&rect);
	GetCursorPos(&point);
	pop->TrackPopupMenu(NULL, point.x, point.y, this);

	*pResult = 0;
}


ULONG SHIFT(ULONG Value)
{
	ULONG i = 1;

	while (Value > 0)
	{
		i++;
		Value /= 2;
	}

	return i - 2;
}

LONG Fat32WriteFsInfo(HANDLE FileHandle, PFAT32_BOOT_SECTOR BootSector)

{
	IO_STATUS_BLOCK IoStatusBlock;
	LONG Status;
	PFAT32_FSINFO FsInfo;
	LARGE_INTEGER FileOffset;
	ULONGLONG FirstDataSector;

	/* Allocate buffer for new sector */

	FsInfo = (PFAT32_FSINFO)RtlAllocateHeap(GetProcessHeap(),
		0,
		BootSector->BytesPerSector);
	if (FsInfo == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	/* Zero the first FsInfo sector */

	RtlZeroMemory(FsInfo, BootSector->BytesPerSector);

	FirstDataSector = BootSector->ReservedSectors + (BootSector->FATCount * BootSector->FATSectors32) + 0;

	FsInfo->LeadSig = 0x41615252;
	FsInfo->StrucSig = 0x61417272;
	FsInfo->FreeCount = (BootSector->SectorsHuge - FirstDataSector) / BootSector->SectorsPerCluster - 1;
	FsInfo->NextFree = 0xffffffff;
	FsInfo->TrailSig = 0xAA550000;

	/* Write the first FsInfo sector */

	FileOffset.QuadPart = BootSector->FSInfoSector * BootSector->BytesPerSector;
	Status = ZwWriteFile(FileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		FsInfo,
		BootSector->BytesPerSector,
		&FileOffset,
		NULL);
	if (!NT_SUCCESS(Status))
	{

		goto done;
	}

	/* Write backup of the first FsInfo sector */

	if (BootSector->BootBackup != 0x0000)
	{
		/* Reset the free cluster count for the backup */

		FsInfo->FreeCount = 0xffffffff;

		FileOffset.QuadPart = (ULONGLONG)(((ULONG)BootSector->BootBackup + (ULONG)BootSector->FSInfoSector) * BootSector->BytesPerSector);
		Status = ZwWriteFile(FileHandle,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			FsInfo,
			BootSector->BytesPerSector,
			&FileOffset,
			NULL);
		if (!NT_SUCCESS(Status))
		{
			goto done;
		}
	}

	/* Zero the second FsInfo sector */

	RtlZeroMemory(FsInfo, BootSector->BytesPerSector);
	FsInfo->TrailSig = 0xAA550000;

	/* Write the second FsInfo sector */

	FileOffset.QuadPart = (BootSector->FSInfoSector + 1) * BootSector->BytesPerSector;
	Status = ZwWriteFile(FileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		FsInfo,
		BootSector->BytesPerSector,
		&FileOffset,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		goto done;
	}

	/* Write backup of the second FsInfo sector */

	if (BootSector->BootBackup != 0x0000)
	{
		FileOffset.QuadPart = (ULONGLONG)(((ULONG)BootSector->BootBackup + (ULONG)BootSector->FSInfoSector + 1) * BootSector->BytesPerSector);
		Status = ZwWriteFile(FileHandle,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			FsInfo,
			BootSector->BytesPerSector,
			&FileOffset,
			NULL);
		if (!NT_SUCCESS(Status))
		{
			goto done;
		}
	}

done:

	/* Free the buffer */

	RtlFreeHeap(GetProcessHeap(), 0, FsInfo);
	return Status;
}


LONG Fat32WriteBootSector(HANDLE FileHandle, PFAT32_BOOT_SECTOR BootSector)
{
	IO_STATUS_BLOCK IoStatusBlock;
	LONG Status;
	PFAT32_BOOT_SECTOR NewBootSector;
	LARGE_INTEGER FileOffset;

	/* Allocate buffer for new bootsector */

	NewBootSector = (PFAT32_BOOT_SECTOR)RtlAllocateHeap(GetProcessHeap(),
		0,
		BootSector->BytesPerSector);
	if (NewBootSector == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	/* Zero the new bootsector */

	RtlZeroMemory(NewBootSector, BootSector->BytesPerSector);

	/* Copy FAT32 BPB to new bootsector */

	memcpy(NewBootSector, BootSector,
		FIELD_OFFSET(FAT32_BOOT_SECTOR, Res2) - FIELD_OFFSET(FAT32_BOOT_SECTOR, Jump));

	/* FAT32 BPB length (up to (not including) Res2) */

	/* Write the boot sector signature */

	NewBootSector->Signature1 = 0xAA550000;

	/* Write sector 0 */

	FileOffset.QuadPart = 0ULL;
	Status = ZwWriteFile(FileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		NewBootSector,
		BootSector->BytesPerSector,
		&FileOffset,
		NULL);
	if (Status < 0)
		goto done;


	/* Write backup boot sector */

	if (BootSector->BootBackup != 0x0000)
	{
		FileOffset.QuadPart = (ULONGLONG)((ULONG)BootSector->BootBackup * BootSector->BytesPerSector);
		Status = ZwWriteFile(FileHandle,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			NewBootSector,
			BootSector->BytesPerSector,
			&FileOffset,
			NULL);
		if (Status < 0)
			goto done;

	}

done:

	/* Free the buffer */

	RtlFreeHeap(GetProcessHeap(), 0, NewBootSector);
	return Status;
}

LONG Fat32WriteFAT(HANDLE FileHandle,
	ULONG SectorOffset,
	PFAT32_BOOT_SECTOR BootSector)
{
	IO_STATUS_BLOCK IoStatusBlock;
	LONG Status;
	PUCHAR Buffer;
	LARGE_INTEGER FileOffset;
	ULONG i;
	ULONG Sectors;

	/* Allocate buffer */

	Buffer = (PUCHAR)RtlAllocateHeap(GetProcessHeap(),
		0,
		64 * 1024);
	if (Buffer == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	/* Zero the buffer */

	RtlZeroMemory(Buffer, 64 * 1024);

	/* FAT cluster 0 */

	Buffer[0] = 0xf8; /* Media type */
	Buffer[1] = 0xff;
	Buffer[2] = 0xff;
	Buffer[3] = 0x0f;

	/* FAT cluster 1 */

	Buffer[4] = 0xff; /* Clean shutdown, no disk read/write errors, end-of-cluster (EOC) mark */
	Buffer[5] = 0xff;
	Buffer[6] = 0xff;
	Buffer[7] = 0x0f;

	/* FAT cluster 2 */

	Buffer[8] = 0xff; /* End of root directory */
	Buffer[9] = 0xff;
	Buffer[10] = 0xff;
	Buffer[11] = 0x0f;

	/* Write first sector of the FAT */

	FileOffset.QuadPart = (SectorOffset + BootSector->ReservedSectors) * BootSector->BytesPerSector;
	Status = ZwWriteFile(FileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		Buffer,
		BootSector->BytesPerSector,
		&FileOffset,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		goto done;
	}

	/* Zero the begin of the buffer */

	RtlZeroMemory(Buffer, 12);

	/* Zero the rest of the FAT */

	Sectors = 64 * 1024 / BootSector->BytesPerSector;
	for (i = 1; i < BootSector->FATSectors32; i += Sectors)
	{
		/* Zero some sectors of the FAT */

		FileOffset.QuadPart = (SectorOffset + BootSector->ReservedSectors + i) * BootSector->BytesPerSector;

		if ((BootSector->FATSectors32 - i) <= Sectors)
		{
			Sectors = BootSector->FATSectors32 - i;
		}

		Status = ZwWriteFile(FileHandle,
			NULL,
			NULL,
			NULL,
			&IoStatusBlock,
			Buffer,
			Sectors * BootSector->BytesPerSector,
			&FileOffset,
			NULL);
		if (!NT_SUCCESS(Status))
		{
			goto done;
		}
	}

done:

	RtlFreeHeap(GetProcessHeap(), 0, Buffer);

	return Status;
}

LONG Fat32WriteRootDirectory(HANDLE FileHandle, PFAT32_BOOT_SECTOR BootSector)
{
	IO_STATUS_BLOCK IoStatusBlock;
	LONG Status;
	PUCHAR Buffer;
	LARGE_INTEGER FileOffset;
	ULONGLONG FirstDataSector;
	ULONGLONG FirstRootDirSector;

	/* Allocate buffer for the cluster */

	Buffer = (PUCHAR)RtlAllocateHeap(GetProcessHeap(), 0, BootSector->SectorsPerCluster * BootSector->BytesPerSector);
	if (Buffer == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;

	/* Zero the buffer */

	RtlZeroMemory(Buffer, BootSector->SectorsPerCluster * BootSector->BytesPerSector);

	/* Write cluster */

	FirstDataSector = BootSector->ReservedSectors + (BootSector->FATCount * BootSector->FATSectors32) + 0 /* RootDirSectors */;

	FirstRootDirSector = ((BootSector->RootCluster - 2) * BootSector->SectorsPerCluster) + FirstDataSector;
	FileOffset.QuadPart = FirstRootDirSector * BootSector->BytesPerSector;

	Status = ZwWriteFile(FileHandle,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		Buffer,
		BootSector->SectorsPerCluster * BootSector->BytesPerSector,
		&FileOffset,
		NULL);
	if (!NT_SUCCESS(Status))
	{

		goto done;
	}

done:

	/* Free the buffer */

	RtlFreeHeap(GetProcessHeap(), 0, Buffer);
	return Status;
}

void DisksWindowPopUp::OnFormatdiskFormatdisk()
{
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	POSITION pos;
	UINT item = 0;
	HANDLE hFile;
	DWORD bytes = 0;
	CREATE_DISK ddisk;
	UNICODE_STRING uni = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	IO_STATUS_BLOCK Iosb = { 0 };
	LONG Status;
	WCHAR buffer[MAX_PATH];
	HANDLE hDevice = 0;
	PARTITION_INFORMATION info = { 0 };
	DISK_GEOMETRY diskinfo = { 0 };
	FAT32_BOOT_SECTOR boot = { 0 };
	ULONG clustersize = 0;
	BYTE ReadBootSector[512];
	IO_STATUS_BLOCK io = { 0 };
	PFAT32_BOOT_SECTOR pReadBoot = 0;

	pos = m_list_disks.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return;

	while (pos)
	{
		item = m_list_disks.GetNextSelectedItem(pos);
		diskid = _wtoi(m_list_disks.GetItemText(item, 0).GetBuffer());
	}

	FILE *fstream = 0;

	fopen_s(&fstream, "c:\\windows\\system32\\disk.txt", "w+");

	fseek(fstream, 0, SEEK_END);
	fprintf(fstream, "select disk %d\n", diskid);
	fseek(fstream, 0, SEEK_END);
	fprintf(fstream, "create partition primary\n");
	fseek(fstream, 0, SEEK_END);
	fprintf(fstream, "format fs=fat32 quick");

	fclose(fstream);

	wsprintfW(buffer, L"\\\\.\\PhysicalDrive%d",diskid);
	hFile = CreateFileW(buffer,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);
	if (hFile == INVALID_HANDLE_VALUE)
		return;

	ddisk.PartitionStyle = PARTITION_STYLE_MBR;
	ddisk.Mbr.Signature = 1;

	Status = ZwDeviceIoControlFile(hFile, 0, 0, 0, &Iosb,
		IOCTL_DISK_CREATE_DISK,
		&ddisk,
		sizeof(CREATE_DISK),
		NULL,
		0);
	if (!NT_SUCCESS(Status))
		return;
	

	Status = ZwDeviceIoControlFile(hFile, 0, 0, 0, &Iosb,
		IOCTL_DISK_UPDATE_PROPERTIES,
		NULL,
		0,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
		return;
	

	if (CreateProcessW(L"C:\\Windows\\System32\\diskpart.exe",
		L"diskpart.exe /s C:\\Windows\\System32\\disk.txt",
		NULL,
		NULL,
		FALSE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi) == FALSE)
		
		return;

	WaitForSingleObject(pi.hProcess, INFINITE);

	ZwClose(hFile);

	::MessageBox(NULL, L"Volume formatted", L"SecureVol Format", NULL);
}
