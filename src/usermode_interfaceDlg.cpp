
// usermode_interfaceDlg.cpp : implementation file
//

#include "pch.h"
#include "ntos.h"
#include "framework.h"
#include "usermode_interface.h"
#include "usermode_interfaceDlg.h"
#include "afxdialogex.h"
#include "DisksWindowPopUp.h"
#include "FsInformation.h"
#include "Common.h"
#include "md5.h"

#include <Windows.h>
#include <virtdisk.h>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"virtdisk.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

static const GUID VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT = { 0xEC984AEC, 0xA0F9, 0x47e9, 0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B };

LIST_ENTRY g_volumelist = { 0 };
CRITICAL_SECTION g_VolLock = { 0 };
CString g_DeviceName;
DWORD HideMountMenu = 0;
CMenu menu;
DWORD diskid = 0;
DWORD disk_flag = 0;
TREE_CONTEXT g_treectx = { 0 };

DWORD FatOpenVirtDisk(PWSTR Path, PHANDLE hFile);
DWORD FatCreateVirtualDisk(PWSTR Path, PHANDLE hFile);
DWORD FatDetachVirtualDisk(PWSTR Path);

HANDLE g_UpdateDeleteFile = NULL;


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
public:
	
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
	
END_MESSAGE_MAP()


// CusermodeinterfaceDlg dialog



CusermodeinterfaceDlg::CusermodeinterfaceDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_USERMODE_INTERFACE_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CusermodeinterfaceDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_MAIN_WINDOW, m_list_main);

	DDX_Control(pDX, IDC_TOP_BAR, m_top_bar);
	DDX_Control(pDX, IDC_LOG_WINDOW, m_log);

}

BEGIN_MESSAGE_MAP(CusermodeinterfaceDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DROPFILES()
	ON_NOTIFY(NM_RCLICK, IDC_LIST_MAIN_WINDOW, &CusermodeinterfaceDlg::OnNMRClickListMainWindow)
	ON_COMMAND(ID_SECUREVOLMAINMENU_INSTALLFILESYSTEM, &CusermodeinterfaceDlg::OnSecurevolmainmenuInstallfilesystem)
	ON_COMMAND(ID_SECUREVOLMAINMENU_MOUNTVOLUME, &CusermodeinterfaceDlg::OnSecurevolmainmenuMountvolume)
	ON_COMMAND(ID_SECUREVOLMAINMENU_FILESYSTEMINFORMATION, &CusermodeinterfaceDlg::OnSecurevolmainmenuFilesysteminformation)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_MAIN_WINDOW, &CusermodeinterfaceDlg::OnNMDblclkListMainWindow)
	//ON_NOTIFY(NM_CLICK, IDC_LIST_MAIN_WINDOW, &CusermodeinterfaceDlg::OnNMClickListMainWindow)
	ON_COMMAND(ID_SECUREVOLMAINMENU_CREATEDIRECTORY, &CusermodeinterfaceDlg::OnSecurevolmainmenuCreatedirectory)
	ON_COMMAND(ID_FILEOPERATIONS_DELETEFILE, &CusermodeinterfaceDlg::OnFileoperationsDeletefile)
END_MESSAGE_MAP()


/*///////////////////////////////////////////////////////////////////////////
	

	Function: OnInitDialog
	
	Purpose: our entry function, initializes lists, resources etc

	Date: 25/07/2021 11:30 AM

	/TODO: Fix memory leak after loading config file


*////////////////////////////////////////////////////////////////////////////

BOOL CusermodeinterfaceDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	LONG Status;
	WCHAR ShellBuffer[MAX_PATH] = L"";
	PVOLUMES_LIST pvol_data = NULL;
	HANDLE ShellHandle = NULL;
	WCHAR ShellFileName[MAX_PATH] = L"";
	ULONG vol_size = 0;
	HANDLE hFile = 0;
	HANDLE DiskFile = NULL;
	WCHAR wzPath[MAX_PATH];
	UNICODE_STRING UnicodeString = {0}, uni = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = {0}, obj = { 0 };
	IO_STATUS_BLOCK Iosb = { 0 };
	CString Temp;
	SHFILEINFOW rInfo = { 0 };

	ChangeWindowMessageFilter(0x0049, MSGFLT_ADD);
	ChangeWindowMessageFilter(WM_DROPFILES, MSGFLT_ADD);

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
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

	HICON big_icon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	HICON small_icon = (HICON)LoadImage(AfxGetResourceHandle(),
		MAKEINTRESOURCE(IDR_MAINFRAME),
		IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);


	SetIcon(big_icon, TRUE);			// Set big icon
	SetIcon(small_icon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	// TODO: Improve error handling

	HIMAGELIST hImageList = NULL;

	HRESULT hRes = CoInitialize(NULL);
	if (hRes == S_OK) {
		hImageList = (HIMAGELIST)SHGetFileInfoW(L"", 0, &rInfo, sizeof(SHFILEINFOW), SHGFI_SYSICONINDEX | SHGFI_ICON | SHGFI_SMALLICON);
	}

	m_ImageList.Attach(hImageList);
	m_list_main.ModifyStyle(0, LVS_SHAREIMAGELISTS);
	m_list_main.SetImageList(&m_ImageList, LVSIL_SMALL);

	m_list_main.SetExtendedStyle(LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EDITLABELS |LVS_EX_INFOTIP | LVS_EX_GRIDLINES);
	m_list_main.InsertColumn(0, _T("File Name"),LVCFMT_CENTER,155);
	m_list_main.InsertColumn(1, _T("File Type"),LVCFMT_CENTER,80);
	m_list_main.InsertColumn(2, _T("Time Creation"),LVCFMT_CENTER,115);
	m_list_main.InsertColumn(3, _T("File Size"),LVCFMT_CENTER,75);
	m_list_main.InsertColumn(4, _T("Encrypted"),LVCFMT_CENTER,70);
	m_list_main.InsertColumn(5, _T("Hash"),LVCFMT_CENTER,120);
	m_list_main.InsertColumn(6, _T("VirtMem"), LVCFMT_CENTER, 122);
	m_list_main.InsertColumn(7, _T("PhysMem"), LVCFMT_CENTER, 125);

	// benchmark function

	/*QueryPerformanceFrequency(&fr);
	wsprintf(freq,L"\nFREQUENCY =============== %I64d",fr.QuadPart);
	OutputDebugString(freq);
	QueryPerformanceCounter(&t1);
	*/



	/*QueryPerformanceCounter(&t2);

	LONGLONG diff = t2.QuadPart - t1.QuadPart;

	WCHAR dif[255];
	wsprintf(dif,L"\nDIFFERENCE ============ %I64d",diff);
	OutputDebugString(dif);
	*/


	//TODO check we are admin otherwise there is no point to keep going

	if (COMMON::SV_CheckIfAdmin(TokenGroups) == FALSE) {
		SetWindowText(L"SecureVol - Standard User");
		::MessageBox(NULL, L"Launching SecureVol with no Administrative rights", L"SecureVol", MB_ICONEXCLAMATION);
	}
	else {
		SetWindowText(L"SecureVol - Administrator");
	}

	// load menu early on

	VERIFY(menu.LoadMenuW(IDR_MENU1));

		
	// init lists + more resources

	InitializeListHead(&g_volumelist);

	RtlInitializeCriticalSection(&g_VolLock);
	RtlInitializeCriticalSection(&g_treectx.tree_item_lock);
	RtlInitializeCriticalSection(&g_treectx.tree_hash_lock);
	
	RtlInitializeGenericTable(&g_treectx.Item_Table, CompareCallback, AllocateCallback, FreeCallback,
		&g_treectx);
	RtlInitializeGenericTable(&g_treectx.Hash_Table, CompareCallback2, AllocateCallback, FreeCallback,
		&g_treectx);

	// create working directory

	Status = COMMON::SV_CreateNativeFolder(L"\\??\\C:\\Program Files (x86)\\SecureVol");
	if (NT_SUCCESS(Status) || Status == STATUS_OBJECT_NAME_COLLISION) {

		// Load config data
		Status = COMMON::SV_LoadConfigData(L"\\??\\C:\\Program Files (x86)\\SecureVol\\SecureVolConfigData",
			&pvol_data, &vol_size);
		if (NT_SUCCESS(Status)) {

			// check if the volume is accessible, if its not, then this means SecureVol is already installed but the system has been restarted
			// since windows does not keep mounted VHD drives.

			Status = COMMON::SV_CheckDiskAvailability(pvol_data);
			if (!NT_SUCCESS(Status)) {

				disk_flag |= FLAG_DISK_NOT_AVAILABLE;

				CusermodeinterfaceDlg::OnSecurevolmainmenuMountvolume();

			}

		}

	}

	if (pvol_data != NULL) {
		LocalFree(pvol_data);
	}


	return TRUE;  // return TRUE  unless you set the focus to a control
}


// TODO
// no need to close $shell global handle and then open a new handle.
// close global handle here after updating the file.. use common sense !!


void CusermodeinterfaceDlg::OnSysCommand(UINT nID, LPARAM lParam) {
	UNICODE_STRING UnicodeString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE hFile;
	IO_STATUS_BLOCK Iosb;
	LONG Status;
	PVOID RestartKey = NULL;
	PSECUREVOL_ITEM_DATA pitem = NULL;
	HANDLE diskHandle = NULL;
	
	if ((nID & 0xFFF0) == IDM_ABOUTBOX) {
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}

	// handle closing notifications

	else if ((nID & 0xFFF0) == SC_CLOSE) {

		while (!IsListEmpty(&g_volumelist)) {

			PVOLUMES_LIST pvol = (PVOLUMES_LIST)RemoveTailList(&g_volumelist);
			LocalFree(pvol);
		}

		// check if there are deletions

		if (g_treectx.DeletionPerformed == TRUE) {

			g_DeviceName += L"$Shell";
			RtlInitUnicodeString(&UnicodeString, g_DeviceName);
			InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
			
			Status = ZwCreateFile(&hFile,
				FILE_GENERIC_WRITE,
				&ObjectAttributes, &Iosb, NULL, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
				FILE_SHARE_WRITE,
				FILE_OVERWRITE_IF,
				FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
				NULL, 0);
			if (NT_SUCCESS(Status)) {

				// loop through current active elements

				RtlEnterCriticalSection(&g_treectx.tree_item_lock);


				for (pitem = (PSECUREVOL_ITEM_DATA)RtlEnumerateGenericTableWithoutSplaying(&g_treectx.Item_Table, &RestartKey);
					pitem != NULL;
					pitem = (PSECUREVOL_ITEM_DATA)RtlEnumerateGenericTableWithoutSplaying(&g_treectx.Item_Table, &RestartKey)) {

					// write them to $Shell

					Status = ZwWriteFile(hFile,
						NULL,
						NULL,
						NULL,
						&Iosb,
						pitem,
						sizeof(SECUREVOL_ITEM_DATA),
						NULL,
						0);
				}


				RtlLeaveCriticalSection(&g_treectx.tree_item_lock);

				ZwClose(hFile);
			}
		}

		// delete b-trees locks

		RtlDeleteCriticalSection(&g_VolLock);
		RtlDeleteCriticalSection(&g_treectx.tree_hash_lock);
		RtlDeleteCriticalSection(&g_treectx.tree_item_lock);
		

		// close event handle

		ZwClose(g_UpdateDeleteFile);

		// detach virtual disk

		ULONG res = FatDetachVirtualDisk(L"C:\\SecureVol.vhdx");

		// detach ourselves from imagelist

		m_ImageList.Detach();

		// syscall to terminate our process

		ZwTerminateProcess(NtCurrentProcess(), STATUS_SUCCESS);
	}

	else {

		CDialogEx::OnSysCommand(nID, lParam);
	}
}

void CusermodeinterfaceDlg::OnPaint()
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
HCURSOR CusermodeinterfaceDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CusermodeinterfaceDlg::OnNMRClickListMainWindow(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here

	//CMenu menu;
	CMenu topmenu;
	RECT rect;
	CPoint point;

	//VERIFY(menu.LoadMenuW(IDR_MENU1));
	CMenu* pop = menu.GetSubMenu(0);

	GetWindowRect(&rect);
	GetCursorPos(&point);
	pop->TrackPopupMenu(NULL, point.x, point.y, this);

	*pResult = 0;
}

/*
	Install kernel-mode driver and possibly modidy regedit.exe entries
*/

void CusermodeinterfaceDlg::OnSecurevolmainmenuInstallfilesystem()
{
	// TODO: Add your command handler code here




}

DWORD FatCreateVirtualDisk(PWSTR Path, PHANDLE hFile)
{
	VIRTUAL_STORAGE_TYPE storage = { 0 };
	CREATE_VIRTUAL_DISK_PARAMETERS params;
	ULONG res = 0;

	storage.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
	storage.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;

	RtlSecureZeroMemory(&params, sizeof(CREATE_VIRTUAL_DISK_PARAMETERS));

	params.Version = CREATE_VIRTUAL_DISK_VERSION_1;
	params.Version1.MaximumSize = 1024 * 1024 * 1024;
	params.Version1.BlockSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_BLOCK_SIZE;
	params.Version1.SectorSizeInBytes = CREATE_VIRTUAL_DISK_PARAMETERS_DEFAULT_SECTOR_SIZE;
	params.Version1.SourcePath = NULL;

	res = CreateVirtualDisk(&storage,
		Path,
		VIRTUAL_DISK_ACCESS_ALL,
		NULL,
		CREATE_VIRTUAL_DISK_FLAG_NONE,
		NULL,
		&params,
		NULL,
		hFile);

	return res;
}

DWORD FatOpenVirtDisk(PWSTR Path, PHANDLE hFile)
{
	VIRTUAL_STORAGE_TYPE storage = { 0 };
	OPEN_VIRTUAL_DISK_PARAMETERS params = { OPEN_VIRTUAL_DISK_VERSION_1 };

	storage.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
	storage.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;

	params.Version1.RWDepth = 1024;

	return OpenVirtualDisk(&storage,
		Path,
		VIRTUAL_DISK_ACCESS_ALL,
		OPEN_VIRTUAL_DISK_FLAG_NONE,
		&params, hFile);
}

DWORD FatDetachVirtualDisk(PWSTR Path) {
	ULONG res = 0;
	HANDLE diskHandle = NULL;

	res = FatOpenVirtDisk(Path, &diskHandle);
	if (res == ERROR_SUCCESS) {
		return DetachVirtualDisk(diskHandle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
	}

	return -1;
}

/*
	Mount filesystem

*/

void CusermodeinterfaceDlg::OnSecurevolmainmenuMountvolume()
{
	LONG Status;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING UnicodeString;
	HANDLE RootHandle = NULL;
	HANDLE virthandle = 0;
	HANDLE ShellHandle = 0;
	ULONG res = 0;
	BOOL bRet;
	ULONG AlreadyCreated = 0;
	IO_STATUS_BLOCK Iosb = { 0 };
	DisksWindowPopUp Disks;
	WCHAR DeviceName[MAX_PATH] = L"";
	HANDLE VolumeHandle = 0;
	WCHAR ShellBuffer[MAX_PATH] = L"";
	WCHAR VolumeName[MAX_PATH] = L"";
	WCHAR Container[MAX_PATH] = { 0 };
	DWORD count = 0, index = 0;
	PVOLUMES_LIST pVol = NULL;
	HANDLE hFile = NULL, StoreData = NULL;
	PLIST_ENTRY Temp = NULL;
	CMenu sub_menu;
	PFILE_BOTH_DIR_INFORMATION pdir = NULL;
	PCHAR Buffer[65536] = { 0 };
	TIME_FIELDS time_fields = { 0 };
	WCHAR strFileName[MAX_PATH] = { 0 };
	UINT item = 0;
	VOLUMES_LIST VolumeList = { 0 };
	CString filename, filetype, filesize, filealloc, filehash, fileencrypted, filetime, dots1, dots2, MountDevName;

	/*
		require permissions
		
		Create VHD 
	
	*/

	res = FatCreateVirtualDisk(L"C:\\SecureVol.vhdx", &virthandle);
	if (res == ERROR_FILE_EXISTS)
	{
		// if we get to this point, the volume was already formatted and mounted,
		// so just open the virtual disk and add a flag to it

		res = FatOpenVirtDisk(L"C:\\SecureVol.vhdx", &virthandle);
		if (res != ERROR_SUCCESS)
			return;
		else
			AlreadyCreated |= FAT_VOLUME_ALREADY_MOUNTED;
	}

	if (res == ERROR_SUCCESS)
	{
		res = AttachVirtualDisk(virthandle,
			NULL,
			ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER |
			ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME,
			0,
			0,
			NULL);
		if (res != ERROR_SUCCESS)
			return;

		ZwClose(virthandle);

		// skip the scanning and formatting process

		if (AlreadyCreated & FAT_VOLUME_ALREADY_MOUNTED)
			goto not_format;
	}

	/*
		Read registry \\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\disk
		to gather number of disks, we can check by latest disk id, so we know which can
		we format
	
	*/


	Disks.DoModal();
	

	/*
		Scan all existing volumes and store information
	
	*/

not_format:


	VolumeHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));
	if (VolumeHandle == INVALID_HANDLE_VALUE)
		return;

	index = wcslen(VolumeName) - 1;

	while (1) {

		VolumeName[index] = L'\0';

		count = QueryDosDeviceW(&VolumeName[4], DeviceName,ARRAYSIZE(DeviceName));

		VolumeName[index] = '\\';

		pVol = (PVOLUMES_LIST)LocalAlloc(LPTR, sizeof(VOLUMES_LIST));
		if (pVol == NULL)
			break;

		RtlSecureZeroMemory(pVol, sizeof(VOLUMES_LIST));

		wcscpy_s(pVol->VolumeName, MAX_PATH, VolumeName);
		wcscpy_s(pVol->DeviceName, MAX_PATH, DeviceName);
		
		RtlEnterCriticalSection(&g_VolLock);

		InsertTailList(&g_volumelist, &pVol->Entry);
		
		RtlLeaveCriticalSection(&g_VolLock);

		if (count == 0)
			break;

		bRet = FindNextVolumeW(VolumeHandle, VolumeName, ARRAYSIZE(VolumeName));
		if (bRet == FALSE) {
			DWORD Err = RtlGetLastWin32Error();
			if (Err != ERROR_NO_MORE_FILES)
				break;

			Err = ERROR_SUCCESS;
			break;
		}
	}

	FindVolumeClose(VolumeHandle);

	// loop through list

	Temp = &g_volumelist;
	
	while (&g_volumelist != Temp->Flink) {

		Temp = Temp->Flink;

		PVOLUMES_LIST pvol = (PVOLUMES_LIST)CONTAINING_RECORD(Temp, VOLUMES_LIST, Entry);

		if(!wcscmp(pvol->VolumeName,L"\\\\?\\Volume{00000001-0000-0000-0000-010000000000}\\")) {

			// we've found our volume name

			g_DeviceName += pvol->DeviceName;
			g_DeviceName += _T("\\");

			MountDevName += pvol->DeviceName;
			MountDevName += _T("\\ROOT");

			// update top bar

			m_top_bar.SetWindowTextW(MountDevName.GetBuffer());

			// hide ''mount volume'' sub-menu item

			CMenu *sub_menu = menu.GetSubMenu(0);
			sub_menu->RemoveMenu(1, MF_BYPOSITION);

			/*///////////////////////////////////

				$Shell code snippet
				
				TODO: improve error handling 
			
			*///////////////////////////////////

			wsprintf(ShellBuffer, L"%ws\\$Shell", pvol->DeviceName);
			RtlInitUnicodeString(&UnicodeString, ShellBuffer);
			InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

			// open file with read permissions

			Status = ZwCreateFile(&ShellHandle,
				FILE_GENERIC_READ,
				&ObjectAttributes,
				&Iosb,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN,
				FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0);
			if (NT_SUCCESS(Status)) {

				// file already exists, get the file size  

				FILE_STANDARD_INFORMATION getsize = { 0 };
				Status = ZwQueryInformationFile(ShellHandle, &Iosb, &getsize,
					sizeof(FILE_STANDARD_INFORMATION),
					FileStandardInformation);
				if (NT_SUCCESS(Status)) {
					
					// allocate memory

					PVOID alloc = NULL;
					Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &alloc, 0, (PSIZE_T)&getsize.EndOfFile.LowPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					if (NT_SUCCESS(Status)) {

						// do a quick file integrity check, possible insert some sort of MD5 string in the file header

					//	if ((getsize.EndOfFile.LowPart % sizeof(SECUREVOL_HASH_DATA)) == 0) {

							// read memory

							Status = ZwReadFile(ShellHandle, NULL, NULL, NULL, &Iosb,
								alloc, getsize.EndOfFile.LowPart,
								NULL, 0);
							if (NT_SUCCESS(Status)) {

								// load b-trees into pre-allocated memory

								PSECUREVOL_ITEM_DATA phashdata = (PSECUREVOL_ITEM_DATA)alloc;
								DWORD number_of_entries = (DWORD)(Iosb.Information / sizeof(SECUREVOL_ITEM_DATA));
								BOOLEAN NewItemElement = FALSE;
								BOOLEAN NewHashElement = FALSE;

								for (DWORD i = 0; i < number_of_entries; i++) {
									if (!RtlInsertElementGenericTable(&g_treectx.Item_Table, &phashdata[i], sizeof(SECUREVOL_ITEM_DATA), &NewItemElement) || 
										!RtlInsertElementGenericTable(&g_treectx.Hash_Table,&phashdata[i].Hash,sizeof(SECUREVOL_HASH_DATA),&NewHashElement))
										break;
								}

							}

						//}
					}
					if (alloc) {
						ZwFreeVirtualMemory(NtCurrentProcess(), &alloc, (PSIZE_T)&getsize.EndOfFile.LowPart, MEM_RELEASE);
					}

					ZwClose(ShellHandle);
					goto write_handle;
				}
			}
			else {

				// file does not exist, create it

			write_handle:


				Status = ZwCreateFile(&ShellHandle, FILE_APPEND_DATA | SYNCHRONIZE,
					&ObjectAttributes,
					&Iosb,
					NULL,
					FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
					FILE_SHARE_WRITE,
					FILE_OPEN_IF,
					FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
					NULL, 0);
				if (!NT_SUCCESS(Status))
					goto end;

			}

			// store handle in global structure 

			g_treectx.Shell = ShellHandle;

			/*///////////////////////////////

				End of $Shell code snipped 
			
			*////////////////////////////////
	
			// create config file and store data

			wsprintf(Container, _T("\\??\\C:\\Program Files (x86)\\SecureVol\\SecureVolConfigData"));
			RtlInitUnicodeString(&UnicodeString, Container);
			InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

			Status = ZwCreateFile(&StoreData, FILE_GENERIC_WRITE, &ObjectAttributes, &Iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, disk_flag ? FILE_OVERWRITE_IF : FILE_CREATE,
				FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
			if (!NT_SUCCESS(Status))
				break;

			wcscpy_s(VolumeList.VolumeName, MAX_PATH, pvol->VolumeName);
			wsprintf(VolumeList.RootPath, L"%ws\\ROOT", pvol->DeviceName);
			wcscpy_s(VolumeList.DeviceName, MAX_PATH, pvol->DeviceName);

			Status = ZwWriteFile(StoreData, NULL, NULL, NULL, &Iosb, &VolumeList, sizeof(VOLUMES_LIST), NULL, 0);
			if (!NT_SUCCESS(Status))
				break;

			// mount the volume, note this call will pass IRP_MN_MOUNT_VOLUME to the underlying fs driver

			RtlInitUnicodeString(&UnicodeString, pvol->DeviceName);
			InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

			Status = ZwOpenFile(&hFile, FILE_GENERIC_READ, &ObjectAttributes, &Iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL);
			if (!NT_SUCCESS(Status))
				break;

			/*/////////////////////////////////////////////////////////////////// 
			
				after mounting volume, create root folder and list contents 

				this application wont allow opening handles to the root volume, we will use
				the root location to store various configuration files only accessible
				from fs driver

			*////////////////////////////////////////////////////////////////////

			m_list_main.DeleteAllItems();


			Status = COMMON::SV_CreateNativeFolder(MountDevName.GetBuffer());
			if (NT_SUCCESS(Status) || Status == STATUS_OBJECT_NAME_COLLISION) {

				MountDevName += _T("\\");

				if (COMMON::SV_TraverseFolder(MountDevName.GetBuffer(), &RootHandle) == FALSE)
					break;

				CListCtrl *newlist = &m_list_main;

				if (COMMON::SV_ListFolderContents(RootHandle,newlist) == FALSE)
					break;

				goto end;
			
			}
			else {

				break;
			}
		}

	}

end:

	if (RootHandle)
		ZwClose(RootHandle);

	if (StoreData)
		ZwClose(StoreData);

	if(hFile)
		ZwClose(hFile);
	
	m_log.AddString(L"[*] Volume Mounted");

}

//filesystem information

void CusermodeinterfaceDlg::OnSecurevolmainmenuFilesysteminformation()
{
	FsInformation fsinfo;
	fsinfo.DoModal();

}

// Double Clicking list view elements, right now this function will only work for going forward or backwards operations 

void CusermodeinterfaceDlg::OnNMDblclkListMainWindow(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	POSITION pos;
	UINT item = 0;
	DWORD file_type = 0;
	DWORD flag = 0;
	HANDLE hFile = NULL;
	WCHAR FilePath[MAX_PATH];
	UNICODE_STRING UnicodeString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK Iosb;
	LONG Status;
	CString get_curr_path;
	CString wzBuffer;
	CString wzType;
	CString final_path;
	DWORD index = 0;

	// make sure we are only selecting folders

	pos = m_list_main.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return;

	while (pos) {

		item = m_list_main.GetNextSelectedItem(pos);

		wzBuffer = m_list_main.GetItemText(item, 0).GetBuffer();
		wzType = m_list_main.GetItemText(item, 1).GetBuffer();

		if (!wcscmp(wzBuffer.GetBuffer(), L".") || !wcscmp(wzBuffer.GetBuffer(), L".."))
			flag |= FLAG_TRAVERSE_BACKWARDS;


		else if (!wcscmp(wzType.GetBuffer(), L"Directory"))
			flag |= FLAG_TRAVERSE_FORWARD;

		else
			return;
	}

	// get current directory path

	m_top_bar.GetWindowTextW(get_curr_path);

	// decide which operation we'll do based on previous flag 

	if (flag & FLAG_TRAVERSE_BACKWARDS) {

		// remove trailing '\\' 
		
		PWSTR ptr = wcsrchr(get_curr_path.GetBuffer(), L'\\');
		if (ptr != NULL) {
			
			// check is user is trying to leave ROOT directory

			if (!wcscmp(ptr, L"\\ROOT")) {
				m_log.AddString(L"[!] Error cannot list root volume directory: Access Denied");
				return;
			}

			//TODO: fix this, we are not using final_path when leaving the conditional

			index = wcslen(ptr) - 1;
			final_path = get_curr_path.Left(get_curr_path.GetLength() - (get_curr_path.Find(L"\\") + index));
		}
	}

	else {

		// forward operation, we need to concatenate strings

		m_top_bar.GetWindowTextW(final_path);
		wsprintf(FilePath, L"%ws\\%ws\\", final_path.GetBuffer(), wzBuffer.GetBuffer());

	}

	m_list_main.DeleteAllItems();

	if (!COMMON::SV_TraverseFolder(FilePath, &hFile))
		return;

	CListCtrl *new_ctrl = &m_list_main;

	if (!COMMON::SV_ListFolderContents(hFile, new_ctrl))
		return;

	*pResult = 0;
}


/*///////////////////////////////////////////////////////////////////////////////////////////////

	Function: OnDropFiles

	Purpose: Allow drag & drop functionality (directories not allowed)

*/////////////////////////////////////////////////////////////////////////////////////////////////

void CusermodeinterfaceDlg::OnDropFiles(HDROP hDropInfo)
{

	UINT  uNumFiles;
	TCHAR szNextFile[MAX_PATH];
	TCHAR Info[MAX_PATH];
	CString str;
	UNICODE_STRING UnicodeString;
	UNICODE_STRING FinalString;
	DWORD FileSize = 0;
	PVOID FileBuffer = NULL;
	PWSTR get_file_name = NULL, remove_trail = NULL;
	HANDLE hFile = NULL;
	SHFILEINFOW psfi = { 0 };
	DWORD nIndex = m_list_main.GetItemCount();
	FILE_BASIC_INFORMATION basicInfo = { 0 };
	LVITEMW lvitem = { 0 };
	DWORD index = 0;
	CString final_path;
	HIMAGELIST hImageList;
	UINT second_query = 0;

	LARGE_INTEGER fr = { 0 }, t1 = { 0 }, t2 = {0};
	WCHAR freq[255] = L"";

	QueryPerformanceFrequency(&fr);
	wsprintf(freq,L"\nFREQUENCY =============== %I64d",fr.QuadPart);
	OutputDebugString(freq);
	QueryPerformanceCounter(&t1);
	

	// Get the # of files being dropped.
	
	uNumFiles = DragQueryFileW(hDropInfo, -1, NULL, 0);
	if (uNumFiles == 0)
	{
		OutputDebugString(L"DragQueryFileW() error");
		goto end;
	}

	for (UINT uFile = 0; uFile < uNumFiles; uFile++)
	{

		second_query = DragQueryFileW(hDropInfo, uFile, szNextFile, MAX_PATH);
		if (second_query == 0)
		{
			OutputDebugString(L"DragQueryFileW() error");
			continue;
		}

		m_top_bar.GetWindowTextW(str);
		if (m_top_bar.GetWindowTextLengthW() == 0)
		{
			OutputDebugString(L"GetWindowTextLength() error");
			break;
		}

		SHGetFileInfoW(szNextFile, 0, &psfi, sizeof(SHFILEINFOW), SHGFI_SYSICONINDEX | SHGFI_ATTRIBUTES | SHGFI_TYPENAME);
		if (!wcscmp(psfi.szTypeName, L"File folder")) 
		{
			m_log.AddString(L"[!] Error: cannot drag & drop directories");
			continue;
		}

		if (RtlDosPathNameToNtPathName_U(szNextFile, &UnicodeString, NULL, NULL) == FALSE)
		{
			OutputDebugString(L"RtlDosPathNameToNtPathName_U() error");
			continue;
		}

		FileBuffer = COMMON::SV_ReadFileFromExplorer(&UnicodeString, &FileSize, &basicInfo);
		if (FileBuffer == NULL)
		{
			OutputDebugString(L"Could not read file");
			continue;
		}

		get_file_name = wcsrchr(szNextFile, L'\\');

		str += get_file_name;

		lvitem.mask = LVIF_IMAGE | LVIF_TEXT;
		lvitem.iItem = nIndex;
		lvitem.iImage = psfi.iIcon;

		RtlInitUnicodeString(&FinalString, str.GetBuffer());
		if (COMMON::SV_WriteFileToVolume(&FinalString, FileBuffer, FileSize,basicInfo,lvitem, get_file_name, psfi.szTypeName) == FALSE)
		{
			OutputDebugString(L"Could not write data to volume");
			continue;
		}

		str = L"";

		ZwFreeVirtualMemory(NtCurrentProcess(), &FileBuffer, (PSIZE_T)&FileSize, MEM_RELEASE);

		// delete current items list and traverse the current folder to collect data

		m_top_bar.GetWindowTextW(str);
		str += _T("\\");
		if (COMMON::SV_TraverseFolder(str.GetBuffer(), &hFile) == FALSE)
		{
			OutputDebugString(L"Could not open directory handle");
			continue;
		}

		m_list_main.DeleteAllItems();
		CListCtrl *new_ctrl = &m_list_main;

		if (COMMON::SV_ListFolderContents(hFile, new_ctrl) == FALSE)
		{
			OutputDebugString(L"Could not list folder contents");
			continue;
		}


		QueryPerformanceCounter(&t2);

		LONGLONG diff = (t2.QuadPart - t1.QuadPart) / (LONGLONG)fr.QuadPart;
		
		WCHAR dif[255];
		wsprintf(dif,L"\nDIFFERENCE ============ %I64d",diff);
		OutputDebugString(dif);
		

		//wsprintf(Info, L"[+] Added file: %ws, Buffer: 0x%X Size: %lu bytes",get_file_name, FileBuffer, FileSize);
		//m_log.AddString(Info);

		nIndex++;

	}

end:

	// Free up memory.

	if (hFile)
		ZwClose(hFile);

	DragFinish(hDropInfo);


}


void CusermodeinterfaceDlg::OnSecurevolmainmenuCreatedirectory()
{
	POSITION pos;
	CString str;
	UINT item = 0;

	pos = m_list_main.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return;

	while (pos) {
		item = m_list_main.GetNextSelectedItem(pos);
		str = m_list_main.GetItemText(item, 0).GetBuffer();
	}



}


/*////////////////////////////////////////////////////////////////

	Function: OnFileoperationsDeleteFile

	Purpose: Deletes a file/directory from FS and ListView

	TODO: We should create an event handler here and 
	everytime a mark for deletion is set to True, update
	the master file, use I/O Overlapped model

*/////////////////////////////////////////////////////////////////
#define SECUREVOL_UPDATE_MASTER_FILE 10

void CusermodeinterfaceDlg::OnFileoperationsDeletefile()
{
	POSITION pos;
	CString str, current_dir;
	UINT item = 0;
	DWORD gen_hash = 0;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	UNICODE_STRING UnicodeString = { 0 };
	PVOID RestartKey = NULL;
	IO_STATUS_BLOCK iosb = { 0 };
	ULONG delflag = 0;

	// get the selected file name 

	pos = m_list_main.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return;

	while (pos) {
		item = m_list_main.GetNextSelectedItem(pos);
		str = m_list_main.GetItemText(item, 0).GetBuffer();
		if (str.GetLength() == 0)
			break;

		// get current directory 

		m_top_bar.GetWindowTextW(current_dir);
		if (current_dir.GetLength() == 0)
			return;

		// form path 

		current_dir += L"\\";
		current_dir += str;
		// loop through elements
		PSECUREVOL_ITEM_DATA pitem = NULL;
		for (pitem = (PSECUREVOL_ITEM_DATA)RtlEnumerateGenericTableWithoutSplaying(&g_treectx.Item_Table, &RestartKey);
			pitem != NULL;
			pitem = (PSECUREVOL_ITEM_DATA)RtlEnumerateGenericTableWithoutSplaying(&g_treectx.Item_Table, &RestartKey)) {
			// if items match
			if (!wcscmp(pitem->szName, str.GetBuffer())) {
				// delete item data
				RtlDeleteElementGenericTable(&g_treectx.Item_Table, pitem);
				// delete hash
				RtlDeleteElementGenericTable(&g_treectx.Hash_Table, &pitem->Hash);
				
				g_treectx.DeletionPerformed = TRUE;

				break;
			}
		}

		// delete file from FS first 

		RtlInitUnicodeString(&UnicodeString, current_dir.GetBuffer());
		InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
		if (ZwDeleteFile(&ObjectAttributes) < 0)
			return;

		// delete element from ListView

		m_list_main.DeleteItem(item);
		pos--;
		RestartKey = NULL;
	}

}
