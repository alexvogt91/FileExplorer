#include "pch.h"


#include "Common.h"


/*
	function: SV_CheckDiskAvailability

	purpose: Checks if volume is active


*/

LONG COMMON::SV_CheckDiskAvailability(PVOLUMES_LIST pvol) {
	WCHAR wzPath[MAX_PATH] = { 0 };
	HANDLE hFile;
	UNICODE_STRING UnicodeString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK Iosb = { 0 };

	RtlInitUnicodeString(&UnicodeString, pvol->DeviceName);
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, 0, 0);

	if (ZwOpenFile(&hFile,
		FILE_GENERIC_READ,
		&ObjectAttributes,
		&Iosb,
		FILE_SHARE_READ,
		NULL) < 0)
		return STATUS_UNSUCCESSFUL;
	
	ZwClose(hFile);

	return STATUS_SUCCESS;
}

/*
	function: SV_CreateNativeFolder

	purpose: Creates a directory

*/

LONG COMMON::SV_CreateNativeFolder(PWCHAR Path) {
	
	HANDLE hFile = NULL;
	UNICODE_STRING UnicodeString = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	IO_STATUS_BLOCK Iosb = { 0 };
	LONG Status;

	if (Path == NULL)
		return STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&UnicodeString, Path);
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwCreateFile(&hFile, FILE_GENERIC_WRITE, &ObjectAttributes, &Iosb, NULL, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_WRITE, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, NULL);

	ZwClose(hFile);

	return Status;

}

/*

	function: SV_LoadConfigData

	purpose: loads configuration file information

*/

LONG COMMON::SV_LoadConfigData(PWCHAR Path, PVOLUMES_LIST *Data, PULONG Size) {

	HANDLE hFile = NULL;
	UNICODE_STRING UnicodeString = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	IO_STATUS_BLOCK Iosb = { 0 };
	LONG Status;
	FILE_STANDARD_INFORMATION fileinfo = { 0 };
	PVOID Alloc = NULL;

	if (Path == NULL)
		return STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&UnicodeString, Path);
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwCreateFile(&hFile,
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
	if (!NT_SUCCESS(Status))

		return STATUS_UNSUCCESSFUL;


	Status = ZwQueryInformationFile(hFile, &Iosb, &fileinfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(Status))
		return STATUS_UNSUCCESSFUL;


	if ((fileinfo.EndOfFile.LowPart % sizeof(VOLUMES_LIST)) != 0)
		return STATUS_UNSUCCESSFUL;


	Alloc = LocalAlloc(LPTR, fileinfo.EndOfFile.LowPart);
	if (Alloc == NULL)
		return STATUS_UNSUCCESSFUL;

	Status = ZwReadFile(hFile,
		NULL, NULL, NULL, &Iosb, Alloc, fileinfo.EndOfFile.LowPart, NULL, 0);
	if (!NT_SUCCESS(Status))
		return STATUS_UNSUCCESSFUL;

	*Size = (ULONG)(Iosb.Information / sizeof(VOLUMES_LIST));
	*Data = (VOLUMES_LIST*)Alloc;

	ZwClose(hFile);

	return STATUS_SUCCESS;

}

/*

	function: SV_TraverseFolder

	purpose: Opens a directory handle, it performs a sanity check beforehand


*/

BOOL COMMON::SV_TraverseFolder(PWCHAR Path, PHANDLE Handle) {
	
	HANDLE hFile = NULL;
	UNICODE_STRING UnicodeString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK Iosb;
	LONG Status;
	DWORD index = 0;

	if (Path == NULL)
		return FALSE;

	index = wcslen(Path) - 1;
	if (Path[index] != '\\')
		return FALSE;

	RtlInitUnicodeString(&UnicodeString, Path);
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);
	Status = ZwCreateFile(&hFile, FILE_LIST_DIRECTORY | SYNCHRONIZE, &ObjectAttributes, &Iosb,
		NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
		return FALSE;


	*Handle = hFile;

	return TRUE;
}

/*

	function: SV_ListFolderContents

	purpose: List directory files, reads binary tree information and displays it in ListView

*/

BOOL COMMON::SV_ListFolderContents(HANDLE Handle, CListCtrl *listctrl) {
	
	PCHAR Buffer[65536];
	LONG Status;
	IO_STATUS_BLOCK Iosb;
	PFILE_BOTH_DIR_INFORMATION pdir = NULL;
	CString filename, filetype, filesize,filehash, fileencrypted, filetime, dots1, dots2, MountDevName, virmem, physmem;
	WCHAR strFileName[MAX_PATH] = L"";
	TIME_FIELDS time_fields = { 0 };
	UINT item = 0;
	LVITEMW lvitemw, lvitem2;
	ULONG I = 0;

	Status = ZwQueryDirectoryFile(Handle,
		NULL,
		NULL,
		NULL,
		&Iosb,
		Buffer,
		65536,
		FileBothDirectoryInformation,
		FALSE,
		NULL,
		TRUE);
	if (!NT_SUCCESS(Status))
		return FALSE;

	pdir = (PFILE_BOTH_DIR_INFORMATION)Buffer;

	for (;;) {


		if ((pdir->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (pdir->FileName)[0] == L'.')
			goto scan_done;

		RtlTimeToTimeFields(&pdir->CreationTime, &time_fields);

		RtlSecureZeroMemory(strFileName, sizeof(strFileName));
		memcpy(strFileName, pdir->FileName, pdir->FileNameLength);

		filename.Format(_T("%ws"), strFileName);
		filetime.Format(_T("%02u/%02u/%03u"), time_fields.Day, time_fields.Month, time_fields.Year);
		filesize.Format(_T("%lu"), pdir->EndOfFile.LowPart);


		filehash.Format(_T("N/A"));
		fileencrypted.Format(_T("N/A"));
		virmem.Format(_T("N/A"));
		physmem.Format(_T("N/A"));

		RtlSecureZeroMemory(&lvitemw, sizeof(LVITEMW));

		if (pdir->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			lvitemw.iItem = 0;
			lvitemw.mask = LVIF_IMAGE | LVFIF_TEXT;
			lvitemw.iImage = 3;
		}

		// search value in tree

		PSECUREVOL_ITEM_DATA pitem = (PSECUREVOL_ITEM_DATA)RtlGetElementGenericTable(&g_treectx.Item_Table, I);

		// fill structure, make sure item is always 0, we only use the index value for lookup operations

		lvitemw.iImage = pitem->icon;
		lvitemw.iItem = 0;
		lvitemw.mask = pitem->mask;
		lvitemw.pszText = pitem->szName;

		listctrl->InsertItem(&lvitemw);

		listctrl->SetItemText(item, 1, pitem->szType);
		listctrl->SetItemText(item, 2, filetime);
		listctrl->SetItemText(item, 3, filesize);
		listctrl->SetItemText(item, 4, fileencrypted);
		listctrl->SetItemText(item, 5, filehash);
		listctrl->SetItemText(item, 6, virmem);
		listctrl->SetItemText(item, 7, physmem);
		

		I++;


	scan_done:

		if (pdir->NextEntryOffset == 0)
			break;
		pdir = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)pdir + pdir->NextEntryOffset);


	}

	RtlSecureZeroMemory(&lvitem2, sizeof(LVITEMW));

	lvitem2.iItem = 0;
	lvitem2.mask = LVIF_IMAGE | LVIF_TEXT;
	lvitem2.iImage = 3;
	lvitem2.pszText = L"..";

	listctrl->InsertItem(&lvitem2);
	lvitem2.pszText = L".";
	listctrl->InsertItem(&lvitem2);
	

	return TRUE;
}

/*

	function: SV_ReadFileFromExplorer

	purpose: read a file 


*/

PVOID COMMON::SV_ReadFileFromExplorer(PUNICODE_STRING FilePath, PULONG FileSize, PFILE_BASIC_INFORMATION pBasicInfo) {

	HANDLE hFile;
	LONG Status;
	UNICODE_STRING UnicodeString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK Iosb;
	PVOID FileBuffer = NULL;
	FILE_STANDARD_INFORMATION fileinfo = { 0 };
	FILE_BASIC_INFORMATION basicinfo = { 0 };

	InitializeObjectAttributes(&ObjectAttributes, FilePath, OBJ_CASE_INSENSITIVE,
		0, 0);

	// opens a handle to a file with read permissions

	Status = ZwCreateFile(&hFile,
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

	if (!NT_SUCCESS(Status))
		return NULL;

	// gather file´s size so we know how much memory we should allocate

	Status = ZwQueryInformationFile(hFile,
		&Iosb,
		&fileinfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(Status))
		return NULL;

	// get file basic info for hash generation

	Status = ZwQueryInformationFile(hFile,
		&Iosb,
		&basicinfo,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation);
	if (!NT_SUCCESS(Status))
		return NULL;

	// Allocate memory

	Status = ZwAllocateVirtualMemory(NtCurrentProcess(),
		&FileBuffer,
		0,
		(SIZE_T*)&fileinfo.EndOfFile.LowPart,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
		return NULL;
	
	// Read File
	
	Status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&Iosb,
		FileBuffer,
		fileinfo.EndOfFile.LowPart,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
		return NULL;

	if (hFile)
		ZwClose(hFile);

	// return file size and structure 

	*FileSize = fileinfo.EndOfFile.LowPart;
	*pBasicInfo = basicinfo;

	// return buffer (file contents)

	return FileBuffer;

}

RTL_GENERIC_COMPARE_RESULTS NTAPI CompareCallback(
	_In_ RTL_GENERIC_TABLE *Table,
	_In_ PVOID FirstStruct,
	_In_ PVOID SecondStruct
)
{
	UNREFERENCED_PARAMETER(Table);
	RTL_GENERIC_COMPARE_RESULTS res;

	PSECUREVOL_ITEM_DATA p1 = (PSECUREVOL_ITEM_DATA)FirstStruct;
	PSECUREVOL_ITEM_DATA p2 = (PSECUREVOL_ITEM_DATA)SecondStruct;

	if (p1->index == p2->index)
		res = GenericEqual;
	else if (p1->index > p2->index)
		res = GenericGreaterThan;
	else
		res = GenericLessThan;

	return res;

}


PVOID NTAPI AllocateCallback(
	_In_ RTL_GENERIC_TABLE *Table,
	_In_ ULONG ByteSize
)
{
	UNREFERENCED_PARAMETER(Table);
	return RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, ByteSize);
}

VOID NTAPI FreeCallback(
	_In_ RTL_GENERIC_TABLE *Table,
	_In_ _Post_invalid_ PVOID Buffer
)
{
	UNREFERENCED_PARAMETER(Table);
	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);
}

RTL_GENERIC_COMPARE_RESULTS NTAPI CompareCallback2(
	_In_ RTL_GENERIC_TABLE *Table,
	_In_ PVOID FirstStruct,
	_In_ PVOID SecondStruct
)
{
	UNREFERENCED_PARAMETER(Table);
	RTL_GENERIC_COMPARE_RESULTS res;

	PSECUREVOL_HASH_DATA p1 = (PSECUREVOL_HASH_DATA)FirstStruct;
	PSECUREVOL_HASH_DATA p2 = (PSECUREVOL_HASH_DATA)SecondStruct;

	if (p1->Hash == p2->Hash)
		res = GenericEqual;
	else if (p1->Hash > p2->Hash)
		res = GenericGreaterThan;
	else
		res = GenericLessThan;

	return res;
}

/*//////////////////////////////////////////////////////////////////////////////////

	function: SV_WriteFileToVolume

	purpose: Write file-data to disk + update binary tree data in $Shell file 
	
*///////////////////////////////////////////////////////////////////////////////////

#define FILE_VALID_FOR_WRITE_OPERATION 10


BOOL COMMON::SV_WriteFileToVolume(PUNICODE_STRING Path, PVOID FileBuffer, ULONG FileSize,FILE_BASIC_INFORMATION fileBasicInfo, LVITEMW Item OPTIONAL, PWCHAR FileNameHash OPTIONAL, PWCHAR TypeName OPTIONAL) {
	UNICODE_STRING UnicodeString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	LONG Status;
	IO_STATUS_BLOCK Iosb;
	HANDLE hFile = NULL;
	ULONG gen_hash = 0;
	//SECUREVOL_ITEM_DATA item_data = { 0 };
	SECUREVOL_HASH_DATA hash_data = { 0 };
	PVOID Newelement = FALSE;
	PWSTR remove_trail = NULL;
	PSECUREVOL_ITEM_DATA pitem = NULL;
	ULONG flag = 0;

	if (FileNameHash != NULL) {

		//remove_trail = FileNameHash + 1;
		//remove_trail != L'\0';

		// compute filename 
		
		gen_hash = (fileBasicInfo.CreationTime.HighPart) + (fileBasicInfo.LastWriteTime.HighPart);

		// lookup hash value first check

		DWORD *check_hash = (DWORD*)RtlLookupElementGenericTable(&g_treectx.Hash_Table,
			&gen_hash);
		
		if (check_hash == 0) {

			// insert elements 

			g_treectx.ItemData.icon = Item.iImage;
			g_treectx.ItemData.mask = Item.mask;
			g_treectx.ItemData.index = Item.iItem;
			g_treectx.ItemData.Hash = gen_hash;

			remove_trail = FileNameHash + 1;
			remove_trail != L'\0';

			wsprintf(g_treectx.ItemData.szType, TypeName);
			wsprintf(g_treectx.ItemData.szName, remove_trail);

			RtlInsertElementGenericTable(&g_treectx.Hash_Table, &gen_hash, sizeof(DWORD), (PBOOLEAN)&Newelement);
			RtlInsertElementGenericTable(&g_treectx.Item_Table, &g_treectx.ItemData, sizeof(SECUREVOL_ITEM_DATA), (PBOOLEAN)&Newelement);

			// update b-tree file

			Status = ZwWriteFile(g_treectx.Shell,
				NULL, NULL, NULL,
				&Iosb,
				&g_treectx.ItemData,
				sizeof(SECUREVOL_ITEM_DATA),
				NULL,
				0);
			if (NT_SUCCESS(Status)) {
				flag |= FILE_VALID_FOR_WRITE_OPERATION;
			}
		}

	}

	if (flag & FILE_VALID_FOR_WRITE_OPERATION) {

		InitializeObjectAttributes(&ObjectAttributes, Path, OBJ_CASE_INSENSITIVE, NULL, NULL);

		// open a handle to file with write attrib

		Status = ZwCreateFile(&hFile,
			FILE_GENERIC_WRITE,
			&ObjectAttributes,
			&Iosb,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_WRITE,
			FILE_CREATE,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);

		if (!NT_SUCCESS(Status))
			return FALSE;


		// write data to volume

		Status = ZwWriteFile(hFile, NULL,
			0,
			0,
			&Iosb,
			FileBuffer,
			FileSize,
			NULL,
			0);
		if (!NT_SUCCESS(Status))
			return FALSE;
	}
	else {
		return FALSE;
	}

	if (hFile)
		ZwClose(hFile);


	return TRUE;
}

/*

	function: SV_CheckIfAdmin

	purpose: Checks if admin is running with Administrative privileges

*/

BOOL COMMON::SV_CheckIfAdmin(TOKEN_INFORMATION_CLASS Tokenclass)
{
	LONG st;
	BOOL ret = FALSE, g_cond = FALSE;
	PTOKEN_GROUPS token;
	HANDLE handle;
	PSID Admin = NULL;
	DWORD bytes = 0, i = 0, attrib = 0;
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;

	st = ZwOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &handle);
	if (!NT_SUCCESS(st))
		return ret;

	do
	{
		if (AllocateAndInitializeSid(
			&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0, (PSID*)&Admin) == FALSE)

			break;

		st = ZwQueryInformationToken(handle, Tokenclass, NULL, 0, &bytes);
		if (st != STATUS_BUFFER_TOO_SMALL)
			break;

		token = (PTOKEN_GROUPS)RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)bytes);
		if (token == NULL)
			break;

		st = ZwQueryInformationToken(handle, Tokenclass, token, bytes, &bytes);
		if (NT_SUCCESS(st))
		{
			if (token->GroupCount > 0)
				for (i = 0; i < token->GroupCount; ++i)
				{
					attrib = token->Groups[i].Attributes;
					if (RtlEqualSid(Admin, token->Groups[i].Sid) == TRUE)
					{
						if ((attrib & SE_GROUP_ENABLED) && (!(attrib & SE_GROUP_USE_FOR_DENY_ONLY)))
						{
							g_cond = TRUE;
							break;
						}
					}
				}
		}
		RtlFreeHeap(GetProcessHeap(), 0, token);

	} while (ret);

	if (Admin != NULL) {
		RtlFreeSid(Admin);
	}

	if (handle != NULL) {
		NtClose(handle);
	}

	return g_cond;
}
