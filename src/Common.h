#pragma once
#include <Windows.h>
#include "ntos.h"
#include "usermode_interfaceDlg.h"

namespace COMMON {
	LONG SV_CreateNativeFolder(PWCHAR Path);
	LONG SV_LoadConfigData(PWCHAR Path, PVOLUMES_LIST *Data, PULONG Size);
	BOOL SV_TraverseFolder(PWCHAR Path, PHANDLE Handle);
	BOOL SV_ListFolderContents(HANDLE Handle, CListCtrl *listctrl);
	LONG SV_CheckDiskAvailability(PVOLUMES_LIST pvol);
	BOOL SV_CheckIfAdmin(TOKEN_INFORMATION_CLASS Tokenclass);
	PVOID SV_ReadFileFromExplorer(PUNICODE_STRING FilePath, PULONG FileSize,PFILE_BASIC_INFORMATION pBasicInfo);
	BOOL SV_WriteFileToVolume(PUNICODE_STRING Path, PVOID FileBuffer, ULONG FileSize,FILE_BASIC_INFORMATION fileBasicInfo,LVITEMW Item OPTIONAL, PWCHAR FileNameHash OPTIONAL, PWCHAR TypeName OPTIONAL);
};

typedef struct _SECUREVOL_HASH_DATA
{
	DWORD Hash;
}SECUREVOL_HASH_DATA, *PSECUREVOL_HASH_DATA;

typedef struct _SECUREVOL_ITEM_DATA
{
	UINT mask;
	INT icon;
	WCHAR szName[255];
	WCHAR szType[80];
	INT index;
	DWORD Hash;
}SECUREVOL_ITEM_DATA, *PSECUREVOL_ITEM_DATA;

typedef struct _TREE_CONTEXT
{
	BOOLEAN DeletionPerformed;
	CRITICAL_SECTION tree_item_lock;
	RTL_GENERIC_TABLE Item_Table;
	HANDLE Shell;
	RTL_GENERIC_TABLE Hash_Table;
	CRITICAL_SECTION tree_hash_lock;
	SECUREVOL_ITEM_DATA ItemData;
}TREE_CONTEXT, *PTREE_CONTEXT;


RTL_GENERIC_COMPARE_RESULTS NTAPI CompareCallback(
	_In_ RTL_GENERIC_TABLE *Table,
	_In_ PVOID FirstStruct,
	_In_ PVOID SecondStruct
);


PVOID NTAPI AllocateCallback(
	_In_ RTL_GENERIC_TABLE *Table,
	_In_ ULONG ByteSize
);

VOID NTAPI FreeCallback(
	_In_ RTL_GENERIC_TABLE *Table,
	_In_ _Post_invalid_ PVOID Buffer
);


RTL_GENERIC_COMPARE_RESULTS NTAPI CompareCallback2(
	_In_ RTL_GENERIC_TABLE *Table,
	_In_ PVOID FirstStruct,
	_In_ PVOID SecondStruct
);



extern TREE_CONTEXT g_treectx;