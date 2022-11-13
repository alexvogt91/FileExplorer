/*****************************************************************************/
/* Ntdll.h                                Copyright (c) Ladislav Zezula 2005 */
/*---------------------------------------------------------------------------*/
/* Header file for the import library "Ntdll.lib"                            */
/*                                                                           */
/* This library has been created because of never-ending problems when       */
/* Ntdll.lib from Windows DDK with SDK libs (duplicate symbols, linker       */
/* errors etc).                                                              */
/* Now, it is possible to use native NT API with no problems, all you need   */
/* is just to include this header file                                       */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 15.05.03  1.00  Lad  The first version of Ntdll.h                         */
/* 16.09.05  2.00  Lad  Far more functions                                   */
/*****************************************************************************/

#ifndef __NTDLL_H__
#define __NTDLL_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _NTDDK_
#error This header cannot be compiled together with NTDDK
#endif

#pragma warning(disable: 4201)                  // nonstandard extension used : nameless struct/union

    //------------------------------------------------------------------------------
    // Defines for NTSTATUS

    //typedef long NTSTATUS;


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((LONG)(Status) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS       ((LONG)0x00000000L)
#endif

#define STATUS_BUFFER_TOO_SMALL ((LONG)0xC0000023L)
#define STATUS_NO_MORE_ENTRIES ((LONG)0x8000001AL)
#define STATUS_MORE_ENTRIES ((LONG) 0x00000105)
#define STATUS_CANNOT_DELETE ((LONG)0xC0000121L) 
#define STATUS_NOT_SUPPORTED ((LONG)0xC00000BBL)
#define STATUS_LOCK_NOT_GRANTED ((LONG)0xC0000055L)
#define STATUS_RANGE_NOT_LOCKED ((LONG)0xC000007EL)
#define STATUS_FILE_LOCKED_WITH_WRITERS ((LONG)0x0000012BL)

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((LONG)0xC0000001L)
#endif

#ifndef ASSERT
#ifdef _DEBUG
#define ASSERT(x) assert(x)
#else
#define ASSERT(x) /* x */
#endif
#endif

#ifndef DEVICE_TYPE
#define DEVICE_TYPE DWORD
#endif


#define RTL_CONSTANT_STRING(s)	{ sizeof(s)-sizeof((s)[0]), sizeof(s), s}

#define HASH_STRING_ALGORITHM_X65599 (1)


//-----------------------------------------------------------------------------
// Definition of intervals for waiting functions

#define ABSOLUTE_INTERVAL(wait) (wait)
#define STATUS_IMAGE_ALREADY_LOADED 0xC000010E
#define STATUS_OBJECT_NAME_COLLISION  0xc0000035
#define RELATIVE_INTERVAL(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILISECONDS(mili) \
(((signed __int64)(mili)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILISECONDS(1000L))

//------------------------------------------------------------------------------
// Structures

#ifndef _NTDEF_
    typedef enum _EVENT_TYPE
    {
        NotificationEvent,
        SynchronizationEvent

    } EVENT_TYPE;

    //
    // ANSI strings are counted 8-bit character strings. If they are
    // NULL terminated, Length does not include trailing NULL.
    //

    typedef struct _STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        PCHAR  Buffer;

    } STRING, * PSTRING;

    //
    // Unicode strings are counted 16-bit character strings. If they are
    // NULL terminated, Length does not include trailing NULL.
    //

    typedef struct _UNICODE_STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;

    } UNICODE_STRING, * PUNICODE_STRING;


    typedef STRING ANSI_STRING;
    typedef PSTRING PANSI_STRING;

    typedef STRING OEM_STRING;
    typedef PSTRING POEM_STRING;
    typedef CONST STRING* PCOEM_STRING;

    typedef const UNICODE_STRING* PCUNICODE_STRING;

#define UNICODE_NULL ((WCHAR)0) // winnt

    //
    // Valid values for the Attributes field
    //

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

//
// Object Attributes structure
//

    typedef struct _OBJECT_ATTRIBUTES
    {
        ULONG Length;
        HANDLE RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG Attributes;
        PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
        PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE

    } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

    //
    // IO_STATUS_BLOCK
    //

    typedef struct _IO_STATUS_BLOCK
    {
        union
        {
            LONG Status;
            PVOID Pointer;
        };

        ULONG_PTR Information;

    } IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

    //
    // ClientId
    //

    typedef struct _CLIENT_ID
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;

    } CLIENT_ID, * PCLIENT_ID;
#endif // _NTDEF_


    //
    // CURDIR structure
    //

    typedef struct _CURDIR
    {
        UNICODE_STRING DosPath;
        HANDLE Handle;

    } CURDIR, * PCURDIR;


    //------------------------------------------------------------------------------
    // Macros

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

//
// Macros for handling LIST_ENTRY-based lists
//

#if !defined(_WDMDDK_) && !defined(_LIST_ENTRY_MACROS_DEFINED_)
#define _LIST_ENTRY_MACROS_DEFINED_

    BOOLEAN
        FORCEINLINE
        IsListEmpty(
            IN const LIST_ENTRY* ListHead
        )
    {
        return (BOOLEAN)(ListHead->Flink == ListHead);
    }

    FORCEINLINE
        VOID
        InitializeListHead(
            IN PLIST_ENTRY ListHead
        )
    {
        ListHead->Flink = ListHead->Blink = ListHead;
    }

    FORCEINLINE
        VOID
        InsertHeadList(
            IN OUT PLIST_ENTRY ListHead,
            IN OUT PLIST_ENTRY Entry
        )
    {
        PLIST_ENTRY Flink;

        Flink = ListHead->Flink;
        Entry->Flink = Flink;
        Entry->Blink = ListHead;
        Flink->Blink = Entry;
        ListHead->Flink = Entry;
    }

    FORCEINLINE
        VOID
        InsertTailList(
            IN OUT PLIST_ENTRY ListHead,
            IN OUT PLIST_ENTRY Entry
        )
    {
        PLIST_ENTRY Blink;

        Blink = ListHead->Blink;
        Entry->Flink = ListHead;
        Entry->Blink = Blink;
        Blink->Flink = Entry;
        ListHead->Blink = Entry;
    }

    FORCEINLINE
        BOOLEAN
        RemoveEntryList(
            IN PLIST_ENTRY Entry
        )
    {
        PLIST_ENTRY Blink;
        PLIST_ENTRY Flink;

        Flink = Entry->Flink;
        Blink = Entry->Blink;
        Blink->Flink = Flink;
        Flink->Blink = Blink;
        return (BOOLEAN)(Flink == Blink);
    }

#define RemoveHeadList(ListHead) \
    (ListHead)->Flink;\
    {RemoveEntryList((ListHead)->Flink);}

#endif  // #if !defined(_WDMDDK_) && !defined(_LIST_ENTRY_MACROS_DEFINED_)

    //-----------------------------------------------------------------------------
    // Unicode string functions

    NTSYSAPI
        VOID
        NTAPI
        RtlInitString(
            PSTRING DestinationString,
            PCSTR SourceString
        );


    NTSYSAPI
        VOID
        NTAPI
        RtlInitUnicodeString(
            PUNICODE_STRING DestinationString,
            PCWSTR SourceString
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlCreateUnicodeString(
            OUT PUNICODE_STRING DestinationString,
            IN PCWSTR SourceString
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlCreateUnicodeStringFromAsciiz(
            OUT PUNICODE_STRING Destination,
            IN PCSTR Source
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlPrefixUnicodeString(
            IN PUNICODE_STRING String1,
            IN PUNICODE_STRING String2,
            IN BOOLEAN CaseInSensitive
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlDuplicateUnicodeString(
            IN  BOOLEAN AllocateNew,
            IN  PUNICODE_STRING SourceString,
            OUT PUNICODE_STRING TargetString
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlAppendUnicodeToString(
            PUNICODE_STRING Destination,
            PCWSTR Source
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlAppendUnicodeStringToString(
            IN OUT PUNICODE_STRING Destination,
            IN PUNICODE_STRING Source
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlUnicodeStringToInteger(
            IN PUNICODE_STRING String,
            IN ULONG Base OPTIONAL,
            OUT PULONG Value
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlIntegerToUnicodeString(
            IN ULONG Value,
            IN ULONG Base OPTIONAL,
            IN OUT PUNICODE_STRING String
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlGUIDFromString(
            IN PUNICODE_STRING GuidString,
            OUT GUID* Guid
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlCompareUnicodeString(
            IN PUNICODE_STRING String1,
            IN PUNICODE_STRING String2,
            IN BOOLEAN CaseInSensitive
        );


    NTSYSAPI
        VOID
        NTAPI
        RtlCopyUnicodeString(
            OUT PUNICODE_STRING DestinationString,
            IN PUNICODE_STRING SourceString
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlUpcaseUnicodeString(
            OUT PUNICODE_STRING DestinationString,
            IN PUNICODE_STRING SourceString,
            IN BOOLEAN AllocateDestinationString
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlDowncaseUnicodeString(
            OUT PUNICODE_STRING DestinationString,
            IN PUNICODE_STRING SourceString,
            IN BOOLEAN AllocateDestinationString
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlEqualUnicodeString(
            IN PUNICODE_STRING String1,
            IN PUNICODE_STRING String2,
            IN BOOLEAN CaseInSensitive
        );


    NTSYSAPI
        VOID
        NTAPI
        RtlFreeUnicodeString(
            IN  PUNICODE_STRING UnicodeString
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlAnsiStringToUnicodeString(
            OUT PUNICODE_STRING DestinationString,
            IN PANSI_STRING SourceString,
            IN BOOLEAN AllocateDestinationString
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlUnicodeStringToAnsiString(
            OUT PANSI_STRING DestinationString,
            IN PUNICODE_STRING SourceString,
            IN BOOLEAN AllocateDestinationString
        );


    NTSYSAPI
        VOID
        NTAPI
        RtlInitAnsiString(
            OUT PANSI_STRING DestinationString,
            IN PCHAR SourceString
        );


    NTSYSAPI
        VOID
        NTAPI
        RtlFreeAnsiString(
            IN PANSI_STRING AnsiString
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlFormatCurrentUserKeyPath(
            OUT PUNICODE_STRING CurrentUserKeyPath
        );


    NTSYSAPI
        VOID
        NTAPI
        RtlRaiseStatus(
            IN LONG Status
        );


    NTSYSAPI
        VOID
        NTAPI
        DbgBreakPoint(
            VOID
        );


    NTSYSAPI
        ULONG
        _cdecl
        DbgPrint(
            PCH Format,
            ...
        );


    NTSYSAPI
        ULONG
        NTAPI
        RtlRandom(
            IN OUT PULONG Seed
        );

    //-----------------------------------------------------------------------------
    // Critical section functions

    NTSYSAPI
        LONG
        NTAPI
        RtlInitializeCriticalSection(
            IN  PRTL_CRITICAL_SECTION CriticalSection
        );


    NTSYSAPI
        BOOL
        NTAPI
        RtlTryEnterCriticalSection(
            IN PRTL_CRITICAL_SECTION CriticalSection
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlEnterCriticalSection(
            IN PRTL_CRITICAL_SECTION CriticalSection
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlLeaveCriticalSection(
            IN PRTL_CRITICAL_SECTION CriticalSection
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlDeleteCriticalSection(
            IN  PRTL_CRITICAL_SECTION CriticalSection
        );

    //-----------------------------------------------------------------------------
    // Compression and decompression

    NTSYSAPI
        LONG
        NTAPI
        RtlCompressBuffer(
            IN  USHORT CompressionFormatAndEngine,
            IN  PUCHAR UncompressedBuffer,
            IN  ULONG UncompressedBufferSize,
            OUT PUCHAR CompressedBuffer,
            IN  ULONG CompressedBufferSize,
            IN  ULONG UncompressedChunkSize,
            OUT PULONG FinalCompressedSize,
            IN  PVOID WorkSpace
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlDecompressBuffer(
            IN  USHORT CompressionFormat,
            OUT PUCHAR UncompressedBuffer,
            IN  ULONG UncompressedBufferSize,
            IN  PUCHAR CompressedBuffer,
            IN  ULONG CompressedBufferSize,
            OUT PULONG FinalUncompressedSize
        );

    //-----------------------------------------------------------------------------
    // Object functions

    //
    // Object Manager Directory Specific Access Rights.
    //

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#endif

    typedef enum _POOL_TYPE {
        NonPagedPool,
        PagedPool,
        NonPagedPoolMustSucceed,
        DontUseThisType,
        NonPagedPoolCacheAligned,
        PagedPoolCacheAligned,
        NonPagedPoolCacheAlignedMustS,
        MaxPoolType
    } POOL_TYPE;


    //
    // For NtQueryObject
    //

    typedef enum _OBJECT_INFORMATION_CLASS {
        ObjectBasicInformation,                 // = 0x00
        ObjectNameInformation,                  // = 0x01
        ObjectTypeInformation,                  // = 0x02
        ObjectTypesInformation,                 // = 0x03    // object handle is ignored
        ObjectHandleFlagInformation             // = 0x04
    } OBJECT_INFORMATION_CLASS;

    //
    // NtQueryObject uses ObjectBasicInformation
    //

    typedef struct _OBJECT_BASIC_INFORMATION {
        ULONG Attributes;
        ACCESS_MASK GrantedAccess;
        ULONG HandleCount;
        ULONG PointerCount;
        ULONG PagedPoolCharge;
        ULONG NonPagedPoolCharge;
        ULONG Reserved[3];
        ULONG NameInfoSize;
        ULONG TypeInfoSize;
        ULONG SecurityDescriptorSize;
        LARGE_INTEGER CreationTime;
    } OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

    //
    // NtQueryObject uses ObjectNameInformation
    //

    typedef struct _OBJECT_NAME_INFORMATION {
        UNICODE_STRING Name;
    } OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

    //
    // NtQueryObject uses ObjectTypeInformation
    //

    typedef struct _OBJECT_TYPE_INFORMATION {
        UNICODE_STRING TypeName;
        ULONG TotalNumberOfObjects;
        ULONG TotalNumberOfHandles;
        ULONG TotalPagedPoolUsage;
        ULONG TotalNonPagedPoolUsage;
        ULONG TotalNamePoolUsage;
        ULONG TotalHandleTableUsage;
        ULONG HighWaterNumberOfObjects;
        ULONG HighWaterNumberOfHandles;
        ULONG HighWaterPagedPoolUsage;
        ULONG HighWaterNonPagedPoolUsage;
        ULONG HighWaterNamePoolUsage;
        ULONG HighWaterHandleTableUsage;
        ULONG InvalidAttributes;
        GENERIC_MAPPING GenericMapping;
        ULONG ValidAccessMask;
        BOOLEAN SecurityRequired;
        BOOLEAN MaintainHandleCount;
        POOL_TYPE PoolType;
        ULONG DefaultPagedPoolCharge;
        ULONG DefaultNonPagedPoolCharge;
    } OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

    //
    // NtQueryObject uses ObjectHandleFlagInformation
    // NtSetInformationObject uses ObjectHandleFlagInformation
    //

    typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
        BOOLEAN Inherit;
        BOOLEAN ProtectFromClose;
    } OBJECT_HANDLE_FLAG_INFORMATION, * POBJECT_HANDLE_FLAG_INFORMATION;

    //
    // NtQueryDirectoryObject uses this type
    //

    typedef struct _OBJECT_DIRECTORY_INFORMATION {
        UNICODE_STRING Name;
        UNICODE_STRING TypeName;
    } OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;


    NTSYSAPI
        LONG
        NTAPI
        ZwOpenDirectoryObject(
            OUT PHANDLE DirectoryHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQueryDirectoryObject(
            IN HANDLE DirectoryHandle,
            OUT PVOID Buffer,
            IN ULONG Length,
            IN BOOLEAN ReturnSingleEntry,
            IN BOOLEAN RestartScan,
            IN OUT PULONG Context,
            OUT PULONG ReturnLength OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQueryObject(
            IN HANDLE ObjectHandle,
            IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
            OUT PVOID ObjectInformation,
            IN ULONG Length,
            OUT PULONG ResultLength OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        NtSetInformationObject(
            IN HANDLE ObjectHandle,
            IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IN PVOID ObjectInformation,
            IN ULONG Length
        );


    NTSYSAPI
        LONG
        NTAPI
        NtDuplicateObject(
            IN HANDLE SourceProcessHandle,
            IN HANDLE SourceHandle,
            IN HANDLE TargetProcessHandle OPTIONAL,
            OUT PHANDLE TargetHandle OPTIONAL,
            IN ACCESS_MASK DesiredAccess,
            IN ULONG HandleAttributes,
            IN ULONG Options
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwQuerySecurityObject(
            IN HANDLE ObjectHandle,
            IN SECURITY_INFORMATION SecurityInformation,
            OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
            IN ULONG DescriptorLength,
            OUT PULONG ReturnLength
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwSetSecurityObject(
            IN HANDLE ObjectHandle,
            IN SECURITY_INFORMATION SecurityInformation,
            IN PSECURITY_DESCRIPTOR SecurityDescriptor
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwMakeTemporaryObject(
            IN HANDLE ObjectHandle
        );

    //-----------------------------------------------------------------------------
    // Handle table RTL functions

#define LEVEL_HANDLE_ID         0x74000000
#define LEVEL_HANDLE_ID_MASK    0xFF000000
#define LEVEL_HANDLE_INDEX_MASK 0x00FFFFFF

    typedef enum _RTL_GENERIC_COMPARE_RESULTS {
        GenericLessThan,
        GenericGreaterThan,
        GenericEqual
    } RTL_GENERIC_COMPARE_RESULTS;


    typedef struct _RTL_SPLAY_LINKS
    {
        struct _RTL_SPLAY_LINKS* Parent;
        struct _RTL_SPLAY_LINKS* LeftChild;
        struct _RTL_SPLAY_LINKS* RightChild;
    } RTL_SPLAY_LINKS, * PRTL_SPLAY_LINKS;


    struct _RTL_GENERIC_TABLE;

    typedef
        RTL_GENERIC_COMPARE_RESULTS
        (NTAPI* PRTL_GENERIC_COMPARE_ROUTINE) (
            struct _RTL_GENERIC_TABLE* Table,
            PVOID FirstStruct,
            PVOID SecondStruct
            );

    typedef
        PVOID
        (NTAPI* PRTL_GENERIC_ALLOCATE_ROUTINE) (
            struct _RTL_GENERIC_TABLE* Table,
            ULONG ByteSize
            );

    typedef
        VOID
        (NTAPI* PRTL_GENERIC_FREE_ROUTINE) (
            struct _RTL_GENERIC_TABLE* Table,
            PVOID Buffer
            );


    typedef struct _RTL_GENERIC_TABLE {
        PRTL_SPLAY_LINKS TableRoot;
        LIST_ENTRY InsertOrderList;
        PLIST_ENTRY OrderedPointer;
        ULONG WhichOrderedElement;
        ULONG NumberGenericTableElements;
        PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine;
        PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine;
        PRTL_GENERIC_FREE_ROUTINE FreeRoutine;
        PVOID TableContext;
    } RTL_GENERIC_TABLE, * PRTL_GENERIC_TABLE;


    typedef struct _RTL_HANDLE_TABLE_ENTRY
    {
        struct _RTL_HANDLE_TABLE_ENTRY* Next;    /* pointer to next free handle */
        PVOID  Object;

    } RTL_HANDLE_TABLE_ENTRY, * PRTL_HANDLE_TABLE_ENTRY;


    typedef struct _RTL_HANDLE_TABLE
    {
        ULONG MaximumNumberOfHandles;
        ULONG SizeOfHandleTableEntry;
        ULONG Unknown01;
        ULONG Unknown02;
        PRTL_HANDLE_TABLE_ENTRY FreeHandles;
        PRTL_HANDLE_TABLE_ENTRY CommittedHandles;
        PRTL_HANDLE_TABLE_ENTRY UnCommittedHandles;
        PRTL_HANDLE_TABLE_ENTRY MaxReservedHandles;
    } RTL_HANDLE_TABLE, * PRTL_HANDLE_TABLE;


    NTSYSAPI
        VOID
        NTAPI
        RtlInitializeGenericTable(
            IN PRTL_GENERIC_TABLE Table,
            IN PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine,
            IN PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine,
            IN PRTL_GENERIC_FREE_ROUTINE FreeRoutine,
            IN PVOID TableContext
        );


    NTSYSAPI
        VOID
        NTAPI
        RtlInitializeHandleTable(
            IN ULONG MaximumNumberOfHandles,
            IN ULONG SizeOfHandleTableEntry,
            OUT PRTL_HANDLE_TABLE HandleTable
        );


    NTSYSAPI
        PRTL_HANDLE_TABLE_ENTRY
        NTAPI
        RtlAllocateHandle(
            IN PRTL_HANDLE_TABLE HandleTable,
            OUT PULONG HandleIndex OPTIONAL
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlFreeHandle(
            IN PRTL_HANDLE_TABLE HandleTable,
            IN PRTL_HANDLE_TABLE_ENTRY Handle
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlIsValidIndexHandle(
            IN PRTL_HANDLE_TABLE HandleTable,
            IN ULONG HandleIndex,
            OUT PRTL_HANDLE_TABLE_ENTRY* Handle
        );


    NTSYSAPI
        PVOID
        NTAPI
        RtlInsertElementGenericTable(
            IN PRTL_GENERIC_TABLE Table,
            IN PVOID Buffer,
            IN LONG BufferSize,
            OUT PBOOLEAN NewElement OPTIONAL
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlIsGenericTableEmpty(
            IN PRTL_GENERIC_TABLE Table
        );

	NTSYSAPI PVOID NTAPI 
		RtlGetElementGenericTable(
		PRTL_GENERIC_TABLE Table,
		ULONG              I
	);

	NTSYSAPI BOOLEAN NTAPI RtlDeleteElementGenericTable(
		PRTL_GENERIC_TABLE Table,
		PVOID              Buffer
	);

    NTSYSAPI
        PVOID
        NTAPI
        RtlLookupElementGenericTable(
            IN PRTL_GENERIC_TABLE Table,
            IN PVOID Buffer
        );


    NTSYSAPI
        PVOID
        NTAPI
        RtlEnumerateGenericTableWithoutSplaying(
            IN  PRTL_GENERIC_TABLE Table,
            IN  PVOID* RestartKey
        );


    NTSYSAPI
        LONG
        NTAPI
        NtClose(
            IN  HANDLE Handle
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwClose(
            IN  HANDLE Handle
        );

    //-----------------------------------------------------------------------------
    // Environment functions

    NTSYSAPI
        LONG
        NTAPI
        RtlOpenCurrentUser(
            IN ULONG DesiredAccess,
            OUT PHANDLE CurrentUserKey
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlCreateEnvironment(
            BOOLEAN CloneCurrentEnvironment,
            PVOID* Environment
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlQueryEnvironmentVariable_U(
            PVOID Environment,
            PUNICODE_STRING Name,
            PUNICODE_STRING Value
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlSetEnvironmentVariable(
            PVOID* Environment,
            PUNICODE_STRING Name,
            PUNICODE_STRING Value
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlDestroyEnvironment(
            PVOID Environment
        );

    //-----------------------------------------------------------------------------
    // Registry functions


    typedef enum _KEY_INFORMATION_CLASS
    {
        KeyBasicInformation,                    // 0x00
        KeyNodeInformation,                     // 0x01
        KeyFullInformation,                     // 0x02
        KeyNameInformation,                     // 0x03
        KeyCachedInformation,                   // 0x04
        KeyFlagsInformation,                    // 0x05
        MaxKeyInfoClass                         // MaxKeyInfoClass should always be the last enum

    } KEY_INFORMATION_CLASS;

    //
    // Key query structures
    //

    typedef struct _KEY_BASIC_INFORMATION
    {
        LARGE_INTEGER LastWriteTime;
        ULONG   TitleIndex;
        ULONG   NameLength;
        WCHAR   Name[1];            // Variable length string

    } KEY_BASIC_INFORMATION, * PKEY_BASIC_INFORMATION;


    typedef struct _KEY_NODE_INFORMATION
    {
        LARGE_INTEGER LastWriteTime;
        ULONG   TitleIndex;
        ULONG   ClassOffset;
        ULONG   ClassLength;
        ULONG   NameLength;
        WCHAR   Name[1];            // Variable length string
    //          Class[1];           // Variable length string not declared
    } KEY_NODE_INFORMATION, * PKEY_NODE_INFORMATION;


    typedef struct _KEY_FULL_INFORMATION
    {
        LARGE_INTEGER LastWriteTime;
        ULONG   TitleIndex;
        ULONG   ClassOffset;
        ULONG   ClassLength;
        ULONG   SubKeys;
        ULONG   MaxNameLen;
        ULONG   MaxClassLen;
        ULONG   Values;
        ULONG   MaxValueNameLen;
        ULONG   MaxValueDataLen;
        WCHAR   Class[1];           // Variable length

    } KEY_FULL_INFORMATION, * PKEY_FULL_INFORMATION;


    // end_wdm
    typedef struct _KEY_NAME_INFORMATION
    {
        ULONG   NameLength;
        WCHAR   Name[1];            // Variable length string

    } KEY_NAME_INFORMATION, * PKEY_NAME_INFORMATION;

    typedef struct _KEY_CACHED_INFORMATION
    {
        LARGE_INTEGER LastWriteTime;
        ULONG   TitleIndex;
        ULONG   SubKeys;
        ULONG   MaxNameLen;
        ULONG   Values;
        ULONG   MaxValueNameLen;
        ULONG   MaxValueDataLen;
        ULONG   NameLength;
        WCHAR   Name[1];            // Variable length string

    } KEY_CACHED_INFORMATION, * PKEY_CACHED_INFORMATION;


    typedef struct _KEY_FLAGS_INFORMATION
    {
        ULONG   UserFlags;

    } KEY_FLAGS_INFORMATION, * PKEY_FLAGS_INFORMATION;



    typedef enum _KEY_VALUE_INFORMATION_CLASS {
        KeyValueBasicInformation,               // 0x00
        KeyValueFullInformation,                // 0x01
        KeyValuePartialInformation,             // 0x02
        KeyValueFullInformationAlign64,         // 0x03
        KeyValuePartialInformationAlign64,      // 0x04
        MaxKeyValueInfoClass                    // MaxKeyValueInfoClass should always be the last enum
    } KEY_VALUE_INFORMATION_CLASS;

    typedef struct _KEY_VALUE_BASIC_INFORMATION
    {
        ULONG TitleIndex;
        ULONG Type;
        ULONG NameLength;
        WCHAR Name[1];  //  Variable size
    } KEY_VALUE_BASIC_INFORMATION, * PKEY_VALUE_BASIC_INFORMATION;

    typedef struct _KEY_VALUE_FULL_INFORMATION
    {
        ULONG TitleIndex;
        ULONG Type;
        ULONG DataOffset;
        ULONG DataLength;
        ULONG NameLength;
        WCHAR Name[1];            // Variable size
    //        Data[1];            // Variable size data not declared
    } KEY_VALUE_FULL_INFORMATION, * PKEY_VALUE_FULL_INFORMATION;


    typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
        ULONG   TitleIndex;
        ULONG   Type;
        ULONG   DataLength;
        UCHAR   Data[1];            // Variable size
    } KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;



    NTSYSAPI
        LONG
        NTAPI
        ZwCreateKey(
            OUT PHANDLE KeyHandle,
            IN  ACCESS_MASK DesiredAccess,
            IN  POBJECT_ATTRIBUTES ObjectAttributes,
            IN  ULONG TitleIndex,
            IN  PUNICODE_STRING Class OPTIONAL,
            IN  ULONG CreateOptions,
            OUT PULONG Disposition OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwOpenKey(
            OUT PHANDLE KeyHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwEnumerateKey(
            IN HANDLE KeyHandle,
            IN ULONG Index,
            IN KEY_INFORMATION_CLASS KeyInformationClass,
            IN PVOID KeyInformation,
            IN ULONG Length,
            IN PULONG ResultLength
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwEnumerateValueKey(
            IN HANDLE KeyHandle,
            IN ULONG Index,
            IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
            OUT PVOID  KeyValueInformation,
            IN  ULONG  Length,
            OUT PULONG  ResultLength
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwDeleteKey(
            IN HANDLE KeyHandle
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQueryKey(
            IN  HANDLE KeyHandle,
            IN  KEY_INFORMATION_CLASS KeyInformationClass,
            OUT PVOID KeyInformation OPTIONAL,
            IN  ULONG Length,
            OUT PULONG ResultLength
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQueryValueKey(
            IN HANDLE KeyHandle,
            IN PUNICODE_STRING ValueName,
            IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
            OUT PVOID KeyValueInformation,
            IN ULONG Length,
            OUT PULONG ResultLength
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwSetValueKey(
            IN HANDLE KeyHandle,
            IN PUNICODE_STRING ValueName,
            IN ULONG TitleIndex OPTIONAL,
            IN ULONG Type,
            IN PVOID Data,
            IN ULONG DataSize
        );


    NTSYSAPI
        LONG
        NTAPI
        NtDeleteValueKey(
            IN HANDLE KeyHandle,
            IN PUNICODE_STRING ValueName
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwFlushKey(
            IN HANDLE KeyHandle
        );

    //-----------------------------------------------------------------------------
    // RtlQueryRegistryValues

    //
    // The following flags specify how the Name field of a RTL_QUERY_REGISTRY_TABLE
    // entry is interpreted.  A NULL name indicates the end of the table.
    //

#define RTL_QUERY_REGISTRY_SUBKEY   0x00000001  // Name is a subkey and remainder of
                                                // table or until next subkey are value
                                                // names for that subkey to look at.

#define RTL_QUERY_REGISTRY_TOPKEY   0x00000002  // Reset current key to original key for
                                                // this and all following table entries.

#define RTL_QUERY_REGISTRY_REQUIRED 0x00000004  // Fail if no match found for this table
                                                // entry.

#define RTL_QUERY_REGISTRY_NOVALUE  0x00000008  // Used to mark a table entry that has no
                                                // value name, just wants a call out, not
                                                // an enumeration of all values.

#define RTL_QUERY_REGISTRY_NOEXPAND 0x00000010  // Used to suppress the expansion of
                                                // REG_MULTI_SZ into multiple callouts or
                                                // to prevent the expansion of environment
                                                // variable values in REG_EXPAND_SZ

#define RTL_QUERY_REGISTRY_DIRECT   0x00000020  // QueryRoutine field ignored.  EntryContext
                                                // field points to location to store value.
                                                // For null terminated strings, EntryContext
                                                // points to UNICODE_STRING structure that
                                                // that describes maximum size of buffer.
                                                // If .Buffer field is NULL then a buffer is
                                                // allocated.
                                                //

#define RTL_QUERY_REGISTRY_DELETE   0x00000040  // Used to delete value keys after they
                                                // are queried.


//
// The following values for the RelativeTo parameter determine what the
// Path parameter to RtlQueryRegistryValues is relative to.
//

#define RTL_REGISTRY_ABSOLUTE     0             // Path is a full path
#define RTL_REGISTRY_SERVICES     1             // \Registry\Machine\System\CurrentControlSet\Services
#define RTL_REGISTRY_CONTROL      2             // \Registry\Machine\System\CurrentControlSet\Control
#define RTL_REGISTRY_WINDOWS_NT   3             // \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
#define RTL_REGISTRY_DEVICEMAP    4             // \Registry\Machine\Hardware\DeviceMap
#define RTL_REGISTRY_USER         5             // \Registry\User\CurrentUser
#define RTL_REGISTRY_MAXIMUM      6
#define RTL_REGISTRY_HANDLE       0x40000000    // Low order bits are registry handle
#define RTL_REGISTRY_OPTIONAL     0x80000000    // Indicates the key node is optional


    typedef LONG(NTAPI* PRTL_QUERY_REGISTRY_ROUTINE)(
        IN PWSTR ValueName,
        IN ULONG ValueType,
        IN PVOID ValueData,
        IN ULONG ValueLength,
        IN PVOID Context,
        IN PVOID EntryContext
        );

    typedef struct _RTL_QUERY_REGISTRY_TABLE
    {
        PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
        ULONG Flags;
        PWSTR Name;
        PVOID EntryContext;
        ULONG DefaultType;
        PVOID DefaultData;
        ULONG DefaultLength;

    } RTL_QUERY_REGISTRY_TABLE, * PRTL_QUERY_REGISTRY_TABLE;


    NTSYSAPI
        LONG
        NTAPI
        RtlQueryRegistryValues(
            IN ULONG  RelativeTo,
            IN PCWSTR  Path,
            IN PRTL_QUERY_REGISTRY_TABLE  QueryTable,
            IN PVOID  Context,
            IN PVOID  Environment OPTIONAL
        );


    //-----------------------------------------------------------------------------
    // Query system information

    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation,                         // 0x00 SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation,                     // 0x01 SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation,                   // 0x02
        SystemTimeOfDayInformation,                     // 0x03
        SystemPathInformation,                          // 0x04
        SystemProcessInformation,                       // 0x05
        SystemCallCountInformation,                     // 0x06
        SystemDeviceInformation,                        // 0x07
        SystemProcessorPerformanceInformation,          // 0x08
        SystemFlagsInformation,                         // 0x09
        SystemCallTimeInformation,                      // 0x0A
        SystemModuleInformation,                        // 0x0B SYSTEM_MODULE_INFORMATION
        SystemLocksInformation,                         // 0x0C
        SystemStackTraceInformation,                    // 0x0D
        SystemPagedPoolInformation,                     // 0x0E
        SystemNonPagedPoolInformation,                  // 0x0F
        SystemHandleInformation,                        // 0x10
        SystemObjectInformation,                        // 0x11
        SystemPageFileInformation,                      // 0x12
        SystemVdmInstemulInformation,                   // 0x13
        SystemVdmBopInformation,                        // 0x14
        SystemFileCacheInformation,                     // 0x15
        SystemPoolTagInformation,                       // 0x16
        SystemInterruptInformation,                     // 0x17
        SystemDpcBehaviorInformation,                   // 0x18
        SystemFullMemoryInformation,                    // 0x19
        SystemLoadGdiDriverInformation,                 // 0x1A
        SystemUnloadGdiDriverInformation,               // 0x1B
        SystemTimeAdjustmentInformation,                // 0x1C
        SystemSummaryMemoryInformation,                 // 0x1D
        SystemMirrorMemoryInformation,                  // 0x1E
        SystemPerformanceTraceInformation,              // 0x1F
        SystemObsolete0,                                // 0x20
        SystemExceptionInformation,                     // 0x21
        SystemCrashDumpStateInformation,                // 0x22
        SystemKernelDebuggerInformation,                // 0x23
        SystemContextSwitchInformation,                 // 0x24
        SystemRegistryQuotaInformation,                 // 0x25
        SystemExtendServiceTableInformation,            // 0x26
        SystemPrioritySeperation,                       // 0x27
        SystemPlugPlayBusInformation,                   // 0x28
        SystemDockInformation,                          // 0x29
        SystemPowerInformationNative,                   // 0x2A
        SystemProcessorSpeedInformation,                // 0x2B
        SystemCurrentTimeZoneInformation,               // 0x2C
        SystemLookasideInformation,                     // 0x2D
        SystemTimeSlipNotification,                     // 0x2E
        SystemSessionCreate,                            // 0x2F
        SystemSessionDetach,                            // 0x30
        SystemSessionInformation,                       // 0x31
        SystemRangeStartInformation,                    // 0x32
        SystemVerifierInformation,                      // 0x33
        SystemAddVerifier,                              // 0x34
        SystemSessionProcessesInformation,              // 0x35
        SystemLoadGdiDriverInSystemSpaceInformation,    // 0x36
        SystemNumaProcessorMap,                         // 0x37
        SystemPrefetcherInformation,                    // 0x38
        SystemExtendedProcessInformation,               // 0x39
        SystemRecommendedSharedDataAlignment,           // 0x3A
        SystemComPlusPackage,                           // 0x3B
        SystemNumaAvailableMemory,                      // 0x3C
        SystemProcessorPowerInformation,                // 0x3D
        SystemEmulationBasicInformation,                // 0x3E
        SystemEmulationProcessorInformation,            // 0x3F
        SystemExtendedHanfleInformation,                // 0x40
        SystemLostDelayedWriteInformation,              // 0x41
        SystemBigPoolInformation,                       // 0x42
        SystemSessionPoolTagInformation,                // 0x43
        SystemSessionMappedViewInformation,             // 0x44
        SystemHotpatchInformation,                      // 0x45
        SystemObjectSecurityMode,                       // 0x46
        SystemWatchDogTimerHandler,                     // 0x47
        SystemWatchDogTimerInformation,                 // 0x48
        SystemLogicalProcessorInformation,              // 0x49
        SystemWo64SharedInformationObosolete,           // 0x4A
        SystemRegisterFirmwareTableInformationHandler,  // 0x4B
        SystemFirmwareTableInformation,                 // 0x4C
        SystemModuleInformationEx,                      // 0x4D
        SystemVerifierTriageInformation,                // 0x4E
        SystemSuperfetchInformation,                    // 0x4F
        SystemMemoryListInformation,                    // 0x50
        SystemFileCacheInformationEx,                   // 0x51
        SystemThreadPriorityClientIdInformation,        // 0x52
        SystemProcessorIdleCycleTimeInformation,        // 0x53
        SystemVerifierCancellationInformation,          // 0x54
        SystemProcessorPowerInformationEx,              // 0x55
        SystemRefTraceInformation,                      // 0x56
        SystemSpecialPoolInformation,                   // 0x57
        SystemProcessIdInformation,                     // 0x58
        SystemErrorPortInformation,                     // 0x59
        SystemBootEnvironmentInformation,               // 0x5A SYSTEM_BOOT_ENVIRONMENT_INFORMATION
        SystemHypervisorInformation,                    // 0x5B
        SystemVerifierInformationEx,                    // 0x5C
        SystemTimeZoneInformation,                      // 0x5D
        SystemImageFileExecutionOptionsInformation,     // 0x5E
        SystemCoverageInformation,                      // 0x5F
        SystemPrefetchPathInformation,                  // 0x60
        SystemVerifierFaultsInformation,                // 0x61
        MaxSystemInfoClass                              // 0x67

    } SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

    //                                                  
    // Thread priority                                  
    //                                                  

    typedef LONG KPRIORITY;

    //
    // Basic System information 
    // NtQuerySystemInformation with SystemBasicInformation
    //

    typedef struct _SYSTEM_BASIC_INFORMATION {
        ULONG Reserved;
        ULONG TimerResolution;
        ULONG PageSize;
        ULONG NumberOfPhysicalPages;
        ULONG LowestPhysicalPageNumber;
        ULONG HighestPhysicalPageNumber;
        ULONG AllocationGranularity;
        ULONG MinimumUserModeAddress;
        ULONG MaximumUserModeAddress;
        KAFFINITY ActiveProcessorsAffinityMask;
        CCHAR NumberOfProcessors;
    } SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

    //
    // Processor information
    // NtQuerySystemInformation with SystemProcessorInformation
    //

    typedef struct _SYSTEM_PROCESSOR_INFORMATION {
        USHORT ProcessorArchitecture;
        USHORT ProcessorLevel;
        USHORT ProcessorRevision;
        USHORT Reserved;
        ULONG ProcessorFeatureBits;
    } SYSTEM_PROCESSOR_INFORMATION, * PSYSTEM_PROCESSOR_INFORMATION;

    //
    // Performance information
    // NtQuerySystemInformation with SystemPerformanceInformation
    //

    typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
        LARGE_INTEGER IdleProcessTime;
        LARGE_INTEGER IoReadTransferCount;
        LARGE_INTEGER IoWriteTransferCount;
        LARGE_INTEGER IoOtherTransferCount;
        ULONG IoReadOperationCount;
        ULONG IoWriteOperationCount;
        ULONG IoOtherOperationCount;
        ULONG AvailablePages;
        ULONG CommittedPages;
        ULONG CommitLimit;
        ULONG PeakCommitment;
        ULONG PageFaultCount;
        ULONG CopyOnWriteCount;
        ULONG TransitionCount;
        ULONG CacheTransitionCount;
        ULONG DemandZeroCount;
        ULONG PageReadCount;
        ULONG PageReadIoCount;
        ULONG CacheReadCount;
        ULONG CacheIoCount;
        ULONG DirtyPagesWriteCount;
        ULONG DirtyWriteIoCount;
        ULONG MappedPagesWriteCount;
        ULONG MappedWriteIoCount;
        ULONG PagedPoolPages;
        ULONG NonPagedPoolPages;
        ULONG PagedPoolAllocs;
        ULONG PagedPoolFrees;
        ULONG NonPagedPoolAllocs;
        ULONG NonPagedPoolFrees;
        ULONG FreeSystemPtes;
        ULONG ResidentSystemCodePage;
        ULONG TotalSystemDriverPages;
        ULONG TotalSystemCodePages;
        ULONG NonPagedPoolLookasideHits;
        ULONG PagedPoolLookasideHits;
        ULONG Spare3Count;
        ULONG ResidentSystemCachePage;
        ULONG ResidentPagedPoolPage;
        ULONG ResidentSystemDriverPage;
        ULONG CcFastReadNoWait;
        ULONG CcFastReadWait;
        ULONG CcFastReadResourceMiss;
        ULONG CcFastReadNotPossible;
        ULONG CcFastMdlReadNoWait;
        ULONG CcFastMdlReadWait;
        ULONG CcFastMdlReadResourceMiss;
        ULONG CcFastMdlReadNotPossible;
        ULONG CcMapDataNoWait;
        ULONG CcMapDataWait;
        ULONG CcMapDataNoWaitMiss;
        ULONG CcMapDataWaitMiss;
        ULONG CcPinMappedDataCount;
        ULONG CcPinReadNoWait;
        ULONG CcPinReadWait;
        ULONG CcPinReadNoWaitMiss;
        ULONG CcPinReadWaitMiss;
        ULONG CcCopyReadNoWait;
        ULONG CcCopyReadWait;
        ULONG CcCopyReadNoWaitMiss;
        ULONG CcCopyReadWaitMiss;
        ULONG CcMdlReadNoWait;
        ULONG CcMdlReadWait;
        ULONG CcMdlReadNoWaitMiss;
        ULONG CcMdlReadWaitMiss;
        ULONG CcReadAheadIos;
        ULONG CcLazyWriteIos;
        ULONG CcLazyWritePages;
        ULONG CcDataFlushes;
        ULONG CcDataPages;
        ULONG ContextSwitches;
        ULONG FirstLevelTbFills;
        ULONG SecondLevelTbFills;
        ULONG SystemCalls;
    } SYSTEM_PERFORMANCE_INFORMATION, * PSYSTEM_PERFORMANCE_INFORMATION;

    //
    // Time of Day information
    // NtQuerySystemInformation with SystemTimeOfDayInformation
    //

    typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
        LARGE_INTEGER BootTime;
        LARGE_INTEGER CurrentTime;
        LARGE_INTEGER TimeZoneBias;
        ULONG TimeZoneId;
        ULONG Reserved;
    } SYSTEM_TIMEOFDAY_INFORMATION, * PSYSTEM_TIMEOFDAY_INFORMATION;

    //
    // Process information
    // NtQuerySystemInformation with SystemProcessInformation
    //

    /*




    new added stuff


    */

    typedef struct _VM_COUNTERS {
        SIZE_T         PeakVirtualSize;
        SIZE_T         VirtualSize;
        ULONG          PageFaultCount;
        SIZE_T         PeakWorkingSetSize;
        SIZE_T         WorkingSetSize;
        SIZE_T         QuotaPeakPagedPoolUsage;
        SIZE_T         QuotaPagedPoolUsage;
        SIZE_T         QuotaPeakNonPagedPoolUsage;
        SIZE_T         QuotaNonPagedPoolUsage;
        SIZE_T         PagefileUsage;
        SIZE_T         PeakPagefileUsage;
    } VM_COUNTERS;

    typedef struct _SYSTEM_THREADS {
        LARGE_INTEGER  KernelTime;
        LARGE_INTEGER  UserTime;
        LARGE_INTEGER  CreateTime;
        ULONG          WaitTime;
        PVOID          StartAddress;
        CLIENT_ID      ClientId;
        KPRIORITY      Priority;
        KPRIORITY      BasePriority;
        ULONG          ContextSwitchCount;
        LONG           State;
        LONG           WaitReason;
    } SYSTEM_THREADS, * PSYSTEM_THREADS;

    typedef struct _SYSTEM_PROCESSES_NT4 {
        ULONG          NextEntryDelta;
        ULONG          ThreadCount;
        ULONG          Reserved1[6];
        LARGE_INTEGER  CreateTime;
        LARGE_INTEGER  UserTime;
        LARGE_INTEGER  KernelTime;
        UNICODE_STRING ProcessName;
        KPRIORITY      BasePriority;
        ULONG          ProcessId;
        ULONG          InheritedFromProcessId;
        ULONG          HandleCount;
        ULONG          Reserved2[2];
        VM_COUNTERS    VmCounters;
        SYSTEM_THREADS Threads[1];
    } SYSTEM_PROCESSES_NT4, * PSYSTEM_PROCESSES_NT4;

    typedef struct _SYSTEM_PROCESSES {
        ULONG          NextEntryDelta;
        ULONG          ThreadCount;
        ULONG          Reserved1[6];
        LARGE_INTEGER  CreateTime;
        LARGE_INTEGER  UserTime;
        LARGE_INTEGER  KernelTime;
        UNICODE_STRING ProcessName;
        KPRIORITY      BasePriority;
#ifdef _WIN64
        ULONG pad1;
        ULONG          ProcessId;
        ULONG pad2;
        ULONG          InheritedFromProcessId;
        ULONG pad3, pad4, pad5;
#else
        ULONG          ProcessId;
        ULONG          InheritedFromProcessId;
#endif
        ULONG          HandleCount;
        ULONG          Reserved2[2];
        VM_COUNTERS    VmCounters;
        IO_COUNTERS    IoCounters;
        SYSTEM_THREADS Threads[1];
    } SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

    typedef enum _THREAD_STATE {
        ThreadStateInitialized,
        ThreadStateReady,
        ThreadStateRunning,
        ThreadStateStandby,
        ThreadStateTerminated,
        ThreadStateWaiting,
        ThreadStateTransition
    } THREAD_STATE, * PTHREAD_STATE;

    typedef enum _THREAD_WAIT_REASON {
        ThreadWaitReasonExecutive,
        ThreadWaitReasonFreePage,
        ThreadWaitReasonPageIn,
        ThreadWaitReasonPoolAllocation,
        ThreadWaitReasonDelayExecution,
        ThreadWaitReasonSuspended,
        ThreadWaitReasonUserRequest,
        ThreadWaitReasonWrExecutive,
        ThreadWaitReasonWrFreePage,
        ThreadWaitReasonWrPageIn,
        ThreadWaitReasonWrPoolAllocation,
        ThreadWaitReasonWrDelayExecution,
        ThreadWaitReasonWrSuspended,
        ThreadWaitReasonWrUserRequest,
        ThreadWaitReasonWrEventPairHigh,
        ThreadWaitReasonWrEventPairLow,
        ThreadWaitReasonWrLpcReceive,
        ThreadWaitReasonWrLpcReply,
        ThreadWaitReasonWrVirtualMemory,
        ThreadWaitReasonWrPageOut,
        ThreadWaitReasonMaximumWaitReason
    } THREAD_WAIT_REASON;



    /*


    end of new added stuff


    */




    typedef struct _SYSTEM_PROCESS_INFORMATION {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER SpareLi1;
        LARGE_INTEGER SpareLi2;
        LARGE_INTEGER SpareLi3;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
        ULONG HandleCount;
        // Next part is platform dependent

    } SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

    //
    // Device information
    // NtQuerySystemInformation with SystemDeviceInformation
    //

    typedef struct _SYSTEM_DEVICE_INFORMATION {
        ULONG NumberOfDisks;
        ULONG NumberOfFloppies;
        ULONG NumberOfCdRoms;
        ULONG NumberOfTapes;
        ULONG NumberOfSerialPorts;
        ULONG NumberOfParallelPorts;
    } SYSTEM_DEVICE_INFORMATION, * PSYSTEM_DEVICE_INFORMATION;

    //
    // Processor performance information
    // NtQuerySystemInformation with SystemProcessorPerformanceInformation
    //

    typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
        LARGE_INTEGER IdleTime;
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER DpcTime;          // DEVL only
        LARGE_INTEGER InterruptTime;    // DEVL only
        ULONG InterruptCount;
    } SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, * PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

    //
    // NT Global Flag information
    // NtQuerySystemInformation with SystemFlagsInformation
    //

    typedef struct _SYSTEM_FLAGS_INFORMATION
    {
        ULONG GlobalFlag;

    } SYSTEM_FLAGS_INFORMATION, * PSYSTEM_FLAGS_INFORMATION;

    //
    // System Module information 
    // NtQuerySystemInformation with SystemModuleInformation
    //

    typedef struct _SYSTEM_MODULE
    {
        HANDLE Section;                 // Not filled in
        PVOID  MappedBase;
        PVOID  ImageBase;
        ULONG  ImageSize;
        ULONG  Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        CHAR   ImageName[256];

    } SYSTEM_MODULE, * PSYSTEM_MODULE;


    typedef struct _SYSTEM_MODULE_INFORMATION
    {
        ULONG         ModulesCount;
        SYSTEM_MODULE Modules[1];

    } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


    typedef struct _SYSTEM_VDM_INSTEMUL_INFO {
        ULONG SegmentNotPresent;
        ULONG VdmOpcode0F;
        ULONG OpcodeESPrefix;
        ULONG OpcodeCSPrefix;
        ULONG OpcodeSSPrefix;
        ULONG OpcodeDSPrefix;
        ULONG OpcodeFSPrefix;
        ULONG OpcodeGSPrefix;
        ULONG OpcodeOPER32Prefix;
        ULONG OpcodeADDR32Prefix;
        ULONG OpcodeINSB;
        ULONG OpcodeINSW;
        ULONG OpcodeOUTSB;
        ULONG OpcodeOUTSW;
        ULONG OpcodePUSHF;
        ULONG OpcodePOPF;
        ULONG OpcodeINTnn;
        ULONG OpcodeINTO;
        ULONG OpcodeIRET;
        ULONG OpcodeINBimm;
        ULONG OpcodeINWimm;
        ULONG OpcodeOUTBimm;
        ULONG OpcodeOUTWimm;
        ULONG OpcodeINB;
        ULONG OpcodeINW;
        ULONG OpcodeOUTB;
        ULONG OpcodeOUTW;
        ULONG OpcodeLOCKPrefix;
        ULONG OpcodeREPNEPrefix;
        ULONG OpcodeREPPrefix;
        ULONG OpcodeHLT;
        ULONG OpcodeCLI;
        ULONG OpcodeSTI;
        ULONG BopCount;
    } SYSTEM_VDM_INSTEMUL_INFO, * PSYSTEM_VDM_INSTEMUL_INFO;


    typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION {
        ULONG TimeAdjustment;
        ULONG TimeIncrement;
        BOOLEAN Enable;
    } SYSTEM_QUERY_TIME_ADJUST_INFORMATION, * PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

    typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION {
        ULONG TimeAdjustment;
        BOOLEAN Enable;
    } SYSTEM_SET_TIME_ADJUST_INFORMATION, * PSYSTEM_SET_TIME_ADJUST_INFORMATION;


    typedef struct _SYSTEM_THREAD_INFORMATION {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        CLIENT_ID ClientId;
        KPRIORITY Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        ULONG ThreadState;
        ULONG WaitReason;
    } SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

    typedef struct _SYSTEM_MEMORY_INFO {
        PUCHAR StringOffset;
        USHORT ValidCount;
        USHORT TransitionCount;
        USHORT ModifiedCount;
        USHORT PageTableCount;
    } SYSTEM_MEMORY_INFO, * PSYSTEM_MEMORY_INFO;

    typedef struct _SYSTEM_MEMORY_INFORMATION {
        ULONG InfoSize;
        ULONG StringStart;
        SYSTEM_MEMORY_INFO Memory[1];
    } SYSTEM_MEMORY_INFORMATION, * PSYSTEM_MEMORY_INFORMATION;

    typedef struct _SYSTEM_CALL_COUNT_INFORMATION {
        ULONG Length;
        ULONG NumberOfTables;
        //ULONG NumberOfEntries[NumberOfTables];
        //ULONG CallCounts[NumberOfTables][NumberOfEntries];
    } SYSTEM_CALL_COUNT_INFORMATION, * PSYSTEM_CALL_COUNT_INFORMATION;

    typedef struct _SYSTEM_CRASH_DUMP_INFORMATION {
        HANDLE CrashDumpSection;
    } SYSTEM_CRASH_DUMP_INFORMATION, * PSYSTEM_CRASH_DUMP_INFORMATION;

    typedef struct _SYSTEM_EXCEPTION_INFORMATION {
        ULONG AlignmentFixupCount;
        ULONG ExceptionDispatchCount;
        ULONG FloatingEmulationCount;
        ULONG ByteWordEmulationCount;
    } SYSTEM_EXCEPTION_INFORMATION, * PSYSTEM_EXCEPTION_INFORMATION;

    typedef struct _SYSTEM_CRASH_STATE_INFORMATION {
        ULONG ValidCrashDump;
    } SYSTEM_CRASH_STATE_INFORMATION, * PSYSTEM_CRASH_STATE_INFORMATION;

    typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    } SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

    typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION {
        ULONG RegistryQuotaAllowed;
        ULONG RegistryQuotaUsed;
        ULONG PagedPoolSize;
    } SYSTEM_REGISTRY_QUOTA_INFORMATION, * PSYSTEM_REGISTRY_QUOTA_INFORMATION;

    typedef struct _SYSTEM_GDI_DRIVER_INFORMATION {
        UNICODE_STRING DriverName;
        PVOID ImageAddress;
        PVOID SectionPointer;
        PVOID EntryPoint;
        PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
        ULONG ImageLength;
    } SYSTEM_GDI_DRIVER_INFORMATION, * PSYSTEM_GDI_DRIVER_INFORMATION;

    typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
        GUID  CurrentBootGuid;
        ULONG Unknown;
    } SYSTEM_BOOT_ENVIRONMENT_INFORMATION, * PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;


    NTSYSAPI
        LONG
        NTAPI
        ZwQuerySystemInformation(
            IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
            OUT PVOID SystemInformation,
            IN ULONG SystemInformationLength,
            OUT PULONG ReturnLength
        );

    NTSYSAPI
        LONG
        NTAPI
        ZwSetSystemInformation(
            IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IN PVOID SystemInformation,
            IN ULONG SystemInformationLength
        );

    //------------------------------------------------------------------------------
    // Shutdown system

    typedef enum _SHUTDOWN_ACTION
    {
        ShutdownNoReboot,
        ShutdownReboot,
        ShutdownPowerOff

    } SHUTDOWN_ACTION, * PSHUTDOWN_ACTION;


    NTSYSAPI
        LONG
        NTAPI
        NtShutdownSystem(
            IN SHUTDOWN_ACTION Action
        );

    //-----------------------------------------------------------------------------
    // File functions

#ifndef OLD_DOS_VOLID
#define OLD_DOS_VOLID   0x00000008
#endif

#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005
#endif  // File create flags


// Define the create/open option flags
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080
#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800
#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000
#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000
#define FILE_DISALLOW_EXCLUSIVE                 0x00020000
#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000
#endif // FILE_DIRECTORY_FILE


//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
//

#ifndef FILE_SUPERSEDED
#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005
#endif


#ifndef PIO_APC_ROUTINE_DEFINED
    typedef
        VOID
        (NTAPI* PIO_APC_ROUTINE) (
            IN PVOID ApcContext,
            IN PIO_STATUS_BLOCK IoStatusBlock,
            IN ULONG Reserved
            );
#define PIO_APC_ROUTINE_DEFINED
#endif  // PIO_APC_ROUTINE_DEFINED


    typedef enum _FILE_INFORMATION_CLASS
    {
        FileDirectoryInformation = 1,
        FileFullDirectoryInformation,           // 0x02
        FileBothDirectoryInformation,           // 0x03
        FileBasicInformation,                   // 0x04  wdm
        FileStandardInformation,                // 0x05  wdm
        FileInternalInformation,                // 0x06
        FileEaInformation,                      // 0x07
        FileAccessInformation,                  // 0x08
        FileNameInformation,                    // 0x09
        FileRenameInformation,                  // 0x0A
        FileLinkInformation,                    // 0x0B
        FileNamesInformation,                   // 0x0C
        FileDispositionInformation,             // 0x0D
        FilePositionInformation,                // 0x0E wdm
        FileFullEaInformation,                  // 0x0F
        FileModeInformation,                    // 0x10
        FileAlignmentInformation,               // 0x11
        FileAllInformation,                     // 0x12
        FileAllocationInformation,              // 0x13
        FileEndOfFileInformation,               // 0x14 wdm
        FileAlternateNameInformation,           // 0x15
        FileStreamInformation,                  // 0x16
        FilePipeInformation,                    // 0x17
        FilePipeLocalInformation,               // 0x18
        FilePipeRemoteInformation,              // 0x19
        FileMailslotQueryInformation,           // 0x1A
        FileMailslotSetInformation,             // 0x1B
        FileCompressionInformation,             // 0x1C
        FileObjectIdInformation,                // 0x1D
        FileCompletionInformation,              // 0x1E
        FileMoveClusterInformation,             // 0x1F
        FileQuotaInformation,                   // 0x20
        FileReparsePointInformation,            // 0x21
        FileNetworkOpenInformation,             // 0x22
        FileAttributeTagInformation,            // 0x23
        FileTrackingInformation,                // 0x24
        FileIdBothDirectoryInformation,         // 0x25
        FileIdFullDirectoryInformation,         // 0x26
        FileValidDataLengthInformation,         // 0x27
        FileShortNameInformation,               // 0x28
        FileIoCompletionNotificationInformation,// 0x29
        FileIoStatusBlockRangeInformation,      // 0x2A
        FileIoPriorityHintInformation,          // 0x2B
        FileSfioReserveInformation,             // 0x2C
        FileSfioVolumeInformation,              // 0x2D
        FileHardLinkInformation,                // 0x2E
        FileProcessIdsUsingFileInformation,     // 0x2F
        FileNormalizedNameInformation,          // 0x30
        FileNetworkPhysicalNameInformation,     // 0x31 
        FileIdGlobalTxDirectoryInformation,     // 0x32
        FileIsRemoteDeviceInformation,          // 0x33
        FileAttributeCacheInformation,          // 0x34
        FileNumaNodeInformation,                // 0x35
        FileStandardLinkInformation,            // 0x36
        FileRemoteProtocolInformation,          // 0x37
        FileMaximumInformation
    } FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;


    typedef struct _FILE_DIRECTORY_INFORMATION {
        ULONG NextEntryOffset;
        ULONG FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;


    typedef struct _FILE_FULL_DIR_INFORMATION {
        ULONG NextEntryOffset;
        ULONG FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        ULONG EaSize;
        WCHAR FileName[1];
    } FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;


    typedef struct _FILE_BOTH_DIR_INFORMATION {
        ULONG NextEntryOffset;
        ULONG FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        ULONG EaSize;
        CCHAR ShortNameLength;
        WCHAR ShortName[12];
        WCHAR FileName[1];
    } FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;


    typedef struct _FILE_BASIC_INFORMATION {
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        ULONG FileAttributes;
    } FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;


    typedef struct _FILE_STANDARD_INFORMATION {
        LARGE_INTEGER AllocationSize;
        LARGE_INTEGER EndOfFile;
        ULONG NumberOfLinks;
        BOOLEAN DeletePending;
        BOOLEAN Directory;
    } FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;


    typedef struct _FILE_INTERNAL_INFORMATION {
        LARGE_INTEGER IndexNumber;
    } FILE_INTERNAL_INFORMATION, * PFILE_INTERNAL_INFORMATION;


    typedef struct _FILE_EA_INFORMATION {
        ULONG EaSize;
    } FILE_EA_INFORMATION, * PFILE_EA_INFORMATION;


    typedef struct _FILE_ACCESS_INFORMATION {
        ACCESS_MASK AccessFlags;
    } FILE_ACCESS_INFORMATION, * PFILE_ACCESS_INFORMATION;


    typedef struct _FILE_NAME_INFORMATION {
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_NAME_INFORMATION, * PFILE_NAME_INFORMATION;


    typedef struct _FILE_RENAME_INFORMATION {
        BOOLEAN ReplaceIfExists;
        HANDLE RootDirectory;
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_RENAME_INFORMATION, * PFILE_RENAME_INFORMATION;


    typedef struct _FILE_NAMES_INFORMATION {
        ULONG NextEntryOffset;
        ULONG FileIndex;
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_NAMES_INFORMATION, * PFILE_NAMES_INFORMATION;


    typedef struct _FILE_DISPOSITION_INFORMATION {
        BOOLEAN DeleteFile;
    } FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;


    typedef struct _FILE_POSITION_INFORMATION {
        LARGE_INTEGER CurrentByteOffset;
    } FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;


    typedef struct _FILE_FULL_EA_INFORMATION {
        ULONG NextEntryOffset;
        UCHAR Flags;
        UCHAR EaNameLength;
        USHORT EaValueLength;
        CHAR EaName[1];
    } FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;


    typedef struct _FILE_MODE_INFORMATION {
        ULONG Mode;
    } FILE_MODE_INFORMATION, * PFILE_MODE_INFORMATION;


    typedef struct _FILE_ALIGNMENT_INFORMATION {
        ULONG AlignmentRequirement;
    } FILE_ALIGNMENT_INFORMATION, * PFILE_ALIGNMENT_INFORMATION;


    typedef struct _FILE_ALL_INFORMATION {
        FILE_BASIC_INFORMATION BasicInformation;
        FILE_STANDARD_INFORMATION StandardInformation;
        FILE_INTERNAL_INFORMATION InternalInformation;
        FILE_EA_INFORMATION EaInformation;
        FILE_ACCESS_INFORMATION AccessInformation;
        FILE_POSITION_INFORMATION PositionInformation;
        FILE_MODE_INFORMATION ModeInformation;
        FILE_ALIGNMENT_INFORMATION AlignmentInformation;
        FILE_NAME_INFORMATION NameInformation;
    } FILE_ALL_INFORMATION, * PFILE_ALL_INFORMATION;


    typedef struct _FILE_ALLOCATION_INFORMATION {
        LARGE_INTEGER AllocationSize;
    } FILE_ALLOCATION_INFORMATION, * PFILE_ALLOCATION_INFORMATION;


    typedef struct _FILE_END_OF_FILE_INFORMATION {
        LARGE_INTEGER EndOfFile;
    } FILE_END_OF_FILE_INFORMATION, * PFILE_END_OF_FILE_INFORMATION;


    typedef struct _FILE_STREAM_INFORMATION {
        ULONG NextEntryOffset;
        ULONG StreamNameLength;
        LARGE_INTEGER StreamSize;
        LARGE_INTEGER StreamAllocationSize;
        WCHAR StreamName[1];
    } FILE_STREAM_INFORMATION, * PFILE_STREAM_INFORMATION;

    typedef struct _FILE_PIPE_INFORMATION {
        ULONG ReadMode;
        ULONG CompletionMode;
    } FILE_PIPE_INFORMATION, * PFILE_PIPE_INFORMATION;


    typedef struct _FILE_PIPE_LOCAL_INFORMATION {
        ULONG NamedPipeType;
        ULONG NamedPipeConfiguration;
        ULONG MaximumInstances;
        ULONG CurrentInstances;
        ULONG InboundQuota;
        ULONG ReadDataAvailable;
        ULONG OutboundQuota;
        ULONG WriteQuotaAvailable;
        ULONG NamedPipeState;
        ULONG NamedPipeEnd;
    } FILE_PIPE_LOCAL_INFORMATION, * PFILE_PIPE_LOCAL_INFORMATION;


    typedef struct _FILE_PIPE_REMOTE_INFORMATION {
        LARGE_INTEGER CollectDataTime;
        ULONG MaximumCollectionCount;
    } FILE_PIPE_REMOTE_INFORMATION, * PFILE_PIPE_REMOTE_INFORMATION;


    typedef struct _FILE_MAILSLOT_QUERY_INFORMATION {
        ULONG MaximumMessageSize;
        ULONG MailslotQuota;
        ULONG NextMessageSize;
        ULONG MessagesAvailable;
        LARGE_INTEGER ReadTimeout;
    } FILE_MAILSLOT_QUERY_INFORMATION, * PFILE_MAILSLOT_QUERY_INFORMATION;


    typedef struct _FILE_MAILSLOT_SET_INFORMATION {
        PLARGE_INTEGER ReadTimeout;
    } FILE_MAILSLOT_SET_INFORMATION, * PFILE_MAILSLOT_SET_INFORMATION;


    typedef struct _FILE_COMPRESSION_INFORMATION {
        LARGE_INTEGER CompressedFileSize;
        USHORT CompressionFormat;
        UCHAR CompressionUnitShift;
        UCHAR ChunkShift;
        UCHAR ClusterShift;
        UCHAR Reserved[3];
    } FILE_COMPRESSION_INFORMATION, * PFILE_COMPRESSION_INFORMATION;


    typedef struct _FILE_LINK_INFORMATION {
        BOOLEAN ReplaceIfExists;
        HANDLE RootDirectory;
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_LINK_INFORMATION, * PFILE_LINK_INFORMATION;


    typedef struct _FILE_OBJECTID_INFORMATION
    {
        LONGLONG FileReference;
        UCHAR ObjectId[16];
        union {
            struct {
                UCHAR BirthVolumeId[16];
                UCHAR BirthObjectId[16];
                UCHAR DomainId[16];
            };
            UCHAR ExtendedInfo[48];
        };
    } FILE_OBJECTID_INFORMATION, * PFILE_OBJECTID_INFORMATION;


    typedef struct _FILE_COMPLETION_INFORMATION {
        HANDLE Port;
        PVOID Key;
    } FILE_COMPLETION_INFORMATION, * PFILE_COMPLETION_INFORMATION;


    typedef struct _FILE_MOVE_CLUSTER_INFORMATION {
        ULONG ClusterCount;
        HANDLE RootDirectory;
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_MOVE_CLUSTER_INFORMATION, * PFILE_MOVE_CLUSTER_INFORMATION;


    typedef struct _FILE_NETWORK_OPEN_INFORMATION {
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER AllocationSize;
        LARGE_INTEGER EndOfFile;
        ULONG FileAttributes;
    } FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;


    typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {
        ULONG FileAttributes;
        ULONG ReparseTag;
    } FILE_ATTRIBUTE_TAG_INFORMATION, * PFILE_ATTRIBUTE_TAG_INFORMATION;


    typedef struct _FILE_TRACKING_INFORMATION {
        HANDLE DestinationFile;
        ULONG ObjectInformationLength;
        CHAR ObjectInformation[1];
    } FILE_TRACKING_INFORMATION, * PFILE_TRACKING_INFORMATION;


    typedef struct _FILE_REPARSE_POINT_INFORMATION {
        LONGLONG FileReference;
        ULONG Tag;
    } FILE_REPARSE_POINT_INFORMATION, * PFILE_REPARSE_POINT_INFORMATION;


    typedef struct _FILE_QUOTA_INFORMATION {
        ULONG NextEntryOffset;
        ULONG SidLength;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER QuotaUsed;
        LARGE_INTEGER QuotaThreshold;
        LARGE_INTEGER QuotaLimit;
        SID Sid;
    } FILE_QUOTA_INFORMATION, * PFILE_QUOTA_INFORMATION;


    typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
        ULONG NextEntryOffset;
        ULONG FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        ULONG EaSize;
        CCHAR ShortNameLength;
        WCHAR ShortName[12];
        LARGE_INTEGER FileId;
        WCHAR FileName[1];
    } FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;


    typedef struct _FILE_ID_FULL_DIR_INFORMATION {
        ULONG NextEntryOffset;
        ULONG FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        ULONG EaSize;
        LARGE_INTEGER FileId;
        WCHAR FileName[1];
    } FILE_ID_FULL_DIR_INFORMATION, * PFILE_ID_FULL_DIR_INFORMATION;


    typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION {
        LARGE_INTEGER ValidDataLength;
    } FILE_VALID_DATA_LENGTH_INFORMATION, * PFILE_VALID_DATA_LENGTH_INFORMATION;

    //
    // Don't queue an entry to an associated completion port if returning success
    // synchronously.
    //
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS    0x1

//
// Don't set the file handle event on IO completion.
//
#define FILE_SKIP_SET_EVENT_ON_HANDLE           0x2

//
// Don't set user supplied event on successful fast-path IO completion.
//
#define FILE_SKIP_SET_USER_EVENT_ON_FAST_IO     0x4

    typedef  struct _FILE_IO_COMPLETION_NOTIFICATION_INFORMATION {
        ULONG Flags;
    } FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, * PFILE_IO_COMPLETION_NOTIFICATION_INFORMATION;


    typedef  struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION {
        ULONG NumberOfProcessIdsInList;
        ULONG_PTR ProcessIdList[1];
    } FILE_PROCESS_IDS_USING_FILE_INFORMATION, * PFILE_PROCESS_IDS_USING_FILE_INFORMATION;


    typedef struct _FILE_IOSTATUSBLOCK_RANGE_INFORMATION {
        PUCHAR       IoStatusBlockRange;
        ULONG        Length;
    } FILE_IOSTATUSBLOCK_RANGE_INFORMATION, * PFILE_IOSTATUSBLOCK_RANGE_INFORMATION;


    typedef enum _IO_PRIORITY_HINT {
        IoPriorityVeryLow = 0,    // Winfs promotion, defragging, content indexing and other background I/Os
        IoPriorityLow,            // Prefetching for applications.
        IoPriorityNormal,         // Normal I/Os
        IoPriorityHigh,           // Used by filesystems for checkpoint I/O
        IoPriorityCritical,       // Used by memory manager. Not available for applications.
        MaxIoPriorityTypes
    } IO_PRIORITY_HINT;


    typedef struct _FILE_IO_PRIORITY_HINT_INFORMATION {
        IO_PRIORITY_HINT   PriorityHint;
    } FILE_IO_PRIORITY_HINT_INFORMATION, * PFILE_IO_PRIORITY_HINT_INFORMATION;


    //
    // Support to reserve bandwidth for a file handle.
    //

    typedef struct _FILE_SFIO_RESERVE_INFORMATION {
        ULONG RequestsPerPeriod;
        ULONG Period;
        BOOLEAN RetryFailures;
        BOOLEAN Discardable;
        ULONG RequestSize;
        ULONG NumOutstandingRequests;
    } FILE_SFIO_RESERVE_INFORMATION, * PFILE_SFIO_RESERVE_INFORMATION;

    //
    // Support to query bandwidth properties of a volume.
    //

    typedef struct _FILE_SFIO_VOLUME_INFORMATION {
        ULONG MaximumRequestsPerPeriod;
        ULONG MinimumPeriod;
        ULONG MinimumTransferSize;
    } FILE_SFIO_VOLUME_INFORMATION, * PFILE_SFIO_VOLUME_INFORMATION;


    typedef struct _FILE_LINK_ENTRY_INFORMATION {
        ULONG NextEntryOffset;
        LONGLONG ParentFileId;
        ULONG FileNameLength;
        WCHAR FileName[1];
    } FILE_LINK_ENTRY_INFORMATION, * PFILE_LINK_ENTRY_INFORMATION;


    typedef struct _FILE_LINKS_INFORMATION
    {
        ULONG BytesNeeded;
        ULONG EntriesReturned;
        FILE_LINK_ENTRY_INFORMATION Entry;
    } FILE_LINKS_INFORMATION, * PFILE_LINKS_INFORMATION;

    typedef struct _FILE_ID_GLOBAL_TX_DIR_INFORMATION
    {
        ULONG          NextEntryOffset;
        ULONG          FileIndex;
        LARGE_INTEGER  CreationTime;
        LARGE_INTEGER  LastAccessTime;
        LARGE_INTEGER  LastWriteTime;
        LARGE_INTEGER  ChangeTime;
        LARGE_INTEGER  EndOfFile;
        LARGE_INTEGER  AllocationSize;
        ULONG          FileAttributes;
        ULONG          FileNameLength;
        LARGE_INTEGER  FileId;
        GUID           LockingTransactionId;
        ULONG          TxInfoFlags;
        WCHAR          FileName[1];
    } FILE_ID_GLOBAL_TX_DIR_INFORMATION, * PFILE_ID_GLOBAL_TX_DIR_INFORMATION;


    typedef struct _FILE_IS_REMOTE_DEVICE_INFORMATION
    {
        BOOLEAN IsRemote;
    } FILE_IS_REMOTE_DEVICE_INFORMATION, * PFILE_IS_REMOTE_DEVICE_INFORMATION;

    typedef struct _FILE_NUMA_NODE_INFORMATION {
        USHORT NodeNumber;
    } FILE_NUMA_NODE_INFORMATION, * PFILE_NUMA_NODE_INFORMATION;

    /*
    typedef struct _FILE_REMOTE_PROTOCOL_INFO
    {
      USHORT StructureVersion;
      USHORT StructureSize;
      ULONG  Protocol;
      USHORT ProtocolMajorVersion;
      USHORT ProtocolMinorVersion;
      USHORT ProtocolRevision;
      USHORT Reserved;
      ULONG  Flags;
      struct {
        ULONG Reserved[8];
      } GenericReserved;
      struct {
        ULONG Reserved[16];
      } ProtocolSpecificReserved;
    } FILE_REMOTE_PROTOCOL_INFO, *PFILE_REMOTE_PROTOCOL_INFO;
    */

    typedef enum _FSINFOCLASS {
        FileFsVolumeInformation = 1,
        FileFsLabelInformation,                 // 0x02
        FileFsSizeInformation,                  // 0x03
        FileFsDeviceInformation,                // 0x04
        FileFsAttributeInformation,             // 0x05
        FileFsControlInformation,               // 0x06
        FileFsFullSizeInformation,              // 0x07
        FileFsObjectIdInformation,              // 0x08
        FileFsDriverPathInformation,            // 0x09
        FileFsVolumeFlagsInformation,           // 0x0A
        FileFsMaximumInformation                // 0x0B
    } FS_INFORMATION_CLASS, * PFS_INFORMATION_CLASS;


    typedef struct _FILE_FS_VOLUME_INFORMATION {
        LARGE_INTEGER VolumeCreationTime;
        ULONG VolumeSerialNumber;
        ULONG VolumeLabelLength;
        BOOLEAN SupportsObjects;
        WCHAR VolumeLabel[1];
    } FILE_FS_VOLUME_INFORMATION, * PFILE_FS_VOLUME_INFORMATION;


    typedef struct _FILE_FS_LABEL_INFORMATION {
        ULONG VolumeLabelLength;
        WCHAR VolumeLabel[1];
    } FILE_FS_LABEL_INFORMATION, * PFILE_FS_LABEL_INFORMATION;


    typedef struct _FILE_FS_SIZE_INFORMATION {
        LARGE_INTEGER TotalAllocationUnits;
        LARGE_INTEGER AvailableAllocationUnits;
        ULONG SectorsPerAllocationUnit;
        ULONG BytesPerSector;
    } FILE_FS_SIZE_INFORMATION, * PFILE_FS_SIZE_INFORMATION;


    typedef struct _FILE_FS_DEVICE_INFORMATION {
        DEVICE_TYPE DeviceType;
        ULONG Characteristics;
    } FILE_FS_DEVICE_INFORMATION, * PFILE_FS_DEVICE_INFORMATION;


    typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
        ULONG FileSystemAttributes;
        LONG MaximumComponentNameLength;
        ULONG FileSystemNameLength;
        WCHAR FileSystemName[1];
    } FILE_FS_ATTRIBUTE_INFORMATION, * PFILE_FS_ATTRIBUTE_INFORMATION;


    typedef struct _FILE_FS_CONTROL_INFORMATION {
        LARGE_INTEGER FreeSpaceStartFiltering;
        LARGE_INTEGER FreeSpaceThreshold;
        LARGE_INTEGER FreeSpaceStopFiltering;
        LARGE_INTEGER DefaultQuotaThreshold;
        LARGE_INTEGER DefaultQuotaLimit;
        ULONG FileSystemControlFlags;
    } FILE_FS_CONTROL_INFORMATION, * PFILE_FS_CONTROL_INFORMATION;


    typedef struct _FILE_FS_FULL_SIZE_INFORMATION {
        LARGE_INTEGER TotalAllocationUnits;
        LARGE_INTEGER CallerAvailableAllocationUnits;
        LARGE_INTEGER ActualAvailableAllocationUnits;
        ULONG SectorsPerAllocationUnit;
        ULONG BytesPerSector;
    } FILE_FS_FULL_SIZE_INFORMATION, * PFILE_FS_FULL_SIZE_INFORMATION;


    typedef struct _FILE_FS_OBJECTID_INFORMATION {
        UCHAR ObjectId[16];
        UCHAR ExtendedInfo[48];
    } FILE_FS_OBJECTID_INFORMATION, * PFILE_FS_OBJECTID_INFORMATION;


    typedef struct _FILE_FS_DRIVER_PATH_INFORMATION {
        BOOLEAN DriverInPath;
        ULONG   DriverNameLength;
        WCHAR   DriverName[1];
    } FILE_FS_DRIVER_PATH_INFORMATION, * PFILE_FS_DRIVER_PATH_INFORMATION;


    typedef struct _FILE_FS_VOLUME_FLAGS_INFORMATION {
        ULONG Flags;
    } FILE_FS_VOLUME_FLAGS_INFORMATION, * PFILE_FS_VOLUME_FLAGS_INFORMATION;




    NTSYSAPI
        LONG
        NTAPI
        ZwCreateFile(
            OUT PHANDLE FileHandle,
            IN  ACCESS_MASK DesiredAccess,
            IN  POBJECT_ATTRIBUTES ObjectAttributes,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN  PLARGE_INTEGER AllocationSize,
            IN  ULONG FileAttributes,
            IN  ULONG ShareAccess,
            IN  ULONG CreateDisposition,
            IN  ULONG CreateOptions,
            IN  PVOID EaBuffer,
            IN  ULONG EaLength);



    NTSYSAPI
        LONG
        NTAPI
        ZwOpenFile(
            OUT PHANDLE FileHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN ULONG ShareAccess,
            IN ULONG OpenOptions
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQueryAttributesFile(
            IN POBJECT_ATTRIBUTES ObjectAttributes,
            OUT PFILE_BASIC_INFORMATION FileInformation
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQueryInformationFile(
            IN HANDLE FileHandle,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            OUT PVOID FileInformation,
            IN ULONG Length,
            IN FILE_INFORMATION_CLASS FileInformationClass
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwQueryDirectoryFile(
            IN HANDLE FileHandle,
            IN HANDLE Event OPTIONAL,
            IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
            IN PVOID ApcContext OPTIONAL,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            OUT PVOID FileInformation,
            IN ULONG Length,
            IN FILE_INFORMATION_CLASS FileInformationClass,
            IN BOOLEAN ReturnSingleEntry,
            IN PUNICODE_STRING FileName OPTIONAL,
            IN BOOLEAN RestartScan
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQueryVolumeInformationFile(
            IN HANDLE FileHandle,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            OUT PVOID FsInformation,
            IN ULONG Length,
            IN FS_INFORMATION_CLASS FsInformationClass
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwSetInformationFile(
            IN HANDLE FileHandle,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN PVOID FileInformation,
            IN ULONG Length,
            IN FILE_INFORMATION_CLASS FileInformationClass
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwSetVolumeInformationFile(
            IN HANDLE FileHandle,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            OUT PVOID FsInformation,
            IN ULONG Length,
            IN FS_INFORMATION_CLASS FsInformationClass
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwQueryEaFile(
            IN  HANDLE FileHandle,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            OUT PVOID Buffer,
            IN  ULONG Length,
            IN  BOOLEAN ReturnSingleEntry,
            IN  PVOID EaList OPTIONAL,
            IN  ULONG EaListLength,
            IN  PULONG EaIndex OPTIONAL,
            IN  BOOLEAN RestartScan);




    NTSYSAPI
        LONG
        NTAPI
        ZwSetEaFile(
            IN  HANDLE FileHandle,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN  PVOID Buffer,
            IN  ULONG Length);



    NTSYSAPI
        LONG
        NTAPI
        ZwReadFile(
            IN HANDLE FileHandle,
            IN HANDLE Event OPTIONAL,
            IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
            IN PVOID ApcContext OPTIONAL,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            OUT PVOID Buffer,
            IN ULONG Length,
            IN PLARGE_INTEGER ByteOffset OPTIONAL,
            IN PULONG Key OPTIONAL
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwWriteFile(
            IN HANDLE FileHandle,
            IN HANDLE Event OPTIONAL,
            IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
            IN PVOID ApcContext OPTIONAL,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN PVOID Buffer,
            IN ULONG Length,
            IN PLARGE_INTEGER ByteOffset OPTIONAL,
            IN PULONG Key OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwDeleteFile(
            IN POBJECT_ATTRIBUTES ObjectAttributes
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwFlushBuffersFile(
            IN HANDLE FileHandle,
            OUT PIO_STATUS_BLOCK IoStatusBlock
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwDeviceIoControlFile(
            IN  HANDLE FileHandle,
            IN  HANDLE Event,
            IN  PIO_APC_ROUTINE ApcRoutine,
            IN  PVOID ApcContext,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN  ULONG IoControlCode,
            IN  PVOID InputBuffer,
            IN  ULONG InputBufferLength,
            IN  PVOID OutputBuffer,
            IN  ULONG OutputBufferLength
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwFsControlFile(
            IN  HANDLE FileHandle,
            IN  HANDLE Event,
            IN  PIO_APC_ROUTINE ApcRoutine,
            IN  PVOID ApcContext,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN  ULONG FsControlCode,
            IN  PVOID InputBuffer,
            IN  ULONG InputBufferLength,
            IN  PVOID OutputBuffer,
            IN  ULONG OutputBufferLength
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwCancelIoFile(
            IN HANDLE Filehandle,
            OUT PIO_STATUS_BLOCK IoStatusBlock
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwLockFile(
            IN HANDLE FileHandle,
            IN HANDLE Event OPTIONAL,
            IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
            IN PVOID ApcContext OPTIONAL,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN PLARGE_INTEGER ByteOffset,
            IN PLARGE_INTEGER Length,
            IN ULONG Key,
            IN BOOLEAN FailImmediately,
            IN BOOLEAN ExclusiveLock
        );


    LONG
        ZwUnlockFile(
            IN HANDLE FileHandle,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN PLARGE_INTEGER ByteOffset,
            IN PLARGE_INTEGER Length,
            IN ULONG Key
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlDosPathNameToNtPathName_U(
            IN  PWSTR DosPathName,
            OUT PUNICODE_STRING NtPathName,
            OUT PWSTR* NtFileNamePart OPTIONAL,
            OUT PCURDIR DirectoryInfo OPTIONAL
        );


    //-----------------------------------------------------------------------------
    // Process functions

#define GDI_HANDLE_BUFFER_SIZE      34 

// For ProcessExecuteFlags
#define MEM_EXECUTE_OPTION_DISABLE   0x01
#define MEM_EXECUTE_OPTION_ENABLE    0x02
#define MEM_EXECUTE_OPTION_PERMANENT 0x08

//
// Process Information Classes
//

    typedef enum _PROCESSINFOCLASS {
        ProcessBasicInformation,                // 0x00
        ProcessQuotaLimits,                     // 0x01
        ProcessIoCounters,                      // 0x02
        ProcessVmCounters,                      // 0x03
        ProcessTimes,                           // 0x04
        ProcessBasePriority,                    // 0x05
        ProcessRaisePriority,                   // 0x06
        ProcessDebugPort,                       // 0x07
        ProcessExceptionPort,                   // 0x08
        ProcessAccessToken,                     // 0x09
        ProcessLdtInformation,                  // 0x0A
        ProcessLdtSize,                         // 0x0B
        ProcessDefaultHardErrorMode,            // 0x0C
        ProcessIoPortHandlers,                  // 0x0D Note: this is kernel mode only
        ProcessPooledUsageAndLimits,            // 0x0E
        ProcessWorkingSetWatch,                 // 0x0F
        ProcessUserModeIOPL,                    // 0x10
        ProcessEnableAlignmentFaultFixup,       // 0x11
        ProcessPriorityClass,                   // 0x12
        ProcessWx86Information,                 // 0x13
        ProcessHandleCount,                     // 0x14
        ProcessAffinityMask,                    // 0x15
        ProcessPriorityBoost,                   // 0x16
        ProcessDeviceMap,                       // 0x17
        ProcessSessionInformation,              // 0x18
        ProcessForegroundInformation,           // 0x19
        ProcessWow64Information,                // 0x1A
        ProcessImageFileName,                   // 0x1B
        ProcessLUIDDeviceMapsEnabled,           // 0x1C
        ProcessBreakOnTermination,              // 0x1D
        ProcessDebugObjectHandle,               // 0x1E
        ProcessDebugFlags,                      // 0x1F
        ProcessHandleTracing,                   // 0x20
        ProcessIoPriority,                      // 0x21
        ProcessExecuteFlags,                    // 0x22
        ProcessTlsInformation,
        ProcessCookie,
        ProcessImageInformation,
        ProcessCycleTime,
        ProcessPagePriority,
        ProcessInstrumentationCallback,
        ProcessThreadStackAllocation,
        ProcessWorkingSetWatchEx,
        ProcessImageFileNameWin32,
        ProcessImageFileMapping,
        ProcessAffinityUpdateMode,
        ProcessMemoryAllocationMode,
        ProcessGroupInformation,
        ProcessTokenVirtualizationEnabled,
        ProcessConsoleHostProcess,
        ProcessWindowInformation,
        MaxProcessInfoClass                     // MaxProcessInfoClass should always be the last enum
    } PROCESSINFOCLASS;

    //
    // Thread Information Classes
    //

    typedef enum _THREADINFOCLASS {
        ThreadBasicInformation,                 // 0x00
        ThreadTimes,                            // 0x01
        ThreadPriority,                         // 0x02
        ThreadBasePriority,                     // 0x03
        ThreadAffinityMask,                     // 0x04
        ThreadImpersonationToken,               // 0x05  HANDLE
        ThreadDescriptorTableEntry,             // 0x06  ULONG Selector + LDT_ENTRY
        ThreadEnableAlignmentFaultFixup,        // 0x07
        ThreadEventPair,                        // 0x08
        ThreadQuerySetWin32StartAddress,        // 0x09
        ThreadZeroTlsCell,                      // 0x0A
        ThreadPerformanceCount,                 // 0x0B
        ThreadAmILastThread,                    // 0x0C  ULONG
        ThreadIdealProcessor,                   // 0x0D
        ThreadPriorityBoost,                    // 0x0E
        ThreadSetTlsArrayAddress,               // 0x0F
        MaxThreadInfoClass
    } THREADINFOCLASS;


    typedef struct _RTL_DRIVE_LETTER_CURDIR
    {
        USHORT Flags;
        USHORT Length;
        ULONG  TimeStamp;
        STRING DosPath;

    } RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


    typedef struct _SECTION_IMAGE_INFORMATION
    {
        PVOID TransferAddress;
        ULONG ZeroBits;
        ULONG_PTR MaximumStackSize;
        ULONG_PTR CommittedStackSize;
        ULONG SubSystemType;
        union _SECTION_IMAGE_INFORMATION_u0
        {
            struct _SECTION_IMAGE_INFORMATION_s0
            {
                USHORT SubSystemMinorVersion;
                USHORT SubSystemMajorVersion;
            };
            ULONG SubSystemVersion;
        };
        ULONG GpValue;
        USHORT ImageCharacteristics;
        USHORT DllCharacteristics;
        USHORT Machine;
        BOOLEAN ImageContainsCode;
        BOOLEAN Spare1;
        ULONG LoaderFlags;
        ULONG Reserved[2];

    } SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;


    typedef struct _RTL_USER_PROCESS_INFORMATION
    {
        ULONG Length;
        HANDLE ProcessHandle;
        HANDLE ThreadHandle;
        CLIENT_ID ClientId;
        SECTION_IMAGE_INFORMATION ImageInformation;

    } RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;


    typedef struct _RTL_USER_PROCESS_PARAMETERS
    {
        ULONG MaximumLength;                            // Should be set before call RtlCreateProcessParameters
        ULONG Length;                                   // Length of valid structure
        ULONG Flags;                                    // Currently only PPF_NORMALIZED (1) is known:
                                                        //  - Means that structure is normalized by call RtlNormalizeProcessParameters
        ULONG DebugFlags;

        PVOID ConsoleHandle;                            // HWND to console window associated with process (if any).
        ULONG ConsoleFlags;
        HANDLE StandardInput;
        HANDLE StandardOutput;
        HANDLE StandardError;

        CURDIR CurrentDirectory;                        // Specified in DOS-like symbolic link path, ex: "C:/WinNT/SYSTEM32"
        UNICODE_STRING DllPath;                         // DOS-like paths separated by ';' where system should search for DLL files.
        UNICODE_STRING ImagePathName;                   // Full path in DOS-like format to process'es file image.
        UNICODE_STRING CommandLine;                     // Command line
        PVOID Environment;                              // Pointer to environment block (see RtlCreateEnvironment)
        ULONG StartingX;
        ULONG StartingY;
        ULONG CountX;
        ULONG CountY;
        ULONG CountCharsX;
        ULONG CountCharsY;
        ULONG FillAttribute;                            // Fill attribute for console window
        ULONG WindowFlags;
        ULONG ShowWindowFlags;
        UNICODE_STRING WindowTitle;
        UNICODE_STRING DesktopInfo;                     // Name of WindowStation and Desktop objects, where process is assigned
        UNICODE_STRING ShellInfo;
        UNICODE_STRING RuntimeData;
        RTL_DRIVE_LETTER_CURDIR CurrentDirectores[0x20];

    } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    //
    // Process Environment Block
    //

    typedef struct _PEB_FREE_BLOCK
    {
        struct _PEB_FREE_BLOCK* Next;
        ULONG Size;

    } PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;


    typedef struct _PEB_LDR_DATA
    {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;               // Points to the loaded modules (main EXE usually)
        LIST_ENTRY InMemoryOrderModuleList;             // Points to all modules (EXE and all DLLs)
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID      EntryInProgress;

    } PEB_LDR_DATA, * PPEB_LDR_DATA;


    typedef struct _LDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;                             // Base address of the module
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG  Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        LIST_ENTRY HashLinks;
        PVOID SectionPointer;
        ULONG CheckSum;
        ULONG TimeDateStamp;
        PVOID LoadedImports;
        PVOID EntryPointActivationContext;
        PVOID PatchInformation;
        PVOID Unknown1;
        PVOID Unknown2;
        PVOID Unknown3;

    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


    typedef struct _PEB
    {
        BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
        BOOLEAN ReadImageFileExecOptions;   //
        BOOLEAN BeingDebugged;              //
        BOOLEAN SpareBool;                  //
        HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PVOID FastPebLock;
        PVOID FastPebLockRoutine;
        PVOID FastPebUnlockRoutine;
        ULONG EnvironmentUpdateCount;
        PVOID KernelCallbackTable;
        HANDLE SystemReserved;
        PVOID  AtlThunkSListPtr32;
        PPEB_FREE_BLOCK FreeList;
        ULONG TlsExpansionCounter;
        PVOID TlsBitmap;
        ULONG TlsBitmapBits[2];         // relates to TLS_MINIMUM_AVAILABLE
        PVOID ReadOnlySharedMemoryBase;
        PVOID ReadOnlySharedMemoryHeap;
        PVOID* ReadOnlyStaticServerData;
        PVOID AnsiCodePageData;
        PVOID OemCodePageData;
        PVOID UnicodeCaseTableData;

        //
        // Useful information for LdrpInitialize

        ULONG NumberOfProcessors;
        ULONG NtGlobalFlag;

        //
        // Passed up from MmCreatePeb from Session Manager registry key
        //

        LARGE_INTEGER CriticalSectionTimeout;
        ULONG HeapSegmentReserve;
        ULONG HeapSegmentCommit;
        ULONG HeapDeCommitTotalFreeThreshold;
        ULONG HeapDeCommitFreeBlockThreshold;

        //
        // Where heap manager keeps track of all heaps created for a process
        // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
        // to point to the first free byte after the PEB and MaximumNumberOfHeaps
        // is computed from the page size used to hold the PEB, less the fixed
        // size of this data structure.
        //

        ULONG NumberOfHeaps;
        ULONG MaximumNumberOfHeaps;
        PVOID* ProcessHeaps;

        //
        //
        PVOID GdiSharedHandleTable;
        PVOID ProcessStarterHelper;
        PVOID GdiDCAttributeList;
        PVOID LoaderLock;

        //
        // Following fields filled in by MmCreatePeb from system values and/or
        // image header. These fields have changed since Windows NT 4.0,
        // so use with caution
        //

        ULONG OSMajorVersion;
        ULONG OSMinorVersion;
        USHORT OSBuildNumber;
        USHORT OSCSDVersion;
        ULONG OSPlatformId;
        ULONG ImageSubsystem;
        ULONG ImageSubsystemMajorVersion;
        ULONG ImageSubsystemMinorVersion;
        ULONG ImageProcessAffinityMask;
        ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];

    } PEB, * PPEB;


    //
    // Thread environment block
    //

    typedef struct _TEB
    {
        NT_TIB NtTib;
        PVOID  EnvironmentPointer;
        CLIENT_ID ClientId;
        PVOID ActiveRpcHandle;
        PVOID ThreadLocalStoragePointer;
        PPEB ProcessEnvironmentBlock;
        ULONG LastErrorValue;
        ULONG CountOfOwnedCriticalSections;
        PVOID CsrClientThread;
        PVOID Win32ThreadInfo;
        // Incomplete

    } TEB, * PTEB;


    typedef struct _PROCESS_BASIC_INFORMATION
    {
        LONG ExitStatus;
        PPEB PebBaseAddress;
        ULONG_PTR AffinityMask;
        KPRIORITY BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;

    } PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;


    typedef VOID(NTAPI* PUSER_THREAD_START_ROUTINE)(IN PVOID ApcArgument1);

    NTSYSAPI
        LONG
        NTAPI
        RtlAdjustPrivilege(
            ULONG    Privilege,
            BOOLEAN  Enable,
            BOOLEAN  CurrentThread,
            PBOOLEAN Enabled
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlCreateProcessParameters(
            PRTL_USER_PROCESS_PARAMETERS* ProcessParameters,
            PUNICODE_STRING ImagePathName,
            PUNICODE_STRING DllPath,
            PUNICODE_STRING CurrentDirectory,
            PUNICODE_STRING CommandLine,
            PVOID Environment,
            PUNICODE_STRING WindowTitle,
            PUNICODE_STRING DesktopInfo,
            PUNICODE_STRING ShellInfo,
            PUNICODE_STRING RuntimeData
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlDestroyProcessParameters(
            PRTL_USER_PROCESS_PARAMETERS ProcessParameters
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlCreateUserProcess(
            PUNICODE_STRING NtImagePathName,
            ULONG Attributes,
            PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
            PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
            PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
            HANDLE ParentProcess,
            BOOLEAN InheritHandles,
            HANDLE DebugPort,
            HANDLE ExceptionPort,
            PRTL_USER_PROCESS_INFORMATION ProcessInformation
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlCreateUserThread(
            IN HANDLE Process,
            IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
            IN BOOLEAN CreateSuspended,
            IN ULONG_PTR ZeroBits OPTIONAL,
            IN SIZE_T MaximumStackSize OPTIONAL,
            IN SIZE_T CommittedStackSize OPTIONAL,
            IN PUSER_THREAD_START_ROUTINE StartAddress,
            IN PVOID Parameter OPTIONAL,
            OUT PHANDLE Thread OPTIONAL,
            OUT PCLIENT_ID ClientId OPTIONAL
        );


#define NtCurrentProcess() ((HANDLE) -1)
#define NtCurrentThread()  ((HANDLE) -2)
#define NtCurrentPeb()     (PPEB)(NtCurrentTeb()->ProcessEnvironmentBlock)


    NTSYSAPI
        LONG
        NTAPI
        ZwCreateProcess(
            OUT PHANDLE ProcessHandle,
            IN  ACCESS_MASK DesiredAccess,
            IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
            IN  HANDLE ParentProcess,
            IN  BOOLEAN InheritObjectTable,
            IN  HANDLE SectionHandle OPTIONAL,
            IN  HANDLE DebugPort OPTIONAL,
            IN  HANDLE ExceptionPort OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwOpenProcess(
            OUT PHANDLE ProcessHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes,
            IN PCLIENT_ID ClientId OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwOpenThread(
            OUT PHANDLE ThreadHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes,
            IN PCLIENT_ID ClientId OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQueryInformationProcess(
            IN HANDLE ProcessHandle,
            IN PROCESSINFOCLASS ProcessInformationClass,
            OUT PVOID ProcessInformation,
            IN ULONG ProcessInformationLength,
            OUT PULONG ReturnLength OPTIONAL
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwQueryInformationThread(
            IN HANDLE ThreadHandle,
            IN THREADINFOCLASS ThreadInformationClass,
            OUT PVOID ThreadInformation,
            IN ULONG ThreadInformationLength,
            OUT PULONG ReturnLength OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwSetInformationProcess(
            IN HANDLE ProcessHandle,
            IN PROCESSINFOCLASS ProcessInformationClass,
            IN PVOID ProcessInformation,
            IN ULONG ProcessInformationLength
        );

    NTSYSAPI
        LONG
        NTAPI
        ZwSuspendThread(
            IN HANDLE ThreadHandle,
            OUT PULONG PreviousSuspendCount OPTIONAL
        );

    NTSYSAPI
        LONG
        NTAPI
        ZwResumeThread(
            IN HANDLE ThreadHandle,
            OUT PULONG PreviousSuspendCount OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwTerminateThread(
            HANDLE Thread,
            LONG ExitStatus
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwTerminateProcess(
            HANDLE Process,
            LONG ExitStatus
        );

    //------------------------------------------------------------------------------
    // LPC Functions

#define MAX_LPC_DATA 0x130    // Maximum number of bytes that can be copied through LPC

// Valid values for PORT_MESSAGE::u2::s2::Type
#define LPC_REQUEST                  1
#define LPC_REPLY                    2
#define LPC_DATAGRAM                 3
#define LPC_LOST_REPLY               4
#define LPC_PORT_CLOSED              5
#define LPC_CLIENT_DIED              6
#define LPC_EXCEPTION                7
#define LPC_DEBUG_EVENT              8
#define LPC_ERROR_EVENT              9
#define LPC_CONNECTION_REQUEST      10

#define ALPC_REQUEST            0x2000 | LPC_REQUEST
#define ALPC_CONNECTION_REQUEST 0x2000 | LPC_CONNECTION_REQUEST


//
// Define header for Port Message
//

    typedef struct _PORT_MESSAGE
    {
        union
        {
            struct
            {
                USHORT DataLength;          // Length of data following the header (bytes)
                USHORT TotalLength;         // Length of data + sizeof(PORT_MESSAGE)
            } s1;
            ULONG Length;
        } u1;

        union
        {
            struct
            {
                USHORT Type;
                USHORT DataInfoOffset;
            } s2;
            ULONG ZeroInit;
        } u2;

        union
        {
            CLIENT_ID ClientId;
            double   DoNotUseThisField;     // Force quadword alignment
        };

        ULONG  MessageId;                   // Identifier of the particular message instance

        union
        {
            ULONG_PTR ClientViewSize;       // Size of section created by the sender (in bytes)
            ULONG  CallbackId;              // 
        };

    } PORT_MESSAGE, * PPORT_MESSAGE;

    //
    // Define structure for initializing shared memory on the caller's side of the port
    //

    typedef struct _PORT_VIEW {

        ULONG  Length;                      // Size of this structure
        HANDLE SectionHandle;               // Handle to section object with
                                            // SECTION_MAP_WRITE and SECTION_MAP_READ
        ULONG  SectionOffset;               // The offset in the section to map a view for
                                            // the port data area. The offset must be aligned 
                                            // with the allocation granularity of the system.
        SIZE_T ViewSize;                    // The size of the view (in bytes)
        PVOID  ViewBase;                    // The base address of the view in the creator
                                            // 
        PVOID  ViewRemoteBase;              // The base address of the view in the process
                                            // connected to the port.
    } PORT_VIEW, * PPORT_VIEW;

    //
    // Define structure for shared memory coming from remote side of the port
    //

    typedef struct _REMOTE_PORT_VIEW {

        ULONG  Length;                      // Size of this structure
        SIZE_T ViewSize;                    // The size of the view (bytes)
        PVOID  ViewBase;                    // Base address of the view

    } REMOTE_PORT_VIEW, * PREMOTE_PORT_VIEW;

    //
    // Macro for initializing the message header
    //

#ifndef InitializeMessageHeader
#define InitializeMessageHeader(ph, l, t)                              \
{                                                                      \
    (ph)->u1.s1.TotalLength      = (USHORT)(l);                        \
    (ph)->u1.s1.DataLength       = (USHORT)(l - sizeof(PORT_MESSAGE)); \
    (ph)->u2.s2.Type             = (USHORT)(t);                        \
    (ph)->u2.s2.DataInfoOffset   = 0;                                  \
    (ph)->ClientId.UniqueProcess = NULL;                               \
    (ph)->ClientId.UniqueThread  = NULL;                               \
    (ph)->MessageId              = 0;                                  \
    (ph)->ClientViewSize         = 0;                                  \
}
#endif

/*++

    NtCreatePort
    ============

    Creates a LPC port object. The creator of the LPC port becomes a server
    of LPC communication

    PortHandle - Points to a variable that will receive the
        port object handle if the call is successful.

    ObjectAttributes - Points to a structure that specifies the object’s
        attributes. OBJ_KERNEL_HANDLE, OBJ_OPENLINK, OBJ_OPENIF, OBJ_EXCLUSIVE,
        OBJ_PERMANENT, and OBJ_INHERIT are not valid attributes for a port object.

    MaxConnectionInfoLength - The maximum size, in bytes, of data that can
        be sent through the port.

    MaxMessageLength - The maximum size, in bytes, of a message
        that can be sent through the port.

    MaxPoolUsage - Specifies the maximum amount of NonPaged pool that can be used for
        message storage. Zero means default value.

    ZwCreatePort verifies that (MaxDataSize <= 0x104) and (MaxMessageSize <= 0x148).

--*/


    NTSYSAPI
        LONG
        NTAPI
        ZwCreatePort(
            OUT PHANDLE PortHandle,
            IN  POBJECT_ATTRIBUTES ObjectAttributes,
            IN  ULONG MaxConnectionInfoLength,
            IN  ULONG MaxMessageLength,
            IN  ULONG MaxPoolUsage
        );


    /*++

        NtConnectPort
        =============

        Creates a port connected to a named port (cliend side).

        PortHandle - A pointer to a variable that will receive the client
            communication port object handle value.

        PortName - Points to a structure that specifies the name
            of the port to connect to.

        SecurityQos - Points to a structure that specifies the level
            of impersonation available to the port listener.

        ClientView - Optionally points to a structure describing
            the shared memory region used to send large amounts of data
            to the listener; if the call is successful, this will be updated.

        ServerView - Optionally points to a caller-allocated buffer
            or variable that receives information on the shared memory region
            used by the listener to send large amounts of data to the
            caller.

        MaxMessageLength - Optionally points to a variable that receives the size,
            in bytes, of the largest message that can be sent through the port.

        ConnectionInformation - Optionally points to a caller-allocated
            buffer or variable that specifies connect data to send to the listener,
            and receives connect data sent by the listener.

        ConnectionInformationLength - Optionally points to a variable that
            specifies the size, in bytes, of the connect data to send
            to the listener, and receives the size of the connect data
            sent by the listener.

    --*/


    NTSYSAPI
        LONG
        NTAPI
        ZwConnectPort(
            OUT PHANDLE PortHandle,
            IN  PUNICODE_STRING PortName,
            IN  PSECURITY_QUALITY_OF_SERVICE SecurityQos,
            IN  OUT PPORT_VIEW ClientView OPTIONAL,
            OUT PREMOTE_PORT_VIEW ServerView OPTIONAL,
            OUT PULONG MaxMessageLength OPTIONAL,
            IN  OUT PVOID ConnectionInformation OPTIONAL,
            IN  OUT PULONG ConnectionInformationLength OPTIONAL
        );


    /*++

        NtListenPort
        ============

        Listens on a port for a connection request message on the server side.

        PortHandle - A handle to a port object. The handle doesn't need
            to grant any specific access.

        ConnectionRequest - Points to a caller-allocated buffer
            or variable that receives the connect message sent to
            the port.

    --*/



    NTSYSAPI
        LONG
        NTAPI
        ZwListenPort(
            IN  HANDLE PortHandle,
            OUT PPORT_MESSAGE RequestMessage
        );

    /*++

        NtAcceptConnectPort
        ===================

        Accepts or rejects a connection request on the server side.

        PortHandle - Points to a variable that will receive the port object
            handle if the call is successful.

        PortContext - A numeric identifier to be associated with the port.

        ConnectionRequest - Points to a caller-allocated buffer or variable
            that identifies the connection request and contains any connect
            data that should be returned to requestor of the connection

        AcceptConnection - Specifies whether the connection should
            be accepted or not

        ServerView - Optionally points to a structure describing
            the shared memory region used to send large amounts of data to the
            requestor; if the call is successful, this will be updated

        ClientView - Optionally points to a caller-allocated buffer
            or variable that receives information on the shared memory
            region used by the requestor to send large amounts of data to the
            caller

    --*/



    NTSYSAPI
        LONG
        NTAPI
        ZwAcceptConnectPort(
            OUT PHANDLE PortHandle,
            IN  PVOID PortContext OPTIONAL,
            IN  PPORT_MESSAGE ConnectionRequest,
            IN  BOOLEAN AcceptConnection,
            IN  OUT PPORT_VIEW ServerView OPTIONAL,
            OUT PREMOTE_PORT_VIEW ClientView OPTIONAL
        );


    /*++

        NtCompleteConnectPort
        =====================

        Completes the port connection process on the server side.

        PortHandle - A handle to a port object. The handle doesn't need
            to grant any specific access.

    --*/



    NTSYSAPI
        LONG
        NTAPI
        ZwCompleteConnectPort(
            IN  HANDLE PortHandle
        );


    /*++

        NtRequestPort
        =============

        Sends a request message to a port (client side)

        PortHandle - A handle to a port object. The handle doesn't need
            to grant any specific access.

        RequestMessage - Points to a caller-allocated buffer or variable
            that specifies the request message to send to the port.

    --*/



    NTSYSAPI
        LONG
        NTAPI
        ZwRequestPort(
            IN  HANDLE PortHandle,
            IN  PPORT_MESSAGE RequestMessage
        );

    /*++

        NtRequestWaitReplyPort
        ======================

        Sends a request message to a port and waits for a reply (client side)

        PortHandle - A handle to a port object. The handle doesn't need
            to grant any specific access.

        RequestMessage - Points to a caller-allocated buffer or variable
            that specifies the request message to send to the port.

        ReplyMessage - Points to a caller-allocated buffer or variable
            that receives the reply message sent to the port.

    --*/




    NTSYSAPI
        LONG
        NTAPI
        ZwRequestWaitReplyPort(
            IN  HANDLE PortHandle,
            IN  PPORT_MESSAGE RequestMessage,
            OUT PPORT_MESSAGE ReplyMessage
        );


    /*++

        NtReplyPort
        ===========

        Sends a reply message to a port (Server side)

        PortHandle - A handle to a port object. The handle doesn't need
            to grant any specific access.

        ReplyMessage - Points to a caller-allocated buffer or variable
            that specifies the reply message to send to the port.

    --*/




    NTSYSAPI
        LONG
        NTAPI
        ZwReplyPort(
            IN  HANDLE PortHandle,
            IN  PPORT_MESSAGE ReplyMessage
        );

    /*++

        NtReplyWaitReplyPort
        ====================

        Sends a reply message to a port and waits for a reply message

        PortHandle - A handle to a port object. The handle doesn't need
            to grant any specific access.

        ReplyMessage - Points to a caller-allocated buffer or variable
            that specifies the reply message to send to the port.

    --*/


    NTSYSAPI
        LONG
        NTAPI
        ZwReplyWaitReplyPort(
            IN  HANDLE PortHandle,
            IN  OUT PPORT_MESSAGE ReplyMessage
        );

    /*++

        NtReplyWaitReceivePort
        ======================

        Optionally sends a reply message to a port and waits for a
        message

        PortHandle - A handle to a port object. The handle doesn't need
            to grant any specific access.

        PortContext - Optionally points to a variable that receives
            a numeric identifier associated with the port.

        ReplyMessage - Optionally points to a caller-allocated buffer
            or variable that specifies the reply message to send to the port.

        ReceiveMessage - Points to a caller-allocated buffer or variable
            that receives the message sent to the port.

    --*/

    NTSYSAPI
        LONG
        NTAPI
        ZwReplyWaitReceivePort(
            IN  HANDLE PortHandle,
            OUT PVOID* PortContext OPTIONAL,
            IN  PPORT_MESSAGE ReplyMessage OPTIONAL,
            OUT PPORT_MESSAGE ReceiveMessage
        );

    //-----------------------------------------------------------------------------
    // Heap functions

#define HEAP_NO_SERIALIZE               0x00000001
#define HEAP_GROWABLE                   0x00000002
#define HEAP_GENERATE_EXCEPTIONS        0x00000004
#define HEAP_ZERO_MEMORY                0x00000008
#define HEAP_REALLOC_IN_PLACE_ONLY      0x00000010
#define HEAP_TAIL_CHECKING_ENABLED      0x00000020
#define HEAP_FREE_CHECKING_ENABLED      0x00000040
#define HEAP_DISABLE_COALESCE_ON_FREE   0x00000080
#define HEAP_CREATE_ALIGN_16            0x00010000
#define HEAP_CREATE_ENABLE_TRACING      0x00020000
#define HEAP_MAXIMUM_TAG                0x0FFF
#define HEAP_PSEUDO_TAG_FLAG            0x8000

//
// Data structure for heap definition. This includes various
// sizing parameters and callback routines, which, if left NULL,
// result in default behavior
//

    typedef struct RTL_HEAP_PARAMETERS {
        ULONG Length;        //sizeof(RTL_HEAP_PARAMETERS)
        ULONG SegmentReserve;
        ULONG SegmentCommit;
        ULONG DeCommitFreeBlockThreshold;
        ULONG DeCommitTotalFreeThreshold;
        ULONG MaximumAllocationSize;
        ULONG VirtualMemoryThreshold;
        ULONG InitialCommit;
        ULONG InitialReserve;
        PVOID CommitRoutine;
        ULONG Reserved;
    } RTL_HEAP_PARAMETERS, * PRTL_HEAP_PARAMETERS;


#define RtlProcessHeap() (HANDLE)(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap)


    NTSYSAPI
        HANDLE
        NTAPI
        RtlCreateHeap(
            IN ULONG Flags,
            IN PVOID BaseAddress OPTIONAL,
            IN ULONG SizeToReserve,
            IN ULONG SizeToCommit,
            IN BOOLEAN Lock OPTIONAL,
            IN PRTL_HEAP_PARAMETERS Definition OPTIONAL
        );


    NTSYSAPI
        ULONG
        NTAPI
        RtlDestroyHeap(
            IN HANDLE HeapHandle
        );


    NTSYSAPI
        PVOID
        NTAPI
        RtlAllocateHeap(
            IN HANDLE HeapHandle,
            IN ULONG Flags,
            IN SIZE_T Size
        );


    NTSYSAPI
        PVOID
        NTAPI
        RtlReAllocateHeap(
            IN HANDLE HeapHandle,
            IN ULONG Flags,
            IN LPVOID Address,
            IN SIZE_T Size
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlFreeHeap(
            IN HANDLE HeapHandle,
            IN ULONG Flags,
            IN PVOID Address
        );


    NTSYSAPI
        ULONG
        NTAPI
        RtlCompactHeap(
            IN HANDLE HeapHandle,
            IN ULONG Flags
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlLockHeap(
            IN HANDLE HeapHandle
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlUnlockHeap(
            IN HANDLE HeapHandle
        );


    NTSYSAPI
        ULONG
        NTAPI
        RtlSizeHeap(
            IN HANDLE HeapHandle,
            IN ULONG Flags,
            IN PVOID Address
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlValidateHeap(
            IN HANDLE HeapHandle,
            IN ULONG Flags,
            IN PVOID Address OPTIONAL
        );


    //-----------------------------------------------------------------------------
    // Virtual memory functions

    typedef enum _MEMORY_INFORMATION_CLASS
    {
        MemoryBasicInformation,                 // 0x00 MEMORY_BASIC_INFORMATION
        MemoryWorkingSetInformation,            // 0x01
        MemoryMappedFilenameInformation,        // 0x02 UNICODE_STRING
        MemoryRegionInformation,                // 0x03
        MemoryWorkingSetExInformation           // 0x04

    } MEMORY_INFORMATION_CLASS;


    NTSYSAPI
        LONG
        NTAPI
        ZwAllocateVirtualMemory(
            IN HANDLE ProcessHandle,
            IN OUT PVOID* BaseAddress,
            IN ULONG ZeroBits,
            IN OUT PSIZE_T RegionSize,
            IN ULONG AllocationType,
            IN ULONG Protect
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwFreeVirtualMemory(
            IN HANDLE ProcessHandle,
            IN OUT PVOID* BaseAddress,
            IN OUT PSIZE_T RegionSize,
            IN ULONG FreeType
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwProtectVirtualMemory(
            IN HANDLE ProcessHandle,
            IN OUT PVOID* BaseAddress,
            IN OUT PSIZE_T RegionSize,
            IN ULONG NewProtect,
            OUT PULONG OldProtect
        );

    NTSYSAPI
        LONG
        NTAPI
        ZwReadVirtualMemory(
            IN HANDLE ProcessHandle,
            IN PVOID BaseAddress,
            OUT PVOID Buffer,
            IN ULONG BufferSize,
            OUT PULONG NumberOfBytesRead OPTIONAL
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwWriteVirtualMemory(
            IN HANDLE ProcessHandle,
            IN PVOID BaseAddress,
            IN PVOID Buffer,
            IN ULONG BufferSize,
            OUT PULONG NumberOfBytesWritten OPTIONAL
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwFlushVirtualMemory(
            IN HANDLE ProcessHandle,
            IN OUT PVOID* BaseAddress,
            IN OUT PSIZE_T RegionSize,
            OUT PIO_STATUS_BLOCK IoStatus
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwQueryVirtualMemory(
            IN HANDLE ProcessHandle,
            IN PVOID BaseAddress,
            IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
            OUT PVOID MemoryInformation,
            IN SIZE_T MemoryInformationLength,
            OUT PSIZE_T ReturnLength OPTIONAL
        );

    //-----------------------------------------------------------------------------
    // Section functions

    typedef enum _SECTION_INHERIT
    {
        ViewShare = 1,
        ViewUnmap = 2

    } SECTION_INHERIT;


    typedef enum _SECTION_INFORMATION_CLASS
    {
        SectionBasicInformation,
        SectionImageInformation

    } SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;


    /*++

        NtCreateSection
        ===============

        Creates a section object.

        SectionHandle - Points to a variable that will receive the section
            object handle if the call is successful.

        DesiredAccess - Specifies the type of access that the caller requires
            to the section object. This parameter can be zero, or any combination
            of the following flags:

            SECTION_QUERY       - Query access
            SECTION_MAP_WRITE   - Can be written when mapped
            SECTION_MAP_READ    - Can be read when mapped
            SECTION_MAP_EXECUTE - Can be executed when mapped
            SECTION_EXTEND_SIZE - Extend access
            SECTION_ALL_ACCESS  - All of the preceding +
                                  STANDARD_RIGHTS_REQUIRED

        ObjectAttributes - Points to a structure that specifies the object’s attributes.
            OBJ_OPENLINK is not a valid attribute for a section object.

        MaximumSize - Optionally points to a variable that specifies the size,
            in bytes, of the section. If FileHandle is zero, the size must be
            specified; otherwise, it can be defaulted from the size of the file
            referred to by FileHandle.

        SectionPageProtection - The protection desired for the pages
            of the section when the section is mapped. This parameter can take
            one of the following values:

            PAGE_READONLY
            PAGE_READWRITE
            PAGE_WRITECOPY
            PAGE_EXECUTE
            PAGE_EXECUTE_READ
            PAGE_EXECUTE_READWRITE
            PAGE_EXECUTE_WRITECOPY

        AllocationAttributes - The attributes for the section. This parameter must
            be a combination of the following values:

            SEC_BASED     0x00200000    // Map section at same address in each process
            SEC_NO_CHANGE 0x00400000    // Disable changes to protection of pages
            SEC_IMAGE     0x01000000    // Map section as an image
            SEC_VLM       0x02000000    // Map section in VLM region
            SEC_RESERVE   0x04000000    // Reserve without allocating pagefile storage
            SEC_COMMIT    0x08000000    // Commit pages; the default behavior
            SEC_NOCACHE   0x10000000    // Mark pages as non-cacheable

        FileHandle - Identifies the file from which to create the section object.
            The file must be opened with an access mode compatible with the protection
            flags specified by the Protect parameter. If FileHandle is zero,
            the function creates a section object of the specified size backed
            by the paging file rather than by a named file in the file system.

    --*/

    NTSYSAPI
        LONG
        NTAPI
        ZwCreateSection(
            OUT PHANDLE SectionHandle,
            IN  ACCESS_MASK DesiredAccess,
            IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
            IN  PLARGE_INTEGER MaximumSize OPTIONAL,
            IN  ULONG SectionPageProtection,
            IN  ULONG AllocationAttributes,
            IN  HANDLE FileHandle OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwOpenSection(
            OUT PHANDLE SectionHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes
        );

    NTSYSAPI
        LONG
        NTAPI
        ZwMapViewOfSection(
            IN HANDLE SectionHandle,
            IN HANDLE ProcessHandle,
            IN OUT PVOID* BaseAddress,
            IN ULONG ZeroBits,
            IN ULONG CommitSize,
            IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
            IN OUT PULONG ViewSize,
            IN SECTION_INHERIT InheritDisposition,
            IN ULONG AllocationType,
            IN ULONG Protect
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwUnmapViewOfSection(
            IN HANDLE ProcessHandle,
            IN PVOID BaseAddress
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwExtendSection(
            IN HANDLE SectionHandle,
            IN OUT PLARGE_INTEGER SectionSize
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwQuerySection(
            IN HANDLE SectionHandle,
            IN SECTION_INFORMATION_CLASS SectionInformationClass,
            OUT PVOID SectionInformation,
            IN ULONG Length,
            OUT PULONG ResultLength OPTIONAL
        );


    //-----------------------------------------------------------------------------
    // Synchronization

    //
    // Wait type
    //

    typedef enum _WAIT_TYPE {
        WaitAll,
        WaitAny
    } WAIT_TYPE;




      NTSYSAPI
        LONG
        NTAPI
        ZwWaitForSingleObject(
            IN HANDLE Handle,
            IN BOOLEAN Alertable,
            IN PLARGE_INTEGER Timeout OPTIONAL
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwWaitForMultipleObjects(
            IN ULONG Count,
            IN HANDLE Handle[],
            IN WAIT_TYPE WaitType,
            IN BOOLEAN Alertable,
            IN PLARGE_INTEGER Timeout OPTIONAL
        );


    //-----------------------------------------------------------------------------
    // Event support

    typedef enum _EVENT_INFORMATION_CLASS {
        EventBasicInformation    // = 0
    } EVENT_INFORMATION_CLASS;

    typedef struct _EVENT_BASIC_INFORMATION {
        EVENT_TYPE EventType;
        LONG EventState;
    } EVENT_BASIC_INFORMATION, * PEVENT_BASIC_INFORMATION;

    //
    // Event handling routines
    //


    NTSYSAPI
        LONG
        NTAPI
        ZwCreateEvent(
            OUT PHANDLE EventHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
            IN EVENT_TYPE EventType,
            IN BOOLEAN InitialState
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwClearEvent(
            IN HANDLE Handle
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwPulseEvent(
            IN HANDLE Handle,
            OUT PLONG PreviousState OPTIONAL
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwResetEvent(
            IN HANDLE Handle,
            OUT PLONG PreviousState OPTIONAL
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwSetEvent(
            IN HANDLE Handle,
            OUT PLONG PreviousState OPTIONAL
        );



    NTSYSAPI
        LONG
        NTAPI
        ZwOpenEvent(
            OUT PHANDLE EventHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes
        );




    NTSYSAPI
        LONG
        NTAPI
        ZwQueryEvent(
            IN HANDLE EventHandle,
            IN EVENT_INFORMATION_CLASS EventInfoClass,
            OUT PVOID EventInfo,
            IN ULONG Length,
            OUT PULONG ResultLength OPTIONAL
        );


    //-----------------------------------------------------------------------------
    // Mutant support

    NTSYSAPI
        LONG
        NTAPI
        ZwCreateMutant(
            OUT PHANDLE MutantHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
            IN BOOLEAN InitialOwner
        );

    NTSYSAPI
        LONG
        NTAPI
        ZwOpenMutant(
            OUT PHANDLE MutantHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
        );

    //-----------------------------------------------------------------------------
    // Semaphore support

    NTSYSAPI
        LONG
        NTAPI
        ZwCreateSemaphore(
            OUT PHANDLE SemaphoreHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
            IN ULONG InitialCount,
            IN ULONG MaximumCount
        );

    NTSYSAPI
        LONG
        NTAPI
        ZwOpenSemaphore(
            OUT PHANDLE SemaphoreHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
        );

    //-----------------------------------------------------------------------------
    // EventPair support

#define EVENT_PAIR_ALL_ACCESS ( STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE )

    NTSYSAPI
        LONG
        NTAPI
        ZwCreateEventPair(
            OUT PHANDLE EventPairHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwOpenEventPair(
            OUT PHANDLE EventPairHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
        );


    //-----------------------------------------------------------------------------
    // Security descriptor functions

    NTSYSAPI
        LONG
        NTAPI
        RtlCreateSecurityDescriptor(
            IN PSECURITY_DESCRIPTOR SecurityDescriptor,
            IN ULONG Revision
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlGetDaclSecurityDescriptor(
            IN PSECURITY_DESCRIPTOR  SecurityDescriptor,
            OUT PBOOLEAN  DaclPresent,
            OUT PACL* Dacl,
            OUT PBOOLEAN  DaclDefaulted
        );

    NTSYSAPI
        LONG
        NTAPI
        RtlSetDaclSecurityDescriptor(
            IN PSECURITY_DESCRIPTOR SecurityDescriptor,
            IN BOOLEAN DaclPresent,
            IN PACL Dacl OPTIONAL,
            IN BOOLEAN DaclDefaulted OPTIONAL
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlSetOwnerSecurityDescriptor(
            IN PSECURITY_DESCRIPTOR SecurityDescriptor,
            IN PSID Owner OPTIONAL,
            IN BOOLEAN OwnerDefaulted OPTIONAL
        );


    NTSYSAPI
        long
        NTAPI
        RtlAllocateAndInitializeSid(
            IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
            IN UCHAR SubAuthorityCount,
            IN ULONG SubAuthority0,
            IN ULONG SubAuthority1,
            IN ULONG SubAuthority2,
            IN ULONG SubAuthority3,
            IN ULONG SubAuthority4,
            IN ULONG SubAuthority5,
            IN ULONG SubAuthority6,
            IN ULONG SubAuthority7,
            OUT PSID* Sid
        );


    NTSYSAPI
        long
        NTAPI
        RtlLengthSid(
            IN PSID Sid
        );


    NTSYSAPI
        BOOLEAN
        NTAPI
        RtlEqualSid(
            IN PSID Sid1,
            IN PSID Sid2
        );


    NTSYSAPI
        PVOID
        NTAPI
        RtlFreeSid(
            IN PSID Sid
        );


    NTSYSAPI
        long
        NTAPI
        RtlCreateAcl(
            IN PACL Acl,
            IN ULONG AclLength,
            IN ULONG AclRevision
        );


    NTSYSAPI
        long
        NTAPI
        RtlGetAce(
            IN PACL Acl,
            IN ULONG AceIndex,
            OUT PVOID* Ace
        );


    NTSYSAPI
        long
        NTAPI
        RtlAddAccessAllowedAce(
            IN OUT PACL Acl,
            IN ULONG AceRevision,
            IN ACCESS_MASK AccessMask,
            IN PSID Sid
        );


    NTSYSAPI
        long
        NTAPI
        RtlAddAccessAllowedAceEx(
            IN OUT PACL Acl,
            IN ULONG AceRevision,
            IN ULONG AceFlags,
            IN ULONG AccessMask,
            IN PSID Sid
        );

    //-----------------------------------------------------------------------------
    // Token functions

    NTSYSAPI
        long
        NTAPI
        ZwOpenProcessToken(
            IN HANDLE ProcessHandle,
            IN ACCESS_MASK DesiredAccess,
            OUT PHANDLE TokenHandle
        );


    NTSYSAPI
        long
        NTAPI
        ZwOpenThreadToken(
            IN HANDLE ThreadHandle,
            IN ACCESS_MASK DesiredAccess,
            IN BOOLEAN OpenAsSelf,
            OUT PHANDLE TokenHandle
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQueryInformationToken(
            IN HANDLE  TokenHandle,
            IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
            OUT PVOID  TokenInformation,
            IN ULONG  TokenInformationLength,
            OUT PULONG  ReturnLength
        );

    NTSYSAPI
        LONG
        NTAPI
        ZwSetInformationToken(
            IN HANDLE  TokenHandle,
            IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
            IN PVOID  TokenInformation,
            IN ULONG  TokenInformationLength
        );


    NTSYSAPI
        LONG
        NTAPI
        NtAdjustPrivilegesToken(
            IN HANDLE TokenHandle,
            IN BOOLEAN DisableAllPrivileges,
            IN PTOKEN_PRIVILEGES NewState OPTIONAL,
            IN ULONG BufferLength OPTIONAL,
            IN PTOKEN_PRIVILEGES PreviousState OPTIONAL,
            OUT PULONG ReturnLength
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwDuplicateToken(
            IN HANDLE ExistingTokenHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes,
            IN BOOLEAN EffectiveOnly,
            IN TOKEN_TYPE TokenType,
            OUT PHANDLE NewTokenHandle
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwCompareTokens(
            IN  HANDLE FirstTokenHandle,
            IN  HANDLE SecondTokenHandle,
            OUT PBOOLEAN IdenticalTokens
        );


    //-----------------------------------------------------------------------------
    // Symbolic links

    //
    // Object Manager Symbolic Link Specific Access Rights.
    //

#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY (0x0001)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#endif

    NTSYSAPI
        LONG
        NTAPI
        ZwCreateSymbolicLinkObject(
            OUT PHANDLE SymbolicLinkHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes,
            IN PUNICODE_STRING DestinationName
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwOpenSymbolicLinkObject(
            OUT PHANDLE SymbolicLinkHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwQuerySymbolicLinkObject(
            IN HANDLE SymbolicLinkHandle,
            OUT PUNICODE_STRING NameString,
            OUT PULONG ResultLength OPTIONAL
        );

    //-----------------------------------------------------------------------------
    // Loader functions

    typedef struct _LDR_RESOURCE_INFO
    {
        ULONG_PTR Type;
        ULONG_PTR Name;
        ULONG_PTR Language;
    } LDR_RESOURCE_INFO, * PLDR_RESOURCE_INFO;

    typedef struct _LDR_ENUM_RESOURCE_INFO
    {
        ULONG_PTR Type;
        ULONG_PTR Name;
        ULONG_PTR Language;
        PVOID Data;
        SIZE_T Size;
        ULONG_PTR Reserved;
    } LDR_ENUM_RESOURCE_INFO, * PLDR_ENUM_RESOURCE_INFO;

    NTSYSAPI
        LONG
        NTAPI
        LdrLoadDll(
            IN PWSTR DllPath OPTIONAL,
            IN PULONG DllCharacteristics OPTIONAL,
            IN PUNICODE_STRING DllName,
            OUT PVOID* DllHandle
        );

    NTSYSAPI
        LONG
        NTAPI
        LdrGetDllHandle(
            IN PWSTR DllPath OPTIONAL,
            IN PULONG DllCharacteristics OPTIONAL,
            IN PUNICODE_STRING DllName,
            OUT PVOID* DllHandle
        );

    NTSYSAPI
        LONG
        NTAPI
        LdrUnloadDll(
            IN PVOID DllHandle
        );

    NTSYSAPI
        LONG
        NTAPI
        LdrGetProcedureAddress(
            IN PVOID DllHandle,
            IN PANSI_STRING ProcedureName OPTIONAL,
            IN ULONG ProcedureNumber OPTIONAL,
            OUT PVOID* ProcedureAddress
        );

    LONG
        NTAPI
        LdrAccessResource(
            IN PVOID BaseAddress,
            IN PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry,
            OUT PVOID* Resource OPTIONAL,
            OUT PULONG Size OPTIONAL
        );

    LONG
        NTAPI
        LdrFindResource_U(
            IN PVOID BaseAddress,
            IN PLDR_RESOURCE_INFO ResourceInfo,
            IN ULONG Level,
            OUT PIMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry
        );

    LONG
        NTAPI
        LdrFindResourceDirectory_U(
            IN PVOID BaseAddress,
            IN PLDR_RESOURCE_INFO ResourceInfo,
            IN ULONG Level,
            OUT PIMAGE_RESOURCE_DIRECTORY* ResourceDirectory
        );

    //-----------------------------------------------------------------------------
    // Driver functions


    NTSYSAPI
        LONG
        NTAPI
        ZwLoadDriver(
            PUNICODE_STRING DriverServiceName
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwUnloadDriver(
            PUNICODE_STRING DriverServiceName
        );

    //-----------------------------------------------------------------------------
    // Functions dealing with NTSTATUS and Win32 error

    NTSYSAPI
        ULONG
        NTAPI
        RtlNtStatusToDosError(
            LONG Status
        );


    NTSYSAPI
        ULONG
        NTAPI
        RtlNtStatusToDosErrorNoTeb(
            LONG Status
        );


    NTSYSAPI
        LONG
        NTAPI
        RtlGetLastNtStatus(
        );


    NTSYSAPI
        ULONG
        NTAPI
        RtlGetLastWin32Error(
        );


    NTSYSAPI
        VOID
        NTAPI
        RtlSetLastWin32Error(
            ULONG WinError
        );


    NTSYSAPI
        VOID
        NTAPI
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
            LONG Status
        );

    ULONG NTAPI RtlComputeCrc32(IN ULONG 	Initial,
        IN PUCHAR 	Data,
        IN ULONG 	Length
    );



    //-----------------------------------------------------------------------------
    // Other functions

    NTSYSAPI
        LONG
        NTAPI
        ZwAllocateLocallyUniqueId(
            OUT PLUID LocallyUniqueId
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwDelayExecution(
            IN BOOLEAN Alertable,
            IN PLARGE_INTEGER DelayInterval
        );


    NTSYSAPI
        LONG
        NTAPI
        ZwDisplayString(
            IN PUNICODE_STRING String
        );

    typedef struct _TIME_FIELDS
    {
        SHORT Year;
        SHORT Month;
        SHORT Day;
        SHORT Hour;
        SHORT Minute;
        SHORT Second;
        SHORT Milliseconds;
        SHORT Weekday;
    } TIME_FIELDS, * PTIME_FIELDS;

    VOID NTAPI RtlTimeToTimeFields(
        PLARGE_INTEGER Time,
        PTIME_FIELDS   TimeFields
    );

    BOOLEAN NTAPI RtlTimeFieldsToTime(
        PTIME_FIELDS   TimeFields,
        PLARGE_INTEGER Time
    );

    LONG NTAPI RtlSystemTimeToLocalTime
    (
        const LARGE_INTEGER* SystemTime,
        PLARGE_INTEGER       LocalTime
    );

    LONG NTAPI RtlLocalTimeToSystemTime(PLARGE_INTEGER localft,
        PLARGE_INTEGER utcft);

    LONG NTAPI ZwQuerySystemTime(OUT PLARGE_INTEGER CurrentTime);

    LONG NTAPI RtlGetCompressionWorkSpaceSize(
        USHORT CompressionFormatAndEngine,
        PULONG CompressBufferWorkSpaceSize,
        PULONG CompressFragmentWorkSpaceSize
    );

    typedef struct _RTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _RTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

    typedef struct _DEBUG_BUFFER {
        HANDLE SectionHandle;
        PVOID SectionBase;
        PVOID RemoteSectionBase;
        ULONG SectionBaseDelta;
        HANDLE EventPairHandle;
        ULONG Unknown[2];
        HANDLE RemoteThreadHandle;
        ULONG InfoClassMask;
        ULONG SizeOfInfo;
        ULONG AllocatedSize;
        ULONG SectionSize;
        PVOID ModuleInformation;
        PVOID BackTraceInformation;
        PVOID HeapInformation;
        PVOID LockInformation;
        PVOID Reserved[8];
    } DEBUG_BUFFER, * PDEBUG_BUFFER;


    PDEBUG_BUFFER
        NTAPI
        RtlCreateQueryDebugBuffer(
            IN ULONG Size,
            IN BOOLEAN EventPair
        );


    LONG
        NTAPI
        RtlQueryProcessDebugInformation(
            IN ULONG ProcessId,
            IN ULONG DebugInfoClassMask,
            IN OUT PDEBUG_BUFFER DebugBuffer
        );

    LONG
        NTAPI
        RtlDestroyQueryDebugBuffer(
            IN PDEBUG_BUFFER DebugBuffer
        );

    LONG  NTAPI RtlHashUnicodeString(
        PCUNICODE_STRING String,
        BOOLEAN          CaseInSensitive,
        ULONG            HashAlgorithm,
        PULONG           HashValue
    );

    typedef struct _DEBUG_MODULE_INFORMATION { // c.f. SYSTEM_MODULE_INFORMATION
        ULONG Reserved[2];
        ULONG Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT ModuleNameOffset;
        CHAR ImageName[256];
    } DEBUG_MODULE_INFORMATION, * PDEBUG_MODULE_INFORMATION;

#define PDI_MODULES 0x01


    LONG
        NTAPI
        ZwImpersonateThread(



            IN HANDLE               ThreadHandle,
            IN HANDLE               ThreadToImpersonate,
            IN PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);


    LONG NTAPI ZwYieldExecution(VOID);


    static const ULONG CrcTable[256] =
    {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
        0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
        0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
        0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
        0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
        0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
        0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
        0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
        0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
        0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
        0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
        0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
        0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
        0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
        0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
        0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
        0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
        0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    };

    ULONG NTAPI _RtlComputeCrc32(ULONG Initial, PUCHAR Data, ULONG Length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // __NTDLL_H__
#pragma once
