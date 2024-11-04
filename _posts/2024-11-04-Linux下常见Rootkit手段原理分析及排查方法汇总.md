---
layout:       post
title:        "Linux下常见Rootkit手段原理分析及排查方法汇总"
subtitle:     "深入分析linux下常见rootkit手段原理，提供相关排查思路"
author:      "Ga0weI"
header-style: text
catalog:      true
tags:
    - Linux
    - 应急
    - Rootkit
    - 内核
    - 影藏
---



此文为作者原创，首发于[奇安信攻防社区](https://forum.butian.net/share/3796)：

# 0x01 前言

本文主要针对黑灰产、以及蠕木僵毒等恶意软件在linux上常用的rootkit手段做一些总结，以及详细分析常见应急响应中遇到的进程、文件隐藏手段的原理以及排查和恢复方法；

从技术实现原理上看，笔者把其常见的rootkit隐藏手段大致分为五大类：

>1、通过文件挂载实现隐藏
>
>2、通过用户层劫持链接器或链接库实现隐藏
>
>3、通过劫持系统环境变量，劫持相关命令，从而实现对影藏
>
>4、通过内核层劫持实现隐藏
>
>5、通过ebpf完成的动态劫持内核逻辑实现隐藏

# 0x02 实现

## 一、通过挂载/proc/pid实现pid隐藏

### 原理

ps 、netstat 是遍历/proc 来显示pid的原理，通过隐藏相关 /proc/pid 文件夹来实现pid隐藏

### 实现

运行如下命令，将pid对应文件夹挂载到隐藏目录上面

 ``mount -o bind /home/.hidden /proc/9212``

### 现象：

如下图，使用root权限调用 netstat 发现 PID和Programname 都是空：

![image-20240429165453901](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429165453901.png)

### 排查方法

1、``cat /proc/$$/mountinfo``

``cat /proc/$$/mountinfo``，发现/proc/9212被挂载到了一个.开头的隐藏文件里面

![image-20240429171202234](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429171202234.png)

2、 ``ls -lai /proc``

在/proc下使用ls -lai:可以发现一个异常的pid目录，异常大小

![image-20240429171934768](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429171934768.png)

### 解除方法

使用umount 解除挂载

``umount /proc/9212``

## 二、通过用户层劫持加载器/连接器隐藏进程pld（用户层rootkit）

### 原理

linux在进程启动后，和windows加载dll一样会按照一定的顺序加载动态链接库，相关顺序如下：

- 加载环境变量``LD_PRELOAD``指定的动态库
- 加载文件``/etc/ld.so.preload``指定的动态库
- 搜索环境变量``LD_LIBRARY_PATH``指定的动态库搜索路径
- 搜索路径``/lib64``下的动态库文件

攻击者常见使用的劫持方式大致存在以下三种：

1、可以通过``LD_PRELOAD`` 最先被加载的特征，攻击者写一些so文件，在这个so文件里面实现一些本来对应命令要使用的函数，运行相应命令会先从该环境变量中加载我们自定义的so文件，从而劫持相应命令对应的函数，实现恶意的逻辑；

2、利用``/etc/ld.so.preload``是系统的默认ld预加载路径，攻击者可以写一些so文件，在这个so文件里面实现一些本来对应命令要使用的函数，然后把恶意so文件的路径写入该文件内容中，从而劫持相应命令对应的函数，实现恶意的逻辑；

3、利用linux基本都是基于glibc的特征，大部分的动态连接的基础文件都是基于几个常见的so文件，比如libc.so.6，Linux下命令的动态链接中基本上都会使用这个so文件，因为这个so文件实现了各种标准C的各种函数。对于GCC而言，默认情况下，所编译的程序中对标准C函数的链接，都是通过动态链接方式来链接libc.so.6这个函数库的；所以这里攻击者可以替换劫持该so文件，从而实现对linux的几乎所有依靠动态连接的命令的劫持；



拿第二种方式举例：

回到这个进程pid的隐藏，``ps\top\netstat``等命令是通过读取遍历/proc/pid内容来返回对应的pid等相关值的，读取文件目录底层是通过 readdir/readdir64 实现，这里我们可以利用ld预加载特性，编写恶意的so文件，在相关文件里面重写上面两个函数，在相关函数中当特殊名称的进程出现的时候，相关函数不做返回，或者返回为空跳过即可，并将路径添加到``/etc/ld.so.preload``中；



该操作对ps的隐藏效果最好，因为ps的所有结果都是完全依赖于 /proc/pid 来获取内容；netstat的话是部分依赖，仅仅获取不到pid和pname（这也是一般netstat能看到网络连接，但是看不到对应的pid和进程名的原因），其他的能拿到的；



参考项目
https://github.com/gianlucaborello/libprocesshider

### 实现：

拿第二种方式举例：

使用上面项目编译生成的.so文件放入受害机器；

修改processhider.c文件里面的process_to_filter 参数，后面修改成要隐藏的进程：

![image-20240429200133367](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429200133367.png)

这个想要通过preload加载，也有好几种方式（1、修改$LD_PRELOAD 环境变量，添加so文件路径；2、创建/etc/ld.so.preload文件并写如对应so文件路径；3、修改动态链接器，一般来说动态链接器里面默认使用的路径是/etc/ld.so.preload，这里可以通过篡改动态连接器，修改文件路径，从而系统就会去新文件路径里面去找so文件加载），这里我们选择在受害机器的``/etx/ld.so.preload``文件中添加对应路径，如下：

![image-20240429195810418](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429195810418.png)

然后这里我们模拟一个叫1234567.py的进程（这个在编译上面.so文件的时候要把这个名称写入），该进程源码如下：就是发起socket连接101.1.1.1:43端口：

```python
import socket


def send_tcp_request(ip, port, message):
    try:
        # 创建一个TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 连接到指定的IP和端口
        sock.connect((ip, port))
        sock.settimeout(100)

        sock.sendall(message.encode())

        # 接收服务器返回的数据
        received_data = sock.recv(1024)
        print("Received:", received_data.decode())

    except socket.error as e:
        print("Socket error:", e)
    finally:
        # 关闭socket连接
        sock.close()


# 测试代码
if __name__ == "__main__":
    ip = '101.1.1.1'  # 要连接的IP地址
    port = 43  # 要连接的端口号
    message = "Hello, server!"  # 要发送的消息
    send_tcp_request(ip, port, message)

```



运行进程：

![image-20240429200243004](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429200243004.png)

### 现象

使用``netstat -pantu``,如下可以看到这里是发现了网络连接，但是没有pid和pname：

![image-20240429200322194](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429200322194.png)

使用ps命令，即使是在知道了被隐藏了进程的名称情况下，也查不到对应的进程：

![image-20240429200840390](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429200840390.png)

### 针对原理的排查方法

1、``echo $LD_PRELOAD``（排查上述原理中第一种实现方式）

查看环境变量是否被劫持，如果存在劫持情况，``unset LD_PRELOAD``，并且删除查出来的对应so文件

2、``cat /etc/ld.so.preload``文件，一般情况下是没有这个文件，或者是有这个文件但是文件内容为空，如果出现内容要重点排查；（排查上述原理中第二种实现方式）

如下图是被劫持的情况：

![image-20240429201633699](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429201633699.png)

3、排查系统的动态连接器是否被劫持，也就是最后不会去/etc/ld.so.preload加载，而是去指定的地方加载（排查上述原理中类似第三种实现方式，替换libc.so.6，但是仅仅是修改了里面默认的内置ld连接文件的位置（这点笔者没有去核实，该路径可能不是在libc.so.6里面的，是其他通用so里面，但是排查方式都是校验完整性和hash））

```
下图先找到命令的二进制文件，然后通过readelf读取其文件头中设置的链接器，然后判断链接器是否被改动
```

![image-20240429203304276](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429203304276.png)

通过时间判断是否动态连接器是否有问题：

![image-20240429203404270](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429203404270.png)

通过rpm来校验是否有问题，这个就是通过hash去判断的，如果前面几个字符中没有出现5 就说明md5没有变动，如下图是未发现 ld-2.17.so文件发生了变动

![image-20240429203454427](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429203454427.png)

### 快速排查的思路：

当发现有问题，进程被隐藏了，建议可以直接使用如下方法快速排查：

1、排查指定命令的动态链接库依赖，从上到下逐一排查so文件是否有问题

``ldd /usr/bin/ps``
如下：
![image-20240429212319942](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429212319942.png)

2、直接使用 strace 命令 追踪 相关命令对文件的操作，ps进程执行的所有操作都会被记录，然后再去看是否存在可疑操作，打开了可疑的so文件等，从而判断问题出在哪个so文件

``strace -o result.txt -e trace=file -f ps``

效果如下：

![image-20240429205457642](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429205457642.png)



### 解除方法

1、如果是环境变量劫持LD_PRELOAD 那就清空LD_PRELOAD，删除劫持的恶意so文件；

unset LD_PRELOAD

2、如果是ld.so.preload劫持，删除 /etc/ld.so.preload里面的劫持内容，删除劫持的恶意so文件；

直接删除ld.so.preload文件也可以

3、如果链接器被篡改了，那就重下载，替换回来；

### 快速排查获取隐藏的pid方法：

1、以其人之道还治其人之身，劫持攻击者的劫持，那么程序就会调用我们的劫持，通过强行指定一个LD_PRELOAD环境变量 去执行对应的命令，如果我们怀疑readdir这个函数被劫持了，那么只要我们指定的LD_PRELOAD实现了readdir这个函数那么就能解除劫持，需要注意的是先要校验我们指定的so有没有被劫持，

![image-20240429213913548](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240429213913548.png)

上面使用的是/lib64/libc.so.6，如下在其导出表里面可以看到其实现了readdir64，所以可以解除劫持

![image-20240430113912688](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240430113912688.png)

2、上传一个busybox，busybox是使用静态连接编译而成的，不会被动态链接相关机制劫持；所以直接使用busybox，可以绕过动态链接机制，拿到pid和pname；


## 三、通过劫持shell环境，实现文件、进程名隐藏等操作

```
/etc/rc.loacl  //系统启动时运行的脚本
/etc/profile.d  //其下的脚本可以为所有用户设置特定的环境变量
/etc/init.d //
```

### 原理

修改或构造``/etc/profile.d/`` 下sh文件，劫持环境变量，从而实现覆盖常见的命令，如：ps、ls、lsof等；
### 实现：
1、配置环境变量 shell脚本：
![](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/Pasted%20image%2020240822120328.png)

重新登录用户之后；或者使用命令``source /etc/profile`` 更新配置，使生效；
2、根目录下存在的myshell.sh文件被隐藏：
执行ls命令效果：
![](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/Pasted%20image%2020240822120513.png)
``ls -lai`` 也一样被隐藏
![](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/Pasted%20image%2020240822120603.png)

### 排查方法：
使用strace 调用执行ls，strace 里面调用ls属于非交互式shell命令执行，不会使用这个被劫持的shell环境
![](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/Pasted%20image%2020240822120739.png)

### 解除方法：

排查	``/etc/profile.d/``发现可疑的环境变量设置脚本文件，删除后，重新登录系统生效，或者手动执行重新加载profile:``source /etc/profile``生效；





## 四、通过LKM 劫持相关函数实现pid隐藏（LKM rootkit）
### 原理
内核层函数劫持，通过hook更为底层的内核函数，从而对底层使用了相关内核函数的命令进程劫持，从而实现pid隐藏；如下是较为常见的劫持访问：

- 修改Syscall表 参考项目：https://github.com/m0nad/Diamorphine

关键代码如下图：其实现通过修改syscall表中的``getdents/getdents64/kill``三个函数地址，劫持三个函数

![image-20240505233104796](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240505233104796.png)



还有一些其他的手段实现内核劫持，如：

- 利用Kprobes ，其是 Linux 内核中的一项动态检测功能，允许开发人员在内核代码路径中的特定点插入自定义代码（探针）。这些探针旨在用于调试、分析、跟踪和收集有关内核行为的运行时信息，而无需修改实际内核代码。

  https://github.com/f0rb1dd3n/Reptile

- 利用Ftrace ，其是 Linux 内核中的内置跟踪框架，它提供了用于收集和分析有关内核行为和性能的不同类型的运行时信息的工具和基础设施。它旨在帮助开发人员和系统管理员了解内核的运行方式，并识别性能瓶颈、调试问题等。 

  参考项目：https://github.com/ilammy/ftrace-hook

- VFS 虚拟文件系统操作，VFS 是类 Unix 操作系统的关键组件，它通过启用 open()、stat()、read()、write()和 chmod() 等系统调用为用户空间程序提供文件系统接口。VFS 抽象并统一了对不同文件系统的访问，允许各种文件系统实现共存。VFS 是表示通用文件模型的一系列数据结构。

  参考项目：https://github.com/mncoppola/suterusu

  参考项目：https://github.com/yaoyumeng/adore-ng

但是这些方法都对攻击者也有一定的限制：

1、攻击者必须具有 root权限；

2、攻击者一般需要在受害机器上编译链接生成相关恶意文件，因为内核模块必须使用与目标系统的内核版本兼容的特定内核头文件.ko进行编译，内核函数和对象因内核版本和体系结构而异

### 一些案例

- **TeamTNT 组：Diamporphine rootkit**

  - 自 2020 年 8 月以来，TeamTNT 在不同的活动中以及最近的活动（例如归因于该组的 Kiss-a-Dog）中使用 Diamorphine 来隐藏加密挖矿过程。

  **Melofee 恶意软件 / 针对易受攻击的 Fortinet 服务的活动 / 针对韩国公司的活动：Reptile rootkit**

  - Reptile 是一个功能强大的 rootkit，除了隐藏恶意活动外，它还提供后门功能。它最近被记录为中国不同归因威胁的一部分;针对易受攻击的 Fortinet 服务、Melofee 恶意软件的活动，以及针对韩国公司的活动。有趣的是，发布后一项活动的公司 ASEC 展示了该活动中发现的工件与 Melofee 恶意软件之间的相似之处。

  **Winnti 组 （APT 41） / RedXor 恶意软件 / Syslogk 恶意软件：Adore-ng、Suterusu rootkits**

  - Adore-ng 最初被记录为 Winnti 组 （APT 41） 工具集的一部分。虽然是一个旧的 rootkit（最后一次提交是 8 年前），适用于旧的内核版本（因此是遗留系统），但它的使用是在最近的恶意软件 RedXor 中观察到的，该恶意软件主要是中国的攻击者使用。2022 年 6 月，Avast 报告了一个新的 rootkit，即 Syslogk，它主要基于 adore-ng。

  **Skidmap 恶意软件**

  - Skidmap 恶意软件使用 LKM rootkit 来隐藏加密挖掘活动。在 trustwave 关于这种不断演变的威胁的最新报告中，可以看到 Skidmap 针对易受攻击的 Redis 实例。

### 实现

#### 1、LKM 中通过修改syscall实现隐藏pid，我们拿上面示例项目Diamorphine举例：

下载项目到linux ，这里测试使用的linux内核版本：5.4， gcc版本：7.5.0：

![image-20240505230600726](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240505230600726.png)

make 编译打包，生成如下文件：

![image-20240505230511058](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240505230511058.png)

使用 insmod命令加载内核模块：

![image-20240505230744446](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240505230744446.png)

加载之后直接通过lsmod看不到加载的模块，因为这里对模块进行了隐藏，发送信号63即可解除模块隐藏：``kill -63 0``,如下图解除之后，可以看到内核加载的daimorphine的模块

![image-20240505230859616](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240505230859616.png)

想要实现进程隐藏发送31信号即可，使用方法如下：

`` kill -31 pid``

如下图：先通过发送31信号隐藏63399进程，ps查看无果，然后发送31恢复：

![image-20240505231443042](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240505231443042.png)

该隐藏对netstat的效果：如下图，63351 是redis server进程：对其隐藏之后，pid和pname看不到了。（通过这里我们也可以得出一个结论，这个大概率还是通过操作readdir函数来做的，为什么这样说呢，之前上面提到用户层ld劫持，就是重写readdir来实现劫持，从而隐藏/proc/pid目录，从而使ps这种需要通过遍历目录拿到的东西的命令失效，但是netstat不会全部失效，只是部分失效，这里只不过内核层做的更加深入，操作的是readdir函数里面的调用的系统调用syscall中的getdents，替换了syscall表里面的getdents函数地址）

![image-20240505231858708](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240505231858708.png)

![image-20240505231757095](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240505231757095.png)

卸载，先使其可见(``kill -63 0``)，然后直接使用``rmmod diamorphine`` 命令即可；





### 排查方法

#### 1、使用rootkit扫描工具

chkrootkit 是一种在本地检查 rootkit 痕迹的工具。

下载地址：https://github.com/Magentron/chkrootkit

下载之后，linux上安装gcc：

 yum install glibc-static

然后执行命令:

``make sense ``

使用如下命令可以快速找到相关警告和异常
``./chkrookit | grep Warning`` 

如下，该机器被攻击者置入Diamorphine rootkit，通过修改lkm的syscall表中特定函数的地址，实现lkm rootkit，
![image-20240509173156967](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240509173156967.png)
查看详情再使用``./chkrootkit``，即可定位被修改的函数：
![image-20240509173204629](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240509173204629.png)

![image-20240909112938749](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240909112938749.png)





#### 2、加载自定义内核模块开展排查

通过加载内核模块修改syscalltable里面系统调用地址实现隐藏的这一大类，我们可以尝试加载我们自己定义的内核模块排查系统调用函数是否被劫持：



如：下面``syscallviewall.c``我们实现对``sys_call_table``里面的系统调用进行遍历输出名称和地址：（下面脚本需要内核版本 > 4.4.0）

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/version.h>

static unsigned long *sys_call_table; 

// 反向查找符号名称
static const char *lookup_function_name(unsigned long addr) {
    static char namebuf[128];
    sprintf(namebuf, "%ps", (void *)addr); // 将函数地址转化为符号名称
    return namebuf;
}

static int __init list_syscall_names_and_addresses(void) {
    int i;
    unsigned long max_syscalls = 1024; //  假设最多1024 个系统调用

    // 获取 sys_call_table 地址
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    if (!sys_call_table) {
        printk(KERN_ERR "Failed to locate sys_call_table.\n");
        return -1;
    }

    printk(KERN_INFO "sys_call_table located at: %px\n", sys_call_table);

    // 遍历 sys_call_table 并输出每个系统调用的名称和地址
    for (i = 0; i < max_syscalls; i++) {
        unsigned long addr = sys_call_table[i];
        if (addr) {
            const char *name = lookup_function_name(addr);
            printk(KERN_INFO "sys_call_table[%d]: %px - %s\n", i, (void *)addr, name);
        } else {
            break; // 末尾
        }
    }

    return 0;
}

static void __exit cleanup(void) {
    printk(KERN_INFO "Module unloaded.\n");
}

module_init(list_syscall_names_and_addresses);
module_exit(cleanup);



```



Makefile:

```
obj-m += syscallviewall.o


# 添加C标准选项
ccflags-y := -std=gnu99

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

```



编译、加载、查看内核日志：

```
make
insmod  sycallviewall.ko
dmesg
```

如下图，可以看到对应的地址和其他函数的地址存在很大的偏差：

![image-20240910113849981](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240910113849981.png)



#### 3、查看内核加载缓冲区的日志

使用`dmesg` 命令可以查看内核的环缓冲区日志，其中包含了系统启动和模块加载的详细信息;

``dmesg | grep -i 'module'``

对输出的结果排查，过滤关键词（比如这里是diamoxxx），还有就是对比响应的结果里面提到的模块，lsmod里面是否存在，两边对不上可能是有问题的，做了隐藏；

![image-20240909182141403](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240909182141403.png)



#### 4、绕过对lsmod的劫持，使用其他命令查看

Linux 系统中的 /sys/module 目录包含当前内核中加载的所有模块，即使模块通过篡改lsmod 输出被隐藏，它仍可能在这个目录中有痕迹，除非攻击者做了文字过滤；

``ls /sys/module``

直接对结果进行工具关键词过滤，缺点是这种方法只能排查公开工具

![image-20240909183110118](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240909183110118.png)







### 解除方法

#### 1、使用工具自己的还原操作还原

特殊工具根据其实现做解除处理，如Diamorphine，这个直接卸载ko即可：

```
kill -63 0 //解除隐藏
rmmod diamorphine //卸载加载的内核模块

```



#### 2、反劫持还原

如果不是开源工具做的劫持，又或者攻击者做恶意内核模块的时候就没做卸载逻辑那么我们该怎么办呢，这里找到被劫持的syscalltable系统调用之后，可以通过加载我们自己的内核模块，做一遍劫持，以毒攻毒，劫持回来从而修复syscalltable里面记录的系统调用地址，所以应急人员最好是能够做一些内核模块的开发，根据排查结果对被劫持的函数反向劫持回来；



**重点**

这里我们简单提下，一个反向劫持回来实现中的一个技术细节：排查的时候我们只能看到被劫持之后该系统调用的地址；那么如何找到``sys_call_table``里面某个被劫持的系统调用其原先的地址呢？

这里大致有两种方法：

（1、利用系统调用地址之间的相对偏移

（2、利用``/boot/system.map-$(uname -r)``符号连接文件



>第1种方法没啥好说的，比较好理解，就是找个差不多的内核版本机器，我们找到一个正常的系统调用地址，以其为参照，找到正常机器上的被篡改的系统调用（这个可以通过名称，以及数组序号来定位）和正常的系统调用之间的相对偏移，然后我们来到受害机器，找到刚刚选择的的正常系统调用在受害机器上的地址，然后减去相对偏移，即可拿到受害机器上被篡改的系统调用其原始的地址；
>
>第2种方法和第一种方法原理上差不多，但是其不需要再专门找一台正常的机器；linux的``/boot/system.map-$(uname -r)``文件是系统内核编译时候生成的符号连接文件，里面可以直接查到相关系统调用的地址，如下我们举个例子来说；





如下图，通过加载我们自己的内核模块开展排查（上文遍历syscalltable的内核模块），我们可以看到，此时系统调用getdents是被diamorphine劫持了：

![image-20240911111757051](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240911111757051.png)

首先我们找到，system.map里面随便一个系统的地址，只要没有被篡改即可，这里我们一般使用syscalltable里面的第一个系统调用，也就是sys_read，一般我们都使用这个就行，只要这个没有被篡改：

````txt
cat /boot/System.map-$(uname -r) | grep sys_read
查出来的地址是 ：ffffffff812deb00
````

![image-20240911112237228](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240911112237228.png)

然后我们查看刚刚的排查结果中，sys_read的地址：

```
地址是：ffffffffb28deb00
```



![image-20240911112651561](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240911112651561.png)

两者相减找到相对偏移：

```
ffffffff b28d eb00(实际地址)-ffffffff 812de b00（符号地址）=3160 0000
```



然后我们再找到system.map里面的被劫持模块名称符号对应的地址：

```
cat /boot/System.map-$(uname -r) | grep  sys_getdent
地址是：ffffffff 812f 58c0
```

![image-20240911113203987](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240911113203987.png)



最后使用获取的地址+相对偏移，我们就拿到了sys_gendens的被篡改之前的原始地址：（有时候这里的相对偏移会是0，这个取决于系统是否开启KASLR：Kernel Address Space Layout Randomization）

```
ffffffff 812f 58c0 + 3160 0000 = ffffffff b28f 58c0
```



我们核对下：

这里我们卸载diamorphine之后，再查看下正常sys_gendents的地址：

![image-20240911113600458](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240911113600458.png)

加载syscalltable遍历逻辑的内核模块：如下图，我们可以看到getdents原本的地址就是我们上面计算出来的地址；

![image-20240911113657949](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240911113657949.png)







## 五、通过ebpf实现pid隐藏

### 原理

ebpf可以不更改内核源码和重启内核的情况下，运行、加载用户自定义的代码逻辑，和上面lkm层面的劫持原理一样，这里我们可以使用ebpf实现对getdent、getdent64返回结果进行篡改（本质上就是对目录查看之后目录结构结果的篡改）；

### 实现

这里我们拿如下case举例，其通过对getdent64系统调用进行逻辑篡改，使其再调用和返回的时候执行隐藏逻辑，从而实现对指定进程的pid隐藏；

https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/24-hide



### 现象

运行编译后的二进制程序 pidhide:

![image-20240911165923187](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240911165923187.png)

相关进程pid被隐藏：

![image-20240911165853532](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240911165853532.png)

### 排查方法

这里我们也不难发现，本身使用ebpf就会产生一个进程，这个进程就是上面我们提到的运行二进制的进程，所以这里我们可以尝试排查一些进程运行参数，是否出现相关端口或者名称：

如下，我们看到是存在一个参数是要被隐藏的进程；（一般在恶意利用的时候，这里也可能会取动态根据进程名称获取pid，然后去隐藏，也有可能没有运行参数直接内置逻辑，所以这里我们排查的主要逻辑可能还是要对所以进程过下，看下是否存在作用未知的可疑进程，并排查对应的可执行文件，结合文件日期属性等开展排查）

![image-20240911170157850](/img/Linux下常见Rootkit手段原理分析及排查方法汇总/image-20240911170157850.png)



### 解除方法

结束排查出来可能使用了ebpf技术的进程即可；





# 0x03 总结

总之，在做linux下的Rootkit入侵应急响应分析时，最理想的情况时，是分析人员能够融汇贯通常见隐藏实现方式的基本原理，这样才能有清晰的排查思路，知道根据第一个结果，如何开展下一个排查项；综合运用内核数据结构的比对、系统调用链的检查、等方法。通过对系统关键日志、内核符号、动态库的全面审查，可以有效发现异常。此外，也可以适当的运用一些入侵检测工具如：**chkrootkit**、**Rkhunter**等；





## 参考：

https://cloud.tencent.cn/developer/article/2443863
https://eunomia.dev/zh/tutorials/24-hide/#ebpf_1
