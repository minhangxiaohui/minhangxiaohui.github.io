---
layout:       post
title:        "BypassUAC_fodhelper进程Registry-Shell_Open_Command提权"
subtitle:     "UACME_33技术分析，利用fodhelper依赖HKCU低权限注册表shell-open-command绕过UAC"
author:      "Ga0weI"
header-style: text
catalog:      true
tags:
    - BypassUAC
    - windows
---



# 0x01 前言

UACME这个项目基本时收录了目前所有公开的bypassuac手段，这些绕过手段大致可以分为几大类，其中较为常见的类型之一是：

通过修改低权限注册表HKCU下的相关项，使某些windows内置的能够不弹窗自提权的exe的逻辑被篡改，从而实现提权；

如UACME33：

**利用fodhelper.exe本身符合uac的无弹窗提权校验（两个条件，一个是路径是system32，一个是manifest里面有autoElevate），以及fodhelper.exe 会依赖HKCU下的相关项，注册表内容，修改``shell\open\command``执行pe文件来bypassuac；**



此文，主要就是详细分析这种bypassuac的手段原理和实现方式；



# 0x02 原理

关于uac本身的校验流程和校验点这里就不再重复概述，fodhelper.exe是符合在可信目录下，并且自带自动提权的标记；如下图是自带自动提权标记:

![image-20240723174730893](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723174730893.png)

关于uac校验详情可以参考： xxxxxx（后续发至攻防社区）

分析fodhelper.exe的行为：

下面测试的环境版本:

![image-20240723164559596](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723164559596.png)

一般来说，如果涉及某个进程对一个路径里面包含``shell\open\command``的项查询的时候，大概率是要调用某个可执行文件；

运行fodhelper.exe 效果如下,弹出可选功能配置的界面,win10才有的;

![image-20240723160636849](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723160636849.png)

运行fodhelper.exe 的时候，使用procmon观察其对注册表的查询操作；

![image-20240723152423882](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723152423882.png)

![image-20240723152543729](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723152543729.png)

如上图，我们可以看到这里去查询``HKCU\Software\Class\ms-settings\Shell\Open\Command``,实验环境这里本地的时候这个键值内容的；

我们可以尝试把这个项创建下，然后重新运行：

![image-20240723152844264](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723152844264.png)



新建之后：

![image-20240723153735292](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723153735292.png)

然后我们再次运行，查询：

![image-20240723153655956](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723153655956.png)



可以看到这里在open到对应的项之后，查了下name的键值，这里我们继续满足，创建Name键值：

![image-20240723153927428](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723153927428.png)

再次运行fodhelper.exe，如下图我们看到，新增在``HKCU\Software\Classes\ms-setting\Shell\Open\command``基础上，对DelegateExecute键的查询；

![image-20240723154213397](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723154213397.png)

我们继续构造相应的键满足需求：

![image-20240723155248728](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723155248728.png)

再次运行fodhelper.exe,如下,虽然是查到了东西,但是附近貌似没有看到相关其他操作和变动,但是我们会发现此时已经无法正常执行fodhelper.exe,即可选功能菜单界面没有正常被运行弹出了;

![image-20240723155224143](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723155224143.png)



我们修改下筛选条件,过滤所有路径中带DelegateExecute对应的键值(``test2``)的内容

![image-20240723155835859](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723155835859.png)

如下图,我们可以看到,获取到DelegateExecute的键值之后,其实还是去HKCR里面查了

![image-20240723155634736](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723155634736.png)

结合HKCR这个项和刚刚的键名 DelegateExecute(委托执行)  , 这里的性质其实大致就是指定一个exe来代替这个原来的执行文件;

我们尝试将这个键值修改成cmd,如下,测试发现,cmd并没有被调用;

但是其实这里已经非常接近正确姿势了;



应该是有大佬逆向分析了这个fodhelper.exe里面的逻辑(这里笔者猜测这个委托的操作因该是用来调用com组件的,因为上面我们看到当填写test2的时候,其尝试去HKCR里面找打这个了),当这个委托执行项为空的时候,发现其会使用默认的键值:

![image-20240723162953931](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723162953931.png)



这里我们直接把要提权执行的路径,写到default里面即可:

![image-20240723163123905](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723163123905.png)

但是直接点击确定,我们会发现,这个注册表ui进程直接被杀了,并且微软报毒,所以这里是做了管控的;

![image-20240723163143006](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723163143006.png)

我们可以尝试使用脚本测试下:

```powershell
[String]$PE = "c:\windows\system32\cmd.exe"
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $PE -Force
```

运行,结果如下,秒被杀,但是我们查看regedit会发现,相关命令已经写入了,这里写入的路径就是cmd,就很神奇)



![image-20240723163552424](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723163552424.png)

![image-20240723171416135](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723171416135.png)



windows Defender只是杀了操作的注册表的进程,但是相关动作却已经发生了;

此时我们再次运行fodhelper.exe,查看相关情况,可以看到此时弹出了cmd,并且是管理员权限;

![image-20240723164401676](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723164401676.png)





# 0x03 实现

这里直接把要新建的项和键都写到脚本里面即可,最后再单独运行fodhelper.exe,拿powershell举例:

```powershell
[String]$PE = "C:\windows\system32\cmd.exe"
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $PE -Force
```



最后单独运行fodhelper.exe,这里之所以要最后单独运行,是因为上面测试的时候我们知道,如果谁去动``HKCU:\Software\Classes\ms-settings\Shell\Open\command``的default的键对应的值,会被windowsdefender直接干掉,进程直接g;所以这里后面的操作不能写到上面一起:

```powershell
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```







删除,所有ms-setting子项:

![image-20240723170407070](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723170407070.png)





运行ps脚本,然后查看注册表:

![image-20240723170959894](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723170959894.png)



然后继续运行起fodhelper.exe的命令:

![image-20240723171552288](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723171552288.png)



# 0x04 提升

这里windows df直接杀非常烦,相关杀软因该也都监控了这个点;网上有人分析发现一个绕过的新思路,上次笔者再分析某个黑灰产的样本的时候,其内置的提权也使用了这个提权方式的变种,即对一些av能够绕过;



如下图,fodhelper.exe运行靠前的位置,其查询了一个``HKCU\Software\Class\ms-settings\CurVer``的键值;

![image-20240723172317155](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723172317155.png)



这个键值是指向一个路径的,他会影响最后去哪找到后面的``shell\open\command``,如下我们给其一个``.pwn``的路径:

![image-20240723173850329](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723173850329.png)

然后重新运行fodhelper.exe并观察,如下图

![image-20240723174115225](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723174115225.png)



如上图,我们上面分析的按相同的思路方法,会发现最后创建一个如下项目,修改默认的键值,

![image-20240723174226517](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723174226517.png)



然后运行fodhelper.exe,即可以管理员权限运行cmd:



![image-20240723174641788](/img/BypassUAC_fodhelper进程Registry-Shell_Open_Command提权/image-20240723174641788.png)



但是这个方法,目前windowsdf也还是会杀,其他av没测,因该效果也不理想;

这里,为什么会存在这个绕过,感觉是微软为这个做fodhelper.exe做的兼容,不同版本使用不同的pe程序;





# 0x05 检测

这个检测的话就比较好做,直接是对注册表进行修改日志做检测;

拿sysmon举例,这里我们监测,谁修改如下两个键即可:

```
HKCU\Software\Class\ms-settings\Shell\Open\command\(default)
HKCU\Software\Class\ms-settings\CurVer\(default)
```











