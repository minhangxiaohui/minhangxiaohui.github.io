---
layout:       post
title:        "一个近期黑产shellcode中惯用的手法"
subtitle:     "简单记录下一个近期分析发现黑产频繁使用的shellcode中的一个特征"
author:      "Ga0weI"
header-style: text
catalog:      true
tags:
    - shellcode
    - 免杀
    - api_hashcode
 
---

# 0x01 背景

最近分析黑产样本的时候，发现多个黑产家族的的样本中的shellcode都存在一个相同的特征；

特征

在shellcode中，需要做到无依赖的获取到要使用函数的地址，一般都是通过peb拿到ldr然后拿到dll基址，遍历导出表来获取；在这个遍历过程中，需要一个条件判断来匹配，正常的思路是使用dll名称和函数名称来对比，比如：我要获取kernel32.dll-VirtualAlloc函数的基址的时候，我就遍历ldr列表中的dll，找到的dllname为kernel32.dll的dll；然后根据获取到的dll基址，遍历导出表中导出函数名称表判断如果name为VirtualAlloc，就获取其地址。

但是一般为了逃避杀软的静态查杀，这个里面使用的用于匹配的字符是会被杀软扫描到的，也就是你调用的每一个函数，杀软都可以直接静态扫描获取到你的意图；从而被静态直接杀了；

于是衍生出来一个叫api_hashcode的东西，笔者称其为特征码；为了避免被杀软通过字符扫描直接获取到shellcode中可能存在的意向，这里其实就是变换了一个比较方式；改用一个间接的存在形式来对相关名称进行比较（这里可以理解成加密或编码或散列，这个三者都可以在这里实现相同效果），即使用特定的算法对名称进行操作，得到一个该名称的映射值；下次比较的时候，我们遍历的到的dll名称获取函数名称都使用这个算法进行操作，从而得到对应的特征码；所以这个问题就从函数名称的比较变成特征码的比较了；从而规避了一些被杀软静态查杀的风险；



目前市面上较为流行的对上面映射的实现是通过简单散列来做的；

拿cobaltstrike举例，cobaltstrike的shellcode中散列的实现如下：

- 逐位字符小写转大写，然后累加，在累加前将上一次的累加结果循环右移14位

![image-20241217113336364](/img/一个近期黑产shellcode中惯用的手法/image-20241217113336364.png)



对于这个特征目前很多杀软都将其加入了查杀库中；

# 0x02 发现的情况

一般做免杀中的shellcode开发的时候，最基本的避免查杀的方式的，就是会使用不同的**散列**  算法；

这次 近段时间笔者分析一些黑产的样本的时候，发现其近期都使用相同的**散列**算法。

银狐样本

![image-20241217141156846](/img/一个近期黑产shellcode中惯用的手法/image-20241217141156846.png)

![image-20241217141719229](/img/一个近期黑产shellcode中惯用的手法/image-20241217141719229.png)

山猫样本

![image-20241217141404534](/img/一个近期黑产shellcode中惯用的手法/image-20241217141404534.png)





使用的散列算法：

- 逐位字符，小写转大写，累加，累加之前将上一次的累加结果乘以131；



拿kernel32.dll举例，对应的特征码是``0x1CCA9CE6``；

使用python实现：

```python
def calcdll_hashcodebystring(input):
    input_len = len(input)
    res = 0
    while input_len:
        i_chr = input[0]
        input = input[1:]

        if ord(i_chr) >= 0x61:
            v8 = ord(i_chr)-32
        else:
            v8=ord(i_chr)

        res = (v8 + 131 * res)& 0x7FFFFFFF
        input_len -= 1  
        print(hex(res))
    return  hex(res)

if __name__ == '__main__':
    dllname = "kernel32.dll"
    hashcode = calcdll_hashcodebystring(dllname)

```



输出如下，挨个迭代计算；

![image-20241217142852024](/img/一个近期黑产shellcode中惯用的手法/image-20241217142852024.png)





笔者在github上找到了这个算法的由来：

![image-20241217144127553](/img/一个近期黑产shellcode中惯用的手法/image-20241217144127553.png)

![image-20241217144150038](/img/一个近期黑产shellcode中惯用的手法/image-20241217144150038.png)

除此之外

连下面这个函数参数都一样，并且为了节省空间，shellcode中兼容了获取getproaddress和其他函数的差别；当第三个参数为0的时候就是获取getprocaddress函数地址；

![image-20241217150945332](/img/一个近期黑产shellcode中惯用的手法/image-20241217150945332.png)



可以说是一摸一样；黑产估计是从这些开源项目借鉴而来。

而且我们会发现 不管是银狐还是山猫，其样本迭代更新的速度非常快，迭代的样本基本可以免杀大多数的杀软；













# 0x03 查杀思路

这里我们可以尝试使用这组特征码来配合其他特征来做查杀；最好是动态dump的扫描查杀，因为样本中可能对shellcode做间接存储，需要解密或解码还原；

比如可以通过hook sleep函数的，在sleep函数里面来做扫描，查杀上面的特征码，以及特征码的计算算法，查杀的精准度肯定会增高不少。

再比如可以通过hook 一些其他shellcode中会调用的函数，比如的网络连接函数等，亦可以实现同样的效果；

