---
title: 协会博客操作方法
date: 2021-01-30 23:00:00
tags: 
- Tutorials
categories: 
- Tutorials
---

# 协会博客操作方法

为了方便以后信安协会这个github博客的维护工作的交接，这里写一篇操作方法方便后来的学弟学妹借鉴。

接管博客的人最好是有一定的git基础。如果没有的话，最快的速成方法是自己去用github+hexo搭建一个个人博客，网上教程很多，但先不要使用他人的开源模板，等到对git命令，ssh，hexo都有一点了解以后，再去尝试使用他人开源的博客模板，这里我写了一篇

[使用博客模板教程]: https://liloong3t.com/2021/02/01/2021-2-1-chong-jian-bo-ke/	"使用博客模板教程"

这时再来操作协会博客应该就会得心应手了。

## 下载源码

我把源码备份在github仓库的`hexo`分支里了，hexo默认把网页push到`master`分支里，管理博客的人只要把hexo分支下载到本地仓库就行了，如果是专门管理这个博客的人，建议是使用ssh方式，方便很多。创建一个ssh专门用于管理协会博客。关于两个或多个ssh密钥的使用和切换，上面贴的这篇博客里有很详细的说明。

想了想，怕以后我这个域名或博客有什么变动，还是把方法也贴这里吧

**在一个电脑上使用两个ssh的方法**

有时候我们会遇到这种情况，手上有两个git账号要管理，一个私人的一个公有的（或者干脆就有两个私人的），但使用ssh远程连接时会遇到问题。

一个ssh密钥只能连接一个账户或者仓库，这使我们管理两个账户时非常不方便，一个用了ssh以后另外一个就不能用了

这时的解决方法是利用config文件再创建一个ssh密钥并指定主机别名来连接远程git账户（无论是github还是别的git服务器都可以）

用git bash或者命令行打开系统盘“用户”目录下的.ssh文件

```bash
ssh-keygen -t rsa -C "这里输入邮箱，其实输啥都行"		//创建新ssh密钥
Generating public/private rsa key pair.
Enter file in which to save the key (/Users/Apple/.ssh/id_rsa): [输入密钥文件名，直接回车就是括号中的默认名称]      //创建第二个ssh密钥不能使用默认的了，我为协会博客创建了一个id_rsa_ais,这个名字可以随便取        

/Users/xxx/.ssh/id_rsa_ais
Enter passphrase (empty for no passphrase): 		//添加密码，建议直接回车，使用ssh就是为了省事和安全，再加个密码多此一举了
Enter same passphrase again: 
Your identification has been saved in /Users/Apple/.ssh/id_rsa_ais.	//私钥
Your public key has been saved in /Users/Apple/.ssh/id_rsa_ais.pub. //公钥
The key fingerprint is:
SHA256:1gepuxDHwJRnFbKvc0Zq/NGrFGE9kEXS06jxatPPrSQ xxx@xxx.com //你刚刚输入的邮箱
The key's randomart image is:
+---[RSA 2048]----+
|      ....=*oo   |
|     o. ooo=+ .  |
|      oo. =+o.   |
|       o =.o..   |
|      . S =o.    |
|       = =++.    |
|      . B.=.Eo.. |
|       o B . +o .|
|          . o.. .. |
+----[SHA256]-----+
```

自己把ssh公钥上传到远程git服务器上去

然后打开.ssh文件中的config文件（没有就自己创建一个）

添加如下代码

```
#Default GitHub
  Host github.com		//主机名称
  HostName github.com	//主机
  User git
  IdentityFile ~/.ssh/id_rsa	//密钥文件

  Host github-wustais	//同上，这里相当于为github.com起了个别名，使用这个别名的时候用的密钥文件就会是id_rsa_ais
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_rsa_ais	//这里你刚刚创建的密钥文件叫什么就改成什么
```

然后

**将GitHub SSH仓库地址中的git@github.com替换成新建的Host别名。**

```
//修改之前
$ git remote -v
github  git@github.com:xxx/xxx.git (fetch)
github  git@github.com:xxx/xxx.git (push)
//这里如果你是使用https方式clone的仓库的话，显示的是https://github.com/xxx/xxx.git,对后续操作没什么影响

//修改 remote set-url
$ git remote set-url github  github-wustais:xxx/xxx.git
```

验证

```
//使用修改后的github-wustais SSH连接，连接成功用户是协会账户，此时公钥是id_rsa_ais

$ ssh -T github-wustais	//这里写成git@github-wustais也行
Hi xxx! You've successfully authenticated, but GitHub does not provide shell access.	//这就是成功了，后面这句话是告诉你你没有远程操作控制台的许可，因为用了命令中用了-T参数

//使用默认的git@github.com SSH去连接,连接成功用户是我的私有账户，此时公钥是id_rsa
$ ssh -T git@github.com
Hi xxx! You've successfully authenticated, but GitHub does not provide shell access.
```

修改之后,需要切换成对应的ssh

**有如下两种解决方法：**

打开.git/config文件

```plain
更改[remote "origin"]项中的url  
对应上面配置的host[remote "origin"] url = git@github-wustais:xxx/xxxx.git	//这里不要git@也行
```

 或者在Git Bash中修改remote  

```plain
$ git remote rm origin
$ git remote add origin git@github-wustais:xxx/xxxx.git		//这里不要git@也行
```

验证

```
$ git remote -v
github  github-wustais:xxx/xxx.git (fetch)
github  github-wustais:xxx/xxx.git (push)
```

这时，使用的ssh就会根据.ssh/onfig文件更改为 id-rsa-ais

便可以连接上远程仓库`github-wustais:xxx/xxx.git`，即`git@github.com:xxx/xxx.git`了。

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

本地仓库准备好以后，执行以下三个命令安装node库文件和插件

```
npm install hexo
npm install
npm install hexo-deployer-git
```

然后就可以愉快的写文章了

如果想建一个图片库，使用命令

```
hexo new page image
```

或者直接在source文件夹下建一个image文件都行，不过不建议在github仓库里放图片，因为github仓库只能免费放100M文件，总有一天会用完的。

## 注意事项

每次发布文章之前记得先push备份源码

```
git add .
git commit -m "备份源码"
git push origin hexo		//这里记得是hexo分支
```

也可以使用

```bash
git branch --set-upstream-to=origin/hexo hexo
```

这条命令指定hexo分支的默认远程上传仓库为hexo，这样hexo 默认`git push`的就是 hexo分支，大大降低手残操作带来的麻烦的可能性。

源码里有个py文件，用于一键提交，原理很简单，打开一看就懂了，用不用随便，其实也没多省事。