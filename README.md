## 项目介绍

FastjsonScan4Burp 一款基于burp被动扫描的fastjson漏洞探测插件，可针对数据包中的存在json的参数或请求体进行payload测试。旨在帮助安全人员更加便捷的发现、探测、深入利用fastjson漏洞，目前以实现fastjson探测、版本探测、依赖探测以及出网及不出网利用和简易的bypass waf功能。

参考代码及检测思路：
```
https://github.com/pmiaowu/BurpFastJsonScan
https://github.com/lemono0/FastJsonParty
https://github.com/safe6Sec/Fastjson
```
## 更新记录
0228：1.修复加载插件后导致列表插件后的其他插件不可用情况 2.修复了yml文件生成时可能出现报错的情况，添加utf-8标准读取文件 
## 工具模块

目前插件具有的功能模块：

- 低感知探测扫描
- 出网扫描
- 不出网扫描
- fastjson版本探测
- fastjson依赖探测
- bypass waf模块
- dns平台实时切换

## 扫描原理
插件会自动发现数据包GET/POST请求中包含有json的value或请求体是否为Content-Type:application/json。判断依据为是否包含有{}或[]
GET中value存在json
<img width="1129" alt="image" src="https://github.com/user-attachments/assets/3bc8f04d-6d51-4f39-adba-0923eabe92c8" />
<img width="1440" alt="image" src="https://github.com/user-attachments/assets/c023b4b4-0f33-4bd4-baa0-7756c1594403" />
POST中value存在json
<img width="1158" alt="image" src="https://github.com/user-attachments/assets/451164de-f698-406f-b806-9bd853f68dfb" />
<img width="1440" alt="image" src="https://github.com/user-attachments/assets/8f37e77a-2d49-4812-bd77-dbbba3e1d658" />
Content-Type为json（以下案例均是，不多赘述）
检测出json后，默认会调用fastjson探测、远程命令执行探测及不出网探测，各模块扫描原理详见下文。


## 使用手册
### 安装
初次加载会在当前目录下创建resources/config.yml文件。
<img width="699" alt="image" src="https://github.com/user-attachments/assets/10c5cbd0-af83-4ce2-a0d3-3571aa47b77b" />

基本设置如下，默认情况下不开启bypass waf模块，可根据实际勾选
<img width="944" alt="image" src="https://github.com/user-attachments/assets/fe6e81a7-74dc-4e09-88a4-675f86154e19" />
### 基于被动扫描

插件会被动式地对数据包进行扫描，只需要启动插件后正常浏览数据包即可。插件扫描队列界面会对扫描结果进行展示。

- extensionMethod：调用的扫描模块名称
- issue：扫描结果
<img width="957" alt="image" src="https://github.com/user-attachments/assets/79a827f7-8010-4780-9797-af205ec0d3f9" />

### 右键主动扫描

部分情况下想对单一某个数据包进行漏洞验证或其他原因，可以在repeater右键选择对应插件选择扫描或探测
<img width="962" alt="image" src="https://github.com/user-attachments/assets/1820bd69-b817-4e4a-9556-9f79a9b83ff5" />

或者使用doPassive再次进行被动扫描

<img width="696" alt="image" src="https://github.com/user-attachments/assets/106a64ef-30b4-402c-91e1-3d55e8ee7204" />

### dnslog切换

当出现dnslog error时，不需要更改config.yml，可直接在设置中切换dnslog平台，并进行下一轮扫描。其中ceye平台和eyes.sh平台需要在config.yml中配置对应token和Identify

<img width="444" alt="image" src="https://github.com/user-attachments/assets/c2c6cd66-0a80-41d3-a020-814f4cc7ebc2" />

### 结果输出

除了在burp中的issue中以及插件界面外，还会在插件部署目录下的resources文件夹中生成result.txt文件

<img width="931" alt="image" src="https://github.com/user-attachments/assets/231a9be0-7d9c-466e-8d59-a08862ae1e21" />

## 扫描模块原理

被动扫描默认会调用低感知扫描、出网及不出网扫描，探测模块则存在于repeater右键中。

敏感环境下可开启bypass waf选项，并关闭命令回显拓展和远程命令拓展，仅保留低感知fastjson扫描。

### 低感知扫描

主要作用类似于xiasql插件，去探测是否使用了fastjson。尽量以相对较少、较低敏的payload对目标进行扫描。

判断方式如下：

1. 破坏json原有数据格式：去除 } 号，匹配响应包中是否还有`syntax error`这种fastjson特征
   <img width="918" alt="image" src="https://github.com/user-attachments/assets/f4cc9c68-9636-41f1-ab70-6f6d35e56539" />

2. 使用出网探测payload，查看dns url是否有解析记录
注：使用如下payload且dnslog有数据不代表有漏洞，仅能证明使用了fastjson
```
{"@type":"java.net.Inet4Address","val":"dnslog-url"}
{{"@type":"java.net.URL","val":"http://dnslog-url"}:"x"}
{"@type":"java.net.InetSocketAddress"{"address":,"val":"dnslog-url"}}
```
对应config.yml扫描模块如下：`dnslogPayloads`可自定义

<img width="699" alt="image" src="https://github.com/user-attachments/assets/9b276a53-db59-4643-95c0-41100e2c53ae" />

### 远程命令拓展扫描

对应config.yml扫描模块如下：`payloads`可自定义

<img width="955" alt="image" src="https://github.com/user-attachments/assets/e4e0fd5d-7b48-451d-8e5c-462c412c3012" />

### 命令回显拓展扫描

对应config.yml扫描模块如下：`payloads`和`commandInputPointField`可自定义。`commandInputPointField`为插入的header头，通过java回显来判断是否存在漏洞

<img width="947" alt="image" src="https://github.com/user-attachments/assets/bf705efd-39d7-4cb2-91d5-328c5b1125e4" />

添加了c3p0和Bcel下的java回现利用payload。其中c3p0二次反序列化调用的是fastjson1.x原生利用链

<img width="903" alt="image" src="https://github.com/user-attachments/assets/bd9bc78c-3c6e-4933-93ba-41f94c162557" />

### 版本探测

对应config.yml扫描模块如下：`regexPayloads`和`dnsLogPayloads`可自定义。

<img width="943" alt="image" src="https://github.com/user-attachments/assets/a9596267-f513-4d1d-8034-912a35536719" />

探测模块使用仅在右键repeater中

<img width="932" alt="image" src="https://github.com/user-attachments/assets/d06ac5be-6bff-425c-b864-f2b3580583a7" />

<img width="948" alt="image" src="https://github.com/user-attachments/assets/3fd056c7-cf8d-45aa-b486-9db93a65222c" />

探测原理：

1. 优先使用`{"@type":"java.lang.AutoCloseable"`，通过左侧的正则去匹配响应包报错版本号（版本1.2.76之后，其报错显示也是1.2.76，不会发生改变）
2. 通过对应dnslog去匹配版本

在自定义dnsLogPayloads时，可编辑 ;左侧内容为任意版本。例如当发现了fastjon2.2版本对应的出网poc为`{"anything":"xaga.dnslog.cn"}`。则添加payload为

```
- "version=2.2; payload={\"anything\":\"dnslog-url\"}"
```

### 依赖探测

对应config.yml扫描模块如下：`libraries`依赖可自定义。

<img width="923" alt="image" src="https://github.com/user-attachments/assets/ec36efc2-1d67-4781-a506-870b71696d19" />
<img width="935" alt="image" src="https://github.com/user-attachments/assets/d8162a01-fe94-4242-970c-7454cebbea20" />
<img width="946" alt="image" src="https://github.com/user-attachments/assets/2dec2c68-b483-4e6d-ac4b-3e93d77602a8" />

原理则是通过Character转换报错，通过接口回显结果来进行判断

```
{
  "x": {
    "@type": "java.lang.Character"{
  "@type": "java.lang.Class",
  "val": ""
}}
```
判断条件一：页面有对应类报错回显，则代表存在依赖

<img width="922" alt="image" src="https://github.com/user-attachments/assets/ff985def-be82-46ec-96de-4b4570e387b7" />

判断条件二：无报错回显则基于响应包进行布尔判断
先发送一个不存在的依赖，记录下响应包结果

<img width="918" alt="image" src="https://github.com/user-attachments/assets/15af68c1-2df1-498a-b5f7-95fd602d790c" />

再对依赖进行fuzz，通过响应包文本相似度（Levenshtein 距离算法）进行比较判断，来得出是否包含该依赖

<img width="949" alt="image" src="https://github.com/user-attachments/assets/e5ca553d-be1e-42d4-8d55-6be285b1c09a" />
<img width="949" alt="image" src="https://github.com/user-attachments/assets/bf3cf30d-dece-426b-adc5-9f4f6d3ce748" />

## bypass waf

通过gson解析json格式，对key、value添加下划线后进行unicode、hex混合编码，在原有json基础上添加注释换行符。针对无法解析的json payload则对@type进行同上编码，在原有json基础上添加注释换行符。

ps：因为一些bypass姿势可能会影响payload的正确率，因此只使用了部分bypass方式。

以https://github.com/lemono0/FastJsonParty/blob/main/1247-jndi-waf/write-up.md环境为例

<img width="940" alt="image" src="https://github.com/user-attachments/assets/b6213ff5-7340-40e7-9636-59e8124f8863" />

<img width="952" alt="image" src="https://github.com/user-attachments/assets/5119ac32-7cfc-4d82-9674-8fd7e0a6ac97" />





