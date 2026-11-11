---
title: Pikachu 靶场 45 关通关：源码漏洞分析
date: 2026-11-11 21:10:00
description: Pikachu Web 漏洞靶场 45 关通关记录与源码级漏洞分析，覆盖暴力破解、XSS、CSRF、SQL 注入、RCE、文件包含/上传、越权、SSRF 等，逐关附通关截图。
categories:
  - 网络安全
tags:
  - Pikachu
  - Web安全
  - 靶场
  - 漏洞分析
---

> 本文记录 Pikachu 靶场（https://github.com/zhuifengshaonianhanlu/pikachu）45 关的通关过程与源码级漏洞分析。截图均为本人本地靶场实际利用的回显；源码路径相对于靶场根目录 `pikachu-master`。
>
> 运行环境：Apache 2.4.39 + PHP 7.3.4 + MySQL 5.7.26。全部目标均为本地搭建的练习靶场，请只对自己拥有或已获授权的目标进行安全测试。

## 〇、公共文件

| 文件 | 作用 |
|---|---|
| `inc/config.inc.php` | 数据库连接参数、`session_start()`、统一输出头 |
| `inc/mysql.inc.php` | `connect()` / `execute()` / `escape()`（mysqli_real_escape_string） |
| `inc/function.php` | 验证码、`set_token()`、各 `check_*_login()` |
| `inc/uploadfunction.php` | `upload_client()` / `upload_sick()` / `upload()` |
| `inc/showvcode.php` | 生成验证码写 session，并把 vcode 明文写进 cookie |

---

## 一、暴力破解

### 01 基于表单的暴力破解
- **源码位置**：`vul/burteforce/bf_form.php`
- **漏洞类型**：无验证码、无频率限制、无账户锁定

```php
if(isset($_POST['submit']) && $_POST['username'] && $_POST['password']){
    $sql = "select * from users where username=? and password=md5(?)";
    $line_pre = $link->prepare($sql);
    $line_pre->bind_param('ss',$username,$password);
    if($line_pre->num_rows>0){ $html.= '<p> login success</p>'; }
}
```

**成因**：登录接口只有用户名/密码两个输入，虽用了预编译（防了 SQL 注入），但没有验证码、尝试次数限制或 IP 锁定，可用字典循环枚举。**利用/回显**：提交 `admin/123456` 返回 `login success`。**修复**：加验证码 + 失败锁定/限速 + 失败统一提示。

![01 表单暴力破解](/images/pikachu/01-brute-bf_form.png)

### 02 验证码绕过(on server)
- **源码位置**：`vul/burteforce/bf_server.php` + `inc/showvcode.php`
- **漏洞类型**：验证码可复用 + 验证码明文泄露到 cookie

```php
// showvcode.php —— 验证码明文写进 cookie
$_SESSION['vcode']=vcodex();
setcookie('bf[vcode]',$_SESSION['vcode']);
// bf_server.php —— 校验后没销毁 session 中的 vcode，同一验证码可反复使用
if (strtolower($_POST['vcode']) != strtolower($_SESSION['vcode'])) { /* 错误 */ } else { /* 登录 */ }
```

**成因**：① `showvcode.php` 把验证码明文写进 `bf[vcode]` cookie；② 校验后未 `unset($_SESSION['vcode'])`。**利用/回显**：读 cookie `bf[vcode]` 携带后提交 `admin/123456` 成功。**修复**：不要泄露验证码，校验后立即销毁。

![02 验证码绕过(server)](/images/pikachu/02-brute-bf_server.png)

### 03 验证码绕过(on client)
- **源码位置**：`vul/burteforce/bf_client.php`（前端 `validate()`）
- **漏洞类型**：仅前端 JS 校验，服务端无校验

```php
// 服务端只校验用户名密码，完全没校验 vcode
if(isset($_POST['submit'])){ if($_POST['username'] && $_POST['password']) { /* 只查 users */ } }
```

**成因**：验证码由前端 JS 生成并在前端比较，服务端不接收/校验 `vcode`。**利用/回显**：绕过表单 `onsubmit` 直接 POST `admin/123456` 成功。**修复**：验证码必须在服务端生成校验。

![03 验证码绕过(client)](/images/pikachu/03-brute-bf_client.png)

### 04 token 防爆破?
- **源码位置**：`vul/burteforce/bf_token.php` + `inc/function.php`
- **漏洞类型**：token 未真正参与防爆破

```php
if($token == $_SESSION['token']){ /* 校验密码 */ }
set_token();  // 校验逻辑之后才重新生成
```

**成因**：token 只做了一次相等判断，不限制尝试次数、不与账号绑定，照样能循环爆破。**利用/回显**：取隐藏域 token 携带后提交 `admin/123456` 成功。**修复**：token 需结合频率限制/锁定。

![04 token 防爆破](/images/pikachu/04-brute-bf_token.png)

---

## 二、XSS

### 05 反射型 XSS(get)
- **源码位置**：`vul/xss/xss_reflected_get.php`
- **漏洞类型**：反射型 XSS（输出未编码）

```php
$html.="<p class='notice'>who is {$_GET['message']},i don't care!</p>"; // 原样输出
```

**利用/回显**：`?message=<script>alert('xss')</script>&submit=submit` 触发弹窗。**修复**：`htmlspecialchars($msg, ENT_QUOTES)`。

![05 反射型XSS(get)](/images/pikachu/05-xss-reflected-get.png)

### 06 反射型 XSS(post)
- **源码位置**：`vul/xss/xsspost/xss_reflected_post.php`

```php
$html.="<p class='notice'>who is {$_POST['message']},i don't care!</p>";
```

**利用/回显**：登录 admin 后 POST `<script>...` 触发。**修复**：输出编码。

![06 反射型XSS(post)](/images/pikachu/06-xss-reflected-post.png)

### 07 存储型 XSS
- **源码位置**：`vul/xss/xss_stored.php`

```php
$message=escape($link, $_POST['message']);   // 只做 SQL 转义，未做 HTML 转义
$query="insert into message(content,time) values('$message',now())";
// 输出
echo "<p class='con'>{$data['content']}</p>";  // 未编码
```

**成因**：入库只 `mysqli_real_escape_string`，输出未 `htmlspecialchars`。**利用/回显**：留言 `<script>` 后每次访问列表都弹窗。**修复**：输出编码。

![07 存储型XSS](/images/pikachu/07-xss-stored.png)

### 08 DOM 型 XSS
- **源码位置**：`vul/xss/xss_dom.php`

```js
var str = document.getElementById("text").value;
document.getElementById("dom").innerHTML = "<a href='"+str+"'>what do you see?</a>";
```

**利用/回显**：输入 `'><img src=x onerror=alert(1)>` 触发。**修复**：用 `textContent` 或先转义。

![08 DOM型XSS](/images/pikachu/08-xss-dom.png)

### 09 DOM 型 XSS-x
- **源码位置**：`vul/xss/xss_dom_x.php`

```js
var str = window.location.search;
var txss = decodeURIComponent(str.split("text=")[1]);
document.getElementById("dom").innerHTML = "<a href='"+xss+"'>...</a>";
```

**利用/回显**：`?text='><img src=x onerror=alert(1)>` 后点击触发。**修复**：DOM 避免直接拼 HTML。

![09 DOM型XSS-x](/images/pikachu/09-xss-dom-x.png)

### 10 XSS 之盲打
- **源码位置**：`vul/xss/xssblind/xss_blind.php` + `admin.php`

```php
// xss_blind.php 入库（仅 SQL 转义）；admin.php 后台回显未编码
<td>{$data['content']}</td>
```

**利用/回显**：提交 `<script>...`，admin 登录后台即触发。**修复**：后台输出编码。

![10 XSS盲打](/images/pikachu/10-xss-blind-admin.png)

### 11 XSS 之过滤
- **源码位置**：`vul/xss/xss_01.php`

```php
$message=preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/', '', $_GET['message']);
```

**成因**：正则大小写敏感且只匹配 `script`，其它标签绕开。**利用/回显**：`<img src=x onerror=alert(1)>` 绕过。**修复**：白名单/统一编码。

![11 XSS过滤绕过](/images/pikachu/11-xss-filter.png)

### 12 XSS 之 htmlspecialchars
- **源码位置**：`vul/xss/xss_02.php`

```php
$message=htmlspecialchars($_GET['message']);   // 默认 ENT_COMPAT，单引号未转义
$html2.="<a href='{$message}'>{$message}</a>";
```

**成因**：输出点在单引号属性里，`' onclick='alert(111)'` 可闭合注入事件。**利用/回显**：点击链接弹窗。**修复**：`htmlspecialchars($msg, ENT_QUOTES)`。

![12 XSS htmlspecialchars](/images/pikachu/12-xss-htmlspecialchars.png)

### 13 XSS 之 href 输出
- **源码位置**：`vul/xss/xss_03.php`

```php
$message=htmlspecialchars($_GET['message'],ENT_QUOTES);
$html.="<a href='{$message}'> 点一下吧</a>";   // 未校验协议
```

**利用/回显**：`javascript:alert(document.cookie)` 点击弹 cookie。**修复**：只允许 http/https。

![13 XSS href输出](/images/pikachu/13-xss-href.png)

### 14 XSS 之 js 输出
- **源码位置**：`vul/xss/xss_04.php`

```php
$jsvar=$_GET['message'];
// ... <script>
$ms='<?php echo $jsvar;?>';
```

**利用/回显**：`';alert('xss');//` 闭合 JS 字符串触发。**修复**：JS 输出点转义引号/反斜杠。

![14 XSS js输出](/images/pikachu/14-xss-js.png)

---

## 三、CSRF

### 15 CSRF(get)
- **源码位置**：`vul/csrf/csrfget/csrf_get_edit.php`

```php
$getdata=escape($link, $_GET);
$query="update member set sex='{$getdata['sex']}',... where username='{$_SESSION['csrf']['username']}'"; // 无 token
```

**利用/回显**：登录 vince 后，构造 GET 链接 `add=HACKED_BY_CSRF` 直接改地址。**修复**：加 CSRF token + 敏感操作改 POST。

![15 CSRF(get)](/images/pikachu/15-csrf-get.png)

### 16 CSRF(post)
- **源码位置**：`vul/csrf/csrfpost/csrf_post_edit.php`
- **关键代码**：同上，只是 `$_POST` 且无 token。
- **利用/回显**：POST `add=HACKED_BY_CSRF_POST` 改地址。**修复**：加 CSRF token。

![16 CSRF(post)](/images/pikachu/16-csrf-post.png)

### 17 CSRF Token（防护对照）
- **源码位置**：`vul/csrf/csrftoken/token_get_edit.php`

```php
if(isset($_GET['submit'])){
    if(... && $_GET['token']==$_SESSION['token']){ /* 更新 */ }
}
set_token();
```

**说明**：该关加了 token 校验，无法直接 CSRF（受保护），用于对照 15/16。**利用/回显**：携带正确 token 才能修改。

![17 CSRF Token](/images/pikachu/17-csrf-token.png)

---

## 四、SQL 注入

### 18 数字型注入(post)
- **源码位置**：`vul/sqli/sqli_id.php`

```php
$id=$_POST['id'];
$query="select username,email from member where id=$id";   // 无引号，直接拼接
```

**利用/回显**：`0 union select username,password from users` 拖出密码哈希。**修复**：预编译 + `(int)$id`。

![18 SQLi数字型](/images/pikachu/18-sqli-id.png)

### 19 字符型注入(get)
- **源码位置**：`vul/sqli/sqli_str.php`

```php
$name=$_GET['name'];
$query="select id,email from member where username='$name'";   // 需闭合单引号
```

**利用/回显**：`x' union select username,password from users#` 拖库。**修复**：预编译。

![19 SQLi字符型](/images/pikachu/19-sqli-str.png)

### 20 搜索型注入
- **源码位置**：`vul/sqli/sqli_search.php`

```php
$query="select username,id,email from member where username like '%$name%'";
```

**利用/回显**：`x%' union select username,id,password from users#`。**修复**：预编译 + `%` 转义。

![20 SQLi搜索型](/images/pikachu/20-sqli-search.png)

### 21 xx 型注入
- **源码位置**：`vul/sqli/sqli_x.php`

```php
$query="select id,email from member where username=('$name')";   // 括号+引号包裹
```

**利用/回显**：`x') union select username,password from users#`。**修复**：预编译。

![21 SQLi xx型](/images/pikachu/21-sqli-x.png)

### 22 delete 注入
- **源码位置**：`vul/sqli/sqli_del.php`

```php
if(array_key_exists('id', $_GET)){
    $query="delete from message where id={$_GET['id']}";   // 无过滤
}
```

**利用/回显**：`?id=1 or 1=1` 删除全部留言（见对比截图）。**修复**：`(int)$_GET['id']`。

![22 delete注入(删除前)](/images/pikachu/22-sqli-del-before.png)
![22 delete注入(删除后)](/images/pikachu/22-sqli-del.png)

### 23 布尔盲注
- **源码位置**：`vul/sqli/sqli_blind_b.php`

```php
$query="select id,email from member where username='$name'";
$result=mysqli_query($link, $query);   // 不打印错误，只能靠布尔判断
```

**利用/回显**：`kobe' and 1=1#` 返回真。**修复**：预编译。

![23 SQLi布尔盲注](/images/pikachu/23-sqli-blind-bool.png)

### 24 时间盲注
- **源码位置**：`vul/sqli/sqli_blind_t.php`
- **关键代码**：同上，但无论结果如何都返回同一句话，只能靠 `sleep()` 时间差。
- **利用/回显**：`kobe' and sleep(5)#` 实测耗时 5423ms。**修复**：预编译。

![24 SQLi时间盲注](/images/pikachu/24-sqli-blind-time.png)

### 25 宽字节注入
- **源码位置**：`vul/sqli/sqli_widebyte.php`

```php
$name = escape($link,$_POST['name']);        // 先按 utf8 转义
$set = "set character_set_client=gbk";       // 再把客户端字符集设为 gbk
execute($link,$set);
```

**成因**：utf8 下 `'` 被转义成 `\'`，但连接改成 GBK 后 `%df`+`\`(0x5C) 被当成一个汉字，`'` 逃逸成功。**利用/回显**：POST `%df' or 1=1#` 拖库。**修复**：统一字符集 + 预编译。

![25 SQLi宽字节](/images/pikachu/25-sqli-widebyte.png)

### 26 insert 注入
- **源码位置**：`vul/sqli/sqli_iu/sqli_reg.php`

```php
$getdata=$_POST;   // 未转义
$query="insert into member(username,pw,sex,phonenum,email,address) values('{$getdata['username']}',md5('{$getdata['password']}'),...)";
```

**利用/回显**：用户名注入 `x' or updatexml(1,concat(0x7e,database(),0x7e),0) or '` 报错泄库名 `~pikachu~`。**修复**：预编译。

![26 SQLi insert](/images/pikachu/26-sqli-insert.png)

### 27 update 注入
- **源码位置**：`vul/sqli/sqli_iu/sqli_edit.php`

```php
$getdata=$_POST;   // 未转义
$query="update member set sex='{$getdata['sex']}',... where username='{$_SESSION['sqli']['username']}'";
```

**利用/回显**：`sex` 字段注入 updatexml 报错泄库名。**修复**：预编译。

![27 SQLi update](/images/pikachu/27-sqli-update.png)

### 28 http header 注入
- **源码位置**：`vul/sqli/sqli_header/sqli_header.php`

```php
$useragent=$_SERVER['HTTP_USER_AGENT'];   // 直接取头，未过滤
$query="insert httpinfo(userid,ipaddress,useragent,...) values('$is_login_id','$remoteipadd','$useragent',...)";
```

**利用/回显**：User-Agent 注入 `x' or updatexml(1,concat(0x7e,database(),0x7e),0) or '` 报错。**修复**：对 `$_SERVER` 头信息同样过滤后再入库。

![28 SQLi http header](/images/pikachu/28-sqli-header.png)

---

## 五、RCE

### 29 命令执行(exec "ping")
- **源码位置**：`vul/rce/rce_ping.php`

```php
$ip=$_POST['ipaddress'];
$result.=shell_exec('ping '.$ip);   // 直接拼接进 shell 命令
```

**利用/回显**：`127.0.0.1 & whoami` 执行系统命令，回显 `laptop-n6vcbrdr\liuru`。**修复**：白名单校验 IP 格式，避免拼接参数。

![29 RCE命令执行](/images/pikachu/29-rce-ping.png)

### 30 代码执行(exec "eval")
- **源码位置**：`vul/rce/rce_eval.php`

```php
if(isset($_POST['submit']) && $_POST['txt'] != null){
    if(@!eval($_POST['txt'])){ $html.="<p>你喜欢的字符还挺奇怪的!</p>"; }
}
```

**利用/回显**：`system('whoami')` 执行，回显 `laptop-n6vcbrdr\liuru`。**修复**：永远不要 `eval` 用户输入。

![30 RCE代码执行](/images/pikachu/30-rce-eval.png)

---

## 六、文件包含 / 下载 / 上传

### 31 本地文件包含(LFI)
- **源码位置**：`vul/fileinclude/fi_local.php`

```php
$filename=$_GET['filename'];
include "include/$filename";   // 变量直接包含，未做白名单
```

**利用/回显**：`filename=../../../README.md` 包含任意文件。**修复**：白名单 + 禁止 `../`。

![31 本地文件包含](/images/pikachu/31-fileinclude-local.png)

### 32 远程文件包含(RFI)
- **源码位置**：`vul/fileinclude/fi_remote.php`

```php
$filename=$_GET['filename'];
include "$filename";   // 需要 allow_url_include=On
```

**利用/回显**：`filename=http://127.0.0.1/pikachu-master/rfi.txt` 远程包含执行 PHP，回显 `RFI_OK laptop-n6vcbrdr\liuru`。**修复**：关闭 `allow_url_include` + 白名单。

![32 远程文件包含](/images/pikachu/32-fileinclude-remote.png)

### 33 不安全文件下载
- **源码位置**：`vul/unsafedownload/execdownload.php`

```php
$file_path="download/{$_GET['filename']}";   // 路径可控，无过滤
```

**利用/回显**：`filename=../../../inc/config.inc.php` 下载源码泄露数据库密码。**修复**：白名单 + `basename()`。

![33 任意文件下载(泄露配置)](/images/pikachu/33-download-leak.png)

### 34 文件上传-客户端绕过
- **源码位置**：`vul/unsafeupload/clientcheck.php` + `inc/uploadfunction.php(upload_client)`
- **关键代码**：`upload_client()` 只 `move_uploaded_file`，完全没校验；唯一校验在前端 JS。
- **利用/回显**：去掉前端 onchange 后传 `shell.php`，访问执行 `whoami`。**修复**：服务端校验。

![34 上传客户端绕过](/images/pikachu/34-upload-clientcheck.png)

### 35 文件上传-MIME 绕过
- **源码位置**：`vul/unsafeupload/servercheck.php` + `inc/uploadfunction.php(upload_sick)`

```php
if(!in_array($_FILES[$key]['type'], $mime)){ /* 只校验客户端传来的 MIME */ }
```

**成因**：`$_FILES['type']` 由浏览器可控。**利用/回显**：把 `shell2.php` MIME 伪造为 `image/jpeg` 上传执行。**修复**：用 `getimagesize`/文件头校验真实类型。

![35 上传MIME绕过](/images/pikachu/35-upload-servercheck.png)

### 36 文件上传-getimagesize 绕过
- **源码位置**：`vul/unsafeupload/getimagesize.php` + `inc/uploadfunction.php(upload)`
- **关键代码**：`upload()` 校验后缀+MIME+`getimagesize()`，但文件头可伪造、保存扩展可控。
- **利用/回显**：`GIF89a` 头 + PHP 代码的 `shell3.jpg` 绕过 getimagesize，再配合 LFI 包含该 `.jpg` 执行 PHP。**修复**：内容校验 + 重命名不可执行扩展 + 独立目录。

![36 上传getimagesize绕过](/images/pikachu/36-upload-getimagesize.png)

---

## 七、越权 / 目录遍历 / 信息泄露

### 37 水平越权
- **源码位置**：`vul/overpermission/op1/op1_mem.php`

```php
$username=escape($link, $_GET['username']);   // 用传参，而非 session 身份
$query="select * from member where username='$username'";
```

**成因**：查询对象用前端传入的 `username`，未与登录态绑定。**利用/回显**：以 lucy 登录，`op1_mem.php?username=lili` 查看 lili 信息。**修复**：用 session 身份。

![37 水平越权](/images/pikachu/37-overpermission-op1.png)

### 38 垂直越权
- **源码位置**：`vul/overpermission/op2/op2_admin_edit.php`

```php
// 只校验登录，没校验 level==1！
if(!check_op2_login($link)){ header("location:op2_login.php"); exit(); }
// 添加用户(本应是 admin 专属)
```

**成因**：只校验登录未校验管理员级别。**利用/回显**：pikachu（普通用户）登录后直接访问 `op2_admin_edit.php` 进入管理页。**修复**：校验 `$_SESSION['op2']['level']==1`。

![38 垂直越权(普通用户视角)](/images/pikachu/38-overpermission-op2-user.png)
![38 垂直越权(进入管理页)](/images/pikachu/38-overpermission-op2-escalate.png)

### 39 目录遍历
- **源码位置**：`vul/dir/dir_list.php`

```php
$filename=$_GET['title'];
require "soup/$filename";   // 直接 require，未过滤 ../
```

**利用/回显**：`title=../../../Dockerfile` 读取任意文件。**修复**：白名单 + 禁止 `../`。

![39 目录遍历](/images/pikachu/39-dir-traversal.png)

### 40 敏感信息泄露
- **源码位置**：`vul/infoleak/findabc.php`
- **关键代码**：登录页源码注释里写死测试账号：

```html
<!-- 测试账号:lili/123456-->
```

**利用/回显**：查看源码发现 `lili/123456`，登录成功。**修复**：删除注释中的敏感信息。

![40 敏感信息泄露(登录页)](/images/pikachu/40-infoleak-login.png)
![40 敏感信息泄露(登录成功)](/images/pikachu/40-infoleak-abc.png)

---

## 八、反序列化 / XXE / 重定向 / SSRF

### 41 PHP 反序列化
- **源码位置**：`vul/unserilization/unser.php`

```php
class S{ var $test = "pikachu"; }
if(isset($_POST['o'])){
    if(!@$unser = unserialize($s)){ ... }
    else{ $html.="<p>{$unser->test}</p>"; }   // 反序列化结果直接输出
}
```

**利用/回显**：构造 `O:1:"S":1:{s:4:"test";s:N:"<script>...";}` 使 `$unser->test` 为 XSS 载荷触发。**修复**：不要反序列化用户输入，或限制类/字段。

![41 PHP反序列化](/images/pikachu/41-unserialize.png)

### 42 XXE
- **源码位置**：`vul/xxe/xxe_1.php`

```php
$data = @simplexml_load_string($xml,'SimpleXMLElement',LIBXML_NOENT);  // 开启外部实体
if($data){ $html.="<pre>{$data}</pre>"; }
```

**成因**：`LIBXML_NOENT` 允许解析外部实体。**利用/回显**：`<!ENTITY f SYSTEM "file:///C:/Windows/win.ini">` 读取系统文件。**修复**：禁用外部实体。

![42 XXE](/images/pikachu/42-xxe.png)

### 43 不安全 URL 跳转
- **源码位置**：`vul/urlredirect/urlredirect.php`

```php
$url = $_GET['url'];
if($url == 'i'){ ... } else { header("location:{$url}"); }   // 任意跳转
```

**利用/回显**：`?url=https://example.com` 跳转外站。**修复**：白名单校验目标 URL。

![43 URL重定向](/images/pikachu/43-urlredirect.png)

### 44 SSRF(curl)
- **源码位置**：`vul/ssrf/ssrf_curl.php`

```php
$URL = $_GET['url'];
$CH = curl_init($URL);
$RES = curl_exec($CH);   // 后端请求并回显结果
echo $RES;
```

**利用/回显**：`url=file:///C:/Windows/win.ini` 读取本地文件。**修复**：限制协议与地址白名单。

![44 SSRF(curl)](/images/pikachu/44-ssrf-curl.png)

### 45 SSRF(file_get_contents)
- **源码位置**：`vul/ssrf/ssrf_fgc.php`

```php
$filename = $_GET['file'];
$str = file_get_contents($filename);   // 任意协议/文件读取
echo $str;
```

**利用/回显**：`file=C:/Windows/win.ini` 读取本地文件。**修复**：白名单 + 禁 `php://`/`file://`。

![45 SSRF(file_get_contents)](/images/pikachu/45-ssrf-fgc.png)

---

## 修复要点总结

| 类别 | 通用修复 |
|---|---|
| SQL 注入 | 一律使用**预编译语句(PDO/mysqli prepare) + 参数绑定** |
| XSS | 输出统一 `htmlspecialchars($s, ENT_QUOTES, 'UTF-8')`，JS/CSS/属性上下文单独转义 |
| CSRF | 加 **CSRF Token**（会话绑定、POST 提交） |
| RCE/文件包含 | 绝不 `eval`/`shell_exec` 拼接用户输入；包含用白名单 |
| 文件上传 | 服务端校验 + 重命名 + 独立目录 + 禁执行 |
| 越权 | 身份从会话取，服务端校验角色权限 |
| SSRF/重定向 | 目标 URL 白名单，限制协议 |
| 反序列化/XXE | 禁反序列化用户输入；禁外部实体 |

---

*本文 45 关均已完成实际利用并截图，源码分析与回显结果一致。*
