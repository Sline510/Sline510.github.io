---
title: curl 与 Nmap 命令实操：HTTP 响应、端口过滤与系统识别
date: 2026-11-04 19:00:00
description: 按截图逐条解析 curl 与 Nmap 命令，记录 HTTP 响应头、API 根入口、端口状态、系统识别和 http-enum 的实际输出与边界。
categories:
  - 网络安全
tags:
  - curl
  - Nmap
  - 信息收集
  - 网络安全
---

> 这篇是 curl 与 Nmap 的实操记录。截图均来自 2026-11-04 的终端页面；代码块按截图转录，为便于阅读只调整了空行和对齐，命令、数值和输出文字没有改动。
>
> 截图中的目标是 `10.34.22.29`，属于 `10.0.0.0/8` 私有地址段，按实验环境处理。请只对自己拥有或已获得明确授权的目标执行扫描；本文不对目标做截图之外的额外操作。

## 一、命令总览

这次实操一共执行了 5 条命令，可以分成两层：

- **HTTP 层**：用 `curl` 观察响应头、状态码和 API 返回内容；
- **网络层**：用 `nmap` 观察端口状态、服务映射、操作系统指纹和 NSE 脚本结果。

| 序号 | 命令 | 目的 | 截图中的关键结果 |
| --- | --- | --- | --- |
| 1 | `curl -I https://www.baidu.com` | 只请求 HTTP 响应头，不下载正文 | `200 OK`、`Server: bfe`、`Content-Length: 0` |
| 2 | `curl https://api.github.com` | 请求 GitHub API 根入口，查看返回的 JSON | 返回一组 API URL 模板 |
| 3 | `nmap -p 22,80,443 10.34.22.29` | 只扫描 22、80、443 三个 TCP 端口 | 三个端口均为 `filtered` |
| 4 | `nmap -O -F 10.34.22.29` | 快速扫描常见端口并尝试识别操作系统 | 135/139/445 开放，操作系统识别无精确匹配 |
| 5 | `nmap -p 80 --script http-enum 10.34.22.29` | 在 80 端口上调用 NSE 脚本枚举常见 Web 路径 | 80 端口 `filtered`，脚本没有拿到 HTTP 响应 |

需要先说明时区：`curl` 响应头里的 `Date` 使用 GMT，而 Nmap 终端里的时间是 EST。两者不能直接按字面比较；例如截图中的 `05:47 EST` 换算成 UTC 是 `10:47 UTC`，和 `curl` 的 `10:46:32 GMT` 基本处于同一时间段。

下面按截图逐条拆开。

## 二、`curl -I`：只取响应头

### 2.1 命令与目的

```bash
curl -I https://www.baidu.com
```

`-I` 是 `--head` 的简写，表示发送 **HEAD** 请求。HEAD 与 GET 请求同一个资源，但方法不同：服务器只返回响应头，不返回响应体。它适合快速确认：

- 目标是否可达、返回什么状态码；
- 使用了什么协议版本；
- 响应头中有哪些缓存、内容类型和服务端标识；
- 是否发生跳转（这次没有跳转）。

### 2.2 截图与实际输出

![curl -I 获取百度响应头](/images/curl-nmap/curl-head.png)

*图 1：`curl -I https://www.baidu.com` 的终端输出，截图时间 2026-11-04。*

```http
HTTP/1.1 200 OK
Cache-Control: private, no-cache, no-store, proxy-revalidate, no-transform
Content-Length: 0
Content-Type: text/html
Pragma: no-cache
Server: bfe
Date: Wed, 04 Nov 2026 10:46:32 GMT
```

### 2.3 逐行解读

| 字段 | 截图中的值 | 说明 |
| --- | --- | --- |
| 状态行 | `HTTP/1.1 200 OK` | 使用 HTTP/1.1，服务器返回 200，表示请求被成功处理 |
| `Cache-Control` | `private, no-cache, no-store, proxy-revalidate, no-transform` | 缓存控制指令，涉及私有缓存、是否需要重新验证、是否允许存储和转换 |
| `Content-Length` | `0` | 响应头声明的长度字段；HEAD 不返回正文，不能仅凭 0 判断页面没有内容 |
| `Content-Type` | `text/html` | 响应头声明的媒体类型是 HTML |
| `Pragma` | `no-cache` | 兼容 HTTP/1.0 的缓存控制字段 |
| `Server` | `bfe` | 服务端自报的软件或接入层标识；该字段可以被修改，不能只凭它推断完整后端架构 |
| `Date` | `Wed, 04 Nov 2026 10:46:32 GMT` | 服务器生成响应的时间，使用 GMT |

这里最容易误读的是 `Content-Length: 0`。因为 `-I` 只取响应头，本来就不下载正文；这个 0 是这次 HEAD 响应里的长度字段，不代表用浏览器访问首页时页面一定为空。要判断正文，应该去掉 `-I` 或使用 `curl -o` 保存响应体后再检查。

另外，`Server: bfe` 只是一个响应头字段，能说明服务端愿意暴露这个标识，但不能单独证明后端用了什么框架、什么语言或什么部署结构。

## 三、`curl`：GET 一个 API 根入口

### 3.1 命令与目的

```bash
curl https://api.github.com
```

不带 `-I` 时，`curl` 默认发送 **GET** 请求，并把响应体输出到标准输出。这里请求的是 GitHub API 的根路径，目的是观察一个 JSON API 的入口返回什么。

### 3.2 截图与实际输出

![curl 请求 GitHub API 根入口](/images/curl-nmap/curl-api.png)

*图 2：`curl https://api.github.com` 的终端输出，截图时间 2026-11-04。下面按截图转录返回的 JSON。*

返回内容是一个 JSON 对象，下面摘录前几行和最后一行：

```json
{
  "current_user_url": "https://api.github.com/user",
  "current_user_authorizations_html_url": "https://github.com/settings/connections/applications{/client_id}",
  "authorizations_url": "https://api.github.com/authorizations",
  "code_search_url": "https://api.github.com/search/code?q={query}{&page,per_page,sort,order}",
  "commit_search_url": "https://api.github.com/search/commits?q={query}{&page,per_page,sort,order}",
  "emails_url": "https://api.github.com/user/emails",
  "emojis_url": "https://api.github.com/emojis",
  "events_url": "https://api.github.com/events",
  "feeds_url": "https://api.github.com/feeds",
  "followers_url": "https://api.github.com/user/followers",
  "following_url": "https://api.github.com/user/following{/target}",
  "gists_url": "https://api.github.com/gists{/gist_id}",
  "hub_url": "https://api.github.com/hub",
  "issue_search_url": "https://api.github.com/search/issues?q={query}{&page,per_page,sort,order}",
  "issues_url": "https://api.github.com/issues",
  "keys_url": "https://api.github.com/user/keys",
  "label_search_url": "https://api.github.com/search/labels?q={query}&repository_id={repository_id}{&page,per_page}",
  "notifications_url": "https://api.github.com/notifications",
  "organization_url": "https://api.github.com/orgs/{org}",
  "organization_repositories_url": "https://api.github.com/orgs/{org}/repos{?type,page,per_page,sort}",
  "organization_teams_url": "https://api.github.com/orgs/{org}/teams",
  "public_gists_url": "https://api.github.com/gists/public",
  "rate_limit_url": "https://api.github.com/rate_limit",
  "repository_url": "https://api.github.com/repos/{owner}/{repo}",
  "repository_search_url": "https://api.github.com/search/repositories?q={query}{&page,per_page,sort,order}",
  "current_user_repositories_url": "https://api.github.com/user/repos{?type,page,per_page,sort}",
  "starred_url": "https://api.github.com/user/starred{/owner}{/repo}",
  "starred_gists_url": "https://api.github.com/gists/starred",
  "topic_search_url": "https://api.github.com/search/topics?q={query}{&page,per_page}",
  "user_url": "https://api.github.com/users/{user}",
  "user_organizations_url": "https://api.github.com/user/orgs",
  "user_repositories_url": "https://api.github.com/users/{user}/repos{?type,page,per_page,sort}",
  "user_search_url": "https://api.github.com/search/users?q={query}{&page,per_page,sort,order}"
}
```

### 3.3 这组 JSON 在表达什么

这不是某个用户的资料，而是 API 根入口返回的“链接目录”。每个键对应一个 API 能力，值是一个 URL 或 URL 模板：

- `current_user_url` 指向当前认证用户；
- `repository_url` 里的 `{owner}`、`{repo}` 需要替换成真实的用户名和仓库名；
- `repository_search_url` 里的 `{query}`、`{&page,per_page,sort,order}` 是 URI 模板变量；
- `rate_limit_url` 指向速率限制信息。

这次 `curl` 没有附加认证头，返回的是 API 根入口的公开链接集合。仅凭这个页面不能推断“所有 API 都不需要认证”；涉及用户、仓库、组织等具体资源时，是否可访问取决于对应接口和权限。

另外，`curl` 默认把响应体直接打印到终端，所以截图里看到的是原始 JSON，没有经过格式化工具处理；也没有用 `-o` 保存文件。

## 四、`nmap -p`：只扫描指定端口

### 4.1 命令与目的

```bash
nmap -p 22,80,443 10.34.22.29
```

`-p` 用逗号列出要扫描的端口。这条命令只关心三个常见的 TCP 端口：

- `22`：SSH；
- `80`：HTTP；
- `443`：HTTPS。

它不做全端口扫描，也不做操作系统识别，适合先确认这几个服务是否可达。

### 4.2 截图与实际输出

![nmap 扫描 22、80、443 端口](/images/curl-nmap/nmap-basic.png)

*图 3：`nmap -p 22,80,443 10.34.22.29` 的终端输出，截图时间 2026-11-04 05:47 EST。*

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-04 05:47 EST
Nmap scan report for 10.34.22.29
Host is up (0.00078s latency).

PORT    STATE    SERVICE
22/tcp  filtered ssh
80/tcp  filtered http
443/tcp filtered https

Nmap done: 1 IP address (1 host up) scanned in 1.53 seconds
```

### 4.3 `filtered` 应该怎么理解

三个端口的状态都是 `filtered`，不是 `open`，也不是 `closed`。

- `open`：目标返回了允许连接的响应，服务大概率在监听；
- `closed`：目标明确拒绝了连接，端口没有服务监听；
- `filtered`：Nmap 没有拿到应有的响应，无法判断端口到底是开放还是关闭。常见原因是防火墙、ACL 或中间设备丢弃了探测包，也可能是网络路径本身有问题。

所以这张截图能说明的是：**Nmap 对这三个端口的探测被过滤或没有响应**。它不能说明“22、80、443 一定没有服务”，也不能说明“主机没有开放任何端口”。

`Host is up (0.00078s latency)` 说明 Nmap 认为主机可达，延迟数值很低。这个数值只表示这次探测的往返时间，不能单独用来判断物理位置；私有地址和低延迟更符合内网或虚拟实验环境的表现，但仍应以实际网络拓扑为准。

## 五、`nmap -O -F`：快速扫描与系统识别

### 5.1 命令与目的

```bash
nmap -O -F 10.34.22.29
```

这条命令组合了两个参数：

- `-F`：fast scan，只扫描 Nmap 认为最常见的 100 个端口，不是全端口；
- `-O`：开启操作系统识别，通过 TCP/IP 栈指纹等特征猜测目标系统。

`-O` 通常需要 root 或管理员权限；截图里的提示符是 root，符合这一条件。

### 5.2 截图与实际输出

![nmap 快速扫描与操作系统识别](/images/curl-nmap/nmap-os-enum.png)

*图 4：`nmap -O -F` 与 `nmap -p 80 --script http-enum` 的连续终端记录，截图时间 2026-11-04 05:49 EST。为便于排版，图片从第二条命令开始截取。*

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-04 05:49 EST
Nmap scan report for 10.34.22.29
Host is up (0.00050s latency).
Not shown: 97 filtered tcp ports (no-response)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows XP SP3 or Windows 7 or Windows Server 2012 (97%), VMware Player virtual NAT device (97%), Microsoft Windows XP SP3 (95%), DD-WRT v24-sp2 (Linux 2.4.37) (94%), Actiontec MI424WR-GEN3I WAP (93%), Linux 3.2 (91%), Linux 4.4 (91%), DVTEL DVT-9540DW network camera (90%), BlueArc Titan 2100 NAS device (88%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.72 seconds
```

### 5.3 结果解读

`-F` 扫的是 100 个常见端口，输出里说 `Not shown: 97 filtered tcp ports (no-response)`，同时列出了 3 个 `open` 端口：

- `135/tcp open msrpc`
- `139/tcp open netbios-ssn`
- `445/tcp open microsoft-ds`

这三个端口常出现在 Windows 的 RPC、NetBIOS 和 SMB 场景中，但端口号只是 Nmap 的服务映射，不能仅凭 135/139/445 就断定目标一定是 Windows，也不能据此判断存在漏洞。服务可能被模拟、转发或由其他实现监听。

更重要的是操作系统识别的警告：

> `OSScan results may be unreliable because we could not find at least 1 open and 1 closed port`

这次 100 个常见端口中，97 个是 `filtered`，3 个是 `open`，没有可用于对比的 `closed` 端口。Nmap 的 OS 识别需要比较目标对不同探测包的响应，缺少“关闭端口”的样本时，结果就会不可靠。

所以下面的 `Aggressive OS guesses` 只能当作候选：

- `Microsoft Windows XP SP3 or Windows 7 or Windows Server 2012 (97%)`
- `VMware Player virtual NAT device (97%)`
- `Microsoft Windows XP SP3 (95%)`
- `DD-WRT v24-sp2 (Linux 2.4.37) (94%)`
- `Actiontec MI424WR-GEN3I WAP (93%)`
- `Linux 3.2 (91%)`
- `Linux 4.4 (91%)`
- `DVTEL DVT-9540DW network camera (90%)`
- `BlueArc Titan 2100 NAS device (88%)`

百分比是 Nmap 指纹匹配的置信度，不是严格的概率结论；`No exact OS matches` 也明确说明没有精确匹配。换句话说，截图可以支持“目标的操作系统指纹与这些系统有相似之处”，但不能写成“目标就是 Windows 7”或“目标就是某个虚拟机”。

## 六、`nmap --script http-enum`：端口不通时脚本也不会出结果

### 6.1 命令与目的

```bash
nmap -p 80 --script http-enum 10.34.22.29
```

- `-p 80`：只针对 80 端口；
- `--script http-enum`：调用 NSE（Nmap Scripting Engine）的 `http-enum` 脚本，尝试枚举常见的 Web 路径。

这个脚本只有在 HTTP 服务可达时才有意义。它会向目标发送 HTTP 请求，因此也属于会产生实际流量的主动探测，必须得到授权。

### 6.2 截图与实际输出

同一张图的下半部分：

```text
Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-04 05:49 EST
Nmap scan report for 10.34.22.29
Host is up (0.00054s latency).

PORT   STATE    SERVICE
80/tcp filtered http

Nmap done: 1 IP address (1 host up) scanned in 0.72 seconds
```

### 6.3 为什么没有路径结果

输出里 80 端口仍然是 `filtered`，说明 Nmap 没有建立到 80 端口的 HTTP 连接。`http-enum` 没有拿到响应，自然也不会列出任何路径。

这里不能写成“目标没有 Web 目录”或“目标没有 Web 服务”。更准确的说法是：**脚本没有执行到能够判断 Web 路径的阶段**。如果端口是 `open`，脚本才会继续发送 HTTP 请求；如果端口是 `closed`，同样不会得到 HTTP 响应。

这也是主动探测的一个基本顺序：先确认端口可达，再谈服务识别和内容枚举。端口层就被过滤时，后面的 Web 枚举没有输入。

## 七、结果边界总结

把这次输出放在一起，可以整理出下面这张表：

| 观察到的现象 | 可以说明 | 不能说明 |
| --- | --- | --- |
| `22/80/443 filtered` | 探测被过滤或没有响应，Nmap 无法判断端口状态 | 端口一定关闭、服务一定不存在 |
| `135/139/445 open` | TCP 连接能够建立，Nmap 将其映射为 msrpc、netbios-ssn、microsoft-ds | 目标一定是 Windows，或一定存在 SMB/RPC 漏洞 |
| `Windows ... (97%)` | 操作系统指纹与候选系统相似 | 目标就是某个具体 Windows 版本 |
| `No exact OS matches` | 没有精确匹配，测试条件不理想 | 可以下确定性的系统结论 |
| `http-enum` 无路径输出 | 80 端口 filtered，脚本没有拿到 HTTP 响应 | 目标没有 Web 目录 |

这次实操最值得记住的三点是：

1. **`curl -I` 和 `curl` 的差别是请求方法**。前者只取响应头，后者默认 GET 并输出正文；不要把 HEAD 的 `Content-Length: 0` 当成页面为空。
2. **`filtered` 不是 `closed`**。Nmap 的端口状态描述的是“探测结果”，不是对服务存在性的最终判决。
3. **OS 识别和 NSE 都有前提**。`-O` 需要足够的开放/关闭端口样本，`http-enum` 需要可达的 HTTP 服务；条件不满足时，正确做法是记录“无法判断”，而不是补一个猜测。

最后再强调一次：`10.34.22.29` 是私有地址，但私有地址不等于可以随意扫描。端口扫描、操作系统识别和 NSE 脚本都会产生真实请求，请只在自有资产或明确授权的实验环境中使用。

## 参考资料

- curl 手册：<https://curl.se/docs/manpage.html>
- Nmap 手册：<https://nmap.org/book/man.html>
- Nmap 端口扫描技术：<https://nmap.org/book/man-port-scanning-techniques.html>
- NSE `http-enum` 文档：<https://nmap.org/nsedoc/scripts/http-enum.html>
- GitHub API 根入口：<https://api.github.com/>
