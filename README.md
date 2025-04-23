# PekVpnProxy

PekVpnProxy 是一个功能强大的 Socks5 代理工具，支持 HTTP 和 HTTPS 协议，可用于网络调试、安全测试和网络访问。该工具提供了服务端和客户端两种模式，支持用户认证、自定义请求路径以及 SSL/TLS 加密连接。

## 功能特点

### Socks5 服务端
- 支持 IPv4 和域名解析
- 支持用户名/密码认证
- 支持多客户端并发连接
- 支持 CONNECT 命令
- 详细的日志记录

### Socks5 客户端
- 支持 HTTP 和 HTTPS 协议
- 支持 SSL/TLS 加密连接
- 支持自定义请求路径
- 支持分块传输编码 (chunked transfer encoding)
- 智能超时处理和重试机制
- 详细的连接状态和响应信息

## 系统要求

- .NET 9.0 或更高版本
- Windows、Linux 或 macOS 操作系统

## 安装方法

### 从源代码构建

1. 克隆仓库
```bash
git clone https://github.com/PeiKeSmart/PekVpnProxy.git
```

2. 进入项目目录
```bash
cd PekVpnProxy
```

3. 构建项目
```bash
dotnet build
```

4. 运行程序
```bash
dotnet run --project PekVpnProxy
```

## 使用方法

### 启动 Socks5 服务端

1. 运行程序并选择模式 1（服务端模式）
2. 配置监听地址（默认：0.0.0.0）
3. 配置监听端口（默认：1080）
4. 选择是否启用认证
5. 如果启用认证，添加用户名和密码

示例：
```
Socks5代理测试工具
=================

请选择模式:
1. 启动Socks5服务端
2. 启动Socks5客户端
请输入选择 (默认: 1): 1

Socks5服务端模式
=================

请输入监听地址 (默认: 0.0.0.0): 
请输入监听端口 (默认: 1080): 
是否启用认证? (y/n, 默认: n): y

添加测试用户:
请输入用户名: admin
请输入密码: password
用户 admin 添加成功

是否继续添加用户? (y/n, 默认: n): n

已添加 1 个用户

服务已启动，按任意键停止服务...
```

### 使用 Socks5 客户端

1. 运行程序并选择模式 2（客户端模式）
2. 配置 Socks5 代理服务器地址（默认：127.0.0.1）
3. 配置 Socks5 代理服务器端口（默认：1080）
4. 选择是否需要认证，如需要则输入用户名和密码
5. 配置目标服务器地址（如 www.google.com）
6. 配置目标服务器端口（HTTP 为 80，HTTPS 为 443）
7. 配置请求路径（默认：/）

示例：
```
Socks5代理测试工具
=================

请选择模式:
1. 启动Socks5服务端
2. 启动Socks5客户端
请输入选择 (默认: 1): 2

Socks5客户端模式
=================

请输入Socks5代理服务器地址 (默认: 127.0.0.1): 
请输入Socks5代理服务器端口 (默认: 1080): 
是否需要认证? (y/n, 默认: n): y
请输入用户名: admin
请输入密码: password

请输入目标服务器地址 (默认: www.google.com): www.example.com
请输入目标服务器端口 (默认: 80): 443
请输入请求路径 (默认: /): /index.html

正在连接...
成功通过Socks5代理连接到 www.example.com:443
成功升级到SSL/TLS加密连接

发送HTTP GET请求...
使用HTTPS协议发送请求
连接状态: HTTPS 连接 (SSL/TLS加密), 加密算法: Tls13, 加密强度: 256 位
请求URL: https://www.example.com/index.html
请求头部:
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 PekVpnProxy
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close

...
```

## 高级功能

### SSL/TLS 支持

PekVpnProxy 客户端模式支持 SSL/TLS 加密连接，当连接到端口 443 时会自动尝试升级到 SSL/TLS 连接。您可以查看连接状态信息，包括加密算法和加密强度。

### 分块传输编码处理

客户端模式能够正确处理 HTTP 分块传输编码 (chunked transfer encoding)，自动检测并解码分块内容，确保完整接收响应数据。

### 超时处理和重试机制

客户端模式实现了智能超时处理和重试机制，避免无限等待，同时尽可能确保完整接收响应数据。

## 注意事项

- 本工具仅用于网络调试、学习和研究目的
- 在生产环境中使用时，请确保启用认证并使用强密码
- SSL/TLS 证书验证目前处于测试模式，接受所有证书，生产环境中应进行适当的证书验证
- 使用代理访问网站时请遵守相关法律法规和网站使用条款

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议。请通过 GitHub Issues 或 Pull Requests 参与项目开发。

## 许可证

本项目采用 MIT 许可证，详情请参阅 [LICENSE](LICENSE) 文件。

## 联系方式

如有问题或建议，请通过 GitHub Issues 与我们联系。

---

**免责声明**：本工具仅供学习和研究网络协议之用，使用者应遵守相关法律法规，不得用于非法用途。开发者对使用者的行为不承担任何法律责任。
