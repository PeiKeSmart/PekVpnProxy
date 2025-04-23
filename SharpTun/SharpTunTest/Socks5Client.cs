using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SharpTunTest;

/// <summary>
/// 统一的Socks5客户端，兼容PekVpnProxy和SharpTunTest
/// </summary>
public class Socks5Client {
    private readonly string _proxyHost;
    private readonly int _proxyPort;
    private readonly string? _username;
    private readonly string? _password;
    private TcpClient? _tcpClient;
    private NetworkStream? _networkStream;
    private SslStream? _sslStream;
    private Stream? _stream; // 当前使用的流（可能是NetworkStream或SslStream）
    private bool _isSecure; // 是否使用SSL/TLS
    private readonly bool _verbose; // 是否输出详细日志

    /// <summary>
    /// 初始化Socks5客户端
    /// </summary>
    /// <param name="proxyHost">Socks5代理服务器地址</param>
    /// <param name="proxyPort">Socks5代理服务器端口</param>
    /// <param name="username">用户名（可选）</param>
    /// <param name="password">密码（可选）</param>
    /// <param name="verbose">是否输出详细日志</param>
    public Socks5Client(string proxyHost, int proxyPort, string? username = null, string? password = null, bool verbose = true)
    {
        _proxyHost = proxyHost;
        _proxyPort = proxyPort;
        _username = username;
        _password = password;
        _verbose = verbose;
    }

    /// <summary>
    /// 连接到目标服务器（通过Socks5代理）
    /// </summary>
    /// <param name="destinationHost">目标服务器地址</param>
    /// <param name="destinationPort">目标服务器端口</param>
    /// <returns>连接成功返回true，否则返回false</returns>
    public async Task<bool> ConnectAsync(string destinationHost, int destinationPort)
    {
        try
        {
            // 连接到Socks5代理服务器
            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(_proxyHost, _proxyPort);
            _networkStream = _tcpClient.GetStream();
            _stream = _networkStream; // 初始化时使用NetworkStream
            _isSecure = false;

            // 进行Socks5握手
            if (!await PerformHandshakeAsync())
            {
                LogMessage("Socks5握手失败");
                return false;
            }

            // 发送连接请求
            if (!await SendConnectRequestAsync(destinationHost, destinationPort))
            {
                LogMessage("Socks5连接请求失败");
                return false;
            }

            LogMessage($"成功通过Socks5代理连接到 {destinationHost}:{destinationPort}");

            // 如果是HTTPS连接（端口443），升级到SSL/TLS
            if (destinationPort == 443)
            {
                if (await UpgradeToSslAsync(destinationHost))
                {
                    LogMessage($"成功升级到SSL/TLS加密连接");
                }
                else
                {
                    LogMessage($"升级到SSL/TLS失败，使用非加密连接继续");
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            LogMessage($"连接失败: {ex.Message}");
            Disconnect();
            return false;
        }
    }

    /// <summary>
    /// 通过SOCKS5代理创建一个TCP连接（同步方法，兼容SharpTunTest）
    /// </summary>
    /// <param name="destinationHost">目标主机</param>
    /// <param name="destinationPort">目标端口</param>
    /// <returns>已连接的Socket</returns>
    public Socket CreateConnection(string destinationHost, int destinationPort)
    {
        try
        {
            // 连接到SOCKS5代理服务器
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(_proxyHost, _proxyPort);

            // 进行SOCKS5握手
            PerformSocks5HandshakeSync(socket);

            // 请求连接到目标服务器
            ConnectToDestinationSync(socket, destinationHost, destinationPort);

            LogMessage($"成功通过Socks5代理连接到 {destinationHost}:{destinationPort}（同步方式）");

            return socket;
        }
        catch (Exception ex)
        {
            LogMessage($"同步连接失败: {ex.Message}");
            throw; // 重新抛出异常，保持与原始行为一致
        }
    }

    /// <summary>
    /// 发送数据
    /// </summary>
    /// <param name="data">要发送的数据</param>
    public async Task SendAsync(byte[] data)
    {
        if (_stream == null || !_tcpClient!.Connected)
            throw new InvalidOperationException("未连接到服务器");

        await _stream.WriteAsync(data);
    }

    /// <summary>
    /// 接收数据
    /// </summary>
    /// <param name="buffer">接收缓冲区</param>
    /// <param name="timeout">超时时间（毫秒），默认30秒</param>
    /// <returns>接收到的字节数</returns>
    public async Task<int> ReceiveAsync(byte[] buffer, int timeout = 30000)
    {
        if (_stream == null || !_tcpClient!.Connected)
            throw new InvalidOperationException("未连接到服务器");

        // 设置读取超时
        _tcpClient.ReceiveTimeout = timeout;

        try
        {
            // 使用超时任务
            var readTask = _stream.ReadAsync(buffer).AsTask(); // 将ValueTask<int>转换为Task<int>

            // 等待读取完成或超时
            if (await Task.WhenAny(readTask, Task.Delay(timeout)) == readTask)
            {
                // 读取成功
                return await readTask;
            }
            else
            {
                // 超时
                LogMessage($"接收数据超时 ({timeout} 毫秒)");
                return 0;
            }
        }
        catch (IOException ex)
        {
            // 连接已关闭
            LogMessage($"接收数据时连接关闭: {ex.Message}");
            return 0;
        }
        catch (Exception ex)
        {
            LogMessage($"接收数据错误: {ex.Message}");
            return 0;
        }
    }

    /// <summary>
    /// 升级到SSL/TLS加密连接
    /// </summary>
    /// <param name="targetHost">目标主机名（用于证书验证）</param>
    /// <returns>升级成功返回true，否则返回false</returns>
    private async Task<bool> UpgradeToSslAsync(string targetHost)
    {
        try
        {
            if (_networkStream == null || _tcpClient == null)
                return false;

            // 创建SslStream，不验证服务器证书
            _sslStream = new SslStream(_networkStream, false, new RemoteCertificateValidationCallback(ValidateServerCertificate));

            // 设置TLS选项
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                RemoteCertificateValidationCallback = ValidateServerCertificate
            };

            // 进行TLS握手
            await _sslStream.AuthenticateAsClientAsync(sslOptions);

            // 切换到加密流
            _stream = _sslStream;
            _isSecure = true;

            return true;
        }
        catch (Exception ex)
        {
            LogMessage($"SSL/TLS升级失败: {ex.Message}");
            // 失败时回退到非加密流
            _stream = _networkStream;
            _isSecure = false;
            return false;
        }
    }

    /// <summary>
    /// 验证服务器证书
    /// </summary>
    private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        // 为了测试目的，我们接受所有证书
        // 在生产环境中应该进行适当的证书验证
        return true;
    }

    /// <summary>
    /// 获取连接状态信息
    /// </summary>
    /// <returns>连接状态信息</returns>
    public string GetConnectionInfo()
    {
        if (_tcpClient == null || _stream == null)
            return "未连接";

        string secureStatus = _isSecure ? "SSL/TLS加密" : "非加密";
        string protocol = _isSecure ? "HTTPS" : "HTTP";

        if (_isSecure && _sslStream != null)
        {
            return $"{protocol} 连接 ({secureStatus}), 加密算法: {_sslStream.SslProtocol}, 加密强度: {_sslStream.CipherStrength} 位";
        }

        return $"{protocol} 连接 ({secureStatus})";
    }

    /// <summary>
    /// 断开连接
    /// </summary>
    public void Disconnect()
    {
        // 先关闭SSL流（如果存在）
        if (_sslStream != null)
        {
            _sslStream.Close();
            _sslStream = null;
        }

        // 关闭网络流
        if (_networkStream != null)
        {
            _networkStream.Close();
            _networkStream = null;
        }

        // 关闭TCP客户端
        if (_tcpClient != null)
        {
            _tcpClient.Close();
            _tcpClient = null;
        }

        // 重置引用
        _stream = null;
        _isSecure = false;
    }

    /// <summary>
    /// 执行Socks5握手（异步）
    /// </summary>
    private async Task<bool> PerformHandshakeAsync()
    {
        if (_stream == null)
            return false;

        // 构建握手请求
        byte[] handshakeRequest;
        if (string.IsNullOrEmpty(_username) || string.IsNullOrEmpty(_password))
        {
            // 无认证方式
            handshakeRequest = new byte[] { 0x05, 0x01, 0x00 };
        }
        else
        {
            // 用户名密码认证方式
            handshakeRequest = new byte[] { 0x05, 0x02, 0x00, 0x02 }; // 支持无认证和用户名密码认证
        }

        // 发送握手请求
        await _stream.WriteAsync(handshakeRequest);

        // 接收握手响应
        byte[] handshakeResponse = new byte[2];
        int bytesRead = await _stream.ReadAsync(handshakeResponse, 0, 2).ConfigureAwait(false);
        if (bytesRead < 2 || handshakeResponse[0] != 0x05)
        {
            LogMessage("无效的Socks5握手响应");
            return false;
        }

        // 检查认证方法
        byte authMethod = handshakeResponse[1];
        if (authMethod == 0xFF)
        {
            LogMessage("服务器不支持任何认证方法");
            return false;
        }

        // 如果需要用户名密码认证
        if (authMethod == 0x02 && !string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
        {
            return await PerformUsernamePasswordAuthAsync();
        }

        return true;
    }

    /// <summary>
    /// 执行用户名密码认证（异步）
    /// </summary>
    private async Task<bool> PerformUsernamePasswordAuthAsync()
    {
        if (_stream == null || string.IsNullOrEmpty(_username) || string.IsNullOrEmpty(_password))
            return false;

        // 构建认证请求
        byte[] usernameBytes = Encoding.ASCII.GetBytes(_username);
        byte[] passwordBytes = Encoding.ASCII.GetBytes(_password);

        byte[] authRequest = new byte[3 + usernameBytes.Length + passwordBytes.Length];
        authRequest[0] = 0x01; // 认证子版本
        authRequest[1] = (byte)usernameBytes.Length;
        Array.Copy(usernameBytes, 0, authRequest, 2, usernameBytes.Length);
        authRequest[2 + usernameBytes.Length] = (byte)passwordBytes.Length;
        Array.Copy(passwordBytes, 0, authRequest, 3 + usernameBytes.Length, passwordBytes.Length);

        // 发送认证请求
        await _stream.WriteAsync(authRequest);

        // 接收认证响应
        byte[] authResponse = new byte[2];
        int bytesRead = await _stream.ReadAsync(authResponse, 0, 2).ConfigureAwait(false);
        if (bytesRead < 2 || authResponse[0] != 0x01)
        {
            LogMessage("无效的认证响应");
            return false;
        }

        // 检查认证结果
        if (authResponse[1] != 0x00)
        {
            LogMessage("认证失败");
            return false;
        }

        return true;
    }

    /// <summary>
    /// 发送连接请求（异步）
    /// </summary>
    private async Task<bool> SendConnectRequestAsync(string destinationHost, int destinationPort)
    {
        if (_stream == null)
            return false;

        // 构建连接请求
        byte[] connectRequest;
        byte addressType;
        byte[] addressBytes;

        // 尝试解析IP地址
        if (IPAddress.TryParse(destinationHost, out IPAddress? ipAddress))
        {
            if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                // IPv4地址
                addressType = 0x01;
                addressBytes = ipAddress.GetAddressBytes();
            }
            else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // IPv6地址
                addressType = 0x04;
                addressBytes = ipAddress.GetAddressBytes();
            }
            else
            {
                LogMessage("不支持的IP地址类型");
                return false;
            }
        }
        else
        {
            // 域名
            addressType = 0x03;
            byte[] domainBytes = Encoding.ASCII.GetBytes(destinationHost);
            addressBytes = new byte[domainBytes.Length + 1];
            addressBytes[0] = (byte)domainBytes.Length;
            Array.Copy(domainBytes, 0, addressBytes, 1, domainBytes.Length);
        }

        // 构建完整的连接请求
        connectRequest = new byte[4 + addressBytes.Length + 2];
        connectRequest[0] = 0x05; // Socks版本
        connectRequest[1] = 0x01; // 连接命令
        connectRequest[2] = 0x00; // 保留字段
        connectRequest[3] = addressType; // 地址类型
        Array.Copy(addressBytes, 0, connectRequest, 4, addressBytes.Length);

        // 添加端口（网络字节序，大端）
        connectRequest[4 + addressBytes.Length] = (byte)(destinationPort >> 8);
        connectRequest[4 + addressBytes.Length + 1] = (byte)(destinationPort & 0xFF);

        // 发送连接请求
        await _stream.WriteAsync(connectRequest);

        // 接收连接响应
        byte[] responseHeader = new byte[4];
        int bytesRead = await _stream.ReadAsync(responseHeader, 0, 4).ConfigureAwait(false);
        if (bytesRead < 4 || responseHeader[0] != 0x05)
        {
            LogMessage("无效的Socks5连接响应");
            return false;
        }

        // 检查连接结果
        if (responseHeader[1] != 0x00)
        {
            string errorMessage = responseHeader[1] switch
            {
                0x01 => "一般性失败",
                0x02 => "规则集不允许连接",
                0x03 => "网络不可达",
                0x04 => "主机不可达",
                0x05 => "连接被拒绝",
                0x06 => "TTL过期",
                0x07 => "不支持的命令",
                0x08 => "不支持的地址类型",
                _ => $"未知错误 (0x{responseHeader[1]:X2})"
            };
            LogMessage($"Socks5连接失败: {errorMessage}");
            return false;
        }

        // 跳过剩余的响应数据（绑定地址和端口）
        byte bindAddressType = responseHeader[3];
        int remainingBytes = bindAddressType switch
        {
            0x01 => 4 + 2, // IPv4 + 端口
            0x03 => 1 + responseHeader[4] + 2, // 域名长度 + 域名 + 端口
            0x04 => 16 + 2, // IPv6 + 端口
            _ => 0
        };

        if (remainingBytes > 0)
        {
            byte[] remainingData = new byte[remainingBytes];
            await _stream.ReadAsync(remainingData, 0, remainingBytes).ConfigureAwait(false);
        }

        return true;
    }

    #region 同步方法（兼容SharpTunTest）

    /// <summary>
    /// 执行SOCKS5握手（同步）
    /// </summary>
    private void PerformSocks5HandshakeSync(Socket socket)
    {
        // SOCKS5握手第一步：发送支持的认证方法
        byte[] authRequest;
        if (_username != null && _password != null)
        {
            // 支持无认证(0x00)和用户名/密码认证(0x02)
            authRequest = new byte[] { 0x05, 0x02, 0x00, 0x02 };
        }
        else
        {
            // 只支持无认证(0x00)
            authRequest = new byte[] { 0x05, 0x01, 0x00 };
        }

        socket.Send(authRequest);

        // 接收服务器选择的认证方法
        byte[] authResponse = new byte[2];
        socket.Receive(authResponse);

        if (authResponse[0] != 0x05)
        {
            throw new Exception("SOCKS5协议错误");
        }

        // 根据服务器选择的认证方法进行认证
        switch (authResponse[1])
        {
            case 0x00:
                // 无需认证
                break;
            case 0x02:
                // 用户名/密码认证
                if (_username == null || _password == null)
                {
                    throw new Exception("服务器要求用户名/密码认证，但未提供凭据");
                }
                PerformUsernamePasswordAuthSync(socket, _username, _password);
                break;
            case 0xFF:
                throw new Exception("SOCKS5服务器不支持任何提供的认证方法");
            default:
                throw new Exception($"不支持的认证方法: {authResponse[1]}");
        }
    }

    /// <summary>
    /// 执行用户名/密码认证（同步）
    /// </summary>
    private void PerformUsernamePasswordAuthSync(Socket socket, string username, string password)
    {
        byte[] usernameBytes = Encoding.ASCII.GetBytes(username);
        byte[] passwordBytes = Encoding.ASCII.GetBytes(password);

        // 构建认证请求
        byte[] authRequest = new byte[3 + usernameBytes.Length + passwordBytes.Length];
        authRequest[0] = 0x01; // 认证子协议版本
        authRequest[1] = (byte)usernameBytes.Length;
        Array.Copy(usernameBytes, 0, authRequest, 2, usernameBytes.Length);
        authRequest[2 + usernameBytes.Length] = (byte)passwordBytes.Length;
        Array.Copy(passwordBytes, 0, authRequest, 3 + usernameBytes.Length, passwordBytes.Length);

        socket.Send(authRequest);

        // 接收认证结果
        byte[] authResponse = new byte[2];
        socket.Receive(authResponse);

        if (authResponse[0] != 0x01 || authResponse[1] != 0x00)
        {
            throw new Exception("用户名/密码认证失败");
        }
    }

    /// <summary>
    /// 请求连接到目标服务器（同步）
    /// </summary>
    private void ConnectToDestinationSync(Socket socket, string destinationHost, int destinationPort)
    {
        // 尝试解析目标主机为IP地址
        bool isIpAddress = IPAddress.TryParse(destinationHost, out IPAddress? ipAddress);

        // 构建连接请求
        byte[] request;
        if (isIpAddress && ipAddress!.AddressFamily == AddressFamily.InterNetwork)
        {
            // 使用IPv4地址连接
            byte[] ipBytes = ipAddress.GetAddressBytes();
            request = new byte[10];
            request[0] = 0x05; // SOCKS5
            request[1] = 0x01; // CONNECT命令
            request[2] = 0x00; // 保留字段
            request[3] = 0x01; // IPv4地址类型

            // 复制IP地址
            Array.Copy(ipBytes, 0, request, 4, 4);

            // 设置端口（网络字节序）
            request[8] = (byte)(destinationPort >> 8);
            request[9] = (byte)(destinationPort & 0xFF);
        }
        else if (isIpAddress && ipAddress!.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // 使用IPv6地址连接
            byte[] ipBytes = ipAddress.GetAddressBytes();
            request = new byte[22]; // 4 + 16 + 2
            request[0] = 0x05; // SOCKS5
            request[1] = 0x01; // CONNECT命令
            request[2] = 0x00; // 保留字段
            request[3] = 0x04; // IPv6地址类型

            // 复制IP地址
            Array.Copy(ipBytes, 0, request, 4, 16);

            // 设置端口（网络字节序）
            request[20] = (byte)(destinationPort >> 8);
            request[21] = (byte)(destinationPort & 0xFF);
        }
        else
        {
            // 使用域名连接
            byte[] domainBytes = Encoding.ASCII.GetBytes(destinationHost);
            request = new byte[7 + domainBytes.Length];
            request[0] = 0x05; // SOCKS5
            request[1] = 0x01; // CONNECT命令
            request[2] = 0x00; // 保留字段
            request[3] = 0x03; // 域名地址类型
            request[4] = (byte)domainBytes.Length; // 域名长度

            // 复制域名
            Array.Copy(domainBytes, 0, request, 5, domainBytes.Length);

            // 设置端口（网络字节序）
            request[5 + domainBytes.Length] = (byte)(destinationPort >> 8);
            request[6 + domainBytes.Length] = (byte)(destinationPort & 0xFF);
        }

        socket.Send(request);

        // 接收连接响应
        byte[] response = new byte[262]; // 最大响应长度（4 + 255 + 2 + 1）
        int bytesRead = socket.Receive(response);

        if (response[0] != 0x05)
        {
            throw new Exception("SOCKS5协议错误");
        }

        // 检查响应状态
        switch (response[1])
        {
            case 0x00:
                // 连接成功
                break;
            case 0x01:
                throw new Exception("SOCKS5服务器一般性失败");
            case 0x02:
                throw new Exception("SOCKS5服务器规则不允许连接");
            case 0x03:
                throw new Exception("网络不可达");
            case 0x04:
                throw new Exception("主机不可达");
            case 0x05:
                throw new Exception("连接被拒绝");
            case 0x06:
                throw new Exception("TTL过期");
            case 0x07:
                throw new Exception("不支持的命令");
            case 0x08:
                throw new Exception("不支持的地址类型");
            default:
                throw new Exception($"未知的SOCKS5错误: {response[1]}");
        }
    }

    #endregion

    /// <summary>
    /// 输出日志消息
    /// </summary>
    private void LogMessage(string message)
    {
        if (_verbose)
        {
            Console.WriteLine($"[Socks5Client] {message}");
        }
    }
}