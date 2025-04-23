using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PekVpnProxy
{
    /// <summary>
    /// Socks5客户端，用于连接Socks5代理服务器
    /// </summary>
    public class Socks5Client
    {
        private readonly string _proxyHost;
        private readonly int _proxyPort;
        private readonly string? _username;
        private readonly string? _password;
        private TcpClient? _tcpClient;
        private NetworkStream? _networkStream;
        private SslStream? _sslStream;
        private Stream? _stream; // 当前使用的流（可能是NetworkStream或SslStream）
        private bool _isSecure; // 是否使用SSL/TLS

        /// <summary>
        /// 初始化Socks5客户端
        /// </summary>
        /// <param name="proxyHost">Socks5代理服务器地址</param>
        /// <param name="proxyPort">Socks5代理服务器端口</param>
        /// <param name="username">用户名（可选）</param>
        /// <param name="password">密码（可选）</param>
        public Socks5Client(string proxyHost, int proxyPort, string? username = null, string? password = null)
        {
            _proxyHost = proxyHost;
            _proxyPort = proxyPort;
            _username = username;
            _password = password;
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
                    Console.WriteLine("Socks5握手失败");
                    return false;
                }

                // 发送连接请求
                if (!await SendConnectRequestAsync(destinationHost, destinationPort))
                {
                    Console.WriteLine("Socks5连接请求失败");
                    return false;
                }

                Console.WriteLine($"成功通过Socks5代理连接到 {destinationHost}:{destinationPort}");

                // 如果是HTTPS连接（端口443），升级到SSL/TLS
                if (destinationPort == 443)
                {
                    if (await UpgradeToSslAsync(destinationHost))
                    {
                        Console.WriteLine($"成功升级到SSL/TLS加密连接");
                    }
                    else
                    {
                        Console.WriteLine($"升级到SSL/TLS失败，使用非加密连接继续");
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"连接失败: {ex.Message}");
                Disconnect();
                return false;
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
                    Console.WriteLine($"接收数据超时 ({timeout} 毫秒)");
                    return 0;
                }
            }
            catch (IOException ex)
            {
                // 连接已关闭
                Console.WriteLine($"接收数据时连接关闭: {ex.Message}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"接收数据错误: {ex.Message}");
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
                Console.WriteLine($"SSL/TLS升级失败: {ex.Message}");
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
        /// 执行Socks5握手
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
                handshakeRequest = new byte[] { 0x05, 0x01, 0x02 };
            }

            // 发送握手请求
            await _stream.WriteAsync(handshakeRequest);

            // 接收握手响应
            byte[] handshakeResponse = new byte[2];
            int bytesRead = await _stream.ReadAsync(handshakeResponse, 0, 2).ConfigureAwait(false);
            if (bytesRead < 2 || handshakeResponse[0] != 0x05)
            {
                Console.WriteLine("无效的Socks5握手响应");
                return false;
            }

            // 检查认证方法
            byte authMethod = handshakeResponse[1];
            if (authMethod == 0xFF)
            {
                Console.WriteLine("服务器不支持任何认证方法");
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
        /// 执行用户名密码认证
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
                Console.WriteLine("无效的认证响应");
                return false;
            }

            // 检查认证结果
            if (authResponse[1] != 0x00)
            {
                Console.WriteLine("认证失败");
                return false;
            }

            return true;
        }

        /// <summary>
        /// 发送连接请求
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
                    Console.WriteLine("不支持的IP地址类型");
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
                Console.WriteLine("无效的Socks5连接响应");
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
                Console.WriteLine($"Socks5连接失败: {errorMessage}");
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
    }
}
