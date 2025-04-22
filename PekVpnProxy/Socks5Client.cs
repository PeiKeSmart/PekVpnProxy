using System.Net;
using System.Net.Sockets;
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
        private NetworkStream? _stream;

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
                _stream = _tcpClient.GetStream();

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
        /// <returns>接收到的字节数</returns>
        public async Task<int> ReceiveAsync(byte[] buffer)
        {
            if (_stream == null || !_tcpClient!.Connected)
                throw new InvalidOperationException("未连接到服务器");

            return await _stream.ReadAsync(buffer);
        }

        /// <summary>
        /// 断开连接
        /// </summary>
        public void Disconnect()
        {
            _stream?.Close();
            _tcpClient?.Close();
            _stream = null;
            _tcpClient = null;
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
            int bytesRead = await _stream.ReadAsync(handshakeResponse, 0, 2);
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
            int bytesRead = await _stream.ReadAsync(authResponse, 0, 2);
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
            int bytesRead = await _stream.ReadAsync(responseHeader, 0, 4);
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
                await _stream.ReadAsync(remainingData, 0, remainingBytes);
            }

            return true;
        }
    }
}
