using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SharpTunTest
{
    /// <summary>
    /// 简单的SOCKS5客户端实现，用于测试
    /// </summary>
    public class Socks5Client
    {
        private readonly string _proxyHost;
        private readonly int _proxyPort;
        private readonly string? _username;
        private readonly string? _password;

        /// <summary>
        /// 创建一个新的SOCKS5客户端
        /// </summary>
        /// <param name="proxyHost">SOCKS5代理服务器地址</param>
        /// <param name="proxyPort">SOCKS5代理服务器端口</param>
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
        /// 通过SOCKS5代理创建一个TCP连接
        /// </summary>
        /// <param name="destinationHost">目标主机</param>
        /// <param name="destinationPort">目标端口</param>
        /// <returns>已连接的Socket</returns>
        public Socket CreateConnection(string destinationHost, int destinationPort)
        {
            // 连接到SOCKS5代理服务器
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(_proxyHost, _proxyPort);

            // 进行SOCKS5握手
            PerformSocks5Handshake(socket);

            // 请求连接到目标服务器
            ConnectToDestination(socket, destinationHost, destinationPort);

            return socket;
        }

        /// <summary>
        /// 执行SOCKS5握手
        /// </summary>
        private void PerformSocks5Handshake(Socket socket)
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
                    PerformUsernamePasswordAuth(socket, _username, _password);
                    break;
                case 0xFF:
                    throw new Exception("SOCKS5服务器不支持任何提供的认证方法");
                default:
                    throw new Exception($"不支持的认证方法: {authResponse[1]}");
            }
        }

        /// <summary>
        /// 执行用户名/密码认证
        /// </summary>
        private void PerformUsernamePasswordAuth(Socket socket, string username, string password)
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
        /// 请求连接到目标服务器
        /// </summary>
        private void ConnectToDestination(Socket socket, string destinationHost, int destinationPort)
        {
            // 尝试解析目标主机为IP地址
            bool isIpAddress = IPAddress.TryParse(destinationHost, out IPAddress? ipAddress);

            // 构建连接请求
            byte[] request;
            if (isIpAddress)
            {
                // 使用IP地址连接
                byte[] ipBytes = ipAddress!.GetAddressBytes();
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
            byte[] response = new byte[10]; // 最大响应长度
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
    }
}
