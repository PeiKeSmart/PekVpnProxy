using NewLife.Log;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PekVpnProxy
{
    /// <summary>
    /// Socks5服务端
    /// </summary>
    public class Socks5Server
    {
        private readonly TcpListener _listener;
        private readonly AuthenticationManager _authManager;
        private readonly int _bufferSize;
        private bool _isRunning;
        private readonly List<Task> _clientTasks = new();
        private readonly CancellationTokenSource _cts = new();

        /// <summary>
        /// 初始化Socks5服务端
        /// </summary>
        /// <param name="listenIp">监听IP地址</param>
        /// <param name="listenPort">监听端口</param>
        /// <param name="authManager">认证管理器</param>
        /// <param name="bufferSize">缓冲区大小</param>
        public Socks5Server(string listenIp, int listenPort, AuthenticationManager authManager, int bufferSize = 8192)
        {
            IPAddress ipAddress = IPAddress.Parse(listenIp);
            _listener = new TcpListener(ipAddress, listenPort);
            _authManager = authManager;
            _bufferSize = bufferSize;
        }

        /// <summary>
        /// 启动服务
        /// </summary>
        public async Task StartAsync()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _listener.Start();
            XTrace.WriteLine($"Socks5服务已启动，监听地址: {((IPEndPoint)_listener.LocalEndpoint).Address}:{((IPEndPoint)_listener.LocalEndpoint).Port}");

            try
            {
                while (_isRunning && !_cts.Token.IsCancellationRequested)
                {
                    TcpClient client = await _listener.AcceptTcpClientAsync(_cts.Token);
                    Task clientTask = HandleClientAsync(client, _cts.Token);
                    _clientTasks.Add(clientTask);

                    // 清理已完成的任务
                    _clientTasks.RemoveAll(t => t.IsCompleted);
                }
            }
            catch (OperationCanceledException)
            {
                // 正常取消
            }
            catch (Exception ex)
            {
                XTrace.WriteLine($"接受连接时发生错误: {ex.Message}");
            }
        }

        /// <summary>
        /// 停止服务
        /// </summary>
        public async Task StopAsync()
        {
            if (!_isRunning)
                return;

            _isRunning = false;
            _cts.Cancel();

            try
            {
                _listener.Stop();
                
                // 等待所有客户端处理完成
                if (_clientTasks.Count > 0)
                {
                    await Task.WhenAll(_clientTasks.ToArray());
                }
            }
            catch (Exception ex)
            {
                XTrace.WriteLine($"停止服务时发生错误: {ex.Message}");
            }

            XTrace.WriteLine("Socks5服务已停止");
        }

        /// <summary>
        /// 处理客户端连接
        /// </summary>
        private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
        {
            string clientEndPoint = client.Client.RemoteEndPoint?.ToString() ?? "未知";
            XTrace.WriteLine($"客户端连接: {clientEndPoint}");

            using (client)
            {
                try
                {
                    NetworkStream clientStream = client.GetStream();

                    // 处理Socks5握手
                    if (!await HandleHandshakeAsync(clientStream, cancellationToken))
                    {
                        XTrace.WriteLine($"客户端 {clientEndPoint} 握手失败");
                        return;
                    }

                    // 处理Socks5请求
                    if (!await HandleRequestAsync(clientStream, cancellationToken))
                    {
                        XTrace.WriteLine($"客户端 {clientEndPoint} 请求处理失败");
                        return;
                    }
                }
                catch (OperationCanceledException)
                {
                    // 正常取消
                }
                catch (Exception ex)
                {
                    XTrace.WriteLine($"处理客户端 {clientEndPoint} 时发生错误: {ex.Message}");
                }
                finally
                {
                    XTrace.WriteLine($"客户端断开连接: {clientEndPoint}");
                }
            }
        }

        /// <summary>
        /// 处理Socks5握手
        /// </summary>
        private async Task<bool> HandleHandshakeAsync(NetworkStream clientStream, CancellationToken cancellationToken)
        {
            // 读取客户端握手请求
            byte[] buffer = new byte[257]; // 最大支持255种认证方法
            int bytesRead = await clientStream.ReadAsync(buffer, 0, 2, cancellationToken); // 先读取版本和方法数量

            if (bytesRead < 2 || buffer[0] != 0x05)
            {
                XTrace.WriteLine("无效的Socks5握手请求");
                return false;
            }

            int methodCount = buffer[1];
            bytesRead = await clientStream.ReadAsync(buffer, 0, methodCount, cancellationToken);
            if (bytesRead < methodCount)
            {
                XTrace.WriteLine("无效的Socks5握手请求");
                return false;
            }

            // 检查支持的认证方法
            byte selectedMethod = 0xFF; // 默认为不支持
            bool supportsNoAuth = false;
            bool supportsUsernamePassword = false;

            for (int i = 0; i < methodCount; i++)
            {
                if (buffer[i] == 0x00) // 无认证
                    supportsNoAuth = true;
                else if (buffer[i] == 0x02) // 用户名密码认证
                    supportsUsernamePassword = true;
            }

            // 选择认证方法
            if (_authManager.RequireAuthentication && supportsUsernamePassword)
            {
                selectedMethod = 0x02; // 用户名密码认证
            }
            else if (!_authManager.RequireAuthentication && supportsNoAuth)
            {
                selectedMethod = 0x00; // 无认证
            }
            else if (!_authManager.RequireAuthentication)
            {
                selectedMethod = 0x00; // 如果服务器不要求认证，默认使用无认证
            }

            // 发送握手响应
            byte[] response = new byte[] { 0x05, selectedMethod };
            await clientStream.WriteAsync(response, 0, response.Length, cancellationToken);

            // 如果选择了用户名密码认证，处理认证
            if (selectedMethod == 0x02)
            {
                return await HandleAuthenticationAsync(clientStream, cancellationToken);
            }

            return selectedMethod != 0xFF;
        }

        /// <summary>
        /// 处理用户名密码认证
        /// </summary>
        private async Task<bool> HandleAuthenticationAsync(NetworkStream clientStream, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[513]; // 最大支持255字节的用户名和255字节的密码
            int bytesRead = await clientStream.ReadAsync(buffer, 0, 2, cancellationToken); // 先读取版本和用户名长度

            if (bytesRead < 2 || buffer[0] != 0x01)
            {
                XTrace.WriteLine("无效的认证请求");
                return false;
            }

            int usernameLength = buffer[1];
            bytesRead = await clientStream.ReadAsync(buffer, 0, usernameLength + 1, cancellationToken); // 读取用户名和密码长度
            if (bytesRead < usernameLength + 1)
            {
                XTrace.WriteLine("无效的认证请求");
                return false;
            }

            string username = Encoding.ASCII.GetString(buffer, 0, usernameLength);
            int passwordLength = buffer[usernameLength];

            bytesRead = await clientStream.ReadAsync(buffer, 0, passwordLength, cancellationToken); // 读取密码
            if (bytesRead < passwordLength)
            {
                XTrace.WriteLine("无效的认证请求");
                return false;
            }

            string password = Encoding.ASCII.GetString(buffer, 0, passwordLength);

            // 验证用户名和密码
            bool authenticated = _authManager.Authenticate(username, password);
            byte authStatus = authenticated ? (byte)0x00 : (byte)0x01;

            // 发送认证响应
            byte[] response = new byte[] { 0x01, authStatus };
            await clientStream.WriteAsync(response, 0, response.Length, cancellationToken);

            if (authenticated)
            {
                XTrace.WriteLine($"用户 {username} 认证成功");
            }
            else
            {
                XTrace.WriteLine($"用户 {username} 认证失败");
            }

            return authenticated;
        }

        /// <summary>
        /// 处理Socks5请求
        /// </summary>
        private async Task<bool> HandleRequestAsync(NetworkStream clientStream, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[_bufferSize];
            int bytesRead = await clientStream.ReadAsync(buffer, 0, 4, cancellationToken); // 读取请求头

            if (bytesRead < 4 || buffer[0] != 0x05)
            {
                XTrace.WriteLine("无效的Socks5请求");
                return false;
            }

            byte command = buffer[1];
            byte addressType = buffer[3];

            // 目前只支持CONNECT命令
            if (command != 0x01)
            {
                await SendReplyAsync(clientStream, 0x07, cancellationToken); // 不支持的命令
                return false;
            }

            // 读取目标地址
            string? destinationHost = null;
            int destinationPort;

            switch (addressType)
            {
                case 0x01: // IPv4
                    bytesRead = await clientStream.ReadAsync(buffer, 0, 4, cancellationToken);
                    if (bytesRead < 4)
                    {
                        await SendReplyAsync(clientStream, 0x01, cancellationToken); // 一般性失败
                        return false;
                    }
                    destinationHost = $"{buffer[0]}.{buffer[1]}.{buffer[2]}.{buffer[3]}";
                    break;

                case 0x03: // 域名
                    bytesRead = await clientStream.ReadAsync(buffer, 0, 1, cancellationToken);
                    if (bytesRead < 1)
                    {
                        await SendReplyAsync(clientStream, 0x01, cancellationToken); // 一般性失败
                        return false;
                    }
                    int domainLength = buffer[0];
                    bytesRead = await clientStream.ReadAsync(buffer, 0, domainLength, cancellationToken);
                    if (bytesRead < domainLength)
                    {
                        await SendReplyAsync(clientStream, 0x01, cancellationToken); // 一般性失败
                        return false;
                    }
                    destinationHost = Encoding.ASCII.GetString(buffer, 0, domainLength);
                    break;

                case 0x04: // IPv6
                    bytesRead = await clientStream.ReadAsync(buffer, 0, 16, cancellationToken);
                    if (bytesRead < 16)
                    {
                        await SendReplyAsync(clientStream, 0x01, cancellationToken); // 一般性失败
                        return false;
                    }
                    byte[] ipv6Bytes = new byte[16];
                    Array.Copy(buffer, 0, ipv6Bytes, 0, 16);
                    destinationHost = new IPAddress(ipv6Bytes).ToString();
                    break;

                default:
                    await SendReplyAsync(clientStream, 0x08, cancellationToken); // 不支持的地址类型
                    return false;
            }

            // 读取端口
            bytesRead = await clientStream.ReadAsync(buffer, 0, 2, cancellationToken);
            if (bytesRead < 2)
            {
                await SendReplyAsync(clientStream, 0x01, cancellationToken); // 一般性失败
                return false;
            }
            destinationPort = (buffer[0] << 8) | buffer[1];

            XTrace.WriteLine($"连接请求: {destinationHost}:{destinationPort}");

            // 尝试连接到目标服务器
            try
            {
                using TcpClient destinationClient = new TcpClient();
                await destinationClient.ConnectAsync(destinationHost, destinationPort, cancellationToken);
                NetworkStream destinationStream = destinationClient.GetStream();

                // 发送成功响应
                await SendReplyAsync(clientStream, 0x00, cancellationToken, ((IPEndPoint)destinationClient.Client.LocalEndPoint!).Address, (ushort)((IPEndPoint)destinationClient.Client.LocalEndPoint!).Port);

                XTrace.WriteLine($"已连接到目标服务器: {destinationHost}:{destinationPort}");

                // 开始转发数据
                await ForwardDataAsync(clientStream, destinationStream, cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                XTrace.WriteLine($"连接到目标服务器失败: {ex.Message}");
                byte replyCode = ex switch
                {
                    SocketException se => se.SocketErrorCode switch
                    {
                        SocketError.NetworkUnreachable => 0x03, // 网络不可达
                        SocketError.HostUnreachable => 0x04, // 主机不可达
                        SocketError.ConnectionRefused => 0x05, // 连接被拒绝
                        SocketError.TimedOut => 0x06, // TTL过期
                        _ => 0x01, // 一般性失败
                    },
                    _ => 0x01, // 一般性失败
                };
                await SendReplyAsync(clientStream, replyCode, cancellationToken);
                return false;
            }
        }

        /// <summary>
        /// 发送Socks5响应
        /// </summary>
        private async Task SendReplyAsync(NetworkStream clientStream, byte replyCode, CancellationToken cancellationToken, IPAddress? bindAddress = null, ushort bindPort = 0)
        {
            bindAddress ??= IPAddress.Any;
            byte[] addressBytes;
            byte addressType;

            if (bindAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                addressType = 0x01; // IPv4
                addressBytes = bindAddress.GetAddressBytes();
            }
            else if (bindAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                addressType = 0x04; // IPv6
                addressBytes = bindAddress.GetAddressBytes();
            }
            else
            {
                addressType = 0x01; // 默认IPv4
                addressBytes = IPAddress.Any.GetAddressBytes();
            }

            byte[] reply = new byte[6 + addressBytes.Length];
            reply[0] = 0x05; // Socks版本
            reply[1] = replyCode; // 回复代码
            reply[2] = 0x00; // 保留字段
            reply[3] = addressType; // 地址类型

            Array.Copy(addressBytes, 0, reply, 4, addressBytes.Length);

            // 端口（网络字节序，大端）
            reply[4 + addressBytes.Length] = (byte)(bindPort >> 8);
            reply[4 + addressBytes.Length + 1] = (byte)(bindPort & 0xFF);

            await clientStream.WriteAsync(reply, 0, reply.Length, cancellationToken);
        }

        /// <summary>
        /// 转发数据
        /// </summary>
        private async Task ForwardDataAsync(NetworkStream clientStream, NetworkStream destinationStream, CancellationToken cancellationToken)
        {
            // 创建两个任务，分别处理双向数据转发
            Task clientToDestination = ForwardStreamAsync(clientStream, destinationStream, "客户端 -> 目标服务器", cancellationToken);
            Task destinationToClient = ForwardStreamAsync(destinationStream, clientStream, "目标服务器 -> 客户端", cancellationToken);

            // 等待任意一个任务完成（表示连接断开）
            await Task.WhenAny(clientToDestination, destinationToClient);
        }

        /// <summary>
        /// 单向转发数据
        /// </summary>
        private async Task ForwardStreamAsync(NetworkStream source, NetworkStream destination, string direction, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[_bufferSize];
            try
            {
                int bytesRead;
                while ((bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                {
                    await destination.WriteAsync(buffer, 0, bytesRead, cancellationToken);
                    await destination.FlushAsync(cancellationToken);
                }
            }
            catch (IOException)
            {
                // 连接已关闭
            }
            catch (OperationCanceledException)
            {
                // 操作被取消
            }
            catch (Exception ex)
            {
                XTrace.WriteLine($"{direction} 数据转发错误: {ex.Message}");
            }
        }
    }
}
