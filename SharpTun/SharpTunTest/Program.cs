using SharpTun.Implementation.Wintun;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace SharpTunTest
{
    internal class Program
    {
        // 测试模式
        enum TestMode
        {
            CaptureOnly,      // 仅捕获流量
            Socks5Proxy,      // SOCKS5代理转发
            Socks5ClientTest  // 测试UnifiedSocks5Client
        }

        // 代理类型
        enum ProxyType
        {
            Socks5,      // SOCKS5代理
            Http,        // HTTP代理
            Https        // HTTPS代理
        }

        // 代理配置
        private static ProxyType _proxyType = ProxyType.Socks5;
        private static string _proxyHost = "127.0.0.1";
        private static int _proxyPort = 1080;
        private static string? _proxyUsername = null;
        private static string? _proxyPassword = null;
        private static bool _handleIcmp = false;  // 是否处理ICMP流量

        // 排除的IP地址列表，这些地址的流量不会通过虚拟适配器
        private static List<string> _excludedIPs = new List<string>();

        // 连接跟踪表
        private static Dictionary<string, Socket> _connectionTable = new Dictionary<string, Socket>();

        // 路由跟踪列表，用于清理
        private static List<(string destination, string mask)> _addedRoutes = new List<(string, string)>();
        private static string? _configuredAdapterName;

        static void Main(string[] args)
        {
            Console.WriteLine("SharpTun 测试程序");
            Console.WriteLine("=====================");
            Console.WriteLine("本程序将创建虚拟网络适配器并捕获数据包。");
            Console.WriteLine("您需要以管理员身份运行此程序。");
            Console.WriteLine();
            Console.WriteLine("选择测试模式：");
            Console.WriteLine("1. 仅捕获 - 只捕获并显示网络数据包");
            Console.WriteLine("2. 代理转发 - 捕获数据包并通过代理转发（支持SOCKS5/HTTP/HTTPS）");
            Console.WriteLine("3. 测试Socks5Client - 测试与PekVpnProxy的兼容性");
            Console.Write("请输入您的选择 (1-3): ");

            TestMode mode = TestMode.CaptureOnly;
            string? choice = Console.ReadLine();
            if (choice == "2")
            {
                mode = TestMode.Socks5Proxy;
                ConfigureSocks5Proxy();
            }
            else if (choice == "3")
            {
                mode = TestMode.Socks5ClientTest;
                // 运行Socks5Client测试
                await Socks5ClientTest.RunTest();
                return; // 测试完成后直接返回
            }

            // 创建一个唯一的GUID用于适配器
            Guid adapterGuid = Guid.NewGuid();
            string adapterName = "SharpTunTest";
            string tunnelType = "WinTun";

            try
            {
                Console.WriteLine($"正在创建适配器 '{adapterName}' ，GUID为 {adapterGuid}...");

                // 创建虚拟网络适配器
                using (var adapter = ManagedWintunAdapter.Create(adapterName, tunnelType, adapterGuid))
                {
                    Console.WriteLine("适配器创建成功。");

                    // 获取适配器的LUID
                    var luid = adapter.GetLuid();
                    Console.WriteLine($"适配器 LUID: {luid.LowPart}, {luid.HighPart}");

                    // 启动会话
                    Console.WriteLine("正在启动会话...");
                    using (var session = adapter.Start(0x400000))
                    {
                        Console.WriteLine("会话启动成功。");
                        Console.WriteLine();
                        Console.WriteLine("现在需要配置适配器的IP地址并设置路由。");

                        // 配置IP地址
                        string adapterIP = "192.168.56.1";
                        string subnetMask = "255.255.255.0";
                        Console.WriteLine($"正在配置适配器 '{adapterName}' 的IP地址 {adapterIP}...");

                        bool configSuccess = ConfigureAdapterIP(adapterName, adapterIP, subnetMask);
                        if (!configSuccess)
                        {
                            Console.WriteLine("配置适配器IP失败。请手动运行以下命令：");
                            Console.WriteLine($"netsh interface ip set address name=\"{adapterName}\" static {adapterIP} {subnetMask}");
                            Console.WriteLine("按任意键继续...");
                            Console.ReadKey();
                        }
                        else
                        {
                            Console.WriteLine("适配器IP配置成功。");
                            _configuredAdapterName = adapterName; // 记录已配置的适配器名称，用于清理
                        }

                        // 如果是SOCKS5代理模式，需要设置路由
                        if (mode == TestMode.Socks5Proxy)
                        {
                            Console.WriteLine();
                            Console.WriteLine("正在设置Socks5代理模式的路由...");

                            // 获取SOCKS5代理服务器的IP地址
                            IPAddress proxyIP = GetProxyServerIP(_socks5Host);
                            string proxyIPStr = proxyIP.ToString();

                            // 获取默认网关
                            IPAddress? defaultGateway = GetDefaultGateway();

                            if (defaultGateway != null)
                            {
                                string gatewayStr = defaultGateway.ToString();

                                // 1. 添加代理服务器的直接路由，避免路由循环
                                Console.WriteLine($"正在添加代理服务器 {proxyIPStr} 的直接路由，通过默认网关 {gatewayStr}...");
                                bool proxyRouteSuccess = AddRoute(proxyIPStr, "255.255.255.255", gatewayStr);

                                // 如果代理服务器是本地地址，添加回环地址的路由
                                if (proxyIPStr == "127.0.0.1" || proxyIPStr.StartsWith("192.168.") || proxyIPStr.StartsWith("10.") || proxyIPStr.StartsWith("172."))
                                {
                                    Console.WriteLine("检测到本地代理服务器，添加回环网络路由...");
                                    // 添加回环网络的路由
                                    bool loopbackRouteSuccess = AddRoute("127.0.0.0", "255.0.0.0", gatewayStr);
                                    if (!loopbackRouteSuccess)
                                    {
                                        Console.WriteLine("添加回环网络路由失败。请手动运行以下命令：");
                                        Console.WriteLine($"route add 127.0.0.0 mask 255.0.0.0 {gatewayStr}");
                                    }
                                    else
                                    {
                                        Console.WriteLine("回环网络路由添加成功。");
                                    }

                                    // 如果是其他本地网络，也添加对应的路由
                                    if (proxyIPStr.StartsWith("192.168."))
                                    {
                                        bool localRouteSuccess = AddRoute("192.168.0.0", "255.255.0.0", gatewayStr);
                                        if (localRouteSuccess)
                                            Console.WriteLine("本地网络 (192.168.0.0/16) 路由添加成功。");
                                    }
                                    else if (proxyIPStr.StartsWith("10."))
                                    {
                                        bool localRouteSuccess = AddRoute("10.0.0.0", "255.0.0.0", gatewayStr);
                                        if (localRouteSuccess)
                                            Console.WriteLine("本地网络 (10.0.0.0/8) 路由添加成功。");
                                    }
                                    else if (proxyIPStr.StartsWith("172."))
                                    {
                                        bool localRouteSuccess = AddRoute("172.16.0.0", "255.240.0.0", gatewayStr);
                                        if (localRouteSuccess)
                                            Console.WriteLine("本地网络 (172.16.0.0/12) 路由添加成功。");
                                    }
                                }

                                if (!proxyRouteSuccess)
                                {
                                    Console.WriteLine("添加代理路由失败。请手动运行以下命令：");
                                    Console.WriteLine($"route add {proxyIPStr} mask 255.255.255.255 {gatewayStr}");
                                }
                                else
                                {
                                    Console.WriteLine("代理路由添加成功。");
                                }

                                // 2. 询问用户是否要路由所有流量或仅特定目标
                                Console.WriteLine();
                                Console.WriteLine("是否要将所有互联网流量通过适配器路由？ (y/n): ");
                                string? routeAllChoice = Console.ReadLine()?.ToLower();

                                if (routeAllChoice == "y" || routeAllChoice == "yes")
                                {
                                    // 路由所有流量
                                    Console.WriteLine("正在添加所有互联网流量的路由...");
                                    bool allRouteSuccess = AddRoute("0.0.0.0", "0.0.0.0", adapterIP);

                                    if (!allRouteSuccess)
                                    {
                                        Console.WriteLine("添加全局路由失败。请手动运行以下命令：");
                                        Console.WriteLine($"route add 0.0.0.0 mask 0.0.0.0 {adapterIP}");
                                    }
                                    else
                                    {
                                        Console.WriteLine("全局路由添加成功。");

                                        // 为排除的IP添加特定路由
                                        if (_excludedIPs.Count > 0)
                                        {
                                            Console.WriteLine("正在为排除的IP地址添加直接路由...");
                                            foreach (string excludedIP in _excludedIPs)
                                            {
                                                // 确保排除的IP流量通过默认网关，而不是虚拟适配器
                                                bool excludeRouteSuccess = AddRoute(excludedIP, "255.255.255.255", gatewayStr);
                                                if (excludeRouteSuccess)
                                                {
                                                    Console.WriteLine($"成功添加排除路由: {excludedIP}");
                                                }
                                                else
                                                {
                                                    Console.WriteLine($"添加排除路由失败: {excludedIP}");
                                                }
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    // 仅路由特定目标
                                    Console.WriteLine("正在添加特定目标的路由 (8.8.8.8 和 1.1.1.1)...");

                                    bool dns1RouteSuccess = AddRoute("8.8.8.8", "255.255.255.255", adapterIP);
                                    bool dns2RouteSuccess = AddRoute("1.1.1.1", "255.255.255.255", adapterIP);

                                    if (!dns1RouteSuccess || !dns2RouteSuccess)
                                    {
                                        Console.WriteLine("添加某些特定路由失败。请手动运行以下命令：");
                                        if (!dns1RouteSuccess) Console.WriteLine($"route add 8.8.8.8 mask 255.255.255.255 {adapterIP}");
                                        if (!dns2RouteSuccess) Console.WriteLine($"route add 1.1.1.1 mask 255.255.255.255 {adapterIP}");
                                    }
                                    else
                                    {
                                        Console.WriteLine("特定路由添加成功。");
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("无法检测到默认网关。请手动配置路由：");
                                Console.WriteLine($"1. route add {proxyIPStr} mask 255.255.255.255 YOUR_DEFAULT_GATEWAY_IP");
                                Console.WriteLine($"2. route add 0.0.0.0 mask 0.0.0.0 {adapterIP}");
                            }
                        }

                        Console.WriteLine();
                        Console.WriteLine("网络配置完成。尝试 ping 8.8.8.8 来生成一些流量。");
                        Console.WriteLine("按任意键开始捕获数据包...");
                        Console.ReadKey();

                        // 开始捕获数据包
                        Console.WriteLine("正在开始捕获数据包。按 Ctrl+C 停止。");

                        // 注册Ctrl+C处理程序
                        Console.CancelKeyPress += (sender, e) => {
                            e.Cancel = true;
                            Console.WriteLine("正在清理...");
                            CloseAllConnections();
                            CleanupRoutes();
                            ResetAdapterIP();
                            Console.WriteLine("清理完成。");
                            Environment.Exit(0);
                        };

                        // 捕获循环
                        while (true)
                        {
                            try
                            {
                                // 接收数据包
                                byte[] packet = session.ReceivePacket();

                                // 分析并显示数据包信息
                                DisplayPacketInfo(packet);

                                // 如果是SOCKS5代理模式，处理数据包转发
                                if (mode == TestMode.Socks5Proxy)
                                {
                                    ProcessPacketForSocks5(packet, session);
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"接收数据包错误: {ex.Message}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"错误: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }

            Console.WriteLine("按任意键退出...");
            Console.ReadKey();
        }

        /// <summary>
        /// 配置代理设置（支持SOCKS5/HTTP/HTTPS）
        /// </summary>
        static void ConfigureSocks5Proxy()
        {
            Console.WriteLine("\n代理配置");
            Console.WriteLine("-------------------------");

            // 选择代理类型
            Console.WriteLine("选择代理类型:");
            Console.WriteLine("1. SOCKS5代理");
            Console.WriteLine("2. HTTP代理");
            Console.WriteLine("3. HTTPS代理");
            Console.Write("请输入您的选择 (1-3, 默认: 1): ");

            string? proxyTypeChoice = Console.ReadLine();
            switch (proxyTypeChoice)
            {
                case "2":
                    _proxyType = ProxyType.Http;
                    break;
                case "3":
                    _proxyType = ProxyType.Https;
                    break;
                default:
                    _proxyType = ProxyType.Socks5;
                    break;
            }

            Console.Write("代理服务器地址 (默认: 127.0.0.1): ");
            string? host = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(host))
            {
                _proxyHost = host;
            }

            Console.Write("代理服务器端口 (默认: 1080): ");
            string? portStr = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(portStr) && int.TryParse(portStr, out int port))
            {
                _proxyPort = port;
            }

            Console.Write("用户名 (留空表示不需要认证): ");
            string? username = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(username))
            {
                _proxyUsername = username;

                Console.Write("密码: ");
                string? password = Console.ReadLine();
                _proxyPassword = password;
            }

            if (_proxyType == ProxyType.Socks5)
            {
                Console.Write("是否通过SOCKS5处理ICMP流量 (ping)? (y/n, 默认: n): ");
                string? handleIcmp = Console.ReadLine()?.ToLower();
                _handleIcmp = handleIcmp == "y" || handleIcmp == "yes";
            }
            else
            {
                // HTTP/HTTPS代理不支持ICMP
                _handleIcmp = false;
            }

            // 配置排除的IP地址
            ConfigureExcludedIPs();

            // 显示配置信息
            string proxyTypeStr = "";
            switch (_proxyType)
            {
                case ProxyType.Socks5:
                    proxyTypeStr = "SOCKS5";
                    break;
                case ProxyType.Http:
                    proxyTypeStr = "HTTP";
                    break;
                case ProxyType.Https:
                    proxyTypeStr = "HTTPS";
                    break;
            }

            Console.WriteLine($"{proxyTypeStr}代理已配置: {_proxyHost}:{_proxyPort}");
            if (_proxyUsername != null)
            {
                Console.WriteLine($"认证方式: 用户名={_proxyUsername}");
            }
            else
            {
                Console.WriteLine("认证方式: 无");
            }

            if (_proxyType == ProxyType.Socks5)
            {
                Console.WriteLine($"处理ICMP流量: {(_handleIcmp ? "是" : "否")}");
            }

            if (_excludedIPs.Count > 0)
            {
                Console.WriteLine($"排除的IP地址: {string.Join(", ", _excludedIPs)}");
            }
        }

        /// <summary>
        /// 处理数据包并通过代理转发（支持SOCKS5/HTTP/HTTPS）
        /// </summary>
        static void ProcessPacketForProxy(byte[] packet, SharpTun.Interface.ITunSession session)
        {
            if (packet.Length < 20)
            {
                return; // 数据包太短，忽略
            }

            // 获取IP版本
            int version = packet[0] >> 4;
            if (version != 4) // 目前只处理IPv4
            {
                Console.WriteLine("跳过非IPv4数据包");
                return;
            }

            // 获取协议
            byte protocol = packet[9];
            if (protocol != 6 && protocol != 17) // 非TCP和UDP
            {
                // 如果是ICMP协议且用户选择了处理ICMP
                if (protocol == 1 && _handleIcmp) // ICMP
                {
                    // 允许处理ICMP
                    Console.WriteLine("正在处理ICMP数据包");
                }
                else
                {
                    // 对于其他协议，我们选择忽略
                    Console.WriteLine($"跳过非TCP/UDP/ICMP数据包 (协议: {protocol})");
                    return;
                }
            }

            // 获取源IP和目标IP
            IPAddress sourceIP = new IPAddress(new byte[] { packet[12], packet[13], packet[14], packet[15] });
            IPAddress destIP = new IPAddress(new byte[] { packet[16], packet[17], packet[18], packet[19] });

            // 创建连接标识符
            string connectionId;
            int sourcePort = 0;
            int destPort = 0;

            if (protocol == 1) // ICMP
            {
                // ICMP没有端口概念，使用类型和代码作为标识
                byte type = packet[20];
                byte code = packet[21];
                // 使用类型和代码作为“端口”
                sourcePort = (type << 8) | code;
                destPort = 0; // 目标端口设为0
                connectionId = $"ICMP-{sourceIP}-{destIP}-{type}-{code}";
            }
            else // TCP或UDP
            {
                // 获取源端口和目标端口
                sourcePort = (packet[20] << 8) | packet[21];
                destPort = (packet[22] << 8) | packet[23];
                connectionId = $"{sourceIP}:{sourcePort}-{destIP}:{destPort}";
            }

            try
            {
                // 检查连接是否已存在
                if (!_connectionTable.TryGetValue(connectionId, out Socket? proxySocket))
                {
                    // 创建新的代理连接
                    if (protocol == 1) // ICMP
                    {
                        // ICMP只能通过SOCKS5代理转发
                        if (_proxyType == ProxyType.Socks5 && _handleIcmp)
                        {
                            Console.WriteLine($"正在为ICMP创建新的SOCKS5连接到 {destIP}");
                            // 对于ICMP，我们使用一个特殊端口（例如7）来创建SOCKS5连接
                            // 实际上，SOCKS5代理通常不直接支持ICMP，这里是一个变通方法
                            Socks5Client socks5Client = new Socks5Client(_proxyHost, _proxyPort, _proxyUsername, _proxyPassword);
                            proxySocket = socks5Client.CreateConnection(destIP.ToString(), 7); // 使用echo端口
                        }
                        else
                        {
                            Console.WriteLine($"跳过ICMP数据包，因为当前代理类型不支持ICMP");
                            return;
                        }
                    }
                    else
                    {
                        // TCP/UDP可以通过任何类型的代理转发
                        switch (_proxyType)
                        {
                            case ProxyType.Socks5:
                                Console.WriteLine($"正在创建新的SOCKS5连接到 {destIP}:{destPort}");
                                Socks5Client socks5Client = new Socks5Client(_proxyHost, _proxyPort, _proxyUsername, _proxyPassword);
                                proxySocket = socks5Client.CreateConnection(destIP.ToString(), destPort);
                                break;

                            case ProxyType.Http:
                                Console.WriteLine($"正在创建新的HTTP代理连接到 {destIP}:{destPort}");
                                HttpProxyClient httpClient = new HttpProxyClient(_proxyHost, _proxyPort, false, _proxyUsername, _proxyPassword);
                                proxySocket = httpClient.CreateConnection(destIP.ToString(), destPort);
                                break;

                            case ProxyType.Https:
                                Console.WriteLine($"正在创建新的HTTPS代理连接到 {destIP}:{destPort}");
                                HttpProxyClient httpsClient = new HttpProxyClient(_proxyHost, _proxyPort, true, _proxyUsername, _proxyPassword);
                                proxySocket = httpsClient.CreateConnection(destIP.ToString(), destPort);
                                break;
                        }
                    }

                    // 添加到连接表
                    _connectionTable[connectionId] = proxySocket;

                    // 启动接收线程
                    StartReceiveThread(proxySocket, connectionId, sourceIP, sourcePort, destIP, destPort, session);
                }

                // 提取数据负载
                int headerLength = (packet[0] & 0x0F) * 4; // IP头部长度
                int payloadOffset = headerLength;

                if (protocol == 6) // TCP
                {
                    int tcpHeaderLength = ((packet[payloadOffset + 12] >> 4) & 0x0F) * 4; // TCP头部长度
                    payloadOffset += tcpHeaderLength;
                }
                else if (protocol == 17) // UDP
                {
                    payloadOffset += 8; // UDP头部长度固定为8字节
                }
                else if (protocol == 1) // ICMP
                {
                    payloadOffset += 8; // ICMP头部长度固定为8字节
                }

                // 检查是否有数据负载
                if (payloadOffset < packet.Length)
                {
                    // 提取数据负载
                    byte[] payload = new byte[packet.Length - payloadOffset];
                    Array.Copy(packet, payloadOffset, payload, 0, payload.Length);

                    // 发送数据到SOCKS5代理
                    proxySocket.Send(payload);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"转发数据包到SOCKS5时出错: {ex.Message}");
                // 移除失败的连接
                if (_connectionTable.ContainsKey(connectionId))
                {
                    _connectionTable[connectionId].Dispose();
                    _connectionTable.Remove(connectionId);
                }
            }
        }

        /// <summary>
        /// 启动接收线程，从SOCKS5代理接收数据并发送回TUN适配器
        /// </summary>
        static void StartReceiveThread(Socket socket, string connectionId, IPAddress sourceIP, int sourcePort,
                                      IPAddress destIP, int destPort, SharpTun.Interface.ITunSession session)
        {
            Thread receiveThread = new Thread(() =>
            {
                byte[] buffer = new byte[8192];
                try
                {
                    while (true)
                    {
                        int bytesRead = socket.Receive(buffer);
                        if (bytesRead <= 0)
                        {
                            break; // 连接关闭
                        }

                        // 构建IP数据包
                        byte[] ipPacket = CreateIpPacket(destIP, sourceIP, destPort, sourcePort, buffer, 0, bytesRead, socket.ProtocolType);

                        // 发送到TUN适配器
                        session.SendPacket(ipPacket);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"接收线程错误: {ex.Message}");
                }
                finally
                {
                    // 清理连接
                    if (_connectionTable.ContainsKey(connectionId))
                    {
                        _connectionTable[connectionId].Dispose();
                        _connectionTable.Remove(connectionId);
                    }
                }
            });

            receiveThread.IsBackground = true;
            receiveThread.Start();
        }

        /// <summary>
        /// 创建IP数据包
        /// </summary>
        static byte[] CreateIpPacket(IPAddress sourceIP, IPAddress destIP, int sourcePort, int destPort,
                                    byte[] payload, int offset, int length, ProtocolType protocolType)
        {
            // 确定协议类型
            byte protocol;
            if (protocolType == ProtocolType.Tcp)
                protocol = 6;  // TCP
            else if (protocolType == ProtocolType.Udp)
                protocol = 17; // UDP
            else if (_handleIcmp) // 如果启用了ICMP处理
                protocol = 1;  // ICMP
            else
                protocol = 17; // 默认使用UDP

            // 计算头部长度
            int headerSize;
            if (protocol == 6) // TCP
                headerSize = 20; // TCP头部长度
            else if (protocol == 17) // UDP
                headerSize = 8;  // UDP头部长度
            else if (protocol == 1) // ICMP
                headerSize = 8;  // ICMP头部长度
            else
                headerSize = 8;  // 默认

            // 计算总长度
            int totalLength = 20 + headerSize + length; // IP头(20) + 协议头 + 数据长度

            byte[] packet = new byte[totalLength];

            // IP头部
            packet[0] = 0x45; // 版本(4) + 头部长度(5*4=20字节)
            packet[1] = 0x00; // 服务类型
            packet[2] = (byte)(totalLength >> 8); // 总长度高字节
            packet[3] = (byte)(totalLength & 0xFF); // 总长度低字节
            packet[4] = 0x00; // 标识高字节
            packet[5] = 0x00; // 标识低字节
            packet[6] = 0x00; // 标志和片偏移高字节
            packet[7] = 0x00; // 片偏移低字节
            packet[8] = 64;   // TTL
            packet[9] = protocol; // 协议
            packet[10] = 0x00; // 头部校验和高字节
            packet[11] = 0x00; // 头部校验和低字节

            // 源IP地址
            byte[] srcIpBytes = sourceIP.GetAddressBytes();
            Array.Copy(srcIpBytes, 0, packet, 12, 4);

            // 目标IP地址
            byte[] dstIpBytes = destIP.GetAddressBytes();
            Array.Copy(dstIpBytes, 0, packet, 16, 4);

            // 计算IP头部校验和
            ushort ipChecksum = CalculateChecksum(packet, 0, 20);
            packet[10] = (byte)(ipChecksum >> 8);
            packet[11] = (byte)(ipChecksum & 0xFF);

            if (protocol == 6) // TCP
            {
                // TCP头部 (简化版)
                packet[20] = (byte)(sourcePort >> 8); // 源端口高字节
                packet[21] = (byte)(sourcePort & 0xFF); // 源端口低字节
                packet[22] = (byte)(destPort >> 8); // 目标端口高字节
                packet[23] = (byte)(destPort & 0xFF); // 目标端口低字节

                // 序列号和确认号 (简化)
                for (int i = 24; i < 32; i++) packet[i] = 0;

                packet[32] = 0x50; // 数据偏移(5*4=20字节) + 保留
                packet[33] = 0x18; // 标志 (ACK, PSH)
                packet[34] = 0x01; // 窗口大小高字节
                packet[35] = 0x00; // 窗口大小低字节
                packet[36] = 0x00; // 校验和高字节
                packet[37] = 0x00; // 校验和低字节
                packet[38] = 0x00; // 紧急指针高字节
                packet[39] = 0x00; // 紧急指针低字节

                // 复制数据负载
                Array.Copy(payload, offset, packet, 40, length);

                // TCP校验和需要伪头部，这里简化处理
            }
            else if (protocol == 17) // UDP
            {
                // UDP头部
                packet[20] = (byte)(sourcePort >> 8); // 源端口高字节
                packet[21] = (byte)(sourcePort & 0xFF); // 源端口低字节
                packet[22] = (byte)(destPort >> 8); // 目标端口高字节
                packet[23] = (byte)(destPort & 0xFF); // 目标端口低字节

                int udpLength = 8 + length; // UDP头部(8) + 数据长度
                packet[24] = (byte)(udpLength >> 8); // 长度高字节
                packet[25] = (byte)(udpLength & 0xFF); // 长度低字节
                packet[26] = 0x00; // 校验和高字节
                packet[27] = 0x00; // 校验和低字节

                // 复制数据负载
                Array.Copy(payload, offset, packet, 28, length);

                // UDP校验和需要伪头部，这里简化处理
            }
            else if (protocol == 1) // ICMP
            {
                // ICMP头部
                packet[20] = 0; // 类型: 0 = Echo Reply
                packet[21] = 0; // 代码: 0
                packet[22] = 0; // 校验和高字节
                packet[23] = 0; // 校验和低字节
                packet[24] = 0; // 标识符高字节
                packet[25] = 0; // 标识符低字节
                packet[26] = 0; // 序列号高字节
                packet[27] = 0; // 序列号低字节

                // 复制数据负载
                Array.Copy(payload, offset, packet, 28, length);

                // 计算ICMP校验和
                ushort icmpChecksum = CalculateChecksum(packet, 20, 8 + length);
                packet[22] = (byte)(icmpChecksum >> 8);
                packet[23] = (byte)(icmpChecksum & 0xFF);
            }

            return packet;
        }

        /// <summary>
        /// 计算IP校验和
        /// </summary>
        static ushort CalculateChecksum(byte[] buffer, int offset, int length)
        {
            int sum = 0;
            int i = offset;

            // 按16位字进行求和
            while (length > 1)
            {
                sum += (buffer[i] << 8) | buffer[i + 1];
                i += 2;
                length -= 2;
            }

            // 如果长度为奇数，处理最后一个字节
            if (length > 0)
            {
                sum += buffer[i] << 8;
            }

            // 将进位加到结果中
            while ((sum >> 16) > 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // 取反
            return (ushort)~sum;
        }

        /// <summary>
        /// 关闭所有连接
        /// </summary>
        static void CloseAllConnections()
        {
            foreach (var socket in _connectionTable.Values)
            {
                try
                {
                    socket.Dispose();
                }
                catch { }
            }
            _connectionTable.Clear();
        }

        /// <summary>
        /// 显示数据包信息
        /// </summary>
        static void DisplayPacketInfo(byte[] packet)
        {
            if (packet.Length < 20)
            {
                Console.WriteLine($"收到的数据包太短: {packet.Length} 字节");
                return;
            }

            // 获取IP版本
            int version = packet[0] >> 4;

            if (version == 4) // IPv4
            {
                // 获取协议
                byte protocol = packet[9];

                // 获取源IP和目标IP
                IPAddress sourceIP = new IPAddress(new byte[] { packet[12], packet[13], packet[14], packet[15] });
                IPAddress destIP = new IPAddress(new byte[] { packet[16], packet[17], packet[18], packet[19] });

                string protocolName = GetProtocolName(protocol);

                Console.WriteLine($"IPv4数据包: {sourceIP} -> {destIP}, 协议: {protocolName}, 长度: {packet.Length} 字节");

                // 如果是ICMP，显示更多信息
                if (protocol == 1) // ICMP
                {
                    byte type = packet[20];
                    byte code = packet[21];
                    Console.WriteLine($"  ICMP类型: {type}, 代码: {code}");
                }
                // 如果是TCP，显示端口信息
                else if (protocol == 6) // TCP
                {
                    int sourcePort = (packet[20] << 8) | packet[21];
                    int destPort = (packet[22] << 8) | packet[23];
                    Console.WriteLine($"  TCP端口: {sourcePort} -> {destPort}");
                }
                // 如果是UDP，显示端口信息
                else if (protocol == 17) // UDP
                {
                    int sourcePort = (packet[20] << 8) | packet[21];
                    int destPort = (packet[22] << 8) | packet[23];
                    Console.WriteLine($"  UDP端口: {sourcePort} -> {destPort}");
                }
            }
            else if (version == 6) // IPv6
            {
                Console.WriteLine($"IPv6数据包: 长度: {packet.Length} 字节");
            }
            else
            {
                Console.WriteLine($"未知IP版本: {version}, 长度: {packet.Length} 字节");
            }
        }

        /// <summary>
        /// 获取协议名称
        /// </summary>
        static string GetProtocolName(byte protocol)
        {
            switch (protocol)
            {
                case 1: return "ICMP";
                case 2: return "IGMP";
                case 6: return "TCP";
                case 17: return "UDP";
                case 50: return "ESP";
                case 51: return "AH";
                case 58: return "ICMPv6";
                default: return protocol.ToString();
            }
        }

        /// <summary>
        /// 配置排除的IP地址
        /// </summary>
        static void ConfigureExcludedIPs()
        {
            Console.WriteLine("\n排除特定IP地址配置");
            Console.WriteLine("-------------------------");
            Console.WriteLine("您可以指定一些不通过虚拟适配器路由的IP地址，例如服务器的IP地址。");
            Console.WriteLine("这将确保这些地址的流量不会通过SOCKS5代理转发。");
            Console.WriteLine("输入多个IP地址时请用逗号分隔，或者留空不排除任何IP。");

            Console.Write("要排除的IP地址: ");
            string? excludedIPsStr = Console.ReadLine();

            if (!string.IsNullOrWhiteSpace(excludedIPsStr))
            {
                // 清空当前列表
                _excludedIPs.Clear();

                // 分割并添加IP地址
                string[] ips = excludedIPsStr.Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string ip in ips)
                {
                    string trimmedIP = ip.Trim();
                    if (IPAddress.TryParse(trimmedIP, out _))
                    {
                        _excludedIPs.Add(trimmedIP);
                    }
                    else
                    {
                        Console.WriteLine($"警告: '{trimmedIP}' 不是有效的IP地址，已忽略。");
                    }
                }

                // 自动添加代理服务器的IP地址
                IPAddress proxyIP = GetProxyServerIP(_proxyHost);
                string proxyIPStr = proxyIP.ToString();

                if (!_excludedIPs.Contains(proxyIPStr))
                {
                    _excludedIPs.Add(proxyIPStr);
                    Console.WriteLine($"自动添加代理服务器IP {proxyIPStr} 到排除列表。");
                }
            }
            else
            {
                // 如果用户没有输入任何IP，自动添加代理服务器的IP
                _excludedIPs.Clear();
                IPAddress proxyIP = GetProxyServerIP(_proxyHost);
                _excludedIPs.Add(proxyIP.ToString());
                Console.WriteLine($"已自动添加代理服务器IP {proxyIP} 到排除列表。");
            }
        }

        /// <summary>
        /// 获取代理服务器的IP地址
        /// </summary>
        static IPAddress GetProxyServerIP(string hostname)
        {
            try
            {
                // 尝试直接解析为IP地址
                if (IPAddress.TryParse(hostname, out IPAddress? ipAddress))
                {
                    return ipAddress;
                }

                // 如果是域名，进行域名解析
                IPHostEntry hostEntry = Dns.GetHostEntry(hostname);
                if (hostEntry.AddressList.Length > 0)
                {
                    // 优先返回IPv4地址
                    foreach (IPAddress addr in hostEntry.AddressList)
                    {
                        if (addr.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return addr;
                        }
                    }

                    // 如果没有IPv4地址，返回第一个地址
                    return hostEntry.AddressList[0];
                }

                // 如果解析失败，返回回环地址
                Console.WriteLine($"警告: 无法解析主机名 {hostname}, 使用回环地址");
                return IPAddress.Loopback;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"解析代理主机名时出错: {ex.Message}");
                return IPAddress.Loopback;
            }
        }

        /// <summary>
        /// 获取默认网关IP地址
        /// </summary>
        static IPAddress? GetDefaultGateway()
        {
            try
            {
                // 获取所有网络接口
                NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (NetworkInterface ni in interfaces)
                {
                    // 只考虑正常工作的接口
                    if (ni.OperationalStatus != OperationalStatus.Up)
                        continue;

                    // 跳过回环接口和虚拟接口
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                        ni.Description.Contains("Virtual") ||
                        ni.Description.Contains("Pseudo"))
                        continue;

                    // 获取接口的网关地址
                    IPInterfaceProperties ipProps = ni.GetIPProperties();
                    GatewayIPAddressInformationCollection gateways = ipProps.GatewayAddresses;

                    if (gateways.Count > 0)
                    {
                        foreach (GatewayIPAddressInformation gateway in gateways)
                        {
                            // 只返回IPv4网关
                            if (gateway.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                return gateway.Address;
                            }
                        }
                    }
                }

                Console.WriteLine("警告: 无法找到默认网关");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"查找默认网关时出错: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// 配置网络适配器的IP地址
        /// </summary>
        static bool ConfigureAdapterIP(string adapterName, string ipAddress, string subnetMask)
        {
            try
            {
                // 使用netsh命令配置IP地址
                ProcessStartInfo psi = new ProcessStartInfo("netsh", $"interface ip set address name=\"{adapterName}\" static {ipAddress} {subnetMask}");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                using (Process process = Process.Start(psi))
                {
                    if (process != null)
                    {
                        process.WaitForExit();
                        return process.ExitCode == 0;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"配置适配器IP时出错: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 添加路由
        /// </summary>
        static bool AddRoute(string destination, string mask, string gateway)
        {
            try
            {
                // 使用route命令添加路由
                ProcessStartInfo psi = new ProcessStartInfo("route", $"add {destination} mask {mask} {gateway}");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                using (Process process = Process.Start(psi))
                {
                    if (process != null)
                    {
                        process.WaitForExit();
                        bool success = process.ExitCode == 0;

                        // 如果成功，添加到路由跟踪列表
                        if (success)
                        {
                            _addedRoutes.Add((destination, mask));
                        }

                        return success;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"添加路由时出错: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// 清理添加的路由
        /// </summary>
        static void CleanupRoutes()
        {
            if (_addedRoutes.Count == 0)
            {
                return;
            }

            Console.WriteLine($"正在删除 {_addedRoutes.Count} 条路由...");

            foreach (var route in _addedRoutes)
            {
                try
                {
                    string destination = route.destination;
                    string mask = route.mask;

                    Console.WriteLine($"删除路由: {destination} mask {mask}");

                    // 使用route命令删除路由
                    ProcessStartInfo psi = new ProcessStartInfo("route", $"delete {destination} mask {mask}");
                    psi.CreateNoWindow = true;
                    psi.UseShellExecute = false;
                    psi.RedirectStandardOutput = true;
                    psi.RedirectStandardError = true;

                    using (Process process = Process.Start(psi))
                    {
                        if (process != null)
                        {
                            process.WaitForExit();
                            if (process.ExitCode != 0)
                            {
                                Console.WriteLine($"删除路由失败: {destination} mask {mask}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"删除路由时出错: {ex.Message}");
                }
            }

            // 清空路由列表
            _addedRoutes.Clear();
        }

        /// <summary>
        /// 重置适配器IP地址
        /// </summary>
        static void ResetAdapterIP()
        {
            if (string.IsNullOrEmpty(_configuredAdapterName))
            {
                return;
            }

            try
            {
                Console.WriteLine($"正在将适配器 '{_configuredAdapterName}' 重置为DHCP...");

                // 使用netsh命令将适配器设置为DHCP
                ProcessStartInfo psi = new ProcessStartInfo("netsh", $"interface ip set address name=\"{_configuredAdapterName}\" dhcp");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                using (Process process = Process.Start(psi))
                {
                    if (process != null)
                    {
                        process.WaitForExit();
                        if (process.ExitCode != 0)
                        {
                            Console.WriteLine($"将适配器 '{_configuredAdapterName}' 重置为DHCP失败");
                        }
                        else
                        {
                            Console.WriteLine($"适配器 '{_configuredAdapterName}' 已成功重置为DHCP");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"重置适配器IP时出错: {ex.Message}");
            }

            // 清空适配器名称
            _configuredAdapterName = null;
        }
    }
}
