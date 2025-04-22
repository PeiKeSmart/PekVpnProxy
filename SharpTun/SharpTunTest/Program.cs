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
            Socks5Proxy       // SOCKS5代理转发
        }

        // SOCKS5代理配置
        private static string _socks5Host = "127.0.0.1";
        private static int _socks5Port = 1080;
        private static string? _socks5Username = null;
        private static string? _socks5Password = null;
        private static bool _handleIcmp = false;  // 是否处理ICMP流量

        // 连接跟踪表
        private static Dictionary<string, Socket> _connectionTable = new Dictionary<string, Socket>();

        static void Main(string[] args)
        {
            Console.WriteLine("SharpTun Test Program");
            Console.WriteLine("=====================");
            Console.WriteLine("This program will create a virtual network adapter and capture packets.");
            Console.WriteLine("You need to run this program as administrator.");
            Console.WriteLine();
            Console.WriteLine("Select test mode:");
            Console.WriteLine("1. Capture Only - Just capture and display network packets");
            Console.WriteLine("2. SOCKS5 Proxy - Capture packets and forward through SOCKS5 proxy");
            Console.Write("Enter your choice (1-2): ");

            TestMode mode = TestMode.CaptureOnly;
            string? choice = Console.ReadLine();
            if (choice == "2")
            {
                mode = TestMode.Socks5Proxy;
                ConfigureSocks5Proxy();
            }

            // 创建一个唯一的GUID用于适配器
            Guid adapterGuid = Guid.NewGuid();
            string adapterName = "SharpTunTest";
            string tunnelType = "WinTun";

            try
            {
                Console.WriteLine($"Creating adapter '{adapterName}' with GUID {adapterGuid}...");

                // 创建虚拟网络适配器
                using (var adapter = ManagedWintunAdapter.Create(adapterName, tunnelType, adapterGuid))
                {
                    Console.WriteLine("Adapter created successfully.");

                    // 获取适配器的LUID
                    var luid = adapter.GetLuid();
                    Console.WriteLine($"Adapter LUID: {luid.LowPart}, {luid.HighPart}");

                    // 启动会话
                    Console.WriteLine("Starting session...");
                    using (var session = adapter.Start(0x400000))
                    {
                        Console.WriteLine("Session started successfully.");
                        Console.WriteLine();
                        Console.WriteLine("Now we need to configure the adapter with an IP address.");
                        Console.WriteLine("Please open another command prompt as administrator and run:");
                        Console.WriteLine($"netsh interface ip set address name=\"{adapterName}\" static 192.168.56.1 255.255.255.0");

                        // 如果是SOCKS5代理模式，需要设置路由
                        if (mode == TestMode.Socks5Proxy)
                        {
                            Console.WriteLine();
                            Console.WriteLine("For SOCKS5 proxy mode, you need to add routes to direct traffic through the adapter.");
                            Console.WriteLine("To route ALL internet traffic through the adapter, run:");
                            Console.WriteLine($"route add 0.0.0.0 mask 0.0.0.0 192.168.56.1");
                            Console.WriteLine();
                            Console.WriteLine("Or for testing with specific destinations only:");
                            Console.WriteLine($"route add 8.8.8.8 mask 255.255.255.255 192.168.56.1");
                            Console.WriteLine($"route add 1.1.1.1 mask 255.255.255.255 192.168.56.1");
                            Console.WriteLine();
                            Console.WriteLine("IMPORTANT: Make sure your SOCKS5 proxy server is accessible directly,");
                            Console.WriteLine("not through the virtual adapter, or you'll create a routing loop!");
                        }

                        Console.WriteLine();
                        Console.WriteLine("After configuring, try to ping 8.8.8.8 to generate some traffic.");
                        Console.WriteLine("Press any key to start capturing packets...");
                        Console.ReadKey();

                        // 开始捕获数据包
                        Console.WriteLine("Starting packet capture. Press Ctrl+C to stop.");

                        // 注册Ctrl+C处理程序
                        Console.CancelKeyPress += (sender, e) => {
                            e.Cancel = true;
                            CloseAllConnections();
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
                                Console.WriteLine($"Error receiving packet: {ex.Message}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        /// <summary>
        /// 配置SOCKS5代理设置
        /// </summary>
        static void ConfigureSocks5Proxy()
        {
            Console.WriteLine("\nSOCKS5 Proxy Configuration");
            Console.WriteLine("-------------------------");

            Console.Write("Proxy Host (default: 127.0.0.1): ");
            string? host = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(host))
            {
                _socks5Host = host;
            }

            Console.Write("Proxy Port (default: 1080): ");
            string? portStr = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(portStr) && int.TryParse(portStr, out int port))
            {
                _socks5Port = port;
            }

            Console.Write("Username (leave empty for no authentication): ");
            string? username = Console.ReadLine();
            if (!string.IsNullOrWhiteSpace(username))
            {
                _socks5Username = username;

                Console.Write("Password: ");
                string? password = Console.ReadLine();
                _socks5Password = password;
            }

            Console.Write("Handle ICMP traffic (ping) through SOCKS5? (y/n, default: n): ");
            string? handleIcmp = Console.ReadLine()?.ToLower();
            _handleIcmp = handleIcmp == "y" || handleIcmp == "yes";

            Console.WriteLine($"SOCKS5 Proxy configured: {_socks5Host}:{_socks5Port}");
            if (_socks5Username != null)
            {
                Console.WriteLine($"Authentication: Username={_socks5Username}");
            }
            else
            {
                Console.WriteLine("Authentication: None");
            }
            Console.WriteLine($"Handle ICMP traffic: {(_handleIcmp ? "Yes" : "No")}");
        }

        /// <summary>
        /// 处理数据包并通过SOCKS5代理转发
        /// </summary>
        static void ProcessPacketForSocks5(byte[] packet, SharpTun.Interface.ITunSession session)
        {
            if (packet.Length < 20)
            {
                return; // 数据包太短，忽略
            }

            // 获取IP版本
            int version = packet[0] >> 4;
            if (version != 4) // 目前只处理IPv4
            {
                Console.WriteLine("Skipping non-IPv4 packet");
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
                    Console.WriteLine("Processing ICMP packet");
                }
                else
                {
                    // 对于其他协议，我们选择忽略
                    Console.WriteLine($"Skipping non-TCP/UDP/ICMP packet (protocol: {protocol})");
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
                    // 创建新的SOCKS5连接
                    if (protocol == 1) // ICMP
                    {
                        Console.WriteLine($"Creating new SOCKS5 connection for ICMP to {destIP}");
                        // 对于ICMP，我们使用一个特殊端口（例如7）来创建SOCKS5连接
                        // 实际上，SOCKS5代理通常不直接支持ICMP，这里是一个变通方法
                        Socks5Client socks5Client = new Socks5Client(_socks5Host, _socks5Port, _socks5Username, _socks5Password);
                        proxySocket = socks5Client.CreateConnection(destIP.ToString(), 7); // 使用echo端口
                    }
                    else
                    {
                        Console.WriteLine($"Creating new SOCKS5 connection to {destIP}:{destPort}");
                        Socks5Client socks5Client = new Socks5Client(_socks5Host, _socks5Port, _socks5Username, _socks5Password);
                        proxySocket = socks5Client.CreateConnection(destIP.ToString(), destPort);
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
                Console.WriteLine($"Error forwarding packet to SOCKS5: {ex.Message}");
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
                    Console.WriteLine($"Error in receive thread: {ex.Message}");
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
                Console.WriteLine($"Received packet too short: {packet.Length} bytes");
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

                Console.WriteLine($"IPv4 Packet: {sourceIP} -> {destIP}, Protocol: {protocolName}, Length: {packet.Length} bytes");

                // 如果是ICMP，显示更多信息
                if (protocol == 1) // ICMP
                {
                    byte type = packet[20];
                    byte code = packet[21];
                    Console.WriteLine($"  ICMP Type: {type}, Code: {code}");
                }
                // 如果是TCP，显示端口信息
                else if (protocol == 6) // TCP
                {
                    int sourcePort = (packet[20] << 8) | packet[21];
                    int destPort = (packet[22] << 8) | packet[23];
                    Console.WriteLine($"  TCP Ports: {sourcePort} -> {destPort}");
                }
                // 如果是UDP，显示端口信息
                else if (protocol == 17) // UDP
                {
                    int sourcePort = (packet[20] << 8) | packet[21];
                    int destPort = (packet[22] << 8) | packet[23];
                    Console.WriteLine($"  UDP Ports: {sourcePort} -> {destPort}");
                }
            }
            else if (version == 6) // IPv6
            {
                Console.WriteLine($"IPv6 Packet: Length: {packet.Length} bytes");
            }
            else
            {
                Console.WriteLine($"Unknown IP version: {version}, Length: {packet.Length} bytes");
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
    }
}
