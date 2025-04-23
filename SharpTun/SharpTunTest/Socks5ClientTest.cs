// 不再需要引用SharpTun命名空间
using System.Text;

namespace SharpTunTest
{
    /// <summary>
    /// 测试Socks5Client与PekVpnProxy中的Socks5Server的连接
    /// </summary>
    public class Socks5ClientTest
    {
        public static async Task RunTest()
        {
            Console.WriteLine("Socks5客户端测试");
            Console.WriteLine("=================\n");

            // 配置Socks5代理服务器信息
            Console.WriteLine("请输入Socks5代理服务器地址 (默认: 127.0.0.1): ");
            string proxyHost = Console.ReadLine() ?? "127.0.0.1";
            if (string.IsNullOrWhiteSpace(proxyHost))
                proxyHost = "127.0.0.1";

            Console.WriteLine("请输入Socks5代理服务器端口 (默认: 1080): ");
            string proxyPortStr = Console.ReadLine() ?? "1080";
            if (!int.TryParse(proxyPortStr, out int proxyPort) || proxyPort <= 0 || proxyPort > 65535)
                proxyPort = 1080;

            Console.WriteLine("是否需要认证? (y/n, 默认: n): ");
            string needAuth = Console.ReadLine() ?? "n";
            string? username = null;
            string? password = null;

            if (needAuth.Trim().ToLower() == "y")
            {
                Console.WriteLine("请输入用户名: ");
                username = Console.ReadLine();
                Console.WriteLine("请输入密码: ");
                password = Console.ReadLine();
            }

            // 配置目标服务器信息
            Console.WriteLine("\n请输入目标服务器地址 (默认: www.google.com): ");
            string destinationHost = Console.ReadLine() ?? "www.google.com";
            if (string.IsNullOrWhiteSpace(destinationHost))
                destinationHost = "www.google.com";

            Console.WriteLine("请输入目标服务器端口 (默认: 80): ");
            string destPortStr = Console.ReadLine() ?? "80";
            if (!int.TryParse(destPortStr, out int destinationPort) || destinationPort <= 0 || destinationPort > 65535)
                destinationPort = 80;

            Console.WriteLine("请输入请求路径 (默认: /): ");
            string requestPath = Console.ReadLine() ?? "/";
            if (string.IsNullOrWhiteSpace(requestPath))
                requestPath = "/";
            if (!requestPath.StartsWith("/"))
                requestPath = "/" + requestPath;

            Console.WriteLine("\n正在连接...");

            // 创建Socks5Client并连接
            var socks5Client = new Socks5Client(proxyHost, proxyPort, username, password);
            bool connected = await socks5Client.ConnectAsync(destinationHost, destinationPort);

            if (connected)
            {
                try
                {
                    // 如果连接成功，发送一个HTTP GET请求（假设目标是HTTP服务器）
                    if (destinationPort == 80 || destinationPort == 8080 || destinationPort == 443)
                    {
                        Console.WriteLine("\n发送HTTP GET请求...");
                        // 准备HTTP请求
                        string protocol = destinationPort == 443 ? "HTTPS" : "HTTP";
                        Console.WriteLine($"使用{protocol}协议发送请求");
                        Console.WriteLine($"连接状态: {socks5Client.GetConnectionInfo()}");

                        // 增加更多HTTP头部以提高兼容性
                        string httpRequest = $"GET {requestPath} HTTP/1.1\r\n" +
                                           $"Host: {destinationHost}\r\n" +
                                           $"User-Agent: Mozilla/5.0 Socks5Client\r\n" +
                                           $"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
                                           $"Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n" +
                                           $"Connection: close\r\n\r\n";
                        Console.WriteLine($"请求URL: {protocol.ToLower()}://{destinationHost}{requestPath}");
                        Console.WriteLine("请求头部:\n" + httpRequest);

                        byte[] requestData = Encoding.ASCII.GetBytes(httpRequest);
                        await socks5Client.SendAsync(requestData);

                        // 接收响应
                        byte[] responseBuffer = new byte[8192];
                        int bytesRead = await socks5Client.ReceiveAsync(responseBuffer, 10000); // 10秒超时

                        if (bytesRead > 0)
                        {
                            string response = Encoding.ASCII.GetString(responseBuffer, 0, bytesRead);
                            Console.WriteLine("\n收到响应 (前1000个字符):\n");
                            Console.WriteLine(response.Length > 1000 ? response.Substring(0, 1000) + "..." : response);
                            Console.WriteLine($"\n[总共接收: {bytesRead} 字节]");
                        }
                        else
                        {
                            Console.WriteLine("未收到响应");
                        }
                    }
                    else
                    {
                        Console.WriteLine("连接成功，但不是HTTP端口，跳过发送HTTP请求");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"通信错误: {ex.Message}");
                }
                finally
                {
                    // 断开连接
                    socks5Client.Disconnect();
                    Console.WriteLine("\n已断开连接");
                }
            }

            // 测试同步方法
            Console.WriteLine("\n测试同步连接方法...");
            try
            {
                var syncClient = new Socks5Client(proxyHost, proxyPort, username, password);
                using (var socket = syncClient.CreateConnection(destinationHost, destinationPort))
                {
                    Console.WriteLine("同步连接成功！");

                    if (destinationPort == 80 || destinationPort == 8080)
                    {
                        // 发送简单的HTTP请求
                        string httpRequest = $"GET {requestPath} HTTP/1.1\r\n" +
                                           $"Host: {destinationHost}\r\n" +
                                           $"Connection: close\r\n\r\n";

                        byte[] requestData = Encoding.ASCII.GetBytes(httpRequest);
                        socket.Send(requestData);

                        // 接收响应
                        byte[] responseBuffer = new byte[8192];
                        int bytesRead = socket.Receive(responseBuffer);

                        if (bytesRead > 0)
                        {
                            string response = Encoding.ASCII.GetString(responseBuffer, 0, bytesRead);
                            Console.WriteLine("\n同步方法收到响应 (前500个字符):\n");
                            Console.WriteLine(response.Length > 500 ? response.Substring(0, 500) + "..." : response);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"同步连接测试失败: {ex.Message}");
            }

            Console.WriteLine("\n按任意键退出...");
            Console.ReadKey();
        }
    }
}
