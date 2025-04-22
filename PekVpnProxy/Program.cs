using NewLife.Log;
using System.Text;

namespace PekVpnProxy
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            XTrace.UseConsole();

            XTrace.WriteLine("Socks5代理测试工具");
            XTrace.WriteLine("=================\n");

            XTrace.WriteLine("请选择模式:");
            XTrace.WriteLine("1. 启动Socks5服务端");
            XTrace.WriteLine("2. 启动Socks5客户端");
            XTrace.WriteLine("请输入选择 (默认: 1): ");

            string choice = Console.ReadLine() ?? "1";
            if (choice == "2")
            {
                await RunClientModeAsync();
            }
            else
            {
                await RunServerModeAsync();
            }
        }

        /// <summary>
        /// 运行服务端模式
        /// </summary>
        static async Task RunServerModeAsync()
        {
            XTrace.WriteLine("\nSocks5服务端模式");
            XTrace.WriteLine("=================\n");

            // 配置服务端参数
            XTrace.WriteLine("请输入监听地址 (默认: 0.0.0.0): ");
            string listenIp = Console.ReadLine() ?? "0.0.0.0";
            if (string.IsNullOrWhiteSpace(listenIp))
                listenIp = "0.0.0.0";

            XTrace.WriteLine("请输入监听端口 (默认: 1080): ");
            string listenPortStr = Console.ReadLine() ?? "1080";
            if (!int.TryParse(listenPortStr, out int listenPort) || listenPort <= 0 || listenPort > 65535)
                listenPort = 1080;

            XTrace.WriteLine("是否启用认证? (y/n, 默认: n): ");
            string enableAuth = Console.ReadLine() ?? "n";
            bool requireAuth = enableAuth.Trim().ToLower() == "y";

            // 创建认证管理器
            var authManager = new AuthenticationManager(requireAuth);

            // 如果启用认证，添加测试用户
            if (requireAuth)
            {
                XTrace.WriteLine("\n添加测试用户:");
                bool addingUsers = true;

                while (addingUsers)
                {
                    XTrace.WriteLine("请输入用户名: ");
                    string? username = Console.ReadLine();

                    if (string.IsNullOrWhiteSpace(username))
                    {
                        XTrace.WriteLine("用户名不能为空，跳过添加");
                    }
                    else
                    {
                        XTrace.WriteLine("请输入密码: ");
                        string? password = Console.ReadLine();

                        if (string.IsNullOrWhiteSpace(password))
                        {
                            XTrace.WriteLine("密码不能为空，跳过添加");
                        }
                        else if (authManager.AddUser(username, password))
                        {
                            XTrace.WriteLine($"用户 {username} 添加成功");
                        }
                        else
                        {
                            XTrace.WriteLine($"用户 {username} 添加失败，可能已存在");
                        }
                    }

                    XTrace.WriteLine("\n是否继续添加用户? (y/n, 默认: n): ");
                    string continueAdding = Console.ReadLine() ?? "n";
                    addingUsers = continueAdding.Trim().ToLower() == "y";
                }

                XTrace.WriteLine($"\n已添加 {authManager.UserCount} 个用户");
            }

            // 创建并启动Socks5服务端
            var server = new Socks5Server(listenIp, listenPort, authManager);

            // 启动服务器任务
            Task serverTask = server.StartAsync();

            XTrace.WriteLine("\n服务已启动，按任意键停止服务...");
            Console.ReadKey(true);

            // 停止服务
            await server.StopAsync();

            XTrace.WriteLine("\n按任意键退出...");
            Console.ReadKey();
        }

        /// <summary>
        /// 运行客户端模式
        /// </summary>
        static async Task RunClientModeAsync()
        {
            XTrace.WriteLine("\nSocks5客户端模式");
            XTrace.WriteLine("=================\n");

            // 配置Socks5代理服务器信息
            XTrace.WriteLine("请输入Socks5代理服务器地址 (默认: 127.0.0.1): ");
            string proxyHost = Console.ReadLine() ?? "127.0.0.1";
            if (string.IsNullOrWhiteSpace(proxyHost))
                proxyHost = "127.0.0.1";

            XTrace.WriteLine("请输入Socks5代理服务器端口 (默认: 1080): ");
            string proxyPortStr = Console.ReadLine() ?? "1080";
            if (!int.TryParse(proxyPortStr, out int proxyPort) || proxyPort <= 0 || proxyPort > 65535)
                proxyPort = 1080;

            XTrace.WriteLine("是否需要认证? (y/n, 默认: n): ");
            string needAuth = Console.ReadLine() ?? "n";
            string? username = null;
            string? password = null;

            if (needAuth.Trim().ToLower() == "y")
            {
                XTrace.WriteLine("请输入用户名: ");
                username = Console.ReadLine();
                XTrace.WriteLine("请输入密码: ");
                password = Console.ReadLine();
            }

            // 配置目标服务器信息
            XTrace.WriteLine("\n请输入目标服务器地址 (默认: www.google.com): ");
            string destinationHost = Console.ReadLine() ?? "www.google.com";
            if (string.IsNullOrWhiteSpace(destinationHost))
                destinationHost = "www.google.com";

            XTrace.WriteLine("请输入目标服务器端口 (默认: 80): ");
            string destPortStr = Console.ReadLine() ?? "80";
            if (!int.TryParse(destPortStr, out int destinationPort) || destinationPort <= 0 || destinationPort > 65535)
                destinationPort = 80;

            XTrace.WriteLine("\n正在连接...");

            // 创建Socks5客户端并连接
            var socks5Client = new Socks5Client(proxyHost, proxyPort, username, password);
            bool connected = await socks5Client.ConnectAsync(destinationHost, destinationPort);

            if (connected)
            {
                try
                {
                    // 如果连接成功，发送一个简单的HTTP GET请求（假设目标是HTTP服务器）
                    if (destinationPort == 80 || destinationPort == 8080)
                    {
                        XTrace.WriteLine("\n发送HTTP GET请求...");
                        string httpRequest = $"GET / HTTP/1.1\r\nHost: {destinationHost}\r\nConnection: close\r\n\r\n";
                        byte[] requestData = Encoding.ASCII.GetBytes(httpRequest);
                        await socks5Client.SendAsync(requestData);

                        // 接收响应
                        byte[] responseBuffer = new byte[4096];
                        int bytesRead = await socks5Client.ReceiveAsync(responseBuffer);

                        if (bytesRead > 0)
                        {
                            string response = Encoding.ASCII.GetString(responseBuffer, 0, bytesRead);
                            XTrace.WriteLine("\n收到响应:\n");
                            // 只显示响应的前500个字符
                            XTrace.WriteLine(response.Length > 500 ? response.Substring(0, 500) + "..." : response);
                        }
                        else
                        {
                            XTrace.WriteLine("未收到响应");
                        }
                    }
                    else
                    {
                        XTrace.WriteLine("连接成功，但不是HTTP端口，跳过发送HTTP请求");
                    }
                }
                catch (Exception ex)
                {
                    XTrace.WriteLine($"通信错误: {ex.Message}");
                }
                finally
                {
                    // 断开连接
                    socks5Client.Disconnect();
                    XTrace.WriteLine("\n已断开连接");
                }
            }

            XTrace.WriteLine("\n按任意键退出...");
            Console.ReadKey();
        }
    }
}
