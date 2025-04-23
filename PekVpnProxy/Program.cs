using NewLife.Log;
using System.Text;
using SharpTunTest;

namespace PekVpnProxy
{
    internal class Program
    {
        /// <summary>
        /// 解码HTTP分块传输编码的正文
        /// </summary>
        /// <param name="chunkedBody">分块传输编码的正文</param>
        /// <returns>解码后的正文</returns>
        private static string DecodeChunkedBody(string chunkedBody)
        {
            try
            {
                StringBuilder result = new StringBuilder();
                int index = 0;

                while (index < chunkedBody.Length)
                {
                    // 查找块大小行的结束位置
                    int lineEnd = chunkedBody.IndexOf("\r\n", index);
                    if (lineEnd == -1) break; // 找不到行结束符，可能数据不完整

                    // 解析块大小（十六进制）
                    string chunkSizeHex = chunkedBody.Substring(index, lineEnd - index).Trim();

                    // 如果块大小行包含其他内容（如分号后的扩展参数），只取分号前的部分
                    int semicolonIndex = chunkSizeHex.IndexOf(';');
                    if (semicolonIndex != -1)
                    {
                        chunkSizeHex = chunkSizeHex.Substring(0, semicolonIndex);
                    }

                    // 尝试解析十六进制大小
                    if (!int.TryParse(chunkSizeHex, System.Globalization.NumberStyles.HexNumber, null, out int chunkSize))
                    {
                        // 解析失败，可能数据不完整或格式错误
                        break;
                    }

                    // 如果块大小为0，表示结束
                    if (chunkSize == 0)
                    {
                        break;
                    }

                    // 计算块内容的起始位置（跳过\r\n）
                    int chunkStart = lineEnd + 2;

                    // 确保有足够的数据
                    if (chunkStart + chunkSize > chunkedBody.Length)
                    {
                        // 数据不完整
                        result.Append(chunkedBody.Substring(chunkStart));
                        break;
                    }

                    // 提取块内容
                    result.Append(chunkedBody.Substring(chunkStart, chunkSize));

                    // 移动到下一个块（跳过当前块的\r\n）
                    index = chunkStart + chunkSize + 2;
                }

                return result.ToString();
            }
            catch (Exception ex)
            {
                // 解码失败，返回原始数据
                XTrace.WriteLine($"解码分块传输编码失败: {ex.Message}");
                return chunkedBody;
            }
        }

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

            XTrace.WriteLine("请输入请求路径 (默认: /): ");
            string requestPath = Console.ReadLine() ?? "/";
            if (string.IsNullOrWhiteSpace(requestPath))
                requestPath = "/";
            if (!requestPath.StartsWith("/"))
                requestPath = "/" + requestPath;

            XTrace.WriteLine("\n正在连接...");

            // 创建Socks5客户端并连接
            var socks5Client = new Socks5Client(proxyHost, proxyPort, username, password);
            bool connected = await socks5Client.ConnectAsync(destinationHost, destinationPort);

            if (connected)
            {
                // 声明在try块外部，以便在finally块中可以访问
                bool isChunked = false;

                try
                {
                    // 如果连接成功，发送一个HTTP GET请求（假设目标是HTTP服务器）
                    if (destinationPort == 80 || destinationPort == 8080 || destinationPort == 443)
                    {
                        XTrace.WriteLine("\n发送HTTP GET请求...");
                        // 准备HTTP请求
                        string protocol = destinationPort == 443 ? "HTTPS" : "HTTP";
                        XTrace.WriteLine($"使用{protocol}协议发送请求");
                        XTrace.WriteLine($"连接状态: {socks5Client.GetConnectionInfo()}");

                        // 增加更多HTTP头部以提高兼容性
                        string httpRequest = $"GET {requestPath} HTTP/1.1\r\n" +
                                           $"Host: {destinationHost}\r\n" +
                                           $"User-Agent: Mozilla/5.0 PekVpnProxy\r\n" +
                                           $"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
                                           $"Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n" +
                                           $"Connection: close\r\n\r\n";
                        XTrace.WriteLine($"请求URL: {protocol.ToLower()}://{destinationHost}{requestPath}");
                        XTrace.WriteLine("请求头部:\n" + httpRequest);

                        byte[] requestData = Encoding.ASCII.GetBytes(httpRequest);
                        await socks5Client.SendAsync(requestData);

                        // 接收响应 - 改进为多次读取
                        byte[] responseBuffer = new byte[8192]; // 增大缓冲区
                        StringBuilder responseBuilder = new StringBuilder();
                        int totalBytesRead = 0;
                        int bytesRead;
                        bool headerReceived = false;
                        int contentLength = -1;

                        // 循环读取直到没有更多数据或连接关闭
                        int consecutiveTimeouts = 0;
                        int maxConsecutiveTimeouts = 3; // 最多连续超时次数

                        while (true)
                        {
                            bytesRead = await socks5Client.ReceiveAsync(responseBuffer, 10000); // 10秒超时

                            if (bytesRead > 0)
                            {
                                // 成功接收数据
                                totalBytesRead += bytesRead;
                                string partialResponse = Encoding.ASCII.GetString(responseBuffer, 0, bytesRead);
                                responseBuilder.Append(partialResponse);

                                // 重置连续超时计数器
                                consecutiveTimeouts = 0;
                            }
                            else
                            {
                                // 超时或连接关闭
                                consecutiveTimeouts++;
                                XTrace.WriteLine($"接收超时 ({consecutiveTimeouts}/{maxConsecutiveTimeouts})");

                                // 如果连续超时多次，退出循环
                                if (consecutiveTimeouts >= maxConsecutiveTimeouts)
                                {
                                    XTrace.WriteLine("达到最大连续超时次数，停止接收");
                                    break;
                                }

                                // 如果已经接收到了完整的响应，可以退出
                                if (headerReceived)
                                {
                                    string fullResponse = responseBuilder.ToString();

                                    // 对于分块传输编码，检查是否有结束块
                                    if (isChunked)
                                    {
                                        int headerEndIndex = fullResponse.IndexOf("\r\n\r\n") + 4;
                                        string body = fullResponse.Substring(headerEndIndex);

                                        if (body.Contains("\r\n0\r\n\r\n") || body.EndsWith("0\r\n\r\n"))
                                        {
                                            XTrace.WriteLine("检测到完整的分块响应，停止接收");
                                            break;
                                        }
                                    }
                                    // 对于普通响应，检查Content-Length
                                    else if (contentLength > 0)
                                    {
                                        int headerEndIndex = fullResponse.IndexOf("\r\n\r\n") + 4;
                                        int bodyLength = fullResponse.Length - headerEndIndex;

                                        if (bodyLength >= contentLength)
                                        {
                                            XTrace.WriteLine("检测到完整的Content-Length响应，停止接收");
                                            break;
                                        }
                                    }
                                }

                                // 继续尝试接收
                                continue;
                            }

                            // 检查是否已接收到HTTP头部
                            if (!headerReceived && responseBuilder.ToString().Contains("\r\n\r\n"))
                            {
                                headerReceived = true;
                                string fullResponse = responseBuilder.ToString();

                                // 检查Content-Length
                                int contentLengthIndex = fullResponse.IndexOf("Content-Length:", StringComparison.OrdinalIgnoreCase);
                                if (contentLengthIndex >= 0)
                                {
                                    int endOfLine = fullResponse.IndexOf("\r\n", contentLengthIndex);
                                    string contentLengthValue = fullResponse.Substring(contentLengthIndex + 15, endOfLine - (contentLengthIndex + 15)).Trim();
                                    if (int.TryParse(contentLengthValue, out contentLength))
                                    {
                                        XTrace.WriteLine($"检测到Content-Length: {contentLength}");
                                    }
                                }

                                // 检查Transfer-Encoding
                                isChunked = fullResponse.IndexOf("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase) >= 0;
                                if (isChunked)
                                {
                                    XTrace.WriteLine("检测到分块传输编码");
                                }
                            }

                            // 在每次成功接收数据后检查是否已完成
                            if (headerReceived)
                            {
                                string fullResponse = responseBuilder.ToString();
                                int headerEndIndex = fullResponse.IndexOf("\r\n\r\n") + 4;

                                // 对于分块传输编码
                                if (isChunked)
                                {
                                    string body = fullResponse.Substring(headerEndIndex);
                                    if (body.Contains("\r\n0\r\n\r\n") || body.EndsWith("0\r\n\r\n"))
                                    {
                                        XTrace.WriteLine("已接收完整内容(Chunked)");
                                        break;
                                    }
                                }
                                // 对于普通响应
                                else if (contentLength > 0)
                                {
                                    int bodyLength = fullResponse.Length - headerEndIndex;
                                    if (bodyLength >= contentLength)
                                    {
                                        XTrace.WriteLine("已接收完整内容(Content-Length)");
                                        break;
                                    }
                                }
                            }

                            // 如果数据量已经足够大，可以停止接收
                            if (totalBytesRead > 2 * 1024 * 1024) // 增加到2MB
                            {
                                XTrace.WriteLine("达到最大接收大小限制");
                                break;
                            }
                        }

                        if (totalBytesRead > 0)
                        {
                            string response = responseBuilder.ToString();
                            XTrace.WriteLine("\n收到响应:\n");

                            // 分离HTTP头和正文
                            int headerEndIndex = response.IndexOf("\r\n\r\n");
                            if (headerEndIndex > 0)
                            {
                                string headers = response.Substring(0, headerEndIndex);
                                string body = response.Substring(headerEndIndex + 4);

                                // 显示完整的HTTP头
                                XTrace.WriteLine(headers);

                                // 处理分块传输编码的正文
                                if (isChunked && body.Length > 0)
                                {
                                    // 尝试解码分块传输编码
                                    string decodedBody = DecodeChunkedBody(body);

                                    XTrace.WriteLine("\n正文内容 (前1000个字符):\n");
                                    XTrace.WriteLine(decodedBody.Length > 1000 ? decodedBody.Substring(0, 1000) + "..." : decodedBody);
                                    XTrace.WriteLine($"\n[总共接收: {totalBytesRead} 字节, 原始正文: {body.Length} 字节, 解码后: {decodedBody.Length} 字节]");

                                    // 检查是否接收完整
                                    bool isComplete = body.Contains("\r\n0\r\n\r\n") || body.EndsWith("0\r\n\r\n");
                                    XTrace.WriteLine(isComplete ? "响应已完整接收" : "响应可能未完整接收");
                                }
                                // 处理普通正文
                                else if (body.Length > 0)
                                {
                                    XTrace.WriteLine("\n正文内容 (前1000个字符):\n");
                                    XTrace.WriteLine(body.Length > 1000 ? body.Substring(0, 1000) + "..." : body);
                                    XTrace.WriteLine($"\n[总共接收: {totalBytesRead} 字节, 正文: {body.Length} 字节]");

                                    // 检查是否接收完整
                                    bool isComplete = contentLength > 0 && body.Length >= contentLength;
                                    XTrace.WriteLine(isComplete ? "响应已完整接收" : "响应可能未完整接收");
                                }
                                else
                                {
                                    XTrace.WriteLine("\n[无正文内容]");
                                }
                            }
                            else
                            {
                                // 无法分离头和正文，显示部分响应
                                XTrace.WriteLine(response.Length > 1000 ? response.Substring(0, 1000) + "..." : response);
                                XTrace.WriteLine($"\n[总共接收: {totalBytesRead} 字节]");
                            }
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
                    // 等待一小段时间，确保所有数据都已接收
                    if (isChunked)
                    {
                        XTrace.WriteLine("\n等待所有分块数据接收完成...");
                        await Task.Delay(1000); // 等待1秒，给服务器更多时间发送数据
                    }

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
