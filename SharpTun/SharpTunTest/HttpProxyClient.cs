using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SharpTunTest
{
    /// <summary>
    /// 简单的HTTP代理客户端实现，用于测试
    /// </summary>
    public class HttpProxyClient
    {
        private readonly string _proxyHost;
        private readonly int _proxyPort;
        private readonly string? _username;
        private readonly string? _password;
        private readonly bool _isHttps;

        /// <summary>
        /// 创建一个新的HTTP代理客户端
        /// </summary>
        /// <param name="proxyHost">HTTP代理服务器地址</param>
        /// <param name="proxyPort">HTTP代理服务器端口</param>
        /// <param name="isHttps">是否是HTTPS代理</param>
        /// <param name="username">用户名（可选）</param>
        /// <param name="password">密码（可选）</param>
        public HttpProxyClient(string proxyHost, int proxyPort, bool isHttps = false, string? username = null, string? password = null)
        {
            _proxyHost = proxyHost;
            _proxyPort = proxyPort;
            _isHttps = isHttps;
            _username = username;
            _password = password;
        }

        /// <summary>
        /// 通过HTTP代理创建一个TCP连接
        /// </summary>
        /// <param name="destinationHost">目标主机</param>
        /// <param name="destinationPort">目标端口</param>
        /// <returns>已连接的Socket</returns>
        public Socket CreateConnection(string destinationHost, int destinationPort)
        {
            // 连接到HTTP代理服务器
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(_proxyHost, _proxyPort);

            // 构建HTTP CONNECT请求
            StringBuilder connectRequest = new StringBuilder();
            connectRequest.AppendLine($"CONNECT {destinationHost}:{destinationPort} HTTP/1.1");
            connectRequest.AppendLine($"Host: {destinationHost}:{destinationPort}");
            connectRequest.AppendLine("Proxy-Connection: Keep-Alive");

            // 添加代理认证（如果需要）
            if (_username != null && _password != null)
            {
                string auth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_username}:{_password}"));
                connectRequest.AppendLine($"Proxy-Authorization: Basic {auth}");
            }

            // 添加空行表示HTTP头部结束
            connectRequest.AppendLine();

            // 发送CONNECT请求
            byte[] requestBytes = Encoding.ASCII.GetBytes(connectRequest.ToString());
            socket.Send(requestBytes);

            // 接收HTTP响应
            byte[] responseBuffer = new byte[8192];
            int bytesRead = socket.Receive(responseBuffer);
            string response = Encoding.ASCII.GetString(responseBuffer, 0, bytesRead);

            // 检查响应是否成功（HTTP 200 OK）
            if (!response.StartsWith("HTTP/1.1 200") && !response.StartsWith("HTTP/1.0 200"))
            {
                socket.Close();
                throw new Exception($"HTTP代理连接失败: {response.Split('\n')[0]}");
            }

            // 连接成功，返回socket
            return socket;
        }
    }
}
