using System.Collections.Concurrent;

namespace PekVpnProxy
{
    /// <summary>
    /// 用户认证管理器
    /// </summary>
    public class AuthenticationManager
    {
        private readonly ConcurrentDictionary<string, string> _users = new();
        private readonly bool _requireAuth;

        /// <summary>
        /// 初始化认证管理器
        /// </summary>
        /// <param name="requireAuth">是否要求认证</param>
        public AuthenticationManager(bool requireAuth = false)
        {
            _requireAuth = requireAuth;
        }

        /// <summary>
        /// 添加用户
        /// </summary>
        /// <param name="username">用户名</param>
        /// <param name="password">密码</param>
        /// <returns>添加成功返回true，否则返回false</returns>
        public bool AddUser(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                return false;

            return _users.TryAdd(username, password);
        }

        /// <summary>
        /// 移除用户
        /// </summary>
        /// <param name="username">用户名</param>
        /// <returns>移除成功返回true，否则返回false</returns>
        public bool RemoveUser(string username)
        {
            return _users.TryRemove(username, out _);
        }

        /// <summary>
        /// 验证用户
        /// </summary>
        /// <param name="username">用户名</param>
        /// <param name="password">密码</param>
        /// <returns>验证成功返回true，否则返回false</returns>
        public bool Authenticate(string username, string password)
        {
            // 如果不要求认证，直接返回true
            if (!_requireAuth)
                return true;

            // 如果要求认证但没有用户，返回false
            if (_users.IsEmpty)
                return false;

            // 验证用户名和密码
            return _users.TryGetValue(username, out string? storedPassword) && password == storedPassword;
        }

        /// <summary>
        /// 是否要求认证
        /// </summary>
        public bool RequireAuthentication => _requireAuth;

        /// <summary>
        /// 获取用户数量
        /// </summary>
        public int UserCount => _users.Count;
    }
}
