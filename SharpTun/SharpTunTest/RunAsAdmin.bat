@echo off
echo SharpTunTest - SOCKS5 流量转发工具
echo ===================================
echo 正在以管理员身份启动程序...

:: 检查是否以管理员身份运行
net session >nul 2>&1
if %errorLevel% == 0 (
    echo 已获得管理员权限，正在启动程序...
) else (
    echo 需要管理员权限才能运行此程序。
    echo 请右键点击此批处理文件，选择"以管理员身份运行"。
    pause
    exit
)

:: 检查 wintun.dll 是否存在
if not exist "wintun.dll" (
    echo 警告: 未找到 wintun.dll 文件。
    echo 程序可能无法正常工作。请确保 wintun.dll 文件位于当前目录。
    echo.
    echo 是否仍要继续? (Y/N)
    set /p choice=
    if /i not "%choice%"=="Y" exit
)

:: 启动程序
echo 启动 SharpTunTest...
echo.
SharpTunTest.exe

:: 如果程序异常退出，提供手动清理选项
if %errorLevel% neq 0 (
    echo.
    echo 程序异常退出，错误代码: %errorLevel%
    echo 是否需要执行清理操作? (Y/N)
    set /p cleanup=
    
    if /i "%cleanup%"=="Y" (
        echo 正在清理路由...
        route delete 0.0.0.0 >nul 2>&1
        route delete 8.8.8.8 >nul 2>&1
        route delete 1.1.1.1 >nul 2>&1
        
        echo 正在重置网络适配器...
        netsh interface ip set address name="SharpTunTest" dhcp >nul 2>&1
        
        echo 清理完成。
    )
)

echo.
echo 程序已退出。
pause
