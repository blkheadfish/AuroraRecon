---
name: tomcat-exploitation
description: Comprehensive Apache Tomcat exploitation covering Manager weak credentials with WAR deployment, PUT method JSP upload (CVE-2017-12615), and AJP Ghostcat file read (CVE-2020-1938).
skill_type: exploit
severity: critical
tags: [tomcat, java, webshell, war, cve, ajp, ghostcat]
---

# Apache Tomcat 综合利用

## Essential Principles

1. Tomcat Manager 弱口令: `manager/html` 默认凭据可部署 WAR 包实现 RCE
2. PUT 上传 (CVE-2017-12615): Windows 上 `PUT /file.jsp/` 可绕过只读限制写入 JSP webshell
3. AJP Ghostcat (CVE-2020-1938): AJP 协议 8009 端口可读取 WEB-INF/web.xml 等任意文件
4. HTTP 头部的 `Server: Apache Tomcat` 或 `Apache-Coyote` 可识别 Tomcat

## When to Use

- 响应头包含 Tomcat 特征
- 端口 8080/8443 开放，确认 Tomcat 服务
- AJP 端口 8009 开放时优先尝试 Ghostcat

## When NOT to Use

- Manager 受 IP 限制（RemoteAddrValve）无法访问
- Tomcat 版本最新且 DefaultServlet readonly=true（PUT 无效）
- AJP Connector 已删除或禁用

## Path Selection

| Condition | Path | Description |
|-----------|------|-------------|
| tomcat_confirmed + manager_exists | manager_weak_cred | 弱口令爆破 + WAR webshell 部署 |
| tomcat_confirmed | put_upload | PUT 方法上传 JSP (CVE-2017-12615) |
| tomcat_confirmed + ajp_open | ajp_ghostcat | AJP Ghostcat 文件读取 (CVE-2020-1938) |

## Quick Start

```bash
# 确认 Tomcat
curl -s -D - http://TARGET:8080/ | head

# Manager 探测
curl -s -o /dev/null -w "%{http_code}" http://TARGET:8080/manager/html

# PUT 上传
curl -X PUT http://TARGET:8080/shell.jsp/ -d '<%@page import="java.io.*"%>...'
```
