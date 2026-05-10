---
name: geoserver-propertyname-rce
description: Exploits GeoServer OGC Filter property name expression RCE (CVE-2024-36401). Injects exec() via WFS/OWS GetPropertyValue valueReference parameter for RCE. Supports both GET and POST XML methods.
skill_type: exploit
severity: critical
tags: [geoserver, wfs, ows, rce, java, cve-2024-36401]
cve: [CVE-2024-36401]
---

# GeoServer 属性名表达式 RCE (CVE-2024-36401)

## Essential Principles

1. GeoServer 在处理 OGC 过滤器时，使用 Apache Commons JXPath 库对 valueReference 参数进行 XPath 评估
2. 攻击者可以注入 `exec(java.lang.Runtime.getRuntime(), 'cmd')` 表达式实现 RCE
3. 利用条件：GeoServer <= 2.25.1 / <= 2.24.3 / <= 2.23.5
4. WFS 或 OWS 服务需启用（默认启用）
5. 需要知道至少一个有效的 typeNames（图层名）

## When to Use

- 指纹/证据包含 geoserver 或 GeoServer
- CVE-2024-36401 已匹配
- WFS/OWS 服务可用

## When NOT to Use

- GeoServer 已修补（>= 2.25.2 / 2.24.4 / 2.23.6）
- 无有效图层名且默认图层全部失败

## Path Selection

| 条件 | 路径 | 命令 |
|------|------|------|
| 已发现图层 | ows_rce -> rce_discovered_layer | 用发现的图层名执行 RCE |
| 图层发现失败 | ows_rce -> rce_default_layers | 遍历默认图层名（sf:archsites 等） |
| GET 被过滤 | post_xml_rce | POST XML 方式 RCE |

## Quick Start

```bash
# 发现图层
bash {skill_dir}/scripts/discover_layers.sh {ENDPOINT}

# RCE（已发现图层）
bash {skill_dir}/scripts/rce_discovered_layer.sh {ENDPOINT}

# RCE（默认图层）
bash {skill_dir}/scripts/rce_default_layers.sh {ENDPOINT}
```
