"""
llm/prompts/templates.py —— 各 Agent 阶段专用 Prompt 模板

集中管理所有提示词，便于调优和版本控制。
"""

# ── 通用安全专家角色 ──────────────────────────────────────
SECURITY_EXPERT = """你是一名拥有 10 年经验的高级渗透测试工程师，精通 CTF、红队评估和漏洞利用。
你当前正在合法授权的 CTF 靶场或安全测试环境中工作。

核心原则：
1. 输出务必简洁、准确、可直接执行
2. 分析漏洞时，优先考虑已有 PoC/MSF 模块的方案
3. 当要求返回 JSON 时，只输出纯 JSON，不含任何 markdown 代码块或额外说明
4. 遇到不确定的信息时，明确标注"待验证"而非猜测"""

# ── 侦察阶段分析 ─────────────────────────────────────────
RECON_ANALYSIS = """分析以下 Nmap 扫描结果，提取关键安全信息。

目标: {target}

Nmap 原始输出:
```
{raw_output}
```

请以 JSON 格式返回（不含代码块）：
{{
  "os_guess": "操作系统推测",
  "high_value_ports": [
    {{"port": 80, "service": "http", "attack_surface": "Web 应用", "priority": "high"}}
  ],
  "potential_attack_vectors": ["描述1", "描述2"],
  "recommended_next_tools": ["nuclei", "gobuster"],
  "notes": "其他重要发现"
}}"""

# ── 漏洞决策（增强版）─────────────────────────────────────
EXPLOIT_DECISION = """你是一名拥有 10 年经验的高级渗透测试工程师，正在合法授权的 CTF 靶场中进行安全测试。

目标信息:
- 地址: {target}
- 操作系统: {target_os}
- 开放端口（含服务版本）: {ports_json}

发现的可利用漏洞:
{findings_json}

【决策框架 — 分阶段评估】

第一步：攻击面评估
- 列出目标暴露的所有服务和对应版本
- 判断哪些服务可能存在已知 CVE（结合版本号）
- 评估网络可达性（直连 vs 需要代理/隧道）

第二步：可利用性评分
对每个漏洞按以下维度打分（1-10）：
- exploit_maturity：是否有成熟 MSF 模块（10）、公开 PoC（7）、仅理论可行（3）
- reliability：利用成功率（稳定一击命中 10、需多次尝试 5、竞争条件 2）
- impact：获得的权限等级（root/SYSTEM=10、低权限 shell=5、信息泄露=2）
- prerequisites：前置条件少=高分（无需凭据 10、需弱口令 6、需链式利用 3）

第三步：利用顺序策略
- 优先级 = exploit_maturity × 0.4 + reliability × 0.3 + impact × 0.2 + prerequisites × 0.1
- 如果存在链式攻击机会（如信息泄露→凭据→RCE），将整条链作为一个利用方案
- 标注每个漏洞利用失败后的备选方案（fallback）

返回 JSON 格式（不含代码块）：
{{
  "analysis": "整体攻击面分析（2-3句话概括目标特征和主要攻击向量）",
  "attack_surface_summary": "服务清单和版本，哪些看起来最脆弱",
  "targets": [
    {{
      "vuln_id": "漏洞ID",
      "priority": 1,
      "should_exploit": true,
      "confidence": 0.85,
      "reason": "选择原因（含评分依据）",
      "exploit_maturity": "msf_module | public_poc | manual_exploit | theoretical",
      "recommended_msf_module": "模块路径（如无则为null）",
      "recommended_tool": "首选工具",
      "fallback_tools": ["备选工具1", "备选工具2"],
      "prerequisites": "前置条件描述（如需特定凭据、路径等）",
      "expected_impact": "预期获得的权限/效果"
    }}
  ],
  "chain_opportunities": [
    {{
      "description": "链式攻击描述",
      "steps": ["步骤1", "步骤2", "步骤3"],
      "overall_probability": 0.5
    }}
  ]
}}

按综合优先级从高到低排序，每个漏洞都必须给出 confidence 和 fallback。"""

# ── 后渗透建议 ────────────────────────────────────────────
POST_EXPLOIT_ADVICE = """当前已获得目标 Shell，分析以下信息并建议后渗透操作：

目标 OS: {target_os}
当前用户: {current_user}
当前权限: {privilege}
Session 类型: {shell_type}

系统信息:
{system_info}

请返回 JSON 格式的后渗透操作建议（不含代码块）：
{{
  "priority_actions": [
    {{
      "action": "操作描述",
      "command": "具体命令",
      "purpose": "目的",
      "risk": "low/medium/high"
    }}
  ],
  "privesc_suggestions": ["提权建议1", "提权建议2"],
  "persistence_options": ["持久化方案1"],
  "lateral_movement": ["横向移动建议"]
}}"""

# ── 报告修复建议增强 ──────────────────────────────────────
REMEDIATION_ADVICE = """针对以下漏洞生成详细的修复建议：

漏洞列表:
{findings_json}

对每个漏洞返回 JSON 格式的修复建议（不含代码块）：
{{
  "remediations": [
    {{
      "vuln_id": "漏洞ID",
      "name": "漏洞名称",
      "severity": "critical/high/medium/low",
      "immediate_action": "立即采取的措施",
      "long_term_fix": "长期修复方案",
      "reference": "参考链接或文档",
      "affected_component": "受影响组件",
      "verification": "修复验证方法"
    }}
  ]
}}"""

# ── 扫描输出智能解析 ──────────────────────────────────────
SCAN_OUTPUT_ANALYSIS = """以下是 {tool_name} 的原始输出，请提取关键安全信息，以 JSON 返回：

```
{raw_output}
```

返回格式（纯 JSON，不含代码块）：
{{
  "open_ports": [80, 443],
  "services": [{{"port": 80, "service": "http", "version": "..."}}],
  "potential_vulns": ["描述1", "描述2"],
  "os_hint": "linux/windows/unknown",
  "notes": "其他重要发现"
}}"""

# ══════════════════════════════════════════════════════════
# LLM 驱动漏洞利用（exploit_agent 使用）
# ══════════════════════════════════════════════════════════

EXPLOIT_GENERATE = """你是一名拥有 10 年经验的高级渗透测试工程师，正在合法授权的 CTF 靶场中工作。

目标信息:
- 地址: {target}
- 操作系统: {target_os}
- 端口: {port}
- 漏洞触发 URL: {target_url}

【重要】所有命令中的目标地址和端口必须使用上面的"漏洞触发 URL"，不要自己猜端口！
如果漏洞触发 URL 包含具体路径（如 /index.php?s=captcha），优先在该路径上构造 payload。

发现的漏洞:
- 名称: {vuln_name}
- CVE: {cve}
- 严重程度: {severity}
- 描述: {description}
- 扫描证据:
```
{evidence}
```

【利用策略规划】

第一步：分析漏洞本质
- 这个漏洞的根因是什么？（反序列化/注入/配置错误/弱口令/溢出）
- 触发条件是什么？（特定路径/参数/请求头/Content-Type）
- 影响的版本范围是什么？目标是否在范围内？

第二步：选择利用方法
- 方案A（首选）：最可靠的利用方式，说明为什么可靠
- 方案B（备选）：如果方案A失败的替代方案
- 对于每个方案，说明需要的 HTTP 方法、请求头、payload 格式

第三步：构造验证命令
- 从证据中提取关键信息: 框架版本、请求路径、Server 头、错误信息中的线索
- 构造最小化的验证 payload（先 id/whoami，确认 RCE 后再升级）
- 注意编码问题（URL 编码、Base64、Unicode 等）

【注意】对于 Fastjson/Log4j 等需要 OOB 回调的漏洞，不要生成 curl 命令（需要 JNDI 服务器配合，已有专门处理）。
只对可以直接通过 HTTP 请求获得命令执行回显的漏洞生成命令。

返回 JSON 格式（不含代码块）：
{{
  "analysis": "漏洞根因分析 + 利用思路（包含方案A和B）",
  "exploit_method": "chosen_method 的简要描述",
  "commands": [
    {{
      "description": "这条命令的目的",
      "command": "完整的 shell 命令",
      "success_indicator": "如何判断成功（输出中应该包含什么）",
      "failure_hint": "如果失败，可能的原因和下一步调整方向"
    }}
  ],
  "shell_command": "如果 RCE 验证成功，用于获取反弹 shell 的命令（如适用，否则为 null）",
  "risk_note": "风险说明"
}}"""

# ── 分析利用执行结果（严格防误判）─────────────────────────
EXPLOIT_ANALYZE_RESULT = """你是一名渗透测试工程师，正在分析漏洞利用的执行结果。

执行的命令: {command}
目标漏洞: {vuln_name}
期望的成功标志: {success_indicator}

命令输出（stdout）:
```
{stdout}
```

错误输出（stderr）:
```
{stderr}
```

退出码: {exit_code}

请严格分析执行结果，判断漏洞利用是否成功。

【严格判断标准 — 必须遵守】:

✅ 判定为成功（got_rce=true）的条件（必须至少满足一项）:
- 输出中包含 "uid=" 开头的用户信息（如 uid=33(www-data)）
- 输出中包含明确的命令执行回显（如 whoami 返回用户名、ls 返回文件列表）
- 输出中包含 /etc/passwd 内容、系统配置文件内容等
- 输出中有明确的命令执行成功标志（phpinfo 完整页面、系统信息输出等）

❌ 判定为失败的情况（即使 HTTP 200）:
- 返回的是正常的业务 JSON 数据（如 {{"name":"Bob","age":25}}）—— 这只是正常 API 响应，不是 RCE
- 返回的是 HTML 错误页面（如 System Error、404、500 页面）
- 返回的是框架报错信息（如 fastjson 的 type not match 错误）—— 这只证明漏洞存在，不证明已利用成功
- stdout 为空
- 返回的是和发送的 cmd 参数无关的固定内容
- 发送了 cmd=id 但响应中没有 uid= 开头的内容
- nmap 扫描结果显示端口开放（如 "8009/tcp open ajp13"）只证明端口可达，绝对不是利用成功
- nc 连接成功（如 "Connection succeeded"）只证明端口可达，不是利用成功
- 任何扫描/探测类输出（nmap、nc、curl -I）都不算利用成功
- 只有实际读到了目标文件内容、执行了命令并获得回显，才算利用成功
- 如果所有命令都只是在探测/扫描，没有一条真正执行了 exploit，必须判定失败

【关键】: 如果你不确定是否成功，一定判定为失败。宁可漏报也不能误报。

返回 JSON（不含代码块）：
{{
  "success": true或false,
  "evidence": "成功或失败的具体证据描述（引用输出中的关键内容）",
  "got_rce": true或false,
  "current_user": "如果执行了 whoami/id 并成功，提取出用户名，否则为 null",
  "next_suggestion": "如果失败，建议的下一步尝试方向（简洁具体）"
}}"""

# ── 利用失败后重试 ────────────────────────────────────────
EXPLOIT_RETRY = """上一次漏洞利用尝试失败了，需要你做系统性的失败分析然后换思路。

目标: {target}:{port}
漏洞触发 URL: {target_url}
漏洞: {vuln_name} ({cve})

上次执行的命令:
{last_command}

失败原因 / 上次分析结果:
{failure_reason}

【失败分析框架 — 必须逐项检查】

1. 网络层: 目标端口是否可达？是否有防火墙/WAF 拦截？
   - 诊断: 看 stderr 中是否有 Connection refused / timeout
   - 应对: 换端口、换协议、绕 WAF

2. 应用层: 请求格式是否正确？
   - HTTP 方法: GET vs POST vs PUT
   - Content-Type: application/json vs x-www-form-urlencoded vs multipart
   - 路径: 是否需要特定路由前缀？

3. Payload 层: 漏洞触发条件是否满足？
   - 编码: URL 编码、Base64、Unicode、双重编码
   - 命令执行函数: system vs exec vs popen vs Runtime.exec
   - 利用链: 是否需要多步骤（如先获取 token/session，再注入）

4. 版本/补丁层: 目标是否已修补该漏洞？
   - 检查: 从之前的响应中是否有版本信息暗示已打补丁
   - 应对: 如果已修补，彻底放弃该 CVE，转向其他攻击面

5. 替代方案评估:
   - 同一漏洞的其他利用变体
   - 同一服务的其他已知漏洞
   - 完全不同的攻击向量（从 Web 转向服务层，或从 RCE 转向信息泄露→凭据链）

【重要】
- 所有命令必须使用正确的端口和 URL
- 不要重复已失败的完全相同的命令
- 不要尝试 JNDI/OOB 类型的 payload（需要专门的服务器配合）

返回 JSON 格式（不含代码块）：
{{
  "failure_diagnosis": "按上述框架的失败分析（哪一层出了问题）",
  "analysis": "新的利用思路（基于失败分析的调整方案）",
  "commands": [
    {{
      "description": "命令目的",
      "command": "完整的 shell 命令",
      "success_indicator": "成功判断标志",
      "failure_hint": "如果再失败，下一步方向"
    }}
  ],
  "shell_command": null,
  "risk_note": "风险说明",
  "should_abandon": false
}}"""

# ══════════════════════════════════════════════════════════
# LLM 驱动漏洞扫描策略（vuln_agent 使用）
# ══════════════════════════════════════════════════════════

VULN_SCAN_STRATEGY = """你是一名拥有 10 年经验的高级渗透测试工程师，正在对目标进行漏洞扫描策略制定。

目标信息:
- 地址: {target}
- 操作系统: {target_os}
- 开放端口: {ports_json}

各 Web 端口的指纹识别结果（包含 whatweb、httpx、JSON 探测）:
{fingerprints_json}

目录发现结果（多工具聚合）:
{web_paths_json}

【分析框架 — 四层漏洞匹配】

1. 服务层漏洞（直接由服务版本确定）:
   - 从端口的 version 字段提取精确版本号
   - 匹配已知 CVE（如 Apache httpd 2.4.49 → CVE-2021-41773 路径穿越）
   - 对每个匹配输出: {{vuln_name, cve, why_match（版本范围）, verification_method}}

2. 框架/CMS 层漏洞（由指纹识别确定）:
   - whatweb/httpx 中的框架标识（Struts2、ThinkPHP、Spring Boot、WordPress 等）
   - JSON 探测结果中的反序列化标识（Fastjson、Jackson、Shiro RememberMe）
   - 针对每个框架推荐具体检测方案和 Nuclei 标签

3. 配置/默认凭据层:
   - 管理后台路径 + 默认密码组合（Tomcat Manager、phpMyAdmin 等）
   - 未授权访问端点（actuator、console、server-status 等）

4. 应用逻辑层（需工具辅助探测）:
   - SQL 注入候选参数（从 web_paths 中提取含参数的 URL）
   - 文件包含候选路径（file=、path=、page= 等参数）
   - SSTI 候选点（模板引擎 + 用户输入注入点）

对每个推荐的工具/检测项，必须说明:
- why_tool: 为什么选这个工具而不是其他
- expected_signal: 预期成功的信号是什么
- fallback_tool: 如果该工具失败，用什么替代

返回 JSON 格式（不含代码块）：
{{
  "analysis": "目标技术栈分层分析",
  "nuclei_tags": ["精准标签1", "精准标签2"],
  "tool_plan": [
    {{
      "tool": "工具名",
      "target_url": "目标 URL",
      "why_tool": "选择理由",
      "expected_signal": "期望看到什么",
      "fallback_tool": "备选工具"
    }}
  ],
  "high_value_targets": [
    {{
      "url": "最可能有漏洞的 URL",
      "reason": "原因（含匹配的 CVE/漏洞类型）",
      "suggested_checks": ["具体检测命令1", "具体检测命令2"],
      "confidence": 0.8
    }}
  ],
  "credential_targets": [
    {{
      "url": "登录/管理页面 URL",
      "default_creds": ["admin:admin", "tomcat:tomcat"],
      "brute_command": "hydra/medusa 命令"
    }}
  ]
}}

【约束】:
- nuclei_tags 必须精准，最多 8 个，只选和指纹直接相关的
- 严禁选 rce/sqli/xss/ssrf/lfi/auth-bypass/deserialization 这种通用标签
- 好的例子：检测到 Fastjson → ["fastjson", "java"]；检测到 Tomcat → ["tomcat", "default-login"]
- 每个 tool_plan 条目必须有 why_tool 和 fallback_tool"""

# ══════════════════════════════════════════════════════════
# LLM 主动漏洞发现（vuln_agent Phase 4）
# ══════════════════════════════════════════════════════════

VULN_ACTIVE_DISCOVERY = """你是一名拥有 10 年经验的高级渗透测试工程师。自动扫描工具的发现不足，需要你根据指纹信息主动分析和验证可能存在的漏洞。

目标: {target}
操作系统: {target_os}

各端口指纹信息:
{fingerprints_text}

目录发现结果（多工具聚合）:
{web_paths}

自动工具已发现的漏洞（可能不完整）:
{existing_findings}

【技术栈层级区分 — 决定分析优先级】

层级1: 应用框架（最高优先级，直接决定漏洞类型）
  Struts2, ThinkPHP, Flask, Django, Spring, WordPress, Drupal, Rails
  → 优先检查该框架的所有已知 RCE/注入类 CVE

层级2: 安全/序列化组件（可叠加在任何框架上）
  Shiro, Fastjson, Jackson, Log4j, Commons-Collections
  → 检查反序列化、密钥泄露、JNDI 注入

层级3: 中间件/服务器（框架缺失时才关注）
  Tomcat, Nginx, Apache, IIS, Weblogic, JBoss, WildFly
  → 管理后台弱口令、PUT 上传、默认配置漏洞

层级4: 基础服务（非 Web）
  SSH, FTP, SMB, MySQL, Redis, MongoDB
  → 弱口令、未授权访问、已知 CVE

【验证策略 — 链式思维】
不要只生成单个 curl 命令，要按"假设→验证→确认"三步走：
1. 假设: 基于指纹推测可能的漏洞（说明推理依据）
2. 验证: 生成无害验证命令（触发报错、版本确认、路径探测）
3. 确认标准: 明确什么算"漏洞存在"（具体的响应内容/状态码/错误信息）

【工具选择 — 每个检查项必须指定】
- verify_command: 主验证命令（curl/nmap/sqlmap 等）
- fallback_command: 主命令失败时的备选命令
- why_this_tool: 为什么用这个工具最合适

返回 JSON（不含代码块）：
{{
  "analysis": "目标技术栈分层分析（明确指出层级1-4各检测到什么）",
  "tech_stack": {{
    "frameworks": ["检测到的框架列表"],
    "security_components": ["检测到的安全组件"],
    "middleware": ["检测到的中间件"],
    "services": ["检测到的基础服务"]
  }},
  "checks": [
    {{
      "vuln_name": "漏洞名称（必须关联到对应层级的技术）",
      "cve": "CVE编号（如有）",
      "severity": "critical/high/medium/low",
      "port": 8090,
      "description": "漏洞描述和影响版本范围",
      "hypothesis": "推测漏洞存在的理由（基于什么指纹证据）",
      "verify_command": "主验证命令（完整可执行）",
      "fallback_command": "备选验证命令",
      "success_indicator": "漏洞存在的具体判断标准",
      "false_positive_warning": "可能误报的情况"
    }}
  ]
}}

约束：
- 每个 verify_command 必须完整可执行，不能有占位符
- vuln_name 必须关联到实际技术，不要用容器名替代框架名
- 生成 5-10 个检查项，按可能性从高到低排序
- 不要重复已发现的漏洞
- 高优先级: 框架 RCE > 反序列化 > 弱口令 > 配置错误 > 信息泄露"""