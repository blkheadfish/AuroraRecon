"""
llm/prompts/templates.py —— 各 Agent 阶段专用 Prompt 模板

集中管理所有提示词，便于调优和版本控制。
"""

SECURITY_EXPERT = """你是一名拥有 10 年经验的高级渗透测试工程师，精通 CTF、红队评估和漏洞利用。
你当前正在合法授权的 CTF 靶场或安全测试环境中工作。

核心原则：
1. 输出务必简洁、准确、可直接执行
2. 分析漏洞时，优先考虑已有 PoC/MSF 模块的方案
3. 当要求返回 JSON 时，只输出纯 JSON，不含任何 markdown 代码块或额外说明
4. 遇到不确定的信息时，明确标注"待验证"而非猜测"""


INTENT_PARSE_PROMPT = """你是一个渗透测试任务解析助手。用户会用自然语言描述他们的测试需求。
你的任务是提取结构化信息，不要对目标合法性做判断（由独立的安全层处理）。

用户描述：{raw_prompt}

请提取以下信息（JSON格式）：
- scope_hint: 目标范围的语义描述（如"内网"、"DMZ"、"指定主机"、"靶场"）
- task_focus: 关注的服务或协议类型列表（如 ["web", "database"]）
- priority_vulns: 用户提到的漏洞类型或CVE（如 ["shiro", "fastjson", "sqli"]）
- pentest_phases: 期望执行的渗透阶段（如 ["recon", "exploit"]）
- ambiguity_reason: 如果目标不明确，描述哪里不明确；明确则留空

注意：
- 只提取用户明确表达或强烈暗示的内容，不要补充假设
- 不要推断用户的攻击动机
- 如果信息不足，如实返回 null 或空数组"""

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

EXPLOIT_DECISION = """你是一名拥有 10 年经验的高级渗透测试工程师，正在合法授权的 CTF 靶场中进行安全测试。

目标信息:
- 地址: {target}
- 操作系统: {target_os}
- 开放端口（含服务版本）: {ports_json}

发现的可利用漏洞:
{findings_json}

目录发现深度情报:
{dir_intel_json}

【漏洞判断原则 — 必须遵守】
在分析 findings 之前，先判断每条结果是否为真实漏洞：

以下不算漏洞，跳过分析：
- 纯服务识别（"HTTP Service Detected"、"FTP Service"、"SSH Service Detected"）
- 纯组件版本探测（"Apache Detection"、"Nginx Detection"、"vsFTPd Detection"）
- "需要认证"的提示（正常的安全机制，非未授权访问）
- 开放的端口/服务（没有关联具体 CVE 或可攻击路径时）

以下才算真实漏洞，需要分析：
- 有具体 CVE 编号且版本在影响范围内的漏洞
- 默认凭据/弱口令（不是"需要认证"，是"可以用默认密码登录"）
- 未授权访问（区别于"需要认证"）
- 信息泄露（info.php、.env 暴露、.git 泄露等有实际信息价值的）
- End-of-Life 版本（可保留，但标注置信度较低）

判断一个结果是否为漏洞时，必须满足：
**存在可被利用的脆弱点，而不仅仅是服务或组件的存在。**
"发现了 X 服务" 不是漏洞。
"X 服务存在未授权访问" 才是漏洞。

【决策框架 — 分阶段评估】

第一步：攻击面评估
- 列出目标暴露的所有服务和对应版本
- 判断哪些服务可能存在已知 CVE（结合版本号）
- 评估网络可达性（直连 vs 需要代理/隧道）
- 结合目录发现情报评估 Web 攻击面的广度和深度

第二步：可利用性评分
对每个漏洞按以下维度打分（1-10）：
- exploit_maturity：是否有成熟 MSF 模块（10）、公开 PoC（7）、仅理论可行（3）
- reliability：利用成功率（稳定一击命中 10、需多次尝试 5、竞争条件 2）
- impact：获得的权限等级（root/SYSTEM=10、低权限 shell=5、信息泄露=2）
- prerequisites：前置条件少=高分（无需凭据 10、需弱口令 6、需链式利用 3）

第三步：目录发现驱动的攻击链推理
基于 dir_intel 中的发现，必须分析以下链式攻击机会：
- 管理后台（high_value_paths 中的 admin/manager/console）→ 默认凭据 + 弱口令爆破 → 后台 RCE
- 备份文件（backup_files）→ 下载分析源码 → 找硬编码凭据/数据库密码 → 登录目标服务
- .git 泄露（git_exposed=true）→ 源码审计 → 找注入点/密钥/内部路径
- API 端点（api_endpoints）→ 未授权访问测试 + 参数注入 + 信息泄露
- 目录列表（dir_listings）→ 遍历找敏感文件 → 信息泄露链
- 上传接口（high_value_paths 中的 upload）→ WebShell 上传
- 带参数的动态页面（potential_entry_points）→ LFI/SQLi/CMDi 注入测试
将这些目录发现驱动的攻击链纳入 chain_opportunities，标注各环节的可行性。

第四步：利用顺序策略
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
      "description": "链式攻击描述（含目录发现驱动的攻击链）",
      "steps": ["步骤1", "步骤2", "步骤3"],
      "overall_probability": 0.5,
      "dir_intel_source": "触发该攻击链的目录发现证据"
    }}
  ]
}}

按综合优先级从高到低排序，每个漏洞都必须给出 confidence 和 fallback。"""

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


VULN_SCAN_STRATEGY = """你是一名拥有 10 年经验的高级渗透测试工程师，正在对目标进行漏洞扫描策略制定。

目标信息:
- 地址: {target}
- 操作系统: {target_os}
- 开放端口: {ports_json}

各 Web 端口的指纹识别结果（包含 whatweb、httpx、JSON 探测）:
{fingerprints_json}

目录发现结果（多工具聚合）:
{web_paths_json}

路径内容探测摘要（标题/关键字/技术线索）:
{path_contents_json}

【漏洞判断原则 — 必须遵守】

判断一个结果是否为漏洞时，必须满足：**存在可被利用的脆弱点，而不仅仅是服务或组件的存在**。

以下不算漏洞（不推荐扫描也不生成漏洞报告）：
- "发现了 HTTP 服务" → 不是漏洞，只是服务识别
- "Apache httpd 存在" → 不是漏洞，只是组件检测
- "FTP 服务开放" → 不是漏洞，只是端口信息
- "需要认证" → 正常安全机制，不是漏洞（除非是未授权访问）
- "Server 头暴露"、"X-Powered-By 暴露" → 信息收集，不是漏洞

以下才是真正需要关注和报告的：
- "Apache httpd 2.4.49 存在路径穿越 CVE-2021-41773" → 有具体可攻击漏洞
- "FTP 服务存在匿名登录" → 有未授权访问
- "管理后台使用默认密码 admin/admin" → 有可利用的脆弱点
- "info.php 可访问，暴露 PHP 配置" → 有信息泄露（但评分应低）

【分析框架 — 四层漏洞匹配】

1. 服务层漏洞（直接由服务版本确定）:
   - 从端口的 version 字段提取精确版本号
   - 匹配已知 CVE（如 Apache httpd 2.4.49 → CVE-2021-41773 路径穿越）
   - 仅在有精确版本号且匹配到具体 CVE 时才推荐 nuclei 标签
   - 对每个匹配输出: {{vuln_name, cve, why_match（版本范围）, verification_method}}

2. 框架/CMS 层漏洞（由指纹识别确定）:
   - whatweb/httpx 中的框架标识（Struts2、ThinkPHP、Spring Boot、WordPress 等）
   - JSON 探测结果中的反序列化标识（Fastjson、Jackson、Shiro RememberMe）
   - 针对每个框架推荐具体检测方案和 Nuclei 标签

3. 配置/默认凭据层:
   - 管理后台路径 + 默认密码组合（Tomcat Manager、phpMyAdmin 等）
   - 未授权访问端点（actuator、console、server-status 等）
   - 注意："需要认证"本身不是漏洞，只有使用弱口令/默认凭据时才是

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


VULN_ACTIVE_DISCOVERY = """你是一名拥有 10 年经验的高级渗透测试工程师。自动扫描工具的发现不足，需要你根据指纹信息主动分析和验证可能存在的漏洞。

目标: {target}
操作系统: {target_os}

各端口指纹信息:
{fingerprints_text}

目录发现结果（多工具聚合）:
{web_paths}

路径内容探测摘要:
{path_contents}

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



DIR_SCAN_STRATEGY = """你是一名拥有 10 年经验的高级渗透测试工程师，正在规划目标的目录发现策略。

目标 URL: {target_url}
技术栈指纹: {tech_hints}
Nmap 服务/版本信息: {service_info}
WAF 检测结果: {waf_status}
首页初始响应信息（Server头/Title等）: {initial_response}

基于以上信息，制定精准的目录发现策略。

【分析维度】
1. 技术栈判断: 目标最可能运行什么应用？(WordPress/Tomcat/Spring Boot/ThinkPHP/自定义PHP等)
   - 从 Server 头、指纹、端口服务版本综合推理
2. 字典选择: 根据技术栈选择最合适的扩展名组合
   - PHP 应用 → php,phtml,php5,inc
   - Java 应用 → jsp,jspx,do,action,xml
   - Python 应用 → py,html,json
   - .NET 应用 → asp,aspx,ashx,asmx,config
3. 优先探测路径: 你认为最可能存在且有价值的 10-20 个路径（基于技术栈推理，不是随便猜）
   - 每个路径必须说明推理依据
4. 递归重点: 哪些一级目录一旦发现就值得做深度递归？
5. 特殊检查: 哪些信息源检查优先级最高？

返回 JSON（不含代码块）:
{{
  "tech_assessment": "一句话技术栈判断和推理依据",
  "scan_profile": "aggressive / balanced / stealth",
  "priority_paths": [
    {{"path": "/manager/html", "reason": "Tomcat 管理后台，可能有默认凭据"}},
    {{"path": "/wp-login.php", "reason": "WordPress 登录页"}}
  ],
  "custom_wordlist_entries": ["应用特有的路径词，如 actuator、druid、nacos"],
  "extensions": "php,jsp,...（根据技术栈选择，逗号分隔）",
  "recursive_targets": ["/api/", "/admin/", "/backup/"],
  "skip_patterns": ["不值得扫的路径模式，如 /static/、/assets/"],
  "special_checks": [
    {{"type": "robots_txt", "priority": "high", "reason": "可能暴露隐藏路径"}},
    {{"type": "git_exposure", "priority": "high", "reason": "源码泄露"}},
    {{"type": "api_schema", "priority": "medium", "reason": "Swagger/OpenAPI"}}
  ]
}}

【约束】
- priority_paths 必须基于技术栈推理，不要列出与检测到的技术无关的路径
- extensions 必须和技术栈匹配，不要把所有扩展名都列上
- custom_wordlist_entries 只列和该技术栈直接相关的特有词"""


DIR_MID_SCAN_EVAL = """你是渗透测试专家，正在监控目录扫描进度并实时调整策略。

目标: {base_url}
当前工具 {tool_name} 刚完成（耗时 {elapsed:.1f}s）

本轮新发现路径（{new_count} 条）:
{new_paths_sample}

累计发现路径（{total_count} 条）:
{all_paths_summary}

已执行工具: {executed_tools}
剩余时间预算: ~{remaining_budget}s

已完成深扫的目录（{scanned_count} 条 — 禁止重复推荐）:
{scanned_paths_summary}

【决策要求 — 每项都要明确回答】

1. 高价值目录识别: 哪些发现的目录值得立即做递归深扫？
   (如发现 /backup/ 但内容未知，应该用 feroxbuster 递归扫)

2. 备份文件变体: 发现的源文件是否值得探测备份变体？
   (发现 /config.php → 探测 /config.php.bak, /.config.php.swp 等)

3. 路径模式推导: 从已发现路径中能推导出哪些新的扫描目标？
   (发现 /api/v1/users → 推导 /api/v2/, /api/v1/admin, /api/v1/login)

4. 策略调整建议:
   - 路径质量是否已足够好？可以提前结束节省时间
   - 方向是否完全错误需要换策略？
   - 后续工具是否需要调整扩展名？

返回 JSON（不含代码块）:
{{
  "assessment": "一句话当前进展评价",
  "deep_scan_targets": [
    {{"path": "/backup/", "reason": "可能包含数据库备份", "wordlist": "small"}}
  ],
  "backup_variant_checks": ["/config.php", "/database.yml"],
  "new_wordlist_entries": ["从路径模式推导的新条目"],
  "extension_adjustment": "jsp,jspx,do,action（如需调整，否则为 null）",
  "strategy_change": null,
  "interesting_findings": ["值得特别关注的发现及原因"],
  "dedupe_note": "一句话说明本轮 deep_scan_targets 与已扫目录的差异（确认没有重复推荐）"
}}

【重复推荐约束 — 硬性规则】
- deep_scan_targets 中任何 path 都不得出现在"已完成深扫的目录"列表里
- 若发现没有新的高价值目录可深扫，deep_scan_targets 返回空数组 [] 并在 dedupe_note 中注明
- 重复推荐已扫目录会被视为决策偏差，必须在 dedupe_note 中自我纠正

strategy_change 可选值: null（不变）/ "early_stop_quality_sufficient"（质量够了，提前结束）/ "switch_to_aggressive"（发现线索，加大力度）"""


DIR_DEEP_DIVE_PLAN = """你是渗透测试专家。目录扫描初始阶段已完成，需要你规划深度探测。

目标: {base_url}
已知技术栈: {tech_stack}

累计发现路径（{total_count} 条，按价值排序取前 50）:
{path_inventory}

目录列表检测结果:
{dirlist_summary}

已执行的特殊检查结果:
{special_checks_results}

【任务: 规划需要额外执行的深度探测】

1. 递归深扫: 哪些目录需要用完整字典做二次扫描？（当前只扫了根目录一层）
   - 只选择真正有价值的目录，不要超过 3 个
   - 必须说明每个目录的预期收益

2. 信息源解析:
   - robots.txt: 如果前面探测到 200，应解析其 Disallow 条目作为新扫描种子
   - sitemap.xml: 如果存在，应提取所有 URL
   - .git/HEAD: 如果存在，应该进一步提取 .git/config 获取仓库信息
   - 注意: 如果前面已检查过某项且返回 404，不要重复

3. API Schema 发现:
   - 是否值得探测 /swagger.json, /openapi.yaml, /api-docs, /.well-known/ ?
   - 只在有 API 端点迹象时才推荐

4. 重点关注:
   - 哪些已发现路径最可能导向可利用漏洞？
   - 是否有路径组合暗示攻击链？（如 /upload + /files → 上传后访问）

返回 JSON（不含代码块）:
{{
  "recursive_scans": [
    {{"base": "/api/", "wordlist": "raft-medium", "depth": 2, "reason": "发现API入口，需要枚举具体端点"}}
  ],
  "info_source_actions": [
    {{"type": "parse_robots", "path": "/robots.txt", "expected_value": "high"}},
    {{"type": "git_dump", "path": "/.git/", "expected_value": "critical"}}
  ],
  "api_schema_checks": ["/swagger.json", "/openapi.yaml"],
  "attack_chain_hints": [
    {{"paths": ["/upload.php", "/uploads/"], "chain": "上传WebShell → 访问执行", "confidence": "medium"}}
  ],
  "priority_summary": "一句话总结最有价值的深挖方向"
}}

【约束】
- recursive_scans 最多 3 个，必须有明确理由
- 不要推荐已经检查过且确认不存在（404）的路径
- 不要在没有 API 迹象时推荐 API schema 检查"""


PLAN_GENERATION_PROMPT = """你是一名拥有 10 年经验的高级渗透测试工程师，正在合法授权的 CTF 靶场或安全测试环境中工作。

用户描述了他们的渗透测试需求。你的任务是：根据用户意图，在**系统现有能力范围内**，生成一份完整的、可执行的渗透策略。

{user_prompt}


你只能从以下已注册工具中选择，不得使用或编造列表之外的工具：

{available_tools}

你只能从以下已注册 Skill 中选择，不得使用或编造列表之外的 Skill：

{available_skills}



根据用户提到的 CVE 编号或漏洞类型，推断目标技术栈特征，指导端口选择和扫描策略：

**Java 反序列化 / Java Web 应用**：
- Shiro (CVE-2016-4437 等) → Java Web 应用，常见端口: 80,443,8080,8443,9080,9443,8090,8009
- Weblogic (CVE-2017-10271 等) → Java EE 中间件，常见端口: 7001,7002
- JBoss (CVE-2017-7504 等) → Java EE 中间件，常见端口: 8080,9990,9999
- Tomcat → Java Servlet 容器，常见端口: 8080,8443,8009(AJP)
- Fastjson/Jackson → Java JSON 库，依附于任何 Java Web 应用，端口跟随父应用
- Log4j (Log4Shell) → Java 日志库，依附于 Java 应用，端口跟随父应用

**Web 框架 RCE**：
- Struts2 → Java MVC 框架，常见端口: 80,443,8080,8443
- ThinkPHP → PHP 框架，常见端口: 80,443,8080
- WordPress → PHP CMS，常见端口: 80,443

**通用漏洞类型**（需要更多侦察）：
- 弱口令/默认口令 → 需要 surface_enum 发现登录入口 + credential_bruteforce
- 未授权访问 → 端口明确时可跳过 vuln_scan，直接测试
- SQL 注入 → 需要 surface_enum 发现注入点 + sqlmap

**端口扫描策略指导**（在 recon 步骤的 command_hint 中体现）：
- 已知 Java Web 应用 → "-p 80,443,8080,8443,9080,9443,8090,7001,8009,8888 -Pn --open"
- 已知 PHP Web 应用 → "-p 80,443,8080,8888,9000 -Pn --open"
- 不明确技术栈 → 使用默认常用端口（nmap 会自动使用内置列表）

**阶段选择指导**：
- 用户明确给出 CVE 编号 + 目标 → 只需 recon + exploit 两个阶段，不需要 surface_enum/intel_harvest/vuln_scan
- 用户只说"渗透测试"或"全面扫描"无具体漏洞 → 需要完整阶段链（recon → surface_enum → vuln_scan → exploit）
- 用户提到"弱口令"或"默认密码" → 需要 surface_enum 发现登录入口
- 用户说"getshell"或"拿shell" → exploit 是必须的，但前置侦察阶段按上述规则判断

典型的渗透测试流程包含以下阶段，按顺序排列。根据用户意图**精准选择**合适的阶段，不需要的阶段不要包含：
- **recon**: 基础侦察（端口扫描、服务识别、指纹识别、子域名枚举）
- **surface_enum**: 攻击面枚举（目录爆破、路径发现、API 端点枚举）—— 仅当需要发现隐藏路径/文件时才包含
- **intel_harvest**: 情报收集（敏感文件提取、配置泄漏分析）—— 仅当发现泄漏端点或已知配置文件时包含
- **vuln_scan**: 漏洞扫描（自动化漏洞扫描、专项漏洞检测）—— 仅当不确定目标漏洞时包含
- **exploit**: 漏洞利用（针对确认的漏洞执行利用，获取初始访问权限）
- **post_exploit**: 后渗透（提权、横向移动、凭据收集、持久化）

**关键原则**：如果用户已经明确了具体漏洞（如 CVE 编号）和攻击方式，不需要 surface_enum、intel_harvest、vuln_scan，直接 recon → exploit 即可。只有当用户意图模糊（如"全面扫描"、"渗透测试"）时，才包含完整的枚举和扫描阶段。

- 每个步骤必须使用**上述列表中实际存在的工具或 Skill**，不得编造
- recon/vuln_scan 阶段使用 **tool**（工具），exploit/post_exploit 阶段使用 **skill**
- 每个步骤说明：为什么用这个工具/Skill（purpose）、大致的参数方向（command_hint）、预期能得到什么信息（expected_output）
- Skill 步骤需要说明触发条件（trigger_condition）和失败后的兜底策略（fallback）
- 步骤之间存在依赖关系时，在 purpose 中说明

如果用户需求中有些攻击方式或工具系统当前不支持：
- 在 unsupported_hints 中明确说明"当前不支持"，不要伪造为步骤
- 如果某个非关键工具缺失，可以在风险备注中提示用户

在 risk_notes 中列出需要用户关注的风险点：
- 可能触发 WAF/IDS 的步骤
- 可能影响目标服务稳定性的操作
- 需要用户确认的高风险操作


严格按以下 JSON 格式输出（不含 markdown 代码块）：

{{
  "target_understanding": "对用户描述的理解摘要，提炼出核心测试目标和关注点",
  "phases": [
    {{
      "phase": "recon",
      "description": "该阶段的目标概述",
      "steps": [
        {{
          "tool": "工具名（必须来自上述已注册工具列表）",
          "purpose": "为什么用这个工具，解决什么问题",
          "command_hint": "大致的命令参数方向（如 '-sV -p 1-1000 目标IP'）",
          "expected_output": "预期能得到什么信息，如何用于后续步骤"
        }}
      ]
    }},
    {{
      "phase": "vuln_scan",
      "description": "该阶段的目标概述",
      "steps": [
        {{
          "tool": "工具名（必须来自上述已注册工具列表）",
          "purpose": "为什么用这个工具",
          "command_hint": "大致的命令参数方向",
          "expected_output": "预期能得到什么信息",
          "depends_on": "依赖的 recon 阶段产出（可选）"
        }}
      ]
    }},
    {{
      "phase": "exploit",
      "description": "该阶段的目标概述",
      "steps": [
        {{
          "skill": "Skill名（必须来自上述已注册 Skill 列表）",
          "trigger_condition": "满足什么条件才执行此 Skill（如指纹匹配 fastjson、端口开放 8080 等）",
          "expected_impact": "成功后的影响（如获取 shell、拿到数据库权限等）",
          "fallback": "Skill 失败后的 LLM 兜底策略或替代方案"
        }}
      ]
    }},
    {{
      "phase": "post_exploit",
      "description": "该阶段的目标概述",
      "steps": [
        {{
          "skill": "Skill名（必须来自上述已注册 Skill 列表）",
          "trigger_condition": "满足什么条件才执行",
          "expected_impact": "预期的横向移动/提权效果",
          "fallback": "失败后的替代方案"
        }}
      ]
    }}
  ],
  "unsupported_hints": [
    "用户意图中当前系统无法覆盖的部分（如用户想要 WebSocket 注入但系统无此工具）"
  ],
  "risk_notes": [
    "需要用户关注的风险点"
  ]
}}

1. 所有 tool 名称必须百分之百来自上述"系统可用工具"列表
2. 所有 skill 名称必须百分之百来自上述"系统可用 Skill"列表
3. 如果用户的需求超出上述能力范围，在 unsupported_hints 中说明，不要在 steps 中填写不存在的工具或 Skill
4. 不要编造工具名或 Skill 名
5. 只输出纯 JSON，不含任何 markdown 代码块或额外说明"""


HYPOTHESIS_GENERATION = """你是一名拥有 10 年经验的高级渗透测试工程师。基于对目标的初步侦察结果，生成 2-3 个可验证的假设，指导后续定向探测。

目标: {target}
目标端口: {target_port}
已检测指纹: {tech_hints}
开放端口及服务: {ports_summary}
Nmap 扫描摘要: {nmap_snippet}

【假设生成框架】
每个假设必须包含：
1. 明确的断言（不是模糊描述）
2. 推理论据（基于什么证据做出的判断）
3. 可验证性（用什么方法可以证实/证伪）
4. 攻击面价值（如果假设正确，对渗透测试的推进作用）

假设类型（每个类型最多一个）：
- tech_stack: 目标运行的技术栈（如"目标为 WordPress 站点"）
- service_version: 特定服务版本推测（如"SSH 版本可能为 OpenSSH 7.4 存在用户名枚举"）
- hidden_resource: 推测存在某个未发现的资源（如"可能存在 /admin 管理后台"）
- vulnerability: 推测存在某类漏洞（如"基于 ThinkPHP 指纹，可能存在 TP5 RCE"）
- configuration: 推测存在配置类弱点（如"Redis 6379 端口可能未授权访问"）

返回 JSON（不含代码块）：
{{
  "hypotheses": [
    {{
      "hypothesis": "具体假设描述",
      "category": "tech_stack|service_version|hidden_resource|vulnerability|configuration",
      "reasoning": "基于什么证据做出此假设",
      "attack_value": "high|medium|low",
      "initial_confidence": 0.5,
      "verify_method": "用什么方法证实或证伪",
      "probe_targets": ["具体的探测路径或端点"]
    }}
  ]
}}

约束：
- 必须基于已有的侦察证据，不得凭空猜测
- 假设数量 2-3 个，宁缺毋滥
- initial_confidence 基于证据强度：强证据 0.7-0.8，弱证据 0.3-0.5
- 每个假设必须有明确的 verify_method 和 probe_targets"""


HYPOTHESIS_VERIFICATION = """你是一名拥有 10 年经验的高级渗透测试工程师。上一轮假设验证的探测结果已经返回，需要你判断每个假设是"证实"还是"证伪"还是"需要更多信息"。

目标: {target}
当前轮次: {round_num}/{max_rounds}

【当前活跃假设与证据历史】
{hypotheses_state}

【本轮探测结果】
{round_results}

【判断标准】
- confirmed: 证据明确支持假设，置信度提高至 >= 0.8
  - 例: 探测 /wp-login.php 返回 200 → 确认 WordPress
  - 例: curl 返回 header "Server: Apache/2.4.49" → 确认版本
- falsified: 证据明确否定假设
  - 例: 探测 /wp-login.php 返回 404 → 可能不是 WordPress
  - 例: 大量路径探测均 404 → 目标不是常见 CMS
- needs_more_info: 证据不充分，需要进一步探测
  - 例: /wp-admin 返回 403 → 可能是 WordPress 但被拦截
  - 例: 仅探测了一个端点不足以判断

【收敛条件】
- 达到收敛: 所有假设 status 均为 confirmed 或 falsified，停止循环
- 未收敛: 仍有 needs_more_info 的假设，继续下一轮
- 强制终止: 达到 max_rounds 或连续 2 轮置信度变化 < 0.1

对每个假设返回 assessment，并给出下一轮的建议探测动作。

返回 JSON（不含代码块）：
{{
  "converged": true,
  "converged_reason": "所有假设已确认或证伪 / 连续2轮无进展",
  "assessments": [
    {{
      "hypothesis_id": "hyp-001",
      "status": "confirmed|falsified|needs_more_info",
      "confidence": 0.85,
      "confidence_delta": 0.15,
      "evidence_summary": "基于哪些证据做出此判断",
      "next_probe": null
    }}
  ]
}}

约束：
- 每个假设都必须给出明确的 status 判断，不得模糊
- confidence 必须在 0.0-1.0 之间
- 连续两轮无进展时必须声明 converged=true 终止循环"""


FILE_INTEL_EXTRACT = """你是一名资深渗透测试工程师，正在分析从目标服务器上获取的文件内容。
你的任务是从文件中提取所有对渗透测试有价值的情报。

目标: {target}
文件路径: {file_path}
HTTP 状态码: {status_code}
文件内容（可能截断）:
---
{file_content}
---

【提取框架 -- 逐项检查，宁缺勿错】

1. 凭据类（credentials）:
   - 数据库连接字符串（JDBC URL、DSN、host/port/user/password）
   - 用户名/密码对（明文 or 哈希，需标注类型）
   - SSH 密钥、API Token、Bearer Token
   - .htpasswd / shadow 格式的密码哈希
   - 注意区分：示例配置(example/sample) vs 真实凭据（看上下文判断）

2. 密钥/密文类（secrets）:
   - AES/DES/Shiro 加密密钥（如 rememberMe cookie key）
   - JWT Secret、签名密钥
   - SSL 私钥（PEM 格式开头 -----BEGIN）
   - 加密盐值（salt）

3. 内部路径与网络信息（internal_info）:
   - 内网 IP 地址段（10.x / 172.16-31.x / 192.168.x）
   - 内部域名、主机名
   - 文件系统绝对路径（如 /var/www、/opt/tomcat、C:\\inetpub）
   - 数据库名、表名

4. 配置情报（config_intel）:
   - 框架版本号（如 Spring Boot 2.3.1、Fastjson 1.2.68）
   - 开启的调试模式（debug=true、FLASK_DEBUG）
   - 禁用的安全特性（CSRF disabled、validateRequest=false）
   - 中间件配置（Tomcat connector、Nginx upstream）

5. 攻击线索（attack_hints）:
   - 可利用的 URL 路径（管理后台、上传接口、API endpoint）
   - SQL 语句中暴露的表结构
   - 代码中的命令执行点（exec/system/popen/Runtime.exec）
   - 反序列化入口（ObjectInputStream、pickle.loads、unserialize）
   - 文件包含入口（include/require + 用户可控参数）

【严格约束】
- 只提取文件内容中实际存在的信息，绝不猜测或编造
- 对每条情报标注置信度: high / medium / low
- 示例/模板文件（含 example、sample、placeholder 字样）置信度降为 low
- 文件内容为空或无价值信息时返回空数组

返回 JSON（不含代码块）:
{{
  "file_type": "sql_dump / xml_config / properties / env / source_code / log / other",
  "risk_level": "critical / high / medium / low / none",
  "summary": "一句话概括此文件的安全价值",
  "credentials": [
    {{"type": "类型", "username": "", "password": "", "service": "关联服务", "context": "原文关键行", "confidence": "high/medium/low"}}
  ],
  "secrets": [
    {{"type": "类型", "value": "值", "algorithm": "算法", "context": "上下文", "confidence": "high/medium/low"}}
  ],
  "internal_info": [
    {{"type": "ip_address/hostname/file_path/db_name", "value": "值", "context": "上下文", "confidence": "high/medium/low"}}
  ],
  "config_intel": [
    {{"key": "配置项", "value": "值", "security_impact": "安全影响", "confidence": "high/medium/low"}}
  ],
  "attack_hints": [
    {{"hint": "线索描述", "action": "建议下一步", "confidence": "high/medium/low"}}
  ],
  "new_paths": ["从文件内容中发现的新 URL 路径"]
}}"""


REPORT_GENERATION = """你是一名拥有 10 年经验的高级渗透测试工程师。请基于以下完整证据链，生成一份结构化的渗透测试报告。

【目标信息】
- 目标: {target}
- 操作系统: {target_os}
- 工作模式: {workflow_mode}
- 最终权限: {privilege_level}

{evidence_chain}

【报告要求 — 五段式结构】

## 1. 执行摘要 (Executive Summary)
- 2-3句话总结本次测试的整体风险等级和关键发现
- 用非技术语言描述业务影响
- 包含关键数据: 漏洞数量、成功利用数、权限等级

## 2. 侦察与发现 (Discovery)
- 目标暴露的攻击面（端口、服务、指纹）
- 假设验证过程（recon_hypotheses 中已确认/证伪的假设）
- 关键发现：技术栈、版本信息、配置暴露

## 3. 漏洞验证 (Verification)
- 按严重等级分组列出确认的漏洞
- 对每个漏洞说明：检测方法、证据、是否可利用
- 标注误报可能性（false_positive_likelihood）
- 区分"已利用成功"和"待验证"

## 4. 攻击链与利用 (Exploitation)
- 从初始立足点到最终权限的完整链路
- 每一步使用的工具和技术
- 成功获取的凭据和资产
- 未成功的路径及原因

## 5. 影响与修复建议 (Impact & Remediation)
- 按优先级排列的修复 checklist（每个项目标注: 漏洞名称、严重等级、修复方法、验证步骤、优先级 P0-P3）
- P0: 立即修复（严重漏洞已成功利用）
- P1: 本周内修复（高危可被利用）
- P2: 本月内修复（中危）
- P3: 下次迭代修复（低危/信息）

返回 JSON（不含代码块）:
{{
  "executive_summary": "面向管理层的 2-3 句摘要",
  "discovery_narrative": "侦察发现部分的详细叙述 (Markdown)",
  "verification_narrative": "漏洞验证部分的详细叙述 (Markdown)",
  "exploitation_narrative": "攻击链部分的详细叙述 (Markdown)",
  "fix_checklist": [
    {{
      "name": "漏洞名称",
      "severity": "critical/high/medium/low",
      "fix_method": "具体修复步骤",
      "verification": "如何验证修复生效",
      "priority": "P0/P1/P2/P3",
      "notes": "补充说明"
    }}
  ],
  "overall_risk": "critical/high/medium/low",
  "key_recommendations": ["总建议1", "总建议2", "总建议3"]
}}

约束:
- 每个部分必须基于提供的证据链，不得凭空推测
- fix_checklist 至少包含 3 项，按优先级排列
- 已成功利用的漏洞（got_shell=true）优先级必须为 P0"""


PAGE_SOURCE_AUDIT = """你是一名资深渗透测试工程师，正在对目标 Web 页面进行源码审计。
你的任务是分析 HTML/JavaScript 源码，找出所有可能存在漏洞的用户输入点。

目标: {target}
页面 URL: {page_url}
HTTP 状态码: {status_code}
响应头摘要: {response_headers}
页面源码:
---
{page_source}
---

【审计框架 -- 逐层检查】

第一层：HTML 表单和链接分析
- <form> 标签：提取 action、method、所有 <input>/<select>/<textarea> 的 name 属性
- <a href="?param=value"> 链接：提取 URL 参数
- <iframe src="...">, <img src="...">：检查是否引用了可控路径
- HTML 注释中的调试信息、隐藏参数、TODO 标记

第二层：JavaScript 代码审计
- AJAX/fetch/XMLHttpRequest 调用：提取请求 URL 和参数
- window.location / document.location 操作
- eval()、innerHTML、document.write() 等危险 sink
- 硬编码的 API 端点、Token、密钥
- 前端路由定义（Vue Router、React Router）中的隐藏路径

第三层：漏洞模式匹配
对每个发现的参数，根据上下文推断最可能的漏洞类型：
- 参数名含 file/path/page/include/template/view/doc/folder/content -> 文件包含(LFI/RFI)
- 参数名含 id/user/name/search/query/sort/order/filter -> SQL 注入
- 参数名含 cmd/exec/command/run/ping/ip/host -> 命令注入
- 参数名含 url/redirect/next/return/goto/link -> SSRF/开放重定向
- 参数名含 template/tpl/layout -> SSTI
- 参数出现在 innerHTML/document.write/eval 中 -> XSS/DOM注入
- PHP代码中出现 include/require/include_once + $_GET/$_POST/$_REQUEST -> LFI（高置信度）
- PHP代码中出现 system/exec/passthru/popen/shell_exec + 用户输入 -> RCE（高置信度）

第四层：上下文线索
- Server 头 / X-Powered-By 头暗示的技术栈
- 页面中的框架指纹（PHP错误信息、Java stack trace、Python traceback）
- 源码注释中泄露的文件路径、数据库名、内部 API

【严格约束】
- 只报告源码中实际存在的参数和模式，不编造
- 对每个发现标注置信度：
  - high: 源码中明确看到 include($_GET['file']) 或类似直接危险模式
  - medium: 参数名强烈暗示漏洞（?file=, ?cmd=），但未看到后端代码
  - low: 仅基于参数名推测，需要进一步验证
- 如果页面是纯静态内容（无表单、无参数、无JS交互），返回空数组

返回 JSON（不含代码块）:
{{
  "page_type": "php_dynamic / jsp_dynamic / static_html / api_endpoint / admin_panel / login_form / error_page / other",
  "tech_stack": ["从源码中识别的技术（PHP/JSP/ASP/Node/Python等）"],
  "injectable_params": [
    {{
      "url": "完整的带参数 URL（如 http://target/info.php?file=）",
      "param_name": "参数名",
      "method": "GET / POST",
      "source": "发现来源（form_action / href_link / js_fetch / js_ajax / html_comment / code_pattern）",
      "vuln_type": "lfi / sqli / cmdi / ssrf / ssti / xss / open_redirect / rfi / unknown",
      "confidence": "high / medium / low",
      "evidence": "源码中的关键行（引用原文）",
      "verify_payload": "建议的验证 payload（如 ?file=../../../etc/passwd）"
    }}
  ],
  "hidden_paths": ["从 JS/HTML 中发现的新 URL 路径"],
  "leaked_info": [
    {{"type": "类型（api_key / internal_path / version / comment_leak）", "value": "值", "context": "上下文"}}
  ]
}}"""