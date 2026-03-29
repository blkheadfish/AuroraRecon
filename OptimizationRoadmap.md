# PentestAI v2 优化路线图

## 当前状态总览

| 状态 | 数量 | 靶场 |
|------|------|------|
| ✅ 已通过 | 7 | S2-045, S2-057, ThinkPHP-5.0.23, Fastjson-1.2.24, Fastjson-1.2.47, Flask-SSTI, Tomcat-CVE-2017-12615 |
| ❌ 已测试未通过 | 2 | Tomcat8 弱口令, Shiro CVE-2016-4437 |
| ⬜ 需要新 Skill | 5 | WebLogic, PHP-FPM, ActiveMQ, JBoss, GeoServer |
| ⬜ 未测试（有 Skill） | 1 | Django CVE-2022-34265 |
| ⬜ VulnHub 综合 | 5 | Tomato, Earth, Jangow, Phineas, Odin |

**通过率: 7/20 (35%)**

---

## 一、当前已知 Bug 和待修复项

### 1.1 Shiro CVE-2016-4437 利用失败（回调方案待验证）

**当前状态**: 已部署回调检测方案，等待测试结果

**失败历程和根因链条**:

| 尝试 | 方案 | 失败原因 |
|------|------|----------|
| 第 1 次 | deleteMe 判断 | CB1 反序列化抛异常但命令已执行，Shiro 仍设 deleteMe，所有组合都显示"密钥错误" |
| 第 2 次 | 延时盲注 sleep 3 | `Runtime.exec("sleep 3")` 非阻塞，Java 启动子进程后立即返回，HTTP 响应不延迟 |
| 第 3 次 | 容器内回调 | 监听器绑在容器 IP 172.18.0.3，目标无法访问 docker 内部网络 |
| 第 4 次（当前） | LHOST + docker -p 映射 | 已验证网络链路通，等待系统级测试 |

**如果回调方案仍失败的备选方案**:
- 方案 A: DNS 外带检测（用 `nslookup shiro-confirm.LHOST` 替代 HTTP 回调，不依赖端口映射）
- 方案 B: 改 shiro_exploit.py 脚本本身（用 JDK 8 + CB1 gadget，去掉 deleteMe 判断逻辑）
- 方案 C: 用 URLDNS gadget 做纯检测（不执行命令，只触发 DNS 查询，确认密钥后再用 CB1 执行命令）

### 1.2 Tomcat8 弱口令

**状态**: Skill 已更新（同时试 text + html 接口），未重新测试

**根因**: Vulhub 靶场给 `tomcat:tomcat` 配的是 `manager-gui` 角色，`/manager/text/list` 需要 `manager-script` 角色。旧 Skill 只试 text 接口。

**待做**: 重新测试。如果 html 接口返回 200，需要用 HTML 表单方式部署 WAR（multipart upload），而不是 text 接口的 `PUT /manager/text/deploy`。

### 1.3 Django CVE-2022-34265

**状态**: KB verification_command 的引号问题已修复（`%27` 替代单引号），未重新测试

**待做**: 重新测试。这个靶场是 SQL 注入类型，没有专门的 Django Skill，依赖 KB 检测 + LLM 兜底利用。可能需要写一个简单的 Django SQL 注入 Skill。

### 1.4 shiro_exploit.py 脚本（toolbox 内）

**状态**: 脚本仍然用 JDK 21 的 `java` 命令 + `--add-opens`，没改成 `/usr/lib/jvm/java-8/bin/java`

**待做**: 改一行 `java` → `/usr/lib/jvm/java-8/bin/java`，去掉 `JAVA_ADD_OPENS`，然后 `docker commit`

### 1.5 MSF RPC Client

**状态**: 所有 MSF 模块调用都报 `'bool' object is not subscriptable`

**根因**: `msf_client.py` 的响应解析逻辑有 bug，MSF RPC 返回 `False` 时当作 dict 访问

**影响**: MSF 通道完全不可用，所有利用都依赖 Skill 引擎

**待做**: 修复 `msf_client.py` 的响应处理（低优先级，Skill 引擎已能替代大部分 MSF 功能）

---

## 二、新 Skill 开发（5 个）

### 2.1 GeoServer CVE-2024-36401（复杂度: 低）

**漏洞原理**: OGC Filter 中的 XPath 表达式被作为代码执行，可通过 WFS/OWS 接口触发 RCE

**利用方式**: 一条 curl 直接打

```
curl "http://TARGET:8080/geoserver/ows?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'id')"
```

**Skill 结构**:
- 探测: 访问 `/geoserver/web/` 确认 GeoServer 存在
- 路径 1: OWS 接口 RCE（上述 curl）
- 路径 2: WFS 接口变体
- 路径 3: LLM 兜底

**预计工作量**: 30 分钟

### 2.2 PHP-FPM CVE-2019-11043（复杂度: 低）

**漏洞原理**: Nginx + PHP-FPM 配置下，特定 URL 路径处理导致缓冲区溢出，可写入 PHP 配置实现 RCE

**利用方式**: 用 `phuip-fpizdam` 工具或手工构造请求

**Skill 结构**:
- 探测: 检查 Nginx + PHP-FPM（响应头 `X-Powered-By: PHP`）
- 路径 1: phuip-fpizdam 自动化（如果 toolbox 有）
- 路径 2: 手工构造 `%0a` 路径覆盖 PHP_VALUE
- 路径 3: LLM 兜底

**toolbox 依赖**: 需要安装 `phuip-fpizdam`（Go 工具）或 Python PoC 脚本

**预计工作量**: 1 小时

### 2.3 ActiveMQ CVE-2022-41678（复杂度: 中）

**漏洞原理**: ActiveMQ Web Console 存在任意文件写入漏洞，可通过 Jolokia 或直接上传 JSP 获取 RCE

**利用方式**: 
1. 用默认凭据 `admin:admin` 登录 Web Console（端口 8161）
2. 通过 Jolokia JMX 接口执行 `org.apache.activemq:type=Broker` 的 `addConnector` 方法写 JSP
3. 或直接 PUT 上传 JSP 到 `/admin/` 目录

**Skill 结构**:
- 探测: 检查 8161 端口 ActiveMQ Web Console + 默认凭据
- 路径 1: Jolokia JMX 写文件
- 路径 2: ClassPathXmlApplicationContext 远程加载
- 路径 3: LLM 兜底

**注意**: 靶场默认端口是 8161（管理口）和 61616（AMQP），不是 8080

**预计工作量**: 1.5 小时

### 2.4 JBoss CVE-2017-7504（复杂度: 中）

**漏洞原理**: JBoss AS 4.x 的 JMXInvokerServlet 反序列化漏洞，未认证即可利用

**利用方式**: 
1. 向 `/invoker/JMXInvokerServlet` 发送 ysoserial 序列化 payload
2. 不需要 AES 加密（与 Shiro 不同），直接发二进制 payload

**Skill 结构**:
- 探测: 检查 `/invoker/JMXInvokerServlet` 是否可访问（返回非 404）
- 路径 1: JDK 8 + ysoserial CB1 直接发送（curl --data-binary）
- 路径 2: 其他 gadget chain 遍历
- 路径 3: LLM 兜底

**toolbox 依赖**: JDK 8 + ysoserial（已有）

**预计工作量**: 1 小时

### 2.5 WebLogic CVE-2023-21839（复杂度: 高）

**漏洞原理**: WebLogic T3/IIOP 协议反序列化漏洞，通过 JNDI 注入实现 RCE

**利用方式**: 
1. 需要专门的 PoC 工具（如 `CVE-2023-21839.py`）
2. 通过 T3 协议（端口 7001）发送恶意 JNDI 引用
3. 目标回连 LDAP/RMI 服务器获取恶意类

**Skill 结构**:
- 探测: 检查 7001 端口 WebLogic Console + T3 协议握手
- 路径 1: CVE-2023-21839 PoC 工具
- 路径 2: T3 协议手工 payload
- 路径 3: LLM 兜底

**toolbox 依赖**: 需要安装 CVE-2023-21839 PoC 工具

**预计工作量**: 2+ 小时

---

## 三、VulnAgent 识别准确率优化

### 3.1 已完成的改进

| 改进 | 描述 | 状态 |
|------|------|------|
| 技术栈层级分类 | APP_FRAMEWORKS > SECURITY > MIDDLEWARE > SERVERS | ✅ |
| HTML body 深度检测 | Struts2(.action 链接), Shiro(rememberMe), GeoServer, ActiveMQ | ✅ |
| KB 匹配过滤 | 有应用框架时跳过容器级弱口令 KB 条目 | ✅ |
| Finding 事后校验 | `_enrich_findings` 降级基础设施误判 | ✅ |
| 探针级成功标志 | `probe_specific_signs` 字典，每个探针有专属确认关键词 | ✅ |
| `_replace_target` 双端口修复 | 正则检测 `{TARGET}` 后是否紧跟 `:端口号` | ✅ |
| ExploitDecision 保留 high/critical | LLM 只能禁用 low/info 级别的漏洞 | ✅ |
| LLM prompt 层级指导 | 教 LLM 区分容器和应用框架 | ✅ |

### 3.2 待改进

| 改进 | 描述 | 优先级 |
|------|------|--------|
| Nuclei 模板覆盖 | 确认 toolbox 的 nuclei 模板是否包含 S2-057、Shiro 等 | 中 |
| 指纹识别超时 | whatweb -a 3 有时候很慢（30s），可以降到 -a 1 | 低 |
| 多端口支持 | ActiveMQ 有 8161（管理）和 61616（AMQP），需要扫描非标准端口 | 中 |
| KB 条目端口修复 | 多个 KB 条目的 `verification_command` 硬编码了错误端口（如 fastjson 写了 8090 但靶场用 8080） | 高 |

---

## 四、Skill 引擎架构优化

### 4.1 端口映射能力（已实现）

`ExploitStep` 新增 `publish_ports` 字段，executor 自动加 `-p` 映射。用于 Shiro 回调检测等需要目标反连的场景。

### 4.2 步骤间变量传递（待实现）

**现状**: Skill 步骤间无法传递数据。例如 Tomcat brute_manager 找到凭据后，deploy_war 步骤需要重新遍历一次凭据。

**方案**: 在 `SkillContext` 中增加 `step_outputs` 字典，每步执行后自动存储 stdout，下一步可以用 `{PREV_STDOUT}` 或 `{step_id.stdout}` 引用。

### 4.3 条件逻辑增强（待实现）

**现状**: `conditions` 只支持 AND 逻辑，所有条件都必须满足。

**方案**: 增加 `conditions_any`（OR 逻辑），任一条件满足即可执行路径。例如 Struts2 的 S2-045 路径只需要 `struts_confirmed=true` 或 `action_suffix_works=true` 任一即可。

### 4.4 Skill 链式执行（待实现）

**现状**: 一个 Finding 只能匹配一个 Skill。Shiro 靶场同时有 Shiro + Struts2 漏洞，但 ExploitAgent 按漏洞逐个匹配 Skill。

**方案**: 当一个 Skill 的所有路径都失败时，允许引擎为同一个 Finding 匹配下一个得分最高的 Skill。

---

## 五、KB 数据质量修复

### 5.1 verification_command 端口问题

多个 KB 条目硬编码了特定端口，但靶场可能用不同端口：

| KB 条目 | 硬编码端口 | 问题 |
|---------|-----------|------|
| `fastjson_1224` | `:8090` | 靶场可能用 8080 |
| `fastjson_1247` | `:8090` | 同上 |
| `activemq_cve2022_41678` | `:8161` | 管理口和数据口分离 |
| `geoserver_cve2024_36401` | `:8080` | 可能是其他端口 |

**修复方案**: verification_command 统一使用 `{TARGET}` 占位符，不硬编码端口。`_replace_target` 已能正确处理。

### 5.2 缺失的 KB 条目

以下靶场没有对应的 KB 条目，需要补充：

| 靶场 | 需要的 KB 条目 |
|------|---------------|
| PHP-FPM CVE-2019-11043 | ✅ 已有 `php_fpm_cve2019_11043.json` |
| WebLogic CVE-2023-21839 | ✅ 已有 `weblogic_cve2023_21839.json` |
| JBoss CVE-2017-7504 | ✅ 已有 `jboss_cve2017_7504.json` |

---

## 六、VulnHub 综合靶场策略

VulnHub 靶场不是单漏洞利用，而是完整渗透流程。需要 Orchestrator 的全链路能力：

### 6.1 靶场分析

| 靶场 | 难度 | 预期突破口 | 需要的能力 |
|------|------|-----------|-----------|
| Tomato | 中等 | 文件包含 / 信息泄露 → 提权 | LFI 检测、Linux 提权 |
| Earth | 困难 | 加密消息解密 → 命令注入 → 提权 | 密码学分析、命令注入 |
| Jangow | 困难 | Web RCE → 内核提权 | PHP 命令注入、内核漏洞利用 |
| Phineas | 中等 | 信息收集 → Web 漏洞 → 提权 | 目录爆破、Web 漏洞利用 |
| Odin | 中等 | WordPress 漏洞 → 提权 | WordPress 扫描、Linux 提权 |

### 6.2 系统能力缺口

| 能力 | 现状 | 需要做的 |
|------|------|---------|
| 目录爆破 | Gobuster 已集成 | 结果解析和自动化利用 |
| LFI/RFI 检测 | 无 | 需要新 Skill |
| 命令注入检测 | 无专门 Skill | 需要新 Skill |
| 提权检测 | PostExploitAgent 存在但不完善 | LinPEAS/LinEnum 集成 |
| WordPress 扫描 | Nuclei 有 WP 模板 | 可能需要 WPScan 集成 |
| 内核漏洞利用 | 无 | 需要 kernel exploit Skill |

### 6.3 建议顺序

1. 先确保所有 15 个 Vulhub 单漏洞靶场通过（目标: 12/15+）
2. 补齐 LFI、命令注入等通用 Skill
3. 增强 PostExploitAgent 的提权能力
4. 最后测试 VulnHub 综合靶场

---

## 七、优先级排序

### P0（立即做，阻塞测试进度）
1. ✅ 验证 Shiro 回调方案是否成功
2. 重测 Tomcat8 弱口令
3. 重测 Django CVE-2022-34265
4. 改 shiro_exploit.py 的 java 路径并 docker commit

### P1（本周完成，扩大覆盖面）
5. 写 GeoServer Skill（30 分钟）
6. 写 PHP-FPM Skill（1 小时）
7. 写 ActiveMQ Skill（1.5 小时）
8. 修复所有 KB 条目的端口硬编码问题

### P2（下周完成）
9. 写 JBoss Skill（1 小时）
10. 写 WebLogic Skill（2 小时）
11. 修复 MSF RPC Client
12. 实现步骤间变量传递

### P3（有时间再做）
13. VulnHub 综合靶场
14. LFI/命令注入 通用 Skill
15. PostExploitAgent 提权增强
16. Skill 链式执行

---

## 八、文件修改清单（当前会话累计）

### 框架代码
| 文件 | 修改内容 |
|------|---------|
| `backend/tools/executor.py` | `publish_ports` 参数支持 |
| `backend/skills/models.py` | `ExploitStep.publish_ports` 字段 |
| `backend/skills/engine.py` | 步骤执行时传 `publish_ports` |
| `backend/agents/vuln_agent.py` | 技术栈层级、HTML body 检测、KB 过滤、Finding 校验、`_replace_target` 修复、探针级成功标志 |
| `backend/agents/orchestrator.py` | ExploitDecision 保留 high/critical、PostExploitAgent task_id 修复 |
| `backend/llm/prompts/templates.py` | VULN_ACTIVE_DISCOVERY 技术栈层级指导 |
| `backend/llm/prompts/react_prompts.py` | JDK 8 路径硬编码、ysoserial 用法说明 |

### Skill YAML
| 文件 | 修改内容 |
|------|---------|
| `backend/skills/java_deserial/shiro.yaml` | v4: deleteMe→延时→回调检测，JDK 8 自动探测，`publish_ports` |
| `backend/skills/java_deserial/fastjson.yaml` | 去掉 `--gadget` 参数，修复 BCEL 假 payload |
| `backend/skills/web_rce/struts2.yaml` | S2-057 的 `-D -` 修复，探测增加 S2-057 OGNL 验证，match rules 扩充 |
| `backend/skills/web_rce/thinkphp.yaml` | 无改动 |
| `backend/skills/web_rce/flask_ssti.yaml` | 无改动 |
| `backend/skills/web_inject/sql_injection.yaml` | 无改动 |
| `backend/skills/server_misconfig/tomcat.yaml` | Manager text+html 双接口暴破，Struts2 检测 |
| `backend/skills/server_misconfig/nginx.yaml` | 无改动 |

### KB 数据
| 文件 | 修改内容 |
|------|---------|
| `backend/knowledge/kb_data/django_cve2022_34265.json` | 引号修复 `%27` |

### toolbox 镜像
| 修改 | 状态 |
|------|------|
| JDK 8 安装（Adoptium Temurin） | ✅ 已 commit |
| shiro_exploit.py java 路径 | ❌ 待修改 |