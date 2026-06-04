# Skill Script 开发规范 (SKILL_SCRIPT_SPEC)

version: "1.0"
status: Approved

---

## 一、输出格式

### 1.1 结构化输出 MUST 使用 NDJSON

所有探测/利用结果 **MUST** 以 NDJSON（每行一个 JSON 对象）输出到 stdout。
原有 grep 文本输出 **MAY** 保留作为 backward compat，但标记为 deprecated。

```bash
# 正确：NDJSON 结构化输出
echo '{"event":"lfi_param_found","payload":{"param":"file","depth":3,"style":"relative","confirmed":true}}'

# 仍然有效（deprecated）：纯文本 grep 输出
echo "LFI_FOUND:file:3:relative"
```

### 1.2 事件类型命名规范

`event` 字段 MUST 使用 `snake_case`，格式为 `<domain>_<action>`：

| 域 | event 示例 | 含义 |
|----|-----------|------|
| lfi | `lfi_param_found` | 发现 LFI 可注入参数 |
| lfi | `lfi_files_readable` | 确认哪些文件可读 |
| lfi | `lfi_wrapper_available` | 检测到 PHP wrapper 可用 |
| rfi | `rfi_param_found` | 发现 RFI 可注入参数 |
| credential | `credential_found` | 凭据已获取 |
| credential | `credentials_found` | 批量凭据获取 |
| rce | `rce_probe_result` | RCE 探测结果 |
| exploit | `exploit_progress` | 利用步骤进行中 |
| exploit | `exploit_success` | 利用成功 |
| exploit | `exploit_failure` | 利用失败 |

### 1.3 Payload 规范

- `payload` 字段 MUST 是字典（object）
- 值类型 MUST 是 JSON 原生类型：string, number, boolean, array, object, null
- 布尔值 MUST 使用 `true`/`false`（非 `"true"` 字符串）
- 文件内容过大时 MUST 使用 base64 编码到 `_b64` 后缀字段

```json
{
  "event": "lfi_files_readable",
  "payload": {
    "files": ["/etc/passwd", "/etc/shadow"],
    "shadow_readable": true,
    "ssh_key_found": false,
    "passwd_content_b64": "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA=="
  }
}
```

---

## 二、输入规范

### 2.1 环境变量优先

脚本 MUST 通过环境变量接收参数，而非依赖位置参数顺序：

```bash
# 引擎自动设置的环境变量（无需脚本声明）
SKILL_ENDPOINT     # 目标 URL
SKILL_TARGET_IP    # 目标 IP
SKILL_TARGET_PORT  # 目标端口
SKILL_LHOST        # 攻击机 IP
SKILL_DIR          # Skill 脚本所在目录
```

```bash
# 脚本中读取
ENDPOINT="${SKILL_ENDPOINT:-http://127.0.0.1:80}"
TARGET_IP="${SKILL_TARGET_IP:-127.0.0.1}"
```

### 2.2 上下文变量读取

探测阶段设置的变量通过同名环境变量传递给后续脚本：

```bash
# engine 将 ctx.variables 注入为环境变量
LFI_PARAM="${lfi_param:-page}"
LFI_DEPTH="${lfi_depth:-5}"
```

---

## 三、错误处理与退出码

### 3.1 退出码语义

| Exit Code | 含义 | 引擎行为 |
|-----------|------|---------|
| 0 | 成功（探测命中 / 利用成功） | 正常继续 |
| 1 | 探测未命中 / 利用失败（无害） | 正常继续，走 on_fail |
| 2 | 超时 | 记录后继续 |
| 3 | 工具缺失（如 john 未安装） | 记录后继续 |

### 3.2 输出分离

- **stdout** → 结构化 event 输出
- **stderr** → 调试信息、警告、错误原因

```bash
# 正确
echo '{"event":"lfi_param_found","payload":{...}}'   # stdout
echo "[WARN] curl timeout on layer 3" >&2             # stderr
```

### 3.3 错误信息 MUST 包含上下文

```bash
# 错误
echo "FAILED" >&2

# 正确
echo "[ERR] curl timeout (6s) on param=$param depth=$depth url=$url" >&2
```

---

## 四、工具依赖声明

### 4.1 头部注释声明

每个脚本顶部 MUST 声明必需工具：

```bash
#!/bin/bash
# required_tools: curl, python3, john, sshpass
# optional_tools: nmap, hydra
set -euo pipefail
```

### 4.2 引擎预检查

Engine 在 `_run_probe_command` 前检查 `required_tools` 可用性。
工具缺失时设置 `tool_missing_<name>=true` 变量并跳过执行。

---

## 五、脚本结构模板

```bash
#!/bin/bash
# required_tools: curl
# optional_tools: nmap
set -euo pipefail

# ── 输入 ──
ENDPOINT="${SKILL_ENDPOINT:-http://127.0.0.1:80}"
LFI_PARAM="${lfi_param:-}"

# ── 探测逻辑 ──
result=$(curl -s "$url" --max-time 6 2>/dev/null)
ec=$?

# ── NDJSON 结构化输出（新）──
if echo "$result" | grep -q "uid="; then
    echo "{\"event\":\"lfi_param_found\",\"payload\":{\"param\":\"$param\",\"depth\":3,\"style\":\"relative\",\"confirmed\":true}}"
else
    echo "{\"event\":\"lfi_param_found\",\"payload\":{\"confirmed\":false}}"
fi

# ── 文本输出（deprecated，保留向后兼容）──
echo "LFI_FOUND:$param:3:relative"

# ── 退出 ──
exit 0
```

---

## 六、迁移计划

### Phase 1: 新技能强制遵循规范（当前阶段）

- 所有新创建的 Skill 脚本 **MUST** 输出 NDJSON
- 新脚本 **SHOULD** 声明 `required_tools`

### Phase 2: A 级技能迁移

迁移这些影响面最大的技能：
- `lfi_rfi`（已完成）
- `shiro`
- `tomcat`
- `fastjson`
- `log_poisoning`

### Phase 3: B 级技能迁移

- `sql_injection`
- `xss_detection`
- `ssh_exploit`
- `mysql_exploit`

### Phase 4: C/D 级技能迁移

- 其余所有技能

### 迁移 checklist（每个技能）

- [ ] 所有探测脚本增加 NDJSON 行（同时保留文本输出）
- [ ] 所有利用脚本增加 `exploit_progress` / `exploit_success` / `exploit_failure` 事件
- [ ] 脚本头部增加 `required_tools` 注释
- [ ] 确认 `skill.yaml` 的 `parse_rules` 仍可工作（backward compat）
- [ ] 确认 `skill.yaml` 的 `selector` 能利用新的结构化变量
- [ ] 跑对应技能的单测
