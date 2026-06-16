# Hash Cracking Reference

> 来源: hashcat wiki, John the Ripper documentation, Hashcat 官方文档, IppSec 教程

## 方法论

密码破解遵循渐进增强策略：**识别 → 字典 → 规则 → 掩码 → 纯暴力**。每一步破解出的密码用于验证是否满足需求，未破解的再进入下一步。

### 破解流程

```
1. hashid / hash-identifier → 自动识别 hash 类型
2. john --wordlist=rockyou.txt (auto-detect) → 快速字典
3. hashcat -a 0 rockyou.txt (指定 mode) → GPU 加速字典
4. hashcat -a 0 rockyou.txt -r best64.rule → 规则变异
5. hashcat -a 3 ?l?l?l?l?l?l?l?l → mask 攻击
6. hashcat -a 3 ?a?a?a?a?a?a?a?a --increment → 增量 mask
```

## Hash 识别

### hashid

```bash
hashid -m '$6$salt$hash...'
# → SHA-512 Crypt (mode 1800)

hashid -m 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
# → NTLM (mode 1000)

hashid -m '$krb5tgs$23$*USER$DOMAIN$...'
# → Kerberos 5 TGS-REP etype 23 (mode 13100)
```

### hash-identifier

```bash
echo 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' | hash-identifier
# → LM + NTLM hash
```

### 手动识别特征

| Hash 类型 | 特征前缀 | 示例 |
|-----------|---------|------|
| NTLM | 32 十六进制字符 | `8846f7eaee8fb117ad06bdd830b7586c` |
| LM + NTLM | `LM:NTLM` (各 32 hex) | `aad3b435b51404ee...:8846f7eaee8fb...` |
| NetNTLMv1 | `USER::DOMAIN:HMAC:CHALLENGE:RESPONSE` | `john::ACME:1122334455667788:...` |
| NetNTLMv2 | `USER::DOMAIN:CHALLENGE:HMAC:BLOB` | `john::ACME:abc123:def456:ghi789` |
| Kerberos TGS | `$krb5tgs$23$*USER$DOMAIN$...` | `$krb5tgs$23$*svc_mssql$ACME.local$...` |
| Kerberos AS-REP | `$krb5asrep$23$USER@DOMAIN` | `$krb5asrep$23$john@ACME.LOCAL:...` |
| SHA512crypt ($6$) | `$6$salt$hash` | `$6$rounds=656000$salt$hash...` |
| MD5crypt ($1$) | `$1$salt$hash` | `$1$abc123$ABcdEFgHi...` |
| bcrypt ($2a$/$2b$) | `$2b$cost$salt+hash` | `$2b$12$salt...` |

---

## hashcat 使用指南

### 核心 Hash 模式映射

| 模式 (-m) | Hash 类型 | 来源 |
|-----------|-----------|------|
| 0 | MD5 | Web app password hash |
| 1000 | NTLM | SAM dump, secretsdump |
| 1100 | Domain Cached Credentials (DCC) | MSCache/mscash |
| 1400 | SHA-256 | Linux /etc/shadow (部分) |
| 1800 | SHA-512 Crypt ($6$) | Linux /etc/shadow |
| 2100 | Domain Cached Credentials 2 (DCC2) | MSCache v2 |
| 5500 | NetNTLMv1 | Responder, Inveigh |
| 5600 | NetNTLMv2 | Responder, Inveigh |
| 13100 | Kerberos 5 TGS-REP etype 23 | Kerberoast (GetUserSPNs) |
| 18200 | Kerberos 5 AS-REP etype 23 | ASREPRoast (GetNPUsers) |
| 3200 | bcrypt ($2b$, $2a$) | Web apps |
| 500 | MD5crypt ($1$) | 旧 Linux 系统 |

### 攻击模式

| 模式 (-a) | 名称 | 用途 |
|-----------|------|------|
| 0 | Wordlist (字典) | 对字典中每个词尝试 |
| 1 | Combination (组合) | 合并两个字典 |
| 3 | Mask (掩码) | 按字符集暴力猜测 |
| 6 | Wordlist + Mask (Hybrid) | 字典词 + 掩码追加 |
| 7 | Mask + Wordlist (Hybrid) | 掩码前缀 + 字典词 |

### 常用命令

```bash
# NTLM 字典攻击
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# NTLM 带规则
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# NTLM mask 攻击 (8 位数字)
hashcat -m 1000 -a 3 hashes.txt ?d?d?d?d?d?d?d?d

# NTLM mask 攻击 (8 位小写字母)
hashcat -m 1000 -a 3 hashes.txt ?l?l?l?l?l?l?l?l

# NTLM mask 攻击 (8 位大小写字母+数字)
hashcat -m 1000 -a 3 hashes.txt -1 ?l?u?d ?1?1?1?1?1?1?1?1

# NetNTLMv2 字典攻击 (模式 5600)
hashcat -m 5600 -a 0 netntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt

# Kerberos TGS 字典攻击 (模式 13100)
hashcat -m 13100 -a 0 kirbi_hashes.txt /usr/share/wordlists/rockyou.txt

# Kerberos TGS 带 OneRuleToRuleThemAll
hashcat -m 13100 -a 0 kirbi_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# SHA512crypt 字典攻击
hashcat -m 1800 -a 0 shadow_hashes.txt /usr/share/wordlists/rockyou.txt

# 显示已破解密码
hashcat -m 1000 --show hashes.txt

# GPU 基准测试
hashcat -b

# 恢复之前中断的会话
hashcat --session mysession --restore

# 强制使用 CPU (无 GPU)
hashcat -m 1000 -a 0 hashes.txt rockyou.txt --force -D 1
```

### Mask 字符集速查

| 占位符 | 匹配字符集 | 示例 |
|--------|-----------|------|
| ?l | abcdefghijklmnopqrstuvwxyz | ?l?l?l = "abc" |
| ?u | ABCDEFGHIJKLMNOPQRSTUVWXYZ | ?u?u = "AB" |
| ?d | 0123456789 | ?d?d?d?d = "1234" |
| ?s | !"#$%&'()*+,-./:;<=>?@[]^_`{|}~ | ?s = "!" |
| ?a | ?l?u?d?s | ?a = 任意可打印字符 |
| ?b | 0x00 - 0xff | 全字节范围 |
| ?h | 0123456789abcdef | 小写 hex |
| ?H | 0123456789ABCDEF | 大写 hex |

### 自定义字符集 (-1/-2/-3/-4)

```bash
# 定义字符集1 为 小写+数字
hashcat -m 1000 -a 3 hashes.txt -1 ?l?d ?1?1?1?1?1?1

# 密码策略: 大写开头 + 5-7位小写 + 1-2位数字
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?l?d?d --increment --increment-min 8
```

---

## John the Ripper 使用指南

### Hash 格式

| 格式 (--format) | Hash 类型 |
|-----------------|-----------|
| NT | NTLM |
| LM | LM hash |
| Raw-MD5 | MD5 |
| sha512crypt | SHA-512 Crypt ($6$) |
| sha256crypt | SHA-256 Crypt ($5$) |
| bcrypt | bcrypt ($2b$ / $2a$) |
| krb5tgs | Kerberos TGS-REP |
| krb5asrep | Kerberos AS-REP |
| netntlmv2 | NetNTLMv2 |
| Raw-SHA256 | SHA-256 |

### 常用命令

```bash
# 自动检测 hash 类型 (推荐)
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# 指定 NTLM 格式
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# 指定 SHA512crypt
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt shadow_hashes.txt

# 显示已破解密码
john --show hashes.txt
john --show --format=NT hashes.txt

# 应用规则
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes.txt

# 应用 specific 规则
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Single hashes.txt

# 增量模式 (纯暴力)
john --incremental hashes.txt

# 增量模式指定字符集
john --incremental=Digits hashes.txt

# 恢复中断的会话
john --restore

# 列出所有支持的格式
john --list=formats

# 查看 hash 统计
john --show --format=NT hashes.txt | wc -l
```

### John Rules

| 规则 | 描述 |
|------|------|
| --rules | 默认规则集 (wordlist mode rules) |
| --rules=Single | 单词变形规则 (基于 username/gecos) |
| --rules=Jumbo | 大型规则集 |
| --rules=NT | NTLM 专用规则 |
| --rules=KoreLogic | 专业级大规则集 |

### 自定义规则示例

在 `/etc/john/john.conf` 或 `~/.john/john.conf` 中：

```
[List.Rules:Custom]
# 追加数字
$[0-9]
# 首字母大写 + 追加 123
c $1 $2 $3
# 每词首字母大写
C
# 翻转
r
```

---

## 常用字典

| 字典 | 位置 | 大小 | 用途 |
|------|------|------|------|
| rockyou.txt | /usr/share/wordlists/rockyou.txt | 14M 密码 | 基础字典 |
| SecLists | /usr/share/seclists/Passwords/ | 多分类 | 专业字典集 |
| darkc0de | darkc0de.lst | 大型 | 综合破解 |
| CrackStation | crackstation-human-only.txt | 1.5GB | 全网排重 |

```bash
# 下载 SecLists
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# 常用 SecLists 路径
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
/usr/share/seclists/Passwords/Common-Credentials/100k-most-common.txt
/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

---

## AD Hash 破解实战

### NTLM → hashcat

```bash
# secretsdump 输出的格式:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::

# hashcat 需要仅提取 NTLM 部分 (第二个冒号后)
echo 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::' > ntlm_hashes.txt

hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### NetNTLMv2 → hashcat

```bash
# Responder 日志中的 NetNTLMv2 格式
# john::ACME:1122334455667788:abc123def456...:0101000000000000...

# 直接使用
hashcat -m 5600 -a 0 netntlmv2_hash.txt /usr/share/wordlists/rockyou.txt
```

### Kerberos TGS → hashcat

```bash
# GetUserSPNs 输出 hashcat 格式
impacket-GetUserSPNs -dc-ip 10.0.0.10 -request -outputfile kirbi_hashes.txt ACME.local/

# 直接破解
hashcat -m 13100 -a 0 kirbi_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 破解性能参考 (NTLM, 单 GPU)

| 显卡 | 速度 (MH/s) |
|------|-------------|
| RTX 4090 | ~300,000 MH/s |
| RTX 3090 | ~120,000 MH/s |
| RTX 3080 | ~90,000 MH/s |
| GTX 1080 | ~20,000 MH/s |
| CPU (i9-13900K) | ~2,000 MH/s |

> NTLM 每秒可尝试 3000 亿次 (RTX 4090)，8 位纯数字 (10^8) 约 0.0003 秒破解。8 位大小写+数字 (?1?1?1?1?1?1?1?1 with -1 ?l?u?d) 尝试空间 (62^8 = 218 万亿)，约 12 分钟。

---

## 参考来源

- hashcat wiki: https://hashcat.net/wiki/doku.php?id=example_hashes
- hashcat: https://github.com/hashcat/hashcat
- John the Ripper: https://github.com/openwall/john
- John 官方文档: https://www.openwall.com/john/doc/
- hashid: https://github.com/psypanda/hashID
- SecLists: https://github.com/danielmiessler/SecLists
- CrackStation: https://crackstation.net/
