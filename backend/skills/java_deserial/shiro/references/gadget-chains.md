# Shiro Gadget Chain 选择指南

## ysoserial 可用 Chains（JDK 8）

| Chain | 依赖 | 适用场景 | JDK 兼容性 |
|-------|------|----------|------------|
| CommonsBeanutils1 | commons-beanutils:1.9.2 | 最通用，90%+ 的 Java 项目都包含 | JDK <= 8 |
| CommonsCollectionsK1 | commons-collections:3.1+ | 老项目常见 | JDK <= 8 |
| CommonsCollectionsK2 | commons-collections:4.0+ | 新项目常见 | JDK <= 8 |
| CommonsCollectionsK3 | commons-collections:3.1+ | 备选 | JDK <= 8 |
| CommonsCollectionsK4 | commons-collections:4.0+ | 备选 | JDK <= 8 |

## shiro_exploit.py 默认遍历顺序

1. CommonsBeanutils1（优先 — 依赖范围最广）
2. CommonsCollectionsK1
3. CommonsCollectionsK2
4. CommonsCollectionsK3
5. CommonsCollectionsK4

## su18 ysoserial 额外 Chains（回显检测用）

EX-TomcatEcho 在反序列化时注入回显机制，从当前线程获取 request/response 对象，
命令输出写入 HTTP 响应。不需要额外依赖。

```bash
# 使用方式
java -jar /opt/ysuserial.jar -g CommonsBeanutils1 -p 'command' -t EX-TomcatEcho
```
