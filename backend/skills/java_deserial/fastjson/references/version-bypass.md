# Fastjson 版本绕过矩阵

| 版本范围 | autoType 限制 | 绕过方式 |
|----------|-------------|---------|
| <= 1.2.24 | 无限制 | 直接 @type 任意类 |
| 1.2.25 ~ 1.2.41 | 黑名单 | `L;` + `;` 前缀/后缀绕过 |
| 1.2.42 ~ 1.2.47 | 修复 L; | `java.lang.Class` 缓存绕过 (1.2.47 bypass) |
| 1.2.48 ~ 1.2.67 | 修复缓存 | 需新 gadget: BasicDataSource, HikariCP 等 |
| 1.2.68 ~ 1.2.80 | safeMode + expectClass | 需开启 autoType + 白名单类 |
| >= 1.2.83 | 默认关闭 | 基本安全 |

## 探测版本技巧

1. 发送 `{"@type":"java.lang.AutoCloseable"}` → 报错信息推断版本
2. 发 1.2.47 bypass payload → 观察是否被拦截
3. DNS/JNDI 外带 → 确认 autoType 实际可用
