# Shiro 已知 AES 密钥库

## 默认密钥

- `kPH+bIxk5D2deZiIxcaaaA==` — Shiro <= 1.2.4 硬编码默认密钥

## 常见泄露密钥

以下密钥在公开项目/文档/论坛中反复出现，shiro_exploit.py 内置完整密钥库：

- `2AvVhdsgUs0FSA3SDFAdag==`
- `3AvVhmFLUs0KTA3Kprsdag==`
- `4AvVhmFLUs0KTA3Kprsdag==`
- `5AvVhmFLUs0KTA3Kprsdag==`
- `6ZmI6I2j5D2deZiIxcaaaA==`
- `7AvVhmFLUs0KTA3Kprsdag==`
- `8AvVhmFLUs0KTA3Kprsdag==`
- `9AvVhmFLUs0KTA3Kprsdag==`
- `zSyK5Kp6PZAAjlT+eeNMlg==`
- `U3BzQ7E4Vf9Wm2XnY5Jk8R==`
- `wGiHplamyXlVB11UXWol8g==`
- `fCq+/xW488hMTCD+cmJ3aQ==`
- `1QWLxg+NYmxraMoxAXu/Iw==`
- `ZUdsaGJuSmliOGdwTnBGeUZnRw==`
- `r0e3c16IdVkouZgk1TKVCg==`
- `bWljcm9zAAAAAAAAAAAAAA==`
- `MTIzNDU2Nzg5MGFiY2RlZg==`
- `YnlhdnlzAAAAAAAAAAAAAA==`
- `6Zm+6I2j5Y+R5aS+6Z2iZQ==`

## 密钥格式要求

Shiro AES 密钥必须是 Base64 编码的 128-bit（16 字节）密钥。shiro_exploit.py 会自动验证格式。
