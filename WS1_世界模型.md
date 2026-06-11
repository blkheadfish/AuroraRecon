# WS1 — 世界模型（枢纽）

> 服务目标：**(b) 攻击路径推理的地基 + (c) 多场景的接入面**。
> 依赖：WS0（评测回归网）。被依赖：WS2（读世界模型）、WS3（往世界模型写）、WS4（沉淀/回灌）。
> 公共约定 / 已确认事实见 `00_总览与公共约定.md`。

## 本工作流在主轴中的角色

这是整件事的枢纽。现在攻击图 `models.py:478` **只写、只在 `orchestrator.py:3280` 读一次（出报告）**（F3），等于把世界模型当摆设。WS1 干两件事：① 把攻击图升级成一个**结构化、可查询的世界模型**（节点/边语义丰富 + 查询 API）；② 让**所有阶段都往里写**（含现在只打日志的 AD/云枚举，F4）。WS1 只立「写入 + 可读接口」，真正的「读了之后怎么决策」是 WS2，真正的「各领域深度」是 WS3。

---

## 契约冻结清单（WS1 的核心交付物 + 验收标准 —— WS2/3/4 据此编码）

> **用法（先给后核）**：本清单**先于 WS1 开工存在**，是 WS1 必须实现的接口表面 + 扩展点，也是 WS1 的验收标准。消费侧的**名字现在锁定**（WS2/3/4 计划已在用）；标「★待定」的返回结构细节由 WS1 落地后填，填完即锁。**WS1 合并前做一次 reconcile**（用真实代码核对本清单、回填★），确认一致后**才对 WS2/3/4 解冻放行**。WS1 实现中若某接口实测不可行，**改本清单 + 在 PR 注明**，不得私自偏离。
>
> **核心原则：用「开放扩展点」而非「封闭枚举 / 集中 switch」，让 WS2/3/4 各加各的而不改同一处**——这是让并发安全的关键（直接消解 `taskLive.ts`/`DecisionTimeline.vue`/`AttackGraphView.vue`/`types.ts` 的冲突）。

### C1. 世界模型查询 API（`backend/agents/world_model.py`，只读）

```python
class WorldModelQuery:
    def __init__(self, graph: AttackGraph, state: PentestState) -> None: ...
    def exploitable_frontier(self) -> list[WMNode]: ...        # exploitable=True 且未 exploited 的 finding
    def unreached_high_value(self) -> list[WMNode]: ...         # objective/credential 类、入边为 0
    def pivot_candidates(self) -> list[WMNode]: ...             # 经已有 session 立足点可达的新 host
    def usable_credentials(self) -> list[WMNode]: ...           # validated 凭据 + 适用目标
    def paths_to_objective(self) -> list[WMPath]: ...           # 立足点→objective 候选路径 + 缺口
    def chains(self) -> list[WMChain]: ...                      # finding+credential 可组合的攻击链候选
    def rank_frontier(self) -> list[tuple[WMNode, float]]: ...  # WS2 用：对 frontier 评分排序

# PentestState 上的便捷访问：
def world_model(self) -> WorldModelQuery: ...                   # 惰性构造
```
- 返回类型 ★已锁定：`WMNode{id: str, type: str, label: str, attrs: dict[str, Any]}`；`WMPath{nodes: list[str], gaps: list[str]}`；`WMChain{start: str, via: str, target: str, score: float, reason: str}`。全部定义于 `backend/agents/world_model.py:17-40`。
- 所有查询**纯读、无副作用、可单测**；空图返回空、不报错；遇未知 type/relation 不崩。

### C2. 世界模型写入 API（`WorldModelWriter`，整合现有 `attach_*_to_graph`）

```python
class WorldModelWriter:
    def upsert_node(self, type: str, key: str, attrs: dict) -> str: ...                  # 返回 node id；幂等
    def add_edge(self, src_id: str, dst_id: str, relation: str, attrs: dict|None=None) -> None: ...
    def add_finding(self, finding) -> str: ...     # 高层封装：建 finding 节点 + vulnerable_to 边
    def add_credential(self, cred) -> str: ...
    def add_session(self, host, privilege, shell_type) -> str: ...
```
- 凡产生 host/service/finding/credential/session 的地方**一律走它**（WS3 写 AD/云也走它）；写入后发 `world_model_update` 事件（见 C6）。

### C3. PentestState 共享字段（WS2/3/4 会读/写，名字在此预登记防撞）

| 字段 | 类型 | 引入者 | 说明 |
|---|---|---|---|
| `attack_graph` | `AttackGraph`（增强，见 C4） | WS1 | 世界模型本体 |
| `authorized_scope` | `list[str]` | WS0 | CIDR/host 白名单 |
| `scope_violations` | `list[dict]` | WS0 | 越界审计 |
| `autonomy_level` | `Literal["manual","supervised","autonomous"]` | WS0 | 自治档位 |
| `failure_hypotheses` | `list[dict]` | WS2 | `{vuln_id,cause,suggested_next,round}` |
| `runtime_facts["prior_intel"]` | `dict` | WS4 | 历史先验（凭据无明文） |

> WS0/WS1 字段在 WS2/3/4 开工前已合并；WS2/WS4 自己引入的字段在各自分支加。

### C4. 攻击图节点/边 schema（开放词汇 + `attrs`）

- `AttackGraphNode` = `{id: str, type: str, label: str, attrs: dict}` —— **`type` 是开放字符串，不是封闭枚举**。
- `AttackGraphEdge` = `{src: str, dst: str, relation: str, attrs: dict}` —— `relation` 同样开放。
- **核心 type 集（WS1 定义）**：`host / service / web_endpoint / finding / credential / session / loot / objective / pivot_point`。
- **核心 relation 集（WS1 定义）**：`runs_on / exposes / vulnerable_to / yields / enables / pivots_to / leads_to / requires`。
- **扩展规则**：WS3 可新增 type（AD：`domain_user/domain_group/domain_computer/share/ticket/spn`；云：`cloud_identity/iam_role/cloud_credential/bucket/cloud_service`）与 relation（AD：`member_of/has_session_on/can_access/kerberoastable/admin_of/trusts`；云：`assumes/can_read/can_write/exposed_via`），**无需改 WS1 模型代码**；C1 查询遇未知 type/relation 必须优雅处理。
- 各 type 的 `attrs` 基本键 ★已锁定（定义于 `WorldModelWriter.add_*`，`backend/agents/world_model.py:262-330`）：finding→`{cve: str, severity: str, exploitable: bool, exploited: bool, tool: str}`；credential→`{service: str, username: str, has_secret: bool, validated: bool}`；session→`{host: str, privilege: str, shell_type: str}`；host→`{ip: str}`；service→`{port: int, service: str, version: str}`。

### C5. `decision_event` 的 `action` 名册（全 WS 预登记，防撞名）

新增 action（各 WS 只能用登记给自己的；新增须先在此登记）：

| action | 引入者 | action | 引入者 |
|---|---|---|---|
| `scope_violation` | WS0 | `chain_selected` | WS2 |
| `world_model_update` | WS1 | `reflection` | WS2 |
| `world_model_readout` | WS1 | `hypothesis_test` | WS2 |
| `target_selected` | WS2 | `objective_path` | WS2 |
| `scene_classified` | WS3 | `prior_intel_loaded` | WS4 |

- 新增 `checkpoint_type`：`irreversible_action`（WS0）、`scope_expand`（WS0/WS2，若启用）。
- 既有 action（`tool_start/tool_result/thought/checkpoint_request/checkpoint_resolved/llm_delta/operator_replan/command_exec/supervisor_route`）**不动**。

### C6. 攻击图事件格式（双通道，★已锁定）

**主通道** — 整图快照（`attack_graph` 协议 v2 顶层事件，来源 `backend/api/services/task_runner.py:69-88`）：

```json
{ "type": "attack_graph",
  "payload": { "nodes": [AttackGraphNode], "edges": [AttackGraphEdge] } }
```

**辅通道** — 增量 delta（`decision_event` action==`"world_model_update"`，前端 `worldGraph` 消费）：

```json
{ "action": "world_model_update",
  "payload": { "nodes_upserted": [{"id":"","type":"","label":"","attrs":{}}],
               "edges_upserted": [{"src":"","dst":"","relation":"","attrs":{}}],
               "nodes_removed": ["id"] } }
```

- 前端 `worldGraph`（`taskLive.ts`）同时消费二者：`attack_graph` 全量覆盖 → `_fullGraphToWorldGraph()`，`world_model_update` delta 增量 → `_applyWorldModelDelta()`。

### C7. 前端扩展点（★已锁定，与代码一致）

这是消解前端并发冲突的关键——WS1 把这些点建成「注册表」，下游 WS 往注册表加东西，不碰主体：

1. **`stores/taskLive.ts` — `registerDecisionHandler(action, handler)`**（`frontend/src/stores/taskLive.ts:103`）：`_decisionHandlers: Map<string, DecisionHandler>` + `export function registerDecisionHandler(...)`。`applyEvent` 对 `decision_event` 按 `action` 查表分发（`:739`）。WS2/3/4 各自 `registerDecisionHandler('target_selected', …)`，**不改 `applyEvent` 本体**。现有 `llm_delta/tool_stream/checkpoint_*` 已迁移为注册 handler。

2. **`components/DecisionTimeline.vue` — `decisionRenderers`**（`:78`附近）：`Record<action, Component>` 映射。模板用 `<component :is="rendererFor(item.action)">` 查表渲染。WS2/3/4 注册自己的渲染组件，不改主体。现有 `thought` action 已迁移为 `DecisionThoughtRenderer` 组件。

3. **`components/AttackGraphView.vue` — `NODE_TYPE_META`**（`:234`）：节点类型样式映射。`DEFAULT_NODE_STYLE` 为未知 type 兜底。WS3 往映射加 AD/云类型样式，不改渲染主体。

4. **`stores/taskLive.ts` — `worldGraph`**（`TaskLiveState:90`）：`{ nodes: Record<string, WMNode>, edges: WMEdge[] }`。消费 `attack_graph` 全量覆盖 + `world_model_update` delta 增量。WS2/3/4 **只读**它。

5. **`types/task.ts`**：`WMNode/WMEdge/WorldModelUpdatePayload`（`:90-107`）基类型 + `DecisionAction`（`:108-121`）可扩展联合。各 WS **只追加**自己的 payload 类型。

> 验收硬指标：WS1 合并后，「新增一个 decision_event action 并在前端渲染」这件事，能在**不修改** `applyEvent` / `DecisionTimeline.vue` / `AttackGraphView.vue` 主体的前提下，仅靠注册完成。WS1 自带一个 demo action 证明该扩展点可用。

---

## [W1-T1] 攻击图升级为可查询世界模型 + 查询 API（须满足契约 C1/C2/C4）

**为什么**：现 `AttackGraph` 只是节点/边容器，无任何面向决策的查询；要成为决策基底必须先有结构化语义 + 查询核。

- **① 底层引擎**（本任务重心）：`agents/models.py` 的 `AttackGraphNode/AttackGraphEdge/AttackGraph`（:459-565）增强：
  - 节点类型补齐并标准化：`host / service / web_endpoint / finding / credential / session / loot / objective / pivot_point`，每类带结构化属性（如 finding 带 `cve/severity/exploitable/exploited`，credential 带 `service/username/has_secret/validated`，session 带 `host/privilege/shell_type`）。
  - 边关系标准化：`runs_on / exposes / vulnerable_to / yields / enables / pivots_to / leads_to / requires`。
  - 新增**查询 API**（新文件 `backend/agents/world_model.py`，作为 `attack_graph` 的只读门面，不复制状态）：
    ```python
    class WorldModelQuery:
        def __init__(self, graph: AttackGraph, state: PentestState): ...
        def exploitable_frontier(self) -> list[Node]        # exploitable=True 且未 exploited 的 finding
        def unreached_high_value(self) -> list[Node]         # objective/credential 类、入边为0(未触达)
        def pivot_candidates(self) -> list[Node]             # 有 session 立足点可达的新 host
        def usable_credentials(self) -> list[Node]           # validated 凭据 + 适用目标
        def paths_to_objective(self) -> list[Path]           # 当前已知边上，从立足点到 objective 的路径
        def chains(self) -> list[Chain]                       # finding+credential 可组合的攻击链候选
    ```
  - 查询纯读、无副作用、可单测。
- **② 后端**：`world_model.py` 的图算法（路径/可达）用轻量内置实现（BFS/拓扑），不引重依赖。
- **③ 智能体层**：无（本任务只建模型与查询，接入在 W1-T4）。
- **④ API**：无。
- **⑤ DB**：节点/边新增属性随 `attack_graph` 序列化进 `state_json`，注意向后兼容（旧 state 反序列化不报错——属性给默认值）。
- **⑥ 前端**：`types/task.ts` 的 `AttackGraphNode/Edge`（:68-87）同步扩展类型（新节点类型 + 属性 + 边关系），**仅类型，不改渲染**（渲染在 W1-T3）。
- **⑦ 测试**：`test_world_model_query.py`：构造含 finding/credential/objective 的图，断言 `exploitable_frontier/unreached_high_value/paths_to_objective/chains` 返回正确；空图返回空、不报错。

**验收**：查询 API 全测试绿；旧 `state_json` 能无损反序列化（补一条兼容测试）。
**scope guard**：查询只读无副作用；不改 `attach_*_to_graph` 写入语义（W1-T2 才动写入）。
**依赖**：WS0（W0-T1 harness 作回归网）。

---

## [W1-T2] 所有阶段写入世界模型（补全写入面）

**为什么**：F3/F4——世界模型写不全，AD/云枚举只打日志。决策要可信，世界模型必须是「所有阶段发现的并集」。

- **① 底层引擎**：统一写入入口——把 `fact_hooks.py` 的 `attach_host_to_graph/attach_service_to_graph/attach_finding_to_graph/attach_credential_to_graph`（:1058-1121）整理成一个 `WorldModelWriter`，保证「凡产生 finding/host/cred/session 的地方都走它」，并在写入时同步建立边（如 finding `vulnerable_to` service、cred `yields` session）。
- **② 后端**：为现在不进图的来源补 parser + 写入：
  - AD/内网枚举（`smb_enum/ldap_enum/kerberos_attack`）：新增 `tools/parsers/{netexec,ldapsearch,getnpusers}_parser.py`（复用 `nmap_parser.py` 风格），把输出结构化为 host/service/credential/finding。
  - 云枚举（`cloud_enum/cloud_exploit`）：新增 `tools/parsers/imds_parser.py`，把 IMDS/IAM/S3 结构化为 finding/credential。
  - （注：这里只做「输出→结构化事实→写入世界模型」；调用真正的 network skills 做纵深在 WS3。）
- **③ 智能体层**：`orchestrator.py` 的 5 个 stub 节点（:3083-3167）：执行后把输出送 parser → `WorldModelWriter` 写入 findings/credential_store/attack_graph，**并触发现有 replan 信号**（自然进入 fact diff）。其余已写入图的节点（recon/vuln/exploit/post）核对补齐边关系。
- **④ API**：无（findings/attack_graph 已在 task detail payload）。
- **⑤ DB**：随 state 落盘。
- **⑥ 前端**：无需新组件——`FindingsPanel.vue`/`AttackGraphView.vue` 自动展示新增 finding/节点（渲染增强在 W1-T3）。
- **⑦ 测试**：`test_world_model_writes.py`：对授权 SMB 靶（私网）+ 本地 mock IMDS 端点，5 个原 stub 节点产出结构化 finding/cred 并进攻击图（而非仅日志）；边关系正确建立。

**验收**：原 5 个 stub 节点输出进世界模型；attack_graph 节点/边数随各阶段增长；harness 不退化。
**scope guard**：受 W0-T2 scope 约束；**不新增攻击手法**，只做「解析+结构化+写入”。
**依赖**：W1-T1。

---

## [W1-T3] 世界模型实时渲染 + 持久化快照（须满足契约 C6/C7：world_model_update 格式 + 前端注册扩展点）

**为什么**：世界模型成为中心后，要能实时看到它演进（对自治系统的可观测至关重要），也要可回放。

- **① 底层引擎**：`attack_graph` 增量更新时发出 `world_model_update` 事件（节点/边 delta），而非整图重推（配合前端增量渲染）。
- **② 后端**：`models.py` 的 `push_decision` 体系新增 `action=="world_model_update"` 事件类型（payload: 新增/更新的节点与边）；写入世界模型的地方触发。
- **③ 智能体层**：`WorldModelWriter` 写入后发 delta 事件。
- **④ API**：world model 快照可经现有 task detail 返回（`attack_graph` 字段已在）；无需新端点。
- **⑤ DB**：随 `state_json`；大图注意 `state_json` 体积（必要时只持久化图、日志单独存，沿用现有分离）。
- **⑥ 前端**（本任务重心）：
  - `components/AttackGraphView.vue` 升级：支持新节点类型/边关系的可视化（按类型着色/图标）；增量应用 `world_model_update` delta（不整图重渲）。
  - `stores/taskLive.ts`：`applyEvent` 新增 `world_model_update` 分支，维护一个 `worldGraph` 响应式结构，增量 upsert 节点/边（**遵守热路径只 append 原则**）。
  - `components/PipelineFlow.vue`/`AttackChain.vue`：与世界模型联动（阶段流转 + 攻击链同源于图）。
  - `types/task.ts`：补 `world_model_update` 事件类型。
- **⑦ 测试**：前端 `npm run build` 通过；`taskLive.ts` 的 delta 应用单测（`composables/__tests__` 风格）：连续 delta 后 `worldGraph` 状态正确。

**验收**：跑一个靶时前端攻击图随阶段实时长出节点/边；F5 刷新后从 IndexedDB 重建一致。
**scope guard**：不重写 `wsManager/eventStore` 热路径；delta 只增量 upsert。
**依赖**：W1-T1、W1-T2。

---

## [W1-T4] 决策可读接口（把世界模型接到决策点，先读后用）（须满足契约 C1/C5）

**为什么**：F3——没人读世界模型。本任务把 `WorldModelQuery` 暴露到决策层，建立「决策可读」通道（**具体读了怎么选在 WS2**；这里只确保能读、且读得到正确数据）。

- **① 底层引擎**：`WorldModelQuery` 实例随 state 可得（`state.world_model() -> WorldModelQuery` 便捷方法，惰性构造）。
- **② 后端**：无新增。
- **③ 智能体层**：在三处决策点注入「只读世界模型」的能力，但**本任务只做注入 + 旁路日志，不改既有决策结果**（行为保持不变，靠 WS0 harness 回归验证）：
  - `supervisor._rule_decide`（`supervisor.py:168`）：可调用 `state.world_model()`，先以 `push_decision({action:"world_model_readout", ...})` 记录「当前 frontier/unreached/paths」供观测，路由结果暂不变。
  - `node_exploit_decision`（`orchestrator.py:2276`）：同样先 readout。
  - `PostExploitAgent` 横向决策点（`post_agent.py:774`）：同样先 readout。
- **④ API**：readout 进决策事件流（前端可见「Agent 当前对世界模型的判断」）。
- **⑤ DB**：无。
- **⑥ 前端**：`components/DecisionTimeline.vue` 新增 `action==="world_model_readout"` 渲染（展示「当前可利用前沿 / 未触达高价值 / 候选路径」）；`StrategyRail.vue` 可侧栏常驻显示当前 readout。
- **⑦ 测试**：`test_world_model_readout.py`：决策点能拿到正确 readout；**关键回归**：注入 readout 后路由/利用决策与注入前**完全一致**（行为不变，靠 harness + 断言）。

**验收**：决策点能读世界模型并在前端可见；行为零变化（为 WS2 铺好「读」通道）。
**scope guard**：本任务**严禁改变任何既有决策结果**，只加只读 readout；改变决策是 WS2 的事。
**依赖**：W1-T1、W1-T2、W1-T3。

---

## WS1 内顺序

`W1-T1（建模+查询）→ W1-T2（补全写入）→ W1-T3（实时渲染）→ W1-T4（接到决策点·只读）`。
W1 完成后，世界模型「写得全、看得见、读得到」，WS2/WS3 才有地基。
---

## 契约 reconcile 记录（WS1.5·R4）

> reconcile 日期：2026-06-11 | 方法：read 源码逐项核对 → 回填本文件

| 项 | 代码位置 | 结论 |
|---|---|---|
| C1 字段 | `world_model.py:17-40` WMNode/WMPath/WMChain | 一致 |
| C1 全方法 | `world_model.py:80-233` | 已建含 unreached/pivot/usable |
| C2 Writer | `world_model.py:251-330` | 签名一致，attach_* 已委托 |
| C4 type/relation 开放 | `models.py:467,482` | 已开放 |
| C4 attrs 基本键 | `world_model.py:262-330` writer | 已回填 |
| C5 action 名册 | `types/task.ts:108-121` DecisionAction | 已注册全量 |
| C6 事件 | `task_runner.py:84` + `taskLive.ts` handler | 双通道已统一 |
| C7-1 register | `taskLive.ts:103` registerDecisionHandler | 已导出 |
| C7-2 renderers | `DecisionTimeline.vue:78` decisionRenderers | 已建含demo |
| C7-3 样式 | `AttackGraphView.vue:234` NODE_TYPE_META+DEFAULT | 已建 |
| C7-4 worldGraph | `taskLive.ts:90` { nodes, edges } | 已建 |
| C7-5 类型 | `types/task.ts:90-121` | 已建 |

**契约对 WS2/3/4 解冻。**
