"""
api/main.py —— 向后兼容入口

所有逻辑已迁移至模块化架构：
  app.py        → FastAPI 实例 + lifespan + middleware
  routers/      → 路由模块
  services/     → 任务执行服务
  state.py      → 状态管理器
  event_bus.py  → 事件总线
  schemas.py    → Pydantic 模型
  deps.py       → 依赖注入

本文件仅做 re-export，保证 `uvicorn backend.api.main:app` 和
`from backend.api.main import app` 等旧引用继续工作。
"""
from backend.api.app import app

from backend.api.services.task_runner import is_msf_available
from backend.api.services.task_runner import get_orchestrator
