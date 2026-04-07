"""
db/database.py —— PostgreSQL 异步数据库层

使用 SQLAlchemy 2.0 async + asyncpg 驱动
负责任务持久化，替代内存 dict 存储
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    Column, String, Text, Integer, Boolean, DateTime, Enum as SAEnum,
    create_engine, text,
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from backend.agents.models import PentestState, TaskStatus

logger = logging.getLogger(__name__)

# ── 连接配置 ──────────────────────────────────────────────
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentest:pentest123@localhost:5432/pentestai",
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# ── ORM 基类 ──────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── 任务表 ────────────────────────────────────────────────
class TaskRecord(Base):
    __tablename__ = "tasks"

    task_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target: Mapped[str] = mapped_column(String(256), nullable=False)
    scope_note: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    current_phase: Mapped[str] = mapped_column(String(64), default="init")
    target_os: Mapped[str] = mapped_column(String(32), default="unknown")
    error_msg: Mapped[str] = mapped_column(Text, default="")

    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    got_shell: Mapped[bool] = mapped_column(Boolean, default=False)
    privilege_level: Mapped[str] = mapped_column(String(32), default="")
    report_path: Mapped[str] = mapped_column(String(512), default="")

    # JSON 序列化的完整状态（用于恢复 PentestState）
    state_json: Mapped[str] = mapped_column(Text, default="{}")
    # 日志独立存储（可能很长）
    phase_log_json: Mapped[str] = mapped_column(Text, default="[]")

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


# ── 用户表 ────────────────────────────────────────────────
class UserRecord(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    nickname: Mapped[str] = mapped_column(String(64), default="")
    avatar_url: Mapped[str] = mapped_column(String(1024), default="")
    oss_url: Mapped[str] = mapped_column(String(1024), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ── 数据库操作 ────────────────────────────────────────────

async def init_db():
    """创建表（幂等）"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("[DB] 数据库表已就绪")


async def save_task(state: PentestState) -> None:
    """保存/更新任务到数据库"""
    async with async_session() as session:
        record = await session.get(TaskRecord, state.task_id)
        if not record:
            record = TaskRecord(task_id=state.task_id)
            session.add(record)

        record.target = state.target
        record.scope_note = state.scope_note
        record.status = state.status.value
        record.current_phase = state.current_phase
        record.target_os = state.target_os
        record.error_msg = state.error_msg
        record.findings_count = len(state.findings)
        record.got_shell = state.got_shell
        record.privilege_level = state.privilege_level
        record.report_path = state.report_path
        record.updated_at = datetime.utcnow()

        # 完整状态序列化
        try:
            record.state_json = state.model_dump_json()
        except Exception:
            record.state_json = "{}"

        # 日志
        try:
            record.phase_log_json = json.dumps(state.phase_log, ensure_ascii=False)
        except Exception:
            record.phase_log_json = "[]"

        await session.commit()


async def load_task(task_id: str) -> Optional[PentestState]:
    """从数据库加载任务状态"""
    async with async_session() as session:
        record = await session.get(TaskRecord, task_id)
        if not record:
            return None
        try:
            return PentestState.model_validate_json(record.state_json)
        except Exception:
            # 回退到基本字段构造
            return PentestState(
                task_id=record.task_id,
                target=record.target,
                scope_note=record.scope_note,
                status=TaskStatus(record.status),
                current_phase=record.current_phase,
                target_os=record.target_os,
                error_msg=record.error_msg,
                got_shell=record.got_shell,
                privilege_level=record.privilege_level,
                report_path=record.report_path,
            )


async def list_tasks_from_db() -> list[dict]:
    """列出所有任务摘要"""
    async with async_session() as session:
        result = await session.execute(
            text("""
                SELECT task_id, target, status, current_phase,
                       findings_count, got_shell, report_path,
                       privilege_level, created_at, updated_at
                FROM tasks ORDER BY created_at DESC
            """)
        )
        rows = result.fetchall()
        return [
            {
                "task_id": r.task_id,
                "target": r.target,
                "status": r.status,
                "current_phase": r.current_phase,
                "findings_count": r.findings_count,
                "got_shell": r.got_shell,
                "report_path": r.report_path or "",
                "privilege_level": r.privilege_level or "",
                "created_at": r.created_at.isoformat() if r.created_at else "",
                "updated_at": r.updated_at.isoformat() if r.updated_at else "",
            }
            for r in rows
        ]


async def delete_task_from_db(task_id: str) -> bool:
    """删除任务记录"""
    async with async_session() as session:
        record = await session.get(TaskRecord, task_id)
        if record:
            await session.delete(record)
            await session.commit()
            return True
        return False


async def get_task_stats() -> dict:
    """获取任务统计信息"""
    async with async_session() as session:
        result = await session.execute(text("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'running') as running,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'failed') as failed,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE got_shell = true) as shells_obtained,
                COALESCE(SUM(findings_count), 0) as total_findings
            FROM tasks
        """))
        row = result.fetchone()
        return {
            "total": row.total,
            "running": row.running,
            "completed": row.completed,
            "failed": row.failed,
            "pending": row.pending,
            "shells_obtained": row.shells_obtained,
            "total_findings": row.total_findings,
        }


# ── 用户操作 ──────────────────────────────────────────────

async def create_user(username: str, password_hash: str, nickname: str = "") -> UserRecord:
    async with async_session() as session:
        user = UserRecord(
            username=username,
            password_hash=password_hash,
            nickname=nickname or username,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


async def get_user_by_username(username: str) -> Optional[UserRecord]:
    async with async_session() as session:
        result = await session.execute(
            text("SELECT * FROM users WHERE username = :u LIMIT 1"),
            {"u": username},
        )
        row = result.fetchone()
        if not row:
            return None
        return await session.get(UserRecord, row.id)


async def get_user_by_id(user_id: str) -> Optional[UserRecord]:
    async with async_session() as session:
        return await session.get(UserRecord, user_id)


async def update_user(user_id: str, **kwargs) -> Optional[UserRecord]:
    async with async_session() as session:
        user = await session.get(UserRecord, user_id)
        if not user:
            return None
        for key, val in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, val)
        await session.commit()
        await session.refresh(user)
        return user
