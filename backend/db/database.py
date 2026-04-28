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
    String, Text, Integer, Boolean, DateTime, text, UniqueConstraint, Index,
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from backend.agents.models import PentestState, TaskStatus

logger = logging.getLogger(__name__)

# ── 连接配置 ──────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "")
if not DATABASE_URL:
    logger.warning(
        "[DB] DATABASE_URL 未设置，使用默认开发配置。"
        "生产环境请在 .env 中设置 DATABASE_URL。"
    )
    DATABASE_URL = "postgresql+asyncpg://pentest:pentest123@localhost:5432/pentestai"

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
    owner_id: Mapped[str] = mapped_column(String(36), default="", index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
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
    role: Mapped[str] = mapped_column(String(16), default="user")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TaskFactRecord(Base):
    __tablename__ = "task_facts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), index=True)
    owner_id: Mapped[str] = mapped_column(String(36), default="", index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    fact_key: Mapped[str] = mapped_column(String(256), index=True)
    fact_type: Mapped[str] = mapped_column(String(64), default="")
    value_json: Mapped[str] = mapped_column(Text, default="{}")
    source: Mapped[str] = mapped_column(String(64), default="")
    source_node: Mapped[str] = mapped_column(String(64), default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("task_id", "fact_key", name="uq_task_fact_task_factkey"),
    )


class TenantAssetRecord(Base):
    __tablename__ = "tenant_assets"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    asset_type: Mapped[str] = mapped_column(String(32), index=True)  # skill|knowledge|prompt
    asset_key: Mapped[str] = mapped_column(String(128), index=True)
    layer: Mapped[str] = mapped_column(String(32), default="user")  # global_template|tenant_override|user_override
    owner_id: Mapped[str] = mapped_column(String(36), default="", index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    content: Mapped[str] = mapped_column(Text, default="")
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("asset_type", "asset_key", "layer", "owner_id", "tenant_id", name="uq_asset_scope"),
        Index("idx_asset_lookup", "asset_type", "asset_key", "tenant_id", "owner_id"),
    )


class UserSettingRecord(Base):
    __tablename__ = "user_settings"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), index=True)
    scope: Mapped[str] = mapped_column(String(32), default="settings")  # settings|profile
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    __table_args__ = (
        UniqueConstraint("owner_id", "scope", name="uq_owner_scope_settings"),
    )


class AuditLogRecord(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), default="", index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str] = mapped_column(String(32), default="")
    resource_key: Mapped[str] = mapped_column(String(128), default="")
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class AdminOverrideRecord(Base):
    __tablename__ = "admin_overrides"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    resource_type: Mapped[str] = mapped_column(String(16), index=True)
    resource_key: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class TaskBranchRecord(Base):
    """任务对话分支元数据 — Claude/Kimi 风格 branch tree。

    payload 全部体检在 LangGraph checkpointer (postgres) 里, 这张表只存关系
    元数据用于 UI 展示和路由。``thread_id`` 决定 LangGraph 落 checkpoint
    的位置, 默认是 ``f"{task_id}:{branch_id}"``; root branch 为兼容老任务
    会把 thread_id 直接设为 task_id (lazy_init_root 决定)。
    """
    __tablename__ = "task_branches"
    branch_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    parent_branch_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    fork_event_id: Mapped[str] = mapped_column(String(128), default="")
    fork_phase: Mapped[str] = mapped_column(String(64), default="")
    fork_round: Mapped[int] = mapped_column(Integer, default=0)
    thread_id: Mapped[str] = mapped_column(String(160), default="", index=True)
    status: Mapped[str] = mapped_column(String(16), default="running")
    label: Mapped[str] = mapped_column(String(128), default="")
    initiating_prompt: Mapped[str] = mapped_column(Text, default="")
    is_root: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow,
    )
    __table_args__ = (
        Index("idx_task_branches_task", "task_id"),
        Index("idx_task_branches_parent", "task_id", "parent_branch_id"),
    )


# ── 数据库操作 ────────────────────────────────────────────

async def init_db():
    """创建表（幂等）+ 增量迁移"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 增量迁移：为已有表添加新列（create_all 不会修改已有表结构）
    migrations = [
        ("tasks", "owner_id", "ALTER TABLE tasks ADD COLUMN owner_id VARCHAR(36) DEFAULT '' NOT NULL"),
        ("tasks", "tenant_id", "ALTER TABLE tasks ADD COLUMN tenant_id VARCHAR(64) DEFAULT 'default' NOT NULL"),
        ("users", "role", "ALTER TABLE users ADD COLUMN role VARCHAR(16) DEFAULT 'user' NOT NULL"),
        ("admin_overrides", "detail_json", "ALTER TABLE admin_overrides ADD COLUMN detail_json TEXT DEFAULT '{}'"),
    ]
    async with engine.begin() as conn:
        for table, column, ddl in migrations:
            try:
                await conn.execute(text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = :t AND column_name = :c"
                ), {"t": table, "c": column})
                row = (await conn.execute(text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = :t AND column_name = :c"
                ), {"t": table, "c": column})).fetchone()
                if not row:
                    await conn.execute(text(ddl))
                    logger.info(f"[DB] 迁移: {table}.{column} 已添加")
            except Exception as e:
                logger.warning(f"[DB] 迁移 {table}.{column} 跳过: {e}")

    # 保证至少一个 admin：如果用户表非空但无任何 admin，把最早注册的用户提升为 admin
    try:
        async with engine.begin() as conn:
            row = (await conn.execute(text(
                "SELECT COUNT(*) AS c FROM users WHERE role = 'admin'"
            ))).fetchone()
            admin_count = int(row.c) if row else 0
            if admin_count == 0:
                first = (await conn.execute(text(
                    "SELECT id FROM users ORDER BY created_at ASC LIMIT 1"
                ))).fetchone()
                if first and first.id:
                    await conn.execute(
                        text("UPDATE users SET role = 'admin' WHERE id = :uid"),
                        {"uid": first.id},
                    )
                    logger.info(f"[DB] 未检测到 admin，已将最早注册用户 {first.id} 提升为 admin")
    except Exception as e:
        logger.warning(f"[DB] admin 自动提升跳过: {e}")

    logger.info("[DB] 数据库表已就绪")


async def save_task(state: PentestState) -> None:
    """保存/更新任务到数据库"""
    async with async_session() as session:
        record = await session.get(TaskRecord, state.task_id)
        if not record:
            record = TaskRecord(task_id=state.task_id)
            session.add(record)

        record.target = state.target
        record.owner_id = state.owner_id or ""
        record.tenant_id = state.tenant_id or "default"
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
                owner_id=record.owner_id or "",
                tenant_id=record.tenant_id or "default",
                scope_note=record.scope_note,
                status=TaskStatus(record.status),
                current_phase=record.current_phase,
                target_os=record.target_os,
                error_msg=record.error_msg,
                got_shell=record.got_shell,
                privilege_level=record.privilege_level,
                report_path=record.report_path,
            )


async def list_tasks_from_db(owner_id: str | None = None) -> list[dict]:
    """列出任务摘要,若指定 owner_id 则只返回该用户创建的任务。"""
    sql = """
        SELECT task_id, target, status, current_phase,
               findings_count, got_shell, report_path,
               privilege_level, created_at, updated_at, owner_id, tenant_id
        FROM tasks
    """
    params: dict[str, str] = {}
    if owner_id:
        sql += " WHERE owner_id = :owner_id"
        params["owner_id"] = owner_id
    sql += " ORDER BY created_at DESC"

    async with async_session() as session:
        result = await session.execute(text(sql), params)
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
                "owner_id": r.owner_id or "",
                "tenant_id": r.tenant_id or "default",
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
                COUNT(*) FILTER (WHERE status = 'awaiting_approval') as awaiting_approval,
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
            "awaiting_approval": row.awaiting_approval,
            "shells_obtained": row.shells_obtained,
            "total_findings": row.total_findings,
        }


async def save_task_facts(state: PentestState) -> None:
    task_facts = state.task_facts or {}
    if not task_facts:
        return
    async with async_session() as session:
        for fact in task_facts.values():
            rid = f"{state.task_id}:{fact.fact_key}"[:64]
            record = await session.get(TaskFactRecord, rid)
            value_json = json.dumps(fact.value, ensure_ascii=False)
            if not record:
                record = TaskFactRecord(
                    id=rid,
                    task_id=state.task_id,
                    owner_id=state.owner_id or "",
                    tenant_id=state.tenant_id or "default",
                    fact_key=fact.fact_key,
                    fact_type=fact.fact_type or "",
                    value_json=value_json,
                    source=fact.source or "",
                    source_node=fact.source_node or "",
                    version=int(fact.version or 1),
                )
                session.add(record)
            else:
                record.owner_id = state.owner_id or ""
                record.tenant_id = state.tenant_id or "default"
                record.fact_type = fact.fact_type or record.fact_type
                record.value_json = value_json
                record.source = fact.source or record.source
                record.source_node = fact.source_node or record.source_node
                record.version = max(record.version + 1, int(fact.version or 1))
                record.last_seen_at = datetime.utcnow()
        await session.commit()


async def upsert_tenant_asset(
    *,
    asset_type: str,
    asset_key: str,
    layer: str,
    owner_id: str,
    tenant_id: str,
    content: str,
) -> TenantAssetRecord:
    rid = f"{asset_type}:{asset_key}:{layer}:{owner_id}:{tenant_id}"[:64]
    async with async_session() as session:
        record = await session.get(TenantAssetRecord, rid)
        if not record:
            record = TenantAssetRecord(
                id=rid,
                asset_type=asset_type,
                asset_key=asset_key,
                layer=layer,
                owner_id=owner_id or "",
                tenant_id=tenant_id or "default",
                content=content,
            )
            session.add(record)
        else:
            record.content = content
            record.is_deleted = False
            record.updated_at = datetime.utcnow()
        await session.commit()
        await session.refresh(record)
        return record


async def list_tenant_assets(asset_type: str, owner_id: str, tenant_id: str = "default") -> list[TenantAssetRecord]:
    async with async_session() as session:
        result = await session.execute(
            text(
                "SELECT id FROM tenant_assets WHERE asset_type=:t AND is_deleted=false "
                "AND (layer='global_template' OR (layer='tenant_override' AND tenant_id=:tenant_id) "
                "OR (layer='user_override' AND owner_id=:owner_id AND tenant_id=:tenant_id))"
            ),
            {"t": asset_type, "owner_id": owner_id or "", "tenant_id": tenant_id or "default"},
        )
        ids = [r.id for r in result.fetchall()]
        rows: list[TenantAssetRecord] = []
        for rid in ids:
            row = await session.get(TenantAssetRecord, rid)
            if row:
                rows.append(row)
        return rows


async def get_tenant_asset_resolved(
    *,
    asset_type: str,
    asset_key: str,
    owner_id: str,
    tenant_id: str = "default",
) -> TenantAssetRecord | None:
    async with async_session() as session:
        for layer, oid, tid in (
            ("user_override", owner_id or "", tenant_id or "default"),
            ("tenant_override", "", tenant_id or "default"),
            ("global_template", "", "default"),
        ):
            result = await session.execute(
                text(
                    "SELECT id FROM tenant_assets WHERE asset_type=:t AND asset_key=:k "
                    "AND layer=:layer AND owner_id=:owner_id AND tenant_id=:tenant_id "
                    "AND is_deleted=false LIMIT 1"
                ),
                {
                    "t": asset_type,
                    "k": asset_key,
                    "layer": layer,
                    "owner_id": oid,
                    "tenant_id": tid,
                },
            )
            row = result.fetchone()
            if row:
                return await session.get(TenantAssetRecord, row.id)
    return None


async def save_user_scoped_json(owner_id: str, scope: str, payload: dict) -> None:
    rid = f"{owner_id}:{scope}"[:64]
    async with async_session() as session:
        record = await session.get(UserSettingRecord, rid)
        data_json = json.dumps(payload or {}, ensure_ascii=False)
        if not record:
            record = UserSettingRecord(id=rid, owner_id=owner_id, scope=scope, data_json=data_json)
            session.add(record)
        else:
            record.data_json = data_json
            record.updated_at = datetime.utcnow()
        await session.commit()


async def load_user_scoped_json(owner_id: str, scope: str) -> dict | None:
    rid = f"{owner_id}:{scope}"[:64]
    async with async_session() as session:
        record = await session.get(UserSettingRecord, rid)
        if not record:
            return None
        try:
            return json.loads(record.data_json or "{}")
        except Exception:
            return {}


async def append_audit_log(
    *,
    owner_id: str,
    tenant_id: str,
    action: str,
    resource_type: str,
    resource_key: str,
    detail: dict,
) -> None:
    rid = uuid4().hex[:32]
    async with async_session() as session:
        session.add(
            AuditLogRecord(
                id=rid,
                owner_id=owner_id or "",
                tenant_id=tenant_id or "default",
                action=action,
                resource_type=resource_type,
                resource_key=resource_key,
                detail_json=json.dumps(detail or {}, ensure_ascii=False),
            )
        )
        await session.commit()


async def list_audit_logs(
    *,
    page: int = 1,
    page_size: int = 50,
    action: str | None = None,
    owner_id: str | None = None,
) -> tuple[list[dict], int]:
    bounded_page = max(1, page)
    bounded_size = max(1, min(page_size, 200))
    offset = (bounded_page - 1) * bounded_size

    where_clauses: list[str] = []
    params: dict = {}
    if action:
        where_clauses.append("action = :action")
        params["action"] = action
    if owner_id:
        where_clauses.append("owner_id = :owner_id")
        params["owner_id"] = owner_id

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    async with async_session() as session:
        count_result = await session.execute(
            text(f"SELECT COUNT(*) AS c FROM audit_logs{where_sql}"), params
        )
        total = int(count_result.scalar() or 0)

        rows_result = await session.execute(
            text(
                f"SELECT id, owner_id, tenant_id, action, resource_type, resource_key, "
                f"detail_json, created_at FROM audit_logs{where_sql} "
                f"ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
            ),
            {**params, "limit": bounded_size, "offset": offset},
        )
        items = []
        for row in rows_result.fetchall():
            detail = {}
            try:
                detail = json.loads(row.detail_json or "{}")
            except Exception:
                pass
            items.append({
                "id": row.id,
                "owner_id": row.owner_id,
                "tenant_id": row.tenant_id,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_key": row.resource_key,
                "detail": detail,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            })
        return items, total


# ── Admin Override 操作 ───────────────────────────────────

async def get_override(resource_type: str, resource_key: str) -> AdminOverrideRecord | None:
    rid = f"{resource_type}:{resource_key}"[:64]
    async with async_session() as session:
        return await session.get(AdminOverrideRecord, rid)


async def set_override(resource_type: str, resource_key: str, enabled: bool) -> AdminOverrideRecord:
    rid = f"{resource_type}:{resource_key}"[:64]
    async with async_session() as session:
        record = await session.get(AdminOverrideRecord, rid)
        if record:
            record.enabled = enabled
            record.updated_at = datetime.utcnow()
        else:
            record = AdminOverrideRecord(
                id=rid,
                resource_type=resource_type,
                resource_key=resource_key,
                enabled=enabled,
            )
            session.add(record)
        await session.commit()
        await session.refresh(record)
        return record


async def list_overrides(resource_type: str | None = None) -> list[dict]:
    async with async_session() as session:
        if resource_type:
            result = await session.execute(
                text("SELECT id, resource_type, resource_key, enabled, updated_at "
                     "FROM admin_overrides WHERE resource_type = :rt ORDER BY resource_key"),
                {"rt": resource_type},
            )
        else:
            result = await session.execute(
                text("SELECT id, resource_type, resource_key, enabled, updated_at "
                     "FROM admin_overrides ORDER BY resource_type, resource_key")
            )
        return [
            {
                "id": row.id,
                "resource_type": row.resource_type,
                "resource_key": row.resource_key,
                "enabled": row.enabled,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            }
            for row in result.fetchall()
        ]


# ── 用户操作 ──────────────────────────────────────────────

async def create_user(
    username: str,
    password_hash: str,
    nickname: str = "",
    role: str = "user",
) -> UserRecord:
    async with async_session() as session:
        user = UserRecord(
            username=username,
            password_hash=password_hash,
            nickname=nickname or username,
            role=role if role in ("admin", "user") else "user",
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


async def count_users() -> int:
    async with async_session() as session:
        result = await session.execute(text("SELECT COUNT(*) AS c FROM users"))
        row = result.fetchone()
        return int(row.c) if row else 0


async def list_all_users() -> list[dict]:
    """管理员：列出所有用户（不含密码哈希）。"""
    async with async_session() as session:
        result = await session.execute(text(
            "SELECT id, username, nickname, avatar_url, oss_url, role, created_at "
            "FROM users ORDER BY created_at ASC"
        ))
        rows = result.fetchall()
        return [
            {
                "id": r.id,
                "username": r.username,
                "nickname": r.nickname or r.username,
                "avatar_url": r.avatar_url or "",
                "oss_url": r.oss_url or "",
                "role": r.role or "user",
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in rows
        ]


async def count_admins() -> int:
    async with async_session() as session:
        result = await session.execute(text(
            "SELECT COUNT(*) AS c FROM users WHERE role = 'admin'"
        ))
        row = result.fetchone()
        return int(row.c) if row else 0


async def delete_user(user_id: str) -> bool:
    async with async_session() as session:
        user = await session.get(UserRecord, user_id)
        if not user:
            return False
        await session.delete(user)
        await session.commit()
        return True


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


# ── 任务分支 CRUD ─────────────────────────────────────────

def _branch_record_to_dict(rec: TaskBranchRecord) -> dict:
    return {
        "branch_id": rec.branch_id,
        "task_id": rec.task_id,
        "parent_branch_id": rec.parent_branch_id or None,
        "fork_event_id": rec.fork_event_id or None,
        "fork_phase": rec.fork_phase or "",
        "fork_round": int(rec.fork_round or 0) or None,
        "thread_id": rec.thread_id or "",
        "status": rec.status or "running",
        "label": rec.label or "",
        "initiating_prompt": rec.initiating_prompt or "",
        "is_root": bool(rec.is_root),
        "created_at": rec.created_at.isoformat() if rec.created_at else "",
        "updated_at": rec.updated_at.isoformat() if rec.updated_at else "",
    }


async def upsert_branch(branch: dict) -> None:
    """Insert or update a branch row keyed by branch_id."""
    bid = branch.get("branch_id") or ""
    if not bid:
        raise ValueError("branch.branch_id is required")
    async with async_session() as session:
        rec = await session.get(TaskBranchRecord, bid)
        if not rec:
            rec = TaskBranchRecord(branch_id=bid)
            session.add(rec)
        rec.task_id = branch.get("task_id") or ""
        rec.parent_branch_id = branch.get("parent_branch_id") or ""
        rec.fork_event_id = branch.get("fork_event_id") or ""
        rec.fork_phase = branch.get("fork_phase") or ""
        rec.fork_round = int(branch.get("fork_round") or 0)
        rec.thread_id = branch.get("thread_id") or ""
        rec.status = branch.get("status") or "running"
        rec.label = (branch.get("label") or "")[:128]
        rec.initiating_prompt = branch.get("initiating_prompt") or ""
        rec.is_root = bool(branch.get("is_root"))
        rec.updated_at = datetime.utcnow()
        await session.commit()


async def list_branches_by_task(task_id: str) -> list[dict]:
    async with async_session() as session:
        result = await session.execute(
            text(
                "SELECT branch_id FROM task_branches "
                "WHERE task_id = :tid ORDER BY created_at ASC"
            ),
            {"tid": task_id},
        )
        ids = [row.branch_id for row in result.fetchall()]
        out = []
        for bid in ids:
            rec = await session.get(TaskBranchRecord, bid)
            if rec:
                out.append(_branch_record_to_dict(rec))
        return out


async def get_branch(branch_id: str) -> Optional[dict]:
    async with async_session() as session:
        rec = await session.get(TaskBranchRecord, branch_id)
        return _branch_record_to_dict(rec) if rec else None


async def delete_branch(branch_id: str) -> bool:
    async with async_session() as session:
        rec = await session.get(TaskBranchRecord, branch_id)
        if not rec:
            return False
        await session.delete(rec)
        await session.commit()
        return True
