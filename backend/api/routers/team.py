"""
routers/team.py —— 团队协作预留接口（阶段二实现）
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["team"])


@router.get("/team/members")
async def list_members():
    return [
        {"user_id": "local-owner", "email": "owner@aurorarecon.local", "role": "owner"},
    ]


@router.post("/team/members")
async def invite_member(data: dict):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")


@router.delete("/team/members/{user_id}")
async def remove_member(user_id: str):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")


@router.post("/tasks/{task_id}/assign")
async def assign_task(task_id: str, data: dict):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")


@router.get("/tasks/{task_id}/comments")
async def get_comments(task_id: str):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")


@router.post("/tasks/{task_id}/comments")
async def add_comment(task_id: str, data: dict):
    raise HTTPException(status_code=501, detail="团队功能阶段二实现")
