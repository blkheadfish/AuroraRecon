"""
agent_checkpoint_registry.py — asyncio.Event bridge for mid-node agent pauses.

LangGraph's ``interrupt_before`` only fires at node boundaries. When the
ExploitAgent needs to pause *inside* a long-running ReAct loop (to ask the
user for step-by-step command approval), we use an asyncio.Event as a
signal bridge:

  1. ExploitAgent calls ``open_and_wait(task_id, payload, state)``
     → pushes checkpoint to frontend, creates an Event, awaits it
  2. API endpoint ``respond_checkpoint()`` calls ``signal(task_id, decision)``
     → writes the user's decision, sets the Event
  3. ExploitAgent wakes up, reads the decision, continues/aborts

This is process-level (same as interrupt_registry.py). For multi-instance
deployments, swap to Redis pub/sub — the interface stays the same.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = int(300)  # 5 minutes

_lock = threading.Lock()
_events: dict[str, asyncio.Event] = {}
_decisions: dict[str, dict[str, Any]] = {}


async def open_and_wait(
    task_id: str,
    checkpoint_payload: dict[str, Any],
    state: Any,  # PentestState — avoid import to prevent circular deps
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Push a checkpoint to the frontend and block until the user responds.

    Returns the user's decision dict, or a default timeout decision.
    """
    if not task_id:
        return _default_decision("approve")

    event = asyncio.Event()
    with _lock:
        _events[task_id] = event
        _decisions.pop(task_id, None)  # clear stale

    try:
        state.open_checkpoint(checkpoint_payload)
    except Exception as exc:
        logger.warning(f"[CheckpointRegistry] open_checkpoint failed: {exc}")

    # Sync state back to StateManager so the API endpoint can see pending_checkpoint.
    # Without this, sm.get(task_id) returns the state snapshot from the *previous*
    # LangGraph node — which has pending_checkpoint=None — and respond_checkpoint
    # rejects the request with HTTP 400.
    try:
        from backend.api.state import get_state_manager
        get_state_manager().set(task_id, state)
    except Exception as exc:
        logger.warning(f"[CheckpointRegistry] state sync failed: {exc}")

    logger.info(
        f"[CheckpointRegistry] open_and_wait task={task_id} "
        f"type={checkpoint_payload.get('checkpoint_type', '?')}"
    )

    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning(
            f"[CheckpointRegistry] timeout ({timeout}s) for task={task_id}, "
            f"falling back to default approve"
        )
        return _default_decision("approve")

    with _lock:
        decision = _decisions.pop(task_id, _default_decision("approve"))

    logger.info(
        f"[CheckpointRegistry] resolved task={task_id} "
        f"action={decision.get('action', '?')}"
    )
    return decision


def signal(task_id: str, decision: dict[str, Any]) -> None:
    """Signal a waiting agent with the user's decision.

    Called from the API layer after ``respond_checkpoint()`` processes
    the user's response. If no agent is waiting for this task_id, this
    is a silent no-op (the task may be at a LangGraph interrupt instead).
    """
    if not task_id:
        return
    with _lock:
        _decisions[task_id] = dict(decision)
        event = _events.get(task_id)
    if event is not None:
        event.set()
        logger.info(
            f"[CheckpointRegistry] signal task={task_id} "
            f"action={decision.get('action', '?')}"
        )
    else:
        logger.debug(
            f"[CheckpointRegistry] signal task={task_id} — no waiting agent (no-op)"
        )


def cleanup(task_id: str) -> None:
    """Remove any pending event/decision for a task.

    Called when a task is cancelled or finishes, to prevent stale events.
    """
    if not task_id:
        return
    with _lock:
        event = _events.pop(task_id, None)
        _decisions.pop(task_id, None)
    if event is not None:
        event.set()  # unblock any waiter so it can exit cleanly
        logger.info(f"[CheckpointRegistry] cleanup task={task_id}")


def is_waiting(task_id: str) -> bool:
    """Check if an agent is currently waiting for this task_id."""
    if not task_id:
        return False
    with _lock:
        return task_id in _events


def snapshot() -> dict[str, dict[str, Any]]:
    """Return a copy of all current waiting states (debug/tests)."""
    with _lock:
        return {
            k: {"waiting": True, "decision": dict(_decisions.get(k, {}))}
            for k in _events
        }


def reset_all() -> None:
    """Clear the entire registry. Mainly for tests."""
    with _lock:
        for event in _events.values():
            event.set()
        _events.clear()
        _decisions.clear()


def _default_decision(action: str = "approve") -> dict[str, Any]:
    return {"action": action, "user_prompt": "", "note": "(timeout default)"}
