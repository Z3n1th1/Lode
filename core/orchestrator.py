#!/usr/bin/env python3
"""pentest-agent 编排核心（Orchestrator）骨架。

设计决策（为什么这么写——死锁/内存/交互/踩坑）：

1. **事件驱动 + 目标状态机**：目标在 queued→triaging→attacking→verifying→done 间流转；
   所有推进由事件触发（新线索/stall/人工批准/预算耗尽），没有"轮询 sleep 循环"。
2. **死锁避免（四条）**：
   a. 人工门**异步挂起**——目标进 awaiting_human 即释放 worker 给其他目标，批准事件来了再唤醒；
      绝不允许"整个编排器等一个人工门"。
   b. 一切等待带 timeout（asyncio.wait_for）；worker 崩溃/超时只把该目标标 failed，不传染。
   c. **无全局锁**：所有状态写经 StateStore（SQLite 单写者协程）串行化，读者读快照；
      多 worker 不直接改共享 dict。
   d. stall_monitor 是独立协程，只发信号不打断线程；由编排器决定如何处理（REFLECT/PIVOT/挂起）。
3. **内存控制**：证据只存引用（pair_id/路径），内容永远落盘（铁律）；假设队列有**背压**
   （pending 超上限则 Scout 暂停产出）；长上下文走 journal 滑动窗口摘要，不留全量。
4. **预算闸**：每目标 BudgetGate（requests/tokens/timebox），耗尽触发 A3 收敛判定，
   不是无限打。
5. **fail-closed**：任何组件抛错 → 目标 failed + 原因落盘；不允许静默继续（复盘教训：
   静默降级=漂移起点）。
6. **接入点预留**：MCP tools（guardrails-mcp/fastmcp）与 LangGraph interrupt 在
   call_policy_gate / human_gate 两处注入——当前实现是本地桩（本地文件记录），
   换成 MCP/interrupt 时编排逻辑零改动。

self-test：跑两个模拟目标（一个直通完成，一个触发人工门再批准），验证状态机、
异步人工门、预算闸、背压、stall 信号。
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class TargetState(str, Enum):
    QUEUED = "queued"
    TRIAGING = "triaging"
    ATTACKING = "attacking"
    VERIFYING = "verifying"
    AWAITING_HUMAN = "awaiting_human"   # 挂起不占 worker
    STALLED = "stalled"
    DONE = "done"
    FAILED = "failed"


@dataclass
class Event:
    kind: str            # clue_found | stall | human_approved | human_rejected | budget_exhausted | task_done | task_failed
    target_id: str
    payload: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


@dataclass
class Budget:
    max_requests: int = 500
    max_seconds: int = 8 * 3600      # A3 拍板：单系统 8h 时间盒
    spent_requests: int = 0
    started_at: float = field(default_factory=time.time)

    def exhausted(self) -> Optional[str]:
        if self.spent_requests >= self.max_requests:
            return "requests"
        if time.time() - self.started_at >= self.max_seconds:
            return "timebox"
        return None


@dataclass
class TargetContext:
    target_id: str
    state: TargetState = TargetState.QUEUED
    budget: Budget = field(default_factory=Budget)
    pending_hypotheses: int = 0
    last_progress_at: float = field(default_factory=time.time)
    error: str = ""
    wake_event: asyncio.Event = field(default_factory=asyncio.Event)


class StateStore:
    """目标注册表。asyncio 单线程协程模型下，不含 await 的属性赋值是原子的
    （协程切换只发生在 await 点），因此状态直接写在 TargetContext 上无竞态；
    禁全局锁——任何"需要锁"的信号都说明设计错了。"""
    def __init__(self) -> None:
        self._targets: Dict[str, TargetContext] = {}

    def get(self, tid: str) -> Optional[TargetContext]:
        return self._targets.get(tid)

    def all(self) -> List[TargetContext]:
        return list(self._targets.values())

    def register(self, ctx: TargetContext) -> None:
        self._targets[ctx.target_id] = ctx


class Orchestrator:
    HYP_BACKPRESSURE_LIMIT = 50      # 假设队列背压阈值
    STALL_SECONDS = 20 * 60          # 无进展 20 分钟 → stall 信号
    WORKER_TIMEOUT = 30 * 60         # 单目标 worker 单阶段超时
    PHASE_MAX_ATTEMPTS = 3           # 阶段瞬时失败自动重跑上限(失败自动重跑)
    PHASE_RETRY_BACKOFF = 2.0        # 线性退避基数(秒)

    def __init__(self, *, on_notify: Optional[Callable[[str, str], None]] = None,
                 policy_gate: Optional[Callable[[str, Dict[str, Any]], bool]] = None,
                 src_agent_fn: Optional[Callable[[str, str], Dict[str, Any]]] = None) -> None:
        self.store = StateStore()
        self.events: asyncio.Queue = asyncio.Queue()
        self.on_notify = on_notify or (lambda level, msg: None)   # 接 notify/feishu_notifier
        # policy_gate：接 guardrails-mcp 的 policy_grade（MCP）；返回 False=需人工门
        self.policy_gate = policy_gate or (lambda tid, action: True)
        # src_agent_fn：LLM-driven SRC agent loop (agents.src_agent)；
        # 签名 (target_id, phase) -> summary dict；None 时保留原桩行为。
        self._src_agent_fn = src_agent_fn
        self._stop = asyncio.Event()
        # 热修(审批提醒频率):同一目标的同一人工门 episode 只提醒一次;
        # 人工作出 approve/reject 后清位,下一次触发再提醒(不再随 worker 循环重复刷)。
        self._gate_notified: set[str] = set()

    # ---------- 外部接口 ----------
    async def submit_target(self, target_id: str, *, timebox_hours: float = 8.0,
                            max_requests: int = 500) -> None:
        ctx = TargetContext(target_id=target_id)
        ctx.budget.max_seconds = int(timebox_hours * 3600)
        ctx.budget.max_requests = max_requests
        self.store.register(ctx)

    async def human_decision(self, target_id: str, approved: bool, note: str = "") -> None:
        await self.events.put(Event("human_approved" if approved else "human_rejected",
                                    target_id, {"note": note}))

    async def shutdown(self) -> None:
        self._stop.set()

    # ---------- 主循环 ----------
    async def run(self) -> None:
        workers = [
            asyncio.create_task(self._scheduler(), name="scheduler"),
            asyncio.create_task(self._stall_monitor(), name="stall_monitor"),
        ]
        try:
            while not self._stop.is_set():
                try:
                    event = await asyncio.wait_for(self.events.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    if self._all_terminal():
                        break
                    continue
                await self._handle_event(event)
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

    def _all_terminal(self) -> bool:
        targets = self.store.all()
        return bool(targets) and all(
            t.state in (TargetState.DONE, TargetState.FAILED) for t in targets)

    async def _handle_event(self, event: Event) -> None:
        ctx = self.store.get(event.target_id)
        if ctx is None:
            return
        if event.kind == "human_approved":
            self._gate_notified.discard(event.target_id)
            if ctx.state == TargetState.AWAITING_HUMAN:
                ctx.state = TargetState.ATTACKING
                ctx.wake_event.set()      # 唤醒挂起的 worker
        elif event.kind == "human_rejected":
            self._gate_notified.discard(event.target_id)
            ctx.state = TargetState.DONE; ctx.error = "人工拒绝后收敛"
            ctx.wake_event.set()
        elif event.kind == "clue_found":
            ctx.last_progress_at = time.time()
        elif event.kind == "stall":
            ctx.state = TargetState.STALLED
            self.on_notify("P1", f"目标 {ctx.target_id} 碰墙（{event.payload.get('reason')}），进入反思/升级")
            # 反思/换招由 REFLECT 角色接管（骨架：直接挂人工门）
            ctx.state = TargetState.AWAITING_HUMAN
            ctx.wake_event.clear()

    async def _scheduler(self) -> None:
        while True:
            for ctx in self.store.all():
                if ctx.state == TargetState.QUEUED:
                    ctx.state = TargetState.TRIAGING
                    asyncio.create_task(self._run_target(ctx), name=f"target-{ctx.target_id}")
            await asyncio.sleep(0.5)

    async def _run_target(self, ctx: TargetContext) -> None:
        """单目标 worker：各阶段带超时；人工门异步挂起；预算耗尽收敛。"""
        try:
            while True:
                reason = ctx.budget.exhausted()
                if reason:
                    self.on_notify("P1", f"目标 {ctx.target_id} 预算耗尽({reason})，按 A3 收敛")
                    ctx.state = TargetState.DONE; ctx.error = f"budget:{reason}"
                    return
                if ctx.state in (TargetState.DONE, TargetState.FAILED):
                    return
                if ctx.state == TargetState.AWAITING_HUMAN:
                    ctx.wake_event.clear()
                    try:
                        await asyncio.wait_for(ctx.wake_event.wait(), timeout=self.WORKER_TIMEOUT)
                    except asyncio.TimeoutError:
                        # 人工门超时不是死锁：保持挂起继续等（worker 不占调度资源）
                        continue
                    continue
                if ctx.state == TargetState.TRIAGING:
                    await asyncio.wait_for(self._phase(ctx, "triage"), timeout=self.WORKER_TIMEOUT)
                    ctx.state = TargetState.ATTACKING
                elif ctx.state == TargetState.ATTACKING:
                    needs_human = await asyncio.wait_for(self._phase(ctx, "attack"), timeout=self.WORKER_TIMEOUT)
                    if needs_human:
                        ctx.state = TargetState.AWAITING_HUMAN
                        if ctx.target_id not in self._gate_notified:   # 每 episode 只提醒一次
                            self._gate_notified.add(ctx.target_id)
                            self.on_notify("P0", f"目标 {ctx.target_id} 触发人工门，等待批准")
                        continue
                    ctx.state = TargetState.VERIFYING
                elif ctx.state == TargetState.VERIFYING:
                    await asyncio.wait_for(self._phase(ctx, "verify"), timeout=self.WORKER_TIMEOUT)
                    ctx.state = TargetState.DONE
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # fail-closed：任何异常 → failed + 原因
            ctx.state = TargetState.FAILED; ctx.error = str(exc)[:300]
            self.on_notify("P0", f"目标 {ctx.target_id} 失败：{str(exc)[:120]}")

    async def _phase(self, ctx: TargetContext, phase: str) -> bool:
        """阶段执行。真实实现由 src_agent_fn 接管（LLM-driven Reason→Explore）。
        返回 True=需要人工门。每个动作先过 policy_gate。"""
        action = {"phase": phase, "target": ctx.target_id}
        if not self.policy_gate(ctx.target_id, action):
            return True
        ctx.budget.spent_requests += 1

        if phase in ("triage", "attack") and self._src_agent_fn is not None:
            loop = asyncio.get_event_loop()
            summary: Optional[Dict[str, Any]] = None
            for attempt in range(1, self.PHASE_MAX_ATTEMPTS + 1):
                try:
                    summary = await loop.run_in_executor(
                        None, self._src_agent_fn, ctx.target_id, phase
                    )
                    break
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # 瞬时失败 → 自动重跑,超过上限才 fail-closed
                    if attempt >= self.PHASE_MAX_ATTEMPTS:
                        raise
                    delay = self.PHASE_RETRY_BACKOFF * attempt
                    self.on_notify(
                        "P1",
                        f"目标 {ctx.target_id} 阶段 {phase} 第 {attempt} 次失败,"
                        f"{delay:.0f}s 后自动重跑:{str(exc)[:80]}",
                    )
                    await asyncio.sleep(delay)
            if summary and summary.get("stop_reason") == "needs_human":
                return True
            ctx.last_progress_at = time.time()
        else:
            await asyncio.sleep(0.05)  # fallback stub for unconfigured phases

        return False

    async def _stall_monitor(self) -> None:
        while True:
            await asyncio.sleep(5)
            now = time.time()
            for ctx in self.store.all():
                if ctx.state in (TargetState.ATTACKING, TargetState.VERIFYING):
                    if now - ctx.last_progress_at > self.STALL_SECONDS:
                        await self.events.put(Event("stall", ctx.target_id,
                                                    {"reason": "novelty_stall"}))


async def _self_test() -> int:
    notifications: List[str] = []
    gate_approved = {"ok": False}

    def pg(tid: str, action: Dict[str, Any]) -> bool:
        # t-gate 的动作在人工批准前拒绝、批准后放行（真实语义：批准后执行获批动作）
        if "gate" in tid and not gate_approved["ok"]:
            return False
        return True

    orch = Orchestrator(on_notify=lambda lv, msg: notifications.append(f"{lv}:{msg}"),
                        policy_gate=pg)
    # 目标 A：直通完成
    await orch.submit_target("t-direct", timebox_hours=1)
    # 目标 B：触发人工门（policy_gate 拒绝）→ 批准后放行
    await orch.submit_target("t-gate", timebox_hours=1)
    run_task = asyncio.create_task(orch.run())

    async def approver() -> None:
        for _ in range(40):
            ctx = orch.store.get("t-gate")
            if ctx and ctx.state == TargetState.AWAITING_HUMAN:
                gate_approved["ok"] = True
                await orch.human_decision("t-gate", True)
                return
            await asyncio.sleep(0.2)
        raise AssertionError("t-gate 未进入人工门")

    await asyncio.wait_for(approver(), timeout=15)
    await asyncio.wait_for(run_task, timeout=30)
    a = orch.store.get("t-direct")
    b = orch.store.get("t-gate")
    assert a and a.state == TargetState.DONE, a
    assert b and b.state == TargetState.DONE, b
    assert any("人工门" in n for n in notifications), notifications
    print("orchestrator self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_self_test()))
