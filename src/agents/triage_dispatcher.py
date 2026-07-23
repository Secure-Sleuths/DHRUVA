"""
WO-H9 — Triage dispatcher: decouples triage from the alert-fetch loop.

Before H9, triage ran INLINE and BLOCKING inside ``main.run_alert_loop``: each
poll fetched a batch and triaged the whole ``risk>=10`` set serially (~40s/alert
in CLI mode) BEFORE the next fetch. That capped throughput at ~1.4 decisions/min
and let a critical alert sit behind a wall of low-value noise.

This module replaces that with a producer/consumer split:

  * The fetch loop (producer) ENQUEUES enriched alerts and returns immediately.
  * A bounded pool of worker threads (consumers) DRAINS the queue in parallel,
    each triaging one alert under its own tenant context.
  * A risk-PRIORITY queue means HIGH-risk alerts are triaged ahead of noise.

Design constraints preserved:
  * Tenant isolation — every queued item carries its ``tenant_id``; the worker
    sets that tenant context before touching the agent or DB, so two tenants'
    alerts never triage under the wrong context.
  * Bounded parallelism — ``max_workers`` threads + a bounded queue cap both
    concurrency and memory (a full queue applies backpressure to the fetcher).
  * The always-escalate gate, WO-H5 cost controls, and dedup all live inside
    ``TriageAgent._process_one`` and are untouched — the dispatcher only changes
    WHEN/HOW MANY run concurrently, never the per-alert decision logic.
"""

from __future__ import annotations

import itertools
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import structlog

logger = structlog.get_logger("triage-dispatcher")

# Sentinel pushed to wake workers for shutdown.
_STOP = object()


@dataclass(order=True)
class _QueuedItem:
    """A queue entry ordered by (tier, priority, seq).

    ``tier`` (WO-H32) is 0 for a TI-CONFIRMED alert (``is_known_malicious`` —
    a matched high/critical IOC) and 1 for everything else, so a proven-bad
    indicator is triaged ahead of the whole non-TI backlog — the live failure
    was a TI-hit alert sitting behind thousands of same-risk noise rows.
    ``priority`` is ``-risk_score`` so Python's min-heap ``PriorityQueue`` pops
    the HIGHEST-risk alert first within a tier. ``seq`` is a strictly
    increasing tie-breaker so equal-risk items keep FIFO order and the heap
    never has to compare the (unorderable) payload dicts.
    """
    tier: int
    priority: float
    seq: int
    alert: dict = field(compare=False)
    tenant_id: str = field(compare=False)
    # Enqueue timestamp (monotonic) for the WO-H32 queue-lag metric.
    enqueued_at: float = field(compare=False, default=0.0)


class TriageDispatcher:
    """Bounded, risk-prioritized, multi-worker triage executor.

    Parameters
    ----------
    triage_agent:
        Object exposing ``_process_one(alert, tenant_id=...) -> AgentDecision``.
    db:
        SOCDatabase (or compatible) exposing ``set_tenant(tenant_id)``. Used to
        pin the correct tenant context on the worker thread before triage.
    max_workers:
        Concurrency cap — number of worker threads (== max concurrent triages).
    on_decision:
        Optional callback ``fn(decision, alert, tenant_id)`` invoked by the
        worker AFTER a successful triage, under the item's tenant context. This
        is where the caller runs downstream per-decision work (incident
        grouping, SOAR evaluation, metrics). Exceptions in the callback are
        logged and swallowed so one bad decision can't kill a worker.
    max_queue:
        Bounded queue size (backpressure). 0 = unbounded (not recommended).
    """

    def __init__(
        self,
        triage_agent: Any,
        db: Any,
        *,
        max_workers: int = 4,
        on_decision: Optional[Callable[[Any, dict, str], None]] = None,
        max_queue: int = 1000,
    ):
        self._agent = triage_agent
        self._db = db
        self._max_workers = max(1, int(max_workers))
        self._on_decision = on_decision
        self._q: "queue.PriorityQueue[Any]" = queue.PriorityQueue(
            maxsize=max(0, int(max_queue)))
        self._seq = itertools.count()
        self._seq_lock = threading.Lock()
        self._workers: list[threading.Thread] = []
        self._started = False
        self._stopping = False
        # Cheap idempotency guard so the SAME alert isn't queued twice while
        # still in flight (the fetch loop can re-observe a not-yet-committed
        # alert on the next poll). Keyed by (tenant_id, alert_id).
        self._inflight: set[tuple] = set()
        self._inflight_lock = threading.Lock()
        # WO-H32 queue-lag stats: how long items WAIT in the queue before a
        # worker picks them up (observed at dequeue). ``max`` resets on each
        # queue_metrics() read so the periodic sampler gets per-window peaks.
        self._lag_lock = threading.Lock()
        self._last_wait_s = 0.0
        self._max_wait_s = 0.0

    # ── lifecycle ──────────────────────────────────────────────────────────

    def start(self):
        if self._started:
            return
        self._started = True
        self._stopping = False
        for i in range(self._max_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"triage-worker-{i}",
                daemon=True,
            )
            t.start()
            self._workers.append(t)
        logger.info("triage_dispatcher_started", workers=self._max_workers)

    def stop(self, drain: bool = True, timeout: float = 15.0):
        """Signal workers to exit.

        If ``drain``, wait up to ``timeout`` seconds for the queue (including
        in-progress items) to fully drain, so alerts already dequeued for triage
        get their decision saved + checkpointed before we exit — otherwise a
        dropped queue item is safely re-fetched/re-triaged on restart (it was
        never durably checkpointed). The wait is BOUNDED so shutdown can't hang
        behind a stuck ~40s triage; anything still unfinished at the deadline is
        left un-checkpointed and re-processed next start.
        """
        self._stopping = True
        if drain:
            self._drain_with_timeout(timeout)
        for _ in self._workers:
            # The sentinel is a real _QueuedItem (tier -1 → always first) so
            # the heap never compares a raw tuple against a dataclass item
            # (that comparison raises TypeError and would kill the put).
            self._q.put(_QueuedItem(tier=-1, priority=float("-inf"),
                                    seq=self._next_seq(), alert=_STOP,
                                    tenant_id=""))
        for t in self._workers:
            t.join(timeout=5)
        self._started = False
        logger.info("triage_dispatcher_stopped")

    def _drain_with_timeout(self, timeout: float):
        """Bounded ``queue.join()`` — waits for all queued + in-progress items to
        finish, but never longer than ``timeout`` seconds."""
        joiner = threading.Thread(target=self._q.join, daemon=True)
        joiner.start()
        joiner.join(timeout)
        if joiner.is_alive():
            logger.warning("triage_dispatcher_drain_timeout",
                           timeout=timeout, backlog=self.backlog_depth())

    # ── producer side ───────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        with self._seq_lock:
            return next(self._seq)

    @staticmethod
    def _risk_of(alert: dict) -> float:
        return float(alert.get("enrichment", {}).get("risk_score", 0) or 0)

    @staticmethod
    def _tier_of(alert: dict) -> int:
        """WO-H32 priority tier: 0 = TI-CONFIRMED (``is_known_malicious`` — a
        matched high/critical IOC), 1 = everything else. A proven-bad
        indicator jumps the entire non-TI backlog; within a tier the risk
        score still orders the queue.

        STARVATION TRADE-OFF (WO-H37, deliberate): under SUSTAINED tier-0
        arrival exceeding total service rate, tier-1 items are deferred
        indefinitely — there is no aging/promotion guard. Accepted because:
        (1) tier 0 requires a matched high/critical IOC, which is rare by
        construction — sustained saturation means an active confirmed-bad
        campaign, and triaging exactly those first IS the intended posture
        (deferring low-signal noise during a confirmed incident is correct,
        not a bug); (2) nothing is lost — deferred items stay queued, the
        bounded queue backpressures the fetcher, and un-checkpointed items
        are re-fetched after a restart; (3) the deferral is OBSERVABLE via
        ``triage_queue_lag_seconds`` (rising lag + steady depth), so an
        operator sees it rather than discovering it forensically. An aging
        guard would need heap re-prioritization (rebuild or re-enqueue
        machinery) — complexity not justified while tier 0 stays IOC-gated.
        Revisit if a noisy TI feed ever makes ``is_known_malicious`` common.
        """
        enr = alert.get("enrichment", {}) or {}
        return 0 if enr.get("is_known_malicious") else 1

    def submit(self, alert: dict, tenant_id: str) -> bool:
        """Enqueue one enriched alert for triage. Returns False if it was
        skipped (already in flight). Blocks if the bounded queue is full
        (backpressure to the fetcher)."""
        alert_id = alert.get("alert_id") or alert.get("id")
        key = (tenant_id, alert_id)
        if alert_id is not None:
            with self._inflight_lock:
                if key in self._inflight:
                    return False
                self._inflight.add(key)
        item = _QueuedItem(
            tier=self._tier_of(alert),        # TI-confirmed first (WO-H32)
            priority=-self._risk_of(alert),   # negate: highest risk pops first
            seq=self._next_seq(),
            alert=alert,
            tenant_id=tenant_id,
            enqueued_at=time.monotonic(),
        )
        self._q.put(item)
        return True

    def submit_batch(self, alerts: list[dict], tenant_id: str) -> int:
        """Enqueue a batch for one tenant. Returns count actually enqueued."""
        n = 0
        for a in alerts:
            if self.submit(a, tenant_id):
                n += 1
        return n

    def backlog_depth(self) -> int:
        """Current queue depth — how many alerts are waiting to be triaged.
        Emitted as the WO-H9 backlog metric so operators can see the pipeline
        falling behind real time."""
        return self._q.qsize()

    def queue_metrics(self) -> dict:
        """WO-H32 queue-depth/lag snapshot for the periodic sampler.

        ``last_wait_seconds`` is the queueing delay of the most recently
        dequeued item; ``max_wait_seconds`` is the peak delay since the last
        read (reset on read, so each sample reports its own window). A rising
        max-wait with a steady depth means the workers can't keep up with the
        arrival rate — the "falling behind real time" signal."""
        with self._lag_lock:
            last, peak = self._last_wait_s, self._max_wait_s
            self._max_wait_s = 0.0
        return {
            "depth": self._q.qsize(),
            "last_wait_seconds": round(last, 3),
            "max_wait_seconds": round(peak, 3),
        }

    def _record_wait(self, item: "_QueuedItem"):
        if not item.enqueued_at:
            return
        wait = max(0.0, time.monotonic() - item.enqueued_at)
        with self._lag_lock:
            self._last_wait_s = wait
            if wait > self._max_wait_s:
                self._max_wait_s = wait

    # ── consumer side ────────────────────────────────────────────────────────

    def _worker_loop(self):
        while True:
            item = self._q.get()
            # The shutdown sentinel is a _QueuedItem carrying _STOP as its
            # payload (tier -1, so it outranks all real work in the heap).
            if item.alert is _STOP:
                self._q.task_done()
                break
            self._record_wait(item)
            try:
                self._handle(item)
            except Exception as e:  # defensive: a worker must never die
                logger.error("triage_worker_item_failed",
                             alert_id=(item.alert.get("alert_id")
                                       if isinstance(item, _QueuedItem) else None),
                             error=str(e))
            finally:
                if isinstance(item, _QueuedItem):
                    aid = item.alert.get("alert_id") or item.alert.get("id")
                    with self._inflight_lock:
                        self._inflight.discard((item.tenant_id, aid))
                self._q.task_done()

    def _handle(self, item: _QueuedItem):
        # Pin the tenant context on THIS worker thread before any agent/DB call
        # (contextvars are per-thread here) — tenant isolation guarantee.
        self._db.set_tenant(item.tenant_id)
        decision = self._agent._process_one(item.alert, tenant_id=item.tenant_id)
        if decision is not None and self._on_decision is not None:
            try:
                self._on_decision(decision, item.alert, item.tenant_id)
            except Exception as e:
                logger.warning("triage_on_decision_failed",
                               alert_id=item.alert.get("alert_id"),
                               error=str(e)[:200])
