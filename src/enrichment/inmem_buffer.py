"""
In-memory alert buffer — Community fallback for the paid AlertBuffer.

Why this exists
---------------
The full ``src.pipeline.AlertBuffer`` persists failed enriched alerts to
Postgres and quarantines poison pills to a dead-letter table. That module
is stripped from Community builds (see scripts/build-source-package.sh).

Without any buffer, transient OpenSearch failures (auth blip, restart,
brief network loss) cause the enrichment loop to drop the affected alerts
on the floor — they hit ``alert_index_failed_no_buffer`` and never get
re-tried after the next successful tick, because the source query window
keeps sliding forward.

This in-memory ring buffer covers that gap with the minimum surface area:
keep the last ~1000 failed alerts in process memory and re-attempt them
on each scheduled flush tick. It is intentionally NOT durable — a
restart loses the buffer. Community installs that need durable buffering
should upgrade to Team or Enterprise.

Interface contract
------------------
Matches the paid ``AlertBuffer`` so main.py can swap one for the other
without conditional wiring: ``buffer_alert``, ``flush_to_opensearch``,
``get_buffer_count``, ``get_dead_letter_count``.
"""

from collections import deque

import structlog

from src.enrichment.opensearch_client import INDEX_OK, INDEX_REJECT

logger = structlog.get_logger(__name__)


class InMemoryAlertBuffer:
    """Bounded in-memory FIFO buffer for failed alert indexing.

    Cap: ~1000 enriched alerts (~few MB at typical size). On overflow the
    oldest alert is dropped — preferring to retain the most recent context
    a SOC operator is likely to care about during an OpenSearch outage.
    """

    MAX_SIZE = 1000

    def __init__(self, db=None):
        self._buffer: deque = deque(maxlen=self.MAX_SIZE)
        # ``db`` accepted for interface parity with paid AlertBuffer; unused.
        self.db = db

    def buffer_alert(self, enriched_alert: dict) -> bool:
        """Append an alert to the ring. Always returns True (deque maxlen
        silently drops oldest on overflow — we just log it)."""
        if len(self._buffer) >= self.MAX_SIZE:
            dropped = self._buffer[0]
            logger.warning(
                "inmem_buffer_overflow_drop",
                dropped_alert_id=dropped.get("alert_id"),
                cap=self.MAX_SIZE,
                message="Community in-memory buffer full — dropping oldest "
                        "alert. Upgrade to Team/Enterprise for durable buffering.",
            )
        self._buffer.append(enriched_alert)
        return True

    def flush_to_opensearch(self, opensearch_client) -> int:
        """Retry buffered alerts against OpenSearch.

        Returns the number of alerts successfully flushed. Stops at the
        first INDEX_DOWN response — OpenSearch is still unreachable, retry
        next tick. INDEX_REJECT (poison pill) drops the alert with a
        warning (Community has no dead-letter table).
        """
        if not self._buffer:
            return 0

        flushed = 0
        dropped_poison = 0
        # Snapshot the count so newly-buffered alerts during a long flush
        # don't extend this loop. They wait for the next tick.
        to_try = len(self._buffer)

        for _ in range(to_try):
            try:
                alert = self._buffer[0]
            except IndexError:
                break

            try:
                result = opensearch_client.index_enriched_alert(alert)
            except Exception as e:
                # index_enriched_alert is supposed to return a tri-state
                # code, not raise. Treat unexpected exceptions as DOWN so
                # we don't drop the alert on the floor.
                logger.warning(
                    "inmem_buffer_flush_exception",
                    error=str(e)[:200],
                    remaining=len(self._buffer),
                )
                break

            if result == INDEX_OK:
                self._buffer.popleft()
                flushed += 1
            elif result == INDEX_REJECT:
                # 4xx — permanent rejection. Drop with a warning; no DLQ
                # in Community.
                dropped = self._buffer.popleft()
                dropped_poison += 1
                logger.warning(
                    "inmem_buffer_poison_pill_dropped",
                    alert_id=dropped.get("alert_id"),
                )
            else:  # INDEX_DOWN
                logger.warning(
                    "inmem_buffer_flush_opensearch_down",
                    remaining=len(self._buffer),
                )
                break

        if flushed:
            logger.info(
                "inmem_buffer_flushed",
                count=flushed,
                remaining=len(self._buffer),
                poison_dropped=dropped_poison,
            )
        return flushed

    def get_buffer_count(self) -> int:
        return len(self._buffer)

    def get_dead_letter_count(self) -> int:
        # Community has no dead-letter persistence; matches interface.
        return 0
