"""Unit tests for eBPF exec monitor core behavior."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from cyberpet.ebpf.exec_monitor import ExecMonitor
from cyberpet.events import EventBus, EventType


class ExecMonitorTests(unittest.IsolatedAsyncioTestCase):
    """Validate graceful degradation and emitted event payloads."""

    async def test_start_returns_false_when_bcc_missing(self) -> None:
        bus = EventBus()
        monitor = ExecMonitor(bus)
        with patch("cyberpet.ebpf.exec_monitor._BCC_AVAILABLE", False):
            started = await monitor.start()
        self.assertFalse(started)

    async def test_published_event_includes_args_and_retval(self) -> None:
        bus = EventBus()
        monitor = ExecMonitor(bus)
        monitor._running = True
        monitor._loop = asyncio.get_running_loop()

        async def _one_event():
            async for event in bus.subscribe():
                return event

        waiter = asyncio.create_task(_one_event())
        monitor._publish_event(
            pid=123,
            ppid=45,
            uid=1000,
            comm="python3",
            filename="/usr/bin/python3",
            args="python3 -c print(1)",
            retval=0,
        )
        event = await asyncio.wait_for(waiter, timeout=1.0)

        self.assertEqual(event.type, EventType.EVENT_EXEC)
        self.assertEqual(event.data.get("pid"), 123)
        self.assertEqual(event.data.get("args"), "python3 -c print(1)")
        self.assertEqual(event.data.get("retval"), 0)


if __name__ == "__main__":
    unittest.main()
