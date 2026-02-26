"""Event system for CyberPet using asyncio.Queue as the internal bus.

Provides EventType enum, Event dataclass, and EventBus class for
fan-out publish-subscribe communication between all CyberPet modules.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import AsyncGenerator


class EventType(Enum):
    """Category of every event flowing through the system."""

    CMD_INTERCEPTED = "CMD_INTERCEPTED"
    CMD_BLOCKED = "CMD_BLOCKED"
    CMD_WARNED = "CMD_WARNED"
    CMD_ALLOWED = "CMD_ALLOWED"
    THREAT_DETECTED = "THREAT_DETECTED"
    SYSTEM_STAT_UPDATE = "SYSTEM_STAT_UPDATE"
    MOOD_CHANGE = "MOOD_CHANGE"
    PET_MESSAGE = "PET_MESSAGE"

    # V2: Kernel monitoring events
    EVENT_EXEC = "EVENT_EXEC"
    FILE_ACCESS_BLOCKED = "FILE_ACCESS_BLOCKED"
    FILE_ACCESS_SUSPICIOUS = "FILE_ACCESS_SUSPICIOUS"

    # V2: Scanning events
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_PROGRESS = "SCAN_PROGRESS"
    THREAT_FOUND = "THREAT_FOUND"
    SCAN_COMPLETE = "SCAN_COMPLETE"

    # V2: Quarantine events
    QUARANTINE_SUCCESS = "QUARANTINE_SUCCESS"


@dataclass
class Event:
    """A single event flowing through the event bus.

    Attributes:
        type: Category of the event.
        timestamp: When the event occurred (auto-set to now on creation).
        source: Module name that published it.
        data: Flexible payload dictionary.
        severity: How severe/important the event is (0-100).
    """

    type: EventType
    source: str
    data: dict = field(default_factory=dict)
    severity: int = 0
    timestamp: datetime = field(default_factory=datetime.now)

    def __post_init__(self) -> None:
        """Validate severity is within bounds."""
        self.severity = max(0, min(100, self.severity))


class EventBus:
    """Central async event bus with fan-out publish-subscribe pattern.

    Wraps asyncio.Queue to support multiple concurrent subscribers.
    Each subscriber gets its own queue, and published events are
    copied to every subscriber's queue (fan-out).

    Thread-safe within a single event loop (daemon and UI run in
    the same event loop).

    Example:
        bus = EventBus()

        async def consumer():
            async for event in bus.subscribe():
                print(event)

        await bus.publish(Event(type=EventType.CMD_ALLOWED, source="guard"))
    """

    def __init__(self) -> None:
        """Initialize the event bus with an empty subscriber list."""
        self._subscribers: list[asyncio.Queue[Event]] = []

    async def publish(self, event: Event) -> None:
        """Publish an event to all subscribers.

        Each subscriber receives its own copy of the event in their
        individual queue.

        Args:
            event: The event to publish to all subscribers.
        """
        for queue in self._subscribers:
            await queue.put(event)

    async def subscribe(self) -> AsyncGenerator[Event, None]:
        """Subscribe to events and yield them as they arrive.

        Creates a new queue for this subscriber and yields events
        as they are published. The subscription lasts until the
        consumer stops iterating.

        Yields:
            Events as they are published to the bus.
        """
        queue: asyncio.Queue[Event] = asyncio.Queue()
        self._subscribers.append(queue)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            self._subscribers.remove(queue)

    @property
    def subscriber_count(self) -> int:
        """Return the number of active subscribers."""
        return len(self._subscribers)
