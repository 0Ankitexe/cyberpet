"""Tests for CyberPet UI listener task lifecycle."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from cyberpet.ui.pet import CyberPetApp


class UIListenerLifecycleTests(unittest.IsolatedAsyncioTestCase):
    """Ensure the UI keeps and cleans up its background listener task."""

    def test_on_mount_keeps_listener_task_reference(self) -> None:
        app = CyberPetApp()
        fake_task = Mock()
        fake_pet_widget = SimpleNamespace(pet_name="")
        created_coroutines = []

        def fake_create_task(coro):
            created_coroutines.append(coro)
            coro.close()
            return fake_task

        with (
            patch("cyberpet.ui.pet.asyncio.create_task", side_effect=fake_create_task),
            patch.object(app, "set_interval"),
            patch.object(app, "query_one", return_value=fake_pet_widget),
            patch.object(app, "_apply_mood_theme"),
        ):
            app.on_mount()

        self.assertIs(app._event_listener_task, fake_task)
        self.assertEqual(len(created_coroutines), 1)

    async def test_on_unmount_cancels_listener_task(self) -> None:
        app = CyberPetApp()
        fake_task = Mock()
        app._event_listener_task = fake_task
        gather_mock = AsyncMock()

        with patch("cyberpet.ui.pet.asyncio.gather", gather_mock):
            await app.on_unmount()

        fake_task.cancel.assert_called_once()
        gather_mock.assert_awaited_once()
        self.assertIsNone(app._event_listener_task)


if __name__ == "__main__":
    unittest.main()
