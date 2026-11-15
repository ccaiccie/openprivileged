import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from vg_api.rotation_gateway import open_managed_session
from vg_core.domain import Actor, DomainError
from vg_core.rotation import AccountBinding, RotationService


class Adapter:
    def change(self, binding, password):
        pass

    def verify(self, binding, password):
        return True


def fixture():
    now = [datetime(2026, 11, 13, tzinfo=UTC)]
    service = RotationService(Adapter(), lambda: now[0])
    service.enroll(
        AccountBinding("a", "o", "t", "tech", "tech-admin", "ad", frozenset({"d"})),
        "synthetic-hidden-password",
    )
    actor = Actor("tech", "o", frozenset({"t"}), "technician")
    return service, actor, now


def test_gateway_only_backend_receives_password():
    async def scenario():
        service, actor, _ = fixture()

        async def authorize():
            return True

        async def connect(username, password):
            assert username == "tech-admin" and password == "synthetic-hidden-password"
            return "opaque-connection"

        async def close(connection):
            pytest.fail("successful connection should transfer ownership")

        assert await open_managed_session(service, actor, "d", authorize, connect, close) == (
            "opaque-connection"
        )

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["before", "after", "overdue"])
def test_gateway_fail_closed(failure):
    async def scenario():
        service, actor, now = fixture()
        calls, closed = [], []

        async def authorize():
            return failure != "before" and not (failure == "after" and calls)

        async def connect(username, password):
            calls.append(username)
            return "connection"

        async def close(connection):
            closed.append(connection)

        if failure == "overdue":
            now[0] += timedelta(hours=4)
        with pytest.raises(DomainError):
            await open_managed_session(service, actor, "d", authorize, connect, close)
        assert calls == (["tech-admin"] if failure == "after" else [])
        assert closed == (["connection"] if failure == "after" else [])

    asyncio.run(scenario())


def test_browser_cancellation_closes_late_connection():
    async def scenario():
        service, actor, _ = fixture()
        started, proceed = asyncio.Event(), asyncio.Event()
        closed = []

        async def authorize():
            return True

        async def connect(username, password):
            started.set()
            await proceed.wait()
            return "late-connection"

        async def close(connection):
            closed.append(connection)

        task = asyncio.create_task(
            open_managed_session(service, actor, "d", authorize, connect, close)
        )
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        proceed.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert closed == ["late-connection"]

    asyncio.run(scenario())
