"""Trusted async session opener retaining the rotation lock through authentication."""

import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import TimeoutError as FutureTimeout

from vg_core.domain import Actor, DomainError
from vg_core.rotation import RotationService


async def open_managed_session[T](
    service: RotationService,
    actor: Actor,
    device_id: str,
    authorize: Callable[[], Awaitable[bool]],
    connect: Callable[[str, str], Awaitable[T]],
    close: Callable[[T], Awaitable[None]],
    timeout: float = 25,
) -> T:
    """Server-only callbacks; neither identity mapping nor credentials come from browser.

    The worker thread holds the service lock until authentication completes.
    Reauthorize on the event loop immediately before and after connection setup.
    Subsequent session expiry/revocation checks remain the transport's obligation.
    """
    if not 0 < timeout <= 60:
        raise ValueError("Invalid connection timeout")
    loop = asyncio.get_running_loop()
    cancelled = asyncio.Event()
    result: list[T] = []

    async def establish(username: str, password: str) -> None:
        opened: T | None = None
        try:
            async with asyncio.timeout(timeout):
                if cancelled.is_set() or not await authorize():
                    raise DomainError("Session authorization ended", 403)
                opened = await connect(username, password)
                if cancelled.is_set() or not await authorize():
                    raise DomainError("Session authorization ended", 403)
                result.append(opened)
                opened = None  # Ownership transfers only after the second authorization check.
        finally:
            if opened is not None:
                await close(opened)

    def inject(username: str, password: str) -> None:
        future = asyncio.run_coroutine_threadsafe(establish(username, password), loop)
        try:
            future.result(timeout + 2)
        except FutureTimeout:
            future.cancel()
            raise DomainError("Backend connection timed out", 502) from None

    task = asyncio.create_task(
        asyncio.to_thread(service.connect, actor, device_id, lambda: None, inject)
    )
    try:
        await asyncio.shield(task)
        if len(result) != 1:
            raise DomainError("Backend connection unavailable", 502)
        return result.pop()
    except BaseException:
        cancelled.set()

        # A cancelled browser must not strand a late successful backend session.
        async def cleanup() -> None:
            try:
                await task
            except Exception:
                pass
            finally:
                for opened in result:
                    await close(opened)
                result.clear()

        cleanup_task = asyncio.create_task(cleanup())
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            pass
        raise
