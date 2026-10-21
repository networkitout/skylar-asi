"""Timing-sensitive reachability tests. Excluded by default (see pytest.ini);
run with: pytest -m perf backend/tests/test_reachability_perf.py
"""
import asyncio
import socket
import time
from unittest.mock import MagicMock, patch

import pytest

from main import check_hostname_reachability

ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 0))]

pytestmark = pytest.mark.perf


# Helper to simulate blocking DNS
def blocking_getaddrinfo(*args, **kwargs):
    time.sleep(1.0)
    return ADDRINFO


# Helper to simulate slow HTTP request
async def slow_get(self, *args, **kwargs):
    await asyncio.sleep(1.0)
    response = MagicMock()
    response.status_code = 200
    response.headers = {}
    return response


async def test_reachability_concurrency():
    """Verify that HTTP and HTTPS checks run concurrently."""
    with patch("socket.getaddrinfo", return_value=ADDRINFO), \
         patch("httpx.AsyncClient.get", slow_get):

        start_time = time.time()
        await check_hostname_reachability("example.com")
        end_time = time.time()

        duration = end_time - start_time
        # If sequential, it would be ~2s. If concurrent, ~1s.
        assert duration < 1.5, f"Execution took {duration}s, expected concurrent execution (~1s)"


async def test_reachability_non_blocking_dns():
    """Verify that DNS resolution does not block the event loop."""

    # Task to measure loop blocking
    async def heartbeat():
        last_time = time.time()
        max_block = 0
        try:
            while True:
                await asyncio.sleep(0.1)
                current_time = time.time()
                diff = current_time - last_time
                if diff > 0.3:  # Allow some jitter, but 1.0s is clearly blocked
                    max_block = max(max_block, diff)
                last_time = current_time
        except asyncio.CancelledError:
            return max_block

    heartbeat_task = asyncio.create_task(heartbeat())

    # Run the function with blocking DNS mock (loop.getaddrinfo runs it in the
    # executor, so the event loop must stay responsive)
    with patch("socket.getaddrinfo", side_effect=blocking_getaddrinfo), \
         patch("httpx.AsyncClient.get", slow_get):

        await check_hostname_reachability("example.com")

    # Check heartbeat results
    heartbeat_task.cancel()
    max_block = await heartbeat_task

    # If blocked, max_block would be > 1.0s. If non-blocking, it should be small (overhead).
    assert max_block < 0.5, f"Event loop was blocked for {max_block}s"
