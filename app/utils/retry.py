"""
Retry utilities with exponential backoff using Tenacity.
"""
import asyncio
from typing import Any, Callable, Type, Tuple, Union
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
from app.logging.logger import get_logger

logger = get_logger(__name__)

def retry_with_backoff(
    max_retries: int = 3,
    min_delay: float = 1.0,
    max_delay: float = 10.0,
    exceptions: Union[Type[Exception], Tuple[Type[Exception], ...]] = Exception,
):
    """
    Decorator for retrying functions with exponential backoff.
    
    Args:
        max_retries: Maximum number of attempts.
        min_delay: Minimum wait time between retries in seconds.
        max_delay: Maximum wait time between retries in seconds.
        exceptions: Exception type(s) to trigger a retry.
    """
    return retry(
        stop=stop_after_attempt(max_retries),
        wait=wait_exponential(multiplier=min_delay, min=min_delay, max=max_delay),
        retry=retry_if_exception_type(exceptions),
        before_sleep=before_sleep_log(logger, "WARNING"),
        reraise=True,
    )

async def run_with_retry(
    func: Callable,
    *args,
    max_retries: int = 3,
    exceptions: Union[Type[Exception], Tuple[Type[Exception], ...]] = Exception,
    **kwargs
) -> Any:
    """
    Programmatic way to run an async function with retry.
    """
    @retry_with_backoff(max_retries=max_retries, exceptions=exceptions)
    async def _wrapped():
        return await func(*args, **kwargs)
    
    return await _wrapped()
