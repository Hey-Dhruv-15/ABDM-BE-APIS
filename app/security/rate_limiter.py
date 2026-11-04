"""
Distributed rate limiting using Redis.
"""
import time
import asyncio
from typing import Dict, Tuple, Any, Optional
from fastapi import Request, HTTPException
import redis.asyncio as redis
from app.logging.logger import get_logger

logger = get_logger(__name__)

class RateLimiter:
    """
    Distributed rate limiter using Redis (Token Bucket / Fixed Window).
    Falls back to in-memory if Redis is unavailable.
    """

    def __init__(self, requests_per_minute: int = 60, redis_url: Optional[str] = None):
        self.requests_per_minute = requests_per_minute
        self.redis_url = redis_url
        self._redis: Optional[redis.Redis] = None
        
        # In-memory fallback: client_id -> (tokens, last_update_time)
        self._local_buckets: Dict[str, Tuple[float, float]] = {}

    async def _get_redis(self) -> Optional[redis.Redis]:
        """Lazy initialization of Redis connection."""
        if not self.redis_url:
            return None
            
        if self._redis is None:
            try:
                self._redis = redis.from_url(self.redis_url, decode_responses=True)
                # Test connection
                await self._redis.ping()
                logger.info("Connected to Redis for rate limiting", url=self.redis_url)
            except Exception as e:
                logger.error("Failed to connect to Redis, falling back to in-memory", error=str(e))
                self._redis = None
        return self._redis

    async def check_rate_limit(self, request: Request, identifier: Optional[str] = None):
        """
        Check if the request exceeds rate limits.
        """
        client_id = identifier or request.client.host
        
        # 1. Try Redis
        redis_client = await self._get_redis()
        if redis_client:
            try:
                return await self._check_redis(client_id)
            except Exception as e:
                logger.warning("Redis rate limit check failed, using fallback", error=str(e))
        
        # 2. Fallback to Local
        return self._check_local(client_id)

    async def _check_redis(self, client_id: str) -> bool:
        """Redis-based fixed window rate limiting."""
        key = f"rate_limit:{client_id}:{int(time.time() / 60)}"
        
        # Increment and set expiry if new
        async with self._redis.pipeline(transaction=True) as pipe:
            await pipe.incr(key)
            await pipe.expire(key, 60)
            results = await pipe.execute()
            
        count = results[0]
        if count > self.requests_per_minute:
            logger.warning("Rate limit exceeded (Redis)", client_id=client_id, count=count)
            raise HTTPException(status_code=429, detail="Too Many Requests")
        return True

    def _check_local(self, client_id: str) -> bool:
        """Local in-memory token bucket fallback."""
        now = time.time()
        tokens, last_update = self._local_buckets.get(client_id, (self.requests_per_minute, now))
        
        # Replenish tokens
        time_passed = now - last_update
        tokens = min(self.requests_per_minute, tokens + time_passed * (self.requests_per_minute / 60.0))
        
        if tokens < 1:
            logger.warning("Rate limit exceeded (Local)", client_id=client_id)
            raise HTTPException(status_code=429, detail="Too Many Requests")
        
        self._local_buckets[client_id] = (tokens - 1, now)
        return True
