"""
Middleware: Rate Limiting + Audit Logging
──────────────────────────────────────────
"""

import os
import time
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv
from jose import jwt, JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .database import SessionLocal
from .models import AuditLog

logger = logging.getLogger("sit.middleware")

env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

JWT_SECRET = os.getenv("JWT_SECRET", "changeme-super-secret-key-2026")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


# ── Rate Limiter ──
class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window in-memory rate limiter (per-IP + endpoint-specific)."""

    def __init__(self, app, global_limit: int = 120, window: int = 60):
        super().__init__(app)
        self.global_limit = global_limit
        self.window = window
        self.buckets: Dict[str, List[float]] = defaultdict(list)
        self.endpoint_limits = {
            "/auth/login": 30,
            "/auth/password-hint": 10,
            "/scans": 40,
            "/reports": 40,
        }

    # Paths that must NEVER be rate-limited (health probes, root)
    EXEMPT_PATHS = frozenset({"/", "/health", "/openapi.json", "/docs", "/redoc"})

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health/docs paths so they always respond fast
        if request.url.path.rstrip("/") in self.EXEMPT_PATHS or request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        ip = request.client.host if request.client else "0.0.0.0"
        now = time.time()
        cutoff = now - self.window

        # Global limit
        gk = f"g:{ip}"
        self.buckets[gk] = [t for t in self.buckets[gk] if t > cutoff]
        if len(self.buckets[gk]) >= self.global_limit:
            return JSONResponse(status_code=429, content={"detail": "Too many requests. Slow down."})
        self.buckets[gk].append(now)

        # Endpoint limit (POST only)
        if request.method == "POST":
            path = request.url.path.rstrip("/")
            limit = self.endpoint_limits.get(path, self.global_limit)
            ek = f"e:{ip}:{path}"
            self.buckets[ek] = [t for t in self.buckets[ek] if t > cutoff]
            if len(self.buckets[ek]) >= limit:
                return JSONResponse(status_code=429, content={"detail": f"Rate limit exceeded for {path}"})
            self.buckets[ek].append(now)

        return await call_next(request)


# ── Audit Logger ──
class AuditLogMiddleware(BaseHTTPMiddleware):
    """Logs POST / PATCH / DELETE mutations to the audit_logs table."""

    # Paths that produce too much noise or must never block
    _SKIP_AUDIT = frozenset({"/health", "/", "/openapi.json", "/docs", "/redoc"})

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if request.method in ("POST", "PATCH", "DELETE") and request.url.path not in self._SKIP_AUDIT:
            actor = _extract_actor(request)
            ip = request.client.host if request.client else None
            ua = (request.headers.get("user-agent") or "")[:500] or None
            action = f"{request.method} {request.url.path}"
            target = str(request.url)

            try:
                db = SessionLocal()
                db.add(AuditLog(
                    actor_email=actor,
                    action=action,
                    target=target[:500],
                    ip_address=ip,
                    user_agent=ua,
                ))
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
            finally:
                try:
                    db.close()
                except Exception:
                    pass

        return response


def _extract_actor(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None
