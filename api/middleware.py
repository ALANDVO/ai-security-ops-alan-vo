import time, logging
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict

logger = logging.getLogger(__name__)

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start
        logger.info("%s %s %.3fs %s", request.method, request.url.path, duration, response.status_code)
        response.headers["X-Process-Time"] = f"{duration:.4f}"
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 100, window: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window
        self.requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        now = time.time()
        self.requests[client] = [t for t in self.requests[client] if now - t < self.window]
        if len(self.requests[client]) >= self.max_requests:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        self.requests[client].append(now)
        return await call_next(request)

class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except Exception as e:
            logger.exception("Unhandled error: %s", str(e))
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=500, content={"detail": "Internal server error"})
