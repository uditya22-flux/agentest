from fastapi import Request
from fastapi.responses import JSONResponse


async def auth_middleware(request: Request, call_next):
    # ✅ Allow public routes
    if request.url.path in ["/", "/health", "/favicon.ico"]:
        return await call_next(request)

    api_key = None

    # 1. Header
    api_key = request.headers.get("X-API-Key")

    # 2. Query param
    if not api_key:
        api_key = request.query_params.get("api_key")

    # ❌ DO NOT read body here (this was your bug)

    if api_key != "demo_key_001":
        return JSONResponse(
            status_code=403,
            content={"detail": "Invalid API key"}
        )

    return await call_next(request)