import contextvars
import re
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        raw_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        if raw_id and not re.match(r"^[a-zA-Z0-9\-_.]{1,128}$", raw_id):
            raw_id = str(uuid.uuid4())
        request_id = raw_id
        request.state.request_id = request_id
        _request_id_var.set(request_id)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
