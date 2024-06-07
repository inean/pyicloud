from functools import wraps

from httpx import Request, Response


def process_cookies(handler):
    @wraps(handler)
    def wrapper(request: Request) -> Response:
        cookies = {}
        if "cookie" in request.headers:
            for pair in request.headers["cookie"].split("; "):
                cookies.update({pair.split("=")[0]: pair.split("=")[1]})
        request.cookies = cookies  # type: ignore
        return handler(request)

    return wrapper
