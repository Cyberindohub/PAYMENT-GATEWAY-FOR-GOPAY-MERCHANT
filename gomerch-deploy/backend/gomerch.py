"""Client for the GoMerch Pro (GoBiz merchant) API at pay.x-api.asia."""
import os
import base64
import httpx

BASE_URL = os.environ.get("GOMERCH_BASE_URL", "https://pay.x-api.asia").rstrip("/")


def _token() -> str:
    return os.environ.get("GOMERCH_TOKEN", "")


async def _post(path: str, payload: dict):
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(f"{BASE_URL}{path}", json=payload)
        try:
            data = r.json()
        except Exception:
            data = {"success": False, "error": r.text}
        return r.status_code, data


async def validate_token():
    return await _post("/api/validate", {"token": _token()})


async def get_profile():
    return await _post("/api/me", {"token": _token()})


async def get_history(start_time: str | None = None):
    payload = {"token": _token()}
    if start_time:
        payload["startTime"] = start_time
    return await _post("/api/history", payload)


async def get_payouts():
    return await _post("/api/payouts", {"token": _token()})


async def qris_status(amount: int, created_at: str):
    return await _post("/api/qris/status", {"token": _token(), "amount": amount, "created_at": created_at})


async def create_qris(amount: int, static_qr: str):
    """Returns (ok: bool, data_url_or_error). The endpoint returns a raw PNG."""
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{BASE_URL}/api/qris/create", params={"amount": amount, "static_qr": static_qr})
        ctype = r.headers.get("content-type", "")
        if r.status_code == 200 and ctype.startswith("image"):
            b64 = base64.b64encode(r.content).decode("utf-8")
            return True, f"data:image/png;base64,{b64}"
        try:
            err = r.json()
        except Exception:
            err = {"error": r.text[:300]}
        return False, err
