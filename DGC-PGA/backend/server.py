from dotenv import load_dotenv
from pathlib import Path
import os

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime, timezone, timedelta
import uuid
import io
import csv
import base64
import logging
import random
import asyncio
import hmac
import pyotp

import auth as auth_lib
import rbac
import gomerch
import email_util

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gomerch")

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI(title="GoMerch Pro Payment Gateway")
api = APIRouter(prefix="/api")

PROJ = ["-_id"]  # helper marker


# ---------------------------------------------------------------- utils
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def clean(doc: dict) -> dict:
    if doc and "_id" in doc:
        doc = {k: v for k, v in doc.items() if k != "_id"}
    return doc


async def log_audit(actor, action, target="", before=None, after=None, ip=""):
    await db.audit_logs.insert_one({
        "id": gen_id("AUD"), "admin_id": actor.get("id") if actor else "system",
        "admin_email": actor.get("email") if actor else "system",
        "action": action, "target": target, "ip": ip,
        "before": before, "after": after, "timestamp": now_iso(),
    })


async def _email_enabled() -> bool:
    s = await db.system_settings.find_one({"id": "global"}, {"_id": 0}) or {}
    return s.get("email_notifications", True)


async def notify(merchant_id, title, message, kind="info"):
    await db.notifications.insert_one({
        "id": gen_id("NOT"), "merchant_id": merchant_id, "title": title,
        "message": message, "kind": kind, "read": False, "timestamp": now_iso(),
    })


# ---------------------------------------------------------------- auth deps
async def get_current_user(request: Request) -> dict:
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Tidak terautentikasi")
    try:
        payload = auth_lib.decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Tipe token tidak valid")
    except Exception:
        raise HTTPException(status_code=401, detail="Token tidak valid atau kedaluwarsa")
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="Pengguna tidak ditemukan")
    user = clean(user)
    user.pop("password_hash", None)
    user["permissions"] = rbac.permissions_for(user["role"])
    user["portal"] = rbac.portal_for(user["role"])
    return user


def require(permission: str):
    async def dep(user: dict = Depends(get_current_user)):
        if not rbac.has_permission(user["role"], permission):
            raise HTTPException(status_code=403, detail="Akses ditolak")
        return user
    return dep


def merchant_scope(user: dict):
    """Return a Mongo filter limiting to the user's own merchant if not admin role."""
    if user["role"] in rbac.MERCHANT_ROLES:
        return {"merchant_id": user.get("merchant_id")}
    return {}


# ---------------------------------------------------------------- models
class RegisterIn(BaseModel):
    name: str
    email: EmailStr
    password: str
    business_name: Optional[str] = None
    phone: Optional[str] = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class UserIn(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    status: Optional[str] = None
    password: Optional[str] = None


class MerchantUpdate(BaseModel):
    business_name: Optional[str] = None
    owner_name: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    fee_percent: Optional[float] = None
    limit: Optional[int] = None
    settlement_account: Optional[str] = None


class PaymentIn(BaseModel):
    amount: int
    merchant_reference: Optional[str] = None
    description: Optional[str] = None
    customer_name: Optional[str] = None
    customer_email: Optional[str] = None
    payment_method: str = "QRIS"


class RefundIn(BaseModel):
    payment_id: str
    amount: int
    reason: str
    partial: bool = False


class FeeIn(BaseModel):
    name: str
    method: str = "QRIS"
    percent: float = 0.7
    fixed: int = 0
    min_fee: int = 0
    max_fee: int = 0


class ApiKeyIn(BaseModel):
    label: str
    environment: str = "sandbox"


class WebhookIn(BaseModel):
    url: str
    events: List[str] = []


class BlacklistIn(BaseModel):
    type: str  # ip, email, merchant, customer, device
    value: str
    reason: Optional[str] = None
    list: str = "blacklist"  # blacklist | whitelist


class FraudRuleIn(BaseModel):
    name: str
    field: str
    operator: str
    value: str
    action: str = "flag"  # flag | block
    enabled: bool = True


class SettingsIn(BaseModel):
    gomerch_static_qr: Optional[str] = None
    default_fee_percent: Optional[float] = None
    settlement_schedule: Optional[str] = None
    company_name: Optional[str] = None
    withdrawal_min: Optional[int] = None
    withdrawal_fee_percent: Optional[float] = None
    withdrawal_admin_fee: Optional[int] = None
    gomerch_token: Optional[str] = None
    logo_url: Optional[str] = None
    email_notifications: Optional[bool] = None
    email_from_name: Optional[str] = None
    email_reply_to: Optional[str] = None
    auto_settlement: Optional[bool] = None


class WithdrawIn(BaseModel):
    amount: int
    bank_account: Optional[str] = None
    note: Optional[str] = None


class ReviewIn(BaseModel):
    approve: bool = True
    reason: Optional[str] = ""


class TotpCode(BaseModel):
    code: str


class MfaVerify(BaseModel):
    mfa_token: str
    code: str


# ================================================================ AUTH
def token_bundle(user):
    return {
        "access_token": auth_lib.create_access_token(user["id"], user["email"], user["role"]),
        "refresh_token": auth_lib.create_refresh_token(user["id"]),
        "user": {
            "id": user["id"], "name": user["name"], "email": user["email"],
            "role": user["role"], "merchant_id": user.get("merchant_id"),
            "role_label": rbac.ROLE_LABELS.get(user["role"], user["role"]),
            "portal": rbac.portal_for(user["role"]),
            "permissions": rbac.permissions_for(user["role"]),
        },
    }


@api.post("/auth/register")
async def register(body: RegisterIn):
    email = body.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="Email sudah terdaftar")
    merchant_id = gen_id("MER")
    now = now_iso()
    await db.merchants.insert_one({
        "id": merchant_id, "business_name": body.business_name or body.name,
        "owner_name": body.name, "email": email, "phone": body.phone or "",
        "address": "", "kyc_status": "PENDING", "account_status": "PENDING",
        "api_status": "inactive", "fee_percent": 0.7, "limit": 50000000,
        "settlement_account": "", "static_qr": "",
        "available_balance": 0, "pending_balance": 0, "settled_balance": 0,
        "created_at": now, "last_activity": now,
    })
    user = {
        "id": str(uuid.uuid4()), "name": body.name, "email": email,
        "password_hash": auth_lib.hash_password(body.password), "role": "merchant",
        "merchant_id": merchant_id, "status": "active", "created_at": now,
    }
    await db.users.insert_one(user)
    return token_bundle(user)


@api.post("/auth/login")
async def login(body: LoginIn, request: Request):
    email = body.email.lower()
    ident = email
    now = datetime.now(timezone.utc)
    attempt = await db.login_attempts.find_one({"identifier": ident})
    if attempt and attempt.get("count", 0) >= 5:
        locked_until = attempt.get("locked_until")
        if locked_until and locked_until > now.isoformat():
            raise HTTPException(status_code=429, detail="Terlalu banyak percobaan. Coba lagi dalam 15 menit.")
        # lock window expired -> reset counter
        await db.login_attempts.delete_one({"identifier": ident})
        attempt = None
    user = await db.users.find_one({"email": email})
    if not user or not auth_lib.verify_password(body.password, user["password_hash"]):
        count = (attempt.get("count", 0) if attempt else 0) + 1
        upd = {"count": count}
        if count >= 5:
            upd["locked_until"] = (now + timedelta(minutes=15)).isoformat()
        await db.login_attempts.update_one({"identifier": ident}, {"$set": upd}, upsert=True)
        raise HTTPException(status_code=401, detail="Email atau kata sandi salah")
    await db.login_attempts.delete_one({"identifier": ident})
    if user.get("totp_enabled"):
        return {"mfa_required": True, "mfa_token": auth_lib.create_mfa_token(user["id"])}
    await log_audit(clean(user), "user.login", user["email"], ip=request.client.host)
    bundle = token_bundle(user)
    if rbac.portal_for(user["role"]) == "admin" and not user.get("totp_enabled"):
        bundle["require_2fa_setup"] = True
    return {"mfa_required": False, **bundle}


@api.post("/auth/refresh")
async def refresh(request: Request):
    body = await request.json()
    rt = body.get("refresh_token")
    if not rt:
        raise HTTPException(status_code=401, detail="Refresh token kosong")
    try:
        payload = auth_lib.decode_token(rt)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Token tidak valid")
    except Exception:
        raise HTTPException(status_code=401, detail="Refresh token tidak valid")
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="Pengguna tidak ditemukan")
    return token_bundle(user)


@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {
        "id": user["id"], "name": user["name"], "email": user["email"],
        "role": user["role"], "role_label": rbac.ROLE_LABELS.get(user["role"], user["role"]),
        "merchant_id": user.get("merchant_id"), "portal": user["portal"],
        "permissions": user["permissions"],
        "totp_enabled": bool(user.get("totp_enabled")),
        "require_2fa_setup": user["portal"] == "admin" and not user.get("totp_enabled"),
    }


@api.post("/auth/login/mfa")
async def login_mfa(body: MfaVerify):
    try:
        payload = auth_lib.decode_token(body.mfa_token)
        if payload.get("type") != "mfa":
            raise ValueError()
    except Exception:
        raise HTTPException(status_code=401, detail="Sesi verifikasi tidak valid atau kedaluwarsa")
    u = await db.users.find_one({"id": payload["sub"]})
    if not u or not u.get("totp_enabled") or not u.get("totp_secret_enc"):
        raise HTTPException(status_code=401, detail="Sesi verifikasi tidak valid")
    ident = f"mfa:{u['id']}"
    now = datetime.now(timezone.utc)
    attempt = await db.login_attempts.find_one({"identifier": ident})
    if attempt and attempt.get("count", 0) >= 5:
        locked_until = attempt.get("locked_until")
        if locked_until and locked_until > now.isoformat():
            raise HTTPException(status_code=429, detail="Terlalu banyak percobaan. Coba lagi dalam 15 menit.")
        await db.login_attempts.delete_one({"identifier": ident})
        attempt = None
    secret = auth_lib.decrypt_secret(u["totp_secret_enc"])
    if not pyotp.TOTP(secret).verify(body.code, valid_window=1):
        count = (attempt.get("count", 0) if attempt else 0) + 1
        upd = {"count": count}
        if count >= 5:
            upd["locked_until"] = (now + timedelta(minutes=15)).isoformat()
        await db.login_attempts.update_one({"identifier": ident}, {"$set": upd}, upsert=True)
        raise HTTPException(status_code=401, detail="Kode autentikasi salah")
    await db.login_attempts.delete_one({"identifier": ident})
    return token_bundle(u)


@api.get("/auth/2fa/status")
async def twofa_status(user: dict = Depends(get_current_user)):
    u = await db.users.find_one({"id": user["id"]})
    return {"enabled": bool(u.get("totp_enabled"))}


@api.post("/auth/2fa/setup")
async def twofa_setup(user: dict = Depends(get_current_user)):
    u = await db.users.find_one({"id": user["id"]})
    if u and u.get("totp_enabled"):
        raise HTTPException(status_code=400, detail="2FA sudah aktif. Nonaktifkan terlebih dahulu untuk mengatur ulang.")
    secret = pyotp.random_base32()
    await db.users.update_one({"id": user["id"]}, {"$set": {"totp_pending_secret_enc": auth_lib.encrypt_secret(secret)}})
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="GoMerch Pro")
    return {"secret": secret, "otpauth_uri": uri}


@api.post("/auth/2fa/enable")
async def twofa_enable(body: TotpCode, user: dict = Depends(get_current_user)):
    u = await db.users.find_one({"id": user["id"]})
    if not u or not u.get("totp_pending_secret_enc"):
        raise HTTPException(status_code=400, detail="Mulai setup 2FA terlebih dahulu")
    secret = auth_lib.decrypt_secret(u["totp_pending_secret_enc"])
    if not pyotp.TOTP(secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Kode tidak valid")
    await db.users.update_one({"id": user["id"]}, {
        "$set": {"totp_secret_enc": u["totp_pending_secret_enc"], "totp_enabled": True},
        "$unset": {"totp_pending_secret_enc": ""},
    })
    await log_audit(user, "user.2fa.enable", user["email"])
    return {"enabled": True}


@api.post("/auth/2fa/disable")
async def twofa_disable(body: TotpCode, user: dict = Depends(get_current_user)):
    u = await db.users.find_one({"id": user["id"]})
    if not u or not u.get("totp_enabled"):
        return {"enabled": False}
    secret = auth_lib.decrypt_secret(u["totp_secret_enc"])
    if not pyotp.TOTP(secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Kode tidak valid")
    await db.users.update_one({"id": user["id"]}, {"$set": {"totp_enabled": False}, "$unset": {"totp_secret_enc": ""}})
    await log_audit(user, "user.2fa.disable", user["email"])
    return {"enabled": False}


@api.get("/roles")
async def roles(user: dict = Depends(require("user.read"))):
    return {"roles": [{"id": k, "label": rbac.ROLE_LABELS[k], "permissions": rbac.permissions_for(k)}
                      for k in rbac.ROLE_LABELS]}


# ================================================================ MERCHANTS
@api.get("/merchants")
async def list_merchants(user: dict = Depends(require("merchant.read")), status: Optional[str] = None):
    q = merchant_scope(user)
    if status:
        q["account_status"] = status
    docs = await db.merchants.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)
    return docs


@api.get("/merchants/{mid}")
async def get_merchant(mid: str, user: dict = Depends(require("merchant.read"))):
    if user["role"] in rbac.MERCHANT_ROLES and user.get("merchant_id") != mid:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    doc = await db.merchants.find_one({"id": mid}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Merchant tidak ditemukan")
    return doc


@api.patch("/merchants/{mid}")
async def update_merchant(mid: str, body: MerchantUpdate, request: Request, user: dict = Depends(get_current_user)):
    own = user["role"] in rbac.MERCHANT_ROLES and user.get("merchant_id") == mid
    if not own and not rbac.has_permission(user["role"], "merchant.update"):
        raise HTTPException(status_code=403, detail="Akses ditolak")
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if updates:
        await db.merchants.update_one({"id": mid}, {"$set": updates})
        await log_audit(user, "merchant.update", mid, after=updates, ip=request.client.host)
    return await db.merchants.find_one({"id": mid}, {"_id": 0})


@api.post("/merchants/{mid}/approve")
async def approve_merchant(mid: str, request: Request, user: dict = Depends(require("merchant.approve"))):
    await db.merchants.update_one({"id": mid}, {"$set": {"account_status": "ACTIVE", "kyc_status": "APPROVED", "api_status": "active"}})
    await log_audit(user, "merchant.approve", mid, ip=request.client.host)
    await notify(mid, "Merchant disetujui", "Akun merchant Anda telah aktif.", "success")
    return await db.merchants.find_one({"id": mid}, {"_id": 0})


@api.post("/merchants/{mid}/suspend")
async def suspend_merchant(mid: str, request: Request, user: dict = Depends(require("merchant.suspend"))):
    await db.merchants.update_one({"id": mid}, {"$set": {"account_status": "SUSPENDED", "api_status": "inactive"}})
    await log_audit(user, "merchant.suspend", mid, ip=request.client.host)
    return await db.merchants.find_one({"id": mid}, {"_id": 0})


@api.post("/merchants/{mid}/kyc")
async def review_kyc(mid: str, request: Request, user: dict = Depends(require("kyc.review"))):
    body = await request.json()
    status = body.get("status", "APPROVED")
    reason = body.get("reason", "")
    await db.merchants.update_one({"id": mid}, {"$set": {"kyc_status": status, "kyc_reason": reason}})
    await log_audit(user, "kyc.review", mid, after={"status": status, "reason": reason}, ip=request.client.host)
    return await db.merchants.find_one({"id": mid}, {"_id": 0})


# ================================================================ PAYMENTS
async def _fee_for(method: str, amount: int, merchant: dict) -> int:
    fee_cfg = await db.fees.find_one({"method": method}, {"_id": 0})
    percent = merchant.get("fee_percent") if merchant else None
    if fee_cfg:
        percent = fee_cfg.get("percent", percent)
        fixed = fee_cfg.get("fixed", 0)
        mn, mx = fee_cfg.get("min_fee", 0), fee_cfg.get("max_fee", 0)
    else:
        percent = percent or 0.7
        fixed, mn, mx = 0, 0, 0
    fee = int(round(amount * (percent / 100.0))) + fixed
    if mn and fee < mn:
        fee = mn
    if mx and fee > mx:
        fee = mx
    return fee


@api.post("/payments")
async def create_payment(body: PaymentIn, request: Request, user: dict = Depends(require("payment.create"))):
    if body.amount <= 0:
        raise HTTPException(status_code=422, detail="Nominal harus lebih dari 0")
    mid = user.get("merchant_id")
    merchant = await db.merchants.find_one({"id": mid}, {"_id": 0}) or {}
    # Idempotency
    idem = request.headers.get("Idempotency-Key")
    if idem:
        existing = await db.payments.find_one({"merchant_id": mid, "idempotency_key": idem}, {"_id": 0})
        if existing:
            return existing
    fee = await _fee_for(body.payment_method, body.amount, merchant)
    # Central QRIS: all merchants collect via the platform's GoMerch merchant account.
    settings_doc = await db.system_settings.find_one({"id": "global"}, {"_id": 0}) or {}
    static_qr = settings_doc.get("gomerch_static_qr", "")
    created_at = now_iso()
    pay_id = gen_id("PAY")
    qr_image = None
    qr_source = "local"
    if static_qr:
        ok, result = await gomerch.create_qris(body.amount, static_qr)
        if ok:
            qr_image = result
            qr_source = "gomerch"
        else:
            logger.warning(f"GoMerch QRIS create failed: {result}")
    doc = {
        "id": pay_id, "merchant_id": mid,
        "merchant_reference": body.merchant_reference or gen_id("ORDER"),
        "amount": body.amount, "fee": fee, "net_amount": body.amount - fee,
        "currency": "IDR", "payment_method": body.payment_method,
        "status": "PENDING", "description": body.description or "",
        "customer_name": body.customer_name or "", "customer_email": body.customer_email or "",
        "qr_image": qr_image, "qr_source": qr_source, "static_qr": static_qr,
        "idempotency_key": idem, "risk": "LOW",
        "created_at": created_at, "updated_at": created_at, "paid_at": None,
    }
    await db.payments.insert_one(doc)
    await log_audit(user, "payment.create", pay_id, after={"amount": body.amount}, ip=request.client.host)
    return clean(doc)


@api.get("/payments")
async def list_payments(user: dict = Depends(require("payment.read")), status: Optional[str] = None, search: Optional[str] = None):
    q = merchant_scope(user)
    if status:
        q["status"] = status
    if search:
        q["$or"] = [{"id": {"$regex": search, "$options": "i"}},
                    {"merchant_reference": {"$regex": search, "$options": "i"}}]
    docs = await db.payments.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)
    return docs


@api.get("/payments/{pid}")
async def get_payment(pid: str, user: dict = Depends(require("payment.read"))):
    q = {"id": pid, **merchant_scope(user)}
    doc = await db.payments.find_one(q, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Pembayaran tidak ditemukan")
    return doc


async def _mark_paid(payment: dict, matched=None):
    now = now_iso()
    await db.payments.update_one({"id": payment["id"]}, {"$set": {"status": "PAID", "paid_at": now, "updated_at": now}})
    trx_id = gen_id("TRX")
    await db.transactions.insert_one({
        "id": trx_id, "payment_id": payment["id"], "merchant_id": payment["merchant_id"],
        "merchant_reference": payment["merchant_reference"], "amount": payment["amount"],
        "fee": payment["fee"], "net_amount": payment["net_amount"], "currency": "IDR",
        "payment_method": payment["payment_method"], "status": "PAID",
        "customer_reference": payment.get("customer_name", ""),
        "settlement_status": "PENDING", "callback_status": "sent",
        "timestamp": now, "source": "gomerch" if matched else "system",
    })
    # ledger entries
    m = await db.merchants.find_one({"id": payment["merchant_id"]})
    before = (m or {}).get("pending_balance", 0)
    await db.merchants.update_one({"id": payment["merchant_id"]},
                                  {"$inc": {"pending_balance": payment["net_amount"]},
                                   "$set": {"last_activity": now}})
    await db.ledger_entries.insert_many([
        {"id": gen_id("LGR"), "merchant_id": payment["merchant_id"], "transaction_id": trx_id,
         "type": "PENDING_BALANCE", "amount": payment["net_amount"], "direction": "CREDIT",
         "balance_before": before, "balance_after": before + payment["net_amount"],
         "description": f"Pembayaran {payment['id']}", "timestamp": now},
        {"id": gen_id("LGR"), "merchant_id": payment["merchant_id"], "transaction_id": trx_id,
         "type": "FEE", "amount": payment["fee"], "direction": "DEBIT",
         "balance_before": 0, "balance_after": 0,
         "description": f"Biaya transaksi {payment['id']}", "timestamp": now},
    ])
    # webhook delivery simulation
    hooks = await db.webhooks.find({"merchant_id": payment["merchant_id"], "active": True}).to_list(20)
    for h in hooks:
        await db.webhook_deliveries.insert_one({
            "id": gen_id("EVT"), "webhook_id": h["id"], "merchant_id": payment["merchant_id"],
            "event": "payment.paid", "payment_id": payment["id"], "url": h["url"],
            "http_status": 200, "response": "OK", "latency_ms": random.randint(80, 400),
            "retry_count": 0, "status": "delivered", "timestamp": now,
        })
    await notify(payment["merchant_id"], "Pembayaran berhasil",
                 f"Pembayaran {payment['id']} sebesar Rp {payment['amount']:,} telah diterima.", "success")
    m3 = await db.merchants.find_one({"id": payment["merchant_id"]}, {"_id": 0}) or {}
    if m3.get("email") and await _email_enabled():
        subj, html = email_util.tpl_payment_received(m3.get("business_name", ""), payment["id"], payment["amount"], payment.get("net_amount", payment["amount"]))
        await email_util.safe_send(m3["email"], subj, html)


@api.get("/payments/{pid}/status")
async def payment_status(pid: str, user: dict = Depends(require("payment.read"))):
    q = {"id": pid, **merchant_scope(user)}
    payment = await db.payments.find_one(q, {"_id": 0})
    if not payment:
        raise HTTPException(status_code=404, detail="Pembayaran tidak ditemukan")
    if payment["status"] == "PAID":
        return {"status": "PAID", "payment": payment}
    # check expiry (30 min)
    created = datetime.fromisoformat(payment["created_at"])
    if datetime.now(timezone.utc) - created > timedelta(minutes=30):
        await db.payments.update_one({"id": pid}, {"$set": {"status": "EXPIRED", "updated_at": now_iso()}})
        return {"status": "EXPIRED", "payment": payment}
    # ask GoMerch
    code, data = await gomerch.qris_status(payment["amount"], payment["created_at"])
    status = "PENDING"
    if isinstance(data, dict) and data.get("status") == "PAID":
        status = "PAID"
        await _mark_paid(payment, matched=data.get("data"))
    fresh = await db.payments.find_one({"id": pid}, {"_id": 0})
    return {"status": fresh["status"], "payment": fresh}


@api.post("/payments/{pid}/cancel")
async def cancel_payment(pid: str, request: Request, user: dict = Depends(require("payment.cancel"))):
    q = {"id": pid, **merchant_scope(user)}
    payment = await db.payments.find_one(q, {"_id": 0})
    if not payment:
        raise HTTPException(status_code=404, detail="Pembayaran tidak ditemukan")
    if payment["status"] not in ("PENDING", "CREATED"):
        raise HTTPException(status_code=409, detail="Pembayaran tidak dapat dibatalkan")
    await db.payments.update_one({"id": pid}, {"$set": {"status": "CANCELLED", "updated_at": now_iso()}})
    await log_audit(user, "payment.cancel", pid, ip=request.client.host)
    return await db.payments.find_one({"id": pid}, {"_id": 0})


# force-paid for demo/testing (merchant simulates a customer paying)
@api.post("/payments/{pid}/simulate-paid")
async def simulate_paid(pid: str, user: dict = Depends(require("payment.create"))):
    q = {"id": pid, **merchant_scope(user)}
    payment = await db.payments.find_one(q, {"_id": 0})
    if not payment:
        raise HTTPException(status_code=404, detail="Pembayaran tidak ditemukan")
    if payment["status"] != "PAID":
        await _mark_paid(payment)
    return await db.payments.find_one({"id": pid}, {"_id": 0})


# ================================================================ TRANSACTIONS
@api.get("/transactions")
async def list_transactions(user: dict = Depends(require("transaction.read")), status: Optional[str] = None,
                            method: Optional[str] = None, search: Optional[str] = None):
    q = merchant_scope(user)
    if status:
        q["status"] = status
    if method:
        q["payment_method"] = method
    if search:
        q["$or"] = [{"id": {"$regex": search, "$options": "i"}},
                    {"merchant_reference": {"$regex": search, "$options": "i"}}]
    return await db.transactions.find(q, {"_id": 0}).sort("timestamp", -1).to_list(1000)


@api.get("/transactions/{tid}")
async def get_transaction(tid: str, user: dict = Depends(require("transaction.read"))):
    doc = await db.transactions.find_one({"id": tid, **merchant_scope(user)}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Transaksi tidak ditemukan")
    return doc


# ================================================================ REFUNDS
@api.get("/refunds")
async def list_refunds(user: dict = Depends(require("refund.read"))):
    return await db.refunds.find(merchant_scope(user), {"_id": 0}).sort("created_at", -1).to_list(500)


@api.post("/refunds")
async def create_refund(body: RefundIn, request: Request, user: dict = Depends(require("refund.create"))):
    payment = await db.payments.find_one({"id": body.payment_id, **merchant_scope(user)}, {"_id": 0})
    if not payment:
        raise HTTPException(status_code=404, detail="Pembayaran tidak ditemukan")
    if payment["status"] != "PAID":
        raise HTTPException(status_code=409, detail="Hanya transaksi PAID yang dapat direfund")
    doc = {
        "id": gen_id("REF"), "merchant_id": user.get("merchant_id"), "payment_id": body.payment_id,
        "amount": body.amount, "reason": body.reason, "partial": body.partial,
        "status": "PENDING", "created_at": now_iso(),
    }
    await db.refunds.insert_one(doc)
    await log_audit(user, "refund.create", doc["id"], after={"amount": body.amount}, ip=request.client.host)
    return clean(doc)


@api.post("/refunds/{rid}/approve")
async def approve_refund(rid: str, request: Request, body: Optional[ReviewIn] = None, user: dict = Depends(require("refund.approve"))):
    approve = body.approve if body else True
    refund = await db.refunds.find_one({"id": rid}, {"_id": 0})
    if not refund:
        raise HTTPException(status_code=404, detail="Refund tidak ditemukan")
    new_status = "COMPLETED" if approve else "REJECTED"
    await db.refunds.update_one({"id": rid}, {"$set": {"status": new_status, "reviewed_at": now_iso()}})
    if approve:
        payment = await db.payments.find_one({"id": refund["payment_id"]}, {"_id": 0})
        pstatus = "PARTIALLY_REFUNDED" if refund.get("partial") else "REFUNDED"
        await db.payments.update_one({"id": refund["payment_id"]}, {"$set": {"status": pstatus}})
        await db.transactions.update_one({"payment_id": refund["payment_id"]}, {"$set": {"status": pstatus}})
        await notify(refund["merchant_id"], "Refund diproses", f"Refund {rid} telah disetujui.", "info")
    await log_audit(user, "refund.approve", rid, after={"status": new_status}, ip=request.client.host)
    return await db.refunds.find_one({"id": rid}, {"_id": 0})


# ================================================================ SETTLEMENT / PAYOUTS
@api.get("/settlements")
async def list_settlements(user: dict = Depends(require("settlement.read"))):
    local = await db.settlements.find(merchant_scope(user), {"_id": 0}).sort("created_at", -1).to_list(200)
    return local


@api.post("/settlements")
async def create_settlement(request: Request, user: dict = Depends(require("settlement.approve"))):
    body = await request.json()
    mid = body.get("merchant_id")
    merchant = await db.merchants.find_one({"id": mid}, {"_id": 0})
    if not merchant:
        raise HTTPException(status_code=404, detail="Merchant tidak ditemukan")
    amount = merchant.get("pending_balance", 0)
    if amount <= 0:
        raise HTTPException(status_code=422, detail="Tidak ada saldo pending untuk disettle")
    now = now_iso()
    doc = {"id": gen_id("STL"), "merchant_id": mid, "amount": amount, "status": "COMPLETED",
           "account": merchant.get("settlement_account", ""), "created_at": now, "completed_at": now}
    await db.settlements.insert_one(doc)
    await db.merchants.update_one({"id": mid}, {"$inc": {"pending_balance": -amount, "settled_balance": amount, "available_balance": amount}})
    await db.ledger_entries.insert_one({
        "id": gen_id("LGR"), "merchant_id": mid, "transaction_id": doc["id"],
        "type": "SETTLED_BALANCE", "amount": amount, "direction": "CREDIT",
        "balance_before": 0, "balance_after": amount,
        "description": f"Settlement {doc['id']}", "timestamp": now})
    await log_audit(user, "settlement.create", doc["id"], after={"amount": amount}, ip=request.client.host)
    await notify(mid, "Settlement selesai", f"Dana Rp {amount:,} telah disettle.", "success")
    return clean(doc)


@api.get("/payouts")
async def payouts(user: dict = Depends(require("settlement.read"))):
    code, data = await gomerch.get_payouts()
    return {"success": data.get("success", False) if isinstance(data, dict) else False, "data": data.get("data") if isinstance(data, dict) else data}


# ================================================================ WITHDRAWALS (merchant -> admin approval)
@api.get("/withdrawals")
async def list_withdrawals(user: dict = Depends(require("withdrawal.read")), status: Optional[str] = None):
    q = merchant_scope(user)
    if status:
        q["status"] = status
    docs = await db.withdrawals.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)
    if user["role"] not in rbac.MERCHANT_ROLES:
        # enrich with merchant name for admin view
        names = {m["id"]: m["business_name"] for m in await db.merchants.find({}, {"_id": 0, "id": 1, "business_name": 1}).to_list(2000)}
        for d in docs:
            d["merchant_name"] = names.get(d["merchant_id"], d["merchant_id"])
    return docs


@api.post("/withdrawals")
async def create_withdrawal(body: WithdrawIn, request: Request, user: dict = Depends(require("withdrawal.create"))):
    mid = user.get("merchant_id")
    merchant = await db.merchants.find_one({"id": mid}, {"_id": 0}) or {}
    available = merchant.get("available_balance", 0)
    pend = await db.withdrawals.find({"merchant_id": mid, "status": "PENDING"}, {"_id": 0}).to_list(500)
    held = sum(w["amount"] for w in pend)
    settings = await db.system_settings.find_one({"id": "global"}, {"_id": 0}) or {}
    wd_min = settings.get("withdrawal_min", 50000)
    fee_pct = settings.get("withdrawal_fee_percent", 0.40)
    admin_fee = settings.get("withdrawal_admin_fee", 4500)
    if body.amount <= 0:
        raise HTTPException(status_code=422, detail="Nominal harus lebih dari 0")
    if body.amount < wd_min:
        raise HTTPException(status_code=422, detail=f"Minimum penarikan Rp {wd_min:,}".replace(",", "."))
    if body.amount > available - held:
        maks = f"{available - held:,}".replace(",", ".")
        raise HTTPException(status_code=422, detail=f"Saldo tersedia tidak cukup (maks Rp {maks})")
    fee = int(round(body.amount * (fee_pct / 100.0))) + admin_fee
    net = body.amount - fee
    doc = {
        "id": gen_id("WDR"), "merchant_id": mid, "amount": body.amount,
        "fee": fee, "fee_percent": fee_pct, "admin_fee": admin_fee, "net_amount": net,
        "bank_account": body.bank_account or merchant.get("settlement_account", ""),
        "note": body.note or "", "status": "PENDING", "created_at": now_iso(),
        "reviewed_at": None, "reviewed_by": None, "reject_reason": None,
    }
    await db.withdrawals.insert_one(doc)
    await log_audit(user, "withdrawal.request", doc["id"], after={"amount": body.amount}, ip=request.client.host)
    await notify(mid, "Permintaan penarikan dikirim", f"Penarikan Rp {body.amount:,} (diterima Rp {net:,}) menunggu persetujuan admin.".replace(",", "."), "info")
    return clean(doc)


@api.post("/withdrawals/{wid}/approve")
async def approve_withdrawal(wid: str, request: Request, body: Optional[ReviewIn] = None, user: dict = Depends(require("withdrawal.approve"))):
    approve = body.approve if body else True
    reason = body.reason if body else ""
    w = await db.withdrawals.find_one({"id": wid}, {"_id": 0})
    if not w:
        raise HTTPException(status_code=404, detail="Penarikan tidak ditemukan")
    if w["status"] != "PENDING":
        raise HTTPException(status_code=409, detail="Penarikan sudah diproses")
    now = now_iso()
    if approve:
        m = await db.merchants.find_one({"id": w["merchant_id"]})
        avail = (m or {}).get("available_balance", 0)
        if w["amount"] > avail:
            raise HTTPException(status_code=422, detail="Saldo merchant tidak mencukupi")
        net = w.get("net_amount", w["amount"])
        await db.merchants.update_one({"id": w["merchant_id"]}, {"$inc": {"available_balance": -w["amount"]}, "$set": {"last_activity": now}})
        await db.ledger_entries.insert_one({
            "id": gen_id("LGR"), "merchant_id": w["merchant_id"], "transaction_id": wid,
            "type": "WITHDRAWAL", "amount": w["amount"], "direction": "DEBIT",
            "balance_before": avail, "balance_after": avail - w["amount"],
            "description": f"Penarikan dana {wid} (net Rp {net:,})".replace(",", "."), "timestamp": now})
        await db.withdrawals.update_one({"id": wid}, {"$set": {"status": "COMPLETED", "reviewed_at": now, "reviewed_by": user["email"]}})
        await notify(w["merchant_id"], "Penarikan disetujui", f"Penarikan Rp {w['amount']:,} disetujui. Dana bersih Rp {net:,} dikirim ke {w['bank_account'] or 'rekening Anda'}.".replace(",", "."), "success")
        if m and m.get("email") and await _email_enabled():
            subj, html = email_util.tpl_withdrawal_approved(m.get("business_name", ""), wid, w["amount"], net, w.get("bank_account", ""))
            await email_util.safe_send(m["email"], subj, html)
    else:
        m = await db.merchants.find_one({"id": w["merchant_id"]}, {"_id": 0})
        await db.withdrawals.update_one({"id": wid}, {"$set": {"status": "REJECTED", "reviewed_at": now, "reviewed_by": user["email"], "reject_reason": reason}})
        await notify(w["merchant_id"], "Penarikan ditolak", f"Penarikan Rp {w['amount']:,} ditolak. {reason}".replace(",", "."), "warning")
        if m and m.get("email") and await _email_enabled():
            subj, html = email_util.tpl_withdrawal_rejected(m.get("business_name", ""), wid, w["amount"], reason)
            await email_util.safe_send(m["email"], subj, html)
    await log_audit(user, f"withdrawal.{'approve' if approve else 'reject'}", wid, ip=request.client.host)
    return await db.withdrawals.find_one({"id": wid}, {"_id": 0})


# ================================================================ LEDGER / BALANCE
@api.get("/withdrawal-config")
async def withdrawal_config(user: dict = Depends(require("withdrawal.read"))):
    s = await db.system_settings.find_one({"id": "global"}, {"_id": 0}) or {}
    return {"min": s.get("withdrawal_min", 50000),
            "fee_percent": s.get("withdrawal_fee_percent", 0.40),
            "admin_fee": s.get("withdrawal_admin_fee", 4500)}


@api.get("/ledger")
async def ledger(user: dict = Depends(require("ledger.read"))):
    return await db.ledger_entries.find(merchant_scope(user), {"_id": 0}).sort("timestamp", -1).to_list(1000)


@api.get("/balance")
async def balance(user: dict = Depends(require("ledger.read"))):
    if user["role"] in rbac.MERCHANT_ROLES:
        m = await db.merchants.find_one({"id": user.get("merchant_id")}, {"_id": 0}) or {}
        return {"available_balance": m.get("available_balance", 0), "pending_balance": m.get("pending_balance", 0),
                "settled_balance": m.get("settled_balance", 0)}
    agg = await db.merchants.aggregate([{"$group": {"_id": None,
        "available_balance": {"$sum": "$available_balance"}, "pending_balance": {"$sum": "$pending_balance"},
        "settled_balance": {"$sum": "$settled_balance"}}}]).to_list(1)
    return clean(agg[0]) if agg else {"available_balance": 0, "pending_balance": 0, "settled_balance": 0}


# ================================================================ FEES
@api.get("/fees")
async def list_fees(user: dict = Depends(require("fee.read"))):
    return await db.fees.find({}, {"_id": 0}).to_list(100)


@api.post("/fees")
async def create_fee(body: FeeIn, request: Request, user: dict = Depends(require("fee.update"))):
    doc = {"id": gen_id("FEE"), **body.model_dump(), "created_at": now_iso()}
    await db.fees.insert_one(doc)
    await log_audit(user, "fee.create", doc["id"], after=body.model_dump(), ip=request.client.host)
    return clean(doc)


@api.patch("/fees/{fid}")
async def update_fee(fid: str, body: FeeIn, request: Request, user: dict = Depends(require("fee.update"))):
    await db.fees.update_one({"id": fid}, {"$set": body.model_dump()})
    await log_audit(user, "fee.update", fid, after=body.model_dump(), ip=request.client.host)
    return await db.fees.find_one({"id": fid}, {"_id": 0})


@api.delete("/fees/{fid}")
async def delete_fee(fid: str, user: dict = Depends(require("fee.update"))):
    await db.fees.delete_one({"id": fid})
    return {"success": True}


# ================================================================ API KEYS
@api.get("/api-keys")
async def list_keys(user: dict = Depends(require("api.read"))):
    docs = await db.api_keys.find(merchant_scope(user), {"_id": 0}).sort("created_at", -1).to_list(100)
    # Mask secret for admin/staff (non-owner) reads — merchants see their own full secret
    if user["role"] in rbac.ADMIN_ROLES:
        for d in docs:
            if d.get("api_secret"):
                d["api_secret"] = d["api_secret"][:10] + "••••••••••••"
    return docs


@api.post("/api-keys")
async def create_key(body: ApiKeyIn, request: Request, user: dict = Depends(require("api.create"))):
    prefix = "sk_test_" if body.environment == "sandbox" else "sk_live_"
    doc = {"id": gen_id("KEY"), "merchant_id": user.get("merchant_id"), "label": body.label,
           "environment": body.environment, "api_key": f"pk_{uuid.uuid4().hex[:20]}",
           "api_secret": f"{prefix}{uuid.uuid4().hex}", "status": "active", "created_at": now_iso(),
           "last_used": None}
    await db.api_keys.insert_one(doc)
    await log_audit(user, "api.create", doc["id"], ip=request.client.host)
    return clean(doc)


@api.post("/api-keys/{kid}/regenerate")
async def regenerate_key(kid: str, request: Request, user: dict = Depends(require("api.create"))):
    key = await db.api_keys.find_one({"id": kid, **merchant_scope(user)}, {"_id": 0})
    if not key:
        raise HTTPException(status_code=404, detail="API key tidak ditemukan")
    prefix = "sk_test_" if key["environment"] == "sandbox" else "sk_live_"
    new_secret = f"{prefix}{uuid.uuid4().hex}"
    await db.api_keys.update_one({"id": kid}, {"$set": {"api_secret": new_secret}})
    await log_audit(user, "api.regenerate", kid, ip=request.client.host)
    return await db.api_keys.find_one({"id": kid}, {"_id": 0})


@api.delete("/api-keys/{kid}")
async def revoke_key(kid: str, user: dict = Depends(require("api.revoke"))):
    await db.api_keys.update_one({"id": kid, **merchant_scope(user)}, {"$set": {"status": "revoked"}})
    return {"success": True}


# ================================================================ WEBHOOKS
@api.get("/webhooks")
async def list_webhooks(user: dict = Depends(require("webhook.read"))):
    return await db.webhooks.find(merchant_scope(user), {"_id": 0}).sort("created_at", -1).to_list(100)


@api.post("/webhooks")
async def create_webhook(body: WebhookIn, user: dict = Depends(require("webhook.create"))):
    doc = {"id": gen_id("WHK"), "merchant_id": user.get("merchant_id"), "url": body.url,
           "events": body.events or ["payment.paid"], "secret": f"whsec_{uuid.uuid4().hex}",
           "active": True, "created_at": now_iso()}
    await db.webhooks.insert_one(doc)
    return clean(doc)


@api.patch("/webhooks/{wid}")
async def update_webhook(wid: str, user: dict = Depends(require("webhook.update")), request: Request = None):
    body = await request.json()
    updates = {k: v for k, v in body.items() if k in ("url", "events", "active")}
    await db.webhooks.update_one({"id": wid, **merchant_scope(user)}, {"$set": updates})
    return await db.webhooks.find_one({"id": wid}, {"_id": 0})


@api.delete("/webhooks/{wid}")
async def delete_webhook(wid: str, user: dict = Depends(require("webhook.update"))):
    await db.webhooks.delete_one({"id": wid, **merchant_scope(user)})
    return {"success": True}


@api.post("/webhooks/{wid}/test")
async def test_webhook(wid: str, user: dict = Depends(require("webhook.test"))):
    hook = await db.webhooks.find_one({"id": wid}, {"_id": 0})
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook tidak ditemukan")
    doc = {"id": gen_id("EVT"), "webhook_id": wid, "merchant_id": hook["merchant_id"],
           "event": "webhook.test", "payment_id": None, "url": hook["url"],
           "http_status": 200, "response": "OK", "latency_ms": random.randint(50, 200),
           "retry_count": 0, "status": "delivered", "timestamp": now_iso()}
    await db.webhook_deliveries.insert_one(doc)
    return clean(doc)


@api.get("/webhook-deliveries")
async def webhook_deliveries(user: dict = Depends(require("webhook.read"))):
    return await db.webhook_deliveries.find(merchant_scope(user), {"_id": 0}).sort("timestamp", -1).to_list(500)


# ================================================================ FRAUD / RISK
@api.get("/fraud-rules")
async def list_fraud_rules(user: dict = Depends(require("fraud.read"))):
    return await db.fraud_rules.find({}, {"_id": 0}).to_list(100)


@api.post("/fraud-rules")
async def create_fraud_rule(body: FraudRuleIn, request: Request, user: dict = Depends(require("fraud.update"))):
    doc = {"id": gen_id("FRD"), **body.model_dump(), "created_at": now_iso()}
    await db.fraud_rules.insert_one(doc)
    await log_audit(user, "fraud.rule.create", doc["id"], ip=request.client.host)
    return clean(doc)


@api.delete("/fraud-rules/{fid}")
async def delete_fraud_rule(fid: str, user: dict = Depends(require("fraud.update"))):
    await db.fraud_rules.delete_one({"id": fid})
    return {"success": True}


@api.get("/blacklists")
async def list_blacklists(user: dict = Depends(require("fraud.read")), list: str = "blacklist"):
    return await db.blacklists.find({"list": list}, {"_id": 0}).sort("created_at", -1).to_list(500)


@api.post("/blacklists")
async def create_blacklist(body: BlacklistIn, request: Request, user: dict = Depends(require("fraud.update"))):
    doc = {"id": gen_id("BLK"), **body.model_dump(), "created_at": now_iso(), "created_by": user["email"]}
    await db.blacklists.insert_one(doc)
    await log_audit(user, f"{body.list}.add", body.value, ip=request.client.host)
    return clean(doc)


@api.delete("/blacklists/{bid}")
async def delete_blacklist(bid: str, user: dict = Depends(require("fraud.update"))):
    await db.blacklists.delete_one({"id": bid})
    return {"success": True}


@api.get("/risk-events")
async def risk_events(user: dict = Depends(require("fraud.read"))):
    return await db.risk_events.find({}, {"_id": 0}).sort("timestamp", -1).to_list(200)


# ================================================================ USERS (RBAC mgmt)
@api.get("/users")
async def list_users(user: dict = Depends(require("user.read"))):
    docs = await db.users.find({}, {"_id": 0, "password_hash": 0}).sort("created_at", -1).to_list(500)
    for d in docs:
        d["role_label"] = rbac.ROLE_LABELS.get(d["role"], d["role"])
    return docs


@api.post("/users")
async def create_user(body: UserIn, request: Request, user: dict = Depends(require("user.create"))):
    if body.role not in rbac.ROLE_LABELS:
        raise HTTPException(status_code=422, detail="Role tidak valid")
    if await db.users.find_one({"email": body.email.lower()}):
        raise HTTPException(status_code=409, detail="Email sudah terdaftar")
    doc = {"id": str(uuid.uuid4()), "name": body.name, "email": body.email.lower(),
           "password_hash": auth_lib.hash_password(body.password), "role": body.role,
           "merchant_id": None, "status": "active", "created_at": now_iso()}
    await db.users.insert_one(doc)
    await log_audit(user, "user.create", body.email, after={"role": body.role}, ip=request.client.host)
    return {"id": doc["id"], "name": doc["name"], "email": doc["email"], "role": doc["role"]}


@api.patch("/users/{uid}")
async def update_user(uid: str, body: UserUpdate, request: Request, user: dict = Depends(require("user.update"))):
    updates = {}
    for k in ("name", "role", "status"):
        v = getattr(body, k)
        if v is not None:
            updates[k] = v
    if body.password:
        updates["password_hash"] = auth_lib.hash_password(body.password)
    if updates:
        await db.users.update_one({"id": uid}, {"$set": updates})
        await log_audit(user, "user.update", uid, after={k: v for k, v in updates.items() if k != "password_hash"}, ip=request.client.host)
    d = await db.users.find_one({"id": uid}, {"_id": 0, "password_hash": 0})
    return d


@api.delete("/users/{uid}")
async def delete_user(uid: str, user: dict = Depends(require("user.delete"))):
    target = await db.users.find_one({"id": uid})
    if target and target.get("role") == "super_admin":
        raise HTTPException(status_code=403, detail="Super Admin tidak dapat dihapus")
    await db.users.delete_one({"id": uid})
    return {"success": True}


# ================================================================ REPORTS
@api.get("/reports/summary")
async def report_summary(user: dict = Depends(require("report.read"))):
    q = merchant_scope(user)
    trx = await db.transactions.find(q, {"_id": 0}).to_list(5000)
    total_amount = sum(t["amount"] for t in trx)
    total_fee = sum(t.get("fee", 0) for t in trx)
    by_method = {}
    for t in trx:
        by_method[t["payment_method"]] = by_method.get(t["payment_method"], 0) + t["amount"]
    return {"total_transactions": len(trx), "total_amount": total_amount, "total_fee": total_fee,
            "revenue": total_fee, "by_method": by_method}


@api.get("/reports/export")
async def report_export(user: dict = Depends(require("report.read")), type: str = "transactions"):
    q = merchant_scope(user)
    rows = await db.transactions.find(q, {"_id": 0}).sort("timestamp", -1).to_list(5000)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Transaction ID", "Reference", "Amount", "Fee", "Net", "Method", "Status", "Timestamp"])
    for r in rows:
        writer.writerow([r["id"], r.get("merchant_reference"), r["amount"], r.get("fee"),
                         r.get("net_amount"), r["payment_method"], r["status"], r["timestamp"]])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=transactions.csv"})


# ================================================================ AUDIT LOGS
@api.get("/audit-logs")
async def audit_logs(user: dict = Depends(require("audit.read"))):
    return await db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(500)


# ================================================================ NOTIFICATIONS
@api.get("/notifications")
async def notifications(user: dict = Depends(get_current_user)):
    q = {"merchant_id": user.get("merchant_id")} if user["role"] in rbac.MERCHANT_ROLES else {}
    return await db.notifications.find(q, {"_id": 0}).sort("timestamp", -1).to_list(100)


@api.post("/notifications/{nid}/read")
async def read_notification(nid: str, user: dict = Depends(get_current_user)):
    await db.notifications.update_one({"id": nid}, {"$set": {"read": True}})
    return {"success": True}


# ================================================================ SETTINGS
@api.get("/settings")
async def get_settings(user: dict = Depends(require("settings.read"))):
    doc = await db.system_settings.find_one({"id": "global"}, {"_id": 0}) or {"id": "global"}
    token_set = bool(doc.pop("gomerch_token", None))
    doc["gomerch_token_set"] = token_set
    return doc


@api.patch("/settings")
async def update_settings(body: SettingsIn, request: Request, user: dict = Depends(require("settings.update"))):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if updates:
        await db.system_settings.update_one({"id": "global"}, {"$set": updates}, upsert=True)
    if updates.get("gomerch_token"):
        os.environ["GOMERCH_TOKEN"] = updates["gomerch_token"]
    if "email_from_name" in updates or "email_reply_to" in updates:
        email_util.configure(from_name=updates.get("email_from_name"), reply_to=updates.get("email_reply_to"))
    safe = {k: v for k, v in updates.items() if k != "gomerch_token"}
    await log_audit(user, "settings.update", "global", after=safe, ip=request.client.host)
    fresh = await db.system_settings.find_one({"id": "global"}, {"_id": 0}) or {}
    token_set = bool(fresh.pop("gomerch_token", None))
    fresh["gomerch_token_set"] = token_set
    return fresh


@api.get("/branding")
async def branding():
    s = await db.system_settings.find_one({"id": "global"}, {"_id": 0}) or {}
    return {"company_name": s.get("company_name", "GoMerch Pro"), "logo_url": s.get("logo_url", "")}


@api.post("/settings/logo")
async def upload_logo(file: UploadFile = File(...), user: dict = Depends(require("settings.update"))):
    data = await file.read()
    if len(data) > 1_500_000:
        raise HTTPException(status_code=413, detail="Ukuran logo maksimal 1.5MB")
    ctype = file.content_type or "image/png"
    if not ctype.startswith("image/"):
        raise HTTPException(status_code=422, detail="File harus berupa gambar")
    url = f"data:{ctype};base64,{base64.b64encode(data).decode()}"
    await db.system_settings.update_one({"id": "global"}, {"$set": {"logo_url": url}}, upsert=True)
    await log_audit(user, "settings.logo.update", "global")
    return {"logo_url": url}


# ================================================================ GOMERCH integration
@api.get("/gomerch/status")
async def gomerch_status(user: dict = Depends(get_current_user)):
    code, data = await gomerch.validate_token()
    ok = isinstance(data, dict) and data.get("success")
    u = data.get("user", {}) if ok else {}
    return {"connected": bool(ok), "merchant": {
        "merchant_id": u.get("merchant_id"), "full_name": u.get("full_name"),
        "phone": u.get("phone"), "roles": u.get("roles"), "approved": u.get("approved"),
        "expired": u.get("expired"), "brand": u.get("brand"),
    } if ok else None}


@api.get("/gomerch/profile")
async def gomerch_profile(user: dict = Depends(get_current_user)):
    code, data = await gomerch.get_profile()
    if isinstance(data, dict) and data.get("success"):
        u = data.get("data", {}).get("user", {})
        return {"success": True, "user": {k: u.get(k) for k in
                ("merchant_id", "full_name", "phone", "email", "language", "roles",
                 "approved", "expired", "confirmed_at", "brand", "two_factor_enabled")}}
    return {"success": False, "error": data}


@api.get("/gomerch/history")
async def gomerch_history(user: dict = Depends(require("transaction.read")), days: int = 7):
    start = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    code, data = await gomerch.get_history(start)
    hits = []
    if isinstance(data, dict) and data.get("success"):
        d = data.get("data", {})
        hits = d.get("hits", []) if isinstance(d, dict) else []
    return {"success": True, "total": len(hits), "hits": hits}


# ================================================================ CRON (platform-scheduled)
@api.post("/cron/auto-settlement")
async def cron_auto_settlement(request: Request):
    # Cron endpoints must ack 2xx immediately; enqueue/background the actual work.
    secret = os.environ.get("WEBHOOK_CRON_SECRET", "")
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    if not secret or not hmac.compare_digest(token, secret):
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        envelope = await request.json()
    except Exception:
        envelope = {}
    run_id = request.headers.get("X-Webhook-Id") or envelope.get("run_id") or gen_id("RUN")
    if await db.cron_runs.find_one({"run_id": run_id}):
        return {"status": "duplicate", "run_id": run_id}
    await db.cron_runs.insert_one({"run_id": run_id, "job": "auto-settlement", "status": "accepted", "created_at": now_iso()})
    asyncio.create_task(_run_auto_settlement(run_id))
    return {"status": "accepted", "run_id": run_id}


async def _run_auto_settlement(run_id: str):
    try:
        s = await db.system_settings.find_one({"id": "global"}, {"_id": 0}) or {}
        if not s.get("auto_settlement", False):
            await db.cron_runs.update_one({"run_id": run_id}, {"$set": {"status": "skipped_disabled", "finished_at": now_iso()}})
            return
        merchants = await db.merchants.find({"pending_balance": {"$gt": 0}, "account_status": "ACTIVE"}, {"_id": 0}).to_list(5000)
        count = 0
        for m in merchants:
            amount = m.get("pending_balance", 0)
            if amount <= 0:
                continue
            now = now_iso()
            sid = gen_id("STL")
            await db.settlements.insert_one({"id": sid, "merchant_id": m["id"], "amount": amount, "status": "COMPLETED",
                                             "account": m.get("settlement_account", ""), "created_at": now, "completed_at": now, "auto": True})
            await db.merchants.update_one({"id": m["id"]}, {"$inc": {"pending_balance": -amount, "settled_balance": amount, "available_balance": amount}})
            await db.ledger_entries.insert_one({"id": gen_id("LGR"), "merchant_id": m["id"], "transaction_id": sid,
                                                "type": "SETTLED_BALANCE", "amount": amount, "direction": "CREDIT",
                                                "balance_before": 0, "balance_after": amount, "description": f"Auto-settlement {sid}", "timestamp": now})
            await db.transactions.update_many({"merchant_id": m["id"], "settlement_status": "PENDING"}, {"$set": {"settlement_status": "SETTLED"}})
            await notify(m["id"], "Settlement otomatis (T+1)", f"Dana Rp {amount:,} dipindahkan ke saldo tersedia.".replace(",", "."), "success")
            count += 1
        await db.cron_runs.update_one({"run_id": run_id}, {"$set": {"status": "done", "settled_merchants": count, "finished_at": now_iso()}})
    except Exception as e:
        logger.error(f"auto-settlement failed: {e}")
        await db.cron_runs.update_one({"run_id": run_id}, {"$set": {"status": "error", "error": str(e), "finished_at": now_iso()}})


# ================================================================ DASHBOARDS
@api.get("/dashboard/merchant")
async def dashboard_merchant(user: dict = Depends(require("dashboard.read"))):
    if user["role"] not in rbac.MERCHANT_ROLES:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    mid = user.get("merchant_id")
    q = {"merchant_id": mid}
    trx = await db.transactions.find(q, {"_id": 0}).to_list(5000)
    payments = await db.payments.find(q, {"_id": 0}).to_list(5000)
    merchant = await db.merchants.find_one({"id": mid}, {"_id": 0}) or {}
    total_amount = sum(t["amount"] for t in trx)
    success = len([p for p in payments if p["status"] == "PAID"])
    failed = len([p for p in payments if p["status"] in ("FAILED", "EXPIRED")])
    pending = len([p for p in payments if p["status"] in ("PENDING", "CREATED")])
    # 7-day chart
    chart = _daily_chart(trx)
    return {"total_transactions": len(trx), "total_amount": total_amount,
            "total_fee": sum(t.get("fee", 0) for t in trx),
            "success": success, "failed": failed, "pending": pending,
            "available_balance": merchant.get("available_balance", 0),
            "pending_balance": merchant.get("pending_balance", 0),
            "settled_balance": merchant.get("settled_balance", 0),
            "chart": chart, "recent": sorted(payments, key=lambda x: x["created_at"], reverse=True)[:5]}


@api.get("/dashboard/admin")
async def dashboard_admin(user: dict = Depends(require("dashboard.read"))):
    if user["role"] in rbac.MERCHANT_ROLES:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    merchants = await db.merchants.find({}, {"_id": 0}).to_list(5000)
    trx = await db.transactions.find({}, {"_id": 0}).to_list(20000)
    payments = await db.payments.find({}, {"_id": 0}).to_list(20000)
    refunds = await db.refunds.find({}, {"_id": 0}).to_list(5000)
    settlements = await db.settlements.find({}, {"_id": 0}).to_list(5000)
    pending_wd = await db.withdrawals.count_documents({"status": "PENDING"})
    return {
        "total_merchants": len(merchants),
        "active_merchants": len([m for m in merchants if m.get("account_status") == "ACTIVE"]),
        "pending_merchants": len([m for m in merchants if m.get("account_status") == "PENDING"]),
        "total_transactions": len(trx),
        "success": len([p for p in payments if p["status"] == "PAID"]),
        "failed": len([p for p in payments if p["status"] in ("FAILED", "EXPIRED")]),
        "pending": len([p for p in payments if p["status"] in ("PENDING", "CREATED")]),
        "total_amount": sum(t["amount"] for t in trx),
        "total_fee": sum(t.get("fee", 0) for t in trx),
        "total_settlement": sum(s["amount"] for s in settlements),
        "refunds": len(refunds),
        "pending_withdrawals": pending_wd,
        "chart": _daily_chart(trx),
        "recent": sorted(payments, key=lambda x: x["created_at"], reverse=True)[:8],
    }


def _daily_chart(trx):
    buckets = {}
    for i in range(6, -1, -1):
        d = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        buckets[d] = {"date": d, "amount": 0, "count": 0}
    for t in trx:
        d = t["timestamp"][:10]
        if d in buckets:
            buckets[d]["amount"] += t["amount"]
            buckets[d]["count"] += 1
    return list(buckets.values())


@api.get("/")
async def root():
    return {"message": "GoMerch Pro Payment Gateway API", "status": "ok"}


# ---------------------------------------------------------------- startup
@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id")
    await db.login_attempts.create_index("identifier")
    # seed super admin
    admin_email = os.environ["ADMIN_EMAIL"].lower()
    admin_pass = os.environ["ADMIN_PASSWORD"]
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "id": str(uuid.uuid4()), "name": "Dedy Harianto", "email": admin_email,
            "password_hash": auth_lib.hash_password(admin_pass), "role": "super_admin",
            "merchant_id": None, "status": "active", "created_at": now_iso()})
    elif not auth_lib.verify_password(admin_pass, existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": auth_lib.hash_password(admin_pass)}})
    # default fees per method (QRIS 1.8%, DANA / e-wallet 3.2%)
    fee_defaults = [("QRIS Standard", "QRIS", 1.8), ("DANA / E-Wallet", "DANA", 3.2), ("E-Wallet", "E-WALLET", 3.2)]
    for fname, method, pct in fee_defaults:
        await db.fees.update_one({"method": method}, {"$setOnInsert": {
            "id": gen_id("FEE"), "name": fname, "method": method, "percent": pct,
            "fixed": 0, "min_fee": 0, "max_fee": 0, "created_at": now_iso()}}, upsert=True)
    await db.fees.update_one({"method": "QRIS", "percent": 0.7}, {"$set": {"percent": 1.8}})
    # global settings
    existing_settings = await db.system_settings.find_one({"id": "global"})
    if not existing_settings:
        await db.system_settings.insert_one({"id": "global", "company_name": "GoMerch Pro",
                                             "gomerch_static_qr": "", "default_fee_percent": 1.8,
                                             "settlement_schedule": "T+1", "logo_url": "",
                                             "email_notifications": True, "auto_settlement": False,
                                             "email_from_name": "GoMerch Pro",
                                             "email_reply_to": os.environ.get("EMAIL_REPLY_TO", ""),
                                             "withdrawal_min": 50000, "withdrawal_fee_percent": 0.40,
                                             "withdrawal_admin_fee": 4500})
    else:
        defaults = {"withdrawal_min": 50000, "withdrawal_fee_percent": 0.40, "withdrawal_admin_fee": 4500,
                    "logo_url": "", "email_notifications": True, "auto_settlement": False,
                    "email_from_name": "GoMerch Pro"}
        patch = {k: v for k, v in defaults.items() if k not in existing_settings}
        if patch:
            await db.system_settings.update_one({"id": "global"}, {"$set": patch})
    s2 = await db.system_settings.find_one({"id": "global"}, {"_id": 0}) or {}
    if s2.get("gomerch_token"):
        os.environ["GOMERCH_TOKEN"] = s2["gomerch_token"]
    email_util.configure(from_name=s2.get("email_from_name"), reply_to=s2.get("email_reply_to"))
    logger.info("Startup complete. Super admin ready.")


app.include_router(api)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=False,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown():
    client.close()
