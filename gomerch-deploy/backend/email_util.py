"""Emergent-managed Resend email (transactional only). Brand: GoMerch Pro."""
import os
import re
import ipaddress
import logging
import httpx
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlparse

logger = logging.getLogger("email")

EMAIL_BASE_URL = ""
EMAIL_KEY = os.environ.get("EMERGENT_EMAIL_KEY", "")
EMAIL_FROM_NAME = os.environ.get("EMAIL_FROM_NAME", "GoMerch Pro")
EMAIL_REPLY_TO = os.environ.get("EMAIL_REPLY_TO")


def configure(from_name=None, reply_to=None):
    global EMAIL_FROM_NAME, EMAIL_REPLY_TO
    if from_name:
        EMAIL_FROM_NAME = from_name
    if reply_to:
        EMAIL_REPLY_TO = reply_to

_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl", "rebrand.ly")
_CRED_ASK = ("reply with your password", "reply with the code", "send your password", "cvv",
             "send us your password", "enter your password below", "confirm your card number",
             "your full card number", "seed phrase", "recovery phrase", "verify your card",
             "social security number", "confirm your bank details")
_HOSTISH = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.I)


def _host_ok(host: str) -> bool:
    if not host or "xn--" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not any(host == s or host.endswith("." + s) for s in _SHORTENERS)


def _same_site(shown: str, real: str) -> bool:
    return shown == real or real.endswith("." + shown) or shown.endswith("." + real)


class _EmailScan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.urls, self.anchors = set(), [], []
        self._href, self._text = None, []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag.lower())
        self.urls += [v for k, v in attrs if k.lower() in ("href", "src") and v]
        if tag.lower() == "a":
            self._href = dict((k.lower(), v) for k, v in attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._text)))
            self._href, self._text = None, []


def _assert_safe_email(subject: str, html: str) -> None:
    scan = _EmailScan(); scan.feed(html)
    if scan.tags & {"form", "input", "textarea", "select"}:
        raise ValueError("No forms or input fields in email (G2)")
    body = f"{subject}\n{html}".lower()
    for p in _CRED_ASK:
        if p in body:
            raise ValueError(f"Email asks the recipient for credentials: {p!r} (G2)")
    for url in scan.urls:
        low = url.strip().lower()
        if low.startswith(("mailto:", "tel:", "cid:", "#")):
            continue
        if not low.startswith("https://"):
            raise ValueError(f"Email links/assets must be absolute https: {url!r} (G3)")
        host = urlparse(low).hostname or ""
        if not _host_ok(host) or urlparse(low).username is not None:
            raise ValueError(f"Shortened, numeric-host or credential-bearing URL: {url!r} (G3)")
    for href, text in scan.anchors:
        real = urlparse(href.strip().lower()).hostname or ""
        if not real:
            continue
        for m in _HOSTISH.finditer(text):
            if not _same_site(m.group(1).lower(), real):
                raise ValueError(f"Anchor text {m.group(1)!r} != real link host {real!r} (G3)")


async def send_email(*, to: str, subject: str, html: str) -> str | None:
    _assert_safe_email(subject, html)
    payload = {"to": [to], "subject": subject, "html": html, "from_name": EMAIL_FROM_NAME}
    if EMAIL_REPLY_TO:
        payload["contact_email"] = EMAIL_REPLY_TO
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(f"{EMAIL_BASE_URL}/api/v1/email/send",
                                 headers={"X-Email-Key": EMAIL_KEY}, json=payload)
    resp.raise_for_status()
    return resp.json().get("id")


async def safe_send(to: str, subject: str, html: str) -> str | None:
    """Best-effort: never break the caller flow if email fails."""
    if not to or not EMAIL_KEY:
        return None
    try:
        return await send_email(to=to, subject=subject, html=html)
    except Exception as e:
        logger.warning(f"Email send skipped/failed to {to}: {e}")
        return None


# ---------------------------------------------------------------- templates
def _rp(n):
    return "Rp " + f"{int(n or 0):,}".replace(",", ".")


def _wrap(inner: str) -> str:
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="background:#f8fafc;padding:24px 0;font-family:Arial,Helvetica,sans-serif">'
        '<tr><td align="center"><table role="presentation" width="520" cellpadding="0" cellspacing="0" '
        'style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden">'
        '<tr><td style="background:#059669;padding:20px 28px">'
        '<span style="color:#ffffff;font-size:18px;font-weight:bold">GoMerch Pro</span></td></tr>'
        f'<tr><td style="padding:28px">{inner}</td></tr>'
        '<tr><td style="padding:18px 28px;border-top:1px solid #f1f5f9;font-size:12px;color:#94a3b8">'
        'Email ini dikirim oleh GoMerch Pro Payment Gateway. Kami tidak pernah meminta kata sandi, '
        'kode OTP, atau detail kartu Anda melalui email.</td></tr>'
        '</table></td></tr></table>'
    )


def tpl_payment_received(business, pay_id, amount, net):
    subject = f"Pembayaran diterima - {_rp(amount)}"
    inner = (
        f'<p style="color:#0f172a;font-size:15px">Halo {escape(business or "Merchant")},</p>'
        f'<p style="color:#475569;font-size:14px">Pembayaran baru telah <b>berhasil diterima</b>.</p>'
        f'<table width="100%" style="margin:16px 0;font-size:14px;color:#334155">'
        f'<tr><td>ID Pembayaran</td><td align="right"><b>{escape(pay_id)}</b></td></tr>'
        f'<tr><td>Nominal</td><td align="right"><b>{_rp(amount)}</b></td></tr>'
        f'<tr><td>Diterima (net)</td><td align="right" style="color:#059669"><b>{_rp(net)}</b></td></tr>'
        f'</table>'
        f'<p style="color:#94a3b8;font-size:13px">Masuk ke dashboard GoMerch Pro untuk melihat detail transaksi.</p>'
    )
    return subject, _wrap(inner)


def tpl_withdrawal_approved(business, wid, amount, net, bank):
    subject = f"Penarikan disetujui - {_rp(net)} dalam proses transfer"
    inner = (
        f'<p style="color:#0f172a;font-size:15px">Halo {escape(business or "Merchant")},</p>'
        f'<p style="color:#475569;font-size:14px">Permintaan penarikan dana Anda telah <b>disetujui</b> dan sedang diproses.</p>'
        f'<table width="100%" style="margin:16px 0;font-size:14px;color:#334155">'
        f'<tr><td>ID Penarikan</td><td align="right"><b>{escape(wid)}</b></td></tr>'
        f'<tr><td>Nominal</td><td align="right">{_rp(amount)}</td></tr>'
        f'<tr><td>Biaya pencairan</td><td align="right" style="color:#ef4444">- {_rp(amount - net)}</td></tr>'
        f'<tr><td>Dana bersih</td><td align="right" style="color:#059669"><b>{_rp(net)}</b></td></tr>'
        f'<tr><td>Rekening tujuan</td><td align="right"><b>{escape(bank or "-")}</b></td></tr>'
        f'</table>'
    )
    return subject, _wrap(inner)


def tpl_withdrawal_rejected(business, wid, amount, reason):
    subject = f"Penarikan ditolak - {_rp(amount)}"
    inner = (
        f'<p style="color:#0f172a;font-size:15px">Halo {escape(business or "Merchant")},</p>'
        f'<p style="color:#475569;font-size:14px">Mohon maaf, permintaan penarikan dana Anda <b>ditolak</b>.</p>'
        f'<table width="100%" style="margin:16px 0;font-size:14px;color:#334155">'
        f'<tr><td>ID Penarikan</td><td align="right"><b>{escape(wid)}</b></td></tr>'
        f'<tr><td>Nominal</td><td align="right">{_rp(amount)}</td></tr>'
        f'<tr><td>Alasan</td><td align="right"><b>{escape(reason or "-")}</b></td></tr>'
        f'</table>'
        f'<p style="color:#94a3b8;font-size:13px">Saldo Anda tidak berkurang. Silakan ajukan kembali atau hubungi admin.</p>'
    )
    return subject, _wrap(inner)
