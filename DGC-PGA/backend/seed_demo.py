"""Seed demo staff + merchant accounts and sample data."""
import asyncio, os, uuid
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(__file__).parent / '.env')
from motor.motor_asyncio import AsyncIOMotorClient
import auth as auth_lib

db = AsyncIOMotorClient(os.environ['MONGO_URL'])[os.environ['DB_NAME']]
PW = auth_lib.hash_password("GoMerch2026!")


def iso(dt=None):
    return (dt or datetime.now(timezone.utc)).isoformat()


async def main():
    staff = [
        ("Admin Operasional", "admin.demo@gomerch.pro", "admin"),
        ("Tim Finance", "finance.demo@gomerch.pro", "finance"),
        ("Tim Support", "support.demo@gomerch.pro", "support"),
        ("Tim Risk", "risk.demo@gomerch.pro", "risk"),
    ]
    for name, email, role in staff:
        if not await db.users.find_one({"email": email}):
            await db.users.insert_one({"id": str(uuid.uuid4()), "name": name, "email": email,
                "password_hash": PW, "role": role, "merchant_id": None, "status": "active", "created_at": iso()})

    # demo merchant
    mid = "MER-DEMO0001"
    if not await db.merchants.find_one({"id": mid}):
        await db.merchants.insert_one({"id": mid, "business_name": "Toko Sinar Jaya", "owner_name": "Budi Santoso",
            "email": "merchant.demo@gomerch.pro", "phone": "081234567890", "address": "Jl. Merdeka No. 10, Jakarta",
            "kyc_status": "APPROVED", "account_status": "ACTIVE", "api_status": "active", "fee_percent": 0.7,
            "limit": 100000000, "settlement_account": "BCA 1234567890", "static_qr": "",
            "available_balance": 4500000, "pending_balance": 1250000, "settled_balance": 4500000,
            "created_at": iso(datetime.now(timezone.utc) - timedelta(days=40)), "last_activity": iso()})
    if not await db.users.find_one({"email": "merchant.demo@gomerch.pro"}):
        await db.users.insert_one({"id": str(uuid.uuid4()), "name": "Budi Santoso", "email": "merchant.demo@gomerch.pro",
            "password_hash": PW, "role": "merchant", "merchant_id": mid, "status": "active", "created_at": iso()})

    # extra pending merchants
    for i, (biz, owner) in enumerate([("Warung Kopi Senja", "Sari Dewi"), ("Digital Store ID", "Andi Wijaya"),
                                       ("Fashion Hub", "Rina Melati")]):
        m2 = f"MER-DEMO000{i+2}"
        if not await db.merchants.find_one({"id": m2}):
            await db.merchants.insert_one({"id": m2, "business_name": biz, "owner_name": owner,
                "email": f"{owner.split()[0].lower()}@example.com", "phone": "0812000000" + str(i),
                "address": "Indonesia", "kyc_status": "PENDING" if i else "UNDER_REVIEW",
                "account_status": "PENDING", "api_status": "inactive", "fee_percent": 0.7, "limit": 50000000,
                "settlement_account": "", "static_qr": "", "available_balance": 0, "pending_balance": 0,
                "settled_balance": 0, "created_at": iso(datetime.now(timezone.utc) - timedelta(days=i)), "last_activity": iso()})

    # sample transactions for demo merchant
    if await db.transactions.count_documents({"merchant_id": mid}) == 0:
        methods = ["QRIS", "QRIS", "QRIS", "VA", "E-WALLET"]
        for i in range(24):
            amt = [15000, 50000, 120000, 250000, 75000, 500000][i % 6]
            fee = int(amt * 0.007)
            ts = iso(datetime.now(timezone.utc) - timedelta(days=i % 7, hours=i))
            pid = f"PAY-DEMO{i:04d}"
            status = "PAID" if i % 5 else "PAID"
            await db.payments.insert_one({"id": pid, "merchant_id": mid, "merchant_reference": f"ORDER-{1000+i}",
                "amount": amt, "fee": fee, "net_amount": amt - fee, "currency": "IDR",
                "payment_method": methods[i % 5], "status": status, "description": "Penjualan produk",
                "customer_name": "Pelanggan", "customer_email": "", "qr_image": None, "qr_source": "demo",
                "static_qr": "", "idempotency_key": None, "risk": "LOW", "created_at": ts, "updated_at": ts, "paid_at": ts})
            await db.transactions.insert_one({"id": f"TRX-DEMO{i:04d}", "payment_id": pid, "merchant_id": mid,
                "merchant_reference": f"ORDER-{1000+i}", "amount": amt, "fee": fee, "net_amount": amt - fee,
                "currency": "IDR", "payment_method": methods[i % 5], "status": "PAID", "customer_reference": "Pelanggan",
                "settlement_status": "SETTLED" if i > 10 else "PENDING", "callback_status": "sent",
                "timestamp": ts, "source": "demo"})
    print("Seed complete")


asyncio.run(main())
